'use strict'

const fs = require('fs')
const path = require('path')
const { spawnSync, spawn } = require('child_process')
const os = require('os')

// ── 常量 ──────────────────────────────────────────────────────────────────────
const REPO_ROOT = path.resolve(__dirname, '..')
const YASA_MAIN = path.join(REPO_ROOT, 'YASA-Engine-main', 'dist', 'main.js')
const RULE_MAP_PATH = path.join(__dirname, 'rule-map.json')
const PENDING_PATH = path.join(__dirname, 'pending-scans.json')
const LOG_PATH = path.join(os.tmpdir(), 'yasa-hook.log')
const FINDINGS_BASE = path.join(os.tmpdir(), 'yasa-findings')
const SYNC_TIMEOUT_MS = 8000
const YASA_ROOT = path.join(REPO_ROOT, 'YASA-Engine-main')
const YASA_INTERMEDIATE_DIR = path.join(os.tmpdir(), 'yasa-cache')

// ── 日志（只写文件，不污染 stdout）────────────────────────────────────────────
function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}\n`
  try { fs.appendFileSync(LOG_PATH, line) } catch (_) {}
}

// ── 读取 stdin ────────────────────────────────────────────────────────────────
function readStdin() {
  return new Promise((resolve) => {
    let buf = ''
    process.stdin.setEncoding('utf8')
    process.stdin.on('data', (d) => { buf += d })
    process.stdin.on('end', () => resolve(buf))
  })
}

// ── 输入校验：断开 stdin 到文件系统/spawn 的污点链 ──────────────────────────
// 只允许看起来像绝对路径的字符串（Windows/Unix），拒绝一切路径遍历序列
function validateFilePath(p) {
  if (typeof p !== 'string' || p.length === 0 || p.length > 4096) return null
  // 必须是绝对路径
  if (!path.isAbsolute(p)) return null
  // 禁止路径遍历
  const normalized = path.normalize(p)
  if (normalized.includes('..')) return null
  return normalized
}

// session_id 只保留字母/数字/连字符，防止目录穿越
function sanitizeSessionId(s) {
  if (typeof s !== 'string') return 'sess'
  return s.replace(/[^a-zA-Z0-9\-_]/g, '').slice(0, 64) || 'sess'
}

// ── 解析 SARIF findings ───────────────────────────────────────────────────────
function parseSarif(reportDir) {
  if (!fs.existsSync(reportDir)) return []
  const files = fs.readdirSync(reportDir).filter(f =>
    (f.startsWith('findings') && f.endsWith('.json')) || f.endsWith('.sarif')
  )
  const results = []
  for (const f of files) {
    try {
      const sarif = JSON.parse(fs.readFileSync(path.join(reportDir, f), 'utf8'))
      const runs = sarif?.runs ?? []
      for (const run of runs) {
        for (const r of (run.results ?? [])) {
          results.push(r)
        }
      }
    } catch (_) {}
  }
  return results
}

// ── 格式化漏洞报告（注入 Claude 上下文）──────────────────────────────────────
function formatFindings(findings, originPath, scanTarget) {
  const targetDesc = scanTarget && scanTarget !== originPath
    ? `${originPath}（reverse 目标：${scanTarget}）`
    : originPath
  const lines = [`⚠ YASA 安全扫描结果（共 ${findings.length} 个问题）触发文件：${targetDesc}\n`]
  findings.forEach((f, i) => {
    const loc = f.locations?.[0]?.physicalLocation
    const region = loc?.region ?? {}
    const snippet = region?.snippet?.text ?? ''
    const lineNo = region?.startLine ?? '?'
    const msg = f.message?.text ?? '未知漏洞'
    const sink = f.sinkInfo?.sinkAttribute ?? ''
    const attr = sink ? ` | ${sink}` : ''
    const locFile = loc?.artifactLocation?.uri
      ? String(loc.artifactLocation.uri).replace(/^file:\/\//, '')
      : originPath

    // 提取污点路径（codeFlows 第一条 threadFlow）
    const flow = f.codeFlows?.[0]?.threadFlows?.[0]?.locations ?? []
    const flowDesc = flow.length >= 2
      ? `    污点路径：${flow[0]?.location?.physicalLocation?.region?.snippet?.text ?? 'source'} → ${flow[flow.length - 1]?.location?.physicalLocation?.region?.snippet?.text ?? 'sink'}（第 ${lineNo} 行）`
      : ''

    lines.push(`[${i + 1}] ${msg}${attr}`)
    lines.push(`    文件：${locFile} 第 ${lineNo} 行`)
    if (snippet) lines.push(`    代码：${snippet.trim()}`)
    if (flowDesc) lines.push(flowDesc)
    lines.push('')
  })
  lines.push('请修复以上问题后重新生成代码。')
  return lines.join('\n')
}

// ── 从规则文件提取 checkerIds ────────────────────────────────────────────────
function extractCheckerIds(absRuleFile) {
  try {
    const rules = JSON.parse(fs.readFileSync(absRuleFile, 'utf8'))
    const ids = []
    for (const r of (Array.isArray(rules) ? rules : [])) {
      if (Array.isArray(r.checkerIds)) ids.push(...r.checkerIds)
    }
    return ids.length ? [...new Set(ids)].join(',') : null
  } catch (_) { return null }
}

// ── 扫描目标决策引擎 ─────────────────────────────────────────────────────────
// 返回 { mode, scanTarget, reason }
// 'forward'  : 检测到路由注册，单文件扫描（YASA 会以 express entrypoint 为起点建 CG）
// 'reverse'  : 检测到 sink 无路由，向上找项目根，目录级扫描建完整 CG 反向追溯
// 'standard' : 无特征，单文件扫描
// 'skip'     : 测试/声明/配置/Hook 脚本自身
function decideScanStrategy(filePath, ruleConfigFile) {
  const basename = path.basename(filePath)

  if (basename === 'yasa-hook.js' || basename === 'yasa-stop-hook.js') {
    return { mode: 'skip', scanTarget: null, reason: '内部 Hook 脚本，跳过扫描' }
  }

  if (/\.(test|spec)\.(js|ts|jsx|tsx)$/.test(filePath))
    return { mode: 'skip', scanTarget: null, reason: '测试文件' }
  if (/\.(d\.ts|min\.js|config\.(js|ts))$/.test(filePath))
    return { mode: 'skip', scanTarget: null, reason: '声明/配置文件' }

  let content = ''
  try { content = fs.readFileSync(filePath, 'utf8') } catch (_) {
    return { mode: 'skip', scanTarget: null, reason: '文件读取失败，跳过扫描' }
  }

  const routePatterns = [
    /\bapp\.(get|post|put|delete|patch|all|use)\s*\(/,
    /\brouter\.(get|post|put|delete|patch|all|use)\s*\(/,
    /@(Get|Post|Put|Delete|Patch|Controller)\s*\(/,
    /\bRoute\s*\(\s*['"`]/,
    /\bexpress\.Router\s*\(\)/,
  ]
  const hasRoute = routePatterns.some(r => r.test(content))

  const builtinSinkPatterns = [
    /\bexec\s*\(/, /\bspawn\s*\(/, /\bexecSync\s*\(/, /\bspawnSync\s*\(/,
    /\.query\s*\(/, /\.execute\s*\(/, /\.raw\s*\(/,
    /\beval\s*\(/, /\bnew\s+Function\s*\(/,
    /\.innerHTML\s*=/, /\.outerHTML\s*=/, /document\.write\s*\(/,
    /\bres\.redirect\s*\(/, /\bRes\.Redirect\s*\(/,
  ]
  let sinkFsigs = []
  try {
    const rules = JSON.parse(fs.readFileSync(ruleConfigFile, 'utf8'))
    for (const r of (Array.isArray(rules) ? rules : [])) {
      const sinkGroups = r.sinks ?? {}
      for (const group of Object.values(sinkGroups)) {
        for (const sink of (Array.isArray(group) ? group : [])) {
          if (sink.fsig) sinkFsigs.push(sink.fsig)
        }
      }
    }
  } catch (_) {}
  const dynamicSinkPatterns = sinkFsigs.map(sig => {
    const fn = sig.split('.').pop()
    return fn ? new RegExp(`\\b${fn}\\s*\\(`) : null
  }).filter(Boolean)

  const hasSink = [...builtinSinkPatterns, ...dynamicSinkPatterns].some(r => r.test(content))

  if (hasRoute) {
    return { mode: 'forward', scanTarget: filePath, reason: '检测到路由注册，正向单文件扫描' }
  }

  if (hasSink) {
    // reverse：找项目根（向上找 package.json），以目录为 sourcePath 建完整 CG
    const projectRoot = findProjectRoot(filePath)
    const scanTarget = projectRoot ?? path.dirname(filePath)
    return {
      mode: 'reverse',
      scanTarget,
      reason: `检测到 sink 调用，反向 CG 回溯（扫描目录：${scanTarget}）`,
    }
  }

  return { mode: 'skip', scanTarget: null, reason: '无路由/sink 特征，跳过扫描' }
}

// ── 向上查找项目根（package.json 所在目录），最多回溯 6 层 ─────────────────────
function findProjectRoot(filePath) {
  let dir = path.dirname(filePath)
  for (let i = 0; i < 6; i++) {
    if (fs.existsSync(path.join(dir, 'package.json'))) return dir
    const parent = path.dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  return null
}

// ── 写入异步任务队列 ──────────────────────────────────────────────────────────
function enqueuePending(task) {
  let queue = []
  try { queue = JSON.parse(fs.readFileSync(PENDING_PATH, 'utf8')) } catch (_) {}
  queue.push(task)
  fs.writeFileSync(PENDING_PATH, JSON.stringify(queue, null, 2))
}

// ── 运行 YASA（同步，带超时）─────────────────────────────────────────────────
function runYasaSync(scanTarget, language, ruleConfigFile, reportDir, useSingleFile) {
  if (!fs.existsSync(YASA_MAIN)) {
    log(`WARN: YASA dist 不存在 (${YASA_MAIN})，跳过扫描`)
    return { skipped: true }
  }
  const absRule = path.isAbsolute(ruleConfigFile)
    ? ruleConfigFile
    : path.join(REPO_ROOT, ruleConfigFile)
  if (!fs.existsSync(absRule)) {
    log(`WARN: 规则文件不存在 (${absRule})，跳过扫描`)
    return { skipped: true }
  }
  fs.mkdirSync(reportDir, { recursive: true })
  fs.mkdirSync(YASA_INTERMEDIATE_DIR, { recursive: true })

  const checkerIds = extractCheckerIds(absRule) || 'taint_flow_js_input,taint_flow_express_input,taint_flow_egg_input'

  const args = [
    YASA_MAIN,
    '--sourcePath', scanTarget,
    '--language', language,
    '--checkerIds', checkerIds,
    '--ruleConfigFile', absRule,
    '--report', reportDir,
    '--intermediate-dir', YASA_INTERMEDIATE_DIR,
    '--incremental', 'true',
  ]
  if (useSingleFile) args.splice(3, 0, '--single')

  const result = spawnSync(process.execPath, args, {
    timeout: SYNC_TIMEOUT_MS,
    encoding: 'utf8',
    cwd: YASA_ROOT,
  })

  if (result.error?.code === 'ETIMEDOUT' || result.signal === 'SIGTERM') {
    return { timeout: true }
  }
  if (result.status !== 0) {
    log(`ERROR: YASA 退出码 ${result.status}: ${((result.stderr ?? '') + (result.stdout ?? '')).slice(0, 240)}`)
    return { error: true }
  }
  return { done: true }
}

// ── 后台异步扫描（超时后继续跑）──────────────────────────────────────────────
function runYasaAsync(scanTarget, language, ruleConfigFile, reportDir, sessionId, useSingleFile) {
  const absRule = path.isAbsolute(ruleConfigFile)
    ? ruleConfigFile
    : path.join(REPO_ROOT, ruleConfigFile)
  fs.mkdirSync(reportDir, { recursive: true })
  fs.mkdirSync(YASA_INTERMEDIATE_DIR, { recursive: true })

  const checkerIds = extractCheckerIds(absRule) || 'taint_flow_js_input,taint_flow_express_input,taint_flow_egg_input'

  const args = [
    YASA_MAIN,
    '--sourcePath', scanTarget,
    '--language', language,
    '--checkerIds', checkerIds,
    '--ruleConfigFile', absRule,
    '--report', reportDir,
    '--intermediate-dir', YASA_INTERMEDIATE_DIR,
    '--incremental', 'true',
  ]
  if (useSingleFile) args.splice(3, 0, '--single')

  const child = spawn(process.execPath, args, { detached: true, stdio: 'ignore', cwd: YASA_ROOT })
  child.unref()

  enqueuePending({ filePath: scanTarget, reportDir, sessionId, startedAt: Date.now(), pid: child.pid })
  log(`ASYNC: 扫描已转后台 pid=${child.pid} target=${scanTarget}`)
}

// ── 主逻辑 ────────────────────────────────────────────────────────────────────
async function main() {
  const raw = await readStdin()
  let event
  try { event = JSON.parse(raw) } catch (_) { process.exit(0) }

  const { tool_name, tool_input, session_id } = event
  if (tool_name !== 'Write' && tool_name !== 'Edit') process.exit(0)

  const rawPath = tool_input?.file_path
  const filePath = validateFilePath(rawPath)
  if (!filePath) {
    log(`SKIP: 非法 file_path (${String(rawPath).slice(0, 120)})`)
    process.exit(0)
  }
  const safeSessionId = sanitizeSessionId(session_id)

  const ext = filePath.split('.').pop()?.toLowerCase() ?? ''
  let ruleMap = {}
  try { ruleMap = JSON.parse(fs.readFileSync(RULE_MAP_PATH, 'utf8')) } catch (_) {}

  const mapping = ruleMap[ext]
  if (!mapping) {
    log(`SKIP: 不支持的扩展名 .${ext} (${filePath})`)
    process.exit(0)
  }

  const { language, ruleConfigFile } = mapping
  const absRule = path.isAbsolute(ruleConfigFile)
    ? ruleConfigFile
    : path.join(REPO_ROOT, ruleConfigFile)
  const ts = Date.now()
  const reportDir = path.join(FINDINGS_BASE, `${safeSessionId}-${ts}`)

  // 扫描目标决策：根据文件特征选择扫描策略
  const strategy = decideScanStrategy(filePath, absRule)
  log(`STRATEGY: ${filePath} → mode=${strategy.mode} (${strategy.reason})`)

  if (strategy.mode === 'skip') {
    process.exit(0)
  }

  // 仅扫描 forward/reverse，其他均 skip
  const useSingleFile = strategy.mode === 'forward'
  const scanTarget = strategy.scanTarget
  if (!scanTarget) process.exit(0)

  log(`SCAN: ${scanTarget} [${language}] mode=${strategy.mode}`)

  const scanResult = runYasaSync(scanTarget, language, ruleConfigFile, reportDir, useSingleFile)

  if (scanResult.skipped || scanResult.error) {
    process.exit(0)
  }

  if (scanResult.timeout) {
    log(`TIMEOUT: 转异步 ${scanTarget}`)
    runYasaAsync(scanTarget, language, ruleConfigFile, reportDir, safeSessionId, useSingleFile)
    process.exit(0)
  }

  // 扫描完成，解析结果
  const findings = parseSarif(reportDir)
  log(`DONE: ${scanTarget} → ${findings.length} 个问题`)

  if (findings.length === 0) process.exit(0)

  const additionalContext = formatFindings(findings, filePath, scanTarget)
  const output = {
    decision: 'block',
    reason: `YASA 发现 ${findings.length} 个安全问题，请修复后继续`,
    hookSpecificOutput: {
      hookEventName: 'PostToolUse',
      additionalContext,
    },
  }
  process.stdout.write(JSON.stringify(output))
  process.exit(0)
}

main().catch((e) => {
  log(`FATAL: ${e.message}`)
  process.exit(0) // fail-open
})
