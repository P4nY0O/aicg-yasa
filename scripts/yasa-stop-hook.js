'use strict'

const fs = require('fs')
const path = require('path')
const os = require('os')

const PENDING_PATH = path.join(__dirname, 'pending-scans.json')
const LOG_PATH = path.join(os.tmpdir(), 'yasa-hook.log')

function log(msg) {
  const line = `[${new Date().toISOString()}] [STOP] ${msg}\n`
  try { fs.appendFileSync(LOG_PATH, line) } catch (_) {}
}

function readStdin() {
  return new Promise((resolve) => {
    let buf = ''
    process.stdin.setEncoding('utf8')
    process.stdin.on('data', (d) => { buf += d })
    process.stdin.on('end', () => resolve(buf))
  })
}

function isProcessAlive(pid) {
  if (!pid || typeof pid !== 'number') return false
  try {
    process.kill(pid, 0)
    return true
  } catch (_) {
    return false
  }
}

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
        for (const r of (run.results ?? [])) results.push(r)
      }
    } catch (_) {}
  }
  return results
}

function formatFindings(findings, filePath) {
  const lines = [`⚠ 后台 YASA 扫描结果（共 ${findings.length} 个问题）文件：${filePath}\n`]
  findings.forEach((f, i) => {
    const loc = f.locations?.[0]?.physicalLocation
    const region = loc?.region ?? {}
    const snippet = region?.snippet?.text ?? ''
    const lineNo = region?.startLine ?? '?'
    const msg = f.message?.text ?? '未知漏洞'
    lines.push(`[${i + 1}] ${msg}`)
    lines.push(`    文件：${filePath} 第 ${lineNo} 行`)
    if (snippet) lines.push(`    代码：${snippet.trim()}`)
    lines.push('')
  })
  lines.push('请根据以上问题进行修复。')
  return lines.join('\n')
}

async function main() {
  await readStdin() // 保持和 hook 协议一致，当前不使用输入字段

  let queue = []
  try { queue = JSON.parse(fs.readFileSync(PENDING_PATH, 'utf8')) } catch (_) { process.exit(0) }
  if (!Array.isArray(queue) || queue.length === 0) process.exit(0)

  const remain = []
  const reports = []

  for (const task of queue) {
    const alive = isProcessAlive(task.pid)
    if (alive) {
      remain.push(task)
      continue
    }
    const findings = parseSarif(task.reportDir)
    if (findings.length > 0) {
      reports.push({
        filePath: task.filePath,
        findings,
      })
    }
  }

  fs.writeFileSync(PENDING_PATH, JSON.stringify(remain, null, 2))

  if (reports.length === 0) {
    process.exit(0)
  }

  const details = reports.map((r, idx) => {
    return `\n=== 文件 ${idx + 1}: ${r.filePath} ===\n${formatFindings(r.findings, r.filePath)}`
  }).join('\n')

  const output = {
    decision: 'block',
    reason: `后台 YASA 扫描完成，发现 ${reports.reduce((n, r) => n + r.findings.length, 0)} 个安全问题`,
    hookSpecificOutput: {
      hookEventName: 'Stop',
      additionalContext: details,
    },
  }

  log(`REPORT: 输出后台扫描漏洞，共 ${reports.length} 个文件`)
  process.stdout.write(JSON.stringify(output))
  process.exit(0)
}

main().catch((e) => {
  log(`FATAL: ${e.message}`)
  process.exit(0)
})
