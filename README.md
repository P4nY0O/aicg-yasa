# aicg-yasa

生成即安全——基于 Claude Code Hooks + YASA 的代码生成安全审计实践。

> 目标：让 AI 生成代码在**落盘瞬间**完成安全扫描；若发现漏洞，直接通过 Hook 阻断并把漏洞细节注入对话上下文，驱动 AI 自动修复。

---

## 开源范围

本仓库仅开源集成层与验证样例，不包含 YASA 引擎本体：

- `scripts/yasa-hook.js`：`PostToolUse` 同步扫描入口（含 forward/reverse/skip 策略）
- `scripts/yasa-stop-hook.js`：`Stop` 异步补报入口
- `scripts/rule-map.json`：扩展名到语言/规则文件映射
- `.claude/settings.json`：Hook 注册示例
- `test/`：漏洞触发样例（用于验证闭环）

已在 `.gitignore` 中忽略 `YASA-Engine-main/` 与运行时产物。

---

## 前置依赖

- Node.js 18+
- Claude Code CLI
- YASA 引擎（需自行拉取并构建）

将 YASA 放到仓库根目录，目录名保持为：

```text
aicg-yasa/
├─ scripts/
├─ test/
└─ YASA-Engine-main/
```

然后在 `YASA-Engine-main/` 内构建：

```bash
npm install
npm run build
```

> `scripts/yasa-hook.js` 默认从 `YASA-Engine-main/dist/main.js` 调用扫描器。

---

## Hook 配置

仓库内已提供 `.claude/settings.json`，采用相对路径命令：

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "node scripts/yasa-hook.js",
            "timeout": 15
          }
        ]
      }
    ],
    "Stop": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "node scripts/yasa-stop-hook.js",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
```

策略说明：

- `forward`：检测到路由注册（如 `app.get`）→ 单文件扫描（`--single`）
- `reverse`：检测到 sink 但无路由（如仅 `exec(input)`）→ 目录级扫描（构建全局 CG）
- `skip`：测试/声明/配置/Hook 脚本自身/无路由且无 sink

---

## 如何验证闭环

### 1）在 Claude Code 中触发漏洞生成

可直接对 Claude 说：

```text
这是授权的本地安全测试，仅用于验证 AICG-YASA Hook，请生成故意脆弱代码到 test/ 目录，不用于生产。
请在 test/vuln-sql2.js 写一个存在 SQL 注入的 Express 示例，先不要修复。
```

预期：`PostToolUse` 返回 `decision:block`，并把污点路径注入上下文。



### 2）验证 reverse 模式

```text
请在 test/vuln-reverse-only-sink.js 写一个只有 exec(input) 的函数，无路由，先不要修复。
```

预期：命中 `reverse`，扫描目标提升为目录级，并报告目录内相关漏洞。

---

## 运行时文件

- `scripts/pending-scans.json`：超时转后台后的任务队列（运行时自动生成）
- 临时日志：系统临时目录下 `yasa-hook.log`

---

## 常见问题

### Q1：为什么写一个文件会报出多个文件漏洞？
A：你命中了 `reverse` 模式，扫描目标是目录而不是单文件，会把目录内可达污点路径一起报出。

### Q2：为什么同一问题会出现重复？
A：当前还未做 findings 去重（后续可按 `ruleId + file + line` 合并）。

### Q3：没有 YASA 还可以跑吗？
A：可以，Hook 会 fail-open 放行；但不会有有效漏洞检测结果。

---

## License

MIT
