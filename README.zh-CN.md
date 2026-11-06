# mcp-audit

[![CI](https://github.com/Charles950311/mcp-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/Charles950311/mcp-audit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen)

[English](README.md)

对 MCP（Model Context Protocol）服务器配置做安全审计的**零依赖** CLI。2026 年 MCP 已成为 AI Agent 接工具的事实标准，但安全实践跟不上扩张——本工具把"配置里最容易翻车的问题"变成一条命令：**静态审计配置文件，还可选地对远程端点做实弹探测**。

- 🔍 **自动发现 10+ 个 MCP 客户端的配置**（Claude Desktop/Code、Cursor、VS Code、Windsurf、Gemini CLI、Cline、Roo Code、Continue、Zed、Codex CLI）
- 🧪 **实弹探测**（`--probe`）：MCP 握手 + 匿名 `tools/list` 检查，支持 streamable HTTP **和** legacy SSE 双传输
- 📤 **SARIF 2.1.0** 输出（带稳定指纹与真实源码行号），可直接上传 GitHub code scanning
- 🧰 内置 **GitHub Action**（composite，含 SARIF 上传）
- 📦 **零依赖**，Node ≥ 18，可完全离线运行

> 分发方式：当前以 **GitHub 直装**为主；npm registry 发布（包名 `mcp-config-scan` 已检重可用）暂缓，有 npm 账号后执行一次 `npm publish` 即可补齐。

## 使用

**免安装（推荐）：**

```bash
npx github:Charles950311/mcp-audit                     # 最新 main
npx github:Charles950311/mcp-audit#v0.5.0              # 锁定到 tag
npx github:Charles950311/mcp-audit --probe cfg.json    # 全参数透传
```

**本地运行（克隆本仓库后）：**

```bash
node bin/mcp-audit.js                    # 跨全部支持的客户端自动发现配置
node bin/mcp-audit.js my-config.json     # 指定文件
node bin/mcp-audit.js --json cfg.json    # CI 用 JSON 输出
node bin/mcp-audit.js --sarif cfg.json   # SARIF 2.1.0（GitHub code scanning 可直接上传）
node bin/mcp-audit.js --fail-high cfg.json  # high 级问题也使退出码为 1
node bin/mcp-audit.js --probe cfg.json   # 实弹探测：MCP 握手 + 匿名 tools/list 检查
node bin/mcp-audit.js --probe --timeout 3000 cfg.json
node bin/mcp-audit.js --version
```

退出码：存在 critical（或 `--fail-high` 时存在 high）→ 1，否则 0，可直接进 GitHub Actions。

## 支持的客户端（自动发现）

无文件参数时，mcp-audit 检查以下位置（只读已存在的文件）：

| 客户端 | 位置 |
|---|---|
| Claude Desktop / Claude Code | `~/.claude.json`、`claude_desktop_config.json`（Windows/macOS/`~/.claude`）、项目级 `.mcp.json` |
| Cursor | `~/.cursor/mcp.json` |
| VS Code | 用户 `settings.json`（`mcp.servers`，JSONC）、工作区 `.vscode/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Gemini CLI | `~/.gemini/settings.json` |
| Cline | VS Code `globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` |
| Roo Code | VS Code `globalStorage/RooVeterinaryInc.roo-cline/settings/mcp_settings.json` |
| Continue | `~/.continue/config.json` |
| Zed | `settings.json`（`context_servers`，JSONC） |
| Codex CLI | `~/.codex/config.toml`（`[mcp_servers.*]`，TOML） |

接受的 server-map 形状：`mcpServers` · `mcp_servers` · `servers` · `mcp.servers` · `context_servers`。

## 远程探测（`--probe`，默认关闭）

对配置里每个 `url` 型 server 按传输阶梯探测，结果带 `transport` 标注：

**① streamable HTTP**（现行标准）：`POST initialize`（JSON-RPC，带 `Accept: application/json, text/event-stream`）
- 401/403 → **auth-required**：端点要求鉴权，好姿态，不扣分
- 404/405 → 落入 ② 继续尝试
- 连接失败/超时/5xx → **unreachable**（low）
- 200 但非 JSON-RPC → **not-mcp**（low）

**② legacy SSE**（2024-11-05 协议）：`GET` url 打开事件流 → 读 `endpoint` 事件拿消息端点 → 向其 POST JSON-RPC、在流上读响应。同样的状态/发现映射；流在 endpoint 事件前结束 → not-mcp，永不发 → 超时 unreachable。

**握手成功后**（两传输相同）：发送 `notifications/initialized`，再 `POST tools/list`
- 200 且列出工具 → **open-tool-listing**（medium）：匿名可枚举工具
- 401/403 → **mcp-protected**：好姿态，不扣分
- 两种传输都被拒绝 → unsupported-transport（如实报告，不判）

探测**从不携带任何凭据**——观察的正是匿名客户端能走到哪一步；顺序执行、单请求、可设超时，对目标端点足够轻。探测发现与静态规则同构，自动并入评分、SARIF 与退出码。

## 静态规则（v0.5）

| 规则 | 级别 | 说明 |
|---|---|---|
| entire-disk-filesystem | critical | filesystem 服务的 root 参数给了 `/`、`C:\`、`~` 等整盘路径 |
| pipe-to-shell | critical | `curl … \| sh` 式安装：今天执行的是端点当前返回的内容 |
| plaintext-secret | high | env / headers 中疑似凭据明文落盘（`${VAR}` 引用则豁免） |
| insecure-remote-url | high | 远程服务走明文 http://（127.0.0.1/localhost 豁免） |
| elevated-privileges | high | sudo/doas 提权运行 |
| unpinned-npx-package | medium | npx 未锁版本，每次启动解析到最新版 |
| wildcard-filesystem-arg | medium | 路径参数含通配符 |
| duplicate-definition | info | 同一 server 在多个配置文件重复定义 |

探测规则：`open-tool-listing`（medium）、`remote-unreachable`（low）、`remote-not-mcp`（low）。

评分：100 起扣（critical −40 / high −20 / medium −10 / low −5），A ≥ 90 > B ≥ 75 > C ≥ 60 > D ≥ 40 > F。

## GitHub Action

`action.yml` 是 composite action：克隆本仓库后即可在其他仓库中使用（`examples/user-workflow.yml` 有用户侧模板），自动运行审计并把 SARIF 上传到 code scanning。输入项：`files`、`fail-high`、`probe`、`timeout`、`upload-sarif`。`npm test` 由本仓库 CI（`.github/workflows/ci.yml`）执行。

## 测试

```bash
npm test   # 规则锚点 + fixtures 评分（clean→A/100，dirty→F/≤40）+ SARIF + 探测引擎 + 发现/解析器
```

探测测试全部离线：SSE 帧/流解析为纯函数单测，传输行为用 Node 内置 `http` 起本地服务器覆盖（streamable 8 场景 + legacy SSE 7 场景）。

## 路线图

- [x] v0.2 — SARIF 2.1.0 输出 + composite GitHub Action + 仓库 CI
- [x] v0.3 — 远程探测（streamable HTTP）+ `headers` 密钥检查
- [x] v0.4 — legacy SSE（2024-11-05）传输探测
- [x] v0.5 — 多客户端发现、SARIF 指纹与行号、JSONC/TOML 解析、英文文档
- [ ] 工具描述投毒 / 遮蔽启发式；rug-pull 基线（跨运行哈希工具清单）
- [ ] `.mcp-audit.json` — ignore/抑制、severity 覆盖
- [ ] npm 发布（包名 `mcp-config-scan` 已检重，带 provenance）
- [ ] JetBrains 客户端支持（XML 配置）

## 边界（诚实声明）

- 静态启发式可能漏报/误报，欢迎 issue
- 探测不验证 server 运行时语义（工具是否危险需人工判断）
- `--probe` 会对目标端点发真实网络请求，请只对自己有权的端点使用
- JetBrains 客户端为 XML 配置，暂未支持
