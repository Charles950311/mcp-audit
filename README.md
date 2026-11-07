# mcp-audit

[![CI](https://github.com/Charles950311/mcp-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/Charles950311/mcp-audit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/Charles950311/mcp-audit/pulls)

[中文文档](README.zh-CN.md)

A **zero-dependency** CLI that audits Model Context Protocol (MCP) server configurations for security risks. MCP became the de-facto standard for connecting tools to AI agents, but security practice hasn't kept up — mcp-audit turns the most common failure modes into one command: **static config auditing, plus opt-in live probing of remote endpoints**.

- 🔍 **Discovers configs from 10+ MCP clients** (Claude Desktop/Code, Cursor, VS Code, Windsurf, Gemini CLI, Cline, Roo Code, Continue, Zed, Codex CLI)
- 🧪 **Live probing** (`--probe`): MCP handshake + anonymous `tools/list` check over streamable HTTP **and** legacy SSE
- 🧬 **Tool poisoning & shadowing** (v0.6, with `--probe`): instruction-injection / invisible-Unicode / collector-URL heuristics over tool descriptions, cross-server tool-name shadowing, and a hash-pinned rug-pull baseline (`--update-baseline`)
- 📤 **SARIF 2.1.0** output with stable fingerprints and real source line numbers — uploads straight to GitHub code scanning
- 🧰 **GitHub Action** included (composite, SARIF upload built in)
- 📦 **Zero dependencies**, Node ≥ 18, runs offline

## Install & run

**No install (recommended):**

```bash
npx github:Charles950311/mcp-audit                     # latest main
npx github:Charles950311/mcp-audit#v0.5.0              # pinned to a tag
npx github:Charles950311/mcp-audit --probe cfg.json    # full flag passthrough
```

**Local (after cloning):**

```bash
node bin/mcp-audit.js                    # discover configs across all supported clients
node bin/mcp-audit.js my-config.json     # explicit file(s)
node bin/mcp-audit.js --json cfg.json    # machine-readable
node bin/mcp-audit.js --sarif cfg.json   # SARIF 2.1.0 (GitHub code scanning)
node bin/mcp-audit.js --fail-high        # exit 1 on high findings too
node bin/mcp-audit.js --probe cfg.json   # live-probe remote (url) servers
node bin/mcp-audit.js --probe --update-baseline cfg.json   # record tool hashes; later runs flag rug-pulls
node bin/mcp-audit.js --version
node bin/mcp-audit.js --help                     # usage + exit codes
```

Exit codes: `0` clean (or nothing found in discovery mode) · `1` findings at threshold (`critical`, or `high` with `--fail-high`) · `2` fatal (unknown flag, missing or unparsable explicit file) — drop it straight into CI.

## Supported clients (auto-discovery)

With no file arguments, mcp-audit checks these locations (existing files only):

| Client | Location |
|---|---|
| Claude Desktop / Claude Code | `~/.claude.json`, `claude_desktop_config.json` (Windows/macOS/`~/.claude`), project `.mcp.json` |
| Cursor | `~/.cursor/mcp.json` |
| VS Code | user `settings.json` (`mcp.servers`, JSONC), workspace `.vscode/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Gemini CLI | `~/.gemini/settings.json` |
| Cline | VS Code `globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` |
| Roo Code | VS Code `globalStorage/RooVeterinaryInc.roo-cline/settings/mcp_settings.json` |
| Continue | `~/.continue/config.json` |
| Zed | `settings.json` (`context_servers`, JSONC) |
| Codex CLI | `~/.codex/config.toml` (`[mcp_servers.*]`, TOML) |

Accepted server-map shapes: `mcpServers` · `mcp_servers` · `servers` · `mcp.servers` · `context_servers`.

## Remote probing (v0.5, `--probe`, off by default)

For every server entry with an http(s) `url`, mcp-audit walks the transport ladder and tags results with `transport`:

**① streamable HTTP** — `POST initialize` (JSON-RPC, `Accept: application/json, text/event-stream`):
- 401/403 → **auth-required** (good posture, no finding)
- 404/405 → fall through to ②
- connect fail / timeout / 5xx → **unreachable** (low)
- 2xx but not JSON-RPC → **not-mcp** (low)

**② legacy SSE** (2024-11-05): `GET` the url for the event stream → read the `endpoint` event → POST JSON-RPC to that endpoint, read responses off the stream. Same status/finding mapping; stream ended before the endpoint event → not-mcp; never sent → timeout → unreachable.

**After handshake** (both transports): send `notifications/initialized`, then `POST tools/list`:
- 200 with tools → **open-tool-listing** (medium): tools enumerable anonymously
- 401/403 → **mcp-protected** (good posture, no finding)
- both transports rejected → unsupported-transport (reported, not scored)

Probing **never sends credentials** — it observes exactly what an anonymous client can reach. Requests are sequential, single-shot, timeout-configurable. Probe findings use the same shape as static findings, so scoring, SARIF and exit codes work unchanged.

## Tool poisoning, shadowing & rug-pull (v0.6, with `--probe`)

Everything below runs on the tool lists captured by `--probe` (name + description per tool, descriptions capped at 4 KB, 50 tools per server) and reuses the same finding/scoring/SARIF pipeline:

| Rule | Severity | Meaning |
|---|---|---|
| tool-description-injection | high | description reads like instructions to the agent ("ignore previous instructions", secret-grabbing directives, …) |
| tool-description-unicode | high | zero-width / bidi / Unicode-tag characters hiding text from the human approving the tool |
| tool-description-exfil-url | high | description embeds a URL on a known collector host (webhook.site, pastebins, bot APIs, …) |
| tool-description-external-url | medium | description embeds a URL on a different host — often a legit docs link; judged by a human |
| tool-description-imperative | medium | multiple ALL-CAPS directive markers — the usual shell around injected text |
| cross-server-tool-shadowing | high | two or more servers expose the same tool name (the cross-server cascade class; Invariant measured 72% of multi-server setups exposed) |
| tool-description-changed | high | rug-pull: tool kept its name but its description changed since the baseline |
| tool-removed | medium | tool disappeared since the baseline |
| tool-added | info | new tool since the baseline |

**Rug-pull baseline**: run once with `--update-baseline` to write `.mcp-audit-baseline.json` (hash-pinned tool lists; commit it to the repo). Every later `--probe` run diffs against it. Server keys use config filename + server name, so a baseline compares equal across machines and CI runners.

Description heuristics run only on model-facing tool descriptions (never on your config text), and each check fires at most once per tool per category.

## Static rules (v0.5)

| Rule | Severity | Meaning |
|---|---|---|
| entire-disk-filesystem | critical | filesystem server root set to `/`, `C:\`, `~`, etc. |
| pipe-to-shell | critical | `curl … \| sh`-style installs: today it runs whatever the endpoint returns |
| plaintext-secret | high | credential-looking values in `env` **or `headers`** (raw `${VAR}` references exempt) |
| insecure-remote-url | high | remote server over plain `http://` (loopback exempt) |
| elevated-privileges | high | `sudo`/`doas` |
| unpinned-npx-package | medium | npx resolves unpinned packages at every launch |
| wildcard-filesystem-arg | medium | glob in filesystem args |
| duplicate-definition | info | same server defined in multiple files |

Probe rules: `open-tool-listing` (medium), `remote-unreachable` (low), `remote-not-mcp` (low) — plus the poisoning/shadowing/baseline rules above.

Scoring: 100 minus deductions (critical −40 / high −20 / medium −10 / low −5); A ≥ 90 > B ≥ 75 > C ≥ 60 > D ≥ 40 > F.

## GitHub Action

`action.yml` is a composite action: point any repo at it (`examples/user-workflow.yml` has a ready template) to run the audit and upload SARIF to code scanning. Inputs: `files`, `fail-high`, `probe`, `timeout`, `upload-sarif`. `npm test` runs in this repo's CI (`.github/workflows/ci.yml`).

## Tests

```bash
npm test   # rule anchors + fixture scoring (clean→A/100, dirty→F/≤40) + SARIF + probe engine + discovery/parsers + CLI exit codes + poisoning/shadowing/baseline (incl. CLI e2e)
```

All offline: probe behavior is covered by a local Node `http` server (streamable 8 scenarios + legacy SSE 7 scenarios), parsers are pure-function unit tests.

## Roadmap

- [x] v0.2 — SARIF 2.1.0 + composite GitHub Action + CI
- [x] v0.3 — remote probing (streamable HTTP) + `headers` secret check
- [x] v0.4 — legacy SSE (2024-11-05) probing
- [x] v0.5 — multi-client discovery, SARIF fingerprints & line numbers, JSONC/TOML parsing, English docs
- [x] v0.5.1 — SARIF uploads on findings-gate failure, fatal on bad explicit paths, `--help` & strict flags
- [x] v0.6 — tool-description poisoning, cross-server shadowing, rug-pull baseline (`--update-baseline`)
- [ ] supply-chain depth (uvx/bunx/pnpm-dlx unpinned, secrets entropy) + `.mcp-audit.json` — ignores/suppressions, severity overrides
- [ ] npm publish (name reserved: `mcp-config-scan`) with provenance
- [ ] JetBrains client support (XML configs)

## Honest limitations

- Static heuristics can miss or mis-fire; issue reports welcome.
- Probing does not judge what a tool does at runtime — whether a tool is dangerous needs human review.
- The rug-pull baseline is only as good as its origin: record it from a trusted state, and a poisoned first sighting becomes the norm.
- `--probe` makes real network requests; only point it at endpoints you have the right to test.
- JetBrains clients use XML configs — not yet supported.
