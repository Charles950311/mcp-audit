#!/usr/bin/env node
/**
 * mcp-audit — audit MCP server configs for security risks.
 *
 * Usage:
 *   mcp-audit [options] [files...]
 *     --json            machine-readable output
 *     --sarif           SARIF 2.1.0 output (GitHub code scanning compatible)
 *     --fail-high       exit 1 on any high/critical finding (default: exit 1 on critical only)
 *     --probe           also probe remote (url) servers over HTTP: handshake + anonymous
 *                       tools/list check. Makes real network requests — opt-in only.
 *     --update-baseline record/refresh the rug-pull baseline (needs --probe); every
 *                       later --probe run diffs tool descriptions against it
 *     --config <path>   .mcp-audit.json: ignore rules + severity overrides
 *                       (default: ./.mcp-audit.json when present)
 *     --timeout <ms>    probe timeout in milliseconds (default 5000)
 *     --version         print version and exit
 *     --help            show usage and exit
 *
 * With no file arguments, discovers configs for Claude Desktop/Code, Cursor,
 * VS Code, Windsurf, Gemini CLI, Cline, Roo Code, Continue, Zed, and Codex CLI.
 *
 * Exit codes: 0 clean (or nothing found in discovery mode) · 1 findings at/above
 * threshold · 2 fatal (unknown flag, missing or unparsable explicit file).
 */
const pkg = require("../package.json");
const { resolveTargets, loadAll } = require("../lib/scan");
const { auditAll, sortFindings, scoreFindings } = require("../lib/rules");
const { toSarif } = require("../lib/sarif");
const { probeAll, probeFindings } = require("../lib/probe");
const { poisonFindings } = require("../lib/poison");
const { shadowFindings } = require("../lib/shadow");
const { BASELINE_FILE, buildBaseline, diffBaseline, readBaseline, writeBaseline } = require("../lib/baseline");
const { readConfig, applyConfig } = require("../lib/config");

const KNOWN_FLAGS = new Set([
  "--json", "--sarif", "--fail-high", "--probe", "--update-baseline", "--config", "--timeout", "--help", "--version",
]);

function parseArgs(argv) {
  const flags = new Set();
  const targets = [];
  let timeout = 5000;
  let configPath = null;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--timeout") timeout = parseInt(argv[++i], 10) || 5000;
    else if (a === "--config") configPath = argv[++i] || "";
    else if (a.startsWith("--")) {
      if (!KNOWN_FLAGS.has(a)) {
        const err = new Error("unknown flag '" + a + "' (run with --help for usage)");
        err.clean = true;
        throw err;
      }
      flags.add(a);
    } else targets.push(a);
  }
  return { flags, targets, timeout, configPath };
}

const PROBE_LABELS = {
  "mcp-protected": "protected",
  "auth-required": "auth on initialize",
  "open-tool-listing": "OPEN TOOLS",
  unreachable: "unreachable",
  "not-mcp": "not MCP",
  "unsupported-transport": "legacy SSE (not probed)",
  "mcp-ok": "ok",
};

async function main() {
  const { flags, targets, timeout, configPath } = parseArgs(process.argv.slice(2));
  if (flags.has("--version")) {
    console.log(pkg.version);
    return 0;
  }
  if (flags.has("--help")) {
    console.log(`mcp-audit ${pkg.version} — audit MCP server configs for security risks

Usage: mcp-audit [options] [files...]

  --json            machine-readable JSON output
  --sarif           SARIF 2.1.0 output (GitHub code scanning compatible)
  --fail-high       exit 1 on any high/critical finding (default: critical only)
  --probe           live-probe remote (url) servers: handshake + anonymous tools/list
  --update-baseline record/refresh the rug-pull baseline (needs --probe)
  --config <path>   .mcp-audit.json: ignore rules + severity overrides
  --timeout <ms>    probe timeout in milliseconds (default 5000)
  --version         print version and exit
  --help            show this help

With no files, discovers configs for Claude Desktop/Code, Cursor, VS Code,
Windsurf, Gemini CLI, Cline, Roo Code, Continue, Zed, and Codex CLI.

Exit codes: 0 clean (or nothing found in discovery mode) · 1 findings at/above
threshold · 2 fatal (unknown flag, missing or unparsable explicit file).`);
    return 0;
  }
  const jsonMode = flags.has("--json");
  const sarifMode = flags.has("--sarif");
  const failHigh = flags.has("--fail-high");
  const probeMode = flags.has("--probe");

  const files = resolveTargets(targets);
  if (files.length === 0) {
    const empty = { files: [], findings: [], probes: [], score: 100, grade: "A" };
    if (sarifMode) console.log(JSON.stringify(toSarif([], empty)));
    else if (jsonMode) console.log(JSON.stringify(empty));
    else console.log("mcp-audit: no MCP config files found (checked Claude Desktop/Code, Cursor, VS Code, Windsurf, Gemini CLI, Cline, Roo Code, Continue, Zed, Codex CLI, and project .mcp.json)");
    return 0;
  }

  const parsed = loadAll(files, targets.length > 0);
  const result = auditAll(parsed);
  const { findings, score, grade } = result;
  const serverCount = parsed.reduce((s, f) => s + f.servers.length, 0);

  let probes = [];
  if (probeMode) {
    probes = await probeAll(parsed, { timeout });
    result.findings = sortFindings([
      ...findings,
      ...probeFindings(probes),
      ...poisonFindings(probes),
      ...shadowFindings(probes),
    ]);
    Object.assign(result, scoreFindings(result.findings));
  }

  // Rug-pull baseline (v0.6): --update-baseline records the tool lists; every
  // later --probe run diffs descriptions against it (change → high).
  const updateBaseline = flags.has("--update-baseline");
  if (updateBaseline && !probeMode) {
    const err = new Error("--update-baseline needs --probe (tool lists come from the live tools/list)");
    err.clean = true;
    throw err;
  }
  if (probeMode && updateBaseline) {
    writeBaseline(buildBaseline(probes));
    console.error("mcp-audit: baseline written to " + BASELINE_FILE);
  } else if (probeMode) {
    const baseline = readBaseline();
    if (baseline) {
      result.findings = sortFindings([...result.findings, ...diffBaseline(baseline, probes)]);
      Object.assign(result, scoreFindings(result.findings));
    } else if (probes.some((p) => Array.isArray(p.tools) && p.tools.length > 0)) {
      console.error(`mcp-audit: no baseline at ${BASELINE_FILE} — run once with --update-baseline to enable rug-pull detection`);
    }
  }

  // .mcp-audit.json（v0.7）：豁免与降级——一条误报不再让 CI 永久红
  const cfg = readConfig(configPath || null);
  if (cfg) {
    const applied = applyConfig(result.findings, cfg);
    result.findings = sortFindings(applied.findings);
    if (applied.suppressed) console.error(`mcp-audit: config ${cfg.source}: ${applied.suppressed} finding(s) suppressed by ignore rules`);
    if (applied.overridden) console.error(`mcp-audit: config ${cfg.source}: ${applied.overridden} severity override(s) applied`);
    Object.assign(result, scoreFindings(result.findings));
  }

  if (sarifMode) {
    console.log(JSON.stringify(toSarif(parsed, result)));
  } else if (jsonMode) {
    console.log(JSON.stringify({
      outputVersion: 2,
      files: parsed.map((f) => f.file),
      serverCount,
      findings: result.findings,
      probes,
      score: result.score,
      grade: result.grade,
    }, null, 2));
  } else {
    console.log(`\nmcp-audit — ${parsed.length} file(s), ${serverCount} server(s)\n`);
    if (result.findings.length === 0) {
      console.log("No issues found. Nice.\n");
    }
    for (const f of result.findings) {
      const tag = f.severity.toUpperCase().padEnd(8);
      const where = f.file ? f.file + " · " : "";
      console.log(`[${tag}] ${where}${f.server}: ${f.rule} → ${f.match}`);
      console.log(`           ${f.detail}\n`);
    }
    if (probeMode) {
      console.log(`Remote probes (${probes.length} endpoint(s), timeout ${timeout}ms):`);
      if (probes.length === 0) console.log("  (no remote url servers in the scanned configs)");
      for (const p of probes) {
        const label = (PROBE_LABELS[p.status] || p.status).padEnd(20);
        const note = p.status === "open-tool-listing"
          ? `${p.toolsCount} tools listed anonymously`
          : p.error || "tools/list requires auth";
        console.log(`  ${label} ${p.server} ${p.url} (${p.latencyMs} ms, ${p.transport || "?"}) · ${note}`);
      }
      console.log("");
    }
    console.log(`Score: ${result.score}/100 (${result.grade})`);
  }

  const allFindings = result.findings;
  const hasCritical = allFindings.some((f) => f.severity === "critical");
  const hasHigh = allFindings.some((f) => f.severity === "high");
  return hasCritical || (failHigh && hasHigh) ? 1 : 0;
}

main().then(
  (code) => process.exit(code),
  (e) => {
    console.error("mcp-audit: fatal: " + (e && e.clean ? e.message : (e && e.stack) || e));
    process.exit(2);
  }
);
