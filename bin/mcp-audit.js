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
 *     --timeout <ms>    probe timeout in milliseconds (default 5000)
 *
 * With no file arguments, scans the common config locations for Claude Desktop,
 * Cursor, and project-level .mcp.json.
 */
const { resolveTargets, loadAll } = require("../lib/scan");
const { auditAll, sortFindings, scoreFindings } = require("../lib/rules");
const { toSarif } = require("../lib/sarif");
const { probeAll, probeFindings } = require("../lib/probe");

function parseArgs(argv) {
  const flags = new Set();
  const targets = [];
  let timeout = 5000;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--timeout") timeout = parseInt(argv[++i], 10) || 5000;
    else if (a.startsWith("--")) flags.add(a);
    else targets.push(a);
  }
  return { flags, targets, timeout };
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
  const { flags, targets, timeout } = parseArgs(process.argv.slice(2));
  const jsonMode = flags.has("--json");
  const sarifMode = flags.has("--sarif");
  const failHigh = flags.has("--fail-high");
  const probeMode = flags.has("--probe");

  const files = resolveTargets(targets);
  if (files.length === 0) {
    const empty = { files: [], findings: [], probes: [], score: 100, grade: "A" };
    if (sarifMode) console.log(JSON.stringify(toSarif([], empty)));
    else if (jsonMode) console.log(JSON.stringify(empty));
    else console.log("mcp-audit: no MCP config files found (checked .mcp.json, claude_desktop_config.json, ~/.claude, ~/Library, %APPDATA%, ~/.cursor)");
    return 0;
  }

  const parsed = loadAll(files);
  const result = auditAll(parsed);
  const { findings, score, grade } = result;
  const serverCount = parsed.reduce((s, f) => s + f.servers.length, 0);

  let probes = [];
  if (probeMode) {
    probes = await probeAll(parsed, { timeout });
    result.findings = sortFindings([...findings, ...probeFindings(probes)]);
    Object.assign(result, scoreFindings(result.findings));
  }

  if (sarifMode) {
    console.log(JSON.stringify(toSarif(parsed, result)));
  } else if (jsonMode) {
    console.log(JSON.stringify({
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
      console.log(`[${tag}] ${f.server}: ${f.rule} → ${f.match}`);
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
    console.error("mcp-audit: fatal: " + (e && e.stack || e));
    process.exit(2);
  }
);
