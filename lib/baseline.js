/**
 * Rug-pull baseline (v0.6): hash-pin every probed tool list and diff against
 * it on later runs. A tool that keeps its name but changes its description is
 * the classic rug-pull — trust is earned first, the payload swapped later.
 *
 * Baseline file: .mcp-audit-baseline.json (cwd), committed to the repo.
 *   { version, generatedAt, servers: { [serverKey]: { [toolName]: hash } } }
 * serverKey = sha256(basename(configFile) + NUL + serverName) — basename only,
 * so the same config compares equal across machines and CI runners.
 *
 * Requires --probe (descriptions come from the live tools/list). Create with
 * --update-baseline; every later run diffs and reports:
 *   description changed → high · tool removed → medium · tool added → info.
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const BASELINE_FILE = ".mcp-audit-baseline.json";

const BASELINE_RULES = {
  "tool-description-changed": {
    id: "tool-description-changed",
    title: "MCP tool description changed since baseline (rug-pull pattern)",
    severity: "high",
    detail:
      "A tool kept its name but its description changed since the baseline was recorded — the rug-pull pattern: trust earned first, payload swapped later. Verify the change is intentional, then refresh the baseline with --update-baseline.",
  },
  "tool-removed": {
    id: "tool-removed",
    title: "MCP tool disappeared since baseline",
    severity: "medium",
    detail:
      "A tool that existed when the baseline was recorded is gone from the server's tools/list. Could be routine maintenance — could be churn worth watching. Update the baseline once explained.",
  },
  "tool-added": {
    id: "tool-added",
    title: "New MCP tool since baseline",
    severity: "info",
    detail:
      "The server gained a tool that was not in the baseline. Informational — new tools deserve a look before the agent starts using them. Refresh with --update-baseline once accepted.",
  },
};

const sha16 = (s) => crypto.createHash("sha256").update(s).digest("hex").slice(0, 16);
const serverKey = (file, server) =>
  sha16(path.basename(String(file || "")) + "\u0000" + String(server || ""));
const toolHash = (t) => sha16(String(t && t.name) + "\u0000" + String((t && t.description) || ""));

function buildBaseline(probes) {
  const servers = {};
  for (const p of probes || []) {
    if (!Array.isArray(p.tools) || p.tools.length === 0) continue;
    const key = serverKey(p.file, p.server);
    servers[key] = servers[key] || {};
    for (const t of p.tools) {
      if (t && t.name) servers[key][t.name] = toolHash(t);
    }
  }
  return { version: 1, generatedAt: new Date().toISOString(), servers };
}

function diffBaseline(baseline, probes) {
  const findings = [];
  if (!baseline || !baseline.servers) return findings;
  for (const p of probes || []) {
    if (!Array.isArray(p.tools) || p.tools.length === 0) continue;
    const prev = baseline.servers[serverKey(p.file, p.server)];
    if (!prev) continue; // first sighting of this server — nothing to diff yet
    for (const t of p.tools) {
      if (!t || !t.name) continue;
      const rule = !(t.name in prev)
        ? BASELINE_RULES["tool-added"]
        : prev[t.name] !== toolHash(t)
          ? BASELINE_RULES["tool-description-changed"]
          : null;
      if (rule) {
        findings.push({
          file: p.file,
          server: p.server,
          rule: rule.id,
          severity: rule.severity,
          title: rule.title,
          match: `tool '${t.name}'`,
          detail: rule.detail,
        });
      }
    }
    for (const name of Object.keys(prev)) {
      if (!p.tools.some((t) => t && t.name === name)) {
        const rule = BASELINE_RULES["tool-removed"];
        findings.push({
          file: p.file,
          server: p.server,
          rule: rule.id,
          severity: rule.severity,
          title: rule.title,
          match: `tool '${name}'`,
          detail: rule.detail,
        });
      }
    }
  }
  return findings;
}

function readBaseline(file = BASELINE_FILE) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}

function writeBaseline(baseline, file = BASELINE_FILE) {
  fs.writeFileSync(file, JSON.stringify(baseline, null, 2) + "\n");
}

module.exports = { BASELINE_FILE, BASELINE_RULES, buildBaseline, diffBaseline, readBaseline, writeBaseline, serverKey, toolHash };
