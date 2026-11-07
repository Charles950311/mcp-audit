/**
 * Cross-server tool shadowing detection (v0.6).
 *
 * When two configured MCP servers expose the same tool name, an agent may
 * resolve the wrong one — Invariant Labs' cross-server cascade class, present
 * in 72% of the multi-server setups they measured. Detection runs on the
 * tool lists captured by --probe; servers that answered without a visible
 * tool list (auth-required, handshake-only) are counted as blind spots and
 * mark the finding partial instead of being silently ignored.
 */

const SHADOW_RULE = {
  id: "cross-server-tool-shadowing",
  title: "Multiple MCP servers expose the same tool name",
  severity: "high",
  detail:
    "Two or more servers declare the same tool name, so a request for that tool can resolve to the wrong server (cross-server shadowing/cascade). Rename or namespace the tool, or drop one of the servers.",
};

/** Build name -> [{server, file}] over probes that returned a visible tool list. */
function indexToolNames(probes) {
  const byName = new Map();
  let blind = 0;
  for (const p of probes || []) {
    if (Array.isArray(p.tools) && p.tools.length > 0) {
      for (const t of p.tools) {
        if (!t || !t.name) continue;
        if (!byName.has(t.name)) byName.set(t.name, { servers: [], files: new Set() });
        const entry = byName.get(t.name);
        if (!entry.servers.includes(p.server)) entry.servers.push(p.server);
        if (p.file) entry.files.add(p.file);
      }
    } else {
      blind++;
    }
  }
  return { byName, blind };
}

function shadowFindings(probes) {
  const { byName, blind } = indexToolNames(probes);
  const findings = [];
  for (const [name, entry] of byName) {
    if (entry.servers.length < 2) continue;
    const partial =
      blind > 0
        ? ` (partial: ${blind} endpoint(s) probed without a visible tool list)`
        : "";
    findings.push({
      file: [...entry.files][0] || "",
      server: name,
      rule: SHADOW_RULE.id,
      severity: SHADOW_RULE.severity,
      title: SHADOW_RULE.title,
      match: `${entry.servers.length} servers expose '${name}': ${entry.servers.join(" ↔ ")}${partial}`,
      detail: SHADOW_RULE.detail,
    });
  }
  return findings;
}

module.exports = { SHADOW_RULE, indexToolNames, shadowFindings };
