/**
 * SARIF 2.1.0 emitter — makes mcp-audit results uploadable to GitHub code scanning.
 * Level mapping: critical/high → error · medium → warning · low/info → note
 *
 * v0.5: results carry real source line numbers (best-effort lookup of the
 * server definition in its config file) and a stable partialFingerprint so
 * code scanning dedupes findings across runs.
 */

const crypto = require("crypto");
const pkg = require("../package.json");
const { RULES, DUPLICATE_RULE, WEIGHTS } = require("./rules");
const { PROBE_RULES } = require("./probe");
const { locateLine } = require("./scan");

const LEVEL = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };

function ruleDescriptors() {
  return [...RULES, DUPLICATE_RULE, ...Object.values(PROBE_RULES)].map((r) => ({
    id: r.id,
    shortDescription: { text: r.title },
    fullDescription: { text: r.detail },
    defaultConfiguration: { level: LEVEL[r.severity] || "note" },
    properties: { "security-severity": String(WEIGHTS[r.severity] ? { critical: 9.0, high: 7.0, medium: 4.0, low: 2.0, info: 1.0 }[r.severity] : 1.0) },
  }));
}

function fingerprint(finding) {
  const basis = [finding.rule, finding.server, finding.file, finding.match].join("\u0000");
  return crypto.createHash("sha1").update(basis).digest("hex");
}

function toSarif(files, result) {
  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "mcp-audit",
            informationUri: "https://github.com/Charles950311/mcp-audit",
            semanticVersion: pkg.version,
            rules: ruleDescriptors(),
          },
        },
        results: result.findings.map((f) => ({
          ruleId: f.rule,
          level: LEVEL[f.severity] || "note",
          message: { text: `${f.title} (${f.server}): ${f.match}` },
          partialFingerprints: { "mcp-audit/v1": fingerprint(f) },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: (f.file || "").replace(/\\/g, "/") },
                region: { startLine: locateLine(f.file, f.server) },
              },
            },
          ],
        })),
        properties: { score: result.score, grade: result.grade },
      },
    ],
  };
}

module.exports = { toSarif };
