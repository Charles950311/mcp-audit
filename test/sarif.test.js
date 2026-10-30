const assert = require("assert");
const path = require("path");
const { loadFile } = require("../lib/scan");
const { auditAll } = require("../lib/rules");
const { toSarif } = require("../lib/sarif");

const dirty = auditAll([loadFile(path.join(__dirname, "..", "fixtures", "dirty.json"))]);
const sarif = toSarif([dirty], dirty);

// ── SARIF 2.1.0 结构 ──
assert.strictEqual(sarif.version, "2.1.0");
assert.strictEqual(sarif.runs.length, 1);
const run = sarif.runs[0];
assert.strictEqual(run.tool.driver.name, "mcp-audit");
assert.ok(Array.isArray(run.tool.driver.rules) && run.tool.driver.rules.length >= 8, "规则清单应含全部规则");

// results 与 findings 一一对应，且 file 进入 artifactLocation
assert.strictEqual(run.results.length, dirty.findings.length);
for (const res of run.results) {
  assert.ok(["error", "warning", "note"].includes(res.level), "level 必须是 SARIF 三值之一: " + res.level);
  assert.ok(res.locations[0].physicalLocation.artifactLocation.uri.length > 0, "结果应带文件路径");
}

// 级别映射：critical/high → error，medium → warning
const critical = dirty.findings.find((f) => f.severity === "critical");
const criticalResult = run.results.find((r) => r.ruleId === critical.rule && r.level === "error");
assert.ok(criticalResult, "critical 应映射为 error");
const medium = dirty.findings.find((f) => f.severity === "medium");
const mediumResult = run.results.find((r) => r.ruleId === medium.rule);
assert.ok(mediumResult.level === "warning", "medium 应映射为 warning");

// 干净夹具：0 results，规则清单仍完整
const clean = auditAll([loadFile(path.join(__dirname, "..", "fixtures", "clean.json"))]);
const cleanSarif = toSarif([clean], clean);
assert.strictEqual(cleanSarif.runs[0].results.length, 0);
assert.ok(cleanSarif.runs[0].tool.driver.rules.length >= 8);

// Windows 路径分隔符应被规范化
const winSarif = toSarif([{ file: "C:\\repo\\.mcp.json", servers: [] }], { findings: [], score: 100, grade: "A" });
assert.ok(!winSarif.runs[0].results.length, "空结果无 results");
assert.ok(toSarif([{ file: "C:\\x.json", servers: [] }], {
  findings: [{ file: "C:\\x.json", server: "s", rule: "plaintext-secret", severity: "high", title: "t", match: "m", detail: "d" }],
  score: 80, grade: "B",
}).runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri === "C:/x.json", "反斜杠应转为 /");

console.log("ALL SARIF TESTS PASSED");
