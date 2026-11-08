/**
 * v0.7: supply-chain depth (unpinned-package over npx/bunx/uvx/pnpm dlx/yarn dlx/uv),
 * secrets hardening (format anchors, connection strings, entropy), and the
 * .mcp-audit.json suppress/override config — plus a CLI e2e for --config.
 */
const assert = require("assert");
const { execFile } = require("child_process");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");

const { auditServer, shannon } = require("../lib/rules");
const { readConfig, applyConfig, globToRe } = require("../lib/config");

const hit = (findings, id) => findings.some((f) => f.rule === id);

// ── 供应链：unpinned-package ──

assert.ok(hit(auditServer("a", { command: "npx", args: ["-y", "@scope/server"] }), "unpinned-package"), "npx 未锁应命中");
assert.ok(hit(auditServer("a", { command: "bunx", args: ["server-x"] }), "unpinned-package"), "bunx 未锁应命中");
assert.ok(hit(auditServer("a", { command: "uvx", args: ["mcp-server-fetch"] }), "unpinned-package"), "uvx 未锁应命中（v0.7 语义）");
assert.ok(hit(auditServer("a", { command: "pnpm", args: ["dlx", "server-x"] }), "unpinned-package"), "pnpm dlx 应命中");
assert.ok(hit(auditServer("a", { command: "yarn", args: ["dlx", "server-x"] }), "unpinned-package"), "yarn dlx 应命中");
assert.ok(hit(auditServer("a", { command: "npm", args: ["exec", "server-x"] }), "unpinned-package"), "npm exec 应命中");
assert.ok(hit(auditServer("a", { command: "uv", args: ["run", "--with", "mcp-fetch"] }), "unpinned-package"), "uv --with 未锁应命中");
assert.ok(!hit(auditServer("a", { command: "uvx", args: ["mcp-server-fetch==1.2.0"] }), "unpinned-package"), "uvx ==1.2.0 已锁");
assert.ok(!hit(auditServer("a", { command: "uv", args: ["run", "--with", "mcp-fetch==2.0.0"] }), "unpinned-package"), "--with 已锁");
assert.ok(!hit(auditServer("a", { command: "pnpm", args: ["install"] }), "unpinned-package"), "pnpm install 不是 runner");
assert.ok(!hit(auditServer("a", { command: "node", args: ["server.js"] }), "unpinned-package"), "node 不相关");
assert.ok(hit(auditServer("a", { command: "npx", args: ["-y", "@scope/server@latest"] }), "unpinned-package"), "@latest 算未锁");
assert.ok(!hit(auditServer("a", { command: "npx", args: ["-y", "@scope/server@1.2.3"] }), "unpinned-package"), "@1.2.3 已锁");
assert.ok(!hit(auditServer("a", { command: "uv", args: ["run", "server.py"] }), "unpinned-package"), "uv run 直跑本地脚本不在检测范围（文档化子集）");

// ── secrets：值格式锚点（键名再隐蔽也能抓） ──

const envServer = (env) => auditServer("s", { command: "node", args: [], env });
assert.ok(hit(envServer({ NOTE: "ghp_" + "aB3dE5fG7hJ9kL1mN3oP5qR7sT9uV1wX" }), "plaintext-secret"), "ghp_ 锚点应命中");
assert.ok(hit(envServer({ NOTE: "AKIAIOSFODNN7EXAMPLE" }), "plaintext-secret"), "AKIA 锚点应命中");
assert.ok(hit(envServer({ NOTE: "sk-ant-api03-xxxxxxxxxxxxxxxxxxxx1234567890abcdef" }), "plaintext-secret"), "sk- 锚点应命中");
assert.ok(hit(envServer({ NOTE: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig" }), "plaintext-secret"), "JWT 锚点应命中");
assert.ok(hit(envServer({ NOTE: "-----BEGIN RSA PRIVATE KEY-----" }), "plaintext-secret"), "PEM 锚点应命中");
assert.ok(hit(envServer({ DATABASE_URL: "postgres://admin:s3cret@db.example.com/prod" }), "plaintext-secret"), "连接串内嵌凭据应命中");
assert.ok(!hit(envServer({ DATABASE_URL: "postgres://db.example.com/prod" }), "plaintext-secret"), "无凭据连接串不应命中 plaintext-secret");
assert.ok(!hit(envServer({ NOTE: "${OPENAI_API_KEY}" }), "plaintext-secret"), "${VAR} 引用豁免");
assert.ok(!hit(envServer({ NOTE: "changeme-please" }), "plaintext-secret"), "占位符不应命中");

// ── secrets：熵检测（键名不含 secret 的高熵长值 → medium） ──

assert.ok(shannon("aaaaaaaaaaaaaaaa") < 1, "重复字符熵应接近 0");
assert.ok(shannon("Zx8Qv2NmK4pLw9RtY3bC") > 3.5, "随机串熵应 > 3.5");
assert.ok(hit(envServer({ CLIENT_ID: "Zx8Qv2NmK4pLw9RtY3bC7hJ5sD6fG1aE" }), "entropy-secret"), "高熵长值应命中 entropy-secret");
assert.ok(!hit(envServer({ CLIENT_ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }), "entropy-secret"), "低熵不应命中");
assert.ok(!hit(envServer({ CLIENT_ID: "https://example.com/Zx8Qv2NmK4pLw9RtY3bC" }), "entropy-secret"), "URI 豁免");
assert.ok(!hit(envServer({ CLIENT_ID: "changeme-Zx8Qv2NmK4pLw9RtY3bC" }), "entropy-secret"), "占位符豁免");
assert.ok(!hit(envServer({ OPENAI_API_KEY: "Zx8Qv2NmK4pLw9RtY3bC7hJ5sD6fG1aE" }), "entropy-secret"), "键名已命中 plaintext-secret 的不再双报熵");
const entF = envServer({ CLIENT_ID: "Zx8Qv2NmK4pLw9RtY3bC7hJ5sD6fG1aE" }).find((f) => f.rule === "entropy-secret");
assert.ok(entF && entF.severity === "medium", "entropy-secret 应为 medium");

// ── .mcp-audit.json：豁免与降级 ──

assert.ok(globToRe("**/.claude.json").test("/home/x/.claude.json"), "** glob 应匹配任意前缀");
assert.ok(!globToRe("**/.claude.json").test("/home/x/other.json"), "glob 不应误匹配");
assert.ok(globToRe("legacy-*").test("legacy-foo"), "* glob 应匹配段内");

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-audit-v07-"));
const cfgFile = path.join(tmp, "mcp-audit.json");
fs.writeFileSync(cfgFile, JSON.stringify({
  ignore: [{ rule: "entire-disk-filesystem" }],
  severityOverrides: { "unpinned-package": "low" },
}));
const cfg = readConfig(cfgFile);
const mixed = [
  ...auditServer("fs", { command: "npx", args: ["-y", "pkg", "/"] }),
  ...auditServer("n", { command: "npx", args: ["pkg"] }),
];
const applied = applyConfig(mixed, cfg);
assert.ok(!applied.findings.some((f) => f.rule === "entire-disk-filesystem"), "ignore 规则应抑制 entire-disk");
assert.strictEqual(applied.suppressed, 1);
const unpinnedF = applied.findings.find((f) => f.rule === "unpinned-package");
assert.ok(unpinnedF && unpinnedF.severity === "low", "severityOverride 应降级为 low");
assert.strictEqual(applyConfig(mixed, null).findings.length, mixed.length, "无配置应原样返回");

// 显式 --config 缺失/损坏 → fatal（clean 标记）
assert.throws(() => readConfig(path.join(tmp, "no-such.json")), /cannot load config/);
fs.writeFileSync(path.join(tmp, "broken.json"), "{{{");
assert.throws(() => readConfig(path.join(tmp, "broken.json")), /cannot load config/);

// 自动发现：目录无配置 → null
assert.strictEqual(readConfig(null), null, "cwd 无配置应返回 null");

// ── CLI e2e：--config 生效 + --config 缺失 fatal ──

(async () => {
  const srv = http.createServer((req, res) => {
    let raw = "";
    req.on("data", () => {});
    req.on("end", () => {
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: {} }));
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const BIN = path.join(__dirname, "..", "bin", "mcp-audit.js");
  // 总是 resolve：夹具含 critical 时 CLI 本来就 exit 1，stdout 仍是有效 JSON
  const run = (args, cwd) =>
    new Promise((resolve) => {
      execFile(process.execPath, [BIN, ...args], { encoding: "utf8", cwd, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
        resolve({
          code: err ? (typeof err.code === "number" ? err.code : -1) : 0,
          stdout: stdout || "",
          stderr: stderr || "",
        });
      });
    });

  const work = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-audit-v07e2e-"));
  const fixture = path.join(work, "cfg.json");
  fs.writeFileSync(fixture, JSON.stringify({
    mcpServers: {
      pinner: { command: "npx", args: ["-y", "server-filesystem", "/"] },
      fetcher: { command: "uvx", args: ["mcp-server-fetch"] },
    },
  }));
  const cfgInWork = path.join(work, "audit.json");
  fs.writeFileSync(cfgInWork, JSON.stringify({ ignore: [{ rule: "unpinned-package" }] }));

  const bare = JSON.parse((await run([fixture, "--json"], work)).stdout);
  assert.ok(hit(bare.findings, "unpinned-package") && hit(bare.findings, "entire-disk-filesystem"), "e2e: 无配置应报两项");

  const withCfg = JSON.parse((await run([fixture, "--config", cfgInWork, "--json"], work)).stdout);
  assert.ok(!hit(withCfg.findings, "unpinned-package"), "e2e: ignore 应抑制 unpinned-package");
  assert.ok(hit(withCfg.findings, "entire-disk-filesystem"), "e2e: 未配置的规则保留");
  assert.strictEqual((await run([fixture, "--config", cfgInWork], work)).code, 1, "critical 仍在 → exit 1");

  assert.strictEqual((await run([fixture, "--config", path.join(work, "no-such.json")], work)).code, 2, "--config 指向缺失文件应 exit 2");

  fs.rmSync(work, { recursive: true, force: true });
  fs.rmSync(tmp, { recursive: true, force: true });
  srv.close();
  console.log("ALL V07 TESTS PASSED");
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
