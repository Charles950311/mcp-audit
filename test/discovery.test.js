const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { extractServers, parseJsonc, stripJsonc, locateLine, loadFile } = require("../lib/scan");
const { parseToml } = require("../lib/toml");

// ── extractServers 形状归一 ──

assert.strictEqual(
  extractServers({ mcpServers: { a: { command: "x" } } }).a.command,
  "x",
  "mcpServers"
);
assert.strictEqual(
  extractServers({ mcp_servers: { a: { command: "y" } } }).a.command,
  "y",
  "mcp_servers (snake_case)"
);
assert.ok(extractServers({ servers: { a: {} } }).a, "servers");
assert.strictEqual(
  extractServers({ mcp: { servers: { vscode: { command: "node" } } } }).vscode.command,
  "node",
  "VS Code settings.json: mcp.servers"
);
assert.strictEqual(
  extractServers({ context_servers: { zed: { command: "zed-x" } } }).zed.command,
  "zed-x",
  "Zed: context_servers"
);
assert.deepStrictEqual(extractServers({}), {});
assert.deepStrictEqual(extractServers(null), {});
assert.deepStrictEqual(extractServers({ mcpServers: [] }), {}, "数组形状应拒绝");

// ── JSONC 宽容解析 ──

const jsonc = `{
  // line comment
  "mcp": {
    /* block
       comment */
    "servers": {
      "vscode-x": { "command": "node", "args": ["a", "b"], }, // trailing comma
    },
  },
}`;
const parsed = parseJsonc(jsonc);
assert.strictEqual(parsed.mcp.servers["vscode-x"].command, "node", "JSONC 注释/尾逗号应解析成功");
assert.strictEqual(
  parseJsonc('{"note": "keep http:// in string // not comment"}').note,
  "keep http:// in string // not comment",
  "字符串内的 // 不应被剥离"
);
assert.strictEqual(
  parseJsonc('{"t": "value with , trailing} inside"}').t,
  "value with , trailing} inside",
  "字符串内的 ,} 不应被当作尾逗号删除"
);
assert.throws(() => parseJsonc("{ definitely not json }"), "彻底非法的 JSON 仍应抛错");
assert.strictEqual(stripJsonc('"a/*b*/c"'), '"a/*b*/c"', "stripJsonc 保留字符串内容");

// ── TOML 解析 ──

const tomlText = `
# full comment line
[mcp_servers.fetch]
command = "uvx"
args = [
  "mcp-server-fetch",   # inline comment
  "--verbose",
]

[mcp_servers.docs]
command = 'npx'   # literal string
args = ["-y", "@scope/docs@0.6.2"]

[mcp_servers.docs.env]
API_KEY = "abc123456"
BASE_URL = "https://example.com"

[mcp_servers.inline]
command = "node"
env = { TOKEN = "tok1234567", DEBUG = true }
retries = 3
flag = true
rate = 1.5
`;
const t = parseToml(tomlText);
assert.strictEqual(t.mcp_servers.fetch.command, "uvx");
assert.deepStrictEqual(t.mcp_servers.fetch.args, ["mcp-server-fetch", "--verbose"], "多行数组");
assert.strictEqual(t.mcp_servers.docs.command, "npx", "字面量字符串");
assert.strictEqual(t.mcp_servers.docs.env.API_KEY, "abc123456", "env 子表");
assert.strictEqual(t.mcp_servers.inline.env.TOKEN, "tok1234567", "内联表 env");
assert.strictEqual(t.mcp_servers.inline.env.DEBUG, true);
assert.strictEqual(t.mcp_servers.inline.retries, 3);
assert.strictEqual(t.mcp_servers.inline.flag, true);
assert.strictEqual(t.mcp_servers.inline.rate, 1.5);

// 精确锚点：与 Codex 真实形状一致
const codex = parseToml(`[mcp_servers.fetch]
command = "uvx"
args = ["mcp-server-fetch"]

[mcp_servers.shell]
command = "node"
args = ["server.js", "--allow"]
`);
assert.deepStrictEqual(Object.keys(codex.mcp_servers).sort(), ["fetch", "shell"]);

assert.throws(() => parseToml("[unterminated"), "坏 header 应抛错");
assert.throws(() => parseToml("just a line"), "无 = 的裸行应抛错");
assert.throws(() => parseToml('a = ["unterminated'), "未闭合数组应抛错");

// ── loadFile 对 .toml / .jsonc 的分发 ──

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-audit-"));
const tomlFile = path.join(tmp, "config.toml");
fs.writeFileSync(tomlFile, codexText());
function codexText() {
  return `[mcp_servers.fetch]
command = "uvx"
args = ["mcp-server-fetch"]
`;
}
const loadedToml = loadFile(tomlFile);
assert.strictEqual(loadedToml.error, null);
assert.strictEqual(loadedToml.servers.length, 1);
assert.strictEqual(loadedToml.servers[0].name, "fetch");

const jsoncFile = path.join(tmp, "settings.json");
fs.writeFileSync(jsoncFile, "{\n  // comment\n  \"mcp\": { \"servers\": { \"vs\": { \"command\": \"code\" } } },\n}");
const loadedJsonc = loadFile(jsoncFile);
assert.strictEqual(loadedJsonc.servers[0].name, "vs");

const badFile = path.join(tmp, "broken.json");
fs.writeFileSync(badFile, "{{{");
assert.ok(loadFile(badFile).error, "坏文件应带 error");

// ── locateLine ──

const jsonLike = path.join(tmp, "mcp.json");
fs.writeFileSync(jsonLike, JSON.stringify({ mcpServers: { filler1: {}, everything: { command: "npx" }, filler2: {} } }, null, 2));
// pretty-printed: "everything" 在第 4 行
const ln = locateLine(jsonLike, "everything");
assert.strictEqual(ln, 4, "JSON key 应定位到真实行，实际 " + ln);
assert.strictEqual(locateLine(jsonLike, "nonexistent"), 1, "找不到应回退第 1 行");
assert.strictEqual(locateLine(path.join(tmp, "no-such-file.json"), "x"), 1, "文件不存在应回退第 1 行");

const tomlLines = path.join(tmp, "again.toml");
fs.writeFileSync(tomlLines, "[other]\nkey = 1\n\n[mcp_servers.shell]\ncommand = 'node'\n");
assert.strictEqual(locateLine(tomlLines, "shell"), 4, "TOML header 应定位到真实行，实际 " + locateLine(tomlLines, "shell"));

fs.rmSync(tmp, { recursive: true, force: true });
console.log("ALL DISCOVERY TESTS PASSED");
