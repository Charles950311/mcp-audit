/**
 * CLI-level behavior: exit codes, flag validation, fatal paths.
 * Runs the real bin via child process — these are the contracts CI relies on.
 */
const assert = require("assert");
const { execFileSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const BIN = path.join(__dirname, "..", "bin", "mcp-audit.js");
const CLEAN = path.join(__dirname, "..", "fixtures", "clean.json");
const DIRTY = path.join(__dirname, "..", "fixtures", "dirty.json");

function run(args) {
  try {
    const stdout = execFileSync(process.execPath, [BIN, ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { code: 0, stdout, stderr: "" };
  } catch (e) {
    return { code: e.status == null ? -1 : e.status, stdout: e.stdout || "", stderr: e.stderr || "" };
  }
}

// ── --help: exit 0 + usage ──
const help = run(["--help"]);
assert.strictEqual(help.code, 0, "--help 应退出 0");
assert.ok(/Usage:/i.test(help.stdout), "--help 应输出用法");

// ── fixtures keep their contracts ──
assert.strictEqual(run([CLEAN]).code, 0, "clean fixture 应退出 0");
assert.strictEqual(run([DIRTY]).code, 1, "dirty fixture 应退出 1");

// ── explicit missing file: fatal exit 2（v0.5.1 前是静默 100/100 通过）──
const miss = run(["no-such-config-file.json"]);
assert.strictEqual(miss.code, 2, "不存在的显式文件应退出 2，实际 " + miss.code);
assert.ok(/file not found/.test(miss.stderr), "stderr 应说明 file not found");

// ── explicit unparsable file: fatal exit 2 ──
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-audit-cli-"));
const garbage = path.join(tmp, "garbage.json");
fs.writeFileSync(garbage, "{{{ not json");
const bad = run([garbage]);
assert.strictEqual(bad.code, 2, "解析失败的显式文件应退出 2");
assert.ok(/cannot load/.test(bad.stderr), "stderr 应说明 cannot load");

// ── unknown flag: fatal exit 2（v0.5.1 前被静默忽略）──
const unk = run(["--sari", CLEAN]);
assert.strictEqual(unk.code, 2, "未知 flag 应退出 2");
assert.ok(/unknown flag/.test(unk.stderr), "stderr 应提示 unknown flag");

// ── discovery mode must never turn into a fatal — machine may have real configs ──
const disc = run([]);
assert.ok(disc.code === 0 || disc.code === 1, "自动发现模式不应 fatal，实际 " + disc.code);

fs.rmSync(tmp, { recursive: true, force: true });
console.log("ALL CLI TESTS PASSED");
