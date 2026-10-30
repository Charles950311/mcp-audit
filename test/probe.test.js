const assert = require("assert");
const http = require("http");
const { sseData, extractResponse, probeServer, probeLegacySse, probeAll, probeFindings, collectRemote, PROBE_RULES, parseSseFrame, createSseStreamParser } = require("../lib/probe");
const { scoreFindings } = require("../lib/rules");

// ── SSE 解析 ──

const sseBody = 'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"ok":1}}\n\n: keep-alive\ndata: {"n":2}\n\n';
assert.strictEqual(sseData(sseBody).length, 2, "SSE 应解析出 2 个 data 帧");
assert.strictEqual(sseData(sseBody)[0].result.ok, 1);
assert.strictEqual(sseData('data: not-json\n\n').length, 0, "非 JSON data 帧应忽略");
assert.strictEqual(sseData("data:\ndata:   \n\n").length, 0, "空 data 帧应忽略");
assert.strictEqual(sseData("").length, 0);

// ── 响应分类 ──

const okJson = extractResponse(200, "application/json", '{"jsonrpc":"2.0","id":7,"result":{}}', 7);
assert.ok(okJson.ok && okJson.json.result, "直接 JSON 应命中");
assert.strictEqual(extractResponse(200, "text/html", "<html>login</html>", 1).ok, false, "HTML 不应命中");
assert.strictEqual(extractResponse(401, "application/json", '{"jsonrpc":"2.0","id":1,"result":{}}', 1).ok, false, "非 200 不解析");
const okSse = extractResponse(200, "text/event-stream", 'data: {"jsonrpc":"2.0","id":3,"result":{"m":1}}\n\n', 3);
assert.ok(okSse.ok && okSse.json.result.m === 1, "SSE 帧应命中");

// ── SSE 帧解析与流式解析器 ──

const f1 = parseSseFrame('event: endpoint\ndata: /messages?sessionId=s1');
assert.strictEqual(f1.event, "endpoint");
assert.strictEqual(f1.data, "/messages?sessionId=s1");
const f2 = parseSseFrame(': keep-alive\ndata: {"a":1}\r\ndata: {"b":2}\r\n');
assert.strictEqual(f2.data, '{"a":1}\n{"b":2}', "多 data 行应按 SSE 规范拼接");
assert.strictEqual(parseSseFrame("event: ping").event, "ping");
const push = createSseStreamParser();
assert.deepStrictEqual(push("event: endpo"), [], "半个帧不应产出");
assert.deepStrictEqual(push("int\ndata: /m\r\n\r\ndata: {\"x\":1}\n\n").map((x) => ({ e: x.event, d: x.data })),
  [{ e: "endpoint", d: "/m" }, { e: "message", d: '{"x":1}' }], "跨 chunk 帧应正确缓冲");
assert.deepStrictEqual(push(": ping\n\n"), [], "纯注释不产出");

// ── 本地 http 集成测试 ──

function startServer(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer(handler);
    srv.listen(0, "127.0.0.1", () => resolve({ srv, url: "http://127.0.0.1:" + srv.address().port + "/mcp" }));
  });
}

function readBody(req) {
  return new Promise((resolve) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      try { resolve(JSON.parse(raw)); } catch { resolve({}); }
    });
  });
}

(async () => {
  // 场景 1：无需鉴权，tools/list 直接成功 → open-tool-listing
  const open = await startServer(async (req, res) => {
    const msg = await readBody(req);
    if (msg.method === "initialize") {
      res.setHeader("Mcp-Session-Id", "sess-42");
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-06-18", capabilities: {}, serverInfo: { name: "open", version: "1" } } }));
    } else if (msg.method === "notifications/initialized") {
      if (req.headers["mcp-session-id"] !== "sess-42") { res.statusCode = 400; return res.end(); }
      res.statusCode = 202; res.end();
    } else if (msg.method === "tools/list") {
      if (req.headers["mcp-session-id"] !== "sess-42") { res.statusCode = 400; return res.end(); }
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "read_file" }, { name: "run_cmd" }, { name: "fetch_url" }, { name: "write_file" }] } }));
    } else { res.statusCode = 500; res.end(); }
  });

  const p1 = await probeServer({ file: "cfg.json", server: "open-one", url: open.url });
  assert.strictEqual(p1.status, "open-tool-listing", "匿名 tools/list 应判 open-tool-listing，实际 " + JSON.stringify(p1));
  assert.strictEqual(p1.toolsCount, 4);
  assert.deepStrictEqual(p1.toolNames, ["read_file", "run_cmd", "fetch_url", "write_file"]);
  assert.ok(p1.latencyMs >= 0 && p1.file === "cfg.json" && p1.server === "open-one");
  assert.strictEqual(p1.transport, "streamable-http", "streamable 传输应标注 transport");

  // 场景 2：initialize 即 401 → auth-required，无 finding
  const locked = await startServer((req, res) => { res.statusCode = 401; res.end("{}"); });
  const p2 = await probeServer({ url: locked.url });
  assert.strictEqual(p2.status, "auth-required");
  assert.strictEqual(probeFindings([p2]).length, 0, "auth-required 不应产生 finding");

  // 场景 3：握手成功但 tools/list 403 → mcp-protected，无 finding
  const guarded = await startServer(async (req, res) => {
    const msg = await readBody(req);
    if (msg.method === "initialize") {
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: {} }));
    } else { res.statusCode = 403; res.end(); }
  });
  const p3 = await probeServer({ url: guarded.url });
  assert.strictEqual(p3.status, "mcp-protected");
  assert.strictEqual(probeFindings([p3]).length, 0, "mcp-protected 不应产生 finding");

  // 场景 4：连接挂起 → 超时 unreachable
  const hanging = await startServer(() => { /* never respond */ });
  const p4 = await probeServer({ file: "cfg.json", server: "hanging", url: hanging.url, timeout: 300 });
  assert.strictEqual(p4.status, "unreachable");
  assert.ok(/timeout/.test(p4.error), "超时应注明原因，实际 " + p4.error);

  // 场景 5：200 但返回 HTML → not-mcp
  const html = await startServer((req, res) => { res.setHeader("Content-Type", "text/html"); res.end("<html>login</html>"); });
  const p5 = await probeServer({ file: "cfg.json", server: "html-one", url: html.url });
  assert.strictEqual(p5.status, "not-mcp");

  // 场景 6：405 → legacy SSE，不判也不报
  const legacy = await startServer((req, res) => { res.statusCode = 405; res.end(); });
  const p6 = await probeServer({ url: legacy.url });
  assert.strictEqual(p6.status, "unsupported-transport");
  assert.strictEqual(probeFindings([p6]).length, 0);

  // 场景 7：SSE 传输的握手 + 匿名 tools/list
  const sse = await startServer(async (req, res) => {
    const msg = await readBody(req);
    res.setHeader("Content-Type", "text/event-stream");
    if (msg.method === "initialize") {
      res.end('event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05"}}\n\n');
    } else if (msg.id !== undefined) {
      res.end('data: {"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"grep_docs"}]}}\n\n');
    } else { res.end(); }
  });
  const p7 = await probeServer({ url: sse.url });
  assert.strictEqual(p7.status, "open-tool-listing", "SSE 匿名工具列表应命中，实际 " + JSON.stringify(p7));
  assert.strictEqual(p7.toolsCount, 1);

  // 场景 8：JSON-RPC error 回 initialize → not-mcp（协议不符）
  const rej = await startServer(async (req, res) => {
    const msg = await readBody(req);
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, error: { code: -32602, message: "bad protocolVersion" } }));
  });
  const p8 = await probeServer({ url: rej.url });
  assert.strictEqual(p8.status, "not-mcp");
  assert.ok(/initialize rejected/.test(p8.error));

  // ── legacy SSE 传输（2024-11-05）──

  const sseWrite = (r, s) => r.write(s + "\n");
  // 场景 L1：POST /sse 405 → 回退 GET SSE：endpoint 事件 + 流上响应 → open-tool-listing
  let sseL1 = null;
  const legacyOpen = await startServer(async (req, res) => {
    if (req.method === "GET") {
      sseL1 = res;
      res.writeHead(200, { "Content-Type": "text/event-stream" });
      sseWrite(res, "event: endpoint\ndata: /messages?sessionId=s9\n\n");
      return;
    }
    if (!req.url.startsWith("/messages")) { res.statusCode = 405; return res.end(); } // /sse 上的 POST 必须拒绝以触发回退
    const msg = await readBody(req);
    if (msg.method === "initialize") {
      sseWrite(sseL1, "event: message\ndata: " + JSON.stringify({ jsonrpc: "2.0", id: 1, result: { protocolVersion: "2024-11-05", serverInfo: { name: "legacy" } } }) + "\n\n");
      res.statusCode = 202; res.end();
    } else if (msg.method === "tools/list") {
      sseWrite(sseL1, "data: " + JSON.stringify({ jsonrpc: "2.0", id: 2, result: { tools: [{ name: "legacy_tool" }, { name: "legacy_search" }] } }) + "\n\n");
      res.statusCode = 202; res.end();
    } else { res.statusCode = 202; res.end(); }
  });
  const pL1 = await probeServer({ file: "cfg.json", server: "legacy-open", url: legacyOpen.url, timeout: 2000 });
  assert.strictEqual(pL1.status, "open-tool-listing", "legacy SSE 匿名工具应命中，实际 " + JSON.stringify(pL1));
  assert.strictEqual(pL1.transport, "sse", "回退后应标注 sse");
  assert.strictEqual(pL1.toolsCount, 2);
  assert.deepStrictEqual(pL1.toolNames, ["legacy_tool", "legacy_search"]);
  const pL1b = await probeLegacySse({ url: legacyOpen.url, timeout: 2000 });
  assert.strictEqual(pL1b.status, "open-tool-listing", "直探 legacy 也应命中");

  // 场景 L2：GET 即 401 → auth-required（POST 先 405 触发回退）
  const legacyAuth = await startServer((req, res) => {
    if (req.method === "GET") { res.statusCode = 401; return res.end(); }
    res.statusCode = 405; res.end();
  });
  const pL2 = await probeServer({ url: legacyAuth.url, timeout: 2000 });
  assert.strictEqual(pL2.status, "auth-required");
  assert.strictEqual(pL2.transport, "sse");

  // 场景 L3：握手成功但 tools/list POST 403 → mcp-protected
  let sseL3 = null;
  const legacyGuard = await startServer(async (req, res) => {
    if (req.method === "GET") {
      sseL3 = res;
      res.writeHead(200, { "Content-Type": "text/event-stream" });
      sseWrite(res, "event: endpoint\ndata: /messages\n\n");
      return;
    }
    if (!req.url.startsWith("/messages")) { res.statusCode = 405; return res.end(); }
    const msg = await readBody(req);
    if (msg.method === "initialize") {
      sseWrite(sseL3, "data: " + JSON.stringify({ jsonrpc: "2.0", id: 1, result: {} }) + "\n\n");
      res.statusCode = 202; res.end();
    } else if (msg.method === "tools/list") {
      res.statusCode = 403; res.end();
    } else { res.statusCode = 202; res.end(); }
  });
  const pL3 = await probeServer({ url: legacyGuard.url, timeout: 2000 });
  assert.strictEqual(pL3.status, "mcp-protected", "legacy 受保护工具应判 mcp-protected，实际 " + JSON.stringify(pL3));
  assert.strictEqual(probeFindings([pL3]).length, 0);

  // 场景 L4：GET 200 但非 SSE → not-mcp
  const legacyHtml = await startServer((req, res) => {
    if (req.method === "GET") { res.setHeader("Content-Type", "text/html"); return res.end("<html>sorry</html>"); }
    res.statusCode = 405; res.end();
  });
  const pL4 = await probeServer({ url: legacyHtml.url, timeout: 2000 });
  assert.strictEqual(pL4.status, "not-mcp");

  // 场景 L5：SSE 打开但永不发 endpoint → 超时 unreachable
  const legacyHang = await startServer((req, res) => {
    if (req.method === "GET") { res.writeHead(200, { "Content-Type": "text/event-stream" }); return; }
    res.statusCode = 405; res.end();
  });
  const pL5 = await probeServer({ url: legacyHang.url, timeout: 300 });
  assert.strictEqual(pL5.status, "unreachable");
  assert.ok(/timeout/.test(pL5.error), "SSE 超时应注明，实际 " + pL5.error);

  // 场景 L6：流在 endpoint 事件前结束 → not-mcp
  const legacyShort = await startServer((req, res) => {
    if (req.method === "GET") { res.writeHead(200, { "Content-Type": "text/event-stream" }); res.write(": hello\n\n"); return res.end(); }
    res.statusCode = 405; res.end();
  });
  const pL6 = await probeServer({ url: legacyShort.url, timeout: 2000 });
  assert.strictEqual(pL6.status, "not-mcp");
  assert.ok(/endpoint event/.test(pL6.error));

  // 场景 L7：两种传输都拒绝 → unsupported-transport 保持
  const legacyNone = await startServer((req, res) => { res.statusCode = 404; res.end(); });
  const pL7 = await probeServer({ url: legacyNone.url, timeout: 2000 });
  assert.strictEqual(pL7.status, "unsupported-transport");

  // ── findings 映射与评分 ──

  const pf = probeFindings([p1, p4, p5]);
  assert.deepStrictEqual(pf.map((f) => f.rule).sort(), ["open-tool-listing", "remote-not-mcp", "remote-unreachable"]);
  for (const f of pf) {
    assert.ok(f.file && f.server && f.title && f.detail && f.match, "finding 字段应完整: " + JSON.stringify(f));
  }
  const sev = Object.fromEntries(pf.map((f) => [f.rule, f.severity]));
  assert.strictEqual(sev["open-tool-listing"], "medium");
  assert.strictEqual(sev["remote-unreachable"], "low");
  assert.strictEqual(sev["remote-not-mcp"], "low");

  const { score, grade } = scoreFindings(pf);
  assert.strictEqual(score, 80, "medium 10 + low 5 + low 5 应扣 20 分，实际 " + score);
  assert.strictEqual(grade, "B");

  // ── collectRemote ──

  const picked = collectRemote([
    { file: "a.json", servers: [{ name: "x", def: { url: "https://m.example.com" } }, { name: "y", def: { command: "node" } }, { name: "z", def: { url: "ftp://no" } }] },
  ]);
  assert.strictEqual(picked.length, 1, "只收 http(s) url");
  assert.strictEqual(picked[0].server, "x");

  // probeAll 顺序批量
  const batch = await probeAll([
    { file: "a.json", servers: [{ name: "open-one", def: { url: open.url } }, { name: "locked", def: { url: locked.url } }] },
  ]);
  assert.deepStrictEqual(batch.map((b) => b.status), ["open-tool-listing", "auth-required"]);

  // 规则表完整性
  for (const id of ["open-tool-listing", "remote-unreachable", "remote-not-mcp"]) {
    assert.ok(PROBE_RULES[id] && PROBE_RULES[id].title && PROBE_RULES[id].detail && PROBE_RULES[id].severity);
  }

  for (const s of [open, locked, guarded, hanging, html, legacy, sse, rej, legacyOpen, legacyAuth, legacyGuard, legacyHtml, legacyHang, legacyShort, legacyNone].map((x) => x.srv)) s.close();
  console.log("ALL PROBE TESTS PASSED");
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
