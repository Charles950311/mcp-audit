/**
 * Live probing of remote MCP servers. v0.4 — both HTTP transports.
 *
 * Opt-in via --probe: makes real network requests to every server definition
 * that carries an http(s) `url`. Never sends credentials — the point is to
 * observe what an anonymous client can do. Findings use the same shape as the
 * static rules, so scoring, SARIF and exit codes work unchanged.
 *
 * Transport ladder (probeServer):
 *   1. streamable HTTP: POST initialize to the url.
 *        401/403            → auth-required (good posture, no finding)
 *        404/405            → fall through to legacy SSE
 *        network fail/5xx   → unreachable (low finding)
 *        2xx non-JSON-RPC   → not-mcp (low finding)
 *   2. legacy SSE (2024-11-05): GET the url for the event stream, read the
 *      `endpoint` event, POST JSON-RPC to that endpoint, read responses off
 *      the stream. Same status/finding mapping as above.
 *   3. Neither works → unsupported-transport (reported, not judged).
 *
 * On handshake success both transports then send notifications/initialized
 * and tools/list:
 *        200 with tools     → open-tool-listing (medium finding)
 *        401/403            → mcp-protected (good posture, no finding)
 */

const PROBE_RULES = {
  "open-tool-listing": {
    id: "open-tool-listing",
    title: "MCP endpoint lists tools without authentication",
    severity: "medium",
    detail:
      "tools/list succeeded with no credentials — anyone who can reach this URL can enumerate (and likely invoke) its tools. Put the endpoint behind auth (OAuth per the MCP spec, or at least a bearer token) unless it is intentionally public.",
  },
  "remote-unreachable": {
    id: "remote-unreachable",
    title: "Remote MCP endpoint unreachable",
    severity: "low",
    detail:
      "No usable response within the timeout (connection failed, timed out, or 5xx). Dead or flaky entries are operational noise and hide config drift — remove or fix the URL.",
  },
  "remote-not-mcp": {
    id: "remote-not-mcp",
    title: "Endpoint did not answer the MCP handshake",
    severity: "low",
    detail:
      "The URL answered but not with a JSON-RPC 2.0 MCP response to initialize — the address may point at something else (login page, proxy, redirect) or predate the streamable-HTTP transport.",
  },
};

const CLIENT_INFO = { name: "mcp-audit", version: "0.4.0" };
const PROTOCOL_VERSION = "2025-06-18";

/** Extract JSON payloads from a complete SSE body (ignores keep-alive comments). */
function sseData(text) {
  const push = createSseStreamParser();
  return push(String(text) + "\n\n")
    .map((f) => tryJson(f.data))
    .filter(Boolean);
}

function tryJson(s) {
  try {
    const v = JSON.parse(s);
    return v && typeof v === "object" ? v : null;
  } catch {
    return null;
  }
}

/** Parse one raw SSE frame (without the blank-line terminator). */
function parseSseFrame(raw) {
  let event = "message";
  const data = [];
  for (const line of String(raw).split("\n")) {
    const l = line.endsWith("\r") ? line.slice(0, -1) : line;
    if (!l || l.startsWith(":")) continue; // comment / keep-alive
    if (l.startsWith("event:")) event = l.slice(6).trim();
    else if (l.startsWith("data:")) data.push(l.slice(5).replace(/^ /, ""));
  }
  return { event, data: data.join("\n") };
}

/**
 * Incremental SSE frame parser: feed it network chunks (handles \r\n and
 * frames split across chunk boundaries), get complete frames back.
 */
function createSseStreamParser() {
  let buf = "";
  return (chunk) => {
    buf += String(chunk).replace(/\r\n/g, "\n");
    const frames = [];
    let i;
    while ((i = buf.indexOf("\n\n")) >= 0) {
      const frame = parseSseFrame(buf.slice(0, i));
      if (frame.data) frames.push(frame); // comment-only / keep-alive blocks are not events
      buf = buf.slice(i + 2);
    }
    return frames;
  };
}

/**

/**
 * Pull the JSON-RPC response matching `id` out of a probe response body.
 * Handles both direct application/json and text/event-stream frames.
 */
function extractResponse(status, contentType, body, id) {
  if (status !== 200) return { ok: false, json: null };
  const parsed = [];
  if (/text\/event-stream/i.test(contentType || "")) parsed.push(...sseData(body));
  else {
    try {
      parsed.push(JSON.parse(body));
    } catch {
      /* html / plain text */
    }
  }
  const json =
    parsed.find(
      (m) =>
        m &&
        typeof m === "object" &&
        ("result" in m || "error" in m) &&
        (m.id === undefined || m.id === id)
    ) || null;
  return { ok: Boolean(json), json };
}

/** Probe one endpoint over the modern streamable-HTTP transport (POST). */
async function probeStreamableHttp({ file, server, url, timeout = 5000, fetchImpl } = {}) {
  if (!/^https?:\/\//i.test(String(url || ""))) {
    throw new Error("probeServer needs an http(s) url");
  }
  const doFetch = fetchImpl || global.fetch;
  if (!doFetch) throw new Error("fetch unavailable (node >= 18 required)");
  const base = { file: file || "", server: server || "", url };
  const started = Date.now();
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeout);

  const post = async (body, extraHeaders = {}) => {
    const res = await doFetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        ...extraHeaders,
      },
      body: JSON.stringify(body),
      signal: ctl.signal,
      redirect: "manual",
    });
    const text = await res.text();
    return {
      status: res.status,
      contentType: res.headers.get("content-type") || "",
      headers: res.headers,
      text,
    };
  };

  try {
    let res;
    try {
      res = await post({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: CLIENT_INFO },
      });
    } catch (e) {
      const reason =
        e && e.name === "AbortError"
          ? `timeout after ${timeout}ms`
          : String((e && e.cause && e.cause.code) || (e && e.message) || e).slice(0, 120);
      return { ...base, status: "unreachable", latencyMs: Date.now() - started, error: reason };
    }
    const latencyMs = Date.now() - started;

    if (res.status === 401 || res.status === 403)
      return { ...base, status: "auth-required", latencyMs };
    if (res.status === 404 || res.status === 405)
      return {
        ...base,
        status: "unsupported-transport",
        latencyMs,
        error: `HTTP ${res.status} on POST — legacy SSE transport not probed`,
      };
    if (res.status >= 300 && res.status < 400)
      return { ...base, status: "not-mcp", latencyMs, error: `HTTP ${res.status} redirect` };
    if (res.status !== 200)
      return { ...base, status: "unreachable", latencyMs, error: `HTTP ${res.status} on initialize` };

    const init = extractResponse(res.status, res.contentType, res.text, 1);
    if (!init.ok || init.json.error || !init.json.result) {
      const msg =
        init.ok && init.json.error
          ? `initialize rejected: ${String(init.json.error.message || "JSON-RPC error").slice(0, 80)}`
          : "response was not a JSON-RPC 2.0 result";
      return { ...base, status: "not-mcp", latencyMs, error: msg };
    }

    const sessionId = res.headers.get("mcp-session-id") || "";
    if (sessionId) {
      try {
        await post({ jsonrpc: "2.0", method: "notifications/initialized" }, { "Mcp-Session-Id": sessionId });
      } catch {
        /* best effort */
      }
    }

    let toolsRes;
    try {
      toolsRes = await post(
        { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
        sessionId ? { "Mcp-Session-Id": sessionId } : {}
      );
    } catch (e) {
      return {
        ...base,
        status: "mcp-ok",
        latencyMs,
        error: "handshake ok; tools/list failed: " + String(e && e.message).slice(0, 80),
      };
    }
    if (toolsRes.status === 401 || toolsRes.status === 403)
      return { ...base, status: "mcp-protected", latencyMs };

    const tools = extractResponse(toolsRes.status, toolsRes.contentType, toolsRes.text, 2);
    if (tools.ok && tools.json.result && Array.isArray(tools.json.result.tools)) {
      const names = tools.json.result.tools.map((t) => t && t.name).filter(Boolean);
      return {
        ...base,
        status: "open-tool-listing",
        latencyMs,
        toolsCount: names.length,
        toolNames: names.slice(0, 5),
      };
    }
    return { ...base, status: "mcp-ok", latencyMs, error: `tools/list → HTTP ${toolsRes.status}` };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Probe one endpoint over the legacy HTTP+SSE transport (2024-11-05):
 * GET the url for the event stream, read the `endpoint` event, POST JSON-RPC
 * to that endpoint — responses arrive on the stream, not on the POST.
 */
async function probeLegacySse({ file, server, url, timeout = 5000, fetchImpl } = {}) {
  const doFetch = fetchImpl || global.fetch;
  if (!doFetch) throw new Error("fetch unavailable (node >= 18 required)");
  const base = { file: file || "", server: server || "", url };
  const started = Date.now();
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeout);
  const at = () => ({ ...base, latencyMs: Date.now() - started });
  const timedOut = () => ctl.signal.aborted;

  try {
    let res;
    try {
      res = await doFetch(url, {
        method: "GET",
        headers: { Accept: "text/event-stream" },
        signal: ctl.signal,
        redirect: "manual",
      });
    } catch (e) {
      const reason =
        e && e.name === "AbortError"
          ? `timeout after ${timeout}ms`
          : String((e && e.cause && e.cause.code) || (e && e.message) || e).slice(0, 120);
      return { ...at(), status: "unreachable", error: reason };
    }
    if (res.status === 401 || res.status === 403) return { ...at(), status: "auth-required" };
    if (res.status !== 200)
      return { ...at(), status: "unsupported-transport", error: `HTTP ${res.status} on GET` };
    if (!/text\/event-stream/i.test(res.headers.get("content-type") || ""))
      return { ...at(), status: "not-mcp", error: "GET did not return a text/event-stream" };

    // Pump frames off the stream; register waiters before triggering requests
    // so a fast server writing the response before its own 202 is never missed.
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    const push = createSseStreamParser();
    const waiters = [];
    const unclaimed = [];
    const dispatch = (frame) => {
      const i = waiters.findIndex((w) => w.predicate(frame));
      if (i >= 0) waiters.splice(i, 1)[0].resolve(frame);
      else unclaimed.push(frame);
    };
    const nextFrame = (predicate) => {
      const j = unclaimed.findIndex((f) => {
        try {
          return predicate(f);
        } catch {
          return false;
        }
      });
      if (j >= 0) return Promise.resolve(unclaimed.splice(j, 1)[0]);
      return new Promise((resolve) => waiters.push({ predicate, resolve }));
    };
    (async () => {
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          for (const frame of push(decoder.decode(value, { stream: true }))) dispatch(frame);
        }
      } catch {
        /* aborted or connection reset */
      }
      while (waiters.length) waiters.shift().resolve(null);
    })();

    const noFrame = (fallback) => (timedOut() ? { ...at(), status: "unreachable", error: `timeout after ${timeout}ms` } : fallback());

    // 1. endpoint event
    const ep = await nextFrame((f) => f.event === "endpoint" && !!f.data);
    if (!ep)
      return noFrame(() => ({
        ...at(),
        status: "not-mcp",
        error: "SSE stream ended before an endpoint event",
      }));
    let endpoint;
    try {
      endpoint = new URL(ep.data.trim(), url).toString();
    } catch {
      return { ...at(), status: "not-mcp", error: "endpoint event was not a usable URL: " + ep.data.slice(0, 80) };
    }

    const post = async (body) => {
      const r = await doFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: ctl.signal,
      });
      return r.status;
    };

    // 2. initialize — the response arrives on the SSE stream
    const initFrameP = nextFrame((f) => {
      const m = tryJson(f.data);
      return m && m.id === 1;
    });
    let initStatus;
    try {
      initStatus = await post({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: CLIENT_INFO },
      });
    } catch (e) {
      return { ...at(), status: "unreachable", error: "initialize POST failed: " + String(e && e.message).slice(0, 80) };
    }
    if (initStatus === 401 || initStatus === 403) return { ...at(), status: "auth-required" };
    if (initStatus >= 400)
      return { ...at(), status: "unreachable", error: `HTTP ${initStatus} on initialize POST` };

    const initFrame = await initFrameP;
    if (!initFrame)
      return noFrame(() => ({ ...at(), status: "not-mcp", error: "no initialize response on the SSE stream" }));
    const initMsg = tryJson(initFrame.data);
    if (!initMsg.result || initMsg.error)
      return {
        ...at(),
        status: "not-mcp",
        error:
          "initialize rejected: " +
          String((initMsg.error && initMsg.error.message) || "JSON-RPC error").slice(0, 80),
      };

    // 3. notifications/initialized (best effort), then tools/list
    try {
      await post({ jsonrpc: "2.0", method: "notifications/initialized" });
    } catch {
      /* best effort */
    }
    const listFrameP = nextFrame((f) => {
      const m = tryJson(f.data);
      return m && m.id === 2;
    });
    let listStatus;
    try {
      listStatus = await post({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
    } catch (e) {
      return { ...at(), status: "mcp-ok", error: "handshake ok; tools/list POST failed: " + String(e && e.message).slice(0, 80) };
    }
    if (listStatus === 401 || listStatus === 403) return { ...at(), status: "mcp-protected" };

    const listFrame = await listFrameP;
    if (listFrame) {
      const msg = tryJson(listFrame.data);
      if (msg && msg.result && Array.isArray(msg.result.tools)) {
        const names = msg.result.tools.map((t) => t && t.name).filter(Boolean);
        return { ...at(), status: "open-tool-listing", toolsCount: names.length, toolNames: names.slice(0, 5) };
      }
    }
    return { ...at(), status: "mcp-ok", error: "handshake ok; tools/list gave no parseable response" };
  } finally {
    clearTimeout(timer);
    try {
      ctl.abort();
    } catch {
      /* stream already closed */
    }
  }
}

/**
 * Probe one remote endpoint: streamable HTTP first, fall back to legacy SSE
 * when the POST is rejected with 404/405. Results carry a `transport` field.
 */
async function probeServer(opts = {}) {
  const primary = await probeStreamableHttp(opts);
  if (primary.status === "unsupported-transport") {
    const legacy = await probeLegacySse(opts);
    if (legacy.status !== "unsupported-transport") return { ...legacy, transport: "sse" };
  }
  return { ...primary, transport: "streamable-http" };
}

/** Collect remote endpoints (http/https url) from parsed config files. */
function collectRemote(files) {
  const out = [];
  for (const f of files || []) {
    for (const s of f.servers || []) {
      const url = s.def && s.def.url;
      if (typeof url === "string" && /^https?:\/\//i.test(url)) {
        out.push({ file: f.file, server: s.name, url });
      }
    }
  }
  return out;
}

/** Probe all remote endpoints sequentially (gentle by design). */
async function probeAll(files, opts = {}) {
  const results = [];
  for (const t of collectRemote(files)) {
    results.push(await probeServer({ ...t, timeout: opts.timeout, fetchImpl: opts.fetchImpl }));
  }
  return results;
}

/** Convert probe results into findings (same shape as static rules). */
function probeFindings(probes) {
  const findings = [];
  for (const p of probes || []) {
    if (p.status === "open-tool-listing") {
      const rule = PROBE_RULES["open-tool-listing"];
      findings.push({
        file: p.file,
        server: p.server,
        rule: rule.id,
        severity: rule.severity,
        title: rule.title,
        match: `${p.toolsCount} tools: ${(p.toolNames || []).join(", ") || "(unnamed)"}`,
        detail: rule.detail,
      });
    } else if (p.status === "unreachable") {
      const rule = PROBE_RULES["remote-unreachable"];
      findings.push({
        file: p.file,
        server: p.server,
        rule: rule.id,
        severity: rule.severity,
        title: rule.title,
        match: p.error || "no response",
        detail: rule.detail,
      });
    } else if (p.status === "not-mcp") {
      const rule = PROBE_RULES["remote-not-mcp"];
      findings.push({
        file: p.file,
        server: p.server,
        rule: rule.id,
        severity: rule.severity,
        title: rule.title,
        match: p.error || "non-MCP response",
        detail: rule.detail,
      });
    }
  }
  return findings;
}

module.exports = {
  PROBE_RULES,
  PROTOCOL_VERSION,
  sseData,
  tryJson,
  parseSseFrame,
  createSseStreamParser,
  extractResponse,
  probeStreamableHttp,
  probeLegacySse,
  probeServer,
  collectRemote,
  probeAll,
  probeFindings,
};
