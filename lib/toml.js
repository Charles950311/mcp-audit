/**
 * Minimal TOML subset parser — enough for MCP server blocks in configs like
 * Codex CLI's `~/.codex/config.toml`:
 *
 *   [mcp_servers.fetch]
 *   command = "uvx"
 *   args = ["mcp-server-fetch"]
 *
 *   [mcp_servers.docs.env]
 *   API_KEY = "${DOCS_KEY}"
 *
 * Supports: [table.headers] (dotted), bare/quoted keys, basic & literal
 * strings, numbers (with _), booleans, single-line and multi-line arrays,
 * inline tables, and comments. Dates are left as strings.
 * Deliberately NOT supported: multi-line strings, dotted keys outside
 * headers, array-of-tables — bail loudly instead of guessing.
 */

function stripComment(line) {
  let inStr = false;
  let strCh = "";
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inStr) {
      if (c === "\\" && strCh === '"') i++;
      else if (c === strCh) inStr = false;
      continue;
    }
    if (c === '"' || c === "'") {
      inStr = true;
      strCh = c;
    } else if (c === "#") {
      return line.slice(0, i);
    }
  }
  return line;
}

/** Split a top-level comma list, respecting strings and bracket depth. */
function splitTopLevel(s) {
  const parts = [];
  let buf = "";
  let depthSq = 0;
  let depthC = 0;
  let inStr = false;
  let strCh = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      buf += c;
      if (c === "\\" && strCh === '"') {
        buf += s[i + 1] || "";
        i++;
      } else if (c === strCh) inStr = false;
      continue;
    }
    if (c === '"' || c === "'") {
      inStr = true;
      strCh = c;
      buf += c;
      continue;
    }
    if (c === "[") depthSq++;
    if (c === "]") depthSq--;
    if (c === "{") depthC++;
    if (c === "}") depthC--;
    if (c === "," && depthSq === 0 && depthC === 0) {
      parts.push(buf);
      buf = "";
      continue;
    }
    buf += c;
  }
  if (buf.trim() !== "" || parts.length) parts.push(buf);
  return parts;
}

function parseValue(raw) {
  let s = raw.trim();
  if (s === "") throw new Error("toml: empty value");
  if (s[0] === '"' || s[0] === "'") {
    const ch = s[0];
    let out = "";
    for (let i = 1; i < s.length; i++) {
      const c = s[i];
      if (ch === '"' && c === "\\") {
        const n = s[i + 1];
        const map = { n: "\n", t: "\t", r: "\r", '"': '"', "\\": "\\" };
        if (n in map) {
          out += map[n];
          i++;
          continue;
        }
        out += c;
        continue;
      }
      if (c === ch) return out;
      out += c;
    }
    throw new Error("toml: unterminated string");
  }
  if (s === "true") return true;
  if (s === "false") return false;
  if (/^[+-]?\d[\d_]*(\.\d[\d_]*)?$/.test(s)) return Number(s.replace(/_/g, ""));
  if (s[0] === "[") {
    if (!s.endsWith("]")) throw new Error("toml: multi-line arrays must be pre-joined");
    const inner = s.slice(1, -1);
    return splitTopLevel(inner)
      .filter((p) => p.trim() !== "")
      .map(parseValue);
  }
  if (s[0] === "{") {
    if (!s.endsWith("}")) throw new Error("toml: unterminated inline table");
    const inner = s.slice(1, -1);
    const obj = {};
    for (const part of splitTopLevel(inner)) {
      if (part.trim() === "") continue;
      const eq = splitTopLevelEq(part);
      obj[parseKey(eq[0])] = parseValue(eq[1]);
    }
    return obj;
  }
  // dates / unknown scalars: keep as raw string rather than guessing
  return s;
}

function splitTopLevelEq(s) {
  let inStr = false;
  let strCh = "";
  let depthSq = 0;
  let depthC = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      if (c === "\\" && strCh === '"') i++;
      else if (c === strCh) inStr = false;
      continue;
    }
    if (c === '"' || c === "'") {
      inStr = true;
      strCh = c;
      continue;
    }
    if (c === "[") depthSq++;
    if (c === "]") depthSq--;
    if (c === "{") depthC++;
    if (c === "}") depthC--;
    if (c === "=" && depthSq === 0 && depthC === 0) {
      return [s.slice(0, i), s.slice(i + 1)];
    }
  }
  throw new Error("toml: key without =");
}

function parseKey(raw) {
  let s = raw.trim();
  if ((s[0] === '"' && s.endsWith('"')) || (s[0] === "'" && s.endsWith("'"))) {
    return s.slice(1, -1);
  }
  return s;
}

function ensureTable(root, dotted) {
  let cur = root;
  for (const seg of dotted.split(".")) {
    const key = parseKey(seg.trim());
    if (!cur[key] || typeof cur[key] !== "object") cur[key] = {};
    cur = cur[key];
  }
  return cur;
}

function parseToml(text) {
  const root = {};
  let cur = root;
  const lines = String(text).split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    let line = stripComment(lines[i]).trim();
    if (line === "") continue;

    // multi-line array: keep consuming until brackets balance
    let value = null;
    const kv = line.match(/^([^=]+?)\s*=\s*(.*)$/);
    if (!kv && line[0] !== "[") {
      throw new Error(`toml line ${i + 1}: expected key=value or [table], got: ${line.slice(0, 60)}`);
    }
    if (kv) {
      let v = kv[2];
      const depth = (str) => {
        let d = 0;
        let inStr = false;
        let strCh = "";
        for (let j = 0; j < str.length; j++) {
          const c = str[j];
          if (inStr) {
            if (c === "\\" && strCh === '"') j++;
            else if (c === strCh) inStr = false;
            continue;
          }
          if (c === '"' || c === "'") {
            inStr = true;
            strCh = c;
            continue;
          }
          if (c === "[" || c === "{") d++;
          if (c === "]" || c === "}") d--;
        }
        return d;
      };
      while (depth(v) > 0 && i + 1 < lines.length) {
        i++;
        v += "\n" + stripComment(lines[i]).trim();
      }
      if (depth(v) > 0) throw new Error(`toml line ${i + 1}: unterminated array/inline-table`);
      value = parseValue(v);
      cur[parseKey(kv[1])] = value;
      continue;
    }

    const header = line.match(/^\[(.+)\]$/);
    if (!header) throw new Error(`toml line ${i + 1}: cannot parse: ${line.slice(0, 60)}`);
    cur = ensureTable(root, header[1]);
  }
  return root;
}

module.exports = { parseToml };
