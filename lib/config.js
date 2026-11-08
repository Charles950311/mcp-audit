/**
 * .mcp-audit.json — user suppression / severity config (v0.7).
 *
 * One CI misfire must not stay red forever. Looked up via --config <path>,
 * else ./.mcp-audit.json in the working directory:
 *   { "ignore": [ { "rule": "plaintext-secret", "path": "(any-star)/.claude.json", "server": "legacy-*" } ],
 *     "severityOverrides": { "wildcard-filesystem-arg": "low" } }
 * path/server are tiny globs: two stars = any path segments, one star = within
 * a single segment. Explicit --config failures are fatal; auto-discovery
 * failures are silent.
 */

const fs = require("fs");
const { parseJsonc } = require("./scan");

const SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

function globToRe(glob) {
  const esc = String(glob)
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "\u0000")
    .replace(/\*/g, "[^/]*")
    .replace(/\u0000/g, ".*");
  return new RegExp("^" + esc + "$", "i");
}

function normalize(parsed, source) {
  const ignore = Array.isArray(parsed.ignore)
    ? parsed.ignore
        .filter((r) => r && typeof r.rule === "string")
        .map((r) => ({
          rule: r.rule,
          path: typeof r.path === "string" ? globToRe(r.path) : null,
          server: typeof r.server === "string" ? globToRe(r.server) : null,
        }))
    : [];
  const severityOverrides = {};
  if (parsed.severityOverrides && typeof parsed.severityOverrides === "object" && !Array.isArray(parsed.severityOverrides)) {
    for (const [k, v] of Object.entries(parsed.severityOverrides)) {
      if (SEVERITIES.has(v)) severityOverrides[k] = v;
    }
  }
  return { ignore, severityOverrides, source };
}

function readConfig(explicitPath) {
  if (explicitPath) {
    try {
      const parsed = parseJsonc(fs.readFileSync(explicitPath, "utf8"));
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("config root must be an object");
      }
      return normalize(parsed, explicitPath);
    } catch (e) {
      const err = new Error("cannot load config '" + explicitPath + "' (" + e.message + ")");
      err.clean = true;
      throw err;
    }
  }
  try {
    const parsed = parseJsonc(fs.readFileSync(".mcp-audit.json", "utf8"));
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return normalize(parsed, ".mcp-audit.json");
    }
  } catch {
    /* no config in cwd — fine */
  }
  return null;
}

/** 过滤 + 降级；返回统计供 stderr 透明化 */
function applyConfig(findings, cfg) {
  if (!cfg) return { findings, suppressed: 0, overridden: 0 };
  const kept = [];
  let suppressed = 0;
  let overridden = 0;
  for (const f of findings) {
    const ignored = cfg.ignore.some(
      (r) =>
        f.rule === r.rule &&
        (!r.path || (f.file && r.path.test(String(f.file).replace(/\\/g, "/")))) &&
        (!r.server || (f.server && r.server.test(String(f.server))))
    );
    if (ignored) {
      suppressed++;
      continue;
    }
    const ov = cfg.severityOverrides[f.rule];
    if (ov && ov !== f.severity) {
      overridden++;
      kept.push({ ...f, severity: ov });
      continue;
    }
    kept.push(f);
  }
  return { findings: kept, suppressed, overridden };
}

module.exports = { readConfig, applyConfig, globToRe };
