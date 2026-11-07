/**
 * Config discovery and parsing for MCP server definitions.
 *
 * Supported clients (v0.5):
 *   Claude Desktop / Claude Code (JSON, ~/.claude.json)
 *   Cursor                       (~/.cursor/mcp.json, project .mcp.json)
 *   VS Code                      (settings.json — JSONC, servers under mcp.servers)
 *   VS Code workspace            (.vscode/mcp.json — servers)
 *   Windsurf                     (~/.codeium/windsurf/mcp_config.json)
 *   Gemini CLI                   (~/.gemini/settings.json)
 *   Cline / Roo Code             (VS Code globalStorage settings JSON)
 *   Continue                     (~/.continue/config.json)
 *   Zed                          (settings.json — JSONC, context_servers)
 *   Codex CLI                    (~/.codex/config.toml — TOML [mcp_servers.*])
 *
 * Accepted shapes (all normalized by extractServers):
 *   { mcpServers: { name: def } } · { mcp_servers: ... } · { servers: ... }
 *   { mcp: { servers: ... } }     · { context_servers: ... } (Zed)
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const { parseToml } = require("./toml");

const HOME = os.homedir();
const GLOBAL_STORAGE = {
  win32: path.join(HOME, "AppData", "Roaming", "Code", "User", "globalStorage"),
  darwin: path.join(HOME, "Library", "Application Support", "Code", "User", "globalStorage"),
  linux: path.join(HOME, ".config", "Code", "User", "globalStorage"),
};

const KNOWN_PATHS = [
  // project-level
  ".mcp.json",
  ".vscode/mcp.json",
  "claude_desktop_config.json",
  // Claude Desktop / Claude Code
  path.join(HOME, ".claude.json"),
  path.join(HOME, ".claude", "claude_desktop_config.json"),
  path.join(HOME, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
  path.join(HOME, "AppData", "Roaming", "Claude", "claude_desktop_config.json"),
  // Cursor
  path.join(HOME, ".cursor", "mcp.json"),
  // VS Code user settings (JSONC)
  path.join(HOME, "AppData", "Roaming", "Code", "User", "settings.json"),
  path.join(HOME, "Library", "Application Support", "Code", "User", "settings.json"),
  path.join(HOME, ".config", "Code", "User", "settings.json"),
  // Windsurf
  path.join(HOME, ".codeium", "windsurf", "mcp_config.json"),
  // Gemini CLI
  path.join(HOME, ".gemini", "settings.json"),
  // Continue
  path.join(HOME, ".continue", "config.json"),
  // Zed
  path.join(HOME, "AppData", "Roaming", "Zed", "settings.json"),
  path.join(HOME, "Library", "Application Support", "Zed", "settings.json"),
  path.join(HOME, ".config", "zed", "settings.json"),
  path.join(HOME, ".zed", "settings.json"),
  // Codex CLI (TOML)
  path.join(HOME, ".codex", "config.toml"),
  // Cline / Roo Code (VS Code extension global storage)
  path.join(GLOBAL_STORAGE.win32, "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
  path.join(GLOBAL_STORAGE.darwin, "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
  path.join(GLOBAL_STORAGE.linux, "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
  path.join(GLOBAL_STORAGE.win32, "RooVeterinaryInc.roo-cline", "settings", "mcp_settings.json"),
  path.join(GLOBAL_STORAGE.darwin, "RooVeterinaryInc.roo-cline", "settings", "mcp_settings.json"),
  path.join(GLOBAL_STORAGE.linux, "RooVeterinaryInc.roo-cline", "settings", "mcp_settings.json"),
];

function resolveTargets(argv) {
  if (argv.length > 0) return argv;
  return KNOWN_PATHS.filter((f) => fs.existsSync(f));
}

function extractServers(config) {
  if (!config || typeof config !== "object") return {};
  const candidates = [
    config.mcpServers,
    config.mcp_servers,
    config.servers,
    config.mcp && typeof config.mcp === "object" ? config.mcp.servers : undefined, // VS Code settings.json
    config.context_servers, // Zed
  ];
  for (const c of candidates) {
    if (c && typeof c === "object" && !Array.isArray(c)) return c;
  }
  return {};
}

/** Strip // and /* *​/ comments outside strings (keeps string contents intact). */
function stripJsonc(text) {
  let out = "";
  let i = 0;
  let inStr = false;
  let strCh = "";
  while (i < text.length) {
    const c = text[i];
    if (inStr) {
      out += c;
      if (c === "\\" && strCh === '"') {
        out += text[i + 1] || "";
        i += 2;
        continue;
      }
      if (c === strCh) inStr = false;
      i++;
      continue;
    }
    if (c === '"' || c === "'") {
      inStr = true;
      strCh = c;
      out += c;
      i++;
      continue;
    }
    if (c === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      continue;
    }
    if (c === "/" && text[i + 1] === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i += 2;
      continue;
    }
    // trailing commas: comma followed (after whitespace/comments) by } or ]
    if (c === ",") {
      let j = i + 1;
      for (;;) {
        while (j < text.length && /\s/.test(text[j])) j++;
        if (text[j] === "/" && text[j + 1] === "/") {
          while (j < text.length && text[j] !== "\n") j++;
          continue;
        }
        if (text[j] === "/" && text[j + 1] === "*") {
          j += 2;
          while (j < text.length && !(text[j] === "*" && text[j + 1] === "/")) j++;
          j += 2;
          continue;
        }
        break;
      }
      if (j < text.length && (text[j] === "}" || text[j] === "]")) {
        i++;
        continue;
      }
    }
    out += c;
    i++;
  }
  return out;
}

/** Strict JSON first; falls back to JSONC (comments + trailing commas). */
function parseJsonc(text) {
  try {
    return JSON.parse(text);
  } catch {
    return JSON.parse(stripJsonc(String(text)));
  }
}

function loadFile(file) {
  let config;
  try {
    if (!fs.existsSync(file)) return { file, error: "file not found", servers: [] };
    const text = fs.readFileSync(file, "utf8");
    config = /\.toml$/i.test(file) ? parseToml(text) : parseJsonc(text);
  } catch (e) {
    return { file, error: "parse failed: " + e.message, servers: [] };
  }
  const servers = extractServers(config);
  return {
    file,
    error: null,
    servers: Object.entries(servers).map(([name, def]) => ({ name, def: def || {} })),
  };
}

function loadAll(files, explicit = false) {
  return files.map(loadFile).filter((r) => {
    if (r.error) {
      if (explicit) {
        // Explicitly requested files must be readable and parseable — a silent
        // skip would turn a typo'd CI path into a green 100/100 run.
        const err = new Error("cannot load '" + r.file + "' (" + r.error + ")");
        err.clean = true;
        throw err;
      }
      console.error("mcp-audit: skipping " + r.file + " (" + r.error + ")");
      return false;
    }
    return true;
  });
}

/**
 * Best-effort source line for a server definition (for SARIF regions):
 * quoted JSON key, bare name, or a TOML [mcp_servers.<name>] header.
 */
function locateLine(file, name) {
  try {
    const lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
    const esc = String(name).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const patterns = [
      new RegExp('["\']' + esc + '["\']'),
      new RegExp("(^|[\\s.])" + esc + "\\s*=\\s*[\\[{\"']"),
      new RegExp("mcp_servers\\." + esc),
    ];
    for (let i = 0; i < lines.length; i++) {
      if (patterns.some((p) => p.test(lines[i]))) return i + 1;
    }
  } catch {
    /* file may be gone; fall through */
  }
  return 1;
}

module.exports = { KNOWN_PATHS, resolveTargets, extractServers, loadFile, loadAll, parseJsonc, stripJsonc, locateLine };
