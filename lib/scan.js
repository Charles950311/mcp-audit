/**
 * Config discovery and parsing for MCP server definitions.
 *
 * Supported shapes (all JSON):
 *   { "mcpServers": { "<name>": { command, args, env } | { url } } }   // Claude Desktop / .mcp.json / Cursor
 *   { "servers":   { ... } }                                            // some forks
 */
const fs = require("fs");
const os = require("os");
const path = require("path");

const KNOWN_PATHS = [
  ".mcp.json",
  "claude_desktop_config.json",
  path.join(os.homedir(), ".claude", "claude_desktop_config.json"),
  path.join(os.homedir(), "Library", "Application Support", "Claude", "claude_desktop_config.json"),
  path.join(os.homedir(), "AppData", "Roaming", "Claude", "claude_desktop_config.json"),
  path.join(os.homedir(), ".cursor", "mcp.json"),
];

function resolveTargets(argv) {
  if (argv.length > 0) return argv;
  return KNOWN_PATHS.filter((f) => fs.existsSync(f));
}

function extractServers(config) {
  if (!config || typeof config !== "object") return {};
  const servers = config.mcpServers || config.servers;
  return servers && typeof servers === "object" ? servers : {};
}

function loadFile(file) {
  let config;
  try {
    config = JSON.parse(fs.readFileSync(file, "utf8"));
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

function loadAll(files) {
  return files.map(loadFile).filter((r) => {
    if (r.error) {
      console.error("mcp-audit: skipping " + r.file + " (" + r.error + ")");
      return false;
    }
    return true;
  });
}

module.exports = { KNOWN_PATHS, resolveTargets, extractServers, loadFile, loadAll };
