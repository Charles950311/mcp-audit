/**
 * Rule engine: each rule checks one server definition and returns findings.
 * Deterministic and pure — safe to unit test and to embed in CI.
 *
 * Severity weights (deducted from a 100-point score):
 *   critical 40 · high 20 · medium 10 · low 5 · info 0
 */

const WEIGHTS = { critical: 40, high: 20, medium: 10, low: 5, info: 0 };
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

const SECRET_KEY_RE = /pass(word)?|secret|token|api[_-]?key|private[_-]?key|credential/i;
const WIDE_FS_ARGS = new Set(["/", "/*", "C:\\", "C:/", "~", "~/"]);

const RULES = [
  {
    id: "plaintext-secret",
    title: "Secret stored in plaintext config",
    severity: "high",
    detail:
      "Env keys that look like credentials are written to disk in cleartext and often synced by dotfile/backup tools. Reference them indirectly instead (many clients expand ${VAR}).",
    check(server) {
      const matches = [];
      for (const [scope, map] of [["env", server.def.env || {}], ["headers", server.def.headers || {}]]) {
        for (const [k, v] of Object.entries(map)) {
          if (SECRET_KEY_RE.test(k) && typeof v === "string" && v.length >= 8 && !v.startsWith("${")) {
            matches.push(`${scope}.${k}`);
          }
        }
      }
      return matches;
    },
  },
  {
    id: "entire-disk-filesystem",
    title: "Filesystem access granted to drive/user root",
    severity: "critical",
    detail:
      "A filesystem-style server received '/', 'C:\\', '~' or similar as its root: the agent can read and write your whole disk. Scope it to a project directory.",
    check(server) {
      const args = server.def.args || [];
      return args.filter((a) => WIDE_FS_ARGS.has(String(a).trim()));
    },
  },
  {
    id: "insecure-remote-url",
    title: "Remote server over plaintext HTTP",
    severity: "high",
    detail: "The server URL uses http:// — tokens and tool payloads travel unencrypted. Use https:// (loopback http://127.0.0.1 is exempt).",
    check(server) {
      const url = server.def.url || "";
      if (/^http:\/\/(?!127\.0\.0\.1|localhost|\[::1\])/.test(url)) return [url];
      return [];
    },
  },
  {
    id: "unpinned-npx-package",
    title: "npx package without a version pin",
    severity: "medium",
    detail:
      "npx resolves unpinned packages to the latest version at every launch — a renamed or hijacked package runs with your local trust. Pin an exact version (pkg@1.2.3).",
    check(server) {
      if (!/^(npx|npm)$/.test(String(server.def.command || "").toLowerCase())) return [];
      const args = server.def.args || [];
      const pkg = args.find((a) => !a.startsWith("-"));
      if (!pkg) return [];
      const versionPart = String(pkg).split("/").pop().split("@").pop();
      if (/^\d/.test(versionPart)) return [];
      return [pkg];
    },
  },
  {
    id: "pipe-to-shell",
    title: "Pipe-to-shell install pattern",
    severity: "critical",
    detail: "curl/wget piped into sh/bash executes whatever the endpoint returns today. Vendor the script or use a package manager instead.",
    check(server) {
      const argv = [String(server.def.command || ""), ...(server.def.args || []).map(String)];
      const joined = argv.join(" ");
      if (/curl[^|]*\|\s*(ba|z|da)?sh\b/i.test(joined) || /wget[^|]*\|\s*(ba|z|da)?sh\b/i.test(joined)) {
        return [joined.slice(0, 120)];
      }
      const cIdx = argv.indexOf("-c");
      if (cIdx >= 0 && /curl|wget/i.test(argv.slice(cIdx + 1).join(" ")) && /\|\s*(ba)?sh\b/i.test(argv.slice(cIdx + 1).join(" "))) {
        return [argv.slice(cIdx + 1).join(" ").slice(0, 120)];
      }
      return [];
    },
  },
  {
    id: "elevated-privileges",
    title: "Runs with elevated privileges",
    severity: "high",
    detail: "sudo in the command or args gives a model-invoked process root. Run the server as a normal user and grant only the capabilities it needs.",
    check(server) {
      const argv = [String(server.def.command || ""), ...(server.def.args || []).map(String)];
      return argv.some((a) => a === "sudo" || a === "doas") ? [argv.join(" ").slice(0, 120)] : [];
    },
  },
  {
    id: "wildcard-filesystem-arg",
    title: "Glob/wildcard in filesystem arguments",
    severity: "medium",
    detail: "Args contain '*' or '**' — wildcard scoping is easy to get wrong; pass explicit directories instead.",
    check(server) {
      const args = (server.def.args || []).map(String);
      return args.filter((a) => a.includes("*") && a !== "*");
    },
  },
];

function auditServer(name, def, file = "") {
  const server = { name, def };
  const findings = [];
  for (const rule of RULES) {
    const matches = rule.check(server);
    for (const match of matches) {
      findings.push({
        file,
        server: name,
        rule: rule.id,
        severity: rule.severity,
        title: rule.title,
        match: String(match),
        detail: rule.detail,
      });
    }
  }
  return findings;
}

// 合成规则（跨文件检测，不在 per-server RULES 里）
const DUPLICATE_RULE = {
  id: "duplicate-definition",
  title: "Same server defined in multiple files",
  severity: "info",
  detail: "Duplicate definitions drift apart over time; keep one canonical config.",
};

function sortFindings(findings) {
  return [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );
}

function scoreFindings(findings) {
  const score = Math.max(
    0,
    100 - (findings || []).reduce((sum, f) => sum + (WEIGHTS[f.severity] || 0), 0)
  );
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  return { score, grade };
}

function auditAll(files) {
  const findings = [];
  const seen = new Map();
  for (const f of files) {
    for (const s of f.servers) {
      findings.push(...auditServer(s.name, s.def, f.file));
      const key = JSON.stringify(s.def);
      if (seen.has(key)) {
        findings.push({
          file: f.file,
          server: s.name,
          rule: DUPLICATE_RULE.id,
          severity: DUPLICATE_RULE.severity,
          title: DUPLICATE_RULE.title,
          match: `${seen.get(key)} ↔ ${f.file}`,
          detail: DUPLICATE_RULE.detail,
        });
      } else {
        seen.set(key, f.file);
      }
    }
  }
  const { score, grade } = scoreFindings(findings);
  return {
    findings: sortFindings(findings),
    score,
    grade,
  };
}

module.exports = { RULES, DUPLICATE_RULE, WEIGHTS, auditServer, auditAll, sortFindings, scoreFindings };
