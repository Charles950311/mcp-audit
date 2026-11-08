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
// v0.7: 值格式锚点——高置信度的凭据形值，键名再隐蔽也能抓到
const SECRET_VALUE_RE = /(sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,}|glpat-[A-Za-z0-9_-]{15,}|dop_v1_[a-f0-9]{30,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/;
// 非凭据键名但值是带 user:pass@ 的连接串（DATABASE_URL 类）
const CONN_KEY_RE = /^(database|db|postgres|postgresql|mysql|mongo|mongodb|redis|amqp|rabbitmq|mssql)[_-]?(url|uri|dsn)$/i;
const CONN_VALUE_RE = /^[a-z][a-z0-9+.-]*:\/\/[^\/\s:@]+:[^\/\s@]+@/i;
// 熵检测的豁免：任何 scheme:// URI、${VAR} 引用、占位符
const URI_SKIP_RE = /^[a-z][a-z0-9+.-]*:\/\//i;
const PLACEHOLDER_RE = /(changeme|change-me|placeholder|your[-_]|example|sample|dummy|xxxx|<[^>]*>)/i;
const WIDE_FS_ARGS = new Set(["/", "/*", "C:\\", "C:/", "~", "~/"]);

/** Shannon 熵（bits/char）——随机令牌高，重复文本低 */
function shannon(s) {
  const freq = new Map();
  for (const c of s) freq.set(c, (freq.get(c) || 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

const RULES = [
  {
    id: "plaintext-secret",
    title: "Secret stored in plaintext config",
    severity: "high",
    detail:
      "A credential-shaped value (secret-looking key name, recognized token format like sk-/ghp_/AKIA/JWT/PEM, or a user:pass connection string) is written to disk in cleartext and often synced by dotfile/backup tools. Reference it indirectly instead (many clients expand ${VAR}).",
    check(server) {
      const matches = [];
      for (const [scope, map] of [["env", server.def.env || {}], ["headers", server.def.headers || {}]]) {
        for (const [k, v] of Object.entries(map)) {
          if (typeof v !== "string" || v.length < 8 || v.includes("${")) continue;
          const connCred = CONN_KEY_RE.test(k) && CONN_VALUE_RE.test(v);
          if (SECRET_KEY_RE.test(k) || connCred || SECRET_VALUE_RE.test(v)) {
            matches.push(`${scope}.${k}`);
          }
        }
      }
      return matches;
    },
  },
  {
    id: "entropy-secret",
    title: "High-entropy value that looks like a credential",
    severity: "medium",
    detail:
      "This value is long and random-looking (Shannon entropy ≥ 3.5) even though the key name does not say 'secret' — often a credential hiding in plain sight, sometimes just an opaque ID. If it is a credential, reference it via ${VAR}; if not, ignore or rename.",
    check(server) {
      const matches = [];
      for (const [scope, map] of [["env", server.def.env || {}], ["headers", server.def.headers || {}]]) {
        for (const [k, v] of Object.entries(map)) {
          if (typeof v !== "string" || v.length < 20 || v.includes("${")) continue;
          if (URI_SKIP_RE.test(v) || PLACEHOLDER_RE.test(v)) continue;
          if (SECRET_KEY_RE.test(k)) continue; // 键名已命中的交给 plaintext-secret，避免双扣分
          if (shannon(v) >= 3.5) matches.push(`${scope}.${k} (entropy ${shannon(v).toFixed(2)})`);
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
    id: "unpinned-package",
    title: "Package resolved without a version pin",
    severity: "medium",
    detail:
      "npx / bunx / uvx / pnpm dlx / yarn dlx resolve unpinned packages to the latest version at every launch — a renamed or hijacked package (npm or PyPI) runs with your local trust. Pin an exact version (pkg@1.2.3 / pkg==1.2.3).",
    check(server) {
      const raw = [String(server.def.command || ""), ...(server.def.args || []).map(String)];
      const tokens = raw.map((t) => t.trim()).filter(Boolean);
      if (!tokens.length) return [];
      const cmd = tokens[0].toLowerCase();
      const rest = tokens.slice(1);
      const lower = rest.map((t) => t.toLowerCase());

      let pkgTokens = null;
      if (/^(npx|bunx|uvx)$/.test(cmd)) {
        pkgTokens = rest;
      } else if (cmd === "npm" && lower[0] === "exec") {
        pkgTokens = rest.slice(1);
      } else if ((cmd === "pnpm" || cmd === "yarn") && lower[0] === "dlx") {
        pkgTokens = rest.slice(1);
      } else if (cmd === "uv" && lower[0] === "tool" && lower[1] === "run") {
        pkgTokens = rest.slice(2);
      } else if (cmd === "uv" && lower[0] === "run") {
        // uv run --with <pkg> / --from <pkg-spec>：逐个取值判锁版本
        const hits = [];
        for (let i = 0; i < rest.length; i++) {
          if (lower[i] === "--with" || lower[i] === "--from") {
            const val = rest[i + 1];
            if (val && !val.startsWith("-") && isUnpinned(val)) {
              hits.push(`${val} (uv ${lower[i].slice(2)})`);
            }
          }
        }
        return hits;
      }
      if (!pkgTokens) return [];
      const pkg = pkgTokens.find((t) => !t.startsWith("-"));
      if (!pkg || !isUnpinned(pkg)) return [];
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

/** 锁版本判定：末段含 @1.2.3（npm 语义）或 ==1.2.3（PyPI 语义）即视为已锁；@latest/无版本均算未锁 */
function isUnpinned(pkg) {
  const last = String(pkg).split("/").pop();
  return !/(?:@|==)\d/.test(last);
}

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

module.exports = { RULES, DUPLICATE_RULE, WEIGHTS, auditServer, auditAll, sortFindings, scoreFindings, shannon, isUnpinned };
