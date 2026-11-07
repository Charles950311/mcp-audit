/**
 * Tool-description poisoning heuristics (v0.6).
 *
 * Operates on the tools[] captured by --probe (name + description; probe
 * truncates descriptions at 4KB). Tool descriptions are natural language
 * written for the model — there is no good reason for them to carry
 * instruction-override text, invisible Unicode, or callbacks to third-party
 * collectors. Alignment with mcp-scan's disclosed tool-poisoning classes:
 * hidden instructions, invisible characters, and exfil endpoints.
 *
 * Every check fires at most once per (server, tool, category, evidence), so
 * one bad description cannot flood the report.
 */

const SUSPICIOUS_HOSTS = [
  "webhook.site", "requestbin", "pipedream.net", "hookb.in", "interact.sh",
  "oast.", "burpcollaborator", "ngrok", "pastebin.com", "hastebin",
  "discord.com/api/webhooks", "discordapp.com/api/webhooks",
  "hooks.slack.com", "api.telegram.org", "telegra.ph",
];

const INJECTION_RES = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
  /disregard\s+(the\s+)?(above|previous|prior|all)\s+instructions/i,
  /\b(system\s*prompt|<system>|<\/?instructions?_>)/i,
  /you\s+must\s+(now|always|immediately|never|not)\b/i,
  /do\s+not\s+(tell|inform|reveal|mention|disclose)\s+(the\s+)?(user|anyone|model|operator)/i,
  /(exfiltrate|send|upload|post|forward|submit)[^.]{0,40}(secret|token|api[-_ ]?key|credential|password|\.env|clipboard)/i,
  /(read|access|grab|collect|exfiltrate)[^.]{0,30}(\.ssh|\.env|\.aws|\.gitconfig|clipboard|keychain|passwords?|cookies?)/i,
];

const UNICODE_RE = /[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF\u{E0000}-\u{E007F}]/gu;

const DIRECTIVE_RE = /\b(IMPORTANT|ATTENTION|CRITICAL|MANDATORY|URGENT)\b[:!]/g;

const URL_RE = /https?:\/\/[^\s<>"'`)\]}]+/gi;

const POISON_RULES = {
  "tool-description-injection": {
    id: "tool-description-injection",
    title: "Tool description carries instruction-override text",
    severity: "high",
    detail:
      "This tool description contains text that reads like instructions to the agent (prompt injection). A malicious server can steer every agent that connects to it. Remove the tool or treat the server as untrusted.",
  },
  "tool-description-unicode": {
    id: "tool-description-unicode",
    title: "Tool description contains invisible/control Unicode",
    severity: "high",
    detail:
      "Zero-width, bidirectional, or Unicode-tag characters in a tool description are a classic way to hide instructions from the human who approves the tool. Normal descriptions never need them.",
  },
  "tool-description-exfil-url": {
    id: "tool-description-exfil-url",
    title: "Tool description points at a known collector/exfil host",
    severity: "high",
    detail:
      "The description embeds a URL on a host commonly used for data exfiltration (webhook collectors, pastebins, bot APIs). Combined with prompt injection this is a ready-made channel for stolen secrets.",
  },
  "tool-description-external-url": {
    id: "tool-description-external-url",
    title: "Tool description references an unrelated external URL",
    severity: "medium",
    detail:
      "The description embeds a URL on a different host than the server itself. Often a legit docs link — but worth a look, because a description is model-readable text and the URL is a built-in exfil target. Judged by a human, not auto-blocked.",
  },
  "tool-description-imperative": {
    id: "tool-description-imperative",
    title: "Tool description uses imperative directives",
    severity: "medium",
    detail:
      "Multiple ALL-CAPS directive markers (IMPORTANT:/ATTENTION:/CRITICAL:) in one description. Alone this is style, but stacked with other signals it is the usual shell around injected instructions.",
  },
};

function hostOf(u) {
  try {
    return new URL(u).host.toLowerCase();
  } catch {
    return "";
  }
}

function quote(s) {
  return String(s).replace(/\s+/g, " ").trim().slice(0, 100);
}

/** Audit one description; returns [{ ruleId, evidence }] — kept pure for tests. */
function checkDescription(desc, ownHost) {
  const hits = [];
  const text = String(desc || "");
  if (!text.trim()) return hits;

  for (const re of INJECTION_RES) {
    const m = text.match(re);
    if (m) {
      hits.push({ ruleId: "tool-description-injection", evidence: quote(m[0]) });
      break; // one injection hit per tool is enough — they travel in packs anyway
    }
  }

  const unicodes = text.match(UNICODE_RE) || [];
  if (unicodes.length) {
    const cps = [...new Set(unicodes.map((c) => "U+" + c.codePointAt(0).toString(16).toUpperCase()))];
    hits.push({ ruleId: "tool-description-unicode", evidence: cps.join(", ") });
  }

  const seenHosts = new Set();
  for (const u of text.match(URL_RE) || []) {
    const host = hostOf(u);
    if (!host || host === ownHost || seenHosts.has(host)) continue;
    seenHosts.add(host);
    const suspicious = SUSPICIOUS_HOSTS.some((s) => host.includes(s));
    hits.push({
      ruleId: suspicious ? "tool-description-exfil-url" : "tool-description-external-url",
      evidence: quote(u),
    });
  }

  const directives = text.match(DIRECTIVE_RE) || [];
  if (directives.length >= 2) {
    hits.push({
      ruleId: "tool-description-imperative",
      evidence: directives.length + " directive markers (" + [...new Set(directives)].join(" ") + ")",
    });
  }
  return hits;
}

/** Convert probe results into findings (same shape as static rules). */
function poisonFindings(probes) {
  const findings = [];
  const seen = new Set();
  for (const p of probes || []) {
    const ownHost = hostOf(p.url);
    for (const t of p.tools || []) {
      for (const hit of checkDescription(t.description, ownHost)) {
        const key = [p.server, t.name, hit.ruleId, hit.evidence].join("\u0000");
        if (seen.has(key)) continue;
        seen.add(key);
        const rule = POISON_RULES[hit.ruleId];
        findings.push({
          file: p.file,
          server: p.server,
          rule: rule.id,
          severity: rule.severity,
          title: rule.title,
          match: `tool '${t.name}': ${hit.evidence}`,
          detail: rule.detail,
        });
      }
    }
  }
  return findings;
}

module.exports = { POISON_RULES, SUSPICIOUS_HOSTS, checkDescription, poisonFindings };
