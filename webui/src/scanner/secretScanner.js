'use strict';

/**
 * Inline secret scanner. Given the text of a retrieved file, find likely
 * secrets (API keys, tokens, credentials, private keys) and return structured
 * findings. Patterns favour high-signal, well-known token shapes to keep the
 * false-positive rate manageable, plus a few generic assignment heuristics.
 */

/**
 * @typedef {Object} SecretRule
 * @property {string} id       stable identifier
 * @property {string} name     human friendly label
 * @property {'critical'|'high'|'medium'|'low'} severity
 * @property {RegExp} regex    global regex; capture group 1 (if present) is the
 *                             value that gets redacted for display
 */

/** @type {SecretRule[]} */
const RULES = [
  {
    id: 'private-key',
    name: 'Private key (PEM)',
    severity: 'critical',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
  },
  {
    id: 'aws-access-key-id',
    name: 'AWS Access Key ID',
    severity: 'critical',
    regex: /\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16})\b/g,
  },
  {
    id: 'aws-secret-access-key',
    name: 'AWS Secret Access Key',
    severity: 'critical',
    regex:
      /aws_secret_access_key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
  },
  {
    id: 'gcp-api-key',
    name: 'Google API Key',
    severity: 'high',
    regex: /\b(AIza[0-9A-Za-z\-_]{35})\b/g,
  },
  {
    id: 'github-token',
    name: 'GitHub Token',
    severity: 'critical',
    regex: /\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,255})\b/g,
  },
  {
    id: 'gitlab-token',
    name: 'GitLab Personal Access Token',
    severity: 'high',
    regex: /\b(glpat-[0-9A-Za-z\-_]{20,})\b/g,
  },
  {
    id: 'slack-token',
    name: 'Slack Token',
    severity: 'high',
    regex: /\b(xox[baprs]-[0-9A-Za-z-]{10,})\b/g,
  },
  {
    id: 'slack-webhook',
    name: 'Slack Webhook URL',
    severity: 'medium',
    regex:
      /(https:\/\/hooks\.slack\.com\/services\/T[0-9A-Za-z_]+\/B[0-9A-Za-z_]+\/[0-9A-Za-z_]+)/g,
  },
  {
    id: 'stripe-key',
    name: 'Stripe Secret Key',
    severity: 'critical',
    regex: /\b((?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,})\b/g,
  },
  {
    id: 'openai-key',
    name: 'OpenAI API Key',
    severity: 'high',
    regex: /\b(sk-(?:proj-)?[0-9A-Za-z\-_]{20,})\b/g,
  },
  {
    id: 'twilio-key',
    name: 'Twilio Account SID',
    severity: 'medium',
    regex: /\b(AC[0-9a-fA-F]{32})\b/g,
  },
  {
    id: 'sendgrid-key',
    name: 'SendGrid API Key',
    severity: 'high',
    regex: /\b(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})\b/g,
  },
  {
    id: 'jwt',
    name: 'JSON Web Token',
    severity: 'medium',
    regex: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
  },
  {
    id: 'db-connection-string',
    name: 'Database Connection String',
    severity: 'high',
    regex:
      /\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s"'<>]+:[^\s"'<>]+@[^\s"'<>]+)/gi,
  },
  {
    id: 'generic-api-key',
    name: 'Generic API Key / Secret assignment',
    severity: 'medium',
    regex:
      /(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*["']([^"'\s]{12,})["']/gi,
  },
  {
    id: 'generic-password',
    name: 'Hardcoded password',
    severity: 'medium',
    regex: /(?:password|passwd|pwd)\s*[:=]\s*["']([^"'\s]{6,})["']/gi,
  },
];

const REDACT_KEEP = 4;

function redact(value) {
  if (!value) return '';
  const v = String(value);
  if (v.length <= REDACT_KEEP * 2) {
    return `${v.slice(0, 2)}${'*'.repeat(Math.max(1, v.length - 2))}`;
  }
  return `${v.slice(0, REDACT_KEEP)}${'*'.repeat(8)}${v.slice(-REDACT_KEEP)}`;
}

function lineNumberOf(content, index) {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content[i] === '\n') line++;
  }
  return line;
}

/**
 * Scan file content for secrets.
 * @param {string} content
 * @returns {Array<{ruleId,name,severity,match,redacted,line}>}
 */
function scanContent(content) {
  if (typeof content !== 'string' || content.length === 0) return [];
  const findings = [];
  const seen = new Set();

  for (const rule of RULES) {
    rule.regex.lastIndex = 0;
    let m;
    while ((m = rule.regex.exec(content)) !== null) {
      // Guard against zero-width matches causing an infinite loop.
      if (m.index === rule.regex.lastIndex) rule.regex.lastIndex++;
      const value = m[1] !== undefined ? m[1] : m[0];
      const dedupeKey = `${rule.id}:${value}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);
      findings.push({
        ruleId: rule.id,
        name: rule.name,
        severity: rule.severity,
        redacted: redact(value),
        line: lineNumberOf(content, m.index),
      });
    }
  }
  return findings;
}

module.exports = { scanContent, RULES, redact };
