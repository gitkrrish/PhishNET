// Sensitive-information detection & redaction for AI Feedback submissions.
//
// User feedback is treated as UNTRUSTED DATA. Before any submission is
// stored — and long before it could reach another user or the AI knowledge
// store — free-text fields are scanned for credentials, tokens, API keys,
// payment data and personally identifiable information (PII). Sensitive
// values are replaced with a safe placeholder so that:
//   - raw secrets are never persisted to disk
//   - other users never see another person's private data
//   - the AI never ingests secrets into its knowledge store
//
// Each rule carries a `name` so the resulting redactionReport lists exactly
// what was found and how many times.

const REDACTED = '[REDACTED]';

// ── Helpers ─────────────────────────────────────────────────────────

// Luhn validity check for credit-card-like number runs.
function passesLuhn(digits) {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0 && sum >= 10;
}

// ── Redaction rules ─────────────────────────────────────────────────
// Order matters: most-specific patterns first so a private key block is
// matched before its inner tokens are considered individually.

const SECRET_PATTERNS = [
  {
    name: 'private_key',
    pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
    replace: REDACTED,
  },
  {
    name: 'aws_access_key_id',
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    replace: REDACTED,
  },
  {
    name: 'aws_secret_key',
    pattern: /((?:aws_)?secret_?access_?key|aws_secret_access_key|secret_?key|secretAccessKeys?|access_?key_?secret)\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}['"]?/gi,
    replace: '$1 ' + REDACTED,
  },
  {
    name: 'generic_api_key',
    pattern: /(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|bearer|token[_-]?secret|private[_-]?key)\s*[:=]\s*['"]([A-Za-z0-9_-]{16,})['"]/gi,
    replace: '$1 ' + REDACTED,
  },
  {
    name: 'bearer_token',
    pattern: /\bBearer\s+[A-Za-z0-9\-._~+/]+=?/gi,
    replace: 'Bearer ' + REDACTED,
  },
  {
    name: 'authorization_header',
    pattern: /(Authorization|Proxy-Authorization)\s*:\s*Basic\s+[A-Za-z0-9+/=]+/gi,
    replace: '$1: Basic ' + REDACTED,
  },
  {
    name: 'session_cookie',
    pattern: /(session[_-]?id|sessionid|sid|auth[_-]?token|access[_-]?token|refresh[_-]?token|jwt)\s*[:=;]\s*['"]?[A-Za-z0-9\-._~+/]+['"]?/gi,
    replace: '$1 ' + REDACTED,
  },
  {
    name: 'github_token',
    pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g,
    replace: REDACTED,
  },
  {
    name: 'google_api_key',
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    replace: REDACTED,
  },
  {
    name: 'slack_token',
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}/gi,
    replace: REDACTED,
  },
  {
    name: 'password_assignment',
    pattern: /((?:my\s+)?(?:password|passwd|pwd)\s*(?:was|is|[:=])\s*)(['"]?)([^\s'",.;!?]{4,})\2/gi,
    replace: (match, prefix, quote, value) => {
      // Avoid redacting benign prose such as "password is required".
      const benign = /^(required|correct|wrong|weak|strong|different|changed|reset|same|long|short|complex|easy|set|good|bad|simple|unique|valid|invalid|expired|unknown|hidden|shown|sent|received|asked|needed|missing|secure|new|old|current|default)$/i;
      if (benign.test(value)) return match;
      return `${prefix}${REDACTED}`;
    },
  },
  {
    name: 'credit_card',
    pattern: /\b(?:\d[ -]*?){13,19}\b/g,
    replace: (match) => {
      const digits = match.replace(/\D/g, '');
      if (digits.length >= 13 && digits.length <= 19 && passesLuhn(digits)) {
        return REDACTED;
      }
      return match;
    },
  },
  {
    name: 'ssn',
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
    replace: REDACTED,
  },
  {
    name: 'phone_number',
    pattern: /(?<![\d.])(?:\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?![\d.])/g,
    replace: REDACTED,
  },
  {
    name: 'email',
    pattern: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
    replace: REDACTED,
  },
];

// HTML escape for any text rendered back to the browser. Defence-in-depth
// against stored XSS — user content is never inserted as raw HTML.
const HTML_ESCAPE_MAP = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

export function escapeHtml(text) {
  if (typeof text !== 'string') return '';
  return text.replace(/[&<>"']/g, (ch) => HTML_ESCAPE_MAP[ch]);
}

// Returns the redacted string and a report of what was removed.
export function redactSensitive(text) {
  if (typeof text !== 'string') return { redacted: '', report: [] };
  const report = [];
  let redacted = text;

  for (const rule of SECRET_PATTERNS) {
    const matches = redacted.match(rule.pattern);
    if (!matches || matches.length === 0) continue;
    let replacedCount = 0;
    if (typeof rule.replace === 'function') {
      redacted = redacted.replace(rule.pattern, (...args) => {
        const out = rule.replace(...args);
        if (out !== args[0]) replacedCount += 1;
        return out;
      });
    } else {
      replacedCount = matches.length;
      redacted = redacted.replace(rule.pattern, rule.replace);
    }
    if (replacedCount > 0) report.push({ name: rule.name, count: replacedCount });
  }

  return { redacted, report };
}

// Redact a whole submission object. Returns { sanitized, redactionReport }.
// Operates on every string field so indicators that are legitimately IPs /
// domains are untouched (they are NOT in SECRET_PATTERNS), while emails,
// phone numbers, keys and cards are scrubbed.
export function sanitizeSubmission(raw) {
  const redactionReport = [];
  const sanitized = {};

  function walk(value, key) {
    if (value === null || value === undefined) return value;
    if (typeof value === 'string') {
      const { redacted, report } = redactSensitive(value);
      if (report.length) {
        redactionReport.push({ field: key, findings: report });
      }
      return redacted;
    }
    if (Array.isArray(value)) return value.map((item, i) => walk(item, `${key}[${i}]`));
    if (typeof value === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(value)) out[k] = walk(v, k);
      return out;
    }
    return value;
  }

  for (const [key, value] of Object.entries(raw)) {
    sanitized[key] = walk(value, key);
  }

  return { sanitized, redactionReport: redactionReport.length ? redactionReport : [] };
}
