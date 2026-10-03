// ============================================================
// PhishNet — Intelligence normalization rules.
//
// Normalization answers one question only: "are these two strings
// the same identifier?" It never answers "are these two people the
// same person?" Entities are linked by correlation with a stated
// confidence, never by string similarity alone.
//
// Every normalized form is stored alongside the original value so
// the source spelling an analyst actually observed is never lost.
// ============================================================

/** Trim, collapse whitespace, and strip zero-width/control characters. */
export function clean(value) {
  return String(value ?? '')
    .replace(/[\u200B-\u200D\uFEFF]/g, '')
    .replace(/[\u0000-\u001F\u007F]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Handles are case-insensitive and ignore padding and separator style. */
export function normalizeHandle(value) {
  return clean(value)
    .toLowerCase()
    .replace(/^@+/, '')
    .replace(/[\s._-]+/g, '');
}

/**
 * PGP fingerprints compare case- and separator-insensitively.
 *
 * A real fingerprint is hex, so separators are removed. A clearly labelled
 * reference (used by synthetic/demo entries, e.g. "TEST-PGP-001") is NOT hex,
 * so its characters must be preserved — stripping non-hex characters would
 * collapse unrelated labels onto the same key.
 */
export function normalizePgp(value) {
  const cleaned = clean(value).toUpperCase();
  if (/^[0-9A-F\s]+$/.test(cleaned)) return cleaned.replace(/[^0-9A-F]/g, '');
  return cleaned.replace(/[^0-9A-Z]/g, '');
}

/** Wallet addresses are case-insensitive; the address is kept verbatim. */
export function normalizeWallet(value) {
  return clean(value).toLowerCase();
}

/** Domains and hosts compare case-insensitively and without a trailing dot. */
export function normalizeHost(value) {
  return clean(value).toLowerCase().replace(/\.+$/, '');
}

/** IPs compare on their canonical form, so IPv4 padding does not fork. */
export function normalizeIp(value) {
  const host = normalizeHost(value);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    return host.split('.').map(part => String(Number(part))).join('.');
  }
  return host;
}

const INFRA_HOSTS = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;

/** Best-effort infrastructure classification. */
export function classifyInfrastructure(value, declaredType) {
  if (declaredType) return String(declaredType).toUpperCase();
  const host = normalizeHost(value);
  if (IPV4.test(host)) return 'IP';
  if (host.startsWith('onion')) return 'ONION';
  if (INFRA_HOSTS.test(host)) return 'DOMAIN';
  return 'DOMAIN';
}

/** The comparison key for infrastructure, scoped by its type. */
export function infrastructureKey(value, type) {
  const normalized = type === 'IP' ? normalizeIp(value) : normalizeHost(value);
  return `${type}:${normalized}`;
}

/** True when the string is structurally valid for the given entity type. */
export function isValidHandle(value) {
  const normalized = normalizeHandle(value);
  return normalized.length >= 2 && normalized.length <= 64 && /^[a-z0-9._-]+$/.test(normalized);
}

export function isValidPgp(value) {
  const raw = clean(value).toUpperCase();
  if (raw.length < 4 || raw.length > 64) return false;
  // Strict path: a real (possibly space-separated) hex fingerprint.
  if (/^[0-9A-F\s]+$/.test(raw)) return normalizePgp(raw).length >= 8;
  // Labelled reference: accepted so synthetic/demo and reference keys are
  // not rejected, but characters are preserved verbatim in normalization.
  return /^[0-9A-Z][0-9A-Z\s._:-]{2,63}$/.test(raw);
}

export function isValidWallet(value) {
  const normalized = normalizeWallet(value);
  return normalized.length >= 6 && normalized.length <= 128 && /^[a-z0-9:_-]+$/.test(normalized);
}

export function isValidHost(value) {
  const host = normalizeHost(value);
  return host.length >= 3 && host.length <= 253 && (INFRA_HOSTS.test(host) || IPV4.test(host));
}

export function isValidEntityId(value) {
  return /^[A-Za-z0-9._:-]{1,64}$/.test(clean(value));
}

/** ISO-8601, or the plain date form the seed data uses. */
export function normalizeTimestamp(value, fallback) {
  const candidate = clean(value);
  if (!candidate) return fallback;
  const parsed = new Date(candidate.length === 10 ? `${candidate}T00:00:00.000Z` : candidate);
  if (Number.isNaN(parsed.getTime())) return fallback;
  return parsed.toISOString();
}

export function now() {
  return new Date().toISOString();
}

/** Clamp to 0..100 so a bad input can never poison a confidence score. */
export function clampConfidence(value, fallback = 50) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.min(100, Math.max(0, numeric));
}

export function toJson(value, fallback) {
  if (value === null || value === undefined) return fallback;
  if (typeof value === 'string') {
    try { return JSON.parse(value); } catch { return fallback; }
  }
  return value;
}

export function toJsonText(value, fallback) {
  return JSON.stringify(toJson(value, fallback));
}

/** Split an analyst's free-text list without inventing structure. */
export function splitList(value) {
  if (Array.isArray(value)) return value.map(clean).filter(Boolean);
  return clean(value)
    .split(/[,\n;]+/)
    .map(item => item.trim())
    .filter(Boolean);
}
