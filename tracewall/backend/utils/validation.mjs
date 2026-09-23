export function requiredString(value, field, max = 5000) {
  if (typeof value !== 'string' || value.trim().length === 0) throw httpError(400, `${field} is required`);
  if (value.length > max) throw httpError(400, `${field} is too long`);
  return value.trim();
}

export function validUrl(value) {
  const input = requiredString(value, 'url', 2048);
  try { return new URL(input).toString(); } catch { throw httpError(400, 'url must be a valid absolute URL'); }
}

export function httpError(status, message) {
  return Object.assign(new Error(message), { status });
}

export function id(prefix) {
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
}
