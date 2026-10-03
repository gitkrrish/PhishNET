// Temporary: exhaustive backend route audit.
// Hits every registered route with valid and deliberately invalid input and
// records whether each one is reachable, authenticated, validated and
// error-safe. Read-only against the dataset except where noted.
const BASE = 'http://127.0.0.1:8787/api';

const session = await fetch(`${BASE}/auth/sign-in`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: 'analyst@tracewall.demo', password: 'demo-password' }),
}).then(r => r.json());
const auth = { 'Content-Type': 'application/json', Authorization: `Bearer ${session.token}` };

async function call(method, path, body, headers = auth) {
  let response;
  try {
    response = await fetch(`${BASE}${path}`, {
      method,
      headers,
      ...(method === 'GET' || method === 'DELETE' || headers === {} ? {} : { body: JSON.stringify(body ?? {}) }),
    });
  } catch (error) {
    return { status: 0, error: `transport: ${error.message}`, data: undefined, shape: null };
  }
  const text = await response.text();
  let payload = null;
  let parseFailed = false;
  try { payload = text ? JSON.parse(text) : null; } catch { parseFailed = true; }
  const shape = payload && typeof payload === 'object'
    ? Object.keys(payload).sort().join(',')
    : typeof payload;
  return {
    status: response.status,
    data: payload?.data,
    error: payload?.error?.message,
    shape,
    parseFailed,
    bytes: text.length,
  };
}

const rows = [];
const record = (area, method, path, expectation, result) => {
  rows.push({ area, method, path, expectation, status: result.status, error: result.error ?? '', shape: result.shape ?? '' });
};

// ── Public / auth ──────────────────────────────────────────────
record('auth', 'GET', '/health', 'public 200', await call('GET', '/health', null, {}));
record('auth', 'POST', '/auth/sign-in', 'public 200', await call('POST', '/auth/sign-in', { email: 'analyst@tracewall.demo', password: 'demo-password' }, {}));
record('auth', 'POST', '/auth/sign-in', 'bad creds -> 401', await call('POST', '/auth/sign-in', { email: 'analyst@tracewall.demo', password: 'wrong' }, {}));
record('auth', 'POST', '/auth/sign-in', 'missing body -> 4xx', await call('POST', '/auth/sign-in', {}, {}));
record('auth', 'GET', '/cases', 'no token -> 401', await call('GET', '/cases', null, {}));
record('auth', 'GET', '/cases', 'bad token -> 401', await call('GET', '/cases', null, { 'Content-Type': 'application/json', Authorization: 'Bearer nonsense' }));

// ── Analysis ───────────────────────────────────────────────────
record('analysis', 'POST', '/analyze/email', '200/201', await call('POST', '/analyze/email', {
  raw: 'From: attacker@evil.example\r\nTo: victim@corp.example\r\nSubject: Urgent wire transfer\r\n\r\nSend funds to IBAN GB33BUKB20201555555555 today.',
}));
record('analysis', 'POST', '/analyze/email', 'empty -> 4xx', await call('POST', '/analyze/email', {}));
record('analysis', 'POST', '/analyze/url', '200/201', await call('POST', '/analyze/url', { url: 'https://example.com/login' }));
record('analysis', 'POST', '/analyze/url', 'bad url -> 4xx', await call('POST', '/analyze/url', { url: 'not a url' }));
record('analysis', 'POST', '/analyze/file', '200/201', await call('POST', '/analyze/file', { name: 'invoice.pdf', contentType: 'application/pdf', size: 1024, base64: Buffer.from('demo').toString('base64') }));
record('analysis', 'POST', '/analyze/ip', '200/201', await call('POST', '/analyze/ip', { ip: '8.8.8.8' }));
record('analysis', 'POST', '/analyze/ip', 'bad ip -> 4xx', await call('POST', '/analyze/ip', { ip: '999.999.999.999' }));
record('analysis', 'POST', '/analyze/domain', '200/201', await call('POST', '/analyze/domain', { domain: 'example.com' }));
record('analysis', 'POST', '/analyze/domain', 'bad domain -> 4xx', await call('POST', '/analyze/domain', { domain: 'nope' }));
record('analysis', 'POST', '/correlate', '200/201', await call('POST', '/correlate', { indicators: { domains: ['example.com'], ips: ['8.8.8.8'] } }));
record('analysis', 'POST', '/exposure/check', '200/201', await call('POST', '/exposure/check', { target: 'user@corp.example', targetType: 'EMAIL' }));

// ── Cases ──────────────────────────────────────────────────────
record('cases', 'GET', '/cases', '200', await call('GET', '/cases'));
record('cases', 'POST', '/cases', 'missing title -> 4xx', await call('POST', '/cases', { severity: 'HIGH', description: 'x', assignedTo: 'y' }));
record('cases', 'POST', '/cases', 'valid', await call('POST', '/cases', { title: 'AUDIT TEMP CASE', severity: 'HIGH', description: 'backend audit probe', assignedTo: 'Demo Analyst' }));

// ── Alerts (legacy app surface) ─────────────────────────────────
record('alerts', 'GET', '/alerts', '200', await call('GET', '/alerts'));
record('alerts', 'POST', '/alerts/NOPE/acknowledge', 'unknown id -> 4xx', await call('POST', '/alerts/NOPE/acknowledge', {}));

// ── Reports / audit / exposures / analyses ─────────────────────
record('reports', 'GET', '/reports', '200', await call('GET', '/reports'));
record('reports', 'POST', '/reports', 'missing caseId -> 4xx', await call('POST', '/reports', { sections: [] }));
record('audit', 'GET', '/audit', '200', await call('GET', '/audit'));
record('audit', 'POST', '/audit', 'valid', await call('POST', '/audit', { action: 'AUDIT_PROBE', target: 'probe', outcome: 'SUCCESS' }));
record('misc', 'GET', '/exposures', '200', await call('GET', '/exposures'));
record('misc', 'GET', '/analyses', '200', await call('GET', '/analyses'));

// ── Feedback ───────────────────────────────────────────────────
record('feedback', 'GET', '/feedback', '200', await call('GET', '/feedback'));
record('feedback', 'GET', '/feedback/categories', '200', await call('GET', '/feedback/categories'));
record('feedback', 'GET', '/feedback/search?q=test', '200', await call('GET', '/feedback/search?q=test'));
record('feedback', 'GET', '/feedback/knowledge?q=auth', '200', await call('GET', '/feedback/knowledge?q=auth'));
record('feedback', 'POST', '/feedback', 'missing fields -> 4xx', await call('POST', '/feedback', {}));
record('feedback', 'GET', '/feedback/NOPE', 'unknown -> 4xx', await call('GET', '/feedback/NOPE'));

// ── Intel: dataset + sync ──────────────────────────────────────
record('intel', 'GET', '/intel/dataset', '200', await call('GET', '/intel/dataset'));
record('intel', 'GET', '/intel/statistics', '200', await call('GET', '/intel/statistics'));
record('intel', 'GET', '/intel/search?q=actor', '200', await call('GET', '/intel/search?q=actor'));
record('intel', 'GET', '/intel/actors', '200', await call('GET', '/intel/actors'));
record('intel', 'GET', '/intel/actors/NOPE', 'unknown -> 404', await call('GET', '/intel/actors/NOPE'));
record('intel', 'GET', '/intel/handles', '200', await call('GET', '/intel/handles'));
record('intel', 'GET', '/intel/pgp-keys', '200', await call('GET', '/intel/pgp-keys'));
record('intel', 'GET', '/intel/wallets', '200', await call('GET', '/intel/wallets'));
record('intel', 'GET', '/intel/infrastructure', '200', await call('GET', '/intel/infrastructure'));
record('intel', 'GET', '/intel/sources', '200', await call('GET', '/intel/sources'));
record('intel', 'GET', '/intel/observations', '200', await call('GET', '/intel/observations'));
record('intel', 'GET', '/intel/evidence', '200', await call('GET', '/intel/evidence'));
record('intel', 'GET', '/intel/timeline', '200', await call('GET', '/intel/timeline'));
record('intel', 'GET', '/intel/relationships', '200', await call('GET', '/intel/relationships'));
record('intel', 'GET', '/intel/alerts', '200', await call('GET', '/intel/alerts'));
record('intel', 'GET', '/intel/investigations', '200', await call('GET', '/intel/investigations'));
record('intel', 'GET', '/intel/audit', '200', await call('GET', '/intel/audit'));
record('intel', 'GET', '/intel/ingestions', '200', await call('GET', '/intel/ingestions'));
record('intel', 'GET', '/intel/ingestions/NOPE', 'unknown -> 404', await call('GET', '/intel/ingestions/NOPE'));
record('intel', 'POST', '/intel/ingest', 'empty -> 4xx or 201', await call('POST', '/intel/ingest', {}));

// ── Intel: monitoring ──────────────────────────────────────────
record('monitoring', 'GET', '/intel/monitoring', '200', await call('GET', '/intel/monitoring'));
record('monitoring', 'GET', '/intel/monitoring/stats', '200', await call('GET', '/intel/monitoring/stats'));
record('monitoring', 'GET', '/intel/monitoring/capabilities', '200', await call('GET', '/intel/monitoring/capabilities'));
record('monitoring', 'GET', '/intel/monitoring/NOPE', 'unknown -> 404', await call('GET', '/intel/monitoring/NOPE'));
record('monitoring', 'GET', '/intel/monitoring/NOPE/events', 'unknown -> 404', await call('GET', '/intel/monitoring/NOPE/events'));
record('monitoring', 'GET', '/intel/monitoring/NOPE/matches', 'unknown -> 404', await call('GET', '/intel/monitoring/NOPE/matches'));
record('monitoring', 'GET', '/intel/monitoring/NOPE/alerts', 'unknown -> 404', await call('GET', '/intel/monitoring/NOPE/alerts'));
record('monitoring', 'GET', '/intel/monitoring/NOPE/targets', 'unknown -> 404', await call('GET', '/intel/monitoring/NOPE/targets'));
record('monitoring', 'POST', '/intel/monitoring', 'bad targetType -> 4xx', await call('POST', '/intel/monitoring', { targetType: 'NOT_A_TYPE', targetId: 'X', frequency: 'HOURLY', severity: 'MEDIUM' }));
record('monitoring', 'POST', '/intel/monitoring', 'unknown entity -> 4xx', await call('POST', '/intel/monitoring', { targetType: 'ACTOR', targetId: 'DOES-NOT-EXIST', frequency: 'HOURLY', severity: 'MEDIUM' }));
record('monitoring', 'POST', '/intel/monitoring', 'bad severity -> 4xx', await call('POST', '/intel/monitoring', { targetType: 'KEYWORD', targetValue: 'probe', severity: 'EXTREME', frequency: 'HOURLY' }));
record('monitoring', 'POST', '/intel/monitoring', 'bad frequency -> 4xx', await call('POST', '/intel/monitoring', { targetType: 'KEYWORD', targetValue: 'probe', severity: 'LOW', frequency: 'EVERY_NANOSECOND' }));
record('monitoring', 'POST', '/intel/monitoring/run/NOPE', 'unknown -> 4xx', await call('POST', '/intel/monitoring/run/NOPE', {}));
record('monitoring', 'POST', '/intel/monitoring/NOPE/pause', 'unknown -> 4xx', await call('POST', '/intel/monitoring/NOPE/pause', {}));
record('monitoring', 'POST', '/intel/monitoring/NOPE/bogusaction', 'unknown action -> 404', await call('POST', '/intel/monitoring/NOPE/bogusaction', {}));
record('monitoring', 'PUT', '/intel/monitoring/NOPE', 'unknown -> 404', await call('PUT', '/intel/monitoring/NOPE', { severity: 'LOW' }));
record('monitoring', 'DELETE', '/intel/monitoring/NOPE', 'unknown -> 404', await call('DELETE', '/intel/monitoring/NOPE'));
record('monitoring', 'GET', '/intel/monitoring/entity/ACTOR/NOPE', '200 (empty list)', await call('GET', '/intel/monitoring/entity/ACTOR/NOPE'));

// ── Intel: alerts ──────────────────────────────────────────────
record('intel-alerts', 'PATCH', '/intel/alerts/NOPE', 'unknown -> 404', await call('PATCH', '/intel/alerts/NOPE', { status: 'ACKNOWLEDGED' }));
record('intel-alerts', 'PATCH', '/intel/alerts/NOPE', 'bad status -> 400', await call('PATCH', '/intel/alerts/NOPE', { status: 'BOGUS' }));
record('intel-alerts', 'POST', '/intel/alerts/NOPE/investigation', 'unknown -> 4xx', await call('POST', '/intel/alerts/NOPE/investigation', { investigationId: 'NOPE' }));
record('intel-alerts', 'GET', '/intel/alerts/NOPE/explanation', 'unknown -> 404', await call('GET', '/intel/alerts/NOPE/explanation'));

// ── Legacy darkweb projections ──────────────────────────────────
for (const path of [
  '/darkweb/actors', '/darkweb/handles', '/darkweb/relationships', '/darkweb/evidence',
  '/darkweb/timeline', '/darkweb/sources', '/darkweb/monitoring', '/darkweb/reports',
  '/darkweb/confidence', '/darkweb/alerts', '/darkweb/investigations',
  '/darkweb/search?q=lock', '/darkweb/search/pgp?fingerprint=AB', '/darkweb/search/wallet?address=1',
  '/darkweb/search/infrastructure?q=com',
]) record('legacy-darkweb', 'GET', path, '200', await call('GET', path));
record('legacy-darkweb', 'POST', '/darkweb/analyze', '200', await call('POST', '/darkweb/analyze', { actorId: 'ACTOR-001' }));

// ── Unknown route ──────────────────────────────────────────────
record('misc', 'GET', '/definitely/not/a/route', '404', await call('GET', '/definitely/not/a/route'));

console.log(JSON.stringify(rows, null, 0));
process.exit(0);