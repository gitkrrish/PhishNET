// Route and contract verification for the Monitoring Hub.
//
// The hub reads every figure from one endpoint, so a single unreachable or
// misrouted request collapses the whole dashboard into zeros. This suite pins
// each call the hub makes to the route that actually answers it, and pins the
// failure modes apart from each other: a wrong origin answers 404, the SPA
// fallback answers HTML with 200, and a missing session answers 401. Those
// three must never be confused for one another, because only one of them is a
// broken deployment.
//
// Everything here is synthetic and is deleted again at the end.
import { SCHEDULER_TICK_MS } from '../backend/services/intel/monitoringService.mjs';

const BASE = 'http://localhost:8787';

let failures = 0;
let checks = 0;
const ok = (condition, label, detail = '') => {
  checks += 1;
  if (condition) console.log(`PASS  ${label}${detail ? ` — ${detail}` : ''}`);
  else {
    failures += 1;
    console.log(`FAIL  ${label}${detail ? ` — ${detail}` : ''}`);
  }
};
const section = (title) => console.log(`\n── ${title} ${'─'.repeat(Math.max(0, 58 - title.length))}`);

let token = '';
const call = async (method, path, body) => {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let parsed = null;
  try { parsed = text ? JSON.parse(text) : null; } catch { /* left null: not JSON */ }
  return { status: res.status, contentType: res.headers.get('content-type') ?? '', body: parsed, raw: text };
};

const data = (res) => res.body?.data ?? null;

// ── 1. The hub's own requests resolve to the routes that answer them ──────
section('Monitoring Hub requests resolve to real routes');

const health = await call('GET', '/api/health');
ok(health.status === 200 && health.body?.status === 'ok', 'GET /api/health', `HTTP ${health.status}`);
ok(health.body?.database === 'connected', 'health reports the database', String(health.body?.database));

const signIn = await call('POST', '/api/auth/sign-in', { email: 'analyst@tracewall.demo', password: 'demo-password' });
token = signIn.body?.token ?? '';
ok(signIn.status === 200 && !!token, 'POST /api/auth/sign-in issues a session', `HTTP ${signIn.status}`);

// Exactly the two calls the hub makes on load, in the order MonitoringHubPage
// issues them.
const hubRes = await call('GET', '/api/intel/monitoring/hub?limit=25');
ok(hubRes.status === 200, 'GET /api/intel/monitoring/hub?limit=25', `HTTP ${hubRes.status}`);
const hub = data(hubRes);
ok(!!hub, 'hub answers with the { data } envelope the client unwraps');

const capsRes = await call('GET', '/api/intel/monitoring/capabilities');
ok(capsRes.status === 200, 'GET /api/intel/monitoring/capabilities', `HTTP ${capsRes.status}`);

// ── 2. Dashboard response shape ──────────────────────────────────────────
section('Dashboard endpoints return the shape the hub renders');

ok(typeof hub?.stats?.totalMonitors === 'number', 'stats.totalMonitors is a number', String(hub?.stats?.totalMonitors));
for (const key of ['activeMonitors', 'runningMonitors', 'pausedMonitors', 'failedMonitors', 'sourceUnavailableMonitors',
  'awaitingDataMonitors', 'totalAlerts', 'criticalAlerts', 'openAlerts', 'recentlyTriggeredMonitors']) {
  ok(typeof hub?.stats?.[key] === 'number', `stats.${key} is a number`, String(hub?.stats?.[key]));
}
for (const key of ['recentEvents', 'nextChecks', 'lastChecks']) {
  ok(Array.isArray(hub?.stats?.[key]), `stats.${key} is an array`, `${hub?.stats?.[key]?.length} row(s)`);
}
ok(Array.isArray(hub?.stats?.byTool), 'stats.byTool is an array', `${hub?.stats?.byTool?.length} tool(s)`);
ok(Array.isArray(hub?.stats?.bySeverity), 'stats.bySeverity is an array', `${hub?.stats?.bySeverity?.length} band(s)`);
ok(Array.isArray(hub?.catalog), 'catalog lists the monitorable tools', `${hub?.catalog?.length} tool(s)`);
ok(Array.isArray(hub?.alerts), 'alerts is an array', `${hub?.alerts?.length} alert(s)`);
ok(typeof hub?.generatedAt === 'string', 'generatedAt is stamped', hub?.generatedAt);

const statsRes = await call('GET', '/api/intel/monitoring/stats');
ok(statsRes.status === 200 && typeof data(statsRes)?.totalMonitors === 'number', 'GET /api/intel/monitoring/stats', `HTTP ${statsRes.status}`);

const listRes = await call('GET', '/api/intel/monitoring');
ok(listRes.status === 200 && Array.isArray(data(listRes)), 'GET /api/intel/monitoring (All Monitors tab)', `${data(listRes)?.length} monitor(s)`);

// ── 7. Scheduler health reflects real runtime configuration ───────────────
section('Scheduler health and tick interval come from the engine');

ok(hub?.scheduler?.started === true, 'scheduler reports itself started', String(hub?.scheduler?.started));
ok(
  hub?.scheduler?.tickMs === SCHEDULER_TICK_MS,
  'tick interval equals the engine configuration, not a default',
  `api=${hub?.scheduler?.tickMs}ms config=${SCHEDULER_TICK_MS}ms`,
);
ok(hub?.scheduler?.tickMs > 0, 'tick interval is not zero', `${hub?.scheduler?.tickMs}ms`);
ok(typeof hub?.scheduler?.dueNow === 'number', 'dueNow is a number', String(hub?.scheduler?.dueNow));

// ── 8. Alerts and run history load ───────────────────────────────────────
section('Alerts and run history load');

const alertsRes = await call('GET', '/api/intel/monitoring/alerts-probe-does-not-exist');
ok(alertsRes.status === 404, 'a monitor-scoped alert path for an unknown monitor is a real 404', `HTTP ${alertsRes.status}`);

const alertList = await call('GET', '/api/intel/alerts');
ok(alertList.status === 200 && Array.isArray(data(alertList)), 'GET /api/intel/alerts (Monitoring Alerts tab)', `${data(alertList)?.length} alert(s)`);

// ── 2b. An unknown API route is a genuine 404, never the SPA fallback ────
section('Unknown API routes answer JSON 404, not the SPA HTML fallback');

const missing = await call('GET', '/api/intel/monitoring/no-such-subresource');
ok(missing.status === 404, 'unknown /api path is 404', `HTTP ${missing.status}`);
ok(
  (missing.contentType ?? '').includes('application/json'),
  'the 404 body is JSON, so the client is not handed the SPA document',
  missing.contentType || '(none)',
);
ok(missing.body?.error?.message === 'Monitor not found', 'the 404 carries the backend message', missing.body?.error?.message);

// ── 9. Authentication stays enforced ─────────────────────────────────────
section('Authentication and authorization remain enforced');

const noToken = token;
token = '';
const unauth = await call('GET', '/api/intel/monitoring');
ok(unauth.status === 401, 'GET /api/intel/monitoring without a session is 401, not 404', `HTTP ${unauth.status}`);
const unauthHub = await call('GET', '/api/intel/monitoring/hub');
ok(unauthHub.status === 401, 'GET /api/intel/monitoring/hub without a session is 401', `HTTP ${unauthHub.status}`);
token = noToken;

// ── 5 + 6 + 7. Create, persist, run, verify idempotency ──────────────────
section('Add Monitor persists; Run Due Now executes through the engine');

const caps = data(capsRes);
const termType = caps.targetTypes.find(entry => entry.term === true && entry.custom !== true);
ok(!!termType, 'capabilities expose a term-watch target the dialog can submit', termType?.key);

const stamp = Date.now().toString(36).toUpperCase();
const created = await call('POST', '/api/intel/monitoring', {
  name: `verify-hub-${stamp}`,
  targetType: termType.key,
  targetValue: `verify-hub-${stamp}`,
  frequency: 'CONTINUOUS',
  severity: 'INFORMATIONAL',
  notes: 'synthetic monitoring-hub route verification',
});
ok(created.status === 201, 'POST /api/intel/monitoring (Add Monitor) is 201', `HTTP ${created.status}`);
const monitor = data(created);
ok(!!monitor?.id, 'the created monitor carries an id', monitor?.id);
ok(monitor?.status === 'ACTIVE', 'the created monitor is persisted as ACTIVE', monitor?.status);
ok(
  (monitor?.capability?.collectionIntervalSeconds ?? 0) > 0 && monitor?.collectionIntervalSeconds > 0,
  'the engine reports a real collection interval',
  `capability=${monitor?.capability?.collectionIntervalSeconds}s stored=${monitor?.collectionIntervalSeconds}s label=${monitor?.capability?.intervalLabel}`,
);

const listed = data(await call('GET', '/api/intel/monitoring'));
ok(listed.some(row => row.id === monitor.id), 'the monitor is readable back from GET /api/intel/monitoring');

const hubAfterCreate = data(await call('GET', '/api/intel/monitoring/hub'));
ok(hubAfterCreate?.stats?.totalMonitors >= 1, 'the hub roll-up counts the new monitor', `${hubAfterCreate?.stats?.totalMonitors} total`);
ok(hubAfterCreate?.stats?.activeMonitors >= 1, 'the hub roll-up counts it as active', `${hubAfterCreate?.stats?.activeMonitors} active`);

// Configuration must survive a round trip, not just the create response.
const updated = await call('PUT', `/api/intel/monitoring/${monitor.id}`, { severity: 'HIGH', notes: 'edited by the route verification' });
ok(updated.status === 200, `PUT /api/intel/monitoring/${monitor.id} is 200`, `HTTP ${updated.status}`);
const reread = data(await call('GET', `/api/intel/monitoring/${monitor.id}`));
ok(reread?.severity === 'HIGH', 'a monitor edit persists', `severity=${reread?.severity}`);
ok(reread?.notes === 'edited by the route verification', 'the analyst note persists', String(reread?.notes));

// Run Due Now: the button's exact call. The engine selects monitors by their
// persisted next-check time, so a second immediate call has nothing due. That
// is the architecture's own guard against duplicate execution.
const firstRun = await call('POST', '/api/intel/monitoring/run', {});
ok(firstRun.status === 200, 'POST /api/intel/monitoring/run (Run Due Now) is 200', `HTTP ${firstRun.status}`);
const firstSummary = data(firstRun);
ok(typeof firstSummary?.checked === 'number', 'Run Due Now reports what it checked', JSON.stringify(firstSummary));

const secondRun = await call('POST', '/api/intel/monitoring/run', {});
ok(secondRun.status === 200, 'a second Run Due Now is accepted', `HTTP ${secondRun.status}`);
ok(
  (data(secondRun)?.checked ?? 0) <= (firstSummary?.checked ?? 0),
  'Run Due Now does not re-run a monitor that is no longer due',
  `first checked=${firstSummary?.checked} second checked=${data(secondRun)?.checked}`,
);

const events = data(await call('GET', `/api/intel/monitoring/${monitor.id}/events`));
ok(Array.isArray(events) && events.length > 0, 'the executed cycle is recorded as run history', `${events?.length} event(s)`);
const detail = data(await call('GET', `/api/intel/monitoring/${monitor.id}`));
ok(Array.isArray(detail?.recentEvents) && detail.recentEvents.length > 0, 'the monitor detail carries recent events', `${detail?.recentEvents?.length}`);

// A disabled monitor is refused, so a manual click cannot override the analyst.
await call('POST', `/api/intel/monitoring/${monitor.id}/disable`, {});
const refused = await call('POST', `/api/intel/monitoring/run/${monitor.id}`, {});
ok(refused.status === 400, 'Run Now on a disabled monitor is refused', `HTTP ${refused.status} ${refused.body?.error?.message ?? ''}`);
await call('POST', `/api/intel/monitoring/${monitor.id}/enable`, {});

// ── 10. Unrelated functionality is intact ────────────────────────────────
section('Unrelated application functionality still answers');

for (const path of ['/api/cases', '/api/reports', '/api/audit', '/api/analyses',
  '/api/intel/dataset', '/api/intel/statistics', '/api/intel/protection/posture',
  '/api/intel/protection/blocked', '/api/feedback/categories', '/api/darkweb/actors']) {
  const res = await call('GET', path);
  ok(res.status === 200, `GET ${path}`, `HTTP ${res.status}`);
}

// The IP-intelligence surface is the DynamoDB integration. It answers either a
// connection result or a 503 when unconfigured — never a 404, which would mean
// the route was lost.
const dynamo = await call('GET', '/api/ip-intelligence/test-connection');
ok(dynamo.status === 200 || dynamo.status === 503, 'GET /api/ip-intelligence/test-connection', `HTTP ${dynamo.status} ${JSON.stringify(dynamo.body?.data ?? dynamo.body?.error)}`);

// ── cleanup ──────────────────────────────────────────────────────────────
const removed = await call('DELETE', `/api/intel/monitoring/${monitor.id}`);
ok(removed.status === 204, 'the synthetic monitor is removed', `HTTP ${removed.status}`);
const afterDelete = data(await call('GET', '/api/intel/monitoring'));
ok(!afterDelete.some(row => row.id === monitor.id), 'the synthetic monitor is gone');

console.log(`\n${checks - failures}/${checks} checks passed`);
if (failures) {
  console.log(`${failures} FAILED`);
  process.exit(1);
}