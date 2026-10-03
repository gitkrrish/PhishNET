// Frontend contract verification for the Monitoring Hub.
//
// Two things are checked here, and neither can be observed from a passing
// build alone:
//
// 1. `request()` — the one place every API call goes through. It must not turn
//    a failed call into a successful-looking one, and it must be able to tell a
//    misrouted origin (404), the SPA fallback (HTML with 200), a missing
//    session (401) and an unreachable host (network) apart. Before the fix, an
//    HTML body was swallowed and returned as `{}`, so a request that never
//    reached the backend looked like an empty success — which is exactly how the
//    hub came to render Total 0 / Active 0 / Scheduler "Stopped" / tick "0s".
//
// 2. The unread-figure helpers. A figure the engine has not answered for must
//    render as unknown, never as a measured zero.
import { request } from '../src/lib/mockBackend';
import { UNREAD, figure, schedulerState, tickLabel } from '../src/lib/intelligence/monitoring';

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

// The module reads a token at import time; a stubbed session keeps these cases
// about the request under test rather than about signing in.
globalThis.window ??= {};
globalThis.sessionStorage ??= { getItem: () => 'test-session-token', setItem: () => {} };

const realFetch = globalThis.fetch;
// The client signs in before its first call, so every case below routes the
// session request to a real 200 and stubs only the call under test. That keeps
// these assertions about the call being examined, not about session handling —
// which the backend suite covers against the real route.
const respondWith = (handler) => {
  globalThis.fetch = async (input, init) => {
    const url = String(input?.url ?? input);
    if (url.includes('/auth/sign-in')) {
      return new Response(JSON.stringify({ token: 'test-session-token', user: { email: 'analyst@tracewall.demo' } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return handler(input, init);
  };
};
const json = (status, payload) => async () => new Response(JSON.stringify(payload), {
  status,
  headers: { 'Content-Type': 'application/json' },
});
const html = (status) => async () => new Response('<!doctype html><html><body><div id="root"></div></body></html>', {
  status,
  headers: { 'Content-Type': 'text/html; charset=utf-8' },
});

let lastUrl = '';
let lastMethod = '';
const record = (handler) => async (input, init) => {
  lastUrl = String(input?.url ?? input);
  lastMethod = init?.method ?? 'GET';
  return handler(input, init);
};
// Stubs every call, including sign-in, for the cases that examine the sign-in
// request itself.
const respondRaw = (handler) => {
  globalThis.fetch = async (input, init) => {
    lastUrl = String(input?.url ?? input);
    lastMethod = init?.method ?? 'GET';
    return handler(input, init);
  };
};

const attempt = async (path, options) => {
  try {
    return { ok: true, value: await request(path, options) };
  } catch (error) {
    return { ok: false, error };
  }
};

// ── successful response ──────────────────────────────────────────────────
section('A successful response is returned as-is');

respondWith(json(200, { data: { scheduler: { started: true, tickMs: 30000, dueNow: 0, nextDueAt: null }, stats: { totalMonitors: 2 } } }));
const success = await attempt('/intel/monitoring/hub?limit=25');
ok(success.ok, 'the hub payload resolves');
ok(success.value?.data?.scheduler?.tickMs === 30000, 'the tick interval reaches the page', String(success.value?.data?.scheduler?.tickMs));

// A 204 carries no body. That is a success, not a parse failure.
respondWith(async () => new Response(null, { status: 204 }));
const deleted = await attempt('/intel/monitoring/MON-1', { method: 'DELETE' });
ok(deleted.ok && deleted.value && typeof deleted.value === 'object', 'a 204 with no body is a success', JSON.stringify(deleted.value));

// ── empty response ───────────────────────────────────────────────────────
section('An empty but valid response is an empty success, not a failure');

respondWith(json(200, { data: [] }));
const empty = await attempt('/intel/monitoring');
ok(empty.ok && Array.isArray(empty.value?.data) && empty.value.data.length === 0, 'an empty monitor list resolves as empty');

// ── misrouted origin ─────────────────────────────────────────────────────
section('A 404 from a wrong origin is reported as a routing failure');

respondWith(record(json(404, { detail: 'Not Found' })));
const notFound = await attempt('/intel/monitoring/hub');
ok(!notFound.ok, 'the 404 throws instead of resolving');
ok(lastUrl.endsWith('/api/intel/monitoring/hub'), 'the request went to the hub path', lastUrl);
ok(lastMethod === 'GET', 'the hub is read with GET', lastMethod);
ok(notFound.error?.status === 404, 'the status is carried on the error', String(notFound.error?.status));
ok(notFound.error?.stage === 'routing', 'the stage is routing', String(notFound.error?.stage));
ok(/GET \/api\/intel\/monitoring\/hub/.test(notFound.error?.message ?? ''), 'the message names the operation', notFound.error?.message);
ok((notFound.error?.message ?? '').includes('HTTP 404'), 'the message carries the status', notFound.error?.message);
// The backend host must not leak into a message the interface renders.
ok(!/https?:\/\//.test(notFound.error?.message ?? ''), 'no upstream host appears in the message');

// ── SPA fallback ─────────────────────────────────────────────────────────
section('An HTML body is a routing failure, never a silent empty success');

respondWith(html(200));
const spa = await attempt('/intel/monitoring/hub');
ok(!spa.ok, 'the HTML 200 throws rather than resolving to {}');
ok(spa.error?.stage === 'routing', 'the stage is routing', String(spa.error?.stage));
ok(/not routed to the API backend/i.test(spa.error?.message ?? ''), 'the message says the request was not routed', spa.error?.message);
ok(!spa.error?.message?.includes('<html'), 'no markup leaks into the message');

// ── the deployed failure, reproduced exactly ──────────────────────────────
// Observed on the live deployment: POST /api/auth/sign-in answered 405 with a
// zero-length body, and GET /api/health answered 200 with the SPA document. The
// API never emits 405 and never answers with anything but JSON, so these are a
// request that never reached it. Reporting the 405 as a rejected method blames
// the wrong component.
section('A method rejection with a non-JSON body is a routing failure, not a contract failure');

respondRaw(async () => new Response(null, { status: 405, statusText: 'Method Not Allowed' }));
const methodRejected = await attempt('/auth/sign-in', { method: 'POST', body: JSON.stringify({ email: 'analyst@tracewall.demo', password: 'demo-password' }) });
ok(!methodRejected.ok, 'the 405 throws');
ok(methodRejected.error?.status === 405, 'the real status is still reported', String(methodRejected.error?.status));
ok(methodRejected.error?.stage === 'routing', 'the stage is routing, not a method contract problem', String(methodRejected.error?.stage));
ok(/not routed to the API backend/i.test(methodRejected.error?.message ?? ''), 'the message names the routing failure', methodRejected.error?.message);
ok(!/does not accept this method/i.test(methodRejected.error?.message ?? ''), 'the message does not blame the API method', methodRejected.error?.message);
ok(lastUrl.endsWith('/api/auth/sign-in') && lastMethod === 'POST', 'the sign-in call itself is correct', `${lastMethod} ${lastUrl}`);

// A 405 that *does* carry JSON is a genuine contract answer and keeps its own
// diagnosis, so the two remain distinguishable.
respondWith(json(405, { error: { message: 'This endpoint accepts GET only' } }));
const contract405 = await attempt('/intel/monitoring/hub');
ok(contract405.error?.message?.includes('accepts GET only'), 'a JSON 405 keeps the backend message', contract405.error?.message);
ok(contract405.error?.stage === 'routing', 'a JSON 405 is still staged as routing', String(contract405.error?.stage));

// An empty 404 has the same signature and the same cause.
respondWith(async () => new Response(null, { status: 404 }));
const emptyNotFound = await attempt('/intel/monitoring/hub');
ok(emptyNotFound.error?.stage === 'routing' && /not routed to the API backend/i.test(emptyNotFound.error?.message ?? ''), 'an empty 404 is reported as routing too', emptyNotFound.error?.message);

// ── authentication ───────────────────────────────────────────────────────
section('A rejected session is reported as an authentication failure');

respondWith(json(401, { error: { message: 'Authentication required' } }));
const unauth = await attempt('/intel/monitoring/hub');
ok(!unauth.ok && unauth.error?.stage === 'authentication', 'a 401 is staged as authentication', String(unauth.error?.stage));
ok(unauth.error?.message?.includes('Authentication required'), 'the backend message is preserved', unauth.error?.message);

respondWith(json(403, { error: { message: 'Insufficient permissions' } }));
const forbidden = await attempt('/intel/protection/block');
ok(!forbidden.ok && forbidden.error?.stage === 'authentication', 'a 403 is staged as authentication', String(forbidden.error?.stage));

// ── server-side failure ──────────────────────────────────────────────────
section('A backend failure is not converted into a success');

respondWith(json(500, { error: { message: 'Monitoring cycle failed' } }));
const broken = await attempt('/intel/monitoring/run', { method: 'POST', body: '{}' });
ok(!broken.ok && broken.error?.status === 500, 'a 500 throws', String(broken.error?.status));
ok(broken.error?.stage === 'validation', 'a 5xx is staged as a request failure the page can report', String(broken.error?.stage));
ok(broken.error?.message?.includes('Monitoring cycle failed'), 'the backend message is preserved', broken.error?.message);

// A validation failure carries the backend's own reason.
respondWith(json(400, { error: { message: 'severity must be one of INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL' } }));
const invalid = await attempt('/intel/monitoring', { method: 'POST', body: '{}' });
ok(!invalid.ok && invalid.error?.status === 400, 'a 400 throws', String(invalid.error?.status));
ok(invalid.error?.stage === 'validation', 'a 400 is staged as validation', String(invalid.error?.stage));
ok(/severity must be one of/.test(invalid.error?.message ?? ''), 'the validation reason reaches the interface', invalid.error?.message);

// ── unreachable host ─────────────────────────────────────────────────────
section('An unreachable backend is a network failure');

respondWith(async () => { throw new TypeError('fetch failed'); });
const offline = await attempt('/intel/monitoring/hub');
ok(!offline.ok, 'an unreachable host throws');
ok(offline.error?.stage === 'network', 'the stage is network', String(offline.error?.stage));
ok(offline.error?.status === 0, 'no status is invented', String(offline.error?.status));
ok(!/fetch failed|ECONNREFUSED|127\.0\.0\.1|localhost/.test(offline.error?.message ?? ''), 'no low-level or host detail leaks', offline.error?.message);

globalThis.fetch = realFetch;

// ── unread figures ───────────────────────────────────────────────────────
section('A figure the engine has not answered for is never a measured zero');

ok(figure(undefined) === UNREAD, 'figure(undefined) is unknown', String(figure(undefined)));
ok(figure(null) === UNREAD, 'figure(null) is unknown', String(figure(null)));
ok(figure(0) === 0, 'figure(0) is a real zero', String(figure(0)));
ok(figure(7) === 7, 'figure(7) is a real count', String(figure(7)));

const unreadScheduler = schedulerState(undefined);
ok(unreadScheduler.label !== 'Running', 'an unread scheduler is never reported Running', unreadScheduler.label);
ok(unreadScheduler.label !== 'Stopped', 'an unread scheduler is never reported Stopped', unreadScheduler.label);
ok(tickLabel(undefined) === UNREAD, 'an unread tick interval is never 0s', String(tickLabel(undefined)));

const running = schedulerState({ started: true, tickMs: 30000 });
ok(running.label === 'Running', 'a started scheduler is reported Running', running.label);
const stopped = schedulerState({ started: false, tickMs: 30000 });
ok(stopped.label === 'Stopped', 'a stopped scheduler is reported Stopped', stopped.label);
ok(tickLabel({ tickMs: 30000 }) === '30s', 'a reported tick interval is formatted from the engine', tickLabel({ tickMs: 30000 }));
ok(tickLabel({ tickMs: 0 }) === '0s', 'a genuinely zero tick interval is shown as measured', tickLabel({ tickMs: 0 }));

console.log(`\n${checks - failures}/${checks} checks passed`);
if (failures) {
  console.log(`${failures} FAILED`);
  process.exit(1);
}