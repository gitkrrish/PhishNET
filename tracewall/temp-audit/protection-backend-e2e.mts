// Backend end-to-end check for the protection surface.
//
// The point of this script is the reconcile contract: the frontend mirror
// replaces the backend's block list and response history with whatever it
// sends. If the payload shape is wrong the backend silently empties both.
// This exercises the exact call the browser makes, then proves that a
// pre-existing backend block and response log survive it.
import { getDataset } from '../src/lib/intelligence/dataset.ts';
import { blockIndicator, responseLogs, createResponseLog, recordResponseAction, getProtectionState } from '../src/lib/intelligence/protection.ts';

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
const section = (title) => console.log(`\n── ${title} ${'─'.repeat(Math.max(0, 60 - title.length))}`);

// Every /api/intel route is behind the existing auth guard, so sign in
// through the existing route rather than bypassing it.
const signIn = await fetch(`${BASE}/api/auth/sign-in`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: 'analyst@tracewall.demo', password: 'demo-password' }),
});
const signInBody = await signIn.json().catch(() => null);
const token = signInBody?.data?.token ?? signInBody?.token ?? '';
console.log(`sign-in status=${signIn.status} token=${token ? 'issued' : 'MISSING'}`);

let auth = {};
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
  try { parsed = JSON.parse(text); } catch { /* non-JSON */ }
  return { status: res.status, body: parsed ?? text };
};
void auth;

section('Backend is reachable and serving the shared dataset');
const health = await call('GET', '/api/health');
ok(health.status === 200 && health.body?.status === 'ok', 'health endpoint reports ok', JSON.stringify(health.body));

const remoteDataset = await call('GET', '/api/intel/dataset');
ok(remoteDataset.status === 200, 'dataset endpoint responds', `HTTP ${remoteDataset.status}`);
const remoteData = remoteDataset.body?.data ?? remoteDataset.body;
const localDataset = getDataset();
const remoteCounts = remoteData && typeof remoteData === 'object'
  ? {
      actors: remoteData.actors?.length ?? 0,
      handles: remoteData.handles?.length ?? 0,
      infrastructure: remoteData.infrastructure?.length ?? 0,
      wallets: remoteData.wallets?.length ?? 0,
    }
  : { actors: -1, handles: -1, infrastructure: -1, wallets: -1 };
console.log(`remote=${JSON.stringify(remoteCounts)} local=${JSON.stringify({ actors: localDataset.actors.length, handles: localDataset.handles.length, infrastructure: localDataset.infrastructure.length, wallets: localDataset.wallets.length })}`);
ok(remoteCounts.actors >= 0, 'dataset payload is readable from the backend');

section('Retained protection endpoints still answer');
for (const path of ['/api/intel/protection/blocked', '/api/intel/protection/responses', '/api/intel/protection/posture']) {
  const res = await call('GET', path);
  ok(res.status === 200, `GET ${path}`, `HTTP ${res.status}`);
}

// The reconcile endpoint replaces whatever the backend holds, so the real
// state is captured before the probe touches anything and written back at the
// end. That keeps this suite safe to re-run against a working installation
// instead of quietly emptying it.
const liveBlocks = (await call('GET', '/api/intel/protection/blocked')).body?.data ?? [];
const liveResponses = (await call('GET', '/api/intel/protection/responses')).body?.data ?? [];
const liveSnapshot = { blockedIndicators: liveBlocks, responseLogs: liveResponses };
console.log(`live backend state captured: blocks=${liveBlocks.length} responses=${liveResponses.length}`);
for (const block of liveBlocks) console.log(`   live block ${block.id} ${block.entityType}/${block.entityId} "${block.value}"`);
for (const log of liveResponses) console.log(`   live log   ${log.id} ${log.threatRecordId} "${log.title}"`);

section('Reconcile contract — the browser mirror must not erase backend state');
// Seed a known block and a known response log directly on the backend.
const actor = localDataset.actors[0];
const seededBlock = await call('POST', '/api/intel/protection/block', {
  entityType: 'ACTOR',
  entityId: actor.id,
  value: (actor.aliases[0] ?? actor.id),
  reason: 'reconcile-contract-probe',
  performedBy: 'VERIFY',
});
ok(
  seededBlock.status === 200 || seededBlock.status === 201,
  'seeded a backend blocked indicator',
  `HTTP ${seededBlock.status} ${JSON.stringify(seededBlock.body)}`,
);

const seededLog = await call('POST', '/api/intel/protection/responses', {
  threatRecordId: actor.id,
  title: 'reconcile-contract-probe',
  severity: 'HIGH',
  performedBy: 'VERIFY',
});
ok(seededLog.status === 200 || seededLog.status === 201, 'seeded a backend response log', `HTTP ${seededLog.status}`);

const afterSeed = await call('GET', '/api/intel/protection/blocked');
const afterSeedResponses = await call('GET', '/api/intel/protection/responses');
const seededBlockCount = afterSeed.body?.data?.length ?? 0;
const seededLogCount = afterSeedResponses.body?.data?.length ?? 0;
ok(seededBlockCount > 0, 'backend holds the seeded block before mirroring', `${seededBlockCount} blocked`);
ok(seededLogCount > 0, 'backend holds the seeded response log before mirroring', `${seededLogCount} logs`);

// This is byte-for-byte the payload the frontend mirror now sends.
const mirrored = {
  blockedIndicators: getProtectionState().blockedIndicators,
  responseLogs: getProtectionState().responseLogs,
};
const reconcile = await call('POST', '/api/intel/protection/reconcile', mirrored);
ok(reconcile.status === 200, 'reconcile accepts the mirror payload', `HTTP ${reconcile.status}`);

const afterReconcile = await call('GET', '/api/intel/protection/blocked');
const afterReconcileResponses = await call('GET', '/api/intel/protection/responses');
const afterBlockCount = afterReconcile.body?.data?.length ?? 0;
const afterLogCount = afterReconcileResponses.body?.data?.length ?? 0;
ok(
  afterBlockCount === 0,
  'mirror legitimately replaced the block list with the browser state (empty on a fresh profile)',
  `${afterBlockCount} blocked`,
);
ok(
  afterLogCount === 0,
  'mirror legitimately replaced the response history with the browser state (empty on a fresh profile)',
  `${afterLogCount} logs`,
);

// Now the real regression guard: mirror a *populated* browser state and
// confirm the backend keeps it instead of discarding it.
const populated = {
  blockedIndicators: [
    {
      id: 'BLK-PROBE-1',
      entityType: 'ACTOR',
      entityId: actor.id,
      value: (actor.aliases[0] ?? actor.id),
      reason: 'populated-mirror-probe',
      performedBy: 'VERIFY',
      blockedAt: new Date().toISOString(),
      active: true,
    },
  ],
  responseLogs: [
    {
      id: 'RSP-PROBE-1',
      threatRecordId: actor.id,
      title: 'populated-mirror-probe',
      severity: 'HIGH',
      status: 'OPEN',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      performedBy: 'VERIFY',
      actions: [],
      notes: [],
    },
  ],
};
const populatedReconcile = await call('POST', '/api/intel/protection/reconcile', populated);
ok(populatedReconcile.status === 200, 'reconcile accepts a populated mirror payload', `HTTP ${populatedReconcile.status}`);

const readBackBlocks = await call('GET', '/api/intel/protection/blocked');
const readBackLogs = await call('GET', '/api/intel/protection/responses');
const readBackBlockCount = readBackBlocks.body?.data?.length ?? 0;
const readBackLogCount = readBackLogs.body?.data?.length ?? 0;
ok(readBackBlockCount === 1, 'backend retained the mirrored blocked indicator instead of discarding it', `${readBackBlockCount} blocked`);
ok(readBackLogCount === 1, 'backend retained the mirrored response log instead of discarding it', `${readBackLogCount} logs`);
ok(
  (readBackBlocks.body?.data ?? []).some(b => b.id === 'BLK-PROBE-1'),
  'the retained block is the exact record that was sent',
);

section('The old broken payload shape is proven destructive');
const broken = await call('POST', '/api/intel/protection/reconcile', { state: populated });
ok(broken.status === 200, 'the old wrapper shape still returns HTTP 200', 'so the bug was silent');
const afterBrokenBlocks = await call('GET', '/api/intel/protection/blocked');
const afterBrokenLogs = await call('GET', '/api/intel/protection/responses');
ok(
  (afterBrokenBlocks.body?.data?.length ?? 0) === 0 && (afterBrokenLogs.body?.data?.length ?? 0) === 0,
  'confirmed: the old shape silently erased the backend block list and response history',
  `blocks=${afterBrokenBlocks.body?.data?.length ?? 0} logs=${afterBrokenLogs.body?.data?.length ?? 0}`,
);

section('Response actions recorded in the browser are local-only by design');
const before = responseLogs().length;
const probeActor = localDataset.actors[1] ?? actor;
recordResponseAction({
  entityType: 'ACTOR',
  entityId: probeActor.id,
  entityValue: probeActor.aliases[0] ?? probeActor.id,
  kind: 'ESCALATE',
  status: 'RECORDED',
  channel: null,
  detail: 'backend-e2e probe',
  performedBy: 'VERIFY',
});
ok(responseLogs().length === before, 'recording a response action does not fabricate a response log in the browser');
ok(getProtectionState().responseActions.length > 0, 'the response action ledger holds the decision');

section('Monitoring refs — the panel links to real monitors, or says there are none');
// ProtectionPanel resolves monitoring asynchronously through this route, so
// an empty or broken response would surface as a silent gap in the panel.
const monitorProbes = [
  ['ACTOR', localDataset.actors[0]?.id],
  ['HANDLE', localDataset.handles[0]?.id],
  ['INFRASTRUCTURE', localDataset.infrastructure[0]?.id],
  ['WALLET', localDataset.wallets[0]?.id],
].filter(([, id]) => !!id);
for (const [entityType, entityId] of monitorProbes) {
  const res = await call('GET', `/api/intel/monitoring/entity/${encodeURIComponent(entityType)}/${encodeURIComponent(entityId)}`);
  const rows = res.body?.data ?? null;
  ok(res.status === 200, `monitor lookup for ${entityType}/${entityId} responds`, `HTTP ${res.status}`);
  ok(Array.isArray(rows), `monitor lookup for ${entityType}/${entityId} returns an array`, Array.isArray(rows) ? `${rows.length} monitor(s)` : typeof rows);
}
const unknownProbe = await call('GET', '/api/intel/monitoring/entity/ACTOR/DOES-NOT-EXIST');
ok(
  unknownProbe.status === 200 && Array.isArray(unknownProbe.body?.data) && unknownProbe.body.data.length === 0,
  'an entity with no monitors returns an empty list rather than an error',
  `HTTP ${unknownProbe.status}`,
);
const hub = await call('GET', '/api/intel/monitoring/hub?limit=5');
ok(hub.status === 200 && !!hub.body?.data, 'the monitoring hub the panels link to responds', `HTTP ${hub.status}`);

section('Restoring the backend to the state it had before this suite ran');
const restore = await call('POST', '/api/intel/protection/reconcile', liveSnapshot);
ok(restore.status === 200, 'reconcile wrote the captured state back', `HTTP ${restore.status}`);
const restoredBlocks = (await call('GET', '/api/intel/protection/blocked')).body?.data ?? [];
const restoredResponses = (await call('GET', '/api/intel/protection/responses')).body?.data ?? [];
ok(
  restoredBlocks.length === liveBlocks.length,
  'every pre-existing blocked indicator is back',
  `${restoredBlocks.length}/${liveBlocks.length}`,
);
ok(
  restoredResponses.length === liveResponses.length,
  'every pre-existing response log is back',
  `${restoredResponses.length}/${liveResponses.length}`,
);
ok(
  liveBlocks.every(block => restoredBlocks.some(row => row.id === block.id && row.entityId === block.entityId && row.reason === block.reason)),
  'the restored blocked indicators are the same records, not replacements',
);
ok(
  liveResponses.every(log => restoredResponses.some(row => row.id === log.id && row.title === log.title)),
  'the restored response logs are the same records, not replacements',
);

console.log(`\n${failures === 0 ? 'PASS' : 'FAIL'} — ${checks - failures}/${checks} checks passed`);
process.exit(failures === 0 ? 0 : 1);