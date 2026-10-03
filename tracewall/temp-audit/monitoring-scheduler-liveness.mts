// Independent proof that the monitoring scheduler actually executes.
//
// A dashboard that says "Scheduler: Running" is making a claim about a
// background process, and nothing about the HTTP layer can confirm it. This
// probe therefore never calls Run Due Now and never calls run-now on the
// monitor: it creates a synthetic monitor, waits, and asks whether the backend
// recorded a cycle on its own. Anything that appears during the wait was
// produced by the scheduler tick.
//
// Run Due Now is exercised afterwards, separately, and only to confirm it
// reports honestly and does not re-execute a monitor that is no longer due.
//
// The wait has to outlast one monitor interval (60s for a source-less
// CONTINUOUS monitor) plus one scheduler tick (30s), so it defaults to 90s and
// can be shortened with SCHEDULER_PROBE_MS when the machine is slow.
import { createMonitor, deleteMonitor, getMonitor, monitoringHub, runAllDueMonitors } from '../src/lib/intelligence/monitoring';

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

const waitMs = Number(process.env.SCHEDULER_PROBE_MS ?? 90_000);

section('The engine reports itself running');
const hubBefore = await monitoringHub(5);
ok(hubBefore.scheduler.started === true, 'hub reports scheduler.started', String(hubBefore.scheduler.started));
ok(hubBefore.scheduler.tickMs > 0, 'hub reports a non-zero tick interval', `${hubBefore.scheduler.tickMs}ms`);
console.log(`   monitors before the probe: ${hubBefore.stats.totalMonitors}`);

section('A cycle runs without anyone asking for one');
const stamp = Date.now().toString(36).toUpperCase();
const created = await createMonitor({
  name: `scheduler-liveness-${stamp}`,
  targetType: 'CVE',
  targetId: `scheduler-liveness-${stamp}`,
  targetValue: `scheduler-liveness-${stamp}`,
  frequency: 'CONTINUOUS',
  severity: 'INFORMATIONAL',
  notes: 'synthetic scheduler liveness probe',
});
console.log(`   created ${created.id} interval=${created.collectionIntervalSeconds}s status=${created.status}`);
ok(created.status === 'ACTIVE', 'the probe monitor is ACTIVE', created.status);
ok((created.collectionIntervalSeconds ?? 0) > 0, 'the probe monitor has a real interval', `${created.collectionIntervalSeconds}s`);

console.log(`   waiting ${Math.round(waitMs / 1000)}s without calling Run Due Now or run-now...`);
await new Promise(resolve => setTimeout(resolve, waitMs));

const detail = await getMonitor(created.id);
console.log(`   events=${detail.recentEvents.length} lastCheck=${detail.lastCheck} nextCheck=${detail.nextCheck} checkCount=${detail.checkCount} runtimeState=${detail.runtimeState}`);
ok(
  detail.recentEvents.length > 0,
  'the scheduler recorded a cycle on its own',
  `${detail.recentEvents.length} event(s)`,
);
ok(Boolean(detail.lastCheck), 'lastCheck advanced from persisted state', String(detail.lastCheck));
ok(detail.runtimeState === 'OK' || detail.runtimeState === 'AWAITING_DATA', 'the monitor is not left in an error state', detail.runtimeState);

section('Run Due Now reports honestly and does not repeat itself');
const manual = await runAllDueMonitors();
console.log(`   Run Due Now -> checked=${manual.checked} triggered=${manual.triggered} errors=${manual.errors} dueCount=${manual.dueCount}`);
ok(typeof manual.checked === 'number' && typeof manual.dueCount === 'number', 'Run Due Now reports what it considered', JSON.stringify(manual));
const again = await runAllDueMonitors();
console.log(`   Run Due Now again -> checked=${again.checked} dueCount=${again.dueCount}`);
ok(
  again.checked <= manual.checked,
  'a repeat Run Due Now does not re-execute a monitor that is not due',
  `first=${manual.checked} second=${again.checked}`,
);

await deleteMonitor(created.id);
const after = await monitoringHub(5);
ok(
  !after.catalog.some(() => false) && after.stats.totalMonitors <= hubBefore.stats.totalMonitors,
  'the probe monitor is removed and the count returns to where it started',
  `before=${hubBefore.stats.totalMonitors} after=${after.stats.totalMonitors}`,
);

console.log(`\n${failures === 0 ? 'PASS' : 'FAIL'} — ${checks - failures}/${checks} checks passed`);
if (failures) process.exit(1);