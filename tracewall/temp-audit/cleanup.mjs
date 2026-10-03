// Temporary: removes audit-probe residue and corrupt records created by
// earlier verification runs, leaving the demo dataset as intended.
const { openStore, getStore, persistStore } = await import('../backend/database/store.mjs');
await openStore();
const { getDatabase } = await import('../backend/database/store.mjs');
const db = getDatabase();
const run = sql => db.prepare(sql).run();

const store = getStore();

// 1. Alert fabricated by the old updateAlert bug.
const before = store.alerts.map(a => a.id);
store.alerts = store.alerts.filter(a => a.id !== 'NOPE');
// 2. Audit entries written by the route probe.
store.audit = store.audit.filter(e => e.action !== 'AUDIT_PROBE');
// 3. Case created by the route probe.
store.cases = store.cases.filter(c => c.title !== 'AUDIT TEMP CASE');

await persistStore();

// 4. Corrupt source rows created by a malformed ingest probe.
run("DELETE FROM intel_source WHERE name = '[object Object]'");

// 5. Monitoring probes.
run('DELETE FROM intel_monitor_match');
run('DELETE FROM intel_monitor_event');
run('DELETE FROM intel_monitor_target');
run('DELETE FROM intel_monitor');
run("DELETE FROM intel_alert WHERE type = 'MONITORING'");

// 6. Synthetic E2E records from earlier verification.
run("DELETE FROM intel_observation WHERE observation_type = 'VULNERABILITY_MENTION'");
run("DELETE FROM intel_observation WHERE content LIKE '%CVE-2026-31337%'");
run("DELETE FROM intel_timeline_event WHERE analyst = 'smoke-test' OR analyst = 'monitoring-service'");
run("DELETE FROM intel_evidence WHERE provenance LIKE '24x7_monitoring%'");
run("DELETE FROM intel_audit WHERE source = '24x7 monitoring cycle'");
run("DELETE FROM intel_ingest_log WHERE analyst IN ('smoke-test','verify')");
run("DELETE FROM intel_actor WHERE id LIKE 'ACTOR-TEST%'");
run("DELETE FROM intel_timeline_event WHERE actor_id LIKE 'ACTOR-TEST%'");

console.log('alerts before:', before.join(', '));
console.log('alerts after: ', getStore().alerts.map(a => `${a.id}(${a.status ?? '-'})`).join(', '));
console.log('cases:', getStore().cases.map(c => c.id).join(', '));
console.log('audit entries:', getStore().audit.length);
console.log('sources:', db.prepare('SELECT count(*) AS n FROM intel_source').get().n);
console.log('monitors:', db.prepare('SELECT count(*) AS n FROM intel_monitor').get().n);
console.log('observations:', db.prepare('SELECT count(*) AS n FROM intel_observation').get().n);
process.exit(0);