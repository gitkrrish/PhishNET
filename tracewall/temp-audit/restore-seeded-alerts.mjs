// One-time restoration of the five seeded demonstration alerts
// (DW-ALERT-001..005) into intel_alert.
//
// Context: a verification-cleanup script used a LEFT JOIN on intel_monitor to
// find alerts belonging to deleted monitors. Every alert that has no monitor
// at all — which is every non-monitoring alert — matched that predicate and
// was removed. The five seeded alerts were collateral damage. Their exact
// source of truth still exists (backend/database/darkwebSeed.json, mirrored
// in src/data/darkWebData.ts), so they are restored verbatim below.
//
// The three other rows lost in the same sweep were stale MONITORING alerts
// from earlier verification sessions (e.g. ALT-MUP19ZJJ-3, "e2e-verify-marker"),
// whose monitors no longer existed. Those are deliberately NOT recreated.
import { openStore } from '../backend/database/store.mjs';
import { db, listAlerts } from '../backend/services/intel/repository.mjs';
import { loadDataset as loadSeed } from '../backend/services/darkwebService.mjs';

await openStore();

const existing = new Set(listAlerts().map(alert => alert.id));
if (listAlerts().some(alert => alert.id.startsWith('DW-ALERT-'))) {
  console.log('seeded alerts already present — nothing to do');
  process.exit(0);
}

const seed = await loadSeed();
const rows = (seed.alerts || []).map(alert => ({
  id: alert.id,
  type: alert.type,
  severity: alert.severity,
  title: alert.title,
  reason: alert.reason,
  raised_at: alert.timestamp,
  actor_id: alert.actorId ?? null,
  entity_id: alert.actorId ?? null,
  entity_type: alert.actorId ? 'ACTOR' : null,
  evidence_ids: JSON.stringify(alert.evidenceIds || []),
  confidence: alert.confidence ?? 50,
  status: alert.status || 'OPEN',
  dedupe_key: `${alert.type}:${alert.actorId ?? 'global'}`,
  created_at: alert.timestamp,
  updated_at: alert.timestamp,
}));

const insert = db().prepare(`INSERT OR IGNORE INTO intel_alert
  (id, type, severity, title, reason, raised_at, actor_id, entity_id, entity_type,
   evidence_ids, confidence, status, dedupe_key, created_at, updated_at,
   trigger_conditions, observation_ids)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', '[]')`);

db().prepare('BEGIN IMMEDIATE').run();
try {
  for (const row of rows) {
    if (existing.has(row.id)) continue;
    insert.run(
      row.id, row.type, row.severity, row.title, row.reason, row.raised_at,
      row.actor_id, row.entity_id, row.entity_type, row.evidence_ids,
      row.confidence, row.status, row.dedupe_key, row.created_at, row.updated_at,
    );
  }
  db().prepare('COMMIT').run();
  console.log(`restored ${rows.length} seeded alerts`);
} catch (error) {
  db().prepare('ROLLBACK').run();
  throw error;
}

console.log(JSON.stringify(listAlerts().map(alert => ({
  id: alert.id, type: alert.type, severity: alert.severity, status: alert.status, title: alert.title,
})), null, 1));
process.exit(0);

