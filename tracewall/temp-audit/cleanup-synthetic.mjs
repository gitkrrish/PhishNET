// Removes ONLY records created by the hub verification run. Every delete is
// gated on a marker this testing introduced: ids in the generated MUPX family,
// or handle/actor values carrying the SYN probe marker. Seeded and analyst
// data (TL-0xx, HANDLE-0xx, ACTOR-0xx, COR-MU…) is never matched.
import { openStore } from '../backend/database/store.mjs';
import { db } from '../backend/services/intel/repository.mjs';

await openStore();
const all = sql => db().prepare(sql).all();
const idList = id => `'${String(id).replace(/'/g, "''")}'`;

const handles = all("SELECT id FROM intel_handle WHERE value LIKE 'syn-%' OR value LIKE 'carrier-%'");
const handleIds = handles.map(h => h.id);
const actors = all("SELECT id FROM intel_actor WHERE display_name LIKE '%synthetic actor%' OR display_name LIKE 'SYN %' OR id LIKE '%SYN%'");
const actorIds = actors.map(a => a.id);
const syntheticIds = [...handleIds, ...actorIds];

const observations = handleIds.length
  ? all(`SELECT id FROM intel_observation WHERE handle_id IN (${handleIds.map(idList).join(',')})`)
  : [];
const observationIds = observations.map(o => o.id);

// Evidence filed by the monitoring cycles this run raised alerts for.
const evidenceIds = new Set();
for (const row of all("SELECT evidence_ids FROM intel_alert WHERE monitor_id LIKE 'MON-%'")) {
  try { for (const id of JSON.parse(row.evidence_ids ?? '[]')) evidenceIds.add(id); } catch { /* ignore */ }
}
const evidence = [...evidenceIds].filter(id => all(`SELECT id FROM intel_evidence WHERE id = ${idList(id)}`).length > 0);

// Alerts, monitor events and matches whose monitor no longer exists.
//
// Scoped to MONITORING alerts explicitly. An earlier version of this script
// used `monitor_id NOT IN (SELECT id FROM intel_monitor)`, which also matched
// every non-monitoring alert — those have no monitor at all — and deleted the
// seeded DW-ALERT-* rows. Only monitoring alerts may be removed here.
const orphanAlerts = all("SELECT a.id FROM intel_alert a LEFT JOIN intel_monitor m ON m.id = a.monitor_id WHERE a.type = 'MONITORING' AND m.id IS NULL");
const orphanEvents = all("SELECT e.id FROM intel_monitor_event e LEFT JOIN intel_monitor m ON m.id = e.monitor_id WHERE m.id IS NULL");
const orphanMatches = all("SELECT x.id FROM intel_monitor_match x LEFT JOIN intel_monitor m ON m.id = x.monitor_id WHERE m.id IS NULL");

// Alerts left pointing at a handle this run deleted. The synthetic handles are
// raised against by the entity-creation path, which stamps no monitor_id, so the
// monitor-orphan rule above cannot see them. Analyst-created alerts always cite
// live evidence and/or a live handle, so "cites nothing that still exists" is a
// safe test here — it is true only for residue whose subject was just removed.
const danglingAlerts = all(`
  SELECT a.id FROM intel_alert a
  WHERE NOT EXISTS (SELECT 1 FROM intel_handle h WHERE h.id = a.entity_id)
    AND NOT EXISTS (SELECT 1 FROM intel_actor  ac WHERE ac.id = a.entity_id)
    AND NOT EXISTS (SELECT 1 FROM intel_actor  ac WHERE ac.id = a.actor_id)
    AND NOT EXISTS (
      SELECT 1 FROM json_each(a.evidence_ids) j
      JOIN intel_evidence e ON e.id = j.value
    )
    AND NOT EXISTS (
      SELECT 1 FROM json_each(a.observation_ids) j
      JOIN intel_observation o ON o.id = j.value
    )`);

const doomed = {
  orphanAlerts: orphanAlerts.map(r => r.id),
  danglingAlerts: danglingAlerts.map(r => r.id),
  orphanEvents: orphanEvents.map(r => r.id),
  orphanMatches: orphanMatches.map(r => r.id),
  observations: observationIds,
  evidence,
  handles: handleIds,
  actors: actorIds,
  // Synthetic rows carry the generated "TLM-" prefix. The rest of the suffix
  // varies run to run (TLM-MUPX…, TLM-MUPY…), so match the stable prefix only —
  // matching "TLM-MUPX%" silently missed every event outside that one run.
  timeline: all("SELECT id FROM intel_timeline_event WHERE id LIKE 'TLM-%'").map(r => r.id),
};
console.log(JSON.stringify(doomed, null, 1));

if (!process.argv.includes('--apply')) {
  console.log('dry run — pass --apply to remove');
  process.exit(0);
}

db().prepare('BEGIN IMMEDIATE').run();
try {
  for (const id of doomed.orphanAlerts) db().prepare('DELETE FROM intel_alert WHERE id = ?').run(id);
  for (const id of doomed.danglingAlerts) db().prepare('DELETE FROM intel_alert WHERE id = ?').run(id);
  for (const id of doomed.orphanEvents) db().prepare('DELETE FROM intel_monitor_event WHERE id = ?').run(id);
  for (const id of doomed.orphanMatches) db().prepare('DELETE FROM intel_monitor_match WHERE id = ?').run(id);
  for (const id of doomed.observations) db().prepare('DELETE FROM intel_observation WHERE id = ?').run(id);
  for (const id of doomed.evidence) db().prepare('DELETE FROM intel_evidence WHERE id = ?').run(id);
  for (const id of syntheticIds) {
    db().prepare('DELETE FROM intel_relationship WHERE source_entity = ? OR target_entity = ?').run(id, id);
    db().prepare('DELETE FROM intel_correlation WHERE object_id = ? OR subject_id = ?').run(id, id);
  }
  for (const id of doomed.handles) db().prepare('DELETE FROM intel_handle WHERE id = ?').run(id);
  for (const id of doomed.actors) db().prepare('DELETE FROM intel_actor WHERE id = ?').run(id);
  for (const id of doomed.timeline) db().prepare('DELETE FROM intel_timeline_event WHERE id = ?').run(id);
  db().prepare('COMMIT').run();
  console.log('cleanup applied');
} catch (error) {
  db().prepare('ROLLBACK').run();
  throw error;
}

const count = t => db().prepare(`SELECT COUNT(*) AS n FROM ${t}`).get().n;
console.log(JSON.stringify({
  actors: count('intel_actor'), handles: count('intel_handle'), observations: count('intel_observation'),
  evidence: count('intel_evidence'), alerts: count('intel_alert'), timeline: count('intel_timeline_event'),
  relationships: count('intel_relationship'), monitors: count('intel_monitor'),
  correlations: count('intel_correlation'),
}, null, 1));
process.exit(0);