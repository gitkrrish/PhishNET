import { openStore } from '../backend/database/store.mjs';
import { db } from '../backend/services/intel/repository.mjs';

await openStore();
const all = sql => db().prepare(sql).all();
console.log('audit actions that pair with an alert:');
for (const row of all("SELECT occurred_at, actor, action, entity, entity_id, after FROM intel_audit WHERE action IN ('HANDLE_ADDED','ACTOR_ADDED','CORRELATION_CREATED','PGP_ADDED','WALLET_ADDED') ORDER BY occurred_at")) {
  console.log(JSON.stringify(row));
}
console.log('\ncorrelations:');
for (const row of all('SELECT * FROM intel_correlation')) console.log(JSON.stringify(row));
console.log('\ninvestigations referencing alerts:');
for (const row of all('SELECT id, title FROM intel_investigation')) console.log(JSON.stringify(row));
process.exit(0);