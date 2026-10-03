import { openStore } from '../backend/database/store.mjs';
import { db } from '../backend/services/intel/repository.mjs';

await openStore();
const all = sql => db().prepare(sql).all();
console.log('intel_alert columns:', db().prepare('PRAGMA table_info(intel_alert)').all().map(c => `${c.name}${c.notnull ? '*' : ''}`).join(', '));
console.log('\ncurrent intel_alert rows:', all('SELECT id FROM intel_alert').length);
console.log('\naudit columns:', db().prepare('PRAGMA table_info(intel_audit)').all().map(c => c.name).join(', '));
console.log('\naudit actions containing ALERT:');
for (const row of all("SELECT * FROM intel_audit WHERE action LIKE '%ALERT%' ORDER BY occurred_at")) {
  console.log(JSON.stringify(row));
}
process.exit(0);
