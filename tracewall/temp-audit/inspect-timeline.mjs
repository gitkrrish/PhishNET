// Read-only: shows every timeline row whose id carries the synthetic TLM-
// prefix, so cleanup coverage can be checked without mutating anything.
import { openStore } from '../backend/database/store.mjs';
import { db } from '../backend/services/intel/repository.mjs';

await openStore();
const d = db();
const rows = d.prepare(
  `SELECT id, occurred_at, event_type, title
     FROM intel_timeline_event
    WHERE id LIKE 'TLM-%'
    ORDER BY occurred_at`,
).all();
for (const row of rows) console.log(`${row.occurred_at}  ${row.id}  ${row.event_type}  | ${(row.title ?? '').slice(0, 70)}`);
console.log(`\n${rows.length} synthetic timeline event(s)`);
process.exit(0);