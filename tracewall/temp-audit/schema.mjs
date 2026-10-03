// Temporary: database schema inventory for the backend audit.
const { openStore, getDatabase } = await import('../backend/database/store.mjs');
await openStore();
const db = getDatabase();

const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all().map(r => r.name);
console.log(`TABLES (${tables.length}):`);
console.log(tables.map(t => '  ' + t).join('\n'));

const idx = db.prepare("SELECT count() AS c FROM sqlite_master WHERE type='index'").get();
const fks = db.prepare("SELECT count() AS c FROM sqlite_master WHERE type='table'").get();
console.log(`\nindexes: ${idx.c}   tables: ${fks.c}`);

console.log('\nCOLUMNS PER TABLE:');
for (const t of tables) {
  const cols = db.prepare(`PRAGMA table_info(${t})`).all().map(c => c.name);
  const count = db.prepare(`SELECT count(*) AS n FROM ${t}`).get().n;
  console.log(`  ${t} [${count} rows]: ${cols.join(', ')}`);
}

console.log('\nFOREIGN KEYS:');
let fkCount = 0;
for (const t of tables) {
  const fks = db.prepare(`PRAGMA foreign_key_list(${t})`).all();
  for (const fk of fks) {
    fkCount++;
    console.log(`  ${t}.${fk.from} -> ${fk.table}.${fk.to}`);
  }
}
console.log(fkCount ? `(${fkCount} foreign keys)` : '  (none declared)');
process.exit(0);