// Temporary: renders the route-audit JSON as a readable table.
import { readFileSync } from 'node:fs';

const raw = readFileSync(new URL('./routes-out.json', import.meta.url), 'utf8');
const rows = JSON.parse(raw.replace(/^\uFEFF/, '').trim());

const pad = (value, width) => String(value ?? '').padEnd(width).slice(0, width);
let lastArea = '';
const problems = [];

for (const row of rows) {
  if (row.area !== lastArea) {
    console.log(`\n=== ${row.area.toUpperCase()} ===`);
    lastArea = row.area;
  }
  const status = row.status;
  // A row is a finding when the observed status contradicts its expectation.
  const expectFail = /\b4xx\b|\b404\b|\b400\b|401/.test(row.expectation);
  const bad = expectFail ? !(status >= 400 && status < 500) : !(status >= 200 && status < 300);
  if (bad) problems.push(row);
  console.log(
    `${bad ? '!!' : '  '} ${pad(row.method, 6)} ${pad(row.path, 46)} -> ${pad(status, 5)} (${row.expectation})` +
    (row.error ? `  err="${String(row.error).slice(0, 70)}"` : ''),
  );
}

console.log(`\nTOTAL ${rows.length} probes, ${problems.length} contradicting expectations`);
if (problems.length) {
  console.log('\nFINDINGS:');
  for (const p of problems) console.log(`  ${p.method} ${p.path} -> ${p.status} (expected ${p.expectation}) ${p.error ?? ''}`);
}