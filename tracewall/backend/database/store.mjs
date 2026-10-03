import { DatabaseSync } from 'node:sqlite';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { config } from '../config/env.mjs';
import { ensureIntelligenceSchema } from './intelligenceSchema.mjs';

let database;
let sqlDatabase;
let writeQueue = Promise.resolve();

export async function openStore() {
  await mkdir(dirname(config.databaseFile), { recursive: true });
  sqlDatabase = new DatabaseSync(config.databaseFile);
  sqlDatabase.exec('CREATE TABLE IF NOT EXISTS app_state (id INTEGER PRIMARY KEY CHECK (id = 1), state_json TEXT NOT NULL)');
  const row = sqlDatabase.prepare('SELECT state_json FROM app_state WHERE id = 1').get();
  database = row ? JSON.parse(row.state_json) : JSON.parse(await readFile(config.recoveryFile, 'utf8'));
  if (!row) sqlDatabase.prepare('INSERT INTO app_state (id, state_json) VALUES (1, ?)').run(JSON.stringify(database));
  // Normalized Dark Web Intelligence tables. Additive only: the app_state row
  // above is untouched, and the schema is created only if absent.
  ensureIntelligenceSchema(sqlDatabase);
  await ensureAppSeed();
}

/**
 * Seed the app-level collections the backend owns but that were never
 * populated: alerts and exposures.
 *
 * Every other app-level collection (analyses, cases, reports, feedback) is
 * already stored here, which left the alert console reading fixture data from
 * the browser while its write endpoints persisted into this document. Seeding
 * the same demo scenario once means GET /alerts returns real stored rows that
 * the action endpoints can then update and audit.
 *
 * Additive only: existing rows are never overwritten, and clearing the store
 * does not lose the demo dataset.
 */
async function ensureAppSeed() {
  let changed = false;
  try {
    const seed = JSON.parse(await readFile(join(dirname(config.databaseFile), 'appSeed.json'), 'utf8'));
    for (const collection of ['alerts', 'exposures']) {
      if (!Array.isArray(database[collection])) {
        database[collection] = [];
        changed = true;
      }
      for (const record of seed[collection] ?? []) {
        const exists = database[collection].some(item => item.id === record.id);
        if (!exists) { database[collection].push(record); changed = true; }
      }
    }
  } catch {
    // A missing or unreadable seed must never stop the API from starting.
  }
  if (changed) {
    sqlDatabase.prepare('INSERT INTO app_state (id, state_json) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET state_json = excluded.state_json').run(JSON.stringify(database));
  }
}

/**
 * The live SQLite connection. Used by the normalized intelligence tables;
 * the legacy `app_state` document keeps using getStore()/persistStore().
 */
export function getDatabase() {
  if (!sqlDatabase) throw new Error('Database is not connected');
  return sqlDatabase;
}

export function getStore() {
  if (!database || !sqlDatabase) throw new Error('Database is not connected');
  return database;
}

export function persistStore() {
  writeQueue = writeQueue.then(async () => {
    sqlDatabase.prepare('INSERT INTO app_state (id, state_json) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET state_json = excluded.state_json').run(JSON.stringify(database));
    const temporaryFile = `${config.recoveryFile}.tmp`;
    await writeFile(temporaryFile, JSON.stringify(database, null, 2));
    await rename(temporaryFile, config.recoveryFile);
  });
  return writeQueue;
}

export function databaseStatus() {
  sqlDatabase.prepare('SELECT 1 AS connected').get();
  return 'connected';
}
