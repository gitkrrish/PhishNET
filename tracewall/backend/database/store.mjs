import { DatabaseSync } from 'node:sqlite';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { config } from '../config/env.mjs';

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
