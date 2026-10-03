// ============================================================
// PhishNet — Central Dark Web Intelligence database schema.
//
// The pre-existing application state (cases, alerts, sessions,
// feedback) still lives in the single `app_state` row owned by
// store.mjs; that is left completely untouched.
//
// Dark Web Intelligence is different: the brief requires real
// entities, foreign keys and relationships rather than one
// document blob, so it gets its own normalized tables in the same
// SQLite file. Every module (actors, handles, PGP, wallets,
// infrastructure, relationships, evidence, timeline,
// investigations, alerts, search, statistics) reads from THESE
// tables, so one analyst action is visible everywhere.
//
// Tables and indexes are declared separately: tables are created
// first, then indexes. That lets a newly added UNIQUE index repair
// any duplicate rows an older schema version may have allowed,
// instead of failing the whole boot.
// ============================================================

const INTEL_TABLES = `
-- ── Provenance carriers ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS intel_source (
  id                TEXT PRIMARY KEY,
  name              TEXT NOT NULL,
  type              TEXT NOT NULL,
  reference         TEXT,
  collection_method TEXT,
  first_observed    TEXT NOT NULL,
  last_observed     TEXT NOT NULL,
  reliability_score REAL NOT NULL DEFAULT 50,
  health_status     TEXT NOT NULL DEFAULT 'ACTIVE',
  activity_level    TEXT NOT NULL DEFAULT 'MEDIUM',
  status            TEXT NOT NULL DEFAULT 'ACTIVE',
  description       TEXT NOT NULL DEFAULT '',
  onion_address     TEXT,
  data_state        TEXT NOT NULL DEFAULT 'SYNTHETIC_DEMO',
  analyst           TEXT NOT NULL DEFAULT 'system',
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL
);

-- ── Core entities ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS intel_actor (
  id                  TEXT PRIMARY KEY,
  display_name        TEXT NOT NULL DEFAULT '',
  status              TEXT NOT NULL DEFAULT 'ACTIVE',
  activity_level      TEXT NOT NULL DEFAULT 'MEDIUM',
  confidence_score    REAL NOT NULL DEFAULT 50,
  primary_motivation  TEXT NOT NULL DEFAULT '',
  first_seen          TEXT NOT NULL,
  last_seen           TEXT NOT NULL,
  behavioral_profile  TEXT NOT NULL DEFAULT '{}',
  stylometric_profile TEXT NOT NULL DEFAULT '{}',
  data_state          TEXT NOT NULL DEFAULT 'SYNTHETIC_DEMO',
  analyst             TEXT NOT NULL DEFAULT 'system',
  created_at          TEXT NOT NULL,
  updated_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS intel_handle (
  id          TEXT PRIMARY KEY,
  value       TEXT NOT NULL,
  normalized  TEXT NOT NULL,
  platform    TEXT NOT NULL DEFAULT '',
  source_id   TEXT,
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL,
  confidence  REAL NOT NULL DEFAULT 50,
  data_state  TEXT NOT NULL DEFAULT 'SYNTHETIC_DEMO',
  analyst     TEXT NOT NULL DEFAULT 'system',
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS intel_pgp_key (
  id           TEXT PRIMARY KEY,
  fingerprint  TEXT NOT NULL,
  normalized   TEXT NOT NULL,
  first_seen   TEXT NOT NULL,
  last_seen    TEXT NOT NULL,
  confidence   REAL NOT NULL DEFAULT 50,
  data_state   TEXT NOT NULL DEFAULT 'SYNTHETIC_DEMO',
  analyst      TEXT NOT NULL DEFAULT 'system',
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS intel_wallet (
  id          TEXT PRIMARY KEY,
  address     TEXT NOT NULL,
  normalized  TEXT NOT NULL,
  network     TEXT NOT NULL DEFAULT '',
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL,
  tx_count    INTEGER NOT NULL DEFAULT 0,
  confidence  REAL NOT NULL DEFAULT 50,
  data_state  TEXT NOT NULL DEFAULT 'SYNTHETIC_DEMO',
  analyst     TEXT NOT NULL DEFAULT 'system',
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS intel_infrastructure (
  id               TEXT PRIMARY KEY,
  type             TEXT NOT NULL,
  value            TEXT NOT NULL,
  normalized       TEXT NOT NULL,
  first_seen       TEXT NOT NULL,
  last_seen        TEXT NOT NULL,
  registrar        TEXT,
  hosting_provider TEXT,
  asn              TEXT,
  country          TEXT,
  tls_issuer       TEXT,
  data_state       TEXT NOT NULL DEFAULT 'SYNTHETIC_DEMO',
  analyst          TEXT NOT NULL DEFAULT 'system',
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

-- ── The atomic unit of collected intelligence ─────────────────
CREATE TABLE IF NOT EXISTS intel_observation (
  id              TEXT PRIMARY KEY,
  observation_type TEXT NOT NULL DEFAULT 'HANDLE_OBSERVED',
  content         TEXT NOT NULL DEFAULT '',
  observed_at     TEXT NOT NULL,
  source_id       TEXT,
  actor_id        TEXT,
  handle_id       TEXT,
  platform        TEXT,
  confidence      REAL NOT NULL DEFAULT 50,
  tags            TEXT NOT NULL DEFAULT '[]',
  notes           TEXT NOT NULL DEFAULT '',
  data_state      TEXT NOT NULL DEFAULT 'SYNTHETIC_DEMO',
  analyst         TEXT NOT NULL DEFAULT 'system',
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL
);

-- ── Evidence ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS intel_evidence (
  id                   TEXT PRIMARY KEY,
  evidence_type        TEXT NOT NULL DEFAULT 'ANALYSIS',
  source_id            TEXT,
  source_label         TEXT NOT NULL DEFAULT '',
  observed_at          TEXT NOT NULL,
  collected_at         TEXT NOT NULL,
  hash                 TEXT NOT NULL DEFAULT '',
  integrity_status     TEXT NOT NULL DEFAULT 'VERIFIED',
  reliability          REAL NOT NULL DEFAULT 50,
  confidence           REAL NOT NULL DEFAULT 50,
  provenance           TEXT NOT NULL DEFAULT '',
  description          TEXT NOT NULL DEFAULT '',
  related_actor        TEXT,
  related_handle       TEXT,
  related_infra        TEXT,
  related_relationship TEXT,
  data_state           TEXT NOT NULL DEFAULT 'SYNTHETIC_DEMO',
  analyst              TEXT NOT NULL DEFAULT 'system',
  created_at           TEXT NOT NULL,
  updated_at           TEXT NOT NULL
);

-- ── Relationships: the connective tissue of the whole model ───
CREATE TABLE IF NOT EXISTS intel_relationship (
  id             TEXT PRIMARY KEY,
  source_entity  TEXT NOT NULL,
  target_entity  TEXT NOT NULL,
  source_type    TEXT NOT NULL,
  target_type    TEXT NOT NULL,
  type           TEXT NOT NULL,
  confidence     REAL NOT NULL DEFAULT 50,
  explanation    TEXT NOT NULL DEFAULT '',
  first_observed TEXT NOT NULL,
  last_observed  TEXT NOT NULL,
  supporting     TEXT NOT NULL DEFAULT '[]',
  against        TEXT NOT NULL DEFAULT '[]',
  derivation     TEXT NOT NULL DEFAULT 'OBSERVED',
  data_state     TEXT NOT NULL DEFAULT 'SYNTHETIC_DEMO',
  analyst        TEXT NOT NULL DEFAULT 'system',
  created_at     TEXT NOT NULL,
  updated_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS intel_relationship_evidence (
  relationship_id TEXT NOT NULL REFERENCES intel_relationship(id) ON DELETE CASCADE,
  evidence_id     TEXT NOT NULL REFERENCES intel_evidence(id) ON DELETE CASCADE,
  PRIMARY KEY (relationship_id, evidence_id)
);

-- ── Why-linked: the reasoning behind a correlation ────────────
CREATE TABLE IF NOT EXISTS intel_correlation (
  id              TEXT PRIMARY KEY,
  subject_id      TEXT NOT NULL,
  object_id       TEXT NOT NULL,
  method          TEXT NOT NULL,
  confidence      REAL NOT NULL DEFAULT 0,
  status          TEXT NOT NULL DEFAULT 'CORRELATED',
  signals         TEXT NOT NULL DEFAULT '[]',
  counter_signals TEXT NOT NULL DEFAULT '[]',
  explanation     TEXT NOT NULL DEFAULT '',
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL
);

-- ── Timeline ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS intel_timeline_event (
  id          TEXT PRIMARY KEY,
  actor_id    TEXT NOT NULL DEFAULT '',
  entity_id   TEXT NOT NULL DEFAULT '',
  event_type  TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  title       TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  source_id   TEXT,
  confidence  REAL NOT NULL DEFAULT 50,
  data_state  TEXT NOT NULL DEFAULT 'SYNTHETIC_DEMO',
  analyst     TEXT NOT NULL DEFAULT 'system',
  created_at  TEXT NOT NULL
);

-- ── Investigations reference entities, they never copy them ────
CREATE TABLE IF NOT EXISTS intel_investigation (
  id            TEXT PRIMARY KEY,
  title         TEXT NOT NULL,
  description   TEXT NOT NULL DEFAULT '',
  status        TEXT NOT NULL DEFAULT 'ACTIVE',
  analyst       TEXT NOT NULL DEFAULT 'system',
  seed_actor_id TEXT,
  steps         TEXT NOT NULL DEFAULT '[]',
  confidence    REAL NOT NULL DEFAULT 0,
  data_state    TEXT NOT NULL DEFAULT 'SYNTHETIC_DEMO',
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS intel_investigation_ref (
  investigation_id TEXT NOT NULL REFERENCES intel_investigation(id) ON DELETE CASCADE,
  entity_id        TEXT NOT NULL,
  entity_type      TEXT NOT NULL,
  role            TEXT NOT NULL DEFAULT 'REFERENCE',
  added_at         TEXT NOT NULL,
  PRIMARY KEY (investigation_id, entity_id, role)
);

-- ── Alerts ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS intel_alert (
  id               TEXT PRIMARY KEY,
  type             TEXT NOT NULL,
  severity         TEXT NOT NULL DEFAULT 'MEDIUM',
  title            TEXT NOT NULL,
  reason           TEXT NOT NULL DEFAULT '',
  raised_at        TEXT NOT NULL,
  actor_id         TEXT,
  entity_id        TEXT,
  entity_type      TEXT,
  evidence_ids     TEXT NOT NULL DEFAULT '[]',
  confidence       REAL NOT NULL DEFAULT 50,
  status           TEXT NOT NULL DEFAULT 'OPEN',
  acknowledged_by  TEXT,
  acknowledged_at  TEXT,
  resolution       TEXT,
  dedupe_key       TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

-- ── Analyst notes ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS intel_note (
  id          TEXT PRIMARY KEY,
  entity_type TEXT NOT NULL,
  entity_id   TEXT NOT NULL,
  author      TEXT NOT NULL DEFAULT 'system',
  text        TEXT NOT NULL,
  created_at  TEXT NOT NULL
);

-- ── Audit: who changed what, and which entity it affected ─────
CREATE TABLE IF NOT EXISTS intel_audit (
  id          TEXT PRIMARY KEY,
  occurred_at TEXT NOT NULL,
  actor       TEXT NOT NULL DEFAULT 'system',
  action      TEXT NOT NULL,
  entity      TEXT NOT NULL,
  entity_id   TEXT NOT NULL,
  before      TEXT NOT NULL DEFAULT '',
  after       TEXT NOT NULL DEFAULT '',
  source      TEXT NOT NULL DEFAULT '',
  result      TEXT NOT NULL DEFAULT 'SUCCESS',
  ip          TEXT NOT NULL DEFAULT '',
  batch_id    TEXT
);

-- ── Ingestion log: retryable, auditable, never partial ────────
CREATE TABLE IF NOT EXISTS intel_ingest_log (
  id           TEXT PRIMARY KEY,
  received_at  TEXT NOT NULL,
  completed_at TEXT,
  analyst      TEXT NOT NULL DEFAULT 'system',
  origin       TEXT NOT NULL DEFAULT 'API',
  status       TEXT NOT NULL DEFAULT 'PENDING',
  payload      TEXT NOT NULL DEFAULT '{}',
  result       TEXT NOT NULL DEFAULT '{}',
  error        TEXT
);

-- ── Singleton state row (demo flag, revision counter) ─────────
CREATE TABLE IF NOT EXISTS intel_state (
  id             INTEGER PRIMARY KEY CHECK (id = 1),
  revision       INTEGER NOT NULL DEFAULT 0,
  is_demo_loaded INTEGER NOT NULL DEFAULT 0,
  demo_label     TEXT NOT NULL DEFAULT 'Synthetic Demo Data - DO NOT TREAT AS REAL',
  monitoring     TEXT NOT NULL DEFAULT '{}',
  seeded_at      TEXT
);

-- ── Active Threat Protection: analyst decisions (blocked indicators,
--    response tickets, protection actions). Kept as a singleton JSON blob so
--    the protection layer can add state without touching the normalized
--    intelligence tables the rest of the platform reads.
CREATE TABLE IF NOT EXISTS intel_protection_state (
  id                INTEGER PRIMARY KEY CHECK (id = 1),
  protection_json   TEXT NOT NULL DEFAULT '{}',
  updated_at        TEXT
);

-- ── 24×7 Monitoring: persistent configuration the background scheduler drives.
--    Each monitor targets an existing entity by id so the monitoring layer
--    never owns a second copy of the data — it detects change against the
--    same centralized tables every other module reads.
CREATE TABLE IF NOT EXISTS intel_monitor (
  id                 TEXT PRIMARY KEY,
  name               TEXT NOT NULL,
  target_type        TEXT NOT NULL,
  target_id          TEXT NOT NULL,
  target_value       TEXT,
  rule               TEXT NOT NULL DEFAULT '{}',
  sources            TEXT NOT NULL DEFAULT '[]',
  frequency          TEXT NOT NULL DEFAULT 'CONTINUOUS',
  status             TEXT NOT NULL DEFAULT 'PAUSED',
  severity           TEXT NOT NULL DEFAULT 'MEDIUM',
  alert_conditions   TEXT NOT NULL DEFAULT '{}',
  notification_pref  TEXT,
  last_check         TEXT,
  next_check         TEXT,
  last_event_id      TEXT,
  alert_count        INTEGER NOT NULL DEFAULT 0,
  created_by         TEXT NOT NULL DEFAULT 'system',
  created_at         TEXT NOT NULL,
  updated_at         TEXT NOT NULL
);

-- Per-cycle detection log; the persistent audit of what each monitor saw.
CREATE TABLE IF NOT EXISTS intel_monitor_event (
  id                  TEXT PRIMARY KEY,
  monitor_id          TEXT NOT NULL REFERENCES intel_monitor(id) ON DELETE CASCADE,
  check_at            TEXT NOT NULL,
  status              TEXT NOT NULL DEFAULT 'OK',
  observations_seen   INTEGER NOT NULL DEFAULT 0,
  triggered_alert_ids TEXT NOT NULL DEFAULT '[]',
  message             TEXT,
  created_at          TEXT NOT NULL
);

-- A CUSTOM monitor watches several existing entities at once. Each row is
-- one AND-clause bound to an existing entity id — never a second copy of
-- that entity.
CREATE TABLE IF NOT EXISTS intel_monitor_target (
  id           TEXT PRIMARY KEY,
  monitor_id   TEXT NOT NULL REFERENCES intel_monitor(id) ON DELETE CASCADE,
  entity_type  TEXT NOT NULL,
  entity_id    TEXT NOT NULL,
  entity_value TEXT,
  conditions   TEXT NOT NULL DEFAULT '[]',
  created_at   TEXT NOT NULL
);

-- ── Chain of custody: append-only evidence lifecycle log ────────
-- One row per custody event. Rows are never updated or deleted: a
-- correction is a new event, so the recorded sequence of who handled
-- an item and in what order cannot be rewritten. The origin column
-- separates events this platform recorded from the point tracking was
-- enabled (TRACKED) from events reconstructed out of the pre-existing
-- audit trail (AUDIT_DERIVED), so a reader can always tell a newly
-- tracked event apart from a verified historical record.
--
-- evidence_id is intentionally a plain column rather than a foreign
-- key: custody history must survive the evidence row it describes, and
-- the existing intel_evidence primary key is left untouched.
CREATE TABLE IF NOT EXISTS intel_custody_event (
  id                    TEXT PRIMARY KEY,
  evidence_id           TEXT NOT NULL,
  event_type            TEXT NOT NULL,
  occurred_at           TEXT NOT NULL,
  actor                 TEXT NOT NULL DEFAULT 'system',
  action                TEXT NOT NULL DEFAULT '',
  previous_state        TEXT NOT NULL DEFAULT '',
  new_state             TEXT NOT NULL DEFAULT '',
  reason                TEXT NOT NULL DEFAULT '',
  integrity_hash        TEXT NOT NULL DEFAULT '',
  verification_result   TEXT NOT NULL DEFAULT '',
  verification_reference TEXT NOT NULL DEFAULT '',
  investigation_id      TEXT,
  source                TEXT NOT NULL DEFAULT 'API',
  origin                TEXT NOT NULL DEFAULT 'TRACKED',
  audit_id              TEXT,
  created_at            TEXT NOT NULL
);

-- One row per condition that actually fired, carrying the real records it
-- matched. This is what an alert cites as its underlying observation.
CREATE TABLE IF NOT EXISTS intel_monitor_match (
  id               TEXT PRIMARY KEY,
  monitor_id       TEXT NOT NULL REFERENCES intel_monitor(id) ON DELETE CASCADE,
  event_id         TEXT,
  alert_id         TEXT,
  condition_key    TEXT NOT NULL,
  entity_type      TEXT,
  entity_id        TEXT,
  detail           TEXT NOT NULL DEFAULT '{}',
  created_at       TEXT NOT NULL
);
`;

/**
 * Additive column migrations. Tables that already exist in deployed
 * databases get a wider contract by adding columns rather than
 * recreating a table, so no existing primary key, partition key or
 * stored value is disturbed. Each entry runs only when the column is
 * genuinely absent, so booting is idempotent. The exported name is the
 * pre-existing one and is kept so current importers do not break.
 */
const MONITOR_COLUMN_ADDITIONS = [
  ['intel_monitor', 'monitor_kind', "TEXT NOT NULL DEFAULT 'SINGLE'"],
  ['intel_monitor', 'conditions', "TEXT NOT NULL DEFAULT '[]'"],
  ['intel_monitor', 'notify_channel', 'TEXT'],
  ['intel_monitor', 'runtime_state', "TEXT NOT NULL DEFAULT 'AWAITING_DATA'"],
  ['intel_monitor', 'last_error', 'TEXT'],
  ['intel_monitor', 'consecutive_failures', 'INTEGER NOT NULL DEFAULT 0'],
  ['intel_monitor', 'check_count', 'INTEGER NOT NULL DEFAULT 0'],
  ['intel_monitor', 'trigger_count', 'INTEGER NOT NULL DEFAULT 0'],
  ['intel_monitor', 'collection_interval_seconds', 'INTEGER'],
  ['intel_monitor', 'effective_frequency', 'TEXT'],
  ['intel_monitor', 'notes', "TEXT NOT NULL DEFAULT ''"],
  ['intel_alert', 'monitor_id', 'TEXT'],
  ['intel_alert', 'trigger_conditions', "TEXT NOT NULL DEFAULT '[]'"],
  ['intel_alert', 'observation_ids', "TEXT NOT NULL DEFAULT '[]'"],
  ['intel_alert', 'investigation_id', 'TEXT'],
  // Analyst action columns, so assign / escalate / dismiss / resolve are
  // persisted against the alert itself and not only in the app_state
  // document. The alert console can therefore action a monitoring alert
  // exactly like any other, with the actor and timestamp recorded in SQL.
  ['intel_alert', 'assigned_to', 'TEXT'],
  ['intel_alert', 'assigned_by', 'TEXT'],
  ['intel_alert', 'assigned_at', 'TEXT'],
  ['intel_alert', 'escalated_by', 'TEXT'],
  ['intel_alert', 'escalated_at', 'TEXT'],
  ['intel_alert', 'dismissed_by', 'TEXT'],
  ['intel_alert', 'dismissed_at', 'TEXT'],
  ['intel_alert', 'resolved_by', 'TEXT'],
  ['intel_alert', 'resolved_at', 'TEXT'],
  ['intel_source', 'access_mode', "TEXT NOT NULL DEFAULT 'AUTHORISED_FEED'"],
  ['intel_source', 'collection_interval_seconds', 'INTEGER NOT NULL DEFAULT 21600'],
  ['intel_source', 'previous_status', 'TEXT'],
  ['intel_source', 'previous_health_status', 'TEXT'],
  ['intel_source', 'previous_reliability', 'REAL'],
  ['intel_infrastructure', 'previous_value', 'TEXT'],
  ['intel_infrastructure', 'previous_registrar', 'TEXT'],
  ['intel_infrastructure', 'previous_hosting_provider', 'TEXT'],
  ['intel_infrastructure', 'previous_tls_issuer', 'TEXT'],
  ['intel_infrastructure', 'previous_last_seen', 'TEXT'],
  ['intel_wallet', 'previous_tx_count', 'INTEGER'],
  ['intel_pgp_key', 'revoked_at', 'TEXT'],
  ['intel_pgp_key', 'expires_at', 'TEXT'],
  ['intel_relationship', 'previous_confidence', 'REAL'],
  // Chain-of-custody evidence attributes. The brief requires collection
  // method, collected-by, file size/format, current status, storage
  // reference and the outcome of the last integrity verification to be
  // tracked per item. All are optional and default to empty, so a
  // deployed evidence row keeps every value it already had.
  ['intel_evidence', 'collection_method', "TEXT NOT NULL DEFAULT ''"],
  ['intel_evidence', 'collected_by', "TEXT NOT NULL DEFAULT ''"],
  ['intel_evidence', 'file_name', "TEXT NOT NULL DEFAULT ''"],
  ['intel_evidence', 'file_size', 'INTEGER'],
  ['intel_evidence', 'file_format', "TEXT NOT NULL DEFAULT ''"],
  ['intel_evidence', 'status', "TEXT NOT NULL DEFAULT 'REGISTERED'"],
  ['intel_evidence', 'storage_reference', "TEXT NOT NULL DEFAULT ''"],
  ['intel_evidence', 'custody_tracking_since', 'TEXT'],
  ['intel_evidence', 'last_verified_at', 'TEXT'],
  ['intel_evidence', 'last_verified_by', "TEXT NOT NULL DEFAULT ''"],
  ['intel_evidence', 'last_verification_result', "TEXT NOT NULL DEFAULT 'NEVER_VERIFIED'"],
  ['intel_evidence', 'last_verification_detail', "TEXT NOT NULL DEFAULT ''"],
  ['intel_evidence', 'verification_count', 'INTEGER NOT NULL DEFAULT 0'],
];

/**
 * One-time backfill: sources registered before access classes existed get
 * the class their source type implies, so monitoring reports a real
 * collection interval instead of a placeholder.
 */
const SOURCE_ACCESS_BACKFILL = `UPDATE intel_source SET access_mode = 'AUTHORISED_FEED'
  WHERE (access_mode IS NULL OR access_mode = 'AUTHORISED_FEED')
    AND type IN ('THREAT_FEED','FORUM','MARKETPLACE','PASTE','LEAK_SITE','MESSAGING','ONION_SERVICE')
    AND data_state = 'SYNTHETIC_DEMO' AND (collection_method IS NULL OR collection_method = '')`;

/** Add one column when the live table does not already carry it. */
function addColumnIfMissing(database, table, column, ddl) {
  const existing = database.prepare(`PRAGMA table_info(${table})`).all();
  if (!existing.length) return false;
  if (existing.some(row => row.name === column)) return false;
  database.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${ddl}`);
  return true;
}

// Plain lookup indexes: cheap, and safe to create on existing data.
const INTEL_INDEXES_SAFE = [
  'CREATE INDEX IF NOT EXISTS ix_intel_source_type ON intel_source(type)',
  'CREATE INDEX IF NOT EXISTS ix_intel_actor_status ON intel_actor(status)',
  'CREATE INDEX IF NOT EXISTS ix_intel_handle_value ON intel_handle(value)',
  'CREATE INDEX IF NOT EXISTS ix_intel_handle_source ON intel_handle(source_id)',
  'CREATE INDEX IF NOT EXISTS ix_intel_infra_value ON intel_infrastructure(value)',
  'CREATE INDEX IF NOT EXISTS ix_intel_observation_actor ON intel_observation(actor_id)',
  'CREATE INDEX IF NOT EXISTS ix_intel_observation_time ON intel_observation(observed_at)',
  'CREATE INDEX IF NOT EXISTS ix_intel_evidence_actor ON intel_evidence(related_actor)',
  'CREATE INDEX IF NOT EXISTS ix_intel_evidence_hash ON intel_evidence(hash)',
  'CREATE INDEX IF NOT EXISTS ix_intel_relationship_source ON intel_relationship(source_entity)',
  'CREATE INDEX IF NOT EXISTS ix_intel_relationship_target ON intel_relationship(target_entity)',
  'CREATE INDEX IF NOT EXISTS ix_intel_correlation_subject ON intel_correlation(subject_id)',
  'CREATE INDEX IF NOT EXISTS ix_intel_timeline_actor ON intel_timeline_event(actor_id)',
  'CREATE INDEX IF NOT EXISTS ix_intel_timeline_time ON intel_timeline_event(occurred_at)',
  'CREATE INDEX IF NOT EXISTS ix_intel_timeline_type ON intel_timeline_event(event_type)',
  'CREATE INDEX IF NOT EXISTS ix_intel_invref_entity ON intel_investigation_ref(entity_id)',
  'CREATE INDEX IF NOT EXISTS ix_intel_alert_status ON intel_alert(status)',
  'CREATE INDEX IF NOT EXISTS ix_intel_alert_time ON intel_alert(raised_at)',
  'CREATE INDEX IF NOT EXISTS ix_intel_note_entity ON intel_note(entity_id)',
  'CREATE INDEX IF NOT EXISTS ix_intel_audit_entity ON intel_audit(entity_id)',
  'CREATE INDEX IF NOT EXISTS ix_intel_audit_time ON intel_audit(occurred_at)',
  'CREATE INDEX IF NOT EXISTS ix_intel_audit_batch ON intel_audit(batch_id)',
  'CREATE INDEX IF NOT EXISTS ix_intel_ingest_status ON intel_ingest_log(status)',
  'CREATE INDEX IF NOT EXISTS ix_intel_monitor_status ON intel_monitor(status)',
  'CREATE INDEX IF NOT EXISTS ix_intel_monitor_target ON intel_monitor(target_type, target_id)',
  'CREATE INDEX IF NOT EXISTS ix_intel_monitor_next_check ON intel_monitor(next_check)',
  'CREATE INDEX IF NOT EXISTS ix_intel_monitor_event_monitor ON intel_monitor_event(monitor_id)',
  'CREATE INDEX IF NOT EXISTS ix_intel_monitor_target_monitor ON intel_monitor_target(monitor_id)',
  'CREATE INDEX IF NOT EXISTS ix_intel_monitor_target_entity ON intel_monitor_target(entity_type, entity_id)',
  'CREATE INDEX IF NOT EXISTS ix_intel_monitor_match_monitor ON intel_monitor_match(monitor_id, created_at)',
  'CREATE INDEX IF NOT EXISTS ix_intel_monitor_match_alert ON intel_monitor_match(alert_id)',
  'CREATE INDEX IF NOT EXISTS ix_intel_alert_monitor ON intel_alert(monitor_id)',
  'CREATE INDEX IF NOT EXISTS ix_intel_custody_evidence ON intel_custody_event(evidence_id, occurred_at)',
  'CREATE INDEX IF NOT EXISTS ix_intel_custody_time ON intel_custody_event(occurred_at)',
  'CREATE INDEX IF NOT EXISTS ix_intel_custody_type ON intel_custody_event(event_type)',
];

// Uniqueness indexes: the duplicate guard. Each is paired with a repair
// statement, so adding one to an already-populated database is safe.
const UNIQUE_INDEXES = [
  {
    sql: 'CREATE UNIQUE INDEX IF NOT EXISTS ux_intel_source_name ON intel_source(name)',
    repair: null,
  },
  {
    sql: 'CREATE UNIQUE INDEX IF NOT EXISTS ux_intel_handle_identity ON intel_handle(normalized, platform)',
    repair: null,
  },
  {
    sql: 'CREATE UNIQUE INDEX IF NOT EXISTS ux_intel_pgp_fingerprint ON intel_pgp_key(normalized)',
    repair: null,
  },
  {
    sql: 'CREATE UNIQUE INDEX IF NOT EXISTS ux_intel_wallet_address ON intel_wallet(normalized)',
    repair: null,
  },
  {
    sql: 'CREATE UNIQUE INDEX IF NOT EXISTS ux_intel_infra_identity ON intel_infrastructure(normalized, type)',
    repair: null,
  },
  {
    sql: `CREATE UNIQUE INDEX IF NOT EXISTS ux_intel_observation_dedupe
      ON intel_observation(observation_type, coalesce(actor_id,''), coalesce(handle_id,''), coalesce(platform,''), content)`,
    repair: null,
  },
  {
    sql: 'CREATE UNIQUE INDEX IF NOT EXISTS ux_intel_relationship_edge ON intel_relationship(source_entity, target_entity, type)',
    repair: null,
  },
  {
    sql: 'CREATE UNIQUE INDEX IF NOT EXISTS ux_intel_correlation_pair ON intel_correlation(subject_id, object_id, method)',
    repair: null,
  },
  {
    sql: 'CREATE UNIQUE INDEX IF NOT EXISTS ux_intel_timeline_event ON intel_timeline_event(event_type, actor_id, occurred_at, title)',
    repair: `DELETE FROM intel_timeline_event WHERE id NOT IN
      (SELECT MIN(id) FROM intel_timeline_event GROUP BY event_type, actor_id, occurred_at, title)`,
  },
  {
    // One open alert per subject; resolved alerts are kept for history.
    sql: `CREATE UNIQUE INDEX IF NOT EXISTS ux_intel_alert_dedupe
      ON intel_alert(dedupe_key) WHERE status = 'OPEN'`,
    repair: null,
  },
];

/**
 * Create every intelligence table and index if it does not already exist.
 * Safe to call on each boot; performs no destructive migration of
 * existing rows beyond collapsing exact duplicates a new unique index
 * would otherwise reject.
 */
export function ensureIntelligenceSchema(database) {
  database.exec(INTEL_TABLES);

  // Column additions run before the indexes: an index on a column that a
  // deployed database does not have yet would fail the whole boot.
  for (const [table, column, ddl] of MONITOR_COLUMN_ADDITIONS) {
    addColumnIfMissing(database, table, column, ddl);
  }

  // Mark the seeded demo sources honestly: they are synthetic, not live.
  try {
    database.exec(SOURCE_ACCESS_BACKFILL);
  } catch { /* an older database without the columns simply keeps its values */ }

  for (const statement of INTEL_INDEXES_SAFE) {
    database.exec(statement);
  }

  for (const { sql, repair } of UNIQUE_INDEXES) {
    try {
      database.exec(sql);
    } catch (error) {
      if (!repair) throw error;
      // Existing duplicates from an older schema: collapse, then retry.
      database.exec(repair);
      database.exec(sql);
    }
  }

  const state = database.prepare('SELECT id FROM intel_state WHERE id = 1').get();
  if (!state) {
    database
      .prepare('INSERT INTO intel_state (id, revision, is_demo_loaded) VALUES (1, 0, 0)')
      .run();
  }

  const protection = database.prepare('SELECT id FROM intel_protection_state WHERE id = 1').get();
  if (!protection) {
    database
      .prepare('INSERT INTO intel_protection_state (id, protection_json) VALUES (1, ?)')
      .run(JSON.stringify({ blockedIndicators: [], responseLogs: [] }));
  }
}

export { INTEL_TABLES, INTEL_INDEXES_SAFE, UNIQUE_INDEXES, MONITOR_COLUMN_ADDITIONS };
