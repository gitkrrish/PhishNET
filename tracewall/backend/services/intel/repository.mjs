// ============================================================
// PhishNet — Central intelligence repository.
//
// The single data-access layer for the normalized Dark Web tables.
// Nothing above this file issues SQL, and nothing below it knows
// about HTTP. Every function is synchronous: node:sqlite's
// DatabaseSync keeps the whole ingestion pipeline inside one real
// transaction, so a failure can never leave partial intelligence
// behind.
// ============================================================
import { getDatabase } from '../../database/store.mjs';
import { now } from './normalize.mjs';

let counter = 0;

/** Stable, human-readable, collision-resistant ids (ACT-TEST-001 style stays possible). */
export function newId(prefix) {
  counter += 1;
  const stamp = Date.now().toString(36).toUpperCase();
  return `${prefix}-${stamp}-${counter.toString(36).toUpperCase()}`;
}

/**
 * Return the proposed id when it is free, otherwise mint a fresh one.
 * Reconcile passes the UI's ids so the backend snapshot matches the
 * frontend byte-for-byte; seeds and ingest paths may already occupy
 * those ids (a different but valid synthetic record), so a taken id
 * must never abort the transaction — the record simply gets a new id.
 */
function freeId(table, proposed, prefix) {
  if (proposed && !getDatabase().prepare(`SELECT 1 FROM ${table} WHERE id = ?`).get(proposed)) return proposed;
  return newId(prefix);
}

/** Run `work` inside a real transaction; any throw rolls the whole thing back. */
export function transact(work) {
  const database = getDatabase();
  database.exec('BEGIN IMMEDIATE');
  try {
    const result = work(database);
    database.exec('COMMIT');
    return result;
  } catch (error) {
    try { database.exec('ROLLBACK'); } catch { /* already rolled back */ }
    throw error;
  }
}

export const db = () => getDatabase();

// ── State / revision ──────────────────────────────────────────
export function getState() {
  return getDatabase().prepare('SELECT * FROM intel_state WHERE id = 1').get();
}

export function bumpRevision() {
  getDatabase().prepare('UPDATE intel_state SET revision = revision + 1 WHERE id = 1').run();
  return getState().revision;
}

export function setDemoLoaded(loaded) {
  getDatabase().prepare('UPDATE intel_state SET is_demo_loaded = ? WHERE id = 1').run(loaded ? 1 : 0);
}

export function setMonitoring(monitoring) {
  getDatabase()
    .prepare('UPDATE intel_state SET monitoring = ? WHERE id = 1')
    .run(JSON.stringify(monitoring || {}));
}

// ── Sources ───────────────────────────────────────────────────
const SOURCE_COLUMNS = 'id, name, type, reference, collection_method, first_observed, last_observed, reliability_score, health_status, activity_level, status, description, onion_address, data_state, analyst, created_at, updated_at, access_mode, collection_interval_seconds, previous_status, previous_health_status, previous_reliability';

export function upsertSource(record) {
  const database = getDatabase();
  const existing = database
    .prepare('SELECT * FROM intel_source WHERE name = ?')
    .get(record.name);
  const timestamp = now();
  if (existing) {
    // Previous status and health are retained so source monitoring can
    // report the real transition instead of only the current value.
    database
      .prepare(
        `UPDATE intel_source SET last_observed = ?, reliability_score = ?, health_status = ?,
         activity_level = ?, status = ?, description = ?, reference = coalesce(?, reference),
         collection_method = coalesce(?, collection_method), updated_at = ?,
         access_mode = coalesce(?, access_mode), collection_interval_seconds = coalesce(?, collection_interval_seconds),
         previous_status = ?, previous_health_status = ?, previous_reliability = ?
         WHERE id = ?`,
      )
      .run(
        record.lastObserved || timestamp,
        record.reliabilityScore ?? existing.reliability_score,
        record.healthStatus || existing.health_status,
        record.activityLevel || existing.activity_level,
        record.status || existing.status,
        record.description ?? existing.description,
        record.reference ?? null,
        record.collectionMethod ?? null,
        timestamp,
        record.accessMode ?? existing.access_mode ?? null,
        record.collectionIntervalSeconds ?? null,
        existing.status,
        existing.health_status,
        existing.reliability_score,
        existing.id,
      );
    return { id: existing.id, created: false };
  }
  const id = freeId('intel_source', record.id, 'SRC');
  database
    .prepare(
      `INSERT INTO intel_source (${SOURCE_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    )
    .run(
      id,
      record.name,
      record.type,
      record.reference ?? null,
      record.collectionMethod ?? null,
      record.firstObserved || timestamp,
      record.lastObserved || timestamp,
      record.reliabilityScore ?? 50,
      record.healthStatus || 'ACTIVE',
      record.activityLevel || 'MEDIUM',
      record.status || 'ACTIVE',
      record.description || '',
      record.onionAddress ?? null,
      record.dataState || 'SYNTHETIC_DEMO',
      record.analyst || 'system',
      timestamp,
      timestamp,
      record.accessMode || defaultAccessMode(record.type),
      record.collectionIntervalSeconds ?? defaultCollectionInterval(record.type, record.accessMode),
      null,
      null,
      null,
    );
  return { id, created: true };
}

/**
 * A source's declared collection class. This is what tells monitoring how
 * often the source can honestly be read; it never implies continuous
 * access the collection method cannot deliver.
 */
export function defaultAccessMode(sourceType) {
  switch (String(sourceType || '').toUpperCase()) {
    case 'THREAT_FEED': return 'AUTHORISED_FEED';
    case 'SYNTHETIC_DEMO': return 'SYNTHETIC_DEMO';
    default: return 'PUBLIC';
  }
}

/**
 * The fastest interval a source class supports in practice. Sources that
 * have no continuous access are stored with their real interval, so a
 * monitor bound to them can never claim to poll them continuously.
 */
export function defaultCollectionInterval(sourceType, accessMode) {
  const class_ = accessMode || defaultAccessMode(sourceType);
  return SOURCE_INTERVAL_SECONDS[class_] ?? SOURCE_INTERVAL_SECONDS[String(sourceType || '').toUpperCase()] ?? 21600;
}

const SOURCE_INTERVAL_SECONDS = {
  THREAT_FEED: 300,
  MESSAGING: 3600,
  FORUM: 21600,
  MARKETPLACE: 21600,
  PASTE: 900,
  LEAK_SITE: 86400,
  ONION_SERVICE: 86400,
  AUTHORISED_FEED: 3600,
  PUBLIC: 21600,
  ANALYST_PROVIDED: 3600,
  SYNTHETIC_DEMO: 60,
};

export const listSources = () =>
  getDatabase().prepare(`SELECT ${SOURCE_COLUMNS} FROM intel_source ORDER BY name`).all();

export const getSource = id =>
  getDatabase().prepare(`SELECT ${SOURCE_COLUMNS} FROM intel_source WHERE id = ?`).get(id);

// ── Actors ────────────────────────────────────────────────────
const ACTOR_COLUMNS = 'id, display_name, status, activity_level, confidence_score, primary_motivation, first_seen, last_seen, behavioral_profile, stylometric_profile, data_state, analyst, created_at, updated_at';

export function upsertActor(record) {
  const database = getDatabase();
  const existing = record.id ? database.prepare('SELECT * FROM intel_actor WHERE id = ?').get(record.id) : null;
  const timestamp = now();
  if (existing) {
    database
      .prepare(
        `UPDATE intel_actor SET display_name = ?, status = ?, activity_level = ?, confidence_score = ?,
         primary_motivation = ?, first_seen = ?, last_seen = ?, behavioral_profile = ?, stylometric_profile = ?,
         data_state = ?, analyst = ?, updated_at = ? WHERE id = ?`,
      )
      .run(
        record.displayName ?? existing.display_name,
        record.status || existing.status,
        record.activityLevel || existing.activity_level,
        record.confidenceScore ?? existing.confidence_score,
        record.primaryMotivation ?? existing.primary_motivation,
        record.firstSeen || existing.first_seen,
        record.lastSeen || timestamp,
        JSON.stringify(record.behavioralProfile ?? JSON.parse(existing.behavioral_profile || '{}')),
        JSON.stringify(record.stylometricProfile ?? JSON.parse(existing.stylometric_profile || '{}')),
        record.dataState || existing.data_state,
        record.analyst || existing.analyst,
        timestamp,
        existing.id,
      );
    return { id: existing.id, created: false };
  }
  const id = freeId('intel_actor', record.id, 'ACT');
  database
    .prepare(`INSERT INTO intel_actor (${ACTOR_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(
      id,
      record.displayName || '',
      record.status || 'ACTIVE',
      record.activityLevel || 'MEDIUM',
      record.confidenceScore ?? 50,
      record.primaryMotivation || '',
      record.firstSeen || timestamp,
      record.lastSeen || timestamp,
      JSON.stringify(record.behavioralProfile || {}),
      JSON.stringify(record.stylometricProfile || {}),
      record.dataState || 'SYNTHETIC_DEMO',
      record.analyst || 'system',
      timestamp,
      timestamp,
    );
  return { id, created: true };
}

export const listActors = () =>
  getDatabase().prepare(`SELECT ${ACTOR_COLUMNS} FROM intel_actor ORDER BY id`).all();

export const getActor = id =>
  getDatabase().prepare(`SELECT ${ACTOR_COLUMNS} FROM intel_actor WHERE id = ?`).get(id);

// ── Handles ───────────────────────────────────────────────────
const HANDLE_COLUMNS = 'id, value, normalized, platform, source_id, first_seen, last_seen, confidence, data_state, analyst, created_at, updated_at';

export function upsertHandle(record) {
  const database = getDatabase();
  const existing = database
    .prepare('SELECT * FROM intel_handle WHERE normalized = ? AND platform = ?')
    .get(record.normalized, record.platform);
  const timestamp = now();
  if (existing) {
    // Same handle on the same platform is the same identity: enrich it.
    database
      .prepare(
        `UPDATE intel_handle SET last_seen = ?, confidence = max(confidence, ?), source_id = coalesce(?, source_id),
         data_state = ?, analyst = ?, updated_at = ? WHERE id = ?`,
      )
      .run(
        record.lastSeen || timestamp,
        record.confidence ?? existing.confidence,
        record.sourceId ?? null,
        record.dataState || existing.data_state,
        record.analyst || existing.analyst,
        timestamp,
        existing.id,
      );
    return { id: existing.id, created: false };
  }
  const id = freeId('intel_handle', record.id, 'HDL');
  database
    .prepare(`INSERT INTO intel_handle (${HANDLE_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(
      id,
      record.value,
      record.normalized,
      record.platform,
      record.sourceId ?? null,
      record.firstSeen || timestamp,
      record.lastSeen || timestamp,
      record.confidence ?? 50,
      record.dataState || 'SYNTHETIC_DEMO',
      record.analyst || 'system',
      timestamp,
      timestamp,
    );
  return { id, created: true };
}

export const listHandles = () =>
  getDatabase().prepare(`SELECT ${HANDLE_COLUMNS} FROM intel_handle ORDER BY id`).all();

export const getHandle = id =>
  getDatabase().prepare(`SELECT ${HANDLE_COLUMNS} FROM intel_handle WHERE id = ?`).get(id);

// ── PGP keys ──────────────────────────────────────────────────
const PGP_COLUMNS = 'id, fingerprint, normalized, first_seen, last_seen, confidence, data_state, analyst, created_at, updated_at, revoked_at, expires_at';

export function upsertPgp(record) {
  const database = getDatabase();
  const existing = database.prepare('SELECT * FROM intel_pgp_key WHERE normalized = ?').get(record.normalized);
  const timestamp = now();
  if (existing) {
    // Revocation and expiry are stored on the key, so a PGP monitor can
    // report them as stored facts rather than inferring them.
    database
      .prepare(
        `UPDATE intel_pgp_key SET last_seen = ?, confidence = max(confidence, ?), data_state = ?, analyst = ?, updated_at = ?,
         revoked_at = coalesce(?, revoked_at), expires_at = coalesce(?, expires_at) WHERE id = ?`,
      )
      .run(
        record.lastSeen || timestamp,
        record.confidence ?? existing.confidence,
        record.dataState || existing.data_state,
        record.analyst || existing.analyst,
        timestamp,
        record.revokedAt ?? null,
        record.expiresAt ?? null,
        existing.id,
      );
    return { id: existing.id, created: false };
  }
  const id = freeId('intel_pgp_key', record.id, 'PGP');
  database
    .prepare(`INSERT INTO intel_pgp_key (${PGP_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(
      id,
      record.fingerprint,
      record.normalized,
      record.firstSeen || timestamp,
      record.lastSeen || timestamp,
      record.confidence ?? 50,
      record.dataState || 'SYNTHETIC_DEMO',
      record.analyst || 'system',
      timestamp,
      timestamp,
      record.revokedAt ?? null,
      record.expiresAt ?? null,
    );
  return { id, created: true };
}

export const listPgp = () =>
  getDatabase().prepare(`SELECT ${PGP_COLUMNS} FROM intel_pgp_key ORDER BY id`).all();

export const getPgp = id => getDatabase().prepare(`SELECT ${PGP_COLUMNS} FROM intel_pgp_key WHERE id = ?`).get(id);

// ── Wallets ───────────────────────────────────────────────────
const WALLET_COLUMNS = 'id, address, normalized, network, first_seen, last_seen, tx_count, confidence, data_state, analyst, created_at, updated_at, previous_tx_count';

export function upsertWallet(record) {
  const database = getDatabase();
  const existing = database.prepare('SELECT * FROM intel_wallet WHERE normalized = ?').get(record.normalized);
  const timestamp = now();
  if (existing) {
    // The prior transaction count is kept so wallet monitoring can report a
    // real change in observed chain activity rather than assume one.
    database
      .prepare(
        `UPDATE intel_wallet SET last_seen = ?, confidence = max(confidence, ?), tx_count = max(tx_count, ?), network = coalesce(?, network), data_state = ?, analyst = ?, updated_at = ?,
         previous_tx_count = ? WHERE id = ?`,
      )
      .run(
        record.lastSeen || timestamp,
        record.confidence ?? existing.confidence,
        record.txCount ?? existing.tx_count,
        record.network ?? null,
        record.dataState || existing.data_state,
        record.analyst || existing.analyst,
        timestamp,
        existing.tx_count,
        existing.id,
      );
    return { id: existing.id, created: false };
  }
  const id = freeId('intel_wallet', record.id, 'WAL');
  database
    .prepare(`INSERT INTO intel_wallet (${WALLET_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(
      id,
      record.address,
      record.normalized,
      record.network || '',
      record.firstSeen || timestamp,
      record.lastSeen || timestamp,
      record.txCount ?? 0,
      record.confidence ?? 50,
      record.dataState || 'SYNTHETIC_DEMO',
      record.analyst || 'system',
      timestamp,
      timestamp,
      null,
    );
  return { id, created: true };
}

export const listWallets = () =>
  getDatabase().prepare(`SELECT ${WALLET_COLUMNS} FROM intel_wallet ORDER BY id`).all();

// ── Infrastructure ────────────────────────────────────────────
const INFRA_COLUMNS = 'id, type, value, normalized, first_seen, last_seen, registrar, hosting_provider, asn, country, tls_issuer, data_state, analyst, created_at, updated_at, previous_value, previous_registrar, previous_hosting_provider, previous_tls_issuer, previous_last_seen';

export function upsertInfrastructure(record) {
  const database = getDatabase();
  const existing = database
    .prepare('SELECT * FROM intel_infrastructure WHERE normalized = ? AND type = ?')
    .get(record.normalized, record.type);
  const timestamp = now();
  if (existing) {
    // Previous values are kept so monitoring can prove a domain, IP,
    // registrar or certificate actually changed rather than guessing.
    database
      .prepare(
        `UPDATE intel_infrastructure SET last_seen = ?, registrar = coalesce(?, registrar), hosting_provider = coalesce(?, hosting_provider),
         asn = coalesce(?, asn), country = coalesce(?, country), tls_issuer = coalesce(?, tls_issuer), updated_at = ?,
         previous_value = ?, previous_registrar = ?, previous_hosting_provider = ?, previous_tls_issuer = ?, previous_last_seen = ?
         WHERE id = ?`,
      )
      .run(
        record.lastSeen || timestamp,
        record.registrar ?? null,
        record.hostingProvider ?? null,
        record.asn ?? null,
        record.country ?? null,
        record.tlsIssuer ?? null,
        timestamp,
        existing.value,
        existing.registrar ?? null,
        existing.hosting_provider ?? null,
        existing.tls_issuer ?? null,
        existing.last_seen,
        existing.id,
      );
    return { id: existing.id, created: false };
  }
  const id = freeId('intel_infrastructure', record.id, 'INF');
  database
    .prepare(`INSERT INTO intel_infrastructure (${INFRA_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(
      id,
      record.type,
      record.value,
      record.normalized,
      record.firstSeen || timestamp,
      record.lastSeen || timestamp,
      record.registrar ?? null,
      record.hostingProvider ?? null,
      record.asn ?? null,
      record.country ?? null,
      record.tlsIssuer ?? null,
      record.dataState || 'SYNTHETIC_DEMO',
      record.analyst || 'system',
      timestamp,
      timestamp,
      null,
      null,
      null,
      null,
      null,
    );
  return { id, created: true };
}

export const listInfrastructure = () =>
  getDatabase().prepare(`SELECT ${INFRA_COLUMNS} FROM intel_infrastructure ORDER BY id`).all();

// ── Observations ──────────────────────────────────────────────
const OBSERVATION_COLUMNS = 'id, observation_type, content, observed_at, source_id, actor_id, handle_id, platform, confidence, tags, notes, data_state, analyst, created_at, updated_at';

export function upsertObservation(record) {
  const database = getDatabase();
  const existing = database
    .prepare(
      `SELECT * FROM intel_observation WHERE observation_type = ? AND coalesce(actor_id,'') = ?
       AND coalesce(handle_id,'') = ? AND coalesce(platform,'') = ? AND content = ?`,
    )
    .get(
      record.observationType,
      record.actorId ?? '',
      record.handleId ?? '',
      record.platform ?? '',
      record.content,
    );
  const timestamp = now();
  if (existing) {
    database
      .prepare('UPDATE intel_observation SET observed_at = ?, confidence = max(confidence, ?), updated_at = ? WHERE id = ?')
      .run(record.observedAt || timestamp, record.confidence ?? existing.confidence, timestamp, existing.id);
    return { id: existing.id, created: false };
  }
  const id = freeId('intel_observation', record.id, 'OBS');
  database
    .prepare(`INSERT INTO intel_observation (${OBSERVATION_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(
      id,
      record.observationType,
      record.content,
      record.observedAt || timestamp,
      record.sourceId ?? null,
      record.actorId ?? null,
      record.handleId ?? null,
      record.platform ?? null,
      record.confidence ?? 50,
      JSON.stringify(record.tags || []),
      record.notes || '',
      record.dataState || 'SYNTHETIC_DEMO',
      record.analyst || 'system',
      timestamp,
      timestamp,
    );
  return { id, created: true };
}

export const listObservations = () =>
  getDatabase().prepare(`SELECT ${OBSERVATION_COLUMNS} FROM intel_observation ORDER BY observed_at DESC`).all();

// ── Evidence ──────────────────────────────────────────────────
const EVIDENCE_COLUMNS = 'id, evidence_type, source_id, source_label, observed_at, collected_at, hash, integrity_status, reliability, confidence, provenance, description, related_actor, related_handle, related_infra, related_relationship, data_state, analyst, created_at, updated_at';

export function upsertEvidence(record) {
  const database = getDatabase();
  // Same content hash from the same source is the same evidence item.
  const existing = record.hash
    ? database.prepare('SELECT * FROM intel_evidence WHERE hash = ? AND source_id IS ?').get(record.hash, record.sourceId ?? null)
    : null;
  const timestamp = now();
  if (existing) {
    database
      .prepare('UPDATE intel_evidence SET collected_at = ?, confidence = max(confidence, ?), updated_at = ? WHERE id = ?')
      .run(record.collectedAt || timestamp, record.confidence ?? existing.confidence, timestamp, existing.id);
    return { id: existing.id, created: false };
  }
  const id = freeId('intel_evidence', record.id, 'EVD');
  database
    .prepare(`INSERT INTO intel_evidence (${EVIDENCE_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(
      id,
      record.evidenceType || 'ANALYSIS',
      record.sourceId ?? null,
      record.sourceLabel || '',
      record.observedAt || timestamp,
      record.collectedAt || timestamp,
      record.hash || '',
      record.integrityStatus || 'VERIFIED',
      record.reliability ?? 50,
      record.confidence ?? 50,
      record.provenance || '',
      record.description || '',
      record.relatedActor ?? null,
      record.relatedHandle ?? null,
      record.relatedInfra ?? null,
      record.relatedRelationship ?? null,
      record.dataState || 'SYNTHETIC_DEMO',
      record.analyst || 'system',
      timestamp,
      timestamp,
    );
  return { id, created: true };
}

export const listEvidence = () =>
  getDatabase().prepare(`SELECT ${EVIDENCE_COLUMNS} FROM intel_evidence ORDER BY collected_at DESC`).all();

export function linkRelationshipEvidence(relationshipId, evidenceId) {
  getDatabase()
    .prepare('INSERT OR IGNORE INTO intel_relationship_evidence (relationship_id, evidence_id) VALUES (?,?)')
    .run(relationshipId, evidenceId);
}

export const evidenceForRelationship = relationshipId =>
  getDatabase()
    .prepare(
      `SELECT e.* FROM intel_evidence e
       JOIN intel_relationship_evidence re ON re.evidence_id = e.id
       WHERE re.relationship_id = ?`,
    )
    .all(relationshipId);

export function evidenceForEntity(entityId) {
  return getDatabase()
    .prepare('SELECT * FROM intel_evidence WHERE related_actor = ? OR related_handle = ? OR related_infra = ? OR related_relationship = ? ORDER BY collected_at DESC')
    .all(entityId, entityId, entityId, entityId);
}

// ── Relationships ─────────────────────────────────────────────
const RELATIONSHIP_COLUMNS = 'id, source_entity, target_entity, source_type, target_type, type, confidence, explanation, first_observed, last_observed, supporting, against, derivation, data_state, analyst, created_at, updated_at, previous_confidence';

export function upsertRelationship(record) {
  const database = getDatabase();
  const existing = database
    .prepare('SELECT * FROM intel_relationship WHERE source_entity = ? AND target_entity = ? AND type = ?')
    .get(record.sourceEntity, record.targetEntity, record.type);
  const timestamp = now();
  if (existing) {
    // Re-deriving a known edge strengthens it; it never duplicates it. The
    // prior confidence is kept so relationship monitoring can prove a
    // confidence change rather than infer one.
    database
      .prepare(
        `UPDATE intel_relationship SET last_observed = ?, confidence = max(confidence, ?), updated_at = ?,
         previous_confidence = ? WHERE id = ?`,
      )
      .run(
        record.lastObserved || timestamp,
        record.confidence ?? existing.confidence,
        timestamp,
        existing.confidence,
        existing.id,
      );
    return { id: existing.id, created: false };
  }
  const id = freeId('intel_relationship', record.id, 'REL');
  database
    .prepare(`INSERT INTO intel_relationship (${RELATIONSHIP_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(
      id,
      record.sourceEntity,
      record.targetEntity,
      record.sourceType,
      record.targetType,
      record.type,
      record.confidence ?? 50,
      record.explanation || '',
      record.firstObserved || timestamp,
      record.lastObserved || timestamp,
      JSON.stringify(record.supporting || []),
      JSON.stringify(record.against || []),
      record.derivation || 'OBSERVED',
      record.dataState || 'SYNTHETIC_DEMO',
      record.analyst || 'system',
      timestamp,
      timestamp,
      null,
    );
  return { id, created: true };
}

export const listRelationships = () =>
  getDatabase().prepare(`SELECT ${RELATIONSHIP_COLUMNS} FROM intel_relationship ORDER BY id`).all();

export const getRelationship = id =>
  getDatabase().prepare(`SELECT ${RELATIONSHIP_COLUMNS} FROM intel_relationship WHERE id = ?`).get(id);

export function relationshipsForEntity(entityId) {
  return getDatabase()
    .prepare('SELECT * FROM intel_relationship WHERE source_entity = ? OR target_entity = ? ORDER BY id')
    .all(entityId, entityId);
}

// ── Correlations (why linked) ──────────────────────────────────
export function upsertCorrelation(record) {
  const database = getDatabase();
  const existing = database
    .prepare('SELECT * FROM intel_correlation WHERE subject_id = ? AND object_id = ? AND method = ?')
    .get(record.subjectId, record.objectId, record.method);
  const timestamp = now();
  if (existing) {
    database
      .prepare('UPDATE intel_correlation SET confidence = max(confidence, ?), signals = ?, counter_signals = ?, explanation = ?, updated_at = ? WHERE id = ?')
      .run(record.confidence, JSON.stringify(record.signals || []), JSON.stringify(record.counterSignals || []), record.explanation || '', timestamp, existing.id);
    return { id: existing.id, created: false };
  }
  const id = freeId('intel_correlation', record.id, 'COR');
  database
    .prepare(
      'INSERT INTO intel_correlation (id, subject_id, object_id, method, confidence, status, signals, counter_signals, explanation, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
    )
    .run(
      id,
      record.subjectId,
      record.objectId,
      record.method,
      record.confidence,
      record.status || 'CORRELATED',
      JSON.stringify(record.signals || []),
      JSON.stringify(record.counterSignals || []),
      record.explanation || '',
      timestamp,
      timestamp,
    );
  return { id, created: true };
}

export const listCorrelations = () =>
  getDatabase().prepare('SELECT * FROM intel_correlation ORDER BY confidence DESC').all();

export const correlationsFor = entityId =>
  getDatabase()
    .prepare('SELECT * FROM intel_correlation WHERE subject_id = ? OR object_id = ? ORDER BY confidence DESC')
    .all(entityId, entityId);

// ── Timeline ──────────────────────────────────────────────────
const TIMELINE_COLUMNS = 'id, actor_id, entity_id, event_type, occurred_at, title, description, source_id, confidence, data_state, analyst, created_at';

export function addTimelineEvent(record) {
  const database = getDatabase();
  const timestamp = now();
  const id = freeId('intel_timeline_event', record.id, 'TLM');
  // Idempotent: an identical historical event (same type, actor, time and
  // title) is the same event, so re-ingesting must not duplicate it.
  database
    .prepare(
      `INSERT OR IGNORE INTO intel_timeline_event (${TIMELINE_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
    )
    .run(
      id,
      record.actorId || '',
      record.entityId || '',
      record.eventType,
      record.occurredAt || timestamp,
      record.title || '',
      record.description || '',
      record.sourceId ?? null,
      record.confidence ?? 50,
      record.dataState || 'SYNTHETIC_DEMO',
      record.analyst || 'system',
      timestamp,
    );
  const stored = database.prepare('SELECT id FROM intel_timeline_event WHERE id = ?').get(id);
  return { id: stored ? id : null, created: Boolean(stored) };
}

export const listTimeline = () =>
  getDatabase().prepare(`SELECT ${TIMELINE_COLUMNS} FROM intel_timeline_event ORDER BY occurred_at DESC`).all();

// ── Investigations ─────────────────────────────────────────────
const INVESTIGATION_COLUMNS = 'id, title, description, status, analyst, seed_actor_id, steps, confidence, data_state, created_at, updated_at';

export function upsertInvestigation(record) {
  const database = getDatabase();
  const existing = record.id ? database.prepare('SELECT * FROM intel_investigation WHERE id = ?').get(record.id) : null;
  const timestamp = now();
  if (existing) {
    database
      .prepare(
        `UPDATE intel_investigation SET title = ?, description = ?, status = ?, analyst = ?, seed_actor_id = ?, steps = ?, confidence = ?, updated_at = ? WHERE id = ?`,
      )
      .run(
        record.title || existing.title,
        record.description ?? existing.description,
        record.status || existing.status,
        record.analyst || existing.analyst,
        record.seedActorId ?? existing.seed_actor_id,
        JSON.stringify(record.steps ?? JSON.parse(existing.steps || '[]')),
        record.confidence ?? existing.confidence,
        timestamp,
        existing.id,
      );
    return { id: existing.id, created: false };
  }
  const id = freeId('intel_investigation', record.id, 'INV');
  database
    .prepare(`INSERT INTO intel_investigation (${INVESTIGATION_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
    .run(
      id,
      record.title,
      record.description || '',
      record.status || 'ACTIVE',
      record.analyst || 'system',
      record.seedActorId ?? null,
      JSON.stringify(record.steps || []),
      record.confidence ?? 0,
      record.dataState || 'SYNTHETIC_DEMO',
      record.timestamp || timestamp,
      timestamp,
    );
  return { id, created: true };
}

export const listInvestigations = () =>
  getDatabase().prepare(`SELECT ${INVESTIGATION_COLUMNS} FROM intel_investigation ORDER BY id`).all();

export const getInvestigation = id =>
  getDatabase().prepare(`SELECT ${INVESTIGATION_COLUMNS} FROM intel_investigation WHERE id = ?`).get(id);

/** Investigations hold references, never copies, so entities stay live. */
export function attachEntityToInvestigation(investigationId, entityId, entityType, role = 'REFERENCE') {
  getDatabase()
    .prepare(
      'INSERT OR IGNORE INTO intel_investigation_ref (investigation_id, entity_id, entity_type, role, added_at) VALUES (?,?,?,?,?)',
    )
    .run(investigationId, entityId, entityType, role, now());
}

export const investigationRefs = investigationId =>
  getDatabase()
    .prepare('SELECT * FROM intel_investigation_ref WHERE investigation_id = ?')
    .all(investigationId);

export const investigationsForEntity = entityId =>
  getDatabase()
    .prepare('SELECT * FROM intel_investigation_ref WHERE entity_id = ?')
    .all(entityId);

// ── Alerts ────────────────────────────────────────────────────
const ALERT_COLUMNS = 'id, type, severity, title, reason, raised_at, actor_id, entity_id, entity_type, evidence_ids, confidence, status, acknowledged_by, acknowledged_at, resolution, dedupe_key, created_at, updated_at, monitor_id, trigger_conditions, observation_ids, investigation_id, assigned_to, assigned_by, assigned_at, escalated_by, escalated_at, dismissed_by, dismissed_at, resolved_by, resolved_at';

// Columns raiseAlert populates. The analyst-action columns are deliberately
// absent: an alert is raised with no assignee or resolution, and those stay
// NULL until an analyst acts on it. Keeping the insert list explicit means an
// additive column migration can widen the table without breaking this insert.
const ALERT_INSERT_COLUMNS = 'id, type, severity, title, reason, raised_at, actor_id, entity_id, entity_type, evidence_ids, confidence, status, acknowledged_by, acknowledged_at, resolution, dedupe_key, created_at, updated_at, monitor_id, trigger_conditions, observation_ids, investigation_id';

export function raiseAlert(record) {
  const database = getDatabase();
  const timestamp = now();
  const dedupeKey = record.dedupeKey || `${record.type}:${record.entityId || record.actorId || 'global'}`;
  // A still-open alert for the same subject is updated, never duplicated.
  const existing = database
    .prepare("SELECT * FROM intel_alert WHERE dedupe_key = ? AND status = 'OPEN'")
    .get(dedupeKey);
  if (existing) {
    database
      .prepare(
        `UPDATE intel_alert SET reason = ?, evidence_ids = ?, confidence = max(confidence, ?),
         trigger_conditions = ?, observation_ids = ?, updated_at = ? WHERE id = ?`,
      )
      .run(
        record.reason || '',
        JSON.stringify(record.evidenceIds || []),
        record.confidence ?? existing.confidence,
        JSON.stringify(record.triggerConditions || []),
        JSON.stringify(record.observationIds || []),
        timestamp,
        existing.id,
      );
    return { id: existing.id, created: false };
  }
  const id = freeId('intel_alert', record.id, 'ALT');
  // Placeholders are derived from the column list so an additive column
  // migration can widen the table without silently breaking this insert.
  const placeholders = ALERT_INSERT_COLUMNS.split(',').map(() => '?').join(',');
  database
    .prepare(`INSERT INTO intel_alert (${ALERT_INSERT_COLUMNS}) VALUES (${placeholders})`)
    .run(
      id,
      record.type,
      record.severity || 'MEDIUM',
      record.title,
      record.reason || '',
      record.raisedAt || timestamp,
      record.actorId ?? null,
      record.entityId ?? null,
      record.entityType ?? null,
      JSON.stringify(record.evidenceIds || []),
      record.confidence ?? 50,
      'OPEN',
      null,
      null,
      null,
      dedupeKey,
      timestamp,
      timestamp,
      record.monitorId ?? null,
      JSON.stringify(record.triggerConditions || []),
      JSON.stringify(record.observationIds || []),
      record.investigationId ?? null,
    );
  return { id, created: true };
}

export const listAlerts = () =>
  getDatabase().prepare(`SELECT ${ALERT_COLUMNS} FROM intel_alert ORDER BY raised_at DESC`).all();

export function updateAlertStatus(id, status, fields = {}) {
  const timestamp = now();
  const current = getDatabase().prepare('SELECT * FROM intel_alert WHERE id = ?').get(id);
  if (!current) return null;
  getDatabase()
    .prepare(
      `UPDATE intel_alert SET status = ?, acknowledged_by = coalesce(?, acknowledged_by),
       acknowledged_at = coalesce(?, acknowledged_at), resolution = coalesce(?, resolution),
       assigned_to = coalesce(?, assigned_to), assigned_by = coalesce(?, assigned_by),
       assigned_at = coalesce(?, assigned_at), escalated_by = coalesce(?, escalated_by),
       escalated_at = coalesce(?, escalated_at), dismissed_by = coalesce(?, dismissed_by),
       dismissed_at = coalesce(?, dismissed_at), resolved_by = coalesce(?, resolved_by),
       resolved_at = coalesce(?, resolved_at), updated_at = ? WHERE id = ?`,
    )
    .run(
      status,
      fields.acknowledgedBy ?? null,
      fields.acknowledgedAt ?? null,
      fields.resolution ?? null,
      fields.assignedTo ?? null,
      fields.assignedBy ?? null,
      fields.assignedAt ?? null,
      fields.escalatedBy ?? null,
      fields.escalatedAt ?? null,
      fields.dismissedBy ?? null,
      fields.dismissedAt ?? null,
      fields.resolvedBy ?? null,
      fields.resolvedAt ?? null,
      timestamp,
      id,
    );
  return getDatabase().prepare(`SELECT ${ALERT_COLUMNS} FROM intel_alert WHERE id = ?`).get(id);
}

// ── Notes ─────────────────────────────────────────────────────
export function addNote(record) {
  const database = getDatabase();
  const id = record.id || newId('NOT');
  const existing = database.prepare('SELECT 1 FROM intel_note WHERE id = ?').get(id);
  database
    .prepare('INSERT OR IGNORE INTO intel_note (id, entity_type, entity_id, author, text, created_at) VALUES (?,?,?,?,?,?)')
    .run(id, record.entityType, record.entityId, record.author || 'system', record.text, record.createdAt || now());
  return { id, created: !existing };
}

export const listNotes = () =>
  getDatabase().prepare('SELECT * FROM intel_note ORDER BY created_at DESC').all();

export const notesForEntity = entityId =>
  getDatabase().prepare('SELECT * FROM intel_note WHERE entity_id = ? ORDER BY created_at DESC').all(entityId);

// ── Audit ─────────────────────────────────────────────────────
export function writeAudit(record) {
  const database = getDatabase();
  const id = freeId('intel_audit', record.id, 'AUD');
  database
    .prepare(
      'INSERT INTO intel_audit (id, occurred_at, actor, action, entity, entity_id, before, after, source, result, ip, batch_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
    )
    .run(
      id,
      record.occurredAt || now(),
      record.actor || 'system',
      record.action,
      record.entity,
      record.entityId,
      record.before ?? '',
      record.after ?? '',
      record.source ?? '',
      record.result || 'SUCCESS',
      record.ip ?? '',
      record.batchId ?? null,
    );
  return { id };
}

export const listAudit = () =>
  getDatabase().prepare('SELECT * FROM intel_audit ORDER BY occurred_at DESC').all();

// ── Ingestion log ─────────────────────────────────────────────
export function logIngestion(record) {
  const database = getDatabase();
  const id = freeId('intel_ingest_log', record.id, 'ING');
  database
    .prepare(
      'INSERT INTO intel_ingest_log (id, received_at, completed_at, analyst, origin, status, payload, result, error) VALUES (?,?,?,?,?,?,?,?,?)',
    )
    .run(
      id,
      record.receivedAt || now(),
      record.completedAt ?? null,
      record.analyst || 'system',
      record.origin || 'API',
      record.status || 'PENDING',
      JSON.stringify(record.payload || {}),
      JSON.stringify(record.result || {}),
      record.error ?? null,
    );
  return id;
}

export function completeIngestion(id, result, error) {
  getDatabase()
    .prepare('UPDATE intel_ingest_log SET completed_at = ?, status = ?, result = ?, error = ? WHERE id = ?')
    .run(now(), error ? 'FAILED' : 'COMPLETED', JSON.stringify(result || {}), error ?? null, id);
}

export const pendingIngestions = () =>
  getDatabase().prepare("SELECT * FROM intel_ingest_log WHERE status IN ('PENDING','FAILED')").all();

export const getIngestion = id =>
  getDatabase().prepare('SELECT * FROM intel_ingest_log WHERE id = ?').get(id);

// ── 24×7 Monitoring ────────────────────────────────────────────────
const MONITOR_COLUMNS =
  'id, name, monitor_kind, target_type, target_id, target_value, rule, conditions, sources, frequency, effective_frequency, collection_interval_seconds, status, runtime_state, severity, alert_conditions, notification_pref, notify_channel, last_check, next_check, last_event_id, last_error, consecutive_failures, check_count, trigger_count, alert_count, created_by, notes, created_at, updated_at';

const MONITOR_PATCH_COLUMNS = {
  name: 'name',
  monitorKind: 'monitor_kind',
  targetType: 'target_type',
  targetId: 'target_id',
  targetValue: 'target_value',
  rule: 'rule',
  conditions: 'conditions',
  sources: 'sources',
  frequency: 'frequency',
  effectiveFrequency: 'effective_frequency',
  collectionIntervalSeconds: 'collection_interval_seconds',
  status: 'status',
  runtimeState: 'runtime_state',
  severity: 'severity',
  alertConditions: 'alert_conditions',
  notificationPref: 'notification_pref',
  notifyChannel: 'notify_channel',
  // The monitor PATCH route has always accepted `notes` and the column
  // already exists on intel_monitor; without this mapping an analyst note was
  // accepted and then discarded.
  notes: 'notes',
  lastCheck: 'last_check',
  nextCheck: 'next_check',
  lastEventId: 'last_event_id',
  lastError: 'last_error',
  consecutiveFailures: 'consecutive_failures',
  checkCount: 'check_count',
  triggerCount: 'trigger_count',
  alertCount: 'alert_count',
};

export function createMonitor(record) {
  const database = getDatabase();
  const timestamp = now();
  const id = record.id || newId('MON');
  const columns = [
    'id', 'name', 'monitor_kind', 'target_type', 'target_id', 'target_value', 'rule', 'conditions',
    'sources', 'frequency', 'effective_frequency', 'collection_interval_seconds', 'status', 'runtime_state',
    'severity', 'alert_conditions', 'notification_pref', 'notify_channel', 'last_check', 'next_check',
    'last_event_id', 'last_error', 'consecutive_failures', 'check_count', 'trigger_count', 'alert_count',
    'created_by', 'notes', 'created_at', 'updated_at',
  ];
  const values = [
    id,
    record.name,
    record.monitorKind || 'SINGLE',
    record.targetType,
    record.targetId,
    record.targetValue ?? null,
    JSON.stringify(record.rule || {}),
    JSON.stringify(record.conditions || []),
    JSON.stringify(record.sources || []),
    record.frequency || 'CONTINUOUS',
    record.effectiveFrequency ?? record.frequency ?? 'CONTINUOUS',
    record.collectionIntervalSeconds ?? null,
    record.status || 'PAUSED',
    record.runtimeState || 'AWAITING_DATA',
    record.severity || 'MEDIUM',
    JSON.stringify(record.alertConditions || {}),
    record.notificationPref ?? null,
    record.notifyChannel ?? null,
    record.lastCheck ?? null,
    record.nextCheck ?? null,
    record.lastEventId ?? null,
    record.lastError ?? null,
    record.consecutiveFailures ?? 0,
    record.checkCount ?? 0,
    record.triggerCount ?? 0,
    record.alertCount ?? 0,
    record.createdBy || 'analyst',
    record.notes ?? '',
    timestamp,
    timestamp,
  ];
  database
    .prepare(`INSERT INTO intel_monitor (${columns.join(',')}) VALUES (${columns.map(() => '?').join(',')})`)
    .run(...values);
  return { id, created: true };
}

export const listMonitors = () =>
  getDatabase().prepare(`SELECT ${MONITOR_COLUMNS} FROM intel_monitor ORDER BY created_at DESC`).all();

export function getMonitor(id) {
  return getDatabase().prepare(`SELECT ${MONITOR_COLUMNS} FROM intel_monitor WHERE id = ?`).get(id);
}

export function updateMonitor(id, patch) {
  const fields = [];
  const values = [];
  for (const [key, col] of Object.entries(MONITOR_PATCH_COLUMNS)) {
    if (patch[key] !== undefined) {
      fields.push(`${col} = ?`);
      values.push(typeof patch[key] === 'object' ? JSON.stringify(patch[key]) : patch[key]);
    }
  }
  if (!fields.length) return getMonitor(id);
  fields.push('updated_at = ?');
  values.push(now());
  values.push(id);
  getDatabase().prepare(`UPDATE intel_monitor SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  return getMonitor(id);
}

export function setMonitorStatus(id, status) {
  const timestamp = now();
  getDatabase().prepare('UPDATE intel_monitor SET status = ?, updated_at = ? WHERE id = ?').run(status, timestamp, id);
  return getMonitor(id);
}

export function deleteMonitor(id) {
  return getDatabase().prepare('DELETE FROM intel_monitor WHERE id = ?').run(id);
}

// ── Monitor targets (CUSTOM monitors watch several existing entities) ──
const MONITOR_TARGET_COLUMNS = 'id, monitor_id, entity_type, entity_id, entity_value, conditions, created_at';

export function replaceMonitorTargets(monitorId, targets) {
  const database = getDatabase();
  database.prepare('DELETE FROM intel_monitor_target WHERE monitor_id = ?').run(monitorId);
  const timestamp = now();
  const created = [];
  for (const target of targets) {
    // A term-based target (CVE, keyword, product) has no stored entity id,
    // so its term is the identity. An entity-backed target must supply one.
    const entityId = String(target?.entityId || '').trim() || (target?.entityValue ? String(target.entityValue).trim() : '');
    if (!entityId || !target?.entityType) continue;
    const id = newId('MTG');
    database
      .prepare(`INSERT INTO intel_monitor_target (${MONITOR_TARGET_COLUMNS}) VALUES (?,?,?,?,?,?,?)`)
      .run(id, monitorId, target.entityType, entityId, target.entityValue ?? null, JSON.stringify(target.conditions || []), timestamp);
    created.push(id);
  }
  return created;
}

export function addMonitorTarget(monitorId, target) {
  const database = getDatabase();
  const id = newId('MTG');
  database
    .prepare(`INSERT INTO intel_monitor_target (${MONITOR_TARGET_COLUMNS}) VALUES (?,?,?,?,?,?,?)`)
    .run(
      id,
      monitorId,
      target.entityType,
      target.entityId,
      target.entityValue ?? null,
      JSON.stringify(target.conditions || []),
      now(),
    );
  return id;
}

export const listMonitorTargets = monitorId =>
  getDatabase()
    .prepare(`SELECT ${MONITOR_TARGET_COLUMNS} FROM intel_monitor_target WHERE monitor_id = ? ORDER BY created_at ASC`)
    .all(monitorId);

export function removeMonitorTarget(monitorId, targetId) {
  return getDatabase().prepare('DELETE FROM intel_monitor_target WHERE monitor_id = ? AND id = ?').run(monitorId, targetId);
}

// ── Monitor matches: what actually fired, with the records it cited ──
const MONITOR_MATCH_COLUMNS = 'id, monitor_id, event_id, alert_id, condition_key, entity_type, entity_id, detail, created_at';

export function logMonitorMatch(record) {
  const database = getDatabase();
  const id = newId('MCH');
  database
    .prepare(`INSERT INTO intel_monitor_match (${MONITOR_MATCH_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?)`)
    .run(
      id,
      record.monitorId,
      record.eventId ?? null,
      record.alertId ?? null,
      record.conditionKey,
      record.entityType ?? null,
      record.entityId ?? null,
      JSON.stringify(record.detail || {}),
      now(),
    );
  return id;
}

/** Rewrite the alert each match row points at, in one statement. */
export function attachMatchesToAlert(matchIds, alertId) {
  if (!matchIds?.length) return;
  const database = getDatabase();
  const statement = database.prepare('UPDATE intel_monitor_match SET alert_id = ? WHERE id = ?');
  for (const matchId of matchIds) statement.run(alertId, matchId);
}

export const listMonitorMatches = (monitorId, limit = 100) =>
  getDatabase()
    .prepare(`SELECT ${MONITOR_MATCH_COLUMNS} FROM intel_monitor_match WHERE monitor_id = ? ORDER BY created_at DESC LIMIT ?`)
    .all(monitorId, limit);

export const listMatchesForAlert = alertId =>
  getDatabase()
    .prepare(`SELECT ${MONITOR_MATCH_COLUMNS} FROM intel_monitor_match WHERE alert_id = ? ORDER BY created_at ASC`)
    .all(alertId);

/** Monitors already watching an entity — drives the "Monitor 24×7" toggle. */
export function monitorsForEntity(entityType, entityId) {
  const database = getDatabase();
  const direct = database
    .prepare(`SELECT ${MONITOR_COLUMNS} FROM intel_monitor WHERE target_type = ? AND target_id = ? ORDER BY created_at DESC`)
    .all(entityType, entityId);
  const viaTarget = database
    .prepare(
      `SELECT DISTINCT m.* FROM intel_monitor m
       JOIN intel_monitor_target t ON t.monitor_id = m.id
       WHERE t.entity_type = ? AND t.entity_id = ? ORDER BY m.created_at DESC`,
    )
    .all(entityType, entityId);
  const seen = new Set();
  return [...direct, ...viaTarget].filter(monitor => {
    if (seen.has(monitor.id)) return false;
    seen.add(monitor.id);
    return true;
  });
}

export function monitorsDue(before = now()) {
  return getDatabase()
    .prepare(
      `SELECT ${MONITOR_COLUMNS} FROM intel_monitor
       WHERE status = 'ACTIVE' AND (next_check IS NULL OR next_check <= ?)
       ORDER BY next_check ASC, created_at ASC`,
    )
    .all(before);
}

const MONITOR_EVENT_COLUMNS =
  'id, monitor_id, check_at, status, observations_seen, triggered_alert_ids, message, created_at';

export function logMonitorEvent(record) {
  const database = getDatabase();
  const timestamp = now();
  const id = record.id || newId('MEV');
  database
    .prepare(`INSERT INTO intel_monitor_event (${MONITOR_EVENT_COLUMNS}) VALUES (?,?,?,?,?,?,?,?)`)
    .run(
      id,
      record.monitorId,
      record.checkAt || timestamp,
      record.status || 'OK',
      record.observationsSeen ?? 0,
      JSON.stringify(record.triggeredAlertIds || []),
      record.message ?? null,
      timestamp,
    );
  return id;
}

export const listMonitorEvents = (monitorId, limit = 50) =>
  getDatabase()
    .prepare(`SELECT ${MONITOR_EVENT_COLUMNS} FROM intel_monitor_event WHERE monitor_id = ? ORDER BY check_at DESC LIMIT ?`)
    .all(monitorId, limit);

export const listRecentMonitorEvents = (limit = 20) =>
  getDatabase()
    .prepare(`SELECT ${MONITOR_EVENT_COLUMNS} FROM intel_monitor_event ORDER BY check_at DESC LIMIT ?`)
    .all(limit);

// Observations tied to a monitored target. SOURCE and PGP/WALLET/INFRA
// entities are not direct columns on intel_observation, so they are scoped
// to the owning actor via the SHARED_* relationship edge.
export const observationsForTarget = (targetType, targetId) => {
  const database = getDatabase();
  if (targetType === 'ACTOR') {
    return database.prepare(`SELECT ${OBSERVATION_COLUMNS} FROM intel_observation WHERE actor_id = ? ORDER BY observed_at DESC`).all(targetId);
  }
  if (targetType === 'HANDLE' || targetType === 'ALIAS') {
    return database.prepare(`SELECT ${OBSERVATION_COLUMNS} FROM intel_observation WHERE handle_id = ? ORDER BY observed_at DESC`).all(targetId);
  }
  if (targetType === 'SOURCE' || targetType === 'FORUM' || targetType === 'MARKETPLACE' || targetType === 'CHANNEL') {
    return database.prepare(`SELECT ${OBSERVATION_COLUMNS} FROM intel_observation WHERE source_id = ? ORDER BY observed_at DESC`).all(targetId);
  }
  const owner = database
    .prepare(
      `SELECT source_entity AS owner FROM intel_relationship
       WHERE ((target_entity = ? AND type IN ('SHARED_PGP','SHARED_WALLET','SHARED_INFRASTRUCTURE'))
            OR (source_entity = ? AND target_type IN ('PGP','WALLET','INFRASTRUCTURE')))
       ORDER BY last_observed DESC LIMIT 1`,
    )
    .get(targetId, targetId);
  return owner
    ? database.prepare(`SELECT ${OBSERVATION_COLUMNS} FROM intel_observation WHERE actor_id = ? ORDER BY observed_at DESC`).all(owner.owner)
    : [];
};

// Evidence tied to a monitored target.
export const evidenceForTarget = (targetType, targetId) => {
  const database = getDatabase();
  const direct = ['ACTOR', 'HANDLE', 'ALIAS', 'INFRASTRUCTURE', 'DOMAIN', 'IP', 'ONION'].map(t => t.toUpperCase()).includes(String(targetType).toUpperCase());
  if (direct) return evidenceForEntity(targetId);
  // PGP/WALLET/SOURCE: evidence reached through the relationships that bind
  // the target to an actor.
  return database
    .prepare(
      `SELECT e.* FROM intel_evidence e
       JOIN intel_relationship_evidence re ON re.evidence_id = e.id
       JOIN intel_relationship r ON r.id = re.relationship_id
       WHERE r.source_entity = ? OR r.target_entity = ?
       ORDER BY e.collected_at DESC`,
    )
    .all(targetId, targetId);
};

// ── Real change detection ──────────────────────────────────────────────
// Every detector answers the same question against the centralized tables:
// "which records for this target changed after `since`?" Nothing here
// invents a record — if the platform has not observed a change, the monitor
// has nothing to report.
const WALLET_SCOPED_COLUMNS = 'id, address, normalized, network, first_seen, last_seen, tx_count, confidence, data_state, analyst, created_at, updated_at';
const INFRA_SCOPED_COLUMNS = 'id, type, value, normalized, first_seen, last_seen, registrar, hosting_provider, asn, country, tls_issuer, data_state, analyst, created_at, updated_at';
const PGP_SCOPED_COLUMNS = 'id, fingerprint, normalized, first_seen, last_seen, confidence, data_state, analyst, created_at, updated_at';

const ACTOR_SCOPED = (table, columns, targetType) => actorId =>
  getDatabase()
    .prepare(
      `SELECT ${columns} FROM ${table} t
       WHERE t.id IN (SELECT target_entity FROM intel_relationship WHERE source_entity = ? AND target_type = '${targetType}'
                      UNION
                      SELECT source_entity FROM intel_relationship WHERE target_entity = ? AND source_type = '${targetType}')
       ORDER BY t.last_seen DESC`,
    )
    .all(actorId, actorId);

export const handlesForActor = ACTOR_SCOPED('intel_handle', HANDLE_COLUMNS, 'HANDLE');
export const walletsForActor = ACTOR_SCOPED('intel_wallet', WALLET_SCOPED_COLUMNS, 'WALLET');
export const pgpForActor = ACTOR_SCOPED('intel_pgp_key', PGP_SCOPED_COLUMNS, 'PGP_KEY');
export const infrastructureForActor = ACTOR_SCOPED('intel_infrastructure', INFRA_SCOPED_COLUMNS, 'INFRASTRUCTURE');

export function relationshipsForActor(actorId) {
  return getDatabase()
    .prepare(
      `SELECT ${RELATIONSHIP_COLUMNS} FROM intel_relationship
       WHERE (source_type = 'ACTOR' AND source_entity = ?) OR (target_type = 'ACTOR' AND target_entity = ?)
       ORDER BY last_observed DESC`,
    )
    .all(actorId, actorId);
}

export const getWallet = id => getDatabase().prepare(`SELECT ${WALLET_COLUMNS} FROM intel_wallet WHERE id = ?`).get(id);
export const getInfrastructure = id =>
  getDatabase().prepare(`SELECT ${INFRA_COLUMNS} FROM intel_infrastructure WHERE id = ?`).get(id);

/** Any supported entity is resolvable by id, so a monitor never invents one. */
export function resolveEntityRecord(entityType, entityId) {
  switch (entityType) {
    case 'ACTOR': return getActor(entityId);
    case 'HANDLE': case 'ALIAS': return getHandle(entityId);
    case 'PGP': case 'PGP_KEY': return getPgp(entityId);
    case 'WALLET': return getWallet(entityId);
    case 'INFRASTRUCTURE': case 'DOMAIN': case 'IP': case 'ONION': return getInfrastructure(entityId);
    case 'SOURCE': case 'FORUM': case 'MARKETPLACE': case 'CHANNEL': return getSource(entityId);
    case 'OBSERVATION': return getDatabase().prepare(`SELECT ${OBSERVATION_COLUMNS} FROM intel_observation WHERE id = ?`).get(entityId);
    case 'EVIDENCE': return getDatabase().prepare(`SELECT ${EVIDENCE_COLUMNS} FROM intel_evidence WHERE id = ?`).get(entityId);
    case 'RELATIONSHIP': return getRelationship(entityId);
    case 'ALERT': return getDatabase().prepare(`SELECT ${ALERT_COLUMNS} FROM intel_alert WHERE id = ?`).get(entityId);
    case 'INVESTIGATION': return getDatabase().prepare(`SELECT ${INVESTIGATION_COLUMNS} FROM intel_investigation WHERE id = ?`).get(entityId);
    default: return null;
  }
}

/** Human label for any monitorable entity, taken from its stored record. */
export function entityLabel(entityType, entityId) {
  const record = resolveEntityRecord(entityType, entityId);
  if (!record) return entityId;
  return record.display_name || record.value || record.fingerprint || record.address || record.name || record.title || record.content || record.id;
}

export const relationshipsInvolving = entityId =>
  getDatabase()
    .prepare(
      `SELECT ${RELATIONSHIP_COLUMNS} FROM intel_relationship
       WHERE source_entity = ? OR target_entity = ? ORDER BY last_observed DESC`,
    )
    .all(entityId, entityId);

/** Free-text scan of the observation log — keyword / CVE / product watches. */
export const observationsMatching = (term, limit = 50) =>
  getDatabase()
    .prepare(
      `SELECT ${OBSERVATION_COLUMNS} FROM intel_observation
       WHERE lower(content) LIKE ? OR lower(notes) LIKE ? OR lower(platform) LIKE ?
       ORDER BY observed_at DESC LIMIT ?`,
    )
    .all(`%${term.toLowerCase()}%`, `%${term.toLowerCase()}%`, `%${term.toLowerCase()}%`, limit);

/** Evidence whose description or provenance cites a term. */
export const evidenceMatching = (term, limit = 50) =>
  getDatabase()
    .prepare(
      `SELECT ${EVIDENCE_COLUMNS} FROM intel_evidence
       WHERE lower(description) LIKE ? OR lower(provenance) LIKE ? OR lower(source_label) LIKE ?
       ORDER BY collected_at DESC LIMIT ?`,
    )
    .all(`%${term.toLowerCase()}%`, `%${term.toLowerCase()}%`, `%${term.toLowerCase()}%`, limit);

export const alertsForMonitor = monitorId =>
  getDatabase()
    .prepare(`SELECT ${ALERT_COLUMNS} FROM intel_alert WHERE monitor_id = ? ORDER BY raised_at DESC`)
    .all(monitorId);

export const getAlert = id => getDatabase().prepare(`SELECT ${ALERT_COLUMNS} FROM intel_alert WHERE id = ?`).get(id);

/** Bind an existing monitoring alert to an existing investigation. */
export function linkAlertToInvestigation(alertId, investigationId) {
  return getDatabase()
    .prepare('UPDATE intel_alert SET investigation_id = ?, updated_at = ? WHERE id = ?')
    .run(investigationId, now(), alertId);
}

// ── Wholesale data management ──────────────────────────────────
const INTEL_TABLES_IN_ORDER = [
  'intel_relationship_evidence',
  'intel_investigation_ref',
  'intel_correlation',
  'intel_relationship',
  'intel_timeline_event',
  'intel_evidence',
  'intel_alert',
  'intel_note',
  'intel_audit',
  'intel_observation',
  'intel_infrastructure',
  'intel_wallet',
  'intel_pgp_key',
  'intel_handle',
  'intel_actor',
  'intel_source',
  'intel_investigation',
  'intel_ingest_log',
  'intel_monitor_match',
  'intel_monitor_target',
  'intel_monitor_event',
  'intel_monitor',
];

export function clearIntelligence() {
  for (const table of INTEL_TABLES_IN_ORDER) {
    getDatabase().prepare(`DELETE FROM ${table}`).run();
  }
  getDatabase()
    .prepare('UPDATE intel_state SET is_demo_loaded = 0, revision = revision + 1 WHERE id = 1')
    .run();
}
