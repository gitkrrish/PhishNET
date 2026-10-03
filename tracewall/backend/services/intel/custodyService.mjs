// ============================================================
// PhishNet — Evidence chain of custody (backend).
//
// Additive: nothing here modifies an existing table, key or route
// contract. It adds one append-only log table (`intel_custody_event`,
// created in intelligenceSchema.mjs) and a handful of optional columns
// on `intel_evidence`.
//
// Two rules shape the whole file:
//
//  1. Append-only. A custody event is inserted and never updated or
//     deleted. A correction is recorded as a new event, so the order
//     in which an item was handled cannot be rewritten after the fact.
//
//  2. No invented history. An evidence row that existed before custody
//     tracking was switched on has no custody log, and none is
//     fabricated for it. What the platform *can* honestly show is the
//     pre-existing audit trail, which is returned separately and
//     labelled AUDIT_DERIVED, while anything this service writes is
//     labelled TRACKED. The reader can always tell which is which.
//
// Integrity verification recalculates SHA-256 over content that is
// actually supplied and compares it with the digest already recorded on
// the evidence row. A matching digest proves the content is
// *consistent with the stored reference* — it says nothing about where
// the original came from, and the result text says so. A mismatch is
// flagged for investigation and the stored digest is never silently
// replaced.
// ============================================================
import { createHash } from 'node:crypto';
import { db, newId, bumpRevision } from './repository.mjs';

const CUSTODY_COLUMNS =
  'id, evidence_id, event_type, occurred_at, actor, action, previous_state, new_state, reason, integrity_hash, verification_result, verification_reference, investigation_id, source, origin, audit_id, created_at';

function database() {
  return db();
}

function now() {
  return new Date().toISOString();
}

/** Every custody event type the log understands, with its display label. */
export const CUSTODY_EVENT_TYPES = [
  'EVIDENCE_COLLECTED',
  'EVIDENCE_IMPORTED',
  'EVIDENCE_REGISTERED',
  'INTEGRITY_VERIFIED',
  'INTEGRITY_VERIFICATION_FAILED',
  'EVIDENCE_ACCESSED',
  'EVIDENCE_EXPORTED',
  'LINKED_TO_INVESTIGATION',
  'STATUS_CHANGED',
  'EVIDENCE_ARCHIVED',
];

export const CUSTODY_EVENT_LABEL = {
  EVIDENCE_COLLECTED: 'Collected',
  EVIDENCE_IMPORTED: 'Imported',
  EVIDENCE_REGISTERED: 'Registered',
  INTEGRITY_VERIFIED: 'Integrity verified',
  INTEGRITY_VERIFICATION_FAILED: 'Integrity verification failed',
  EVIDENCE_ACCESSED: 'Accessed',
  EVIDENCE_EXPORTED: 'Exported / transferred',
  LINKED_TO_INVESTIGATION: 'Linked to investigation',
  STATUS_CHANGED: 'Status changed',
  EVIDENCE_ARCHIVED: 'Archived',
};

// ── Reads ─────────────────────────────────────────────────────

function mapCustodyRow(row) {
  return {
    id: row.id,
    evidenceId: row.evidence_id,
    eventType: row.event_type,
    label: CUSTODY_EVENT_LABEL[row.event_type] ?? row.event_type.replace(/_/g, ' '),
    occurredAt: row.occurred_at,
    actor: row.actor,
    action: row.action,
    previousState: row.previous_state,
    newState: row.new_state,
    reason: row.reason,
    integrityHash: row.integrity_hash,
    verificationResult: row.verification_result,
    verificationReference: row.verification_reference,
    investigationId: row.investigation_id,
    source: row.source,
    origin: row.origin,
    auditId: row.audit_id,
  };
}

/** Tracked events for one item, oldest first. */
export function listCustodyEvents(evidenceId) {
  return database()
    .prepare(`SELECT ${CUSTODY_COLUMNS} FROM intel_custody_event WHERE evidence_id = ? ORDER BY occurred_at ASC, id ASC`)
    .all(evidenceId)
    .map(mapCustodyRow);
}

/** Tracked events across every item — the store-wide custody ledger. */
export function listAllCustodyEvents(limit = 500) {
  return database()
    .prepare(`SELECT ${CUSTODY_COLUMNS} FROM intel_custody_event ORDER BY occurred_at DESC LIMIT ?`)
    .all(limit)
    .map(mapCustodyRow);
}

/**
 * Audit actions that merely mirror a custody event.
 *
 * Recording a custody event also writes an audit row (so the existing
 * audit trail stays complete), which means the audit-derived history
 * below would otherwise repeat the very same event a second time under
 * a different label. Every mirrored row is written with a `CUSTODY_`
 * prefix, so the prefix is matched rather than an enumerated list —
 * a new event type cannot leak through as a phantom history entry.
 * The explicit names cover the verification mirror and any rows written
 * before the prefix existed.
 */
const CUSTODY_MIRROR_AUDIT_PREFIX = 'CUSTODY_';
const CUSTODY_MIRROR_AUDIT_ACTIONS = [
  'EVIDENCE_INTEGRITY_CHECKED',
  'EVIDENCE_INTEGRITY_FAILED',
];

function isCustodyMirrorAudit(action) {
  const name = String(action ?? '').toUpperCase();
  return name.startsWith(CUSTODY_MIRROR_AUDIT_PREFIX) || CUSTODY_MIRROR_AUDIT_ACTIONS.includes(name);
}

/**
 * Pre-existing audit rows that reference this evidence item.
 *
 * These are verified historical records — written by the existing audit
 * trail, not reconstructed — but they are not custody events, so they
 * are returned separately and never merged into the tracked sequence.
 */
export function auditDerivedHistory(evidenceId) {
  return database()
    .prepare(
      `SELECT id, occurred_at, actor, action, before, after, source, result
       FROM intel_audit
       WHERE entity_id = ? OR before = ? OR after = ?
       ORDER BY occurred_at ASC, id ASC`,
    )
    .all(evidenceId, evidenceId, evidenceId)
    .filter(row => !isCustodyMirrorAudit(row.action))
    .map(row => ({
      id: row.id,
      evidenceId,
      eventType: row.action,
      label: row.action.replace(/_/g, ' '),
      occurredAt: row.occurred_at,
      actor: row.actor,
      action: row.action,
      previousState: row.before || '',
      newState: row.after || '',
      reason: '',
      integrityHash: '',
      verificationResult: '',
      verificationReference: '',
      investigationId: null,
      source: row.source || 'AUDIT',
      origin: 'AUDIT_DERIVED',
      auditId: row.id,
    }));
}

const EVIDENCE_CUSTODY_COLUMNS =
  'id, evidence_type, source_id, source_label, observed_at, collected_at, hash, integrity_status, reliability, confidence, provenance, description, related_actor, related_handle, related_infra, related_relationship, data_state, analyst, created_at, updated_at, collection_method, collected_by, file_name, file_size, file_format, status, storage_reference, custody_tracking_since, last_verified_at, last_verified_by, last_verification_result, last_verification_detail, verification_count';

export function getEvidenceForCustody(evidenceId) {
  return database()
    .prepare(`SELECT ${EVIDENCE_CUSTODY_COLUMNS} FROM intel_evidence WHERE id = ?`)
    .get(evidenceId);
}

/**
 * The verification columns for every evidence item.
 *
 * `intel_evidence.integrity_status` is a value written at ingest and
 * claims nothing on its own. These fields record what the chain of
 * custody actually did: how many verifications ran and what the last
 * one returned. Consumers that need to know "has this been verified?"
 * must read this map, not `integrity_status`.
 */
export function listEvidenceIntegrityRows() {
  return database()
    .prepare(
      `SELECT id, hash, integrity_status, last_verified_at, last_verified_by,
              last_verification_result, last_verification_detail, verification_count
       FROM intel_evidence`,
    )
    .all();
}

/** id → { verified, label, reason } for every evidence item. */
export function evidenceIntegrityIndex() {
  const index = new Map();
  for (const row of listEvidenceIntegrityRows()) {
    const runs = Number(row.verification_count ?? 0);
    const lastResult = String(row.last_verification_result ?? '').toUpperCase();
    if (runs === 0) {
      // `integrity_status` is an ingest-time field that can read VERIFIED
      // on an item nothing has ever checked. Restating it bare alongside
      // "never verified" reads as a contradiction, so it is named as the
      // claim it is.
      const ingestClaim = String(row.integrity_status ?? '').trim();
      index.set(row.id, {
        verified: false,
        label: 'never verified',
        reason: ingestClaim
          ? `no chain-of-custody verification has ever been run; the ingest-time integrity_status field reads "${ingestClaim}", which is a recorded claim, not a digest comparison`
          : 'no chain-of-custody verification has ever been run',
      });
      continue;
    }
    if (lastResult === 'MATCH') {
      // "Digest matched", not "verified": agreement with the stored
      // reference is not evidence that the content is authentic.
      index.set(row.id, {
        verified: true,
        label: 'digest matched',
        reason: `SHA-256 recalculated over supplied content and matched the stored reference on ${row.last_verified_at}; a match shows the content is unaltered, not that the original source was authentic`,
      });
      continue;
    }
    if (lastResult === 'MISMATCH') {
      index.set(row.id, { verified: false, label: 'verification failed', reason: `SHA-256 mismatch recorded on ${row.last_verified_at}` });
      continue;
    }
    index.set(row.id, {
      verified: false,
      label: lastResult.toLowerCase().replace(/_/g, ' ') || 'not verified',
      reason: row.last_verification_detail || `last verification returned ${lastResult || 'no result'}`,
    });
  }
  return index;
}

function investigationsFor(evidenceId) {
  return database()
    .prepare('SELECT investigation_id, entity_type, role, added_at FROM intel_investigation_ref WHERE entity_id = ?')
    .all(evidenceId)
    .map(row => ({
      investigationId: row.investigation_id,
      entityType: row.entity_type,
      role: row.role,
      linkedAt: row.added_at,
    }));
}

/**
 * The full chain-of-custody view for one evidence item.
 *
 * `trackingStartedAt` is the first event this platform recorded, or the
 * evidence row's `custody_tracking_since` marker when the item was
 * already present before tracking existed. When there are no tracked
 * events at all, `historyStatus` says so explicitly so the UI can
 * state that nothing was inferred rather than showing a blank panel.
 */
export function custodyChain(evidenceId) {
  const evidence = getEvidenceForCustody(evidenceId);
  if (!evidence) return null;

  const tracked = listCustodyEvents(evidenceId);
  const historical = auditDerivedHistory(evidenceId);
  const merged = [...tracked, ...historical].sort((a, b) =>
    a.occurredAt === b.occurredAt ? a.id.localeCompare(b.id) : a.occurredAt < b.occurredAt ? -1 : 1,
  );

  const trackingStartedAt =
    tracked[0]?.occurredAt ?? evidence.custody_tracking_since ?? null;

  return {
    evidence: {
      id: evidence.id,
      evidenceType: evidence.evidence_type,
      name: evidence.file_name || evidence.description || evidence.provenance || evidence.id,
      sourceId: evidence.source_id,
      sourceLabel: evidence.source_label,
      source: evidence.source_label || evidence.source_id || 'Unknown source',
      sourceLabelText: evidence.source_label || '',
      observedAt: evidence.observed_at,
      collectedAt: evidence.collected_at,
      collectionMethod: evidence.collection_method || '',
      collectedBy: evidence.collected_by || evidence.analyst || '',
      fileName: evidence.file_name || '',
      fileSize: evidence.file_size ?? null,
      fileFormat: evidence.file_format || '',
      hash: evidence.hash || '',
      hashAlgorithm: hashAlgorithmOf(evidence.hash || ''),
      integrityStatus: evidence.integrity_status || '',
      lastVerifiedAt: evidence.last_verified_at,
      lastVerifiedBy: evidence.last_verified_by || '',
      lastVerificationResult: evidence.last_verification_result || 'NEVER_VERIFIED',
      lastVerificationDetail: evidence.last_verification_detail || '',
      verificationCount: evidence.verification_count ?? 0,
      status: evidence.status || 'REGISTERED',
      storageReference: evidence.storage_reference || '',
      provenance: evidence.provenance || '',
      description: evidence.description || '',
      relatedActor: evidence.related_actor,
      relatedHandle: evidence.related_handle,
      relatedInfrastructure: evidence.related_infra,
      relatedRelationship: evidence.related_relationship,
      dataState: evidence.data_state,
      analyst: evidence.analyst,
      createdAt: evidence.created_at,
      updatedAt: evidence.updated_at,
      reliability: evidence.reliability,
      confidence: evidence.confidence,
    },
    investigations: investigationsFor(evidenceId),
    events: merged,
    trackedEvents: tracked,
    historicalEvents: historical,
    trackingStartedAt,
    historyStatus: tracked.length
      ? 'TRACKED'
      : historical.length
        ? 'HISTORICAL_ONLY'
        : 'NO_HISTORY',
    // Stated once, at the source, so every surface that shows this
    // chain repeats the same limitation instead of implying more.
    integrityDisclaimer:
      'A matching digest shows the supplied content is consistent with the digest already recorded on this item. ' +
      'It does not establish that the original source was authentic, because the recorded digest itself was never independently attested.',
    verificationLimitation:
      'No evidence file bytes are stored alongside this record, so a digest cannot be recomputed unless content is supplied. ' +
      'Verification is reported as NOT VERIFIABLE in that case rather than assumed to have passed.',
  };
}

// ── Writes ────────────────────────────────────────────────────

/**
 * Append one custody event. There is deliberately no update or delete
 * path: the log is the record of what happened, in the order it
 * happened.
 */
export function recordCustodyEvent({
  evidenceId,
  eventType,
  actor = 'system',
  action = '',
  previousState = '',
  newState = '',
  reason = '',
  integrityHash = '',
  verificationResult = '',
  verificationReference = '',
  investigationId = null,
  source = 'API',
  origin = 'TRACKED',
  auditId = null,
  occurredAt = null,
}) {
  const type = String(eventType || '').toUpperCase();
  if (!CUSTODY_EVENT_TYPES.includes(type)) {
    throw Object.assign(new Error(`eventType must be one of ${CUSTODY_EVENT_TYPES.join(', ')}`), { status: 400 });
  }
  if (!getEvidenceForCustody(evidenceId)) {
    throw Object.assign(new Error('Evidence not found'), { status: 404 });
  }

  // The timestamp is server-side and trusted; a caller cannot backdate
  // a custody entry by supplying its own occurredAt.
  const timestamp = now();
  const row = {
    id: newId('CUS'),
    evidence_id: evidenceId,
    event_type: type,
    occurred_at: timestamp,
    actor: actor || 'system',
    action: action || CUSTODY_EVENT_LABEL[type] || type,
    previous_state: previousState ?? '',
    new_state: newState ?? '',
    reason: reason ?? '',
    integrity_hash: integrityHash ?? '',
    verification_result: verificationResult ?? '',
    verification_reference: verificationReference ?? verificationResult ?? '',
    investigation_id: investigationId ?? null,
    source: source || 'API',
    origin,
    audit_id: auditId ?? null,
    created_at: timestamp,
  };

  database()
    .prepare(
      `INSERT INTO intel_custody_event
       (id, evidence_id, event_type, occurred_at, actor, action, previous_state, new_state, reason,
        integrity_hash, verification_result, verification_reference, investigation_id, source, origin,
        audit_id, created_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    )
    .run(
      row.id, row.evidence_id, row.event_type, row.occurred_at, row.actor, row.action,
      row.previous_state, row.new_state, row.reason, row.integrity_hash, row.verification_result,
      row.verification_reference, row.investigation_id, row.source, row.origin, row.audit_id, row.created_at,
    );

  // Mark the point tracking began, without disturbing created_at or any
  // pre-existing column on the evidence row.
  database()
    .prepare(
      `UPDATE intel_evidence SET custody_tracking_since = coalesce(custody_tracking_since, ?), updated_at = ? WHERE id = ?`,
    )
    .run(timestamp, timestamp, evidenceId);

  bumpRevision();
  return mapCustodyRow(row);
}

/** SHA-256 over supplied content, hex encoded. */
function sha256(content) {
  return createHash('sha256').update(content).digest('hex');
}

/**
 * Split a stored digest into its algorithm label and its hex body.
 *
 * Records in this dataset carry the digest in two shapes: a bare hex
 * string, and an explicitly labelled `sha256:<hex>` string. Comparing a
 * freshly calculated hex digest against the labelled form would fail
 * for correct content, so the label is separated before any comparison.
 */
function splitDigest(value) {
  const raw = String(value ?? '').trim();
  const match = raw.match(/^([A-Za-z][A-Za-z0-9-]*)\s*:\s*([0-9a-fA-F]+)$/);
  if (match) return { algorithm: match[1].toUpperCase().replace('-', ''), hex: match[2].toLowerCase(), labelled: true };
  return { algorithm: '', hex: raw.toLowerCase(), labelled: false };
}

/** Best-effort digest algorithm, for display only. */
function hashAlgorithmOf(digest) {
  const { algorithm, hex, labelled } = splitDigest(digest);
  if (labelled) return algorithm || 'UNKNOWN';
  const length = hex.replace(/[^0-9a-f]/g, '').length;
  if (length === 64) return 'SHA-256';
  if (length === 40) return 'SHA-1';
  if (length === 32) return 'MD5';
  return length ? `UNRECOGNISED-${length}` : 'NONE';
}

/**
 * Verify an evidence item against its recorded digest.
 *
 * Content is supplied by the caller (base64 or utf8). With no content
 * there is nothing to hash, and the honest result is NOT VERIFIABLE —
 * this function never reports a pass it could not compute.
 *
 * The stored `hash` column is read-only here: a mismatch is flagged for
 * investigation and left in place, because replacing the reference would
 * destroy the very evidence of the discrepancy.
 */
export function verifyEvidenceIntegrity(evidenceId, { content, contentEncoding = 'utf8', actor = 'system', reason = '' } = {}) {
  const evidence = getEvidenceForCustody(evidenceId);
  if (!evidence) throw Object.assign(new Error('Evidence not found'), { status: 404 });

  const storedHash = String(evidence.hash || '').trim();
  const timestamp = now();
  const actorName = actor || 'system';

  const finish = (result, detail, calculated, reference) => {
    database()
      .prepare(
        `UPDATE intel_evidence
         SET last_verified_at = ?, last_verified_by = ?, last_verification_result = ?,
             last_verification_detail = ?, verification_count = coalesce(verification_count,0) + 1,
             updated_at = ?
         WHERE id = ?`,
      )
      .run(timestamp, actorName, result, detail, timestamp, evidenceId);

    const event = recordCustodyEvent({
      evidenceId,
      eventType: result === 'MATCH' || result === 'NOT_VERIFIABLE' ? 'INTEGRITY_VERIFIED' : 'INTEGRITY_VERIFICATION_FAILED',
      actor: actorName,
      action: `Integrity verification: ${result}`,
      previousState: evidence.last_verification_result || 'NEVER_VERIFIED',
      newState: result,
      reason: reason || detail,
      integrityHash: calculated || storedHash,
      verificationResult: result,
      verificationReference: reference,
    });

    return {
      evidenceId,
      result,
      detail,
      algorithm: hashAlgorithmOf(storedHash),
      storedHash,
      calculatedHash: calculated,
      verifiedAt: timestamp,
      verifiedBy: actorName,
      verificationCount: (evidence.verification_count ?? 0) + 1,
      integrityStatus: evidence.integrity_status,
      custodyEventId: event.id,
      // Never upgraded from a digest comparison: matching a digest is
      // not proof the source was authentic.
      authenticityEstablished: false,
      disclaimer:
        result === 'MATCH'
          ? 'Content is byte-consistent with the digest already recorded on this item. This demonstrates consistency with the stored reference, not the authenticity of the original source.'
          : result === 'MISMATCH'
            ? 'Calculated digest does not match the recorded reference. The recorded digest has been preserved unchanged and the item is flagged for investigation.'
            : 'Verification could not be performed because no evidence content was available to hash. No pass or fail is claimed.',
    };
  };

  // No stored reference to compare against.
  if (!storedHash) {
    return finish(
      'NO_REFERENCE',
      'This evidence record carries no cryptographic digest, so there is no reference to verify against.',
      '',
      'NO_REFERENCE',
    );
  }

  // No content to hash.
  if (content === undefined || content === null || content === '') {
    return finish(
      'NOT_VERIFIABLE',
      'No evidence content was supplied, so the digest could not be recalculated. This is not a pass.',
      '',
      'NOT_VERIFIABLE',
    );
  }

  let calculated;
  try {
    calculated = contentEncoding === 'base64' ? sha256(Buffer.from(String(content), 'base64')) : sha256(String(content));
  } catch (error) {
    return finish('NOT_VERIFIABLE', `Supplied content could not be decoded (${error.message}). No pass or fail is claimed.`, '', 'NOT_VERIFIABLE');
  }

  const stored = splitDigest(storedHash);
  const calculatedHex = calculated.toLowerCase();

  // The recorded reference must be a SHA-256 digest for a SHA-256
  // recalculation to mean anything. Saying so is better than reporting
  // a mismatch that is really an algorithm mismatch.
  if (stored.algorithm && stored.algorithm !== 'SHA256') {
    return finish(
      'NOT_VERIFIABLE',
      `The recorded digest is labelled ${stored.algorithm}, but this verifier recalculates SHA-256. A ${stored.algorithm} recalculation was not performed, so no pass or fail is claimed.`,
      calculatedHex,
      'ALGORITHM_MISMATCH',
    );
  }

  if (calculatedHex === stored.hex) {
    return finish('MATCH', 'Recalculated SHA-256 matches the digest recorded on this item.', calculatedHex, calculatedHex.slice(0, 16));
  }

  return finish(
    'MISMATCH',
    'Recalculated SHA-256 does not match the digest recorded on this item. The recorded digest has been preserved unchanged.',
    calculatedHex,
    calculatedHex.slice(0, 16),
  );
}

/**
 * Register a newly tracked item's first custody event.
 *
 * Called from the ingestion pipeline for evidence created *after* this
 * feature exists, so the log starts at the moment the record enters the
 * platform. Existing evidence rows are never back-filled this way — a
 * fabricated collection event would be worse than an honest gap.
 */
export function registerEvidenceCustody(record, analyst) {
  const dataState = String(record?.dataState || '').toUpperCase();
  const eventType =
    dataState === 'IMPORTED' ? 'EVIDENCE_IMPORTED'
      : dataState === 'OBSERVED' ? 'EVIDENCE_COLLECTED'
        : 'EVIDENCE_REGISTERED';
  try {
    return recordCustodyEvent({
      evidenceId: record.id,
      eventType,
      actor: analyst || record.analyst || 'system',
      action:
        dataState === 'IMPORTED' ? 'Evidence imported into the locker'
          : dataState === 'OBSERVED' ? 'Evidence collected and recorded'
            : 'Evidence registered in the locker',
      newState: 'REGISTERED',
      integrityHash: record.hash || '',
      source: 'INGEST',
    });
  } catch {
    // Custody tracking must never abort an ingestion that already
    // succeeded — the evidence row is the primary record.
    return null;
  }
}