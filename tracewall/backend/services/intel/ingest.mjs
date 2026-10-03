// ============================================================
// PhishNet — Central intelligence ingestion pipeline.
//
//   validate → normalize → extract → deduplicate → store
//   → correlate → relate → timeline → evidence → alerts
//   → source reliability → provenance → audit
//
// The whole run is ONE sqlite transaction. If any step throws, the
// transaction rolls back and the caller gets a meaningful error, so
// the database can never hold half of an ingestion.
//
// The pipeline is idempotent: submitting the same intelligence twice
// enriches the existing entities and updates last-seen values rather
// than creating duplicates.
// ============================================================
import { createHash } from 'node:crypto';
import {
  addNote,
  addTimelineEvent,
  attachEntityToInvestigation,
  bumpRevision,
  completeIngestion,
  correlationsFor,
  evidenceForEntity,
  linkRelationshipEvidence,
  listActors,
  listEvidence,
  listHandles,
  listInfrastructure,
  listPgp,
  listRelationships,
  listSources,
  listWallets,
  logIngestion,
  newId,
  raiseAlert,
  relationshipsForEntity,
  transact,
  upsertActor,
  upsertCorrelation,
  upsertEvidence,
  upsertHandle,
  upsertInfrastructure,
  upsertInvestigation,
  upsertObservation,
  upsertPgp,
  upsertRelationship,
  upsertSource,
  upsertWallet,
  writeAudit,
} from './repository.mjs';
import { correlateActors, confidenceBand } from './correlate.mjs';
import { registerEvidenceCustody } from './custodyService.mjs';
import {
  clampConfidence,
  clean,
  classifyInfrastructure,
  infrastructureKey,
  isValidEntityId,
  isValidHandle,
  isValidHost,
  isValidPgp,
  isValidWallet,
  normalizeHandle,
  normalizeHost,
  normalizePgp,
  normalizeTimestamp,
  normalizeWallet,
  now,
  splitList,
} from './normalize.mjs';

const VALID_SOURCE_TYPES = ['FORUM', 'MARKETPLACE', 'PASTE', 'LEAK_SITE', 'MESSAGING', 'THREAT_FEED', 'ONION_SERVICE'];
const VALID_EVIDENCE_TYPES = ['FORUM_POST', 'MARKETPLACE_LISTING', 'PASTE', 'LEAK_RECORD', 'MESSAGE', 'TRANSACTION', 'PGP_KEY', 'DOMAIN_REGISTRATION', 'LOG', 'ANALYSIS'];

function invalid(field, detail) {
  return Object.assign(new Error(detail ? `${field}: ${detail}` : `${field} is invalid`), { status: 400 });
}

/** Stable content hash so identical evidence is recognised, not duplicated. */
function contentHash(value) {
  return createHash('sha256').update(clean(value)).digest('hex');
}

/**
 * Reliability for a source is a running, evidence-weighted average.
 * It rises with corroboration and falls when a source is contradicted,
 * so it is never a hand-typed constant.
 */
function updateSourceReliability(sourceId) {
  if (!sourceId) return;
  const evidence = listEvidence().filter(item => item.source_id === sourceId);
  const observations = listHandles().filter(item => item.source_id === sourceId);
  if (!evidence.length && !observations.length) return;

  const evidenceScore = evidence.length
    ? evidence.reduce((sum, item) => sum + (item.reliability || 50), 0) / evidence.length
    : 50;
  const corroboration = Math.min(20, Math.max(0, new Set(evidence.map(item => item.source_id)).size - 1) * 5);
  const blended = Math.round(Math.min(100, Math.max(0, evidenceScore * 0.7 + corroboration + 15)));

  const source = listSources().find(item => item.id === sourceId);
  if (!source || source.reliability_score === blended) return;
  upsertSource({ id: source.id, name: source.name, type: source.type, reliabilityScore: blended });
}

/**
 * Ingest one submission. `payload` may carry any combination of
 * actor, handles, pgp keys, wallets, infrastructure, a source, an
 * observation, evidence, relationships, timeline events, an
 * investigation and notes — the Add Intelligence form maps onto this.
 */
export function ingest(payload, context = {}) {
  const receivedAt = now();
  const analyst = clean(context.analyst) || 'system';
  const origin = context.origin || 'API';

  // The raw submission is journalled before anything is attempted, so a
  // failure is retryable and the analyst's input is never lost.
  const ingestId = logIngestion({ receivedAt, analyst, origin, status: 'PENDING', payload });

  try {
    const result = transact(() => runPipeline(payload, { analyst, origin, receivedAt, batchId: ingestId }));
    completeIngestion(ingestId, result);
    return { ingestionId: ingestId, ...result };
  } catch (error) {
    completeIngestion(ingestId, { error: error.message }, error.message);
    // Preserve the observation: record why it failed, then re-throw so the
    // caller receives a meaningful error and nothing partial was committed.
    writeAudit({
      actor: analyst,
      action: 'INGESTION_REJECTED',
      entity: 'INGESTION',
      entityId: ingestId,
      after: clean(error.message).slice(0, 400),
      result: 'REJECTED',
      source: origin,
      batchId: ingestId,
    });
    throw error;
  }
}

function runPipeline(payload, context) {
  const { analyst, origin, receivedAt, batchId } = context;
  if (!payload || typeof payload !== 'object') throw invalid('payload', 'must be an object');

  // An empty or unrecognised submission is rejected rather than journalled as a
  // successful no-op: a 201 that created nothing reads as "ingested" to a caller
  // and hides a client that is sending the wrong field names. Every collection
  // key the pipeline understands is listed here, so a payload carrying at least
  // one of them is still accepted.
  const INGESTABLE_KEYS = [
    'source', 'sourceId', 'actor', 'actorId', 'actorName',
    'handle', 'handles', 'pgpKey', 'pgpKeys', 'wallet', 'wallets',
    'infrastructure', 'domains', 'ips', 'onionServices',
    'observation', 'content', 'evidence', 'relationships', 'timeline',
    'investigations', 'notes', 'alerts',
  ];
  const provided = INGESTABLE_KEYS.filter(key => {
    const value = payload[key];
    if (value === undefined || value === null) return false;
    if (typeof value === 'string') return value.trim().length > 0;
    if (Array.isArray(value)) return value.length > 0;
    if (typeof value === 'object') return Object.keys(value).length > 0;
    return true;
  });
  if (!provided.length) {
    throw invalid('payload', `must contain at least one ingestable field (${INGESTABLE_KEYS.join(', ')})`);
  }

  const created = {
    sources: [],
    actors: [],
    handles: [],
    pgp: [],
    wallets: [],
    infrastructure: [],
    observations: [],
    evidence: [],
    relationships: [],
    timeline: [],
    investigations: [],
    notes: [],
    correlations: [],
    alerts: [],
  };
  const merged = {
    sources: [],
    actors: [],
    handles: [],
    pgp: [],
    wallets: [],
    infrastructure: [],
    observations: [],
    evidence: [],
    relationships: [],
    timeline: [],
    investigations: [],
    notes: [],
    correlations: [],
    alerts: [],
  };

  // ── 1. Source ───────────────────────────────────────────────
  // Every observation must be attributable, so a source is resolved
  // first and referenced by everything that follows.
  let sourceId = null;
  let sourceLabel = clean(payload.source) || '';
  if (payload.sourceId && isValidEntityId(payload.sourceId)) sourceId = payload.sourceId;

  if (!sourceId && sourceLabel) {
    const type = VALID_SOURCE_TYPES.includes(String(payload.sourceType || '').toUpperCase())
      ? String(payload.sourceType).toUpperCase()
      : 'FORUM';
    const source = upsertSource({
      name: sourceLabel,
      type,
      reference: clean(payload.sourceReference) || null,
      collectionMethod: clean(payload.collectionMethod) || 'analyst-entry',
      lastObserved: receivedAt,
      dataState: payload.dataState || 'ANALYST_ADDED',
      analyst,
    });
    sourceId = source.id;
    if (source.created) created.sources.push(source.id);
    merged.sources.push(source.id);
  }

  if (payload.newSource && clean(payload.newSource.name)) {
    const source = upsertSource({
      name: clean(payload.newSource.name),
      type: VALID_SOURCE_TYPES.includes(String(payload.newSource.type).toUpperCase())
        ? String(payload.newSource.type).toUpperCase()
        : 'FORUM',
      reliabilityScore: clampConfidence(payload.newSource.reliabilityScore, 50),
      healthStatus: 'ACTIVE',
      activityLevel: payload.newSource.activityLevel || 'MEDIUM',
      description: clean(payload.newSource.description),
      dataState: 'ANALYST_ADDED',
      analyst,
    });
    sourceId = source.id;
    if (source.created) created.sources.push(source.id);
    merged.sources.push(source.id);
  }

  const observedAt = normalizeTimestamp(payload.observedAt || payload.timestamp, receivedAt);

  // ── 2. Actor ────────────────────────────────────────────────
  let actorId = null;
  const actorInput = payload.actor || (payload.actorId ? { id: payload.actorId } : null);
  if (actorInput) {
    const requestedId = clean(actorInput.id);
    if (requestedId && !isValidEntityId(requestedId)) throw invalid('actor.id', 'contains unsupported characters');

    // Re-submitting an existing actor id updates it; a new one is created.
    if (requestedId) {
      const existing = listActors().find(item => item.id === requestedId);
      if (existing) {
        actorId = existing.id;
        if (clean(actorInput.name) || splitList(actorInput.aliases).length) {
          upsertActor({
            id: existing.id,
            displayName: clean(actorInput.name) || existing.display_name,
            status: actorInput.status || existing.status,
            activityLevel: actorInput.activityLevel || existing.activity_level,
            confidenceScore: actorInput.confidence !== undefined ? clampConfidence(actorInput.confidence, existing.confidence_score) : existing.confidence_score,
            firstSeen: existing.first_seen,
            lastSeen: observedAt,
            dataState: payload.dataState || existing.data_state,
            analyst,
          });
        }
      }
    }
    if (!actorId) {
      const actor = upsertActor({
        id: requestedId || undefined,
        displayName: clean(actorInput.name),
        status: actorInput.status || 'ACTIVE',
        activityLevel: actorInput.activityLevel || 'MEDIUM',
        confidenceScore: clampConfidence(actorInput.confidence, 60),
        primaryMotivation: clean(actorInput.motivation),
        firstSeen: observedAt,
        lastSeen: observedAt,
        behavioralProfile: actorInput.behavioralProfile || {},
        stylometricProfile: actorInput.stylometricProfile || {},
        dataState: payload.dataState || 'ANALYST_ADDED',
        analyst,
      });
      actorId = actor.id;
      if (actor.created) created.actors.push(actor.id);
      merged.actors.push(actor.id);

      writeAudit({
        actor: analyst,
        action: 'ACTOR_CREATED',
        entity: 'ACTOR',
        entityId: actor.id,
        after: `${clean(actorInput.name) || actor.id} (${observedAt})`,
        source: sourceLabel || 'Central Intelligence Model',
        batchId,
      });
      addTimelineEvent({
        actorId: actor.id,
        entityId: actor.id,
        eventType: 'FIRST_SEEN',
        occurredAt: observedAt,
        title: 'Actor discovered',
        description: `${clean(actorInput.name) || actor.id} was entered into the central intelligence model.`,
        sourceId,
        confidence: clampConfidence(actorInput.confidence, 60),
        dataState: payload.dataState || 'ANALYST_ADDED',
        analyst,
      });
    }
  }

  // ── 3. Handles ──────────────────────────────────────────────
  const handleValues = Array.isArray(payload.handles)
    ? payload.handles
    : splitList(payload.handles).map(value => ({ handle: value }));
  const handleIds = [];
  for (const entry of handleValues) {
    const value = clean(entry.handle || entry.value);
    if (!value) continue;
    if (!isValidHandle(value)) throw invalid('handle', `"${value}" is not a usable handle`);
    const platform = clean(entry.platform) || 'UNKNOWN';
    const handle = upsertHandle({
      value,
      normalized: normalizeHandle(value),
      platform,
      sourceId,
      firstSeen: observedAt,
      lastSeen: observedAt,
      confidence: clampConfidence(entry.confidence, 70),
      dataState: payload.dataState || 'OBSERVED',
      analyst,
    });
    handleIds.push(handle.id);
    (handle.created ? created.handles : merged.handles).push(handle.id);

    if (handle.created) {
      writeAudit({
        actor: analyst,
        action: 'HANDLE_ADDED',
        entity: 'HANDLE',
        entityId: handle.id,
        after: `${value} on ${platform}`,
        source: sourceLabel || 'Central Intelligence Model',
        batchId,
      });
      raiseAlert({
        type: 'NEW_HANDLE',
        severity: 'MEDIUM',
        title: `New handle detected: ${value}`,
        reason: `Handle "${value}" was first observed on ${platform}${sourceLabel ? ` via ${sourceLabel}` : ''}.`,
        entityId: handle.id,
        entityType: 'HANDLE',
        actorId,
        confidence: clampConfidence(entry.confidence, 70),
        dedupeKey: `NEW_HANDLE:${handle.id}`,
      });
    }

    if (actorId) {
      const relationship = upsertRelationship({
        sourceEntity: actorId,
        targetEntity: handle.id,
        sourceType: 'ACTOR',
        targetType: 'HANDLE',
        type: 'USES_HANDLE',
        confidence: clampConfidence(entry.confidence, 70),
        explanation: `Actor ${actorId} was observed using handle "${value}" on ${platform}.`,
        firstObserved: observedAt,
        lastObserved: observedAt,
        supporting: [`Handle ${value} on ${platform}${sourceLabel ? ` from ${sourceLabel}` : ''}`],
        against: [],
        derivation: 'OBSERVED',
        dataState: payload.dataState || 'OBSERVED',
        analyst,
      });
      (relationship.created ? created.relationships : merged.relationships).push(relationship.id);
      if (relationship.created) {
        writeAudit({
          actor: analyst,
          action: 'RELATIONSHIP_CREATED',
          entity: 'RELATIONSHIP',
          entityId: relationship.id,
          after: `${actorId} USES_HANDLE ${handle.id}`,
          source: sourceLabel,
          batchId,
        });
        addTimelineEvent({
          actorId,
          entityId: handle.id,
          eventType: 'HANDLE_OBSERVED',
          occurredAt: observedAt,
          title: `Handle observed: ${value}`,
          description: `${value} was observed on ${platform}.`,
          sourceId,
          confidence: clampConfidence(entry.confidence, 70),
          dataState: payload.dataState || 'OBSERVED',
          analyst,
        });
      }
    }
  }

  // ── 4. PGP keys ─────────────────────────────────────────────
  const pgpValues = Array.isArray(payload.pgpKeys) ? payload.pgpKeys : splitList(payload.pgpKeys).map(fingerprint => ({ fingerprint }));
  for (const entry of pgpValues) {
    const fingerprint = clean(entry.fingerprint || entry.value);
    if (!fingerprint) continue;
    if (!isValidPgp(fingerprint)) throw invalid('pgpKey', `"${fingerprint}" is not a usable fingerprint`);
    const key = upsertPgp({
      fingerprint,
      normalized: normalizePgp(fingerprint),
      firstSeen: observedAt,
      lastSeen: observedAt,
      confidence: clampConfidence(entry.confidence, 80),
      dataState: payload.dataState || 'OBSERVED',
      analyst,
    });
    (key.created ? created.pgp : merged.pgp).push(key.id);

    if (key.created) {
      writeAudit({
        actor: analyst,
        action: 'PGP_ADDED',
        entity: 'PGP',
        entityId: key.id,
        after: fingerprint,
        source: sourceLabel,
        batchId,
      });
      raiseAlert({
        type: 'NEW_PGP',
        severity: 'MEDIUM',
        title: `New PGP key: ${fingerprint}`,
        reason: `PGP key ${fingerprint} was first observed.`,
        entityId: key.id,
        entityType: 'PGP',
        actorId,
        confidence: clampConfidence(entry.confidence, 80),
        dedupeKey: `NEW_PGP:${key.id}`,
      });
    }

    if (actorId) {
      const relationship = upsertRelationship({
        sourceEntity: actorId,
        targetEntity: key.id,
        sourceType: 'ACTOR',
        targetType: 'PGP',
        type: 'SHARED_PGP',
        confidence: clampConfidence(entry.confidence, 80),
        explanation: `Actor ${actorId} was observed using PGP key ${fingerprint}.`,
        firstObserved: observedAt,
        lastObserved: observedAt,
        supporting: [`PGP key ${fingerprint} used by ${actorId}`],
        against: [],
        derivation: 'OBSERVED',
        dataState: payload.dataState || 'OBSERVED',
        analyst,
      });
      (relationship.created ? created.relationships : merged.relationships).push(relationship.id);
      if (relationship.created) {
        addTimelineEvent({
          actorId,
          entityId: key.id,
          eventType: 'PGP_OBSERVED',
          occurredAt: observedAt,
          title: 'PGP key observed',
          description: `Key ${fingerprint} was linked to ${actorId}.`,
          sourceId,
          confidence: clampConfidence(entry.confidence, 80),
          dataState: payload.dataState || 'OBSERVED',
          analyst,
        });
      }
    }
  }

  // ── 5. Wallets ──────────────────────────────────────────────
  const walletValues = Array.isArray(payload.wallets) ? payload.wallets : splitList(payload.wallets).map(address => ({ address }));
  for (const entry of walletValues) {
    const address = clean(entry.address || entry.value);
    if (!address) continue;
    if (!isValidWallet(address)) throw invalid('wallet', `"${address}" is not a usable wallet address`);
    const wallet = upsertWallet({
      address,
      normalized: normalizeWallet(address),
      network: clean(entry.network),
      firstSeen: observedAt,
      lastSeen: observedAt,
      txCount: Number(entry.txCount) || 0,
      confidence: clampConfidence(entry.confidence, 75),
      dataState: payload.dataState || 'OBSERVED',
      analyst,
    });
    (wallet.created ? created.wallets : merged.wallets).push(wallet.id);

    if (wallet.created) {
      writeAudit({
        actor: analyst,
        action: 'WALLET_ADDED',
        entity: 'WALLET',
        entityId: wallet.id,
        after: address,
        source: sourceLabel,
        batchId,
      });
      raiseAlert({
        type: 'NEW_WALLET',
        severity: 'MEDIUM',
        title: `New wallet: ${address}`,
        reason: `Wallet ${address} was first observed.`,
        entityId: wallet.id,
        entityType: 'WALLET',
        actorId,
        confidence: clampConfidence(entry.confidence, 75),
        dedupeKey: `NEW_WALLET:${wallet.id}`,
      });
    }

    if (actorId) {
      const relationship = upsertRelationship({
        sourceEntity: actorId,
        targetEntity: wallet.id,
        sourceType: 'ACTOR',
        targetType: 'WALLET',
        type: 'SHARED_WALLET',
        confidence: clampConfidence(entry.confidence, 75),
        explanation: `Actor ${actorId} was observed using wallet ${address}.`,
        firstObserved: observedAt,
        lastObserved: observedAt,
        supporting: [`Wallet ${address} used by ${actorId}`],
        against: [],
        derivation: 'OBSERVED',
        dataState: payload.dataState || 'OBSERVED',
        analyst,
      });
      (relationship.created ? created.relationships : merged.relationships).push(relationship.id);
    }
  }

  // ── 6. Infrastructure ───────────────────────────────────────
  const infraValues = Array.isArray(payload.infrastructure)
    ? payload.infrastructure
    : splitList(payload.infrastructure).map(value => ({ value }));
  for (const entry of infraValues) {
    const value = clean(entry.value || entry.domain || entry.address);
    if (!value) continue;
    if (!isValidHost(value)) throw invalid('infrastructure', `"${value}" is not a usable domain or address`);
    const type = classifyInfrastructure(value, entry.type);
    const normalized = infrastructureKey(value, type).split(':').slice(1).join(':');
    const infra = upsertInfrastructure({
      id: entry.id && isValidEntityId(entry.id) ? entry.id : undefined,
      type,
      value,
      normalized: type === 'IP' ? normalized : normalizeHost(value),
      firstSeen: observedAt,
      lastObserved: observedAt,
      registrar: clean(entry.registrar) || null,
      hostingProvider: clean(entry.hostingProvider) || null,
      asn: clean(entry.asn) || null,
      country: clean(entry.country) || null,
      tlsIssuer: clean(entry.tlsIssuer) || null,
      dataState: payload.dataState || 'OBSERVED',
      analyst,
    });
    (infra.created ? created.infrastructure : merged.infrastructure).push(infra.id);

    if (infra.created) {
      writeAudit({
        actor: analyst,
        action: 'INFRASTRUCTURE_ADDED',
        entity: 'INFRASTRUCTURE',
        entityId: infra.id,
        after: `${type} ${value}`,
        source: sourceLabel,
        batchId,
      });
      raiseAlert({
        type: 'INFRASTRUCTURE_CHANGE',
        severity: 'MEDIUM',
        title: `New infrastructure: ${value}`,
        reason: `${type} ${value} was first observed.`,
        entityId: infra.id,
        entityType: 'INFRASTRUCTURE',
        actorId,
        confidence: clampConfidence(entry.confidence, 65),
        dedupeKey: `INFRA:${infra.id}`,
      });
    }

    if (actorId) {
      const relationship = upsertRelationship({
        sourceEntity: actorId,
        targetEntity: infra.id,
        sourceType: 'ACTOR',
        targetType: 'INFRASTRUCTURE',
        type: 'SHARED_INFRASTRUCTURE',
        confidence: clampConfidence(entry.confidence, 65),
        explanation: `Actor ${actorId} was observed using ${type} ${value}.`,
        firstObserved: observedAt,
        lastObserved: observedAt,
        supporting: [`${type} ${value} attributed to ${actorId}`],
        against: [],
        derivation: 'OBSERVED',
        dataState: payload.dataState || 'OBSERVED',
        analyst,
      });
      (relationship.created ? created.relationships : merged.relationships).push(relationship.id);
      if (relationship.created) {
        addTimelineEvent({
          actorId,
          entityId: infra.id,
          eventType: 'INFRASTRUCTURE_CHANGE',
          occurredAt: observedAt,
          title: 'Infrastructure discovered',
          description: `${type} ${value} was linked to ${actorId}.`,
          sourceId,
          confidence: clampConfidence(entry.confidence, 65),
          dataState: payload.dataState || 'OBSERVED',
          analyst,
        });
      }
    }
  }

  // ── 7. Evidence ─────────────────────────────────────────────
  // Evidence is created after the entities it supports exist, so it can
  // reference them without a second pass.
  let evidenceId = null;
  const evidenceInput = payload.evidence || (payload.evidenceContent ? { content: payload.evidenceContent } : null);
  if (evidenceInput) {
    const content = clean(evidenceInput.content || evidenceInput.provenance || 'Analyst-submitted evidence');
    const evidence = upsertEvidence({
      id: evidenceInput.id && isValidEntityId(evidenceInput.id) ? evidenceInput.id : undefined,
      evidenceType: VALID_EVIDENCE_TYPES.includes(String(evidenceInput.evidenceType).toUpperCase())
        ? String(evidenceInput.evidenceType).toUpperCase()
        : 'ANALYSIS',
      sourceId,
      sourceLabel,
      observedAt,
      collectedAt: receivedAt,
      hash: evidenceInput.hash ? clean(evidenceInput.hash) : contentHash(content),
      reliability: clampConfidence(evidenceInput.reliability, sourceId ? 60 : 50),
      confidence: clampConfidence(evidenceInput.confidence, 70),
      provenance: clean(evidenceInput.provenance) || `${sourceLabel || 'Analyst entry'} — recorded by ${analyst}`,
      description: content,
      relatedActor: actorId,
      relatedHandle: handleIds[0] ?? null,
      relatedInfra: created.infrastructure[0] ?? merged.infrastructure[0] ?? null,
      dataState: payload.dataState || 'ANALYST_ADDED',
      analyst,
    });
    evidenceId = evidence.id;
    (evidence.created ? created.evidence : merged.evidence ?? []).push(evidence.id);

    if (evidence.created) {
      writeAudit({
        actor: analyst,
        action: 'EVIDENCE_ADDED',
        entity: 'EVIDENCE',
        entityId: evidence.id,
        after: content.slice(0, 200),
        source: sourceLabel,
        batchId,
      });
      // Open this item's chain of custody at the moment it entered the
      // platform. Only newly created rows get an opening event: a row
      // that already existed has no such record, and inventing one
      // would be a fabricated custody entry.
      registerEvidenceCustody(
        { id: evidence.id, hash: evidenceInput.hash ? clean(evidenceInput.hash) : contentHash(content), dataState: payload.dataState || 'ANALYST_ADDED', analyst },
        analyst,
      );
      addTimelineEvent({
        actorId: actorId || '',
        entityId: evidence.id,
        eventType: 'EVIDENCE_COLLECTION',
        occurredAt: observedAt,
        title: 'Evidence collected',
        description: content.slice(0, 200),
        sourceId,
        confidence: clampConfidence(evidenceInput.confidence, 70),
        dataState: payload.dataState || 'ANALYST_ADDED',
        analyst,
      });
    }
  }

  // Support every relationship created in this run with the evidence
  // that justified it, so the evidence chain is never empty.
  if (evidenceId) {
    for (const relationshipId of created.relationships) linkRelationshipEvidence(relationshipId, evidenceId);
  }

  // ── 8. Observation ──────────────────────────────────────────
  if (payload.observation || clean(payload.content)) {
    const content = clean((payload.observation && payload.observation.content) || payload.content);
    const observation = upsertObservation({
      observationType: clean((payload.observation && payload.observation.type) || payload.observationType) || 'HANDLE_OBSERVED',
      content,
      observedAt,
      sourceId,
      actorId,
      handleId: handleIds[0] ?? null,
      platform: clean(payload.platform) || null,
      confidence: clampConfidence((payload.observation && payload.observation.confidence) ?? payload.confidence, 60),
      tags: splitList((payload.observation && payload.observation.tags) || payload.tags),
      notes: clean((payload.observation && payload.observation.notes) || payload.notes),
      dataState: payload.dataState || 'OBSERVED',
      analyst,
    });
    (observation.created ? created.observations : merged.observations ?? []).push(observation.id);
    if (observation.created) {
      writeAudit({
        actor: analyst,
        action: 'OBSERVATION_ADDED',
        entity: 'OBSERVATION',
        entityId: observation.id,
        after: content.slice(0, 200),
        source: sourceLabel,
        batchId,
      });
    }
  }

  // ── 9. Explicit relationships from the analyst ──────────────
  for (const entry of Array.isArray(payload.relationships) ? payload.relationships : []) {
    const sourceEntity = clean(entry.sourceEntity);
    const targetEntity = clean(entry.targetEntity);
    if (!sourceEntity || !targetEntity) continue;
    const relationship = upsertRelationship({
      sourceEntity,
      targetEntity,
      sourceType: clean(entry.sourceType) || 'UNKNOWN',
      targetType: clean(entry.targetType) || 'UNKNOWN',
      type: clean(entry.type) || 'ASSOCIATED_WITH',
      confidence: clampConfidence(entry.confidence, 60),
      explanation: clean(entry.explanation) || `Recorded by ${analyst}.`,
      firstObserved: observedAt,
      lastObserved: observedAt,
      supporting: splitList(entry.supporting),
      against: splitList(entry.against),
      derivation: 'OBSERVED',
      dataState: payload.dataState || 'ANALYST_ADDED',
      analyst,
    });
    (relationship.created ? created.relationships : merged.relationships).push(relationship.id);
    if (evidenceId) linkRelationshipEvidence(relationship.id, evidenceId);
    if (relationship.created) {
      writeAudit({
        actor: analyst,
        action: 'RELATIONSHIP_CREATED',
        entity: 'RELATIONSHIP',
        entityId: relationship.id,
        after: `${sourceEntity} ${clean(entry.type)} ${targetEntity}`,
        source: sourceLabel,
        batchId,
      });
      addTimelineEvent({
        actorId: sourceEntity.startsWith('ACT') ? sourceEntity : actorId || '',
        entityId: relationship.id,
        eventType: 'RELATIONSHIP_FORMATION',
        occurredAt: observedAt,
        title: 'Relationship recorded',
        description: clean(entry.explanation) || `${sourceEntity} → ${targetEntity}`,
        sourceId,
        confidence: clampConfidence(entry.confidence, 60),
        dataState: payload.dataState || 'ANALYST_ADDED',
        analyst,
      });
    }
  }

  // ── 10. Timeline events from the analyst ────────────────────
  for (const entry of Array.isArray(payload.timeline) ? payload.timeline : []) {
    const title = clean(entry.title);
    if (!title) continue;
    addTimelineEvent({
      actorId: clean(entry.actorId) || actorId || '',
      entityId: clean(entry.entityId) || actorId || '',
      eventType: clean(entry.type) || 'PLATFORM_ACTIVITY',
      occurredAt: normalizeTimestamp(entry.occurredAt, observedAt),
      title,
      description: clean(entry.description),
      sourceId,
      confidence: clampConfidence(entry.confidence, 60),
      dataState: payload.dataState || 'ANALYST_ADDED',
      analyst,
    });
    created.timeline.push(title);
  }

  // ── 11. Investigation ───────────────────────────────────────
  let investigationId = null;
  const investigationInput = payload.investigation;
  if (investigationInput && clean(investigationInput.title)) {
    const investigation = upsertInvestigation({
      id: investigationInput.id && isValidEntityId(investigationInput.id) ? investigationInput.id : undefined,
      title: clean(investigationInput.title),
      description: clean(investigationInput.description),
      status: investigationInput.status || 'ACTIVE',
      analyst,
      seedActorId: clean(investigationInput.seedActorId) || actorId,
      steps: Array.isArray(investigationInput.steps) ? investigationInput.steps : [],
      confidence: clampConfidence(investigationInput.confidence, 0),
      dataState: payload.dataState || 'ANALYST_ADDED',
    });
    investigationId = investigation.id;
    if (investigation.created) created.investigations.push(investigation.id);

    // References, never copies: the investigation always sees live data.
    const seedActorRef = investigationInput.seedActorId && isValidEntityId(investigationInput.seedActorId)
      ? investigationInput.seedActorId
      : actorId;
    for (const entityId of [seedActorRef, ...handleIds, ...created.pgp, ...created.wallets, ...created.infrastructure, evidenceId].filter(Boolean)) {
      attachEntityToInvestigation(investigation.id, entityId, 'REFERENCE');
    }
    if (investigation.created) {
      writeAudit({
        actor: analyst,
        action: 'INVESTIGATION_CREATED',
        entity: 'INVESTIGATION',
        entityId: investigation.id,
        after: clean(investigationInput.title),
        source: sourceLabel,
        batchId,
      });
    }
  }

  // ── 12. Notes ───────────────────────────────────────────────
  for (const entry of Array.isArray(payload.notes) ? payload.notes : []) {
    const text = clean(entry.text);
    if (!text) continue;
    const note = addNote({
      entityType: clean(entry.entityType) || 'ACTOR',
      entityId: clean(entry.entityId) || actorId || '',
      author: analyst,
      text,
    });
    created.notes.push(note.id);
  }

  // ── 13. Correlation ─────────────────────────────────────────
  // Re-run correlation over the whole graph so newly shared identifiers
  // are picked up everywhere, not just for the submitted actor.
  const correlation = correlateActors();
  created.correlations = correlation.created;

  // A strong new correlation is worth an analyst's attention.
  for (const item of correlation.created) {
    if (item.confidence >= 60) {
      raiseAlert({
        type: 'HIGH_CONFIDENCE_CORRELATION',
        severity: 'INFO',
        title: `${item.left} ↔ ${item.right} (${item.confidence}%)`,
        reason: `Correlated by ${item.signals.join(' + ')}. This is a correlation, not confirmed identity.`,
        entityId: item.right,
        entityType: 'ACTOR',
        actorId: item.left,
        confidence: item.confidence,
        dedupeKey: `CORRELATION:${item.left}:${item.right}`,
      });
    }
  }

  // ── 14. Source reliability ──────────────────────────────────
  if (sourceId) updateSourceReliability(sourceId);

  const revision = bumpRevision();
  writeAudit({
    actor: analyst,
    action: 'INGESTION_COMPLETED',
    entity: 'INGESTION',
    entityId: batchId,
    after: `created ${Object.values(created).flat().length} record(s)`,
    source: sourceLabel || 'Central Intelligence Model',
    batchId,
  });

  const totalCreated = Object.values(created).flat().length;
  const totalMerged = Object.values(merged).flat().length;

  return {
    status: 'ok',
    revision,
    analyst,
    sourceId,
    actorId,
    evidenceId,
    investigationId,
    created,
    merged,
    correlation: { created: correlation.created.length, updated: correlation.updated.length },
    counts: { created: totalCreated, merged: totalMerged },
  };
}

/** Convenience wrapper used by the AI layer to answer "what is connected to X". */
export function describeEntity(entityId) {
  const normalized = normalizeHost(entityId);
  const actors = listActors();
  const actor = actors.find(item => item.id === entityId || item.id.toLowerCase() === normalized);
  const handle = listHandles().find(
    item => item.id === entityId || item.normalized === normalizeHandle(entityId) || item.value.toLowerCase() === normalized,
  );
  const wallet = listWallets().find(item => item.id === entityId || item.normalized === normalizeWallet(entityId));
  const infra = listInfrastructure().find(item => item.id === entityId || item.value.toLowerCase() === normalized);
  const key = listPgp().find(item => item.id === entityId || item.normalized === normalizePgp(entityId));

  const resolved = actor || handle || wallet || infra || key;
  if (!resolved) return null;

  const observed = [];
  const correlations = [];
  for (const link of correlationsFor(resolved.id)) {
    correlations.push({
      other: link.subject_id === resolved.id ? link.object_id : link.subject_id,
      confidence: link.confidence,
      band: confidenceBand(link.confidence),
      status: link.status,
      explanation: link.explanation,
    });
  }

  return {
    entity: resolved,
    kind: actor ? 'ACTOR' : handle ? 'HANDLE' : wallet ? 'WALLET' : infra ? 'INFRASTRUCTURE' : 'PGP',
    relationships: relationshipsForEntity(resolved.id),
    evidence: evidenceForEntity(resolved.id),
    correlations,
    // Observed facts and analytical inferences stay in separate buckets.
    observedFacts: [
      handle ? `Handle "${handle.value}" observed on ${handle.platform}` : null,
      wallet ? `Wallet ${wallet.address} observed ${wallet.tx_count} transaction(s)` : null,
      infra ? `Infrastructure ${infra.value} (${infra.type}) observed` : null,
      key ? `PGP key ${key.fingerprint} observed` : null,
    ].filter(Boolean),
    inferences: correlations.filter(item => item.status === 'CANDIDATE'),
  };
}

export { contentHash, VALID_SOURCE_TYPES, VALID_EVIDENCE_TYPES };
