// ============================================================
// PhishNet — Frontend dataset reconciliation.
//
// The existing UI is local-first and synchronous: every mutation
// rebuilds the in-memory dataset immediately so no page has to wait.
// The backend, however, is the authoritative store. This module
// accepts a full intelligence snapshot exactly as the frontend holds
// it, reconciles it into the normalized tables using natural keys
// (so records are enriched, never duplicated), and returns the
// canonical dataset for the frontend to keep as its cache.
//
// Reconcile is additive: a snapshot never deletes a backend record
// the snapshot does not mention, because a fresh browser tab with an
// older cache must not silently wipe intelligence another tab wrote.
// Reset / Clear are explicit, separate controls.
// ============================================================
import {
  addTimelineEvent,
  addNote,
  attachEntityToInvestigation,
  bumpRevision,
  linkRelationshipEvidence,
  transact,
  upsertActor,
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
import { correlateActors } from './correlate.mjs';
import { buildDataset } from './query.mjs';
import {
  classifyInfrastructure,
  normalizeHandle,
  normalizeHost,
  normalizePgp,
  normalizeTimestamp,
  normalizeWallet,
  now,
} from './normalize.mjs';

const ANALYST = 'analyst-sync';

function confidence(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? Math.round(Math.min(100, Math.max(0, numeric))) : 50;
}

/**
 * Reconcile a full frontend `IntelligenceDataset` snapshot into the
 * normalized tables. Records are matched by natural key — normalized
 * handle+platform, normalized PGP fingerprint, normalized wallet
 * address, normalized infrastructure value+type, source name, actor id
 * — so backend-assigned ids (`HDL-XXXX`) are kept and the frontend's
 * display ids are never assumed to be canonical.
 */
export function reconcileDataset(dataset = {}) {
  const stamp = now();

  return transact(() => {
    let actors = 0;
    let handles = 0;
    let pgp = 0;
    let wallets = 0;
    let infrastructure = 0;
    let observations = 0;
    let evidence = 0;
    let relationships = 0;
    let timeline = 0;
    let investigations = 0;
    let notes = 0;

    // Natural-key maps so edges reference the *stored* ids, not display ids.
    const handleIds = new Map();
    const pgpIds = new Map();
    const walletIds = new Map();
    const infraIds = new Map();
    const sourceNameIds = new Map();

    // ── Sources ──────────────────────────────────────────────
    for (const source of dataset.sources || []) {
      const result = upsertSource({
        id: source.id,
        name: source.name,
        type: source.type || 'FORUM',
        reference: source.reference,
        collectionMethod: source.collectionMethod,
        firstObserved: normalizeTimestamp(source.firstObserved, stamp),
        lastObserved: normalizeTimestamp(source.lastObserved, stamp),
        reliabilityScore: confidence(source.reliabilityScore),
        healthStatus: 'ACTIVE',
        activityLevel: source.activityLevel || 'MEDIUM',
        status: source.status || 'ACTIVE',
        description: source.description || '',
        onionAddress: source.onionAddress,
        dataState: source.dataState || 'ANALYST_ADDED',
        analyst: ANALYST,
      });
      sourceNameIds.set(source.id, result.id);
      if (source.name) sourceNameIds.set(source.name, result.id);
    }

    // ── Actors ───────────────────────────────────────────────
    for (const actor of dataset.actors || []) {
      const result = upsertActor({
        id: actor.id,
        displayName: actor.aliases?.[0] || actor.id,
        status: actor.status || 'ACTIVE',
        activityLevel: actor.activityLevel || 'MEDIUM',
        confidenceScore: confidence(actor.confidenceScore),
        primaryMotivation: actor.primaryMotivation || '',
        firstSeen: normalizeTimestamp(actor.firstSeen, stamp),
        lastSeen: normalizeTimestamp(actor.lastSeen, stamp),
        behavioralProfile: actor.behavioralProfile || {},
        stylometricProfile: actor.stylometricProfile || {},
        dataState: actor.dataState || 'ANALYST_ADDED',
        analyst: ANALYST,
      });
      if (result.created) actors += 1;
    }

    // ── Handles ──────────────────────────────────────────────
    for (const handle of dataset.handles || []) {
      const normalized = handle.normalized || normalizeHandle(handle.value);
      const result = upsertHandle({
        id: handle.id,
        value: handle.value,
        normalized,
        platform: handle.platform || 'UNKNOWN',
        sourceId: handle.sourceId
          ? sourceNameIds.get(handle.sourceId) || null
          : null,
        firstSeen: normalizeTimestamp(handle.firstSeen, stamp),
        lastSeen: normalizeTimestamp(handle.lastSeen, stamp),
        confidence: confidence(handle.confidence),
        dataState: handle.dataState || 'ANALYST_ADDED',
        analyst: ANALYST,
      });
      handleIds.set(handle.id, result.id);
      handleIds.set(handle.value, result.id);
      handleIds.set(normalized, result.id);
      if (result.created) handles += 1;

      // Ownership edge from the frontend twin so the graph, bundle and
      // searches all agree on "this actor uses this handle".
      const actorId = handle.actorId || dataset.handles.find(h => h.id === handle.id)?.actorId;
      if (actorId) {
        const relationship = upsertRelationship({
          sourceEntity: actorId,
          targetEntity: result.id,
          sourceType: 'ACTOR',
          targetType: 'HANDLE',
          type: 'USES_HANDLE',
          confidence: confidence(handle.confidence),
          explanation: `${actorId} uses handle "${handle.value}" on ${handle.platform}.`,
          derivation: 'OBSERVED',
          supporting: [`Handle observed on ${handle.platform}`],
          dataState: 'ANALYST_ADDED',
          analyst: ANALYST,
        });
        if (relationship.created) relationships += 1;
      }
    }

    // ── PGP keys ─────────────────────────────────────────────
    for (const key of dataset.pgpKeys || []) {
      const normalized = normalizePgp(key.fingerprint);
      const result = upsertPgp({
        id: key.id,
        fingerprint: key.fingerprint,
        normalized,
        firstSeen: normalizeTimestamp(key.firstSeen, stamp),
        lastSeen: normalizeTimestamp(key.lastSeen, stamp),
        confidence: confidence(key.confidence),
        dataState: key.dataState || 'ANALYST_ADDED',
        analyst: ANALYST,
      });
      pgpIds.set(key.id, result.id);
      if (result.created) pgp += 1;
      for (const actorId of key.actorIds || []) {
        const relationship = upsertRelationship({
          sourceEntity: actorId,
          targetEntity: result.id,
          sourceType: 'ACTOR',
          targetType: 'PGP',
          type: 'SHARED_PGP',
          confidence: confidence(key.confidence),
          explanation: `${actorId} uses PGP key ${key.fingerprint}.`,
          derivation: 'OBSERVED',
          supporting: [`PGP key ${key.fingerprint}`],
          dataState: 'ANALYST_ADDED',
          analyst: ANALYST,
        });
        if (relationship.created) relationships += 1;
      }
    }

    // ── Wallets ──────────────────────────────────────────────
    for (const wallet of dataset.wallets || []) {
      const normalized = normalizeWallet(wallet.address);
      const result = upsertWallet({
        id: wallet.id,
        address: wallet.address,
        normalized,
        network: wallet.network || '',
        firstSeen: normalizeTimestamp(wallet.firstSeen, stamp),
        lastSeen: normalizeTimestamp(wallet.lastSeen, stamp),
        txCount: Number(wallet.txCount) || 0,
        confidence: confidence(wallet.confidence),
        dataState: wallet.dataState || 'ANALYST_ADDED',
        analyst: ANALYST,
      });
      walletIds.set(wallet.id, result.id);
      walletIds.set(wallet.address, result.id);
      if (result.created) wallets += 1;
      for (const actorId of wallet.actorIds || []) {
        const relationship = upsertRelationship({
          sourceEntity: actorId,
          targetEntity: result.id,
          sourceType: 'ACTOR',
          targetType: 'WALLET',
          type: 'SHARED_WALLET',
          confidence: confidence(wallet.confidence),
          explanation: `${actorId} uses wallet ${wallet.address}.`,
          derivation: 'OBSERVED',
          supporting: [`Wallet ${wallet.address}`],
          dataState: 'ANALYST_ADDED',
          analyst: ANALYST,
        });
        if (relationship.created) relationships += 1;
      }
    }

    // ── Infrastructure ───────────────────────────────────────
    for (const item of dataset.infrastructure || []) {
      const type = classifyInfrastructure(item.value, item.type);
      const normalized = normalizeHost(item.value);
      const result = upsertInfrastructure({
        id: item.id,
        type,
        value: item.value,
        normalized,
        firstSeen: normalizeTimestamp(item.firstSeen, stamp),
        lastSeen: normalizeTimestamp(item.lastSeen, stamp),
        registrar: item.registrar,
        hostingProvider: item.hostingProvider,
        asn: item.asn,
        country: item.country,
        tlsIssuer: item.tlsIssuer,
        dataState: item.dataState || 'ANALYST_ADDED',
        analyst: ANALYST,
      });
      infraIds.set(item.id, result.id);
      infraIds.set(item.value, result.id);
      infraIds.set(normalized, result.id);
      if (result.created) infrastructure += 1;
      for (const actorId of item.actorIds || []) {
        const relationship = upsertRelationship({
          sourceEntity: actorId,
          targetEntity: result.id,
          sourceType: 'ACTOR',
          targetType: 'INFRASTRUCTURE',
          type: 'SHARED_INFRASTRUCTURE',
          confidence: 65,
          explanation: `${actorId} uses ${type} ${item.value}.`,
          derivation: 'OBSERVED',
          supporting: [`${type} ${item.value}`],
          dataState: 'ANALYST_ADDED',
          analyst: ANALYST,
        });
        if (relationship.created) relationships += 1;
      }
    }

    // ── Observations ─────────────────────────────────────────
    for (const observation of dataset.observations || []) {
      const result = upsertObservation({
        actorId: observation.actorId,
        handleId: observation.handleId ? handleIds.get(observation.handleId) || null : null,
        platform: observation.platform,
        observationType: observation.observationType,
        content: observation.content,
        observedAt: normalizeTimestamp(observation.timestamp, stamp),
        sourceId: observation.source ? sourceNameIds.get(observation.source) || null : null,
        confidence: confidence(observation.confidence),
        dataState: observation.dataState || 'ANALYST_ADDED',
        analyst: ANALYST,
      });
      if (result.created) observations += 1;
    }

    // ── Evidence ─────────────────────────────────────────────
    for (const item of (dataset.evidence || [])) {
      const result = upsertEvidence({
        id: item.id,
        evidenceType: item.evidenceType || 'ANALYSIS',
        sourceId: item.source ? sourceNameIds.get(item.source) || null : null,
        sourceLabel: item.source || '',
        observedAt: normalizeTimestamp(item.timestamp, stamp),
        collectedAt: normalizeTimestamp(item.collectionTimestamp, stamp),
        hash: item.hash?.replace(/^sha256:/, '') || '',
        reliability: confidence(item.reliability),
        confidence: confidence(item.confidence),
        provenance: item.provenance || item.description || '',
        relatedActor: item.relatedActor || null,
        relatedHandle: item.relatedHandle || null,
        relatedInfra: item.relatedInfrastructure || null,
        relatedRelationship: item.relatedRelationship || null,
        dataState: item.dataState || 'ANALYST_ADDED',
        analyst: ANALYST,
      });
      if (result.created) evidence += 1;
    }

    // ── Relationships ────────────────────────────────────────
    for (const relationship of dataset.relationships || []) {
      // Remap only edges whose endpoints are identifiers in this snapshot;
      // edges already using authoritative ids are passed through unchanged.
      const sourceEntity = [relationship.sourceEntity]
        .map(id =>
          handleIds.get(id) || pgpIds.get(id) || walletIds.get(id) || infraIds.get(id) || id,
        )[0];
      const targetEntity = [relationship.targetEntity]
        .map(id =>
          handleIds.get(id) || pgpIds.get(id) || walletIds.get(id) || infraIds.get(id) || id,
        )[0];
      const result = upsertRelationship({
        id: relationship.id,
        sourceEntity,
        targetEntity,
        sourceType: relationship.sourceType || 'UNKNOWN',
        targetType: relationship.targetType || 'UNKNOWN',
        type: relationship.type || 'ASSOCIATED_WITH',
        confidence: confidence(relationship.confidence),
        explanation: relationship.explanation || '',
        firstObserved: normalizeTimestamp(relationship.firstObserved, stamp),
        lastObserved: normalizeTimestamp(relationship.lastObserved, stamp),
        supporting: relationship.supporting || [],
        against: relationship.against || [],
        derivation: 'OBSERVED',
        dataState: relationship.dataState || 'ANALYST_ADDED',
        analyst: ANALYST,
      });
      if (result.created) relationships += 1;
      for (const evidenceId of relationship.evidenceIds || []) {
        linkRelationshipEvidence(result.id, evidenceId);
      }
    }

    // ── Timeline ─────────────────────────────────────────────
    for (const event of dataset.timeline || []) {
      const result = addTimelineEvent({
        id: event.id,
        actorId: event.actorId || '',
        entityId: event.actorId || event.id || '',
        eventType: event.type || 'PLATFORM_ACTIVITY',
        occurredAt: normalizeTimestamp(event.time, stamp),
        title: event.title || 'Timeline event',
        description: event.description || '',
        confidence: confidence(event.confidence),
        dataState: event.dataState || 'ANALYST_ADDED',
        analyst: ANALYST,
      });
      if (result.created) timeline += 1;
    }

    // ── Investigations ───────────────────────────────────────
    for (const investigation of dataset.investigations || []) {
      const result = upsertInvestigation({
        id: investigation.id,
        title: investigation.title,
        description: investigation.description,
        status: investigation.status || 'ACTIVE',
        analyst: investigation.analyst || ANALYST,
        seedActorId: investigation.seedActorId || '',
        steps: investigation.steps || [],
        confidence: confidence(investigation.confidence),
        dataState: investigation.dataState || 'ANALYST_ADDED',
        timestamp: normalizeTimestamp(investigation.createdAt, stamp),
      });
      if (result.created) investigations += 1;
      for (const entityId of investigation.entityIds || []) {
        attachEntityToInvestigation(result.id, entityId, 'REFERENCE');
      }
    }

    // ── Notes ────────────────────────────────────────────────
    for (const note of dataset.notes || []) {
      const result = addNote({
        id: note.id,
        entityType: note.entityType || 'ACTOR',
        entityId: note.entityId || '',
        author: note.author || ANALYST,
        text: note.text || '',
        createdAt: normalizeTimestamp(note.createdAt, stamp),
      });
      if (result.created) notes += 1;
    }

    // Correlations are computed from the reconciled edges, then the
    // revision moves so any polling frontend sees the change.
    const correlations = correlateActors();
    bumpRevision();

    writeAudit({
      actor: ANALYST,
      action: 'IMPORT_COMPLETED',
      entity: 'DATASET',
      entityId: 'SYSTEM',
      after: `Reconciled frontend snapshot: ${actors} actors, ${handles} handles, ${pgp} PGP, ${wallets} wallets, ${infrastructure} infrastructure, ${relationships} relationships`,
      source: 'Frontend sync',
    });

    return {
      status: 'ok',
      source: 'reconcile',
      counts: {
        sources: dataset.sources?.length || 0,
        actors,
        handles,
        pgp,
        wallets,
        infrastructure,
        observations,
        evidence,
        relationships,
        timeline,
        investigations,
        notes,
        correlations: correlations.created.length,
      },
      dataset: buildDataset(),
    };
  });
}