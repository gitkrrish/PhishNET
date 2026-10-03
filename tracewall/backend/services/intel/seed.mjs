// ============================================================
// PhishNet — Synthetic dataset import.
//
// Brings the pre-existing demonstration intelligence (the seed file
// the old read-only /api/darkweb routes served, plus any local
// dataset an analyst has already built) into the normalized
// tables, so nothing that used to be visible disappears.
//
// Import is idempotent: every entity has a stable id and every
// relationship edge is upserted, so re-running it enriches rather
// than duplicates. The Load Demo / Reset / Clear controls in the UI
// call straight into these functions.
// ============================================================
import {
  addTimelineEvent,
  clearIntelligence,
  linkRelationshipEvidence,
  listSources,
  setDemoLoaded,
  setMonitoring,
  transact,
  upsertActor,
  upsertEvidence,
  upsertHandle,
  upsertInfrastructure,
  upsertInvestigation,
  upsertPgp,
  upsertRelationship,
  upsertSource,
  upsertWallet,
  writeAudit,
} from './repository.mjs';
import { classifyInfrastructure, normalizeHandle, normalizeHost, normalizePgp, normalizeTimestamp, normalizeWallet, now } from './normalize.mjs';
import { loadDataset as loadSeed } from '../darkwebService.mjs';

const ANALYST = 'seed-import';

function seedReliability(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : 50;
}

/**
 * Import the synthetic demonstration dataset into the normalized tables.
 * `options.reset` clears existing intelligence first (the Reset control);
 * otherwise the import is additive.
 */
export async function importSeedDataset(options = {}) {
  const seed = await loadSeed();
  const stamp = now();

  return transact(() => {
    if (options.reset) clearIntelligence();

    let actors = 0;
    let handles = 0;
    let pgp = 0;
    let wallets = 0;
    let infrastructure = 0;
    let relationships = 0;
    let evidence = 0;
    let timeline = 0;
    let investigations = 0;

    // ── Sources ──────────────────────────────────────────────
    const sourceIdByName = new Map();
    for (const source of seed.sources || []) {
      const result = upsertSource({
        id: source.id,
        name: source.name,
        type: source.type,
        reference: source.reference,
        collectionMethod: 'seed',
        firstObserved: normalizeTimestamp(source.firstObserved, stamp),
        lastObserved: normalizeTimestamp(source.lastObserved, stamp),
        reliabilityScore: seedReliability(source.reliabilityScore),
        healthStatus: 'ACTIVE',
        activityLevel: source.activityLevel || 'MEDIUM',
        status: source.status || 'ACTIVE',
        description: source.description || '',
        onionAddress: source.onionAddress,
        dataState: 'SYNTHETIC_DEMO',
        analyst: ANALYST,
      });
      sourceIdByName.set(source.name, result.id);
      if (result.created) actors += 0;
    }

    // ── Actors ───────────────────────────────────────────────
    for (const actor of seed.actors || []) {
      upsertActor({
        id: actor.id,
        displayName: actor.aliases?.[0] || actor.id,
        status: actor.status || 'ACTIVE',
        activityLevel: actor.activityLevel || 'MEDIUM',
        confidenceScore: seedReliability(actor.confidenceScore),
        primaryMotivation: actor.primaryMotivation || '',
        firstSeen: normalizeTimestamp(actor.firstSeen, stamp),
        lastSeen: normalizeTimestamp(actor.lastSeen, stamp),
        behavioralProfile: actor.behavioralProfile || {},
        stylometricProfile: actor.stylometricProfile || {},
        dataState: 'SYNTHETIC_DEMO',
        analyst: ANALYST,
      });
      actors += 1;
    }

    // ── Handles ──────────────────────────────────────────────
    for (const handle of seed.handles || []) {
      const result = upsertHandle({
        id: handle.id,
        value: handle.value,
        normalized: handle.normalized || normalizeHandle(handle.value),
        platform: handle.platform || 'UNKNOWN',
        sourceId: sourceIdByName.get(handle.sourceId) || handle.sourceId || null,
        firstSeen: normalizeTimestamp(handle.firstSeen, stamp),
        lastSeen: normalizeTimestamp(handle.lastSeen, stamp),
        confidence: seedReliability(handle.confidence),
        dataState: 'SYNTHETIC_DEMO',
        analyst: ANALYST,
      });
      if (result.created) handles += 1;

      // The seed lists handles per actor as plain strings; re-resolve them
      // into real entity edges so the graph is not string-matched at render.
      for (const actor of seed.actors || []) {
        if ((actor.handles || []).some(value => normalizeHandle(value) === (handle.normalized || normalizeHandle(handle.value)))) {
          const relationship = upsertRelationship({
            id: `REL-${actor.id}-${result.id}`.replace(/[^A-Za-z0-9._-]/g, '-'),
            sourceEntity: actor.id,
            targetEntity: result.id,
            sourceType: 'ACTOR',
            targetType: 'HANDLE',
            type: 'USES_HANDLE',
            confidence: seedReliability(handle.confidence),
            explanation: `${actor.id} was observed using handle "${handle.value}" on ${handle.platform}.`,
            firstObserved: normalizeTimestamp(handle.firstSeen, stamp),
            lastObserved: normalizeTimestamp(handle.lastSeen, stamp),
            supporting: [`Handle ${handle.value} on ${handle.platform}`],
            against: [],
            derivation: 'OBSERVED',
            dataState: 'SYNTHETIC_DEMO',
            analyst: ANALYST,
          });
          if (relationship.created) relationships += 1;
        }
      }
    }

    // ── PGP keys ─────────────────────────────────────────────
    for (const key of seed.pgpKeys || []) {
      const result = upsertPgp({
        id: key.id,
        fingerprint: key.fingerprint,
        normalized: normalizePgp(key.fingerprint),
        firstSeen: normalizeTimestamp(key.firstSeen, stamp),
        lastSeen: normalizeTimestamp(key.lastSeen, stamp),
        confidence: seedReliability(key.confidence),
        dataState: 'SYNTHETIC_DEMO',
        analyst: ANALYST,
      });
      if (result.created) pgp += 1;
      for (const actorId of key.actorIds || []) {
        const relationship = upsertRelationship({
          sourceEntity: actorId,
          targetEntity: result.id,
          sourceType: 'ACTOR',
          targetType: 'PGP',
          type: 'SHARED_PGP',
          confidence: seedReliability(key.confidence),
          explanation: `${actorId} was observed using PGP key ${key.fingerprint}.`,
          firstObserved: normalizeTimestamp(key.firstSeen, stamp),
          lastObserved: normalizeTimestamp(key.lastSeen, stamp),
          supporting: [`PGP key ${key.fingerprint} used by ${actorId}`],
          against: [],
          derivation: 'OBSERVED',
          dataState: 'SYNTHETIC_DEMO',
          analyst: ANALYST,
        });
        if (relationship.created) relationships += 1;
      }
    }

    // ── Wallets ──────────────────────────────────────────────
    for (const wallet of seed.wallets || []) {
      const result = upsertWallet({
        id: wallet.id,
        address: wallet.address,
        normalized: normalizeWallet(wallet.address),
        network: wallet.network || '',
        firstSeen: normalizeTimestamp(wallet.firstSeen, stamp),
        lastSeen: normalizeTimestamp(wallet.lastSeen, stamp),
        txCount: Number(wallet.txCount) || 0,
        confidence: seedReliability(wallet.confidence),
        dataState: 'SYNTHETIC_DEMO',
        analyst: ANALYST,
      });
      if (result.created) wallets += 1;
      for (const actorId of wallet.actorIds || []) {
        const relationship = upsertRelationship({
          sourceEntity: actorId,
          targetEntity: result.id,
          sourceType: 'ACTOR',
          targetType: 'WALLET',
          type: 'SHARED_WALLET',
          confidence: seedReliability(wallet.confidence),
          explanation: `${actorId} was observed using wallet ${wallet.address}.`,
          firstObserved: normalizeTimestamp(wallet.firstSeen, stamp),
          lastObserved: normalizeTimestamp(wallet.lastSeen, stamp),
          supporting: [`Wallet ${wallet.address} used by ${actorId}`],
          against: [],
          derivation: 'OBSERVED',
          dataState: 'SYNTHETIC_DEMO',
          analyst: ANALYST,
        });
        if (relationship.created) relationships += 1;
      }
    }

    // ── Infrastructure ───────────────────────────────────────
    for (const item of seed.infrastructure || []) {
      const type = classifyInfrastructure(item.value, item.type);
      const result = upsertInfrastructure({
        id: item.id,
        type,
        value: item.value,
        normalized: normalizeHost(item.value),
        firstSeen: normalizeTimestamp(item.firstSeen, stamp),
        lastSeen: normalizeTimestamp(item.lastSeen, stamp),
        registrar: item.registrar,
        hostingProvider: item.hostingProvider,
        asn: item.asn,
        country: item.country,
        tlsIssuer: item.tlsIssuer,
        dataState: 'SYNTHETIC_DEMO',
        analyst: ANALYST,
      });
      if (result.created) infrastructure += 1;
      for (const actorId of item.actorIds || []) {
        const relationship = upsertRelationship({
          sourceEntity: actorId,
          targetEntity: result.id,
          sourceType: 'ACTOR',
          targetType: 'INFRASTRUCTURE',
          type: 'SHARED_INFRASTRUCTURE',
          confidence: 65,
          explanation: `${actorId} was observed using ${type} ${item.value}.`,
          firstObserved: normalizeTimestamp(item.firstSeen, stamp),
          lastObserved: normalizeTimestamp(item.lastSeen, stamp),
          supporting: [`${type} ${item.value} attributed to ${actorId}`],
          against: [],
          derivation: 'OBSERVED',
          dataState: 'SYNTHETIC_DEMO',
          analyst: ANALYST,
        });
        if (relationship.created) relationships += 1;
      }
    }

    // ── Evidence ─────────────────────────────────────────────
    for (const item of seed.evidence || []) {
      const result = upsertEvidence({
        id: item.id,
        evidenceType: item.evidenceType || 'ANALYSIS',
        sourceId: sourceIdByName.get(item.source) || null,
        sourceLabel: item.source || '',
        observedAt: normalizeTimestamp(item.timestamp, stamp),
        collectedAt: normalizeTimestamp(item.collectionTimestamp, stamp),
        hash: item.hash || '',
        reliability: seedReliability(item.reliability),
        confidence: seedReliability(item.confidence),
        provenance: item.provenance || '',
        relatedActor: item.relatedActor || null,
        relatedRelationship: item.relatedRelationship || null,
        dataState: 'SYNTHETIC_DEMO',
        analyst: ANALYST,
      });
      if (result.created) evidence += 1;
    }

    // ── Relationships ────────────────────────────────────────
    for (const relationship of seed.relationships || []) {
      const result = upsertRelationship({
        id: relationship.id,
        sourceEntity: relationship.sourceEntity,
        targetEntity: relationship.targetEntity,
        sourceType: relationship.sourceType || 'UNKNOWN',
        targetType: relationship.targetType || 'UNKNOWN',
        type: relationship.type || 'ASSOCIATED_WITH',
        confidence: seedReliability(relationship.confidence),
        explanation: relationship.explanation || '',
        firstObserved: normalizeTimestamp(relationship.firstObserved, stamp),
        lastObserved: normalizeTimestamp(relationship.lastObserved, stamp),
        supporting: relationship.supporting || [],
        against: relationship.against || [],
        derivation: 'OBSERVED',
        dataState: 'SYNTHETIC_DEMO',
        analyst: ANALYST,
      });
      if (result.created) relationships += 1;
      for (const evidenceId of relationship.evidenceIds || []) {
        linkRelationshipEvidence(result.id, evidenceId);
      }
    }

    // ── Timeline ─────────────────────────────────────────────
    // Written through the repository (not ingest()) so the whole import
    // stays inside one transaction — ingest() opens its own.
    for (const event of seed.timeline || []) {
      const result = addTimelineEvent({
        id: event.id,
        actorId: event.actorId || '',
        entityId: event.actorId || '',
        eventType: event.type || 'PLATFORM_ACTIVITY',
        occurredAt: normalizeTimestamp(event.time, stamp),
        title: event.title || 'Timeline event',
        description: event.description || '',
        confidence: seedReliability(event.confidence),
        dataState: 'SYNTHETIC_DEMO',
        analyst: ANALYST,
      });
      if (result) timeline += 1;
    }

    // ── Investigations ───────────────────────────────────────
    for (const investigation of seed.investigations || []) {
      const result = upsertInvestigation({
        id: investigation.id,
        title: investigation.title,
        description: investigation.description,
        status: investigation.status || 'ACTIVE',
        analyst: investigation.analyst || ANALYST,
        seedActorId: investigation.seedActorId,
        steps: investigation.steps || [],
        confidence: seedReliability(investigation.confidence),
        dataState: 'SYNTHETIC_DEMO',
        timestamp: normalizeTimestamp(investigation.createdAt, stamp),
      });
      if (result.created) investigations += 1;
    }

    setDemoLoaded(true);
    setMonitoring({
      status: 'PAUSED',
      lastCollection: stamp,
      nextCollection: stamp,
      sourcesMonitored: listSources().length,
      newIndicators: handles,
      newActors: actors,
      newRelationships: relationships,
      alerts: 0,
    });

    writeAudit({
      actor: ANALYST,
      action: 'IMPORT_COMPLETED',
      entity: 'DATASET',
      entityId: 'SYSTEM',
      after: `Imported synthetic seed: ${actors} actors, ${handles} handles, ${pgp} PGP, ${wallets} wallets, ${infrastructure} infrastructure, ${relationships} relationships`,
      source: 'Synthetic seed dataset',
    });

    return {
      status: 'ok',
      source: 'seed',
      counts: { actors, handles, pgp, wallets, infrastructure, relationships, evidence, timeline, investigations },
    };
  });
}

/** Remove all intelligence (the existing "Clear" control). */
export function clearAllIntelligence() {
  return transact(() => {
    clearIntelligence();
    setMonitoring({
      status: 'PAUSED',
      lastCollection: now(),
      nextCollection: now(),
      sourcesMonitored: 0,
      newIndicators: 0,
      newActors: 0,
      newRelationships: 0,
      alerts: 0,
    });
    writeAudit({
      actor: 'system',
      action: 'DEMO_DATASET_CLEARED',
      entity: 'DATASET',
      entityId: 'SYSTEM',
      after: 'Central intelligence cleared',
    });
    return { status: 'ok', cleared: true };
  });
}
