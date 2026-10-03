// ============================================================
// PhishNet — Central intelligence query layer.
//
// Every read a module performs goes through here, so "Threat Actors",
// "Infrastructure", "Relationships", "Timeline", "Evidence" and
// "Overview" are all views over the SAME tables rather than
// separate copies of the data.
//
// `buildDataset()` returns the exact shape the frontend store
// already consumes, which is what lets the UI keep its current
// contract while the backend becomes the source of truth.
// ============================================================
import {
  correlationsFor,
  getActor,
  getState,
  investigationsForEntity,
  listActors,
  listAlerts,
  listAudit,
  listEvidence,
  listHandles,
  listInfrastructure,
  listInvestigations,
  listNotes,
  listObservations,
  listPgp,
  listMonitors,
  listRelationships,
  listSources,
  listTimeline,
  listWallets,
  evidenceForEntity,
  evidenceForRelationship,
  investigationRefs,
  notesForEntity,
  relationshipsForEntity,
} from './repository.mjs';
import { whyLinked, confidenceBand } from './correlate.mjs';
import { toJson } from './normalize.mjs';

const parse = (value, fallback) => toJson(value, fallback);

// ── Overview statistics (never hardcoded) ─────────────────────
export function statistics() {
  const actors = listActors();
  const handles = listHandles();
  const pgp = listPgp();
  const wallets = listWallets();
  const infrastructure = listInfrastructure();
  const relationships = listRelationships();
  const evidence = listEvidence();
  const investigations = listInvestigations();
  const alerts = listAlerts();
  const timeline = listTimeline();
  const sources = listSources();
  const observations = listObservations();
  const nowMs = Date.now();
  const thirtyDays = 1000 * 60 * 60 * 24 * 30;

  const within = stamp => nowMs - new Date(stamp).getTime() <= thirtyDays;

  return {
    totalActors: actors.length,
    activeActors: actors.filter(a => a.status === 'ACTIVE').length,
    dormantActors: actors.filter(a => a.status === 'DORMANT').length,
    suspendedActors: actors.filter(a => a.status === 'SUSPENDED').length,
    knownHandles: handles.length,
    pgpKeys: pgp.length,
    wallets: wallets.length,
    infrastructureIndicators: infrastructure.length,
    relationships: relationships.length,
    evidenceItems: evidence.length,
    observations: observations.length,
    activeInvestigations: investigations.filter(i => i.status === 'ACTIVE').length,
    openAlerts: alerts.filter(a => a.status === 'OPEN').length,
    totalAlerts: alerts.length,
    sources: sources.length,
    healthySources: sources.filter(s => s.health_status === 'ACTIVE').length,
    averageConfidence: actors.length
      ? Math.round(actors.reduce((sum, a) => sum + (a.confidence_score || 0), 0) / actors.length)
      : 0,
    newIntelligence: {
      actors: actors.filter(a => within(a.created_at)).length,
      handles: handles.filter(h => within(h.created_at)).length,
      infrastructure: infrastructure.filter(i => within(i.created_at)).length,
      evidence: evidence.filter(e => within(e.created_at)).length,
    },
    recentAlerts: alerts.slice(0, 5),
    recentTimeline: timeline.slice(0, 8),
    monitoring: (() => {
      const monitors = listMonitors();
      const monitoringAlerts = alerts.filter(a => a.type === 'MONITORING');
      return {
        totalMonitors: monitors.length,
        activeMonitors: monitors.filter(m => m.status === 'ACTIVE').length,
        pausedMonitors: monitors.filter(m => m.status === 'PAUSED').length,
        failedMonitors: monitors.filter(m => m.runtime_state === 'ERROR').length,
        openMonitoringAlerts: monitoringAlerts.filter(a => a.status === 'OPEN').length,
        criticalMonitoringAlerts: monitoringAlerts.filter(a => a.severity === 'CRITICAL' && a.status === 'OPEN').length,
      };
    })(),
    sourceHealth: sources.map(s => ({
      id: s.id,
      name: s.name,
      type: s.type,
      status: s.status,
      health: s.health_status,
      reliability: s.reliability_score,
      lastObserved: s.last_observed,
    })),
    revision: getState().revision,
  };
}

// ── Per-module views ──────────────────────────────────────────
export function actorBundle(entityId) {
  const actor = getActor(entityId);
  if (!actor) return null;
  const relationships = relationshipsForEntity(actor.id);
  const relatedIds = new Set();

  for (const relationship of relationships) {
    const other = relationship.source_entity === actor.id ? relationship.target_entity : relationship.source_entity;
    relatedIds.add(other);
  }

  const handles = listHandles().filter(h => [...relatedIds].includes(h.id));
  const wallets = listWallets().filter(w => [...relatedIds].includes(w.id));
  const pgpKeys = listPgp().filter(k => [...relatedIds].includes(k.id));
  const infrastructure = listInfrastructure().filter(i => [...relatedIds].includes(i.id));

  return {
    id: actor.id,
    displayName: actor.display_name,
    status: actor.status,
    activityLevel: actor.activity_level,
    confidenceScore: actor.confidence_score,
    primaryMotivation: actor.primary_motivation,
    firstSeen: actor.first_seen,
    lastSeen: actor.last_seen,
    behavioralProfile: parse(actor.behavioral_profile, {}),
    stylometricProfile: parse(actor.stylometric_profile, {}),
    dataState: actor.data_state,
    handles,
    pgpKeys,
    wallets,
    infrastructure,
    relationships,
    evidence: evidenceForEntity(actor.id),
    timeline: listTimeline().filter(event => event.actor_id === actor.id),
    notes: notesForEntity(actor.id),
    alerts: listAlerts().filter(alert => alert.actor_id === actor.id),
    investigations: investigationsForEntity(actor.id),
    whyLinked: whyLinked(actor.id),
  };
}

export function evidenceChain(evidenceId) {
  const evidence = listEvidence().find(item => item.id === evidenceId);
  if (!evidence) return [];
  const relationships = listRelationships().filter(
    item => relationshipEvidenceIds(item.id).includes(evidenceId) || evidence.related_relationship === item.id,
  );
  return [
    {
      step: 1,
      label: 'Source',
      detail: evidence.source_label || evidence.source_id || 'Unknown source',
      reference: evidence.source_id,
      kind: 'OBSERVED',
    },
    {
      step: 2,
      label: 'Evidence',
      detail: evidence.description || evidence.provenance,
      reference: evidence.id,
      kind: 'OBSERVED',
    },
    ...relationships.map((relationship, index) => ({
      step: 3 + index,
      label: 'Relationship',
      detail: relationship.explanation || `${relationship.source_entity} → ${relationship.target_entity}`,
      reference: relationship.id,
      kind: relationship.derivation,
    })),
  ];
}

// ── Search across every entity type ───────────────────────────
export function search(term, options = {}) {
  const raw = String(term || '').trim().toLowerCase();
  if (!raw) return { term: '', actors: [], handles: [], pgpKeys: [], wallets: [], infrastructure: [], relationships: [], evidence: [], investigations: [], sources: [], timeline: [] };
  const limit = Math.min(Number(options.limit) || 25, 200);
  const contains = (value, query = raw) => String(value || '').toLowerCase().includes(query);

  return {
    term: raw,
    actors: listActors().filter(a => contains(a.id) || contains(a.display_name) || contains(a.primary_motivation)).slice(0, limit),
    handles: listHandles().filter(h => contains(h.value) || contains(h.platform) || contains(h.normalized)).slice(0, limit),
    pgpKeys: listPgp().filter(k => contains(k.fingerprint) || contains(k.normalized)).slice(0, limit),
    wallets: listWallets().filter(w => contains(w.address) || contains(w.network)).slice(0, limit),
    infrastructure: listInfrastructure().filter(i => contains(i.value) || contains(i.hosting_provider) || contains(i.asn) || contains(i.registrar)).slice(0, limit),
    relationships: listRelationships().filter(r => contains(r.id) || contains(r.type) || contains(r.explanation) || contains(r.source_entity) || contains(r.target_entity)).slice(0, limit),
    evidence: listEvidence().filter(e => contains(e.id) || contains(e.provenance) || contains(e.description)).slice(0, limit),
    investigations: listInvestigations().filter(i => contains(i.id) || contains(i.title) || contains(i.description)).slice(0, limit),
    sources: listSources().filter(s => contains(s.id) || contains(s.name) || contains(s.type)).slice(0, limit),
    timeline: listTimeline().filter(t => contains(t.title) || contains(t.description) || contains(t.event_type)).slice(0, limit),
  };
}

/** Rebuild every id lookup from the collections the backend can see. */
function buildLookups(dataset) {
  const byId = (items) => Object.fromEntries((items ?? []).map(item => [item.id, item]));
  const cves = dataset.cves ?? [];
  const walletTransactions = dataset.walletTransactions ?? [];
  const walletClusters = dataset.walletClusters ?? [];
  const groupBy = (items, key) => {
    const out = {};
    for (const item of items) {
      const k = key(item);
      if (!k) continue;
      (out[k] ??= []).push(item);
    }
    return out;
  };
  return {
    actorsById: byId(dataset.actors),
    handlesById: byId(dataset.handles),
    pgpById: byId(dataset.pgpKeys),
    walletsById: byId(dataset.wallets),
    infraById: byId(dataset.infrastructure),
    sourcesById: byId(dataset.sources),
    relationshipsById: byId(dataset.relationships),
    evidenceById: byId(dataset.evidence),
    timelineById: byId(dataset.timeline),
    investigationsById: byId(dataset.investigations),
    alertsById: byId(dataset.alerts),
    observationsById: byId(dataset.observations),
    mitreTtpsById: byId(dataset.mitreTtps),
    cvesById: byId(cves),
    cvesByCveId: Object.fromEntries(cves.map(cve => [cve.cveId.toUpperCase(), cve])),
    vulnerabilitiesById: byId(dataset.vulnerabilities),
    walletTransactionsById: byId(walletTransactions),
    walletTransactionsByWalletId: groupBy(walletTransactions, tx => tx.walletId),
    walletClustersById: byId(walletClusters),
    walletClustersByWalletId: groupBy(walletClusters, cluster => cluster.walletIds?.[0]),
    exchangesById: byId(dataset.exchanges),
    communicationChannelsById: byId(dataset.communicationChannels),
    communicationMessagesById: byId(dataset.communicationMessages),
    methodologiesById: byId(dataset.methodologies),
    playbooksById: byId(dataset.playbooks),
  };
}

// ── Dataset hydration for the frontend store ──────────────────
//
// The shape matches the `IntelligenceDataset` interface the existing
// UI already consumes, so the frontend swaps its local cache for this
// response without any component changing.
export function buildDataset() {
  const state = getState();
  const actors = listActors();
  const handles = listHandles();
  const pgpKeys = listPgp();
  const wallets = listWallets();
  const infrastructure = listInfrastructure();
  const sources = listSources();
  const observations = listObservations();
  const relationships = listRelationships();
  const evidence = listEvidence();
  const timeline = listTimeline();
  const investigations = listInvestigations();
  const alerts = listAlerts();
  const notes = listNotes();
  const audit = listAudit();

  // Ownership, for display, is derived from the stored relationship edges.
  const handleOwner = new Map();
  const actorHandles = new Map();
  const actorPgp = new Map();
  const actorWallets = new Map();
  const actorInfra = new Map();
  const actorPlatforms = new Map();
  const actorDomains = new Map();
  const actorRelated = new Map();
  const actorEvidence = new Map();
  const handleActors = new Map();
  const pgpActors = new Map();
  const walletActors = new Map();
  const infraActors = new Map();

  const addTo = (map, key, value) => {
    if (!key) return;
    if (!map.has(key)) map.set(key, new Set());
    map.get(key).add(value);
  };
  const listOf = (map, key) => [...(map.get(key) || [])];

  for (const relationship of relationships) {
    const isActorSource = relationship.source_type === 'ACTOR';
    const isActorTarget = relationship.target_type === 'ACTOR';
    if (isActorSource && isActorTarget) {
      addTo(actorRelated, relationship.source_entity, relationship.target_entity);
      addTo(actorRelated, relationship.target_entity, relationship.source_entity);
    } else if (isActorSource) {
      addTo(actorHandles, relationship.source_entity, relationship.target_entity);
      addTo(handleActors, relationship.target_entity, relationship.source_entity);
      handleOwner.set(relationship.target_entity, relationship.source_entity);
      const platform = handles.find(h => h.id === relationship.target_entity)?.platform;
      if (platform) addTo(actorPlatforms, relationship.source_entity, platform);
    } else if (isActorTarget) {
      addTo(actorHandles, relationship.target_entity, relationship.source_entity);
      addTo(handleActors, relationship.source_entity, relationship.target_entity);
    }
    if (relationship.type === 'SHARED_PGP') {
      addTo(actorPgp, relationship.source_entity, relationship.target_entity);
      addTo(pgpActors, relationship.target_entity, relationship.source_entity);
    }
    if (relationship.type === 'SHARED_WALLET') {
      addTo(actorWallets, relationship.source_entity, relationship.target_entity);
      addTo(walletActors, relationship.target_entity, relationship.source_entity);
    }
    if (relationship.type === 'SHARED_INFRASTRUCTURE') {
      addTo(actorInfra, relationship.source_entity, relationship.target_entity);
      addTo(infraActors, relationship.target_entity, relationship.source_entity);
      const record = infrastructure.find(i => i.id === relationship.target_entity);
      if (record?.type === 'DOMAIN') addTo(actorDomains, relationship.source_entity, record.value);
    }
  }

  for (const item of evidence) {
    if (item.related_actor) addTo(actorEvidence, item.related_actor, item.id);
  }
  for (const relationship of relationships) {
    for (const evidenceId of relationshipEvidenceIds(relationship.id)) {
      addTo(actorEvidence, relationship.source_entity, evidenceId);
      addTo(actorEvidence, relationship.target_entity, evidenceId);
    }
  }

  const handleRecords = handles.map(h => ({
    id: h.id,
    value: h.value,
    platform: h.platform,
    sourceId: h.source_id,
    firstSeen: h.first_seen,
    lastSeen: h.last_seen,
    confidence: h.confidence,
    normalized: h.normalized,
    actorId: handleOwner.get(h.id) ?? null,
    dataState: h.data_state,
    analyst: h.analyst,
  }));

  const actorRecords = actors.map(a => ({
    id: a.id,
    aliases: [a.display_name, a.id].filter(Boolean),
    handles: listOf(actorHandles, a.id),
    pgpFingerprints: listOf(actorPgp, a.id),
    walletAddrs: listOf(actorWallets, a.id),
    domains: listOf(actorDomains, a.id),
    platforms: listOf(actorPlatforms, a.id),
    firstSeen: a.first_seen,
    lastSeen: a.last_seen,
    activityLevel: a.activity_level,
    confidenceScore: a.confidence_score,
    status: a.status,
    relatedActorIds: listOf(actorRelated, a.id),
    associatedEvidence: listOf(actorEvidence, a.id),
    behavioralProfile: parse(a.behavioral_profile, {}),
    stylometricProfile: parse(a.stylometric_profile, {}),
    primaryMotivation: a.primary_motivation,
    isSynthetic: a.data_state === 'SYNTHETIC_DEMO',
    dataState: a.data_state,
    analyst: a.analyst,
  }));

  const relationshipRecords = relationships.map(r => ({
    id: r.id,
    sourceEntity: r.source_entity,
    targetEntity: r.target_entity,
    sourceType: r.source_type,
    targetType: r.target_type,
    type: r.type,
    confidence: r.confidence,
    evidenceIds: relationshipEvidenceIds(r.id),
    explanation: r.explanation,
    firstObserved: r.first_observed,
    lastObserved: r.last_observed,
    supporting: parse(r.supporting, []),
    against: parse(r.against, []),
    dataState: r.data_state,
    analyst: r.analyst,
  }));

  const evidenceRecords = evidence.map(e => ({
    id: e.id,
    source: e.source_label || e.source_id || 'unknown',
    sourceType: 'FORUM',
    timestamp: e.observed_at,
    collectionTimestamp: e.collected_at,
    hash: e.hash,
    relatedActor: e.related_actor,
    relatedRelationship: e.related_relationship,
    evidenceType: e.evidence_type,
    reliability: e.reliability,
    confidence: e.confidence,
    provenance: e.provenance,
    isSynthetic: e.data_state === 'SYNTHETIC_DEMO',
    description: e.description,
    relatedHandle: e.related_handle,
    relatedInfrastructure: e.related_infra,
    integrityStatus: e.integrity_status,
    dataState: e.data_state,
    analyst: e.analyst,
  }));

  return {
    version: 1,
    revision: state.revision,
    updatedAt: new Date().toISOString(),
    demoLabel: state.demo_label,
    isDemoLoaded: Boolean(state.is_demo_loaded),
    actors: actorRecords,
    handles: handleRecords,
    pgpKeys: pgpKeys.map(k => ({
      id: k.id,
      fingerprint: k.fingerprint,
      actorIds: listOf(pgpActors, k.id),
      firstSeen: k.first_seen,
      lastSeen: k.last_seen,
      sources: [],
      confidence: k.confidence,
      dataState: k.data_state,
      analyst: k.analyst,
      handleIds: [],
    })),
    wallets: wallets.map(w => ({
      id: w.id,
      address: w.address,
      actorIds: listOf(walletActors, w.id),
      observedSources: [],
      firstSeen: w.first_seen,
      lastSeen: w.last_seen,
      txCount: w.tx_count,
      confidence: w.confidence,
      network: w.network,
      dataState: w.data_state,
      analyst: w.analyst,
      handleIds: [],
    })),
    infrastructure: infrastructure.map(i => ({
      id: i.id,
      type: i.type === 'ONION' ? 'DOMAIN' : i.type,
      value: i.value,
      actorIds: listOf(infraActors, i.id),
      firstSeen: i.first_seen,
      lastSeen: i.last_seen,
      registrar: i.registrar || undefined,
      hostingProvider: i.hosting_provider || undefined,
      asn: i.asn || undefined,
      country: i.country || undefined,
      tlsIssuer: i.tls_issuer || undefined,
      dataState: i.data_state,
      analyst: i.analyst,
    })),
    sources: sources.map(s => ({
      id: s.id,
      name: s.name,
      type: s.type,
      firstObserved: s.first_observed,
      lastObserved: s.last_observed,
      reliabilityScore: s.reliability_score,
      activityLevel: s.activity_level,
      status: s.status,
      actorCount: listOf(handleActors, s.id).length,
      indicatorCount: handles.filter(h => h.source_id === s.id).length,
      collectionTimestamp: s.created_at,
      description: s.description,
      onionAddress: s.onion_address || undefined,
      isSynthetic: s.data_state === 'SYNTHETIC_DEMO',
      reference: s.reference || undefined,
      collectionMethod: s.collection_method || undefined,
      dataState: s.data_state,
    })),
    observations: observations.map(o => ({
      id: o.id,
      actorId: o.actor_id,
      handleId: o.handle_id,
      platform: o.platform,
      observationType: o.observation_type,
      content: o.content,
      timestamp: o.observed_at,
      source: o.source_id || '',
      confidence: o.confidence,
      tags: parse(o.tags, []),
      notes: o.notes,
      dataState: o.data_state,
      analyst: o.analyst,
      evidenceIds: [],
    })),
    relationships: relationshipRecords,
    evidence: evidenceRecords,
    timeline: timeline.map(t => ({
      id: t.id,
      actorId: t.actor_id,
      time: t.occurred_at,
      type: normalizeTimelineType(t.event_type),
      title: t.title,
      description: t.description,
      confidence: t.confidence,
      source: t.source_id || '',
      evidenceIds: [],
      dataState: t.data_state,
    })),
    investigations: investigations.map(i => ({
      id: i.id,
      title: i.title,
      description: i.description,
      status: i.status,
      analyst: i.analyst,
      createdAt: i.created_at,
      updatedAt: i.updated_at,
      seedActorId: i.seed_actor_id || '',
      steps: parse(i.steps, []),
      confidence: i.confidence,
      entityIds: investigationRefs(i.id).map(ref => ref.entity_id),
      dataState: i.data_state,
    })),
    alerts: alerts.map(a => ({
      id: a.id,
      type: a.type,
      severity: a.severity,
      title: a.title,
      timestamp: a.raised_at,
      actorId: a.actor_id,
      reason: a.reason,
      evidenceIds: parse(a.evidence_ids, []),
      observationIds: parse(a.observation_ids, []),
      triggerConditions: parse(a.trigger_conditions, []),
      monitorId: a.monitor_id,
      investigationId: a.investigation_id,
      confidence: a.confidence,
      status: a.status,
      entityType: a.entity_type,
      entityId: a.entity_id,
      acknowledgedBy: a.acknowledged_by || undefined,
      acknowledgedAt: a.acknowledged_at || undefined,
      resolution: a.resolution || undefined,
      dataState: 'OBSERVED',
    })),
    audit: audit.map(a => ({
      id: a.id,
      time: a.occurred_at,
      actor: a.actor,
      action: a.action,
      entity: a.entity,
      entityId: a.entity_id,
      before: a.before,
      after: a.after,
      source: a.source,
      result: a.result,
      outcome: a.result,
      ip: a.ip,
    })),
    notes: notes.map(n => ({
      id: n.id,
      entityType: n.entity_type,
      entityId: n.entity_id,
      author: n.author,
      createdAt: n.created_at,
      text: n.text,
    })),
    reports: [],
    mitreTtps: [],
    cves: [],
    vulnerabilities: [],
    walletTransactions: [],
    walletClusters: [],
    exchanges: [],
    communicationChannels: [],
    communicationMessages: [],
    methodologies: [],
    playbooks: [],
    lookups: buildLookups({
      actors: actorRecords,
      handles: handleRecords,
      pgpKeys: pgpKeys.map(k => ({
        id: k.id,
        fingerprint: k.fingerprint,
        actorIds: listOf(pgpActors, k.id),
        firstSeen: k.first_seen,
        lastSeen: k.last_seen,
        sources: [],
        confidence: k.confidence,
        dataState: k.data_state,
        analyst: k.analyst,
        handleIds: [],
      })),
      wallets: wallets.map(w => ({
        id: w.id,
        address: w.address,
        actorIds: listOf(walletActors, w.id),
        observedSources: [],
        firstSeen: w.first_seen,
        lastSeen: w.last_seen,
        txCount: w.tx_count,
        confidence: w.confidence,
        network: w.network,
        dataState: w.data_state,
        analyst: w.analyst,
        handleIds: [],
      })),
      infrastructure: infrastructure.map(i => ({
        id: i.id,
        type: i.type === 'ONION' ? 'DOMAIN' : i.type,
        value: i.value,
        actorIds: listOf(infraActors, i.id),
        firstSeen: i.first_seen,
        lastSeen: i.last_seen,
        registrar: i.registrar || undefined,
        hostingProvider: i.hosting_provider || undefined,
        asn: i.asn || undefined,
        country: i.country || undefined,
        tlsIssuer: i.tls_issuer || undefined,
        dataState: i.data_state,
        analyst: i.analyst,
      })),
      sources,
      observations: observations.map(o => ({
        id: o.id,
        actorId: o.actor_id,
        handleId: o.handle_id,
        platform: o.platform,
        observationType: o.observation_type,
        content: o.content,
        timestamp: o.observed_at,
        source: o.source_id || '',
        confidence: o.confidence,
        tags: parse(o.tags, []),
        notes: o.notes,
        dataState: o.data_state,
        analyst: o.analyst,
        evidenceIds: [],
      })),
      relationships: relationshipRecords,
      evidence: evidenceRecords,
      timeline: timeline.map(t => ({
        id: t.id,
        actorId: t.actor_id,
        time: t.occurred_at,
        type: normalizeTimelineType(t.event_type),
        title: t.title,
        description: t.description,
        confidence: t.confidence,
        source: t.source_id || '',
        evidenceIds: [],
        dataState: t.data_state,
      })),
      investigations: investigations.map(i => ({
        id: i.id,
        title: i.title,
        description: i.description,
        status: i.status,
        analyst: i.analyst,
        createdAt: i.created_at,
        updatedAt: i.updated_at,
        seedActorId: i.seed_actor_id || '',
        steps: parse(i.steps, []),
        confidence: i.confidence,
        entityIds: investigationRefs(i.id).map(ref => ref.entity_id),
        dataState: i.data_state,
      })),
      alerts: alerts.map(a => ({
        id: a.id,
        type: a.type,
        severity: a.severity,
        title: a.title,
        timestamp: a.raised_at,
        actorId: a.actor_id,
        reason: a.reason,
        evidenceIds: parse(a.evidence_ids, []),
        observationIds: parse(a.observation_ids, []),
        triggerConditions: parse(a.trigger_conditions, []),
        monitorId: a.monitor_id,
        investigationId: a.investigation_id,
        confidence: a.confidence,
        status: a.status,
        entityType: a.entity_type,
        entityId: a.entity_id,
        acknowledgedBy: a.acknowledged_by || undefined,
        acknowledgedAt: a.acknowledged_at || undefined,
        resolution: a.resolution || undefined,
        dataState: 'OBSERVED',
      })),
      audit: audit.map(a => ({
        id: a.id,
        time: a.occurred_at,
        actor: a.actor,
        action: a.action,
        entity: a.entity,
        entityId: a.entity_id,
        before: a.before,
        after: a.after,
        source: a.source,
        result: a.result,
        outcome: a.result,
        ip: a.ip,
      })),
      notes: notes.map(n => ({
        id: n.id,
        entityType: n.entity_type,
        entityId: n.entity_id,
        author: n.author,
        createdAt: n.created_at,
        text: n.text,
      })),
    }),
    monitoring: monitoringSummary(state, { sources, handles, actors, relationships, alerts }),
  };
}

/**
 * The monitoring strip the existing dashboard reads. It merges the stored
 * collection state with live monitor counts so the dashboard reflects the
 * 24x7 layer without a second source of truth. When no monitor exists the
 * historical seed values are preserved, so nothing that renders this
 * changes appearance.
 */
function monitoringSummary(state, counts) {
  const stored = parse(state.monitoring, {});
  const monitors = listMonitors();
  const monitoringAlerts = listAlerts().filter(alert => alert.type === 'MONITORING');
  const nextChecks = monitors
    .filter(m => m.status === 'ACTIVE' && m.next_check)
    .map(m => new Date(m.next_check).getTime());
  const active = monitors.filter(m => m.status === 'ACTIVE').length;

  if (!monitors.length) {
    return {
      status: stored.status ?? 'PAUSED',
      lastCollection: stored.lastCollection ?? new Date().toISOString(),
      nextCollection: stored.nextCollection ?? new Date().toISOString(),
      sourcesMonitored: stored.sourcesMonitored ?? counts.sources.length,
      newIndicators: stored.newIndicators ?? counts.handles.length,
      newActors: stored.newActors ?? counts.actors.length,
      newRelationships: stored.newRelationships ?? counts.relationships.length,
      alerts: counts.alerts.filter(a => a.status === 'OPEN').length,
      activeMonitors: 0,
      pausedMonitors: 0,
      failedMonitors: 0,
      criticalAlerts: 0,
    };
  }

  return {
    ...stored,
    status: active > 0 ? 'ACTIVE' : 'PAUSED',
    lastCollection: monitors
      .filter(m => m.last_check)
      .map(m => m.last_check)
      .sort()
      .slice(-1)[0] ?? new Date().toISOString(),
    nextCollection: nextChecks.length
      ? new Date(Math.min(...nextChecks)).toISOString()
      : new Date().toISOString(),
    sourcesMonitored: active,
    alerts: monitoringAlerts.filter(a => a.status === 'OPEN').length,
    activeMonitors: active,
    pausedMonitors: monitors.filter(m => m.status === 'PAUSED').length,
    failedMonitors: monitors.filter(m => m.runtime_state === 'ERROR').length,
    criticalAlerts: monitoringAlerts.filter(a => a.severity === 'CRITICAL' && a.status === 'OPEN').length,
    totalMonitors: monitors.length,
  };
}

/** Evidence ids joined to a relationship, via the link table. */
function relationshipEvidenceIds(relationshipId) {
  return evidenceForRelationship(relationshipId).map(item => item.id);
}

/** Map stored event types onto the fixed union the UI already renders. */
function normalizeTimelineType(type) {
  const known = [
    'HANDLE_CHANGE', 'PLATFORM_ACTIVITY', 'INFRASTRUCTURE_CHANGE', 'PERSONA_MIGRATION',
    'RELATIONSHIP_FORMATION', 'EVIDENCE_COLLECTION', 'FIRST_SEEN', 'LAST_SEEN', 'FIRST_SEEN_NEW',
  ];
  if (known.includes(type)) return type;
  if (type === 'HANDLE_OBSERVED') return 'HANDLE_CHANGE';
  return 'PLATFORM_ACTIVITY';
}

export { confidenceBand };
