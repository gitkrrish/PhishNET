// ============================================================
// PhishNet — SIMULATED DEMO DATA loader.
//
// Builds the complete central intelligence model from the existing
// relational synthetic seed in src/data/darkWebData.ts, then derives
// the records that seed did not carry explicitly (observations and
// audit events) *from those same records* so every demo entity is
// relational — nothing here is randomly generated.
//
// ACTOR-001 ─ ghostwire / shadowfox, PGP-001, WAL-001, ghostwire-relay.net
// ACTOR-002 ─ nightstalk / VoidCipher, PGP-002, WAL-002, shared relay IP
// ACTOR-003 ─ ghostwire (migrated persona), PGP-001, WAL-001/002
// ACTOR-004 ─ pulsar, PGP-003, WAL-003, pulsar-drop.onion
// ACTOR-005 ─ driftwood, PGP-004, WAL-004
//
// ALL OF IT IS SIMULATED DEMO DATA — NOT REAL INTELLIGENCE.
// ============================================================
import {
  threatActors,
  darkWebHandles,
  darkWebPgpKeys,
  darkWebWallets,
  darkWebInfrastructure,
  darkWebSources,
  darkWebRelationships,
  darkWebEvidence,
  darkWebTimeline,
  darkWebInvestigations,
  darkWebAlerts,
  darkWebReports,
  darkWebMonitoring,
  DARKWEB_DEMO_LABEL,
} from '../../data/darkWebData';
import {
  darkWebMitreTtps,
  darkWebCves,
  darkWebVulnerabilities,
} from '../../data/darkWebExtendedData';
import {
  darkWebWalletTransactions,
  darkWebWalletClusters,
  darkWebExchanges,
} from '../../data/darkWebCryptoData';
import {
  darkWebCommunicationChannels,
  darkWebCommunicationMessages,
  darkWebMethodologies,
  darkWebPlaybooks,
} from '../../data/darkWebCommsData';
import type {
  MitreTtpRecord,
  CveRecordRecord,
  VulnerabilityRecordRecord,
  WalletTransactionRecord,
  WalletClusterRecord,
  ExchangeRecordRecord,
  CommunicationChannelRecord,
  CommunicationMessageRecord,
  MethodologyRecord,
  TtpPlaybookRecord,
} from './types';
import type {
  IntelligenceDataset,
  ActorRecord,
  HandleRecord,
  PgpRecord,
  WalletRecord,
  InfrastructureRecord,
  SourceRecord,
  RelationshipRecord,
  EvidenceRecord,
  TimelineRecord,
  InvestigationRecord,
  AlertRecord,
  ReportRecord,
  Observation,
  IntelligenceAuditEvent,
  DataState,
} from './types';
import { normalizeHandle, normalizePgp } from './normalize';

const DEMO_STATE: DataState = 'SYNTHETIC_DEMO';
const DEMO_ANALYST = 'System (Demo Loader)';

function demoAudit(
  id: string,
  time: string,
  action: IntelligenceAuditEvent['action'],
  entity: string,
  entityId: string,
  after: string,
  source: string,
): IntelligenceAuditEvent {
  return {
    id,
    time,
    actor: DEMO_ANALYST,
    action,
    entity,
    entityId,
    before: '—',
    after,
    source,
    result: 'SUCCESS',
    outcome: 'SUCCESS',
    ip: 'SYSTEM',
  };
}

/** The handle value a seed actor is known by, linked explicitly for cross-module joins. */
function actorForHandleSeed(normalized: string): string | null {
  for (const actor of threatActors) {
    if (actor.handles.some(handle => normalizeHandle(handle) === normalized)) return actor.id;
  }
  return null;
}

export function buildDemoDataset(): IntelligenceDataset {
  const actors: ActorRecord[] = threatActors.map(actor => ({
    ...actor,
    dataState: DEMO_STATE,
    analyst: DEMO_ANALYST,
    tags: actor.aliases,
    notes: 'Simulated actor record for demonstration and training purposes only.',
  }));

  const handles: HandleRecord[] = darkWebHandles.map(handle => ({
    ...handle,
    actorId: actorForHandleSeed(normalizeHandle(handle.normalized || handle.value)),
    dataState: DEMO_STATE,
    analyst: DEMO_ANALYST,
    source: handle.sourceId,
    notes: 'Simulated handle observation.',
  }));

  const pgpKeys: PgpRecord[] = darkWebPgpKeys.map(key => ({
    ...key,
    dataState: DEMO_STATE,
    analyst: DEMO_ANALYST,
    handleIds: handles.filter(handle => key.actorIds.includes(handle.actorId ?? '')).map(handle => handle.id),
    notes: 'Simulated PGP identity — synthetic fingerprint, not a real key.',
  }));

  const wallets: WalletRecord[] = darkWebWallets.map(wallet => ({
    ...wallet,
    dataState: DEMO_STATE,
    analyst: DEMO_ANALYST,
    network: wallet.address.startsWith('bc1') ? 'Bitcoin (synthetic)' : 'Bitcoin (synthetic)',
    handleIds: handles.filter(handle => wallet.actorIds.includes(handle.actorId ?? '')).map(handle => handle.id),
    notes: 'Synthetic wallet identifier for demonstration only.',
  }));

  const infrastructure: InfrastructureRecord[] = darkWebInfrastructure.map(infra => ({
    ...infra,
    dataState: DEMO_STATE,
    analyst: DEMO_ANALYST,
    source: 'Synthetic collection pipeline',
    nameserver: infra.type === 'DOMAIN' ? 'ns1.synthetic-dns.invalid' : undefined,
    notes: 'Simulated infrastructure indicator.',
  }));

  const sources: SourceRecord[] = darkWebSources.map(source => ({
    ...source,
    dataState: DEMO_STATE,
    analyst: DEMO_ANALYST,
    reference: source.onionAddress,
    collectionMethod: 'LAWFUL_SIMULATED',
    notes: 'Lawful / synthetic collection source used for demonstration.',
  }));

  const relationships: RelationshipRecord[] = darkWebRelationships.map(rel => ({
    ...rel,
    dataState: DEMO_STATE,
    analyst: DEMO_ANALYST,
    createdAt: rel.firstObserved,
    sourceLabel: 'Synthetic correlation engine',
  }));

  const evidence: EvidenceRecord[] = darkWebEvidence.map(item => ({
    ...item,
    dataState: DEMO_STATE,
    analyst: DEMO_ANALYST,
    description: item.provenance,
    relatedHandle: null,
    relatedInfrastructure: null,
    notes: 'Simulated evidence item with retained provenance chain.',
  }));

  const timeline: TimelineRecord[] = darkWebTimeline.map(event => ({
    ...event,
    dataState: DEMO_STATE,
    analyst: DEMO_ANALYST,
    source: 'Synthetic collection pipeline',
    evidenceIds: evidence.filter(item => item.relatedActor === event.actorId).slice(0, 2).map(item => item.id),
  }));

  const investigations: InvestigationRecord[] = darkWebInvestigations.map(inv => ({
    ...inv,
    dataState: DEMO_STATE,
    entityIds: [
      ...new Set([
        inv.seedActorId,
        ...inv.steps.flatMap(step => step.actorIds),
      ]),
    ],
  }));

  const alerts: AlertRecord[] = darkWebAlerts.map(alert => ({
    ...alert,
    dataState: DEMO_STATE,
    entityType: alert.actorId ? 'ACTOR' : 'UNKNOWN',
    entityId: alert.actorId,
  }));

  const reports: ReportRecord[] = darkWebReports.map(report => ({
    ...report,
    dataState: DEMO_STATE,
  }));

  // ── Observations derived from the seed records above ─────────
  const observations: Observation[] = [];

  for (const handle of handles) {
    observations.push({
      id: `OBS-${handle.id}`,
      actorId: handle.actorId ?? null,
      handleId: handle.id,
      platform: handle.platform,
      observationType: 'HANDLE_OBSERVED',
      content: `Handle "${handle.value}" observed on ${handle.platform}.`,
      timestamp: handle.firstSeen,
      source: handle.source ?? handle.sourceId,
      confidence: handle.confidence,
      tags: ['handle', normalizeHandle(handle.value)],
      notes: 'Derived from the stored handle record.',
      dataState: DEMO_STATE,
      analyst: DEMO_ANALYST,
      evidenceIds: evidence.filter(item => item.relatedActor === handle.actorId).slice(0, 1).map(item => item.id),
    });
  }

  for (const infra of infrastructure) {
    for (const actorId of infra.actorIds) {
      observations.push({
        id: `OBS-INF-${infra.id}-${actorId}`,
        actorId,
        handleId: null,
        platform: null,
        observationType: 'INFRASTRUCTURE_CHANGE',
        content: `${infra.type} ${infra.value} associated with ${actorId}${infra.hostingProvider ? ` (host: ${infra.hostingProvider})` : ''}.`,
        timestamp: infra.firstSeen,
        source: 'Synthetic collection pipeline',
        confidence: 80,
        tags: ['infrastructure', infra.type.toLowerCase()],
        notes: 'Derived from the stored infrastructure record.',
        dataState: DEMO_STATE,
        analyst: DEMO_ANALYST,
        evidenceIds: [],
      });
    }
  }

  for (const rel of relationships.filter(item => item.type === 'PERSONA_MIGRATION' || item.type === 'ASSOCIATED_WITH')) {
    observations.push({
      id: `OBS-REL-${rel.id}`,
      actorId: rel.sourceEntity,
      handleId: null,
      platform: null,
      observationType: rel.type === 'PERSONA_MIGRATION' ? 'PERSONA_CHANGE' : 'RELATIONSHIP_DISCOVERED',
      content: rel.explanation,
      timestamp: rel.lastObserved,
      source: 'Synthetic correlation engine',
      confidence: rel.confidence,
      tags: ['relationship', rel.type.toLowerCase()],
      notes: 'Derived from the stored relationship record.',
      dataState: DEMO_STATE,
      analyst: DEMO_ANALYST,
      evidenceIds: rel.evidenceIds,
    });
  }

  for (const key of pgpKeys) {
    observations.push({
      id: `OBS-${key.id}`,
      actorId: key.actorIds[0] ?? null,
      handleId: null,
      platform: null,
      observationType: 'NEW_PLATFORM_ACTIVITY',
      content: `PGP identity ${shortFp(key.fingerprint)} published by ${key.actorIds.join(', ') || 'unattributed source'}.`,
      timestamp: key.firstSeen,
      source: key.sources[0] ?? 'Synthetic feed',
      confidence: key.confidence,
      tags: ['pgp', 'cryptographic-identity'],
      notes: 'Derived from the stored PGP record.',
      dataState: DEMO_STATE,
      analyst: DEMO_ANALYST,
      evidenceIds: evidence.filter(item => item.evidenceType === 'PGP_KEY').slice(0, 1).map(item => item.id),
    });
  }

  // ── Extended collections ──────────────────────────────────────
  // Seeded from the synthetic demo modules. Attribution inside the seed
  // only references evidence ids that already exist above, so the graph
  // never asserts a link the evidence cannot carry.
  const mitreTtps: MitreTtpRecord[] = darkWebMitreTtps;
  const cves: CveRecordRecord[] = darkWebCves;
  const vulnerabilities: VulnerabilityRecordRecord[] = darkWebVulnerabilities;
  const walletTransactions: WalletTransactionRecord[] = darkWebWalletTransactions;
  const walletClusters: WalletClusterRecord[] = darkWebWalletClusters;
  const exchanges: ExchangeRecordRecord[] = darkWebExchanges;
  const communicationChannels: CommunicationChannelRecord[] = darkWebCommunicationChannels;
  const communicationMessages: CommunicationMessageRecord[] = darkWebCommunicationMessages;
  const methodologies: MethodologyRecord[] = darkWebMethodologies;
  const playbooks: TtpPlaybookRecord[] = darkWebPlaybooks;

  // ── Demo-safe audit trail ────────────────────────────────────
  const audit: IntelligenceAuditEvent[] = [
    demoAudit('AUD-INT-0005', '2026-09-13T04:00:00Z', 'DEMO_DATASET_LOADED', 'Dataset', 'DEMO-DARKWEB', 'Synthetic dark web dataset loaded into central intelligence model', 'SYSTEM'),
    demoAudit('AUD-INT-0004', '2026-09-13T04:00:00Z', 'ALERT_CREATED', 'Alert', 'DW-ALERT-004', 'HIGH_CONFIDENCE_CORRELATION raised for ACTOR-001', 'Correlation engine'),
    demoAudit('AUD-INT-0003', '2026-09-11T23:59:00Z', 'RELATIONSHIP_CREATED', 'Relationship', 'REL-003', 'PERSONA_MIGRATION ACTOR-001 → ACTOR-003 @ 91%', 'Correlation engine'),
    demoAudit('AUD-INT-0002', '2026-09-13T04:30:00Z', 'INVESTIGATION_CREATED', 'Investigation', 'INV-DW-001', 'Project SHADOWFOX opened with seed actor ACTOR-001', 'Analyst'),
    demoAudit('AUD-INT-0001', '2026-07-15T09:00:00Z', 'ACTOR_CREATED', 'Actor', 'ACTOR-003', 'New threat actor recorded from persona correlation', 'Correlation engine'),
  ];

  const dataset: IntelligenceDataset = {
    version: 1,
    revision: 0,
    updatedAt: new Date().toISOString(),
    demoLabel: DARKWEB_DEMO_LABEL,
    isDemoLoaded: true,
    actors,
    handles,
    pgpKeys,
    wallets,
    infrastructure,
    sources,
    observations,
    relationships,
    evidence,
    timeline,
    investigations,
    alerts,
    audit,
    notes: [],
    reports,
    monitoring: {
      ...darkWebMonitoring,
      status: 'ACTIVE',
      sourcesMonitored: sources.length,
      alerts: alerts.filter(alert => alert.status === 'OPEN').length,
    },
    lookups: {
      actorsById: {},
      handlesById: {},
      pgpById: {},
      walletsById: {},
      infraById: {},
      sourcesById: {},
      relationshipsById: {},
      evidenceById: {},
      timelineById: {},
      investigationsById: {},
      alertsById: {},
      observationsById: {},
      mitreTtpsById: {},
      cvesById: {},
      cvesByCveId: {},
      vulnerabilitiesById: {},
      walletTransactionsById: {},
      walletTransactionsByWalletId: {},
      walletClustersById: {},
      walletClustersByWalletId: {},
      exchangesById: {},
      communicationChannelsById: {},
      communicationMessagesById: {},
      methodologiesById: {},
      playbooksById: {},
    },
    // Extended collections (MITRE ATT&CK, vulnerabilities, crypto, comms).
    // Seeded from the synthetic demo modules, then owned by this model, so
    // every mutation, lookup and page reads the same arrays.
    mitreTtps,
    cves,
    vulnerabilities,
    walletTransactions,
    walletClusters,
    exchanges,
    communicationChannels,
    communicationMessages,
    methodologies,
    playbooks,
  };

  return rebuildLookups(dataset);
}

function shortFp(fingerprint: string): string {
  return normalizePgp(fingerprint).slice(0, 12);
}

/** Rebuild every id lookup so no page can ever hold a stale map. */
export function rebuildLookups(dataset: IntelligenceDataset): IntelligenceDataset {
  const byId = <T extends { id: string }>(items: T[]): Record<string, T> =>
    Object.fromEntries(items.map(item => [item.id, item]));

  // The extended collections are optional on a dataset restored from an older
  // local cache, so they are read defensively and normalised to empty arrays.
  const walletTransactions = dataset.walletTransactions ?? [];
  const walletClusters = dataset.walletClusters ?? [];
  const cves = dataset.cves ?? [];

  const groupBy = <T,>(items: T[], key: (item: T) => string | null | undefined): Record<string, T[]> => {
    const out: Record<string, T[]> = {};
    for (const item of items) {
      const k = key(item);
      if (!k) continue;
      (out[k] ??= []).push(item);
    }
    return out;
  };

  return {
    ...dataset,
    updatedAt: dataset.updatedAt,
    walletTransactions,
    walletClusters,
    cves,
    lookups: {
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
      // Extended lookups. These were previously declared but never populated,
      // which made every mutation that reads them dereference `undefined`.
      mitreTtpsById: byId(dataset.mitreTtps ?? []),
      cvesById: byId(cves),
      cvesByCveId: Object.fromEntries(cves.map(cve => [cve.cveId.toUpperCase(), cve])),
      vulnerabilitiesById: byId(dataset.vulnerabilities ?? []),
      walletTransactionsById: byId(walletTransactions),
      walletTransactionsByWalletId: groupBy(walletTransactions, tx => tx.walletId),
      walletClustersById: byId(walletClusters),
      walletClustersByWalletId: groupBy(walletClusters, cluster => cluster.walletIds?.[0]),
      exchangesById: byId(dataset.exchanges ?? []),
      communicationChannelsById: byId(dataset.communicationChannels ?? []),
      communicationMessagesById: byId(dataset.communicationMessages ?? []),
      methodologiesById: byId(dataset.methodologies ?? []),
      playbooksById: byId(dataset.playbooks ?? []),
    },
  };
}
