// ============================================================
// PhishNet — Derived intelligence selectors.
//
// Every number, indicator, graph edge and timeline row shown in the
// product is computed here from the central dataset. Nothing is
// hardcoded, so a single record write updates the dashboard, the
// graph, search, the "WHY LINKED?" panel, reports and AI answers at
// the same time.
// ============================================================
import type { Node, Edge } from '@xyflow/react';
import type {
  IntelligenceDataset,
  ActorRecord,
  IntelligenceAuditEvent,
  ActivityItem,
  Observation,
  RelationshipRecord,
  EvidenceRecord,
} from './types';
import { ACTIVITY_LABEL } from './dataset';
import { normalizeHandle, normalizePgp, normalizeDomain, similarity, shortFingerprint } from './normalize';

// ── Dashboard / posture metrics ────────────────────────────────
export interface DashboardMetrics {
  actors: number;
  activeActors: number;
  dormantActors: number;
  newIndicators: number;
  handles: number;
  pgpKeys: number;
  wallets: number;
  infrastructure: number;
  identities: number;
  relationships: number;
  highConfidenceRelationships: number;
  personaMigrations: number;
  evidence: number;
  observations: number;
  sources: number;
  activeSources: number;
  activeInvestigations: number;
  investigations: number;
  openAlerts: number;
  totalAlerts: number;
  averageConfidence: number;
  lastCollection: string;
  activityByDay: Array<{ date: string; count: number }>;
  activityByMonth: Array<{ month: string; activity: number; identity: number; infrastructure: number }>;
  postureSummary: string;
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

export function dashboardMetrics(dataset: IntelligenceDataset): DashboardMetrics {
  const activeActors = dataset.actors.filter(actor => actor.status === 'ACTIVE');
  const highConfidenceRelationships = dataset.relationships.filter(rel => rel.confidence >= 75);
  const identities = dataset.handles.length + dataset.pgpKeys.length + dataset.wallets.length;
  const newIndicators =
    dataset.handles.length +
    dataset.pgpKeys.length +
    dataset.wallets.length +
    dataset.infrastructure.length;
  const averageConfidence = dataset.actors.length
    ? Math.round(dataset.actors.reduce((sum, actor) => sum + actor.confidenceScore, 0) / dataset.actors.length)
    : 0;

  const activityByDay = new Map<string, number>();
  const activityByMonth = new Map<string, { activity: number; identity: number; infrastructure: number }>();
  for (const event of dataset.timeline) {
    const date = new Date(event.time);
    if (Number.isNaN(date.getTime())) continue;
    const dayKey = date.toISOString().slice(0, 10);
    activityByDay.set(dayKey, (activityByDay.get(dayKey) ?? 0) + 1);
    const monthKey = `${date.getUTCFullYear()}-${date.getUTCMonth()}`;
    const bucket = activityByMonth.get(monthKey) ?? { activity: 0, identity: 0, infrastructure: 0 };
    bucket.activity += 1;
    if (['FIRST_SEEN', 'FIRST_SEEN_NEW', 'PERSONA_MIGRATION', 'HANDLE_CHANGE', 'RELATIONSHIP_FORMATION'].includes(event.type)) {
      bucket.identity += 1;
    }
    if (['INFRASTRUCTURE_CHANGE', 'PLATFORM_ACTIVITY'].includes(event.type)) {
      bucket.infrastructure += 1;
    }
    activityByMonth.set(monthKey, bucket);
  }

  const activeSources = dataset.sources.filter(source => source.status === 'ACTIVE');
  const activeInvestigations = dataset.investigations.filter(inv => inv.status !== 'COMPLETED');

  return {
    actors: dataset.actors.length,
    activeActors: activeActors.length,
    dormantActors: dataset.actors.length - activeActors.length,
    newIndicators,
    handles: dataset.handles.length,
    pgpKeys: dataset.pgpKeys.length,
    wallets: dataset.wallets.length,
    infrastructure: dataset.infrastructure.length,
    identities,
    relationships: dataset.relationships.length,
    highConfidenceRelationships: highConfidenceRelationships.length,
    personaMigrations: dataset.relationships.filter(rel => rel.type === 'PERSONA_MIGRATION').length,
    evidence: dataset.evidence.length,
    observations: dataset.observations.length,
    sources: dataset.sources.length,
    activeSources: activeSources.length,
    activeInvestigations: activeInvestigations.length,
    investigations: dataset.investigations.length,
    openAlerts: dataset.alerts.filter(alert => alert.status === 'OPEN' || alert.status === 'ACKNOWLEDGED').length,
    totalAlerts: dataset.alerts.length,
    averageConfidence,
    lastCollection: dataset.monitoring.lastCollection,
    activityByDay: [...activityByDay.entries()]
      .map(([date, count]) => ({ date, count }))
      .sort((a, b) => a.date.localeCompare(b.date)),
    activityByMonth: [...activityByMonth.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => {
        const [year, month] = key.split('-').map(Number);
        return { month: `${MONTHS[month]} ${String(year).slice(2)}`, ...value };
      }),
    postureSummary: `${dataset.actors.length} threat actors under continuous observation across ${dataset.sources.length} dark web sources. ${activeInvestigations.length} active investigation · ${identities} correlated identities · ${highConfidenceRelationships.length} high-confidence relationships · ${dataset.evidence.length} evidence items. Last collection ${new Date(dataset.monitoring.lastCollection).toLocaleString()}.`,
  };
}

// ── Shared activity feed ──────────────────────────────────────
const ACTIVITY_PATH: Record<string, (id: string) => string> = {
  ACTOR_CREATED: id => `/app/darkweb/actors/${id}`,
  HANDLE_ADDED: id => `/app/darkweb/handles/${id}`,
  PGP_ADDED: id => `/app/darkweb/pgp-keys/${id}`,
  WALLET_ADDED: id => `/app/darkweb/wallets/${id}`,
  INFRASTRUCTURE_ADDED: () => '/app/darkweb/infrastructure',
  SOURCE_ADDED: () => '/app/darkweb/sources',
  OBSERVATION_ADDED: id => `/app/darkweb/observations/${id}`,
  EVIDENCE_ADDED: () => '/app/darkweb/evidence',
  RELATIONSHIP_CREATED: () => '/app/darkweb/graph',
  INVESTIGATION_CREATED: id => `/app/darkweb/investigations/${id}`,
  ALERT_CREATED: () => '/app/darkweb/alerts',
  TIMELINE_EVENT_ADDED: () => '/app/darkweb/timeline',
  IMPORT_COMPLETED: () => '/app/settings',
  DEMO_DATASET_LOADED: () => '/app/briefing',
  DEMO_DATASET_RESET: () => '/app/briefing',
  DEMO_DATASET_CLEARED: () => '/app/briefing',
  DATASET_EXPORTED: () => '/app/settings',
};

export function activityFeed(dataset: IntelligenceDataset, limit = 25): ActivityItem[] {
  return [...dataset.audit]
    .sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime())
    .slice(0, limit)
    .map((event: IntelligenceAuditEvent) => ({
      id: event.id,
      time: event.time,
      kind: event.action,
      label: ACTIVITY_LABEL[event.action] ?? event.action.replace(/_/g, ' '),
      detail: event.after,
      entity: event.entity,
      entityId: event.entityId,
      actor: event.actor,
      path: (ACTIVITY_PATH[event.action] ?? (() => '/app/briefing'))(event.entityId),
    }));
}

// ── Entity resolution (ONE entity, one record) ─────────────────
export function findActor(dataset: IntelligenceDataset, ref: string): ActorRecord | null {
  const target = (ref || '').trim();
  if (!target) return null;
  const upper = target.toUpperCase();
  const byId = dataset.lookups.actorsById[target] ?? dataset.lookups.actorsById[upper];
  if (byId) return byId;
  const lower = target.toLowerCase();
  return (
    dataset.actors.find(actor => actor.aliases.some(alias => alias.toLowerCase() === lower)) ??
    dataset.actors.find(actor => actor.handles.some(handle => normalizeHandle(handle) === lower)) ??
    null
  );
}

export interface ActorBundle {
  actor: ActorRecord;
  handles: IntelligenceDataset['handles'];
  pgpKeys: IntelligenceDataset['pgpKeys'];
  wallets: IntelligenceDataset['wallets'];
  infrastructure: IntelligenceDataset['infrastructure'];
  relationships: RelationshipRecord[];
  evidence: EvidenceRecord[];
  timeline: IntelligenceDataset['timeline'];
  observations: Observation[];
  alerts: IntelligenceDataset['alerts'];
  investigations: IntelligenceDataset['investigations'];
}

export function actorBundle(dataset: IntelligenceDataset, ref: string): ActorBundle | null {
  const actor = findActor(dataset, ref);
  if (!actor) return null;
  const lowerHandles = new Set(actor.handles.map(normalizeHandle));

  return {
    actor,
    handles: dataset.handles.filter(
      handle => handle.actorId === actor.id || lowerHandles.has(normalizeHandle(handle.normalized || handle.value)),
    ),
    pgpKeys: dataset.pgpKeys.filter(key => key.actorIds.includes(actor.id)),
    wallets: dataset.wallets.filter(wallet => wallet.actorIds.includes(actor.id)),
    infrastructure: dataset.infrastructure.filter(infra => infra.actorIds.includes(actor.id)),
    relationships: dataset.relationships.filter(
      rel =>
        rel.sourceEntity === actor.id ||
        rel.targetEntity === actor.id ||
        actor.relatedActorIds.includes(rel.sourceEntity) ||
        actor.relatedActorIds.includes(rel.targetEntity),
    ),
    evidence: dataset.evidence.filter(item => item.relatedActor === actor.id),
    timeline: dataset.timeline.filter(event => event.actorId === actor.id),
    observations: dataset.observations.filter(obs => obs.actorId === actor.id),
    alerts: dataset.alerts.filter(alert => alert.actorId === actor.id),
    investigations: dataset.investigations.filter(
      inv => inv.seedActorId === actor.id || (inv.entityIds ?? []).includes(actor.id),
    ),
  };
}

export function actorTimeline(dataset: IntelligenceDataset, actorId?: string): IntelligenceDataset['timeline'] {
  const events = actorId
    ? dataset.timeline.filter(event => event.actorId === actorId)
    : dataset.timeline;
  return [...events].sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime());
}

// ── "WHY LINKED?" — computed from stored records ───────────────
export interface WhyLinked {
  exists: boolean;
  relationship: RelationshipRecord | null;
  indicators: string[];
  evidenceIds: string[];
  confidence: number;
  supporting: string[];
  against: string[];
  computedFrom: string[];
}

function entityIndicators(dataset: IntelligenceDataset, entityId: string): Set<string> {
  const indicators = new Set<string>();
  const actor = dataset.lookups.actorsById[entityId];
  const handle = dataset.handles.find(item => item.value === entityId || item.id === entityId);
  const pgp = dataset.pgpKeys.find(key => key.id === entityId || normalizePgp(key.fingerprint) === normalizePgp(entityId));
  const wallet = dataset.wallets.find(item => item.id === entityId || item.address === entityId);
  const infra = dataset.infrastructure.find(item => item.id === entityId || item.value === entityId);

  if (actor) {
    actor.handles.forEach(handle => indicators.add(`HANDLE:${normalizeHandle(handle)}`));
    actor.pgpFingerprints.forEach(fp => indicators.add(`PGP:${normalizePgp(fp)}`));
    actor.walletAddrs.forEach(wallet => indicators.add(`WALLET:${wallet}`));
    actor.domains.forEach(domain => indicators.add(`DOMAIN:${normalizeDomain(domain)}`));
  }
  if (handle) {
    indicators.add(`HANDLE:${normalizeHandle(handle.normalized || handle.value)}`);
    if (handle.actorId) {
      const owner = dataset.lookups.actorsById[handle.actorId];
      owner?.pgpFingerprints.forEach(fp => indicators.add(`PGP:${normalizePgp(fp)}`));
    }
  }
  if (pgp) indicators.add(`PGP:${normalizePgp(pgp.fingerprint)}`);
  if (wallet) indicators.add(`WALLET:${wallet.address}`);
  if (infra) {
    indicators.add(`DOMAIN:${normalizeDomain(infra.value)}`);
    indicators.add(`INFRA:${infra.value}`);
  }

  for (const key of dataset.pgpKeys) if (key.fingerprint === entityId) indicators.add(`PGP:${normalizePgp(entityId)}`);
  for (const item of dataset.infrastructure) if (item.value === entityId) indicators.add(`INFRA:${item.value}`);

  return indicators;
}

function overlaps(a: string, b: string): boolean {
  if (!a || !b) return false;
  return new Date(a).getTime() <= new Date(b).getTime();
}

/**
 * Real, stored-data explanation of a link between two entities.
 * If the dataset holds no such relationship the answer says so — the
 * UI never displays a fabricated "why linked" list.
 */
export function whyLinked(dataset: IntelligenceDataset, sourceId: string, targetId: string): WhyLinked {
  const relationship =
    dataset.relationships.find(
      rel =>
        (rel.sourceEntity === sourceId && rel.targetEntity === targetId) ||
        (rel.sourceEntity === targetId && rel.targetEntity === sourceId),
    ) ?? null;

  const left = entityIndicators(dataset, sourceId);
  const right = entityIndicators(dataset, targetId);
  const shared = [...left].filter(item => right.has(item));
  const kinds = new Set(shared.map(item => item.split(':')[0]));

  const indicators: string[] = [];
  if (kinds.has('HANDLE')) indicators.push('Shared handle');
  if (kinds.has('PGP')) indicators.push('Shared PGP fingerprint');
  if (kinds.has('WALLET')) indicators.push('Shared wallet address');
  if (kinds.has('DOMAIN')) indicators.push('Infrastructure overlap (domain)');
  if (kinds.has('INFRA')) indicators.push('Infrastructure overlap (indicator)');

  const sourceActor = findActor(dataset, sourceId);
  const targetActor = findActor(dataset, targetId);
  if (sourceActor && targetActor) {
    const overlapStart = overlaps(sourceActor.firstSeen, targetActor.lastSeen) &&
      overlaps(targetActor.firstSeen, sourceActor.lastSeen);
    if (overlapStart) indicators.push('Temporal overlap');
  }

  const evidenceIds = new Set<string>(relationship?.evidenceIds ?? []);
  for (const item of dataset.evidence) {
    if (
      (item.relatedActor && (item.relatedActor === sourceId || item.relatedActor === targetId)) ||
      (item.relatedHandle && (item.relatedHandle === sourceId || item.relatedHandle === targetId))
    ) {
      evidenceIds.add(item.id);
    }
  }

  const evidenceList = [...evidenceIds].filter(evidenceId => dataset.lookups.evidenceById[evidenceId]);
  const sourceReliability = evidenceList.length
    ? Math.round(
        evidenceList.reduce((sum, evidenceId) => sum + dataset.lookups.evidenceById[evidenceId].reliability, 0) /
          evidenceList.length,
      )
    : 0;

  const confidence = relationship
    ? relationship.confidence
    : indicators.length
      ? Math.max(35, Math.min(95, 40 + indicators.length * 12 + (sourceReliability ? Math.round(sourceReliability / 10) : 0)))
      : 0;

  return {
    exists: !!relationship || indicators.length > 0,
    relationship,
    indicators,
    evidenceIds: evidenceList,
    confidence,
    supporting: relationship?.supporting ?? indicators,
    against: relationship?.against ?? [],
    computedFrom: [...new Set([...indicators, ...(sourceReliability ? [`Source reliability R${sourceReliability}`] : [])])],
  };
}

/** Similar-entity resolution for an arbitrary free-text handle. */
export function resolveEntityValue(dataset: IntelligenceDataset, value: string) {
  const target = normalizeHandle(value);
  if (!target) return null;
  const tally = new Map<string, number>();

  for (const handle of dataset.handles) {
    const normalized = normalizeHandle(handle.normalized || handle.value);
    let score = 0;
    if (normalized === target) score = 100;
    else if (normalized.includes(target) || target.includes(normalized)) score = 80;
    else score = Math.round(similarity(normalized, target) * 100);
    if (score < 60) continue;
    if (handle.actorId) tally.set(handle.actorId, (tally.get(handle.actorId) ?? 0) + score);
  }

  if (!tally.size) return null;
  const ranked = [...tally.entries()].sort((a, b) => b[1] - a[1]);
  const [primaryActorId, score] = ranked[0];
  const actor = dataset.lookups.actorsById[primaryActorId];
  if (!actor) return null;
  return {
    primaryActorId,
    confidence: Math.min(99, score),
    label: `${actor.id} — ${actor.aliases[0] ?? actor.id}`,
    alternatives: ranked.slice(1).map(([id, value]) => ({ actorId: id, score: Math.min(99, value) })),
  };
}

// ── Relationship graph from central data ───────────────────────
export const NODE_TYPE_CONFIG: Record<string, { label: string; colorVar: string }> = {
  actor: { label: 'Threat Actor', colorVar: '--tw-critical' },
  handle: { label: 'Handle', colorVar: '--tw-burgundy' },
  pgp: { label: 'PGP Key', colorVar: '--tw-brass' },
  wallet: { label: 'Wallet', colorVar: '--tw-info' },
  domain: { label: 'Domain', colorVar: '--tw-medium' },
  ip: { label: 'IP', colorVar: '--tw-dust' },
  tls: { label: 'TLS', colorVar: '--tw-moss' },
  forum: { label: 'Forum', colorVar: '--tw-low' },
  marketplace: { label: 'Marketplace', colorVar: '--tw-low' },
  evidence: { label: 'Evidence', colorVar: '--tw-text-muted' },
  persona: { label: 'Persona', colorVar: '--tw-burgundy' },
  platform: { label: 'Platform', colorVar: '--tw-low' },
  source: { label: 'Source', colorVar: '--tw-info' },
};

const INFRA_NODE_TYPE: Record<string, string> = {
  DOMAIN: 'domain',
  IP: 'ip',
  HOSTING: 'domain',
  TLS: 'tls',
  NAMESERVER: 'domain',
};

export interface GraphNodeData {
  label: string;
  type: string;
  subType?: string;
  confidence?: number;
  color?: string;
  meta?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface GraphFilters {
  actors?: boolean;
  handles?: boolean;
  pgp?: boolean;
  wallets?: boolean;
  infrastructure?: boolean;
  platforms?: boolean;
  evidence?: boolean;
  sources?: boolean;
}

export const DEFAULT_GRAPH_FILTERS: Required<GraphFilters> = {
  actors: true,
  handles: true,
  pgp: true,
  wallets: true,
  infrastructure: true,
  platforms: false,
  evidence: true,
  sources: true,
};

export function confidenceColor(conf: number): string {
  if (conf >= 90) return 'var(--tw-critical)';
  if (conf >= 75) return 'var(--tw-high)';
  if (conf >= 60) return 'var(--tw-medium)';
  return 'var(--tw-low)';
}

function graphNode(id: string, type: string, label: string, x: number, y: number, confidence?: number, meta?: Record<string, unknown>): Node {
  return { id, type, data: { label, type, confidence, meta } as GraphNodeData, position: { x, y } };
}

function graphEdge(id: string, source: string, target: string, label: string, confidence?: number): Edge {
  return { id, source, target, label, data: { label, confidence } };
}

function place(index: number, count: number, radius = 280): { x: number; y: number } {
  const angle = (index / Math.max(1, count)) * 2 * Math.PI;
  return { x: 240 + Math.cos(angle) * radius, y: 180 + Math.sin(angle) * radius };
}

/**
 * Graph built entirely from stored records: nodes from entities,
 * edges from relationships. Nothing is hardcoded, so a relationship
 * created a second ago is renderable immediately.
 */
export function buildIntelligenceGraph(
  dataset: IntelligenceDataset,
  seed?: string,
  filters: GraphFilters = DEFAULT_GRAPH_FILTERS,
): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const seen = new Set<string>();

  const push = (id: string, type: string, label: string, confidence?: number, meta?: Record<string, unknown>) => {
    if (seen.has(id)) return;
    seen.add(id);
    nodes.push(graphNode(id, type, label, 0, 0, confidence, meta));
  };

  const relationshipEdges = () => {
    for (const rel of dataset.relationships) {
      const source = resolveGraphNodeId(dataset, rel.sourceEntity, rel.sourceType);
      const target = resolveGraphNodeId(dataset, rel.targetEntity, rel.targetType);
      if (!source || !target || source === target) continue;
      if (!seen.has(source) || !seen.has(target)) continue;
      edges.push(graphEdge(`e_${rel.id}`, source, target, rel.type.replace(/_/g, ' '), rel.confidence));
    }
  };

  /** Deterministic radial layout so the graph renders identically each build. */
  const layout = () => {
    const hubCount = Math.min(nodes.length, Math.ceil(nodes.length / 2));
    const hub = nodes.slice(0, hubCount);
    hub.forEach((node, index) => {
      const { x, y } = place(index, hub.length, 40);
      node.position = { x, y };
    });
    nodes.slice(hubCount).forEach((node, index) => {
      const { x, y } = place(index, nodes.length - hubCount, 300);
      node.position = { x, y };
    });
  };

  // ── Full graph ────────────────────────────────────────────
  if (!seed || seed === 'all') {
    if (filters.actors !== false) {
      for (const actor of dataset.actors) {
        push(actor.id, 'actor', actor.id, actor.confidenceScore, { aliases: actor.aliases, platforms: actor.platforms });
      }
    }
    if (filters.handles !== false) {
      for (const handle of dataset.handles) {
        push(`h_${handle.id}`, 'handle', handle.value, handle.confidence, { platform: handle.platform, source: handle.sourceId });
      }
    }
    if (filters.pgp !== false) {
      for (const key of dataset.pgpKeys) {
        push(`k_${key.id}`, 'pgp', shortFingerprint(key.fingerprint), key.confidence, { actorIds: key.actorIds, fingerprint: key.fingerprint });
      }
    }
    if (filters.wallets !== false) {
      for (const wallet of dataset.wallets) {
        push(`w_${wallet.id}`, 'wallet', wallet.address.slice(0, 14), wallet.confidence, { actorIds: wallet.actorIds, txCount: wallet.txCount });
      }
    }
    if (filters.infrastructure !== false) {
      for (const infra of dataset.infrastructure) {
        push(`i_${infra.id}`, INFRA_NODE_TYPE[infra.type] ?? 'domain', infra.value.slice(0, 20), undefined, { type: infra.type, actorIds: infra.actorIds });
      }
    }
    if (filters.platforms) {
      const platforms = new Set(dataset.sources.map(source => source.name));
      for (const platform of platforms) {
        push(`p_${platform}`, 'platform', platform, undefined, { type: 'PLATFORM' });
      }
    }
    if (filters.evidence) {
      for (const item of dataset.evidence) {
        push(`ev_${item.id}`, 'evidence', item.id, item.confidence, { evidenceType: item.evidenceType, source: item.source });
      }
    }
    if (filters.sources !== false) {
      for (const item of dataset.sources) {
        push(`src_${item.id}`, 'source', item.name, item.reliabilityScore, { type: item.type, sourceId: item.id });
      }
    }

    // Actor → owned indicator edges come from the stored actor record.
    for (const actor of dataset.actors) {
      for (const handle of dataset.handles.filter(item => item.actorId === actor.id)) {
        edges.push(graphEdge(`e_own_${actor.id}_${handle.id}`, actor.id, `h_${handle.id}`, 'Uses handle', handle.confidence));
      }
      for (const key of dataset.pgpKeys.filter(item => item.actorIds.includes(actor.id))) {
        edges.push(graphEdge(`e_own_${actor.id}_${key.id}`, actor.id, `k_${key.id}`, 'Owns PGP', key.confidence));
      }
      for (const wallet of dataset.wallets.filter(item => item.actorIds.includes(actor.id))) {
        edges.push(graphEdge(`e_own_${actor.id}_${wallet.id}`, actor.id, `w_${wallet.id}`, 'Owns wallet', wallet.confidence));
      }
      for (const infra of dataset.infrastructure.filter(item => item.actorIds.includes(actor.id))) {
        edges.push(graphEdge(`e_own_${actor.id}_${infra.id}`, actor.id, `i_${infra.id}`, 'Owns', 80));
      }
    }

    relationshipEdges();
    layout();
    return { nodes, edges };
  }

  // ── Focused graph around one seed entity ──────────────────
  const actor = findActor(dataset, seed);
  const seedHandle = dataset.handles.find(
    item => item.id === seed || normalizeHandle(item.normalized || item.value) === normalizeHandle(seed),
  );

  if (actor) {
    push(actor.id, 'actor', actor.id, actor.confidenceScore, { aliases: actor.aliases });
    if (filters.handles !== false) {
      for (const handle of dataset.handles.filter(item => item.actorId === actor.id || actor.handles.some(h => normalizeHandle(h) === normalizeHandle(item.normalized || item.value)))) {
        push(`h_${handle.id}`, 'handle', handle.value, handle.confidence, { platform: handle.platform });
        edges.push(graphEdge(`e_own_${actor.id}_${handle.id}`, actor.id, `h_${handle.id}`, 'Uses handle', handle.confidence));
      }
    }
    if (filters.pgp !== false) {
      for (const key of dataset.pgpKeys.filter(item => item.actorIds.includes(actor.id))) {
        push(`k_${key.id}`, 'pgp', shortFingerprint(key.fingerprint), key.confidence, { actorIds: key.actorIds, fingerprint: key.fingerprint });
        edges.push(graphEdge(`e_own_${actor.id}_${key.id}`, actor.id, `k_${key.id}`, 'Owns PGP', key.confidence));
      }
    }
    if (filters.wallets !== false) {
      for (const wallet of dataset.wallets.filter(item => item.actorIds.includes(actor.id))) {
        push(`w_${wallet.id}`, 'wallet', wallet.address.slice(0, 14), wallet.confidence, { actorIds: wallet.actorIds });
        edges.push(graphEdge(`e_own_${actor.id}_${wallet.id}`, actor.id, `w_${wallet.id}`, 'Owns wallet', wallet.confidence));
      }
    }
    if (filters.infrastructure !== false) {
      for (const infra of dataset.infrastructure.filter(item => item.actorIds.includes(actor.id))) {
        push(`i_${infra.id}`, INFRA_NODE_TYPE[infra.type] ?? 'domain', infra.value.slice(0, 20), undefined, { type: infra.type, actorIds: infra.actorIds });
        edges.push(graphEdge(`e_own_${actor.id}_${infra.id}`, actor.id, `i_${infra.id}`, 'Owns', 80));
      }
    }
    if (filters.evidence) {
      for (const item of dataset.evidence.filter(entry => entry.relatedActor === actor.id)) {
        push(`ev_${item.id}`, 'evidence', item.id, item.confidence, { evidenceType: item.evidenceType });
        edges.push(graphEdge(`e_ev_${actor.id}_${item.id}`, `ev_${item.id}`, actor.id, 'Evidence for', item.confidence));
      }
    }
    for (const relatedId of actor.relatedActorIds) {
      const related = dataset.lookups.actorsById[relatedId];
      if (related) push(related.id, 'actor', related.id, related.confidenceScore, { aliases: related.aliases });
    }
    if (filters.platforms) {
      for (const platform of actor.platforms) {
        push(`p_${platform}`, 'platform', platform, undefined, { type: 'PLATFORM' });
        edges.push(graphEdge(`e_plat_${actor.id}_${platform}`, actor.id, `p_${platform}`, 'Active on', 70));
      }
    }
  } else if (seedHandle) {
    push(`h_${seedHandle.id}`, 'handle', seedHandle.value, seedHandle.confidence, { platform: seedHandle.platform });
    const owner = seedHandle.actorId ? dataset.lookups.actorsById[seedHandle.actorId] : null;
    if (owner) {
      push(owner.id, 'actor', owner.id, owner.confidenceScore, { aliases: owner.aliases });
      edges.push(graphEdge(`e_own_${owner.id}_${seedHandle.id}`, owner.id, `h_${seedHandle.id}`, 'Uses handle', seedHandle.confidence));
    }
    if (filters.evidence) {
      for (const item of dataset.evidence.filter(entry => entry.relatedActor === seedHandle.actorId)) {
        push(`ev_${item.id}`, 'evidence', item.id, item.confidence, {});
        edges.push(graphEdge(`e_ev_${seedHandle.id}_${item.id}`, `ev_${item.id}`, `h_${seedHandle.id}`, 'Evidence for', item.confidence));
      }
    }
  } else {
    // Seed is a PGP / wallet / infrastructure value.
    const pgp = dataset.pgpKeys.find(item => item.id === seed || normalizePgp(item.fingerprint) === normalizePgp(seed));
    const wallet = dataset.wallets.find(item => item.id === seed || item.address === seed);
    const infra = dataset.infrastructure.find(item => item.id === seed || item.value === seed);
    if (pgp) {
      push(`k_${pgp.id}`, 'pgp', shortFingerprint(pgp.fingerprint), pgp.confidence, { actorIds: pgp.actorIds });
      for (const actorId of pgp.actorIds) {
        const owner = dataset.lookups.actorsById[actorId];
        if (!owner) continue;
        push(owner.id, 'actor', owner.id, owner.confidenceScore, { aliases: owner.aliases });
        edges.push(graphEdge(`e_own_${owner.id}_${pgp.id}`, owner.id, `k_${pgp.id}`, 'Owns PGP', pgp.confidence));
      }
    }
    if (wallet) {
      push(`w_${wallet.id}`, 'wallet', wallet.address.slice(0, 14), wallet.confidence, { actorIds: wallet.actorIds });
      for (const actorId of wallet.actorIds) {
        const owner = dataset.lookups.actorsById[actorId];
        if (!owner) continue;
        push(owner.id, 'actor', owner.id, owner.confidenceScore, { aliases: owner.aliases });
        edges.push(graphEdge(`e_own_${owner.id}_${wallet.id}`, owner.id, `w_${wallet.id}`, 'Owns wallet', wallet.confidence));
      }
    }
    if (infra) {
      push(`i_${infra.id}`, INFRA_NODE_TYPE[infra.type] ?? 'domain', infra.value.slice(0, 20), undefined, { type: infra.type, actorIds: infra.actorIds });
      for (const actorId of infra.actorIds) {
        const owner = dataset.lookups.actorsById[actorId];
        if (!owner) continue;
        push(owner.id, 'actor', owner.id, owner.confidenceScore, { aliases: owner.aliases });
        edges.push(graphEdge(`e_own_${owner.id}_${infra.id}`, owner.id, `i_${infra.id}`, 'Owns', 80));
      }
    }
  }

  relationshipEdges();
  layout();
  return { nodes, edges };
}

/**
 * A relationship may reference an entity by id ("HND-003") or by the value
 * the analyst typed ("nightstalk"). Both must resolve to the same node, so
 * lookups try the id first and then the human-readable value.
 */
export function resolveGraphNodeId(dataset: IntelligenceDataset, entity: string, entityType: string): string | null {
  const ref = (entity ?? '').trim();
  if (!ref) return null;

  const actor = dataset.lookups.actorsById[ref] ?? dataset.lookups.actorsById[ref.toUpperCase()];
  if (actor) return actor.id;

  const handle = dataset.handles.find(
    item =>
      item.id === ref ||
      item.value.toLowerCase() === ref.toLowerCase() ||
      normalizeHandle(item.normalized || item.value) === normalizeHandle(ref),
  );
  const pgp = dataset.pgpKeys.find(
    item => item.id === ref || item.fingerprint === ref || normalizePgp(item.fingerprint) === normalizePgp(ref),
  );
  const wallet = dataset.wallets.find(item => item.id === ref || item.address === ref);
  const infra = dataset.infrastructure.find(item => item.id === ref || item.value === ref);
  const source = dataset.sources.find(item => item.id === ref || item.name === ref);

  if (entityType === 'Handle') return handle ? `h_${handle.id}` : null;
  if (entityType === 'PGP') return pgp ? `k_${pgp.id}` : null;
  if (entityType === 'Wallet') return wallet ? `w_${wallet.id}` : null;
  if (entityType === 'Infrastructure') return infra ? `i_${infra.id}` : null;
  if (entityType === 'Evidence') return dataset.lookups.evidenceById[ref] ? `ev_${ref}` : null;
  if (entityType === 'Source') return source ? `src_${source.id}` : null;

  if (handle) return `h_${handle.id}`;
  if (pgp) return `k_${pgp.id}`;
  if (wallet) return `w_${wallet.id}`;
  if (infra) return `i_${infra.id}`;
  if (source) return `src_${source.id}`;
  return null;
}

// ── Evidence chain: source → observation → indicator → entity →
//    relationship → investigation ────────────────────────────────
export interface EvidenceChainStep {
  step: number;
  label: string;
  record: string;
  detail: string;
  path: string;
}

export function evidenceChain(dataset: IntelligenceDataset, evidenceId: string): EvidenceChainStep[] {
  const item = dataset.lookups.evidenceById[evidenceId];
  if (!item) return [];

  const source = dataset.sources.find(entry => entry.name === item.source);
  const observations = dataset.observations.filter(obs => obs.evidenceIds.includes(item.id));
  const indicators: string[] = [];
  if (item.relatedActor) {
    const actor = dataset.lookups.actorsById[item.relatedActor];
    if (actor) indicators.push(...actor.handles.map(normalizeHandle), ...actor.pgpFingerprints.map(normalizePgp));
  }
  const relationship = item.relatedRelationship ? dataset.lookups.relationshipsById[item.relatedRelationship] : null;
  const investigations = dataset.investigations.filter(inv =>
    inv.steps.some(step => step.evidenceIds.includes(item.id)),
  );

  const steps: EvidenceChainStep[] = [
    {
      step: 1,
      label: 'Source',
      record: source?.id ?? item.source,
      detail: source ? `${source.name} · reliability R${source.reliabilityScore}` : item.source,
      path: '/app/darkweb/sources',
    },
    {
      step: 2,
      label: 'Observation',
      record: observations[0]?.id ?? '—',
      detail: observations[0]?.content ?? `Captured at ${item.timestamp}`,
      path: '/app/darkweb/timeline',
    },
    {
      step: 3,
      label: 'Indicator',
      record: [...new Set(indicators)].slice(0, 3).join(' · ') || item.evidenceType,
      detail: item.provenance,
      path: '/app/darkweb/correlation',
    },
    {
      step: 4,
      label: 'Entity',
      record: item.relatedActor ?? 'Unattributed',
      detail: item.relatedActor
        ? dataset.lookups.actorsById[item.relatedActor]?.aliases[0] ?? item.relatedActor
        : 'No actor attribution recorded for this item',
      path: item.relatedActor ? `/app/darkweb/actors/${item.relatedActor}` : '/app/darkweb/actors',
    },
    {
      step: 5,
      label: 'Relationship',
      record: relationship?.id ?? '—',
      detail: relationship
        ? `${relationship.sourceEntity} → ${relationship.targetEntity} (${relationship.type.replace(/_/g, ' ').toLowerCase()}, ${relationship.confidence}%)`
        : 'No relationship references this item',
      path: '/app/darkweb/graph',
    },
    {
      step: 6,
      label: 'Investigation',
      record: investigations[0]?.id ?? '—',
      detail: investigations[0]?.title ?? 'Not yet attached to an investigation',
      path: investigations[0] ? `/app/darkweb/investigations/${investigations[0].id}` : '/app/darkweb/investigations',
    },
  ];

  return steps;
}

/** Every record an investigation case should show, resolved from the dataset. */
export function investigationBundle(dataset: IntelligenceDataset, investigationId: string) {
  const investigation = dataset.lookups.investigationsById[investigationId];
  if (!investigation) return null;
  const actorIds = new Set<string>([investigation.seedActorId, ...(investigation.entityIds ?? [])]);
  for (const step of investigation.steps) step.actorIds.forEach(id => actorIds.add(id));
  const relationshipIds = new Set(investigation.steps.flatMap(step => step.relationshipIds));
  const evidenceIds = new Set(investigation.steps.flatMap(step => step.evidenceIds));

  return {
    investigation,
    actors: dataset.actors.filter(actor => actorIds.has(actor.id)),
    handles: dataset.handles.filter(handle => actorIds.has(handle.actorId ?? '')),
    pgpKeys: dataset.pgpKeys.filter(key => key.actorIds.some(id => actorIds.has(id))),
    wallets: dataset.wallets.filter(wallet => wallet.actorIds.some(id => actorIds.has(id))),
    infrastructure: dataset.infrastructure.filter(infra => infra.actorIds.some(id => actorIds.has(id))),
    relationships: dataset.relationships.filter(rel => relationshipIds.has(rel.id) || actorIds.has(rel.sourceEntity) || actorIds.has(rel.targetEntity)),
    evidence: dataset.evidence.filter(item => evidenceIds.has(item.id) || (item.relatedActor ? actorIds.has(item.relatedActor) : false)),
    timeline: dataset.timeline.filter(event => actorIds.has(event.actorId)),
    observations: dataset.observations.filter(obs => obs.actorId ? actorIds.has(obs.actorId) : false),
    alerts: dataset.alerts.filter(alert => alert.actorId ? actorIds.has(alert.actorId) : false),
  };
}
