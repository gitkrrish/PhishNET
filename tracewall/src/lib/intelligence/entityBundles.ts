// ============================================================
// PhishNet — Per-entity investigation bundles.
//
// A Handle, a PGP key, a Wallet and an Observation are already
// first-class records in the central model. These selectors do
// NOT create new records or a new store: given an existing record
// id, they resolve everything the record is already connected to
// in that same model — actor, related identities, sources,
// evidence, relationships, timeline and investigations.
//
// Every specialized entity workspace renders from these bundles, so
// a Handle, PGP, Wallet and Observation page can never disagree
// with Actor, Relationships, Timeline, Evidence or Investigations.
// ============================================================
import type {
  IntelligenceDataset,
  HandleRecord,
  PgpRecord,
  WalletRecord,
  Observation,
  RelationshipRecord,
  EvidenceRecord,
  TimelineRecord,
  InvestigationRecord,
  InfrastructureRecord,
  SourceRecord,
  ActorRecord,
} from './types';
import { normalizeHandle, normalizePgp, normalizeWallet, normalizeDomain } from './normalize';

// ── Canonical deep links ─────────────────────────────────────────
// One place decides which specialized page owns an entity, so a
// link written in a workspace, a search hit or an activity row all
// resolve to the same page and the same central backend id.

export const ENTITY_PATH = {
  handles: '/app/darkweb/handles',
  pgpKeys: '/app/darkweb/pgp-keys',
  wallets: '/app/darkweb/wallets',
  observations: '/app/darkweb/observations',
  actors: '/app/darkweb/actors',
  sources: '/app/darkweb/sources',
  evidence: '/app/darkweb/evidence',
  timeline: '/app/darkweb/timeline',
  graph: '/app/darkweb/graph',
  investigations: '/app/darkweb/investigations',
  correlation: '/app/darkweb/correlation',
  infrastructure: '/app/darkweb/infrastructure',
  attack: '/app/darkweb/attack',
  ai: '/app/darkweb/ai',
} as const;

export const handlePath = (id: string) => `${ENTITY_PATH.handles}/${encodeURIComponent(id)}`;
export const pgpPath = (id: string) => `${ENTITY_PATH.pgpKeys}/${encodeURIComponent(id)}`;
export const walletPath = (id: string) => `${ENTITY_PATH.wallets}/${encodeURIComponent(id)}`;
export const observationPath = (id: string) => `${ENTITY_PATH.observations}/${encodeURIComponent(id)}`;
export const actorPath = (id: string) => `${ENTITY_PATH.actors}/${encodeURIComponent(id)}`;

// ── Shared resolution helpers ───────────────────────────────────

/** A handle may be referenced by id, raw value or normalized form. */
function handleKeys(handle: HandleRecord): string[] {
  return [handle.id, handle.value, handle.normalized, normalizeHandle(handle.value)]
    .filter(Boolean)
    .map(value => value.toLowerCase());
}

export function findHandle(dataset: IntelligenceDataset, ref: string): HandleRecord | null {
  const target = (ref ?? '').trim();
  if (!target) return null;
  const byId = dataset.lookups.handlesById[target];
  if (byId) return byId;
  const lower = target.toLowerCase();
  const normalized = normalizeHandle(target);
  return (
    dataset.handles.find(handle => handle.value.toLowerCase() === lower) ??
    dataset.handles.find(handle => normalizeHandle(handle.normalized || handle.value) === normalized) ??
    null
  );
}

export function findPgp(dataset: IntelligenceDataset, ref: string): PgpRecord | null {
  const target = (ref ?? '').trim();
  if (!target) return null;
  const byId = dataset.lookups.pgpById[target];
  if (byId) return byId;
  const flat = normalizePgp(target);
  const exact =
    dataset.pgpKeys.find(key => key.fingerprint === target) ??
    dataset.pgpKeys.find(key => normalizePgp(key.fingerprint) === flat) ??
    dataset.pgpKeys.find(key => key.id.toUpperCase() === target.toUpperCase());
  if (exact) return exact;

  // The dossiers show short fingerprints, so a pasted short form must resolve.
  // Require a real-length prefix and only accept it when it is unambiguous.
  if (flat.length < 8) return null;
  const prefixMatches = dataset.pgpKeys.filter(key => normalizePgp(key.fingerprint).startsWith(flat));
  return prefixMatches.length === 1 ? prefixMatches[0] : null;
}

export function findWallet(dataset: IntelligenceDataset, ref: string): WalletRecord | null {
  const target = (ref ?? '').trim();
  if (!target) return null;
  const byId = dataset.lookups.walletsById[target];
  if (byId) return byId;
  return (
    dataset.wallets.find(wallet => normalizeWallet(wallet.address) === normalizeWallet(target)) ??
    dataset.wallets.find(wallet => wallet.id.toUpperCase() === target.toUpperCase()) ??
    null
  );
}

export function findObservation(dataset: IntelligenceDataset, ref: string): Observation | null {
  const target = (ref ?? '').trim();
  if (!target) return null;
  return dataset.observations.find(obs => obs.id === target) ?? null;
}

/** Actors that use this handle, by direct attribution or stored handle list. */
export function actorsForHandle(dataset: IntelligenceDataset, handle: HandleRecord): ActorRecord[] {
  const keys = handleKeys(handle);
  return dataset.actors.filter(
    actor =>
      actor.id === (handle.actorId ?? '') ||
      actor.handles.some(value => keys.includes(normalizeHandle(value))) ||
      actor.aliases.some(alias => keys.includes(normalizeHandle(alias))),
  );
}

function relationshipsFor(
  dataset: IntelligenceDataset,
  keys: string[],
  actorIds: string[],
  types?: string[],
): RelationshipRecord[] {
  const keySet = new Set(keys.map(key => key.toLowerCase()));
  const actorSet = new Set(actorIds);
  return dataset.relationships.filter(rel => {
    if (types && !types.includes(rel.type)) return false;
    const source = (rel.sourceEntity ?? '').toLowerCase();
    const target = (rel.targetEntity ?? '').toLowerCase();
    if (keySet.has(source) || keySet.has(target)) return true;
    return actorSet.has(source) || actorSet.has(target);
  });
}

function evidenceFor(dataset: IntelligenceDataset, actorIds: string[], handleIds: string[]): EvidenceRecord[] {
  const actorSet = new Set(actorIds);
  const handleSet = new Set(handleIds);
  return dataset.evidence.filter(
    item =>
      (item.relatedActor ? actorSet.has(item.relatedActor) : false) ||
      (item.relatedHandle ? handleSet.has(item.relatedHandle) : false) ||
      (item.relatedInfrastructure ? handleSet.has(item.relatedInfrastructure) : false),
  );
}

function timelineFor(dataset: IntelligenceDataset, actorIds: string[]): TimelineRecord[] {
  const actorSet = new Set(actorIds);
  return dataset.timeline
    .filter(event => actorSet.has(event.actorId))
    .sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime());
}

function investigationsFor(dataset: IntelligenceDataset, actorIds: string[]): InvestigationRecord[] {
  const actorSet = new Set(actorIds);
  return dataset.investigations.filter(
    inv => actorSet.has(inv.seedActorId) || (inv.entityIds ?? []).some(id => actorSet.has(id)),
  );
}

function sourcesFor(dataset: IntelligenceDataset, ids: Array<string | undefined | null>): SourceRecord[] {
  const wanted = new Set(ids.filter(Boolean).map(value => (value as string).toLowerCase()));
  return dataset.sources.filter(
    source => wanted.has(source.id.toLowerCase()) || wanted.has(source.name.toLowerCase()),
  );
}

function infrastructureFor(dataset: IntelligenceDataset, actors: ActorRecord[]): InfrastructureRecord[] {
  const ids = new Set(actors.map(actor => actor.id));
  return dataset.infrastructure.filter(infra => infra.actorIds.some(id => ids.has(id)));
}

function pgpFor(dataset: IntelligenceDataset, actors: ActorRecord[]): PgpRecord[] {
  const ids = new Set(actors.map(actor => actor.id));
  const fingerprints = new Set(actors.flatMap(actor => actor.pgpFingerprints.map(normalizePgp)));
  return dataset.pgpKeys.filter(key => key.actorIds.some(id => ids.has(id)) || fingerprints.has(normalizePgp(key.fingerprint)));
}

function walletsFor(dataset: IntelligenceDataset, actors: ActorRecord[]): WalletRecord[] {
  const ids = new Set(actors.map(actor => actor.id));
  const addresses = new Set(actors.flatMap(actor => actor.walletAddrs.map(normalizeWallet)));
  return dataset.wallets.filter(wallet => wallet.actorIds.some(id => ids.has(id)) || addresses.has(normalizeWallet(wallet.address)));
}

function handlesFor(dataset: IntelligenceDataset, actors: ActorRecord[]): HandleRecord[] {
  const ids = new Set(actors.map(actor => actor.id));
  const values = new Set(actors.flatMap(actor => actor.handles.map(normalizeHandle)));
  return dataset.handles.filter(
    handle => (handle.actorId ? ids.has(handle.actorId) : false) || values.has(normalizeHandle(handle.normalized || handle.value)),
  );
}

// ── Handle bundle ──────────────────────────────────────────────
export interface HandleBundle {
  handle: HandleRecord;
  actors: ActorRecord[];
  aliasHandles: HandleRecord[];
  platforms: string[];
  sources: SourceRecord[];
  pgpKeys: PgpRecord[];
  wallets: WalletRecord[];
  infrastructure: InfrastructureRecord[];
  relationships: RelationshipRecord[];
  evidence: EvidenceRecord[];
  timeline: TimelineRecord[];
  investigations: InvestigationRecord[];
  observations: Observation[];
  /** Stored supporting / against indicators for the handle's own links. */
  whyLinked: Array<{ indicator: string; source: 'RELATIONSHIP' | 'SHARED_IDENTITY'; detail: string }>;
}

export function handleBundle(dataset: IntelligenceDataset, ref: string): HandleBundle | null {
  const handle = findHandle(dataset, ref);
  if (!handle) return null;

  const keys = handleKeys(handle);
  const actors = actorsForHandle(dataset, handle);
  const actorIds = actors.map(actor => actor.id);
  const aliasHandles = dataset.handles.filter(
    item =>
      item.id !== handle.id &&
      normalizeHandle(item.normalized || item.value) === normalizeHandle(handle.normalized || handle.value),
  );

  const relationships = relationshipsFor(dataset, keys, actorIds);
  const evidence = evidenceFor(dataset, actorIds, [handle.id, ...aliasHandles.map(item => item.id)]);
  const platforms = [handle.platform, ...aliasHandles.map(item => item.platform)].filter(
    (value, index, list) => value && list.indexOf(value) === index,
  );
  const sources = sourcesFor(dataset, [
    handle.sourceId,
    handle.source,
    ...aliasHandles.map(item => item.sourceId),
    ...evidence.map(item => item.source),
  ]);

  const whyLinked: HandleBundle['whyLinked'] = relationships.map(rel => ({
    indicator: rel.type.replace(/_/g, ' '),
    source: 'RELATIONSHIP',
    detail: rel.explanation,
  }));
  if (aliasHandles.length) {
    whyLinked.push({
      indicator: 'Cross-platform reuse',
      source: 'SHARED_IDENTITY',
      detail: `Identical normalized form "@${handle.normalized || handle.value}" observed on ${aliasHandles
        .map(item => item.platform)
        .join(', ')}.`,
    });
  }

  return {
    handle,
    actors,
    aliasHandles,
    platforms,
    sources,
    pgpKeys: pgpFor(dataset, actors),
    wallets: walletsFor(dataset, actors),
    infrastructure: infrastructureFor(dataset, actors),
    relationships,
    evidence,
    timeline: timelineFor(dataset, actorIds),
    investigations: investigationsFor(dataset, actorIds),
    observations: dataset.observations.filter(obs => obs.handleId === handle.id),
    whyLinked,
  };
}

// ── PGP bundle ─────────────────────────────────────────────────
export interface PgpBundle {
  key: PgpRecord;
  actors: ActorRecord[];
  handles: HandleRecord[];
  platforms: string[];
  sources: SourceRecord[];
  wallets: WalletRecord[];
  infrastructure: InfrastructureRecord[];
  relationships: RelationshipRecord[];
  evidence: EvidenceRecord[];
  timeline: TimelineRecord[];
  investigations: InvestigationRecord[];
  observations: Observation[];
  keyId: string;
  whyLinked: Array<{ indicator: string; detail: string }>;
}

export function pgpBundle(dataset: IntelligenceDataset, ref: string): PgpBundle | null {
  const key = findPgp(dataset, ref);
  if (!key) return null;

  const actorIds = new Set(key.actorIds);
  const actors = dataset.actors.filter(actor => actorIds.has(actor.id));
  const linked = actors.length ? actors : [];
  const handles = (key.handleIds?.length
    ? dataset.handles.filter(handle => key.handleIds?.includes(handle.id))
    : handlesFor(dataset, linked));

  const keys = [key.id, key.fingerprint, normalizePgp(key.fingerprint)];
  const relationships = relationshipsFor(dataset, keys, actors.map(actor => actor.id));
  const evidence = dataset.evidence.filter(
    item =>
      (item.relatedActor ? actorIds.has(item.relatedActor) : false) ||
      item.evidenceType === 'PGP_KEY' ||
      item.provenance.toLowerCase().includes(key.id.toLowerCase()),
  );
  const sources = sourcesFor(dataset, key.sources);

  const whyLinked: PgpBundle['whyLinked'] = relationships.map(rel => ({
    indicator: rel.type.replace(/_/g, ' '),
    detail: rel.explanation,
  }));
  if (actors.length > 1) {
    whyLinked.push({
      indicator: 'Shared cryptographic identity',
      detail: `One fingerprint is attributed to ${actors.length} actors (${actors
        .map(actor => actor.id)
        .join(', ')}). A PGP key is a sanctioned, long-lived identity artifact, so reuse is a strong linking indicator.`,
    });
  }

  return {
    key,
    keyId: key.id,
    actors,
    handles,
    platforms: [
      ...new Set([...actors.flatMap(actor => actor.platforms), ...sources.map(source => source.name)]),
    ],
    sources,
    wallets: walletsFor(dataset, linked),
    infrastructure: infrastructureFor(dataset, linked),
    relationships,
    evidence,
    timeline: timelineFor(dataset, actors.map(actor => actor.id)),
    investigations: investigationsFor(dataset, actors.map(actor => actor.id)),
    observations: dataset.observations.filter(obs => {
      const text = obs.content.toLowerCase();
      const prefix = normalizePgp(key.fingerprint).slice(0, 8).toLowerCase();
      return text.includes(key.id.toLowerCase()) || (!!prefix && text.includes(prefix));
    }),
    whyLinked,
  };
}

// ── Wallet bundle ──────────────────────────────────────────────
export interface WalletBundle {
  wallet: WalletRecord;
  actors: ActorRecord[];
  handles: HandleRecord[];
  network: string;
  platforms: string[];
  sources: SourceRecord[];
  pgpKeys: PgpRecord[];
  infrastructure: InfrastructureRecord[];
  relationships: RelationshipRecord[];
  evidence: EvidenceRecord[];
  timeline: TimelineRecord[];
  investigations: InvestigationRecord[];
  observations: Observation[];
  /** Other wallets held by the same attributed actor — a cluster view. */
  relatedWallets: WalletRecord[];
  transactions: IntelligenceDataset['walletTransactions'];
  clusters: IntelligenceDataset['walletClusters'];
  exchanges: IntelligenceDataset['exchanges'];
  whyLinked: Array<{ indicator: string; detail: string }>;
}

export function walletBundle(dataset: IntelligenceDataset, ref: string): WalletBundle | null {
  const wallet = findWallet(dataset, ref);
  if (!wallet) return null;

  const actorIds = new Set(wallet.actorIds);
  const actors = dataset.actors.filter(actor => actorIds.has(actor.id));
  const handles = (wallet.handleIds?.length
    ? dataset.handles.filter(handle => wallet.handleIds?.includes(handle.id))
    : handlesFor(dataset, actors));

  const keys = [wallet.id, wallet.address];
  const relationships = relationshipsFor(dataset, keys, actors.map(actor => actor.id));
  const evidence = dataset.evidence.filter(
    item =>
      (item.relatedActor ? actorIds.has(item.relatedActor) : false) ||
      item.provenance.toLowerCase().includes(wallet.id.toLowerCase()) ||
      item.provenance.includes(wallet.address.slice(0, 12)),
  );
  const sources = sourcesFor(dataset, wallet.observedSources);

  const relatedWallets = dataset.wallets.filter(
    item => item.id !== wallet.id && item.actorIds.some(id => actorIds.has(id)),
  );

  // The demo dataset carries no transaction table. Treat the collection as
  // optional so a wallet dossier renders read-only analysis rather than
  // throwing, and never synthesise transaction rows that do not exist.
  const allTransactions = dataset.walletTransactions ?? [];
  const transactions = allTransactions.filter(tx => tx.walletId === wallet.id);
  const allClusters = dataset.walletClusters ?? [];
  const clusterIds = new Set(allClusters.filter(c => c.walletIds.includes(wallet.id)).map(c => c.id));
  const transactionsWithCluster = transactions.length
    ? transactions
    : allTransactions.filter(tx => !!tx.clusterId && clusterIds.has(tx.clusterId));

  const whyLinked: WalletBundle['whyLinked'] = relationships.map(rel => ({
    indicator: rel.type.replace(/_/g, ' '),
    detail: rel.explanation,
  }));
  if (relatedWallets.length) {
    whyLinked.push({
      indicator: 'Shared wallet cluster',
      detail: `${relatedWallets.length} further address${relatedWallets.length === 1 ? '' : 'es'} attributed to the same actor${actors.length ? ` (${actors.map(actor => actor.id).join(', ')})` : ''}.`,
    });
  }

  return {
    wallet,
    actors,
    handles,
    network: wallet.network || (wallet.address.startsWith('bc1') ? 'BTC' : 'UNSPECIFIED'),
    platforms: sources.map(source => source.name),
    sources,
    pgpKeys: pgpFor(dataset, actors),
    infrastructure: infrastructureFor(dataset, actors),
    relationships,
    evidence,
    timeline: timelineFor(dataset, actors.map(actor => actor.id)),
    investigations: investigationsFor(dataset, actors.map(actor => actor.id)),
    observations: dataset.observations.filter(obs => obs.content.includes(wallet.address)),
    relatedWallets,
    transactions: transactionsWithCluster,
    clusters: allClusters.filter(cluster => cluster.walletIds.includes(wallet.id)),
    exchanges: (dataset.exchanges ?? []).filter(exchange =>
      exchange.walletAddresses.some(address => normalizeWallet(address) === normalizeWallet(wallet.address)),
    ),
    whyLinked,
  };
}

// ── Observation bundle ─────────────────────────────────────────
export interface ExtractedEntity {
  kind: 'Handle' | 'PGP' | 'Wallet' | 'Infrastructure' | 'Actor' | 'Source';
  label: string;
  normalized: string;
  id: string;
  path: string;
}

export interface ObservationBundle {
  observation: Observation;
  source: SourceRecord | null;
  actor: ActorRecord | null;
  handle: HandleRecord | null;
  pgpKeys: PgpRecord[];
  wallets: WalletRecord[];
  infrastructure: InfrastructureRecord[];
  evidence: EvidenceRecord[];
  timeline: TimelineRecord[];
  relationships: RelationshipRecord[];
  investigation: InvestigationRecord | null;
  /** Entities read directly out of the raw observation text. */
  extracted: ExtractedEntity[];
  /** Of the extracted entities, those already normalized in the model. */
  normalized: ExtractedEntity[];
  processingStatus: { label: string; detail: string };
}

const PROCESSING_LABEL: Record<string, string> = {
  OBSERVED: 'OBSERVED',
  IMPORTED: 'IMPORTED',
  ANALYST_ADDED: 'ANALYST RECORDED',
  AI_DERIVED: 'AI DERIVED',
  SYNTHETIC_DEMO: 'SYNTHETIC DEMO',
};

/**
 * Reads an observation's raw text and reports which stored entities it
 * names. This is a read-only projection over records that already exist
 * in the central model — it never creates an entity.
 */
export function extractEntities(dataset: IntelligenceDataset, content: string): ExtractedEntity[] {
  const text = (content ?? '').toLowerCase();
  if (!text) return [];
  const found: ExtractedEntity[] = [];
  const seen = new Set<string>();

  const push = (entity: ExtractedEntity) => {
    const key = `${entity.kind}:${entity.normalized}`;
    if (seen.has(key)) return;
    seen.add(key);
    found.push(entity);
  };

  for (const handle of dataset.handles) {
    const normalized = normalizeHandle(handle.normalized || handle.value);
    if (normalized && text.includes(normalized)) {
      push({
        kind: 'Handle',
        label: handle.value,
        normalized,
        id: handle.id,
        path: handlePath(handle.id),
      });
    }
  }
  for (const key of dataset.pgpKeys) {
    const flat = normalizePgp(key.fingerprint);
    const prefix = flat.slice(0, 8).toLowerCase();
    if ((prefix && text.includes(prefix)) || text.includes(key.id.toLowerCase())) {
      push({ kind: 'PGP', label: key.fingerprint, normalized: flat, id: key.id, path: pgpPath(key.id) });
    }
  }
  for (const wallet of dataset.wallets) {
    if (wallet.address && text.includes(wallet.address.toLowerCase())) {
      push({
        kind: 'Wallet',
        label: wallet.address,
        normalized: wallet.address,
        id: wallet.id,
        path: walletPath(wallet.id),
      });
    }
  }
  for (const infra of dataset.infrastructure) {
    const normalized = normalizeDomain(infra.value);
    if (normalized && text.includes(normalized)) {
      push({
        kind: 'Infrastructure',
        label: infra.value,
        normalized,
        id: infra.id,
        path: ENTITY_PATH.infrastructure,
      });
    }
  }
  for (const actor of dataset.actors) {
    const hit =
      text.includes(actor.id.toLowerCase()) ||
      actor.aliases.some(alias => alias.length > 3 && text.includes(alias.toLowerCase()));
    if (hit) {
      push({
        kind: 'Actor',
        label: actor.aliases[0] ?? actor.id,
        normalized: actor.id.toLowerCase(),
        id: actor.id,
        path: actorPath(actor.id),
      });
    }
  }
  for (const source of dataset.sources) {
    if (source.name.length > 3 && text.includes(source.name.toLowerCase())) {
      push({
        kind: 'Source',
        label: source.name,
        normalized: source.name.toLowerCase(),
        id: source.id,
        path: ENTITY_PATH.sources,
      });
    }
  }
  return found;
}

export function observationBundle(dataset: IntelligenceDataset, ref: string): ObservationBundle | null {
  const observation = findObservation(dataset, ref);
  if (!observation) return null;

  const handle = observation.handleId ? dataset.lookups.handlesById[observation.handleId] ?? null : null;
  const actor = observation.actorId ? dataset.lookups.actorsById[observation.actorId] ?? null : null;
  const source = sourcesFor(dataset, [observation.source])[0] ?? null;

  const evidence = dataset.evidence.filter(item => observation.evidenceIds.includes(item.id));
  const extracted = extractEntities(dataset, observation.content);
  const normalizedIds = new Set([
    ...dataset.handles.map(handle => `Handle:${normalizeHandle(handle.normalized || handle.value)}`),
    ...dataset.pgpKeys.map(key => `PGP:${normalizePgp(key.fingerprint)}`),
    ...dataset.wallets.map(wallet => `Wallet:${wallet.address}`),
  ]);
  const normalizedEntities = extracted.filter(entity =>
    normalizedIds.has(`${entity.kind}:${entity.normalized}`),
  );

  const relationshipKeys = [
    observation.id,
    handle?.id,
    handle?.value,
    actor?.id,
    ...extracted.filter(entity => entity.kind === 'Handle').map(entity => entity.id),
  ].filter(Boolean) as string[];

  return {
    observation,
    source,
    actor: actor ?? null,
    handle: handle ?? null,
    pgpKeys: extracted
      .filter(entity => entity.kind === 'PGP')
      .map(entity => dataset.lookups.pgpById[entity.id])
      .filter(Boolean),
    wallets: extracted
      .filter(entity => entity.kind === 'Wallet')
      .map(entity => dataset.lookups.walletsById[entity.id])
      .filter(Boolean),
    infrastructure: extracted
      .filter(entity => entity.kind === 'Infrastructure')
      .map(entity => dataset.infrastructure.find(item => item.id === entity.id))
      .filter((item): item is InfrastructureRecord => !!item),
    evidence,
    timeline: timelineFor(dataset, actor ? [actor.id] : []),
    relationships: relationshipsFor(dataset, relationshipKeys, actor ? [actor.id] : []),
    investigation:
      investigationsFor(dataset, actor ? [actor.id] : [])[0] ??
      dataset.investigations.find(inv =>
        inv.steps.some(step => step.actorIds.includes(observation.id)),
      ) ??
      null,
    extracted,
    normalized: normalizedEntities,
    processingStatus: {
      label: PROCESSING_LABEL[observation.dataState ?? 'OBSERVED'] ?? 'OBSERVED',
      detail:
        observation.dataState === 'ANALYST_ADDED'
          ? 'Recorded by an analyst through Add Intelligence.'
          : observation.dataState === 'AI_DERIVED'
            ? 'Produced by an AI extraction pass over collected material.'
            : 'Captured during collection.',
    },
  };
}
