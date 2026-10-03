// ============================================================
// PhishNet — global dark web intelligence search.
//
// This is an INDEX over the existing engines, not a new search
// system. Every match is produced by `aiEngine` / `darkWebData`,
// so the search can never disagree with the analysis pages.
//
// Nothing here invents a result: each hit carries the id of the
// record it came from and a deep link into the module that owns
// that record.
// ============================================================
import {
  correlateHandles,
  searchPgp,
  searchWallet,
  searchInfrastructure,
  resolveEntity,
  type HandleMatch,
} from './aiEngine';
import {
  darkWebActors,
  darkWebActorsById,
  darkWebEvidence,
  darkWebHandles,
  darkWebHandlesById,
  darkWebInfrastructure,
  darkWebInvestigations,
  darkWebPgpKeys,
  darkWebRelationships,
  darkWebSources,
  darkWebWallets,
  darkWebObservations,
  darkWebMitreTtps,
  darkWebCves,
} from './liveData';
import {
  handlePath,
  observationPath,
  pgpPath,
  walletPath,
} from '../intelligence/entityBundles';

/** The ATT&CK workspace owns technique, coverage and CVE cross-references. */
const ATTACK_PATH = '/app/darkweb/attack';

export type SearchKind =
  | 'ACTOR'
  | 'HANDLE'
  | 'PGP'
  | 'WALLET'
  | 'INFRASTRUCTURE'
  | 'SOURCE'
  | 'OBSERVATION'
  | 'EVIDENCE'
  | 'INVESTIGATION'
  | 'RELATIONSHIP'
  | 'ATTACK_TECHNIQUE'
  | 'CVE';

export const SEARCH_KIND_LABEL: Record<SearchKind, string> = {
  ACTOR: 'Threat Actor',
  HANDLE: 'Handle',
  PGP: 'PGP Fingerprint',
  WALLET: 'Wallet',
  INFRASTRUCTURE: 'Infrastructure',
  SOURCE: 'Source',
  OBSERVATION: 'Observation',
  EVIDENCE: 'Evidence',
  INVESTIGATION: 'Investigation',
  RELATIONSHIP: 'Relationship',
  ATTACK_TECHNIQUE: 'ATT&CK Technique',
  CVE: 'CVE',
};

export interface SearchHit {
  kind: SearchKind;
  id: string;
  title: string;
  subtitle: string;
  detail: string;
  confidence: number;
  path: string;
}

export interface SearchResult {
  query: string;
  actor: SearchHit | null;
  handles: SearchHit[];
  pgp: SearchHit[];
  wallets: SearchHit[];
  infrastructure: SearchHit[];
  sources: SearchHit[];
  observations: SearchHit[];
  evidence: SearchHit[];
  investigations: SearchHit[];
  relationships: SearchHit[];
  attackTechniques: SearchHit[];
  cves: SearchHit[];
  hits: SearchHit[];
  total: number;
  /** Entity-resolution hypothesis, when the query looks like a handle. */
  entity: { primaryActorId: string; confidence: number; label: string } | null;
}

const EMPTY: SearchResult = {
  query: '',
  actor: null,
  handles: [],
  pgp: [],
  wallets: [],
  infrastructure: [],
  sources: [],
  observations: [],
  evidence: [],
  investigations: [],
  relationships: [],
  attackTechniques: [],
  cves: [],
  hits: [],
  total: 0,
  entity: null,
};

function contains(value: string, needle: string): boolean {
  return value.toLowerCase().includes(needle);
}

function actorName(id: string): string {
  const actor = darkWebActorsById[id];
  return actor ? `${actor.id} — ${actor.aliases[0] ?? id}` : id;
}

/**
 * The live bridge publishes the base entity shape; attribution lives on the
 * central record's optional extension. Reads it without widening the type.
 */
function handleActorId(handle: { id: string }): string | null {
  return (darkWebHandlesById[handle.id] as { actorId?: string | null } | undefined)?.actorId ?? null;
}

/** Most probable threat actor for a free-text query, if any engine claims one. */
function resolveActorId(handleMatches: HandleMatch[]): string | null {
  const tally: Record<string, number> = {};
  for (const match of handleMatches) {
    if (match.actorId) tally[match.actorId] = (tally[match.actorId] ?? 0) + match.confidence;
  }
  const ids = Object.keys(tally);
  if (!ids.length) return null;
  return ids.reduce((best, id) => (tally[id] > tally[best] ? id : best));
}

function buildActorHit(query: string, handleMatches: HandleMatch[]): {
  hit: SearchHit | null;
  actorId: string | null;
} {
  const actorId = resolveActorId(handleMatches);
  const candidates = darkWebActors.filter(
    (actor) =>
      contains(actor.id, query) ||
      actor.aliases.some(alias => contains(alias, query)) ||
      actor.handles.some(handle => contains(handle, query)) ||
      actor.domains.some(domain => contains(domain, query)),
  );

  if (actorId) {
    const actor = darkWebActorsById[actorId];
    if (actor) {
      return {
        hit: {
          kind: 'ACTOR',
          id: actor.id,
          title: actor.aliases[0] ?? actor.id,
          subtitle: `${actor.id} · ${actor.status} · ${actor.activityLevel} activity`,
          detail: `${actor.handles.length} handles · ${actor.pgpFingerprints.length} PGP · ${actor.walletAddrs.length} wallets · ${actor.domains.length} domains`,
          confidence: actor.confidenceScore,
          path: `/app/darkweb/actors/${actor.id}`,
        },
        actorId,
      };
    }
  }

  if (candidates.length) {
    const actor = candidates[0];
    return {
      hit: {
        kind: 'ACTOR',
        id: actor.id,
        title: actor.aliases[0] ?? actor.id,
        subtitle: `${actor.id} · ${actor.status} · ${actor.activityLevel} activity`,
        detail: actor.primaryMotivation,
        confidence: actor.confidenceScore,
        path: `/app/darkweb/actors/${actor.id}`,
      },
      actorId: actor.id,
    };
  }

  return { hit: null, actorId: null };
}

function handleHits(query: string): SearchHit[] {
  const seen = new Set<string>();
  const hits: SearchHit[] = [];

  for (const match of correlateHandles(query)) {
    // Cross-platform artefacts the correlation engine synthesises (a PGP
    // fingerprint or wallet observed alongside the handle) are not handle
    // records, so they resolve to the module that owns them instead.
    if (match.matchType === 'SHARED_IDENTIFIER') continue;
    if (seen.has(match.handleId)) continue;
    if (!darkWebHandlesById[match.handleId]) continue;
    seen.add(match.handleId);
    hits.push({
      kind: 'HANDLE',
      id: match.handleId,
      title: match.value,
      subtitle: `${match.platform} · ${match.matchType.replace(/_/g, ' ')}`,
      detail: match.why,
      confidence: match.confidence,
      path: handlePath(match.handleId),
    });
  }

  if (!hits.length) {
    for (const handle of darkWebHandles) {
      if (!contains(handle.value, query) && !contains(handle.normalized, query)) continue;
      if (seen.has(handle.id)) continue;
      seen.add(handle.id);
      hits.push({
        kind: 'HANDLE',
        id: handle.id,
        title: handle.value,
        subtitle: `${handle.platform} · observed handle`,
        detail: `Normalized form "${handle.normalized}" · first seen ${handle.firstSeen} · last seen ${handle.lastSeen}`,
        confidence: handle.confidence,
        path: handlePath(handle.id),
      });
    }
  }

  // A handle the analyst recorded with no stored value match still belongs
  // in results when the id itself is what was typed.
  for (const handle of darkWebHandles) {
    if (seen.has(handle.id)) continue;
    if (!contains(handle.id, query)) continue;
    seen.add(handle.id);
    hits.push({
      kind: 'HANDLE',
      id: handle.id,
      title: handle.value,
      subtitle: `${handle.platform} · record ${handle.id}`,
      detail: handleActorId(handle) ? `Attributed to ${handleActorId(handle)}` : 'Unattributed handle record',
      confidence: handle.confidence,
      path: handlePath(handle.id),
    });
  }

  return hits;
}

function pgpHits(query: string): SearchHit[] {
  const hits: SearchHit[] = [];
  const seen = new Set<string>();

  for (const { key, actor } of searchPgp(query)) {
    if (seen.has(key.id)) continue;
    seen.add(key.id);
    hits.push({
      kind: 'PGP',
      id: key.id,
      title: key.fingerprint,
      subtitle: actor ? actorName(actor.id) : 'Unattributed PGP key',
      detail: key.actorIds.length
        ? `Linked to ${key.actorIds.join(', ')}`
        : 'No actor attribution in current dataset',
      confidence: key.confidence,
      path: pgpPath(key.id),
    });
  }

  for (const key of darkWebPgpKeys) {
    if (seen.has(key.id)) continue;
    if (!contains(key.fingerprint, query) && !contains(key.id, query)) continue;
    seen.add(key.id);
    hits.push({
      kind: 'PGP',
      id: key.id,
      title: key.fingerprint,
      subtitle: key.actorIds.length ? `Linked to ${key.actorIds.join(', ')}` : 'Unattributed',
      detail: `${key.id} · first seen ${key.firstSeen} · last seen ${key.lastSeen}`,
      confidence: key.actorIds.length ? key.confidence : Math.round(key.confidence * 0.7),
      path: pgpPath(key.id),
    });
  }

  return hits;
}

function walletHits(query: string): SearchHit[] {
  const seen = new Set<string>();
  const hits: SearchHit[] = [];

  for (const { wallet, actor } of searchWallet(query)) {
    if (seen.has(wallet.id)) continue;
    seen.add(wallet.id);
    hits.push({
      kind: 'WALLET',
      id: wallet.id,
      title: wallet.address,
      subtitle: actor ? actorName(actor.id) : 'Unattributed wallet',
      detail: wallet.actorIds.length
        ? `Linked to ${wallet.actorIds.join(', ')} · ${wallet.txCount} transactions`
        : `${wallet.txCount} transactions observed`,
      confidence: wallet.confidence,
      path: walletPath(wallet.id),
    });
  }

  for (const wallet of darkWebWallets) {
    if (seen.has(wallet.id)) continue;
    if (!contains(wallet.address, query) && !contains(wallet.id, query)) continue;
    seen.add(wallet.id);
    hits.push({
      kind: 'WALLET',
      id: wallet.id,
      title: wallet.address,
      subtitle: `${wallet.id} · ${wallet.txCount} transactions`,
      detail: wallet.actorIds.length ? `Linked to ${wallet.actorIds.join(', ')}` : 'Unattributed address',
      confidence: wallet.confidence,
      path: walletPath(wallet.id),
    });
  }

  return hits;
}

function infrastructureHits(query: string): SearchHit[] {
  const hits: SearchHit[] = [];
  const seen = new Set<string>();

  for (const { infra, actor } of searchInfrastructure(query)) {
    if (seen.has(infra.id)) continue;
    seen.add(infra.id);
    hits.push({
      kind: 'INFRASTRUCTURE',
      id: infra.id,
      title: infra.value,
      subtitle: `${infra.type} · ${actor ? actorName(actor.id) : 'unattributed'}`,
      detail: infra.actorIds.length
        ? `Shared by ${infra.actorIds.join(', ')}`
        : 'No shared actor attribution',
      confidence: actor?.confidenceScore ?? 60,
      path: '/app/darkweb/infrastructure',
    });
  }

  for (const infra of darkWebInfrastructure) {
    if (seen.has(infra.id)) continue;
    if (!contains(infra.value, query) && !contains(infra.asn ?? '', query)) continue;
    seen.add(infra.id);
    hits.push({
      kind: 'INFRASTRUCTURE',
      id: infra.id,
      title: infra.value,
      subtitle: `${infra.type} · partial match`,
      detail: `${infra.hostingProvider ?? 'Unknown host'} · ${infra.country ?? 'unknown'}`,
      confidence: 55,
      path: '/app/darkweb/infrastructure',
    });
  }

  return hits;
}

function sourceHits(query: string): SearchHit[] {
  return darkWebSources
    .filter((source) => contains(source.name, query) || contains(source.type, query) || contains(source.description, query))
    .map((source) => ({
      kind: 'SOURCE' as const,
      id: source.id,
      title: source.name,
      subtitle: `${source.type} · reliability R${source.reliabilityScore}`,
      detail: source.description,
      confidence: source.reliabilityScore,
      path: '/app/darkweb/sources',
    }));
}

function observationHits(query: string, actorId: string | null): SearchHit[] {
  return darkWebObservations
    .filter(
      (obs) =>
        contains(obs.id, query) ||
        contains(obs.content, query) ||
        contains(obs.source, query) ||
        contains(obs.observationType, query) ||
        obs.tags.some(tag => contains(tag, query)) ||
        (!!actorId && obs.actorId === actorId) ||
        (!!actorId && obs.handleId ? handleActorId({ id: obs.handleId }) === actorId : false),
    )
    .slice(0, 12)
    .map((obs) => ({
      kind: 'OBSERVATION' as const,
      id: obs.id,
      title: obs.id,
      subtitle: `${obs.observationType.replace(/_/g, ' ')} · ${obs.source}`,
      detail: obs.content.slice(0, 160),
      confidence: obs.confidence,
      path: observationPath(obs.id),
    }));
}

/** ATT&CK techniques resolve into the ATT&CK workspace, which owns the matrix. */
function attackTechniqueHits(query: string): SearchHit[] {
  return darkWebMitreTtps
    .filter(ttp =>
      contains(ttp.techniqueId, query) ||
      contains(ttp.name, query) ||
      contains(ttp.tactic, query) ||
      (ttp.subTechnique ? contains(ttp.subTechnique, query) : false) ||
      ttp.actorIds.some(id => contains(actorName(id), query)),
    )
    .slice(0, 12)
    .map(ttp => ({
      kind: 'ATTACK_TECHNIQUE' as const,
      id: ttp.techniqueId,
      title: `${ttp.techniqueId} — ${ttp.name}`,
      subtitle: `${ttp.tactic.replace(/_/g, ' ')} · ${ttp.actorIds.length} actor(s) · ${ttp.evidenceIds.length} evidence`,
      detail: ttp.description.slice(0, 160),
      confidence: ttp.confidence,
      path: `${ATTACK_PATH}?technique=${encodeURIComponent(ttp.techniqueId)}`,
    }));
}

/** CVEs have no dedicated page yet, so they open the ATT&CK workspace coverage view. */
function cveHits(query: string): SearchHit[] {
  return darkWebCves
    .filter(cve =>
      contains(cve.cveId, query) ||
      contains(cve.title, query) ||
      contains(cve.description, query) ||
      cve.cweIds.some(cwe => contains(cwe, query)) ||
      cve.affectedSoftware.some(product => contains(product, query)),
    )
    .slice(0, 12)
    .map(cve => ({
      kind: 'CVE' as const,
      id: cve.id,
      title: `${cve.cveId} — ${cve.title}`,
      subtitle: `${cve.severity} · CVSS ${cve.cvssScore} · ${cve.exploitationStatus.replace(/_/g, ' ')}`,
      detail: cve.description.slice(0, 160),
      confidence: cve.confidence,
      path: `${ATTACK_PATH}?cve=${encodeURIComponent(cve.cveId)}`,
    }));
}

function evidenceHits(query: string, actorId: string | null): SearchHit[] {
  return darkWebEvidence
    .filter(
      (item) =>
        contains(item.id, query) ||
        contains(item.source, query) ||
        contains(item.provenance, query) ||
        contains(item.evidenceType, query) ||
        (!!actorId && item.relatedActor === actorId),
    )
    .slice(0, 12)
    .map((item) => ({
      kind: 'EVIDENCE' as const,
      id: item.id,
      title: item.id,
      subtitle: `${item.evidenceType.replace(/_/g, ' ')} · ${item.source}`,
      detail: item.provenance,
      confidence: item.confidence,
      path: '/app/darkweb/evidence',
    }));
}

function investigationHits(query: string): SearchHit[] {
  return darkWebInvestigations
    .filter(
      (inv) =>
        contains(inv.id, query) ||
        contains(inv.title, query) ||
        contains(inv.description, query) ||
        contains(inv.analyst, query),
    )
    .map((inv) => ({
      kind: 'INVESTIGATION' as const,
      id: inv.id,
      title: inv.title,
      subtitle: `${inv.id} · ${inv.status} · ${inv.analyst}`,
      detail: inv.description,
      confidence: inv.confidence,
      path: `/app/darkweb/investigations/${inv.id}`,
    }));
}

function relationshipHits(query: string, actorId: string | null): SearchHit[] {
  return darkWebRelationships
    .filter(
      (rel) =>
        contains(rel.id, query) ||
        contains(rel.type, query) ||
        contains(rel.explanation, query) ||
        contains(rel.sourceEntity, query) ||
        contains(rel.targetEntity, query) ||
        (!!actorId && (rel.sourceEntity === actorId || rel.targetEntity === actorId)),
    )
    .map((rel) => ({
      kind: 'RELATIONSHIP' as const,
      id: rel.id,
      title: `${rel.sourceEntity} → ${rel.targetEntity}`,
      subtitle: rel.type.replace(/_/g, ' '),
      detail: rel.explanation,
      confidence: rel.confidence,
      path: `/app/darkweb/graph?seed=${encodeURIComponent(rel.sourceEntity)}`,
    }));
}

/**
 * Global dark-web intelligence search.
 *
 * Accepts a handle, alias, actor id, PGP fingerprint, wallet address,
 * domain, source name, evidence id or free text such as "shadowfox".
 */
export function globalSearch(rawQuery: string): SearchResult {
  const query = rawQuery.trim().toLowerCase();
  if (!query) return { ...EMPTY };

  const { hit: actor, actorId } = buildActorHit(query, correlateHandles(query));
  const handles = handleHits(query);
  const pgp = pgpHits(query);
  const wallets = walletHits(query);
  const infrastructure = infrastructureHits(query);
  const sources = sourceHits(query);
  const observations = observationHits(query, actorId);
  const evidence = evidenceHits(query, actorId);
  const investigations = investigationHits(query);
  const relationships = relationshipHits(query, actorId);
  const attackTechniques = attackTechniqueHits(query);
  const cves = cveHits(query);

  const hits: SearchHit[] = [
    ...(actor ? [actor] : []),
    ...handles,
    ...pgp,
    ...wallets,
    ...infrastructure,
    ...sources,
    ...observations,
    ...investigations,
    ...relationships,
    ...evidence,
    ...attackTechniques,
    ...cves,
  ].sort((a, b) => b.confidence - a.confidence);

  let entity: SearchResult['entity'] = null;
  try {
    const resolution = resolveEntity(query);
    if (resolution.primaryActorId) {
      entity = {
        primaryActorId: resolution.primaryActorId,
        confidence: resolution.confidence,
        label: resolution.label,
      };
    }
  } catch {
    entity = null;
  }

  return {
    query: rawQuery.trim(),
    actor,
    handles,
    pgp,
    wallets,
    infrastructure,
    sources,
    observations,
    evidence,
    investigations,
    relationships,
    attackTechniques,
    cves,
    hits,
    total: hits.length,
    entity,
  };
}
