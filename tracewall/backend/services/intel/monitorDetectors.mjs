// ============================================================
// PhishNet — Monitoring detectors.
//
// A detector answers one question: "has this condition fired for this
// target since the last check?" It reads only the centralized tables and
// returns the REAL records it matched, so every alert the monitoring
// layer raises cites evidence that actually exists in the platform.
//
// If nothing changed, a detector returns nothing. There is no fallback
// that manufactures a trigger, and no detector invents a record.
import {
  getActor,
  getHandle,
  getPgp,
  getWallet,
  getInfrastructure,
  getSource,
  getRelationship,
  handlesForActor,
  walletsForActor,
  pgpForActor,
  infrastructureForActor,
  relationshipsForActor,
  relationshipsInvolving,
  observationsForTarget,
  evidenceForTarget,
  observationsMatching,
  evidenceMatching,
  correlationsFor,
  listHandles,
  listInfrastructure,
  listWallets,
  listObservations,
  evidenceForRelationship,
} from './repository.mjs';
import { CONDITIONS, SEVERITY_RANK } from './monitoringRegistry.mjs';

const stamp = value => (value ? new Date(value).getTime() : 0);

/** Wall-clock instant a monitor's previous check ended. */
export function detectionWindow(monitor) {
  const since = monitor.last_check
    ? new Date(monitor.last_check).getTime()
    : new Date(monitor.created_at).getTime();
  return Number.isFinite(since) ? since : Date.now();
}

const fresh = (record, since, field = 'updated_at') => stamp(record[field]) > since;
const firstSeen = (record, since) => stamp(record.created_at) > since;
const seen = (record, since, field = 'last_seen') => stamp(record[field]) > since;

// ── ACTOR ────────────────────────────────────────────────────────────
function actorScope(actorId, since) {
  const handles = handlesForActor(actorId).filter(r => seen(r, since));
  const wallets = walletsForActor(actorId).filter(r => seen(r, since));
  const pgp = pgpForActor(actorId).filter(r => seen(r, since));
  const infra = infrastructureForActor(actorId).filter(r => seen(r, since));
  const relationships = relationshipsForActor(actorId).filter(r => fresh(r, since, 'last_observed') || firstSeen(r, since));
  const observations = observationsForTarget('ACTOR', actorId).filter(r => seen(r, since, 'observed_at'));
  const evidence = evidenceForTarget('ACTOR', actorId).filter(r => fresh(r, since, 'collected_at'));
  return { handles, wallets, pgp, infra, relationships, observations, evidence };
}

function detectActorConditions(actorId, targetType, conditions, since) {
  const hits = [];
  const scope = actorScope(actorId, since);
  const actor = getActor(actorId);
  const allHandles = handlesForActor(actorId);
  // A platform appearance is only new if the actor was not already on that
  // platform before this check window.
  const platformsBefore = new Set(
    allHandles.filter(h => !firstSeen(h, since)).map(h => h.platform).filter(Boolean),
  );
  const newHandles = allHandles.filter(h => firstSeen(h, since));
  const newPlatformHandles = newHandles.filter(h => h.platform && !platformsBefore.has(h.platform));

  const add = (key, matches, render) => {
    if (!conditions.includes(key) || !matches.length) return;
    hits.push({ condition: key, matches: matches.slice(0, 25).map(render), count: matches.length });
  };

  add('NEW_ACTIVITY', scope.observations, o => ({ id: o.id, type: o.observation_type, label: o.content.slice(0, 160), at: o.observed_at, sourceId: o.source_id }));
  add('NEW_HANDLE', newHandles, h => ({ id: h.id, label: `@${h.value} (${h.platform})`, at: h.first_seen, sourceId: h.source_id }));
  add('NEW_ALIAS', newHandles, h => ({ id: h.id, label: `@${h.value} (${h.platform})`, at: h.first_seen }));
  add('NEW_PLATFORM_APPEARANCE', newPlatformHandles, h => ({ id: h.id, label: `@${h.value} — ${h.platform} (platform not previously used)`, at: h.first_seen }));
  add('NEW_INFRASTRUCTURE', scope.infra, i => ({ id: i.id, label: `${i.value} (${i.type})`, at: i.first_seen }));
  add('NEW_RELATIONSHIP', scope.relationships, r => ({ id: r.id, label: `${r.source_entity} → ${r.target_entity} (${r.type})`, at: r.last_observed }));
  add('NEW_EVIDENCE', scope.evidence, e => ({ id: e.id, label: e.description || e.provenance, at: e.collected_at }));
  add('NEW_ATTACK_BEHAVIOR', scope.relationships.filter(r => r.type.includes('TTP') || r.type.includes('ATTACK')), r => ({ id: r.id, label: `${r.type} — ${r.explanation}`, at: r.last_observed }));
  add('ACTOR_STATUS_CHANGE', actor && fresh(actor, since) ? [actor] : [], a => ({ id: a.id, label: `${a.status} · activity ${a.activity_level}`, at: a.updated_at }));
  return hits;
}

// ── HANDLE / ALIAS ──────────────────────────────────────────────────
function detectHandleConditions(handleId, conditions, since) {
  const hits = [];
  const handle = getHandle(handleId);
  if (!handle) return hits;
  const appearances = observationsForTarget('HANDLE', handleId).filter(o => seen(o, since, 'observed_at'));
  const platforms = appearances.map(o => o.platform).filter(Boolean);
  const newPlatform = platforms.filter(p => p && p !== handle.platform);
  const correlations = correlationsFor(handleId).filter(c => firstSeen(c, since));

  const add = (key, matches, render) => {
    if (!conditions.includes(key) || !matches.length) return;
    hits.push({ condition: key, matches: matches.slice(0, 25).map(render), count: matches.length });
  };

  add('NEW_APPEARANCE', appearances, o => ({ id: o.id, label: o.content.slice(0, 160), at: o.observed_at, sourceId: o.source_id }));
  add('NEW_PLATFORM', newPlatform.length ? newPlatform.map(p => ({ platform: p })) : [], p => ({ label: p }));
  add('NEW_ACTOR_CORRELATION', correlations, c => ({ id: c.object_id, label: `${c.object_id} via ${c.method} @${c.confidence}%`, at: c.created_at }));
  add('HANDLE_STATUS_CHANGE', firstSeen(handle, since) || seen(handle, since) ? [handle] : [], h => ({ id: h.id, label: `${h.platform} · R${h.confidence}`, at: h.last_seen }));
  return hits;
}

// ── PGP ─────────────────────────────────────────────────────────────
function detectPgpConditions(keyId, conditions, since) {
  const hits = [];
  const key = getPgp(keyId);
  if (!key) return hits;
  const observations = observationsForTarget('PGP_KEY', keyId).filter(o => seen(o, since, 'observed_at'));
  const relationships = relationshipsInvolving(keyId).filter(r => firstSeen(r, since) || fresh(r, since, 'last_observed'));
  const evidence = evidenceForTarget('PGP_KEY', keyId).filter(e => fresh(e, since, 'collected_at'));
  const expiry = key.expires_at || key.expiry || null;
  const expired = expiry ? stamp(expiry) < Date.now() : false;
  const revoked = Boolean(key.revoked || key.revoked_at || key.revocation);

  const add = (keyName, matches, render) => {
    if (!conditions.includes(keyName) || !matches.length) return;
    hits.push({ condition: keyName, matches: matches.slice(0, 25).map(render), count: matches.length });
  };

  add('NEW_OBSERVATION', observations, o => ({ id: o.id, label: o.content.slice(0, 160), at: o.observed_at }));
  add('NEW_ASSOCIATION', relationships, r => ({ id: r.id, label: `${r.source_entity} → ${r.target_entity} (${r.type})`, at: r.last_observed }));
  add('NEW_IDENTITY_ASSOCIATION', relationships.filter(r => r.type.includes('IDENTITY') || r.type.includes('UID')), r => ({ id: r.id, label: `${r.type} — ${r.explanation}`, at: r.last_observed }));
  add('KEY_REVOCATION', revoked ? [{ id: key.id, revokedAt: key.revoked_at }] : [], k => ({ id: k.id, label: 'Key carries a revocation marker', at: k.revoked_at || key.updated_at }));
  add('KEY_EXPIRATION', expired ? [{ id: key.id, expiresAt: expiry }] : [], k => ({ id: k.id, label: `Key expired ${expiry}`, at: expiry }));
  if (!conditions.includes('NEW_OBSERVATION') && evidence.length && conditions.includes('NEW_SUPPORTING_EVIDENCE')) {
    hits.push({ condition: 'NEW_SUPPORTING_EVIDENCE', count: evidence.length, matches: evidence.map(e => ({ id: e.id, label: e.description || e.provenance, at: e.collected_at })) });
  }
  return hits;
}

// ── WALLET / CRYPTO ─────────────────────────────────────────────────
// A new wallet transaction is a fact only when the stored tx count grew.
function detectWalletConditions(walletId, conditions, since, options = {}) {
  const hits = [];
  const wallet = getWallet(walletId);
  if (!wallet) return hits;
  const previousTxCount = wallet.previous_tx_count ?? null;
  const txDelta = previousTxCount === null ? 0 : Math.max(0, (wallet.tx_count || 0) - previousTxCount);
  const walletChanged = previousTxCount !== null && (wallet.tx_count || 0) !== previousTxCount;
  const relationships = relationshipsInvolving(walletId);
  const newAssociations = relationships.filter(r => firstSeen(r, since) || fresh(r, since, 'last_observed'));
  const observations = observationsForTarget('WALLET', walletId).filter(o => seen(o, since, 'observed_at'));
  const txNotes = observations.filter(o => /transaction|incoming|outgoing|transfer/i.test(o.observation_type + ' ' + o.content));
  const spikeThreshold = Number(options.spikeThreshold ?? 5);
  const volume = txDelta;

  const add = (key, matches, render) => {
    if (!conditions.includes(key) || !matches.length) return;
    hits.push({ condition: key, matches: matches.slice(0, 25).map(render), count: matches.length });
  };

  add('NEW_TRANSACTION', walletChanged ? [{ delta: txDelta }] : [], v => ({ label: `${v.delta} new transaction(s) observed · stored tx count ${wallet.tx_count}`, at: wallet.last_seen }));
  add('INCOMING_ACTIVITY', txNotes.filter(o => /incoming|inbound|received|value in/i.test(`${o.observation_type} ${o.content}`)), o => ({ id: o.id, label: o.content.slice(0, 160), at: o.observed_at }));
  add('OUTGOING_ACTIVITY', txNotes.filter(o => /outgoing|outbound|sent|value out/i.test(`${o.observation_type} ${o.content}`)), o => ({ id: o.id, label: o.content.slice(0, 160), at: o.observed_at }));
  add('ACTIVITY_SPIKE', volume > spikeThreshold ? [{ volume }] : [], v => ({ label: `${v.volume} new transactions this cycle (spike threshold ${spikeThreshold})`, at: wallet.last_seen }));
  add('NEW_ASSOCIATED_WALLET', newAssociations.filter(r => r.type.includes('WALLET') || r.type.includes('CLUSTER')), r => ({ id: r.id, label: `${r.source_entity} → ${r.target_entity} (${r.type})`, at: r.last_observed }));
  add('SERVICE_ASSOCIATION', newAssociations.filter(r => r.type.includes('EXCHANGE') || r.type.includes('SERVICE')), r => ({ id: r.id, label: `${r.explanation || r.type}`, at: r.last_observed }));
  add('PRIVACY_SERVICE_INDICATOR', newAssociations.filter(r => /mixer|privacy|tumbler|zcash/i.test(`${r.type} ${r.explanation}`)), r => ({ id: r.id, label: `${r.explanation || r.type}`, at: r.last_observed }));
  add('BALANCE_CHANGE', walletChanged ? [wallet] : [], w => ({ id: w.id, label: `Transaction count ${previousTxCount} → ${w.tx_count} · last seen ${w.last_seen}`, at: w.last_seen }));
  return hits;
}

// ── INFRASTRUCTURE ──────────────────────────────────────────────────
function detectInfrastructureConditions(infraId, conditions, since) {
  const hits = [];
  const infra = getInfrastructure(infraId);
  if (!infra) return hits;
  const relationships = relationshipsInvolving(infraId);
  const newAssociations = relationships.filter(r => firstSeen(r, since) || fresh(r, since, 'last_observed'));
  const observations = observationsForTarget('INFRASTRUCTURE', infraId).filter(o => seen(o, since, 'observed_at'));
  const changed = fresh(infra, since);
  const has = field => Boolean(infra[field] && infra[`previous_${field}`] && infra[field] !== infra[`previous_${field}`]);

  const add = (key, matches, render) => {
    if (!conditions.includes(key) || !matches.length) return;
    hits.push({ condition: key, matches: matches.slice(0, 25).map(render), count: matches.length });
  };

  add('DOMAIN_CHANGE', changed && has('registrar') ? [infra] : [], i => ({ id: i.id, label: `Registrar ${i.previous_registrar} → ${i.registrar}`, at: i.updated_at }));
  add('IP_CHANGE', changed && has('value') ? [infra] : [], i => ({ id: i.id, label: `${i.previous_value} → ${i.value}`, at: i.updated_at }));
  add('DNS_CHANGE', observations.filter(o => /dns|nameserver|ns\b|resolve/i.test(o.observation_type + ' ' + o.content)), o => ({ id: o.id, label: o.content.slice(0, 160), at: o.observed_at }));
  add('CERTIFICATE_CHANGE', changed && has('tls_issuer') ? [infra] : [], i => ({ id: i.id, label: `Issuer ${i.previous_tls_issuer} → ${i.tls_issuer}`, at: i.updated_at }));
  add('ONION_AVAILABILITY_CHANGE', observations.filter(o => /onion|availability|reachable|timeout/i.test(o.observation_type + ' ' + o.content)), o => ({ id: o.id, label: o.content.slice(0, 160), at: o.observed_at }));
  add('NEW_INFRA_ASSOCIATION', newAssociations, r => ({ id: r.id, label: `${r.source_entity} → ${r.target_entity} (${r.type})`, at: r.last_observed }));
  add('MIRROR_DISCOVERY', newAssociations.filter(r => r.type.includes('MIRROR')), r => ({ id: r.id, label: `${r.explanation || r.type}`, at: r.last_observed }));
  return hits;
}

// ── SOURCE ──────────────────────────────────────────────────────────
function detectSourceConditions(sourceId, conditions, since) {
  const hits = [];
  const source = getSource(sourceId);
  if (!source) return hits;
  const observations = observationsForTarget('SOURCE', sourceId).filter(o => seen(o, since, 'observed_at'));
  const evidence = evidenceForTarget('SOURCE', sourceId).filter(e => fresh(e, since, 'collected_at'));
  const changed = fresh(source, since);
  const failure = [...observations, ...evidence].filter(item => /fail|error|timeout|unavailable|blocked/i.test(`${item.observation_type || item.evidence_type || ''} ${item.content || item.description || ''}`));

  const add = (key, matches, render) => {
    if (!conditions.includes(key) || !matches.length) return;
    hits.push({ condition: key, matches: matches.slice(0, 25).map(render), count: matches.length });
  };

  add('SOURCE_AVAILABILITY', changed ? [source] : [], s => ({ id: s.id, label: `${s.health_status} · ${s.status}`, at: s.updated_at }));
  add('SOURCE_STATUS_CHANGE', changed && (source.previous_status !== source.status || source.previous_health_status !== source.health_status) ? [source] : [], s => ({ id: s.id, label: `${s.previous_status ?? '—'} → ${s.status}`, at: s.updated_at }));
  add('COLLECTION_HEALTH', changed ? [source] : [], s => ({ id: s.id, label: `Reliability ${s.reliability_score} · activity ${s.activity_level}`, at: s.updated_at }));
  add('NEW_SOURCE_INTELLIGENCE', [...observations, ...evidence], item => ({ id: item.id, label: (item.content || item.description || '').slice(0, 160), at: item.observed_at || item.collected_at }));
  add('COLLECTION_FAILURE', failure, item => ({ id: item.id, label: (item.content || item.description || '').slice(0, 160), at: item.observed_at || item.collected_at }));
  return hits;
}

// ── RELATIONSHIP ────────────────────────────────────────────────────
function detectRelationshipConditions(relationshipId, conditions, since) {
  const hits = [];
  const relationship = getRelationship(relationshipId);
  if (!relationship) return hits;
  const evidence = evidenceForRelationship(relationshipId).filter(e => fresh(e, since, 'collected_at'));
  const changed = fresh(relationship, since, 'last_observed');
  const inactive = changed && stamp(relationship.last_observed) < since - 24 * 3600 * 1000;

  const add = (key, matches, render) => {
    if (!conditions.includes(key) || !matches.length) return;
    hits.push({ condition: key, matches: matches.slice(0, 25).map(render), count: matches.length });
  };

  add('RELATIONSHIP_CHANGE', changed ? [relationship] : [], r => ({ id: r.id, label: `${r.source_entity} → ${r.target_entity} (${r.type})`, at: r.last_observed }));
  add('CONFIDENCE_CHANGE', changed && relationship.previous_confidence !== undefined && relationship.previous_confidence !== relationship.confidence ? [relationship] : [], r => ({ id: r.id, label: `${r.previous_confidence}% → ${r.confidence}%`, at: r.updated_at }));
  add('NEW_SUPPORTING_EVIDENCE', evidence, e => ({ id: e.id, label: e.description || e.provenance, at: e.collected_at }));
  add('RELATIONSHIP_INACTIVE', inactive ? [relationship] : [], r => ({ id: r.id, label: `No observation since ${r.last_observed}`, at: r.last_observed }));
  return hits;
}

// ── TERM-BASED (CVE, keyword, product, org, ATT&CK) ────────────────
const EXPLOIT_PATTERN = /exploit|payload|rce|proof of concept|poc\b|weaponis/i;
const PRODUCT_PATTERN = /affected product|vendor|appliance|firmware|version/i;

function detectTermConditions(term, targetType, conditions, since) {
  const hits = [];
  if (!term) return hits;
  const observations = observationsMatching(term).filter(o => seen(o, since, 'observed_at'));
  const evidence = evidenceMatching(term).filter(e => fresh(e, since, 'collected_at'));
  const relatedRelationships = listObservations()
    .filter(o => o.observed_at && stamp(o.observed_at) > since)
    .flatMap(o => (o.actor_id ? relationshipsInvolving(o.actor_id) : []))
    .filter(r => firstSeen(r, since));

  const add = (key, matches, render) => {
    if (!conditions.includes(key) || !matches.length) return;
    hits.push({ condition: key, matches: matches.slice(0, 25).map(render), count: matches.length });
  };

  const describe = item => ({
    id: item.id,
    label: (item.content || item.description || item.provenance || '').slice(0, 160),
    at: item.observed_at || item.collected_at,
  });

  add('NEW_MATCHING_OBSERVATION', observations, describe);
  add('NEW_RELEVANT_OBSERVATION', observations, describe);
  add('NEW_OBSERVATION', observations, describe);
  add('NEW_MENTION', [...observations, ...evidence], describe);
  add('NEW_SOURCE_APPEARANCE', observations.filter(o => o.source_id), o => ({ id: o.id, label: `New appearance on source ${o.source_id}`, at: o.observed_at }));
  add('NEW_ACTOR_ASSOCIATION', relatedRelationships, r => ({ id: r.id, label: `${r.source_entity} → ${r.target_entity} (${r.type})`, at: r.last_observed }));
  add('NEW_TERM_INFRA_ASSOCIATION', relatedRelationships.filter(r => r.target_type === 'INFRASTRUCTURE'), r => ({ id: r.id, label: `${r.explanation || r.type}`, at: r.last_observed }));
  add('NEW_INFRA_ASSOCIATION', relatedRelationships.filter(r => r.target_type === 'INFRASTRUCTURE'), r => ({ id: r.id, label: `${r.explanation || r.type}`, at: r.last_observed }));
  add('NEW_ATTACK_BEHAVIOR', observations.filter(o => /ttp|technique|tactic|behaviou?r/i.test(`${o.observation_type} ${o.content}`)), describe);
  add('NEW_EXPLOIT_INTELLIGENCE', [...observations, ...evidence].filter(item => EXPLOIT_PATTERN.test(`${item.content || ''} ${item.description || ''}`)), describe);
  add('NEW_PRODUCT_REFERENCE', [...observations, ...evidence].filter(item => PRODUCT_PATTERN.test(`${item.content || ''} ${item.description || ''}`)), describe);
  return hits;
}

// ── Dispatch ────────────────────────────────────────────────────────

/**
 * Evaluate every configured condition for one target and return only the
 * conditions that genuinely fired, each carrying the records it matched.
 */
export function detectForTarget(targetType, targetId, conditions, since, options = {}) {
  const list = Array.isArray(conditions) ? conditions : [];
  switch (String(targetType).toUpperCase()) {
    case 'ACTOR':
    case 'PERSONA':
      return detectActorConditions(targetId, String(targetType).toUpperCase(), list, since);
    case 'HANDLE':
    case 'ALIAS':
      return detectHandleConditions(targetId, list, since);
    case 'PGP':
    case 'PGP_KEY':
      return detectPgpConditions(targetId, list, since);
    case 'WALLET':
      return detectWalletConditions(targetId, list, since, options);
    case 'INFRASTRUCTURE':
    case 'DOMAIN':
    case 'IP':
    case 'ONION':
      return detectInfrastructureConditions(targetId, list, since);
    case 'SOURCE':
    case 'FORUM':
    case 'MARKETPLACE':
    case 'CHANNEL':
      return detectSourceConditions(targetId, list, since);
    case 'RELATIONSHIP':
      return detectRelationshipConditions(targetId, list, since);
    case 'OBSERVATION':
    case 'EVIDENCE':
    case 'CVE':
    case 'VULNERABILITY':
    case 'KEYWORD':
    case 'ORGANIZATION':
    case 'PRODUCT':
    case 'ATTACK':
    case 'EMAIL':
    case 'URL':
    case 'FILE':
      return detectTermConditions(options.term ?? targetId, targetType, list, since);
    default:
      return [];
  }
}

/**
 * Severity for a trigger.
 *
 * The analyst's configured severity is a CEILING: a rule may never
 * escalate an alert past what the analyst authorised, which is what stops
 * an event being labelled Critical without supporting conditions. The
 * condition's own base severity then sets the level below that ceiling, so
 * an informational condition does not inherit a Critical setting, and weak
 * evidence is capped at Low regardless.
 */
export function resolveSeverity({ conditionKeys, configured, evidenceConfidence = 50 }) {
  const ceilingKey = String(configured || 'MEDIUM').toUpperCase();
  const ceiling = SEVERITY_RANK[ceilingKey] ?? SEVERITY_RANK.MEDIUM;
  let floor = SEVERITY_RANK.INFORMATIONAL;
  for (const key of conditionKeys) {
    const rank = SEVERITY_RANK[CONDITIONS[key]?.baseSeverity] ?? SEVERITY_RANK.INFORMATIONAL;
    if (rank > floor) floor = rank;
  }
  // Low-confidence evidence cannot present as a high-confidence alert.
  let rank = Math.min(ceiling, floor);
  if (evidenceConfidence < 40) rank = Math.min(rank, SEVERITY_RANK.LOW);
  // A condition whose base severity equals the ceiling means the analyst
  // explicitly authorised that level for this class of event.
  const found = Object.entries(SEVERITY_RANK).find(([, value]) => value === rank);
  return found ? found[0] : 'MEDIUM';
}

/**
 * Conditions whose matched records are observations rather than entity
 * records. An alert cites these as observation references.
 */
const OBSERVATION_CONDITIONS = new Set([
  'NEW_ACTIVITY', 'NEW_OBSERVATION', 'NEW_MATCHING_OBSERVATION', 'NEW_RELEVANT_OBSERVATION',
  'NEW_MENTION', 'NEW_SOURCE_APPEARANCE', 'NEW_EXPLOIT_INTELLIGENCE', 'NEW_PRODUCT_REFERENCE',
  'NEW_ATTACK_BEHAVIOR', 'INCOMING_ACTIVITY', 'OUTGOING_ACTIVITY', 'NEW_TRANSACTION',
]);

/** Flatten matches into the ids an alert should cite. */
export function collectEvidenceReferences(hits) {
  const observationIds = [];
  const entityRefs = [];
  for (const hit of hits) {
    for (const match of hit.matches) {
      if (!match?.id) continue;
      entityRefs.push(match.id);
      if (OBSERVATION_CONDITIONS.has(hit.condition)) observationIds.push(match.id);
    }
  }
  return { observationIds: [...new Set(observationIds)], entityRefs: [...new Set(entityRefs)] };
}

/** Source health decides whether a monitor can truthfully run right now. */
export function sourceAvailability(sources) {
  const rows = (sources || []).filter(Boolean);
  if (!rows.length) return { available: true, reason: 'No source bound — the monitor evaluates centralized intelligence only.', unavailable: [] };
  const unavailable = rows.filter(source => {
    const status = String(source.status || 'ACTIVE').toUpperCase();
    const health = String(source.health_status || 'ACTIVE').toUpperCase();
    return status !== 'ACTIVE' || health === 'DOWN' || health === 'DEGRADED' || health === 'OFFLINE';
  });
  return {
    available: unavailable.length === 0,
    reason: unavailable.length
      ? `${unavailable.length} bound source(s) are not healthy; the monitor reports their real status instead of claiming live collection.`
      : 'All bound sources are healthy.',
    unavailable: unavailable.map(s => ({ id: s.id, name: s.name, status: s.status, health: s.health_status })),
  };
}

export { CONDITIONS };