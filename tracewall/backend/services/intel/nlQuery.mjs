// ============================================================
// PhishNet — Natural language search over the central intelligence
// model (backend).
//
// A plain-language question is parsed into a list of *operations*
// against fields this platform actually stores, then executed against
// the normalized tables. Three rules govern the output:
//
//  1. Nothing is implied that was not applied. Every clause the
//     parser recognises becomes an operation with `applied: true` and
//     an executable filter, or it lands in `unsupported` with the
//     reason it cannot be honoured. The UI renders both, so a result
//     set never looks more specific than the question asked.
//
//  2. Every result is a real stored record. Each match cites the ids
//     and the field values that caused it, so the analyst can open the
//     underlying evidence or investigation and check the reasoning.
//
//  3. Findings are separated by how they were obtained: `observed`
//     (read straight off a stored field), `correlation` (a join across
//     stored records) and `inference` (analyst reasoning, always
//     labelled). No entity or evidence is invented, and "no records
//     matched" is reported as exactly that.
//
// Two scopes share this parser and executor: `investigations` (filter
// cases) and `intelligence` (answer a question about any record the
// analyst may read). The scope changes only what is returned, never
// what is filtered.
//
// Entity adjacency is read from `intel_relationship` — the same edges
// the relationship graph and the actor dossiers already use — rather
// than from denormalized columns, so there is one source of truth.
// ============================================================
import {
  listActors,
  listHandles,
  listPgp,
  listWallets,
  listInfrastructure,
  listEvidence,
  listRelationships,
  listInvestigations,
  listTimeline,
  listAlerts,
  evidenceForRelationship,
  investigationRefs,
  investigationsForEntity,
} from './repository.mjs';
import { listBlockedIndicators, listResponseLogs } from './protectionService.mjs';
import { evidenceIntegrityIndex } from './custodyService.mjs';

// ── Lexicon ───────────────────────────────────────────────────
// Each entry maps a recognised phrase onto one structured filter.
// Nothing outside this table is treated as a filter, which is what
// keeps the parser honest about what it can do.

const STATUS_WORDS = [
  [/\bopen\b|\bactive\b|\brunning\b|in[- ]progress|\bongoing\b/i, 'ACTIVE'],
  [/\bpending\b|\bqueued\b|\bawaiting\b|not started|\btodo\b/i, 'PENDING'],
  [/\bclosed\b|\bcomplete(d)?\b|\bfinished\b|\bdone\b|\bresolved\b/i, 'COMPLETED'],
];

const SEVERITY_WORDS = [
  [/\bcritical\b/i, 'CRITICAL'],
  [/\bhigh\b/i, 'HIGH'],
  [/\bmedium\b|\bmoderate\b/i, 'MEDIUM'],
  [/\blow\b/i, 'LOW'],
  [/\binfo\b|\binformational\b/i, 'INFO'],
];

const RECENCY_RE = /\b(last|past|recent|recently|within)\b/i;
const UNVERIFIED_WORDS = /unverified|not verified|unconfirmed|never verified|verification (?:has )?failed|integrity (?:check )?fail|without integrity/i;
const PENDING_ACTION_WORDS = /pending (?:response )?action|outstanding action|open response|response (?:ticket|action|log) (?:pending|open)|pending response/i;
const MALICIOUS_INFRA_WORDS = /malicious infrastructure|suspicious infrastructure|attacker infrastructure|hostile infrastructure|command and control|\bc2\b/i;
// The stored field this operation actually reads is "infrastructure used by
// more than one actor", so the trigger has to name that relationship rather
// than only the "malicious" phrasing. Asking for shared/both/common
// infrastructure, or for the infrastructure class as a whole, maps onto the
// same stored data.
const SHARED_INFRA_WORDS = /shared infrastructure|infrastructure shared|common infrastructure|shared hosting|shared (?:ip|address|domain|relay|server)|same infrastructure|infrastructure (?:shared|between|across)|both actors|more than one actor|multiple actors|several actors/i;
const INFRA_CLASS_WORDS = /\binfrastructures?\b|\bhosting\b|\brelays?\b|\bservers?\b/i;
const HIGH_RISK_WORDS = /high[- ]risk|highest risk|most dangerous|\bsevere\b/i;
const SUMMARIZE_WORDS = /summari[sz]e|summary|key findings|findings (?:for|associated)/i;
const EXPLAIN_WORDS = /explain why|why (?:is|are|was|were)\b.*\b(link|associat|connect)|how (?:is|are)\b.*\b(link|associat|connect)/i;
const CHANGE_WORDS = /recent changes?|what changed|changes? (?:in|to|associated)|latest changes?/i;
const RELATIONSHIP_WORDS = /relationship|connected|linked|association|relates? to|\bbetween\b/i;
const EVIDENCE_WORDS = /\bevidence\b|\bproof\b|arte?facts?/i;
const INDICATOR_WORDS = /indicators?|\bioc|\baddress\b|\bdomain\b|\bip\b|fingerprint|\bhandle\b/i;

const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
// Hostname with a plausible public TLD. Deliberately narrow: an ordinary
// word must never be read as a domain.
const DOMAIN = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:example|com|net|org|io|co|ru|cn|onion|info|biz|xyz|top|site|dev|app|me|uk|de)\b/gi;
const WALLET = /\b(?:bc1[a-z0-9]{20,}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b/g;
const HEX_FINGERPRINT = /\b(?:[0-9a-f]{8}[\s-]?){4,}[0-9a-f]{8}\b/gi;
const ENTITY_ID = /\b(?:ACTOR|HND|EVD|EVID|REL|INV|SRC|INF|WAL|PGP|TL|ANOM)-[A-Za-z0-9-]+\b/gi;

function lower(value) {
  return String(value ?? '').toLowerCase();
}

function parseJson(value, fallback) {
  try {
    const parsed = JSON.parse(value ?? '');
    return parsed ?? fallback;
  } catch {
    return fallback;
  }
}

function daysWindow(text) {
  const match = String(text).match(/(\d+)\s*(hour|day|week|month|year)/i);
  if (!match) return null;
  const factor = { hour: 1 / 24, day: 1, week: 7, month: 30, year: 365 }[match[2].toLowerCase()] ?? 1;
  return Number(match[1]) * factor;
}

/**
 * Which stored entity classes a question is asking to enumerate.
 *
 * Only fires when the question asks for a class ("all IP addresses",
 * "suspicious domains") rather than naming one record, so a bare word
 * can never widen a search the analyst did not ask to widen.
 */
function entityClassRequested(haystack) {
  const wanted = [];
  if (/\bips?\b|\bip addresses?\b/.test(haystack)) wanted.push('IP infrastructure');
  if (/\bdomains?\b/.test(haystack)) wanted.push('domains');
  if (/\bonion\b|\bsites?\b/.test(haystack)) wanted.push('onion services');
  if (/\bhandles?\b|\busernames?\b|\baliases?\b/.test(haystack)) wanted.push('handles');
  if (/\bwallets?\b|\bbitcoin addresses?\b|\bcrypto wallets?\b/.test(haystack)) wanted.push('wallets');
  if (/\bfingerprints?\b|\bpgp\b|\bkeys?\b/.test(haystack)) wanted.push('PGP keys');
  if (/\bactors?\b/.test(haystack)) wanted.push('threat actors');
  return wanted;
}

// ── Relationship-derived adjacency ────────────────────────────
// The normalized tables deliberately do not denormalize actor ids onto
// handles, wallets, keys or infrastructure: those links are edges in
// intel_relationship. Reading them from there keeps this service
// consistent with the graph and the actor dossier.

/** Canonical entity type for a relationship endpoint. */
function normalizeType(value) {
  const upper = String(value ?? '').toUpperCase();
  if (upper === 'ACTOR' || upper === 'ACTORS') return 'ACTOR';
  if (upper.startsWith('HANDLE')) return 'HANDLE';
  if (upper.startsWith('PGP')) return 'PGP';
  if (upper.startsWith('WALLET')) return 'WALLET';
  if (upper.startsWith('INFRA')) return 'INFRASTRUCTURE';
  if (upper.startsWith('EVID')) return 'EVIDENCE';
  return upper || 'UNKNOWN';
}

/**
 * entity id → its typed neighbours, from the stored relationship edges.
 *
 * Each entry records the *neighbour's* id and type, which is what
 * `neighboursOf` filters on: for the edge ACTOR-001 — WAL-001 the
 * index must yield, under `ACTOR-001`, an entry `{ id: 'WAL-001',
 * type: 'WALLET' }`.
 */
function buildAdjacency(relationships = listRelationships()) {
  const index = new Map();
  const attach = (fromId, toId, toType) => {
    const key = String(fromId).toUpperCase();
    if (!index.has(key)) index.set(key, []);
    index.get(key).push({ id: String(toId).toUpperCase(), type: toType });
  };
  for (const relationship of relationships) {
    const sourceType = normalizeType(relationship.source_type);
    const targetType = normalizeType(relationship.target_type);
    attach(relationship.source_entity, relationship.target_entity, targetType);
    attach(relationship.target_entity, relationship.source_entity, sourceType);
  }
  return index;
}

/** Typed neighbours of an entity. `type` may be a string or a list. */
function neighboursOf(adjacency, entityId, type) {
  const wanted = (Array.isArray(type) ? type : [type]).map(normalizeType);
  const edges = adjacency.get(String(entityId).toUpperCase()) ?? [];
  const seen = new Set();
  const out = [];
  for (const edge of edges) {
    if (!wanted.includes(edge.type)) continue;
    if (edge.id === String(entityId).toUpperCase()) continue;
    if (seen.has(edge.id)) continue;
    seen.add(edge.id);
    out.push(edge.id);
  }
  return out;
}

// ── Entity extraction ─────────────────────────────────────────

/**
 * Resolve every entity the question names. Free text (an alias, a
 * handle value, a domain) is resolved against the stored records
 * rather than assumed to be an id, and an id that does not exist is
 * reported as unresolved instead of being used as a filter.
 */
export function extractEntities(text) {
  const actors = listActors();
  const handles = listHandles();
  const wallets = listWallets();
  const pgp = listPgp();
  const infrastructure = listInfrastructure();
  const adjacency = buildAdjacency();

  const found = {
    actorIds: new Set(),
    handleIds: new Set(),
    handleValues: new Set(),
    walletIds: new Set(),
    walletAddresses: new Set(),
    pgpFingerprints: new Set(),
    infrastructureIds: new Set(),
    infrastructureValues: new Set(),
    evidenceIds: new Set(),
    relationshipIds: new Set(),
    investigationIds: new Set(),
    ipValues: new Set(),
    domainValues: new Set(),
    rawIds: new Set(),
  };

  for (const id of text.match(ENTITY_ID) ?? []) found.rawIds.add(id.toUpperCase());
  for (const ip of text.match(IPV4) ?? []) found.ipValues.add(ip);
  for (const domain of text.match(DOMAIN) ?? []) found.domainValues.add(domain.toLowerCase());
  for (const wallet of text.match(WALLET) ?? []) found.walletAddresses.add(wallet);
  for (const fp of text.match(HEX_FINGERPRINT) ?? []) found.pgpFingerprints.add(fp.replace(/[\s-]/g, '').toLowerCase());

  // Explicit ids, resolved against the real collections.
  for (const id of found.rawIds) {
    if (actors.some(a => a.id.toUpperCase() === id)) found.actorIds.add(id);
    if (handles.some(h => h.id.toUpperCase() === id)) found.handleIds.add(id);
    if (wallets.some(w => w.id.toUpperCase() === id)) found.walletIds.add(id);
    if (infrastructure.some(i => i.id.toUpperCase() === id)) found.infrastructureIds.add(id);
    if (listEvidence().some(e => e.id.toUpperCase() === id)) found.evidenceIds.add(id);
    if (listRelationships().some(r => r.id.toUpperCase() === id)) found.relationshipIds.add(id);
    if (listInvestigations().some(i => i.id.toUpperCase() === id)) found.investigationIds.add(id);
  }

  // Free-text resolution. A word only counts as an entity when it
  // equals a stored identifier exactly, so "the" or "actor" cannot be
  // mistaken for a record.
  const said = new Set(
    (text.toLowerCase().match(/[a-z0-9][a-z0-9._-]{2,}/g) ?? []).map(token => token.replace(/[.,]$/, '')),
  );
  const saidExactly = (value) => !!value && said.has(lower(value));
  const saidFingerprint = (value) => !!value && said.has(lower(String(value).replace(/[\s-]/g, '')));

  for (const actor of actors) {
    if (saidExactly(actor.id) || saidExactly(actor.display_name)) found.actorIds.add(actor.id);
  }
  for (const handle of handles) {
    if (saidExactly(handle.id) || saidExactly(handle.value) || saidExactly(handle.normalized)) {
      found.handleIds.add(handle.id);
      found.handleValues.add(handle.value);
      for (const actorId of neighboursOf(adjacency, handle.id, 'ACTOR')) found.actorIds.add(actorId);
    }
  }
  for (const wallet of wallets) {
    if (saidExactly(wallet.id) || saidExactly(wallet.address) || found.walletAddresses.has(wallet.address)) {
      found.walletIds.add(wallet.id);
      found.walletAddresses.add(wallet.address);
      for (const actorId of neighboursOf(adjacency, wallet.id, 'ACTOR')) found.actorIds.add(actorId);
    }
  }
  for (const key of pgp) {
    const bare = String(key.normalized ?? key.fingerprint ?? '').replace(/[\s-]/g, '');
    if (saidFingerprint(bare) || found.pgpFingerprints.has(lower(bare))) found.pgpFingerprints.add(lower(bare));
  }
  for (const infra of infrastructure) {
    const value = lower(infra.value);
    if (saidExactly(infra.id) || saidExactly(infra.value) || found.domainValues.has(value) || found.ipValues.has(infra.value)) {
      found.infrastructureIds.add(infra.id);
      found.infrastructureValues.add(infra.value);
      for (const actorId of neighboursOf(adjacency, infra.id, 'ACTOR')) found.actorIds.add(actorId);
    }
  }

  const unresolvedIds = [...found.rawIds].filter(
    id =>
      !found.actorIds.has(id) && !found.handleIds.has(id) && !found.walletIds.has(id) &&
      !found.infrastructureIds.has(id) && !found.evidenceIds.has(id) &&
      !found.relationshipIds.has(id) && !found.investigationIds.has(id),
  );

  return {
    actorIds: [...found.actorIds],
    handleIds: [...found.handleIds],
    handleValues: [...found.handleValues],
    walletIds: [...found.walletIds],
    walletAddresses: [...found.walletAddresses],
    pgpFingerprints: [...found.pgpFingerprints],
    infrastructureIds: [...found.infrastructureIds],
    infrastructureValues: [...found.infrastructureValues],
    evidenceIds: [...found.evidenceIds],
    relationshipIds: [...found.relationshipIds],
    investigationIds: [...found.investigationIds],
    ipValues: [...found.ipValues],
    domainValues: [...found.domainValues],
    unresolvedIds,
  };
}

// ── Planning ──────────────────────────────────────────────────

/**
 * Turn a question into an executable plan.
 *
 * `operations` are honoured and will filter. `unsupported` records
 * every recognised-but-not-honoured clause with the reason, so the
 * caller can show the limitation instead of hiding it.
 */
export function planNaturalLanguageQuery(text, scope = 'investigations') {
  const query = String(text ?? '').trim();
  const haystack = lower(query);
  const operations = [];
  const unsupported = [];

  if (!query) {
    return { query, scope, operations, unsupported: [{ clause: '(empty question)', reason: 'No question was supplied.' }], entities: extractEntities('') };
  }

  const entities = extractEntities(query);

  // Whether the question named anything resolvable. Needed both when
  // deciding to answer for a whole entity class and when deciding to
  // ask for clarification, so it is computed once, up front.
  const namesNoEntity =
    !entities.actorIds.length && !entities.handleIds.length && !entities.walletIds.length &&
    !entities.infrastructureIds.length && !entities.investigationIds.length && !entities.evidenceIds.length;

  // A phrase like "pending response actions" describes an action queue,
  // not an investigation status. Detect it first and mask it out, so
  // "pending" is never silently read as `status = PENDING`.
  const mentionsPendingAction = PENDING_ACTION_WORDS.test(haystack);
  const statusHaystack = mentionsPendingAction
    ? haystack.replace(/pending\s+(response\s+)?(action|actions|ticket|tickets|log|logs)/g, ' ')
    : haystack;

  // Status.
  const status = STATUS_WORDS.find(([pattern]) => pattern.test(statusHaystack))?.[1];
  if (status) operations.push({ kind: 'STATUS', label: `Status = ${status}`, value: status, applied: true });

  // Confidence threshold, then severity as the derived fallback.
  const confidenceMatch =
    haystack.match(/confidence (?:of |at |above |over |>= |greater than |higher than |minimum of |at least )?(\d{1,3})/) ||
    haystack.match(/(?:confidence|severity) (?:above|over|>=|at least|minimum) (\d{1,3})/);
  if (confidenceMatch) {
    operations.push({ kind: 'MIN_CONFIDENCE', label: `Confidence >= ${confidenceMatch[1]}`, value: Number(confidenceMatch[1]), applied: true });
  } else if (/\b(investigations?|cases?)\b/.test(haystack)) {
    const severity = SEVERITY_WORDS.find(([pattern]) => pattern.test(haystack))?.[1];
    // Severity is computed from stored alert severity plus stored
    // confidence, so the label says so rather than implying the field
    // exists on the investigation row.
    if (severity) operations.push({ kind: 'SEVERITY', label: `Derived severity = ${severity}`, value: severity, applied: true });
  }

  // Recency.
  if (RECENCY_RE.test(haystack) && /\b(investigations?|cases?|activit|recent)\b/.test(haystack)) {
    const days = daysWindow(haystack) ?? 30;
    operations.push({ kind: 'RECENT', label: `Activity within the last ${Math.round(days)} day(s)`, value: days, applied: true });
  }

  // Named entities.
  if (entities.actorIds.length) operations.push({ kind: 'ACTOR', label: `Threat actor: ${entities.actorIds.join(', ')}`, value: entities.actorIds, applied: true });
  if (entities.walletIds.length || entities.walletAddresses.length) {
    operations.push({ kind: 'WALLET', label: `Wallet: ${[...entities.walletIds, ...entities.walletAddresses].join(', ')}`, value: [...entities.walletIds, ...entities.walletAddresses], applied: true });
  }
  if (entities.handleIds.length) {
    operations.push({ kind: 'HANDLE', label: `Handle: ${entities.handleValues.join(', ') || entities.handleIds.join(', ')}`, value: entities.handleIds, applied: true });
  }
  const infraShown = [...entities.infrastructureIds, ...entities.infrastructureValues, ...entities.ipValues, ...entities.domainValues];
  if (infraShown.length) operations.push({ kind: 'INFRASTRUCTURE', label: `Infrastructure: ${infraShown.join(', ')}`, value: infraShown, applied: true });

// Conceptual filters.
if (MALICIOUS_INFRA_WORDS.test(haystack) || SHARED_INFRA_WORDS.test(haystack)) {
    operations.push({
      kind: 'INFRASTRUCTURE_SHARED',
      label: 'Infrastructure recorded against more than one actor',
      value: 'SHARED_INFRASTRUCTURE',
      applied: true,
    });
  } else if (INFRA_CLASS_WORDS.test(haystack) && !entities.infrastructureIds.length && !entities.infrastructureValues.length && !entities.ipValues.length && !entities.domainValues.length && scope === 'intelligence') {
    // A question about infrastructure as a class, with no specific value
    // named. Only offered in the whole-model scope, because the
    // investigation scope filters cases and an infrastructure class cannot
    // select one.
    operations.push({
      kind: 'INFRASTRUCTURE_SHARED',
      label: 'Infrastructure recorded against more than one actor',
      value: 'SHARED_INFRASTRUCTURE',
      applied: true,
    });
  }
  if (UNVERIFIED_WORDS.test(haystack)) operations.push({ kind: 'EVIDENCE_UNVERIFIED', label: 'Evidence without a successful integrity verification', value: true, applied: true });
  if (mentionsPendingAction) operations.push({ kind: 'PENDING_RESPONSE', label: 'Investigation with a pending response action', value: true, applied: true });
  if (HIGH_RISK_WORDS.test(haystack)) operations.push({ kind: 'HIGH_RISK', label: 'Evidence reliability >= 80', value: 80, applied: true });

  // Answer-shape intents — intelligence scope only.
  if (scope === 'intelligence') {
    if (SUMMARIZE_WORDS.test(haystack)) operations.push({ kind: 'SUMMARIZE', label: 'Summarize stored findings', value: true, applied: true });
    if (EXPLAIN_WORDS.test(haystack)) operations.push({ kind: 'EXPLAIN', label: 'Explain the recorded association', value: true, applied: true });
    if (CHANGE_WORDS.test(haystack)) operations.push({ kind: 'CHANGES', label: 'Recent recorded changes (timeline)', value: true, applied: true });
    if (RELATIONSHIP_WORDS.test(haystack)) operations.push({ kind: 'RELATIONSHIPS', label: 'Stored relationships', value: true, applied: true });
    if (EVIDENCE_WORDS.test(haystack)) operations.push({ kind: 'EVIDENCE_SET', label: 'Supporting evidence records', value: true, applied: true });
    if (INDICATOR_WORDS.test(haystack)) operations.push({ kind: 'INDICATORS', label: 'Indicators linked to the named entity', value: true, applied: true });

    // "Find suspicious IP addresses" / "show all domains": the analyst
    // asked for a whole class of indicator, not one entity. That is a
    // supported reading, so it is answered from the stored collection
    // rather than being reported as an empty result.
    const asksForClass = /\b(all|any|every|available|suspicious|known|recorded)\b.{0,40}\b(ip|ips|ip address|ip addresses|domain|domains|handle|handles|wallet|wallets|address|addresses|fingerprint|fingerprints|pgp|actor|actors|indicator|indicators)\b/i.test(haystack);
    if (asksForClass && namesNoEntity) {
      const wanted = entityClassRequested(haystack);
      if (wanted.length) {
        operations.push({
          kind: 'ENTITY_CLASS',
          label: `Every stored ${wanted.join(', ')} record`,
          value: wanted,
          applied: true,
        });
      }
    }
  }

  // Honest reporting of what could not be honoured.
  if (entities.unresolvedIds.length) {
    unsupported.push({
      clause: entities.unresolvedIds.join(', '),
      reason: 'These look like record ids but do not exist in the current dataset, so they were not used as a filter.',
    });
  }
  if (RECENCY_RE.test(haystack) && !operations.some(operation => operation.kind === 'RECENT')) {
    unsupported.push({ clause: 'recency', reason: 'A recency phrase was present but no activity window could be derived from it, so no recency filter was applied.' });
  }

  // A question that refers to an entity without naming one cannot be
  // resolved, and guessing would be worse than asking.
  if (namesNoEntity && /\b(this|these|that|those|the)\s+(entity|entities|handle|handles|wallet|wallets|actor|actors|domain|ip|address|indicator|indicators|case|investigation)s?\b/i.test(haystack)) {
    unsupported.push({
      clause: 'unnamed subject',
      reason:
        'The question refers to an entity without naming one, so there is nothing to resolve against the dataset. ' +
        'Name a threat actor, handle value, wallet address, IP address, domain or record id and the search will apply it.',
    });
  }
  if (namesNoEntity && scope === 'intelligence' && (byIntent('RELATIONSHIPS') || byIntent('EXPLAIN')) && !byIntent('INFRASTRUCTURE_SHARED')) {
    // Shared infrastructure is a stored relationship in its own right, so
    // asking for it without naming an endpoint is answerable. Only a
    // genuinely open-ended relationship question needs a subject named.
    unsupported.push({
      clause: 'relationship subject',
      reason:
        'Relationship questions are answered from stored edges, which need at least one endpoint. ' +
        'Name the handles, wallets, actors or infrastructure to relate.',
    });
  }

  if (!operations.length) {
    unsupported.push({
      clause: query,
      reason:
        'No filter could be derived from this question. Name a threat actor, wallet, handle, IP address, domain, investigation status, confidence threshold or a recency window (for example "last 30 days") and the search will apply it.',
    });
  }

  return { query, scope, operations, unsupported, entities };

  function byIntent(kind) {
    return operations.some(operation => operation.kind === kind);
  }
}

// ── Evidence integrity ────────────────────────────────────────
// `intel_evidence.integrity_status` is a value recorded at ingest. The
// authoritative signal for "has this actually been verified?" is the
// chain-of-custody verification counter, which only advances when a
// real digest comparison was performed.
//
// Read lazily and memoised per search: this module is imported before
// the store is opened, so nothing here may touch the database at load
// time.

let integrityCache = null;

function integrityState(item) {
  integrityCache ??= evidenceIntegrityIndex();
  return (
    integrityCache.get(item.id) ?? {
      verified: false,
      label: 'no verification record',
      reason: 'no chain-of-custody verification is recorded for this item',
    }
  );
}

function evidenceByIdSet(ids) {
  const wanted = new Set(ids.map(id => String(id).toUpperCase()));
  return listEvidence().filter(item => wanted.has(String(item.id).toUpperCase()));
}

// ── Execution ─────────────────────────────────────────────────

function investigationEntityIds(investigation) {
  const ids = new Set();
  if (investigation.seed_actor_id) ids.add(String(investigation.seed_actor_id).toUpperCase());
  for (const step of parseJson(investigation.steps, [])) {
    for (const id of step.evidenceIds ?? []) ids.add(String(id).toUpperCase());
    for (const id of step.relationshipIds ?? []) ids.add(String(id).toUpperCase());
    for (const id of step.actorIds ?? []) ids.add(String(id).toUpperCase());
  }
  return ids;
}

function investigationLinkedIds(investigationId) {
  return new Set(investigationRefs(investigationId).map(ref => String(ref.entity_id).toUpperCase()));
}

/** Latest activity for an investigation across every store it can touch. */
function latestActivity(investigation) {
  const entityIds = new Set([...investigationEntityIds(investigation), ...investigationLinkedIds(investigation.id)]);
  const stamps = [investigation.updated_at, investigation.created_at].filter(Boolean);
  for (const event of listTimeline()) {
    if (event.entity_id && entityIds.has(String(event.entity_id).toUpperCase())) stamps.push(event.occurred_at);
    if (event.actor_id && entityIds.has(String(event.actor_id).toUpperCase())) stamps.push(event.occurred_at);
  }
  for (const alert of listAlerts()) {
    if (alert.investigation_id === investigation.id) stamps.push(alert.raised_at);
    if (alert.entity_id && entityIds.has(String(alert.entity_id).toUpperCase())) stamps.push(alert.raised_at);
  }
  const values = stamps.map(stamp => new Date(stamp).getTime()).filter(value => !Number.isNaN(value));
  return values.length ? Math.max(...values) : 0;
}

/** Entities that still have an unresolved response action against them. */
function pendingResponseEntities() {
  const open = new Set();
  const logOpen = status => !status || ['OPEN', 'PENDING', 'IN_PROGRESS'].includes(String(status).toUpperCase());
  const actionOpen = status => !status || ['PENDING', 'QUEUED', 'REQUESTED'].includes(String(status).toUpperCase());
  for (const log of listResponseLogs()) {
    if (!logOpen(log.status)) continue;
    for (const action of log.actions ?? []) {
      if (actionOpen(action.status) && action.entityId) open.add(String(action.entityId).toUpperCase());
    }
  }
  return open;
}

/** Derived severity, from stored alert severity and stored confidence. */
function derivedSeverity(investigation, linkedIds) {
  const alertSeverities = listAlerts()
    .filter(alert => (alert.entity_id && linkedIds.has(String(alert.entity_id).toUpperCase())) || alert.investigation_id === investigation.id)
    .map(alert => String(alert.severity ?? '').toUpperCase())
    .filter(Boolean);
  const confidence = Number(investigation.confidence ?? 0);
  // The highest linked alert severity wins; stored confidence is only
  // consulted when the investigation has no linked alert.
  const highestSeverity = alertSeverities.length
    ? ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].find(level => alertSeverities.includes(level)) ?? 'INFO'
    : null;
  const severity = highestSeverity ?? (confidence >= 85 ? 'HIGH' : confidence >= 60 ? 'MEDIUM' : 'LOW');
  return { severity, alertCount: alertSeverities.length, highestSeverity: highestSeverity ?? 'none', confidence };
}

/** Run the plan against the investigation collection. */
function executeOnInvestigations(plan) {
  const relationships = listRelationships();
  const adjacency = buildAdjacency(relationships);
  const all = listInvestigations();
  const byKind = kind => plan.operations.find(operation => operation.kind === kind);
  const pendingEntities = byKind('PENDING_RESPONSE') ? pendingResponseEntities() : new Set();

  const actorsNeedingSharedInfra = (() => {
    if (!byKind('INFRASTRUCTURE_SHARED')) return null;
    const shared = new Map();
    for (const infra of listInfrastructure()) {
      const actorIds = neighboursOf(adjacency, infra.id, 'ACTOR');
      if (actorIds.length < 2) continue;
      shared.set(infra.id, { infra, actorIds });
    }
    return shared;
  })();

  const matches = [];
  for (const investigation of all) {
    const reasons = [];
    const linkedIds = new Set([...investigationEntityIds(investigation), ...investigationLinkedIds(investigation.id)]);
    const ownedEvidence = () => evidenceByIdSet([...linkedIds]);

    const statusOp = byKind('STATUS');
    if (statusOp) {
      if (String(investigation.status).toUpperCase() !== statusOp.value) continue;
      reasons.push({ field: 'status', matched: `stored status is ${investigation.status}`, kind: 'observed' });
    }

    const minConfidence = byKind('MIN_CONFIDENCE');
    if (minConfidence) {
      const confidence = Number(investigation.confidence ?? 0);
      if (confidence < minConfidence.value) continue;
      reasons.push({ field: 'confidence', matched: `stored confidence ${confidence} >= ${minConfidence.value}`, kind: 'observed' });
    }

    const severityOp = byKind('SEVERITY');
    if (severityOp) {
      const { severity, alertCount, confidence, highestSeverity } = derivedSeverity(investigation, linkedIds);
      if (severity !== severityOp.value) continue;
      reasons.push({
        field: 'severity',
        matched: `derived severity ${severity} from ${alertCount} linked alert(s) (highest ${highestSeverity}) and stored confidence ${confidence}`,
        kind: 'correlation',
      });
    }

    const actorOp = byKind('ACTOR');
    if (actorOp) {
      const hit = actorOp.value.filter(id => linkedIds.has(String(id).toUpperCase()));
      if (!hit.length) continue;
      reasons.push({ field: 'threatActor', matched: `references ${hit.join(', ')}`, kind: 'observed' });
    }

    const walletOp = byKind('WALLET');
    if (walletOp) {
      const rows = listWallets().filter(wallet => walletOp.value.some(value => lower(value) === lower(wallet.id) || lower(value) === lower(wallet.address)));
      const actorIds = new Set(rows.flatMap(wallet => neighboursOf(adjacency, wallet.id, 'ACTOR')));
      const hit = [...actorIds].filter(id => linkedIds.has(id));
      if (!hit.length) continue;
      reasons.push({ field: 'wallet', matched: `${rows.map(w => w.address).join(', ')} is linked to ${hit.join(', ')}`, kind: 'correlation' });
    }

    const handleOp = byKind('HANDLE');
    if (handleOp) {
      const rows = listHandles().filter(handle => handleOp.value.some(value => lower(value) === lower(handle.id) || lower(value) === lower(handle.value) || lower(value) === lower(handle.normalized)));
      const actorIds = new Set(rows.flatMap(handle => neighboursOf(adjacency, handle.id, 'ACTOR')));
      const hit = [...actorIds].filter(id => linkedIds.has(id));
      if (!hit.length) continue;
      reasons.push({ field: 'handle', matched: `${rows.map(h => `"${h.value}" (${h.platform})`).join(', ')} is linked to ${hit.join(', ')}`, kind: 'correlation' });
    }

    const infraOp = byKind('INFRASTRUCTURE');
    if (infraOp) {
      const rows = listInfrastructure().filter(infra => infraOp.value.some(value => lower(value) === lower(infra.id) || lower(value) === lower(infra.value)));
      const actorIds = new Set(rows.flatMap(infra => neighboursOf(adjacency, infra.id, 'ACTOR')));
      const hit = [...actorIds].filter(id => linkedIds.has(id));
      if (!hit.length) continue;
      reasons.push({ field: 'infrastructure', matched: `${rows.map(i => `${i.type} ${i.value}`).join(', ')} is linked to ${hit.join(', ')}`, kind: 'correlation' });
    }

    if (actorsNeedingSharedInfra) {
      const hit = [...actorsNeedingSharedInfra.entries()]
        .filter(([, entry]) => entry.actorIds.some(id => linkedIds.has(id)))
        .map(([, entry]) => entry);
      if (!hit.length) continue;
      const actorNames = [...new Set(hit.flatMap(entry => entry.actorIds.filter(id => linkedIds.has(id))))];
      reasons.push({
        field: 'infrastructure',
        matched: `shares infrastructure with ${actorNames.join(', ')}: ${hit.slice(0, 4).map(entry => entry.infra.value).join(', ')}`,
        kind: 'correlation',
      });
    }

    const evidenceOp = byKind('EVIDENCE');
    if (evidenceOp) {
      const hit = evidenceOp.value.filter(id => linkedIds.has(String(id).toUpperCase()));
      if (!hit.length) continue;
      reasons.push({ field: 'evidence', matched: `references evidence ${hit.join(', ')}`, kind: 'observed' });
    }

    const unverifiedOp = byKind('EVIDENCE_UNVERIFIED');
    if (unverifiedOp) {
      const owned = ownedEvidence();
      const failing = owned.filter(item => !integrityState(item).verified);
      if (!failing.length) continue;
      reasons.push({
        field: 'evidenceIntegrity',
        matched: `${failing.length} of ${owned.length} evidence item(s) unverified — ${failing.slice(0, 5).map(item => `${item.id} (${integrityState(item).label})`).join(', ')}${failing.length > 5 ? '…' : ''}`,
        kind: 'observed',
      });
    }

    const highRiskOp = byKind('HIGH_RISK');
    if (highRiskOp) {
      const owned = ownedEvidence().filter(item => Number(item.reliability ?? 0) >= highRiskOp.value);
      if (!owned.length) continue;
      reasons.push({
        field: 'evidenceReliability',
        matched: `${owned.length} evidence item(s) at reliability >= ${highRiskOp.value}: ${owned.slice(0, 5).map(item => item.id).join(', ')}${owned.length > 5 ? '…' : ''}`,
        kind: 'observed',
      });
    }

    const pendingOp = byKind('PENDING_RESPONSE');
    if (pendingOp) {
      const hit = [...linkedIds].filter(id => pendingEntities.has(id));
      if (!hit.length) continue;
      reasons.push({ field: 'responseActions', matched: `pending response action against ${hit.join(', ')}`, kind: 'correlation' });
    }

    const recentOp = byKind('RECENT');
    let latest = 0;
    if (recentOp) {
      latest = latestActivity(investigation);
      const cutoff = Date.now() - recentOp.value * 86400000;
      if (!latest || latest < cutoff) continue;
      reasons.push({ field: 'lastActivity', matched: `latest recorded activity ${new Date(latest).toISOString()} falls within the last ${Math.round(recentOp.value)} day(s)`, kind: 'observed' });
    } else {
      latest = latestActivity(investigation);
    }

    const owned = ownedEvidence();
    matches.push({
      id: investigation.id,
      title: investigation.title,
      status: investigation.status,
      analyst: investigation.analyst,
      confidence: Number(investigation.confidence ?? 0),
      updatedAt: investigation.updated_at,
      lastActivityAt: latest ? new Date(latest).toISOString() : null,
      evidenceCount: owned.length,
      unverifiedEvidenceCount: owned.filter(item => !integrityState(item).verified).length,
      entityCount: linkedIds.size,
      reasons,
      navigation: { investigationPath: `/app/darkweb/investigations/${investigation.id}` },
      sourceRecords: {
        investigationId: investigation.id,
        evidenceIds: owned.map(item => item.id),
        relationshipIds: [...linkedIds].filter(id => relationships.some(row => row.id.toUpperCase() === id)),
        actorIds: [...linkedIds].filter(id => listActors().some(actor => actor.id.toUpperCase() === id)),
      },
    });
  }

  return matches;
}

/** Run the plan across the whole intelligence model and answer the question. */
function executeOnIntelligence(plan) {
  const applied = plan.operations.some(operation => operation.applied);
  // Nothing was recognised in the question, so there is nothing to
  // answer. Returning the dataset here would dress an unparsed question
  // up as a successful lookup.
  if (!applied) {
    return { answerKind: 'NO_MATCH', observed: [], correlation: [], inference: [], total: 0, matchedInvestigations: [] };
  }

  const relationships = listRelationships();
  const adjacency = buildAdjacency(relationships);
  const entities = plan.entities;
  const byKind = kind => plan.operations.find(operation => operation.kind === kind);
  const observed = [];
  const correlation = [];
  const inference = [];

  const recordEvidence = (item, statement) =>
    observed.push({
      statement,
      sourceId: item.id,
      integrity: integrityState(item),
      navigation: { evidencePath: `/app/darkweb/evidence?actor=${item.related_actor ?? ''}` },
    });

  // ── Infrastructure used by more than one actor ──
  //
  // Answerable without naming an endpoint: the question "which
  // infrastructure is shared" reads the stored actor-to-infrastructure
  // edges directly. Each line is a join of two stored records, so it is
  // reported as a correlation rather than an observation.
  if (byKind('INFRASTRUCTURE_SHARED')) {
    const namedInfra = new Set(
      [...entities.infrastructureIds, ...entities.infrastructureValues, ...entities.ipValues, ...entities.domainValues]
        .map(value => String(value).toUpperCase()),
    );
    for (const infra of listInfrastructure()) {
      const actorIds = neighboursOf(adjacency, infra.id, 'ACTOR');
      if (actorIds.length < 2) continue;
      // When the question also named specific infrastructure, only those
      // records are in scope.
      if (namedInfra.size && !namedInfra.has(infra.id.toUpperCase()) && !namedInfra.has(String(infra.value).toUpperCase())) continue;
      const actorNames = actorIds.map(id => listActors().find(row => row.id.toUpperCase() === id)?.display_name ?? id);
      // Infrastructure records carry no confidence field, so the line states
      // the attributes that do exist rather than printing an empty one.
      const attributes = [
        infra.hosting_provider ? `hosted by ${infra.hosting_provider}` : null,
        infra.asn ? `on ${infra.asn}` : null,
        infra.country ? `registered in ${infra.country}` : null,
        infra.registrar ? `via ${infra.registrar}` : null,
        `first seen ${String(infra.first_seen ?? 'unknown').slice(0, 10)}`,
      ].filter(Boolean).join(', ');
      correlation.push({
        statement:
          `${infra.type} ${infra.value} is recorded against ${actorIds.length} threat actors (${actorIds.join(', ')}: ${actorNames.join(', ')})`
          + `${attributes ? `, ${attributes}` : ''}.`,
        sourceId: infra.id,
        navigation: { infrastructurePath: `/app/darkweb/infrastructure?seed=${infra.id}` },
      });
      for (const investigationId of investigationsForEntity(infra.id).map(ref => ref.investigation_id)) {
        const investigation = listInvestigations().find(row => row.id === investigationId);
        if (!investigation) continue;
        observed.push({
          statement: `Investigation ${investigation.id} "${investigation.title}" references ${infra.value}.`,
          sourceId: investigation.id,
          navigation: { investigationPath: `/app/darkweb/investigations/${investigation.id}` },
        });
      }
    }
  }

  // ── Indicators linked to the named entity ──
  if (byKind('ACTOR') || byKind('INDICATORS') || byKind('WALLET') || byKind('HANDLE') || byKind('INFRASTRUCTURE') || byKind('INFRASTRUCTURE_SHARED')) {
    for (const actorId of entities.actorIds) {
      const actor = listActors().find(row => row.id.toUpperCase() === actorId);
      if (!actor) continue;
      observed.push({
        statement: `${actor.id} (${actor.display_name}) is recorded with status ${actor.status}, activity ${actor.activity_level} and confidence ${actor.confidence_score}.`,
        sourceId: actor.id,
        navigation: { actorPath: `/app/darkweb/actors/${actor.id}` },
      });

      for (const handleId of neighboursOf(adjacency, actor.id, 'HANDLE')) {
        const handle = listHandles().find(row => row.id.toUpperCase() === handleId);
        if (!handle) continue;
        observed.push({
          statement: `Handle "${handle.value}" on ${handle.platform} is linked to ${actor.id} (confidence ${handle.confidence}, last seen ${handle.last_seen}).`,
          sourceId: handle.id,
          navigation: { handlePath: `/app/darkweb/handles/${handle.id}` },
        });
      }
      for (const walletId of neighboursOf(adjacency, actor.id, 'WALLET')) {
        const wallet = listWallets().find(row => row.id.toUpperCase() === walletId);
        if (!wallet) continue;
        observed.push({
          statement: `Wallet ${wallet.address}${wallet.network ? ` on ${wallet.network}` : ''} is linked to ${actor.id}; ${wallet.tx_count} recorded transaction(s), confidence ${wallet.confidence}.`,
          sourceId: wallet.id,
          navigation: { walletPath: `/app/darkweb/wallets/${wallet.id}` },
        });
      }
      for (const keyId of neighboursOf(adjacency, actor.id, 'PGP')) {
        const key = listPgp().find(row => row.id.toUpperCase() === keyId);
        if (!key) continue;
        observed.push({
          statement: `PGP key ${key.fingerprint} is linked to ${actor.id}; first seen ${key.first_seen}, last seen ${key.last_seen}.`,
          sourceId: key.id,
          navigation: { pgpPath: `/app/darkweb/pgp-keys/${key.id}` },
        });
      }
      for (const infraId of neighboursOf(adjacency, actor.id, 'INFRASTRUCTURE')) {
        const infra = listInfrastructure().find(row => row.id.toUpperCase() === infraId);
        if (!infra) continue;
        const sharedWith = neighboursOf(adjacency, infra.id, 'ACTOR').filter(id => id !== actor.id);
        observed.push({
          statement: `${infra.type} ${infra.value} is linked to ${actor.id}${infra.hosting_provider ? ` (hosted by ${infra.hosting_provider}${infra.asn ? `, ${infra.asn}` : ''})` : ''}${sharedWith.length ? ` and also to ${sharedWith.join(', ')}` : ''}.`,
          sourceId: infra.id,
          navigation: { infrastructurePath: `/app/darkweb/infrastructure?seed=${infra.id}` },
        });
      }
      for (const evidence of listEvidence().filter(row => String(row.related_actor ?? '').toUpperCase() === actor.id)) {
        recordEvidence(evidence, `Evidence ${evidence.id} (${evidence.evidence_type}) from ${evidence.source_label || evidence.source_id || 'unrecorded source'}: ${evidence.provenance}`);
      }
    }

    for (const infraId of entities.infrastructureIds) {
      const infra = listInfrastructure().find(row => row.id.toUpperCase() === infraId);
      if (!infra) continue;
      observed.push({
        statement: `Infrastructure ${infra.type} ${infra.value} is recorded first seen ${infra.first_seen}, last seen ${infra.last_seen}.`,
        sourceId: infra.id,
        navigation: { infrastructurePath: `/app/darkweb/infrastructure?seed=${infra.id}` },
      });
      for (const evidence of listEvidence().filter(row => String(row.related_infra ?? '').toUpperCase() === infraId)) {
        recordEvidence(evidence, `Evidence ${evidence.id} references ${infra.value}: ${evidence.provenance}`);
      }
      for (const investigationId of investigationsForEntity(infraId).map(ref => ref.investigation_id)) {
        const investigation = listInvestigations().find(row => row.id === investigationId);
        if (!investigation) continue;
        correlation.push({
          statement: `Investigation ${investigation.id} "${investigation.title}" references ${infra.value}.`,
          sourceId: investigation.id,
          navigation: { investigationPath: `/app/darkweb/investigations/${investigation.id}` },
        });
      }
    }

    for (const walletId of entities.walletIds) {
      const wallet = listWallets().find(row => row.id.toUpperCase() === walletId);
      if (!wallet) continue;
      observed.push({
        statement: `Wallet ${wallet.address}${wallet.network ? ` on ${wallet.network}` : ''} holds ${wallet.tx_count} recorded transaction(s); confidence ${wallet.confidence}.`,
        sourceId: wallet.id,
        navigation: { walletPath: `/app/darkweb/wallets/${wallet.id}` },
      });
    }
  }

  // ── Relationships and their recorded basis ──
  if (byKind('RELATIONSHIPS') || byKind('EXPLAIN') || entities.relationshipIds.length) {
    const focus = new Set([...entities.actorIds, ...entities.handleIds, ...entities.walletIds, ...entities.infrastructureIds]);
    const rows = relationships.filter(
      row => entities.relationshipIds.includes(row.id.toUpperCase()) || focus.has(String(row.source_entity).toUpperCase()) || focus.has(String(row.target_entity).toUpperCase()),
    );
    for (const relationship of rows.slice(0, 80)) {
      const bucket = String(relationship.derivation ?? '').toUpperCase() === 'OBSERVED' ? observed : correlation;
      bucket.push({
        statement: `${relationship.id}: ${relationship.source_entity} → ${relationship.target_entity} (${relationship.type}, confidence ${relationship.confidence}). Recorded basis: ${relationship.explanation || 'not recorded'}.`,
        sourceId: relationship.id,
        relationshipId: relationship.id,
        derivation: relationship.derivation,
        evidenceIds: evidenceForRelationship(relationship.id).map(item => item.id),
        navigation: { graphPath: `/app/darkweb/graph?seed=${relationship.source_entity}` },
      });
    }
  }

  // ── A whole entity class, when the question asked for one ──
  const classOp = byKind('ENTITY_CLASS');
  if (classOp) {
    const wanted = new Set(classOp.value);
    const noteShared = (id) => {
      const peers = neighboursOf(adjacency, id, 'ACTOR').filter(peer => peer !== id);
      return peers.length ? ` shared with ${peers.join(', ')}` : '';
    };

    if (wanted.has('IP infrastructure')) {
      for (const infra of listInfrastructure().filter(row => String(row.type).toUpperCase() === 'IP')) {
        observed.push({
          statement: `IP ${infra.value}${infra.hosting_provider ? ` hosted by ${infra.hosting_provider}` : ''}${infra.asn ? ` (${infra.asn})` : ''}${infra.country ? `, ${infra.country}` : ''} — first seen ${infra.first_seen}, last seen ${infra.last_seen}.${noteShared(infra.id)}`,
          sourceId: infra.id,
          navigation: { infrastructurePath: `/app/darkweb/infrastructure?seed=${infra.id}` },
        });
      }
    }
    if (wanted.has('domains') || wanted.has('onion services')) {
      for (const infra of listInfrastructure().filter(row => String(row.type).toUpperCase() === 'DOMAIN' || String(row.type).toUpperCase() === 'ONION_SERVICE')) {
        observed.push({
          statement: `${infra.type} ${infra.value}${infra.registrar ? ` registered via ${infra.registrar}` : ''} — first seen ${infra.first_seen}, last seen ${infra.last_seen}.${noteShared(infra.id)}`,
          sourceId: infra.id,
          navigation: { infrastructurePath: `/app/darkweb/infrastructure?seed=${infra.id}` },
        });
      }
    }
    if (wanted.has('handles')) {
      for (const handle of listHandles()) {
        observed.push({
          statement: `Handle "${handle.value}" on ${handle.platform}, confidence ${handle.confidence}, last seen ${handle.last_seen}.${noteShared(handle.id)}`,
          sourceId: handle.id,
          navigation: { handlePath: `/app/darkweb/handles/${handle.id}` },
        });
      }
    }
    if (wanted.has('wallets')) {
      for (const wallet of listWallets()) {
        observed.push({
          statement: `Wallet ${wallet.address}${wallet.network ? ` on ${wallet.network}` : ''} — ${wallet.tx_count} recorded transaction(s), confidence ${wallet.confidence}.${noteShared(wallet.id)}`,
          sourceId: wallet.id,
          navigation: { walletPath: `/app/darkweb/wallets/${wallet.id}` },
        });
      }
    }
    if (wanted.has('PGP keys')) {
      for (const key of listPgp()) {
        observed.push({
          statement: `PGP key ${key.fingerprint} — first seen ${key.first_seen}, last seen ${key.last_seen}, confidence ${key.confidence}.${noteShared(key.id)}`,
          sourceId: key.id,
          navigation: { pgpPath: `/app/darkweb/pgp-keys/${key.id}` },
        });
      }
    }
    if (wanted.has('threat actors')) {
      for (const actor of listActors()) {
        observed.push({
          statement: `${actor.id} (${actor.display_name}) — status ${actor.status}, activity ${actor.activity_level}, confidence ${actor.confidence_score}, last seen ${actor.last_seen}.`,
          sourceId: actor.id,
          navigation: { actorPath: `/app/darkweb/actors/${actor.id}` },
        });
      }
    }
  }

  // ── Recorded changes ──
  if (byKind('CHANGES')) {
    const focus = new Set([...entities.actorIds, ...entities.infrastructureIds, ...entities.handleIds]);
    const events = listTimeline()
      .filter(event => (focus.size === 0 ? true : focus.has(String(event.actor_id).toUpperCase()) || focus.has(String(event.entity_id).toUpperCase())))
      .slice(0, 50);
    for (const event of events) {
      observed.push({
        statement: `${event.occurred_at} — ${event.title} (${event.event_type}): ${event.description}`,
        sourceId: event.id,
        navigation: { timelinePath: '/app/darkweb/timeline' },
      });
    }
  }

  // ── Supporting evidence ──
  if (byKind('EVIDENCE_SET') || byKind('HIGH_RISK') || byKind('EVIDENCE_UNVERIFIED')) {
    const highRisk = byKind('HIGH_RISK');
    const unverified = byKind('EVIDENCE_UNVERIFIED');
    let pool = listEvidence();
    if (entities.actorIds.length) pool = pool.filter(item => entities.actorIds.includes(String(item.related_actor ?? '').toUpperCase()));
    if (highRisk) pool = pool.filter(item => Number(item.reliability ?? 0) >= highRisk.value);
    if (unverified) pool = pool.filter(item => !integrityState(item).verified);
    for (const item of pool.slice(0, 60)) {
      const state = integrityState(item);
      recordEvidence(
        item,
        `${item.id} (${item.evidence_type}) from ${item.source_label || item.source_id || 'unrecorded source'}: ${item.provenance} — reliability ${item.reliability}, integrity ${state.label} (${state.reason}).`,
      );
    }
  }

  // ── Summary of a named investigation ──
  let summaryInvestigations = [];
  if (byKind('SUMMARIZE')) {
    const targets = entities.investigationIds.length
      ? entities.investigationIds
      : listInvestigations().filter(investigation => entities.actorIds.includes(String(investigation.seed_actor_id).toUpperCase())).map(row => row.id);
    for (const investigationId of targets) {
      const investigation = listInvestigations().find(row => row.id === investigationId);
      if (!investigation) continue;
      const steps = parseJson(investigation.steps, []);
      observed.push({
        statement: `Investigation ${investigation.id} "${investigation.title}" is ${investigation.status}, owned by ${investigation.analyst}, stored confidence ${investigation.confidence}, last updated ${investigation.updated_at}.`,
        sourceId: investigation.id,
        navigation: { investigationPath: `/app/darkweb/investigations/${investigation.id}` },
      });
      for (const step of steps) {
        observed.push({
          statement: `Step ${step.step} — ${step.title}: ${step.description} (confidence ${step.confidence}).`,
          sourceId: investigation.id,
          evidenceIds: step.evidenceIds ?? [],
          relationshipIds: step.relationshipIds ?? [],
        });
      }
      const evidenceIds = [...new Set(steps.flatMap(step => step.evidenceIds ?? []))];
      const relationshipCount = new Set(steps.flatMap(step => step.relationshipIds ?? [])).size;
      correlation.push({
        statement: `${evidenceIds.length} distinct evidence item(s) and ${relationshipCount} relationship(s) support this investigation.`,
        sourceId: investigation.id,
      });
      summaryInvestigations = executeOnInvestigations({ ...plan, operations: plan.operations.filter(operation => operation.kind === 'SUMMARIZE') }).map(match => ({
        id: match.id,
        title: match.title,
        status: match.status,
        confidence: match.confidence,
        reasons: match.reasons,
        navigation: match.navigation,
      }));
    }
  }

  // ── Stored analyst decisions ──
  if (byKind('PENDING_RESPONSE')) {
    for (const blocked of listBlockedIndicators()) {
      observed.push({ statement: `Indicator ${blocked.value} (${blocked.entityType}) is blocked: ${blocked.reason} — recorded by ${blocked.blockedBy} at ${blocked.blockedAt}.`, sourceId: blocked.id });
    }
    for (const log of listResponseLogs().filter(row => !row.status || ['OPEN', 'PENDING', 'IN_PROGRESS'].includes(String(row.status).toUpperCase()))) {
      observed.push({ statement: `Response ticket ${log.id} "${log.title}" is ${log.status || 'OPEN'} with ${(log.actions ?? []).length} recorded action(s).`, sourceId: log.id });
    }
  }

  return {
    answerKind: byKind('SUMMARIZE') ? 'SUMMARY' : byKind('EXPLAIN') ? 'EXPLANATION' : 'ANSWER',
    observed,
    correlation,
    inference,
    total: observed.length + correlation.length + inference.length,
    matchedInvestigations: summaryInvestigations,
  };
}

const SCOPE_NOTE = {
  investigations:
    'Natural language search reads the stored investigation records and the entities they reference. Every filter listed as applied really filtered the result set; anything not applied is listed with the reason.',
  intelligence:
    'Answers are built only from records this analyst is authorized to read. Observed statements are read directly from stored fields, correlations are joins across stored records, and nothing is presented as an inference unless it is labelled as one.',
};

/** Public entry point. `scope` is `investigations` or `intelligence`. */
export function naturalLanguageSearch(text, { scope = 'investigations', limit = 50 } = {}) {
  // Fresh integrity state for every search: a verification performed a
  // moment ago must be visible to the next query.
  integrityCache = null;
  const plan = planNaturalLanguageQuery(text, scope);
  const capped = Math.min(Number(limit) || 50, 200);

  if (scope === 'intelligence') {
    const answer = executeOnIntelligence(plan);
    const applied = plan.operations.some(operation => operation.applied);
    return {
      query: plan.query,
      scope,
      operations: plan.operations,
      unsupported: plan.unsupported,
      entities: plan.entities,
      note: SCOPE_NOTE[scope],
      ...answer,
      // No language model is consulted by this endpoint, so nothing is
      // presented as an AI inference. The bucket stays empty and
      // `inferenceAvailable` says so, rather than being padded.
      inferenceAvailable: false,
      // Same rule as the investigation scope: with no recognised filter
      // the answer says so instead of dumping the dataset.
      unfiltered: !applied,
    };
  }

  const evaluated = listInvestigations().length;

  // With no filter applied there is no match to report. Returning the
  // whole population under `matches` would imply the question selected
  // those records when nothing was actually applied, so the population
  // is reported as a count and the caller is asked to rephrase.
  if (!plan.operations.some(operation => operation.applied)) {
    return {
      query: plan.query,
      scope,
      operations: plan.operations,
      unsupported: plan.unsupported,
      entities: plan.entities,
      note: SCOPE_NOTE[scope],
      evaluated,
      total: 0,
      matches: [],
      truncated: false,
      unfiltered: true,
    };
  }

  const matches = executeOnInvestigations(plan);
  return {
    query: plan.query,
    scope,
    operations: plan.operations,
    unsupported: plan.unsupported,
    entities: plan.entities,
    note: SCOPE_NOTE[scope],
    // The whole stored population, so "no matches" can be reported as
    // "no matches out of N stored investigations" rather than leaving
    // the analyst to guess whether the search ran at all.
    evaluated,
    total: matches.length,
    matches: matches.slice(0, capped),
    truncated: matches.length > capped,
    unfiltered: false,
  };
}