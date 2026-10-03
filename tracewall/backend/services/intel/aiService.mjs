// ============================================================
// PhishNet — AI Intelligence / AI Investigation backend.
//
// The intelligence pages previously answered questions entirely in the
// browser. This service moves that work behind the API so every answer is
// produced from the centralized records the rest of the platform uses,
// and so each AI action is auditable.
//
// The separation the platform requires is enforced structurally here: a
// response always has three buckets and never mixes them.
//
//   observed    — statements traceable to a specific stored record
//   derived     — computed from stored records by a documented rule
//                 (shared infrastructure, stylometric distance, counts)
//   inference   — model interpretation, produced only when a provider is
//                 configured, and labelled as such even when it is absent
//
// Nothing in this file invents an entity, a relationship or an event. If
// the records do not support an answer, the service says so.
// ============================================================
import { config } from '../../config/env.mjs';
import {
  correlationsFor,
  entityLabel,
  listActors,
  listAlerts,
  listEvidence,
  listHandles,
  listInfrastructure,
  listInvestigations,
  listObservations,
  listPgp,
  listRelationships,
  listSources,
  listTimeline,
  listWallets,
  relationshipsInvolving,
  resolveEntityRecord,
  getActor,
} from './repository.mjs';
import { httpError, requiredString } from '../../utils/validation.mjs';

const AI_TIMEOUT_MS = Number(process.env.AI_ANALYSIS_TIMEOUT_MS || 20000);

// ── Inference provider ─────────────────────────────────────────

/**
 * Ask the configured model to interpret supplied records.
 *
 * Returns a provider status rather than throwing: a missing or failing
 * provider degrades the `inference` bucket to an explicit "not produced"
 * and leaves `observed` and `derived` untouched and still useful.
 */
async function infer({ system, prompt }) {
  if (!config.groqApiKey) {
    return { available: false, provider: null, status: 'NOT CONFIGURED', note: 'No AI provider is configured, so no inference was produced. Everything above is derived from stored records.' };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), AI_TIMEOUT_MS);
  try {
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      signal: controller.signal,
      headers: { Authorization: `Bearer ${config.groqApiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'groq/compound-mini',
        messages: [{ role: 'system', content: system }, { role: 'user', content: prompt }],
        temperature: 0.1,
        max_tokens: 900,
      }),
    });
    if (response.status === 401 || response.status === 403) {
      return { available: false, provider: 'Llama3 (Groq)', status: 'FAILED', note: 'The AI provider rejected the configured key. No inference was produced.' };
    }
    if (response.status === 429) {
      return { available: false, provider: 'Llama3 (Groq)', status: 'RATE LIMITED', note: 'The AI provider is rate limited. No inference was produced.' };
    }
    if (!response.ok) {
      return { available: false, provider: 'Llama3 (Groq)', status: 'FAILED', note: `The AI provider returned ${response.status}. No inference was produced.` };
    }
    const payload = await response.json();
    const text = payload?.choices?.[0]?.message?.content;
    if (!text) return { available: false, provider: 'Llama3 (Groq)', status: 'EMPTY', note: 'The AI provider returned no content. No inference was produced.' };
    return { available: true, provider: 'Llama3 (Groq)', status: 'OK', summary: text.trim() };
  } catch (error) {
    const reason = error?.name === 'AbortError' ? 'timed out' : 'was unreachable';
    return { available: false, provider: 'Llama3 (Groq)', status: 'UNAVAILABLE', note: `The AI provider ${reason}. No inference was produced.` };
  } finally {
    clearTimeout(timer);
  }
}

const INFERENCE_SYSTEM = `You are a threat-intelligence analyst supporting an authorised defensive investigation.

RULES:
- Use ONLY the records provided in the prompt. Never add an indicator, actor, date or relationship that is not in them.
- Clearly separate what the records state from what you conclude.
- If the records are insufficient to answer, say so plainly instead of speculating.
- State uncertainty explicitly. Do not present a hypothesis as a finding.
- Do not provide offensive instructions.`;

// ── Observed-facts builders ────────────────────────────────────

/**
 * Ownership is derived from the stored relationship edges, which is how the
 * rest of the platform models it: there is no actor_id column on handles,
 * keys, wallets or infrastructure.
 */
function ownershipIndex() {
  const index = {
    actorHandles: new Map(), handleActors: new Map(),
    actorPgp: new Map(), actorWallets: new Map(), actorInfra: new Map(),
    actorRelated: new Map(),
  };
  const addTo = (map, key, value) => {
    if (!key) return;
    if (!map.has(key)) map.set(key, new Set());
    map.get(key).add(value);
  };
  for (const relationship of listRelationships()) {
    const sourceIsActor = relationship.source_type === 'ACTOR';
    const targetIsActor = relationship.target_type === 'ACTOR';
    if (sourceIsActor && targetIsActor) {
      addTo(index.actorRelated, relationship.source_entity, relationship.target_entity);
      addTo(index.actorRelated, relationship.target_entity, relationship.source_entity);
    } else if (sourceIsActor) {
      addTo(index.actorHandles, relationship.source_entity, relationship.target_entity);
      addTo(index.handleActors, relationship.target_entity, relationship.source_entity);
    } else if (targetIsActor) {
      addTo(index.actorHandles, relationship.target_entity, relationship.source_entity);
      addTo(index.handleActors, relationship.source_entity, relationship.target_entity);
    }
    if (relationship.type === 'SHARED_PGP') addTo(index.actorPgp, relationship.source_entity, relationship.target_entity);
    if (relationship.type === 'SHARED_WALLET') addTo(index.actorWallets, relationship.source_entity, relationship.target_entity);
    if (String(relationship.type).includes('INFRA')) {
      addTo(index.actorInfra, relationship.source_entity, relationship.target_entity);
      addTo(index.actorInfra, relationship.target_entity, relationship.source_entity);
    }
  }
  const listOf = (map, key) => [...(map.get(key) || [])];
  return {
    handlesOf: id => listOf(index.actorHandles, id),
    actorsOf: id => listOf(index.handleActors, id),
    pgpOf: id => listOf(index.actorPgp, id),
    walletsOf: id => listOf(index.actorWallets, id),
    infraOf: id => listOf(index.actorInfra, id),
    relatedActors: id => listOf(index.actorRelated, id),
  };
}

/** Every stored fact about an entity, each traceable to its record id. */
function observedFacts(entityType, entityId) {
  const facts = [];
  const push = (statement, source) => facts.push({ statement, sourceId: source });
  const owned = ownershipIndex();

  if (entityType === 'ACTOR') {
    const actor = getActor(entityId);
    if (!actor) return facts;
    push(`${actor.display_name} (${actor.id}) has status ${actor.status} and activity level ${actor.activity_level}.`, actor.id);
    push(`Confidence recorded as ${actor.confidence_score}.`, actor.id);
    if (actor.first_seen) push(`First seen ${actor.first_seen}; last seen ${actor.last_seen}.`, actor.id);

    for (const handleId of owned.handlesOf(actor.id)) {
      const handle = listHandles().find(item => item.id === handleId);
      if (handle) push(`Handle @${handle.value} on ${handle.platform}, first seen ${handle.first_seen}, confidence ${handle.confidence}.`, handle.id);
    }
    for (const keyId of owned.pgpOf(actor.id)) {
      const key = listPgp().find(item => item.id === keyId);
      if (key) push(`PGP key ${key.fingerprint} (confidence ${key.confidence}).`, key.id);
    }
    for (const walletId of owned.walletsOf(actor.id)) {
      const wallet = listWallets().find(item => item.id === walletId);
      if (wallet) push(`Wallet ${wallet.address} on ${wallet.network}, ${wallet.tx_count} transaction(s) observed.`, wallet.id);
    }
    for (const infraId of owned.infraOf(actor.id)) {
      const infra = listInfrastructure().find(item => item.id === infraId);
      if (infra) push(`Infrastructure ${infra.type} ${infra.value} (registrar ${infra.registrar ?? 'unrecorded'}).`, infra.id);
    }
    for (const evidence of listEvidence().filter(item => item.related_actor === actor.id)) {
      push(`Evidence ${evidence.evidence_type} from ${evidence.source_label ?? 'unrecorded source'}, reliability ${evidence.reliability}, hash ${evidence.hash ? 'present' : 'absent'}.`, evidence.id);
    }
    for (const relatedId of owned.relatedActors(actor.id)) {
      push(`Related actor recorded in the stored graph: ${relatedId}.`, relatedId);
    }
  } else {
    const record = resolveEntityRecord(entityType, entityId);
    if (record) {
      push(`${entityType} ${entityLabel(entityType, entityId)} exists with ${Object.keys(record).length} stored field(s).`, entityId);
      for (const [field, value] of Object.entries(record)) {
        if (value == null || value === '' || typeof value === 'object') continue;
        push(`${field}: ${String(value).slice(0, 200)}.`, entityId);
      }
      const owners = owned.actorsOf(entityId);
      if (owners.length) push(`Attributed by the stored graph to actor(s): ${owners.join(', ')}.`, entityId);
    }
  }

  return facts;
}

/** Documented rules that combine stored records into a derived statement. */
function derivedRelations(entityType, entityId) {
  const relations = relationshipsInvolving(entityId);
  return relations.map(relation => ({
    statement: `${relation.source_entity} —[${relation.type}]→ ${relation.target_entity} at confidence ${relation.confidence}.`,
    relationshipId: relation.id,
    evidenceIds: [],
  }));
}

/**
 * Stylometric and behavioural comparison between two stored actors.
 *
 * Both scores are cosine similarity over the normalized profiles stored on
 * the actor records, so they are derived values with a stated method rather
 * than an opaque score.
 */
export function stylometry(leftId, rightId) {
  const a = getActor(leftId);
  const b = getActor(rightId);
  if (!a) throw httpError(404, 'Actor not found');
  if (!b) throw httpError(404, 'Actor not found');

  const cosine = (x = {}, y = {}) => {
    const keys = [...new Set([...Object.keys(x), ...Object.keys(y)])];
    let dot = 0, magX = 0, magY = 0;
    for (const key of keys) {
      const vx = Number(x[key]) || 0, vy = Number(y[key]) || 0;
      dot += vx * vy; magX += vx * vx; magY += vy * vy;
    }
    const denominator = Math.sqrt(magX) * Math.sqrt(magY);
    return denominator ? Math.round((dot / denominator) * 100) : 0;
  };

  const stylometric = cosine(a.stylometric_profile, b.stylometric_profile);
  const behavioral = cosine(a.behavioral_profile, b.behavioral_profile);
  return {
    method: 'Cosine similarity over the normalized stylometric and behavioural profiles stored on each actor record.',
    left: { id: a.id, name: a.display_name },
    right: { id: b.id, name: b.display_name },
    stylometricSimilarity: stylometric,
    behavioralSimilarity: behavioral,
    // A combined score is a derived convenience value; both inputs are
    // reported alongside it so it can never stand in for the evidence.
    combinedScore: Math.round((stylometric + behavioral) / 2),
    interpretation: stylometric + behavioral === 0
      ? 'Both profiles are empty, so no similarity can be computed.'
      : 'High similarity is an indicator worth reviewing, not an identity determination.',
  };
}

/** Records that diverge from their own history — computed, not asserted. */
export function anomalies() {
  const found = [];
  const owned = ownershipIndex();
  for (const actor of listActors()) {
    if (actor.first_seen && actor.last_seen) {
      const first = new Date(actor.first_seen).getTime();
      const last = new Date(actor.last_seen).getTime();
      if (last < first) {
        found.push({ type: 'IMPOSSIBLE_SEQUENCE', entityId: actor.id, detail: `last_seen (${actor.last_seen}) precedes first_seen (${actor.first_seen})`, severity: 'HIGH' });
      }
    }
    // Platform breadth is computed from the handles the graph attributes.
    const platforms = new Set(owned.handlesOf(actor.id)
      .map(handleId => listHandles().find(item => item.id === handleId)?.platform)
      .filter(Boolean));
    if (platforms.size >= 5) {
      found.push({ type: 'PLATFORM_BREADTH', entityId: actor.id, detail: `attributed handles span ${platforms.size} distinct platforms`, severity: 'MEDIUM' });
    }
  }
  for (const alert of listAlerts()) {
    if (String(alert.severity).toUpperCase() === 'CRITICAL' && (alert.confidence ?? 0) < 70) {
      found.push({ type: 'CRITICAL_WITHOUT_CONFIDENCE', entityId: alert.id, detail: `CRITICAL severity at confidence ${alert.confidence}`, severity: 'HIGH' });
    }
  }
  for (const source of listSources()) {
    if (source.status !== 'ACTIVE' && source.health_status === 'ACTIVE') {
      found.push({ type: 'STATUS_HEALTH_MISMATCH', entityId: source.id, detail: `status ${source.status} but health ${source.health_status}`, severity: 'MEDIUM' });
    }
  }
  for (const relation of listRelationships()) {
    const first = new Date(relation.first_observed).getTime();
    const last = new Date(relation.last_observed).getTime();
    if (Number.isFinite(first) && Number.isFinite(last) && last < first) {
      found.push({ type: 'IMPOSSIBLE_RELATIONSHIP_SEQUENCE', entityId: relation.id, detail: `last_observed precedes first_observed`, severity: 'HIGH' });
    }
  }
  return found;
}

// ── Public API ─────────────────────────────────────────────────

/**
 * Answer a natural-language investigation question from stored records.
 *
 * Recognised intents are answered from the database. Anything else is
 * reported as not-answered with the records that were available, rather
 * than being free-associated by the model.
 */
export async function askInvestigation({ question, contextEntityId, enrich = true }) {
  const text = requiredString(question, 'question', 2000);
  const q = text.toLowerCase();

  const focus = contextEntityId && resolveEntityRecord('ACTOR', contextEntityId) ? contextEntityId : null;
  const entityIdsInQuestion = [
    ...listActors().map(a => a.id),
    ...listHandles().map(h => h.id),
    ...listWallets().map(w => w.id),
    ...listPgp().map(p => p.id),
    ...listInfrastructure().map(i => i.id),
  ].filter(id => text.toUpperCase().includes(String(id).toUpperCase()));

  const subjects = [...new Set([focus, ...entityIdsInQuestion].filter(Boolean))];
  const observed = [];
  const derived = [];

  if (subjects.length) {
    for (const id of subjects) {
      const type = resolveEntityRecord('ACTOR', id) ? 'ACTOR'
        : listHandles().some(h => h.id === id) ? 'HANDLE'
        : listWallets().some(w => w.id === id) ? 'WALLET'
        : listPgp().some(p => p.id === id) ? 'PGP'
        : listInfrastructure().some(i => i.id === id) ? 'INFRASTRUCTURE'
        : 'UNKNOWN';
      observed.push(...observedFacts(type, id));
      derived.push(...derivedRelations(type, id));
    }
  }

  // "Why are X and Y linked" — answered from the stored graph.
  const whyMatch = text.match(/why.*?([A-Z]+-[A-Z0-9-]+).*?([A-Z]+-[A-Z0-9-]+).*link/i)
    || text.match(/([A-Z]+-[A-Z0-9-]+).*?(?:and|with).*?([A-Z]+-[A-Z0-9-]+).*link/i);
  if (whyMatch) {
    const pair = [whyMatch[1], whyMatch[2]];
    const relation = listRelationships().find(r =>
      (pair.includes(r.source_entity) && pair.includes(r.target_entity)) ||
      (pair.includes(r.source_entity) && pair.includes(r.target_entity)));
    if (relation) {
      observed.push({ statement: `Relationship ${relation.id} connects ${relation.source_entity} to ${relation.target_entity} with type ${relation.type}.`, sourceId: relation.id });
      derived.push({ statement: `Stated basis: ${relation.explanation ?? 'not recorded'}.`, relationshipId: relation.id, evidenceIds: [] });
    } else {
      observed.push({ statement: `No stored relationship connects ${pair[0]} and ${pair[1]}.`, sourceId: null });
    }
  }

  if (/summar/.test(q)) {
    for (const investigation of listInvestigations().filter(i => subjects.includes(i.seed_actor_id) || subjects.includes(i.id))) {
      const events = listTimeline().filter(e => e.entity_id === investigation.id || e.actor_id === investigation.seed_actor_id);
      observed.push({ statement: `Investigation ${investigation.id} "${investigation.title}" is ${investigation.status} with ${events.length} related timeline event(s).`, sourceId: investigation.id });
    }
  }

  const counts = {
    actors: listActors().length,
    handles: listHandles().length,
    wallets: listWallets().length,
    pgpKeys: listPgp().length,
    infrastructure: listInfrastructure().length,
    relationships: listRelationships().length,
    evidence: listEvidence().length,
    alerts: listAlerts().length,
    observations: listObservations().length,
    sources: listSources().length,
  };

  const inference = enrich && (observed.length || derived.length)
    ? await infer({
      system: INFERENCE_SYSTEM,
      prompt: `Question: ${text}\n\nRECORDS AVAILABLE:\n${JSON.stringify({ observed, derived }, null, 2)}\n\nAnswer using only these records.`,
    })
    : { available: false, provider: null, status: 'NOT REQUESTED', note: 'Inference was not requested, so no model interpretation was produced.' };

  return {
    question: text,
    answered: observed.length > 0,
    answer: observed.length
      ? `${observed.length} stored fact(s) and ${derived.length} derived statement(s) relate to this question.`
      : 'No stored record matches this question. Nothing was inferred.',
    observed,
    derived,
    inference: {
      available: inference.available,
      provider: inference.provider ?? null,
      summary: inference.summary ?? null,
      status: inference.status ?? 'NOT CONFIGURED',
      note: inference.note ?? '',
    },
    datasetSize: counts,
    disclaimer: 'Observed facts come from stored records. Derived statements come from documented rules over those records. Inference is model interpretation and is labelled separately.',
  };
}

/** Investigation summary built from the investigation's own stored records. */
export async function investigationSummary({ investigationId, enrich = true }) {
  const investigation = listInvestigations().find(item => item.id === investigationId);
  if (!investigation) throw httpError(404, 'Investigation not found');

  const events = listTimeline().filter(event => event.actor_id === investigation.seed_actor_id);
  const evidence = listEvidence().filter(item => item.related_actor === investigation.seed_actor_id);
  const alerts = listAlerts().filter(item => item.actor_id === investigation.seed_actor_id);
  const correlations = correlationsFor(investigation.seed_actor_id);

  const observed = [
    { statement: `Investigation ${investigation.id} "${investigation.title}" is ${investigation.status} with recorded confidence ${investigation.confidence}.`, sourceId: investigation.id },
    { statement: `${events.length} timeline event(s) recorded for ${investigation.seed_actor_id}.`, sourceId: investigation.id },
    { statement: `${evidence.length} evidence item(s) linked to ${investigation.seed_actor_id}.`, sourceId: investigation.id },
    { statement: `${alerts.length} alert(s) raised for ${investigation.seed_actor_id}.`, sourceId: investigation.id },
  ];
  const derived = correlations.map(correlation => ({
    statement: `Correlation ${correlation.id}: ${correlation.method} at confidence ${correlation.confidence}.`,
    relationshipId: correlation.id,
    evidenceIds: [],
  }));

  const inference = enrich
    ? await infer({
      system: INFERENCE_SYSTEM,
      prompt: `Summarize this investigation from the records only.\n\n${JSON.stringify({ investigation, observed, derived }, null, 2)}`,
    })
    : { available: false, provider: null, status: 'NOT REQUESTED', note: 'Inference was not requested.' };

  return {
    investigationId,
    title: investigation.title,
    status: investigation.status,
    observed,
    derived,
    inference: {
      available: inference.available,
      provider: inference.provider ?? null,
      summary: inference.summary ?? null,
      status: inference.status ?? 'NOT CONFIGURED',
      note: inference.note ?? '',
    },
    disclaimer: 'Counts and statements are from stored records; the narrative summary is model interpretation and may be incomplete.',
  };
}

/** Extract entity references from free text against the centralized records. */
export function extractEntities({ text }) {
  const raw = requiredString(text, 'text', 20000);
  const upper = raw.toUpperCase();
  const found = [];
  const claim = (id, kind, label, matched) => found.push({ entityId: id, entityType: kind, label, matchedAs: matched });

  for (const actor of listActors()) {
    if (upper.includes(actor.id.toUpperCase())) claim(actor.id, 'ACTOR', actor.display_name, actor.id);
  }
  for (const handle of listHandles()) {
    if (raw.toLowerCase().includes(`@${handle.value}`.toLowerCase()) || upper.includes(handle.id.toUpperCase())) {
      claim(handle.id, 'HANDLE', `@${handle.value}`, handle.value);
    }
  }
  for (const wallet of listWallets()) {
    if (raw.toLowerCase().includes(wallet.address.toLowerCase())) claim(wallet.id, 'WALLET', wallet.address, wallet.address);
  }
  for (const key of listPgp()) {
    if (raw.toUpperCase().includes(key.fingerprint.toUpperCase())) claim(key.id, 'PGP_KEY', key.fingerprint, key.fingerprint);
  }
  for (const infra of listInfrastructure()) {
    if (raw.toLowerCase().includes(infra.value.toLowerCase())) claim(infra.id, 'INFRASTRUCTURE', infra.value, infra.value);
  }
  for (const cve of raw.match(/CVE-\d{4}-\d{4,7}/g) || []) {
    found.push({ entityId: cve, entityType: 'CVE', label: cve, matchedAs: cve, resolved: false });
  }

  return {
    text: raw,
    entities: found,
    resolved: found.filter(item => item.resolved !== false).length,
    unresolved: found.filter(item => item.resolved === false).length,
    note: 'Only identifiers that already exist in the centralized records were resolved. A CVE identifier is reported unresolved because no stored vulnerability record carries it.',
  };
}

export const aiCapabilities = () => ({
  aiProvider: config.groqApiKey ? 'Llama3 (Groq)' : null,
  aiProviderConfigured: Boolean(config.groqApiKey),
  analysis: ['investigation_question', 'investigation_summary', 'entity_extraction', 'stylometry', 'anomaly_detection'],
  buckets: ['observed', 'derived', 'inference'],
  note: 'Observed and derived results are always available from stored records. Inference requires a configured provider and is returned separately.',
});