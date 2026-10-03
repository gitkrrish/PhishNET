// ============================================================
// PhishNet — Correlation engine.
//
// Turns shared identifiers into *proposed* relationships with an
// explicit confidence and a recorded reason. It deliberately does
// NOT merge entities and does NOT treat a single weak signal as
// identity proof:
//
//   • A shared strong identifier (PGP, wallet) is a high-confidence
//     correlation, never a merge.
//   • A shared handle is only as strong as the platform context.
//   • Behavioural and stylometric similarity alone stays low and is
//     always reported as inference.
//
// Every correlation records its supporting signals, its
// counter-signals, and whether it is OBSERVED or INFERRED, so the
// UI can keep the three levels of certainty visibly separate.
// ============================================================
import {
  correlationsFor,
  listHandles,
  listInfrastructure,
  listPgp,
  listRelationships,
  listWallets,
  upsertCorrelation,
} from './repository.mjs';

/** Identifiers strong enough to carry a strong correlation on their own. */
const STRONG_METHODS = new Set(['SHARED_PGP', 'SHARED_WALLET']);

/**
 * Confidence contributed by one shared signal.
 * Kept explicit (rather than tuned) so the number is explainable.
 */
const SIGNAL_WEIGHT = {
  SHARED_PGP: 55,
  SHARED_WALLET: 50,
  SHARED_INFRASTRUCTURE: 40,
  SHARED_HANDLE: 30,
  OBSERVED_ON: 15,
  SHARED_BEHAVIOR: 12,
  SIMILAR_PERSONA: 10,
  TEMPORAL_OVERLAP: 8,
};

const MAX_SIGNAL_WEIGHT = 70;
const DECAY_PER_EXTRA_SIGNAL = 6;

/**
 * Corroboration rule: several independent weak signals together are
 * more meaningful than one strong signal alone, so extra signals
 * add a smaller, decaying amount rather than compounding blindly.
 */
function scoreFromSignals(signals, counterSignals) {
  const sorted = [...signals].sort((a, b) => (SIGNAL_WEIGHT[b] || 0) - (SIGNAL_WEIGHT[a] || 0));
  if (!sorted.length) return { confidence: 0, capped: false };

  let confidence = SIGNAL_WEIGHT[sorted[0]] || 0;
  for (const signal of sorted.slice(1)) {
    confidence += Math.max(2, (SIGNAL_WEIGHT[signal] || 0) - DECAY_PER_EXTRA_SIGNAL);
  }
  const capped = confidence > MAX_SIGNAL_WEIGHT;

  // Counter-signals (shared source, temporal gaps, explicit analyst doubt)
  // reduce confidence but can never silently delete the relationship.
  confidence -= counterSignals.length * 8;
  return { confidence: Math.max(5, Math.min(95, Math.round(confidence))), capped };
}

/** How the confidence should be labelled in the UI. */
export function confidenceBand(confidence) {
  if (confidence >= 80) return 'HIGH';
  if (confidence >= 60) return 'MEDIUM';
  if (confidence >= 35) return 'LOW';
  return 'WEAK';
}

/**
 * Build the shared-signal profile for one actor against every other
 * actor.
 *
 * Ownership is derived from the stored relationship edges rather than
 * from columns on the entity rows, so there is exactly one place that
 * says "this actor uses this handle".
 */
function sharedSignalsForActor(actorId, ownership, entities) {
  const { handles, wallets, pgp, infra } = entities;
  const actorHandles = ownership.handles.get(actorId) || new Set();
  const actorWallets = ownership.wallets.get(actorId) || new Set();
  const actorPgp = ownership.pgp.get(actorId) || new Set();
  const actorInfra = ownership.infra.get(actorId) || new Set();

  return (otherId) => {
    const signals = [];
    const counterSignals = [];
    const support = [];

    const otherHandles = ownership.handles.get(otherId) || new Set();
    const otherWallets = ownership.wallets.get(otherId) || new Set();
    const otherPgp = ownership.pgp.get(otherId) || new Set();
    const otherInfra = ownership.infra.get(otherId) || new Set();

    const overlapPgp = [...actorPgp].filter(id => otherPgp.has(id));
    if (overlapPgp.length) {
      signals.push('SHARED_PGP');
      support.push(`Shared PGP key: ${overlapPgp.join(', ')}`);
    }

    const overlapWallets = [...actorWallets].filter(id => otherWallets.has(id));
    if (overlapWallets.length) {
      signals.push('SHARED_WALLET');
      support.push(`Shared wallet: ${overlapWallets.join(', ')}`);
    }

    const overlapInfra = [...actorInfra].filter(id => otherInfra.has(id));
    if (overlapInfra.length) {
      signals.push('SHARED_INFRASTRUCTURE');
      support.push(`Shared infrastructure: ${overlapInfra.join(', ')}`);
    }

    // A handle shared across two actors is real, but the platform it was
    // seen on bounds how much it can prove.
    const sharedHandleIds = [...actorHandles].filter(id => otherHandles.has(id));
    if (sharedHandleIds.length) {
      signals.push('SHARED_HANDLE');
      const platforms = sharedHandleIds
        .map(id => handles.find(h => h.id === id)?.platform)
        .filter(Boolean);
      support.push(
        `Shared handle: ${sharedHandleIds.join(', ')}${platforms.length ? ` (${platforms.join(', ')})` : ''}`,
      );
      // Same handle on a single platform is weak evidence of shared control.
      if (platforms.length <= 1) counterSignals.push('Handle shared on a single platform only');
    }

    // Infrastructure reused by a large number of actors says little about
    // any one relationship.
    for (const infraId of overlapInfra) {
      let users = 0;
      for (const ids of ownership.infra.values()) {
        if (ids.has(infraId)) users += 1;
      }
      if (users > 3) {
        counterSignals.push(`Infrastructure ${infraId} is shared by ${users} actors`);
      }
    }

    return { signals, counterSignals, support };
  };
}

/**
 * Correlate every actor pair that shares at least one identifier and
 * persist the result as a scored, explained correlation record.
 *
 * Returns a summary so the caller can raise alerts and write audit
 * entries from the same pass.
 */
export function correlateActors() {
  const handles = listHandles();
  const pgp = listPgp();
  const infra = listInfrastructure();
  const relationships = listRelationships();

  // Ownership maps are derived from the stored edges, so "who uses this
  // handle" is answered in exactly one place.
  const ownership = { handles: new Map(), wallets: new Map(), pgp: new Map(), infra: new Map() };
  const addTo = (map, key, value) => {
    if (!key) return;
    if (!map.has(key)) map.set(key, new Set());
    map.get(key).add(value);
  };

  for (const relationship of relationships) {
    if (relationship.source_type !== 'ACTOR') continue;
    const owner = relationship.source_entity;
    switch (relationship.type) {
      case 'USES_HANDLE':
        addTo(ownership.handles, owner, relationship.target_entity);
        break;
      case 'SHARED_PGP':
        addTo(ownership.pgp, owner, relationship.target_entity);
        break;
      case 'SHARED_WALLET':
        addTo(ownership.wallets, owner, relationship.target_entity);
        break;
      case 'SHARED_INFRASTRUCTURE':
        addTo(ownership.infra, owner, relationship.target_entity);
        break;
      default:
        break;
    }
  }

  const actorIds = [...ownership.handles.keys(), ...ownership.wallets.keys(), ...ownership.pgp.keys(), ...ownership.infra.keys()]
    .filter((value, index, all) => all.indexOf(value) === index)
    .sort();

  const entities = { handles, wallets: [], pgp, infra };
  const created = [];
  const updated = [];

  for (let i = 0; i < actorIds.length; i += 1) {
    const left = actorIds[i];
    // Profile is built per left-hand actor, so ownership is always explicit.
    const leftProfile = sharedSignalsForActor(left, ownership, entities);
    for (let j = i + 1; j < actorIds.length; j += 1) {
      const right = actorIds[j];
      const view = leftProfile(right);
      if (!view.signals.length) continue;

      const { confidence, capped } = scoreFromSignals(view.signals, view.counterSignals);
      const derivation = view.signals.every(signal => STRONG_METHODS.has(signal)) ? 'OBSERVED' : 'INFERRED';

      const explanation = [
        `Linked by ${view.signals.join(' + ')}.`,
        `Supporting: ${view.support.join('; ')}.`,
        view.counterSignals.length
          ? `Counter-indicators: ${view.counterSignals.join('; ')}.`
          : 'No counter-indicators recorded.',
        capped ? 'Confidence capped: corroborating signals do not raise it further.' : '',
        `This is a correlation (${confidenceBand(confidence)} confidence), not a confirmed identity.`,
      ]
        .filter(Boolean)
        .join(' ');

      const result = upsertCorrelation({
        subjectId: left,
        objectId: right,
        method: view.signals[0],
        confidence,
        status: confidence >= 60 ? 'CORRELATED' : 'CANDIDATE',
        signals: view.signals,
        counterSignals: view.counterSignals,
        explanation,
        derivation,
      });

      if (result.created) created.push({ left, right, confidence, derivation, signals: view.signals });
      else updated.push({ left, right, confidence });
    }
  }

  return { created, updated, pairs: actorIds.length };
}

/** The stored reasoning behind one specific link, for "why linked?" views. */
export function whyLinked(entityId) {
  const correlations = correlationsFor(entityId);
  return correlations.map(row => ({
    id: row.id,
    other: row.subject_id === entityId ? row.object_id : row.subject_id,
    method: row.method,
    confidence: row.confidence,
    band: confidenceBand(row.confidence),
    status: row.status,
    signals: JSON.parse(row.signals || '[]'),
    counterSignals: JSON.parse(row.counter_signals || '[]'),
    explanation: row.explanation,
    createdAt: row.created_at,
  }));
}

export { scoreFromSignals };
