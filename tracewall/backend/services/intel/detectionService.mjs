// ============================================================
// PhishNet — Active Threat Detection engine (backend).
//
// Computes threat scores for every intelligence entity the backend
// holds, using the SAME signal weights as the client-side engine in
// src/lib/intelligence/protection.ts. Detection is a pure derivation
// over the normalized tables — it never invents intelligence.
//
// The extended ATT&CK / CVE / crypto / communication intelligence is
// frontend-only (kept in the local store), so the backend posture is
// computed over the entities it can see: actors, handles, PGP keys,
// wallets and infrastructure.
// ============================================================
import { buildDataset } from './query.mjs';
import { isEntityBlocked, listBlockedIndicators, listResponseLogs } from './protectionService.mjs';

const MOTIVATION_IMPACT = {
  RANSOMWARE: 10, DATA_THEFT: 10, FINANCIAL: 8, CREDENTIAL: 9,
  EXTORTION: 9, APT: 12, CYBERCRIME_SERVICE: 7, INFO_BROKER: 6,
};
const IMPACT_TACTICS = /* not persisted on backend */ null;

const ACTOR_STATUS_WEIGHT = { ACTIVE: 12, DORMANT: 4, SUSPENDED: 0 };
const ACTIVITY_WEIGHT = { HIGH: 6, MEDIUM: 3, LOW: 1 };
const TACTIC_WEIGHT = { EXFILTRATION: 6, IMPACT: 8, COLLECTION: 5, COMMAND_AND_CONTROL: 5, PRIVILEGE_ESCALATION: 4, CREDENTIAL_ACCESS: 6, INITIAL_ACCESS: 3, EXECUTION: 3, PERSISTENCE: 4, DEFENSE_EVASION: 3 };

function clamp(n, min = 0, max = 100) { return Math.max(min, Math.min(max, n)); }

function motivationWeight(motivation) {
  const lower = (motivation || '').toLowerCase();
  if (!lower) return 5;
  for (const [keyword, weight] of Object.entries(MOTIVATION_IMPACT)) {
    if (lower.includes(keyword.toLowerCase())) return weight;
  }
  return 5;
}

function riskLevelOf(score, active) {
  if (!active && score < 50) return 'INACTIVE';
  if (score >= 85) return 'CRITICAL';
  if (score >= 70) return 'HIGH';
  if (score >= 45) return 'MEDIUM';
  return 'LOW';
}

function buildScore(value, reasons, entityType, active) {
  const score = clamp(value, 0, 100);
  const riskLevel = riskLevelOf(score, active);
  return {
    value: score,
    riskLevel,
    reasons,
    recommendedAction: recommend(score, riskLevel, entityType, reasons).action,
    responsePriority: recommend(score, riskLevel, entityType, reasons).priority,
    computedAt: new Date().toISOString(),
  };
}

function recommend(score, level, entityType, reasons) {
  const topSignal = reasons.length ? [...reasons].sort((a, b) => b.weight - a.weight)[0] : null;
  if (level === 'CRITICAL' || level === 'HIGH') {
    if (entityType === 'HANDLE') return { action: 'BLOCK_HANDLE', priority: 'CRITICAL' };
    if (entityType === 'WALLET' || topSignal?.signal === 'WALLET_TRANSACTION_VOLUME') return { action: 'QUARANTINE_WALLET', priority: 'CRITICAL' };
    if (entityType === 'INFRASTRUCTURE') return { action: 'REVIEW_INFRASTRUCTURE', priority: 'HIGH' };
    if (entityType === 'PGP') return { action: 'MONITOR_ENTITY', priority: 'HIGH' };
    return { action: 'ESCALATE_REPORT', priority: level === 'CRITICAL' ? 'CRITICAL' : 'HIGH' };
  }
  if (level === 'MEDIUM') {
    return entityType === 'ACTOR' ? { action: 'ENRICH_TTP', priority: 'MEDIUM' } : { action: 'MONITOR_ENTITY', priority: 'MEDIUM' };
  }
  return { action: 'MONITOR_ENTITY', priority: 'INFORMATIONAL' };
}

const handleActivity = handle => {
  const spanMs = new Date(handle.lastSeen).getTime() - new Date(handle.firstSeen).getTime();
  const days = spanMs / (1000 * 60 * 60 * 24);
  if (days < 7) return 'HIGH';
  if (days < 60) return 'MEDIUM';
  return 'LOW';
};

function scoreActor(actor, dataset) {
  const reasons = [];
  let score = 0;
  const confContrib = clamp(Math.round((actor.confidenceScore / 100) * 30));
  if (confContrib > 0) {
    score += confContrib;
    reasons.push({ signal: 'CONFIDENCE', label: 'Attribution confidence', detail: `${actor.confidenceScore}% confidence in actor attribution`, weight: confContrib });
  }
  const statusW = ACTOR_STATUS_WEIGHT[actor.status] ?? 0;
  if (statusW > 0) {
    score += statusW;
    reasons.push({ signal: 'ACTIVE_STATUS', label: 'Active status', detail: `Actor is ${actor.status.toLowerCase()}`, weight: statusW });
  }
  const actW = ACTIVITY_WEIGHT[actor.activityLevel] ?? 0;
  if (actW > 0) {
    score += actW;
    reasons.push({ signal: 'ACTIVITY_LEVEL', label: 'Activity level', detail: `${actor.activityLevel.toLowerCase()} operational tempo`, weight: actW });
  }
  const motW = motivationWeight(actor.primaryMotivation);
  score += motW;
  reasons.push({ signal: 'BEHAVIORAL_PROFILE', label: 'Behavioral motivation', detail: `${actor.primaryMotivation || 'unknown'} motive profile`, weight: motW });

  // Persona migration churn
  const migrations = dataset.timeline.filter(t => t.actorId === actor.id && t.type === 'PERSONA_MIGRATION').length;
  if (migrations > 0) {
    const mW = clamp(migrations * 3);
    score += mW;
    reasons.push({ signal: 'PERSONA_MIGRATION', label: 'Persona migration churn', detail: `${migrations} persona migration(s)`, weight: mW });
  }

  // Shared PGP
  for (const fp of actor.pgpFingerprints) {
    const key = dataset.pgpKeys.find(k => k.fingerprint === fp || k.id === fp);
    if (key && key.actorIds.length > 1) {
      const w = 6;
      score += w;
      reasons.push({ signal: 'SHARED_PGP', label: 'Shared PGP identity', detail: `Fingerprint shared across ${key.actorIds.length} actors`, weight: w });
    }
  }
  // Shared wallets / infrastructure
  for (const wallet of dataset.wallets.filter(w => w.actorIds.includes(actor.id))) {
    if (wallet.actorIds.length > 1) {
      const w = 5;
      score += w;
      reasons.push({ signal: 'SHARED_WALLET', label: 'Shared wallet', detail: `Payment address shared across ${wallet.actorIds.length} actors`, weight: w });
    }
  }
  for (const infra of dataset.infrastructure.filter(i => i.actorIds.includes(actor.id))) {
    if (infra.actorIds.length > 1) {
      const w = 5;
      score += w;
      reasons.push({ signal: 'SHARED_INFRASTRUCTURE', label: 'Shared infrastructure', detail: `Infra ${infra.value} used by ${infra.actorIds.length} actors`, weight: w });
    }
  }

  // High-reliability evidence
  const evidence = dataset.evidence.filter(e => e.relatedActor === actor.id);
  const highRel = evidence.filter(e => e.reliability >= 85).length;
  if (highRel > 0) {
    const eW = clamp(highRel * 2);
    score += eW;
    reasons.push({ signal: 'EVIDENCE_RELIABILITY', label: 'High-reliability evidence', detail: `${highRel} evidence item(s) at R85+`, weight: eW });
  }

  // Open alerts
  const actorAlerts = dataset.alerts.filter(a => a.actorId === actor.id && (a.status === 'OPEN' || a.status === 'ACKNOWLEDGED'));
  if (actorAlerts.length > 0) {
    const w = clamp(actorAlerts.length * 4, 0, 12);
    score += w;
    reasons.push({ signal: 'MONITORING_ALERT', label: 'Active monitoring alerts', detail: `${actorAlerts.length} open/acknowledged alert(s)`, weight: w });
  }

  return buildScore(score, reasons, 'ACTOR', actor.status === 'ACTIVE');
}

function scoreHandle(handle, dataset) {
  const reasons = [];
  let score = 0;
  const confContrib = clamp(Math.round((handle.confidence / 100) * 25));
  if (confContrib > 0) {
    score += confContrib;
    reasons.push({ signal: 'CONFIDENCE', label: 'Handle confidence', detail: `${handle.confidence}% confidence`, weight: confContrib });
  }
  const activity = handleActivity(handle);
  const actW = ACTIVITY_WEIGHT[activity] ?? 3;
  score += actW;
  reasons.push({ signal: 'ACTIVITY_LEVEL', label: 'Recency of activity', detail: `Active on ${handle.platform} · ${activity.toLowerCase()}`, weight: actW });

  const transfers = dataset.timeline.filter(t => {
    const hay = `${t.title ?? ''} ${t.description ?? ''}`.toLowerCase();
    return t.actorId === handle.id || (handle.normalized && hay.includes(handle.normalized.toLowerCase()));
  }).length;
  if (transfers > 0) {
    const w = clamp(transfers * 3, 0, 9);
    score += w;
    reasons.push({ signal: 'PERSONA_MIGRATION', label: 'Identity reuse detected', detail: `${transfers} timeline event(s) linked to this handle`, weight: w });
  }

  const rels = dataset.relationships.filter(r => r.targetEntity === handle.id || r.sourceEntity === handle.id);
  const actorCount = new Set(rels.flatMap(r => [r.sourceEntity, r.targetEntity]).filter(id => dataset.lookups.actorsById[id])).size;
  if (actorCount > 1) {
    const w = clamp(actorCount * 4, 0, 12);
    score += w;
    reasons.push({ signal: 'SHARED_WALLET', label: 'Shared identity', detail: `Handle observed under ${actorCount} attributed actors`, weight: w });
  }

  const activeAlerts = dataset.alerts.filter(a => a.entityId === handle.id && (a.status === 'OPEN' || a.status === 'ACKNOWLEDGED')).length;
  if (activeAlerts > 0) {
    const w = clamp(activeAlerts * 5, 0, 10);
    score += w;
    reasons.push({ signal: 'MONITORING_ALERT', label: 'Monitoring alert', detail: `${activeAlerts} open alert(s)`, weight: w });
  }

  return buildScore(score, reasons, 'HANDLE', activity === 'HIGH');
}

function scorePgp(key, dataset) {
  const reasons = [];
  let score = 0;
  const confContrib = clamp(Math.round((key.confidence / 100) * 30));
  if (confContrib > 0) {
    score += confContrib;
    reasons.push({ signal: 'CONFIDENCE', label: 'PGP attribution confidence', detail: `${key.confidence}% confidence`, weight: confContrib });
  }
  if (key.actorIds.length > 1) {
    const w = clamp(key.actorIds.length * 5, 0, 12);
    score += w;
    reasons.push({ signal: 'SHARED_PGP', label: 'Shared PGP identity', detail: `Key shared across ${key.actorIds.length} actors`, weight: w });
  }
  const activeAlerts = dataset.alerts.filter(a => a.entityId === key.id && (a.status === 'OPEN' || a.status === 'ACKNOWLEDGED')).length;
  if (activeAlerts > 0) {
    const w = clamp(activeAlerts * 5, 0, 10);
    score += w;
    reasons.push({ signal: 'MONITORING_ALERT', label: 'Monitoring alert', detail: `${activeAlerts} open alert(s)`, weight: w });
  }
  const isActive = new Date(key.lastSeen).getTime() > Date.now() - 1000 * 60 * 60 * 24 * 90;
  return buildScore(score, reasons, 'PGP', isActive);
}

function scoreWallet(wallet, dataset) {
  const reasons = [];
  let score = 0;
  const confContrib = clamp(Math.round((wallet.confidence / 100) * 25));
  if (confContrib > 0) {
    score += confContrib;
    reasons.push({ signal: 'CONFIDENCE', label: 'Wallet attribution confidence', detail: `${wallet.confidence}% confidence`, weight: confContrib });
  }
  const txCount = wallet.txCount ?? 0;
  const txW = clamp(Math.log1p(txCount) * 4, 0, 12);
  if (txW > 0) {
    score += txW;
    reasons.push({ signal: 'WALLET_TRANSACTION_VOLUME', label: 'Transaction volume', detail: `${txCount} on-chain transaction(s)`, weight: txW });
  }
  if (wallet.actorIds.length > 1) {
    const w = clamp(wallet.actorIds.length * 5, 0, 12);
    score += w;
    reasons.push({ signal: 'SHARED_WALLET', label: 'Shared payment address', detail: `Linked to ${wallet.actorIds.length} actors`, weight: w });
  }
  const activeAlerts = dataset.alerts.filter(a => a.entityId === wallet.id && (a.status === 'OPEN' || a.status === 'ACKNOWLEDGED')).length;
  if (activeAlerts > 0) {
    const w = clamp(activeAlerts * 5, 0, 10);
    score += w;
    reasons.push({ signal: 'MONITORING_ALERT', label: 'Monitoring alert', detail: `${activeAlerts} open alert(s)`, weight: w });
  }
  const isActive = txCount > 0 && new Date(wallet.lastSeen).getTime() > Date.now() - 1000 * 60 * 60 * 24 * 90;
  return buildScore(score, reasons, 'WALLET', isActive);
}

function scoreInfrastructure(infra, dataset) {
  const reasons = [];
  let score = 0;
  const sharedActors = infra.actorIds.length;
  if (sharedActors > 1) {
    const w = clamp(sharedActors * 4, 0, 12);
    score += w;
    reasons.push({ signal: 'SHARED_INFRASTRUCTURE', label: 'Shared infrastructure', detail: `Used by ${sharedActors} actors`, weight: w });
  }
  if (infra.type === 'DOMAIN' && /(\.onion|\.i2p)/i.test(infra.value)) {
    score += 10;
    reasons.push({ signal: 'SHARED_INFRASTRUCTURE', label: 'Onion / anonymous hosting', detail: `${infra.value} is an anonymous network address`, weight: 10 });
  }
  if (infra.tlsIssuer) {
    const sameIssuer = dataset.infrastructure.filter(i => i !== infra && i.tlsIssuer && i.tlsIssuer === infra.tlsIssuer).length;
    if (sameIssuer > 0) {
      const w = clamp(sameIssuer * 3, 0, 9);
      score += w;
      reasons.push({ signal: 'SHARED_INFRASTRUCTURE', label: 'Shared TLS issuer', detail: `${sameIssuer} other indicator(s) share TLS issuer "${infra.tlsIssuer}"`, weight: w });
    }
  }
  const activeAlerts = dataset.alerts.filter(a => a.entityId === infra.id && (a.status === 'OPEN' || a.status === 'ACKNOWLEDGED')).length;
  if (activeAlerts > 0) {
    const w = clamp(activeAlerts * 4, 0, 8);
    score += w;
    reasons.push({ signal: 'MONITORING_ALERT', label: 'Monitoring alert', detail: `${activeAlerts} open alert(s)`, weight: w });
  }
  const isActive = new Date(infra.lastSeen).getTime() > Date.now() - 1000 * 60 * 60 * 24 * 90;
  return buildScore(score, reasons, 'INFRASTRUCTURE', isActive);
}

const SCORERS = {
  ACTOR: (a, d) => scoreActor(a, d),
  HANDLE: (h, d) => scoreHandle(h, d),
  PGP: (k, d) => scorePgp(k, d),
  WALLET: (w, d) => scoreWallet(w, d),
  INFRASTRUCTURE: (i, d) => scoreInfrastructure(i, d),
};

export function computeEntityScore(entityType, entityId) {
  const dataset = buildDataset();
  const scorer = SCORERS[entityType];
  if (!scorer) return null;
  switch (entityType) {
    case 'ACTOR': {
      const entity = dataset.lookups.actorsById[entityId];
      return entity ? scorer(entity, dataset) : null;
    }
    case 'HANDLE': {
      const entity = dataset.lookups.handlesById[entityId];
      return entity ? scorer(entity, dataset) : null;
    }
    case 'PGP': {
      const entity = dataset.lookups.pgpById[entityId];
      return entity ? scorer(entity, dataset) : null;
    }
    case 'WALLET': {
      const entity = dataset.lookups.walletsById[entityId];
      return entity ? scorer(entity, dataset) : null;
    }
    case 'INFRASTRUCTURE': {
      const entity = dataset.lookups.infraById[entityId];
      return entity ? scorer(entity, dataset) : null;
    }
    default:
      return null;
  }
}

function protectionStatus(record) {
  const blocked = isEntityBlocked(record.entityId);
  if (record.score.riskLevel === 'INACTIVE') return 'RESOLVED';
  if (record.score.riskLevel === 'CRITICAL' || record.score.riskLevel === 'HIGH') return blocked ? 'PROTECTED' : 'AT_RISK';
  return blocked ? 'PROTECTED' : 'MONITORED';
}

function blockedMap() {
  const map = new Map();
  for (const b of listBlockedIndicators()) map.set(b.entityId, b);
  return map;
}

export function computeThreatRecords() {
  const dataset = buildDataset();
  const blocked = blockedMap();
  const lastAction = new Map();
  for (const log of listResponseLogs()) {
    if (log.createdAt) lastAction.set(log.threatRecordId, log.createdAt);
    for (const a of log.actions) lastAction.set(log.threatRecordId, a.timestamp);
  }

  const records = [];
  for (const entity of dataset.actors) {
    const score = scoreActor(entity, dataset);
    const id = entity.id;
    records.push({
      entityType: 'ACTOR', entityId: id, entityDisplayName: entity.aliases?.[0] ?? entity.id,
      status: protectionStatus({ score, entityId: id }),
      score, isBlocked: blocked.has(id), lastActionAt: lastAction.get(`${id}`) ?? null,
    });
  }
  for (const entity of dataset.handles) {
    const score = scoreHandle(entity, dataset);
    records.push({ entityType: 'HANDLE', entityId: entity.id, entityDisplayName: entity.value, status: protectionStatus({ score, entityId: entity.id }), score, isBlocked: blocked.has(entity.id), lastActionAt: lastAction.get(`HANDLE:${entity.id}`) ?? null });
  }
  for (const entity of dataset.pgpKeys) {
    const score = scorePgp(entity, dataset);
    records.push({ entityType: 'PGP', entityId: entity.id, entityDisplayName: entity.fingerprint.slice(0, 12), status: protectionStatus({ score, entityId: entity.id }), score, isBlocked: blocked.has(entity.id), lastActionAt: lastAction.get(`PGP:${entity.id}`) ?? null });
  }
  for (const entity of dataset.wallets) {
    const score = scoreWallet(entity, dataset);
    records.push({ entityType: 'WALLET', entityId: entity.id, entityDisplayName: entity.address.slice(0, 14), status: protectionStatus({ score, entityId: entity.id }), score, isBlocked: blocked.has(entity.id), lastActionAt: lastAction.get(`WALLET:${entity.id}`) ?? null });
  }
  for (const entity of dataset.infrastructure) {
    const score = scoreInfrastructure(entity, dataset);
    records.push({ entityType: 'INFRASTRUCTURE', entityId: entity.id, entityDisplayName: entity.value, status: protectionStatus({ score, entityId: entity.id }), score, isBlocked: blocked.has(entity.id), lastActionAt: lastAction.get(`INFRASTRUCTURE:${entity.id}`) ?? null });
  }
  return records;
}

export function computeThreatPosture() {
  const records = computeThreatRecords();
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INACTIVE: 0 };
  for (const r of records) counts[r.score.riskLevel] = (counts[r.score.riskLevel] ?? 0) + 1;
  return {
    overall: counts.CRITICAL > 0 ? 'CRITICAL' : counts.HIGH > 3 ? 'HIGH' : counts.MEDIUM > 5 ? 'MEDIUM' : 'LOW',
    critical: counts.CRITICAL,
    high: counts.HIGH,
    medium: counts.MEDIUM,
    low: counts.LOW,
    inactive: counts.INACTIVE,
    blocked: records.filter(r => r.isBlocked).length,
    monitored: records.filter(r => r.status === 'MONITORED' || r.status === 'AT_RISK').length,
    total: records.length,
    lastComputed: new Date().toISOString(),
  };
}
