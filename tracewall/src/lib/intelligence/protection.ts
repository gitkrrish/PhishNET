// ============================================================
// PhishNet — Threat Protection & Active Detection engine.
//
// This module turns passive dark-web intelligence into active threat
// protection. It has two halves that never share mutable state:
//
//   1. DERIVED engine (pure): threat scores for every intelligence
//      entity, computed only from the central dataset. Scores are
//      deterministic, explainable, and always rebuild from the latest
//      records — no separate truth table is ever invented.
//
//   2. PERSISTED protection state: analyst actions (block a handle,
//      quarantine a wallet, open a response ticket). This is stored
//      separately in localStorage and mirrored to the backend.
//
// The derived engine is intentionally conservative: a score means
// "this entity carries signals worth acting on", not "this actor will
// attack you". Response priority and recommended action always
// require an analyst to confirm.
// ============================================================
import type { IntelligenceDataset, IntelligenceLookups } from './types';
import {
  type ActorRecord,
  type HandleRecord,
  type PgpRecord,
  type WalletRecord,
  type InfrastructureRecord,
  type CveRecordRecord,
  type VulnerabilityRecordRecord,
} from './types';
import type {
  RiskLevel,
  ResponsePriority,
  DetectionReason,
  RecommendedAction,
  ThreatScore,
  ThreatProtectionRecord,
  ProtectionStatus,
  ProtectionActionKind,
  ProtectionAction,
  BlockedIndicator,
  ResponseLog,
  ResponseStatus,
  ThreatPosture,
  ThreatProtectionState,
  ResponseActionRecord,
  ResponseActionKind,
  ResponseActionStatus,
  EnforcementChannelKey,
} from './types-protection';

// ── Signal weight maps ──────────────────────────────────────────

/** Motivation → impact weight (ransomware-style motives carry more force). */
const MOTIVATION_IMPACT: Record<string, number> = {
  RANSOMWARE: 10,
  DATA_THEFT: 10,
  FINANCIAL: 8,
  CREDENTIAL: 9,
  EXTORTION: 9,
  APT: 12,
  CYBERCRIME_SERVICE: 7,
  INFO_BROKER: 6,
};

function motivationWeight(motivation: string | undefined): number {
  const lower = (motivation || '').toLowerCase();
  if (!lower) return 5;
  for (const [keyword, weight] of Object.entries(MOTIVATION_IMPACT)) {
    if (lower.includes(keyword.toLowerCase())) return weight;
  }
  return 5;
}

/** High-impact ATT&CK tactics that amplify an actor's threat rating. */
const IMPACT_TACTICS = new Set([
  'EXFILTRATION',
  'IMPACT',
  'COLLECTION',
  'COMMAND_AND_CONTROL',
  'PRIVILEGE_ESCALATION',
  'CREDENTIAL_ACCESS',
]);

/** Tactic → score weight. */
const TACTIC_WEIGHT: Record<string, number> = {
  EXFILTRATION: 6,
  IMPACT: 8,
  COLLECTION: 5,
  COMMAND_AND_CONTROL: 5,
  PRIVILEGE_ESCALATION: 4,
  CREDENTIAL_ACCESS: 6,
  INITIAL_ACCESS: 3,
  EXECUTION: 3,
  PERSISTENCE: 4,
  DEFENSE_EVASION: 3,
};

const EXPLOITATION_BOOST: Record<string, number> = {
  ACTIVE: 8,
  IN_THE_WILD: 7,
  ZERO_DAY: 10,
  PROOF_OF_CONCEPT: 5,
  UNVERIFIED: 3,
};

const SEVERITY_WEIGHT: Record<string, number> = {
  CRITICAL: 8,
  HIGH: 6,
  MEDIUM: 4,
  LOW: 2,
};

const ACTIVITY_WEIGHT: Record<string, number> = { HIGH: 6, MEDIUM: 3, LOW: 1 };

const ACTOR_STATUS_WEIGHT: Record<string, number> = {
  ACTIVE: 12,
  DORMANT: 4,
  SUSPENDED: 0,
};

const handleActivity = (handle: HandleRecord) => {
  const spanMs = new Date(handle.lastSeen).getTime() - new Date(handle.firstSeen).getTime();
  const days = spanMs / (1000 * 60 * 60 * 24);
  if (days < 7) return 'HIGH';
  if (days < 60) return 'MEDIUM';
  return 'LOW';
};

const clamp = (n: number, min = 0, max = 100) => Math.max(min, Math.min(max, n));

function riskLevelOf(score: number, active: boolean): RiskLevel {
  if (!active && score < 50) return 'INACTIVE';
  if (score >= 85) return 'CRITICAL';
  if (score >= 70) return 'HIGH';
  if (score >= 45) return 'MEDIUM';
  return 'LOW';
}

/** Pick the recommended action/priority from the strongest risk signals. */
function recommend(score: ThreatScore, entityType: string): { action: RecommendedAction; priority: ResponsePriority } {
  const level = score.riskLevel;
  const topSignal = score.reasons.length ? [...score.reasons].sort((a, b) => b.weight - a.weight)[0] : null;

  if (level === 'CRITICAL' || level === 'HIGH') {
    if (entityType === 'HANDLE') return { action: 'BLOCK_HANDLE', priority: 'CRITICAL' };
    if (entityType === 'WALLET' || topSignal?.signal === 'WALLET_TRANSACTION_VOLUME') return { action: 'QUARANTINE_WALLET', priority: 'CRITICAL' };
    if (entityType === 'INFRASTRUCTURE') return { action: 'REVIEW_INFRASTRUCTURE', priority: 'HIGH' };
    if (entityType === 'CVE' || entityType === 'VULNERABILITY') return { action: 'ENRICH_TTP', priority: 'CRITICAL' };
    if (entityType === 'PGP') return { action: 'MONITOR_ENTITY', priority: 'HIGH' };
    return { action: 'ESCALATE_REPORT', priority: level === 'CRITICAL' ? 'CRITICAL' : 'HIGH' };
  }
  if (level === 'MEDIUM') {
    return entityType === 'ACTOR' ? { action: 'ENRICH_TTP', priority: 'MEDIUM' } : { action: 'MONITOR_ENTITY', priority: 'MEDIUM' };
  }
  return { action: 'MONITOR_ENTITY', priority: 'INFORMATIONAL' };
}

function buildScore(value: number, reasons: DetectionReason[], entityType: string, active: boolean): ThreatScore {
  const score = clamp(value, 0, 100);
  const riskLevel = riskLevelOf(score, active);
  const base: ThreatScore = {
    value: score,
    riskLevel,
    reasons,
    recommendedAction: 'NO_ACTION',
    responsePriority: 'INFORMATIONAL',
    computedAt: new Date().toISOString(),
  };
  const rec = recommend(base, entityType);
  return { ...base, recommendedAction: rec.action, responsePriority: rec.priority };
}

// ── Per-entity scorers ───────────────────────────────────────────

function actorSharedIndicatorWeight(actor: ActorRecord, dataset: IntelligenceDataset, lookups: IntelligenceLookups): DetectionReason[] {
  const reasons: DetectionReason[] = [];
  // Shared PGP keys (a key whose actorIds span more than one actor)
  for (const fp of actor.pgpFingerprints) {
    const key = dataset.pgpKeys.find(k => k.fingerprint === fp || k.id === fp) ?? lookups.pgpById[fp];
    if (key && key.actorIds.length > 1) {
      reasons.push({
        signal: 'SHARED_PGP',
        label: 'Shared PGP identity',
        detail: `Fingerprint shared across ${key.actorIds.length} actors`,
        weight: 6,
      });
    }
  }
  // Shared wallets — wallets attributed to this actor that other actors also use.
  //
  // Aggregated for the same reason as shared infrastructure: one row per wallet
  // produced several identically titled "Shared wallet" findings.
  const sharedWallets = dataset.wallets.filter(w => w.actorIds.includes(actor.id) && w.actorIds.length > 1);
  if (sharedWallets.length > 0) {
    reasons.push({
      signal: 'SHARED_WALLET',
      label: 'Shared wallet',
      detail:
        sharedWallets.length === 1
          ? `Payment address shared across ${sharedWallets[0].actorIds.length} actors`
          : `${sharedWallets.length} payment address(es) shared across actors`,
      weight: 5 * sharedWallets.length,
    });
  }
  // Shared infrastructure.
  //
  // Aggregated rather than one reason per indicator: an actor with several
  // shared indicators produced several rows all titled "Shared infrastructure",
  // which read as a repeated finding and collided as React keys. The weight is
  // unchanged, so the score is identical — only the reporting is clearer.
  const sharedInfra = dataset.infrastructure.filter(i => i.actorIds.includes(actor.id) && i.actorIds.length > 1);
  if (sharedInfra.length > 0) {
    reasons.push({
      signal: 'SHARED_INFRASTRUCTURE',
      label: 'Shared infrastructure',
      detail:
        sharedInfra.length === 1
          ? `Infrastructure ${sharedInfra[0].value} used by ${sharedInfra[0].actorIds.length} actors`
          : `${sharedInfra.length} indicator(s) shared across actors: ${sharedInfra.map(i => i.value).join(', ')}`,
      weight: 5 * sharedInfra.length,
    });
  }
  return reasons;
}

export function scoreActor(actor: ActorRecord, dataset: IntelligenceDataset, lookups: IntelligenceLookups): ThreatScore {
  const reasons: DetectionReason[] = [];
  let score = 0;

  const confContrib = clamp(Math.round((actor.confidenceScore / 100) * 30));
  if (confContrib > 0) {
    score += confContrib;
    reasons.push({ signal: 'CONFIDENCE', label: 'Attribution confidence', detail: `${actor.confidenceScore}% confidence in actor attribution`, weight: confContrib });
  }

  const statusW = ACTOR_STATUS_WEIGHT[actor.status as string] ?? 0;
  if (statusW > 0) {
    score += statusW;
    reasons.push({ signal: 'ACTIVE_STATUS', label: 'Active status', detail: `Actor is ${actor.status.toLowerCase()}`, weight: statusW });
  }

  const actW = ACTIVITY_WEIGHT[actor.activityLevel as string] ?? 0;
  if (actW > 0) {
    score += actW;
    reasons.push({ signal: 'ACTIVITY_LEVEL', label: 'Activity level', detail: `${actor.activityLevel.toLowerCase()} operational tempo`, weight: actW });
  }

  const motW = motivationWeight(actor.primaryMotivation);
  score += motW;
  reasons.push({ signal: 'BEHAVIORAL_PROFILE', label: 'Behavioral motivation', detail: `${actor.primaryMotivation || 'unknown'} motive profile`, weight: motW });

  // Persona migration churn from timeline.
  const migrations = dataset.timeline.filter(t => t.actorId === actor.id && t.type === 'PERSONA_MIGRATION').length;
  if (migrations > 0) {
    const mW = clamp(migrations * 3);
    score += mW;
    reasons.push({ signal: 'PERSONA_MIGRATION', label: 'Persona migration churn', detail: `${migrations} persona migration(s)`, weight: mW });
  }

  // Shared indicators
  const sharedReasons = actorSharedIndicatorWeight(actor, dataset, lookups);
  for (const r of sharedReasons) {
    score += r.weight;
    reasons.push(r);
  }

  // Evidence reliability backing this actor.
  const evidence = dataset.evidence.filter(e => e.relatedActor === actor.id);
  const highRel = evidence.filter(e => e.reliability >= 85).length;
  if (highRel > 0) {
    const eW = clamp(highRel * 2);
    score += eW;
    reasons.push({ signal: 'EVIDENCE_RELIABILITY', label: 'High-reliability evidence', detail: `${highRel} evidence item(s) at R85+`, weight: eW });
  }

  // ATT&CK impact tactics
  //
  // Grouped by tactic, so a tactic mapped through several techniques is one
  // finding naming all of them rather than N identical rows.
  const impactTtps = dataset.mitreTtps.filter(t => t.actorIds.includes(actor.id) && IMPACT_TACTICS.has(t.tactic as string));
  const impactByTactic = new Map<string, typeof impactTtps>();
  for (const ttp of impactTtps) {
    const list = impactByTactic.get(ttp.tactic) ?? [];
    list.push(ttp);
    impactByTactic.set(ttp.tactic, list);
  }
  for (const [tactic, ttps] of impactByTactic) {
    const w = (TACTIC_WEIGHT[tactic] ?? 3) * ttps.length;
    score += w;
    reasons.push({
      signal: 'ATTEX_VULNERABILITY',
      label: `ATT&CK tactic: ${tactic}`,
      detail:
        ttps.length === 1
          ? `Technique ${ttps[0].techniqueId} (${ttps[0].name}) at ${ttps[0].confidence}% confidence`
          : `${ttps.length} technique(s): ${ttps.map(t => `${t.techniqueId} ${t.name}`).join(', ')}`,
      weight: w,
    });
  }

  // CVE exploitation linked via MITRE infrastructure / actor
  const cves = dataset.cves.filter(c => c.actorIds.includes(actor.id));
  for (const cve of cves) {
    const boost = EXPLOITATION_BOOST[cve.exploitationStatus as string] ?? 0;
    const sevW = SEVERITY_WEIGHT[cve.severity as string] ?? 0;
    if (boost + sevW > 0) {
      const w = clamp(boost + sevW);
      score += w;
      reasons.push({ signal: 'CVE_EXPLOITATION', label: `Exploits ${cve.cveId}`, detail: `${cve.severity} severity · ${cve.exploitationStatus}`, weight: w });
    }
  }

  // Wallet transaction activity / mixing
  //
  // One finding for the actor rather than one per wallet: several mixing
  // wallets each produced an identically titled "Mixing activity" row. The
  // weight is the sum of the per-wallet weights, so the score is unchanged.
  let mixingWeight = 0;
  let mixingTxCount = 0;
  let mixingWalletCount = 0;
  for (const ref of actor.walletAddrs) {
    const wallet = dataset.wallets.find(w => w.id === ref || w.address === ref);
    if (!wallet) continue;
    const mixers = dataset.walletTransactions.filter(t => t.walletId === wallet.id && t.mixingService).length;
    if (mixers === 0) continue;
    mixingWeight += clamp(mixers * 3, 0, 10);
    mixingTxCount += mixers;
    mixingWalletCount += 1;
  }
  if (mixingWeight > 0) {
    score += mixingWeight;
    reasons.push({
      signal: 'WALLET_TRANSACTION_VOLUME',
      label: 'Mixing activity',
      detail:
        mixingWalletCount === 1
          ? `${mixingTxCount} transaction(s) routed through a mixing service`
          : `${mixingTxCount} transaction(s) across ${mixingWalletCount} address(es) routed through a mixing service`,
      weight: mixingWeight,
    });
  }

  // Encrypted communication channels
  const channels = dataset.communicationChannels.filter(c => c.actorIds.includes(actor.id));
  const encrypted = channels.filter(c => c.encryptionProtocol !== 'NONE' && c.encryptionProtocol !== 'TLS').length;
  if (encrypted > 0) {
    const w = clamp(encrypted * 3, 0, 12);
    score += w;
    reasons.push({ signal: 'ENCRYPTED_COMMUNICATION', label: 'Encrypted communications', detail: `${encrypted} channel(s) using non-TLS encryption`, weight: w });
  }

  // Open monitoring alerts for this actor
  const actorAlerts = dataset.alerts.filter(a => a.actorId === actor.id && (a.status === 'OPEN' || a.status === 'ACKNOWLEDGED'));
  if (actorAlerts.length > 0) {
    const w = clamp(actorAlerts.length * 4, 0, 12);
    score += w;
    reasons.push({ signal: 'MONITORING_ALERT', label: 'Active monitoring alerts', detail: `${actorAlerts.length} open/acknowledged alert(s)`, weight: w });
  }

  return buildScore(score, reasons, 'ACTOR', actor.status === 'ACTIVE');
}

export function scoreHandle(handle: HandleRecord, dataset: IntelligenceDataset): ThreatScore {
  const reasons: DetectionReason[] = [];
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

  // Persona migration / identity-reuse events referencing this handle.
  const normalized = handle.normalized?.toLowerCase?.() ?? '';
  const transfers = dataset.timeline.filter(t => {
    const hay = `${t.title ?? ''} ${t.description ?? ''}`.toLowerCase();
    return t.actorId === handle.id || (normalized && hay.includes(normalized));
  }).length;
  if (transfers > 0) {
    const w = clamp(transfers * 3, 0, 9);
    score += w;
    reasons.push({ signal: 'PERSONA_MIGRATION', label: 'Identity reuse detected', detail: `${transfers} timeline event(s) linked to this handle`, weight: w });
  }

  // Shared across multiple actors?
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

export function scoreWallet(wallet: WalletRecord, dataset: IntelligenceDataset): ThreatScore {
  const reasons: DetectionReason[] = [];
  let score = 0;

  const confContrib = clamp(Math.round((wallet.confidence / 100) * 25));
  if (confContrib > 0) {
    score += confContrib;
    reasons.push({ signal: 'CONFIDENCE', label: 'Wallet attribution confidence', detail: `${wallet.confidence}% confidence`, weight: confContrib });
  }

  // Transaction volume
  const txCount = wallet.txCount ?? 0;
  const txW = clamp(Math.log1p(txCount) * 4, 0, 12);
  if (txW > 0) {
    score += txW;
    reasons.push({ signal: 'WALLET_TRANSACTION_VOLUME', label: 'Transaction volume', detail: `${txCount} on-chain transaction(s)`, weight: txW });
  }

  // Shared wallet across actors
  if (wallet.actorIds.length > 1) {
    const w = clamp(wallet.actorIds.length * 5, 0, 12);
    score += w;
    reasons.push({ signal: 'SHARED_WALLET', label: 'Shared payment address', detail: `Linked to ${wallet.actorIds.length} actors`, weight: w });
  }

  // Mixing / high-risk transactions
  const txs = dataset.walletTransactions.filter(t => t.walletId === wallet.id);
  const mixers = txs.filter(t => t.mixingService).length;
  const flagged = txs.filter(t => t.isFlagged).length;
  if (mixers + flagged > 0) {
    const w = clamp((mixers + flagged) * 4, 0, 12);
    score += w;
    reasons.push({ signal: 'WALLET_TRANSACTION_VOLUME', label: 'High-risk transaction pattern', detail: `${mixers} mixer(s), ${flagged} flagged transaction(s)`, weight: w });
  }

  // Sanctions match (runtime-only field on wallet records)
  const walletAny = wallet as WalletRecord & { tags?: string[] };
  if (walletAny.tags?.some(t => /sanction/i.test(t))) {
    score += 15;
    reasons.push({ signal: 'ENCRYPTED_COMMUNICATION', label: 'Sanctions list match', detail: 'Address appears on a sanctions watchlist', weight: 15 });
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

export function scoreInfrastructure(infra: InfrastructureRecord, dataset: IntelligenceDataset): ThreatScore {
  const reasons: DetectionReason[] = [];
  let score = 0;

  const sharedActors = infra.actorIds.length;
  if (sharedActors > 1) {
    const w = clamp(sharedActors * 4, 0, 12);
    score += w;
    reasons.push({ signal: 'SHARED_INFRASTRUCTURE', label: 'Shared infrastructure', detail: `Used by ${sharedActors} actors`, weight: w });
  }

  // Onion / domain infrastructure is higher baseline risk.
  if (infra.type === 'DOMAIN' && /(\.onion|\.i2p)/i.test(infra.value)) {
    score += 10;
    reasons.push({ signal: 'SHARED_INFRASTRUCTURE', label: 'Onion / anonymous hosting', detail: `${infra.value} is an anonymous network address`, weight: 10 });
  }

  // TLS issuer reuse across actors
  const sameIssuer = dataset.infrastructure.filter(i => i !== infra && i.tlsIssuer && i.tlsIssuer === infra.tlsIssuer).length;
  if (sameIssuer > 0) {
    const w = clamp(sameIssuer * 3, 0, 9);
    score += w;
    reasons.push({ signal: 'SHARED_INFRASTRUCTURE', label: 'Shared TLS issuer', detail: `${sameIssuer} other indicator(s) share TLS issuer "${infra.tlsIssuer}"`, weight: w });
  }

  const activeAlerts = dataset.alerts.filter(a => a.entityId === infra.id && (a.status === 'OPEN' || a.status === 'ACKNOWLEDGED')).length;
  if (activeAlerts > 0) {
    score += clamp(activeAlerts * 4, 0, 8);
    reasons.push({ signal: 'MONITORING_ALERT', label: 'Monitoring alert', detail: `${activeAlerts} open alert(s)`, weight: clamp(activeAlerts * 4, 0, 8) });
  }

  const isActive = new Date(infra.lastSeen).getTime() > Date.now() - 1000 * 60 * 60 * 24 * 90;
  return buildScore(score, reasons, 'INFRASTRUCTURE', isActive);
}

export function scoreCve(cve: CveRecordRecord, _dataset?: IntelligenceDataset, _lookups?: IntelligenceLookups): ThreatScore {
  const reasons: DetectionReason[] = [];
  let score = 0;

  const sevW = SEVERITY_WEIGHT[cve.severity as string] ?? 0;
  if (sevW > 0) {
    score += sevW;
    reasons.push({ signal: 'CVE_EXPLOITATION', label: `CVSS ${cve.severity}`, detail: `${cve.severity} severity (CVSS ${cve.cvssScore}/10)`, weight: sevW });
  }

  const boost = EXPLOITATION_BOOST[cve.exploitationStatus as string] ?? 0;
  if (boost > 0) {
    score += boost;
    reasons.push({ signal: 'CVE_EXPLOITATION', label: 'Dark-web exploitation', detail: `Status: ${cve.exploitationStatus}`, weight: boost });
  }

  const darkWeb = cve.darkWebSources.length;
  if (darkWeb > 0) {
    const w = clamp(darkWeb * 2, 0, 6);
    score += w;
    reasons.push({ signal: 'CVE_EXPLOITATION', label: 'Dark-web discussion', detail: `Mentioned in ${darkWeb} source(s)`, weight: w });
  }

  return buildScore(score, reasons, 'CVE', cve.exploitationStatus === 'ACTIVE' || cve.exploitationStatus === 'IN_THE_WILD');
}

export function scoreVulnerability(vuln: VulnerabilityRecordRecord, _dataset?: IntelligenceDataset, _lookups?: IntelligenceLookups): ThreatScore {
  const reasons: DetectionReason[] = [];
  let score = 0;

  const sevW = SEVERITY_WEIGHT[vuln.severity as string] ?? 0;
  if (sevW > 0) {
    score += sevW;
    reasons.push({ signal: 'ATTEX_VULNERABILITY', label: `Severity ${vuln.severity}`, detail: `CVSS ${vuln.cvssScore}/10`, weight: sevW });
  }

  const boost = EXPLOITATION_BOOST[vuln.exploitationStatus as string] ?? 0;
  if (boost > 0) {
    score += boost;
    reasons.push({ signal: 'CVE_EXPLOITATION', label: 'Exploitation status', detail: `${vuln.exploitationStatus}${vuln.isZeroDay ? ' · zero-day' : ''}`, weight: boost });
  }

  const darkWeb = vuln.darkWebSources.length;
  if (darkWeb > 0) {
    const w = clamp(darkWeb * 2, 0, 6);
    score += w;
    reasons.push({ signal: 'CVE_EXPLOITATION', label: 'Dark-web discussion', detail: `Mentioned in ${darkWeb} source(s)`, weight: w });
  }

  return buildScore(score, reasons, 'VULNERABILITY', vuln.exploitationStatus === 'ACTIVE' || vuln.exploitationStatus === 'IN_THE_WILD' || vuln.isZeroDay);
}

export function scorePgp(key: PgpRecord, dataset: IntelligenceDataset): ThreatScore {
  const reasons: DetectionReason[] = [];
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

  // Revoked / expiring soon (runtime-only fields on PGP records)
  const pgpAny = key as PgpRecord & { expiresAt?: string; revokedAt?: string };
  if (pgpAny.expiresAt && new Date(pgpAny.expiresAt).getTime() < Date.now() + 1000 * 60 * 60 * 24 * 30) {
    score += 5;
    reasons.push({ signal: 'BEHAVIORAL_PROFILE', label: 'Expiring PGP key', detail: `Expires ${new Date(pgpAny.expiresAt).toLocaleDateString()}`, weight: 5 });
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

// ── Dispatcher ───────────────────────────────────────────────────

export const ENTITY_SCORER: Record<string, (entity: any, dataset: IntelligenceDataset, lookups: IntelligenceLookups) => ThreatScore> =
  {
    ACTOR: (a, d, l) => scoreActor(a, d, l),
    HANDLE: (h, d) => scoreHandle(h, d),
    PGP: (k, d) => scorePgp(k, d),
    WALLET: (w, d) => scoreWallet(w, d),
    INFRASTRUCTURE: (i, d) => scoreInfrastructure(i, d),
    CVE: (c) => scoreCve(c),
    VULNERABILITY: (v) => scoreVulnerability(v),
  };

export function computeEntityScore(
  entityType: string,
  entityId: string,
  dataset: IntelligenceDataset,
  lookups: IntelligenceLookups,
): ThreatScore | null {
  const scorer = ENTITY_SCORER[entityType];
  if (!scorer) return null;
  switch (entityType) {
    case 'ACTOR': {
      const entity = lookups.actorsById[entityId];
      return entity ? scorer(entity, dataset, lookups) : null;
    }
    case 'HANDLE': {
      const entity = lookups.handlesById[entityId];
      return entity ? scorer(entity, dataset, lookups) : null;
    }
    case 'PGP': {
      const entity = lookups.pgpById[entityId];
      return entity ? scorer(entity, dataset, lookups) : null;
    }
    case 'WALLET': {
      const entity = lookups.walletsById[entityId];
      return entity ? scorer(entity, dataset, lookups) : null;
    }
    case 'INFRASTRUCTURE': {
      const entity = lookups.infraById[entityId];
      return entity ? scorer(entity, dataset, lookups) : null;
    }
     case 'CVE': {
      const entity = lookups.cvesById[entityId];
      return entity ? scorer(entity, dataset, lookups) : null;
    }
    case 'VULNERABILITY': {
      const entity = lookups.vulnerabilitiesById[entityId];
      return entity ? scorer(entity, dataset, lookups) : null;
    }
    default:
      return null;
  }
}

// ── Derived protection records (computed from the dataset) ───────

export function protectionRecords(dataset: IntelligenceDataset): ThreatProtectionRecord[] {
  const { lookups } = dataset;
  const records: ThreatProtectionRecord[] = [];

  for (const entity of dataset.actors) {
    const score = scoreActor(entity, dataset, lookups);
    records.push(toRecord('ACTOR', entity.id, entity.aliases?.[0] ?? entity.id, score));
  }
  for (const entity of dataset.handles) {
    const score = scoreHandle(entity, dataset);
    records.push(toRecord('HANDLE', entity.id, entity.value, score));
  }
  for (const entity of dataset.pgpKeys) {
    const score = scorePgp(entity, dataset);
    records.push(toRecord('PGP', entity.id, entity.fingerprint.slice(0, 12), score));
  }
  for (const entity of dataset.wallets) {
    const score = scoreWallet(entity, dataset);
    records.push(toRecord('WALLET', entity.id, entity.address.slice(0, 14), score));
  }
  for (const entity of dataset.infrastructure) {
    const score = scoreInfrastructure(entity, dataset);
    records.push(toRecord('INFRASTRUCTURE', entity.id, entity.value, score));
  }
  for (const entity of dataset.cves) {
    const score = scoreCve(entity);
    records.push(toRecord('CVE', entity.id, entity.cveId, score));
  }
  for (const entity of dataset.vulnerabilities) {
    const score = scoreVulnerability(entity);
    records.push(toRecord('VULNERABILITY', entity.id, entity.vulnerabilityId, score));
  }
  return records;
}

function toRecord(entityType: string, entityId: string, displayName: string, score: ThreatScore): ThreatProtectionRecord {
  const verdict = enforcementVerdict(entityId);
  const status: ProtectionStatus =
    score.riskLevel === 'INACTIVE' ? 'RESOLVED'
    : verdict === 'VERIFIED' ? 'PROTECTED'
    : verdict === 'DECIDED' ? 'PENDING'
    : score.riskLevel === 'CRITICAL' ? 'AT_RISK'
    : score.riskLevel === 'HIGH' ? 'AT_RISK'
    : 'MONITORED';
  return {
    entityType,
    entityId,
    entityDisplayName: displayName,
    status,
    score,
    isBlocked: verdict !== 'NONE',
    lastActionAt: lastActionAtFor(entityId),
  };
}

// ── Threat posture roll-up ─────────────────────────────────────────

export function threatPosture(dataset: IntelligenceDataset): ThreatPosture {
  const records = protectionRecords(dataset);
  const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INACTIVE: 0 };
  for (const r of records) counts[r.score.riskLevel] = (counts[r.score.riskLevel] ?? 0) + 1;
  const blocked = records.filter(r => r.isBlocked).length;
  const monitored = records.filter(r => r.status === 'MONITORED' || r.status === 'AT_RISK').length;
  const critical = counts.CRITICAL;
  return {
    overall: critical > 0 ? 'CRITICAL' : counts.HIGH > 3 ? 'HIGH' : counts.MEDIUM > 5 ? 'MEDIUM' : 'LOW',
    critical,
    high: counts.HIGH,
    medium: counts.MEDIUM,
    low: counts.LOW,
    inactive: counts.INACTIVE,
    blocked,
    monitored,
    total: records.length,
    lastComputed: new Date().toISOString(),
  };
}

export function riskLevelColor(level: RiskLevel): string {
  switch (level) {
    case 'CRITICAL': return 'var(--tw-critical)';
    case 'HIGH': return 'var(--tw-high)';
    case 'MEDIUM': return 'var(--tw-medium)';
    case 'LOW': return 'var(--tw-low)';
    case 'INACTIVE': return 'var(--tw-dust)';
    default: return 'var(--tw-text-muted)';
  }
}

export function responsePriorityColor(priority: ResponsePriority): string {
  switch (priority) {
    case 'CRITICAL': return 'var(--tw-critical)';
    case 'HIGH': return 'var(--tw-high)';
    case 'MEDIUM': return 'var(--tw-medium)';
    case 'LOW': return 'var(--tw-low)';
    case 'INFORMATIONAL': return 'var(--tw-text-muted)';
    default: return 'var(--tw-text-muted)';
  }
}

// ── Persisted protection-action store ─────────────────────────────
//
// Analyst decisions (blocks, response tickets, actions) are kept in
// localStorage and mirrored to the backend. The derived threat
// scores above are recomputed from the dataset on every read and are
// never persisted.

const PROTECTION_STORAGE_KEY = 'phishnet-protection-state-v1';

interface ProtectionPersisted {
  blockedIndicators: BlockedIndicator[];
  responseLogs: ResponseLog[];
  /**
   * Outcome ledger for response actions. This is a *decision and outcome*
   * trail against existing record ids, not a second intelligence model:
   * every entry points back at an id that already exists in the dataset.
   */
  responseActions: ResponseActionRecord[];
}

let protectionState: ProtectionPersisted = loadProtectionState();
const protectionListeners = new Set<() => void>();

let protectionRevision = 0;
let protectionSnapshot: { revision: number; blocked: BlockedIndicator[]; logs: ResponseLog[]; actions: ResponseActionRecord[] } | null = null;

function bumpProtection(): void {
  protectionRevision += 1;
  protectionSnapshot = null;
  notifyProtection();
}

export function getProtectionSnapshot(): { revision: number; blocked: BlockedIndicator[]; logs: ResponseLog[]; actions: ResponseActionRecord[] } {
  if (!protectionSnapshot || protectionSnapshot.revision !== protectionRevision) {
    protectionSnapshot = {
      revision: protectionRevision,
      blocked: blockedIndicators(),
      logs: responseLogs(),
      actions: responseActionRecords(),
    };
  }
  return protectionSnapshot;
}

function loadProtectionState(): ProtectionPersisted {
  if (typeof window === 'undefined') {
    return { blockedIndicators: [], responseLogs: [], responseActions: [] };
  }
  try {
    const raw = window.localStorage.getItem(PROTECTION_STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      return {
        blockedIndicators: parsed.blockedIndicators ?? [],
        responseLogs: parsed.responseLogs ?? [],
        responseActions: parsed.responseActions ?? [],
      };
    }
  } catch {
    /* corrupted — fall through to empty */
  }
  return { blockedIndicators: [], responseLogs: [], responseActions: [] };
}

function persistProtection(): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(PROTECTION_STORAGE_KEY, JSON.stringify(protectionState));
  } catch {
    /* quota / private mode — in-memory still holds */
  }
}

export function getProtectionState(): ProtectionPersisted {
  return protectionState;
}

export function subscribeProtection(listener: () => void): () => void {
  protectionListeners.add(listener);
  return () => protectionListeners.delete(listener);
}

function notifyProtection(): void {
  for (const listener of protectionListeners) listener();
}

function nowIso(): string {
  return new Date().toISOString();
}

export function isEntityBlocked(entityId: string): boolean {
  return protectionState.blockedIndicators.some(b => b.entityId === entityId && b.active);
}

/**
 * The strongest protection outcome actually achieved for an entity.
 *
 * `VERIFIED` means an authorised integration confirmed a control. A bare
 * analyst decision is `DECIDED`, which is deliberately *not* the same thing:
 * recording a block in this platform does not block anything anywhere else.
 */
export type EnforcementVerdict = 'VERIFIED' | 'DECIDED' | 'FAILED' | 'NONE';

export function enforcementVerdict(entityId: string): EnforcementVerdict {
    const actions = protectionState.responseActions.filter(a => a.entityId === entityId);
    if (actions.some(a => a.status === 'ENFORCED_VERIFIED')) return 'VERIFIED';
    if (actions.some(a => a.status === 'FAILED')) return 'FAILED';
    if (protectionState.blockedIndicators.some(b => b.entityId === entityId && b.active)) return 'DECIDED';
    // Sent but unconfirmed is a decision that has not taken effect, so it can
    // never resolve to VERIFIED and never reads as protected.
    if (
      actions.some(
        a => a.status === 'AWAITING_INTEGRATION' || a.status === 'AWAITING_APPROVAL' || a.status === 'SUBMITTED_UNCONFIRMED',
      )
    ) return 'DECIDED';
    return 'NONE';
}

function lastActionAtFor(entityId: string): string | null {
  const logs = protectionState.responseLogs.filter(l => l.threatRecordId === entityId);
  const actions: string[] = [];
  for (const log of logs) {
    if (log.createdAt) actions.push(log.createdAt);
    for (const a of log.actions) actions.push(a.timestamp);
  }
  for (const record of protectionState.responseActions.filter(a => a.entityId === entityId)) {
    actions.push(record.recordedAt);
  }
  if (!actions.length) return null;
  return actions.sort().slice(-1)[0];
}

const blockedCounter = { n: 0 };
const logCounter = { n: 0 };
const actionCounter = { n: 0 };

function nextId(prefix: string, counter: { n: number }): string {
  counter.n += 1;
  return `${prefix}-${Date.now().toString(36).toUpperCase()}-${counter.n}`;
}

export function blockIndicator(
  entityType: string,
  entityId: string,
  value: string,
  reason: string,
  _performedBy = 'Analyst',
  expiresAt?: string,
): BlockedIndicator {
  const existing = protectionState.blockedIndicators.find(b => b.entityId === entityId && b.active);
  if (existing) {
    existing.reason = reason;
    existing.expiresAt = expiresAt ?? existing.expiresAt;
    existing.blockedAt = nowIso();
    existing.active = true;
    return existing;
  }
  const blocked: BlockedIndicator = {
    id: nextId('BLK', blockedCounter),
    entityType,
    entityId,
    value,
    blockedAt: nowIso(),
    reason,
    expiresAt: expiresAt ?? null,
    active: true,
  };
  protectionState.blockedIndicators.push(blocked);
  persistProtection();
  bumpProtection();
  backendMirrorProtection();
  return blocked;
}

export function unblockIndicator(indicatorId: string, _performedBy = 'Analyst'): BlockedIndicator | null {
  const idx = protectionState.blockedIndicators.findIndex(b => b.id === indicatorId);
  if (idx < 0) return null;
  const blocked = protectionState.blockedIndicators[idx];
  blocked.active = false;
  persistProtection();
  bumpProtection();
  backendMirrorProtection();
  return blocked;
}

export function blockedIndicators(): BlockedIndicator[] {
  return [...protectionState.blockedIndicators].filter(b => b.active);
}

export function createResponseLog(
  threatRecordId: string,
  title: string,
  severity: ResponsePriority,
  _performedBy = 'Analyst',
): ResponseLog {
  const log: ResponseLog = {
    id: nextId('RSP', logCounter),
    threatRecordId,
    title,
    severity,
    createdAt: nowIso(),
    status: 'OPEN',
    assignedTo: null,
    actions: [],
    notes: [],
  };
  protectionState.responseLogs.push(log);
  persistProtection();
  bumpProtection();
  backendMirrorProtection();
  return log;
}

export function addResponseAction(logId: string, kind: ProtectionActionKind, reason: string, performedBy = 'Analyst'): ResponseLog | null {
  const log = protectionState.responseLogs.find(l => l.id === logId);
  if (!log) return null;
  const action: ProtectionAction = {
    id: nextId('ACT', actionCounter),
    threatRecordId: log.threatRecordId,
    kind,
    performedBy,
    reason,
    timestamp: nowIso(),
    detail: reason,
  };
   log.actions.push(action);
  persistProtection();
  bumpProtection();
  backendMirrorProtection();
  return log;
}

export function updateResponseStatus(logId: string, status: ResponseStatus, notes?: string): ResponseLog | null {
  const log = protectionState.responseLogs.find(l => l.id === logId);
  if (!log) return null;
  log.status = status;
  if (notes) log.notes.push(`${nowIso()} — ${notes}`);
  persistProtection();
  bumpProtection();
  backendMirrorProtection();
  return log;
}

export function responseLogs(): ResponseLog[] {
  return [...protectionState.responseLogs].sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
}

// ── Response action ledger ─────────────────────────────────────
//
// One record per analyst decision, carrying the outcome the responsible
// integration actually returned. `ENFORCED_VERIFIED` is only ever set by
// `runEnforcement`, which only sets it when a configured control plane
// confirmed the change.

export function responseActionRecords(entityId?: string): ResponseActionRecord[] {
  const all = [...protectionState.responseActions].sort((a, b) => (a.recordedAt < b.recordedAt ? 1 : -1));
  return entityId ? all.filter(a => a.entityId === entityId) : all;
}

/**
 * A one-line, honest summary of the most recent protection action on an
 * entity: what was decided and what the responsible integration returned.
 */
export function lastActionSummary(entityId: string): string | null {
  const latest = responseActionRecords(entityId)[0];
  if (!latest) return null;
  const at = new Date(latest.recordedAt).toLocaleDateString();
  return `${latest.kind.replace(/_/g, ' ').toLowerCase()} · ${latest.status.replace(/_/g, ' ').toLowerCase()} · ${at}`;
}

export function recordResponseAction(input: {
  entityType: string;
  entityId: string;
  entityValue: string;
  kind: ResponseActionKind;
  status: ResponseActionStatus;
  channel: EnforcementChannelKey | null;
  detail: string;
  performedBy?: string;
  confirmedAt?: string | null;
}): ResponseActionRecord {
  const record: ResponseActionRecord = {
    id: nextId('ACT', actionCounter),
    entityType: input.entityType,
    entityId: input.entityId,
    entityValue: input.entityValue,
    kind: input.kind,
    status: input.status,
    channel: input.channel,
    detail: input.detail,
    performedBy: input.performedBy ?? 'Analyst',
    recordedAt: nowIso(),
    confirmedAt: input.confirmedAt ?? null,
  };
  protectionState.responseActions.push(record);

  // A denial decision mirrors into the analyst-decision list so the
  // existing entity pages keep showing one consistent decision state.
  if (
    input.status === 'ENFORCED_VERIFIED' ||
    input.status === 'AWAITING_APPROVAL' ||
    input.status === 'AWAITING_INTEGRATION' ||
    input.status === 'SUBMITTED_UNCONFIRMED'
  ) {
    const already = protectionState.blockedIndicators.find(b => b.entityId === input.entityId && b.active);
    if (!already) {
      protectionState.blockedIndicators.push({
        id: nextId('BLK', blockedCounter),
        entityType: input.entityType,
        entityId: input.entityId,
        value: input.entityValue,
        blockedAt: record.recordedAt,
        reason: input.detail,
        expiresAt: null,
        active: true,
      });
    }
  }

  persistProtection();
  bumpProtection();
  backendMirrorProtection();
  return record;
}

/** Clear a previously verified enforcement record after an unblock decision. */
export function clearEnforcementFor(entityId: string, reason: string, performedBy = 'Analyst'): void {
  for (const record of protectionState.responseActions) {
    if (record.entityId === entityId && record.status === 'ENFORCED_VERIFIED') {
      record.status = 'RECORDED';
      record.detail = `${record.detail} — superseded by ${performedBy}: ${reason}`;
      record.confirmedAt = null;
    }
  }
  for (const blocked of protectionState.blockedIndicators) {
    if (blocked.entityId === entityId && blocked.active) {
      blocked.active = false;
      blocked.reason = reason;
    }
  }
  persistProtection();
  bumpProtection();
  backendMirrorProtection();
}

export function fullProtectionState(dataset: IntelligenceDataset): ThreatProtectionState {
  return {
    records: protectionRecords(dataset),
    blockedIndicators: blockedIndicators(),
    responseLogs: responseLogs(),
    posture: threatPosture(dataset),
    lastComputed: nowIso(),
  };
}

// ── Backend mirror (best-effort) ───────────────────────────────

function backendBaseUrl(): string | null {
  if (typeof window === 'undefined') return null;
  const origin = window.location.origin;
  return origin;
}

function backendMirrorProtection(): void {
  if (typeof window === 'undefined') return;
  const base = backendBaseUrl();
  if (!base) return;
  try {
    // The reconcile handler reads `blockedIndicators` and `responseLogs` off
    // the request body and replaces whatever it holds with them. Sending a
    // wrapper object instead of those two arrays makes the backend fall back
    // to empty arrays and silently erase its block list and response
    // history, so the payload has to match that contract exactly.
    //
    // The response-action ledger is deliberately not sent: the backend has
    // never persisted it, and mirroring a field it discards would claim a
    // sync that did not happen.
    fetch(`${base}/api/intel/protection/reconcile`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        blockedIndicators: protectionState.blockedIndicators,
        responseLogs: protectionState.responseLogs,
      }),
    }).catch(() => {
      /* offline — local state still holds */
    });
  } catch {
    /* no backend reachable */
  }
}
