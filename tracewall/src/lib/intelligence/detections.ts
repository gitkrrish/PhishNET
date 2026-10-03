// ============================================================
// PhishNet — Per-module detection selectors.
//
// Every Dark Web Intelligence module already owns a record type. These
// selectors add the *active* reading of those same records: what was
// detected, why, what corroborates it, and which response actions are
// actually available.
//
// Rules this file follows without exception:
//
//   * A detection is always derived from an existing record. Nothing here
//     creates, renames or duplicates an intelligence entity.
//   * A signal is never stated as a fact it is not. Correlations say
//     "correlated", unconfirmed mappings say "unconfirmed", and anything
//     the model cannot see is reported as unknown rather than guessed.
//   * No indicator is called malicious, compromised, patched or blocked on
//     the strength of this file alone. Enforcement lives in
//     `enforcement.ts` and is only ever confirmed by an integration.
// ============================================================
import type {
  ActorRecord,
  AlertRecord,
  CveRecordRecord,
  EvidenceRecord,
  IntelligenceDataset,
  InvestigationRecord,
  MitreTtpRecord,
  RelationshipRecord,
  TimelineRecord,
  VulnerabilityRecordRecord,
  WalletClusterRecord,
  WalletRecord,
  WalletTransactionRecord,
} from './types';
import type {
  DetectionReason,
  FactTone,
  MonitoringStateRef,
  ModuleProtectionRow,
  ModuleProtectionSummary,
  ProtectionFact,
  ProtectionStatus,
  ProtectionView,
  RecommendedAction,
  RelatedAlertRef,
  RelatedEvidenceRef,
  RelatedInvestigationRef,
  ResponseActionStatus,
  RiskLevel,
  ThreatScore,
} from './types-protection';
import {
  computeEntityScore,
  enforcementVerdict,
  lastActionSummary,
  protectionRecords,
  responseActionRecords,
} from './protection';
import { responseActionOptions } from './enforcement';
import { actorPath, handlePath, observationPath, pgpPath, walletPath, ENTITY_PATH } from './entityBundles';

const NO_MONITOR: MonitoringStateRef = {
  status: 'NONE',
  label: 'NOT MONITORED',
  detail: 'No 24×7 monitor is bound to this record. Monitoring binds to this existing id, so nothing is duplicated when one is started.',
};

const DAY_MS = 24 * 60 * 60 * 1000;

const SCORED_ONLY =
  'A score describes signals present on the record. It is not a verdict about intent, attribution or impact on your organisation.';

function daysSince(iso: string | undefined | null): number | null {
  if (!iso) return null;
  const then = new Date(iso).getTime();
  if (!Number.isFinite(then)) return null;
  return Math.round((Date.now() - then) / DAY_MS);
}

function ageLabel(iso: string | undefined | null): string {
  const days = daysSince(iso);
  if (days === null) return 'unknown';
  if (days <= 0) return 'today';
  if (days === 1) return '1 day ago';
  if (days < 30) return `${days} days ago`;
  if (days < 365) return `${Math.round(days / 30)} months ago`;
  return `${(days / 365).toFixed(1)} years ago`;
}

const RECOMMENDATION_LABEL: Record<RecommendedAction, string> = {
  ESCALATE_REPORT: 'Escalate for reporting',
  ENRICH_TTP: 'Enrich the ATT&CK mapping',
  REVIEW_CREDENTIALS: 'Review exposed credentials',
  BLOCK_HANDLE: 'Restrict the identity at its platform',
  QUARANTINE_WALLET: 'Monitor the wallet and prepare an abuse report',
  REVIEW_INFRASTRUCTURE: 'Review infrastructure for blocking',
  MONITOR_ENTITY: 'Continue monitoring',
  ADD_EVIDENCE: 'Attach supporting evidence',
  LINK_TO_INVESTIGATION: 'Link to an investigation',
  PAUSE_MONITOR: 'Adjust the monitor cadence',
  PATCH_ASSET: 'Patch or upgrade the affected asset',
  REVOKE_TRUST: 'Review and revoke the key trust record',
  NO_ACTION: 'No action required yet',
};

const STATUS_TONE: Record<ProtectionStatus, FactTone> = {
  PROTECTED: 'ok',
  PENDING: 'medium',
  AT_RISK: 'critical',
  MONITORED: 'low',
  RESOLVED: 'ok',
  ASSESSED: 'low',
};

const STATUS_LABEL: Record<ProtectionStatus, string> = {
  PROTECTED: 'PROTECTED · VERIFIED',
  PENDING: 'ACTION PENDING',
  AT_RISK: 'AT RISK',
  MONITORED: 'MONITORED',
  RESOLVED: 'NO CURRENT RISK',
  ASSESSED: 'ASSESSED · NO RISK SCORE',
};

export function protectionStatusLabel(status: ProtectionStatus): string {
  return STATUS_LABEL[status];
}

export function protectionStatusTone(status: ProtectionStatus): FactTone {
  return STATUS_TONE[status];
}

// ── Shared relationship resolution ─────────────────────────────

/**
 * Action outcomes that mean a decision exists but has not taken effect. None
 * of them may ever be presented as a control that is actually in place.
 */
const PENDING_ACTION_STATUSES: ReadonlySet<ResponseActionStatus> = new Set<ResponseActionStatus>([
  'AWAITING_INTEGRATION',
  'AWAITING_APPROVAL',
  'SUBMITTED_UNCONFIRMED',
]);

interface EntityContext {
  actorIds: string[];
  alerts: AlertRecord[];
  evidence: EvidenceRecord[];
  investigations: InvestigationRecord[];
  timeline: TimelineRecord[];
  relationships: RelationshipRecord[];
}

function emptyContext(): EntityContext {
  return { actorIds: [], alerts: [], evidence: [], investigations: [], timeline: [], relationships: [] };
}

function pushUnique(list: string[], value: string | null | undefined): void {
  if (value && !list.includes(value)) list.push(value);
}

/**
 * Resolve everything an entity is *already* connected to in the central
 * model. This is what keeps a protection panel consistent with the
 * actor, evidence, alert and investigation pages: they all read the same
 * dataset rows, so none of them can drift.
 */
function contextFor(dataset: IntelligenceDataset, keys: string[], actorIds: string[]): EntityContext {
  const keySet = new Set(keys.filter(Boolean));
  const actorSet = new Set(actorIds);
  const context = emptyContext();

  for (const actor of dataset.actors) {
    if (actorSet.has(actor.id)) pushUnique(context.actorIds, actor.id);
    if (actor.handles.some(value => keySet.has(value))) pushUnique(context.actorIds, actor.id);
    if (actor.pgpFingerprints.some(value => keySet.has(value))) pushUnique(context.actorIds, actor.id);
    if (actor.walletAddrs.some(value => keySet.has(value))) pushUnique(context.actorIds, actor.id);
    if (actor.domains.some(value => keySet.has(value))) pushUnique(context.actorIds, actor.id);
  }

  const allKeys = new Set<string>([...keySet, ...context.actorIds]);
  context.alerts = dataset.alerts.filter(alert =>
    (alert.entityId ? allKeys.has(alert.entityId) : false) ||
    (alert.actorId ? actorSet.has(alert.actorId) : false),
  );
  context.evidence = dataset.evidence.filter(item =>
    (item.relatedActor ? actorSet.has(item.relatedActor) : false) ||
    (item.relatedHandle ? allKeys.has(item.relatedHandle) : false) ||
    (item.relatedInfrastructure ? allKeys.has(item.relatedInfrastructure) : false),
  );
  context.investigations = dataset.investigations.filter(inv =>
    (inv.entityIds ?? []).some(id => allKeys.has(id) || actorSet.has(id)) || actorSet.has(inv.seedActorId),
  );
  context.timeline = dataset.timeline.filter(event => actorSet.has(event.actorId));
  context.relationships = dataset.relationships.filter(rel => keySet.has(rel.sourceEntity) || keySet.has(rel.targetEntity));
  return context;
}

/**
 * The single place that answers "what is this record already connected to".
 *
 * Both the detail panel and the module roll-up go through this function, so a
 * count on a list page can never disagree with the panel behind it. Keep the
 * per-type key resolution here rather than in the individual selectors.
 */
export function relatedContextFor(dataset: IntelligenceDataset, entityType: string, entityId: string): EntityContext {
  switch (entityType) {
    case 'ACTOR': {
      const actor = dataset.lookups.actorsById[entityId];
      if (!actor) return emptyContext();
      return contextFor(
        dataset,
        [actor.id, ...actor.aliases, ...actor.handles, ...actor.walletAddrs, ...actor.pgpFingerprints, ...actor.domains],
        [actor.id],
      );
    }
    case 'HANDLE': {
      const handle = dataset.lookups.handlesById[entityId];
      if (!handle) return emptyContext();
      const identity = (handle.normalized || handle.value).toLowerCase();
      const aliasRecords = dataset.handles.filter(item => item.id !== handle.id && (item.normalized || item.value).toLowerCase() === identity);
      const actors = dataset.actors.filter(
        actor => actor.id === handle.actorId || actor.handles.includes(handle.value) || actor.aliases.includes(handle.value),
      );
      return contextFor(
        dataset,
        [handle.id, handle.value, handle.normalized, ...aliasRecords.map(item => item.id)],
        actors.map(actor => actor.id),
      );
    }
    case 'PGP': {
      const key = dataset.pgpKeys.find(item => item.id === entityId);
      if (!key) return emptyContext();
      return contextFor(dataset, [key.id, key.fingerprint], key.actorIds);
    }
    case 'WALLET': {
      const wallet = dataset.wallets.find(item => item.id === entityId);
      if (!wallet) return emptyContext();
      return contextFor(dataset, [wallet.id, wallet.address], wallet.actorIds);
    }
    case 'INFRASTRUCTURE': {
      const infra = dataset.infrastructure.find(item => item.id === entityId);
      if (!infra) return emptyContext();
      return contextFor(dataset, [infra.id, infra.value], infra.actorIds);
    }
    case 'SOURCE': {
      const source = dataset.sources.find(item => item.id === entityId);
      if (!source) return emptyContext();
      return contextFor(dataset, [source.id, source.name], []);
    }
    case 'OBSERVATION': {
      const observation = dataset.observations.find(item => item.id === entityId);
      if (!observation) return emptyContext();
      const actor = observation.actorId ? dataset.lookups.actorsById[observation.actorId] : null;
      return contextFor(dataset, [observation.id, ...observation.tags], actor ? [actor.id] : []);
    }
    case 'EVIDENCE': {
      const item = dataset.evidence.find(row => row.id === entityId);
      if (!item) return emptyContext();
      return contextFor(dataset, [item.id, item.hash], item.relatedActor ? [item.relatedActor] : []);
    }
    case 'RELATIONSHIP': {
      const rel = dataset.relationships.find(item => item.id === entityId);
      if (!rel) return emptyContext();
      return contextFor(dataset, [rel.id, rel.sourceEntity, rel.targetEntity], []);
    }
    case 'MITRE_TTP': {
      const ttp = dataset.mitreTtps.find(item => item.id === entityId);
      if (!ttp) return emptyContext();
      return contextFor(dataset, [ttp.id, ttp.techniqueId], ttp.actorIds);
    }
    case 'CVE': {
      const cve = dataset.cves.find(item => item.id === entityId);
      if (!cve) return emptyContext();
      return contextFor(dataset, [cve.id, cve.cveId], cve.actorIds);
    }
    case 'VULNERABILITY': {
      const record = dataset.vulnerabilities.find(item => item.id === entityId);
      if (!record) return emptyContext();
      return contextFor(dataset, [record.id, record.vulnerabilityId], record.actorIds);
    }
    case 'WALLET_TRANSACTION': {
      const tx = dataset.walletTransactions.find(item => item.id === entityId);
      if (!tx) return emptyContext();
      const wallet = dataset.wallets.find(item => item.id === tx.walletId);
      return contextFor(dataset, [tx.id, tx.hash, tx.walletId, tx.fromAddress, tx.toAddress], wallet ? wallet.actorIds : []);
    }
    case 'WALLET_CLUSTER': {
      const cluster = dataset.walletClusters.find(item => item.id === entityId);
      if (!cluster) return emptyContext();
      return contextFor(dataset, [cluster.id, ...cluster.walletIds], cluster.actorId ? [cluster.actorId] : []);
    }
    case 'INVESTIGATION': {
      const inv = dataset.investigations.find(item => item.id === entityId);
      if (!inv) return emptyContext();
      return contextFor(dataset, [inv.id, inv.seedActorId, ...(inv.entityIds ?? [])], [inv.seedActorId]);
    }
    default:
      return emptyContext();
  }
}

function alertRefs(alerts: AlertRecord[]): RelatedAlertRef[] {  return alerts
    .filter(alert => alert.status !== 'RESOLVED' && alert.status !== 'DISMISSED')
    .slice()
    .sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1))
    .slice(0, 6)
    .map(alert => ({ id: alert.id, title: alert.title, severity: alert.severity, status: alert.status, raisedAt: alert.timestamp }));
}

function evidenceRefs(evidence: EvidenceRecord[]): RelatedEvidenceRef[] {
  return evidence
    .slice()
    .sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1))
    .slice(0, 8)
    .map(item => ({ id: item.id, evidenceType: item.evidenceType, reliability: item.reliability, timestamp: item.timestamp }));
}

function investigationRefs(investigations: InvestigationRecord[]): RelatedInvestigationRef[] {
  return investigations.slice(0, 5).map(inv => ({ id: inv.id, title: inv.title, status: inv.status }));
}

interface ViewInput {
  entityType: string;
  entityId: string;
  entityLabel: string;
  entityPath?: string;
  headline: string;
  detectionSummary: string;
  facts: ProtectionFact[];
  context: EntityContext;
  caveats?: string[];
  recommendation?: RecommendedAction;
}

function statusFromVerdict(score: ThreatScore | null, entityId: string): ProtectionStatus {
  const verdict = enforcementVerdict(entityId);
  if (verdict === 'VERIFIED') return 'PROTECTED';
  if (verdict === 'DECIDED') return 'PENDING';
  // No numeric score means this record class has no risk model, which is not
  // the same as being safe. Say that instead of implying "no current risk".
  if (!score) return 'ASSESSED';
  if (score.riskLevel === 'INACTIVE') return 'RESOLVED';
  if (score.riskLevel === 'CRITICAL' || score.riskLevel === 'HIGH') return 'AT_RISK';
  return 'MONITORED';
}

/** Assemble the one view shape every module renders. */
function buildView(dataset: IntelligenceDataset, input: ViewInput): ProtectionView {
  const score = computeEntityScore(input.entityType, input.entityId, dataset, dataset.lookups);
  const status = statusFromVerdict(score, input.entityId);
  const recommendation = input.recommendation ?? score?.recommendedAction ?? 'MONITOR_ENTITY';
  const openActions = responseActionRecords(input.entityId);

  return {
    entityType: input.entityType,
    entityId: input.entityId,
    entityLabel: input.entityLabel,
    entityPath: input.entityPath,
    score,
    status,
    headline: input.headline,
    detectionSummary: input.detectionSummary,
    facts: [
      ...input.facts,
      { label: 'Protection status', value: STATUS_LABEL[status], tone: STATUS_TONE[status] },
      { label: 'Last response action', value: lastActionSummary(input.entityId) ?? 'none recorded', tone: openActions.length > 0 ? 'medium' : 'muted' },
    ],
    reasons: score?.reasons ?? [],
    recommendation: {
      action: recommendation,
      label: RECOMMENDATION_LABEL[recommendation],
      detail: score
        ? `Derived from ${score.reasons.length} recorded signal${score.reasons.length === 1 ? '' : 's'} on this entity. An analyst confirms before any control is changed.`
        : 'This module owns no scored entity type, so the recommendation is read from this module’s own detection rules.',
    },
    actions: responseActionOptions(input.entityType, input.entityLabel),
    alerts: alertRefs(input.context.alerts),
    evidence: evidenceRefs(input.context.evidence),
    investigations: investigationRefs(input.context.investigations),
    monitoring: NO_MONITOR,
    records: openActions,
    caveats: input.caveats ?? [],
  };
}

// ── Actor ──────────────────────────────────────────────────────

export function actorProtectionView(dataset: IntelligenceDataset, actorId: string): ProtectionView | null {
  const actor = dataset.lookups.actorsById[actorId];
  if (!actor) return null;
  const context = contextFor(
    dataset,
    [actor.id, ...actor.aliases, ...actor.handles, ...actor.walletAddrs, ...actor.pgpFingerprints, ...actor.domains],
    [actor.id],
  );

  const ttps = dataset.mitreTtps.filter(ttp => ttp.actorIds.includes(actor.id));
  const tactics = [...new Set(ttps.map(ttp => ttp.tactic))];
  const cves = dataset.cves.filter(cve => cve.actorIds.includes(actor.id));
  const liveExploits = cves.filter(cve => cve.exploitationStatus === 'ACTIVE' || cve.exploitationStatus === 'IN_THE_WILD');
  const openAlerts = dataset.alerts.filter(alert => alert.actorId === actor.id && alert.status !== 'RESOLVED' && alert.status !== 'DISMISSED');
  const infra = dataset.infrastructure.filter(item => item.actorIds.includes(actor.id));

  const facts: ProtectionFact[] = [
    { label: 'Operational status', value: actor.status, tone: actor.status === 'ACTIVE' ? 'critical' : actor.status === 'DORMANT' ? 'medium' : 'low' },
    { label: 'Activity level', value: actor.activityLevel },
    { label: 'Attribution confidence', value: `${actor.confidenceScore}%` },
    { label: 'First seen', value: ageLabel(actor.firstSeen) },
    { label: 'Last seen', value: ageLabel(actor.lastSeen) },
    { label: 'ATT&CK techniques mapped', value: `${ttps.length} across ${tactics.length} tactic(s)` },
    { label: 'Linked infrastructure', value: `${infra.length} indicator(s)` },
    { label: 'Dark-web CVEs linked', value: liveExploits.length > 0 ? `${liveExploits.length} reported as actively exploited` : `${cves.length} linked, none confirmed in the wild`, tone: liveExploits.length > 0 ? 'high' : 'ok' },
    { label: 'Open monitoring alerts', value: String(openAlerts.length), tone: openAlerts.length > 0 ? 'high' : 'ok' },
  ];

  return buildView(dataset, {
    entityType: 'ACTOR',
    entityId: actor.id,
    entityLabel: actor.aliases[0] ?? actor.id,
    entityPath: actorPath(actor.id),
    headline: `${actor.aliases[0] ?? actor.id} — ${actor.status.toLowerCase()} ${actor.primaryMotivation.toLowerCase()} operator`,
    detectionSummary: `Detection reads this actor’s recorded activity, ${ttps.length} mapped technique(s), ${cves.length} linked vulnerability record(s) and its open alerts. Nothing here asserts the actor has targeted you.`,
    facts,
    context,
    caveats: [
      SCORED_ONLY,
      'A technique mapping records what a source reported. It is a confirmed behaviour only when the evidence behind it is cited.',
    ],
  });
}

// ── Handle ─────────────────────────────────────────────────────

export function handleProtectionView(dataset: IntelligenceDataset, handleId: string): ProtectionView | null {
  const handle = dataset.lookups.handlesById[handleId];
  if (!handle) return null;
  const identity = (handle.normalized || handle.value).toLowerCase();
  const aliasRecords = dataset.handles.filter(item => item.id !== handle.id && (item.normalized || item.value).toLowerCase() === identity);
  const actors = dataset.actors.filter(
    actor => actor.id === handle.actorId || actor.handles.includes(handle.value) || actor.aliases.includes(handle.value),
  );
  const context = contextFor(dataset, [handle.id, handle.value, handle.normalized, ...aliasRecords.map(item => item.id)], actors.map(actor => actor.id));

  const migrationEvents = dataset.timeline.filter(event =>
    event.type === 'PERSONA_MIGRATION' && `${event.title} ${event.description}`.toLowerCase().includes(identity),
  );
  const handleStrings = new Set<string>();
  for (const actor of actors) for (const value of actor.handles) handleStrings.add(value.toLowerCase());
  const contested = handleStrings.size > 1;

  const facts: ProtectionFact[] = [
    { label: 'Platform', value: handle.platform },
    { label: 'Attribution confidence', value: `${handle.confidence}%` },
    { label: 'First seen', value: ageLabel(handle.firstSeen) },
    { label: 'Last seen', value: ageLabel(handle.lastSeen) },
    { label: 'Cross-platform reuse', value: `${aliasRecords.length} alias record(s) on ${new Set(aliasRecords.map(item => item.platform)).size} platform(s)`, tone: aliasRecords.length > 0 ? 'high' : 'ok' },
    { label: 'Persona-migration events', value: String(migrationEvents.length), tone: migrationEvents.length > 0 ? 'high' : 'ok' },
    { label: 'Attributed actors', value: String(actors.length), tone: actors.length > 1 ? 'critical' : 'low' },
    { label: 'Open alerts', value: String(dataset.alerts.filter(a => a.entityId === handle.id && a.status !== 'RESOLVED').length) },
  ];

  return buildView(dataset, {
    entityType: 'HANDLE',
    entityId: handle.id,
    entityLabel: handle.value,
    entityPath: handlePath(handle.id),
    headline: `@${handle.value} on ${handle.platform}`,
    detectionSummary:
      'Impersonation signals here are reuse of one normalized identity across platforms, persona-migration events naming this identity, and attribution conflict where more than one actor claims it.',
    facts,
    context,
    caveats: [
      'A reused handle string is a correlation, not proof of one person. Shared and abandoned accounts are common and legitimate.',
      contested
        ? 'More than one attributed actor uses this identity string, so the attribution is contested until the links are separated.'
        : 'Handle attribution is only as reliable as the confidence recorded with it, which is bounded by its source.',
    ],
  });
}

// ── PGP ────────────────────────────────────────────────────────

export function pgpProtectionView(dataset: IntelligenceDataset, keyId: string): ProtectionView | null {
  const key = dataset.lookups.pgpById[keyId];
  if (!key) return null;
  const context = contextFor(dataset, [key.id, key.fingerprint], key.actorIds);
  const keyMaterial = dataset.evidence.filter(
    item => item.evidenceType === 'PGP_KEY' && item.provenance.toLowerCase().includes(key.id.toLowerCase()),
  );

  const facts: ProtectionFact[] = [
    { label: 'Attributed actors', value: String(key.actorIds.length), tone: key.actorIds.length > 1 ? 'critical' : 'low' },
    { label: 'Attribution confidence', value: `${key.confidence}%` },
    { label: 'First seen', value: ageLabel(key.firstSeen) },
    { label: 'Last seen', value: ageLabel(key.lastSeen) },
    { label: 'Sources publishing the key', value: String(key.sources.length) },
    { label: 'Stored key material', value: keyMaterial.length > 0 ? `${keyMaterial.length} evidence item(s)` : 'none stored — revocation and expiry cannot be checked' },
    { label: 'Open alerts', value: String(dataset.alerts.filter(a => a.entityId === key.id && a.status !== 'RESOLVED').length) },
  ];

  return buildView(dataset, {
    entityType: 'PGP',
    entityId: key.id,
    entityLabel: key.fingerprint,
    entityPath: pgpPath(key.id),
    headline: `PGP identity ${key.fingerprint.slice(0, 16)}… attributed to ${key.actorIds.length || 'no'} actor(s)`,
    detectionSummary:
      'A PGP key is long-lived and deliberately published, so the strong linking signal is reuse across actors — which indicates a shared operator or a copied key. Both need out-of-band verification before trust changes.',
    facts,
    context,
    recommendation: key.actorIds.length > 1 ? 'REVIEW_CREDENTIALS' : 'MONITOR_ENTITY',
    caveats: [
      'This platform holds no keyserver confirmation. It cannot state that a key is revoked, expired or compromised, and does not: it reports only what the stored material shows.',
      'A fingerprint shared by two actors is a strong linking signal, not evidence that either key is fraudulent. Verify out of band before revoking trust.',
    ],
  });
}

// ── Wallet ─────────────────────────────────────────────────────

export function walletProtectionView(dataset: IntelligenceDataset, walletId: string): ProtectionView | null {
  const wallet = dataset.lookups.walletsById[walletId];
  if (!wallet) return null;
  const context = contextFor(dataset, [wallet.id, wallet.address], wallet.actorIds);
  const transactions = (dataset.walletTransactions ?? []).filter(tx => tx.walletId === wallet.id);
  const flagged = transactions.filter(tx => tx.isFlagged);
  const mixed = transactions.filter(tx => !!tx.mixingService);
  const clusters = (dataset.walletClusters ?? []).filter(cluster => cluster.walletIds.includes(wallet.id));
  const exchanges = (dataset.exchanges ?? []).filter(exchange => exchange.walletAddresses.includes(wallet.address));
  const flaggedReasons = [...new Set(flagged.map(tx => tx.flagReason).filter(Boolean))] as string[];

  const facts: ProtectionFact[] = [
    { label: 'Attributed actors', value: String(wallet.actorIds.length), tone: wallet.actorIds.length > 1 ? 'critical' : 'low' },
    { label: 'Attribution confidence', value: `${wallet.confidence}%` },
    { label: 'Transaction records held', value: String(transactions.length), tone: transactions.length === 0 ? 'muted' : undefined },
    { label: 'Observed transaction count', value: String(wallet.txCount) },
    { label: 'Flagged transactions', value: flaggedReasons.length > 0 ? `${flagged.length} — ${flaggedReasons.join('; ')}` : 'none recorded', tone: flagged.length > 0 ? 'high' : 'ok' },
    { label: 'Mixing-service transfers', value: String(mixed.length), tone: mixed.length > 0 ? 'high' : 'ok' },
    { label: 'Wallet clusters', value: String(clusters.length) },
    { label: 'Exchange exposure', value: exchanges.length > 0 ? exchanges.map(item => item.name).join(', ') : 'none recorded' },
    { label: 'Last seen on chain', value: ageLabel(wallet.lastSeen) },
  ];

  return buildView(dataset, {
    entityType: 'WALLET',
    entityId: wallet.id,
    entityLabel: wallet.address,
    entityPath: walletPath(wallet.id),
    headline: `Wallet ${wallet.address.slice(0, 12)}… linked to ${wallet.actorIds.length || 'no'} actor(s)`,
    detectionSummary:
      transactions.length > 0
        ? `Risk is read from ${transactions.length} recorded transaction(s): ${flagged.length} flagged and ${mixed.length} routed through a mixing service.`
        : 'No transaction records are stored for this address, so no flow pattern was computed. An aggregate count alone cannot be analysed.',
    facts,
    context,
    recommendation: flagged.length + mixed.length > 0 ? 'QUARANTINE_WALLET' : 'MONITOR_ENTITY',
    caveats: [
      'This platform cannot freeze, seize or block a public-chain address. The available actions are monitoring, alerting, investigation and — where an authorised exchange relationship exists — an abuse report.',
      transactions.length === 0
        ? 'Any flow statistics for this address describe only the transactions this model holds, which is not the address’s history.'
        : 'Flow statistics describe only the transactions this model holds.',
    ],
  });
}

// ── Infrastructure ─────────────────────────────────────────────

/**
 * Whether a network control could actually act on this value, and what
 * that means operationally. An onion address is a domain by shape but not
 * by reachability, so a DNS filter would never see it.
 */
function enforceableClass(isIp: boolean, isDomain: boolean, isOnion: boolean): string {
  if (isIp) return 'IP address — firewall and proxy rules apply';
  if (isOnion) return 'onion address — not reachable by DNS or perimeter filtering';
  if (isDomain) return 'domain — DNS, mail and proxy rules apply';
  return 'not a network indicator — no address-control workflow applies';
}

export function infrastructureProtectionView(dataset: IntelligenceDataset, infraId: string): ProtectionView | null {
  const infra = dataset.lookups.infraById[infraId];
  if (!infra) return null;
  const context = contextFor(dataset, [infra.id, infra.value], infra.actorIds);
  const siblings = dataset.infrastructure.filter(item => item.id !== infra.id && item.tlsIssuer && infra.tlsIssuer && item.tlsIssuer === infra.tlsIssuer);
  const sameHosting = dataset.infrastructure.filter(item => item.id !== infra.id && infra.hostingProvider && item.hostingProvider === infra.hostingProvider);
  const cves = dataset.cves.filter(cve => cve.infrastructureIds.includes(infra.id));
  const valueType = infra.value.replace(/^www\./i, '');
  const isIp = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(valueType);
  const isDomain = /^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i.test(valueType);
  const isOnion = /(\.onion|\.i2p)$/i.test(valueType);

  const facts: ProtectionFact[] = [
    { label: 'Indicator type', value: infra.type },
    { label: 'Enforceable class', value: enforceableClass(isIp, isDomain, isOnion), tone: isIp || (isDomain && !isOnion) ? 'low' : 'muted' },
    { label: 'Actors using it', value: String(infra.actorIds.length), tone: infra.actorIds.length > 1 ? 'critical' : 'low' },
    { label: 'First seen', value: ageLabel(infra.firstSeen) },
    { label: 'Last seen', value: ageLabel(infra.lastSeen) },
    { label: 'Hosting / ASN / country', value: [infra.hostingProvider, infra.asn, infra.country].filter(Boolean).join(' · ') || 'not recorded' },
    { label: 'Shared TLS issuer', value: siblings.length > 0 ? `${siblings.length} other indicator(s)` : 'none', tone: siblings.length > 0 ? 'medium' : 'ok' },
    { label: 'Shared hosting provider', value: sameHosting.length > 0 ? `${sameHosting.length} other indicator(s)` : 'none' },
    { label: 'Linked CVEs', value: cves.length > 0 ? String(cves.length) : 'none' },
    { label: 'Open alerts', value: String(dataset.alerts.filter(a => a.entityId === infra.id && a.status !== 'RESOLVED').length) },
  ];

  return buildView(dataset, {
    entityType: 'INFRASTRUCTURE',
    entityId: infra.id,
    entityLabel: infra.value,
    entityPath: ENTITY_PATH.infrastructure,
    headline: `${infra.type} ${infra.value} used by ${infra.actorIds.length || 'no'} actor(s)`,
    detectionSummary: isIp || isDomain
      ? 'This indicator is enforceable, so a blocking workflow is offered — and it only reports success once the configured control plane confirms it.'
      : 'This value is not an IP, domain or URL, so no network control can act on it directly. Only monitoring, alerting and takedown workflows apply.',
    facts,
    context,
    recommendation: 'REVIEW_INFRASTRUCTURE',
    caveats: [
      'Use by an actor is an attribution recorded in this model. It is not proof of who controlled the host at any given moment, and it says nothing about whether the host is malicious.',
      'Shared hosting or a shared TLS issuer is a weak signal: many unrelated services share both. Treat it as a lead, not a finding.',
      isOnion ? 'An onion address is not resolvable by ordinary DNS filtering, so a DNS-based block will not cover it.' : '',
    ].filter(Boolean),
  });
}

// ── Source ─────────────────────────────────────────────────────

export function sourceProtectionView(dataset: IntelligenceDataset, sourceId: string): ProtectionView | null {
  const source = dataset.lookups.sourcesById[sourceId];
  if (!source) return null;
  const context = contextFor(dataset, [source.id, source.name], []);
  const evidence = dataset.evidence.filter(item => item.source === source.name || item.source === source.id);
  const observations = dataset.observations.filter(obs => obs.source === source.name || obs.source === source.id);
  const timeline = dataset.timeline.filter(event => event.source === source.name);
  const stalenessDays = daysSince(source.lastObserved);
  const freshness: FactTone = stalenessDays === null ? 'muted' : stalenessDays <= 7 ? 'ok' : stalenessDays <= 30 ? 'medium' : 'high';

  const facts: ProtectionFact[] = [
    { label: 'Source type', value: source.type },
    { label: 'Reliability', value: `R${source.reliabilityScore}`, tone: source.reliabilityScore >= 85 ? 'ok' : source.reliabilityScore >= 70 ? 'medium' : 'high' },
    { label: 'Operational status', value: source.status, tone: source.status === 'ACTIVE' ? 'low' : source.status === 'DORMANT' ? 'medium' : 'high' },
    { label: 'Activity level', value: source.activityLevel },
    { label: 'Data freshness', value: stalenessDays === null ? 'unknown' : `last observed ${stalenessDays} day(s) ago`, tone: freshness },
    { label: 'Actors attributed here', value: String(source.actorCount) },
    { label: 'Indicators claimed', value: String(source.indicatorCount) },
    { label: 'Evidence held', value: `${evidence.length} item(s) · ${observations.length} observation(s)` },
    { label: 'Timeline events sourced', value: String(timeline.length) },
  ];

  return buildView(dataset, {
    entityType: 'SOURCE',
    entityId: source.id,
    entityLabel: source.name,
    entityPath: ENTITY_PATH.sources,
    headline: `${source.name} — ${source.status.toLowerCase()} ${source.type.toLowerCase().replace(/_/g, ' ')}, R${source.reliabilityScore}`,
    detectionSummary: 'Collection health is read from the source’s own reliability, status and freshness, then weighted against how much of the dataset depends on it.',
    facts,
    context,
    recommendation: source.status === 'ACTIVE' ? 'MONITOR_ENTITY' : 'MONITOR_ENTITY',
    caveats: [
      'Reliability is the score recorded for this source. It is a collection-quality judgement, not a guarantee that any individual item from it is accurate.',
      stalenessDays !== null && stalenessDays > 30
        ? 'This source has not been observed recently, so absence of new intelligence from it is not evidence that activity has stopped.'
        : '',
    ].filter(Boolean),
  });
}

// ── Observation ────────────────────────────────────────────────

export function observationProtectionView(dataset: IntelligenceDataset, observationId: string): ProtectionView | null {
  const observation = dataset.lookups.observationsById[observationId];
  if (!observation) return null;
  const actor = observation.actorId ? dataset.lookups.actorsById[observation.actorId] ?? null : null;
  const context = contextFor(dataset, [observation.id, ...observation.tags], actor ? [actor.id] : []);
  const indicators = extractIndicators(observation.content);
  const anomalyTypes: Record<string, string> = {
    HANDLE_OBSERVED: 'New or changed identity observed',
    NEW_PLATFORM_ACTIVITY: 'Activity on a platform not previously linked to this actor',
    INFRASTRUCTURE_CHANGE: 'Infrastructure changed for a known actor',
    PERSONA_CHANGE: 'Persona, alias or behavioural profile changed',
    RELATIONSHIP_DISCOVERED: 'New relationship surfaced by collection',
    NEW_EVIDENCE: 'New evidence attached',
    BEHAVIOR_ANOMALY: 'Behaviour departs from the recorded profile',
  };
  const isAnomaly = observation.observationType === 'BEHAVIOR_ANOMALY' || observation.observationType === 'PERSONA_CHANGE';

  const facts: ProtectionFact[] = [
    { label: 'Observation type', value: observation.observationType.replace(/_/g, ' '), tone: isAnomaly ? 'high' : 'low' },
    { label: 'Signal meaning', value: anomalyTypes[observation.observationType] ?? 'recorded observation' },
    { label: 'Platform', value: observation.platform ?? 'not specified' },
    { label: 'Confidence', value: `${observation.confidence}%` },
    { label: 'Captured', value: ageLabel(observation.timestamp) },
    { label: 'Provenance', value: observation.dataState.replace(/_/g, ' ') },
    { label: 'Indicators extracted from text', value: indicators.length > 0 ? indicators.map(kind => `${kind} ×1`).join(' · ') : 'none', tone: indicators.length > 0 ? 'medium' : 'muted' },
    { label: 'Evidence linked', value: String(observation.evidenceIds.length) },
    { label: 'Attributed actor', value: actor ? `${actor.id} (${actor.aliases[0] ?? ''})` : 'unattributed', tone: actor ? 'low' : 'muted' },
  ];

  return buildView(dataset, {
    entityType: 'OBSERVATION',
    entityId: observation.id,
    entityLabel: observation.id,
    entityPath: observationPath(observation.id),
    headline: `${observation.observationType.replace(/_/g, ' ')} — ${observation.source}`,
    detectionSummary: `The observation text yields ${indicators.length} indicator class(es) and is read against ${observation.evidenceIds.length} linked evidence item(s) and ${actor ? `actor ${actor.id}` : 'no attributed actor'}.`,
    facts,
    context,
    recommendation: isAnomaly ? 'ESCALATE_REPORT' : 'MONITOR_ENTITY',
    caveats: [
      'Extraction reads the raw observation text against entities already stored. It resolves references; it never creates an entity from a string.',
      'An observation is a record of what a source published. It is not independently verified fact, and the source’s reliability bounds how far it can be read.',
    ],
  });
}

const IP_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const DOMAIN_PATTERN = /\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|xyz|top|onion|info|biz|co|uk|de|nl)\b/gi;
const WALLET_PATTERN = /\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,62}|0x[a-fA-F0-9]{40})\b/g;
const HANDLE_PATTERN = /@[A-Za-z0-9_.-]{3,}/g;
const HASH_PATTERN = /\b[a-fA-F0-9]{64}\b/g;

/**
 * Indicator extraction over observation text, reporting only classes and
 * never asserting what they are. It matches against the same normalized
 * forms the dataset uses, so a match here is a reference the model can
 * already resolve.
 */
export function extractIndicators(content: string): string[] {
  const text = content ?? '';
  const found = new Set<string>();
  if (IP_PATTERN.test(text)) found.add('IP');
  IP_PATTERN.lastIndex = 0;
  if (DOMAIN_PATTERN.test(text)) found.add('DOMAIN');
  DOMAIN_PATTERN.lastIndex = 0;
  if (WALLET_PATTERN.test(text)) found.add('WALLET');
  WALLET_PATTERN.lastIndex = 0;
  if (HANDLE_PATTERN.test(text)) found.add('HANDLE');
  HANDLE_PATTERN.lastIndex = 0;
  if (HASH_PATTERN.test(text)) found.add('SHA-256');
  HASH_PATTERN.lastIndex = 0;
  return [...found];
}

// ── Evidence ───────────────────────────────────────────────────

const TRUSTED_HASH_ALGORITHM = 'SHA-256';

export function evidenceProtectionView(dataset: IntelligenceDataset, evidenceId: string): ProtectionView | null {
  const item = dataset.lookups.evidenceById[evidenceId];
  if (!item) return null;
  const context = contextFor(dataset, [item.id, item.hash], item.relatedActor ? [item.relatedActor] : []);
  const indicators = extractIndicators(`${item.provenance} ${item.description ?? ''}`);
  const hashLength = item.hash.length;
  const digestAlgorithm = /^[a-fA-F0-9]{64}$/.test(item.hash) ? TRUSTED_HASH_ALGORITHM : /^[a-fA-F0-9]{40}$/.test(item.hash) ? 'SHA-1 (weak)' : /^[a-fA-F0-9]{32}$/.test(item.hash) ? 'MD5 (unusable)' : 'unrecognised digest';
  const citingRelationships = dataset.relationships.filter(rel => rel.evidenceIds.includes(item.id));

  const facts: ProtectionFact[] = [
    { label: 'Evidence type', value: item.evidenceType.replace(/_/g, ' ') },
    { label: 'Reliability grade', value: `R${item.reliability}`, tone: item.reliability >= 85 ? 'ok' : item.reliability >= 70 ? 'medium' : 'high' },
    { label: 'Confidence', value: `${item.confidence}%` },
    { label: 'Digest algorithm', value: digestAlgorithm, tone: digestAlgorithm === TRUSTED_HASH_ALGORITHM ? 'ok' : 'high' },
    { label: 'Digest length', value: `${hashLength} characters` },
    { label: 'Collected', value: ageLabel(item.collectionTimestamp ?? item.timestamp) },
    { label: 'Provenance', value: item.provenance },
    { label: 'Indicators in the record text', value: indicators.length > 0 ? indicators.join(' · ') : 'none', tone: indicators.length > 0 ? 'medium' : 'muted' },
    { label: 'Cited by relationships', value: String(citingRelationships.length), tone: citingRelationships.length > 0 ? 'ok' : 'medium' },
  ];

  return buildView(dataset, {
    entityType: 'EVIDENCE',
    entityId: item.id,
    entityLabel: item.id,
    entityPath: ENTITY_PATH.evidence,
    headline: `${item.evidenceType.replace(/_/g, ' ')} evidence R${item.reliability} — ${item.source}`,
    detectionSummary:
      'Integrity is judged from the stored digest, and the record is scored on what corroborates it: which relationships cite it, which actor it is attributed to, and what indicators its text carries.',
    facts,
    context,
    recommendation: citingRelationships.length > 0 ? 'LINK_TO_INVESTIGATION' : 'ADD_EVIDENCE',
    caveats: [
      'No malware scanning is performed by this panel. A verdict from a scanner would come from an authorised endpoint or sandbox integration, and until one is configured the item is unscanned.',
      'Indicators found in the text are references, not confirmed malicious artefacts. Resolve them against the dataset before acting.',
      digestAlgorithm !== TRUSTED_HASH_ALGORITHM
        ? `The stored digest is a ${digestAlgorithm}. Integrity can be re-checked for consistency but not collision-resistant against an adversary.`
        : '',
    ].filter(Boolean),
  });
}

// ── Relationship ───────────────────────────────────────────────

export function relationshipProtectionView(dataset: IntelligenceDataset, relationshipId: string): ProtectionView | null {
  const rel = dataset.lookups.relationshipsById[relationshipId];
  if (!rel) return null;
  const context = contextFor(dataset, [rel.id, rel.sourceEntity, rel.targetEntity], []);
  const against = rel.against ?? [];
  const supporting = rel.supporting ?? [];
  const corroboration = supporting.length - against.length;

  const facts: ProtectionFact[] = [
    { label: 'Relationship type', value: rel.type.replace(/_/g, ' ') },
    { label: 'Endpoints', value: `${rel.sourceType} → ${rel.targetType}` },
    { label: 'Confidence', value: `${rel.confidence}%`, tone: rel.confidence >= 80 ? 'low' : rel.confidence >= 60 ? 'medium' : 'high' },
    { label: 'First observed', value: ageLabel(rel.firstObserved) },
    { label: 'Last observed', value: ageLabel(rel.lastObserved) },
    { label: 'Supporting indicators', value: String(supporting.length), tone: supporting.length > 0 ? 'ok' : 'high' },
    { label: 'Indicators against', value: String(against.length), tone: against.length > 0 ? 'high' : 'ok' },
    { label: 'Corroboration balance', value: corroboration > 0 ? `+${corroboration}` : String(corroboration), tone: corroboration > 0 ? 'ok' : 'high' },
    { label: 'Cited evidence', value: String((rel.evidenceIds ?? []).length) },
  ];

  return buildView(dataset, {
    entityType: 'RELATIONSHIP',
    entityId: rel.id,
    entityLabel: `${rel.sourceEntity} → ${rel.targetEntity}`,
    entityPath: ENTITY_PATH.graph,
    headline: `${rel.type.replace(/_/g, ' ')} — ${rel.sourceEntity} → ${rel.targetEntity} (${rel.confidence}%)`,
    detectionSummary: 'This link is treated as risk-relevant when its recorded confidence is high and its supporting evidence outnumbers the recorded counter-indicators.',
    facts,
    context,
    recommendation: rel.confidence >= 80 && supporting.length > 0 ? 'REVIEW_INFRASTRUCTURE' : 'MONITOR_ENTITY',
    caveats: [
      'A stored relationship is a correlation, not an established fact. It should be read as “the model links these because of the recorded reasons”, never as proof that the two are the same operator.',
      against.length > 0 ? 'This link has recorded counter-indicators. Read both sides before treating it as risk-relevant.' : '',
    ].filter(Boolean),
  });
}

// ── ATT&CK technique ───────────────────────────────────────────

export function ttpProtectionView(dataset: IntelligenceDataset, ttpId: string): ProtectionView | null {
  const ttp: MitreTtpRecord | undefined =
    dataset.lookups.mitreTtpsById[ttpId] ?? dataset.mitreTtps.find(item => item.techniqueId === ttpId);
  if (!ttp) return null;
  const context = contextFor(dataset, [ttp.id, ttp.techniqueId], ttp.actorIds);
  const infra = dataset.infrastructure.filter(item => ttp.infrastructureIds.includes(item.id));
  const dataSources = [...new Set(ttp.dataSources)];

  const facts: ProtectionFact[] = [
    { label: 'Tactic', value: ttp.tactic.replace(/_/g, ' ') },
    { label: 'Mapping confidence', value: `${ttp.confidence}%`, tone: ttp.confidence >= 80 ? 'low' : ttp.confidence >= 55 ? 'medium' : 'high' },
    { label: 'Actors mapped', value: String(ttp.actorIds.length), tone: ttp.actorIds.length > 1 ? 'medium' : 'low' },
    { label: 'Platforms', value: ttp.platforms.join(', ') || 'not specified' },
    { label: 'Detectable data sources', value: dataSources.length > 0 ? dataSources.join(', ') : 'none recorded', tone: dataSources.length > 0 ? 'ok' : 'high' },
    { label: 'Required permissions', value: ttp.permissionsRequired.join(', ') || 'none recorded' },
    { label: 'Associated infrastructure', value: String(infra.length) },
    { label: 'Citing evidence', value: String(ttp.evidenceIds.length) },
    { label: 'Last observed', value: ageLabel(ttp.lastSeen) },
  ];

  return buildView(dataset, {
    entityType: 'MITRE_TTP',
    entityId: ttp.id,
entityLabel: `${ttp.techniqueId} ${ttp.name}`,
      entityPath: ENTITY_PATH.attack,
    headline: `${ttp.techniqueId} — ${ttp.name} (${ttp.tactic.replace(/_/g, ' ')})`,
    detectionSummary: `Detection coverage is read from the ${dataSources.length} data source(s) ATT&CK records for this technique. Coverage is a property of the framework mapping, not a statement that this environment is being monitored for it.`,
    facts,
    context,
    recommendation: 'ENRICH_TTP',
    caveats: [
      'A mapping records that a source attributed this technique to these actors. It is unconfirmed unless evidence behind it is cited and that citation is in the record.',
      'Listed data sources are what the framework says could detect the technique. This platform does not hold telemetry from those sources, so it cannot report whether detection is actually happening.',
    ],
  });
}

// ── CVE / vulnerability ────────────────────────────────────────

export function cveProtectionView(dataset: IntelligenceDataset, cveId: string): ProtectionView | null {
  const cve: CveRecordRecord | undefined =
    dataset.lookups.cvesById[cveId] ?? dataset.lookups.cvesByCveId[cveId] ?? dataset.cves.find(item => item.cveId === cveId);
  if (!cve) return null;
  const context = contextFor(dataset, [cve.id, cve.cveId], cve.actorIds);
  const live = cve.exploitationStatus === 'ACTIVE' || cve.exploitationStatus === 'IN_THE_WILD';
  const infrastructure = dataset.infrastructure.filter(item => cve.infrastructureIds.includes(item.id));
  const actors = cve.actorIds.map(id => dataset.lookups.actorsById[id]).filter(Boolean) as ActorRecord[];

  const facts: ProtectionFact[] = [
    { label: 'CVSS', value: `${cve.cvssScore}/10 · ${cve.severity}`, tone: cve.severity === 'CRITICAL' ? 'critical' : cve.severity === 'HIGH' ? 'high' : cve.severity === 'MEDIUM' ? 'medium' : 'low' },
    { label: 'Exploitation status', value: cve.exploitationStatus.replace(/_/g, ' '), tone: live ? 'critical' : 'muted' },
    { label: 'Weakness classes', value: cve.cweTypes.map(item => item.replace(/_/g, ' ')).join(', ') || 'not recorded' },
    { label: 'Affected software', value: cve.affectedSoftware.join(', ') || 'not recorded' },
    { label: 'Dark-web sources mentioning it', value: String(cve.darkWebSources.length) },
    { label: 'Actors linked', value: actors.length > 0 ? actors.map(actor => actor.id).join(', ') : 'none', tone: actors.length > 0 ? 'high' : 'ok' },
    { label: 'Infrastructure linked', value: String(infrastructure.length) },
    { label: 'Citing evidence', value: String(cve.evidenceIds.length) },
    { label: 'Remediation status', value: 'not verified — this platform holds no asset inventory or patch telemetry', tone: 'muted' },
  ];

  return buildView(dataset, {
    entityType: 'CVE',
    entityId: cve.id,
entityLabel: cve.cveId,
      entityPath: ENTITY_PATH.attack,
    headline: `${cve.cveId} — ${cve.severity} (CVSS ${cve.cvssScore})`,
    detectionSummary: 'Applicability is assessed only against what is recorded here: the affected software it names, and the infrastructure and actors this model already links to it.',
    facts,
    context,
    recommendation: 'PATCH_ASSET' as RecommendedAction,
    caveats: [
      'No asset is called vulnerable here. A dark-web mention of a CVE is not evidence that any asset runs the affected software, and this model holds no asset inventory to check against.',
      'Remediation is not reported as done. Verification requires patch telemetry or a scan from a configured integration, neither of which this platform performs.',
      live ? 'Exploitation status is reported by the sources that published it. Treat in-the-wild claims as reported, not confirmed by this platform.' : '',
    ].filter(Boolean),
  });
}

export function vulnerabilityProtectionView(dataset: IntelligenceDataset, vulnerabilityId: string): ProtectionView | null {
  const record: VulnerabilityRecordRecord | undefined =
    dataset.lookups.vulnerabilitiesById[vulnerabilityId] ?? dataset.vulnerabilities.find(item => item.vulnerabilityId === vulnerabilityId);
  if (!record) return null;
  const context = contextFor(dataset, [record.id, record.vulnerabilityId], record.actorIds);
  const live = record.exploitationStatus === 'ACTIVE' || record.exploitationStatus === 'IN_THE_WILD' || record.isZeroDay;

  const facts: ProtectionFact[] = [
    { label: 'Severity', value: `${record.severity}${record.cvssScore !== undefined ? ` · CVSS ${record.cvssScore}` : ''}`, tone: record.severity === 'CRITICAL' ? 'critical' : record.severity === 'HIGH' ? 'high' : 'medium' },
    { label: 'Exploitation status', value: record.exploitationStatus.replace(/_/g, ' '), tone: live ? 'critical' : 'muted' },
    { label: 'Zero-day', value: record.isZeroDay ? 'yes — no vendor patch known' : 'no', tone: record.isZeroDay ? 'critical' : 'ok' },
    { label: 'Weakness classes', value: (record.cweIds ?? []).join(', ') || 'not recorded' },
    { label: 'Categories', value: record.categories.map(item => item.replace(/_/g, ' ')).join(', ') || 'not recorded' },
    { label: 'Dark-web sources', value: String(record.darkWebSources.length) },
    { label: 'Actors linked', value: record.actorIds.length > 0 ? record.actorIds.join(', ') : 'none', tone: record.actorIds.length > 0 ? 'high' : 'ok' },
    { label: 'Remediation status', value: 'not verified — no asset or patch telemetry available', tone: 'muted' },
  ];

  return buildView(dataset, {
    entityType: 'VULNERABILITY',
    entityId: record.id,
entityLabel: record.vulnerabilityId,
      headline: `${record.vulnerabilityId} — ${record.severity}${record.isZeroDay ? ' · zero-day' : ''}`,
    detectionSummary: 'Applicability is read from the affected categories and the infrastructure and actors this model already links to it. No asset inventory is held here, so no host is called affected.',
    facts,
    context,
    recommendation: 'PATCH_ASSET' as RecommendedAction,
    caveats: [
      'No asset is called vulnerable without asset evidence, and this platform holds none. Affectedness must be confirmed against a real inventory before any remediation claim.',
'Remediation is never reported as complete without verification from a scan or patch telemetry source.',
        'This record has no detail view of its own in the product, so no "open record" link is offered. Track the affected asset in the inventory and record the outcome against this record.',
      ],
  });
}

// ── Transaction / cluster ──────────────────────────────────────

export function transactionProtectionView(dataset: IntelligenceDataset, transactionId: string): ProtectionView | null {
  const tx: WalletTransactionRecord | undefined = dataset.lookups.walletTransactionsById[transactionId];
  if (!tx) return null;
  const wallet = dataset.lookups.walletsById[tx.walletId];
  const siblings = (dataset.walletTransactions ?? []).filter(item => item.walletId === tx.walletId);
  const context = contextFor(dataset, [tx.id, tx.hash, tx.walletId, tx.fromAddress, tx.toAddress], wallet ? wallet.actorIds : []);
  const cluster = (dataset.walletClusters ?? []).find(item => item.id === tx.clusterId);

  const facts: ProtectionFact[] = [
    { label: 'Network', value: tx.network },
    { label: 'Direction', value: tx.direction },
    { label: 'Status', value: tx.status.replace(/_/g, ' ') },
    { label: 'Amount', value: `${tx.amount} ${tx.currency}` },
    { label: 'Flagged', value: tx.isFlagged ? `yes — ${tx.flagReason ?? 'no reason recorded'}` : 'no', tone: tx.isFlagged ? 'high' : 'ok' },
    { label: 'Mixing service', value: tx.mixingService ?? 'none recorded', tone: tx.mixingService ? 'high' : 'ok' },
    { label: 'Wallet', value: wallet ? `${wallet.id} · ${wallet.address.slice(0, 12)}…` : tx.walletId },
    { label: 'Transactions on this wallet', value: String(siblings.length) },
    { label: 'Cluster', value: cluster ? `${cluster.id} (${cluster.method.replace(/_/g, ' ')}, ${cluster.confidence}%)` : 'none' },
    { label: 'Timestamp', value: new Date(tx.timestamp).toLocaleString() },
  ];

  return buildView(dataset, {
    entityType: 'WALLET_TRANSACTION',
    entityId: tx.id,
    entityLabel: tx.hash,
    entityPath: ENTITY_PATH.wallets,
    headline: `${tx.direction} ${tx.amount} ${tx.currency} on ${tx.network}`,
    detectionSummary:
      'Suspicion here comes from the recorded transaction itself — a flag, a mixing service, or a position in a cluster — never from the address alone.',
    facts,
    context,
    recommendation: tx.isFlagged || tx.mixingService ? 'ESCALATE_REPORT' : 'MONITOR_ENTITY',
    caveats: [
      'A flagged transaction reflects the recorded flag reason. Flagging is an analyst or source judgement, not a proven illicit transfer.',
      'This platform cannot reverse, freeze or seize an on-chain transaction. Available actions are monitoring, alerting and investigation.',
    ],
  });
}

export function clusterProtectionView(dataset: IntelligenceDataset, clusterId: string): ProtectionView | null {
  const cluster: WalletClusterRecord | undefined = dataset.lookups.walletClustersById[clusterId];
  if (!cluster) return null;
  const wallets = cluster.walletIds.map(id => dataset.lookups.walletsById[id]).filter(Boolean) as WalletRecord[];
  const transactions = (dataset.walletTransactions ?? []).filter(tx => cluster.walletIds.includes(tx.walletId));
  const flagged = transactions.filter(tx => tx.isFlagged);
  const context = contextFor(dataset, [cluster.id, ...cluster.walletIds], cluster.actorId ? [cluster.actorId] : []);

  const facts: ProtectionFact[] = [
    { label: 'Clustering method', value: cluster.method.replace(/_/g, ' ') },
    { label: 'Cluster confidence', value: `${cluster.confidence}%`, tone: cluster.confidence >= 80 ? 'low' : cluster.confidence >= 60 ? 'medium' : 'high' },
    { label: 'Wallets in cluster', value: String(cluster.walletIds.length) },
    { label: 'Attributed actor', value: cluster.actorId ?? 'unattributed', tone: cluster.actorId ? 'low' : 'muted' },
    { label: 'Transactions observed', value: String(transactions.length) },
    { label: 'Flagged transactions', value: String(flagged.length), tone: flagged.length > 0 ? 'high' : 'ok' },
    { label: 'First seen', value: ageLabel(cluster.firstSeen) },
    { label: 'Last seen', value: ageLabel(cluster.lastSeen) },
    { label: 'Reasoning recorded', value: cluster.reasoning },
  ];

  return buildView(dataset, {
    entityType: 'WALLET_CLUSTER',
    entityId: cluster.id,
    entityLabel: cluster.id,
    entityPath: ENTITY_PATH.wallets,
    headline: `Cluster ${cluster.id} — ${cluster.walletIds.length} wallet(s), ${cluster.confidence}% confidence`,
    detectionSummary: `Cluster risk is read from ${wallets.length} linked wallet(s) and ${transactions.length} transaction record(s), ${flagged.length} of which are flagged.`,
    facts,
    context,
    recommendation: flagged.length > 0 ? 'ESCALATE_REPORT' : 'MONITOR_ENTITY',
    caveats: [
      'Cluster membership is a heuristic result from the recorded method. Wallets in one cluster are not necessarily controlled by one person.',
      'Cluster risk is not a legal or financial determination. It is an investigative lead.',
    ],
  });
}

// ── Investigation ──────────────────────────────────────────────

export function investigationProtectionView(dataset: IntelligenceDataset, investigationId: string): ProtectionView | null {
  const inv = dataset.lookups.investigationsById[investigationId];
  if (!inv) return null;
  const context = contextFor(dataset, [inv.id, inv.seedActorId, ...(inv.entityIds ?? [])], [inv.seedActorId]);
  const actors = [inv.seedActorId, ...inv.steps.flatMap(step => step.actorIds)]
    .filter((id, index, list) => list.indexOf(id) === index)
    .map(id => dataset.lookups.actorsById[id])
    .filter(Boolean) as ActorRecord[];
  const openAlerts = context.alerts.filter(alert => alert.status !== 'RESOLVED' && alert.status !== 'DISMISSED');
  const unmitigated = actors.filter(actor => {
    const score = computeEntityScore('ACTOR', actor.id, dataset, dataset.lookups);
    return !score || score.riskLevel === 'CRITICAL' || score.riskLevel === 'HIGH';
  });

  const facts: ProtectionFact[] = [
    { label: 'Case status', value: inv.status, tone: inv.status === 'ACTIVE' ? 'medium' : inv.status === 'PENDING' ? 'low' : 'ok' },
    { label: 'Analyst', value: inv.analyst },
    { label: 'Opened', value: ageLabel(inv.createdAt) },
    { label: 'Last updated', value: ageLabel(inv.updatedAt) },
    { label: 'Entities in scope', value: String(new Set([inv.seedActorId, ...(inv.entityIds ?? [])]).size) },
    { label: 'Actors at CRITICAL/HIGH risk', value: unmitigated.length > 0 ? unmitigated.map(actor => actor.id).join(', ') : 'none', tone: unmitigated.length > 0 ? 'critical' : 'ok' },
    { label: 'Open alerts in scope', value: String(openAlerts.length), tone: openAlerts.length > 0 ? 'high' : 'ok' },
    { label: 'Evidence cited', value: String(new Set(inv.steps.flatMap(step => step.evidenceIds)).size) },
    { label: 'Response actions recorded', value: String(responseActionRecords().filter(action => (inv.entityIds ?? []).includes(action.entityId) || action.entityId === inv.seedActorId).length) },
  ];

  return buildView(dataset, {
    entityType: 'INVESTIGATION',
    entityId: inv.id,
    entityLabel: `${inv.id} ${inv.title}`,
    entityPath: ENTITY_PATH.investigations,
    headline: `${inv.id} — ${inv.title} (${inv.status})`,
    detectionSummary: 'Detection events, findings and response outcomes already attached to this case are surfaced here without altering the case workflow or its history.',
    facts,
    context,
    recommendation: unmitigated.length > 0 ? 'ESCALATE_REPORT' : 'MONITOR_ENTITY',
    caveats: [
      'Response actions recorded against entities in this case are shown for context. The investigation workflow, its steps and its history are unchanged.',
      'A closed case is not a remediated threat. Closure records an outcome, not verified containment.',
    ],
  });
}

// ── Dispatcher ─────────────────────────────────────────────────

export type ProtectionEntityType =
  | 'ACTOR'
  | 'HANDLE'
  | 'PGP'
  | 'WALLET'
  | 'INFRASTRUCTURE'
  | 'SOURCE'
  | 'OBSERVATION'
  | 'EVIDENCE'
  | 'RELATIONSHIP'
  | 'MITRE_TTP'
  | 'CVE'
  | 'VULNERABILITY'
  | 'WALLET_TRANSACTION'
  | 'WALLET_CLUSTER'
  | 'INVESTIGATION';

/**
 * One entry point, so a page never has to know which module owns which
 * detection logic. Unknown ids return null rather than an empty shell that
 * could be mistaken for "nothing detected".
 */
export function protectionView(dataset: IntelligenceDataset, entityType: string, entityId: string): ProtectionView | null {
  switch (entityType) {
    case 'ACTOR': return actorProtectionView(dataset, entityId);
    case 'HANDLE': return handleProtectionView(dataset, entityId);
    case 'PGP':
    case 'PGP_KEY': return pgpProtectionView(dataset, entityId);
    case 'WALLET': return walletProtectionView(dataset, entityId);
    case 'INFRASTRUCTURE': return infrastructureProtectionView(dataset, entityId);
    case 'SOURCE': return sourceProtectionView(dataset, entityId);
    case 'OBSERVATION': return observationProtectionView(dataset, entityId);
    case 'EVIDENCE': return evidenceProtectionView(dataset, entityId);
    case 'RELATIONSHIP': return relationshipProtectionView(dataset, entityId);
    case 'MITRE_TTP': return ttpProtectionView(dataset, entityId);
    case 'CVE': return cveProtectionView(dataset, entityId);
    case 'VULNERABILITY': return vulnerabilityProtectionView(dataset, entityId);
    case 'WALLET_TRANSACTION': return transactionProtectionView(dataset, entityId);
    case 'WALLET_CLUSTER': return clusterProtectionView(dataset, entityId);
    case 'INVESTIGATION': return investigationProtectionView(dataset, entityId);
    default: return null;
  }
}

// ── Module roll-up ─────────────────────────────────────────────

const MODULE_LABEL: Record<string, string> = {
  ACTOR: 'Threat Actors',
  HANDLE: 'Handle Intelligence',
  PGP: 'PGP Intelligence',
  WALLET: 'Crypto Wallet Intelligence',
  INFRASTRUCTURE: 'Infrastructure',
  SOURCE: 'Source Intelligence',
  OBSERVATION: 'Observation Intelligence',
  EVIDENCE: 'Evidence',
  RELATIONSHIP: 'Relationships',
  MITRE_TTP: 'ATT&CK Intelligence',
  CVE: 'CVE Intelligence',
  VULNERABILITY: 'Vulnerability Intelligence',
  WALLET_TRANSACTION: 'Transaction Intelligence',
  WALLET_CLUSTER: 'Cluster Intelligence',
  INVESTIGATION: 'Investigations',
};

export function moduleLabel(entityType: string): string {
  return MODULE_LABEL[entityType] ?? entityType.replace(/_/g, ' ');
}

const MODULE_PATH: Record<string, string | undefined> = {
  ACTOR: ENTITY_PATH.actors,
  HANDLE: ENTITY_PATH.handles,
  PGP: ENTITY_PATH.pgpKeys,
  WALLET: ENTITY_PATH.wallets,
  INFRASTRUCTURE: ENTITY_PATH.infrastructure,
  SOURCE: ENTITY_PATH.sources,
  OBSERVATION: ENTITY_PATH.observations,
  EVIDENCE: ENTITY_PATH.evidence,
  RELATIONSHIP: ENTITY_PATH.graph,
  // Technique and CVE records belong to the ATT&CK workspace, which is where
  // the rest of the app already sends them (see globalSearch). Pointing these
  // at the AI page would offer a link to a page that shows neither.
  MITRE_TTP: ENTITY_PATH.attack,
  CVE: ENTITY_PATH.attack,
  // A vulnerability record has no detail view anywhere in the product, so no
  // "open record" link is offered rather than pointing at a page that would
  // not show it. The panel still states what it can and cannot claim.
  VULNERABILITY: undefined,
  WALLET_TRANSACTION: ENTITY_PATH.wallets,
  WALLET_CLUSTER: ENTITY_PATH.wallets,
  INVESTIGATION: ENTITY_PATH.investigations,
};

export function modulePathFor(entityType: string, entityId: string): string | undefined {
  const base = MODULE_PATH[entityType];
  if (!base) return undefined;
  switch (entityType) {
    case 'ACTOR': return actorPath(entityId);
    case 'HANDLE': return handlePath(entityId);
    case 'PGP': return pgpPath(entityId);
    case 'WALLET': return walletPath(entityId);
    case 'OBSERVATION': return observationPath(entityId);
    default: return base;
  }
}

/**
 * The records a module owns, for the types that carry no numeric threat
 * score. A module panel must still be able to show what it is protecting,
 * so every module resolves its own collection instead of being limited to
 * the scored entity classes.
 */
function moduleMembers(dataset: IntelligenceDataset, entityType: string): Array<{ id: string; label: string }> {
  switch (entityType) {
    case 'SOURCE':
      return dataset.sources.map(source => ({ id: source.id, label: source.name }));
    case 'OBSERVATION':
      return dataset.observations.map(observation => ({ id: observation.id, label: observation.id }));
    case 'EVIDENCE':
      return dataset.evidence.map(item => ({ id: item.id, label: item.id }));
    case 'RELATIONSHIP':
      return dataset.relationships.map(rel => ({ id: rel.id, label: `${rel.sourceEntity} → ${rel.targetEntity}` }));
    case 'MITRE_TTP':
      return dataset.mitreTtps.map(ttp => ({ id: ttp.id, label: `${ttp.techniqueId} ${ttp.name}` }));
    case 'WALLET_TRANSACTION':
      return (dataset.walletTransactions ?? []).map(tx => ({ id: tx.id, label: tx.hash }));
    case 'WALLET_CLUSTER':
      return (dataset.walletClusters ?? []).map(cluster => ({ id: cluster.id, label: cluster.id }));
    case 'INVESTIGATION':
      return dataset.investigations.map(inv => ({ id: inv.id, label: `${inv.id} ${inv.title}` }));
    default:
      return [];
  }
}

/**
 * Roll every record of one module up into a protection posture.
 *
 * Scored modules read their derived protection records; the remaining
 * modules read their own detection views, so a panel shows real detections
 * either way. One computation per render, so a count on a list page can
 * never disagree with the detail page behind it.
 */
export function moduleProtectionSummary(dataset: IntelligenceDataset, entityType: string): ModuleProtectionSummary {
  const actions = responseActionRecords();
  const derived = protectionRecords(dataset).filter(record => record.entityType === entityType);
  const members = derived.length > 0
    ? derived.map(record => ({ id: record.entityId, label: record.entityDisplayName, score: record.score, status: record.status }))
    : moduleMembers(dataset, entityType).map(member => {
        const view = protectionView(dataset, entityType, member.id);
        return {
          id: member.id,
          label: member.label,
          score: view?.score ?? null,
          status: view?.status ?? ('ASSESSED' as ProtectionStatus),
        };
      });

  const rows: ModuleProtectionRow[] = members
    .map(member => {
      const entityActions = actions.filter(action => action.entityId === member.id);
      const reasons = member.score?.reasons ?? [];
      const view = protectionView(dataset, entityType, member.id);
      return {
        entityId: member.id,
        label: member.label,
        path: modulePathFor(entityType, member.id),
        score: member.score,
        riskLevel: member.score?.riskLevel ?? 'INACTIVE',
        status: member.status,
        topReason: reasons.length ? [...reasons].sort((a, b) => b.weight - a.weight)[0] : null,
        recommendation: view?.recommendation.label ?? 'No action required yet',
        openActions: entityActions.length,
        awaitingIntegration: entityActions.filter(action => PENDING_ACTION_STATUSES.has(action.status)).length,
      };
    })
    .sort((a, b) => (b.score?.value ?? -1) - (a.score?.value ?? -1));

  const riskCount = (level: RiskLevel) => rows.filter(row => row.riskLevel === level).length;
  const memberIds = new Set(members.map(member => member.id));
  // Resolved through the same relationship walk the detail panel uses, so a
  // roll-up counter can never under-report what the panel shows.
  const linkedEvidence = new Set(
    members.flatMap(member =>
      relatedContextFor(dataset, entityType, member.id)
        .evidence.map(item => item.id),
    ),
  ).size;
  const openAlerts = members.reduce((total, member) => {
    const alerts = relatedContextFor(dataset, entityType, member.id).alerts;
    return total + alerts.filter(alert => alert.status !== 'RESOLVED' && alert.status !== 'DISMISSED').length;
  }, 0);

  return {
    entityType,
    label: moduleLabel(entityType),
    total: rows.length,
    critical: riskCount('CRITICAL'),
    high: riskCount('HIGH'),
    medium: riskCount('MEDIUM'),
    low: riskCount('LOW'),
    inactive: riskCount('INACTIVE'),
    protectedCount: rows.filter(row => row.status === 'PROTECTED').length,
    monitoredCount: rows.filter(row => row.status === 'MONITORED').length,
    atRiskCount: rows.filter(row => row.status === 'AT_RISK').length,
    enforcedCount: actions.filter(action => action.status === 'ENFORCED_VERIFIED' && memberIds.has(action.entityId)).length,
    awaitingIntegrationCount: actions.filter(
      action => PENDING_ACTION_STATUSES.has(action.status) && memberIds.has(action.entityId),
    ).length,
    openAlerts,
    linkedEvidence,
    rows,
    generatedAt: new Date().toISOString(),
  };
}

export type {
  ModuleProtectionRow,
  ModuleProtectionSummary,
  ProtectionFact,
  ProtectionView,
  RelatedAlertRef,
  RelatedEvidenceRef,
  RelatedInvestigationRef,
  MonitoringStateRef,
  DetectionReason,
};
