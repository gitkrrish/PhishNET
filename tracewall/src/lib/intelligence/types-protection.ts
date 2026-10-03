// ============================================================
// PhishNet — Active detection & response data model.
//
// Extends the central intelligence model with a threat-detection
// and response layer. Every value below is *derived* from the
// existing intelligence records — no separate store of fabricated
// truth is introduced. Protection records reference the entity
// (actor / handle / wallet / infrastructure / etc.) they act on.
//
// Nothing here creates a second intelligence model. A detection is a
// read over an existing record; a response action is a decision an
// analyst records against that same record id.
// ============================================================

export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INACTIVE';

export type ResponsePriority = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export type DetectionSignal =
  | 'CONFIDENCE'
  | 'ACTIVE_STATUS'
  | 'ACTIVITY_LEVEL'
  | 'BEHAVIORAL_PROFILE'
  | 'SHARED_PGP'
  | 'SHARED_WALLET'
  | 'SHARED_INFRASTRUCTURE'
  | 'PERSONA_MIGRATION'
  | 'HANDLE_CHURN'
  | 'EVIDENCE_RELIABILITY'
  | 'ATTEX_VULNERABILITY'
  | 'CVE_EXPLOITATION'
  | 'WALLET_TRANSACTION_VOLUME'
  | 'WALLET_CLUSTER'
  | 'ENCRYPTED_COMMUNICATION'
  | 'MONITORING_ALERT'
  | 'SHARED_INFRA_USAGE';

export interface DetectionReason {
  signal: DetectionSignal;
  label: string;
  detail: string;
  weight: number;
}

export type RecommendedAction =
  | 'ESCALATE_REPORT'
  | 'ENRICH_TTP'
  | 'REVIEW_CREDENTIALS'
  | 'BLOCK_HANDLE'
  | 'QUARANTINE_WALLET'
  | 'REVIEW_INFRASTRUCTURE'
  | 'MONITOR_ENTITY'
  | 'ADD_EVIDENCE'
  | 'LINK_TO_INVESTIGATION'
  | 'PAUSE_MONITOR'
  | 'PATCH_ASSET'
  | 'REVOKE_TRUST'
  | 'NO_ACTION';

export interface ThreatScore {
  value: number;
  riskLevel: RiskLevel;
  reasons: DetectionReason[];
  recommendedAction: RecommendedAction;
  responsePriority: ResponsePriority;
  /** When the score was last recomputed, as an ISO timestamp. */
  computedAt: string;
}

/**
 * `PROTECTED` is reserved for a control an authorised integration has
 * confirmed. An analyst decision that no integration has carried out is
 * `PENDING`, never `PROTECTED`.
 */
export type ProtectionStatus = 'PROTECTED' | 'PENDING' | 'AT_RISK' | 'MONITORED' | 'RESOLVED' | 'ASSESSED';

/**
 * A protection record is a computed view over an intelligence entity.
 * The `entityId` always resolves to a record in the central dataset;
 * protection actions never create standalone intelligence of their own.
 */
export interface ThreatProtectionRecord {
  entityType: string;
  entityId: string;
  entityDisplayName: string;
  status: ProtectionStatus;
  score: ThreatScore;
  /** Whether a protection action is currently applied to this entity. */
  isBlocked: boolean;
  /** ISO timestamp of the most recent protection action. */
  lastActionAt: string | null;
}

export type ProtectionActionKind =
  | 'BLOCK'
  | 'UNBLOCK'
  | 'QUARANTINE'
  | 'MONITOR'
  | 'ESCALATE'
  | 'ADD_EVIDENCE'
  | 'LINK_INVESTIGATION';

export interface ProtectionAction {
  id: string;
  threatRecordId: string;
  kind: ProtectionActionKind;
  performedBy: string;
  reason: string;
  timestamp: string;
  detail: string;
}

export interface BlockedIndicator {
  id: string;
  entityType: string;
  entityId: string;
  value: string;
  blockedAt: string;
  reason: string;
  expiresAt: string | null;
  active: boolean;
}

export type ResponseStatus = 'OPEN' | 'ACKNOWLEDGED' | 'IN_PROGRESS' | 'RESOLVED' | 'DISMISSED';

export interface ResponseLog {
  id: string;
  threatRecordId: string;
  title: string;
  severity: ResponsePriority;
  createdAt: string;
  status: ResponseStatus;
  assignedTo: string | null;
  actions: ProtectionAction[];
  notes: string[];
}

export interface ThreatPosture {
  overall: RiskLevel;
  critical: number;
  high: number;
  medium: number;
  low: number;
  inactive: number;
  blocked: number;
  monitored: number;
  total: number;
  lastComputed: string;
}

export interface ThreatProtectionState {
  records: ThreatProtectionRecord[];
  blockedIndicators: BlockedIndicator[];
  responseLogs: ResponseLog[];
  posture: ThreatPosture;
  lastComputed: string;
}

// ── Enforcement ────────────────────────────────────────────────
//
// Enforcing anything changes state in a system *outside* this
// platform: a firewall rule set, a DNS security gateway, an endpoint
// quarantine, a trust store, an abuse desk. The platform therefore
// never asserts that a control has been applied. It reports what was
// attempted, through which configured integration, and whether that
// integration confirmed the result.

/** Control planes an operator may connect. Each is optional. */
export type EnforcementChannelKey =
  | 'FIREWALL'
  | 'DNS_SECURITY_GATEWAY'
  | 'SECURE_PROXY'
  | 'ENDPOINT_PROTECTION'
  | 'IDENTITY_TRUST'
  | 'MESSAGE_FILTER'
  | 'CHAIN_ANALYTICS'
  | 'ABUSE_DESK';

export interface EnforcementChannel {
  key: EnforcementChannelKey;
  label: string;
  controlPlane: string;
  /** Deployment setting that enables this channel. */
  configKey: string;
  /** Deployment setting that supplies this channel's endpoint. */
  endpointConfigKey: string;
  configured: boolean;
  /** Where the platform would send the request, when configured. */
  endpoint: string | null;
  /** What the operator must have authorised for this to be usable. */
  authorization: string;
}

/**
 * Why an action is or is not offered. `AVAILABLE` means a configured,
 * authorised integration will accept it. Everything else is honest
 * about the fact that no control plane will act on it.
 */
export type ActionAvailability =
  | 'AVAILABLE'
  | 'APPROVAL_REQUIRED'
  | 'RECOMMENDATION'
  | 'UNSUPPORTED';

export type ResponseActionKind =
  | 'BLOCK_IP'
  | 'BLOCK_DOMAIN'
  | 'BLOCK_URL'
  | 'BLOCK_HANDLE'
  | 'QUARANTINE_FILE'
  | 'REVOKE_TRUST'
  | 'MONITOR_WALLET'
  | 'PATCH_ASSET'
  | 'TAKEDOWN_REQUEST'
  | 'ALERT'
  | 'ESCALATE'
  | 'LINK_INVESTIGATION'
  | 'ADD_EVIDENCE'
  | 'MONITOR';

export interface ResponseActionOption {
  kind: ResponseActionKind;
  label: string;
  detail: string;
  availability: ActionAvailability;
  /** Null when the action is not a control-plane change at all. */
  channel: EnforcementChannelKey | null;
  /** Always stated, so the UI never has to invent a reason. */
  availabilityReason: string;
  /** True when an analyst must approve before it can be applied. */
  requiresApproval: boolean;
}

/**
 * The truthful outcome of a response action. `ENFORCED_VERIFIED` is
 * only reachable when a configured integration confirmed the change.
 */
export type ResponseActionStatus =
  | 'ENFORCED_VERIFIED'
  | 'AWAITING_APPROVAL'
  | 'AWAITING_INTEGRATION'
  | 'SUBMITTED_UNCONFIRMED'
  | 'FAILED'
  | 'RECORDED';

export interface ResponseActionRecord {
  id: string;
  /** Always an existing intelligence record id — never a new entity. */
  entityType: string;
  entityId: string;
  entityValue: string;
  kind: ResponseActionKind;
  status: ResponseActionStatus;
  channel: EnforcementChannelKey | null;
  detail: string;
  performedBy: string;
  recordedAt: string;
  /** Set only when an integration confirmed the change. */
  confirmedAt: string | null;
}

// ── Shared protection view ──────────────────────────────────────
//
// One shape, rendered by one component, on every module that owns an
// entity. This is how protection stays centralised without becoming a
// separate tool: the data is assembled per entity and shown inside the
// module that already owns the record.

export type FactTone = 'critical' | 'high' | 'medium' | 'low' | 'ok' | 'muted';

export interface ProtectionFact {
  label: string;
  value: string;
  tone?: FactTone;
}

export interface RelatedAlertRef {
  id: string;
  title: string;
  severity: string;
  status: string;
  raisedAt: string;
}

export interface RelatedEvidenceRef {
  id: string;
  evidenceType: string;
  reliability: number;
  timestamp: string;
}

export interface RelatedInvestigationRef {
  id: string;
  title: string;
  status: string;
}

export interface MonitoringStateRef {
  status: 'ACTIVE' | 'PAUSED' | 'DISABLED' | 'NONE';
  label: string;
  detail: string;
}

export interface ProtectionView {
  entityType: string;
  entityId: string;
  entityLabel: string;
  /** Canonical deep link back to the record's own page. */
  entityPath?: string;
  /** Null when the module owns no scored entity type. */
  score: ThreatScore | null;
  status: ProtectionStatus;
  headline: string;
  detectionSummary: string;
  facts: ProtectionFact[];
  reasons: DetectionReason[];
  recommendation: { action: RecommendedAction; label: string; detail: string };
  actions: ResponseActionOption[];
  alerts: RelatedAlertRef[];
  evidence: RelatedEvidenceRef[];
  investigations: RelatedInvestigationRef[];
  monitoring: MonitoringStateRef;
  records: ResponseActionRecord[];
  caveats: string[];
}

export interface ModuleProtectionRow {
  entityId: string;
  label: string;
  path?: string;
  /** Null for module types that own no scored entity class. */
  score: ThreatScore | null;
  riskLevel: RiskLevel;
  status: ProtectionStatus;
  topReason: DetectionReason | null;
  recommendation: string;
  openActions: number;
  awaitingIntegration: number;
}

export interface ModuleProtectionSummary {
  entityType: string;
  label: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  inactive: number;
  protectedCount: number;
  monitoredCount: number;
  atRiskCount: number;
  enforcedCount: number;
  awaitingIntegrationCount: number;
  openAlerts: number;
  linkedEvidence: number;
  rows: ModuleProtectionRow[];
  generatedAt: string;
}
