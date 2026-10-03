// ============================================================
// PhishNet — Central Dark Web Intelligence data model.
//
// ONE source of truth. Every module (dashboard, search, correlation,
// graph, timeline, evidence, investigations, alerts, AI, reports,
// audit) reads and writes the records defined here. The synthetic
// dataset in src/data/darkWebData.ts is only the *seed* — it is
// loaded once into this model and then owned by it.
//
// Existing entity shapes (ThreatActor, Handle, PgpKey, …) are reused
// verbatim from the seed module so no existing page has to change how
// it renders a record. Only genuinely required fields are added.
// ============================================================
import type {
  ThreatActor,
  Handle,
  PgpKey,
  Wallet,
  Infrastructure,
  DarkWebSource,
  Relationship,
  Evidence,
  TimelineEvent,
  Investigation,
  Alert,
  SourceType,
  Severity,
  RelationshipType,
  EvidenceType,
  ActorStatus,
  Report,
} from '../../data/darkWebData';
import type {
  MitreTtp,
  MitreTactic,
  MitrePlatform,
  MitreDataSource,
  MitrePermission,
  MitreMatrix,
  MitreMatrixRow,
  MitreMatrixCell,
  ActorMitreProfile,
  MitreTtpCorrelation,
  MitreFilterOptions,
} from './types-mitre';
import type {
  CveRecord,
  VulnerabilityRecord,
  Vulnerability,
  CveSeverity,
  CweType,
  ExploitationStatus,
  VulnerabilityCategory,
  VulnerabilityTimelineEvent,
  VulnerabilityFilterOptions,
  VulnerabilityStats,
  ActorVulnerabilityProfile,
} from './types-vulnerability';
import type {
  WalletTransaction,
  WalletCluster,
  ExchangeRecord,
  BlockchainNetwork,
  TransactionDirection,
  TransactionStatus,
  ClusteringMethod,
  WalletAnalysis,
  WalletRiskFactor,
  TransactionPattern,
  ExchangeAssociation,
  WalletAnomaly,
  WalletTransactionStats,
  WalletTransactionFilterOptions,
  SanctionsEntry,
} from './types-wallet-enhanced';
import type {
  CommunicationChannel,
  CommunicationMessage,
  ExtractedEntity,
  CommunicationPlatform,
  ChannelType,
  MessageType,
  LanguageCode,
  EncryptionProtocol,
  Methodology,
  MethodologyCategory,
  TtpPlaybook,
  PlaybookStep,
  CommunicationPattern,
  ActorCommunicationProfile,
  CommunicationFilterOptions,
  MethodologyFilterOptions,
} from './types-communication';

/** How a record entered the platform. Keeps the dataset transparent. */
export type DataState =
  | 'OBSERVED'
  | 'IMPORTED'
  | 'ANALYST_ADDED'
  | 'AI_DERIVED'
  | 'SYNTHETIC_DEMO';

/**
 * Provenance carried by every intelligence record so an investigation
 * can always answer "where did this come from and who recorded it?".
 */
export interface Provenance {
  dataState: DataState;
  source: string;
  sourceType: SourceType | 'ANALYST' | 'IMPORT';
  analyst: string;
  provenance: string;
  collectionTimestamp: string;
  observationTimestamp: string;
  confidence: number;
}

/** A single raw observation — the atomic unit of collected intelligence. */
export interface Observation {
  id: string;
  actorId: string | null;
  handleId: string | null;
  platform: string | null;
  observationType:
    | 'HANDLE_OBSERVED'
    | 'NEW_PLATFORM_ACTIVITY'
    | 'INFRASTRUCTURE_CHANGE'
    | 'PERSONA_CHANGE'
    | 'RELATIONSHIP_DISCOVERED'
    | 'NEW_EVIDENCE'
    | 'BEHAVIOR_ANOMALY';
  content: string;
  timestamp: string;
  source: string;
  confidence: number;
  tags: string[];
  notes: string;
  dataState: DataState;
  analyst: string;
  evidenceIds: string[];
}

/** Audit record for every intelligence operation. Secrets are never stored. */
export interface IntelligenceAuditEvent {
  id: string;
  time: string;
  actor: string;
  action:
    | 'ACTOR_CREATED'
    | 'HANDLE_ADDED'
    | 'PGP_ADDED'
    | 'WALLET_ADDED'
    | 'INFRASTRUCTURE_ADDED'
    | 'SOURCE_ADDED'
    | 'OBSERVATION_ADDED'
    | 'EVIDENCE_ADDED'
    | 'RELATIONSHIP_CREATED'
    | 'INVESTIGATION_CREATED'
    | 'ALERT_CREATED'
    | 'TIMELINE_EVENT_ADDED'
    | 'IMPORT_COMPLETED'
    | 'DEMO_DATASET_LOADED'
    | 'DEMO_DATASET_RESET'
    | 'DEMO_DATASET_CLEARED'
    | 'DATASET_EXPORTED'
    // Extended entity types: MITRE ATT&CK, vulnerability, crypto.
    | 'MITRE_TTP_ADDED'
    | 'CVE_ADDED'
    | 'WALLET_TRANSACTION_ADDED'
    | 'WALLET_CLUSTER_ADDED';
  entity: string;
  entityId: string;
  before: string;
  after: string;
  source: string;
  result: 'SUCCESS' | 'REJECTED';
  outcome: 'SUCCESS' | 'REJECTED';
  ip: string;
}

/** Free-text analyst note attached to any central record. */
export interface AnalystNote {
  id: string;
  entityType: string;
  entityId: string;
  author: string;
  createdAt: string;
  text: string;
}

export type ActorRecord = ThreatActor & { dataState?: DataState; analyst?: string; notes?: string; tags?: string[] };
export type HandleRecord = Handle & { actorId?: string | null; dataState?: DataState; analyst?: string; source?: string; notes?: string };
export type PgpRecord = PgpKey & { dataState?: DataState; analyst?: string; handleIds?: string[]; notes?: string };
export type WalletRecord = Wallet & { dataState?: DataState; analyst?: string; network?: string; handleIds?: string[]; notes?: string };
export type InfrastructureRecord = Infrastructure & { dataState?: DataState; analyst?: string; source?: string; nameserver?: string; notes?: string };
export type SourceRecord = DarkWebSource & { dataState?: DataState; analyst?: string; reference?: string; collectionMethod?: string; notes?: string };
export type RelationshipRecord = Relationship & { dataState?: DataState; analyst?: string; createdAt?: string; sourceLabel?: string };
export type EvidenceRecord = Evidence & { dataState?: DataState; analyst?: string; relatedHandle?: string | null; relatedInfrastructure?: string | null; relatedRelationship?: string | null; description?: string; notes?: string };
export type TimelineRecord = TimelineEvent & { dataState?: DataState; analyst?: string; source?: string; evidenceIds?: string[] };
export type InvestigationRecord = Investigation & { dataState?: DataState; entityIds?: string[]; notes?: string };
export type AlertRecord = Alert & { dataState?: DataState; entityType?: string; entityId?: string | null; acknowledgedBy?: string; acknowledgedAt?: string; resolution?: string };
export type ReportRecord = Report & { dataState?: DataState };

// New record types for extended capabilities
export type MitreTtpRecord = MitreTtp & { dataState?: DataState; analyst?: string; notes?: string; tags?: string[] };
export type CveRecordRecord = CveRecord & { dataState?: DataState; analyst?: string; notes?: string; tags?: string[] };
export type VulnerabilityRecordRecord = VulnerabilityRecord & { dataState?: DataState; analyst?: string; notes?: string; tags?: string[] };
export type WalletTransactionRecord = WalletTransaction & { dataState?: DataState; analyst?: string; notes?: string; tags?: string[] };
export type WalletClusterRecord = WalletCluster & { dataState?: DataState; analyst?: string; notes?: string; tags?: string[] };
export type ExchangeRecordRecord = ExchangeRecord & { dataState?: DataState; analyst?: string; notes?: string; tags?: string[] };
export type CommunicationChannelRecord = CommunicationChannel & { dataState?: DataState; analyst?: string; notes?: string; tags?: string[] };
export type CommunicationMessageRecord = CommunicationMessage & { dataState?: DataState; analyst?: string; notes?: string; tags?: string[] };
export type MethodologyRecord = Methodology & { dataState?: DataState; analyst?: string; notes?: string; tags?: string[] };
export type TtpPlaybookRecord = TtpPlaybook & { dataState?: DataState; analyst?: string; notes?: string; tags?: string[] };

export interface MonitoringState {
  status: 'ACTIVE' | 'PAUSED';
  lastCollection: string;
  nextCollection: string;
  sourcesMonitored: number;
  newIndicators: number;
  newActors: number;
  newRelationships: number;
  alerts: number;
}

/** Id lookups rebuilt on every dataset change so no page keeps stale maps. */
export interface IntelligenceLookups {
  actorsById: Record<string, ActorRecord>;
  handlesById: Record<string, HandleRecord>;
  pgpById: Record<string, PgpRecord>;
  walletsById: Record<string, WalletRecord>;
  infraById: Record<string, InfrastructureRecord>;
  sourcesById: Record<string, SourceRecord>;
  relationshipsById: Record<string, RelationshipRecord>;
  evidenceById: Record<string, EvidenceRecord>;
  timelineById: Record<string, TimelineRecord>;
  investigationsById: Record<string, InvestigationRecord>;
  alertsById: Record<string, AlertRecord>;
  observationsById: Record<string, Observation>;
  // New lookups for extended capabilities
  mitreTtpsById: Record<string, MitreTtpRecord>;
  cvesById: Record<string, CveRecordRecord>;
  cvesByCveId: Record<string, CveRecordRecord>;
  vulnerabilitiesById: Record<string, VulnerabilityRecordRecord>;
  walletTransactionsById: Record<string, WalletTransactionRecord>;
  walletTransactionsByWalletId: Record<string, WalletTransactionRecord[]>;
  walletClustersById: Record<string, WalletClusterRecord>;
  walletClustersByWalletId: Record<string, WalletClusterRecord[]>;
  exchangesById: Record<string, ExchangeRecordRecord>;
  communicationChannelsById: Record<string, CommunicationChannelRecord>;
  communicationMessagesById: Record<string, CommunicationMessageRecord>;
  methodologiesById: Record<string, MethodologyRecord>;
  playbooksById: Record<string, TtpPlaybookRecord>;
}

/** The single central dataset every module reads from. */
export interface IntelligenceDataset {
  version: number;
  /**
   * Monotonic write counter. It changes on every committed mutation, which lets
   * a React component depend on "something was written" even when the helper it
   * calls reads the dataset at call time and cannot depend on a collection.
   */
  revision: number;
  updatedAt: string;
  demoLabel: string;
  isDemoLoaded: boolean;
  actors: ActorRecord[];
  handles: HandleRecord[];
  pgpKeys: PgpRecord[];
  wallets: WalletRecord[];
  infrastructure: InfrastructureRecord[];
  sources: SourceRecord[];
  observations: Observation[];
  relationships: RelationshipRecord[];
  evidence: EvidenceRecord[];
  timeline: TimelineRecord[];
  investigations: InvestigationRecord[];
  alerts: AlertRecord[];
  audit: IntelligenceAuditEvent[];
  notes: AnalystNote[];
  reports: ReportRecord[];
  monitoring: MonitoringState;
  lookups: IntelligenceLookups;
  // New collections for extended capabilities
  mitreTtps: MitreTtpRecord[];
  cves: CveRecordRecord[];
  vulnerabilities: VulnerabilityRecordRecord[];
  walletTransactions: WalletTransactionRecord[];
  walletClusters: WalletClusterRecord[];
  exchanges: ExchangeRecordRecord[];
  communicationChannels: CommunicationChannelRecord[];
  communicationMessages: CommunicationMessageRecord[];
  methodologies: MethodologyRecord[];
  playbooks: TtpPlaybookRecord[];
}

/** Shared activity-feed event kinds — mirrors the audit action union. */
export type ActivityKind = IntelligenceAuditEvent['action'];

export interface ActivityItem {
  id: string;
  time: string;
  kind: ActivityKind;
  label: string;
  detail: string;
  entity: string;
  entityId: string;
  actor: string;
  path: string;
}

export type IntelligenceEntityKind =
  | 'ACTOR'
  | 'HANDLE'
  | 'PGP'
  | 'WALLET'
  | 'INFRASTRUCTURE'
  | 'SOURCE'
  | 'OBSERVATION'
  | 'EVIDENCE'
  | 'TIMELINE'
  | 'RELATIONSHIP'
  | 'INVESTIGATION'
  | 'MITRE_TTP'
  | 'CVE'
  | 'VULNERABILITY'
  | 'WALLET_TRANSACTION'
  | 'WALLET_CLUSTER'
  | 'EXCHANGE'
  | 'COMMUNICATION_CHANNEL'
  | 'COMMUNICATION_MESSAGE'
  | 'METHODOLOGY'
  | 'PLAYBOOK';

export const INTELLIGENCE_KIND_LABEL: Record<IntelligenceEntityKind, string> = {
  ACTOR: 'Threat Actor',
  HANDLE: 'Handle',
  PGP: 'PGP Identity',
  WALLET: 'Wallet Indicator',
  INFRASTRUCTURE: 'Infrastructure',
  SOURCE: 'Source',
  OBSERVATION: 'Observation',
  EVIDENCE: 'Evidence',
  TIMELINE: 'Timeline Event',
  RELATIONSHIP: 'Relationship',
  INVESTIGATION: 'Investigation',
  MITRE_TTP: 'MITRE ATT&CK TTP',
  CVE: 'CVE Vulnerability',
  VULNERABILITY: 'Vulnerability',
  WALLET_TRANSACTION: 'Wallet Transaction',
  WALLET_CLUSTER: 'Wallet Cluster',
  EXCHANGE: 'Exchange',
  COMMUNICATION_CHANNEL: 'Communication Channel',
  COMMUNICATION_MESSAGE: 'Communication Message',
  METHODOLOGY: 'Methodology',
  PLAYBOOK: 'TTP Playbook',
};

export type {
  ThreatActor,
  Handle,
  PgpKey,
  Wallet,
  Infrastructure,
  DarkWebSource,
  Relationship,
  Evidence,
  TimelineEvent,
  Investigation,
  Alert,
  Report,
  SourceType,
  Severity,
  RelationshipType,
  EvidenceType,
  ActorStatus,
};

// Re-export all new types
export type {
  // MITRE ATT&CK
  MitreTtp,
  MitreTactic,
  MitrePlatform,
  MitreDataSource,
  MitrePermission,
  MitreMatrix,
  MitreMatrixRow,
  MitreMatrixCell,
  ActorMitreProfile,
  MitreTtpCorrelation,
  MitreFilterOptions,
  // Vulnerability
  CveRecord,
  VulnerabilityRecord,
  Vulnerability,
  CveSeverity,
  CweType,
  ExploitationStatus,
  VulnerabilityCategory,
  VulnerabilityTimelineEvent,
  VulnerabilityFilterOptions,
  VulnerabilityStats,
  ActorVulnerabilityProfile,
  // Wallet Enhanced
  WalletTransaction,
  WalletCluster,
  ExchangeRecord,
  BlockchainNetwork,
  TransactionDirection,
  TransactionStatus,
  ClusteringMethod,
  WalletAnalysis,
  WalletRiskFactor,
  TransactionPattern,
  ExchangeAssociation,
  WalletAnomaly,
  WalletTransactionStats,
  WalletTransactionFilterOptions,
  SanctionsEntry,
  // Communication
  CommunicationChannel,
  CommunicationMessage,
  ExtractedEntity,
  CommunicationPlatform,
  ChannelType,
  MessageType,
  LanguageCode,
  EncryptionProtocol,
  Methodology,
  MethodologyCategory,
  TtpPlaybook,
  PlaybookStep,
  CommunicationPattern,
  ActorCommunicationProfile,
  CommunicationFilterOptions,
  MethodologyFilterOptions,
};

