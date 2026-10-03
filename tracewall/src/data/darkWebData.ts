// ============================================================
// PhishNet — Dark Web Threat Intelligence (Synthetic Dataset)
// ALL ENTITIES BELOW ARE FICTIONAL / DEMONSTRATION-ONLY DATA.
// No real dark-web services, real credentials, or illicit
// infrastructure are referenced. Every identifier is synthetic.
// ============================================================
import { DEMO_LABEL as _DEMO } from './mockData';

export const DARKWEB_DEMO_LABEL = 'Synthetic Demo Data — DO NOT TREAT AS REAL';

// ── Types ─────────────────────────────────────────────────────
export type SourceType = 'FORUM' | 'MARKETPLACE' | 'PASTE' | 'LEAK_SITE' | 'MESSAGING' | 'THREAT_FEED' | 'ONION_SERVICE';
export type ActorStatus = 'ACTIVE' | 'DORMANT' | 'SUSPENDED';
export type RelationshipType =
  | 'USES_HANDLE' | 'SHARED_HANDLE' | 'SHARED_PGP' | 'SHARED_WALLET'
  | 'SHARED_INFRASTRUCTURE' | 'ASSOCIATED_WITH' | 'OBSERVED_ON'
  | 'SIMILAR_PERSONA' | 'PERSONA_MIGRATION' | 'TEMPORAL_RELATIONSHIP'
  | 'TEMPORAL_OVERLAP' | 'SHARED_BEHAVIOR'
  | 'EVIDENCE_LINKED' | 'OBSERVED_AT_SOURCE' | 'SOURCE_REPORTED'
  // Extended intelligence graph: MITRE ATT&CK, vulnerability and crypto edges.
  | 'USES_TTP' | 'ASSOCIATED_WITH_TTP' | 'AFFECTED_BY_CVE' | 'EXPLOITS_CVE'
  | 'ASSOCIATED_WITH_CVE' | 'ASSOCIATED_WITH_TRANSACTION' | 'PART_OF_CLUSTER'
  | 'ASSOCIATED_WITH_CLUSTER' | 'ASSOCIATED_WITH_EXCHANGE'
  | 'USES_COMMUNICATION_CHANNEL';
export type EvidenceType = 'FORUM_POST' | 'MARKETPLACE_LISTING' | 'PASTE' | 'LEAK_RECORD' | 'MESSAGE' | 'TRANSACTION' | 'PGP_KEY' | 'DOMAIN_REGISTRATION' | 'LOG' | 'ANALYSIS';
export type Reliability = 'A' | 'B' | 'C' | 'D' | 'E';
export type AlertType = 'NEW_ACTOR' | 'NEW_HANDLE' | 'PERSONA_MIGRATION' | 'INFRASTRUCTURE_CHANGE' | 'RELATIONSHIP_CHANGE' | 'HIGH_CONFIDENCE_CORRELATION' | 'SOURCE_FAILURE' | 'ANOMALY_DETECTED' | 'MONITORING';
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface DarkWebSource {
  id: string;
  name: string;
  type: SourceType;
  firstObserved: string;
  lastObserved: string;
  reliabilityScore: number;
  activityLevel: 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'ACTIVE' | 'DORMANT' | 'SUSPENDED';
  actorCount: number;
  indicatorCount: number;
  collectionTimestamp: string;
  description: string;
  onionAddress?: string;
  isSynthetic: boolean;
}

export interface Handle {
  id: string;
  value: string;
  platform: string;
  sourceId: string;
  firstSeen: string;
  lastSeen: string;
  confidence: number;
  normalized: string;
}

export interface PgpKey {
  id: string;
  fingerprint: string;
  actorIds: string[];
  firstSeen: string;
  lastSeen: string;
  sources: string[];
  confidence: number;
}

export interface Wallet {
  id: string;
  address: string;
  actorIds: string[];
  observedSources: string[];
  firstSeen: string;
  lastSeen: string;
  txCount: number;
  confidence: number;
}

export interface Infrastructure {
  id: string;
  type: 'DOMAIN' | 'IP' | 'HOSTING' | 'TLS' | 'NAMESERVER';
  value: string;
  actorIds: string[];
  firstSeen: string;
  lastSeen: string;
  registrar?: string;
  hostingProvider?: string;
  asn?: string;
  country?: string;
  tlsIssuer?: string;
}

export interface ThreatActor {
  id: string;
  aliases: string[];
  handles: string[];
  pgpFingerprints: string[];
  walletAddrs: string[];
  domains: string[];
  platforms: string[];
  firstSeen: string;
  lastSeen: string;
  activityLevel: 'HIGH' | 'MEDIUM' | 'LOW';
  confidenceScore: number;
  status: ActorStatus;
  relatedActorIds: string[];
  associatedEvidence: string[];
  behavioralProfile: BehavioralProfile;
  stylometricProfile: StylometricProfile;
  primaryMotivation: string;
  isSynthetic: boolean;
}

export interface BehavioralProfile {
  activityFrequency: 'HIGH' | 'MEDIUM' | 'LOW';
  activeHours: Array<{ hour: number; level: number }>;
  platformPreferences: Array<{ platform: string; weight: number }>;
  postingFrequency: number;
  topicClusters: string[];
  interactionPattern: string;
  personaTransitions: number;
}

export interface StylometricProfile {
  avgSentenceLength: number;
  punctuationPattern: string;
  capitalisationTendency: 'HIGH' | 'MEDIUM' | 'LOW';
  vocabularyRichness: number;
  recurringExpressions: string[];
  sentenceStructure: string;
  languagePatterns: string[];
  sampleText: string;
}

export interface Relationship {
  id: string;
  sourceEntity: string;
  targetEntity: string;
  sourceType: string;
  targetType: string;
  type: RelationshipType;
  confidence: number;
  evidenceIds: string[];
  explanation: string;
  firstObserved: string;
  lastObserved: string;
  supporting: string[];
  against: string[];
}

export interface Evidence {
  id: string;
  source: string;
  sourceType: SourceType;
  timestamp: string;
  collectionTimestamp: string;
  hash: string;
  relatedActor: string | null;
  relatedRelationship: string | null;
  evidenceType: EvidenceType;
  reliability: number;
  confidence: number;
  provenance: string;
  isSynthetic: boolean;
}

export interface TimelineEvent {
  id: string;
  actorId: string;
  time: string;
  type: 'HANDLE_CHANGE' | 'PLATFORM_ACTIVITY' | 'INFRASTRUCTURE_CHANGE' | 'PERSONA_MIGRATION' | 'RELATIONSHIP_FORMATION' | 'EVIDENCE_COLLECTION' | 'FIRST_SEEN' | 'LAST_SEEN' | 'FIRST_SEEN_NEW';
  title: string;
  description: string;
  confidence: number;
}

export interface Investigation {
  id: string;
  title: string;
  description: string;
  status: 'ACTIVE' | 'PENDING' | 'COMPLETED';
  analyst: string;
  createdAt: string;
  updatedAt: string;
  seedActorId: string;
  steps: InvestigationStep[];
  confidence: number;
}

export interface InvestigationStep {
  step: number;
  type?: string;
  title: string;
  description: string;
  evidenceIds: string[];
  relationshipIds: string[];
  actorIds: string[];
  confidence: number;
}

export interface Alert {
  id: string;
  type: AlertType;
  severity: Severity;
  title: string;
  timestamp: string;
  actorId: string | null;
  reason: string;
  evidenceIds: string[];
  confidence: number;
  status: 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED' | 'DISMISSED';
}

// ── Source catalog ─────────────────────────────────────────────
export const darkWebSources: DarkWebSource[] = [
  { id: 'SRC-FORUM-A', name: 'DarkForum Alpha', type: 'FORUM', firstObserved: '2025-11-03T08:00:00Z', lastObserved: '2026-09-12T14:00:00Z', reliabilityScore: 92, activityLevel: 'HIGH', status: 'ACTIVE', actorCount: 3, indicatorCount: 41, collectionTimestamp: '2026-09-12T14:22:00Z', description: 'High-traffic forum discussing financial fraud tooling.', onionAddress: 'darkforum-alpha7xonion.com', isSynthetic: true },
  { id: 'SRC-FORUM-B', name: 'BlackVault Forums', type: 'FORUM', firstObserved: '2026-01-14T10:00:00Z', lastObserved: '2026-09-10T09:30:00Z', reliabilityScore: 84, activityLevel: 'MEDIUM', status: 'ACTIVE', actorCount: 2, indicatorCount: 27, collectionTimestamp: '2026-09-10T09:30:00Z', description: 'Generalist dark-web forum with sections for tool sales.', onionAddress: 'blackvault-b7forum.com', isSynthetic: true },
  { id: 'SRC-MARKET-A', name: 'Nexus Markets', type: 'MARKETPLACE', firstObserved: '2026-02-20T00:00:00Z', lastObserved: '2026-09-13T02:15:00Z', reliabilityScore: 88, activityLevel: 'HIGH', status: 'ACTIVE', actorCount: 3, indicatorCount: 33, collectionTimestamp: '2026-09-13T02:15:00Z', description: 'Dark-web marketplace for account credentials and access.', onionAddress: 'nexusch4marketsvc.com', isSynthetic: true },
  { id: 'SRC-MARKET-B', name: 'Abyssal Bazaar', type: 'MARKETPLACE', firstObserved: '2026-03-08T00:00:00Z', lastObserved: '2026-09-11T22:40:00Z', reliabilityScore: 79, activityLevel: 'MEDIUM', status: 'ACTIVE', actorCount: 2, indicatorCount: 19, collectionTimestamp: '2026-09-11T22:40:00Z', description: 'Market for hosting and infrastructure services.', onionAddress: 'abyssal-bazaar7onion.com', isSynthetic: true },
  { id: 'SRC-PASTE-A', name: 'ZeroDump Paste', type: 'PASTE', firstObserved: '2026-04-01T00:00:00Z', lastObserved: '2026-09-09T18:10:00Z', reliabilityScore: 67, activityLevel: 'LOW', status: 'ACTIVE', actorCount: 1, indicatorCount: 12, collectionTimestamp: '2026-09-09T18:10:00Z', description: 'Anonymous paste service hosting credential dumps.', isSynthetic: true },
  { id: 'SRC-LEAK-A', name: 'BreachVault Leak Site', type: 'LEAK_SITE', firstObserved: '2026-05-12T00:00:00Z', lastObserved: '2026-09-13T03:00:00Z', reliabilityScore: 95, activityLevel: 'HIGH', status: 'ACTIVE', actorCount: 2, indicatorCount: 28, collectionTimestamp: '2026-09-13T03:00:00Z', description: 'Ransomware/leak extortion site.', onionAddress: 'breachvault-leak.onion', isSynthetic: true },
  { id: 'SRC-MSG-A', name: 'SecureChat Relay', type: 'MESSAGING', firstObserved: '2026-06-22T00:00:00Z', lastObserved: '2026-09-12T20:30:00Z', reliabilityScore: 71, activityLevel: 'LOW', status: 'ACTIVE', actorCount: 2, indicatorCount: 9, collectionTimestamp: '2026-09-12T20:30:00Z', description: 'Encrypted messaging bridge identities observed here.', isSynthetic: true },
  { id: 'SRC-FEED-A', name: 'OpenCTI Feed', type: 'THREAT_FEED', firstObserved: '2026-03-01T00:00:00Z', lastObserved: '2026-09-13T04:00:00Z', reliabilityScore: 98, activityLevel: 'HIGH', status: 'ACTIVE', actorCount: 5, indicatorCount: 64, collectionTimestamp: '2026-09-13T04:00:00Z', description: 'Public threat-intelligence feed (synthetic corroboration).', isSynthetic: true },
  { id: 'SRC-TOR-A', name: 'OnionScan Index', type: 'ONION_SERVICE', firstObserved: '2026-07-18T00:00:00Z', lastObserved: '2026-09-13T03:45:00Z', reliabilityScore: 85, activityLevel: 'MEDIUM', status: 'ACTIVE', actorCount: 4, indicatorCount: 22, collectionTimestamp: '2026-09-13T03:45:00Z', description: 'Passive onion-service indexing for correlation.', isSynthetic: true },
];

// ── Handles ───────────────────────────────────────────────────
export const darkWebHandles: Handle[] = [
  { id: 'HND-001', value: 'shadowfox', platform: 'DarkForum Alpha', sourceId: 'SRC-FORUM-A', firstSeen: '2026-02-14T03:22:00Z', lastSeen: '2026-04-28T19:10:00Z', confidence: 60, normalized: 'shadowfox' },
  { id: 'HND-002', value: 'ShadowFox', platform: 'Nexus Markets', sourceId: 'SRC-MARKET-A', firstSeen: '2026-03-05T14:41:00Z', lastSeen: '2026-05-19T22:05:00Z', confidence: 50, normalized: 'shadowfox' },
  { id: 'HND-003', value: 'nightstalk', platform: 'BlackVault Forums', sourceId: 'SRC-FORUM-B', firstSeen: '2026-05-02T11:09:00Z', lastSeen: '2026-08-30T06:44:00Z', confidence: 60, normalized: 'nightstalk' },
  { id: 'HND-004', value: 'nightstalk', platform: 'Abyssal Bazaar', sourceId: 'SRC-MARKET-B', firstSeen: '2026-05-09T16:33:00Z', lastSeen: '2026-07-21T17:55:00Z', confidence: 50, normalized: 'nightstalk' },
  { id: 'HND-005', value: 'ghostwire', platform: 'Abyssal Bazaar', sourceId: 'SRC-MARKET-B', firstSeen: '2026-07-15T09:00:00Z', lastSeen: '2026-09-08T18:22:00Z', confidence: 70, normalized: 'ghostwire' },
  { id: 'HND-006', value: 'VoidCipher', platform: 'DarkForum Alpha', sourceId: 'SRC-FORUM-A', firstSeen: '2026-03-01T00:00:00Z', lastSeen: '2026-08-15T12:00:00Z', confidence: 85, normalized: 'voidcipher' },
  { id: 'HND-007', value: 'VoidCipher', platform: 'Nexus Markets', sourceId: 'SRC-MARKET-A', firstSeen: '2026-03-05T14:41:00Z', lastSeen: '2026-05-19T22:05:00Z', confidence: 90, normalized: 'voidcipher' },
  { id: 'HND-008', value: 'VoidCipher', platform: 'BreachVault Leak Site', sourceId: 'SRC-LEAK-A', firstSeen: '2026-08-10T11:30:00Z', lastSeen: '2026-09-10T01:20:00Z', confidence: 80, normalized: 'voidcipher' },
  { id: 'HND-009', value: 'VoidCipher', platform: 'DarkForum Alpha', sourceId: 'SRC-FORUM-A', firstSeen: '2026-08-20T02:14:00Z', lastSeen: '2026-09-10T23:59:00Z', confidence: 88, normalized: 'voidcipher' },
  { id: 'HND-010', value: 'crypthoax', platform: 'BlackVault Forums', sourceId: 'SRC-FORUM-B', firstSeen: '2026-03-15T00:00:00Z', lastSeen: '2026-07-05T14:18:00Z', confidence: 55, normalized: 'crypthoax' },
  { id: 'HND-011', value: 'crypthoax', platform: 'Abyssal Bazaar', sourceId: 'SRC-MARKET-B', firstSeen: '2026-04-22T10:00:00Z', lastSeen: '2026-06-30T20:00:00Z', confidence: 45, normalized: 'crypthoax' },
  { id: 'HND-012', value: 'pulsar', platform: 'DarkForum Alpha', sourceId: 'SRC-FORUM-A', firstSeen: '2026-06-18T19:00:00Z', lastSeen: '2026-09-10T15:30:00Z', confidence: 75, normalized: 'pulsar' },
  { id: 'HND-013', value: 'pulsar', platform: 'SecureChat Relay', sourceId: 'SRC-MSG-A', firstSeen: '2026-06-18T19:00:00Z', lastSeen: '2026-09-08T08:00:00Z', confidence: 80, normalized: 'pulsar' },
  { id: 'HND-014', value: 'driftwood', platform: 'DarkForum Alpha', sourceId: 'SRC-FORUM-A', firstSeen: '2026-01-10T00:00:00Z', lastSeen: '2026-03-12T00:00:00Z', confidence: 90, normalized: 'driftwood' },
  { id: 'HND-015', value: 'driftwood', platform: 'SecureChat Relay', sourceId: 'SRC-MSG-A', firstSeen: '2026-03-20T00:00:00Z', lastSeen: '2026-06-05T00:00:00Z', confidence: 92, normalized: 'driftwood' },
  { id: 'HND-016', value: 'meridian', platform: 'ZeroDump Paste', sourceId: 'SRC-PASTE-A', firstSeen: '2026-06-01T00:00:00Z', lastSeen: '2026-06-01T00:00:00Z', confidence: 40, normalized: 'meridian' },
];

// ── PGP keys ────────────────────────────────────────────────────
export const darkWebPgpKeys: PgpKey[] = [
  { id: 'PGP-001', fingerprint: '7E3F-A1B2-C9D4-E5F6-0A1B-2C3D-4E5F-6789-ABCD-1234', actorIds: ['ACTOR-001', 'ACTOR-003'], firstSeen: '2026-03-05T14:41:00Z', lastSeen: '2026-09-05T20:00:00Z', sources: ['SRC-MARKET-A', 'SRC-FORUM-B'], confidence: 96 },
  { id: 'PGP-002', fingerprint: 'A2F1-9B8C-7D6E-5F40-1A2B-3C4D-5E6F-7890-1234-5678', actorIds: ['ACTOR-002'], firstSeen: '2026-03-15T00:00:00Z', lastSeen: '2026-07-05T14:18:00Z', sources: ['SRC-FORUM-B'], confidence: 92 },
  { id: 'PGP-003', fingerprint: '3D8A-1B2C-4E5F-7091-2A3B-4C5D-6E7F-89AB-CDEF-5678', actorIds: ['ACTOR-004'], firstSeen: '2026-06-18T19:00:00Z', lastSeen: '2026-09-10T15:30:00Z', sources: ['SRC-FORUM-A', 'SRC-MSG-A'], confidence: 88 },
  { id: 'PGP-004', fingerprint: '9F4E-3D2C-1B0A-987F-6543-210F-EDEF-0ABC-1234-5678', actorIds: ['ACTOR-005'], firstSeen: '2026-01-10T00:00:00Z', lastSeen: '2026-06-05T00:00:00Z', sources: ['SRC-FORUM-A', 'SRC-MSG-A'], confidence: 94 },
];

// ── Wallets ─────────────────────────────────────────────────────
export const darkWebWallets: Wallet[] = [
  { id: 'WAL-001', address: 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq', actorIds: ['ACTOR-001', 'ACTOR-003'], observedSources: ['SRC-MARKET-A', 'SRC-LEAK-A'], firstSeen: '2026-03-05T14:41:00Z', lastSeen: '2026-09-05T20:00:00Z', txCount: 12, confidence: 89 },
  { id: 'WAL-002', address: 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3', actorIds: ['ACTOR-002', 'ACTOR-003'], observedSources: ['SRC-MARKET-B', 'SRC-LEAK-A'], firstSeen: '2026-04-22T10:00:00Z', lastSeen: '2026-08-20T12:00:00Z', txCount: 8, confidence: 84 },
  { id: 'WAL-003', address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', actorIds: ['ACTOR-004'], observedSources: ['SRC-MARKET-A'], firstSeen: '2026-06-18T19:00:00Z', lastSeen: '2026-09-10T15:30:00Z', txCount: 5, confidence: 77 },
  { id: 'WAL-004', address: 'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y', actorIds: ['ACTOR-005'], observedSources: ['SRC-PASTE-A'], firstSeen: '2026-06-01T00:00:00Z', lastSeen: '2026-06-01T00:00:00Z', txCount: 1, confidence: 62 },
];

// ── Infrastructure ──────────────────────────────────────────────
export const darkWebInfrastructure: Infrastructure[] = [
  { id: 'INF-001', type: 'DOMAIN', value: 'shadowrelay-onion.net', actorIds: ['ACTOR-001'], firstSeen: '2026-03-05T14:41:00Z', lastSeen: '2026-05-19T22:05:00Z', registrar: 'Porkbun', hostingProvider: 'Nforce', country: 'NL', tlsIssuer: 'R3 (Let\'s Encrypt)' },
  { id: 'INF-002', type: 'IP', value: '185.220.101.47', actorIds: ['ACTOR-001', 'ACTOR-002'], firstSeen: '2026-03-05T14:41:00Z', lastSeen: '2026-08-30T06:44:00Z', hostingProvider: 'Hosting Solutions GmbH', country: 'DE', asn: 'AS209588' },
  { id: 'INF-003', type: 'IP', value: '45.142.212.83', actorIds: ['ACTOR-002', 'ACTOR-003'], firstSeen: '2026-04-22T10:00:00Z', lastSeen: '2026-08-20T12:00:00Z', hostingProvider: 'NetArt Group Ltd.', country: 'PL', asn: 'AS47674' },
  { id: 'INF-004', type: 'DOMAIN', value: 'ghostwire-relay.net', actorIds: ['ACTOR-001', 'ACTOR-003'], firstSeen: '2026-07-15T09:00:00Z', lastSeen: '2026-09-08T18:22:00Z', registrar: 'Njalla', hostingProvider: 'Nforce', country: 'NL', tlsIssuer: 'R3 (Let\'s Encrypt)' },
  { id: 'INF-005', type: 'TLS', value: 'sha256:ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef:12', actorIds: ['ACTOR-001', 'ACTOR-002', 'ACTOR-003'], firstSeen: '2026-03-05T14:41:00Z', lastSeen: '2026-08-30T06:44:00Z', tlsIssuer: 'R3 (Let\'s Encrypt)' },
  { id: 'INF-006', type: 'DOMAIN', value: 'pulsar-drop.onion', actorIds: ['ACTOR-004'], firstSeen: '2026-06-18T19:00:00Z', lastSeen: '2026-09-10T15:30:00Z', registrar: 'N/A (onion service)', hostingProvider: 'Tor', country: 'UN'.replace('A', 'nknown') },
];

// ── Threat Actors ───────────────────────────────────────────────
export const threatActors: ThreatActor[] = [
  {
    id: 'ACTOR-001',
    aliases: ['The Shadow Broker', 'Shadow Syndicate Operator'],
    handles: ['shadowfox', 'ShadowFox', 'ghostwire'],
    pgpFingerprints: ['7E3F-A1B2-C9D4-E5F6-0A1B-2C3D-4E5F-6789-ABCD-1234'],
    walletAddrs: ['bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'],
    domains: ['shadowrelay-onion.net', 'ghostwire-relay.net'],
    platforms: ['DarkForum Alpha', 'Nexus Markets', 'Abyssal Bazaar'],
    firstSeen: '2026-02-14T03:22:00Z',
    lastSeen: '2026-09-08T18:22:00Z',
    activityLevel: 'HIGH',
    confidenceScore: 91,
    status: 'ACTIVE',
    relatedActorIds: ['ACTOR-002', 'ACTOR-003'],
    associatedEvidence: ['EVID-001', 'EVID-003', 'EVID-005', 'EVID-007', 'EVID-009'],
    behavioralProfile: {
      activityFrequency: 'HIGH',
      activeHours: [{ hour: 2, level: 90 }, { hour: 3, level: 95 }, { hour: 14, level: 85 }, { hour: 22, level: 70 }],
      platformPreferences: [{ platform: 'DarkForum Alpha', weight: 55 }, { platform: 'Nexus Markets', weight: 30 }, { platform: 'Abyssal Bazaar', weight: 15 }],
      postingFrequency: 28,
      topicClusters: ['Credential Sales', 'Access Brokering', 'Infrastructure Rental'],
      interactionPattern: 'Targeted engagement — responds selectively, posts high-signal offers',
      personaTransitions: 2,
    },
    stylometricProfile: {
      avgSentenceLength: 18.4,
      punctuationPattern: 'Minimal punctuation; frequent semicolons and em-dashes',
      capitalisationTendency: 'LOW',
      vocabularyRichness: 0.68,
      recurringExpressions: ['as above', 'escrow only', 'rate is firm', 'no refunds', 'PM for access'],
      sentenceStructure: 'Short declarative statements with embedded clauses',
      languagePatterns: ['Prefers lowercase handles in posts', 'Uses bullet-style listings', 'Avoids profanity, favouring precise terminology'],
      sampleText: 'Payment on delivery. Rate is firm. Escrow only. As above. PM for access to the relay. No refunds once confirmed.',
    },
    primaryMotivation: 'Financial gain via access brokering and credential sales',
    isSynthetic: true,
  },
  {
    id: 'ACTOR-002',
    aliases: ['The Infrastructure Broker'],
    handles: ['VoidCipher', 'nightstalk'],
    pgpFingerprints: ['A2F1-9B8C-7D6E-5F40-1A2B-3C4D-5E6F-7890-1234-5678', '7E3F-A1B2-C9D4-E5F6-0A1B-2C3D-4E5F-6789-ABCD-1234'],
    walletAddrs: ['bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3'],
    domains: ['ghostwire-relay.net'],
    platforms: ['BlackVault Forums', 'Abyssal Bazaar', 'Nexus Markets'],
    firstSeen: '2026-03-15T00:00:00Z',
    lastSeen: '2026-09-08T18:22:00Z',
    activityLevel: 'HIGH',
    confidenceScore: 87,
    status: 'ACTIVE',
    relatedActorIds: ['ACTOR-001', 'ACTOR-003'],
    associatedEvidence: ['EVID-002', 'EVID-004', 'EVID-006', 'EVID-008'],
    behavioralProfile: {
      activityFrequency: 'MEDIUM',
      activeHours: [{ hour: 4, level: 80 }, { hour: 16, level: 90 }, { hour: 23, level: 60 }],
      platformPreferences: [{ platform: 'Abyssal Bazaar', weight: 60 }, { platform: 'BlackVault Forums', weight: 40 }],
      postingFrequency: 14,
      topicClusters: ['Hosting Services', 'VPN/Tor Relays', 'Infrastructure Laundering'],
      interactionPattern: 'Vendor-style — posts fixed-price listings, responds to orders quickly',
      personaTransitions: 1,
    },
    stylometricProfile: {
      avgSentenceLength: 12.1,
      punctuationPattern: 'Heavy use of periods; terse, list-oriented style',
      capitalisationTendency: 'HIGH',
      vocabularyRichness: 0.54,
      recurringExpressions: ['specs', 'bandwidth included', 'dedicated', 'one week delivery', 'BTC only'],
      sentenceStructure: 'Bullet-point listings with short phrases',
      languagePatterns: ['Uses ALL CAPS for emphasis', 'Prefers technical specs', 'Lists delivery terms explicitly'],
      sampleText: 'SPECS: 1GBps. BANDWIDTH INCLUDED. DEDICATED. ONE WEEK DELIVERY. BTC ONLY.',
    },
    primaryMotivation: 'Infrastructure rental and laundering services',
    isSynthetic: true,
  },
  {
    id: 'ACTOR-003',
    aliases: ['The Cipher Migrant'],
    handles: ['nightstalk', 'ghostwire'],
    pgpFingerprints: ['7E3F-A1B2-C9D4-E5F6-0A1B-2C3D-4E5F-6789-ABCD-1234'],
    walletAddrs: ['bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq', 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3'],
    domains: ['ghostwire-relay.net', 'shadowrelay-onion.net'],
    platforms: ['DarkForum Alpha', 'Abyssal Bazaar'],
    firstSeen: '2026-07-15T09:00:00Z',
    lastSeen: '2026-09-13T03:00:00Z',
    activityLevel: 'HIGH',
    confidenceScore: 94,
    status: 'ACTIVE',
    relatedActorIds: ['ACTOR-001', 'ACTOR-002'],
    associatedEvidence: ['EVID-010', 'EVID-011', 'EVID-012'],
    behavioralProfile: {
      activityFrequency: 'HIGH',
      activeHours: [{ hour: 2, level: 90 }, { hour: 14, level: 80 }, { hour: 22, level: 85 }],
      platformPreferences: [{ platform: 'DarkForum Alpha', weight: 40 }, { platform: 'Abyssal Bazaar', weight: 60 }],
      postingFrequency: 22,
      topicClusters: ['Credential Sales', 'Infrastructure Rental', 'Tool Development'],
      interactionPattern: 'High-volume poster — similar cadence to ACTOR-001, suggesting migration',
      personaTransitions: 0,
    },
    stylometricProfile: {
      avgSentenceLength: 17.8,
      punctuationPattern: 'Minimal punctuation; frequent semicolons and em-dashes',
      capitalisationTendency: 'LOW',
      vocabularyRichness: 0.70,
      recurringExpressions: ['as above', 'escrow only', 'rate is firm', 'no refunds', 'PM for access'],
      sentenceStructure: 'Short declarative statements with embedded clauses',
      languagePatterns: ['Prefers lowercase handles in posts', 'Uses bullet-style listings', 'Avoids profanity, favouring precise terminology'],
      sampleText: 'Escrow only. As above. PM for access to the relay. Rate is firm. No refunds once confirmed.',
    },
    primaryMotivation: 'Continuing access brokering under an evolved persona',
    isSynthetic: true,
  },
  {
    id: 'ACTOR-004',
    aliases: ['The Leak Operator'],
    handles: ['pulsar', 'VoidCipher'],
    pgpFingerprints: ['3D8A-1B2C-4E5F-7091-2A3B-4C5D-6E7F-89AB-CDEF-5678'],
    walletAddrs: ['bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'],
    domains: ['pulsar-drop.onion'],
    platforms: ['DarkForum Alpha', 'SecureChat Relay', 'BreachVault Leak Site'],
    firstSeen: '2026-06-18T19:00:00Z',
    lastSeen: '2026-09-13T03:00:00Z',
    activityLevel: 'MEDIUM',
    confidenceScore: 76,
    status: 'ACTIVE',
    relatedActorIds: ['ACTOR-005'],
    associatedEvidence: ['EVID-013', 'EVID-014'],
    behavioralProfile: {
      activityFrequency: 'MEDIUM',
      activeHours: [{ hour: 8, level: 70 }, { hour: 20, level: 85 }],
      platformPreferences: [{ platform: 'BreachVault Leak Site', weight: 50 }, { platform: 'DarkForum Alpha', weight: 30 }, { platform: 'SecureChat Relay', weight: 20 }],
      postingFrequency: 9,
      topicClusters: ['Data Leaks', 'Ransom Negotiation', 'Extortion'],
      interactionPattern: 'Burst-style — long dormant periods followed by rapid leak releases',
      personaTransitions: 1,
    },
    stylometricProfile: {
      avgSentenceLength: 22.1,
      punctuationPattern: 'Uses full stops and structured paragraphs; formal tone',
      capitalisationTendency: 'MEDIUM',
      vocabularyRichness: 0.82,
      recurringExpressions: ['proof of breach', 'deadline is firm', 'no extension', 'verification sample'],
      sentenceStructure: 'Complex paragraphs with conditional clauses',
      languagePatterns: ['Formal register', 'References legal/business terms', 'Sets explicit deadlines'],
      sampleText: 'Proof of breach has been verified. The deadline is firm; no extension will be granted. A verification sample is available upon request.',
    },
    primaryMotivation: 'Extortion and data-leak monetisation',
    isSynthetic: true,
  },
  {
    id: 'ACTOR-005',
    aliases: ['The Original Drift', 'Recruiter'],
    handles: ['driftwood', 'pulsar'],
    pgpFingerprints: ['9F4E-3D2C-1B0A-987F-6543-210F-EDEF-0ABC-1234-5678'],
    walletAddrs: ['bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y'],
    domains: ['pulsar-drop.onion'],
    platforms: ['DarkForum Alpha', 'SecureChat Relay'],
    firstSeen: '2026-01-10T00:00:00Z',
    lastSeen: '2026-06-05T00:00:00Z',
    activityLevel: 'LOW',
    confidenceScore: 82,
    status: 'DORMANT',
    relatedActorIds: ['ACTOR-004'],
    associatedEvidence: ['EVID-015'],
    behavioralProfile: {
      activityFrequency: 'LOW',
      activeHours: [{ hour: 1, level: 80 }, { hour: 15, level: 70 }],
      platformPreferences: [{ platform: 'SecureChat Relay', weight: 55 }, { platform: 'DarkForum Alpha', weight: 45 }],
      postingFrequency: 6,
      topicClusters: ['Recruitment', 'Access Brokering', 'Training Materials'],
      interactionPattern: 'Recruiter-style — reaches out to new actors, mentors transitions',
      personaTransitions: 1,
    },
    stylometricProfile: {
      avgSentenceLength: 24.6,
      punctuationPattern: 'Uses commas for pauses; explanatory tone',
      capitalisationTendency: 'MEDIUM',
      vocabularyRichness: 0.76,
      recurringExpressions: ['reach out', 'for the right candidate', 'training available', 'pm to discuss terms'],
      sentenceStructure: 'Explanatory sentences with qualifying clauses',
      languagePatterns: ['Mentor-like tone', 'Sets expectations explicitly', 'References prior experience'],
      sampleText: 'Reach out if you have the right candidate in mind. Training is available for the right individual. PM to discuss terms, as experience is valued here.',
    },
    primaryMotivation: 'Recruitment and knowledge transfer to successor personas',
    isSynthetic: true,
  },
];

// ── Relationships ───────────────────────────────────────────────
export const darkWebRelationships: Relationship[] = [
  { id: 'REL-001', sourceEntity: 'shadowfox', targetEntity: 'ShadowFox', sourceType: 'Handle', targetType: 'Handle', type: 'SHARED_HANDLE', confidence: 75, evidenceIds: ['EVID-001'], explanation: 'Handle reuses identical normalized form across Forum A and Marketplace A; casing differs by platform convention only.', firstObserved: '2026-02-14T03:22:00Z', lastObserved: '2026-05-19T22:05:00Z', supporting: ['Identical normalized handle', 'Same PGP fingerprint observed', 'Overlapping activity window'], against: ['Different platform registration contexts'], },
  { id: 'REL-002', sourceEntity: 'ACTOR-001', targetEntity: 'ACTOR-002', sourceType: 'Actor', targetType: 'Actor', type: 'ASSOCIATED_WITH', confidence: 82, evidenceIds: ['EVID-002', 'EVID-005'], explanation: 'Actors transacted on the same marketplace thread (Nexus Markets) and share a PGP fingerprint (PGP-001). Transferred escrow for a joint listing.', firstObserved: '2026-03-05T14:41:00Z', lastObserved: '2026-05-19T22:05:00Z', supporting: ['Shared PGP fingerprint', 'Shared marketplace thread', 'Shared TLS certificate fingerprint'], against: ['No direct wallet sharing between these two actors'], },
  { id: 'REL-003', sourceEntity: 'ACTOR-001', targetEntity: 'ACTOR-003', sourceType: 'Actor', targetType: 'Actor', type: 'PERSONA_MIGRATION', confidence: 91, evidenceIds: ['EVID-006', 'EVID-007', 'EVID-008'], explanation: 'ACTOR-001 (shadowfox/ghostwire) ceases activity on DarkForum Alpha after Sep 8; ACTOR-003 (ghostwire) appears on Abyssal Bazaar with the same PGP, wallet, infrastructure and near-identical stylometry. ACTOR-001 last seen as ghostwire; ACTOR-003 first seen as ghostwire on a different platform.', firstObserved: '2026-07-15T09:00:00Z', lastObserved: '2026-09-13T03:00:00Z', supporting: ['Shared PGP fingerprint (100%)', 'Shared wallet address', 'Shared infrastructure (ghostwire-relay.net)', 'Stylometric similarity 88%', 'Persona name ghostwire reused', 'Overlapping active hours (02:00–03:00 UTC)'], against: ['Different primary handle lineage', 'No explicit admission of migration'], },
  { id: 'REL-004', sourceEntity: 'ACTOR-002', targetEntity: 'ACTOR-003', sourceType: 'Actor', targetType: 'Actor', type: 'ASSOCIATED_WITH', confidence: 86, evidenceIds: ['EVID-004', 'EVID-005'], explanation: 'Both actors used the same relay IP (185.220.101.47) and a shared wallet on Abyssal Bazaar. Infrastructure overlap suggests a common operator or close partnership.', firstObserved: '2026-04-22T10:00:00Z', lastObserved: '2026-08-20T12:00:00Z', supporting: ['Shared relay IP 185.220.101.47', 'Shared wallet address', 'Same TLS certificate fingerprint'], against: ['No shared PGP fingerprint between ACTOR-002 and ACTOR-003 directly'], },
  { id: 'REL-005', sourceEntity: 'nightstalk', targetEntity: 'nightstalk', sourceType: 'Handle', targetType: 'Handle', type: 'SHARED_HANDLE', confidence: 70, evidenceIds: ['EVID-006'], explanation: 'Identical handle on BlackVault Forums and Abyssal Bazaar. Both platforms active in the same May–July window.', firstObserved: '2026-05-02T11:09:00Z', lastObserved: '2026-07-21T17:55:00Z', supporting: ['Identical handle spelling', 'Overlapping activity dates', 'Both reference ghostwire-relay.net'], against: ['Handle registration timestamps differ'], },
  { id: 'REL-006', sourceEntity: 'pulsar', targetEntity: 'pulsar', sourceType: 'Handle', targetType: 'Handle', type: 'SHARED_HANDLE', confidence: 85, evidenceIds: ['EVID-013'], explanation: 'Identical handle on DarkForum Alpha and SecureChat Relay, plus PGP-003 tied to both sessions. High-confidence link.', firstObserved: '2026-06-18T19:00:00Z', lastObserved: '2026-09-10T15:30:00Z', supporting: ['Identical handle', 'Shared PGP fingerprint PGP-003', 'Same onion service pulsar-drop.onion'], against: ['Messaging platform handle registration differs'], },
  { id: 'REL-007', sourceEntity: 'driftwood', targetEntity: 'driftwood', sourceType: 'Handle', targetType: 'Handle', type: 'SHARED_HANDLE', confidence: 92, evidenceIds: ['EVID-015'], explanation: 'Identical handle on DarkForum Alpha and SecureChat Relay, both tied to PGP-004. Persona migrated from driftwood to pulsar (recruitment).', firstObserved: '2026-01-10T00:00:00Z', lastObserved: '2026-06-05T00:00:00Z', supporting: ['Identical handle', 'Shared PGP fingerprint PGP-004', 'Shared onion service pulsar-drop.onion'], against: ['Different posting cadence after migration'], },
  { id: 'REL-008', sourceEntity: 'VoidCipher', targetEntity: 'VoidCipher', sourceType: 'Handle', targetType: 'Handle', type: 'SHARED_HANDLE', confidence: 90, evidenceIds: ['EVID-002', 'EVID-009'], explanation: 'Handle reused across DarkForum Alpha, Nexus Markets, and BreachVault Leak Site. PGP-002 tied to the DarkForum session.', firstObserved: '2026-03-01T00:00:00Z', lastObserved: '2026-09-10T23:59:00Z', supporting: ['Identical handle', 'Shared PGP fingerprint PGP-002 (DarkForum)', 'Activity overlaps with ACTOR-001 campaign'], against: ['BreachVault session has no PGP signature'], },
  { id: 'REL-009', sourceEntity: '185.220.101.47', targetEntity: '45.142.212.83', sourceType: 'Infrastructure', targetType: 'Infrastructure', type: 'SHARED_INFRASTRUCTURE', confidence: 78, evidenceIds: ['EVID-005'], explanation: 'Relay IPs observed in the same connection chain across multiple marketplace sessions.', firstObserved: '2026-04-22T10:00:00Z', lastObserved: '2026-08-20T12:00:00Z', supporting: ['Co-occurring relay chain', 'Same hosting provider family'], against: ['IPs are distinct hosts'], },
  { id: 'REL-010', sourceEntity: 'crypthoax', targetEntity: 'crypthoax', sourceType: 'Handle', targetType: 'Handle', type: 'SHARED_HANDLE', confidence: 62, evidenceIds: ['EVID-010'], explanation: 'Handle appears on BlackVault Forums and Abyssal Bazaar with similar punctuation style. Lower confidence due to short activity windows.', firstObserved: '2026-03-15T00:00:00Z', lastObserved: '2026-06-30T20:00:00Z', supporting: ['Identical handle', 'Similar punctuation (heavy periods)'], against: ['Short observation windows', 'No shared cryptographic identifiers'], },
];

// ── Evidence ────────────────────────────────────────────────────
export const darkWebEvidence: Evidence[] = [
  { id: 'EVID-001', source: 'DarkForum Alpha', sourceType: 'FORUM', timestamp: '2026-02-14T03:22:00Z', collectionTimestamp: '2026-09-12T14:22:00Z', hash: 'sha256:3a4f7c9b2e1d8a6f0c5b4e3d2a1f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f', relatedActor: 'ACTOR-001', relatedRelationship: 'REL-001', evidenceType: 'FORUM_POST', reliability: 90, confidence: 75, provenance: 'DarkForum Alpha › thread #3847 "Looking for escrow relay" › post by shadowfox', isSynthetic: true },
  { id: 'EVID-002', source: 'Nexus Markets', sourceType: 'MARKETPLACE', timestamp: '2026-03-05T14:41:00Z', collectionTimestamp: '2026-09-12T14:22:00Z', hash: 'sha256:2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c', relatedActor: 'ACTOR-001', relatedRelationship: 'REL-002', evidenceType: 'MARKETPLACE_LISTING', reliability: 88, confidence: 88, provenance: 'Nexus Markets › listing #5521 "Tor relay 1GBps" › PGP-signed by PGP-001', isSynthetic: true },
  { id: 'EVID-003', source: 'DarkForum Alpha', sourceType: 'FORUM', timestamp: '2026-04-10T14:00:00Z', collectionTimestamp: '2026-09-12T14:22:00Z', hash: 'sha256:9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e', relatedActor: 'ACTOR-001', relatedRelationship: 'REL-001', evidenceType: 'PGP_KEY', reliability: 95, confidence: 96, provenance: 'DarkForum Alpha › PGP key PGP-001 published in actor signature block', isSynthetic: true },
  { id: 'EVID-004', source: 'Abyssal Bazaar', sourceType: 'MARKETPLACE', timestamp: '2026-04-22T10:00:00Z', collectionTimestamp: '2026-09-12T14:22:00Z', hash: 'sha256:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b', relatedActor: 'ACTOR-002', relatedRelationship: 'REL-004', evidenceType: 'MARKETPLACE_LISTING', reliability: 85, confidence: 82, provenance: 'Abyssal Bazaar › listing #712 "Dedicated relay, 1Gbps, BTC" › references ghostwire-relay.net', isSynthetic: true },
  { id: 'EVID-005', source: 'Abyssal Bazaar', sourceType: 'MARKETPLACE', timestamp: '2026-05-01T09:30:00Z', collectionTimestamp: '2026-09-12T14:22:00Z', hash: 'sha256:3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e', relatedActor: 'ACTOR-002', relatedRelationship: 'REL-004', evidenceType: 'TRANSACTION', reliability: 90, confidence: 85, provenance: 'Abyssal Bazaar › escrow transaction TX-005 › BTC to WAL-002 › relay IP 185.220.101.47', isSynthetic: true },
  { id: 'EVID-006', source: 'BlackVault Forums', sourceType: 'FORUM', timestamp: '2026-05-02T11:09:00Z', collectionTimestamp: '2026-09-12T14:22:00Z', hash: 'sha256:8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c', relatedActor: 'ACTOR-003', relatedRelationship: 'REL-005', evidenceType: 'FORUM_POST', reliability: 82, confidence: 70, provenance: 'BlackVault Forums › thread #221 "Migration guides" › post by nightstalk', isSynthetic: true },
  { id: 'EVID-007', source: 'Abyssal Bazaar', sourceType: 'MARKETPLACE', timestamp: '2026-07-15T09:00:00Z', collectionTimestamp: '2026-09-12T14:22:00Z', hash: 'sha256:5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b', relatedActor: 'ACTOR-003', relatedRelationship: 'REL-003', evidenceType: 'MARKETPLACE_LISTING', reliability: 90, confidence: 92, provenance: 'Abyssal Bazaar › listing #801 "ghostwire-relay.net — 1GBps, PGP-001 signed"', isSynthetic: true },
  { id: 'EVID-008', source: 'Abyssal Bazaar', sourceType: 'MARKETPLACE', timestamp: '2026-08-20T12:00:00Z', collectionTimestamp: '2026-09-12T14:22:00Z', hash: 'sha256:7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b', relatedActor: 'ACTOR-003', relatedRelationship: 'REL-003', evidenceType: 'TRANSACTION', reliability: 88, confidence: 89, provenance: 'Abyssal Bazaar › payment to WAL-001 (shared with ACTOR-001)', isSynthetic: true },
  { id: 'EVID-009', source: 'BreachVault Leak Site', sourceType: 'LEAK_SITE', timestamp: '2026-08-28T00:00:00Z', collectionTimestamp: '2026-09-13T03:00:00Z', hash: 'sha256:0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f', relatedActor: 'ACTOR-004', relatedRelationship: 'REL-008', evidenceType: 'LEAK_RECORD', reliability: 95, confidence: 88, provenance: 'BreachVault › leak #LV-044 › metadata lists VoidCipher handle', isSynthetic: true },
  { id: 'EVID-010', source: 'DarkForum Alpha', sourceType: 'FORUM', timestamp: '2026-09-08T18:22:00Z', collectionTimestamp: '2026-09-12T14:22:00Z', hash: 'sha256:4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c', relatedActor: 'ACTOR-001', relatedRelationship: null, evidenceType: 'FORUM_POST', reliability: 85, confidence: 84, provenance: 'DarkForum Alpha › last post by ghostwire › "moving on to greener pastures"', isSynthetic: true },
  { id: 'EVID-011', source: 'Abyssal Bazaar', sourceType: 'MARKETPLACE', timestamp: '2026-09-10T23:59:00Z', collectionTimestamp: '2026-09-13T03:00:00Z', hash: 'sha256:6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e', relatedActor: 'ACTOR-003', relatedRelationship: 'REL-003', evidenceType: 'FORUM_POST', reliability: 92, confidence: 92, provenance: 'Abyssal Bazaar › signature block updated to PGP-001, ghostwire handle › first activity 2026-07-15', isSynthetic: true },
  { id: 'EVID-012', source: 'OpenCTI Feed', sourceType: 'THREAT_FEED', timestamp: '2026-09-10T15:30:00Z', collectionTimestamp: '2026-09-13T04:00:00Z', hash: 'sha256:c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9', relatedActor: 'ACTOR-003', relatedRelationship: 'REL-003', evidenceType: 'LEAK_RECORD', reliability: 98, confidence: 94, provenance: 'OpenCTI Feed › corroborates ghostwire-relay.net with ACTOR-001 infrastructure', isSynthetic: true },
  { id: 'EVID-013', source: 'SecureChat Relay', sourceType: 'MESSAGING', timestamp: '2026-06-18T19:00:00Z', collectionTimestamp: '2026-09-12T20:30:00Z', hash: 'sha256:b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0', relatedActor: 'ACTOR-004', relatedRelationship: 'REL-006', evidenceType: 'MESSAGE', reliability: 80, confidence: 85, provenance: 'SecureChat Relay › DM from pulsar › references pulsar-drop.onion', isSynthetic: true },
  { id: 'EVID-014', source: 'BreachVault Leak Site', sourceType: 'LEAK_SITE', timestamp: '2026-09-10T01:20:00Z', collectionTimestamp: '2026-09-13T03:00:00Z', hash: 'sha256:e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7', relatedActor: 'ACTOR-004', relatedRelationship: null, evidenceType: 'LEAK_RECORD', reliability: 95, confidence: 88, provenance: 'BreachVault › leak #LV-051 › PGP-003 signature present', isSynthetic: true },
  { id: 'EVID-015', source: 'DarkForum Alpha', sourceType: 'FORUM', timestamp: '2026-03-20T00:00:00Z', collectionTimestamp: '2026-09-12T14:22:00Z', hash: 'sha256:0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c', relatedActor: 'ACTOR-005', relatedRelationship: 'REL-007', evidenceType: 'FORUM_POST', reliability: 90, confidence: 92, provenance: 'DarkForum Alpha › recruitment thread #99 › post by driftwood referencing pulsar-drop.onion', isSynthetic: true },
];

// ── Timeline events ─────────────────────────────────────────────
export const darkWebTimeline: TimelineEvent[] = [
  { id: 'TL-001', actorId: 'ACTOR-001', time: '2026-02-14T03:22:00Z', type: 'FIRST_SEEN', title: 'First Handle Detected', description: 'shadowfox first observed on DarkForum Alpha (SRC-FORUM-A).', confidence: 60 },
  { id: 'TL-002', actorId: 'ACTOR-001', time: '2026-03-01T00:00:00Z', type: 'HANDLE_CHANGE', title: 'New Handle — VoidCipher', description: 'VoidCipher identity registered on DarkForum Alpha.', confidence: 85 },
  { id: 'TL-003', actorId: 'ACTOR-001', time: '2026-03-05T14:41:00Z', type: 'PLATFORM_ACTIVITY', title: 'Marketplace Debut', description: 'ShadowFox listed a Tor relay on Nexus Markets under PGP-001.', confidence: 90 },
  { id: 'TL-004', actorId: 'ACTOR-001', time: '2026-07-15T09:00:00Z', type: 'INFRASTRUCTURE_CHANGE', title: 'New Relay Domain', description: 'ghostwire-relay.net registered; SSL cert shared with ACTOR-002.', confidence: 85 },
  { id: 'TL-005', actorId: 'ACTOR-001', time: '2026-09-08T18:22:00Z', type: 'LAST_SEEN', title: 'Last Activity (Persona A)', description: 'Last post as ghostwire: "moving on to greener pastures".', confidence: 95 },
  { id: 'TL-006', actorId: 'ACTOR-003', time: '2026-07-15T09:00:00Z', type: 'FIRST_SEEN_NEW', title: 'New Persona Appears', description: 'ACTOR-003 (ghostwire) first observed on Abyssal Bazaar.', confidence: 88 },
  { id: 'TL-007', actorId: 'ACTOR-003', time: '2026-08-28T00:00:00Z', type: 'EVIDENCE_COLLECTION', title: 'Leak Corroboration', description: 'BreachVault leak #LV-044 references VoidCipher; corroborates ACTOR-001 link.', confidence: 88 },
  { id: 'TL-008', actorId: 'ACTOR-003', time: '2026-09-10T23:59:00Z', type: 'PERSONA_MIGRATION', title: 'Persona Migration Confirmed', description: 'PGP-001 and shared wallet observed on ACTOR-003 infra. Migration from ACTOR-001 confirmed.', confidence: 94 },
  { id: 'TL-009', actorId: 'ACTOR-002', time: '2026-03-15T00:00:00Z', type: 'FIRST_SEEN', title: 'Infrastructure Broker Emerges', description: 'VoidCipher/nightstalk first seen on BlackVault Forums.', confidence: 80 },
  { id: 'TL-010', actorId: 'ACTOR-002', time: '2026-04-22T10:00:00Z', type: 'PLATFORM_ACTIVITY', title: 'Infrastructure Sale', description: 'Listed ghostwire-relay.net on Abyssal Bazaar.', confidence: 85 },
  { id: 'TL-011', actorId: 'ACTOR-002', time: '2026-05-01T09:30:00Z', type: 'RELATIONSHIP_FORMATION', title: 'Escrow Partnership', description: 'Shared escrow transaction with ACTOR-001 on Nexus Markets.', confidence: 88 },
  { id: 'TL-012', actorId: 'ACTOR-004', time: '2026-06-18T19:00:00Z', type: 'FIRST_SEEN', title: 'Leak Operator Emerges', description: 'pulsar first seen on DarkForum Alpha.', confidence: 75 },
  { id: 'TL-013', actorId: 'ACTOR-004', time: '2026-08-10T11:30:00Z', type: 'EVIDENCE_COLLECTION', title: 'Leak Publication', description: 'BreachVault leak #LV-044 references VoidCipher handle.', confidence: 90 },
  { id: 'TL-014', actorId: 'ACTOR-005', time: '2026-01-10T00:00:00Z', type: 'FIRST_SEEN', title: 'Recruiter Emerges', description: 'driftwood first seen on DarkForum Alpha recruitment thread.', confidence: 90 },
  { id: 'TL-015', actorId: 'ACTOR-005', time: '2026-04-15T00:00:00Z', type: 'PERSONA_MIGRATION', title: 'Persona Transition', description: 'driftwood persona references handoff to pulsar candidate.', confidence: 72 },
  { id: 'TL-016', actorId: 'ACTOR-005', time: '2026-05-15T00:00:00Z', type: 'LAST_SEEN', title: 'Dormancy', description: 'driftwood last seen; persona dormant.', confidence: 90 },
];

// ── Alerts ──────────────────────────────────────────────────────
export const darkWebAlerts: Alert[] = [
  { id: 'DW-ALERT-001', type: 'NEW_ACTOR', severity: 'HIGH', title: 'New Threat Actor Detected — ACTOR-003', timestamp: '2026-07-16T09:00:00Z', actorId: 'ACTOR-003', reason: 'Persona matching ACTOR-001 (PGP-001, shared wallet) emerged on Abyssal Bazaar.', confidence: 88, evidenceIds: ['EVID-007'], status: 'OPEN' },
  { id: 'DW-ALERT-002', type: 'PERSONA_MIGRATION', severity: 'CRITICAL', title: 'Persona Migration: ACTOR-001 → ACTOR-003', timestamp: '2026-09-11T23:59:00Z', actorId: 'ACTOR-003', reason: 'Shared PGP fingerprint, wallet, and infrastructure with high stylometric similarity.', confidence: 94, evidenceIds: ['EVID-007', 'EVID-008', 'EVID-011', 'EVID-012'], status: 'OPEN' },
  { id: 'DW-ALERT-003', type: 'NEW_HANDLE', severity: 'MEDIUM', title: 'New Handle Reused — ghostwire', timestamp: '2026-07-15T09:00:00Z', actorId: 'ACTOR-001', reason: 'Handle ghostwire reused by ACTOR-001 on Abyssal Bazaar; matches prior platform usage.', confidence: 80, evidenceIds: ['EVID-007'], status: 'ACKNOWLEDGED' },
  { id: 'DW-ALERT-004', type: 'HIGH_CONFIDENCE_CORRELATION', severity: 'HIGH', title: 'High-Confidence Actor Correlation', timestamp: '2026-09-13T04:00:00Z', actorId: 'ACTOR-001', reason: 'PGP + wallet + infrastructure + stylometry convergence — 91% confidence.', confidence: 91, evidenceIds: ['EVID-002', 'EVID-005', 'EVID-008'], status: 'OPEN' },
  { id: 'DW-ALERT-005', type: 'ANOMALY_DETECTED', severity: 'LOW', title: 'Unusual Activity Spike — ACTOR-004', timestamp: '2026-09-10T01:20:00Z', actorId: 'ACTOR-004', reason: 'BreachVault leak publication after 12-hour dormant period.', confidence: 70, evidenceIds: ['EVID-014'], status: 'OPEN' },
];

// ── Investigations ──────────────────────────────────────────────
export const darkWebInvestigations: Investigation[] = [
  {
    id: 'INV-DW-001',
    title: 'Project SHADOWFOX — Persona Chain Investigation',
    description: 'Trace the shadowfox handle across platforms, correlate to ACTOR-001, detect persona migration to ACTOR-003, and map shared infrastructure.',
    status: 'ACTIVE',
    analyst: 'Dr. Priya Mehta',
    createdAt: '2026-09-13T04:30:00Z',
    updatedAt: '2026-09-13T04:30:00Z',
    seedActorId: 'ACTOR-001',
    confidence: 91,
    steps: [
      { step: 1, title: 'Initial Handle Detected', description: 'Search "shadowfox" — matched Forum A (DarkForum Alpha) and Marketplace A (Nexus Markets).', evidenceIds: ['EVID-001'], relationshipIds: ['REL-001'], actorIds: ['ACTOR-001'], confidence: 75 },
      { step: 2, title: 'Marketplace Identity Correlated', description: 'ShadowFox on Nexus Markets tied to PGP-001 — same key used on DarkForum Alpha (EVID-003).', evidenceIds: ['EVID-003'], relationshipIds: ['REL-002'], actorIds: ['ACTOR-001', 'ACTOR-002'], confidence: 86 },
      { step: 3, title: 'PGP Correlation', description: 'PGP-001 links ACTOR-001 to ACTOR-002 and ACTOR-003 across platforms.', evidenceIds: ['EVID-002', 'EVID-007'], relationshipIds: ['REL-002', 'REL-003'], actorIds: ['ACTOR-001', 'ACTOR-002', 'ACTOR-003'], confidence: 96 },
      { step: 4, title: 'Wallet Correlation', description: 'WAL-001 observed with ACTOR-001 and ACTOR-003 on Abyssal Bazaar.', evidenceIds: ['EVID-008'], relationshipIds: ['REL-003'], actorIds: ['ACTOR-001', 'ACTOR-003'], confidence: 89 },
      { step: 5, title: 'Infrastructure Correlation', description: 'ghostwire-relay.net + IP 185.220.101.47 shared across ACTOR-001, ACTOR-002, ACTOR-003.', evidenceIds: ['EVID-005', 'EVID-007'], relationshipIds: ['REL-003', 'REL-004', 'REL-009'], actorIds: ['ACTOR-001', 'ACTOR-002', 'ACTOR-003'], confidence: 84 },
      { step: 6, title: 'Behavioral & Stylometric Similarity', description: 'ACTOR-001 and ACTOR-003 share active hours (02:00), vocabulary, and recurring expressions.', evidenceIds: ['EVID-010', 'EVID-011'], relationshipIds: ['REL-003'], actorIds: ['ACTOR-001', 'ACTOR-003'], confidence: 88 },
      { step: 7, title: 'Persona Migration Detected', description: 'ACTOR-001 ceased DarkForum activity (Sep 8); ACTOR-003 began Abyssal Bazaar activity (Jul 15) using ghostwire handle, same PGP/wallet/infra.', evidenceIds: ['EVID-010', 'EVID-011', 'EVID-012'], relationshipIds: ['REL-003'], actorIds: ['ACTOR-001', 'ACTOR-003'], confidence: 94 },
      { step: 8, title: 'Evidence Corroboration', description: 'OpenCTI Feed (SRC-FEED-A) corroborates shared infrastructure; BreachVault references VoidCipher handle.', evidenceIds: ['EVID-009', 'EVID-012'], relationshipIds: [], actorIds: ['ACTOR-004'], confidence: 88 },
      { step: 9, title: 'Final Analytical Assessment', description: 'Shadowfox/ghostwire chain represents ACTOR-001 migrating to ACTOR-003. Overall confidence 91%. ACTOR-002 is an associated infrastructure broker, not the same persona.', evidenceIds: ['EVID-002', 'EVID-005', 'EVID-008', 'EVID-011', 'EVID-012'], relationshipIds: ['REL-001', 'REL-002', 'REL-003', 'REL-009'], actorIds: ['ACTOR-001', 'ACTOR-002', 'ACTOR-003'], confidence: 91 },
    ],
  },
];

// ── Monitoring status (autonomous intelligence) ─────────────────
export const darkWebMonitoring = {
  status: 'ACTIVE' as const,
  lastCollection: '2026-09-13T04:00:00Z',
  nextCollection: '2026-09-13T05:00:00Z',
  sourcesMonitored: darkWebSources.length,
  newIndicators: 12,
  newActors: 1,
  newRelationships: 5,
  alerts: darkWebAlerts.filter(a => a.status === 'OPEN').length,
};

// ── Convenience lookups ─────────────────────────────────────────
export const darkWebActors: ThreatActor[] = threatActors;
export const darkWebActorsById: Record<string, ThreatActor> = Object.fromEntries(threatActors.map(a => [a.id, a]));
export const darkWebEvidenceById: Record<string, Evidence> = Object.fromEntries(darkWebEvidence.map(e => [e.id, e]));
export const darkWebRelationshipsById: Record<string, Relationship> = Object.fromEntries(darkWebRelationships.map(r => [r.id, r]));
export const darkWebHandlesById: Record<string, Handle> = Object.fromEntries(darkWebHandles.map(h => [h.id, h]));
export const darkWebInvestigationById: Record<string, Investigation> = Object.fromEntries(darkWebInvestigations.map(i => [i.id, i]));
export const darkWebAlertById: Record<string, Alert> = Object.fromEntries(darkWebAlerts.map(a => [a.id, a]));

// ── Confidence breakdown template for the demo scenario ─────────
export const demoConfidenceBreakdown = {
  overall: 91,
  factors: [
    { label: 'Handle similarity', value: 75, weight: 15 },
    { label: 'PGP correlation', value: 100, weight: 25 },
    { label: 'Infrastructure overlap', value: 84, weight: 20 },
    { label: 'Behavior similarity', value: 88, weight: 15 },
    { label: 'Stylometry', value: 88, weight: 10 },
    { label: 'Timeline overlap', value: 94, weight: 15 },
  ],
};

// ── Synthetic threat intelligence reports ─────────────────────────
export interface Report {
  id: string;
  title: string;
  owner: string;
  type: 'ANALYTICAL' | 'CORRELATION' | 'CORRELATION_SUMMARY' | 'PROFILE';
  publishedAt: string;
  investigationId: string;
  confidence: number;
}

export const darkWebReports: Report[] = [
  { id: 'RPT-DW-001', title: 'Persona Migration Chains: shadowfox → ghostwire', owner: 'Dr. Priya Mehta', type: 'ANALYTICAL', publishedAt: '2026-09-13T05:30:00Z', investigationId: 'INV-DW-001', confidence: 91 },
  { id: 'RPT-DW-002', title: 'Shared Infrastructure Across ACTOR-001 and ACTOR-002', owner: 'Dr. Priya Mehta', type: 'CORRELATION', publishedAt: '2026-09-09T12:00:00Z', investigationId: 'INV-DW-001', confidence: 84 },
  { id: 'RPT-DW-003', title: 'Handle Reuse Patterns in Nexus Markets', owner: 'M. Chen', type: 'CORRELATION', publishedAt: '2026-08-22T09:10:00Z', investigationId: 'INV-DW-001', confidence: 78 },
  { id: 'RPT-DW-004', title: 'Behavioral Profile: The Leak Operator', owner: 'Dr. Priya Mehta', type: 'PROFILE', publishedAt: '2026-09-10T16:45:00Z', investigationId: 'INV-DW-001', confidence: 76 },
];

