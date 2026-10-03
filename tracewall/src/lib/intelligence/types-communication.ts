// ============================================================
// PhishNet — Communication & Methodology Type Definitions
//
// Communication channel and methodology/TTP types for threat actor analysis.
// These types extend the central intelligence model.
// ============================================================

/** Communication platform types */
export type CommunicationPlatform =
  | 'FORUM'
  | 'MARKETPLACE'
  | 'MESSAGING_APP'
  | 'SOCIAL_MEDIA'
  | 'ENCRYPTED_MESSENGER'
  | 'IRC'
  | 'XMPP'
  | 'DISCORD'
  | 'TELEGRAM'
  | 'SIGNAL'
  | 'WHATSAPP'
  | 'THREAT_FEED'
  | 'LEAK_SITE'
  | 'PASTE_SITE'
  | 'EMAIL'
  | 'ONION_SERVICE'
  | 'OTHER';

/** Communication channel type */
export type ChannelType =
  | 'PUBLIC'
  | 'PRIVATE'
  | 'INVITE_ONLY'
  | 'ENCRYPTED'
  | 'ANONYMOUS'
  | 'VERIFIED'
  | 'MODERATED'
  | 'UNMODERATED';

/** Message type */
export type MessageType =
  | 'TEXT'
  | 'IMAGE'
  | 'VIDEO'
  | 'AUDIO'
  | 'FILE'
  | 'LINK'
  | 'CODE'
  | 'ENCRYPTED'
  | 'DELETED'
  | 'EDITED';

/** Language codes (ISO 639-1) */
export type LanguageCode =
  | 'en' | 'es' | 'fr' | 'de' | 'it' | 'pt' | 'ru' | 'zh' | 'ja' | 'ar'
  | 'hi' | 'bn' | 'pa' | 'tr' | 'nl' | 'sv' | 'fi' | 'pl' | 'uk' | 'vi'
  | 'th' | 'ko' | 'id' | 'ms' | 'tl' | 'he' | 'fa' | 'ur' | 'other';

/** Encryption protocol */
export type EncryptionProtocol =
  | 'NONE'
  | 'TLS'
  | 'SSL'
  | 'PGP'
  | 'GPG'
  | 'OTR'
  | 'SIGNAL_PROTOCOL'
  | 'DOUBLE_RATCHET'
  | 'AES'
  | 'RSA'
  | 'ECC'
  | 'CHACHA20'
  | 'WICKR'
  | 'SESSION'
  | 'OTHER';

/** Communication channel */
export interface CommunicationChannel {
  id: string;
  /** Platform where this channel exists */
  platform: CommunicationPlatform;
  /** Channel type (public, private, etc.) */
  channelType: ChannelType;
  /** Channel identifier (name, ID, URL, etc.) */
  identifier: string;
  /** Display name */
  displayName?: string;
  /** Description */
  description?: string;
  /** Actors known to use this channel */
  actorIds: string[];
  /** Handle IDs associated with this channel */
  handleIds: string[];
  /** First seen timestamp */
  firstSeen: string;
  /** Last seen timestamp */
  lastSeen: string;
  /** Total message count */
  messageCount: number;
  /** Active member count */
  memberCount?: number;
  /** Primary language used */
  language: LanguageCode;
  /** Other languages observed */
  otherLanguages: LanguageCode[];
  /** Encryption protocol used */
  encryptionProtocol: EncryptionProtocol;
  /** Whether encryption is used */
  encryptionUsed: boolean;
  /** Whether channel is still active */
  isActive: boolean;
  /** Channel status */
  status: 'ACTIVE' | 'DORMANT' | 'SUSPENDED' | 'DELETED' | 'ARCHIVED';
  /** Confidence score (0-100) for channel attribution */
  confidence: number;
  /** Topics discussed in this channel */
  topics: string[];
  /** Evidence IDs supporting this channel */
  evidenceIds: string[];
  /** Related infrastructure IDs */
  infrastructureIds: string[];
  /** Whether this channel is synthetic/demo data */
  isSynthetic?: boolean;
  /** Data state tracking */
  dataState?: string;
  /** Analyst who added/updated this */
  analyst?: string;
  /** Notes */
  notes?: string;
  /** Tags for categorization */
  tags?: string[];
}

/** Communication message */
export interface CommunicationMessage {
  id: string;
  /** Channel ID this message belongs to */
  channelId: string;
  /** Message hash/ID */
  messageId: string;
  /** Message type */
  messageType: MessageType;
  /** Message content (text, file hash, link URL, etc.) */
  content: string;
  /** Message content preview (first N characters) */
  preview?: string;
  /** Author handle ID if known */
  authorHandleId?: string;
  /** Author actor ID if known */
  authorActorId?: string;
  /** Timestamp when message was posted */
  timestamp: string;
  /** Whether message has been edited */
  isEdited: boolean;
  /** Whether message has been deleted */
  isDeleted: boolean;
  /** Delete timestamp if deleted */
  deletedAt?: string;
  /** Reply to message ID if this is a reply */
  replyToId?: string;
  /** Number of replies */
  replyCount: number;
  /** Number of reactions/upvotes */
  reactionCount: number;
  /** Language of the message */
  language: LanguageCode;
  /** Confidence score (0-100) for message attribution */
  confidence: number;
  /** Extracted entities (handles, wallets, PGP keys, etc.) */
  extractedEntities: ExtractedEntity[];
  /** Evidence IDs supporting this message */
  evidenceIds: string[];
  /** Whether this message is synthetic/demo data */
  isSynthetic?: boolean;
  /** Data state tracking */
  dataState?: string;
  /** Analyst who added/updated this */
  analyst?: string;
  /** Notes */
  notes?: string;
}

/** Extracted entity from communication */
export interface ExtractedEntity {
  /** Entity type */
  type: 'HANDLE' | 'WALLET' | 'PGP' | 'ACTOR' | 'INFRASTRUCTURE' | 'CVE' | 'URL' | 'EMAIL' | 'IP' | 'DOMAIN';
  /** Entity value */
  value: string;
  /** Entity ID if resolved */
  entityId?: string;
  /** Confidence score (0-100) for extraction */
  confidence: number;
  /** Context around the entity in the message */
  context?: string;
}

/** Methodology/TTP category */
export type MethodologyCategory =
  | 'RECONNAISSANCE'
  | 'INITIAL_ACCESS'
  | 'PERSISTENCE'
  | 'PRIVILEGE_ESCALATION'
  | 'DEFENSE_EVASION'
  | 'CREDENTIAL_ACCESS'
  | 'DISCOVERY'
  | 'LATERAL_MOVEMENT'
  | 'COLLECTION'
  | 'COMMAND_AND_CONTROL'
  | 'EXFILTRATION'
  | 'IMPACT'
  | 'SOCIAL_ENGINEERING'
  | 'PHISHING'
  | 'MALWARE'
  | 'RANSOMWARE'
  | 'CRYPTO_MINING'
  | 'FRAUD'
  | 'SCAM'
  | 'INFORMATION_OPERATIONS'
  | 'OTHER';

/** Methodology/TTP type */
export interface Methodology {
  id: string;
  /** Methodology name */
  name: string;
  /** Detailed description */
  description: string;
  /** Category this methodology belongs to */
  category: MethodologyCategory;
  /** MITRE ATT&CK TTP IDs related to this methodology */
  mitreTtpIds: string[];
  /** Actors known to use this methodology */
  actorIds: string[];
  /** Handle IDs associated with this methodology */
  handleIds: string[];
  /** Infrastructure IDs associated with this methodology */
  infrastructureIds: string[];
  /** Communication channel IDs where this methodology is discussed */
  channelIds: string[];
  /** Indicators of compromise (IOCs) associated with this methodology */
  indicators: string[];
  /** Evidence IDs supporting this methodology */
  evidenceIds: string[];
  /** First seen timestamp */
  firstSeen: string;
  /** Last seen timestamp */
  lastSeen: string;
  /** Confidence score (0-100) for methodology attribution */
  confidence: number;
  /** Maturity level (how developed/advanced this methodology is) */
  maturity: 'EMERGING' | 'DEVELOPING' | 'MATURE' | 'DECLINING' | 'OBSOLETE';
  /** Difficulty level (how hard it is to detect/prevent) */
  difficulty: 'LOW' | 'MEDIUM' | 'HIGH' | 'EXTREME';
  /** Whether this methodology is synthetic/demo data */
  isSynthetic?: boolean;
  /** Data state tracking */
  dataState?: string;
  /** Analyst who added/updated this */
  analyst?: string;
  /** Notes */
  notes?: string;
  /** Tags for categorization */
  tags?: string[];
  /** Related methodologies */
  relatedMethodologyIds: string[];
  /** Prevention strategies */
  preventionStrategies?: string[];
  /** Detection strategies */
  detectionStrategies?: string[];
  /** Response strategies */
  responseStrategies?: string[];
}

/** TTP Playbook (step-by-step methodology) */
export interface TtpPlaybook {
  id: string;
  /** Playbook name */
  name: string;
  /** Detailed description */
  description: string;
  /** Methodology ID this playbook belongs to */
  methodologyId: string;
  /** Actor ID this playbook is attributed to */
  actorId: string;
  /** Steps in the playbook */
  steps: PlaybookStep[];
  /** First seen timestamp */
  firstSeen: string;
  /** Last seen timestamp */
  lastSeen: string;
  /** Confidence score (0-100) */
  confidence: number;
  /** Whether this playbook is synthetic/demo data */
  isSynthetic?: boolean;
  /** Data state tracking */
  dataState?: string;
  /** Analyst who added/updated this */
  analyst?: string;
  /** Notes */
  notes?: string;
  /** Tags */
  tags?: string[];
}

/** Playbook step */
export interface PlaybookStep {
  step: number;
  /** Step title */
  title: string;
  /** Step description */
  description: string;
  /** Step type */
  type: 'RECONNAISSANCE' | 'PREPARATION' | 'EXECUTION' | 'PERSISTENCE' | 'CLEANUP' | 'OTHER';
  /** Tools used in this step */
  tools?: string[];
  /** Commands used in this step */
  commands?: string[];
  /** Indicators to look for */
  indicators?: string[];
  /** Expected duration */
  duration?: string;
  /** Dependencies (previous steps) */
  dependencies: number[];
  /** Evidence IDs supporting this step */
  evidenceIds: string[];
}

/** Communication pattern analysis */
export interface CommunicationPattern {
  channelId: string;
  /** Pattern type */
  patternType:
    | 'ACTIVITY_SPIKE'
    | 'NEW_MEMBER_SURGE'
    | 'TOPIC_SHIFT'
    | 'LANGUAGE_CHANGE'
    | 'ENCRYPTION_CHANGE'
    | 'MESSAGE_FREQUENCY'
    | 'MESSAGE_LENGTH'
    | 'SENTIMENT_CHANGE'
    | 'KEYWORD_BURST'
    | 'OTHER';
  /** Pattern description */
  description: string;
  /** First detected timestamp */
  firstDetected: string;
  /** Last detected timestamp */
  lastDetected: string;
  /** Number of occurrences */
  occurrences: number;
  /** Confidence score (0-100) */
  confidence: number;
  /** Severity */
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  /** Related actor IDs */
  actorIds: string[];
  /** Related evidence IDs */
  evidenceIds: string[];
}

/** Actor communication profile */
export interface ActorCommunicationProfile {
  actorId: string;
  /** Preferred platforms */
  preferredPlatforms: CommunicationPlatform[];
  /** Preferred languages */
  preferredLanguages: LanguageCode[];
  /** Preferred channel types */
  preferredChannelTypes: ChannelType[];
  /** Active channels */
  activeChannels: string[];
  /** Communication frequency (messages per day) */
  communicationFrequency: number;
  /** Active hours (24-hour format) */
  activeHours: number[];
  /** Topics of interest */
  topics: string[];
  /** Encryption usage */
  encryptionUsage: {
    usesEncryption: boolean;
    preferredProtocols: EncryptionProtocol[];
  };
  /** Message patterns */
  messagePatterns: {
    avgMessageLength: number;
    messageTypes: Record<MessageType, number>;
  };
  /** Social connections (other actors in same channels) */
  socialConnections: string[];
}

/** Communication search/filter options */
export interface CommunicationFilterOptions {
  platforms?: CommunicationPlatform[];
  channelTypes?: ChannelType[];
  languages?: LanguageCode[];
  actors?: string[];
  handles?: string[];
  minMessageCount?: number;
  maxMessageCount?: number;
  isActive?: boolean;
  statuses?: ('ACTIVE' | 'DORMANT' | 'SUSPENDED' | 'DELETED' | 'ARCHIVED')[];
  minConfidence?: number;
  searchQuery?: string;
  dateRange?: {
    start: string;
    end: string;
  };
}

/** Methodology search/filter options */
export interface MethodologyFilterOptions {
  categories?: MethodologyCategory[];
  actors?: string[];
  mitreTtps?: string[];
  maturityLevels?: ('EMERGING' | 'DEVELOPING' | 'MATURE' | 'DECLINING' | 'OBSOLETE')[];
  difficultyLevels?: ('LOW' | 'MEDIUM' | 'HIGH' | 'EXTREME')[];
  minConfidence?: number;
  searchQuery?: string;
  dateRange?: {
    start: string;
    end: string;
  };
}
