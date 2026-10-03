// ============================================================
// PhishNet — Enhanced Cryptocurrency Intelligence Type Definitions
//
// Extended wallet types for transaction analysis, clustering, and forensics.
// These types extend the central intelligence model.
// ============================================================

/** Blockchain network types */
export type BlockchainNetwork =
  | 'BITCOIN'
  | 'ETHEREUM'
  | 'MONERO'
  | 'LITECOIN'
  | 'DASH'
  | 'ZCASH'
  | 'DOGECOIN'
  | 'BITCOIN_CASH'
  | 'CARDANO'
  | 'SOLANA'
  | 'POLKADOT'
  | 'RIPPLE'
  | 'STELLAR'
  | 'TRON'
  | 'BINANCE_SMART_CHAIN'
  | 'OTHER';

/** Transaction direction */
export type TransactionDirection = 'IN' | 'OUT' | 'SELF';

/** Transaction status */
export type TransactionStatus =
  | 'PENDING'
  | 'CONFIRMED'
  | 'UNCONFIRMED'
  | 'DOUBLE_SPEND'
  | 'REPLACED'
  | 'FAILED';

/** Wallet clustering method */
export type ClusteringMethod =
  | 'HEURISTIC'      // Based on behavioral patterns
  | 'MULTI_SIG'      // Multi-signature wallet
  | 'ADDRESS_REUSE'  // Address reuse analysis
  | 'TIME_BASED'     // Temporal clustering
  | 'AMOUNT_BASED'   // Transaction amount patterns
  | 'EXCHANGE'       // Exchange withdrawal patterns
  | 'SANCTIONS'      // Sanctions list association
  | 'AI_ANALYSIS'    // AI/ML-based clustering
  | 'ANALYST'        // Manual analyst clustering
  | 'INTEL_SHARING'  // Intelligence sharing
  | 'OTHER';

/** Exchange/service identifier */
export interface ExchangeRecord {
  id: string;
  /** Exchange name */
  name: string;
  /** Exchange type */
  type: 'CENTRALIZED' | 'DECENTRALIZED' | 'PEER_TO_PEER' | 'MIXER' | 'BRIDGE' | 'OTHER';
  /** Known wallet addresses associated with this exchange */
  walletAddresses: string[];
  /** IP addresses associated with this exchange */
  ipAddresses: string[];
  /** Domains associated with this exchange */
  domains: string[];
  /** Jurisdiction/country */
  jurisdiction?: string;
  /** KYC/AML requirements */
  kycRequired: boolean;
  /** Registration required */
  registrationRequired: boolean;
  /** Confidence score (0-100) for wallet-exchange association */
  confidence: number;
  /** First seen timestamp */
  firstSeen: string;
  /** Last seen timestamp */
  lastSeen: string;
  /** Whether this exchange is synthetic/demo data */
  isSynthetic?: boolean;
  /** Data state tracking */
  dataState?: string;
  /** Analyst who added/updated this */
  analyst?: string;
  /** Notes */
  notes?: string;
}

/** Wallet transaction */
export interface WalletTransaction {
  id: string;
  /** Wallet ID this transaction belongs to */
  walletId: string;
  /** Transaction hash */
  hash: string;
  /** Blockchain network */
  network: BlockchainNetwork;
  /** Transaction timestamp (ISO 8601) */
  timestamp: string;
  /** Block height */
  blockHeight: number;
  /** Transaction amount (in base units, e.g., satoshis for BTC) */
  amount: number;
  /** Currency/unit (e.g., "BTC", "ETH", "XMR") */
  currency: string;
  /** Amount in USD (if available) */
  amountUsd?: number;
  /** From address */
  fromAddress: string;
  /** To address */
  toAddress: string;
  /** Transaction fee */
  fee: number;
  /** Fee in USD (if available) */
  feeUsd?: number;
  /** Transaction direction relative to the wallet */
  direction: TransactionDirection;
  /** Transaction status */
  status: TransactionStatus;
  /** Number of confirmations */
  confirmations: number;
  /** Exchange IDs that have seen this transaction */
  exchangeIds: string[];
  /** Cluster ID if this transaction is part of a cluster */
  clusterId?: string;
  /** Related actor IDs */
  actorIds: string[];
  /** Related handle IDs */
  handleIds: string[];
  /** Evidence IDs supporting this transaction */
  evidenceIds: string[];
  /** Confidence score (0-100) for attribution */
  confidence: number;
  /** Whether this is a coinbase transaction (mining reward) */
  isCoinbase: boolean;
  /** Whether this is a coinjoin/mixing transaction */
  isMixing: boolean;
  /** Mixing service identifier if applicable */
  mixingService?: string;
  /** Input count */
  inputCount: number;
  /** Output count */
  outputCount: number;
  /** Total input value */
  totalInput: number;
  /** Total output value */
  totalOutput: number;
  /** Whether this transaction has been flagged */
  isFlagged: boolean;
  /** Flag reason */
  flagReason?: string;
  /** Whether this is synthetic/demo data */
  isSynthetic?: boolean;
  /** Data state tracking */
  dataState?: string;
  /** Analyst who added/updated this */
  analyst?: string;
  /** Notes */
  notes?: string;
}

/** Wallet cluster (group of wallets controlled by same entity) */
export interface WalletCluster {
  id: string;
  /** Wallet IDs in this cluster */
  walletIds: string[];
  /** Actor ID attributed to this cluster */
  actorId?: string;
  /** Clustering method used */
  method: ClusteringMethod;
  /** Reasoning/explanation for the clustering */
  reasoning: string;
  /** Confidence score (0-100) for the clustering */
  confidence: number;
  /** First seen timestamp */
  firstSeen: string;
  /** Last seen timestamp */
  lastSeen: string;
  /** Total transaction count across all wallets */
  totalTransactions: number;
  /** Total value received (in USD) */
  totalReceivedUsd?: number;
  /** Total value sent (in USD) */
  totalSentUsd?: number;
  /** Current balance (in USD) */
  currentBalanceUsd?: number;
  /** Exchange IDs associated with this cluster */
  exchangeIds: string[];
  /** Evidence IDs supporting this cluster */
  evidenceIds: string[];
  /** Whether this cluster is synthetic/demo data */
  isSynthetic?: boolean;
  /** Data state tracking */
  dataState?: string;
  /** Analyst who added/updated this */
  analyst?: string;
  /** Tags for categorization */
  tags?: string[];
}

/** Wallet analysis result */
export interface WalletAnalysis {
  walletId: string;
  /** Risk score (0-100) */
  riskScore: number;
  /** Risk factors */
  riskFactors: WalletRiskFactor[];
  /** Transaction patterns */
  transactionPatterns: TransactionPattern[];
  /** Clustering information */
  clustering: {
    clusterIds: string[];
    confidence: number;
  };
  /** Exchange associations */
  exchangeAssociations: ExchangeAssociation[];
  /** Sanctions information */
  sanctions: {
    isSanctioned: boolean;
    sanctionsList?: string;
    sanctionsReason?: string;
  };
  /** Anomalies detected */
  anomalies: WalletAnomaly[];
  /** Recommendations */
  recommendations: string[];
}

/** Wallet risk factor */
export interface WalletRiskFactor {
  id: string;
  name: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  score: number; // 0-100
  confidence: number; // 0-100
}

/** Transaction pattern */
export interface TransactionPattern {
  id: string;
  patternType: 'FREQUENCY' | 'AMOUNT' | 'TIMING' | 'DESTINATION' | 'SOURCE';
  description: string;
  occurrences: number;
  firstSeen: string;
  lastSeen: string;
  confidence: number;
}

/** Exchange association */
export interface ExchangeAssociation {
  exchangeId: string;
  exchangeName: string;
  confidence: number;
  firstSeen: string;
  lastSeen: string;
  transactionCount: number;
}

/** Wallet anomaly */
export interface WalletAnomaly {
  id: string;
  anomalyType:
    | 'HIGH_VALUE_TRANSACTION'
    | 'RAPID_TRANSACTIONS'
    | 'UNUSUAL_HOURS'
    | 'NEW_DESTINATION'
    | 'MIXING_SERVICE'
    | 'SANCTIONS_MATCH'
    | 'CLUSTER_MISMATCH'
    | 'BALANCE_ANOMALY'
    | 'FEE_ANOMALY'
    | 'OTHER';
  description: string;
  timestamp: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: number;
  relatedTransactionId?: string;
}

/** Wallet transaction statistics */
export interface WalletTransactionStats {
  walletId: string;
  /** Total transaction count */
  totalTransactions: number;
  /** Total received (in base units) */
  totalReceived: number;
  /** Total sent (in base units) */
  totalSent: number;
  /** Current balance (in base units) */
  currentBalance: number;
  /** First transaction timestamp */
  firstTransaction: string;
  /** Last transaction timestamp */
  lastTransaction: string;
  /** Average transaction amount */
  avgAmount: number;
  /** Median transaction amount */
  medianAmount: number;
  /** Maximum transaction amount */
  maxAmount: number;
  /** Minimum transaction amount */
  minAmount: number;
  /** Total fees paid */
  totalFees: number;
  /** Average fee */
  avgFee: number;
  /** Unique addresses interacted with */
  uniqueAddresses: number;
  /** Incoming transaction count */
  incomingCount: number;
  /** Outgoing transaction count */
  outgoingCount: number;
  /** Self transaction count */
  selfCount: number;
  /** Transactions by network */
  byNetwork: Record<BlockchainNetwork, number>;
  /** Transactions by direction */
  byDirection: Record<TransactionDirection, number>;
  /** Transactions by status */
  byStatus: Record<TransactionStatus, number>;
}

/** Wallet transaction filter options */
export interface WalletTransactionFilterOptions {
  networks?: BlockchainNetwork[];
  directions?: TransactionDirection[];
  statuses?: TransactionStatus[];
  minAmount?: number;
  maxAmount?: number;
  minDate?: string;
  maxDate?: string;
  exchanges?: string[];
  actors?: string[];
  clusters?: string[];
  isFlagged?: boolean;
  searchQuery?: string;
}

/** Sanctions list entry */
export interface SanctionsEntry {
  id: string;
  /** Sanctions list name */
  listName: string;
  /** Sanctions list source */
  source: string;
  /** Wallet addresses on sanctions list */
  addresses: string[];
  /** Reason for sanctions */
  reason: string;
  /** Date added to sanctions list */
  dateAdded: string;
  /** Date last updated */
  dateUpdated: string;
  /** Jurisdiction */
  jurisdiction: string;
  /** Confidence score */
  confidence: number;
  /** References */
  references: string[];
}
