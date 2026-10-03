// ============================================================
// PhishNet — Cryptocurrency intelligence derivation.
//
// Read-side analysis over stored transactions, clusters and services.
//
// Two rules govern everything here:
//
//  1. Nothing is executed and nothing is fetched. This reads records that
//     were already collected and stored; it has no ability to move funds.
//  2. A privacy-service association is an OBSERVATION about a payment
//     pattern, never a conclusion about the owner. Every indicator carries
//     the reason it fired so an analyst can disagree with it.
//
// Address validation reports what is structurally checkable offline. The
// bech32 checksum is verified. The EIP-55 mixed-case checksum is NOT, because
// it requires keccak-256; the result says so explicitly rather than implying
// a verification that never happened.
// ============================================================
import type {
  IntelligenceDataset,
  WalletTransactionRecord,
  WalletClusterRecord,
  ExchangeRecordRecord,
  BlockchainNetwork,
} from './types';

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32_GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

export type AddressVerdict = 'VALID' | 'CHECKSUM_INVALID' | 'FORMAT_UNKNOWN' | 'LENGTH_INVALID' | 'CHARSET_INVALID';

export interface AddressCheck {
  address: string;
  /** The network the address actually matches, which may differ from the record. */
  detected: BlockchainNetwork | null;
  verdict: AddressVerdict;
  /** What was actually verified, stated plainly. */
  verified: string;
  detail: string;
}

function polymod(values: number[]): number {
  let chk = 1;
  for (const value of values) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ value;
    for (let i = 0; i < 5; i += 1) if ((top >> i) & 1) chk ^= BECH32_GENERATOR[i];
  }
  return chk;
}

function bech32HrpExpand(hrp: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < hrp.length; i += 1) out.push(hrp.charCodeAt(i) >> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i += 1) out.push(hrp.charCodeAt(i) & 31);
  return out;
}

/**
 * Full bech32/bech32m structural + checksum validation. Returns the reason on
 * failure so a malformed address is diagnosable rather than just rejected.
 */
function checkBech32(address: string): { ok: boolean; reason: string; hrp: string } {
  const hasLower = address !== address.toUpperCase();
  const hasUpper = address !== address.toLowerCase();
  if (hasLower && hasUpper) return { ok: false, reason: 'mixed case is not permitted', hrp: '' };
  const value = address.toLowerCase();
  const separator = value.lastIndexOf('1');
  if (separator < 1 || separator + 7 > value.length) {
    return { ok: false, reason: 'missing separator or too short for a checksum', hrp: '' };
  }
  const hrp = value.slice(0, separator);
  const data: number[] = [];
  for (let i = separator + 1; i < value.length; i += 1) {
    const index = BECH32_CHARSET.indexOf(value[i]);
    if (index === -1) return { ok: false, reason: `character "${value[i]}" is not in the bech32 charset`, hrp };
    data.push(index);
  }
  const checksum = polymod([...bech32HrpExpand(hrp), ...data]);
  // bech32 (BIP-173) and bech32m (BIP-350) use different constants.
  const ok = checksum === 1 || checksum === 0x2bc830a3;
  return { ok, reason: ok ? '' : 'checksum does not match', hrp };
}

/**
 * Structurally validate an address and report the network it matches.
 * Deliberately conservative: an address it cannot recognise is reported as
 * FORMAT_UNKNOWN rather than being accepted.
 */
export function validateAddress(address: string): AddressCheck {
  const value = (address ?? '').trim();
  if (!value) {
    return { address: value, detected: null, verdict: 'LENGTH_INVALID', verified: 'nothing', detail: 'Empty address.' };
  }
  const lower = value.toLowerCase();

  // ── EVM / EVM-compatible ──
  if (lower.startsWith('0x')) {
    const body = value.slice(2);
    if (body.length !== 40) {
      return {
        address: value, detected: 'ETHEREUM', verdict: 'LENGTH_INVALID', verified: 'prefix and length',
        detail: `0x-prefixed address must be 40 hex characters; found ${body.length}.`,
      };
    }
    if (!/^[0-9a-fA-F]{40}$/.test(body)) {
      const bad = [...body].find(ch => !/[0-9a-fA-F]/.test(ch));
      return {
        address: value, detected: 'ETHEREUM', verdict: 'CHARSET_INVALID', verified: 'prefix and charset',
        detail: `"${bad}" is not a hexadecimal character.`,
      };
    }
    const mixedCase = body !== body.toLowerCase() && body !== body.toUpperCase();
    return {
      address: value, detected: 'ETHEREUM', verdict: 'VALID', verified: 'length and charset',
      detail: mixedCase
        ? 'Well-formed. The address claims an EIP-55 checksum, which needs keccak-256 and was not verified offline.'
        : 'Well-formed and all one case, so no EIP-55 checksum is claimed.',
    };
  }

  // ── Bech32 native chains ──
  if (/^(bc1|ltc1|bcrt1|tb1|bch1|blc1|eqr1|zec1)/.test(lower)) {
    // The human-readable part excludes the "1" separator, so it is "bc", not "bc1".
    const hrp = lower.slice(0, lower.indexOf('1'));
    const result = checkBech32(value);
    const network: BlockchainNetwork =
      hrp === 'bc' || hrp === 'tb' ? 'BITCOIN'
        : hrp === 'ltc' ? 'LITECOIN'
          : hrp === 'bcrt' ? 'BITCOIN'
            : hrp === 'bch' ? 'BITCOIN_CASH'
              : hrp === 'zec' ? 'ZCASH'
                : 'OTHER';
    return {
      address: value, detected: network,
      verdict: result.ok ? 'VALID' : 'CHECKSUM_INVALID',
      verified: 'bech32 prefix, length and checksum',
      detail: result.ok
        ? `Valid bech32 ${hrp}1 address; the checksum verifies.`
        : `bech32 checksum failed: ${result.reason}.`,
    };
  }

  // ── Base58 legacy chains ──
  if (/^[13][1-9A-HJ-NP-Za-km-z]{25,34}$/.test(value)) {
    return {
      address: value, detected: 'BITCOIN', verdict: 'VALID', verified: 'base58 charset and length',
      detail: 'Well-formed P2PKH or P2SH address. The base58check payload was not decoded offline.',
    };
  }
  if (/^[LM][1-9A-HJ-NP-Za-km-z]{26,33}$/.test(value)) {
    return {
      address: value, detected: 'LITECOIN', verdict: 'VALID', verified: 'base58 charset and length',
      detail: 'Well-formed Litecoin address. The base58check payload was not decoded offline.',
    };
  }
  if (/^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$/.test(value)) {
    return {
      address: value, detected: 'MONERO', verdict: 'VALID', verified: 'monero prefix and length',
      detail: 'Well-formed standard Monero address. The payment ID was not decoded offline.',
    };
  }
  if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value)) {
    return {
      address: value, detected: 'SOLANA', verdict: 'VALID', verified: 'base58 charset and length',
      detail: 'Well-formed Solana-style base58 address. The account was not resolved offline.',
    };
  }

  return {
    address: value, detected: null, verdict: 'FORMAT_UNKNOWN', verified: 'nothing',
    detail: 'The address matches no supported network format. It is reported as unrecognised rather than assumed valid.',
  };
}

export interface TransactionStats {
  total: number;
  incoming: number;
  outgoing: number;
  selfTransfers: number;
  totalIn: number;
  totalOut: number;
  /** Net base units, in the dominant currency. */
  net: number;
  currency: string;
  networks: BlockchainNetwork[];
  firstActivity: string;
  lastActivity: string;
  activeDays: number;
  /** Transactions per active day. */
  velocity: number;
  /** Median gap between consecutive transactions, in hours. */
  medianIntervalHours: number;
  confirmed: number;
  pending: number;
  totalFees: number;
}

/** Volume, velocity and window statistics computed from the stored records. */
export function transactionStats(transactions: WalletTransactionRecord[]): TransactionStats {
  const sorted = [...transactions].sort(
    (a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp),
  );
  const times = sorted.map(tx => Date.parse(tx.timestamp)).filter(Number.isFinite);

  const gaps: number[] = [];
  for (let i = 1; i < times.length; i += 1) gaps.push(times[i] - times[i - 1]);
  const sortedGaps = [...gaps].sort((a, b) => a - b);
  const medianIntervalHours = sortedGaps.length
    ? Math.round(sortedGaps[Math.floor(sortedGaps.length / 2)] / 3_600_000)
    : 0;

  const counts = new Map<string, number>();
  for (const tx of sorted) counts.set(tx.currency, (counts.get(tx.currency) ?? 0) + 1);
  const currency = [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? '';

  const activeDays = new Set(times.map(time => new Date(time).toISOString().slice(0, 10))).size;
  const totalIn = transactions.filter(tx => tx.direction === 'IN').reduce((sum, tx) => sum + tx.amount, 0);
  const totalOut = transactions.filter(tx => tx.direction === 'OUT').reduce((sum, tx) => sum + tx.amount, 0);

  return {
    total: transactions.length,
    incoming: transactions.filter(tx => tx.direction === 'IN').length,
    outgoing: transactions.filter(tx => tx.direction === 'OUT').length,
    selfTransfers: transactions.filter(tx => tx.direction === 'SELF').length,
    totalIn,
    totalOut,
    net: totalIn - totalOut,
    currency,
    networks: [...new Set(transactions.map(tx => tx.network))].sort(),
    firstActivity: times.length ? new Date(Math.min(...times)).toISOString() : '',
    lastActivity: times.length ? new Date(Math.max(...times)).toISOString() : '',
    activeDays,
    velocity: activeDays ? Math.round((transactions.length / activeDays) * 10) / 10 : 0,
    medianIntervalHours,
    confirmed: transactions.filter(tx => tx.status === 'CONFIRMED').length,
    pending: transactions.filter(tx => tx.status !== 'CONFIRMED').length,
    totalFees: transactions.reduce((sum, tx) => sum + tx.fee, 0),
  };
}

export interface MixerIndicator {
  id: string;
  label: string;
  reason: string;
  source: string;
  transactionIds: string[];
  confidence: number;
  /** Always present — the module never asserts criminality. */
  caveat: string;
}

const PRIVACY_CAVEAT =
  'Association with a privacy-enhancing service is not evidence of criminal activity. '
  + 'Legitimate uses exist; treat this as a review trigger, not a finding.';

/**
 * Privacy-service indicators, assembled from what was actually recorded.
 * Two independent signals are reported separately rather than merged: an
 * explicit analyst/collector flag, and a payment to a service whose recorded
 * type is a mixer.
 */
export function mixerIndicators(
  dataset: IntelligenceDataset,
  transactions: WalletTransactionRecord[],
): MixerIndicator[] {
  const exchanges = dataset.exchanges ?? [];
  const indicators: MixerIndicator[] = [];

  const flagged = transactions.filter(tx => tx.isMixing);
  if (flagged.length) {
    const services = [...new Set(flagged.map(tx => tx.mixingService).filter(Boolean))];
    indicators.push({
      id: 'MIX-FLAGGED',
      label: 'Recorded mixing / privacy indicator',
      reason: flagged[0]?.flagReason
        ?? 'The stored record carries a mixing indicator and a detection reason.',
      source: services.length ? services.join(', ') : 'Stored transaction record',
      transactionIds: flagged.map(tx => tx.id),
      confidence: Math.round(flagged.reduce((sum, tx) => sum + tx.confidence, 0) / flagged.length),
      caveat: PRIVACY_CAVEAT,
    });
  }

  const mixerServiceIds = new Set(
    exchanges.filter(item => item.type === 'MIXER').map(item => item.id),
  );
  const toMixer = transactions.filter(tx => tx.exchangeIds.some(id => mixerServiceIds.has(id)));
  if (toMixer.length && !flagged.length) {
    indicators.push({
      id: 'MIX-SERVICE',
      label: 'Payment to a recorded privacy service',
      reason: 'A stored transaction names a service whose recorded type is MIXER, but the transaction itself carries no mixing flag.',
      source: toMixer.map(tx => tx.exchangeIds.find(id => mixerServiceIds.has(id))).filter(Boolean).join(', '),
      transactionIds: toMixer.map(tx => tx.id),
      confidence: Math.round(toMixer.reduce((sum, tx) => sum + tx.confidence, 0) / toMixer.length),
      caveat: PRIVACY_CAVEAT,
    });
  }

  // Equal-value batches to a single counterparty are the classic shape of a
  // CoinJoin-style batch, but they are also ordinary behaviour, so this is
  // reported only as a pattern worth a look.
  const byCounterparty = new Map<string, string[]>();
  for (const tx of transactions) {
    const counterparty = tx.direction === 'IN' ? tx.fromAddress : tx.toAddress;
    const key = `${counterparty}|${tx.amount}`;
    byCounterparty.set(key, [...(byCounterparty.get(key) ?? []), tx.id]);
  }
  const batches = [...byCounterparty.entries()].filter(([, ids]) => ids.length >= 3);
  if (batches.length) {
    indicators.push({
      id: 'MIX-BATCH',
      label: 'Repeated equal-value transfers',
      reason: 'Three or more transfers of an identical amount to the same counterparty. This is a batching pattern, and batching has legitimate explanations.',
      source: 'Computed from stored transaction values',
      transactionIds: batches.flatMap(([, ids]) => ids),
      confidence: 50,
      caveat: PRIVACY_CAVEAT,
    });
  }

  return indicators;
}

export interface ExchangeLink {
  exchange: ExchangeRecordRecord;
  transactionIds: string[];
  totalUsd: number;
  confidence: number;
  lastSeen: string;
}

/** Service attribution, resolved through the central exchange records. */
export function exchangeLinks(
  exchanges: ExchangeRecordRecord[],
  transactions: WalletTransactionRecord[],
): ExchangeLink[] {
  const links: ExchangeLink[] = [];
  for (const exchange of exchanges) {
    const related = transactions.filter(tx => tx.exchangeIds.includes(exchange.id));
    if (!related.length) continue;
    links.push({
      exchange,
      transactionIds: related.map(tx => tx.id),
      totalUsd: related.reduce((sum, tx) => sum + (tx.amountUsd ?? 0), 0),
      confidence: Math.round(related.reduce((sum, tx) => sum + tx.confidence, 0) / related.length),
      lastSeen: related.map(tx => tx.timestamp).sort().slice(-1)[0] ?? '',
    });
  }
  return links.sort((a, b) => b.totalUsd - a.totalUsd);
}

export interface ActivityBucket {
  date: string;
  count: number;
  inbound: number;
  outbound: number;
}

export function activityByDay(transactions: WalletTransactionRecord[]): ActivityBucket[] {
  const buckets = new Map<string, ActivityBucket>();
  for (const tx of transactions) {
    const date = tx.timestamp.slice(0, 10);
    const bucket = buckets.get(date) ?? { date, count: 0, inbound: 0, outbound: 0 };
    bucket.count += 1;
    if (tx.direction === 'IN') bucket.inbound += 1;
    if (tx.direction === 'OUT') bucket.outbound += 1;
    buckets.set(date, bucket);
  }
  return [...buckets.values()].sort((a, b) => a.date.localeCompare(b.date));
}

export interface CryptoBundle {
  walletId: string;
  address: string;
  addressCheck: AddressCheck;
  /** The network recorded on the wallet, and whether the address agrees. */
  declaredNetwork: string;
  networkMismatch: boolean;
  transactions: WalletTransactionRecord[];
  stats: TransactionStats;
  activity: ActivityBucket[];
  indicators: MixerIndicator[];
  services: ExchangeLink[];
  clusters: WalletClusterRecord[];
  counterparties: { address: string; count: number; directions: string[] }[];
}

/**
 * Reduce a recorded network label to a canonical chain token, or null when the
 * label is too vague to compare against ("Crypto", "Unknown", "multi-chain").
 */
function declaredChainKey(label: string): BlockchainNetwork | null {
  const l = label.toLowerCase();
  if (/\b(bit ?coin ?cash|cash ?addr)\b/.test(l)) return 'BITCOIN_CASH';
  if (/\b(bitcoin|btc|segwit)\b/.test(l)) return 'BITCOIN';
  if (/\blitecoin\b|\bltc\b/.test(l)) return 'LITECOIN';
  if (/\bzcash\b/.test(l)) return 'ZCASH';
  if (/\bmonero\b|\bxmr\b/.test(l)) return 'MONERO';
  if (/\b(ethereum|eth|erc-?20|erc-?721|base|arbitrum|optimism|polygon|matic|bsc|binance)\b/.test(l)) {
    // All EVM chains collapse to one token: the record model records them as a
    // single network, and an L2 label is not a disagreement with that.
    return 'ETHEREUM';
  }
  if (/\bsolana\b|\bsol\b/.test(l)) return 'SOLANA';
  if (/\bbitcoin ?sv\b|\bbsv\b/.test(l)) return 'LITECOIN';
  return null;
}

/** Everything the wallet workspace needs, resolved through central lookups. */
export function cryptoBundle(dataset: IntelligenceDataset, walletId: string): CryptoBundle | null {
  const wallet = dataset.lookups.walletsById[walletId];
  if (!wallet) return null;

  const transactions = (dataset.walletTransactions ?? [])
    .filter(tx => tx.walletId === wallet.id)
    .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));

  const addressCheck = validateAddress(wallet.address);
  const declaredNetwork = wallet.network ?? 'UNSPECIFIED';
  const detectedLabel = addressCheck.detected ?? 'UNKNOWN';
  // Records carry human labels such as "Bitcoin (synthetic)", so the declared
  // side is reduced to a chain token before the two are compared. A label we
  // cannot reduce is left out of the comparison rather than assumed to conflict.
  const declaredChain = declaredChainKey(declaredNetwork);

  const counterparts = new Map<string, { count: number; directions: Set<string> }>();
  for (const tx of transactions) {
    const other = tx.direction === 'IN' ? tx.fromAddress : tx.toAddress;
    const entry = counterparts.get(other) ?? { count: 0, directions: new Set<string>() };
    entry.count += 1;
    entry.directions.add(tx.direction);
    counterparts.set(other, entry);
  }

  return {
    walletId: wallet.id,
    address: wallet.address,
    addressCheck,
    declaredNetwork,
    // Only a *conflicting* positive detection is a mismatch. An unrecognised
    // format must not be reported as disagreeing with the record.
    networkMismatch: !!addressCheck.detected && !!declaredChain && declaredChain !== detectedLabel,
    transactions,
    stats: transactionStats(transactions),
    activity: activityByDay(transactions),
    indicators: mixerIndicators(dataset, transactions),
    services: exchangeLinks(dataset.exchanges ?? [], transactions),
    clusters: (dataset.walletClusters ?? []).filter(cluster => cluster.walletIds.includes(wallet.id)),
    counterparties: [...counterparts.entries()]
      .map(([address, entry]) => ({ address, count: entry.count, directions: [...entry.directions].sort() }))
      .sort((a, b) => b.count - a.count),
  };
}
