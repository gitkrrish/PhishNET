// ============================================================
// Source collection health and access classification.
//
// A source record answers "what did we see". This module answers the
// two questions an analyst actually has to act on:
//
//   1. Can we still collect from it? Access to a source is not a
//      property of its type alone. A paste self-deletes, a forum
//      needs an account, an onion service needs Tor, and a feed is
//      machine-readable. These have different failure modes and
//      different evidence value when they fail.
//
//   2. Is the record internally consistent? A source marked ACTIVE
//      that was last observed weeks ago, an onion service with no
//      address, or an activity level that contradicts its indicator
//      count are all record defects, not intelligence.
//
// Everything is derived from fields already on the record. Nothing
// here contacts a source, and no finding is phrased as a conclusion
// about what a source currently contains.
// ============================================================

export type AccessClass =
  | 'FEED'
  | 'ARCHIVE'
  | 'ACCOUNT_GATED'
  | 'EPHEMERAL'
  | 'REALTIME'
  | 'TOR_HOSTED'
  | 'PASSIVE_INDEX';

export interface AccessProfile {
  access: AccessClass;
  label: string;
  /** What is required before anything can be collected from this source. */
  requirements: string[];
  /** What is lost when collection fails, which differs per access class. */
  onFailure: string;
  /** How long content is expected to remain available. */
  persistence: 'PERSISTENT' | 'MODERATE' | 'TRANSIENT' | 'REAL_TIME_ONLY' | 'NOT_APPLICABLE';
  /** Whether the record carries what collection needs to even start. */
  prerequisitesMet: boolean;
  /** Reasons prerequisites are not met. */
  blockers: string[];
}

export type HealthSeverity = 'ok' | 'info' | 'warn' | 'critical';

export interface SourceFinding {
  label: string;
  detail: string;
  severity: HealthSeverity;
  /** A stable key so the same finding can be de-duplicated in a view. */
  code: string;
}

export interface SourceHealth {
  id: string;
  name: string;
  access: AccessProfile;
  /** Whole days since the source was last observed, against `asOf`. */
  daysSinceLastObserved: number | null;
  /** Whole days since the source was first observed. */
  daysSinceFirstObserved: number | null;
  /** Whole days between last observation and collection. */
  observationToCollectionDays: number | null;
  findings: SourceFinding[];
  /** Single worst severity, for sorting. */
  worstSeverity: HealthSeverity;
  /** A short label for the workspace badge. */
  verdict: string;
  /** How many evidence records cite this source. */
  evidenceCount: number;
}

const SEVERITY_ORDER: Record<HealthSeverity, number> = { ok: 0, info: 1, warn: 2, critical: 3 };

/** A v3 onion address is exactly 56 base32 characters; v2 was 16. */
const ONION_V3_LENGTH = 56;
const ONION_V2_LENGTH = 16;

/** Classify how a source must be collected from. */
export function classifyAccess(source: {
  type: string;
  onionAddress?: string;
  status: string;
}): AccessProfile {
  const address = source.onionAddress?.trim() ?? '';
  const looksOnion = /\.onion$/i.test(address);
  // A field named onionAddress holding a clearnet domain is a record defect,
  // not evidence of a Tor-hosted service.
  const clearnetInOnionField = !!address && !looksOnion;

  const base: Omit<AccessProfile, 'blockers' | 'prerequisitesMet'> =
    source.type === 'THREAT_FEED'
      ? {
          access: 'FEED',
          label: 'Machine-readable feed',
          requirements: ['Feed credentials or an API key', 'A reachable transport to the feed'],
          onFailure: 'Corroboration from this source stops, but every other source still stands on its own. A feed carries no direct actor content, so losing it degrades confidence rather than coverage.',
          persistence: 'PERSISTENT',
        }
      : source.type === 'LEAK_SITE'
        ? {
            access: 'ARCHIVE',
            label: 'Static leak archive',
            requirements: ['Confirmation the dump is still published', 'Storage for a large one-time download'],
            onFailure: 'The dump is usually replaced rather than removed, so a missed fetch can still be retried. Legal and handling exposure rises sharply with a live leak site, so a failed fetch is not automatically worth retrying.',
            persistence: 'MODERATE',
          }
        : source.type === 'PASTE'
          ? {
              access: 'EPHEMERAL',
              label: 'Ephemeral paste',
              requirements: ['Collection inside the paste retention window'],
              onFailure: 'Content that expires is unrecoverable. A missed paste is usually gone permanently, which makes paste coverage the hardest gap to explain after the fact.',
              persistence: 'TRANSIENT',
            }
          : source.type === 'MESSAGING'
            ? {
                access: 'REALTIME',
                label: 'Real-time channel',
                requirements: ['An account or bridge identity', 'Collection while the message is live'],
                onFailure: 'There is no archive to fall back on. Real-time channels are the least reliably collected source type, and gaps in them are rarely recoverable.',
                persistence: 'REAL_TIME_ONLY',
              }
        : source.type === 'ONION_SERVICE'
          ? {
              access: 'TOR_HOSTED',
              label: 'Tor-hosted service',
              requirements: [
                looksOnion ? 'A working Tor transport' : 'A Tor transport and a confirmed onion address',
                'The address must resolve to a live service',
              ],
              onFailure: 'An onion address that no longer resolves is silent: nothing announces the loss. Address churn on these services is routine, so a dead address is often a rotation rather than a takedown.',
              persistence: 'MODERATE',
            }
          : source.type === 'FORUM' || source.type === 'MARKETPLACE'
            ? {
                access: 'ACCOUNT_GATED',
                label: 'Account-gated community',
                requirements: ['A registered account', 'Sufficient posting history to reach the relevant sections', 'A persistent session to avoid re-registration'],
                onFailure: 'Lapsed sessions are the usual failure, and they are quiet. Losing a session loses the archive view along with new content, because older threads are frequently gated behind it too.',
                persistence: 'PERSISTENT',
              }
            : {
                access: 'PASSIVE_INDEX',
                label: 'Passive index',
                requirements: ['Index coverage of the target service'],
                onFailure: 'A passive index cannot be lost so much as go blind. It only reports what it already saw, so a gap is a coverage limit and not a collection failure.',
                persistence: 'NOT_APPLICABLE',
              };

  const blockers: string[] = [];
  if (source.type === 'ONION_SERVICE' && !address) {
    blockers.push('This record is typed as an onion service but stores no address, so there is nothing to connect to.');
  }
  if (clearnetInOnionField) {
    blockers.push(`The onionAddress field holds "${address}", which is a clearnet domain rather than an .onion address, so the field does not describe a Tor service.`);
  }
  if (looksOnion) {
    const base56 = address.replace(/\.onion$/i, '');
    if (base56.length === ONION_V2_LENGTH) {
      blockers.push(`"${address}" is a v2 onion address (16 characters). v2 addresses stopped working in 2021, so this service cannot be reached at this address and the record is describing something that is already gone.`);
    } else if (base56.length !== ONION_V3_LENGTH) {
      blockers.push(`"${address}" is ${base56.length} characters. A v3 onion address is exactly 56, so this address is malformed rather than merely unreachable.`);
    }
  }
  if (source.status === 'SUSPENDED' || source.status === 'DORMANT') {
    blockers.push(`The record is marked ${source.status}, so collection is not expected to be succeeding.`);
  }

  return { ...base, blockers, prerequisitesMet: blockers.length === 0 };
}

/**
 * Assess one source. `asOf` is injectable so staleness is measured against
 * a fixed point in tests and in replayed datasets rather than drifting with
 * the wall clock.
 */
export function assessSource(
  source: {
    id: string; name: string; type: string; status: string;
    activityLevel: string; reliabilityScore: number;
    actorCount: number; indicatorCount: number;
    firstObserved: string; lastObserved: string;
    collectionTimestamp: string; onionAddress?: string;
  },
  context: { evidenceCount: number; asOf?: number } = { evidenceCount: 0 },
): SourceHealth {
  const asOf = context.asOf ?? Date.now();
  const findings: SourceFinding[] = [];
  const access = classifyAccess(source);

  const first = Date.parse(source.firstObserved);
  const last = Date.parse(source.lastObserved);
  const collected = Date.parse(source.collectionTimestamp);
  const daysSinceLastObserved = Number.isFinite(last) ? Math.floor((asOf - last) / 86_400_000) : null;
  const daysSinceFirstObserved = Number.isFinite(first) ? Math.floor((asOf - first) / 86_400_000) : null;
  const observationToCollectionDays = Number.isFinite(last) && Number.isFinite(collected)
    ? Math.round((collected - last) / 86_400_000)
    : null;

  // Staleness: the record claims the source is usable, so the gap between
  // its own last observation and now is the real signal.
  if (daysSinceLastObserved === null) {
    findings.push({
      code: 'unreadable-timestamp', severity: 'warn', label: 'Last observation unreadable',
      detail: 'The lastObserved value could not be parsed, so how current this source is cannot be determined from the record.',
    });
  } else if (daysSinceLastObserved > 30) {
    findings.push({
      code: 'stale', severity: daysSinceLastObserved > 90 ? 'critical' : 'warn',
      label: `Not observed for ${daysSinceLastObserved} days`,
      detail: `The record is marked ${source.status} but was last observed ${daysSinceLastObserved} days ago. A status that no longer matches the observation history is a record defect; it should not be read as a claim that the source is still serving content.`,
    });
  } else if (daysSinceLastObserved > 14) {
    findings.push({
      code: 'ageing', severity: 'info', label: `Not observed for ${daysSinceLastObserved} days`,
      detail: 'Somewhat stale against the rest of this dataset. Worth a refresh before the record is relied on.',
    });
  }

  if (observationToCollectionDays !== null && observationToCollectionDays < 0) {
    findings.push({
      code: 'inverted-timestamps', severity: 'warn', label: 'Collected before it was last seen',
      detail: 'collectionTimestamp is earlier than lastObserved, which is not a possible order of events. At least one of the two fields is wrong.',
    });
  }

  if (source.status === 'ACTIVE' && daysSinceLastObserved !== null && daysSinceLastObserved > 30) {
    findings.push({
      code: 'status-contradiction', severity: 'critical', label: 'Status contradicts the observation history',
      detail: 'The record asserts ACTIVE while the observation history does not support it. Trust the observation history over the status flag until the record is re-checked.',
    });
  }

  // Activity level against the volume actually recorded.
  const indicatorsPerActor = source.actorCount > 0 ? source.indicatorCount / source.actorCount : 0;
  if (source.activityLevel === 'LOW' && indicatorsPerActor >= 10) {
    findings.push({
      code: 'activity-contradiction', severity: 'warn', label: 'Activity level looks understated',
      detail: `The record is marked LOW activity but carries ${source.indicatorCount} indicators across ${source.actorCount} actors, about ${indicatorsPerActor.toFixed(1)} each. One of the two fields is wrong.`,
    });
  }
  if (source.activityLevel === 'HIGH' && source.actorCount > 0 && indicatorsPerActor < 2) {
    findings.push({
      code: 'activity-contradiction-high', severity: 'info', label: 'Activity level looks overstated',
      detail: `HIGH activity is recorded, but the ${source.actorCount} actor(s) carry only ${source.indicatorCount} indicators between them. Activity may refer to volume the model did not capture.`,
    });
  }

  if (source.actorCount === 0) {
    findings.push({
      code: 'no-attribution', severity: 'warn', label: 'No actor attributed',
      detail: 'No actor is attributed to this source, so nothing collected from it currently supports an attribution. That may be correct, or it may mean the source has not been worked yet.',
    });
  }

  if (context.evidenceCount === 0) {
    findings.push({
      code: 'no-evidence', severity: 'info', label: 'No evidence cites this source',
      detail: 'No evidence record references this source, so its coverage in this model rests entirely on the summary counters rather than on itemised evidence.',
    });
  }

  for (const blocker of access.blockers) {
    findings.push({
      code: 'access-blocked', severity: source.type === 'ONION_SERVICE' ? 'critical' : 'warn',
      label: 'Collection prerequisites not met', detail: blocker,
    });
  }

  // Reliability is an opinion about a source, not a measure of it, so it is
  // only worth a note when it is high and collection prerequisites fail.
  if (source.reliabilityScore >= 90 && !access.prerequisitesMet) {
    findings.push({
      code: 'reliability-vs-access', severity: 'warn', label: 'High reliability with unmet prerequisites',
      detail: `The record scores ${source.reliabilityScore}/100 for reliability while its own fields say it cannot currently be collected from. A high score describes past observations and should not be read as present-day access.`,
    });
  }

  const worst = findings.reduce<HealthSeverity>(
    (acc, f) => (SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[acc] ? f.severity : acc),
    'ok',
  );

  return {
    id: source.id,
    name: source.name,
    access,
    daysSinceLastObserved,
    daysSinceFirstObserved,
    observationToCollectionDays,
    findings,
    worstSeverity: worst,
    verdict: worst === 'ok' ? 'HEALTHY' : worst === 'info' ? 'AGING' : worst === 'warn' ? 'AT RISK' : 'DEFECTIVE',
    evidenceCount: context.evidenceCount,
  };
}

// ── Collection-wide summary ────────────────────────────────────

export interface CollectionOverview {
  asOf: string;
  total: number;
  byAccessClass: Record<string, number>;
  byVerdict: Record<string, number>;
  /** Sources whose prerequisites are not met. */
  uncollectable: number;
  /** Sources whose coverage is known to be lossy, by persistence. */
  lossyTypes: string[];
  /** The finding codes present across all sources. */
  findingCodes: Array<{ code: string; count: number; severity: HealthSeverity }>;
  sources: SourceHealth[];
  /** Standing limits on reading any of this. */
  caveats: string[];
}

export function collectionOverview(
  sources: Array<Parameters<typeof assessSource>[0]>,
  options: { evidence: Array<{ source: string }>; asOf?: number } = { evidence: [] },
): CollectionOverview {
  const asOf = options.asOf ?? Date.now();
  const assessed = sources.map(source =>
    assessSource(source, {
      evidenceCount: options.evidence.filter(e => e.source === source.name).length,
      asOf,
    }),
  );

  const byAccessClass: Record<string, number> = {};
  const byVerdict: Record<string, number> = {};
  const codeCounts = new Map<string, { count: number; severity: HealthSeverity }>();
  for (const health of assessed) {
    byAccessClass[health.access.access] = (byAccessClass[health.access.access] ?? 0) + 1;
    byVerdict[health.verdict] = (byVerdict[health.verdict] ?? 0) + 1;
    for (const finding of health.findings) {
      const existing = codeCounts.get(finding.code);
      codeCounts.set(finding.code, { count: (existing?.count ?? 0) + 1, severity: finding.severity });
    }
  }

  const lossyTypes = Array.from(new Set(
    assessed
      .filter(h => h.access.persistence === 'TRANSIENT' || h.access.persistence === 'REAL_TIME_ONLY')
      .map(h => h.access.label),
  ));

  return {
    asOf: new Date(asOf).toISOString(),
    total: assessed.length,
    byAccessClass,
    byVerdict,
    uncollectable: assessed.filter(h => !h.access.prerequisitesMet).length,
    lossyTypes,
    findingCodes: [...codeCounts.entries()]
      .map(([code, v]) => ({ code, count: v.count, severity: v.severity }))
      .sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || b.count - a.count),
    sources: assessed,
    caveats: [
      'Access classification describes how a source must be collected. It says nothing about what the source currently contains.',
      'A reliability score is a judgement about past observations. It is not a measure of present-day access, and a high score on a source that can no longer be reached is not a contradiction.',
      'Staleness is measured against the as-of time supplied by the caller, so a replayed dataset reports the same result it did when it was collected.',
      'Absence of a finding is not a positive assurance. It means no stored field contradicted itself.',
    ],
  };
}
