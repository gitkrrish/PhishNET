// ============================================================
// PhishNet — 24x7 monitoring capability registry.
//
// This file declares WHAT can be watched, WHICH conditions the
// centralized backend can genuinely evaluate for each target, and
// HOW OFTEN each source class can technically be collected.
//
// Two rules govern the whole registry:
//
//  1. A condition only exists here if the centralized tables can be
//     queried to prove it fired. There are no aspirational conditions.
//  2. A frequency is only offered when the source class can actually be
//     read at that interval. Sources that cannot be polled continuously
//     report their real collection interval instead of pretending.
//
// Collection is limited to public sources, authorised feeds,
// analyst-provided sources and synthetic/demo sources.
// ============================================================

/** Requested collection cadence, in seconds. */
export const FREQUENCIES = [
  { key: 'CONTINUOUS', label: 'Continuous (24x7)', seconds: 60 },
  { key: 'EVERY_5_MIN', label: 'Every 5 minutes', seconds: 300 },
  { key: 'EVERY_15_MIN', label: 'Every 15 minutes', seconds: 900 },
  { key: 'EVERY_30_MIN', label: 'Every 30 minutes', seconds: 1800 },
  { key: 'HOURLY', label: 'Every hour', seconds: 3600 },
  { key: 'EVERY_6_HOURS', label: 'Every 6 hours', seconds: 21600 },
  { key: 'DAILY', label: 'Daily', seconds: 86400 },
];

export const FREQUENCY_SECONDS = Object.fromEntries(FREQUENCIES.map(f => [f.key, f.seconds]));
export const FREQUENCY_KEYS = FREQUENCIES.map(f => f.key);

export function frequencySeconds(freq) {
  return FREQUENCY_SECONDS[freq] ?? FREQUENCY_SECONDS.CONTINUOUS;
}

/**
 * Real collection capability per source class.
 *
 * `seconds` is the fastest interval that class supports in practice.
 * `continuous` is true only where a pushed feed genuinely delivers
 * without polling. Anything else is honestly labelled as interval
 * collection so the UI never shows "live" for a source that cannot be.
 */
export const SOURCE_CAPABILITIES = {
  THREAT_FEED: { seconds: 300, continuous: true, label: 'Pushed authorised threat feed', note: 'Delivered by push; new indicators appear as the feed publishes them.' },
  MESSAGING: { seconds: 3600, continuous: false, label: 'Authorised messaging collection', note: 'Session-scoped collection. Only observable while an authorised collector session is open.' },
  FORUM: { seconds: 21600, continuous: false, label: 'Periodic forum sweep', note: 'Threaded forums are re-read on a sweep. Posting cadence is not real-time.' },
  MARKETPLACE: { seconds: 21600, continuous: false, label: 'Periodic marketplace sweep', note: 'Listings are re-read on a sweep; vendor changes are not push-notified.' },
  PASTE: { seconds: 900, continuous: false, label: 'Periodic paste sweep', note: 'Paste sites are polled on a short interval; short-lived pastes may expire between sweeps.' },
  LEAK_SITE: { seconds: 86400, continuous: false, label: 'Daily leak-site sweep', note: 'Checked daily. Credential material is never collected, only the exposure indicator.' },
  ONION_SERVICE: { seconds: 86400, continuous: false, label: 'Daily onion availability check', note: 'Availability and metadata only. No interaction with the hidden service beyond a read of its index.' },
  ANALYST_FEED: { seconds: 3600, continuous: false, label: 'Analyst-supplied collection', note: 'Collected only from material the organisation is authorised to hold.' },
  SYNTHETIC_DEMO: { seconds: 60, continuous: true, label: 'Synthetic demo stream', note: 'Simulated demo data. Clearly labelled SYNTHETIC_DEMO in every record it produces.' },
};

export const SOURCE_ACCESS_MODES = [
  'PUBLIC',
  'AUTHORISED_FEED',
  'ANALYST_PROVIDED',
  'SYNTHETIC_DEMO',
];

export function sourceCapability(source) {
  const key = String(source?.access_mode || source?.type || '').toUpperCase();
  return (
    SOURCE_CAPABILITIES[key] ||
    SOURCE_CAPABILITIES[source?.type] ||
    { seconds: 21600, continuous: false, label: 'Interval collection', note: 'Collected on an interval; this class has no continuous access.' }
  );
}

/**
 * The fastest interval that every source bound to a monitor can support.
 * A monitor's effective cadence is never faster than its slowest source,
 * so "Last Check / Next Check" always reflects reality.
 */
export function resolveCollectionInterval(sources, requestedFrequency) {
  const requested = frequencySeconds(requestedFrequency);
  const rows = (sources || []).filter(Boolean);
  // With no bound source nothing is streaming, so the monitor cannot be
  // continuous. It re-evaluates the centralized records on the requested
  // cadence, and the UI says exactly that rather than implying live access.
  if (!rows.length) {
    return {
      seconds: requested,
      continuous: false,
      limitedBy: null,
      note: 'No source bound. This monitor re-evaluates existing records on the configured cadence; it has no live stream and is not continuous collection.',
    };
  }
  let slowest = 0;
  let limitedBy = null;
  let continuous = true;
  for (const source of rows) {
    const capability = sourceCapability(source);
    if (capability.seconds > slowest) {
      slowest = capability.seconds;
      limitedBy = source.id || source.name || source.type;
    }
    if (!capability.continuous) continuous = false;
  }
  const seconds = Math.max(requested, slowest);
  const downgraded = seconds > requested;
  return {
    seconds,
    continuous: continuous && !downgraded,
    limitedBy: downgraded ? limitedBy : null,
    note: downgraded
      ? `Capped to the source's real collection interval (${formatInterval(slowest)}); the requested ${formatInterval(requested)} is not technically available for this source class.`
      : 'Cadence matches the configured frequency and every bound source supports it.',
  };
}

export function formatInterval(seconds) {
  const value = Number(seconds) || 0;
  if (value < 60) return `${value}s`;
  if (value < 3600) return `${Math.round(value / 60)}m`;
  if (value < 86400) return `${Math.round(value / 3600)}h`;
  return `${Math.round(value / 86400)}d`;
}

export const SEVERITIES = [
  { key: 'INFORMATIONAL', label: 'Informational', rank: 0 },
  { key: 'LOW', label: 'Low', rank: 1 },
  { key: 'MEDIUM', label: 'Medium', rank: 2 },
  { key: 'HIGH', label: 'High', rank: 3 },
  { key: 'CRITICAL', label: 'Critical', rank: 4 },
];

export const SEVERITY_RANK = Object.fromEntries(SEVERITIES.map(s => [s.key, s.rank]));

export const MONITOR_STATUSES = [
  'ACTIVE', 'PAUSED', 'DISABLED', 'RUNNING', 'COMPLETED', 'ERROR', 'SOURCE_UNAVAILABLE', 'AWAITING_DATA',
];

/** Lifecycle states the analyst sets. */
export const LIFECYCLE_STATUSES = ['ACTIVE', 'PAUSED', 'DISABLED'];

/** Runtime states the engine reports. */
export const RUNTIME_STATES = [
  'RUNNING', 'OK', 'COMPLETED', 'ERROR', 'SOURCE_UNAVAILABLE', 'AWAITING_DATA',
];

// ── Conditions ──────────────────────────────────────────────────
// Every condition declares how it is verified. `entityScope` names the
// relationship of the monitored record to the records it watches, so the
// detector knows which query answers it honestly.
const CONDITION = (key, label, group, description, scope, baseSeverity) => ({
  key, label, group, description, scope, baseSeverity,
});

export const CONDITIONS = {
  // ACTOR
  NEW_ACTIVITY: CONDITION('NEW_ACTIVITY', 'New activity', 'ACTOR', 'A new observation was recorded against the actor.', 'actor', 'MEDIUM'),
  NEW_ALIAS: CONDITION('NEW_ALIAS', 'New alias', 'ACTOR', 'A new handle or alias is bound to the actor.', 'actor', 'MEDIUM'),
  NEW_HANDLE: CONDITION('NEW_HANDLE', 'New handle', 'ACTOR', 'A new handle record exists for the actor.', 'actor', 'MEDIUM'),
  NEW_PLATFORM_APPEARANCE: CONDITION('NEW_PLATFORM_APPEARANCE', 'New platform appearance', 'ACTOR', 'The actor appears on a platform it was not previously seen on.', 'actor', 'MEDIUM'),
  NEW_INFRASTRUCTURE: CONDITION('NEW_INFRASTRUCTURE', 'New infrastructure', 'ACTOR', 'New domain, IP or onion infrastructure is associated with the actor.', 'actor', 'HIGH'),
  NEW_RELATIONSHIP: CONDITION('NEW_RELATIONSHIP', 'New relationship', 'ACTOR', 'A new relationship edge touches the actor.', 'entity', 'MEDIUM'),
  NEW_EVIDENCE: CONDITION('NEW_EVIDENCE', 'New evidence', 'ACTOR', 'New evidence was filed against the actor.', 'entity', 'LOW'),
  NEW_ATTACK_BEHAVIOR: CONDITION('NEW_ATTACK_BEHAVIOR', 'New ATT&CK behaviour', 'ACTOR', 'A new ATT&CK technique or behaviour is mapped to the actor.', 'actor', 'MEDIUM'),
  ACTOR_STATUS_CHANGE: CONDITION('ACTOR_STATUS_CHANGE', 'Status change', 'ACTOR', 'The recorded actor status changed.', 'actor', 'MEDIUM'),

  // HANDLE / ALIAS
  NEW_APPEARANCE: CONDITION('NEW_APPEARANCE', 'New appearance', 'HANDLE', 'The handle was observed again more recently than the last check.', 'handle', 'INFORMATIONAL'),
  NEW_PLATFORM: CONDITION('NEW_PLATFORM', 'New platform', 'HANDLE', 'The handle appears on a platform not previously recorded.', 'handle', 'MEDIUM'),
  NEW_ACTOR_CORRELATION: CONDITION('NEW_ACTOR_CORRELATION', 'New actor correlation', 'HANDLE', 'The handle is now attributed to an actor it was not previously linked to.', 'handle', 'HIGH'),
  HANDLE_STATUS_CHANGE: CONDITION('HANDLE_STATUS_CHANGE', 'Status change', 'HANDLE', 'The recorded handle state changed.', 'handle', 'LOW'),

  // PGP
  NEW_OBSERVATION: CONDITION('NEW_OBSERVATION', 'New observation', 'PGP', 'A new observation references the key.', 'entity', 'INFORMATIONAL'),
  NEW_ASSOCIATION: CONDITION('NEW_ASSOCIATION', 'New association', 'PGP', 'The key is newly associated with an actor or handle.', 'pgp', 'HIGH'),
  KEY_REVOCATION: CONDITION('KEY_REVOCATION', 'Revocation', 'PGP', 'The key record carries a revocation or expiry marker.', 'pgp', 'HIGH'),
  KEY_EXPIRATION: CONDITION('KEY_EXPIRATION', 'Expiration', 'PGP', 'The key passed its recorded expiry.', 'pgp', 'MEDIUM'),
  NEW_IDENTITY_ASSOCIATION: CONDITION('NEW_IDENTITY_ASSOCIATION', 'New identity / UID association', 'PGP', 'The key resolves to a new identity or UID.', 'pgp', 'HIGH'),

  // WALLET / CRYPTO
  NEW_TRANSACTION: CONDITION('NEW_TRANSACTION', 'New transaction observation', 'WALLET', 'A new transaction was observed on the address.', 'wallet', 'MEDIUM'),
  INCOMING_ACTIVITY: CONDITION('INCOMING_ACTIVITY', 'Incoming activity', 'WALLET', 'Value arrived at the address.', 'wallet', 'MEDIUM'),
  OUTGOING_ACTIVITY: CONDITION('OUTGOING_ACTIVITY', 'Outgoing activity', 'WALLET', 'Value left the address.', 'wallet', 'MEDIUM'),
  ACTIVITY_SPIKE: CONDITION('ACTIVITY_SPIKE', 'Activity spike', 'WALLET', 'Observed transaction volume exceeded the monitor spike threshold.', 'wallet', 'HIGH'),
  NEW_ASSOCIATED_WALLET: CONDITION('NEW_ASSOCIATED_WALLET', 'New associated wallet', 'WALLET', 'A previously unseen wallet is linked to this address.', 'wallet', 'HIGH'),
  SERVICE_ASSOCIATION: CONDITION('SERVICE_ASSOCIATION', 'Known service / exchange association', 'WALLET', 'The address is linked to a known exchange or service.', 'wallet', 'HIGH'),
  PRIVACY_SERVICE_INDICATOR: CONDITION('PRIVACY_SERVICE_INDICATOR', 'Mixer / privacy-service indicator', 'WALLET', 'Public chain data indicates a mixer or privacy service.', 'wallet', 'CRITICAL'),
  BALANCE_CHANGE: CONDITION('BALANCE_CHANGE', 'Balance change', 'WALLET', 'A material balance change is visible in reliable public chain data.', 'wallet', 'MEDIUM'),

  // INFRASTRUCTURE
  DOMAIN_CHANGE: CONDITION('DOMAIN_CHANGE', 'Domain change', 'INFRASTRUCTURE', 'Registrar, nameserver or hosting provider changed.', 'infra', 'HIGH'),
  IP_CHANGE: CONDITION('IP_CHANGE', 'IP change', 'INFRASTRUCTURE', 'The resolved address for this indicator changed.', 'infra', 'HIGH'),
  DNS_CHANGE: CONDITION('DNS_CHANGE', 'DNS change', 'INFRASTRUCTURE', 'A DNS record or resolution changed.', 'infra', 'HIGH'),
  CERTIFICATE_CHANGE: CONDITION('CERTIFICATE_CHANGE', 'Certificate change', 'INFRASTRUCTURE', 'The TLS issuer or certificate changed.', 'infra', 'MEDIUM'),
  ONION_AVAILABILITY_CHANGE: CONDITION('ONION_AVAILABILITY_CHANGE', 'Onion availability change', 'INFRASTRUCTURE', 'The onion service became reachable or stopped responding.', 'infra', 'MEDIUM'),
  NEW_INFRA_ASSOCIATION: CONDITION('NEW_INFRA_ASSOCIATION', 'New infrastructure association', 'INFRASTRUCTURE', 'The indicator is newly linked to an actor or handle.', 'infra', 'HIGH'),
  MIRROR_DISCOVERY: CONDITION('MIRROR_DISCOVERY', 'Potential mirror discovery', 'INFRASTRUCTURE', 'A new infrastructure record shares characteristics with this indicator.', 'infra', 'MEDIUM'),

  // SOURCE
  SOURCE_AVAILABILITY: CONDITION('SOURCE_AVAILABILITY', 'Source availability', 'SOURCE', 'The source status or health changed.', 'source', 'MEDIUM'),
  COLLECTION_HEALTH: CONDITION('COLLECTION_HEALTH', 'Collection health', 'SOURCE', 'Reliability or activity level moved.', 'source', 'LOW'),
  NEW_SOURCE_INTELLIGENCE: CONDITION('NEW_SOURCE_INTELLIGENCE', 'New intelligence', 'SOURCE', 'New observations or evidence arrived from this source.', 'source', 'MEDIUM'),
  COLLECTION_FAILURE: CONDITION('COLLECTION_FAILURE', 'Collection failure', 'SOURCE', 'A collection attempt failed.', 'source', 'HIGH'),
  SOURCE_STATUS_CHANGE: CONDITION('SOURCE_STATUS_CHANGE', 'Source status change', 'SOURCE', 'The recorded source status changed.', 'source', 'HIGH'),

  // CVE / VULNERABILITY
  NEW_RELEVANT_OBSERVATION: CONDITION('NEW_RELEVANT_OBSERVATION', 'New relevant observation', 'CVE', 'A new observation references the CVE.', 'term', 'MEDIUM'),
  NEW_MENTION: CONDITION('NEW_MENTION', 'New mention', 'CVE', 'The identifier is newly mentioned in collected intelligence.', 'term', 'MEDIUM'),
  NEW_EXPLOIT_INTELLIGENCE: CONDITION('NEW_EXPLOIT_INTELLIGENCE', 'New exploit-related intelligence', 'CVE', 'Exploit-related intelligence references the identifier.', 'term', 'CRITICAL'),
  NEW_PRODUCT_REFERENCE: CONDITION('NEW_PRODUCT_REFERENCE', 'New affected product reference', 'CVE', 'A new affected product is referenced for the identifier.', 'term', 'HIGH'),

  // RELATIONSHIP
  RELATIONSHIP_CHANGE: CONDITION('RELATIONSHIP_CHANGE', 'Relationship change', 'RELATIONSHIP', 'The relationship edge itself changed.', 'relationship', 'MEDIUM'),
  CONFIDENCE_CHANGE: CONDITION('CONFIDENCE_CHANGE', 'Confidence change', 'RELATIONSHIP', 'The recorded relationship confidence moved.', 'relationship', 'MEDIUM'),
  NEW_SUPPORTING_EVIDENCE: CONDITION('NEW_SUPPORTING_EVIDENCE', 'New supporting evidence', 'RELATIONSHIP', 'Evidence was linked to the relationship.', 'relationship', 'LOW'),
  RELATIONSHIP_INACTIVE: CONDITION('RELATIONSHIP_INACTIVE', 'Relationship became inactive', 'RELATIONSHIP', 'A previously observed relationship stopped being observed.', 'relationship', 'MEDIUM'),

  // KEYWORD / INDICATOR / TERM
  NEW_MATCHING_OBSERVATION: CONDITION('NEW_MATCHING_OBSERVATION', 'New matching observation', 'TERM', 'A new observation contains the watched term.', 'term', 'MEDIUM'),
  NEW_SOURCE_APPEARANCE: CONDITION('NEW_SOURCE_APPEARANCE', 'New source appearance', 'TERM', 'The watched term was seen in a source not previously citing it.', 'term', 'MEDIUM'),
  NEW_ACTOR_ASSOCIATION: CONDITION('NEW_ACTOR_ASSOCIATION', 'New actor association', 'TERM', 'The watched term became associated with an actor.', 'term', 'HIGH'),
  NEW_TERM_INFRA_ASSOCIATION: CONDITION('NEW_TERM_INFRA_ASSOCIATION', 'New infrastructure association', 'TERM', 'The watched term became associated with infrastructure.', 'term', 'HIGH'),
};

export function conditionKeysFor(targetType) {
  return Object.values(CONDITIONS)
    .filter(condition => condition.group === targetType || (targetType === 'CUSTOM' && condition.group !== 'RELATIONSHIP'))
    .map(condition => condition.key);
}

/**
 * Every monitorable target type. `entityTypes` lists the aliases that
 * resolve to the same centralized table, so an analyst can monitor a
 * Domain, IP or Onion service directly without a new entity kind.
 */
export const TARGET_TYPES = [
  { key: 'ACTOR', label: 'Threat Actor', entityTypes: ['ACTOR'], defaultConditions: ['NEW_ACTIVITY', 'NEW_ALIAS', 'NEW_HANDLE', 'NEW_PLATFORM_APPEARANCE', 'NEW_INFRASTRUCTURE', 'NEW_RELATIONSHIP', 'NEW_EVIDENCE', 'NEW_ATTACK_BEHAVIOR', 'ACTOR_STATUS_CHANGE'] },
  { key: 'PERSONA', label: 'Persona', entityTypes: ['ACTOR'], defaultConditions: ['NEW_ACTIVITY', 'NEW_ALIAS', 'NEW_PLATFORM_APPEARANCE', 'NEW_HANDLE'] },
  { key: 'HANDLE', label: 'Handle / Alias', entityTypes: ['HANDLE', 'ALIAS'], defaultConditions: ['NEW_APPEARANCE', 'NEW_PLATFORM', 'NEW_ACTOR_CORRELATION', 'HANDLE_STATUS_CHANGE'] },
  { key: 'PGP', label: 'PGP Key / Fingerprint', entityTypes: ['PGP_KEY', 'PGP'], defaultConditions: ['NEW_OBSERVATION', 'NEW_ASSOCIATION', 'KEY_REVOCATION', 'KEY_EXPIRATION', 'NEW_IDENTITY_ASSOCIATION'] },
  { key: 'WALLET', label: 'Crypto Wallet / Indicator', entityTypes: ['WALLET'], defaultConditions: ['NEW_TRANSACTION', 'INCOMING_ACTIVITY', 'OUTGOING_ACTIVITY', 'ACTIVITY_SPIKE', 'NEW_ASSOCIATED_WALLET', 'SERVICE_ASSOCIATION', 'PRIVACY_SERVICE_INDICATOR', 'BALANCE_CHANGE'] },
  { key: 'INFRASTRUCTURE', label: 'Infrastructure', entityTypes: ['INFRASTRUCTURE'], defaultConditions: ['DOMAIN_CHANGE', 'IP_CHANGE', 'DNS_CHANGE', 'CERTIFICATE_CHANGE', 'ONION_AVAILABILITY_CHANGE', 'NEW_INFRA_ASSOCIATION', 'MIRROR_DISCOVERY'] },
  { key: 'DOMAIN', label: 'Domain', entityTypes: ['INFRASTRUCTURE'], defaultConditions: ['DOMAIN_CHANGE', 'DNS_CHANGE', 'CERTIFICATE_CHANGE', 'NEW_INFRA_ASSOCIATION', 'MIRROR_DISCOVERY'] },
  { key: 'IP', label: 'IP Address', entityTypes: ['INFRASTRUCTURE'], defaultConditions: ['IP_CHANGE', 'DNS_CHANGE', 'CERTIFICATE_CHANGE', 'NEW_INFRA_ASSOCIATION'] },
  { key: 'ONION', label: 'Onion Service', entityTypes: ['INFRASTRUCTURE'], defaultConditions: ['ONION_AVAILABILITY_CHANGE', 'NEW_INFRA_ASSOCIATION', 'MIRROR_DISCOVERY'] },
  { key: 'SOURCE', label: 'Source / Forum / Marketplace', entityTypes: ['SOURCE', 'FORUM', 'MARKETPLACE', 'CHANNEL'], defaultConditions: ['SOURCE_AVAILABILITY', 'COLLECTION_HEALTH', 'NEW_SOURCE_INTELLIGENCE', 'COLLECTION_FAILURE', 'SOURCE_STATUS_CHANGE'] },
  { key: 'OBSERVATION', label: 'Observation', entityTypes: ['OBSERVATION'], defaultConditions: ['NEW_OBSERVATION', 'NEW_MATCHING_OBSERVATION', 'NEW_SUPPORTING_EVIDENCE'] },
  { key: 'EVIDENCE', label: 'Evidence-linked indicator', entityTypes: ['EVIDENCE'], defaultConditions: ['NEW_SUPPORTING_EVIDENCE', 'NEW_RELATIONSHIP'] },
  { key: 'RELATIONSHIP', label: 'Relationship', entityTypes: ['RELATIONSHIP'], defaultConditions: ['RELATIONSHIP_CHANGE', 'CONFIDENCE_CHANGE', 'NEW_SUPPORTING_EVIDENCE', 'RELATIONSHIP_INACTIVE'] },
  { key: 'CVE', label: 'CVE / Vulnerability', entityTypes: [], defaultConditions: ['NEW_RELEVANT_OBSERVATION', 'NEW_MENTION', 'NEW_EXPLOIT_INTELLIGENCE', 'NEW_PRODUCT_REFERENCE'], term: true },
  { key: 'VULNERABILITY', label: 'Vulnerability', entityTypes: [], defaultConditions: ['NEW_RELEVANT_OBSERVATION', 'NEW_MENTION', 'NEW_EXPLOIT_INTELLIGENCE'], term: true },
  { key: 'KEYWORD', label: 'Keyword / Indicator', entityTypes: [], defaultConditions: ['NEW_MATCHING_OBSERVATION', 'NEW_SOURCE_APPEARANCE', 'NEW_ACTOR_ASSOCIATION', 'NEW_TERM_INFRA_ASSOCIATION'], term: true },
  { key: 'ORGANIZATION', label: 'Organization Name', entityTypes: [], defaultConditions: ['NEW_MATCHING_OBSERVATION', 'NEW_MENTION', 'NEW_ACTOR_ASSOCIATION'], term: true },
  { key: 'PRODUCT', label: 'Product Name', entityTypes: [], defaultConditions: ['NEW_MATCHING_OBSERVATION', 'NEW_MENTION', 'NEW_PRODUCT_REFERENCE'], term: true },
  { key: 'ATTACK', label: 'ATT&CK Technique', entityTypes: [], defaultConditions: ['NEW_MATCHING_OBSERVATION', 'NEW_MENTION', 'NEW_ATTACK_BEHAVIOR'], term: true },
  // Indicator terms from the analysis tools. An email address, a URL and a
  // file hash have no first-class entity row anywhere in the platform, and
  // inventing one would duplicate intelligence that already lives in
  // observations and evidence. They are therefore term watches: the value
  // itself is the identity, and detection is the same LIKE sweep the other
  // term targets already use.
  { key: 'EMAIL', label: 'Email Address', entityTypes: [], defaultConditions: ['NEW_MATCHING_OBSERVATION', 'NEW_MENTION', 'NEW_SOURCE_APPEARANCE', 'NEW_ACTOR_ASSOCIATION', 'NEW_INFRA_ASSOCIATION'], term: true, termHint: 'analyst@domain.tld' },
  { key: 'URL', label: 'URL', entityTypes: [], defaultConditions: ['NEW_MATCHING_OBSERVATION', 'NEW_MENTION', 'NEW_SOURCE_APPEARANCE', 'NEW_ACTOR_ASSOCIATION', 'NEW_INFRA_ASSOCIATION'], term: true, termHint: 'https://example.tld/path' },
  { key: 'FILE', label: 'File Hash', entityTypes: [], defaultConditions: ['NEW_MATCHING_OBSERVATION', 'NEW_MENTION', 'NEW_SOURCE_APPEARANCE', 'NEW_ACTOR_ASSOCIATION'], term: true, termHint: 'sha256:3a4f… or a bare 64-char hash' },
  { key: 'CUSTOM', label: 'Custom (multi-target)', entityTypes: [], defaultConditions: [], custom: true },
];

export const TARGET_TYPE_KEYS = TARGET_TYPES.map(t => t.key);

export function targetTypeSpec(targetType) {
  return TARGET_TYPES.find(t => t.key === String(targetType || '').toUpperCase()) || null;
}

/** The whole capability surface, for the UI to render without hardcoding. */
export function monitoringCapabilities() {
  return {
    targetTypes: TARGET_TYPES,
    conditions: CONDITIONS,
    conditionGroups: Object.values(CONDITIONS).reduce((acc, condition) => {
      acc[condition.group] = (acc[condition.group] || 0) + 1;
      return acc;
    }, {}),
    frequencies: FREQUENCIES,
    severities: SEVERITIES,
    statuses: MONITOR_STATUSES,
    lifecycleStatuses: LIFECYCLE_STATUSES,
    runtimeStates: RUNTIME_STATES,
    sourceCapabilities: SOURCE_CAPABILITIES,
    sourceAccessModes: SOURCE_ACCESS_MODES,
  };
}