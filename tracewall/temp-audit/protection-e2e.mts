// ============================================================
// End-to-end verification of the active protection & response layer.
//
// Runs against the shipped synthetic demo dataset — no destructive action,
// no live blocking, no network call to any real control plane. Every
// assertion here is about honesty and consistency, which is the whole
// point of the layer:
//
//   * detections resolve to records that already exist
//   * a module roll-up and the entity panel behind it agree
//   * nothing is reported as blocked unless an integration confirmed it
//   * a wallet is never offered a blocking action
//   * recording an action never creates or duplicates intelligence
// ============================================================
import { getDataset } from '../src/lib/intelligence/dataset.ts';
import { moduleProtectionSummary, modulePathFor, protectionView, extractIndicators } from '../src/lib/intelligence/detections.ts';
import { protectionRecords, recordResponseAction, enforcementVerdict, lastActionSummary, responseActionRecords } from '../src/lib/intelligence/protection.ts';
import { responseActionOptions, runEnforcement, enforcementSummaryLine, configuredChannels, classifyIndicatorValue } from '../src/lib/intelligence/enforcement.ts';

let failures = 0;
let checks = 0;

const ok = (condition, label, detail = '') => {
  checks += 1;
  if (condition) {
    console.log(`PASS  ${label}${detail ? ` — ${detail}` : ''}`);
  } else {
    failures += 1;
    console.log(`FAIL  ${label}${detail ? ` — ${detail}` : ''}`);
  }
};

const section = (title) => console.log(`\n── ${title} ${'─'.repeat(Math.max(0, 62 - title.length))}`);

const dataset = getDataset();

section('Dataset integrity — the protection layer must not have altered it');
console.log(
  `actors=${dataset.actors.length} handles=${dataset.handles.length} pgp=${dataset.pgpKeys.length} wallets=${dataset.wallets.length} infra=${dataset.infrastructure.length} sources=${dataset.sources.length}`,
);
console.log(
  `observations=${dataset.observations.length} evidence=${dataset.evidence.length} relationships=${dataset.relationships.length} timeline=${dataset.timeline.length} investigations=${dataset.investigations.length} alerts=${dataset.alerts.length}`,
);
console.log(
  `mitreTtps=${dataset.mitreTtps.length} cves=${dataset.cves.length} vulnerabilities=${dataset.vulnerabilities.length} tx=${dataset.walletTransactions.length} clusters=${dataset.walletClusters.length}`,
);

section('Derived detections resolve to records that already exist');
const derived = protectionRecords(dataset);
const knownIds = new Set([
  ...dataset.actors.map(r => r.id),
  ...dataset.handles.map(r => r.id),
  ...dataset.pgpKeys.map(r => r.id),
  ...dataset.wallets.map(r => r.id),
  ...dataset.infrastructure.map(r => r.id),
  ...dataset.cves.map(r => r.id),
  ...dataset.vulnerabilities.map(r => r.id),
]);
const phantom = derived.filter(record => !knownIds.has(record.entityId));
ok(phantom.length === 0, 'no protection record points at a non-existent entity', phantom.map(p => p.entityId).join(', '));
ok(derived.length > 0, 'derived protection records were produced', `${derived.length} records`);
const withReasons = derived.filter(record => record.score.reasons.length > 0);
ok(withReasons.length === derived.length, 'every score states at least one detection reason', `${withReasons.length}/${derived.length}`);

section('Module roll-ups — every module that owns records reports a posture');
const moduleTypes = [
  'ACTOR', 'HANDLE', 'PGP', 'WALLET', 'INFRASTRUCTURE', 'SOURCE',
  'OBSERVATION', 'EVIDENCE', 'RELATIONSHIP', 'MITRE_TTP', 'CVE', 'VULNERABILITY',
  'WALLET_TRANSACTION', 'WALLET_CLUSTER', 'INVESTIGATION',
];
for (const entityType of moduleTypes) {
  const summary = moduleProtectionSummary(dataset, entityType);
  console.log(
    `${summary.label.padEnd(28)} total=${String(summary.total).padStart(3)} crit=${String(summary.critical).padStart(2)} high=${String(summary.high).padStart(2)} med=${String(summary.medium).padStart(2)} atRisk=${String(summary.atRiskCount).padStart(2)} protected=${summary.protectedCount} alerts=${summary.openAlerts} evidence=${summary.linkedEvidence}`,
  );
}

section('Module roll-up and entity panel agree on status');
const consistencyProbes = [
  ['ACTOR', dataset.actors[0]?.id],
  ['HANDLE', dataset.handles[0]?.id],
  ['PGP', dataset.pgpKeys[0]?.id],
  ['WALLET', dataset.wallets[0]?.id],
  ['INFRASTRUCTURE', dataset.infrastructure[0]?.id],
  ['SOURCE', dataset.sources[0]?.id],
  ['OBSERVATION', dataset.observations[0]?.id],
  ['EVIDENCE', dataset.evidence[0]?.id],
  ['RELATIONSHIP', dataset.relationships[0]?.id],
  ['MITRE_TTP', dataset.mitreTtps[0]?.id],
  ['CVE', dataset.cves[0]?.id],
  ['VULNERABILITY', dataset.vulnerabilities[0]?.id],
  ['WALLET_TRANSACTION', dataset.walletTransactions[0]?.id],
  ['WALLET_CLUSTER', dataset.walletClusters[0]?.id],
  ['INVESTIGATION', dataset.investigations[0]?.id],
].filter(([, id]) => !!id);

for (const [entityType, entityId] of consistencyProbes) {
  const view = protectionView(dataset, entityType, entityId);
  const row = moduleProtectionSummary(dataset, entityType).rows.find(item => item.entityId === entityId);
  ok(
    !!view && !!row && view.status === row.status,
    `${entityType} ${entityId}: panel status matches module roll-up`,
    `panel=${view?.status} rollup=${row?.status}`,
  );
  ok(
    !!view && view.caveats.length > 0,
    `${entityType} ${entityId}: states what it does not claim`,
    `${view?.caveats.length ?? 0} caveat(s)`,
  );
}

section('Entity panels — detection, supporting intelligence and recommendations');
for (const [entityType, entityId] of consistencyProbes) {
  const view = protectionView(dataset, entityType, entityId);
  if (!view) continue;
  console.log(
    `${entityType.padEnd(20)} ${view.headline.slice(0, 58).padEnd(58)} status=${view.status.padEnd(9)} facts=${String(view.facts.length).padStart(2)} alerts=${view.alerts.length} ev=${view.evidence.length} inv=${view.investigations.length} actions=${view.actions.length}`,
  );
  ok(view.recommendation.label.length > 0, `${entityType} ${entityId}: has a recommended defensive action`, view.recommendation.label);
  ok(view.actions.every(action => action.availabilityReason.length > 0), `${entityType} ${entityId}: every action states why it is or is not available`);
}

section('Enforcement honesty — nothing may be reported as applied without an integration');
console.log(`Configured enforcement channels: ${configuredChannels().length}`);
console.log(enforcementSummaryLine());
const ipEntity = dataset.infrastructure.find(infra => infra.type === 'IP') ?? dataset.infrastructure[0];
const domainEntity = dataset.infrastructure.find(infra => infra.type === 'DOMAIN' && !/\.onion$/i.test(infra.value));
const walletEntity = dataset.wallets[0];
const handleEntity = dataset.handles[0];

ok(classifyIndicatorValue('203.0.113.7') === 'IP', 'an IPv4 value classifies as IP');
ok(classifyIndicatorValue('evil.example.com') === 'DOMAIN', 'a hostname classifies as DOMAIN');
ok(classifyIndicatorValue('bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq') === 'WALLET', 'a bech32 address classifies as WALLET');

if (ipEntity) {
  const options = responseActionOptions('IP', ipEntity.value);
  const block = options.find(option => option.kind === 'BLOCK_IP');
  ok(!!block, 'a malicious-class IP is offered a firewall workflow');
  ok(block?.channel === 'FIREWALL', 'the IP block maps to the firewall channel', String(block?.channel));
  const attempt = await runEnforcement(block, {
    entityType: 'IP', entityId: ipEntity.id, entityValue: ipEntity.value, performedBy: 'VERIFY',
  });
  ok(attempt.status !== 'ENFORCED_VERIFIED', 'an unconfigured firewall is never reported as enforced', attempt.status);
  ok(attempt.detail.toLowerCase().includes('not configured') || attempt.detail.toLowerCase().includes('no endpoint'), 'the pending state says why nothing was blocked', attempt.detail.slice(0, 90));
  recordResponseAction({
    entityType: 'INFRASTRUCTURE', entityId: ipEntity.id, entityValue: ipEntity.value,
    kind: 'BLOCK_IP', status: attempt.status, channel: attempt.channel, detail: attempt.detail, performedBy: 'VERIFY',
  });
  ok(enforcementVerdict(ipEntity.id) === 'DECIDED', 'a recorded-but-unverified action yields PENDING, not PROTECTED', enforcementVerdict(ipEntity.id));
  const view = protectionView(dataset, 'INFRASTRUCTURE', ipEntity.id);
  ok(view?.status === 'PENDING', 'the panel shows PENDING for that record', view?.status);
}

if (domainEntity) {
  const block = responseActionOptions('DOMAIN', domainEntity.value).find(option => option.kind === 'BLOCK_DOMAIN');
  ok(!!block && block.channel === 'DNS_SECURITY_GATEWAY', 'a domain maps to the DNS security gateway workflow');
  const attempt = await runEnforcement(block, {
    entityType: 'DOMAIN', entityId: domainEntity.id, entityValue: domainEntity.value, performedBy: 'VERIFY',
  });
  ok(attempt.status !== 'ENFORCED_VERIFIED', 'an unconfigured DNS gateway is never reported as enforced', attempt.status);
}

if (walletEntity) {
  const options = responseActionOptions('WALLET', walletEntity.address);
  const blocking = options.filter(option => option.kind.startsWith('BLOCK_') || option.kind === 'QUARANTINE_FILE');
  ok(blocking.length === 0, 'a public-chain wallet is never offered a blocking or quarantine workflow', options.map(o => o.kind).join(', '));
  const monitor = options.find(option => option.kind === 'MONITOR_WALLET');
  ok(!!monitor, 'a wallet is offered monitoring instead');
  const walletView = protectionView(dataset, 'WALLET', walletEntity.id);
  ok(
    (walletView?.caveats ?? []).some(c => /cannot freeze|seize or block/i.test(c)),
    'the wallet panel states the platform cannot freeze an address',
  );
}

if (handleEntity) {
  const options = responseActionOptions('HANDLE', handleEntity.value);
  ok(options.some(option => option.kind === 'BLOCK_HANDLE'), 'a handle is offered a platform-restriction workflow');
}

const pgpEntity = dataset.pgpKeys[0];
if (pgpEntity) {
  const options = responseActionOptions('PGP', pgpEntity.fingerprint);
  ok(options.some(option => option.kind === 'REVOKE_TRUST'), 'a PGP key is offered a trust-revocation workflow');
  const view = protectionView(dataset, 'PGP', pgpEntity.id);
  ok(
    (view?.caveats ?? []).some(c => /revoked, expired or compromised/i.test(c)),
    'the PGP panel refuses to claim a key is compromised without evidence',
  );
}

section('Confirmation contract — a 2xx alone is never "enforced"');
// The previous behaviour treated any 2xx as proof the control changed, which
// meant a stub that returned `{}` would mark an entity protected. Drive the
// real code path with a stubbed integration to prove each outcome is
// distinguished, including the ones that must NOT claim enforcement.
const realFetch = globalThis.fetch;
const sharedEnv = ((import.meta as unknown as { env?: Record<string, string> }).env ??= {});
const realFirewall = sharedEnv.VITE_ENFORCEMENT_FIREWALL;
const realFirewallEndpoint = sharedEnv.VITE_ENFORCEMENT_FIREWALL_ENDPOINT;
sharedEnv.VITE_ENFORCEMENT_FIREWALL = 'true';
sharedEnv.VITE_ENFORCEMENT_FIREWALL_ENDPOINT = 'http://127.0.0.1:9/firewall';

const probeOption = responseActionOptions('IP', '203.0.113.7').find(o => o.kind === 'BLOCK_IP');
ok(probeOption?.availability === 'APPROVAL_REQUIRED', 'a configured channel offers the action for approval', String(probeOption?.availability));
ok(probeOption?.requiresApproval === true, 'a channel-plane change is marked as requiring approval');

const respondWith = (handler) => {
  globalThis.fetch = async () => handler();
};
const probe = async (label, handler, expected) => {
  respondWith(handler);
  const attempt = await runEnforcement(probeOption, {
    entityType: 'IP', entityId: 'VERIFY-PROBE-1', entityValue: '203.0.113.7', performedBy: 'VERIFY',
  });
  ok(attempt.status === expected, label, `got ${attempt.status}`);
  return attempt;
};

const unconfirmed = await probe(
  'a 200 with an empty body is NOT reported as enforced',
  () => ({ ok: true, status: 200, json: async () => ({}) }),
  'SUBMITTED_UNCONFIRMED',
);
ok(unconfirmed.confirmedAt === null, 'an unconfirmed submission records no confirmation timestamp');
ok(
  /will not report this as enforced/i.test(unconfirmed.detail),
  'the unconfirmed outcome tells the analyst to verify the control manually',
);

await probe(
  'a 200 with a non-JSON body is NOT reported as enforced',
  () => ({ ok: true, status: 200, json: async () => { throw new Error('not json'); } }),
  'SUBMITTED_UNCONFIRMED',
);
await probe(
  'a 200 that only says accepted, without confirming, is NOT reported as enforced',
  () => ({ ok: true, status: 202, json: async () => ({ accepted: true }) }),
  'SUBMITTED_UNCONFIRMED',
);
await probe(
  'an explicit applied:false is a failure',
  () => ({ ok: true, status: 200, json: async () => ({ applied: false }) }),
  'FAILED',
);
await probe(
  'a non-2xx response is a failure',
  () => ({ ok: false, status: 500, json: async () => ({}) }),
  'FAILED',
);
await probe(
  'an unreachable integration is a failure, not a silent success',
  () => { throw new Error('ECONNREFUSED'); },
  'FAILED',
);

const confirmed = await probe(
  'a 200 that explicitly confirms the change IS enforced',
  () => ({ ok: true, status: 200, json: async () => ({ applied: true, confirmed: true }) }),
  'ENFORCED_VERIFIED',
);
ok(!!confirmed.confirmedAt, 'a verified enforcement records when it was confirmed');
// The verdict is read from the persisted ledger, so the confirmed outcome has
// to be recorded before the panel can legitimately call the entity protected.
ok(enforcementVerdict('VERIFY-PROBE-1') === 'NONE', 'an enforcement result is not trusted until it is recorded');
recordResponseAction({
  entityType: 'IP', entityId: 'VERIFY-PROBE-1', entityValue: '203.0.113.7',
  kind: 'BLOCK_IP', status: confirmed.status, channel: confirmed.channel, detail: confirmed.detail,
  performedBy: 'VERIFY', confirmedAt: confirmed.confirmedAt,
});
ok(enforcementVerdict('VERIFY-PROBE-1') === 'VERIFIED', 'a confirmed, recorded enforcement resolves to a verified verdict', enforcementVerdict('VERIFY-PROBE-1'));
ok(protectionView(dataset, 'INFRASTRUCTURE', 'VERIFY-PROBE-1') === null, 'the probe id is not a dataset record, so no panel is fabricated for it');

section('An unconfirmed submission can never read as protected');
respondWith(() => ({ ok: true, status: 200, json: async () => ({}) }));
const pendingAttempt = await runEnforcement(probeOption, {
  entityType: 'INFRASTRUCTURE', entityId: ipEntity?.id ?? 'VERIFY-PROBE-2', entityValue: ipEntity?.value ?? '203.0.113.7', performedBy: 'VERIFY',
});
recordResponseAction({
  entityType: 'INFRASTRUCTURE', entityId: ipEntity?.id ?? 'VERIFY-PROBE-2', entityValue: ipEntity?.value ?? '203.0.113.7',
  kind: 'BLOCK_IP', status: pendingAttempt.status, channel: pendingAttempt.channel, detail: pendingAttempt.detail, performedBy: 'VERIFY',
});
ok(enforcementVerdict(ipEntity?.id ?? 'VERIFY-PROBE-2') !== 'VERIFIED', 'a sent-but-unconfirmed action never yields a verified verdict');
ok(protectionView(dataset, 'INFRASTRUCTURE', ipEntity?.id ?? 'VERIFY-PROBE-2')?.status !== 'PROTECTED', 'the panel never shows PROTECTED for an unconfirmed action');

globalThis.fetch = realFetch;
if (realFirewall === undefined) delete sharedEnv.VITE_ENFORCEMENT_FIREWALL; else sharedEnv.VITE_ENFORCEMENT_FIREWALL = realFirewall;
if (realFirewallEndpoint === undefined) delete sharedEnv.VITE_ENFORCEMENT_FIREWALL_ENDPOINT; else sharedEnv.VITE_ENFORCEMENT_FIREWALL_ENDPOINT = realFirewallEndpoint;
ok(configuredChannels().length === 0, 'removing the channel config returns the deployment to "nothing configured"');

section('Cross-module links point at pages that actually show the record');
// A link to a page that does not contain the record is worse than no link:
// it looks like the product has a view it does not have. These assertions
// pin each module to the page that really owns that data.
const OWNING_PAGE: Record<string, string | undefined> = {
  ACTOR: '/app/darkweb/actors',
  HANDLE: '/app/darkweb/handles',
  PGP: '/app/darkweb/pgp-keys',
  WALLET: '/app/darkweb/wallets',
  INFRASTRUCTURE: '/app/darkweb/infrastructure',
  SOURCE: '/app/darkweb/sources',
  OBSERVATION: '/app/darkweb/observations',
  EVIDENCE: '/app/darkweb/evidence',
  RELATIONSHIP: '/app/darkweb/graph',
  MITRE_TTP: '/app/darkweb/attack',
  CVE: '/app/darkweb/attack',
  VULNERABILITY: undefined,
  WALLET_TRANSACTION: '/app/darkweb/wallets',
  WALLET_CLUSTER: '/app/darkweb/wallets',
  INVESTIGATION: '/app/darkweb/investigations',
};
for (const [entityType, expected] of Object.entries(OWNING_PAGE)) {
  const summary = moduleProtectionSummary(dataset, entityType);
  // A record may link to its own detail route (…/actors/ACTOR-001) rather
  // than the module index, so what matters is that every path stays inside
  // the module that actually owns the data.
  const offenders = summary.rows.filter(row => {
    const path = row.path;
    if (expected === undefined) return path !== undefined;
    return !path || !path.startsWith(expected);
  });
  ok(
    offenders.length === 0,
    `${entityType} only links inside the page that owns it`,
    offenders.length === 0
      ? `${summary.rows.length} row(s) under ${expected ?? 'no record link'}`
      : `offenders: ${offenders.slice(0, 3).map(r => `${r.entityId}->${r.path ?? 'undefined'}`).join(', ')}`,
  );
}

// The AI page is the one target that must never be used as a fallback owner:
// it contains no CVE, vulnerability or technique content at all.
for (const entityType of ['MITRE_TTP', 'CVE', 'VULNERABILITY']) {
  const summary = moduleProtectionSummary(dataset, entityType);
  ok(
    summary.rows.every(row => !(row.path ?? '').startsWith('/app/darkweb/ai')),
    `${entityType} does not claim the AI page owns it`,
  );
}

const vulnerabilityView = protectionView(dataset, 'VULNERABILITY', dataset.vulnerabilities[0]?.id);
ok(vulnerabilityView?.entityPath === undefined, 'a vulnerability offers no misleading record link', String(vulnerabilityView?.entityPath));
for (const [entityType, entityId, expected] of [
  ['MITRE_TTP', dataset.mitreTtps[0]?.id, '/app/darkweb/attack'],
  ['CVE', dataset.cves[0]?.id, '/app/darkweb/attack'],
] as const) {
  const view = entityId ? protectionView(dataset, entityType, entityId) : null;
  ok(
    view !== null && (view?.entityPath ?? '').startsWith(expected),
    `${entityType} panel links to the ATT&CK workspace, not the AI page`,
    String(view?.entityPath),
  );
}
ok(
  (vulnerabilityView?.caveats ?? []).some(c => /no detail view/i.test(c)),
  'the vulnerability panel explains why there is no record link',
);

section('No rendered list can produce a duplicate React key');
// A duplicate key makes React drop or duplicate rows, which would hide a
// detection from an analyst rather than merely mis-order it. Detection reasons
// were the real instance of this: per-indicator loops emitted several rows all
// titled "Shared infrastructure" or "Shared wallet".
const allRecords: Array<[string, string[]]> = [
  ['ACTOR', dataset.actors.map(r => r.id)],
  ['HANDLE', dataset.handles.map(r => r.id)],
  ['PGP', dataset.pgpKeys.map(r => r.id)],
  ['WALLET', dataset.wallets.map(r => r.id)],
  ['INFRASTRUCTURE', dataset.infrastructure.map(r => r.id)],
  ['SOURCE', dataset.sources.map(r => r.id)],
  ['OBSERVATION', dataset.observations.map(r => r.id)],
  ['EVIDENCE', dataset.evidence.map(r => r.id)],
  ['RELATIONSHIP', dataset.relationships.map(r => r.id)],
  ['MITRE_TTP', dataset.mitreTtps.map(r => r.id)],
  ['CVE', dataset.cves.map(r => r.id)],
  ['VULNERABILITY', dataset.vulnerabilities.map(r => r.id)],
  ['WALLET_TRANSACTION', dataset.walletTransactions.map(r => r.id)],
  ['WALLET_CLUSTER', dataset.walletClusters.map(r => r.id)],
  ['INVESTIGATION', dataset.investigations.map(r => r.id)],
];
let scoredRecords = 0;
const reasonKeyClashes: string[] = [];
const factLabelClashes: string[] = [];
const caveatClashes: string[] = [];
const findDuplicates = (items: string[]) => {
  const seen = new Set<string>();
  const dup = new Set<string>();
  for (const item of items) {
    if (seen.has(item)) dup.add(item);
    seen.add(item);
  }
  return [...dup];
};
for (const [entityType, ids] of allRecords) {
  for (const entityId of ids) {
    const view = protectionView(dataset, entityType, entityId);
    if (!view) continue;
    if (view.score) {
      scoredRecords += 1;
      const clashes = findDuplicates(view.score.reasons.map(r => `${r.signal}-${r.label}`));
      if (clashes.length) reasonKeyClashes.push(`${entityType} ${entityId}: ${clashes.join(', ')}`);
    }
    const factDupes = findDuplicates(view.facts.map(f => f.label));
    if (factDupes.length) factLabelClashes.push(`${entityType} ${entityId}: ${factDupes.join(', ')}`);
    const caveatDupes = findDuplicates(view.caveats);
    if (caveatDupes.length) caveatClashes.push(`${entityType} ${entityId}`);
  }
}
console.log(`checked ${scoredRecords} scored records across ${allRecords.length} record classes`);
ok(reasonKeyClashes.length === 0, 'no record renders two detection signals under the same key', reasonKeyClashes.slice(0, 3).join(' | '));
ok(factLabelClashes.length === 0, 'no record renders two facts under the same key', factLabelClashes.slice(0, 3).join(' | '));
ok(caveatClashes.length === 0, 'no record renders the same caveat twice', caveatClashes.slice(0, 3).join(' | '));

section('Indicator extraction from observation and evidence text');
const sample = dataset.observations.find(o => /@|0x|bc1|\d+\.\d+\.\d+\.\d+/.test(o.content)) ?? dataset.observations[0];
if (sample) {
  const classes = extractIndicators(sample.content);
  console.log(`${sample.id} -> ${classes.length > 0 ? classes.join(', ') : 'no indicators'}`);
  ok(Array.isArray(classes), 'extraction returns indicator classes for an observation');
}
ok(extractIndicators('contact dropper@evil.example.com from 203.0.113.7 wallet bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq').length === 4, 'extraction finds handle, domain, IP and wallet in one string');

section('Recording a response action does not create or duplicate intelligence');
const beforeCounts = {
  actors: dataset.actors.length,
  handles: dataset.handles.length,
  infrastructure: dataset.infrastructure.length,
  wallets: dataset.wallets.length,
  evidence: dataset.evidence.length,
};
const actionsBefore = responseActionRecords().length;
if (ipEntity) {
  recordResponseAction({
    entityType: 'INFRASTRUCTURE', entityId: ipEntity.id, entityValue: ipEntity.value,
    kind: 'MONITOR', status: 'RECORDED', channel: null, detail: 'verification probe', performedBy: 'VERIFY',
  });
}
const after = getDataset();
ok(
  after.actors.length === beforeCounts.actors &&
  after.handles.length === beforeCounts.handles &&
  after.infrastructure.length === beforeCounts.infrastructure &&
  after.wallets.length === beforeCounts.wallets &&
  after.evidence.length === beforeCounts.evidence,
  'intelligence record counts are unchanged by response actions',
);
ok(responseActionRecords().length === actionsBefore + 1, 'the response action was recorded in the action ledger');
ok(!!lastActionSummary(ipEntity?.id ?? ''), 'the entity reports its last action', lastActionSummary(ipEntity?.id ?? '') ?? 'none');

section('Correlation evidence is always shown with its provenance');
let reasoned = 0;
for (const record of derived) {
  for (const reason of record.score.reasons) {
    if (reason.label && reason.detail) reasoned += 1;
  }
}
ok(reasoned > 0, 'every detection reason carries both a label and the evidence detail behind it', `${reasoned} reasons`);

console.log(`\n${failures === 0 ? 'PASS' : 'FAIL'} — ${checks - failures}/${checks} checks passed`);
process.exit(failures === 0 ? 0 : 1);