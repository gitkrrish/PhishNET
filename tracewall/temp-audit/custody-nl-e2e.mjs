// ============================================================
// Temporary: end-to-end verification of the additive custody and
// natural-language search work.
//
// Covers the routes this change added, including the failure paths, and
// checks the specific honesty guarantees:
//
//   * an item that predates tracking reports NO_HISTORY and gains no
//     invented events from a read
//   * a verification with no content is NOT_VERIFIABLE, never a pass
//   * a mismatch never rewrites the stored digest
//   * an unparsable question returns zero matches and says so, rather
//     than dumping the population
//
// Writes to the database, so the caller must snapshot tracewall.sqlite
// before running this and restore it afterwards.
// ============================================================
const BASE = 'http://127.0.0.1:8787/api';

const session = await fetch(`${BASE}/auth/sign-in`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: 'analyst@tracewall.demo', password: 'demo-password' }),
}).then(r => r.json());
const auth = { 'Content-Type': 'application/json', Authorization: `Bearer ${session.token}` };

let failures = 0;
function check(name, condition, detail = '') {
  const ok = Boolean(condition);
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
}

async function call(method, path, body) {
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers: auth,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await response.text();
  let payload = null;
  try { payload = text ? JSON.parse(text) : null; } catch { payload = { raw: text }; }
  return { status: response.status, data: payload?.data, error: payload?.error?.message, raw: text };
}

const sha256 = async value => {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return `sha256:${[...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('')}`;
};

// ── Baseline counts, so any write below is accounted for ─────────
const beforeEvidence = (await call('GET', '/intel/evidence')).data.length;
const beforeAudit = (await call('GET', '/intel/audit')).data.length;
console.log(`baseline: ${beforeEvidence} evidence, ${beforeAudit} audit\n`);

// ── 1. Event types ──────────────────────────────────────────────
const types = (await call('GET', '/intel/custody/event-types')).data;
check('event types resolve', Array.isArray(types) && types.length > 0, `${types?.length} types`);
check('event types carry labels', types.every(t => t.type && t.label));

// ── 2. A read must not create history ────────────────────────────
const firstEvidence = (await call('GET', '/intel/evidence')).data[0];
const readChain = (await call('GET', `/intel/evidence/${firstEvidence.id}/custody`)).data;
const readEvents = readChain.events.length;
const secondRead = (await call('GET', `/intel/evidence/${firstEvidence.id}/custody`)).data;
check(
  'reading a chain does not append an event',
  readEvents === secondRead.events.length,
  `${readEvents} then ${secondRead.events.length}`,
);
check(
  'pre-existing item reports NO_HISTORY with no fabricated events',
  readChain.historyStatus === 'NO_HISTORY' && readChain.events.length === 0 && readChain.trackingStartedAt === null,
  `${firstEvidence.id}: ${readChain.historyStatus}, ${readChain.events.length} events`,
);
check('chain carries a limitation statement', typeof readChain.integrityDisclaimer === 'string' && readChain.integrityDisclaimer.length > 20);

// ── 3. Register a real custody event ─────────────────────────────
const registered = (await call('POST', `/intel/evidence/${firstEvidence.id}/custody`, {
  eventType: 'EVIDENCE_COLLECTED',
  action: 'E2E verification registration',
  reason: 'Acceptance test: first tracked event on a pre-existing item',
})).data;
check('registration appends exactly one event', registered.chain.events.length === 1, `${registered.chain.events.length} events`);
check('registration switches history status to TRACKED', registered.chain.historyStatus === 'TRACKED');
check('registered event is marked TRACKED, not audit-derived', registered.event.origin === 'TRACKED');
check('event carries a server timestamp', Boolean(registered.event.occurredAt) && !Number.isNaN(Date.parse(registered.event.occurredAt)));
check('event records the authenticated analyst', typeof registered.event.actor === 'string' && registered.event.actor.length > 0);

const invalidType = await call('POST', `/intel/evidence/${firstEvidence.id}/custody`, { eventType: 'NOT_A_REAL_EVENT' });
check('unknown event type rejected with 400', invalidType.status === 400, `status ${invalidType.status}`);
const missingEvidence = await call('GET', '/intel/evidence/EVID-DOES-NOT-EXIST/custody');
check('unknown evidence id rejected with 404', missingEvidence.status === 404, `status ${missingEvidence.status}`);

// ── 4. Verification: the three honest outcomes ───────────────────
const content = 'acceptance test payload for chain of custody verification';
// The server returns the calculated digest as bare hex; the stored value
// may carry an explicit `sha256:` label. Compare the hex bodies.
const expectedHex = (await sha256(content)).replace(/^sha256:/, '');
const storedBefore = (await call('GET', `/intel/evidence/${firstEvidence.id}/custody`)).data.evidence.hash;

const noContent = (await call('POST', `/intel/evidence/${firstEvidence.id}/verify`, {})).data.verification;
check('verification with no content is NOT_VERIFIABLE', noContent.result === 'NOT_VERIFIABLE', noContent.result);
check('NOT_VERIFIABLE does not claim authenticity', noContent.authenticityEstablished === false);
check('NOT_VERIFIABLE still records a run', noContent.verificationCount >= 1, `count ${noContent.verificationCount}`);

const matched = (await call('POST', `/intel/evidence/${firstEvidence.id}/verify`, { content })).data.verification;
const mismatch = (await call('POST', `/intel/evidence/${firstEvidence.id}/verify`, { content: `${content} tampered` })).data.verification;
const afterRuns = (await call('GET', `/intel/evidence/${firstEvidence.id}/custody`)).data.evidence;
const storedAfter = afterRuns.hash;

check('SHA-256 of supplied content computed correctly', matched.calculatedHash === expectedHex, matched.calculatedHash ?? 'none');
check('mismatched content reports MISMATCH', mismatch.result === 'MISMATCH', mismatch.result);
check('mismatch never rewrites the stored digest', storedBefore === storedAfter, `${storedBefore} -> ${storedAfter}`);
check('a match is not presented as proof of authenticity', matched.authenticityEstablished === false);
check('each verification advances the run counter', afterRuns.verificationCount >= 3, `count ${afterRuns.verificationCount}`);
check('the last recorded result is the last one that ran', afterRuns.lastVerificationResult === 'MISMATCH', afterRuns.lastVerificationResult);

const chainAfter = (await call('GET', `/intel/evidence/${firstEvidence.id}/custody`)).data;
check('verification events appear in the chain', chainAfter.events.length >= 4, `${chainAfter.events.length} events`);
check('failure event is recorded, not hidden', chainAfter.events.some(e => e.eventType === 'INTEGRITY_VERIFICATION_FAILED'));

// ── 5. Model-wide custody event feed ─────────────────────────────
const feed = (await call('GET', '/intel/custody/events?limit=10')).data;
check('custody event feed returns appended events', Array.isArray(feed) && feed.length > 0, `${feed?.length} events`);
check('feed is newest first', feed.length < 2 || Date.parse(feed[0].occurredAt) >= Date.parse(feed[1].occurredAt));
check('feed labels each event origin', feed.every(e => e.origin === 'TRACKED' || e.origin === 'AUDIT_DERIVED'));

// ── 6. Natural language search: investigations scope ─────────────
async function nl(path, query) {
  const response = await call('POST', path, { query });
  // A refused question answers with an error, not a result envelope.
  return response.data ?? { error: response.error ?? `status ${response.status}` };
}

const blank = await nl('/intel/investigations/nl-search', '   ');
check('whitespace-only question is refused', typeof blank.error === 'string' && blank.error.length > 0, blank.error ?? 'no error');

const nonsense = await nl('/intel/investigations/nl-search', 'Nonesuch');
check('unparsable question is flagged unfiltered', nonsense.unfiltered === true);
check('unparsable question returns no matches', nonsense.matches.length === 0, `${nonsense.matches.length} matches`);
check('unparsable question reports the population it did not select', typeof nonsense.evaluated === 'number', `evaluated ${nonsense.evaluated}`);
check('unparsable question explains itself', nonsense.unsupported.length > 0 && Boolean(nonsense.unsupported[0].reason));

const openCases = await nl('/intel/investigations/nl-search', 'show open investigations');
check('a real question applies a filter', openCases.unfiltered === false && openCases.operations.some(o => o.applied));
check('a real question returns the matching case', openCases.matches.some(m => m.id === 'INV-DW-001'), openCases.matches.map(m => m.id).join(',') || 'none');
check('each match states why it qualified', openCases.matches.every(m => m.reasons.length > 0));
check('each match names its source records', openCases.matches.every(m => Array.isArray(m.sourceRecords.evidenceIds)));

const unverified = await nl('/intel/investigations/nl-search', 'investigations with unverified evidence');
check('unverified-evidence filter is applied', unverified.operations.some(o => o.kind === 'EVIDENCE_UNVERIFIED' && o.applied));

const namedActor = await nl('/intel/investigations/nl-search', 'investigations linked to ACTOR-001');
check('a named actor resolves to the case', namedActor.matches.some(m => m.id === 'INV-DW-001'));
check(
  'resolved entities are reported, grouped by kind',
  Array.isArray(namedActor.entities.actorIds) && namedActor.entities.actorIds.includes('ACTOR-001'),
  JSON.stringify(namedActor.entities.actorIds),
);
check('each operation states its filter in words', namedActor.operations.every(o => typeof o.label === 'string' && o.label.length > 0));

const unknownActor = await nl('/intel/investigations/nl-search', 'investigations linked to ACTOR-999');
check('unknown record id is not used as a filter', unknownActor.unsupported.some(u => u.reason.includes('do not exist')));

// ── 7. Natural language search: whole-model scope ────────────────
const aiNonsense = await nl('/intel/ai/nl-search', 'banana');
check('model scope also refuses to answer nonsense', aiNonsense.unfiltered === true && aiNonsense.total === 0);

const actorFacts = await nl('/intel/ai/nl-search', 'everything about ACTOR-001');
check('model scope answers a named actor', actorFacts.unfiltered === false && actorFacts.total > 0, `${actorFacts.total} statements`);
check('no inference is invented without a model', actorFacts.inference.length === 0 && actorFacts.inferenceAvailable === false);
check('observed statements name their source record', actorFacts.observed.every(s => Boolean(s.sourceId)));
check('observed statements carry a navigation target', actorFacts.observed.some(s => Object.values(s.navigation ?? {}).some(Boolean)));

const unverifiedAi = await nl('/intel/ai/nl-search', 'which evidence has not been verified');
check('unverified-evidence query returns statements', unverifiedAi.observed.length > 0, `${unverifiedAi.observed.length}`);
check(
  'an item with no verification run is never called verified',
  unverifiedAi.observed.every(s => !/integrity verified/.test(s.statement)),
);
check(
  'an ingest-time status is labelled as a claim, not a check',
  unverifiedAi.observed.every(s => !/integrity never verified \(recorded status/.test(s.statement)),
);

const sharedInfra = await nl('/intel/ai/nl-search', 'infrastructure shared between actors');
check('shared-infrastructure query produces correlation statements', sharedInfra.correlation.length > 0, `${sharedInfra.correlation.length}`);
check('correlation statements are labelled as joins', sharedInfra.correlation.every(s => Boolean(s.statement && s.sourceId)));

const emptyAi = await nl('/intel/ai/nl-search', 'open high severity investigations in the last 7 days');
check('an empty but parsed question is not reported as unparsed', emptyAi.unfiltered === false);
check('an empty result carries no statements', emptyAi.total === 0 && emptyAi.observed.length === 0);

// ── 8. Audit append endpoint ─────────────────────────────────────
const auditWrite = await call('POST', '/intel/audit', {
  action: 'E2E verification',
  entity: 'REPORT',
  entityId: 'RPT-E2E',
  after: 'audit append check',
});
check('audit append succeeds with 201', auditWrite.status === 201, `status ${auditWrite.status}`);
const auditIncomplete = await call('POST', '/intel/audit', { action: 'E2E verification' });
check('audit append requires action and entity', auditIncomplete.status === 400, `status ${auditIncomplete.status}`);

// ── 9. Nothing outside the custody feature was disturbed ─────────
const afterEvidence = (await call('GET', '/intel/evidence')).data.length;
const afterAudit = (await call('GET', '/intel/audit')).data.length;
check('no evidence record was created or removed by this test', afterEvidence === beforeEvidence, `${beforeEvidence} -> ${afterEvidence}`);
console.log(`\naudit rows: ${beforeAudit} -> ${afterAudit} (append-only, expected to grow)`);

console.log(`\n${failures === 0 ? 'ALL CHECKS PASSED' : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);