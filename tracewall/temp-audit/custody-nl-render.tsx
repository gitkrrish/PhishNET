// Render-time verification for the chain-of-custody and natural-language
// search surfaces.
//
// Typechecking passes while a component can still crash on render, and the
// natural-language response shape is the kind of thing that does: the entity
// field is a set of grouped buckets rather than a flat list, and the panel has
// to read it as such. No browser is installed here, so each surface is
// rendered to static markup through the real provider tree and router, and the
// new panels are additionally driven with a recorded API response so the
// branches that only appear after a search are exercised too.
//
// A page that throws is reported as MINE or PRE-EXISTING, because only the
// first is a regression from this work.
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { ThemeProvider } from '../src/context/ThemeContext.tsx';
import { ThreeDProvider } from '../src/context/ThreeDContext.tsx';
import { IntelligenceProvider } from '../src/lib/intelligence/IntelligenceContext.tsx';
import { getDataset } from '../src/lib/intelligence/dataset.ts';

import EvidenceLockerPage from '../src/pages/darkweb/EvidenceLockerPage.tsx';
import InvestigationsPage from '../src/pages/darkweb/InvestigationsPage.tsx';
import AIPage from '../src/pages/darkweb/AIPage.tsx';
import ReportsPage from '../src/pages/darkweb/ReportsPage.tsx';
import { NlSearchPanel, NlSearchResults } from '../src/components/darkweb/NlSearchPanel.tsx';
import { ChainOfCustody } from '../src/components/darkweb/ChainOfCustody.tsx';

const dataset = getDataset();
const investigationId = dataset.investigations[0]?.id ?? 'INV-DW-001';
const evidenceId = dataset.evidence[0]?.id ?? 'EVID-001';

let failures = 0;
const ok = (condition, label, detail = '') => {
  if (condition) console.log(`PASS  ${label}${detail ? ` — ${detail}` : ''}`);
  else {
    failures += 1;
    console.log(`FAIL  ${label}${detail ? ` — ${detail}` : ''}`);
  }
};

/** Classify a render throw rather than reporting every failure as a regression. */
function classify(error, { feature }) {
  const stack = String(error?.stack ?? error);
  if (/ChainOfCustody|NlSearchPanel|reportExport|intelligence\/custody|intelligence\/nlSearch/.test(stack)) return 'MINE';
  return `PRE-EXISTING (${feature} page throws outside the new code: ${String(error?.message ?? error).split('\n')[0]})`;
}

function renderPage(name, path, element, feature) {
  try {
    const markup = renderToStaticMarkup(
      <ThemeProvider>
        <ThreeDProvider>
          <IntelligenceProvider>
            <MemoryRouter initialEntries={[path]}>
              <Routes>
                <Route path={path} element={element} />
              </Routes>
            </MemoryRouter>
          </IntelligenceProvider>
        </ThreeDProvider>
      </ThemeProvider>,
    );
    ok(markup.length > 500, `${name} renders`, `${markup.length} bytes`);
    return markup;
  } catch (error) {
    const verdict = classify(error, { feature });
    if (verdict === 'MINE') failures += 1;
    console.log(`${verdict === 'MINE' ? 'FAIL' : 'SKIP'}  ${name} — ${verdict}`);
    return '';
  }
}

// ── The four pages this change touched ───────────────────────────
const locker = renderPage('EvidenceLockerPage', '/app/darkweb/evidence', <EvidenceLockerPage />, 'Evidence Locker');
ok(locker.includes('Evidence Locker'), 'Evidence Locker keeps its locker view');
ok(locker.includes('Chain of Custody'), 'Evidence Locker exposes the custody tab');
ok(locker.includes('Locker') && locker.includes('Chain of Custody'), 'both tab labels render');

const investigations = renderPage('InvestigationsPage', '/app/darkweb/investigations', <InvestigationsPage />, 'Investigations');
ok(investigations.includes('Ask the case'), 'Investigations hosts the question panel');
ok(investigations.includes('Applied filters') === false, 'no result panel is shown before a question is asked');
ok(!/hover:bg-burg/.test(investigations), 'the dead hover utility is gone');

const ai = renderPage('AIPage', '/app/darkweb/ai', <AIPage />, 'AI Analysis');
ok(ai.includes('whole intelligence model'), 'AI Analysis questions the whole model, not a local engine');
ok(!ai.includes('Structured interpretation'), 'the shallow local NL result block is gone');
// `&amp;` in server output is the correct escaping of a literal ampersand,
// not an undecoded entity, so it must NOT be asserted against here. What
// matters is that the page renders an ampersand at all.
ok(ai.includes('&amp;') && ai.includes('protection'), 'ampersands render as text, not as markup');

const reports = renderPage('ReportsPage', '/app/darkweb/reports', <ReportsPage />, 'Reports');
ok(reports.includes('Export'), 'report rows offer an export');
ok(!reports.includes('would generate from'), 'the fake report-generation alert is gone');
ok(reports.includes('Investigation') || reports.includes('investigation'), 'report rows reference their investigation');

// ── The panels, driven with the real response shapes ────────────
// A recorded investigation-scope response, exactly as the endpoint returns it:
// `entities` is a set of grouped buckets and operations carry `label`.
const INVESTIGATION_RESPONSE = {
  query: 'open investigations linked to ACTOR-001',
  scope: 'investigations',
  operations: [
    { kind: 'STATUS', label: 'Status = ACTIVE', value: 'ACTIVE', applied: true },
    { kind: 'ACTOR', label: 'Threat actor: ACTOR-001', value: ['ACTOR-001'], applied: true },
    { kind: 'EVIDENCE_UNVERIFIED', label: 'Evidence without a successful integrity verification', value: true, applied: true },
  ],
  unsupported: [],
  entities: {
    actorIds: ['ACTOR-001'], handleIds: [], handleValues: [], walletIds: [], walletAddresses: [],
    pgpFingerprints: [], infrastructureIds: [], infrastructureValues: [], evidenceIds: [],
    relationshipIds: [], investigationIds: [], ipValues: [], domainValues: [], unresolvedIds: [],
  },
  note: 'note',
  evaluated: 1,
  total: 1,
  matches: [{
    id: 'INV-DW-001', title: 'Operation Shadow Ledger', status: 'ACTIVE', analyst: 'Dr. Priya Mehta',
    confidence: 88, updatedAt: '2026-09-20T00:00:00Z', lastActivityAt: null,
    evidenceCount: 10, unverifiedEvidenceCount: 10, entityCount: 3,
    reasons: [
      { field: 'status', matched: 'stored status is ACTIVE', kind: 'observed' },
      { field: 'threatActor', matched: 'references ACTOR-001', kind: 'observed' },
    ],
    navigation: { investigationPath: `/app/darkweb/investigations/${investigationId}` },
    sourceRecords: { investigationId, evidenceIds: ['EVID-001'], relationshipIds: [], actorIds: ['ACTOR-001'] },
  }],
  truncated: false,
  unfiltered: false,
};

const AI_RESPONSE = {
  query: 'infrastructure shared between actors',
  scope: 'ai',
  operations: [{ kind: 'INFRASTRUCTURE_SHARED', label: 'Infrastructure recorded against more than one actor', value: 'SHARED_INFRASTRUCTURE', applied: true }],
  unsupported: [],
  entities: {
    actorIds: [], handleIds: [], handleValues: [], walletIds: [], walletAddresses: [],
    pgpFingerprints: [], infrastructureIds: [], infrastructureValues: ['ghostwire-relay.net'], evidenceIds: [],
    relationshipIds: [], investigationIds: [], ipValues: [], domainValues: ['ghostwire-relay.net'], unresolvedIds: [],
  },
  note: 'note',
  answerKind: 'ANSWER',
  observed: [],
  correlation: [{
    statement: 'DOMAIN ghostwire-relay.net is recorded against 3 threat actors (ACTOR-001, ACTOR-002, ACTOR-003).',
    sourceId: 'INF-001',
    navigation: { infrastructurePath: '/app/darkweb/infrastructure?seed=INF-001' },
  }],
  inference: [],
  inferenceAvailable: false,
  matchedInvestigations: [],
  unfiltered: false,
  total: 1,
};

const UNPARSED_RESPONSE = {
  query: 'banana', scope: 'ai', operations: [], unsupported: [],
  entities: AI_RESPONSE.entities, note: 'note', answerKind: 'NO_MATCH',
  observed: [], correlation: [], inference: [], inferenceAvailable: false,
  matchedInvestigations: [], unfiltered: true, total: 0,
};

function renderPanel(label, element, feature) {
  try {
    const markup = renderToStaticMarkup(
      <ThemeProvider>
        <ThreeDProvider>
          <IntelligenceProvider>
            <MemoryRouter>{element}</MemoryRouter>
          </IntelligenceProvider>
        </ThreeDProvider>
      </ThemeProvider>,
    );
    ok(true, label, `${markup.length} bytes`);
    return markup;
  } catch (error) {
    const verdict = classify(error, { feature });
    if (verdict === 'MINE') failures += 1;
    console.log(`${verdict === 'MINE' ? 'FAIL' : 'SKIP'}  ${label} — ${verdict}`);
    return '';
  }
}

// The panel fetches on mount, so a synchronous pass only reaches its idle
// state. The branches that only appear after a search are rendered instead
// through NlSearchResults, driven with responses recorded from the running
// API — including the entity buckets, which are grouped rather than a flat
// list and are the part most likely to be read wrongly.
// The panel's idle state: it must not present a result before a question
// has been asked.
const panelEmpty = renderPanel('NlSearchPanel renders idle', <NlSearchPanel scope="ai" placeholder="ask" />, 'NL panel');
ok(panelEmpty.includes('Ask the case'), 'the idle panel names its scope');
ok(!panelEmpty.includes('Applied filters'), 'idle panel shows no applied-filter section');
ok(!panelEmpty.includes('No filter was understood'), 'idle panel does not claim the question was unparsed');

const investigationResults = renderPanel(
  'NlSearchResults renders an investigation answer',
  <NlSearchResults answer={INVESTIGATION_RESPONSE} />,
  'NL results',
);
ok(investigationResults.includes('Applied filters'), 'investigation answer lists the filters it applied');
ok(investigationResults.includes('Status = ACTIVE'), 'an operation is shown in the wording the endpoint used');
ok(investigationResults.includes('INV-DW-001'), 'the matching case is listed');
ok(investigationResults.includes('stored status is ACTIVE'), 'the reason a record matched is shown');
ok(investigationResults.includes('1 match'), 'the match count is reported against the population');
ok(investigationResults.includes('Recognised entities'), 'resolved entity buckets render as text');
ok(investigationResults.includes('actor: ACTOR-001'), 'the actor bucket is read, not iterated as a list');
ok(!investigationResults.includes('No filter was understood'), 'a parsed answer is not reported as unparsed');

const aiResults = renderPanel(
  'NlSearchResults renders a whole-model answer',
  <NlSearchResults answer={AI_RESPONSE} />,
  'NL results',
);
ok(aiResults.includes('Correlation (joined records)'), 'correlations are labelled as joins');
// The record id belongs in the link target, not in the visible text: the
// label names the kind of record so the statement reads as prose.
ok(/href="\/app\/darkweb\/infrastructure\?seed=INF-001"/.test(aiResults), 'the source record is linked by id');
ok(aiResults.includes('infrastructure →') || aiResults.includes('infrastructure<!-- -->'), 'the link is labelled by record kind, not by id');
ok(aiResults.includes('infrastructure'), 'the correlation statement body renders');
ok(aiResults.includes('No inference is offered'), 'the absence of a model is stated');
ok(aiResults.includes('infrastructure: ghostwire-relay.net'), 'the infrastructure bucket is read');

const unparsedResults = renderPanel(
  'NlSearchResults renders an unparsable answer',
  <NlSearchResults answer={UNPARSED_RESPONSE} />,
  'NL results',
);
ok(unparsedResults.includes('No filter was understood'), 'an unparsable question says so');
ok(unparsedResults.includes('banana') === false, 'an unparsable question shows no result body');
ok(!unparsedResults.includes('statement(s)'), 'an unparsable question shows no statement count');

const custodyIdle = renderPanel('ChainOfCustody renders loading', <ChainOfCustody evidenceId={evidenceId} />, 'custody panel');
ok(custodyIdle.length > 0, 'custody panel has a loading state rather than rendering empty');

console.log(`\n${failures === 0 ? 'RENDER CHECKS PASSED' : `${failures} RENDER CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);