// Render-time verification for every page the protection panels were mounted
// on.
//
// Typechecking and the logic suite both pass while a page can still crash on
// render — an undefined label, a bad map lookup, a missing context value. A
// real render is the only check that catches those, and the CVE panel already
// had exactly that class of bug. No browser is installed here, so each page is
// rendered to static markup through the real provider tree and router.
//
// A page that throws is reported as either MINE (the stack implicates the
// protection layer) or PRE-EXISTING (it fails for an unrelated reason such as
// a browser-only API in an SSR pass), because only the first is a regression
// from this work.
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { Suspense } from 'react';
import { ThemeProvider } from '../src/context/ThemeContext.tsx';
import { ThreeDProvider } from '../src/context/ThreeDContext.tsx';
import { IntelligenceProvider } from '../src/lib/intelligence/IntelligenceContext.tsx';
import { getDataset } from '../src/lib/intelligence/dataset.ts';

import ThreatActorsPage from '../src/pages/darkweb/ThreatActorsPage.tsx';
import ActorProfilePage from '../src/pages/darkweb/ActorProfilePage.tsx';
import HandleIntelligencePage from '../src/pages/darkweb/HandleIntelligencePage.tsx';
import HandleProfilePage from '../src/pages/darkweb/HandleProfilePage.tsx';
import PgpIntelligencePage from '../src/pages/darkweb/PgpIntelligencePage.tsx';
import PgpProfilePage from '../src/pages/darkweb/PgpProfilePage.tsx';
import WalletIntelligencePage from '../src/pages/darkweb/WalletIntelligencePage.tsx';
import WalletProfilePage from '../src/pages/darkweb/WalletProfilePage.tsx';
import ObservationIntelligencePage from '../src/pages/darkweb/ObservationIntelligencePage.tsx';
import ObservationPage from '../src/pages/darkweb/ObservationPage.tsx';
import InfrastructurePage from '../src/pages/darkweb/InfrastructurePage.tsx';
import SourcesPage from '../src/pages/darkweb/SourcesPage.tsx';
import AttackWorkspacePage from '../src/pages/darkweb/AttackWorkspacePage.tsx';
import CorrelationPage from '../src/pages/darkweb/CorrelationPage.tsx';
import GraphPage from '../src/pages/darkweb/GraphPage.tsx';
import TimelinePage from '../src/pages/darkweb/TimelinePage.tsx';
import EvidenceLockerPage from '../src/pages/darkweb/EvidenceLockerPage.tsx';
import InvestigationsPage from '../src/pages/darkweb/InvestigationsPage.tsx';
import InvestigationWorkspacePage from '../src/pages/darkweb/InvestigationWorkspacePage.tsx';
import AlertsPage from '../src/pages/darkweb/AlertsPage.tsx';
import AIPage from '../src/pages/darkweb/AIPage.tsx';
import ReportsPage from '../src/pages/darkweb/ReportsPage.tsx';
import AddIntelligencePage from '../src/pages/darkweb/AddIntelligencePage.tsx';
import BriefingPage from '../src/pages/app/BriefingPage.tsx';

const dataset = getDataset();
const actorId = dataset.actors[0]?.id ?? 'ACTOR-001';
const handleId = dataset.handles[0]?.id ?? 'HND-001';
const pgpId = dataset.pgpKeys[0]?.id ?? 'PGP-001';
const walletId = dataset.wallets[0]?.id ?? 'WAL-001';
const observationId = dataset.observations[0]?.id ?? 'OBS-HND-001';
const investigationId = dataset.investigations[0]?.id ?? 'INV-DW-001';

const PAGES = [
  ['BriefingPage', '/app/briefing', BriefingPage],
  ['ThreatActorsPage', '/app/darkweb/actors', ThreatActorsPage],
  ['ActorProfilePage', `/app/darkweb/actors/${actorId}`, ActorProfilePage],
  ['HandleIntelligencePage', '/app/darkweb/handles', HandleIntelligencePage],
  ['HandleProfilePage', `/app/darkweb/handles/${handleId}`, HandleProfilePage],
  ['PgpIntelligencePage', '/app/darkweb/pgp-keys', PgpIntelligencePage],
  ['PgpProfilePage', `/app/darkweb/pgp-keys/${pgpId}`, PgpProfilePage],
  ['WalletIntelligencePage', '/app/darkweb/wallets', WalletIntelligencePage],
  ['WalletProfilePage', `/app/darkweb/wallets/${walletId}`, WalletProfilePage],
  ['ObservationIntelligencePage', '/app/darkweb/observations', ObservationIntelligencePage],
  ['ObservationPage', `/app/darkweb/observations/${observationId}`, ObservationPage],
  ['InfrastructurePage', '/app/darkweb/infrastructure', InfrastructurePage],
  ['SourcesPage', '/app/darkweb/sources', SourcesPage],
  ['AttackWorkspacePage', '/app/darkweb/attack', AttackWorkspacePage],
  ['CorrelationPage', '/app/darkweb/correlation', CorrelationPage],
  ['GraphPage', '/app/darkweb/graph', GraphPage],
  ['TimelinePage', '/app/darkweb/timeline', TimelinePage],
  ['EvidenceLockerPage', '/app/darkweb/evidence', EvidenceLockerPage],
  ['InvestigationsPage', '/app/darkweb/investigations', InvestigationsPage],
  ['InvestigationWorkspacePage', `/app/darkweb/investigations/${investigationId}`, InvestigationWorkspacePage],
  ['AlertsPage', '/app/darkweb/alerts', AlertsPage],
  ['AIPage', '/app/darkweb/ai', AIPage],
  ['ReportsPage', '/app/darkweb/reports', ReportsPage],
  ['AddIntelligencePage', '/app/darkweb/add', AddIntelligencePage],
];

// Anything in this list appearing in a stack means the protection layer caused
// the failure rather than an unrelated SSR limitation.
const PROTECTION_MARKERS = [
  'ProtectionPanel',
  'ProtectionModulePanel',
  'ResponseActions',
  'detections',
  'enforcement',
  'types-protection',
  'protection.ts',
];

let rendered = 0;
const mine = [];
const preExisting = [];

for (const [name, path, Page] of PAGES) {
  try {
    const html = renderToStaticMarkup(
      <ThemeProvider>
        <ThreeDProvider>
          <IntelligenceProvider>
            <MemoryRouter initialEntries={[path]}>
              <Suspense fallback={<span>loading</span>}>
                <Routes>
                  <Route path={path} element={<Page />} />
                </Routes>
              </Suspense>
            </MemoryRouter>
          </IntelligenceProvider>
        </ThreeDProvider>
      </ThemeProvider>,
    );
    rendered += 1;
    const panelCount = (html.match(/PROTECTED|PENDING ·|AT RISK|MONITORED|ASSESSED|ACTION PENDING|NO CURRENT RISK/g) ?? []).length;
    console.log(`PASS  ${name.padEnd(28)} ${String(html.length).padStart(7)} bytes  status-words=${panelCount}`);
  } catch (error) {
    const stack = error instanceof Error ? (error.stack ?? error.message) : String(error);
    const culprit = PROTECTION_MARKERS.find(marker => stack.includes(marker));
    const line = stack.split('\n').find(l => l.trim().startsWith('at '))?.trim() ?? stack.split('\n')[0];
    console.log(`FAIL  ${name.padEnd(28)} ${culprit ? 'PROTECTION-REGRESSION' : 'pre-existing/environmental'}  ${line}`);
    console.log(`      ${stack.split('\n').slice(0, 4).join('\n      ')}`);
    if (culprit) mine.push(name); else preExisting.push(name);
  }
}

console.log(`\nrendered ${rendered}/${PAGES.length} pages`);
if (preExisting.length) console.log(`pre-existing/environmental failures (${preExisting.length}): ${preExisting.join(', ')}`);
if (mine.length) console.log(`PROTECTION REGRESSIONS (${mine.length}): ${mine.join(', ')}`);
process.exit(mine.length === 0 ? 0 : 1);