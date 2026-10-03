// Component-level render verification for the protection panels.
//
// The page-level harness renders the profile routes, but those pages resolve
// their entity asynchronously and so render a "not found" skeleton in a single
// synchronous pass — which means the protection panel itself was never
// actually rendered by it. These panels are the highest-risk surface in this
// change (an undefined label or a missing map lookup only shows up at render),
// so each one is rendered directly against a real view built from the shipped
// dataset, for every entity type and every module.
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';
import { ThemeProvider } from '../src/context/ThemeContext.tsx';
import { ThreeDProvider } from '../src/context/ThreeDContext.tsx';
import { IntelligenceProvider } from '../src/lib/intelligence/IntelligenceContext.tsx';
import { getDataset } from '../src/lib/intelligence/dataset.ts';
import { protectionView, moduleProtectionSummary } from '../src/lib/intelligence/detections.ts';
import { ProtectionPanel } from '../src/components/darkweb/ProtectionPanel.tsx';
import { ProtectionModulePanel } from '../src/components/darkweb/ProtectionModulePanel.tsx';
import { ResponseActions, ActionHistory, Caveats, ProtectionLinks } from '../src/components/darkweb/ResponseActions.tsx';

const dataset = getDataset();

const PROBES = [
  ['ACTOR', dataset.actors[0]?.id],
  ['ACTOR', dataset.actors.find(a => a.status === 'DORMANT')?.id ?? dataset.actors[0]?.id],
  ['HANDLE', dataset.handles[0]?.id],
  ['HANDLE', dataset.handles.find(h => /shadow/i.test(h.value))?.id ?? dataset.handles[0]?.id],
  ['PGP', dataset.pgpKeys[0]?.id],
  ['WALLET', dataset.wallets[0]?.id],
  ['INFRASTRUCTURE', dataset.infrastructure.find(i => i.type === 'IP')?.id ?? dataset.infrastructure[0]?.id],
  ['INFRASTRUCTURE', dataset.infrastructure.find(i => i.type === 'DOMAIN')?.id ?? dataset.infrastructure[0]?.id],
  ['SOURCE', dataset.sources[0]?.id],
  ['OBSERVATION', dataset.observations[0]?.id],
  ['EVIDENCE', dataset.evidence[0]?.id],
  ['RELATIONSHIP', dataset.relationships[0]?.id],
  ['MITRE_TTP', dataset.mitreTtps[0]?.id],
  ['CVE', dataset.cves[0]?.id],
  ['CVE', dataset.cves.find(c => c.exploitationStatus === 'ACTIVE')?.id ?? dataset.cves[0]?.id],
  ['VULNERABILITY', dataset.vulnerabilities[0]?.id],
  ['WALLET_TRANSACTION', dataset.walletTransactions[0]?.id],
  ['WALLET_CLUSTER', dataset.walletClusters[0]?.id],
  ['INVESTIGATION', dataset.investigations[0]?.id],
].filter(([, id]) => !!id);

const MODULES = [
  'ACTOR', 'HANDLE', 'PGP', 'WALLET', 'INFRASTRUCTURE', 'SOURCE',
  'OBSERVATION', 'EVIDENCE', 'RELATIONSHIP', 'MITRE_TTP', 'CVE', 'VULNERABILITY',
  'WALLET_TRANSACTION', 'WALLET_CLUSTER', 'INVESTIGATION',
];

let failures = 0;
let checks = 0;
const ok = (condition, label, detail = '') => {
  checks += 1;
  if (condition) console.log(`PASS  ${label}${detail ? ` — ${detail}` : ''}`);
  else {
    failures += 1;
    console.log(`FAIL  ${label}${detail ? ` — ${detail}` : ''}`);
  }
};
const section = (title) => console.log(`\n── ${title} ${'─'.repeat(Math.max(0, 58 - title.length))}`);

const wrap = (node) =>
  renderToStaticMarkup(
    <ThemeProvider>
      <ThreeDProvider>
        <IntelligenceProvider>
          <MemoryRouter initialEntries={['/app/darkweb/actors']}>{node}</MemoryRouter>
        </IntelligenceProvider>
      </ThreeDProvider>
    </ThemeProvider>,
  );

section('ProtectionPanel renders for every entity type');
for (const [entityType, entityId] of PROBES) {
  const label = `${entityType} ${entityId}`;
  try {
    const html = wrap(<ProtectionPanel entityType={entityType} entityId={entityId} />);
    // A panel that resolved nothing would render the "no detection coverage"
    // placeholder instead of real detections; require actual content.
    const hasStatus = /PROTECTED|ACTION PENDING|AT RISK|MONITORED|ASSESSED|NO CURRENT RISK/.test(html);
    const hasCaveats = /does not|not claim|cannot|no numeric risk score|no detection coverage/i.test(html);
    ok(html.length > 1500, `${label}: panel rendered substantial content`, `${html.length} bytes`);
    ok(hasStatus, `${label}: panel shows a protection status`);
    ok(hasCaveats, `${label}: panel states its limits`);
  } catch (error) {
    ok(false, `${label}: panel rendered`, error instanceof Error ? error.message : String(error));
  }
}

section('ProtectionModulePanel renders for every module');
for (const entityType of MODULES) {
  const summary = moduleProtectionSummary(dataset, entityType);
  try {
    const html = wrap(<ProtectionModulePanel entityType={entityType} title={summary.label} />);
    ok(html.length > 400, `${entityType} module panel rendered`, `${html.length} bytes, ${summary.total} row(s)`);
    ok(
      /MONITORED|AT RISK|ASSESSED|ACTION PENDING|PROTECTED|NO CURRENT RISK/.test(html),
      `${entityType} module panel shows a posture per row`,
    );
  } catch (error) {
    ok(false, `${entityType} module panel rendered`, error instanceof Error ? error.message : String(error));
  }
}

section('Response action surfaces render from real views');
let viewsWithActions = 0;
for (const [entityType, entityId] of PROBES) {
  const view = protectionView(dataset, entityType, entityId);
  if (!view) {
    ok(false, `${entityType} ${entityId}: view resolved`);
    continue;
  }
  const label = `${entityType} ${entityId}`;
  try {
    if (view.actions.length > 0) viewsWithActions += 1;
    const actions = wrap(<ResponseActions view={view} />);
    const history = wrap(<ActionHistory view={view} />);
    const caveats = wrap(<Caveats caveats={view.caveats} />);
    const links = wrap(<ProtectionLinks view={view} />);
    ok(actions.length > 200, `${label}: response actions rendered`, view.actions.length + ' action(s)');
    ok(caveats.length > 50, `${label}: caveats rendered`, view.caveats.length + ' caveat(s)');
    ok(links.length > 20, `${label}: cross-module links rendered`);
    void history;
  } catch (error) {
    ok(false, `${label}: response surfaces rendered`, error instanceof Error ? error.message : String(error));
  }
}
ok(viewsWithActions > 0, 'at least one real record offers response actions', `${viewsWithActions} view(s)`);

section('A view with no applicable workflow still renders its guidance');
const noActionView = protectionView(dataset, 'SOURCE', dataset.sources[0]?.id);
if (noActionView) {
  try {
    const html = wrap(<ResponseActions view={noActionView} />);
    ok(html.length > 0, 'a zero-action view renders its explanatory text rather than crashing', `${html.length} bytes`);
  } catch (error) {
    ok(false, 'a zero-action view renders', error instanceof Error ? error.message : String(error));
  }
}

console.log(`\n${failures === 0 ? 'PASS' : 'FAIL'} — ${checks - failures}/${checks} checks passed`);
process.exit(failures === 0 ? 0 : 1);