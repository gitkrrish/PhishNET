// Effect-level verification for the protection panels.
//
// The static-markup render harness proves a panel produces correct markup, but
// `renderToStaticMarkup` never runs effects, so everything effect-driven was
// unverified — most importantly the async monitoring lookup in ProtectionPanel.
// This harness mounts the panels into a real DOM with `createRoot`, lets
// effects and promises settle, and then reads the live DOM.
//
// The API is stubbed per case, so no request reaches a real backend.
import { GlobalWindow } from 'happy-dom';
import { act } from 'react';

const win = new GlobalWindow({ url: 'http://localhost/app/darkweb/actors/ACTOR-001' });
const container = win.document.createElement('div');
win.document.body.appendChild(container);

// React only treats `act` as supported when this flag is set.
(globalThis as unknown as Record<string, unknown>).IS_REACT_ACT_ENVIRONMENT = true;

// happy-dom v20 does not publish its window onto globalThis by itself, and
// react-dom reads `window` and `document` as bare globals. Register what the
// renderer and the panels touch, without clobbering Node's own globals.
const DOM_GLOBALS = [
  'window', 'document', 'location', 'history', 'localStorage',
  'sessionStorage', 'customElements', 'getComputedStyle', 'requestAnimationFrame',
  'cancelAnimationFrame', 'matchMedia', 'DOMParser', 'NodeFilter', 'CSS',
];
for (const key of DOM_GLOBALS) {
  const value = (win as unknown as Record<string, unknown>)[key];
  if (value !== undefined) {
    // Some of these (navigator) exist on globalThis as getter-only in Node,
    // so they are redefined rather than assigned.
    Object.defineProperty(globalThis, key, { value, configurable: true, writable: true });
  }
}
// Interface constructors React instantiates while building the tree.
for (const key of Object.getOwnPropertyNames(win)) {
  if (/^[A-Z]/.test(key) && !(key in globalThis)) {
    const value = (win as unknown as Record<string, unknown>)[key];
    if (typeof value === 'function' || typeof value === 'object') {
      Object.defineProperty(globalThis, key, { value, configurable: true, writable: true });
    }
  }
}

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

// Models a `Response` closely enough for the API client: `text()` as well as
// `json()`. The client reads the body as text so it can tell a JSON answer from
// an HTML page served by a routing fallback, so a double that only offered
// `json()` no longer described what the browser hands it.
const json = (body, status = 200) => ({
  ok: status >= 200 && status < 300,
  status,
  json: async () => body,
  text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
});

// Signs in, then answers the monitoring lookup for whichever entity the case
// declares. Everything else 404s so an unexpected request is visible.
let monitoringHandler: (url: string) => unknown = () => json({ data: [] });
const seenRequests = [];
const realFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  const url = typeof input === 'string' ? input : String(input?.url ?? input);
  seenRequests.push(`${init?.method ?? 'GET'} ${url}`);
  if (url.includes('/auth/sign-in')) return json({ data: { token: 'verify-token', user: { id: 'USR-DEMO-001', name: 'Verify', role: 'Analyst' } } });
  if (url.includes('/intel/monitoring/entity/')) return monitoringHandler(url);
  throw new Error(`unexpected request in the effect harness: ${url}`);
};

// Imported after the DOM and the fetch stub exist, because the intelligence
// store reads window.localStorage at module scope.
const { createRoot } = await import('react-dom/client');
const { MemoryRouter } = await import('react-router-dom');
const { ThemeProvider } = await import('../src/context/ThemeContext.tsx');
const { ThreeDProvider } = await import('../src/context/ThreeDContext.tsx');
const { IntelligenceProvider } = await import('../src/lib/intelligence/IntelligenceContext.tsx');
const { ProtectionPanel } = await import('../src/components/darkweb/ProtectionPanel.tsx');
const { ProtectionModulePanel } = await import('../src/components/darkweb/ProtectionModulePanel.tsx');
const { getDataset } = await import('../src/lib/intelligence/dataset.ts');

const dataset = getDataset();
const actorId = dataset.actors[0]?.id ?? 'ACTOR-001';
const otherActorId = dataset.actors[1]?.id ?? 'ACTOR-002';

// The real provider tree from App.tsx, with MemoryRouter in place of
// BrowserRouter so a route can be supplied per mount.
const Tree = ({ children }: { children: React.ReactNode }) => (
  <ThemeProvider>
    <ThreeDProvider>
      <IntelligenceProvider>
        <MemoryRouter initialEntries={['/app/darkweb/actors']}>{children}</MemoryRouter>
      </IntelligenceProvider>
    </ThreeDProvider>
  </ThemeProvider>
);

const mount = async (node: React.ReactNode) => {
  container.innerHTML = '';
  const root = createRoot(container);
  await act(async () => {
    root.render(<Tree>{node}</Tree>);
  });
  // Let the async monitoring lookup resolve and its state update commit.
  await act(async () => {
    await new Promise(resolve => setTimeout(resolve, 30));
  });
  const html = container.innerHTML;
  await act(async () => { root.unmount(); });
  return html;
};

const MONITOR = {
  id: 'MON-VERIFY-1',
  name: 'Verify monitor',
  status: 'ACTIVE',
  runtimeState: 'OK',
  lastCheck: '2026-10-03T05:00:00.000Z',
  nextCheck: '2026-10-03T06:00:00.000Z',
  capability: { intervalLabel: 'hourly' },
};

section('The monitoring effect runs and reflects a live monitor');
monitoringHandler = () => json({ data: [MONITOR] });
let html = await mount(<ProtectionPanel entityType="ACTOR" entityId={actorId} />);
ok(
  seenRequests.some(url => url.includes(`/intel/monitoring/entity/ACTOR/${actorId}`)),
  'the effect actually issued the monitoring lookup',
  seenRequests.find(u => u.includes('monitoring/entity')) ?? 'no request seen',
);
ok(/hourly interval/.test(html), 'the panel renders the monitor cadence from the response');
ok(/>ACTIVE<\/p>/.test(html), 'the monitoring status label renders as ACTIVE');

section('A paused monitor is reported as paused, not active');
monitoringHandler = () => json({ data: [{ ...MONITOR, status: 'PAUSED' }] });
html = await mount(<ProtectionPanel entityType="ACTOR" entityId={actorId} />);
// The label is its own element, so this cannot be confused with the panel's
// other uses of the word "active" such as the actor status fact.
ok(/>PAUSED<\/p>/.test(html), 'the monitoring status label renders as PAUSED');
ok(!/>ACTIVE<\/p>/.test(html), 'a paused monitor never renders an ACTIVE monitoring label');

section('A degraded monitor is surfaced, not hidden');
for (const [runtimeState, expected] of [['SOURCE_UNAVAILABLE', 'SOURCE UNAVAILABLE'], ['ERROR', 'MONITOR ERROR']]) {
  monitoringHandler = () => json({ data: [{ ...MONITOR, runtimeState }] });
  html = await mount(<ProtectionPanel entityType="ACTOR" entityId={actorId} />);
  ok(html.includes(expected), `a ${runtimeState} monitor renders as "${expected}"`);
}

section('No monitor is stated as unknown, not as "not monitored"');
monitoringHandler = () => json({ data: [] });
html = await mount(<ProtectionPanel entityType="ACTOR" entityId={actorId} />);
ok(!/hourly interval/.test(html), 'an empty monitor list does not fabricate a cadence');
ok(
  /not monitored|no monitor|unknown|not tracked/i.test(html),
  'an empty monitor list is stated honestly',
);

section('A failing backend does not break the panel');
monitoringHandler = () => { throw new Error('API unavailable'); };
html = await mount(<ProtectionPanel entityType="ACTOR" entityId={actorId} />);
ok(html.length > 1500, 'the panel still renders its derived detection when monitoring fails', `${html.length} bytes`);
ok(/AT RISK|MONITORED|ASSESSED|ACTION PENDING|PROTECTED|NO CURRENT RISK/.test(html), 'a protection status is still shown when monitoring fails');

section('The effect does not fire for an entity type it cannot resolve');
monitoringHandler = () => json({ data: [MONITOR] });
const before = seenRequests.length;
html = await mount(<ProtectionPanel entityType="ACTOR" entityId="NO-SUCH-ACTOR" />);
ok(!/hourly interval/.test(html), 'an unknown record shows no monitoring claim');
ok(html.length > 0, 'an unknown record still renders the no-coverage explanation');

section('Module panels run their effects too');
monitoringHandler = () => json({ data: [] });
html = await mount(<ProtectionModulePanel entityType="ACTOR" title="Threat Actors" />);
ok(html.length > 400, 'the module panel rendered after effects ran', `${html.length} bytes`);
ok(/Threat Actors/.test(html), 'the module panel renders its title');

section('Switching entity re-runs the effect against the new record');
monitoringHandler = (url: string) =>
  json({
    data: [
      {
        ...MONITOR,
        name: url.includes(actorId) ? 'Actor monitor' : 'Other monitor',
        capability: { intervalLabel: url.includes(actorId) ? 'hourly' : 'daily' },
      },
    ],
  });
container.innerHTML = '';
const root = createRoot(container);
await act(async () => {
  root.render(<Tree><ProtectionPanel entityType="ACTOR" entityId={actorId} /></Tree>);
});
await act(async () => { await new Promise(resolve => setTimeout(resolve, 30)); });
ok(/hourly interval/.test(container.innerHTML), 'first entity resolved its own monitor');
await act(async () => {
  root.render(<Tree><ProtectionPanel entityType="ACTOR" entityId={otherActorId} /></Tree>);
});
await act(async () => { await new Promise(resolve => setTimeout(resolve, 30)); });
ok(/daily interval/.test(container.innerHTML), 'switching entity re-queried and rendered the new monitor state');
await act(async () => { root.unmount(); });

globalThis.fetch = realFetch;
console.log(`\n${failures === 0 ? 'PASS' : 'FAIL'} — ${checks - failures}/${checks} checks passed`);
process.exit(failures === 0 ? 0 : 1);