// Bundle config for the scheduler liveness probe.
//
// The probe drives the real monitoring client, which reads `import.meta.env`
// once at module scope and keeps its session token in `sessionStorage`. Vite's
// replacement of that expression does not happen in this build and Node has no
// session storage, so both are provided ahead of every module body. The API
// base defaults to the local dev proxy, so the probe travels the same path the
// browser does rather than skipping the proxy.
//
//   PHISHTWALL_API_BASE=http://localhost:8787/api npm run verify:monitoring:scheduler
const apiBase = process.env.PHISHTWALL_API_BASE ?? 'http://localhost:5173/api';

export default {
  input: ['temp-audit/monitoring-scheduler-liveness.mts'],
  plugins: [{ name: 'css-stub', load(id) { if (id.endsWith('.css')) return 'export default {};'; } }],
  transform: { jsx: 'react-jsx' },
  platform: 'node',
  output: {
    dir: 'temp-audit/.out',
    entryFileNames: '[name].mjs',
    format: 'esm',
    banner: [
      `import.meta.env = { VITE_API_URL: '${apiBase}' };`,
      'globalThis.sessionStorage ??= { getItem: () => null, setItem: () => {}, removeItem: () => {} };',
    ].join('\n'),
  },
};