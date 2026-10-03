import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

// ── API origin, resolved once ────────────────────────────────────────────
//
// In development the browser talks to `/api` and the dev proxy above forwards
// to the local backend. In production the browser also talks to `/api`, and
// `vercel.json` proxies that to the deployed backend — but only if it knows
// where the backend is. That destination is `${PHISHNET_API_ORIGIN}`, expanded
// by Vercel at request time from the project's environment.
//
// If that variable is absent the rewrite has no origin, so the request falls
// through to the SPA rule below and every `/api/*` call is answered by the
// static site: GET returns the HTML document with a 200 that looks like
// success, POST returns a bodyless 405. Nothing about that reads as a
// misconfiguration from the outside, which is exactly how a deployment like
// that reaches production unnoticed.
//
// VITE_API_URL is the documented alternative: set it to a full backend origin
// (e.g. `https://<backend>/api`) and the browser calls the backend directly,
// with no rewrite involved. Either variable satisfies the requirement; having
// neither means the API cannot work in the artifact being built.
function assertProductionApiOrigin() {
  const onVercelProduction = process.env.VERCEL === '1' && process.env.VERCEL_ENV === 'production'
  if (!onVercelProduction) return

  const origin = process.env.PHISHNET_API_ORIGIN?.trim()
  const direct = process.env.VITE_API_URL?.trim()

  if (!origin && !direct) {
    throw new Error(
      [
        'Refusing to build: the deployed API has no origin.',
        '',
        'vercel.json proxies /api/* to ${PHISHNET_API_ORIGIN}. Without it the',
        'rewrite cannot resolve, /api/* falls through to the SPA fallback, and',
        'every API call is answered by the static site (GET returns the HTML',
        'document with a 200, POST returns a bodyless 405).',
        '',
        'Set one of these in the Vercel project environment:',
        '  PHISHNET_API_ORIGIN  the deployed backend origin, no trailing slash,',
        '                        no path — e.g. https://<service>.onrender.com',
        '                        (the Node backend in backend/server.mjs)',
        '  VITE_API_URL         instead, the full backend API base including',
        '                        /api — e.g. https://<service>.onrender.com/api —',
        '                        which sends the browser straight to the backend',
        '',
        'This application cannot run on Vercel serverless: it stores state in',
        'node:sqlite on a writable filesystem and runs an in-process scheduler.',
        'The backend needs a long-running Node host.',
      ].join('\n'),
    )
  }

  // A trailing slash or an included /api would silently produce `//api/*` or
  // `/api/api/*`, which fails the same way as no origin at all.
  if (origin && !/^https:\/\/[^\s/]+$/.test(origin)) {
    throw new Error(
      [
        `Refusing to build: PHISHNET_API_ORIGIN is "${origin}".`,
        'Expected a bare https origin with no trailing slash and no path, e.g.',
        'https://phishnet-api-abc123.onrender.com — vercel.json appends /api/*.',
      ].join('\n'),
    )
  }
  if (direct && !/^https:\/\/[^\s]+\/api$/.test(direct)) {
    throw new Error(
      [
        `Refusing to build: VITE_API_URL is "${direct}".`,
        'Expected a full https API base ending in /api, e.g.',
        'https://phishnet-api-abc123.onrender.com/api — the client appends the',
        'path itself.',
      ].join('\n'),
    )
  }
}

assertProductionApiOrigin()

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    watch: {
      ignored: ['**/backend/database/**'],
    },
    proxy: {
      '/api': 'http://localhost:8787',
    },
  },
  resolve: {
    alias: {
      '@': new URL('./src', import.meta.url).pathname,
    },
  },
})