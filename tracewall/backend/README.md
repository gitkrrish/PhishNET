# PhishNet Backend

The backend is a separate Node.js service for the PhishNet frontend.

## Start

```bash
npm run api
```

The API listens on `http://localhost:8787` by default. Vite proxies `/api` requests to it during development.

## Structure

- `server.mjs`: process entrypoint
- `config/`: environment and path configuration
- `database/`: SQLite state store and non-destructive JSON recovery copy
- `middleware/`: HTTP parsing and authentication
- `routes/`: HTTP route boundary
- `controllers/`: request dispatch and response mapping
- `services/`: auth, analysis, case, report, alert, and audit business logic
- `utils/`: validation and identifiers

## Configuration

- `API_PORT`: API port, default `8787`
- `CORS_ORIGIN`: allowed frontend origin, default `*` for local development
- `SESSION_HOURS`: session lifetime, default `8`
- `MAX_BODY_BYTES`: JSON request limit, default `5 MB`

The service uses Node 24's built-in SQLite driver. The existing `tracewall.json` file is retained as a recovery seed/backup and is never used to reset the SQLite database. No destructive reset or seed command exists.

## API contract

- `GET /api/health`
- `POST /api/auth/sign-in`
- `GET /api/cases`, `POST /api/cases`
- `POST /api/cases/:id/note`, `POST /api/cases/:id/task`, `POST /api/cases/:id/timeline`
- `PATCH /api/cases/:id/tasks/:taskId`
- `POST /api/analyze/email`, `/api/analyze/file`, `/api/analyze/url`
- `POST /api/exposure/check`, `GET /api/exposures`
- `POST /api/correlate`, `GET /api/analyses`
- `POST /api/reports`, `GET /api/reports`
- `POST /api/alerts/:id/acknowledge|assign|escalate|dismiss|resolve`, `GET /api/alerts`
- `POST /api/audit`, `GET /api/audit`

Protected routes require `Authorization: Bearer <session-token>`.
