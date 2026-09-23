# PhishNET — TraceWall

> A phishing investigation and threat-intelligence platform for security analysts.

---

## Overview

PhishNET (codename **TraceWall**) is a full-stack, analyst-facing security operations platform designed to accelerate phishing investigations and infrastructure threat analysis. It combines a React 19 front-end with a dependency-free Node.js back-end to give analysts a single, cohesive workspace for investigating suspicious emails, URLs, files, IP addresses, and domains.

The platform solves a common SOC problem: threat-intelligence data is scattered across a dozen separate provider dashboards. PhishNET aggregates AbuseIPDB, VirusTotal, AlienVault OTX, IPWhois, IPinfo, IPQualityScore, ProxyCheck, and Groq (Llama 3 AI) into one interface, enriches raw evidence with DNS lookups (SPF, DKIM, DMARC), geolocation maps, and risk scoring, and lets analysts convert findings into structured cases, reports, and audit trails.

**Intended for:** Security Operations Centre (SOC) analysts, threat hunters, incident responders, and security researchers who investigate phishing campaigns and malicious infrastructure.

---

## Features

### Email Analysis
- Upload raw email files (`.eml`, `.msg`) or paste raw headers/body directly
- Full MIME parsing with attachment metadata extraction (filename, MIME type, SHA-256 hash)
- Independent SPF evaluation against live DNS (walks `include:` chains up to depth 10)
- DKIM signature detection with selector + DNS key lookup
- DMARC policy retrieval and alignment evaluation (strict and relaxed modes)
- Relay-hop extraction from `Received` headers
- Extraction of embedded URLs, domains, IP addresses, and email addresses
- VirusTotal URL and domain lookups for extracted indicators
- AbuseIPDB reputation checks for extracted relay IPs
- RDAP/WHOIS lookups for extracted IPs
- Composite risk score and HIGH / MEDIUM / LOW verdict
- Evidence ID generation for downstream case creation

### Infrastructure Intelligence (IP & Domain)
- Live IP analysis aggregated from **8 concurrent providers**:
  - AbuseIPDB (abuse confidence score, total reports, Tor flag)
  - VirusTotal (multi-engine threat stats, ASN, WHOIS)
  - AlienVault OTX (threat pulse count with pulse metadata)
  - IPWhois / ipwho.is (geolocation, ASN, VPN/proxy/Tor/hosting flags)
  - IPinfo (geolocation, organisation, privacy layer)
  - IPQualityScore (fraud score, bot detection, abuse velocity)
  - ProxyCheck (proxy type, risk score, days seen)
  - Groq Llama 3 AI (structured natural-language assessment with evidence summary)
- Multi-provider correlated VPN / Proxy / Tor / Hosting detection with per-signal confidence scores
- Domain analysis with DNS record resolution (A, AAAA, MX, NS, TXT, CNAME, PTR, DMARC, SPF)
- Interactive MapTiler map showing geolocation for analysed IPs
- Composite risk score weighted across all provider evidence
- JSON export of full analysis result
- One-click case creation from any analysis

### Case Management
- Create investigation cases with title, severity, description, and assignee
- Per-case notes, analyst tasks (with done/toggle), and timeline events
- Timeline tracks every analyst action with actor name and timestamp

### Alert Management
- Acknowledge, assign, escalate, dismiss (mark false positive), or resolve alerts
- All actions persisted with actor identity and timestamp

### Reports
- Generate structured reports from cases, with configurable sections
- Reports stored in draft state for review before distribution

### Exposure Monitoring
- Check email addresses and other identifiers against breach-monitoring feeds
- Redacted exposure records stored with recommended remediation actions

### AI Feedback & Knowledge Base
- Community-driven security knowledge submission (phishing reports, IOCs, prevention tips)
- 15 categorised submission types (Phishing, Malware, Ransomware, Account Compromise, etc.)
- Automatic PII and credential redaction before storage (private keys, API keys, credit cards, SSNs, bearer tokens, session cookies, phone numbers, email addresses)
- Moderator workflow: PENDING → APPROVED / REJECTED / PRIVATE / FLAGGED
- Approved submissions anonymised and indexed as a searchable knowledge base
- Knowledge retrieval endpoint consumed by AI analyst tools

### Security & Privacy
- Bearer-token session authentication with configurable expiry
- Role-based access control
- Input body size limit (default 5 MB)
- SQL injection prevention via parameterised Node.js SQLite driver
- HTML-escape applied to all knowledge content before exposure to users
- Comprehensive PII redaction pipeline on all feedback submissions

### Frontend
- Dark-mode forensic aesthetic with Tailwind CSS v4
- Framer Motion animations and 3D threat-network visualisations
- Interactive flow graphs via @xyflow/react and reactflow
- Recharts area and bar charts for activity timelines
- Light / dark theme context
- Optional 3D mode with performance guard and error boundary

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Frontend framework** | React 19 + TypeScript |
| **Routing** | React Router v7 |
| **Styling** | Tailwind CSS v4 (via @tailwindcss/vite) |
| **Animation** | Framer Motion |
| **3D visualisation** | React Three Fiber (lazy-loaded with error boundary) |
| **Flow graphs** | @xyflow/react, reactflow |
| **Charts** | Recharts |
| **Mapping** | MapTiler SDK (@maptiler/sdk) |
| **Icons** | lucide-react |
| **Build tool** | Vite 8 |
| **Linter** | oxlint |
| **Backend runtime** | Node.js (ESM, no framework) |
| **Database** | Node.js built-in node:sqlite (SQLite, with JSON recovery file) |
| **HTTP server** | Node.js built-in node:http |
| **DNS resolution** | Node.js built-in node:dns/promises |
| **Authentication** | Custom Bearer-token sessions (node:crypto random bytes) |
| **External threat intel** | AbuseIPDB, VirusTotal, AlienVault OTX, IPWhois, IPinfo, IPQualityScore, ProxyCheck |
| **AI / LLM** | Groq API (Llama 3 / groq/compound-mini) |

---

## Project Structure

```
PhishNET/
└── tracewall/
    ├── .env.example
    ├── index.html
    ├── vite.config.ts
    ├── package.json
    ├── backend/
    │   ├── server.mjs
    │   ├── config/
    │   │   └── env.mjs
    │   ├── controllers/
    │   │   └── apiController.mjs
    │   ├── database/
    │   │   ├── store.mjs
    │   │   ├── tracewall.sqlite
    │   │   └── tracewall.json
    │   ├── middleware/
    │   │   ├── auth.mjs
    │   │   └── http.mjs
    │   ├── routes/
    │   │   └── apiRoutes.mjs
    │   ├── services/
    │   │   ├── analysisService.mjs
    │   │   ├── emailAnalysisService.mjs
    │   │   ├── infrastructureService.mjs
    │   │   ├── authService.mjs
    │   │   ├── caseService.mjs
    │   │   ├── alertService.mjs
    │   │   ├── reportService.mjs
    │   │   ├── feedbackService.mjs
    │   │   └── auditService.mjs
    │   └── utils/
    │       ├── sanitizer.mjs
    │       └── validation.mjs
    └── src/
        ├── main.tsx
        ├── App.tsx
        ├── index.css
        ├── context/
        │   ├── ThemeContext.tsx
        │   └── ThreeDContext.tsx
        ├── components/
        │   ├── 3d/
        │   ├── layout/
        │   ├── maps/
        │   └── ui/
        ├── pages/
        │   ├── LandingPage.tsx
        │   ├── PublicPages.tsx
        │   └── app/
        │       ├── BriefingPage.tsx
        │       ├── InvestigatePage.tsx
        │       ├── InfrastructurePage.tsx
        │       ├── UrlAnalysisPage.tsx
        │       ├── FileAnalysisPage.tsx
        │       ├── ExposurePage.tsx
        │       ├── IntelligencePage.tsx
        │       ├── CasesPage.tsx
        │       ├── EvidencePage.tsx
        │       ├── AlertsPage.tsx
        │       ├── ReportsPage.tsx
        │       ├── AuditPage.tsx
        │       ├── DecisionDeskPage.tsx
        │       ├── FeedbackPage.tsx
        │       └── SettingsPage.tsx
        ├── data/
        │   └── mockData.ts
        └── lib/
            ├── mockBackend.ts
            └── styles.ts
```

---

## Getting Started

### Prerequisites

- **Node.js 22+** — required for the built-in `node:sqlite` module used with the `--experimental-sqlite` flag
- API keys for the threat-intelligence providers you want to use (all optional — the platform degrades gracefully when keys are absent)

### 1. Clone the repository

```bash
git clone https://github.com/gitkrrish/PhishNET.git
cd PhishNET/tracewall
```

### 2. Install dependencies

```bash
npm install
```

### 3. Configure environment variables

```bash
cp .env.example .env.local
```

Edit `.env.local` and fill in your values:

```env
# Server
API_PORT=8787
CORS_ORIGIN=http://localhost:5173
SESSION_HOURS=8
DEMO_PASSWORD=your-secure-password

# Threat intelligence providers (all optional)
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
OTX_API_KEY=
IPWHO_API_KEY=
IPINFO_TOKEN=
IPQUALITYSCORE_API_KEY=
PROXYCHECK_API_KEY=
GROQ_API_KEY=

# Frontend
VITE_API_URL=/api
VITE_MAPTILER_API_KEY=
VITE_MAPTILER_STYLE=streets-v2
```

> The platform runs fully in demo mode without any API keys. Provider statuses will show as `NOT CONFIGURED` and corresponding data sections are skipped gracefully.

### 4. Start the development servers

**Terminal 1 — API server:**

```bash
npm run api
# PhishNet API listening on http://localhost:8787
```

**Terminal 2 — Frontend dev server:**

```bash
npm run dev
# Vite dev server at http://localhost:5173
```

The Vite dev server automatically proxies `/api/*` to the backend.

### 5. Sign in

Navigate to `http://localhost:5173/signin`:

| Field | Value |
|---|---|
| Email | `analyst@tracewall.demo` |
| Password | Your `DEMO_PASSWORD` value |

---

## API Reference

All endpoints except `/api/health` and `/api/auth/sign-in` require `Authorization: Bearer <token>`.

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/auth/sign-in` | Authenticate, receive session token |
| `POST` | `/api/analyze/email` | Full email analysis (SPF/DKIM/DMARC/DNS/VT/AbuseIPDB) |
| `POST` | `/api/analyze/url` | URL reputation analysis |
| `POST` | `/api/analyze/file` | File metadata and risk analysis |
| `POST` | `/api/analyze/ip` | Multi-provider IP intelligence |
| `POST` | `/api/analyze/domain` | Domain DNS and reputation analysis |
| `POST` | `/api/exposure/check` | Breach exposure lookup |
| `POST` | `/api/correlate` | Cross-indicator campaign correlation |
| `GET` | `/api/analyses` | List all stored analysis results |
| `GET/POST` | `/api/cases` | List / create cases |
| `POST` | `/api/cases/:id/note` | Add a case note |
| `POST` | `/api/cases/:id/task` | Add a case task |
| `POST` | `/api/cases/:id/timeline` | Add a timeline event |
| `PATCH` | `/api/cases/:id/tasks/:taskId` | Toggle task done state |
| `GET` | `/api/alerts` | List alerts |
| `POST` | `/api/alerts/:id/acknowledge` | Acknowledge an alert |
| `POST` | `/api/alerts/:id/assign` | Assign an alert |
| `POST` | `/api/alerts/:id/escalate` | Escalate an alert |
| `POST` | `/api/alerts/:id/dismiss` | Dismiss as false positive |
| `POST` | `/api/alerts/:id/resolve` | Resolve an alert |
| `GET/POST` | `/api/reports` | List / create reports |
| `GET/POST` | `/api/audit` | Audit log |
| `GET/POST` | `/api/feedback` | Community knowledge submissions |
| `GET` | `/api/feedback/categories` | Valid feedback categories |
| `GET` | `/api/feedback/search` | Search approved knowledge |
| `GET` | `/api/feedback/knowledge` | AI knowledge retrieval |
| `PATCH` | `/api/feedback/:id/moderate` | Moderate a submission |
| `POST` | `/api/feedback/:id/flag` | Flag a submission |
| `GET` | `/api/exposures` | List exposure records |

---

## Available Scripts

| Command | Description |
|---|---|
| `npm run dev` | Start Vite frontend dev server |
| `npm run api` | Start Node.js API server |
| `npm run build` | TypeScript compile + Vite production build |
| `npm run preview` | Serve the production build locally |
| `npm run lint` | Run oxlint |

---

## Security Considerations

- **No outbound requests from the frontend.** All provider lookups happen server-side only.
- **No suspicious URLs are visited and no attachments are executed** during analysis. Every result includes a disclaimer confirming this.
- **PII is redacted before storage.** All community submissions pass through a redaction pipeline that scrubs private keys, API keys, bearer tokens, session cookies, credit card numbers (Luhn-validated), SSNs, phone numbers, email addresses, and passwords before any data is written to disk.
- **The AI knowledge base only ingests approved, anonymised content.** Pending and rejected submissions are never exposed to the AI or other users.
- **IP geolocation is an infrastructure estimate**, not a physical person location. The UI enforces an analyst acknowledgement before any analysis begins.

---

## License

This project does not yet include a license file. All rights reserved unless explicitly stated otherwise.
