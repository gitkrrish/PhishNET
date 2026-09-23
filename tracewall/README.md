# PhishNet — Evidence Before Assumption

A premium, enterprise-grade forensic intelligence workspace for email threat investigation,
credential exposure monitoring, and AI-driven threat intelligence.

## Platform Summary

PhishNet is designed for authorised security analysts, incident-response teams, government
organisations, universities, banks, and enterprise security units. It provides a calm, evidence-first
investigation environment — not a neon cyberpunk dashboard.

**Visual identity:** Editorial Forensic Workspace — warm ivory surfaces, burgundy investigation
accents, muted brass markers, editorial serif headings, monospace technical evidence fields.

---

## Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm run dev
# → http://localhost:5173

# Production build
npm run build

# Preview production build
npm run preview
```

---

## Application Routes

| Route | Page |
|---|---|
| `/` | Landing Page |
| `/app/briefing` | Daily Briefing |
| `/app/investigate` | Email Investigation Workspace |
| `/app/exposure` | Exposure Ledger |
| `/app/intelligence` | AI Threat Intelligence & Relationship Canvas |
| `/app/campaigns` | Campaign Analysis |
| `/app/cases` | Case Management |
| `/app/evidence` | Evidence & Chain of Custody |
| `/app/reports` | Forensic Investigation Dossier |
| `/app/alerts` | Alert Management |
| `/app/decisions` | Decision Desk (Response Orchestration) |
| `/app/audit` | Audit Log |
| `/app/settings` | Platform Settings |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | React 19 + TypeScript |
| Build | Vite 8 |
| Styling | Tailwind CSS v4 (custom design tokens) |
| Routing | React Router DOM v7 |
| Charts | Recharts |
| Relationship Graph | @xyflow/react (React Flow) |
| Animation | Framer Motion |
| Icons | Lucide React |
| Fonts | DM Serif Display · Manrope · IBM Plex Mono (Google Fonts) |

---

## Design System

### Color Tokens

```
Canvas:
  Ivory Mist:    #F4F1EA
  Warm White:    #FBFAF6
  Graphite Ink:  #181818

Surfaces:
  Slate Paper:   #E7E8E5
  Stone Gray:    #C8CBC6
  Pale Sand:     #EDE8DD

Brand:
  Burgundy:      #731F32
  Deep Wine:     #481521
  Muted Brass:   #B18A4A
  Moss Green:    #586B54
  Dust Blue:     #657581

Threat Levels:
  Critical:      #7E1D2F
  High:          #A13A3A
  Medium:        #A47535
  Low:           #596E5B
  Info:          #657581
```

### Typography

- **Headings:** DM Serif Display (editorial, high-contrast)
- **Body / UI:** Manrope (humanist sans-serif)
- **Technical fields:** IBM Plex Mono (IP addresses, hashes, IDs, headers)

---

## Key Components

| Component | Location | Purpose |
|---|---|---|
| `AppMasthead` | `components/layout/` | Top navigation with section nav |
| `AppLayout` | `components/layout/` | App shell with masthead |
| `EvidenceStamp` | `components/ui/` | Verdict stamp (HIGH RISK, CONTAIN…) |
| `SeverityBadge` | `components/ui/` | Severity level badge |
| `AuthBadge` | `components/ui/` | SPF/DKIM/DMARC result card |
| `ConfidenceBar` | `components/ui/` | Confidence percentage bar |
| `DemoLabel` | `components/ui/` | "Simulated Demo Data" badge |

---

## Mock Data

All data is located in `src/data/mockData.ts`. It is entirely fictional — no real organisation,
individual, or incident is represented.

Demo scenario: A probable invoice-diversion BEC campaign targeting the Finance department of a
fictional organisation called "SecureOps Intelligence Unit."

---

## Privacy & Security Architecture

- No real credentials are stored, displayed, or handled
- Exposure records use masked identifiers (`a••••@example.org`)
- Plaintext secrets are never shown — only `REDACTED` placeholder
- All high-impact response actions require analyst approval and a stated reason
- Approval-based workflow with audit logging for every sensitive action
- Role-based access model: Admin · Analyst · Investigator · Viewer · Auditor
- IP geolocation displayed as "Estimated Infrastructure Location" — never as exact attacker identity
- AI assessments clearly labelled with confidence, evidence sources, and limitations
- All demo data labelled "Simulated Demo Data" throughout the UI

---

## Important Limitations (Displayed In-App)

> IP geolocation represents estimated infrastructure location — not the physical location or identity
> of any person. VPNs, Tor, proxies, cloud servers, and compromised relay nodes reduce accuracy.

> This risk score is an analytical assessment and is not a legal conclusion.

> Sender-controlled headers cannot be independently verified.

> Authentication results (SPF/DKIM/DMARC) indicate configuration issues but do not confirm
> malicious intent. A compromised legitimate account can pass all authentication checks.

---

## No Real API Keys Required

All intelligence is served from the local mock data layer (`src/data/mockData.ts`). 
Integration placeholders show "Integration Unavailable" or "Demo Mode" where real APIs
would connect.

To add real integrations, replace the mock functions in `src/data/mockData.ts` with
API calls to your chosen providers behind a backend proxy. **Never expose API keys
in frontend code.**

---

## Authorised Use Notice

This platform is for authorised security personnel only. It must not be used to:
- Monitor individuals without authorisation
- Purchase, store, or redistribute stolen credentials  
- Make unsupported claims of exact attacker identity
- Conduct surveillance beyond verified organisational assets

---

*PhishNet — Evidence Before Assumption.*
