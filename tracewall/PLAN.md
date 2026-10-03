# PhishNet Feature-Integration Plan

## Inventory

| Requested capability | Existing route/component | Status | Action |
|---|---|---|---|
| Email threat detection, header forensics, authentication, relay path, domain intelligence | `/app/investigate` — `InvestigatePage` | Partially built | Extend intake validation and add forensic, IP/geolocation, URL, attachment, BEC, and evidence tabs |
| AI threat intelligence | `/app/intelligence` — `IntelligencePage` | Partially built | Extend assessment metadata, relationship labels, and campaign evidence |
| Dark-web monitoring and credential response | `/app/exposure` — `ExposurePage` | Partially built | Extend masked exposure fields, response workflow, retention/privacy notices, and Asteron demo record |
| Campaign correlation | `/app/campaigns` — `CampaignsPage` | Partially built | Add URLs, exposure links, timeline, and Asteron campaign view |
| Investigation cases | `/app/cases` and `/app/cases/:id` — `CasesPage` | Partially built | Use the existing case list/detail pattern for all demo cases and expose evidence fields |
| Evidence and chain of custody | `/app/evidence` — `EvidencePage` | Partially built | Extend evidence metadata, preview, access history, classification, and hash verification |
| Forensic reports | `/app/reports` — `ReportsPage` | Partially built | Repair duplicate declarations, then extend structured sections, JSON export, and print preview |
| Alert center | `/app/alerts` — `AlertsPage` | Partially built | Add requested categories/statuses, assignment/evidence fields, and empty state |
| Approval-based response actions | `/app/decisions` — `DecisionDeskPage` | Partially built | Repair syntax, retain RBAC/confirmation/audit behavior, and add evidence/approval history context |
| Audit logs | `/app/audit` — `AuditPage` | Built | Leave unchanged |
| Guided demo | `/app/briefing` — `BriefingPage` | Built | Leave unchanged; existing entry button and overlay are functional |

## Integration Rules

- Preserve the existing warm ivory, burgundy, brass, moss, and dust token system in `src/index.css`.
- Reuse the existing panels, tabs, badges, tables, timeline, graph, buttons, and Framer Motion transitions.
- Keep all existing routes and navigation items. Add no duplicate route or visual system.
- Use only fictional `.example` domains and documentation-range IPs for new demo content.
- Label every new demo surface with `DemoLabel` / “Simulated Demo Data”.
- Never display or store plaintext secrets; mask exposure identifiers by default.
- Keep high-impact response actions behind permission checks, confirmation, reason capture, and audit logging.

## Implementation Sequence

1. Repair the existing compile blocker in `DecisionDeskPage.tsx` without changing its behavior.
2. Extend `InvestigatePage.tsx` with the missing forensic tabs and functional intake states.
3. Extend the existing intelligence, exposure, campaign, case, evidence, report, alert, and decision pages only where their current workflows are incomplete.
4. Add missing fictional Asteron demo records to `mockData.ts` and connect them to the existing pages.
5. Run `npm run build`, `npm run lint`, and a production preview smoke check.
