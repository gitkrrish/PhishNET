// ============================================================
// PhishNet — Central intelligence HTTP controller.
//
// These routes are added alongside the existing ones; nothing
// pre-existing is modified or removed. The read endpoints are views
// over the normalized tables, and the write endpoints all funnel into
// the single ingestion pipeline.
// ============================================================
import { readJson, sendJson } from '../../middleware/http.mjs';
import { httpError } from '../../utils/validation.mjs';
import {
  addNote,
  bumpRevision,
  deleteMonitor,
  getIngestion,
  getMonitor,
  investigationRefs,
  listAlerts,
  listActors,
  listAudit,
  listCorrelations,
  listEvidence,
  listHandles,
  listInfrastructure,
  listInvestigations,
  listNotes,
  listObservations,
  listPgp,
  listRelationships,
  listTimeline,
  listWallets,
  listMonitorEvents,
  listMonitorMatches,
  listMonitorTargets,
  listMonitors,
  listSources,
  monitorsForEntity,
  notesForEntity,
  pendingIngestions,
  relationshipsForEntity,
  setMonitorStatus,
  updateAlertStatus,
  updateMonitor,
  writeAudit,
  getAlert,
  getInvestigation,
  attachEntityToInvestigation,
  linkAlertToInvestigation,
  replaceMonitorTargets,
  addMonitorTarget,
  removeMonitorTarget,
} from './repository.mjs';
import { analyzeMonitor, explainAlert } from './monitoringAnalysis.mjs';
import { resolveCollectionInterval } from './monitoringRegistry.mjs';
import {
  monitoringCapabilities,
  monitoringStats,
  monitoringHub,
  monitorCapability,
  provisionMonitor,
  runMonitorCycle,
  runNow,
  toMonitorDto,
  toMonitorEventDto,
  toMonitorMatchDto,
  toAlertDto,
  targetsFor,
  conditionsFor,
} from './monitoringService.mjs';
import { actorBundle, buildDataset, evidenceChain, search, statistics } from './query.mjs';
import { describeEntity, ingest } from './ingest.mjs';
import { clearAllIntelligence, importSeedDataset } from './seed.mjs';
import { reconcileDataset } from './sync.mjs';
import { whyLinked } from './correlate.mjs';
import { computeThreatRecords, computeThreatPosture, computeEntityScore } from './detectionService.mjs';
import {
  listBlockedIndicators,
  listResponseLogs,
  blockIndicator,
  unblockIndicator,
  createResponseLog,
  addResponseAction,
  updateResponseStatus,
  setProtectionState,
} from './protectionService.mjs';
import {
  aiCapabilities,
  anomalies as detectAnomalies,
  askInvestigation,
  extractEntities,
  investigationSummary,
  stylometry,
} from './aiService.mjs';
import {
  CUSTODY_EVENT_TYPES,
  CUSTODY_EVENT_LABEL,
  auditDerivedHistory,
  custodyChain,
  listAllCustodyEvents,
  listCustodyEvents,
  recordCustodyEvent,
  registerEvidenceCustody,
  verifyEvidenceIntegrity,
} from './custodyService.mjs';
import { naturalLanguageSearch } from './nlQuery.mjs';

const ALERT_STATUSES = ['OPEN', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'DISMISSED'];

/** Handle every /api/intel/* route. Returns true when the path matched. */
export async function handleIntelligenceRequest(request, response, user, path) {
  if (!path.startsWith('/api/intel')) return false;

  const method = request.method;
  const query = method === 'GET'
    ? Object.fromEntries(new URL(request.url, `http://${request.headers.host}`).searchParams)
    : {};
  // PUT is read too: `PUT /api/intel/monitoring/:id` is the only PUT route
  // here, and without it the request body was never consumed, so every monitor
  // edit was accepted with HTTP 200 and silently discarded.
  const body = method === 'POST' || method === 'PUT' || method === 'PATCH' ? await readJson(request) : {};
  const context = {
    analyst: user?.name || user?.email || 'analyst',
    origin: 'API',
  };

  // ── Reads: the shared views every module is built on ────────
  if (method === 'GET' && path === '/api/intel/dataset') {
    return sendJson(response, 200, { data: buildDataset() }), true;
  }

  if (method === 'GET' && path === '/api/intel/statistics') {
    return sendJson(response, 200, { data: statistics() }), true;
  }

  if (method === 'GET' && path === '/api/intel/search') {
    if (!query.q) throw httpError(400, 'q is required');
    return sendJson(response, 200, { data: search(query.q, query) }), true;
  }

  if (method === 'GET' && path === '/api/intel/audit') {
    return sendJson(response, 200, { data: listAudit() }), true;
  }

  // Append to the same audit trail. Read-only before now; this adds a
  // write so client-side actions that generate no server record of
  // their own — a report export, for example — are still auditable.
  // `writeAudit` inserts and returns; nothing in intel_audit is ever
  // updated or deleted.
  if (method === 'POST' && path === '/api/intel/audit') {
    if (!body.action || !body.entity) throw httpError(400, 'action and entity are required');
    const written = writeAudit({
      actor: context.analyst,
      action: String(body.action).toUpperCase().replace(/[^A-Z0-9_]/g, '_'),
      entity: String(body.entity),
      entityId: String(body.entityId ?? ''),
      before: body.before ?? '',
      after: body.after ?? '',
      source: body.source ?? 'API',
      result: body.result ?? 'SUCCESS',
      ip: '',
      batchId: body.batchId ?? null,
    });
    return sendJson(response, 201, { data: written }), true;
  }

  // ── Entity collections ─────────────────────────────────────
  // Every entity the central model holds is readable directly, so a caller
  // never has to know that /intel/dataset is the aggregate view. These are
  // views over the same normalized tables — not a second store.
  const COLLECTION_READS = [
    ['/api/intel/actors', listActors],
    ['/api/intel/handles', listHandles],
    ['/api/intel/pgp-keys', listPgp],
    ['/api/intel/wallets', listWallets],
    ['/api/intel/infrastructure', listInfrastructure],
    ['/api/intel/sources', listSources],
    ['/api/intel/observations', listObservations],
    ['/api/intel/evidence', listEvidence],
    ['/api/intel/timeline', listTimeline],
    ['/api/intel/relationships', listRelationships],
    ['/api/intel/correlations', listCorrelations],
    ['/api/intel/notes', listNotes],
    ['/api/intel/investigations', listInvestigations],
    ['/api/intel/alerts', listAlerts],
    ['/api/intel/audit', listAudit],
  ];
  for (const [collectionPath, read] of COLLECTION_READS) {
    if (method === 'GET' && path === collectionPath) {
      return sendJson(response, 200, { data: read() }), true;
    }
  }

  // ── AI Intelligence / AI Investigation ───────────────────────
  // Answers are produced from the centralized records and always return
  // observed / derived / inference separately. Inference is confined to the
  // `inference` bucket and is omitted entirely when no provider is set up.
  if (method === 'GET' && path === '/api/intel/ai/capabilities') {
    return sendJson(response, 200, { data: aiCapabilities() }), true;
  }

  // ── Natural language search (additive) ──────────────────────────
  //
  // One parser, two scopes. `investigations` filters stored cases;
  // `intelligence` answers a question about any record the caller may
  // read. Both run under the same session the rest of the API uses, so
  // existing authentication and per-investigation access controls
  // continue to apply unchanged.
  //
  // The response always carries `operations` (what was actually
  // applied) and `unsupported` (what was recognised but could not be
  // honoured, and why). The client renders both, so a result set is
  // never presented as more specific than the question asked.
  const nlScope = path.match(/^\/api\/intel\/(investigations|ai)\/nl-search\/?$/);
  if (nlScope && method === 'POST') {
    const question = String(body.query || body.question || '').trim();
    if (!question) throw httpError(400, 'query is required');
    const scope = nlScope[1] === 'ai' ? 'intelligence' : 'investigations';
    const result = naturalLanguageSearch(question, { scope, limit: body.limit });
    writeAudit({
      actor: context.analyst,
      action: 'NATURAL_LANGUAGE_SEARCH',
      entity: scope === 'intelligence' ? 'AI' : 'INVESTIGATION',
      entityId: `${scope}/nl-search`,
      after: `${question.slice(0, 180)} → ${scope === 'intelligence' ? `${result.total} statement(s)` : `${result.total} investigation(s)`}`,
      source: 'API',
    });
    return sendJson(response, 200, { data: result }), true;
  }

  if (method === 'POST' && path === '/api/intel/ai/ask') {
    if (!body.question) throw httpError(400, 'question is required');
    const answer = await askInvestigation({
      question: body.question,
      contextEntityId: body.contextEntityId || null,
      enrich: body.enrich !== false,
    });
    writeAudit({
      actor: context.analyst,
      action: 'AI_INVESTIGATION_QUESTION',
      entity: 'AI',
      entityId: 'ai/ask',
      after: String(body.question).slice(0, 200),
      source: 'API',
    });
    return sendJson(response, 200, { data: answer }), true;
  }

  const aiSummary = path.match(/^\/api\/intel\/ai\/investigation\/([^/]+)\/summary\/?$/);
  if (method === 'POST' && aiSummary) {
    const summary = await investigationSummary({
      investigationId: decodeURIComponent(aiSummary[1]),
      enrich: body.enrich !== false,
    });
    writeAudit({ actor: context.analyst, action: 'AI_INVESTIGATION_SUMMARY', entity: 'INVESTIGATION', entityId: summary.investigationId, source: 'API' });
    return sendJson(response, 200, { data: summary }), true;
  }

  if (method === 'POST' && path === '/api/intel/ai/extract') {
    if (!body.text) throw httpError(400, 'text is required');
    const extraction = extractEntities({ text: body.text });
    writeAudit({ actor: context.analyst, action: 'AI_ENTITY_EXTRACTION', entity: 'AI', entityId: 'ai/extract', after: `${extraction.resolved} resolved / ${extraction.unresolved} unresolved`, source: 'API' });
    return sendJson(response, 200, { data: extraction }), true;
  }

  if (method === 'GET' && path === '/api/intel/ai/anomalies') {
    const found = detectAnomalies();
    return sendJson(response, 200, {
      data: {
        anomalies: found,
        count: found.length,
        method: 'Each anomaly is a computed inconsistency between stored fields. None is an assertion about intent.',
      },
    }), true;
  }

  const aiStylometry = path.match(/^\/api\/intel\/ai\/stylometry\/([^/]+)\/([^/]+)\/?$/);
  if (method === 'GET' && aiStylometry) {
    return sendJson(response, 200, {
      data: stylometry(decodeURIComponent(aiStylometry[1]), decodeURIComponent(aiStylometry[2])),
    }), true;
  }

  // ── Entity views ───────────────────────────────────────────
  const actorMatch = path.match(/^\/api\/intel\/actors\/([^/]+)$/);
  if (method === 'GET' && actorMatch) {
    const bundle = actorBundle(decodeURIComponent(actorMatch[1]));
    if (!bundle) throw httpError(404, 'Actor not found');
    return sendJson(response, 200, { data: bundle }), true;
  }

  const whyMatch = path.match(/^\/api\/intel\/entities\/([^/]+)\/why-linked$/);
  if (method === 'GET' && whyMatch) {
    return sendJson(response, 200, { data: whyLinked(decodeURIComponent(whyMatch[1])) }), true;
  }

  const describeMatch = path.match(/^\/api\/intel\/entities\/([^/]+)$/);
  if (method === 'GET' && describeMatch) {
    const described = describeEntity(decodeURIComponent(describeMatch[1]));
    if (!described) throw httpError(404, 'Entity not found');
    return sendJson(response, 200, { data: described }), true;
  }

  const evidenceMatch = path.match(/^\/api\/intel\/evidence\/([^/]+)\/chain$/);
  if (method === 'GET' && evidenceMatch) {
    return sendJson(response, 200, { data: evidenceChain(decodeURIComponent(evidenceMatch[1])) }), true;
  }

  // ── Chain of custody (additive) ────────────────────────────────
  //
  // The append-only custody log for one evidence item, plus the
  // append-only write and the integrity verification. Reads never
  // create a record, so opening an item cannot alter its history.
  //
  // A tracked event (origin TRACKED) is one this platform recorded
  // itself; an audit-derived event (origin AUDIT_DERIVED) is a real row
  // from the pre-existing audit trail. Nothing is synthesised for an
  // item that predates tracking: historyStatus reports NO_HISTORY and
  // the client states that plainly.
  const custodyForEvidence = path.match(/^\/api\/intel\/evidence\/([^/]+)\/custody\/?$/);
  if (method === 'GET' && custodyForEvidence) {
    const chain = custodyChain(decodeURIComponent(custodyForEvidence[1]));
    if (!chain) throw httpError(404, 'Evidence not found');
    return sendJson(response, 200, { data: chain }), true;
  }
  if (method === 'POST' && custodyForEvidence) {
    const evidenceId = decodeURIComponent(custodyForEvidence[1]);
    if (!listEvidence().some(item => item.id === evidenceId)) throw httpError(404, 'Evidence not found');
    const eventType = String(body.eventType || '').toUpperCase();
    if (!CUSTODY_EVENT_TYPES.includes(eventType)) {
      throw httpError(400, `eventType must be one of ${CUSTODY_EVENT_TYPES.join(', ')}`);
    }
    const event = recordCustodyEvent({
      evidenceId,
      eventType,
      actor: context.analyst,
      action: body.action,
      previousState: body.previousState,
      newState: body.newState,
      reason: body.reason,
      integrityHash: body.integrityHash,
      investigationId: body.investigationId || null,
      source: 'API',
    });
    writeAudit({
      actor: context.analyst,
      action: `CUSTODY_${eventType}`,
      entity: 'EVIDENCE',
      entityId: evidenceId,
      after: body.reason || CUSTODY_EVENT_LABEL[eventType] || eventType,
      source: 'API',
    });
    return sendJson(response, 201, { data: { event, chain: custodyChain(evidenceId) } }), true;
  }

  // The custody event types this endpoint accepts, so the UI never has
  // to hard-code a list it cannot validate against.
  if (method === 'GET' && path === '/api/intel/custody/event-types') {
    return sendJson(response, 200, {
      data: CUSTODY_EVENT_TYPES.map(type => ({ type, label: CUSTODY_EVENT_LABEL[type] })),
    }), true;
  }

  // The store-wide ledger, newest first.
  if (method === 'GET' && path === '/api/intel/custody/events') {
    const limit = Math.min(Number(query.limit) || 200, 1000);
    return sendJson(response, 200, { data: listAllCustodyEvents(limit) }), true;
  }

  // Integrity verification. Content must be supplied: without bytes
  // there is nothing to hash, and the result is NOT VERIFIABLE rather
  // than an assumed pass. The stored digest is never rewritten.
  const verifyEvidence = path.match(/^\/api\/intel\/evidence\/([^/]+)\/verify$/);
  if (method === 'POST' && verifyEvidence) {
    const evidenceId = decodeURIComponent(verifyEvidence[1]);
    if (!listEvidence().some(item => item.id === evidenceId)) throw httpError(404, 'Evidence not found');
    const result = verifyEvidenceIntegrity(evidenceId, {
      content: body.content,
      contentEncoding: body.contentEncoding === 'base64' ? 'base64' : 'utf8',
      actor: context.analyst,
      reason: body.reason,
    });
    writeAudit({
      actor: context.analyst,
      action: result.result === 'MISMATCH' ? 'EVIDENCE_INTEGRITY_FAILED' : 'EVIDENCE_INTEGRITY_CHECKED',
      entity: 'EVIDENCE',
      entityId: evidenceId,
      before: 'previous verification result',
      after: `${result.result}${result.calculatedHash ? ` (${result.calculatedHash.slice(0, 16)}…)` : ''}`,
      source: 'API',
      result: result.result === 'MISMATCH' ? 'REJECTED' : 'SUCCESS',
    });
    return sendJson(response, 200, { data: { verification: result, chain: custodyChain(evidenceId) } }), true;
  }

  const entityRelations = path.match(/^\/api\/intel\/entities\/([^/]+)\/relationships$/);
  if (method === 'GET' && entityRelations) {
    return sendJson(response, 200, { data: relationshipsForEntity(decodeURIComponent(entityRelations[1])) }), true;
  }

  const entityNotes = path.match(/^\/api\/intel\/entities\/([^/]+)\/notes$/);
  if (method === 'GET' && entityNotes) {
    return sendJson(response, 200, { data: notesForEntity(decodeURIComponent(entityNotes[1])) }), true;
  }

  const investigationRefsMatch = path.match(/^\/api\/intel\/investigations\/([^/]+)\/refs$/);
  if (method === 'GET' && investigationRefsMatch) {
    return sendJson(response, 200, { data: investigationRefs(decodeURIComponent(investigationRefsMatch[1])) }), true;
  }

  const ingestionMatch = path.match(/^\/api\/intel\/ingestions\/([^/]+)$/);
  if (method === 'GET' && ingestionMatch) {
    const record = getIngestion(decodeURIComponent(ingestionMatch[1]));
    if (!record) throw httpError(404, 'Ingestion not found');
    return sendJson(response, 200, { data: record }), true;
  }

  if (method === 'GET' && path === '/api/intel/ingestions') {
    return sendJson(response, 200, { data: pendingIngestions() }), true;
  }

  // ── Writes: one pipeline for every module ──────────────────
  if (method === 'POST' && path === '/api/intel/ingest') {
    const result = ingest(body, context);
    return sendJson(response, 201, { data: result }), true;
  }

  const noteMatch = path.match(/^\/api\/intel\/entities\/([^/]+)\/notes$/);
  if (method === 'POST' && noteMatch) {
    const text = String(body.text || '').trim();
    if (!text) throw httpError(400, 'text is required');
    const note = addNote({
      entityType: String(body.entityType || 'UNKNOWN'),
      entityId: decodeURIComponent(noteMatch[1]),
      author: context.analyst,
      text,
    });
    writeAudit({
      actor: context.analyst,
      action: 'NOTE_ADDED',
      entity: 'NOTE',
      entityId: note.id,
      after: text.slice(0, 200),
    });
    return sendJson(response, 201, { data: note }), true;
  }

  const alertMatch = path.match(/^\/api\/intel\/alerts\/([^/]+)$/);
  if (method === 'PATCH' && alertMatch) {
    const status = String(body.status || '').toUpperCase();
    if (!ALERT_STATUSES.includes(status)) throw httpError(400, `status must be one of ${ALERT_STATUSES.join(', ')}`);
    // Only an actual acknowledgement stamps who/when; escalating or
    // re-opening an alert must not overwrite the original acknowledgement.
    const acknowledging = status === 'ACKNOWLEDGED';
    const updated = updateAlertStatus(decodeURIComponent(alertMatch[1]), status, {
      ...(acknowledging
        ? { acknowledgedBy: body.acknowledgedBy || context.analyst, acknowledgedAt: new Date().toISOString() }
        : {}),
      resolution: body.resolution,
    });
    if (!updated) throw httpError(404, 'Alert not found');
    writeAudit({
      actor: context.analyst,
      action: 'ALERT_UPDATED',
      entity: 'ALERT',
      entityId: updated.id,
      after: status,
    });
    return sendJson(response, 200, { data: toAlertDto(updated) }), true;
  }

  // ── Dataset controls (the existing Load Demo / Reset / Clear) ──
  if (method === 'POST' && path === '/api/intel/demo/load') {
    const result = await importSeedDataset({ reset: Boolean(body.reset) });
    return sendJson(response, 200, { data: result }), true;
  }

  if (method === 'POST' && path === '/api/intel/reconcile') {
    const result = reconcileDataset(body.dataset || {});
    return sendJson(response, 200, { data: result }), true;
  }

  if (method === 'POST' && path === '/api/intel/dataset/clear') {
    return sendJson(response, 200, { data: clearAllIntelligence() }), true;
  }

  // ── 24×7 Dark Web Monitoring (additive) ────────────────────────
  //
  // Every monitor configuration lives in the centralized backend; the
  // frontend never holds monitoring state. These routes are the only
  // way a monitor is created, changed, paused or run.
  if (method === 'GET' && path === '/api/intel/monitoring/capabilities') {
    return sendJson(response, 200, { data: monitoringCapabilities() }), true;
  }
  if (method === 'GET' && path === '/api/intel/monitoring') {
    const rows = listMonitors();
    return sendJson(response, 200, {
      data: rows.map(row => ({ ...toMonitorDto(row), capability: monitorCapability(row) })),
    }), true;
  }
  if (method === 'GET' && path === '/api/intel/monitoring/stats') {
    return sendJson(response, 200, { data: monitoringStats() }), true;
  }
  // The centralized 24x7 hub roll-up. Registered ahead of the `/:id` pattern
  // below so "hub" is never mistaken for a monitor id. It only reads the
  // rows the rest of the monitoring stack already owns.
  const monitoringHubPath = path.match(/^\/api\/intel\/monitoring\/hub\/?$/);
  if (method === 'GET' && monitoringHubPath) {
    return sendJson(response, 200, { data: monitoringHub({ alertLimit: query.limit }) }), true;
  }
  if (method === 'POST' && path === '/api/intel/monitoring') {
    const created = provisionMonitor(body, context.analyst);
    const row = getMonitor(created.id);
    return sendJson(response, 201, { data: { ...toMonitorDto(row), capability: monitorCapability(row) } }), true;
  }

  const monitorRunAll = path.match(/^\/api\/intel\/monitoring\/run\/?$/);
  if (method === 'POST' && monitorRunAll) {
    const result = runMonitorCycle();
    return sendJson(response, 200, { data: result }), true;
  }
  const monitorRunOne = path.match(/^\/api\/intel\/monitoring\/run\/([^/]+)$/);
  if (method === 'POST' && monitorRunOne) {
    const result = runNow(decodeURIComponent(monitorRunOne[1]));
    if (result?.error) throw httpError(400, result.error);
    return sendJson(response, 200, { data: result }), true;
  }

  // A single monitor with everything the UI renders: configuration, real
  // collection interval, source health, recent cycles, matches and alerts.
  const monitorById = path.match(/^\/api\/intel\/monitoring\/([^/]+)$/);
  if (method === 'GET' && monitorById) {
    const id = decodeURIComponent(monitorById[1]);
    const row = getMonitor(id);
    if (!row) throw httpError(404, 'Monitor not found');
    const dto = toMonitorDto(row);
    return sendJson(response, 200, {
      data: {
        ...dto,
        capability: monitorCapability(row),
        targets: targetsFor(row).map(t => ({ ...t, label: t.label || t.targetValue })),
        conditions: conditionsFor(row),
        recentEvents: listMonitorEvents(id, 25).map(toMonitorEventDto),
        recentMatches: listMonitorMatches(id, 25).map(toMonitorMatchDto),
        alerts: listAlerts().filter(alert => alert.monitor_id === id).map(toAlertDto),
      },
    }), true;
  }
  if (method === 'PUT' && monitorById) {
    const id = decodeURIComponent(monitorById[1]);
    const existing = getMonitor(id);
    if (!existing) throw httpError(404, 'Monitor not found');
    const patch = {};
    for (const key of ['name', 'severity', 'frequency', 'status', 'rule', 'sources', 'alertConditions', 'notificationPref', 'notifyChannel', 'notes']) {
      if (body[key] !== undefined) patch[key] = body[key];
    }
    if (Array.isArray(body.conditions)) patch.conditions = body.conditions;
    if (body.targets !== undefined) {
      patch.conditions = Array.isArray(body.conditions) ? body.conditions : conditionsFor(existing);
      patch.sources = Array.isArray(body.sources) ? body.sources : parseList(existing.sources);
      const interval = provisionMonitorInterval(patch, body.frequency || existing.frequency);
      patch.collectionIntervalSeconds = interval.seconds;
      patch.effectiveFrequency = interval.continuous ? (body.frequency || existing.frequency) : 'INTERVAL_CAPPED';
    }
    updateMonitor(id, patch);
    if (Array.isArray(body.targets)) replaceTargets(id, body.targets);
    bumpRevision();
    writeAudit({
      actor: context.analyst,
      action: 'MONITOR_UPDATED',
      entity: 'MONITOR',
      entityId: id,
      after: Object.keys(patch).join(','),
      source: 'API',
    });
    const row = getMonitor(id);
    return sendJson(response, 200, { data: { ...toMonitorDto(row), capability: monitorCapability(row) } }), true;
  }
  if (method === 'DELETE' && monitorById) {
    const id = decodeURIComponent(monitorById[1]);
    // Deleting something that is not there is a client error, not a
    // silent success: the caller needs to know the id was wrong.
    if (!getMonitor(id)) throw httpError(404, 'Monitor not found');
    deleteMonitor(id);
    bumpRevision();
    writeAudit({ actor: context.analyst, action: 'MONITOR_DELETED', entity: 'MONITOR', entityId: id, source: 'API' });
    return sendJson(response, 204, {}), true;
  }

  const monitorEvents = path.match(/^\/api\/intel\/monitoring\/([^/]+)\/events\/?$/);
  if (method === 'GET' && monitorEvents) {
    const id = decodeURIComponent(monitorEvents[1]);
    if (!getMonitor(id)) throw httpError(404, 'Monitor not found');
    return sendJson(response, 200, { data: listMonitorEvents(id).map(toMonitorEventDto) }), true;
  }
  const monitorMatches = path.match(/^\/api\/intel\/monitoring\/([^/]+)\/matches\/?$/);
  if (method === 'GET' && monitorMatches) {
    const id = decodeURIComponent(monitorMatches[1]);
    if (!getMonitor(id)) throw httpError(404, 'Monitor not found');
    return sendJson(response, 200, { data: listMonitorMatches(id).map(toMonitorMatchDto) }), true;
  }
  const monitorAlerts = path.match(/^\/api\/intel\/monitoring\/([^/]+)\/alerts\/?$/);
  if (method === 'GET' && monitorAlerts) {
    const id = decodeURIComponent(monitorAlerts[1]);
    if (!getMonitor(id)) throw httpError(404, 'Monitor not found');
    return sendJson(response, 200, { data: listAlerts().filter(a => a.monitor_id === id).map(toAlertDto) }), true;
  }
  const monitorAnalyze = path.match(/^\/api\/intel\/monitoring\/([^/]+)\/analyze\/?$/);
  if (method === 'POST' && monitorAnalyze) {
    const row = getMonitor(decodeURIComponent(monitorAnalyze[1]));
    if (!row) throw httpError(404, 'Monitor not found');
    const analysis = await analyzeMonitor(row, { enrich: body.enrich !== false });
    return sendJson(response, 200, { data: analysis }), true;
  }
  const monitorAction = path.match(/^\/api\/intel\/monitoring\/([^/]+)\/(pause|resume|disable|enable)$/);
  if (method === 'POST' && monitorAction) {
    const id = decodeURIComponent(monitorAction[1]);
    const statusMap = { pause: 'PAUSED', resume: 'ACTIVE', disable: 'DISABLED', enable: 'ACTIVE' };
    const next = statusMap[monitorAction[2]];
    if (!getMonitor(id)) throw httpError(404, 'Monitor not found');
    setMonitorStatus(id, next);
    bumpRevision();
    writeAudit({ actor: context.analyst, action: 'MONITOR_UPDATED', entity: 'MONITOR', entityId: id, after: `status=${next}`, source: 'API' });
    const row = getMonitor(id);
    return sendJson(response, 200, { data: { ...toMonitorDto(row), capability: monitorCapability(row) } }), true;
  }

  const monitorTargetByEntity = path.match(/^\/api\/intel\/monitoring\/entity\/([^/]+)\/([^/]+)$/);
  if (method === 'GET' && monitorTargetByEntity) {
    const entityType = decodeURIComponent(monitorTargetByEntity[1]);
    const entityId = decodeURIComponent(monitorTargetByEntity[2]);
    const rows = monitorsForEntity(entityType, entityId);
    return sendJson(response, 200, {
      data: rows.map(row => ({ ...toMonitorDto(row), capability: monitorCapability(row) })),
    }), true;
  }

  const monitorTargetAdd = path.match(/^\/api\/intel\/monitoring\/([^/]+)\/targets$/);
  if (method === 'POST' && monitorTargetAdd) {
    const monitorId = decodeURIComponent(monitorTargetAdd[1]);
    if (!getMonitor(monitorId)) throw httpError(404, 'Monitor not found');
    const entityType = String(body.entityType || '');
    const entityId = String(body.entityId || '');
    if (!entityType || !entityId) throw httpError(400, 'entityType and entityId are required');
    const targetId = addMonitorTarget(monitorId, { entityType, entityId, entityValue: body.entityValue, conditions: body.conditions || [] });
    bumpRevision();
    return sendJson(response, 201, { data: { id: targetId, monitorId, entityType, entityId } }), true;
  }
  const monitorTargetRemove = path.match(/^\/api\/intel\/monitoring\/([^/]+)\/targets\/([^/]+)$/);
  if (method === 'DELETE' && monitorTargetRemove) {
    const monitorId = decodeURIComponent(monitorTargetRemove[1]);
    if (!getMonitor(monitorId)) throw httpError(404, 'Monitor not found');
    removeMonitorTarget(monitorId, decodeURIComponent(monitorTargetRemove[2]));
    bumpRevision();
    return sendJson(response, 204, {}), true;
  }
  const monitorTargetList = path.match(/^\/api\/intel\/monitoring\/([^/]+)\/targets$/);
  if (method === 'GET' && monitorTargetList) {
    const id = decodeURIComponent(monitorTargetList[1]);
    if (!getMonitor(id)) throw httpError(404, 'Monitor not found');
    return sendJson(response, 200, { data: listMonitorTargets(id) }), true;
  }

  // ── Active Threat Protection (additive) ────────────────────────
  //
  // Threat *scores* are derived by the detection engine from the
  // normalized tables; protection *state* (blocks, response tickets)
  // is persisted in intel_protection_state. Nothing pre-existing changes.
  if (method === 'GET' && path === '/api/intel/protection/posture') {
    return sendJson(response, 200, { data: computeThreatPosture() }), true;
  }
  if (method === 'GET' && path === '/api/intel/protection/records') {
    const entityType = query?.entityType;
    const all = computeThreatRecords();
    const data = entityType ? all.filter(r => r.entityType === entityType) : all;
    return sendJson(response, 200, { data }), true;
  }

  const protectionRecordMatch = path.match(/^\/api\/intel\/protection\/records\/([^/]+)\/([^/]+)\/?$/);
  if (method === 'GET' && protectionRecordMatch) {
    const score = computeEntityScore(decodeURIComponent(protectionRecordMatch[1]), decodeURIComponent(protectionRecordMatch[2]));
    if (!score) throw httpError(404, 'Entity not found or no score available');
    return sendJson(response, 200, { data: score }), true;
  }

  if (method === 'GET' && path === '/api/intel/protection/blocked') {
    return sendJson(response, 200, { data: listBlockedIndicators() }), true;
  }
  if (method === 'POST' && path === '/api/intel/protection/block') {
    if (!body.entityType || !body.entityId || !body.value || !body.reason) throw httpError(400, 'entityType, entityId, value and reason are required');
    const created = blockIndicator({
      entityType: body.entityType,
      entityId: body.entityId,
      value: body.value,
      reason: body.reason,
      performedBy: context.analyst,
      expiresAt: body.expiresAt ?? null,
    });
    writeAudit({ actor: context.analyst, action: 'THREAT_BLOCK_CREATED', entity: body.entityType, entityId: body.entityId, after: body.reason, source: 'API' });
    return sendJson(response, 201, { data: created }), true;
  }

  const blockedDelete = path.match(/^\/api\/intel\/protection\/blocked\/([^/]+)$/);
  if (method === 'DELETE' && blockedDelete) {
    const removed = unblockIndicator(decodeURIComponent(blockedDelete[1]));
    if (!removed) throw httpError(404, 'Blocked indicator not found');
    writeAudit({ actor: context.analyst, action: 'THREAT_BLOCK_REMOVED', entity: 'BLOCK', entityId: removed.id, source: 'API' });
    return sendJson(response, 204, {}), true;
  }

  if (method === 'GET' && path === '/api/intel/protection/responses') {
    return sendJson(response, 200, { data: listResponseLogs() }), true;
  }
  if (method === 'POST' && path === '/api/intel/protection/responses') {
    if (!body.threatRecordId || !body.title || !body.severity) throw httpError(400, 'threatRecordId, title and severity are required');
    const created = createResponseLog({ threatRecordId: body.threatRecordId, title: body.title, severity: body.severity, performedBy: context.analyst });
    writeAudit({ actor: context.analyst, action: 'THREAT_RESPONSE_CREATED', entity: 'RESPONSE', entityId: created.id, after: body.title, source: 'API' });
    return sendJson(response, 201, { data: created }), true;
  }

  const responsePatch = path.match(/^\/api\/intel\/protection\/responses\/([^/]+)$/);
  if (method === 'PATCH' && responsePatch) {
    const log = updateResponseStatus(decodeURIComponent(responsePatch[1]), body.status, body.notes);
    if (!log) throw httpError(404, 'Response log not found');
    return sendJson(response, 200, { data: log }), true;
  }

  if (method === 'POST' && path === '/api/intel/protection/actions') {
    if (!body.logId || !body.kind || !body.reason) throw httpError(400, 'logId, kind and reason are required');
    const log = addResponseAction(body.logId, { kind: body.kind, reason: body.reason, performedBy: context.analyst });
    if (!log) throw httpError(404, 'Response log not found');
    return sendJson(response, 200, { data: log }), true;
  }

  if (method === 'POST' && path === '/api/intel/protection/reconcile') {
    const result = setProtectionState({
      blockedIndicators: Array.isArray(body.blockedIndicators) ? body.blockedIndicators : [],
      responseLogs: Array.isArray(body.responseLogs) ? body.responseLogs : [],
    });
    return sendJson(response, 200, { data: { reconciled: true } }), true;
  }

  // ── Monitoring alerts: investigate, attach, explain ─────────────
  const alertById = path.match(/^\/api\/intel\/alerts\/([^/]+)$/);
  if (method === 'GET' && alertById) {
    const row = getAlert(decodeURIComponent(alertById[1]));
    if (!row) throw httpError(404, 'Alert not found');
    return sendJson(response, 200, { data: { ...toAlertDto(row), explanation: explainAlert(row) } }), true;
  }
  const alertInvestigation = path.match(/^\/api\/intel\/alerts\/([^/]+)\/investigation$/);
  if (method === 'POST' && alertInvestigation) {
    const alertId = decodeURIComponent(alertInvestigation[1]);
    const alert = getAlert(alertId);
    if (!alert) throw httpError(404, 'Alert not found');
    const investigationId = String(body.investigationId || '').trim();
    if (!investigationId) throw httpError(400, 'investigationId is required');
    const investigation = getInvestigation(investigationId);
    if (!investigation) throw httpError(404, 'Investigation not found');
    const attached = [];
    for (const ref of body.entityRefs || []) {
      attachEntityToInvestigation(investigationId, ref.id ?? ref, ref.entityType || alert.entity_type || 'UNKNOWN', 'ALERT_EVIDENCE');
      attached.push(ref.id ?? ref);
    }
    if (alert.entity_id) {
      attachEntityToInvestigation(investigationId, alert.entity_id, alert.entity_type || 'UNKNOWN', 'ALERT_SUBJECT');
      attached.push(alert.entity_id);
    }
    for (const evidenceId of JSON.parse(alert.evidence_ids || '[]')) {
      attachEntityToInvestigation(investigationId, evidenceId, 'EVIDENCE', 'ALERT_EVIDENCE');
      attached.push(evidenceId);
    }
    linkAlertToInvestigation(alertId, investigationId);
    updateAlertStatus(alertId, 'INVESTIGATING', { acknowledgedBy: context.analyst, acknowledgedAt: new Date().toISOString() });
    bumpRevision();
    writeAudit({
      actor: context.analyst,
      action: 'ALERT_INVESTIGATION_ATTACHED',
      entity: 'ALERT',
      entityId: alertId,
      after: `investigation=${investigationId} entities=${attached.join(',')}`,
      source: 'API',
    });
    return sendJson(response, 200, {
      data: { alert: toAlertDto(getAlert(alertId)), investigationId, attachedEntities: [...new Set(attached)] },
    }), true;
  }

  throw httpError(404, 'Route not found');
}

/** Sources may arrive as ids or names; both resolve against intel_source. */
function parseList(value) {
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

/** Recompute a monitor's real collection interval from its bound sources. */
function provisionMonitorInterval(patch, frequency) {
  const sources = (patch.sources || [])
    .map(ref => listSources().find(source => source.id === ref || source.name === ref))
    .filter(Boolean);
  return resolveCollectionInterval(sources, frequency);
}

function replaceTargets(monitorId, targets) {
  replaceMonitorTargets(
    monitorId,
    targets
      .filter(target => target?.entityId && target?.entityType)
      .map(target => ({
        entityType: target.entityType,
        entityId: target.entityId,
        entityValue: target.entityValue ?? null,
        conditions: Array.isArray(target.conditions) ? target.conditions : [],
      })),
  );
}
