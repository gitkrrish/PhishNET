import { databaseStatus, getStore } from '../database/store.mjs';
import { readEmailInput, readJson, sendJson } from '../middleware/http.mjs';
import { signIn } from '../services/authService.mjs';
import { analyzeEmail, analyzeFile, analyzeUrl, checkExposure, correlate, listAnalyses } from '../services/analysisService.mjs';
import { analyzeEmail as analyzeRealEmail } from '../services/emailAnalysisService.mjs';
import { analyzeIp, analyzeDomain } from '../services/infrastructureService.mjs';
import { addNote, addTask, addTimeline, createCase, getCase, listCases, toggleTask } from '../services/caseService.mjs';
import { createReport, getReport, listReports } from '../services/reportService.mjs';
import { updateAlert } from '../services/alertService.mjs';
import { createAudit, listAudit } from '../services/auditService.mjs';
import { createFeedback, listFeedback, getFeedback, moderateFeedback, searchFeedback, getKnowledge, flagFeedback, FEEDBACK_CATEGORIES } from '../services/feedbackService.mjs';
import * as darkweb from '../services/darkwebService.mjs';
import { handleIntelligenceRequest } from '../services/intel/controller.mjs';
import { listAlerts as listIntelAlerts } from '../services/intel/repository.mjs';
import { toAlertDto } from '../services/intel/monitoringService.mjs';
import { id, httpError } from '../utils/validation.mjs';
import { getIpIntelligence, updateIpIntelligence, deleteIpIntelligence, queryIpIntelligence, getIpRelatedIntelligence, linkActorToIp, linkHandleToIp, linkPgpToIp, linkWalletToIp, linkInfrastructureToIp, linkEvidenceToIp, linkInvestigationToIp, isIpIntelligenceEnabled } from '../services/ipIntelligenceService.mjs';

/**
 * Every alert the console can act on, newest first.
 *
 * Two stores still hold alerts during the migration off the legacy
 * `app_state` document: the normalized `intel_alert` table, which ingestion,
 * correlation and the 24x7 monitoring pipeline write to, and the seeded
 * app-level alert rows. The console is a single list, so both are returned
 * here; ids are disjoint, so no row appears twice.
 */
function listAllAlerts() {
  const legacy = getStore().alerts ?? [];
  const seen = new Set(legacy.map(row => row.id));
  const normalized = listIntelAlerts()
    .filter(row => !seen.has(row.id))
    .map(toAlertDto);
  return [...legacy, ...normalized].sort(
    (a, b) => new Date(b.raisedAt || b.createdAt || 0) - new Date(a.raisedAt || a.createdAt || 0),
  );
}

export async function handleRequest(request, response, user, path) {
  // Central Dark Web Intelligence: the normalized data layer every module
  // shares. Checked first so the intelligence routes win over the legacy
  // /api/darkweb projections, which are left intact below.
  if (path.startsWith('/api/intel')) {
    const handled = await handleIntelligenceRequest(request, response, user, path);
    if (handled) return;
  }

  if (request.method === 'GET' && path === '/api/health') return sendJson(response, 200, { status: 'ok', database: databaseStatus(), timestamp: new Date().toISOString() });
  if (request.method === 'POST' && path === '/api/auth/sign-in') return sendJson(response, 200, await signIn(await readJson(request)));
  const input = request.method === 'POST' || request.method === 'PUT' || request.method === 'PATCH'
    ? (path === '/api/analyze/email' ? await readEmailInput(request) : await readJson(request))
    : {};
  const query = request.method === 'GET' ? Object.fromEntries(new URL(request.url, `http://${request.headers.host}`).searchParams) : {};

  if (request.method === 'GET' && path === '/api/cases') return sendJson(response, 200, { data: await listCases() });
  if (request.method === 'GET' && path === '/api/reports') return sendJson(response, 200, { data: await listReports() });
  if (request.method === 'GET' && path === '/api/audit') return sendJson(response, 200, { data: await listAudit() });
  if (request.method === 'GET' && path === '/api/alerts') return sendJson(response, 200, { data: listAllAlerts() });
  if (request.method === 'GET' && path === '/api/exposures') return sendJson(response, 200, { data: getStore().exposures });
  if (request.method === 'GET' && path === '/api/analyses') return sendJson(response, 200, { data: await listAnalyses() });

  if (request.method === 'POST' && path === '/api/analyze/email') return sendJson(response, 201, await analyzeRealEmail(input, user));
  if (request.method === 'POST' && path === '/api/analyze/url') return sendJson(response, 201, await analyzeUrl(input, user));
  if (request.method === 'POST' && path === '/api/analyze/file') return sendJson(response, 201, await analyzeFile(input, user));
  if (request.method === 'POST' && path === '/api/analyze/ip') return sendJson(response, 201, await analyzeIp(input, user));
  if (request.method === 'POST' && path === '/api/analyze/domain') return sendJson(response, 201, await analyzeDomain(input, user));
  if (request.method === 'POST' && path === '/api/exposure/check') return sendJson(response, 201, await checkExposure(input, user));
  if (request.method === 'POST' && path === '/api/correlate') return sendJson(response, 201, await correlate(input, user));
  if (request.method === 'POST' && path === '/api/cases') return sendJson(response, 201, await createCase(input, user));
  if (request.method === 'POST' && path === '/api/reports') return sendJson(response, 201, await createReport(input, user));
  if (request.method === 'POST' && path === '/api/audit') return sendJson(response, 201, await createAudit(input, user, request.socket.remoteAddress));

  // ── AI Feedback ──────────────────────────────────────────────────
  if (request.method === 'GET' && path === '/api/feedback') return sendJson(response, 200, { data: await listFeedback(query) });
  if (request.method === 'GET' && path === '/api/feedback/categories') return sendJson(response, 200, { data: FEEDBACK_CATEGORIES });
  if (request.method === 'GET' && path === '/api/feedback/search') return sendJson(response, 200, { data: await searchFeedback(query) });
  if (request.method === 'GET' && path === '/api/feedback/knowledge') return sendJson(response, 200, { data: await getKnowledge(query) });
  if (request.method === 'POST' && path === '/api/feedback') return sendJson(response, 201, await createFeedback(input, user));

  const feedbackSingle = path.match(/^\/api\/feedback\/([^/]+)\/?$/);
  if (request.method === 'GET' && feedbackSingle) return sendJson(response, 200, { data: await getFeedback(feedbackSingle[1]) });
  const feedbackModerate = path.match(/^\/api\/feedback\/([^/]+)\/moderate\/?$/);
  if (request.method === 'PATCH' && feedbackModerate) return sendJson(response, 200, { data: await moderateFeedback(feedbackModerate[1], input, user) });
  const feedbackFlag = path.match(/^\/api\/feedback\/([^/]+)\/flag\/?$/);
  if (request.method === 'POST' && feedbackFlag) return sendJson(response, 200, { data: await flagFeedback(feedbackFlag[1], user) });

  const caseNote = path.match(/^\/api\/cases\/([^/]+)\/note$/);
  if (request.method === 'POST' && caseNote) return sendJson(response, 201, await addNote(decodeURIComponent(caseNote[1]), input, user));
  const caseTask = path.match(/^\/api\/cases\/([^/]+)\/task$/);
  if (request.method === 'POST' && caseTask) return sendJson(response, 201, await addTask(decodeURIComponent(caseTask[1]), input, user));
  const caseTimeline = path.match(/^\/api\/cases\/([^/]+)\/timeline$/);
  if (request.method === 'POST' && caseTimeline) return sendJson(response, 201, await addTimeline(decodeURIComponent(caseTimeline[1]), input, user));
  const taskUpdate = path.match(/^\/api\/cases\/([^/]+)\/tasks\/([^/]+)$/);
  if (request.method === 'PATCH' && taskUpdate) return sendJson(response, 200, await toggleTask(decodeURIComponent(taskUpdate[1]), decodeURIComponent(taskUpdate[2]), input, user));

  // Single-record reads, so a caller can fetch one case/report without
  // downloading the whole collection.
  const caseById = path.match(/^\/api\/cases\/([^/]+)$/);
  if (request.method === 'GET' && caseById) return sendJson(response, 200, { data: await getCase(decodeURIComponent(caseById[1])) });
  const reportById = path.match(/^\/api\/reports\/([^/]+)$/);
  if (request.method === 'GET' && reportById) return sendJson(response, 200, { data: await getReport(decodeURIComponent(reportById[1])) });
  const analysisById = path.match(/^\/api\/analyses\/([^/]+)$/);
  if (request.method === 'GET' && analysisById) {
    const found = (await listAnalyses()).find(item => item.id === decodeURIComponent(analysisById[1]));
    if (!found) throw httpError(404, 'Analysis not found');
    return sendJson(response, 200, { data: found });
  }

  // ── IP Intelligence (DynamoDB) ──────────────────────────────────────
  if (request.method === 'GET' && path === '/api/ip-intelligence/test-connection') {
    if (!isIpIntelligenceEnabled()) return sendJson(response, 503, { error: 'IP Intelligence (DynamoDB) is not configured' });
    const { testDynamoConnection } = await import('../services/dynamodbService.mjs');
    const result = await testDynamoConnection();
    return sendJson(response, 200, { data: result });
  }
  const ipIntelByIp = path.match(/^\/api\/ip-intelligence\/([^/]+)$/);
  if (request.method === 'GET' && ipIntelByIp) {
    if (!isIpIntelligenceEnabled()) return sendJson(response, 503, { error: 'IP Intelligence (DynamoDB) is not configured' });
    const record = await getIpIntelligence(decodeURIComponent(ipIntelByIp[1]));
    if (!record) throw httpError(404, 'IP intelligence record not found');
    return sendJson(response, 200, { data: record });
  }
  if (request.method === 'PUT' && ipIntelByIp) {
    if (!isIpIntelligenceEnabled()) return sendJson(response, 503, { error: 'IP Intelligence (DynamoDB) is not configured' });
    const updated = await updateIpIntelligence(decodeURIComponent(ipIntelByIp[1]), input, user);
    return sendJson(response, 200, { data: updated });
  }
  if (request.method === 'DELETE' && ipIntelByIp) {
    if (!isIpIntelligenceEnabled()) return sendJson(response, 503, { error: 'IP Intelligence (DynamoDB) is not configured' });
    const deleted = await deleteIpIntelligence(decodeURIComponent(ipIntelByIp[1]), user);
    return sendJson(response, 200, { data: deleted });
  }
  if (request.method === 'GET' && path === '/api/ip-intelligence') {
    if (!isIpIntelligenceEnabled()) return sendJson(response, 503, { error: 'IP Intelligence (DynamoDB) is not configured' });
    const ip = query.ip;
    if (!ip) throw httpError(400, 'ip query parameter is required');
    const records = await queryIpIntelligence(ip);
    return sendJson(response, 200, { data: records });
  }
  if (request.method === 'GET' && path === '/api/ip-intelligence/related') {
    if (!isIpIntelligenceEnabled()) return sendJson(response, 503, { error: 'IP Intelligence (DynamoDB) is not configured' });
    const ip = query.ip;
    if (!ip) throw httpError(400, 'ip query parameter is required');
    const related = await getIpRelatedIntelligence(ip);
    return sendJson(response, 200, { data: related });
  }
  const linkActor = path.match(/^\/api\/ip-intelligence\/([^/]+)\/actor$/);
  if (request.method === 'POST' && linkActor) {
    if (!isIpIntelligenceEnabled()) return sendJson(response, 503, { error: 'IP Intelligence (DynamoDB) is not configured' });
    const { actorId } = input;
    if (!actorId) throw httpError(400, 'actorId is required');
    const linked = await linkActorToIp(decodeURIComponent(linkActor[1]), actorId, user);
    return sendJson(response, 201, { data: linked });
  }
  const linkHandle = path.match(/^\/api\/ip-intelligence\/([^/]+)\/handle$/);
  if (request.method === 'POST' && linkHandle) {
    if (!isIpIntelligenceEnabled()) return sendJson(response, 503, { error: 'IP Intelligence (DynamoDB) is not configured' });
    const { handleId } = input;
    if (!handleId) throw httpError(400, 'handleId is required');
    const linked = await linkHandleToIp(decodeURIComponent(linkHandle[1]), handleId, user);
    return sendJson(response, 201, { data: linked });
  }
  const linkPgp = path.match(/^\/api\/ip-intelligence\/([^/]+)\/pgp$/);
  if (request.method === 'POST' && linkPgp) {
    if (!isIpIntelligenceEnabled()) return sendJson(response, 503, { error: 'IP Intelligence (DynamoDB) is not configured' });
    const { pgpId } = input;
    if (!pgpId) throw httpError(400, 'pgpId is required');
    const linked = await linkPgpToIp(decodeURIComponent(linkPgp[1]), pgpId, user);
    return sendJson(response, 201, { data: linked });
  }
  const linkWallet = path.match(/^\/api\/ip-intelligence\/([^/]+)\/wallet$/);
  if (request.method === 'POST' && linkWallet) {
    if (!isIpIntelligenceEnabled()) return sendJson(response, 503, { error: 'IP Intelligence (DynamoDB) is not configured' });
    const { walletId } = input;
    if (!walletId) throw httpError(400, 'walletId is required');
    const linked = await linkWalletToIp(decodeURIComponent(linkWallet[1]), walletId, user);
    return sendJson(response, 201, { data: linked });
  }
  const linkInfra = path.match(/^\/api\/ip-intelligence\/([^/]+)\/infrastructure$/);
  if (request.method === 'POST' && linkInfra) {
    if (!isIpIntelligenceEnabled()) return sendJson(response, 503, { error: 'IP Intelligence (DynamoDB) is not configured' });
    const { infrastructureId } = input;
    if (!infrastructureId) throw httpError(400, 'infrastructureId is required');
    const linked = await linkInfrastructureToIp(decodeURIComponent(linkInfra[1]), infrastructureId, user);
    return sendJson(response, 201, { data: linked });
  }
  const linkEvidence = path.match(/^\/api\/ip-intelligence\/([^/]+)\/evidence$/);
  if (request.method === 'POST' && linkEvidence) {
    if (!isIpIntelligenceEnabled()) return sendJson(response, 503, { error: 'IP Intelligence (DynamoDB) is not configured' });
    const { evidenceId } = input;
    if (!evidenceId) throw httpError(400, 'evidenceId is required');
    const linked = await linkEvidenceToIp(decodeURIComponent(linkEvidence[1]), evidenceId, user);
    return sendJson(response, 201, { data: linked });
  }
  const linkInvestigation = path.match(/^\/api\/ip-intelligence\/([^/]+)\/investigation$/);
  if (request.method === 'POST' && linkInvestigation) {
    if (!isIpIntelligenceEnabled()) return sendJson(response, 503, { error: 'IP Intelligence (DynamoDB) is not configured' });
    const { investigationId } = input;
    if (!investigationId) throw httpError(400, 'investigationId is required');
    const linked = await linkInvestigationToIp(decodeURIComponent(linkInvestigation[1]), investigationId, user);
    return sendJson(response, 201, { data: linked });
  }

  const alert = path.match(/^\/api\/alerts\/([^/]+)\/(acknowledge|assign|escalate|dismiss|resolve)$/);
  if (request.method === 'POST' && alert) return sendJson(response, 200, { data: await updateAlert(decodeURIComponent(alert[1]), alert[2], input, user) });

  // ── Dark Web Threat Intelligence (synthetic dataset) ─────────────
  const actorById = path.match(/^\/api\/darkweb\/actors\/([^/]+)$/);
  if (request.method === 'GET' && path === '/api/darkweb/actors') return sendJson(response, 200, { data: await darkweb.getActors() });
  if (request.method === 'GET' && actorById) return sendJson(response, 200, { data: await darkweb.getActorById(decodeURIComponent(actorById[1])) });
  if (request.method === 'GET' && path === '/api/darkweb/handles') return sendJson(response, 200, { data: await darkweb.getHandles() });
  if (request.method === 'GET' && path === '/api/darkweb/relationships') return sendJson(response, 200, { data: await darkweb.getRelationships() });
  if (request.method === 'GET' && path === '/api/darkweb/evidence') return sendJson(response, 200, { data: await darkweb.getEvidence() });
  if (request.method === 'GET' && path === '/api/darkweb/timeline') return sendJson(response, 200, { data: await darkweb.getTimeline(query) });
  if (request.method === 'GET' && path === '/api/darkweb/sources') return sendJson(response, 200, { data: await darkweb.getSources() });
  if (request.method === 'GET' && path === '/api/darkweb/monitoring') return sendJson(response, 200, { data: await darkweb.getMonitoring() });
  if (request.method === 'GET' && path === '/api/darkweb/reports') return sendJson(response, 200, { data: await darkweb.getReports() });
  if (request.method === 'GET' && path === '/api/darkweb/confidence') return sendJson(response, 200, { data: await darkweb.getConfidenceBreakdown() });
  if (request.method === 'GET' && path === '/api/darkweb/alerts') return sendJson(response, 200, { data: await darkweb.getAlerts() });
  if (request.method === 'GET' && path === '/api/darkweb/investigations') return sendJson(response, 200, { data: await darkweb.getInvestigations() });
  const invById = path.match(/^\/api\/darkweb\/investigations\/([^/]+)$/);
  if (request.method === 'GET' && invById) return sendJson(response, 200, { data: await darkweb.getInvestigationById(decodeURIComponent(invById[1])) });
  if (request.method === 'GET' && path === '/api/darkweb/search/pgp') return sendJson(response, 200, { data: await darkweb.searchPgp(query.fingerprint) });
  if (request.method === 'GET' && path === '/api/darkweb/search/wallet') return sendJson(response, 200, { data: await darkweb.searchWallet(query.address) });
  if (request.method === 'GET' && path === '/api/darkweb/search/infrastructure') return sendJson(response, 200, { data: await darkweb.searchInfrastructure(query.q) });
  if (request.method === 'GET' && path === '/api/darkweb/search') return sendJson(response, 200, { data: await darkweb.searchAll(query.q) });
  if (request.method === 'POST' && path === '/api/darkweb/analyze') return sendJson(response, 200, { data: await darkweb.analyze(input) });

  throw httpError(404, 'Route not found');
}

export const requestId = () => id('REQ');
