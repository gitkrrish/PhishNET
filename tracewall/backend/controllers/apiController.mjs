import { databaseStatus, getStore } from '../database/store.mjs';
import { readEmailInput, readJson, sendJson } from '../middleware/http.mjs';
import { signIn } from '../services/authService.mjs';
import { analyzeEmail, analyzeFile, analyzeUrl, checkExposure, correlate } from '../services/analysisService.mjs';
import { analyzeEmail as analyzeRealEmail } from '../services/emailAnalysisService.mjs';
import { analyzeIp, analyzeDomain } from '../services/infrastructureService.mjs';
import { addNote, addTask, addTimeline, createCase, listCases, toggleTask } from '../services/caseService.mjs';
import { createReport, listReports } from '../services/reportService.mjs';
import { updateAlert } from '../services/alertService.mjs';
import { createAudit, listAudit } from '../services/auditService.mjs';
import { createFeedback, listFeedback, getFeedback, moderateFeedback, searchFeedback, getKnowledge, flagFeedback, FEEDBACK_CATEGORIES } from '../services/feedbackService.mjs';
import { id, httpError } from '../utils/validation.mjs';

export async function handleRequest(request, response, user, path) {
  if (request.method === 'GET' && path === '/api/health') return sendJson(response, 200, { status: 'ok', database: databaseStatus(), timestamp: new Date().toISOString() });
  if (request.method === 'POST' && path === '/api/auth/sign-in') return sendJson(response, 200, await signIn(await readJson(request)));
  const input = request.method === 'POST' || request.method === 'PATCH'
    ? (path === '/api/analyze/email' ? await readEmailInput(request) : await readJson(request))
    : {};
  const query = request.method === 'GET' ? Object.fromEntries(new URL(request.url, `http://${request.headers.host}`).searchParams) : {};

  if (request.method === 'GET' && path === '/api/cases') return sendJson(response, 200, { data: await listCases() });
  if (request.method === 'GET' && path === '/api/reports') return sendJson(response, 200, { data: await listReports() });
  if (request.method === 'GET' && path === '/api/audit') return sendJson(response, 200, { data: await listAudit() });
  if (request.method === 'GET' && path === '/api/alerts') return sendJson(response, 200, { data: getStore().alerts });
  if (request.method === 'GET' && path === '/api/exposures') return sendJson(response, 200, { data: getStore().exposures });
  if (request.method === 'GET' && path === '/api/analyses') return sendJson(response, 200, { data: getStore().analyses });

  if (request.method === 'POST' && path === '/api/analyze/email') return sendJson(response, 201, await analyzeRealEmail(input, user));
  if (request.method === 'POST' && path === '/api/analyze/url') return sendJson(response, 201, await analyzeUrl(input, user));
  if (request.method === 'POST' && path === '/api/analyze/file') return sendJson(response, 201, await analyzeFile(input, user));
  if (request.method === 'POST' && path === '/api/analyze/ip') return sendJson(response, 201, await analyzeIp(input, user));
  if (request.method === 'POST' && path === '/api/analyze/domain') return sendJson(response, 201, await analyzeDomain(input, user));
  if (request.method === 'POST' && path === '/api/exposure/check') return sendJson(response, 201, await checkExposure(input));
  if (request.method === 'POST' && path === '/api/correlate') return sendJson(response, 201, await correlate(input));
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
  if (request.method === 'POST' && caseTask) return sendJson(response, 201, await addTask(decodeURIComponent(caseTask[1]), input));
  const caseTimeline = path.match(/^\/api\/cases\/([^/]+)\/timeline$/);
  if (request.method === 'POST' && caseTimeline) return sendJson(response, 201, await addTimeline(decodeURIComponent(caseTimeline[1]), input, user));
  const taskUpdate = path.match(/^\/api\/cases\/([^/]+)\/tasks\/([^/]+)$/);
  if (request.method === 'PATCH' && taskUpdate) return sendJson(response, 200, await toggleTask(decodeURIComponent(taskUpdate[1]), decodeURIComponent(taskUpdate[2]), input));

  const alert = path.match(/^\/api\/alerts\/([^/]+)\/(acknowledge|assign|escalate|dismiss|resolve)$/);
  if (request.method === 'POST' && alert) return sendJson(response, 200, await updateAlert(decodeURIComponent(alert[1]), alert[2], input, user));
  throw httpError(404, 'Route not found');
}

export const requestId = () => id('REQ');
