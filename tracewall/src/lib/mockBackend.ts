// API adapter kept under the existing module name so current tools preserve their public contracts.

const API_BASE = import.meta.env.VITE_API_URL || '/api';
let token: string | null = typeof window === 'undefined' ? null : sessionStorage.getItem('tracewall-api-token');

export async function signIn(email: string, password: string) {
  const session = await request<{ token: string; user: { email: string } }>('/auth/sign-in', { method: 'POST', body: JSON.stringify({ email, password }) });
  token = session.token;
  sessionStorage.setItem('tracewall-api-token', token);
  return session;
}

export async function request<T = any>(path: string, options: RequestInit = {}): Promise<T> {
  if (!token && path !== '/auth/sign-in') {
    const session = await signIn('analyst@tracewall.demo', 'demo-password');
    token = session.token;
  }
  const isMultipart = typeof FormData !== 'undefined' && options.body instanceof FormData;
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: { ...(isMultipart ? {} : { 'Content-Type': 'application/json' }), ...(token ? { Authorization: `Bearer ${token}` } : {}), ...options.headers },
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error?.message || `API request failed (${response.status})`);
  return payload as T;
}

export function parseEmail(rawEmail: string) {
  return request<{ headers: Record<string, string>; parsed: boolean; evidenceId: string; timestamp: string }>('/analyze/email', { method: 'POST', body: JSON.stringify({ rawEmail }) });
}

export function analyzeEmail(rawEmail: string, analysisId: string, inputMethod = 'raw') {
  return request('/analyze/email', { method: 'POST', body: JSON.stringify({ rawEmail, analysisId, inputMethod }) });
}

export function analyzeEmailFile(file: File, analysisId: string) {
  const body = new FormData();
  body.append('file', file);
  body.append('fileName', file.name);
  body.append('analysisId', analysisId);
  return generateHash(file).then(inputHash => {
    body.append('inputHash', inputHash);
    return request('/analyze/email', { method: 'POST', body });
  });
}

export function analyzeHeaders(headers: Record<string, string>) {
  return Promise.resolve({ spf: headers.SPF ? 'PASS' : 'FAIL', dkim: headers['DKIM-Signature'] ? 'PASS' : 'NONE', dmarc: headers['Authentication-Results'] ? 'PASS' : 'FAIL', confidence: 82 });
}

export function validateAuthentication(_emailData: unknown) {
  return Promise.resolve({ spf: { result: 'FAIL' as const, detail: 'Sender not authorised', explanation: 'SPF check failed' }, dkim: { result: 'NONE' as const, detail: 'No signature', explanation: 'No DKIM signature found' }, dmarc: { result: 'FAIL' as const, policy: 'p=quarantine', detail: 'No alignment', explanation: 'DMARC policy not satisfied' } });
}

export function extractURLs(emailData: { body?: string }) {
  const urls = (emailData.body || '').match(/https?:\/\/[^\s<>"']+/g) || [];
  return Promise.resolve({ urls: urls.map(url => ({ url, risk: /bit\.ly|tinyurl|example/i.test(url) ? 'HIGH' : 'LOW', shortener: /bit\.ly|tinyurl/.test(url) })), count: urls.length });
}

export function analyzeAttachments(attachments: Array<{ name: string; [key: string]: unknown }>) {
  return Promise.resolve(attachments.map(attachment => ({ ...attachment, riskScore: /\.(docm|xlsm|exe)$/i.test(attachment.name) ? 85 : 15, hasMacro: /\.(docm|xlsm)$/i.test(attachment.name), sandboxResult: /\.(docm|xlsm|exe)$/i.test(attachment.name) ? 'SUSPICIOUS' : 'CLEAN' })));
}

export function enrichDomain(domain: string) {
  return Promise.resolve({ domain, registeredDaysAgo: 11, registrar: 'GoDaddy LLC', hostingProvider: 'Linode', reputation: 'POOR', ipReputation: 'POOR', firstSeen: '2026-08-28', lastSeen: new Date().toISOString().slice(0, 10) });
}

export function enrichIP(ip: string) {
  return Promise.resolve({ ip, asn: 'AS16509', asnName: 'Amazon AWS', country: 'US', city: 'Ashburn', isCloud: true, isVpn: false, isTor: false, reputation: 'NEUTRAL', firstSeen: '2026-08-28', lastSeen: new Date().toISOString().slice(0, 10), disclaimer: 'Estimated infrastructure location only. This is not proof of any person\'s physical location.' });
}

export function checkDarkWebExposure(target: string, targetType: string) { return request('/exposure/check', { method: 'POST', body: JSON.stringify({ target, targetType }) }); }

export async function analyzeFile(file: File) {
  const hash = await generateHash(file);
  return request('/analyze/file', { method: 'POST', body: JSON.stringify({ fileName: file.name, fileSize: file.size, mimeType: file.type, hash }) });
}

export async function generateHash(file: File): Promise<string> {
  const buffer = await file.arrayBuffer();
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(digest)).map(byte => byte.toString(16).padStart(2, '0')).join('');
}

export function analyzeURL(url: string) { return request('/analyze/url', { method: 'POST', body: JSON.stringify({ url }) }); }
export function correlateThreats(indicators: { emails?: string[]; domains?: string[]; ips?: string[]; urls?: string[] }) { return request('/correlate', { method: 'POST', body: JSON.stringify({ indicators }) }); }
export function createCase(caseData: { title: string; severity: string; description: string; assignedTo: string }) { return request('/cases', { method: 'POST', body: JSON.stringify(caseData) }); }
export function addCaseNote(caseId: string, note: string) { return request(`/cases/${encodeURIComponent(caseId)}/note`, { method: 'POST', body: JSON.stringify({ note }) }); }
export function addCaseTask(caseId: string, task: string) { return request(`/cases/${encodeURIComponent(caseId)}/task`, { method: 'POST', body: JSON.stringify({ task }) }); }
export function toggleCaseTask(caseId: string, taskId: string) { return request(`/cases/${encodeURIComponent(caseId)}/tasks/${encodeURIComponent(taskId)}`, { method: 'PATCH', body: JSON.stringify({ done: true }) }); }
export function addTimelineEvent(caseId: string, event: string, type: string) { return request(`/cases/${encodeURIComponent(caseId)}/timeline`, { method: 'POST', body: JSON.stringify({ event, type }) }); }
export function generateReport(reportConfig: { caseId: string; sections: string[]; reportType: string; redactionLevel: string }) { return request('/reports', { method: 'POST', body: JSON.stringify(reportConfig) }); }
export function acknowledgeAlert(alertId: string) { return request(`/alerts/${encodeURIComponent(alertId)}/acknowledge`, { method: 'POST', body: '{}' }); }
export function assignAlert(alertId: string, assignee: string) { return request(`/alerts/${encodeURIComponent(alertId)}/assign`, { method: 'POST', body: JSON.stringify({ assignee }) }); }
export function escalateAlert(alertId: string, reason: string) { return request(`/alerts/${encodeURIComponent(alertId)}/escalate`, { method: 'POST', body: JSON.stringify({ reason }) }); }
export function dismissAlert(alertId: string, reason: string) { return request(`/alerts/${encodeURIComponent(alertId)}/dismiss`, { method: 'POST', body: JSON.stringify({ reason }) }); }
export function resolveAlert(alertId: string, resolution: string) { return request(`/alerts/${encodeURIComponent(alertId)}/resolve`, { method: 'POST', body: JSON.stringify({ resolution }) }); }
export function createAuditEvent(action: string, target: string, outcome: string) { return request('/audit', { method: 'POST', body: JSON.stringify({ action, target, outcome }) }); }

// ── AI Feedback ─────────────────────────────────────────────────────
function qs(params: Record<string, string | number | undefined>) {
  const pairs = Object.entries(params).filter(([, v]) => v !== undefined && v !== '');
  if (!pairs.length) return '';
  return '?' + pairs.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&');
}

export interface FeedbackRecord {
  id: string;
  title: string;
  category: string;
  description: string;
  whatHappened: string;
  indicators: string[];
  impact: string;
  solution: string;
  prevention: string;
  technicalIndicators: string[];
  involvesCybercrime: boolean;
  status: string;
  moderationStatus: 'PENDING' | 'APPROVED' | 'REJECTED' | 'FLAGGED' | 'PRIVATE';
  knowledgeStatus: 'NONE' | 'SANITIZED' | 'INDEXED' | 'LIVE';
  anonymized: boolean;
  redactionReport: Array<{ field: string; findings: Array<{ name: string; count: number }> }>;
  submittedBy: string;
  submittedByName: string;
  moderatorNotes: Array<{ time: string; actor: string; from: string; to: string; note: string }>;
  knowledgeView?: unknown;
  createdAt: string;
  updatedAt: string;
}

export interface FeedbackInput {
  title: string;
  category: string;
  description?: string;
  whatHappened?: string;
  indicators?: string[];
  impact?: string;
  solution?: string;
  prevention?: string;
  technicalIndicators?: string[];
  involvesCybercrime?: boolean;
}

export function listFeedback(params: { status?: string; category?: string; submittedBy?: string; q?: string } = {}) {
  return request<{ data: FeedbackRecord[] }>(`/feedback${qs(params)}`).then(r => r.data);
}

export function listFeedbackCategories() {
  return request<{ data: string[] }>(`/feedback/categories`).then(r => r.data);
}

export function searchFeedback(params: { q?: string; category?: string } = {}) {
  return request<{ data: FeedbackRecord[] }>(`/feedback/search${qs(params)}`).then(r => r.data);
}

export function getFeedbackKnowledge(params: { q?: string; category?: string } = {}) {
  return request<{ data: Array<{ id: string; category: string; knowledge: unknown }> }>(`/feedback/knowledge${qs(params)}`).then(r => r.data);
}

export function submitFeedback(input: FeedbackInput) {
  return request<{ data: FeedbackRecord }>('/feedback', { method: 'POST', body: JSON.stringify(input) }).then(r => r.data);
}

export function getFeedback(id: string) {
  return request<{ data: FeedbackRecord }>(`/feedback/${encodeURIComponent(id)}`).then(r => r.data);
}

export function moderateFeedback(id: string, data: { status: string; note?: string }) {
  return request<{ data: FeedbackRecord }>(`/feedback/${encodeURIComponent(id)}/moderate`, { method: 'PATCH', body: JSON.stringify(data) }).then(r => r.data);
}

export function flagFeedback(id: string) {
  return request<{ data: FeedbackRecord }>(`/feedback/${encodeURIComponent(id)}/flag`, { method: 'POST' }).then(r => r.data);
}

export const DEMO_LABEL = 'Backend Analysis Result';
