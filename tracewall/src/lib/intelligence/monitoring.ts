// ============================================================
// PhishNet — 24x7 monitoring API client.
//
// Every monitor configuration lives in the centralized backend. This
// module is the only place the UI talks to it, so the monitoring state
// the interface shows is always the backend's, never a local copy.
//
// Nothing here mirrors monitoring into the intelligence dataset: the
// dataset remains the record model, and monitoring is a view over it plus
// the alert it raised.
// ============================================================
import { request } from '../mockBackend';
import { severityColor } from '../styles';
import { useCallback, useEffect, useRef, useState } from 'react';

// ── Contracts, mirroring backend/services/intel/monitoringRegistry.mjs ──
export interface MonitorCondition {
  key: string;
  label: string;
  group: string;
  description: string;
  scope: string;
  baseSeverity: string;
}

export interface TargetTypeSpec {
  key: string;
  label: string;
  entityTypes: string[];
  defaultConditions: string[];
  term?: boolean;
  custom?: boolean;
  /** Example value for a term watch, so the analyst is not guessing the format. */
  termHint?: string;
}

export interface MonitorConditionGroup {
  [group: string]: number;
}

export interface MonitoringCapabilities {
  targetTypes: TargetTypeSpec[];
  conditions: Record<string, MonitorCondition>;
  conditionGroups: MonitorConditionGroup;
  frequencies: Array<{ key: string; label: string; seconds: number }>;
  severities: Array<{ key: string; label: string; rank: number }>;
  statuses: string[];
  lifecycleStatuses: string[];
  runtimeStates: string[];
  sourceCapabilities: Record<string, { seconds: number; continuous: boolean; label: string; note: string }>;
  sourceAccessModes: string[];
}

export interface MonitorSource {
  id: string;
  name: string;
  type: string;
  status: string;
  health: string;
  reliability: number;
  accessMode: string;
  collectionIntervalSeconds: number;
  capability: { seconds: number; continuous: boolean; label: string; note: string };
}

export interface MonitorCapability {
  sources: MonitorSource[];
  requestedFrequency: string;
  requestedIntervalSeconds: number;
  effectiveFrequency: string;
  collectionIntervalSeconds: number;
  intervalLabel: string;
  continuous: boolean;
  intervalNote: string;
  intervalLimitedBy: string | null;
  sourceAvailable: boolean;
  sourceNote: string;
  unavailableSources: Array<{ id: string; name: string; status: string; health: string }>;
  targets: Array<{ targetType: string; targetId: string; targetValue: string | null; conditions: string[]; label: string }>;
}

export interface Monitor {
  id: string;
  name: string;
  monitorKind: 'SINGLE' | 'CUSTOM';
  targetType: string;
  targetId: string;
  targetValue: string | null;
  targetLabel: string;
  conditions: string[];
  sources: string[];
  frequency: string;
  effectiveFrequency: string;
  collectionIntervalSeconds: number | null;
  status: string;
  runtimeState: string;
  severity: string;
  notificationPref: string | null;
  notifyChannel: string | null;
  lastCheck: string | null;
  nextCheck: string | null;
  lastEventId: string | null;
  lastError: string | null;
  consecutiveFailures: number;
  checkCount: number;
  triggerCount: number;
  alertCount: number;
  createdBy: string;
  notes: string;
  createdAt: string;
  updatedAt: string;
  capability: MonitorCapability;
  targets?: MonitorTarget[];
}

export interface MonitorTarget {
  id?: string;
  entityType: string;
  entityId: string;
  entityValue?: string | null;
  label?: string;
  conditions?: string[];
}

export interface MonitorEvent {
  id: string;
  monitorId: string;
  checkAt: string;
  status: string;
  observationsSeen: number;
  triggeredAlertIds: string[];
  message: string | null;
  createdAt: string;
}

export interface MonitorMatch {
  id: string;
  monitorId: string;
  eventId: string | null;
  alertId: string | null;
  condition: string;
  conditionLabel: string;
  entityType: string | null;
  entityId: string | null;
  detail: { conditionLabel?: string; targetLabel?: string; count?: number; matches?: Array<{ id?: string; label?: string; at?: string }>; evidenceId?: string };
  createdAt: string;
}

export interface MonitoringAlert {
  id: string;
  type: string;
  severity: string;
  title: string;
  reason: string;
  raisedAt: string;
  actorId: string | null;
  entityId: string | null;
  entityType: string | null;
  evidenceIds: string[];
  observationIds: string[];
  triggerConditions: Array<{ key: string; label: string; count: number }>;
  confidence: number;
  status: string;
  monitorId: string | null;
  investigationId: string | null;
  acknowledgedBy?: string | null;
  acknowledgedAt?: string | null;
  resolution?: string | null;
  explanation?: string;
}

export interface MonitoringStats {
  totalMonitors: number;
  byStatus: Record<string, number>;
  byRuntimeState: Record<string, number>;
  activeMonitors: number;
  pausedMonitors: number;
  disabledMonitors: number;
  runningMonitors: number;
  failedMonitors: number;
  awaitingDataMonitors: number;
  sourceUnavailableMonitors: number;
  recentlyTriggeredMonitors: number;
  openAlerts: number;
  criticalAlerts: number;
  totalAlerts: number;
  recentEvents: MonitorEvent[];
  nextChecks: Monitor[];
  lastChecks: Monitor[];
}

export interface MonitorDetail extends Monitor {
  recentEvents: MonitorEvent[];
  recentMatches: MonitorMatch[];
  alerts: MonitoringAlert[];
}

export interface MonitoringAnalysis {
  monitor: Record<string, unknown>;
  observed: {
    statement: string;
    matches: Array<{ condition: string; conditionLabel: string; entity: string | null; recordCount: number; records: Array<{ id: string | null; description: string | null; observedAt: string | null }>; evidenceId: string | null; observedAt: string }>;
    alerts: Array<{ id: string; severity: string; status: string; raisedAt: string; evidenceCount: number }>;
    sourceHealth: Array<{ id: string; name: string; status: string; health: string; reliability: number }>;
  };
  correlated: Array<{ kind: string; relationshipId: string | null; detail: string }>;
  inference: {
    available: boolean;
    provider: string | null;
    summary: string | null;
    attackMapping: string[];
    cveRelevance: string[];
    anomalies: string[];
    explanation: string | null;
    note: string;
  };
  priority: { score: number; band: string; reasons: string[] };
  disclaimer: string;
}

export interface MonitorInput {
  name: string;
  targetType: string;
  targetId?: string;
  targetValue?: string;
  targets?: MonitorTarget[];
  sources?: string[];
  frequency: string;
  severity: string;
  conditions?: string[];
  notificationPref?: string;
  notifyChannel?: string;
  notes?: string;
  status?: string;
}

// ── Endpoints ──────────────────────────────────────────────────
const data = <T,>(envelope: { data: T }) => envelope.data;

// ── Centralized 24x7 hub roll-up ────────────────────────────────
//
// A read-only aggregation over the same monitor rows every tool manages.
// The hub has no store of its own; this shape exists so the overview does
// not have to re-derive per-tool counts in the browser.

export interface MonitorToolCount {
  key: string;
  label: string;
  total: number;
  active: number;
  paused: number;
  disabled: number;
  error: number;
  sourceUnavailable: number;
  awaitingData: number;
  alerts: number;
}

export interface MonitorSeverityCount {
  key: string;
  label: string;
  total: number;
  alerts: number;
}

export interface MonitorToolCatalogEntry {
  key: string;
  label: string;
  term: boolean;
  custom: boolean;
  conditionCount: number;
  monitors: number;
}

export interface MonitoringHubAlert extends MonitoringAlert {
  monitorName: string | null;
  monitorTargetType: string | null;
  monitorTargetId: string | null;
  monitorTargetValue: string | null;
}

export interface MonitoringHubData {
  generatedAt: string;
  scheduler: { started: boolean; tickMs: number; dueNow: number; nextDueAt: string | null };
  stats: MonitoringStats & { byTool: MonitorToolCount[]; bySeverity: MonitorSeverityCount[] };
  catalog: MonitorToolCatalogEntry[];
  alerts: MonitoringHubAlert[];
  alertsBySeverity: Record<string, number>;
}

export const monitoringHub = (alertLimit = 50) =>
  request<{ data: MonitoringHubData }>(`/intel/monitoring/hub?limit=${encodeURIComponent(alertLimit)}`).then(data);

export const listMonitors = () => request<{ data: Monitor[] }>('/intel/monitoring').then(data);
export const getMonitor = (id: string) => request<{ data: MonitorDetail }>(`/intel/monitoring/${encodeURIComponent(id)}`).then(data);
export const monitoringStats = () => request<{ data: MonitoringStats }>('/intel/monitoring/stats').then(data);
export const monitoringCapabilities = () => request<{ data: MonitoringCapabilities }>('/intel/monitoring/capabilities').then(data);
export const monitorsForEntity = (entityType: string, entityId: string) =>
  request<{ data: Monitor[] }>(`/intel/monitoring/entity/${encodeURIComponent(entityType)}/${encodeURIComponent(entityId)}`).then(data);

export const createMonitor = (input: MonitorInput) =>
  request<{ data: Monitor }>('/intel/monitoring', { method: 'POST', body: JSON.stringify(input) }).then(data);

export const updateMonitor = (id: string, patch: Partial<MonitorInput>) =>
  request<{ data: Monitor }>(`/intel/monitoring/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(patch) }).then(data);

export const deleteMonitor = (id: string) =>
  request<unknown>(`/intel/monitoring/${encodeURIComponent(id)}`, { method: 'DELETE' });

export const setMonitorStatus = (id: string, action: 'pause' | 'resume' | 'disable' | 'enable') =>
  request<{ data: Monitor }>(`/intel/monitoring/${encodeURIComponent(id)}/${action}`, { method: 'POST', body: '{}' }).then(data);

export const runMonitor = (id: string) =>
  request<{ data: unknown }>(`/intel/monitoring/run/${encodeURIComponent(id)}`, { method: 'POST', body: '{}' }).then(data);

export const runAllDueMonitors = () =>
  request<{ data: { checked: number; triggered: number; errors: number; dueCount: number } }>('/intel/monitoring/run', { method: 'POST', body: '{}' }).then(data);

export const listMonitorEvents = (id: string) =>
  request<{ data: MonitorEvent[] }>(`/intel/monitoring/${encodeURIComponent(id)}/events`).then(data);

export const listMonitorMatches = (id: string) =>
  request<{ data: MonitorMatch[] }>(`/intel/monitoring/${encodeURIComponent(id)}/matches`).then(data);

export const listMonitorAlerts = (id: string) =>
  request<{ data: MonitoringAlert[] }>(`/intel/monitoring/${encodeURIComponent(id)}/alerts`).then(data);

export const analyzeMonitor = (id: string, enrich = true) =>
  request<{ data: MonitoringAnalysis }>(`/intel/monitoring/${encodeURIComponent(id)}/analyze`, {
    method: 'POST',
    body: JSON.stringify({ enrich }),
  }).then(data);

// ── Audit log ───────────────────────────────────────────────────
// The app-level audit trail is written by the backend services, so it is
// read from the API rather than assembled in the browser.

export interface AuditEntry {
  id: string;
  time: string;
  actor: string;
  action: string;
  target: string;
  outcome: string;
  ip: string;
  detail?: string;
}

export const listAudit = () => request<{ data: AuditEntry[] }>('/audit').then(data);

// ── App-level alerts ────────────────────────────────────────────

export interface AppAlert {
  id: string;
  status?: string;
  acknowledgedBy?: string;
  acknowledgedAt?: string;
  escalatedBy?: string;
  escalatedAt?: string;
  reason?: string;
  dismissedBy?: string;
  resolvedBy?: string;
  resolution?: string;
  assignedTo?: string;
  [key: string]: unknown;
}

export const listAppAlerts = () => request<{ data: AppAlert[] }>('/alerts').then(data);

export const actOnAppAlert = (alertId: string, action: 'acknowledge' | 'assign' | 'escalate' | 'dismiss' | 'resolve', body: Record<string, string> = {}) =>
  request<{ data: AppAlert }>(`/alerts/${encodeURIComponent(alertId)}/${action}`, { method: 'POST', body: JSON.stringify(body) }).then(data);

export const listInvestigations = () => request<{ data: Array<{ id: string; title: string; status: string }> }>('/intel/investigations').then(data);

// ── AI Intelligence / AI Investigation ──────────────────────────
//
// These answers are produced by the backend from the centralized records,
// never in the browser. The three buckets are kept separate here exactly as
// the backend returns them, so the UI cannot blur a stored fact into a guess.

export interface AiBucket {
  statement: string;
  sourceId: string | null;
  relationshipId?: string | null;
  evidenceIds?: string[];
}

export interface AiInference {
  available: boolean;
  provider: string | null;
  summary: string | null;
  status: string;
  note: string;
}

export interface AiAnswer {
  question: string;
  answered: boolean;
  answer: string;
  observed: AiBucket[];
  derived: AiBucket[];
  inference: AiInference;
  datasetSize?: Record<string, number>;
  disclaimer: string;
}

export interface AiInvestigationSummary {
  investigationId: string;
  title: string;
  status: string;
  observed: AiBucket[];
  derived: AiBucket[];
  inference: AiInference;
  disclaimer: string;
}

export interface AiExtraction {
  text: string;
  entities: Array<{ entityId: string; entityType: string; label: string; matchedAs: string; resolved?: boolean }>;
  resolved: number;
  unresolved: number;
  note: string;
}

export interface AiAnomalies {
  anomalies: Array<{ type: string; entityId: string; detail: string; severity: string }>;
  count: number;
  method: string;
}

export interface AiCapabilities {
  aiProvider: string | null;
  aiProviderConfigured: boolean;
  analysis: string[];
  buckets: string[];
  note: string;
}

export const aiCapabilities = () => request<{ data: AiCapabilities }>('/intel/ai/capabilities').then(data);

export const askInvestigation = (question: string, contextEntityId?: string, enrich = true) =>
  request<{ data: AiAnswer }>('/intel/ai/ask', {
    method: 'POST',
    body: JSON.stringify({ question, contextEntityId: contextEntityId ?? null, enrich }),
  }).then(data);

export const investigationAiSummary = (investigationId: string, enrich = true) =>
  request<{ data: AiInvestigationSummary }>(`/intel/ai/investigation/${encodeURIComponent(investigationId)}/summary`, {
    method: 'POST',
    body: JSON.stringify({ enrich }),
  }).then(data);

export const extractEntities = (text: string) =>
  request<{ data: AiExtraction }>('/intel/ai/extract', { method: 'POST', body: JSON.stringify({ text }) }).then(data);

export const aiAnomalies = () => request<{ data: AiAnomalies }>('/intel/ai/anomalies').then(data);

export const stylometryComparison = (leftId: string, rightId: string) =>
  request<{ data: Record<string, unknown> }>(`/intel/ai/stylometry/${encodeURIComponent(leftId)}/${encodeURIComponent(rightId)}`).then(data);

/** Attach a monitoring alert (and the records it cites) to an existing investigation. */
export const attachAlertToInvestigation = (alertId: string, investigationId: string) =>
  request<{ data: { alert: MonitoringAlert; investigationId: string; attachedEntities: string[] } }>(
    `/intel/alerts/${encodeURIComponent(alertId)}/investigation`,
    { method: 'POST', body: JSON.stringify({ investigationId }) },
  ).then(data);

export const setAlertStatus = (alertId: string, status: string, resolution?: string) =>
  request<{ data: MonitoringAlert }>(`/intel/alerts/${encodeURIComponent(alertId)}`, {
    method: 'PATCH',
    body: JSON.stringify({ status, resolution }),
  }).then(data);

// ── Shared polling hook ─────────────────────────────────────────
/**
 * Poll the monitoring endpoints on the scheduler cadence. This is what
 * makes a 24x7 monitor visible in the UI without any frontend-owned
 * state: every value rendered comes from the backend response.
 */
export function useMonitoringPolling<T>(loader: () => Promise<T>, intervalMs = 30000) {
  const [value, setValue] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const loaderRef = useRef(loader);
  loaderRef.current = loader;

  const refresh = useCallback(async () => {
    try {
      setValue(await loaderRef.current());
      setError(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), intervalMs);
    return () => clearInterval(timer);
  }, [refresh, intervalMs]);

  return { value, error, refresh };
}

// ── Presentation helpers ────────────────────────────────────────

/**
 * Lifecycle state + runtime state → the single status the UI shows.
 * Both come from the backend; this only maps them to a label.
 */
export function monitorStatus(monitor: { status: string; runtimeState?: string }): { label: string; color: string } {
  if (monitor.runtimeState === 'ERROR') return { label: 'ERROR', color: 'var(--tw-critical)' };
  if (monitor.runtimeState === 'SOURCE_UNAVAILABLE') return { label: 'SOURCE UNAVAILABLE', color: 'var(--tw-high)' };
  if (monitor.status === 'DISABLED') return { label: 'DISABLED', color: 'var(--tw-dust)' };
  if (monitor.status === 'PAUSED') return { label: 'PAUSED', color: 'var(--tw-medium)' };
  if (monitor.runtimeState === 'RUNNING') return { label: 'RUNNING', color: 'var(--tw-burgundy)' };
  if (monitor.runtimeState === 'AWAITING_DATA') return { label: 'AWAITING DATA', color: 'var(--tw-info)' };
  if (monitor.runtimeState === 'COMPLETED') return { label: 'COMPLETED', color: 'var(--tw-low)' };
  return { label: 'ACTIVE', color: 'var(--tw-low)' };
}

export const MONITOR_STATUS_COLORS: Record<string, string> = {
  ACTIVE: 'var(--tw-low)',
  RUNNING: 'var(--tw-burgundy)',
  PAUSED: 'var(--tw-medium)',
  DISABLED: 'var(--tw-dust)',
  COMPLETED: 'var(--tw-low)',
  ERROR: 'var(--tw-critical)',
  SOURCE_UNAVAILABLE: 'var(--tw-high)',
  AWAITING_DATA: 'var(--tw-info)',
};

export function conditionLabel(capabilities: MonitoringCapabilities | null, key: string): string {
  return capabilities?.conditions?.[key]?.label ?? key.replace(/_/g, ' ').toLowerCase();
}

/**
 * "2 min ago" for the hub's last/next-check columns. Every other page inlines
 * `toLocaleString()`; monitoring is read against a tick, so a relative
 * age is the honest way to show a scheduler that moves continuously.
 */
export function formatRelativeTime(iso: string | null | undefined, nowMs = Date.now()): string {
  if (!iso) return 'never';
  const then = new Date(iso).getTime();
  if (!Number.isFinite(then)) return 'unknown';
  const seconds = Math.round((nowMs - then) / 1000);
  const magnitude = (value: number, unit: string) => `${Math.abs(value)} ${unit}${Math.abs(value) === 1 ? '' : 's'}`;
  if (seconds < 45) return seconds >= 0 ? 'just now' : `in ${magnitude(seconds, 's')}`;
  const minutes = Math.round(seconds / 60);
  if (Math.abs(minutes) < 60) return minutes > 0 ? `${magnitude(minutes, 'min')} ago` : `in ${magnitude(minutes, 'min')}`;
  const hours = Math.round(minutes / 60);
  if (Math.abs(hours) < 24) return hours > 0 ? `${magnitude(hours, 'hour')} ago` : `in ${magnitude(hours, 'hour')}`;
  const days = Math.round(hours / 24);
  return days > 0 ? `${magnitude(days, 'day')} ago` : `in ${magnitude(days, 'day')}`;
}

/**
 * Severity → CSS variable. The registry's lowest band is INFORMATIONAL,
 * which the app-wide `severityColor` does not know, so it is mapped here
 * rather than widening a shared helper other pages depend on.
 */
export function monitorSeverityColor(severity: string): string {
  if (String(severity).toUpperCase() === 'INFORMATIONAL') return 'var(--tw-dust)';
  return severityColor(String(severity).toUpperCase());
}

// ── Submitted file / URL analysis (real, backend-computed) ─────
//
// Both routes run the server's own static analysis and persist the result, so
// the console shows the risk, findings and extracted indicators the backend
// actually derived from the submitted artefact instead of a demo fixture.

export interface FileAnalysisResponse {
  id: string;
  fileName: string;
  fileSize: string;
  fileType: string;
  mimeType: string;
  uploadedAt: string;
  riskScore: number;
  verdict: string;
  severity: string;
  suspiciousFindings: Array<{ signal: string; detail: string }>;
  extractedIndicators: { urls: string[]; domains: string[]; ips: string[]; emailAddresses: string[] };
  hash: string | null;
}

export interface UrlAnalysisResponse {
  id: string;
  originalUrl: string;
  extractedUrl: string;
  scheme: string;
  finalDomain: string;
  registrableDomain: string;
  shortenedUrl: string | null;
  path: string;
  suspiciousParams: string[];
  riskScore: number;
  verdict: string;
  severity: string;
  phishingIndicators: Array<{ signal: string; detail: string; weight: number }>;
  [key: string]: unknown;
}

// The analysis routes answer with the analysis document itself, not the
// `{ data }` envelope the collection routes use, so these return the
// response as-is.
export const submitFileAnalysis = (input: {
  fileName: string;
  fileSize: number;
  mimeType?: string;
  sha256?: string;
  contentText?: string;
  base64?: string;
}) => request<FileAnalysisResponse>('/analyze/file', { method: 'POST', body: JSON.stringify(input) });

export const submitUrlAnalysis = (url: string) =>
  request<UrlAnalysisResponse>('/analyze/url', { method: 'POST', body: JSON.stringify({ url }) });