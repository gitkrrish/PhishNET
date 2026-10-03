// ============================================================
// PhishNet — AI analysis of monitoring events.
//
// The existing AI Intelligence system may analyse anything monitoring
// detects. This module adds one entry point for monitoring and enforces
// the separation the platform requires:
//
//   observed   — records that exist in the centralized tables
//   correlation— relationships the stored graph already asserts
//   inference  — AI interpretation, always labelled as such
//
// Nothing here fabricates an event or an evidence item. If the AI
// provider is unreachable, the caller still receives the observed and
// correlated buckets plus an explicit statement that no inference was
// produced.
// ============================================================
import { config } from '../../config/env.mjs';
import {
  alertsForMonitor,
  correlationsFor,
  entityLabel,
  listMonitorMatches,
  listSources,
  relationshipsInvolving,
} from './repository.mjs';
import { CONDITIONS, formatInterval } from './monitoringRegistry.mjs';
import { whyLinked } from './correlate.mjs';

const SEVERITY_ORDER = ['INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function rank(severity) {
  const index = SEVERITY_ORDER.indexOf(String(severity || 'INFORMATIONAL').toUpperCase());
  return index < 0 ? 0 : index;
}

/**
 * Build the full analysis for a monitor. `observed` and `correlated` are
 * derived purely from stored records; `inference` is only filled when an
 * AI provider answered, and is always returned as a separate bucket.
 */
export async function analyzeMonitor(monitor, options = {}) {
  const matches = listMonitorMatches(monitor.id, 50).map(row => ({
    id: row.id,
    condition: row.condition_key,
    conditionLabel: CONDITIONS[row.condition_key]?.label || row.condition_key,
    entityType: row.entity_type,
    entityId: row.entity_id,
    entityLabel: row.entity_id ? entityLabel(row.entity_type, row.entity_id) : null,
    detail: JSON.parse(row.detail || '{}'),
    createdAt: row.created_at,
  }));
  const alerts = alertsForMonitor(monitor.id);
  const relatedEntities = [...new Set(matches.map(m => m.entityId).filter(Boolean))];

  const observed = {
    statement: `${matches.length} monitoring condition match(es) recorded against this monitor.`,
    matches: matches.map(m => ({
      condition: m.condition,
      conditionLabel: m.conditionLabel,
      entity: m.entityLabel || m.entityId,
      recordCount: m.detail?.count ?? 0,
      records: (m.detail?.matches || []).slice(0, 10).map(record => ({
        id: record.id ?? null,
        description: record.label ?? null,
        observedAt: record.at ?? m.createdAt,
      })),
      evidenceId: m.detail?.evidenceId ?? null,
      observedAt: m.createdAt,
    })),
    alerts: alerts.map(alert => ({
      id: alert.id,
      severity: alert.severity,
      status: alert.status,
      raisedAt: alert.raised_at,
      evidenceCount: JSON.parse(alert.evidence_ids || '[]').length,
    })),
    sourceHealth: listSources().map(source => ({
      id: source.id,
      name: source.name,
      status: source.status,
      health: source.health_status,
      reliability: source.reliability_score,
    })),
  };

  const correlated = relatedEntities.flatMap(entityId => {
    const relationships = relationshipsInvolving(entityId);
    const reasons = whyLinked(entityId);
    return [
      ...relationships.slice(0, 10).map(relationship => ({
        kind: 'RELATIONSHIP',
        relationshipId: relationship.id,
        detail: `${relationship.source_entity} → ${relationship.target_entity} (${relationship.type}) at ${relationship.confidence}% — ${relationship.explanation || 'no explanation recorded'}`,
      })),
      ...reasons.slice(0, 5).map(reason => ({
        kind: 'WHY_LINKED',
        relationshipId: null,
        detail: `${reason.indicator}: ${reason.detail}`,
      })),
      ...correlationsFor(entityId).slice(0, 5).map(correlation => ({
        kind: 'CORRELATION',
        relationshipId: null,
        detail: `${correlation.method} → ${correlation.object_id === entityId ? correlation.subject_id : correlation.object_id} at ${correlation.confidence}% (${correlation.status})`,
      })),
    ];
  });

  const priority = {
    score: 0,
    band: 'LOW',
    reasons: [],
  };
  const highestSeverity = alerts.reduce((worst, alert) => (rank(alert.severity) > rank(worst) ? alert.severity : worst), 'INFORMATIONAL');
  priority.score = rank(highestSeverity) * 20 + Math.min(20, matches.length * 2);
  priority.band = priority.score >= 80 ? 'CRITICAL' : priority.score >= 60 ? 'HIGH' : priority.score >= 40 ? 'MEDIUM' : 'LOW';
  if (matches.length) priority.reasons.push(`${matches.length} condition match(es) recorded.`);
  if (alerts.some(a => a.status === 'OPEN')) priority.reasons.push(`${alerts.filter(a => a.status === 'OPEN').length} alert(s) still open.`);
  if (monitor.consecutive_failures) priority.reasons.push(`${monitor.consecutive_failures} consecutive collection failure(s).`);

  const analysis = {
    monitor: {
      id: monitor.id,
      name: monitor.name,
      targetType: monitor.target_type,
      targetId: monitor.target_id,
      frequency: monitor.frequency,
      collectionInterval: formatInterval(monitor.collection_interval_seconds ?? 300),
      status: monitor.status,
      runtimeState: monitor.runtime_state,
      lastCheck: monitor.last_check,
      nextCheck: monitor.next_check,
    },
    observed,
    correlated,
    inference: {
      available: false,
      provider: config.groqApiKey ? 'groq' : null,
      summary: null,
      attackMapping: [],
      cveRelevance: [],
      anomalies: [],
      explanation: null,
      note: config.groqApiKey
        ? 'AI enrichment is available through the configured provider.'
        : 'No AI provider is configured, so no inference was produced. Observed and correlated sections are complete and come from stored records only.',
    },
    priority,
    disclaimer: 'Monitoring analysis. Observed data comes from stored records; correlation comes from the stored relationship graph; inference is AI interpretation and is never stored as observed data.',
  };

  if (config.groqApiKey && options.enrich !== false) {
    const enriched = await enrichWithProvider(monitor, observed, correlated, priority);
    if (enriched) analysis.inference = { ...analysis.inference, ...enriched, available: true };
  }

  return analysis;
}

/**
 * Ask the configured provider for interpretation only. The prompt forbids
 * inventing records, and its output is confined to the `inference`
 * bucket — it can never add to `observed` or `correlated`.
 */
async function enrichWithProvider(monitor, observed, correlated, priority) {
  const conditions = [...new Set(observed.matches.map(m => m.conditionLabel))];
  const payload = {
    model: 'groq/compound-mini',
    messages: [
      {
        role: 'system',
        content:
          'You analyse dark web threat monitoring events. You may only interpret the supplied records. Never invent events, entities, evidence or identifiers. Return JSON with keys summary (string), attackMapping (array of strings), cveRelevance (array of strings), anomalies (array of strings), explanation (string).',
      },
      {
        role: 'user',
        content: JSON.stringify({
          monitor: monitor.name,
          targetType: monitor.target_type,
          targetId: monitor.target_id,
          conditions,
          matches: observed.matches.slice(0, 8),
          correlations: correlated.slice(0, 8),
          priority: priority.band,
        }),
      },
    ],
    temperature: 0.2,
    response_format: { type: 'json_object' },
  };
  try {
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${config.groqApiKey}` },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(config.requestTimeoutMs),
    });
    if (!response.ok) return null;
    const data = await response.json();
    const content = data?.choices?.[0]?.message?.content;
    if (!content) return null;
    const parsed = JSON.parse(content);
    return {
      summary: parsed.summary ?? null,
      attackMapping: Array.isArray(parsed.attackMapping) ? parsed.attackMapping : [],
      cveRelevance: Array.isArray(parsed.cveRelevance) ? parsed.cveRelevance : [],
      anomalies: Array.isArray(parsed.anomalies) ? parsed.anomalies : [],
      explanation: parsed.explanation ?? null,
      note: 'AI inference. Interpretive only — the observed and correlated sections are unaffected and remain record-derived.',
    };
  } catch {
    return null;
  }
}

/** Short alert explanation used by the alert centre. */
export function explainAlert(alert) {
  const conditions = JSON.parse(alert.trigger_conditions || '[]');
  const lines = [
    `Monitor ${alert.monitor_id || '—'} raised this alert at ${alert.raised_at}.`,
    conditions.length
      ? `Conditions matched: ${conditions.map(c => `${c.label || c.key} (${c.count ?? 0} record(s))`).join(', ')}.`
      : 'No conditions were recorded on this alert.',
    `${JSON.parse(alert.evidence_ids || '[]').length} evidence item(s) and ${JSON.parse(alert.observation_ids || '[]').length} observation(s) are attached.`,
    `Confidence ${alert.confidence}/100. Severity ${alert.severity} was derived from the configured rule, not assigned automatically.`,
  ];
  return lines.join(' ');
}