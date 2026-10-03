// ============================================================
// PhishNet — 24x7 Dark Web Monitoring engine.
//
// The continuous-observation layer that sits ON TOP of the existing
// centralized intelligence tables. A monitor binds to entities that
// already exist by id — it never creates a second copy of anything — and
// its cycle is:
//
//   resolve sources → check real source availability → detect change
//   in the centralized tables → file evidence → raise a real alert
//   citing the records it matched → write a timeline event → log the
//   cycle → advance the next check to the source's real interval
//
// Two commitments shape every function here:
//
//   • Alerts are never fabricated. If the centralized tables show no
//     change, the cycle logs "no new intelligence" and produces no alert.
//   • Continuous collection is never claimed where it is impossible. A
//     monitor's effective cadence is capped by the slowest source it is
//     bound to, and that cap is surfaced in the API rather than hidden.
// ============================================================
import { now, toJson } from './normalize.mjs';
import {
  CONDITIONS,
  FREQUENCIES,
  FREQUENCY_KEYS,
  FREQUENCY_SECONDS,
  MONITOR_STATUSES,
  RUNTIME_STATES,
  LIFECYCLE_STATUSES,
  SEVERITIES,
  SEVERITY_RANK,
  SOURCE_ACCESS_MODES,
  SOURCE_CAPABILITIES,
  TARGET_TYPES,
  formatInterval,
  frequencySeconds,
  monitoringCapabilities,
  resolveCollectionInterval,
  sourceCapability,
  targetTypeSpec,
} from './monitoringRegistry.mjs';
import {
  collectEvidenceReferences,
  detectForTarget,
  detectionWindow,
  resolveSeverity,
  sourceAvailability,
} from './monitorDetectors.mjs';
import {
  addTimelineEvent,
  addMonitorTarget,
  alertsForMonitor,
  attachMatchesToAlert,
  bumpRevision,
  createMonitor,
  entityLabel,
  getMonitor,
  listAlerts,
  listMonitorEvents,
  listMonitorMatches,
  listMonitorTargets,
  listMonitors,
  listRecentMonitorEvents,
  listSources,
  logMonitorEvent,
  logMonitorMatch,
  monitorsDue,
  raiseAlert,
  replaceMonitorTargets,
  resolveEntityRecord,
  setMonitorStatus,
  updateMonitor,
  upsertEvidence,
  writeAudit,
  transact,
  db,
  setMonitoring,
} from './repository.mjs';

// Re-exported so callers (and the controller) keep one import site.
export { FREQUENCIES, FREQUENCY_SECONDS, frequencySeconds, MONITOR_STATUSES, SEVERITIES, TARGET_TYPES, CONDITIONS, monitoringCapabilities, sourceCapability };
export { formatInterval };

/** The scheduler only re-evaluates due monitors; per-monitor cadence governs the rest. */
export const SCHEDULER_TICK_MS = 30_000;

export const FREQ = Object.fromEntries(FREQUENCIES.map(f => [f.key, f.key]));

const parse = (value, fallback) => toJson(value, fallback);

/** Owned actor for a monitored entity, via the relationship that binds them. */
function ownerActorForTarget(database, targetType, targetId) {
  const owner = database
    .prepare(
      `SELECT source_entity AS owner FROM intel_relationship
       WHERE target_entity = ? AND type IN ('SHARED_PGP','SHARED_WALLET','SHARED_INFRASTRUCTURE')
       ORDER BY last_observed DESC LIMIT 1`,
    )
    .get(targetId);
  return owner ? owner.owner : targetType === 'ACTOR' ? targetId : null;
}

/** Resolve the source records a monitor is bound to, by id or by name. */
function resolveSources(monitor) {
  const wanted = parse(monitor.sources, []);
  if (!wanted.length) return [];
  const all = listSources();
  return wanted
    .map(ref => all.find(s => s.id === ref || s.name === ref) || null)
    .filter(Boolean);
}

/** Conditions a monitor evaluates: explicit selection, else the type defaults. */
export function conditionsFor(monitor) {
  const explicit = parse(monitor.conditions, []);
  if (Array.isArray(explicit) && explicit.length) return explicit;
  const rule = parse(monitor.rule, {});
  if (Array.isArray(rule.conditions) && rule.conditions.length) return rule.conditions;
  const spec = targetTypeSpec(monitor.target_type);
  return spec ? spec.defaultConditions : [];
}

/** Every entity a monitor watches. CUSTOM monitors watch a list of them. */
export function targetsFor(monitor) {
  if (String(monitor.monitor_kind || 'SINGLE').toUpperCase() === 'CUSTOM') {
    const rows = listMonitorTargets(monitor.id);
    if (rows.length) {
      return rows.map(row => ({
        targetType: row.entity_type,
        targetId: row.entity_id,
        targetValue: row.entity_value || entityLabel(row.entity_type, row.entity_id),
        conditions: parse(row.conditions, []),
        targetRowId: row.id,
      }));
    }
  }
  return [{
    targetType: monitor.target_type,
    targetId: monitor.target_id,
    targetValue: monitor.target_value || entityLabel(monitor.target_type, monitor.target_id),
    conditions: conditionsFor(monitor),
    targetRowId: null,
  }];
}

/**
 * The capability picture for one monitor: what it watches, at what real
 * cadence, and against which sources. This is what the UI renders, so no
 * component has to guess or hardcode an interval.
 */
export function monitorCapability(monitor) {
  const sources = resolveSources(monitor);
  const interval = resolveCollectionInterval(sources, monitor.frequency);
  const availability = sourceAvailability(sources);
  const targets = targetsFor(monitor);
  return {
    sources: sources.map(source => ({
      id: source.id,
      name: source.name,
      type: source.type,
      status: source.status,
      health: source.health_status,
      reliability: source.reliability_score,
      accessMode: source.access_mode,
      capability: sourceCapability(source),
      collectionIntervalSeconds: source.collection_interval_seconds,
    })),
    requestedFrequency: monitor.frequency,
    requestedIntervalSeconds: frequencySeconds(monitor.frequency),
    effectiveFrequency: monitor.effective_frequency || monitor.frequency,
    collectionIntervalSeconds: monitor.collection_interval_seconds ?? interval.seconds,
    intervalLabel: formatInterval(monitor.collection_interval_seconds ?? interval.seconds),
    continuous: interval.continuous,
    intervalNote: interval.note,
    intervalLimitedBy: interval.limitedBy,
    sourceAvailable: availability.available,
    sourceNote: availability.reason,
    unavailableSources: availability.unavailable,
    targets: targets.map(t => ({ ...t, label: entityLabel(t.targetType, t.targetId) })),
  };
}

export function toMonitorDto(row) {
  if (!row) return null;
  const dto = {
    id: row.id,
    name: row.name,
    monitorKind: row.monitor_kind || 'SINGLE',
    targetType: row.target_type,
    targetId: row.target_id,
    targetValue: row.target_value,
    targetLabel: entityLabel(row.target_type, row.target_id),
    rule: parse(row.rule, {}),
    conditions: parse(row.conditions, []),
    sources: parse(row.sources, []),
    frequency: row.frequency,
    effectiveFrequency: row.effective_frequency || row.frequency,
    collectionIntervalSeconds: row.collection_interval_seconds,
    status: row.status,
    runtimeState: row.runtime_state || 'AWAITING_DATA',
    severity: row.severity,
    alertConditions: parse(row.alert_conditions, {}),
    notificationPref: row.notification_pref,
    notifyChannel: row.notify_channel,
    lastCheck: row.last_check,
    nextCheck: row.next_check,
    lastEventId: row.last_event_id,
    lastError: row.last_error,
    consecutiveFailures: row.consecutive_failures ?? 0,
    checkCount: row.check_count ?? 0,
    triggerCount: row.trigger_count ?? 0,
    alertCount: row.alert_count ?? 0,
    createdBy: row.created_by,
    notes: row.notes || '',
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
  if (String(dto.monitorKind).toUpperCase() === 'CUSTOM') {
    dto.targets = listMonitorTargets(row.id).map(target => ({
      id: target.id,
      entityType: target.entity_type,
      entityId: target.entity_id,
      entityValue: target.entity_value,
      label: entityLabel(target.entity_type, target.entity_id),
      conditions: parse(target.conditions, []),
    }));
  }
  return dto;
}

export function toMonitorEventDto(row) {
  if (!row) return null;
  return {
    id: row.id,
    monitorId: row.monitor_id,
    checkAt: row.check_at,
    status: row.status,
    observationsSeen: row.observations_seen,
    triggeredAlertIds: parse(row.triggered_alert_ids, []),
    message: row.message,
    createdAt: row.created_at,
  };
}

export function toMonitorMatchDto(row) {
  if (!row) return null;
  return {
    id: row.id,
    monitorId: row.monitor_id,
    eventId: row.event_id,
    alertId: row.alert_id,
    condition: row.condition_key,
    conditionLabel: CONDITIONS[row.condition_key]?.label || row.condition_key,
    entityType: row.entity_type,
    entityId: row.entity_id,
    detail: parse(row.detail, {}),
    createdAt: row.created_at,
  };
}

export function toAlertDto(row) {
  if (!row) return null;
  return {
    id: row.id,
    type: row.type,
    severity: row.severity,
    title: row.title,
    reason: row.reason,
    raisedAt: row.raised_at,
    actorId: row.actor_id,
    entityId: row.entity_id,
    entityType: row.entity_type,
    evidenceIds: parse(row.evidence_ids, []),
    observationIds: parse(row.observation_ids, []),
    triggerConditions: parse(row.trigger_conditions, []),
    confidence: row.confidence,
    status: row.status,
    monitorId: row.monitor_id,
    investigationId: row.investigation_id,
    acknowledgedBy: row.acknowledged_by,
    acknowledgedAt: row.acknowledged_at,
    resolution: row.resolution,
    dedupeKey: row.dedupe_key,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/**
 * File the evidence a trigger rests on. Monitoring never invents content:
 * it stores the observed record reference, its provenance and the monitor
 * that observed it, through the existing chain-of-custody writer.
 */
function fileMonitoringEvidence(monitor, target, hits, observedAt) {
  const digest = JSON.stringify(hits.map(h => ({ c: h.condition, m: h.matches.map(m => m.id).sort() })));
  let hash = null;
  try {
    hash = `MON-${monitor.id}-${Buffer.from(digest).toString('base64').slice(0, 44).replace(/[^A-Za-z0-9]/g, '')}`;
  } catch {
    hash = `MON-${monitor.id}-${observedAt}`;
  }
  const sources = resolveSources(monitor);
  const sourceId = sources[0]?.id ?? null;
  const matchCount = hits.reduce((sum, hit) => sum + hit.matches.length, 0);
  return upsertEvidence({
    evidenceType: 'ANALYSIS',
    sourceId,
    sourceLabel: sources[0]?.name || '24x7 Monitoring',
    observedAt,
    collectedAt: observedAt,
    hash,
    reliability: sources[0]?.reliability_score ?? 50,
    confidence: 60,
    provenance: `24x7_monitoring:${monitor.id}`,
    description: `Monitoring cycle for ${target.targetType} ${target.targetId} matched ${matchCount} record(s) across condition(s) ${hits.map(h => h.condition).join(', ')}.`,
    relatedActor: target.targetType === 'ACTOR' ? target.targetId : null,
    relatedHandle: ['HANDLE', 'ALIAS'].includes(String(target.targetType).toUpperCase()) ? target.targetId : null,
    relatedInfra: ['INFRASTRUCTURE', 'DOMAIN', 'IP', 'ONION'].includes(String(target.targetType).toUpperCase()) ? target.targetId : null,
    dataState: sources[0]?.data_state || 'SYNTHETIC_DEMO',
    analyst: 'monitoring-service',
  });
}

/**
 * Run one monitor's detect → file evidence → alert → timeline cycle.
 * Designed to run inside repository.transact(): any throw rolls the whole
 * cycle back, so a monitor never leaves half an alert behind.
 */
export function detectAndAlert(monitor) {
  const database = db();
  const cycleStart = now();
  const capability = monitorCapability(monitor);
  const targets = capability.targets;

  // Honest gating: an unhealthy source yields its real status, not a fake alert.
  if (!capability.sourceAvailable) {
    const message = capability.sourceNote;
    const eventId = logMonitorEvent({
      monitorId: monitor.id,
      checkAt: cycleStart,
      status: 'SOURCE_UNAVAILABLE',
      observationsSeen: 0,
      triggeredAlertIds: [],
      message,
    });
    updateMonitor(monitor.id, {
      lastCheck: cycleStart,
      nextCheck: new Date(Date.now() + (monitor.collection_interval_seconds ?? 3600) * 1000).toISOString(),
      lastEventId: eventId,
      runtimeState: 'SOURCE_UNAVAILABLE',
      lastError: message,
      checkCount: (monitor.check_count ?? 0) + 1,
    });
    return { status: 'SOURCE_UNAVAILABLE', message, eventId, triggered: 0, sources: capability.sources };
  }

  const intervalSeconds = monitor.collection_interval_seconds ?? capability.collectionIntervalSeconds ?? frequencySeconds(monitor.frequency);
  const nextCheck = new Date(Date.now() + intervalSeconds * 1000).toISOString();
  const sinceByTarget = new Map(targets.map(t => [t.targetId, detectionWindow(monitor)]));

  const allHits = [];
  for (const target of targets) {
    const since = sinceByTarget.get(target.targetId) ?? detectionWindow(monitor);
    // A term watch (CVE, keyword, product…) resolves against the term, not an id.
    const term = target.targetValue || target.targetId;
    const resolved = resolveEntityRecord(target.targetType, target.targetId);
    const hits = detectForTarget(target.targetType, target.targetId, target.conditions, since, { term });
    for (const hit of hits) {
      allHits.push({ ...hit, targetType: target.targetType, targetId: target.targetId, targetLabel: target.label || term });
    }
  }

  const conditionKeys = [...new Set(allHits.map(hit => hit.condition))];

  // Confidence reflects how much real matching evidence the cycle found:
  // a cycle matching a handful of records is not a high-confidence finding.
  const matchedRecords = allHits.reduce((sum, hit) => sum + hit.matches.length, 0);
  const confidence = matchedRecords >= 10 ? 75 : matchedRecords >= 4 ? 65 : 55;

  // No change detected → no alert. The cycle is still recorded honestly.
  if (!allHits.length) {
    const eventId = logMonitorEvent({
      monitorId: monitor.id,
      checkAt: cycleStart,
      status: 'OK',
      observationsSeen: 0,
      triggeredAlertIds: [],
      message: `No new intelligence for ${targets.map(t => t.label).join(', ') || monitor.target_id} since ${monitor.last_check || 'the monitor was created'}.`,
    });
    updateMonitor(monitor.id, {
      lastCheck: cycleStart,
      nextCheck,
      lastEventId: eventId,
      runtimeState: 'OK',
      lastError: null,
      consecutiveFailures: 0,
      checkCount: (monitor.check_count ?? 0) + 1,
    });
    refreshMonitoringState(database);
    return { status: 'OK', eventId, triggered: 0, message: 'No new intelligence.' };
  }

  // Real matches exist. File evidence, then alert with a rule-derived severity.
  const severity = resolveSeverity({
    conditionKeys,
    configured: monitor.severity,
    evidenceConfidence: confidence,
  });

  const matchRows = [];
  const matchIds = [];
  for (const hit of allHits) {
    const evidence = fileMonitoringEvidence(monitor, hit, [hit], cycleStart);
    const matchId = logMonitorMatch({
      monitorId: monitor.id,
      conditionKey: hit.condition,
      entityType: hit.targetType,
      entityId: hit.targetId,
      detail: {
        conditionLabel: CONDITIONS[hit.condition]?.label || hit.condition,
        targetLabel: hit.targetLabel,
        count: hit.count,
        matches: hit.matches,
        evidenceId: evidence.id,
      },
    });
    matchIds.push(matchId);
    matchRows.push({ ...hit, evidenceId: evidence.id, matchId });
  }

  const evidenceIds = [...new Set(matchRows.map(row => row.evidenceId))];
  const { observationIds } = collectEvidenceReferences(allHits);
  const primaryTarget = targets[0];
  const owner = ownerActorForTarget(database, primaryTarget?.targetType || monitor.target_type, primaryTarget?.targetId || monitor.target_id);

  const reason = buildReason(monitor, matchRows, capability);

  const alert = raiseMonitoringAlert({
    monitor,
    severity,
    reason,
    targetType: primaryTarget?.targetType || monitor.target_type,
    targetId: primaryTarget?.targetId || monitor.target_id,
    actorId: owner,
    evidenceIds,
    observationIds,
    triggerConditions: conditionKeys.map(key => ({
      key,
      label: CONDITIONS[key]?.label || key,
      count: matchRows.filter(row => row.condition === key).reduce((sum, row) => sum + row.matches.length, 0),
    })),
    confidence,
    raisedAt: cycleStart,
  });
  attachMatchesToAlert(matchIds, alert.id);

  // Timeline: every monitoring event writes one, referencing the entity.
  for (const row of matchRows) {
    addTimelineEvent({
      eventType: timelineTypeFor(row.condition),
      actorId: owner || '',
      entityId: row.targetId || '',
      occurredAt: cycleStart,
      title: `${CONDITIONS[row.condition]?.label || row.condition} — ${row.targetLabel || row.targetId}`,
      description: `24x7 monitor ${monitor.name} (${monitor.id}) detected: ${row.matches.slice(0, 3).map(m => m.label || m.id).join('; ')}${row.matches.length > 3 ? ` +${row.matches.length - 3} more` : ''}.`,
      sourceId: capability.sources[0]?.id ?? null,
      confidence,
      dataState: 'SYNTHETIC_DEMO',
      analyst: 'monitoring-service',
    });
  }

  // Refresh the actor's last-seen so dashboards reflect the new activity.
  touchActor(database, owner, cycleStart);

  writeAudit({
    actor: 'monitoring-service',
    action: 'MONITORING_ALERT_RAISED',
    entity: monitor.target_type,
    entityId: monitor.target_id,
    after: `monitor:${monitor.id} -> alert:${alert.id} conditions=${conditionKeys.join(',')} severity=${severity}`,
    source: '24x7 monitoring cycle',
  });

  const eventId = logMonitorEvent({
    monitorId: monitor.id,
    checkAt: cycleStart,
    status: 'TRIGGERED',
    observationsSeen: allHits.reduce((sum, hit) => sum + hit.matches.length, 0),
    triggeredAlertIds: [alert.id],
    message: `Matched ${conditionKeys.length} condition(s): ${reason}`,
  });

  updateMonitor(monitor.id, {
    lastCheck: cycleStart,
    nextCheck,
    lastEventId: eventId,
    runtimeState: 'RUNNING',
    lastError: null,
    consecutiveFailures: 0,
    checkCount: (monitor.check_count ?? 0) + 1,
    triggerCount: (monitor.trigger_count ?? 0) + 1,
    alertCount: (monitor.alert_count ?? 0) + (alert.created ? 1 : 0),
  });

  refreshMonitoringState(database);
  return {
    status: 'TRIGGERED',
    alertCreated: alert.created,
    alertId: alert.id,
    eventId,
    severity,
    conditions: conditionKeys,
    triggered: matchRows.length,
  };
}

/** Human-readable reason built only from what actually matched. */
function buildReason(monitor, matchRows, capability) {
  const parts = matchRows.map(row => {
    const label = CONDITIONS[row.condition]?.label || row.condition;
    const sample = row.matches.slice(0, 2).map(m => m.label || m.id).join('; ');
    return `${label} ×${row.matches.length}${sample ? ` (${sample})` : ''}`;
  });
  const source = capability.sources[0];
  return `${parts.join(' | ')}. Source: ${source ? `${source.name} [${capability.sources.length} bound]` : 'centralized intelligence only'}. Interval: ${capability.intervalLabel}${capability.continuous ? ' (continuous)' : ' (interval collection)'}.`;
}

/** Timeline event type per condition, mapped onto the existing UI union. */
function timelineTypeFor(condition) {
  switch (condition) {
    case 'NEW_HANDLE': case 'NEW_ALIAS': case 'NEW_PLATFORM': case 'NEW_PLATFORM_APPEARANCE':
    case 'NEW_APPEARANCE': case 'NEW_ACTOR_CORRELATION':
      return 'HANDLE_CHANGE';
    case 'DOMAIN_CHANGE': case 'IP_CHANGE': case 'DNS_CHANGE': case 'CERTIFICATE_CHANGE':
    case 'ONION_AVAILABILITY_CHANGE': case 'MIRROR_DISCOVERY': case 'NEW_INFRASTRUCTURE':
    case 'NEW_INFRA_ASSOCIATION': case 'NEW_TERM_INFRA_ASSOCIATION':
      return 'INFRASTRUCTURE_CHANGE';
    case 'NEW_RELATIONSHIP': case 'RELATIONSHIP_CHANGE': case 'CONFIDENCE_CHANGE':
    case 'NEW_ASSOCIATION': case 'NEW_ASSOCIATED_WALLET': case 'SERVICE_ASSOCIATION':
    case 'PRIVACY_SERVICE_INDICATOR': case 'NEW_IDENTITY_ASSOCIATION':
      return 'RELATIONSHIP_FORMATION';
    case 'NEW_EVIDENCE': case 'NEW_SUPPORTING_EVIDENCE':
      return 'EVIDENCE_COLLECTION';
    case 'NEW_IDENTITY_ASSOCIATION_PERSONA':
      return 'PERSONA_MIGRATION';
    default:
      return 'MONITORING_EVENT';
  }
}

/** Update the owning actor's last-seen so dashboards stay truthful. */
function touchActor(database, actorId, at) {
  if (!actorId) return;
  database
    .prepare('UPDATE intel_actor SET last_seen = ?, updated_at = ? WHERE id = ? AND last_seen < ?')
    .run(at, at, actorId, at);
}

/** Raise (or update) the alert for a trigger, citing the matched records. */
function raiseMonitoringAlert({
  monitor, severity, reason, targetType, targetId, actorId,
  evidenceIds, observationIds, triggerConditions, confidence, raisedAt,
}) {
  return raiseAlert({
    type: 'MONITORING',
    severity,
    title: `24x7 Monitoring: ${monitor.name}`,
    reason,
    raisedAt,
    actorId,
    entityId: targetId,
    entityType: targetType,
    evidenceIds,
    observationIds,
    triggerConditions,
    confidence,
    monitorId: monitor.id,
    // One open alert per (monitor, condition set): a repeat trigger updates
    // the existing alert rather than flooding the alert centre.
    dedupeKey: `MONITOR:${monitor.id}:${triggerConditions.map(c => c.key).sort().join('+')}`,
  });
}

/** Keep the existing intel_state.monitoring object in sync for the dashboard. */
function refreshMonitoringState(database) {
  const monitors = listMonitors();
  const active = monitors.filter(m => m.status === 'ACTIVE').length;
  const monitoringAlerts = listAlerts().filter(a => a.type === 'MONITORING' && a.status === 'OPEN');
  const nextChecks = monitors
    .filter(m => m.status === 'ACTIVE' && m.next_check)
    .map(m => new Date(m.next_check).getTime())
    .sort((a, b) => a - b);
  const lastChecks = monitors
    .filter(m => m.last_check)
    .map(m => new Date(m.last_check).getTime())
    .sort((a, b) => b - a);
  setMonitoring({
    status: active > 0 ? 'ACTIVE' : 'PAUSED',
    lastCollection: lastChecks.length ? new Date(lastChecks[0]).toISOString() : now(),
    nextCollection: nextChecks.length ? new Date(Math.min(...nextChecks)).toISOString() : now(),
    sourcesMonitored: active,
    newIndicators: 0,
    newActors: 0,
    newRelationships: 0,
    alerts: monitoringAlerts.length,
    activeMonitors: active,
    pausedMonitors: monitors.filter(m => m.status === 'PAUSED').length,
    failedMonitors: monitors.filter(m => m.runtime_state === 'ERROR').length,
    criticalAlerts: monitoringAlerts.filter(a => a.severity === 'CRITICAL').length,
    monitors: monitors.length,
  });
}

export function runMonitorCycle() {
  const due = monitorsDue();
  const summary = { checked: 0, triggered: 0, errors: 0, dueCount: due.length };
  for (const monitor of due) {
    summary.checked += 1;
    try {
      const result = transact(() => detectAndAlert(monitor));
      if (result?.status === 'TRIGGERED') summary.triggered += 1;
    } catch (error) {
      summary.errors += 1;
      const message = error?.message || String(error);
      try {
        logMonitorEvent({
          monitorId: monitor.id,
          checkAt: now(),
          status: 'ERROR',
          observationsSeen: 0,
          triggeredAlertIds: [],
          message,
        });
        updateMonitor(monitor.id, {
          runtimeState: 'ERROR',
          lastError: message,
          consecutiveFailures: (monitor.consecutive_failures ?? 0) + 1,
        });
      } catch { /* the outer audit below still runs */ }
      writeAudit({
        actor: 'monitoring-service',
        action: 'MONITORING_CYCLE_ERROR',
        entity: 'MONITOR',
        entityId: monitor.id,
        after: message,
        source: '24x7 monitoring cycle',
        result: 'REJECTED',
      });
    }
  }
  if (summary.checked) bumpRevision();
  return summary;
}

export function runNow(monitorId) {
  if (monitorId) {
    const monitor = getMonitor(monitorId);
    if (!monitor) return { error: 'Monitor not found' };
    // A disabled monitor is off. Running it anyway would let a manual
    // check produce alerts the analyst has switched off, so refuse it.
    const status = String(monitor.status || '').toUpperCase();
    if (status === 'DISABLED') {
      return { error: 'Monitor is disabled. Enable it before running a check.', status: 'DISABLED', refused: true };
    }
    try {
      const result = transact(() => detectAndAlert(monitor));
      bumpRevision();
      return result;
    } catch (error) {
      const message = error?.message || String(error);
      logMonitorEvent({ monitorId, checkAt: now(), status: 'ERROR', observationsSeen: 0, triggeredAlertIds: [], message });
      updateMonitor(monitorId, { runtimeState: 'ERROR', lastError: message, consecutiveFailures: 1 });
      return { error: message, status: 'ERROR' };
    }
  }
  return runMonitorCycle();
}

export function monitoringStats() {
  const monitors = listMonitors();
  const alerts = listAlerts().filter(a => a.type === 'MONITORING');
  const byStatus = monitors.reduce((acc, m) => {
    acc[m.status] = (acc[m.status] || 0) + 1;
    return acc;
  }, {});
  const byRuntimeState = monitors.reduce((acc, m) => {
    const state = m.runtime_state || 'AWAITING_DATA';
    acc[state] = (acc[state] || 0) + 1;
    return acc;
  }, {});
  const active = monitors.filter(m => m.status === 'ACTIVE');
  const recentEvents = listRecentMonitorEvents(20).map(toMonitorEventDto);
  const recentlyTriggered = recentEvents.filter(e => e.status === 'TRIGGERED');
  return {
    totalMonitors: monitors.length,
    byStatus,
    byRuntimeState,
    activeMonitors: active.length,
    pausedMonitors: monitors.filter(m => m.status === 'PAUSED').length,
    disabledMonitors: monitors.filter(m => m.status === 'DISABLED').length,
    runningMonitors: monitors.filter(m => (m.runtime_state || '') === 'RUNNING').length,
    failedMonitors: monitors.filter(m => (m.runtime_state || '') === 'ERROR').length,
    awaitingDataMonitors: monitors.filter(m => (m.runtime_state || '') === 'AWAITING_DATA').length,
    sourceUnavailableMonitors: monitors.filter(m => (m.runtime_state || '') === 'SOURCE_UNAVAILABLE').length,
    recentlyTriggeredMonitors: new Set(recentlyTriggered.map(e => e.monitorId)).size,
    openAlerts: alerts.filter(a => a.status === 'OPEN').length,
    criticalAlerts: alerts.filter(a => a.severity === 'CRITICAL' && a.status === 'OPEN').length,
    totalAlerts: alerts.length,
    recentEvents,
    nextChecks: active
      .filter(m => m.next_check)
      .sort((a, b) => new Date(a.next_check).getTime() - new Date(b.next_check).getTime())
      .slice(0, 5)
      .map(toMonitorDto),
    lastChecks: active
      .filter(m => m.last_check)
      .sort((a, b) => new Date(b.last_check).getTime() - new Date(a.last_check).getTime())
      .slice(0, 5)
      .map(toMonitorDto),
  };
}

/**
 * The centralized monitoring picture for the whole platform, assembled by
 * READING the same rows every other monitoring consumer reads. There is no
 * second store and no second engine here: this is a roll-up, so the 24x7
 * hub can never drift from the monitors the tools themselves manage.
 *
 * `byTool` groups monitors by the registry target type, which is the only
 * honest "tool" a monitor has — the backend stores no origin/orchestrator
 * field, and inventing one would misattribute monitors created from a
 * dossier page to the hub that lists them.
 */
export function monitoringHub({ alertLimit = 25 } = {}) {
  const stats = monitoringStats();
  const monitors = listMonitors();
  const monitorById = new Map(monitors.map(row => [row.id, row]));
  const alerts = listAlerts().filter(alert => alert.type === 'MONITORING');

  const bucket = () => ({ total: 0, active: 0, paused: 0, disabled: 0, error: 0, sourceUnavailable: 0, awaitingData: 0, alerts: 0 });
  const bump = (map, key, apply) => {
    if (!map.has(key)) map.set(key, bucket());
    apply(map.get(key));
  };

  const toolMap = new Map();
  const severityMap = new Map();
  for (const row of monitors) {
    const state = row.runtime_state || 'AWAITING_DATA';
    bump(toolMap, row.target_type, b => {
      b.total += 1;
      if (row.status === 'ACTIVE') b.active += 1;
      if (row.status === 'PAUSED') b.paused += 1;
      if (row.status === 'DISABLED') b.disabled += 1;
      if (state === 'ERROR') b.error += 1;
      if (state === 'SOURCE_UNAVAILABLE') b.sourceUnavailable += 1;
      if (state === 'AWAITING_DATA') b.awaitingData += 1;
    });
    bump(severityMap, row.severity, b => { b.total += 1; });
  }
  for (const alert of alerts) {
    if (!alert.monitor_id) continue;
    const owner = monitorById.get(alert.monitor_id);
    if (!owner) continue;
    const tool = toolMap.get(owner.target_type);
    if (tool) tool.alerts += 1;
    const severity = severityMap.get(owner.severity);
    if (severity) severity.alerts += 1;
  }

  const rank = key => SEVERITY_RANK[key] ?? 0;
  const sortedTool = [...toolMap.entries()]
    .map(([key, value]) => ({ key, label: targetTypeSpec(key)?.label || key, ...value }))
    .sort((a, b) => b.total - a.total || a.key.localeCompare(b.key));
  const sortedSeverity = [...severityMap.entries()]
    .map(([key, value]) => ({ key, label: key, ...value }))
    .sort((a, b) => rank(b.key) - rank(a.key));

  // Every registry target type is reported, including the ones with no
  // monitors yet, so the hub can list what is monitorable rather than only
  // what happens to be watched today.
  const catalog = TARGET_TYPES.map(spec => {
    const counts = toolMap.get(spec.key);
    return {
      key: spec.key,
      label: spec.label,
      term: spec.term === true,
      custom: spec.custom === true,
      conditionCount: spec.defaultConditions.length,
      monitors: counts ? counts.total : 0,
    };
  });

  const recentAlerts = alerts
    .slice()
    .sort((a, b) => new Date(b.raised_at).getTime() - new Date(a.raised_at).getTime())
    .slice(0, Math.max(1, Math.min(100, Number(alertLimit) || 25)))
    .map(row => {
      const dto = toAlertDto(row);
      const owner = row.monitor_id ? monitorById.get(row.monitor_id) : null;
      return {
        ...dto,
        monitorName: owner ? owner.name : null,
        monitorTargetType: owner ? owner.target_type : null,
        monitorTargetId: owner ? owner.target_id : null,
        monitorTargetValue: owner ? owner.target_value : null,
      };
    });

  const dueNow = monitors.filter(row => row.status === 'ACTIVE' && (!row.next_check || new Date(row.next_check).getTime() <= Date.now()));

  return {
    generatedAt: now(),
    scheduler: {
      started: schedulerStarted,
      tickMs: SCHEDULER_TICK_MS,
      dueNow: dueNow.length,
      nextDueAt: dueNow
        .map(row => row.next_check)
        .filter(Boolean)
        .sort()
        .find(Boolean) || null,
    },
    stats: { ...stats, byTool: sortedTool, bySeverity: sortedSeverity },
    catalog,
    alerts: recentAlerts,
    alertsBySeverity: alerts.reduce((acc, alert) => {
      acc[alert.severity] = (acc[alert.severity] || 0) + 1;
      return acc;
    }, {}),
  };
}

let schedulerStarted = false;
let schedulerHandle = null;

export function startScheduler() {
  if (schedulerStarted) return schedulerHandle;
  schedulerStarted = true;
  try {
    runMonitorCycle();
  } catch (error) {
    console.error('[monitoring] initial cycle failed:', error?.message || error);
  }
  schedulerHandle = setInterval(() => {
    try {
      runMonitorCycle();
    } catch (error) {
      console.error('[monitoring] scheduled cycle failed:', error?.message || error);
    }
  }, SCHEDULER_TICK_MS);
  schedulerHandle.unref?.();
  return schedulerHandle;
}

/**
 * Create a monitor. `targetType` decides which conditions are meaningful,
 * `sources` decides the real collection interval, and the effective
 * cadence is stored so the UI never has to re-derive it.
 */
export function provisionMonitor(input, analyst) {
  const targetType = String(input.targetType || '').toUpperCase();
  const spec = targetTypeSpec(targetType);
  if (!spec) throw Object.assign(new Error(`Unsupported target type: ${input.targetType}`), { status: 400 });
  const isCustom = spec.custom === true;
  const monitorKind = isCustom ? 'CUSTOM' : 'SINGLE';

  const sources = (input.sources || []).filter(Boolean);
  const interval = resolveCollectionInterval(
    sources.map(id => listSources().find(s => s.id === id || s.name === id)).filter(Boolean),
    input.frequency,
  );

  const conditions = Array.isArray(input.conditions) && input.conditions.length
    ? input.conditions
    : spec.defaultConditions;

  // A term-based monitor (CVE, keyword, product, ATT&CK technique) watches a
  // term, not a stored entity, so the term itself is the target identity.
  // An entity-backed monitor requires the id of an existing record.
  const termBased = spec.term === true;
  const targetId = String(input.targetId || '').trim() || (termBased ? String(input.targetValue || '').trim() : '');
  if (!isCustom && !targetId) {
    throw Object.assign(
      new Error(termBased
        ? 'targetValue is required for a term-based monitor'
        : 'targetId is required for a single-target monitor'),
      { status: 400 },
    );
  }
  if (isCustom && !(input.targets || []).length) {
    throw Object.assign(new Error('A custom monitor needs at least one target'), { status: 400 });
  }

  // Refuse to bind to something that does not exist: a monitor must never
  // create the entity it claims to watch. Term-based targets are exempt
  // because their subject is the term itself, not a record.
  if (!isCustom && !termBased) {
    const entityType = spec.entityTypes[0] || targetType;
    const record = resolveEntityRecord(entityType, targetId);
    if (!record) {
      throw Object.assign(new Error(`No existing ${entityType} entity with id ${targetId}. Monitoring attaches to existing records and never creates them.`), { status: 400 });
    }
  }

// Reject an unknown severity or frequency rather than silently storing a
  // default. A monitor's severity is an analyst decision: quietly turning
  // an unrecognised value into MEDIUM would misreport what was authorised.
  const requestedSeverity = input.severity == null ? 'MEDIUM' : String(input.severity).toUpperCase();
  if (!SEVERITIES.some(s => s.key === requestedSeverity)) {
    throw Object.assign(new Error(`severity must be one of ${SEVERITIES.map(s => s.key).join(', ')}`), { status: 400 });
  }
  const requestedFrequency = String(input.frequency || 'CONTINUOUS').toUpperCase();
  if (!FREQUENCY_KEYS.includes(requestedFrequency)) {
    throw Object.assign(new Error(`frequency must be one of ${FREQUENCY_KEYS.join(', ')}`), { status: 400 });
  }
  const requestedStatus = String(input.status || 'ACTIVE').toUpperCase();
  if (!LIFECYCLE_STATUSES.includes(requestedStatus)) {
    throw Object.assign(new Error(`status must be one of ${LIFECYCLE_STATUSES.join(', ')}`), { status: 400 });
  }

  const created = createMonitor({
    name: input.name || `${spec.label} monitor`,
    monitorKind,
    targetType: isCustom ? 'CUSTOM' : targetType,
    targetId: isCustom ? 'MULTI' : targetId,
    targetValue: isCustom ? null : (input.targetValue || entityLabel(targetType, targetId)),
    rule: input.rule || {},
    conditions,
    sources,
    frequency: requestedFrequency,
    // INTERVAL_CAPPED is only truthful when a bound source actually forced a
    // slower cadence. Otherwise the effective frequency is what the analyst
    // asked for, and "not continuous" is conveyed by the capability block.
    effectiveFrequency: interval.limitedBy ? 'INTERVAL_CAPPED' : requestedFrequency,
    collectionIntervalSeconds: interval.seconds,
    status: requestedStatus,
    runtimeState: 'AWAITING_DATA',
    severity: requestedSeverity,
    alertConditions: input.alertConditions || {},
    notificationPref: input.notificationPref || 'IN_PLATFORM',
    notifyChannel: input.notifyChannel || 'PLATFORM',
    nextCheck: input.nextCheck || now(),
    createdBy: analyst || 'analyst',
    notes: input.notes || '',
  });

  if (isCustom) {
    replaceMonitorTargets(created.id, input.targets || []);
  }

  bumpRevision();
  writeAudit({
    actor: analyst || 'analyst',
    action: 'MONITOR_CREATED',
    entity: targetType,
    entityId: created.id,
    after: `target=${input.targetId || 'MULTI'} frequency=${input.frequency || 'CONTINUOUS'} interval=${formatInterval(interval.seconds)} severity=${input.severity || 'MEDIUM'}`,
    source: 'API',
  });
  return created;
}

export { SOURCE_CAPABILITIES, SOURCE_ACCESS_MODES, RUNTIME_STATES, LIFECYCLE_STATUSES };