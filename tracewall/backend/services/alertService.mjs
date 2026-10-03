import { getStore, persistStore } from '../database/store.mjs';
import { requiredString, httpError } from '../utils/validation.mjs';
import { recordAudit } from './auditService.mjs';
import { getAlert, updateAlertStatus } from './intel/repository.mjs';

/** The alert transitions the alert console can perform. */
const ACTIONS = {
  acknowledge: { status: 'ACKNOWLEDGED', audit: 'ALERT_ACKNOWLEDGED' },
  assign: { status: 'ASSIGNED', audit: 'ALERT_ASSIGNED' },
  escalate: { status: 'ESCALATED', audit: 'ALERT_ESCALATED' },
  dismiss: { status: 'FALSE_POSITIVE', audit: 'ALERT_DISMISSED' },
  resolve: { status: 'RESOLVED', audit: 'ALERT_RESOLVED' },
};

/**
 * Apply an analyst action to an existing alert.
 *
 * The alert must already exist: an unknown id is a 404 rather than a silent
 * push that would invent an alert nobody raised.
 *
 * Alerts live in two places during the migration away from the legacy
 * `app_state` document: the normalized `intel_alert` table (every alert raised
 * by ingestion, correlation and the 24x7 monitoring pipeline) and the seeded
 * app-level alert collection. The centralized table is checked first so a
 * monitoring alert can be actioned by the same console, and the legacy
 * document is only consulted for its own seeded rows. The action is written
 * back to whichever store owns the alert, and is always audited.
 */
export async function updateAlert(alertId, action, input, user) {
  const definition = ACTIONS[action];
  if (!definition) {
    throw httpError(400, `action must be one of ${Object.keys(ACTIONS).join(', ')}`);
  }

  const timestamp = new Date().toISOString();
  const who = user?.name || user?.email || 'analyst';
  const inputBody = input && typeof input === 'object' ? input : {};

  // Normalized alert (ingestion / monitoring / correlation).
  const intelAlert = getAlert(alertId);
  if (intelAlert) {
    const fields = {};
    if (action === 'acknowledge') {
      fields.acknowledgedBy = who;
      fields.acknowledgedAt = timestamp;
    } else if (action === 'assign') {
      fields.assignedTo = requiredString(inputBody.assignee, 'assignee', 200);
      fields.assignedBy = who;
      fields.assignedAt = timestamp;
    } else if (action === 'escalate') {
      fields.escalatedBy = who;
      fields.escalatedAt = timestamp;
      fields.resolution = requiredString(inputBody.reason, 'reason', 2000);
    } else if (action === 'dismiss') {
      fields.dismissedBy = who;
      fields.dismissedAt = timestamp;
      fields.resolution = requiredString(inputBody.reason, 'reason', 2000);
    } else {
      fields.resolvedBy = who;
      fields.resolvedAt = timestamp;
      fields.resolution = requiredString(inputBody.resolution, 'resolution', 2000);
    }
    const updated = updateAlertStatus(alertId, definition.status, fields);
    if (!updated) throw httpError(404, 'Alert not found');
    recordAudit({
      actor: who,
      action: definition.audit,
      target: alertId,
      outcome: 'SUCCESS',
      detail: `${definition.status}${fields.assignedTo ? ` -> ${fields.assignedTo}` : ''}`,
    });
    return { success: true, alertId, status: definition.status, ...fields, alert: updated };
  }

  // Legacy app_state alert (seeded demo rows). Kept working while the rest of
  // the app store is migrated to the normalized tables.
  const store = getStore();
  const existing = store.alerts.find(item => item.id === alertId);
  if (!existing) throw httpError(404, 'Alert not found');

  const result = { success: true, alertId, status: definition.status };
  if (action === 'acknowledge') {
    Object.assign(result, { acknowledgedBy: who, acknowledgedAt: timestamp });
  } else if (action === 'assign') {
    Object.assign(result, { assignedTo: requiredString(inputBody.assignee, 'assignee', 200), assignedBy: who, assignedAt: timestamp });
  } else if (action === 'escalate') {
    Object.assign(result, { escalatedBy: who, escalatedAt: timestamp, reason: requiredString(inputBody.reason, 'reason', 2000) });
  } else if (action === 'dismiss') {
    Object.assign(result, { dismissedBy: who, dismissedAt: timestamp, reason: requiredString(inputBody.reason, 'reason', 2000) });
  } else {
    Object.assign(result, { resolvedBy: who, resolvedAt: timestamp, resolution: requiredString(inputBody.resolution, 'resolution', 2000) });
  }

  Object.assign(existing, result);
  await persistStore();
  recordAudit({
    actor: who,
    action: definition.audit,
    target: alertId,
    outcome: 'SUCCESS',
    detail: result.status,
  });
  return result;
}
