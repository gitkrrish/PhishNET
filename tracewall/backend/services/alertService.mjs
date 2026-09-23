import { getStore, persistStore } from '../database/store.mjs';
import { requiredString } from '../utils/validation.mjs';

export async function updateAlert(alertId, action, input, user) {
  const now = new Date().toISOString();
  const result = { success: true, alertId };
  if (action === 'acknowledge') Object.assign(result, { status: 'ACKNOWLEDGED', acknowledgedBy: user.name, acknowledgedAt: now });
  if (action === 'assign') Object.assign(result, { assignedTo: requiredString(input.assignee, 'assignee', 200), assignedBy: user.name, assignedAt: now });
  if (action === 'escalate') Object.assign(result, { status: 'ESCALATED', escalatedBy: user.name, escalatedAt: now, reason: requiredString(input.reason, 'reason', 2000) });
  if (action === 'dismiss') Object.assign(result, { status: 'FALSE_POSITIVE', dismissedBy: user.name, dismissedAt: now, reason: requiredString(input.reason, 'reason', 2000) });
  if (action === 'resolve') Object.assign(result, { status: 'RESOLVED', resolvedBy: user.name, resolvedAt: now, resolution: requiredString(input.resolution, 'resolution', 2000) });
  const store = getStore(); const existing = store.alerts.find(item => item.id === alertId); if (existing) Object.assign(existing, result); else store.alerts.push({ id: alertId, ...result });
  await persistStore(); return result;
}
