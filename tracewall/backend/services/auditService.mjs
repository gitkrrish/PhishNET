import { getStore, persistStore } from '../database/store.mjs';
import { id, requiredString } from '../utils/validation.mjs';

export async function listAudit() { return getStore().audit; }

/**
 * Append one audit event.
 *
 * Every state-changing service records through here so the audit log is a
 * single, consistently-shaped stream rather than ad-hoc entries written by
 * individual routes. Secrets are never accepted: only the action, the target
 * and a short outcome summary.
 */
export function recordAudit({ actor, action, target, outcome = 'SUCCESS', ip = 'internal', detail = '' }) {
  const event = {
    id: id('AUD'),
    time: new Date().toISOString(),
    actor: actor || 'system',
    action: requiredString(action, 'action', 200),
    target: requiredString(target, 'target', 200),
    outcome: outcome || 'SUCCESS',
    ip: ip || 'internal',
  };
  if (detail) event.detail = String(detail).slice(0, 500);
  getStore().audit.unshift(event);
  persistStore();
  return event;
}

export async function createAudit(input, user, ip) {
  return recordAudit({
    actor: user?.name || user?.email,
    action: input.action,
    target: input.target,
    outcome: input.outcome,
    ip: ip || 'unknown',
  });
}