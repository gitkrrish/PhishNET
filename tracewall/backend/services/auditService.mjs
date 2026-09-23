import { getStore, persistStore } from '../database/store.mjs';
import { id, requiredString } from '../utils/validation.mjs';

export async function listAudit() { return getStore().audit; }

export async function createAudit(input, user, ip) {
  const event = { id: id('AUD'), time: new Date().toISOString(), actor: user.name, action: requiredString(input.action, 'action', 200), target: requiredString(input.target, 'target', 200), outcome: requiredString(input.outcome, 'outcome', 100), ip: ip || 'unknown' };
  getStore().audit.unshift(event); await persistStore(); return event;
}
