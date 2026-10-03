// ============================================================
// PhishNet — Active Threat Protection service (backend).
//
// Persists analyst protection decisions — blocked indicators and
// response tickets — in the `intel_protection_state` singleton row.
// The derived threat *scores* live in detectionService.mjs; this file
// only owns the mutable, analyst-authored protection state. Every
// write bumps the central intel revision so the frontend store
// reconciles.
// ============================================================
import { db, newId, bumpRevision } from './repository.mjs';

const EMPTY_STATE = { blockedIndicators: [], responseLogs: [] };

function getDatabase() {
  return db();
}

export function getProtectionState() {
  const row = getDatabase().prepare('SELECT protection_json FROM intel_protection_state WHERE id = 1').get();
  if (!row) return { ...EMPTY_STATE };
  try {
    const parsed = JSON.parse(row.protection_json || '{}');
    return {
      blockedIndicators: Array.isArray(parsed.blockedIndicators) ? parsed.blockedIndicators : [],
      responseLogs: Array.isArray(parsed.responseLogs) ? parsed.responseLogs : [],
    };
  } catch {
    return { ...EMPTY_STATE };
  }
}

export function saveProtectionState(state) {
  const database = getDatabase();
  const now = new Date().toISOString();
  database
    .prepare('UPDATE intel_protection_state SET protection_json = ?, updated_at = ? WHERE id = 1')
    .run(JSON.stringify(state), now);
  bumpRevision();
}

export function setProtectionState(state) {
  return saveProtectionState(state);
}

export function listBlockedIndicators() {
  return getProtectionState().blockedIndicators.filter(b => b.active);
}

export function isEntityBlocked(entityId) {
  return listBlockedIndicators().some(b => b.entityId === entityId);
}

export function listResponseLogs() {
  return [...getProtectionState().responseLogs].sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
}

export function blockIndicator({ entityType, entityId, value, reason, performedBy = 'analyst', expiresAt = null }) {
  const state = getProtectionState();
  const existing = state.blockedIndicators.find(b => b.entityId === entityId && b.active);
  let result;
  if (existing) {
    existing.reason = reason;
    existing.expiresAt = expiresAt ?? existing.expiresAt;
    existing.blockedAt = new Date().toISOString();
    existing.blockedBy = performedBy;
    result = existing;
  } else {
    const blocked = {
      id: newId('BLK'),
      entityType,
      entityId,
      value,
      blockedAt: new Date().toISOString(),
      blockedBy: performedBy,
      reason,
      expiresAt: expiresAt ?? null,
      active: true,
    };
    state.blockedIndicators.push(blocked);
    result = blocked;
  }
  saveProtectionState(state);
  return result;
}

export function unblockIndicator(id) {
  const state = getProtectionState();
  const blocked = state.blockedIndicators.find(b => b.id === id);
  if (!blocked) return null;
  blocked.active = false;
  saveProtectionState(state);
  return blocked;
}

export function createResponseLog({ threatRecordId, title, severity, performedBy = 'analyst' }) {
  const state = getProtectionState();
  const log = {
    id: newId('RSP'),
    threatRecordId,
    title,
    severity,
    createdAt: new Date().toISOString(),
    status: 'OPEN',
    assignedTo: null,
    actions: [],
    notes: [],
  };
  state.responseLogs.push(log);
  saveProtectionState(state);
  return log;
}

export function addResponseAction(logId, { kind, reason, performedBy = 'analyst' }) {
  const state = getProtectionState();
  const log = state.responseLogs.find(l => l.id === logId);
  if (!log) return null;
  const action = {
    id: newId('ACT'),
    threatRecordId: log.threatRecordId,
    kind,
    performedBy,
    reason,
    timestamp: new Date().toISOString(),
    detail: reason,
  };
  log.actions.push(action);
  saveProtectionState(state);
  return log;
}

export function updateResponseStatus(logId, status, notes) {
  const state = getProtectionState();
  const log = state.responseLogs.find(l => l.id === logId);
  if (!log) return null;
  log.status = status;
  if (notes) log.notes.push(`${new Date().toISOString()} — ${notes}`);
  saveProtectionState(state);
  return log;
}
