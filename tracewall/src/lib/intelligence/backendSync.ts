// ============================================================
// PhishNet — Backend synchronization for the intelligence store.
//
// The UI stays local-first and synchronous: every mutation rebuilds
// the in-memory dataset immediately (so no page ever waits) and the
// backend is the authoritative store. This module bridges the two:
//
//   • On mount the backend dataset is pulled into the local cache
//     (server → UI). If the backend was never seeded, the current
//     local dataset is pushed once so the stores become identical.
//   • After any local mutation the full snapshot is reconciled into
//     the backend (UI → server), debounced, through the normalized
//     reconcile endpoint.
//   • A poll + focus handler keeps a long-lived tab in sync when
//     another tab or the seed pipeline changes the backend.
//   • A cleared local dataset clears the backend; demo load/reset
//     simply reconcile the demo snapshot, Additive-only by design.
//   • If the API process is unreachable the app keeps working from
//     the local cache exactly as before.
//
// Reconciliation is additive (it never deletes backend records a
// snapshot does not mention), so an older cache can never wipe newer
// intelligence another tab wrote. Reset / Clear remain explicit.
// ============================================================
import { getDataset, replaceDataset, subscribe } from './dataset';
import { request } from '../mockBackend';
import type { IntelligenceDataset } from './types';

const DATASET_URL = '/intel/dataset';
const RECONCILE_URL = '/intel/reconcile';
const CLEAR_URL = '/intel/dataset/clear';
const PUSH_DEBOUNCE_MS = 1200;
const POLL_MS = 30000;

/**
 * The backend serializes every frontend field except the derived
 * id lookups; `replaceDataset` recomputes those locally.
 */
type ServerDataset = Omit<IntelligenceDataset, 'lookups'>;

interface ReconcileEnvelope {
  status: string;
  counts: Record<string, number>;
  dataset: ServerDataset;
}

let started = false;
/** Guards against echoing a server-applied dataset straight back up. */
let applying = false;
/** The last backend revision we applied, so polls act only on changes. */
let lastServerRevision: number | null = null;
/** True once we have observed a seeded (non-empty) backend. */
let backendInitialized = false;
let debounce: ReturnType<typeof setTimeout> | null = null;
let teardown: (() => void) | null = null;

function hasRows(dataset: IntelligenceDataset | ServerDataset): boolean {
  return (
    dataset.actors.length +
      dataset.handles.length +
      dataset.pgpKeys.length +
      dataset.wallets.length +
      dataset.infrastructure.length +
      // A backend seeded only with extended intelligence is still a seeded
      // backend, so it must not be treated as empty and overwritten.
      (dataset.mitreTtps?.length ?? 0) +
      (dataset.cves?.length ?? 0) +
      (dataset.walletTransactions?.length ?? 0) +
      (dataset.communicationChannels?.length ?? 0) >
    0
  );
}

async function getRemoteDataset(): Promise<ServerDataset> {
  const envelope = await request<{ data: ServerDataset }>(DATASET_URL);
  return envelope.data;
}

/** Keep frontend-only data (reports, local audit, triage state) over the server copy. */
function mergeServer(current: IntelligenceDataset, server: ServerDataset): ServerDataset {
  return {
    ...server,
    reports: current.reports,
    audit: mergeUnique(current.audit, server.audit),
    alerts: mergeUnique(current.alerts, server.alerts),
    notes: mergeUnique(current.notes, server.notes),
    monitoring: current.monitoring,
  };
}

function mergeUnique<T extends { id: string }>(...groups: T[][]): T[] {
  const byId = new Map<string, T>();
  for (const group of groups) {
    for (const item of group) {
      if (!byId.has(item.id)) byId.set(item.id, item);
    }
  }
  return [...byId.values()];
}

/** Write a server snapshot into the local cache (rebuilds lookups + revision). */
function applyServerDataset(server: ServerDataset): void {
  applying = true;
  try {
    replaceDataset(mergeServer(getDataset(), server) as IntelligenceDataset, { persist: true });
    lastServerRevision = server.revision ?? null;
  } finally {
    applying = false;
  }
}

/** Reconcile the current local snapshot into the backend. */
async function pushDataset(): Promise<void> {
  const current = getDataset();
  if (!hasRows(current)) return;
  const envelope = await request<{ data: ReconcileEnvelope }>(RECONCILE_URL, {
    method: 'POST',
    body: JSON.stringify({ dataset: current }),
  });
  applyServerDataset(envelope.data.dataset);
}

/** Backend clear — local store is already emptied by the UI's clearDataset(). */
async function clearRemote(): Promise<void> {
  await request(CLEAR_URL, { method: 'POST' });
}

/**
 * Pull server → UI. On first contact with an empty backend the local
 * cache seeds it once, so a fresh browser shows exactly what it built.
 * A later empty backend (an explicit clear) propagates to this tab.
 */
async function syncFromServer(): Promise<void> {
  try {
    const server = await getRemoteDataset();
    if (hasRows(server)) {
      backendInitialized = true;
      if (server.revision !== lastServerRevision) applyServerDataset(server);
      return;
    }
    if (backendInitialized) {
      if (server.revision !== lastServerRevision) applyServerDataset(server);
      return;
    }
    await pushDataset();
    backendInitialized = true;
  } catch {
    /* API unreachable — keep the local cache and retry on the next tick. */
  }
}

/** After any local mutation, mirror it to the backend (debounced). */
function schedulePush(): void {
  if (applying) return;
  if (debounce) clearTimeout(debounce);
  debounce = setTimeout(() => {
    debounce = null;
    const current = getDataset();
    if (hasRows(current)) {
      void pushDataset().catch(() => {});
    } else {
      void clearRemote().catch(() => {});
    }
  }, PUSH_DEBOUNCE_MS);
}

export function startBackendSync(): () => void {
  if (started) return teardown ?? (() => undefined);
  started = true;

  const unsubscribe = subscribe(schedulePush);
  const interval = setInterval(() => void syncFromServer(), POLL_MS);
  const onFocus = () => void syncFromServer();

  if (typeof window !== 'undefined') window.addEventListener('focus', onFocus);
  void syncFromServer().catch(() => {});

  teardown = () => {
    unsubscribe();
    clearInterval(interval);
    if (typeof window !== 'undefined') window.removeEventListener('focus', onFocus);
    if (debounce) clearTimeout(debounce);
    started = false;
    teardown = null;
  };
  return teardown;
}

export function stopBackendSync(): void {
  teardown?.();
}