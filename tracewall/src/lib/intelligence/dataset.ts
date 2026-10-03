// ============================================================
// PhishNet — Live central intelligence store.
//
// A single observable dataset instance. Mutations go through
// `updateDataset`, which rebuilds every id lookup and notifies all
// subscribers, so search, dashboard, graph, timeline, evidence,
// investigations, alerts, AI and reports all refresh from the same
// records after a single write.
//
// Persistence is local-first (so the app works with or without the
// API process running) and mirrored to the backend when reachable.
// ============================================================
import { buildDemoDataset, rebuildLookups } from './demoDataset';
import type { IntelligenceDataset, IntelligenceAuditEvent, ActivityKind } from './types';

const STORAGE_KEY = 'phishnet-intelligence-dataset-v1';

type Listener = () => void;

let current: IntelligenceDataset = loadInitial();
const listeners = new Set<Listener>();

function loadInitial(): IntelligenceDataset {
  if (typeof window === 'undefined') return buildDemoDataset();
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as IntelligenceDataset;
      if (parsed && Array.isArray(parsed.actors)) {
        return rebuildLookups({ ...parsed, revision: parsed.revision ?? 0 });
      }
    }
  } catch {
    /* corrupted local cache — fall through to the demo dataset */
  }
  return buildDemoDataset();
}

function persist(dataset: IntelligenceDataset): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(dataset));
  } catch {
    /* storage unavailable (private mode / quota) — in-memory state still holds */
  }
}

function notify(): void {
  for (const listener of listeners) listener();
}

export function getDataset(): IntelligenceDataset {
  return current;
}

export function subscribe(listener: Listener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** The only sanctioned write path. Immutably produces the next dataset. */
export function updateDataset(
  mutate: (draft: IntelligenceDataset) => IntelligenceDataset | void,
  options: { persist?: boolean } = {},
): IntelligenceDataset {
  const draft = mutate(current) ?? current;
  const next = rebuildLookups({
    ...draft,
    revision: (draft.revision ?? 0) + 1,
    updatedAt: new Date().toISOString(),
  });
  current = next;
  if (options.persist !== false) persist(next);
  notify();
  return next;
}

export function replaceDataset(dataset: IntelligenceDataset, options: { persist?: boolean } = {}): IntelligenceDataset {
  const next = rebuildLookups({
    ...dataset,
    revision: (current.revision ?? 0) + 1,
    updatedAt: new Date().toISOString(),
  });
  current = next;
  if (options.persist !== false) persist(next);
  notify();
  return next;
}

// ── Demo dataset controls ──────────────────────────────────────
export function loadDemoDataset(): IntelligenceDataset {
  return replaceDataset(buildDemoDataset());
}

export function resetDemoDataset(): IntelligenceDataset {
  return replaceDataset(buildDemoDataset());
}

export function clearDataset(): IntelligenceDataset {
  const empty = buildDemoDataset();
  return replaceDataset({
    ...empty,
    isDemoLoaded: false,
    actors: [],
    handles: [],
    pgpKeys: [],
    wallets: [],
    infrastructure: [],
    sources: [],
    observations: [],
    relationships: [],
    evidence: [],
    timeline: [],
    investigations: [],
    alerts: [],
    reports: [],
    audit: [],
    notes: [],
    // Extended collections must be cleared too, otherwise a cleared dataset
    // would keep reporting ATT&CK, CVE and crypto intelligence.
    mitreTtps: [],
    cves: [],
    vulnerabilities: [],
    walletTransactions: [],
    walletClusters: [],
    exchanges: [],
    communicationChannels: [],
    communicationMessages: [],
    methodologies: [],
    playbooks: [],
    monitoring: {
      status: 'PAUSED',
      lastCollection: new Date().toISOString(),
      nextCollection: new Date().toISOString(),
      sourcesMonitored: 0,
      newIndicators: 0,
      newActors: 0,
      newRelationships: 0,
      alerts: 0,
    },
  });
}

export function exportDataset(): IntelligenceDataset {
  return getDataset();
}

export function refreshDataset(): IntelligenceDataset {
  notify();
  return current;
}

// ── Audit / activity ───────────────────────────────────────────
let auditCounter = 0;

export function createAuditEvent(
  action: IntelligenceAuditEvent['action'],
  entity: string,
  entityId: string,
  after: string,
  actor = 'Analyst',
  source = 'Central Intelligence Model',
  result: IntelligenceAuditEvent['result'] = 'SUCCESS',
  before = '—',
): IntelligenceAuditEvent {
  auditCounter += 1;
  return {
    id: `AUD-INT-${Date.now().toString(36).toUpperCase()}-${auditCounter}`,
    time: new Date().toISOString(),
    actor,
    action,
    entity,
    entityId,
    before,
    after,
    source,
    result,
    outcome: result,
    ip: 'SESSION',
  };
}

/** Human labels for the shared activity feed. */
export const ACTIVITY_LABEL: Record<string, string> = {
  ACTOR_CREATED: 'New Actor Added',
  HANDLE_ADDED: 'New Handle Observed',
  PGP_ADDED: 'PGP Correlation Created',
  WALLET_ADDED: 'Wallet Indicator Added',
  INFRASTRUCTURE_ADDED: 'Infrastructure Updated',
  SOURCE_ADDED: 'Source Registered',
  OBSERVATION_ADDED: 'Observation Recorded',
  EVIDENCE_ADDED: 'Evidence Added',
  RELATIONSHIP_CREATED: 'Relationship Discovered',
  INVESTIGATION_CREATED: 'Investigation Created',
  ALERT_CREATED: 'Alert Generated',
  TIMELINE_EVENT_ADDED: 'Timeline Event Added',
  IMPORT_COMPLETED: 'Import Completed',
  DEMO_DATASET_LOADED: 'Demo Dataset Loaded',
  DEMO_DATASET_RESET: 'Demo Dataset Reset',
  DEMO_DATASET_CLEARED: 'Demo Dataset Cleared',
  DATASET_EXPORTED: 'Intelligence Exported',
};

export type { ActivityKind };
