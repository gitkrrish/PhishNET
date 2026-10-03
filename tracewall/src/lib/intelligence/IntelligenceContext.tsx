// ============================================================
// PhishNet — React binding for the central intelligence model.
//
// The store itself lives in `dataset.ts` and is framework-agnostic.
// This provider exposes it to the UI exactly once, so every page,
// panel, chart, search box and AI answer reads the same records and
// re-renders from a single write — with no page-level copy of the
// data and no second source of truth.
// ============================================================
import { createContext, useContext, useEffect, useMemo, useSyncExternalStore, type ReactNode } from 'react';
import type { Node, Edge } from '@xyflow/react';
import {
  getDataset,
  subscribe,
  loadDemoDataset,
  resetDemoDataset,
  clearDataset,
  exportDataset,
} from './dataset';
import { startBackendSync } from './backendSync';
import {
  threatPosture,
  protectionRecords,
  isEntityBlocked,
  blockIndicator,
  unblockIndicator,
  createResponseLog,
  addResponseAction,
  updateResponseStatus,
  getProtectionSnapshot,
  subscribeProtection,
  computeEntityScore,
  responseActionRecords,
  recordResponseAction,
  clearEnforcementFor,
  enforcementVerdict,
} from './protection';
import type {
  ThreatPosture,
  ThreatProtectionRecord,
  BlockedIndicator,
  ResponseLog,
  ResponseActionRecord,
  ResponseActionKind,
  ResponseActionStatus,
  EnforcementChannelKey,
} from './types-protection';
import {
  activityFeed,
  actorBundle,
  actorTimeline,
  buildIntelligenceGraph,
  dashboardMetrics,
  evidenceChain,
  investigationBundle,
  resolveEntityValue,
  whyLinked,
  type ActorBundle,
  type DashboardMetrics,
  type EvidenceChainStep,
  type GraphFilters,
  type WhyLinked,
} from './derive';
import {
  addActor,
  addEvidence,
  addHandle,
  addInfrastructure,
  addInvestigation,
  addNote,
  addObservation,
  addPgp,
  addRelationship,
  addSource,
  addTimelineEvent,
  addWallet,
  attachToInvestigation,
  addMitreTtp,
  linkActorToMitreTtp,
  addCve,
  linkCveToInfrastructure,
  addWalletTransaction,
  addWalletCluster,
  linkWalletToExchange,
  entityTypeOf,
  importDatasetJson,
  type MutationResult,
} from './mutations';
import type { IntelligenceDataset, ActivityItem } from './types';

export interface IntelligenceApi {
  /** The single live dataset. Every module reads from here. */
  dataset: IntelligenceDataset;
  /**
   * Monotonic counter that changes on every committed write. Use it as a
   * `useMemo` dependency when a component calls a helper that reads the
   * dataset at call time (for example `globalSearch`) and therefore cannot
   * depend on one of the collections directly.
   */
  revision: number;
  metrics: DashboardMetrics;
  activity: ActivityItem[];
  isDemoLoaded: boolean;
  demoLabel: string;
  storageKey: string;

  // ── selectors ──────────────────────────────────────────────
  getActorBundle: (ref: string) => ActorBundle | null;
  getTimeline: (actorId?: string) => IntelligenceDataset['timeline'];
  getWhyLinked: (sourceId: string, targetId: string) => WhyLinked;
  getEvidenceChain: (evidenceId: string) => EvidenceChainStep[];
  getInvestigation: (investigationId: string) => ReturnType<typeof investigationBundle>;
  getGraph: (seed?: string, filters?: GraphFilters) => { nodes: Node[]; edges: Edge[] };
  resolveValue: (value: string) => ReturnType<typeof resolveEntityValue>;
  typeOf: (entityId: string) => string;

  // ── mutations (one analyst action fans out everywhere) ────
  createActor: typeof addActor;
  createHandle: typeof addHandle;
  createPgp: typeof addPgp;
  createWallet: typeof addWallet;
  createInfrastructure: typeof addInfrastructure;
  createSource: typeof addSource;
  createObservation: typeof addObservation;
  createEvidence: typeof addEvidence;
  createRelationship: typeof addRelationship;
  createTimelineEvent: typeof addTimelineEvent;
  createInvestigation: typeof addInvestigation;
  attachEntity: typeof attachToInvestigation;
  createNote: typeof addNote;

  // ── extended intelligence (ATT&CK, vulnerability, crypto) ──
  createMitreTtp: typeof addMitreTtp;
  linkMitreTtp: typeof linkActorToMitreTtp;
  createCve: typeof addCve;
  linkCve: typeof linkCveToInfrastructure;
  createWalletTransaction: typeof addWalletTransaction;
  createWalletCluster: typeof addWalletCluster;
  linkWalletExchange: typeof linkWalletToExchange;

  // ── dataset controls ───────────────────────────────────────
  loadDemo: typeof loadDemoDataset;
  resetDemo: typeof resetDemoDataset;
  clearData: typeof clearDataset;
  exportData: typeof exportDataset;
  importData: typeof importDatasetJson;
}

/**
 * Active protection and response API.
 *
 * Threat *scores* are derived from the central dataset on every read;
 * analyst *decisions and their outcomes* are persisted and mirrored to the
 * backend. `PROTECTED` is only ever reached when a configured, authorised
 * integration confirms the control — see `enforcement.ts`.
 */
export interface ProtectionApi {
  posture: ThreatPosture;
  records: ThreatProtectionRecord[];
  blockedIndicators: BlockedIndicator[];
  responseLogs: ResponseLog[];
  responseActions: ResponseActionRecord[];
  scoreEntity: (entityType: string, entityId: string) => ReturnType<typeof computeEntityScore>;
  isBlocked: (entityId: string) => boolean;
  verdictFor: (entityId: string) => ReturnType<typeof enforcementVerdict>;
  blockIndicator: typeof blockIndicator;
  unblockIndicator: typeof unblockIndicator;
  createResponseLog: typeof createResponseLog;
  addResponseAction: typeof addResponseAction;
  updateResponseStatus: typeof updateResponseStatus;
  recordAction: (input: {
    entityType: string;
    entityId: string;
    entityValue: string;
    kind: ResponseActionKind;
    status: ResponseActionStatus;
    channel: EnforcementChannelKey | null;
    detail: string;
    performedBy?: string;
    confirmedAt?: string | null;
  }) => ResponseActionRecord;
  clearEnforcement: typeof clearEnforcementFor;
  actionsFor: (entityId?: string) => ResponseActionRecord[];
  refresh: () => void;
}

const IntelligenceContext = createContext<IntelligenceApi | null>(null);

export const INTELLIGENCE_STORAGE_KEY = 'phishnet-intelligence-dataset-v1';

export function useProtection(): ProtectionApi {
  const { dataset } = useIntelligence();
  // Persisted analyst actions (decisions / response tickets) are reactive on
  // their own store; derived threat records rebuild from the dataset.
  const protectionStore = useSyncExternalStore(subscribeProtection, getProtectionSnapshot, getProtectionSnapshot);
  return useMemo<ProtectionApi>(
    () => ({
      posture: threatPosture(dataset),
      records: protectionRecords(dataset),
      blockedIndicators: protectionStore.blocked,
      responseLogs: protectionStore.logs,
      responseActions: protectionStore.actions,
      scoreEntity: (entityType, entityId) => computeEntityScore(entityType, entityId, dataset, dataset.lookups),
      isBlocked: isEntityBlocked,
      verdictFor: enforcementVerdict,
      blockIndicator,
      unblockIndicator,
      createResponseLog,
      addResponseAction,
      updateResponseStatus,
      recordAction: recordResponseAction,
      clearEnforcement: clearEnforcementFor,
      actionsFor: responseActionRecords,
      refresh: () => threatPosture(dataset),
    }),
    // `dataset` reference changes on every committed write (it bumps
    // dataset.revision); `protectionStore` reference changes on every
    // analyst protection action. Both are stable between changes.
    [dataset, protectionStore],
  );
}

export function IntelligenceProvider({ children }: { children: ReactNode }) {
  const dataset = useSyncExternalStore(subscribe, getDataset, getDataset);
  const revision = dataset.revision;

  // The backend is authoritative; the local cache mirrors it. The sync
  // layer does not change any exposed selector or mutation contract.
  useEffect(() => startBackendSync(), []);

  const value = useMemo<IntelligenceApi>(
    () => ({
      dataset,
      revision,
      metrics: dashboardMetrics(dataset),
      activity: activityFeed(dataset),
      isDemoLoaded: dataset.isDemoLoaded,
      demoLabel: dataset.demoLabel,
      storageKey: INTELLIGENCE_STORAGE_KEY,

      getActorBundle: ref => actorBundle(dataset, ref),
      getTimeline: actorId => actorTimeline(dataset, actorId),
      getWhyLinked: (sourceId, targetId) => whyLinked(dataset, sourceId, targetId),
      getEvidenceChain: evidenceId => evidenceChain(dataset, evidenceId),
      getInvestigation: investigationId => investigationBundle(dataset, investigationId),
      getGraph: (seed, filters) => buildIntelligenceGraph(dataset, seed, filters),
      resolveValue: value_ => resolveEntityValue(dataset, value_),
      typeOf: entityId => entityTypeOf(dataset, entityId),

      createActor: addActor,
      createHandle: addHandle,
      createPgp: addPgp,
      createWallet: addWallet,
      createInfrastructure: addInfrastructure,
      createSource: addSource,
      createObservation: addObservation,
      createEvidence: addEvidence,
      createRelationship: addRelationship,
      createTimelineEvent: addTimelineEvent,
      createInvestigation: addInvestigation,
      attachEntity: attachToInvestigation,
      createNote: addNote,
  createMitreTtp: addMitreTtp,
  linkMitreTtp: linkActorToMitreTtp,
  createCve: addCve,
  linkCve: linkCveToInfrastructure,
  createWalletTransaction: addWalletTransaction,
  createWalletCluster: addWalletCluster,
  linkWalletExchange: linkWalletToExchange,

      loadDemo: loadDemoDataset,
      resetDemo: resetDemoDataset,
      clearData: clearDataset,
      exportData: exportDataset,
      importData: importDatasetJson,
    }),
    [dataset, revision],
  );

  return <IntelligenceContext.Provider value={value}>{children}</IntelligenceContext.Provider>;
}

export function useIntelligence(): IntelligenceApi {
  const value = useContext(IntelligenceContext);
  if (!value) {
    throw new Error('useIntelligence must be used inside <IntelligenceProvider>');
  }
  return value;
}

/**
 * The central collections under their original names.
 *
 * Existing pages destructure the same identifiers they always used, so
 * the rendered output is unchanged — but the values now come from the
 * live dataset and every write re-renders the page automatically.
 */
export function useIntelligenceData() {
  const { dataset } = useIntelligence();
  return useMemo(
    () => ({
      darkWebActors: dataset.actors,
      darkWebHandles: dataset.handles,
      darkWebPgpKeys: dataset.pgpKeys,
      darkWebWallets: dataset.wallets,
      darkWebInfrastructure: dataset.infrastructure,
      darkWebSources: dataset.sources,
      darkWebRelationships: dataset.relationships,
      darkWebEvidence: dataset.evidence,
      darkWebTimeline: dataset.timeline,
      darkWebInvestigations: dataset.investigations,
      darkWebAlerts: dataset.alerts,
      darkWebObservations: dataset.observations,
      darkWebNotes: dataset.notes,
      darkWebReports: dataset.reports,
      darkWebMonitoring: dataset.monitoring,
      darkWebAudit: dataset.audit,
      darkWebActorsById: dataset.lookups.actorsById,
      darkWebHandlesById: dataset.lookups.handlesById,
      darkWebPgpKeysById: dataset.lookups.pgpById,
      darkWebWalletsById: dataset.lookups.walletsById,
      darkWebEvidenceById: dataset.lookups.evidenceById,
      darkWebRelationshipsById: dataset.lookups.relationshipsById,
      darkWebInvestigationById: dataset.lookups.investigationsById,
      darkWebAlertById: dataset.lookups.alertsById,
      lookups: dataset.lookups,
    }),
    [dataset],
  );
}

export type { MutationResult };
