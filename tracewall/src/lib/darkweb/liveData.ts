// ============================================================
// PhishNet — live dataset bridge for the analysis engines.
//
// aiEngine, globalSearch, graphData and graphLookup were written
// against the static seed module. They now read this bridge instead,
// so every correlation, search answer and graph they produce comes
// from the central intelligence dataset — including anything the
// analyst has added, imported, edited or removed.
//
// The collections are live views: they are read at call time, never
// captured at import time, so a page never keeps a stale snapshot.
// ============================================================
import { getDataset } from '../intelligence/dataset';
import type { IntelligenceDataset } from '../intelligence/types';
import type {
  Alert,
  DarkWebSource,
  Evidence,
  Handle,
  Infrastructure,
  Investigation,
  InvestigationStep,
  PgpKey,
  Relationship,
  ThreatActor,
  TimelineEvent,
  Wallet,
} from '../../data/darkWebData';

export type {
  Alert,
  DarkWebSource,
  Evidence,
  Handle,
  Infrastructure,
  Investigation,
  InvestigationStep,
  PgpKey,
  Relationship,
  ThreatActor,
  TimelineEvent,
  Wallet,
};

/**
 * A read-only array view that resolves to the current dataset on access.
 *
 * Array methods must be bound to the resolved array. Without this the proxy
 * would be the `this` receiver, and `has` lookups would fall through to the
 * empty proxy target — so filter/map/slice/forEach silently returned nothing
 * while index access and iteration kept working.
 */
function liveCollection<T>(pick: (dataset: IntelligenceDataset) => T[]): T[] {
  return new Proxy([] as T[], {
    get: (_target, property) => {
      const current = pick(getDataset());
      const value = Reflect.get(current, property, current);
      return typeof value === 'function' ? value.bind(current) : value;
    },
    has: (_target, property) => Reflect.has(pick(getDataset()), property),
  });
}

/** A read-only id map view resolved against the current dataset. */
function liveMap<T>(pick: (dataset: IntelligenceDataset) => Record<string, T>): Record<string, T> {
  return new Proxy({} as Record<string, T>, {
    get: (_target, property) => (typeof property === 'string' ? pick(getDataset())[property] : undefined),
  });
}

export const threatActors = liveCollection<ThreatActor>(dataset => dataset.actors);
export const darkWebActors = threatActors;
export const darkWebHandles = liveCollection<Handle>(dataset => dataset.handles);
export const darkWebPgpKeys = liveCollection<PgpKey>(dataset => dataset.pgpKeys);
export const darkWebWallets = liveCollection<Wallet>(dataset => dataset.wallets);
export const darkWebInfrastructure = liveCollection<Infrastructure>(dataset => dataset.infrastructure);
export const darkWebRelationships = liveCollection<Relationship>(dataset => dataset.relationships);
export const darkWebEvidence = liveCollection<Evidence>(dataset => dataset.evidence);
export const darkWebSources = liveCollection<DarkWebSource>(dataset => dataset.sources);
export const darkWebTimeline = liveCollection<TimelineEvent>(dataset => dataset.timeline);
export const darkWebInvestigations = liveCollection<Investigation>(dataset => dataset.investigations);
export const darkWebAlerts = liveCollection<Alert>(dataset => dataset.alerts);
export const darkWebObservations = liveCollection<IntelligenceDataset['observations'][number]>(dataset => dataset.observations);

// ── Extended intelligence collections ──────────────────────────
// Read through the same live bridge as the legacy records, so ATT&CK,
// vulnerability, crypto and communication intelligence stay connected to
// the single central dataset rather than sitting in a parallel store.
export const darkWebMitreTtps = liveCollection<IntelligenceDataset['mitreTtps'][number]>(dataset => dataset.mitreTtps ?? []);
export const darkWebCves = liveCollection<IntelligenceDataset['cves'][number]>(dataset => dataset.cves ?? []);
export const darkWebVulnerabilities = liveCollection<IntelligenceDataset['vulnerabilities'][number]>(dataset => dataset.vulnerabilities ?? []);
export const darkWebWalletTransactions = liveCollection<IntelligenceDataset['walletTransactions'][number]>(dataset => dataset.walletTransactions ?? []);
export const darkWebWalletClusters = liveCollection<IntelligenceDataset['walletClusters'][number]>(dataset => dataset.walletClusters ?? []);
export const darkWebExchanges = liveCollection<IntelligenceDataset['exchanges'][number]>(dataset => dataset.exchanges ?? []);
export const darkWebCommunicationChannels = liveCollection<IntelligenceDataset['communicationChannels'][number]>(dataset => dataset.communicationChannels ?? []);
export const darkWebCommunicationMessages = liveCollection<IntelligenceDataset['communicationMessages'][number]>(dataset => dataset.communicationMessages ?? []);
export const darkWebMethodologies = liveCollection<IntelligenceDataset['methodologies'][number]>(dataset => dataset.methodologies ?? []);
export const darkWebPlaybooks = liveCollection<IntelligenceDataset['playbooks'][number]>(dataset => dataset.playbooks ?? []);

export const darkWebActorsById = liveMap<ThreatActor>(dataset => dataset.lookups.actorsById);
export const darkWebHandlesById = liveMap<Handle>(dataset => dataset.lookups.handlesById);
export const darkWebPgpKeysById = liveMap(dataset => dataset.lookups.pgpById);
export const darkWebWalletsById = liveMap(dataset => dataset.lookups.walletsById);
export const darkWebEvidenceById = liveMap<Evidence>(dataset => dataset.lookups.evidenceById);
export const darkWebRelationshipsById = liveMap<Relationship>(dataset => dataset.lookups.relationshipsById);
export const darkWebInvestigationById = liveMap<Investigation>(dataset => dataset.lookups.investigationsById);
export const darkWebAlertById = liveMap<Alert>(dataset => dataset.lookups.alertsById);
export const darkWebMitreTtpById = liveMap(dataset => dataset.lookups.mitreTtpsById ?? {});
export const darkWebCveById = liveMap(dataset => dataset.lookups.cvesByCveId ?? {});
export const darkWebExchangesById = liveMap(dataset => dataset.lookups.exchangesById ?? {});
export const darkWebWalletTransactionsById = liveMap(dataset => dataset.lookups.walletTransactionsById ?? {});
export const darkWebCommunicationChannelsById = liveMap(dataset => dataset.lookups.communicationChannelsById ?? {});

/** The live dataset itself, for callers that need more than a collection. */
export { getDataset as liveDataset };
