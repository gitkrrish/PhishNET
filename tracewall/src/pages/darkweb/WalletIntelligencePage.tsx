import { useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
  Wallet, Search, Users, Database, Clock, Network, FileText, Globe,
  Layers, Key, ArrowLeftRight, Boxes, Landmark, ShieldAlert, Activity, BadgeCheck, ShieldX,
} from 'lucide-react';
import { dw, sectionStyle } from '../../lib/darkweb/styles';
import { useIntelligence } from '../../lib/intelligence/IntelligenceContext';
import { walletBundle, walletPath, actorPath, handlePath, pgpPath, ENTITY_PATH } from '../../lib/intelligence/entityBundles';
import { cryptoBundle, type CryptoBundle } from '../../lib/intelligence/crypto';
import { ConfidenceBar } from '../../components/ui/ConfidenceBar';
import { RelationshipChip } from '../../components/darkweb/RelationshipChip';
import {
  EntityLink, EntityPageHeader, EntityRow, EntitySection,
  EmptyNote, EmptySelection, MetaCell, RecordEntityLink,
  entityInputClass, entityInputStyle, selectStyle,
} from '../../components/darkweb/EntityWorkspace';
import { ProtectionModulePanel } from '../../components/darkweb/ProtectionModulePanel';

// ============================================================
// Crypto Wallet Intelligence.
//
// A wallet address is a linking indicator rather than an identity:
// addresses are shared deliberately, and mixed or clustered. The
// workspace therefore reads as a chain-of-funds view — who holds
// the address, what else they hold, which transactions the model
// already holds against it, and which exchanges or clusters it sits
// in. Nothing here moves funds; it is analysis of records already
// stored in the central model.
// ============================================================
// ============================================================
// Address validation panel.
//
// A malformed address is one of the few objective facts available
// about a payment identifier, so it is reported plainly. What the
// check cannot establish is stated too: a well-formed address
// proves nothing about who controls it, and where a checksum needs
// Keccak-256 the result is reported as unverified rather than
// guessed at.
// ============================================================
function AddressValidationPanel({ chain }: { chain: CryptoBundle }) {
  const { addressCheck } = chain;
  const tone = addressCheck.verdict === 'VALID' ? dw.moss : addressCheck.verdict === 'FORMAT_UNKNOWN' ? dw.faint : dw.critical;
  const Icon = addressCheck.verdict === 'VALID' ? BadgeCheck : addressCheck.verdict === 'FORMAT_UNKNOWN' ? ShieldAlert : ShieldX;

  return (
    <div className="p-3 rounded-sm border space-y-2" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
      <div className="flex items-center justify-between gap-2">
        <span className="flex items-center gap-1.5 font-mono text-[10px] tracking-wider uppercase" style={tone}>
          <Icon size={12} /> {addressCheck.verdict.replace(/_/g, ' ')}
        </span>
        {addressCheck.detected && (
          <span className="font-mono text-[9px] px-1.5 py-0.5 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)', color: 'var(--tw-text-muted)' }}>
            detected: {addressCheck.detected}
          </span>
        )}
      </div>
      <p className="font-mono text-[10px] leading-relaxed" style={dw.muted}>{addressCheck.detail}</p>
      {chain.networkMismatch && (
        <p className="font-mono text-[10px] leading-relaxed" style={dw.critical}>
          The record labels this address &ldquo;{chain.declaredNetwork}&rdquo; but its format is {addressCheck.detected}.
          A single address does not exist on two networks, so one of the two fields is wrong — most often the
          label was copied from an associated cluster rather than from the address itself.
        </p>
      )}
      {addressCheck.verified && (
        <p className="font-mono text-[9px]" style={dw.faint}>verified: {addressCheck.verified}</p>
      )}
    </div>
  );
}

export default function WalletIntelligencePage() {
  const { dataset } = useIntelligence();
  const [search, setSearch] = useState('');
  const [networkFilter, setNetworkFilter] = useState<string>('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const networkOf = (address: string, network?: string) =>
    network || (address.startsWith('bc1') ? 'BTC' : address.startsWith('0x') ? 'ETH' : 'UNSPECIFIED');

  const networks = useMemo(
    () => Array.from(new Set(dataset.wallets.map(item => networkOf(item.address, item.network)))).sort(),
    [dataset.wallets],
  );

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    return dataset.wallets.filter(wallet => {
      if (networkFilter !== 'all' && networkOf(wallet.address, wallet.network) !== networkFilter) return false;
      if (!query) return true;
      return (
        wallet.address.toLowerCase().includes(query) ||
        wallet.id.toLowerCase().includes(query) ||
        wallet.actorIds.some(id => id.toLowerCase().includes(query))
      );
    });
  }, [dataset.wallets, search, networkFilter]);

  const selectedRef = selectedId ?? filtered[0]?.id ?? dataset.wallets[0]?.id ?? null;
  const bundle = useMemo(
    () => (selectedRef ? walletBundle(dataset, selectedRef) : null),
    [dataset, selectedRef],
  );
  // Address validation, flow statistics and privacy indicators are derived
  // independently of the wallet bundle so the two can disagree — that
  // disagreement is itself a signal worth showing.
  const chain = useMemo(
    () => (selectedRef ? cryptoBundle(dataset, selectedRef) : null),
    [dataset, selectedRef],
  );

  const sharedWallets = dataset.wallets.filter(item => item.actorIds.length > 1);
  const totalTx = dataset.wallets.reduce((sum, item) => sum + (item.txCount ?? 0), 0);

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">

        <EntityPageHeader
          icon={<Wallet size={18} style={dw.critical} />}
          eyebrow="Cryptocurrency Intelligence"
          title="Crypto Wallet Intelligence"
          byline="Every payment address recorded through Add Intelligence. A wallet is a linking indicator rather than an identity, so the analysis is a chain-of-funds view: who holds the address, what else they hold, and which transactions, clusters and exchanges the model already holds against it. This is read-only analysis — no transaction is ever executed from here."
          stats={[
            { label: 'Wallets', value: dataset.wallets.length },
            { label: 'Shared addresses', value: sharedWallets.length, color: dw.burg },
            { label: 'Observed transactions', value: totalTx },
          ]}
        />

        <div className="flex flex-col md:flex-row gap-3 items-center justify-between">
          <div className="relative w-full md:w-80">
            <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: 'var(--tw-text-faint)' }} />
            <input
              value={search}
              onChange={event => setSearch(event.target.value)}
              placeholder="Search address, wallet id or actor…"
              className={entityInputClass}
              style={entityInputStyle}
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[10px]" style={dw.faint}>NETWORK:</span>
            <select
              value={networkFilter}
              onChange={event => setNetworkFilter(event.target.value)}
              className="font-mono text-[10px] px-2 py-1.5 rounded-sm focus:outline-none"
              style={selectStyle}
            >
              <option value="all">ALL NETWORKS</option>
              {networks.map(network => <option key={network} value={network}>{network}</option>)}
            </select>
            <RecordEntityLink to="/app/darkweb/add" label="+ Record wallet" />
          </div>
        </div>

        <div className="grid lg:grid-cols-12 gap-6">
          <div className="lg:col-span-5 space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>WALLET RECORDS ({filtered.length})</span>
              <span className="font-mono text-[9px]" style={dw.faint}>CLICK TO INSPECT</span>
            </div>
            <div className="space-y-2 max-h-[620px] overflow-y-auto pr-1">
              {filtered.map(item => (
                <EntityRow key={item.id} selected={bundle?.wallet.id === item.id} onClick={() => setSelectedId(item.id)}>
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5 mb-1">
                        <span className="font-mono text-[9px] uppercase px-1 py-0.5 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)', color: 'var(--tw-text-muted)' }}>
                          {item.id}
                        </span>
                        {item.actorIds.length > 1 && (
                          <span className="font-mono text-[9px] uppercase px-1 py-0.5 rounded-sm" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-info) 18%, transparent)', color: 'var(--tw-info)' }}>
                            SHARED ×{item.actorIds.length}
                          </span>
                        )}
                      </div>
                      <p className="font-mono text-[11px] font-medium truncate" style={dw.text}>{item.address}</p>
                    </div>
                    <span className="font-mono text-[9px] shrink-0" style={dw.faint}>{item.confidence}%</span>
                  </div>
                  <div className="flex items-center justify-between mt-2 pt-2 border-t font-mono text-[9px]" style={{ borderColor: 'var(--tw-border-mid)' }}>
                    <span style={dw.muted}>{networkOf(item.address, item.network)} · {item.txCount} tx</span>
                    <span style={item.actorIds.length ? dw.burg : dw.faint}>{item.actorIds.join(', ') || 'unattributed'}</span>
                  </div>
                </EntityRow>
              ))}
              {filtered.length === 0 && (
                <p className="font-mono text-[10px] p-4 rounded-sm border" style={{ ...dw.panel, ...dw.muted }}>
                  No wallet matches the current filter.
                </p>
              )}
            </div>
          </div>

          <div className="lg:col-span-7 space-y-4">
            {bundle ? (
              <>
                <div className="rounded-sm border p-5 space-y-4" style={dw.panel}>
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[10px] tracking-wider uppercase" style={dw.info}>{bundle.wallet.id}</span>
                        <span className="font-mono text-[9px] px-1.5 py-0.5 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)', color: 'var(--tw-text-muted)' }}>
                          {bundle.network}
                        </span>
                        {bundle.wallet.dataState && (
                          <span className="font-mono text-[9px] uppercase" style={dw.faint}>{bundle.wallet.dataState.replace(/_/g, ' ')}</span>
                        )}
                      </div>
                      <h2 className="font-mono text-sm font-bold mt-1 break-all" style={dw.text}>{bundle.wallet.address}</h2>
                    </div>
                    <Link
                      to={walletPath(bundle.wallet.id)}
                      className="font-mono text-[10px] tracking-wider uppercase px-2.5 py-1.5 rounded-sm border shrink-0"
                      style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-burgundy)' }}
                    >
                      Open dossier
                    </Link>
                  </div>

                  <div className="grid sm:grid-cols-4 gap-3 p-3 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)' }}>
                    <MetaCell label="Network" value={bundle.network} />
                    <MetaCell label="First seen" value={new Date(bundle.wallet.firstSeen).toLocaleDateString()} />
                    <MetaCell label="Last seen" value={new Date(bundle.wallet.lastSeen).toLocaleDateString()} />
                    <MetaCell label="Transactions" value={bundle.wallet.txCount} />
                  </div>

                  {chain && <AddressValidationPanel chain={chain} />}

                  <div className="space-y-1">
                    <ConfidenceBar value={bundle.wallet.confidence} />
                    <p className="font-mono text-[9px]" style={dw.faint}>Attribution confidence carried on the central wallet record.</p>
                  </div>

                  <div className="flex flex-wrap gap-2 pt-1">
                    {bundle.actors.map(actor => (
                      <EntityLink key={actor.id} to={actorPath(actor.id)}>
                        <Users size={10} /> {actor.id} — {actor.aliases[0] ?? actor.id}
                      </EntityLink>
                    ))}
                    {bundle.handles.map(handle => (
                      <EntityLink key={handle.id} to={handlePath(handle.id)}>
                        @{handle.value}
                      </EntityLink>
                    ))}
                    {bundle.pgpKeys.map(key => (
                      <EntityLink key={key.id} to={pgpPath(key.id)} accent="var(--tw-brass)">
                        <Key size={10} /> {key.id}
                      </EntityLink>
                    ))}
                    <EntityLink to={`${ENTITY_PATH.graph}?focus=${encodeURIComponent(bundle.wallet.id)}`} accent="var(--tw-text-muted)">
                      <Network size={10} /> Graph
                    </EntityLink>
                  </div>
                </div>

                <EntitySection
                  icon={<ArrowLeftRight size={13} style={dw.critical} />}
                  title={`Related transactions (${bundle.transactions.length})`}
                  aside={<span className="font-mono text-[9px] uppercase" style={dw.faint}>RECORDED IN MODEL</span>}
                >
                  {bundle.transactions.length > 0 ? (
                    <div className="space-y-2">
                      {bundle.transactions.slice(0, 8).map(tx => (
                        <div key={tx.id} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                          <div className="flex items-center justify-between gap-2">
                            <span style={tx.direction === 'IN' ? dw.moss : dw.medium}>
                              {tx.direction} · {tx.amount} {tx.currency}
                            </span>
                            <span style={dw.faint}>{new Date(tx.timestamp).toLocaleString()}</span>
                          </div>
                          <p className="mt-1 break-all" style={dw.text}>{tx.hash}</p>
                          <p className="mt-0.5" style={dw.muted}>
                            {tx.status} · {tx.confirmations} confirmations{tx.isFlagged ? ' · FLAGGED' : ''}
                          </p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <EmptyNote>
                      No transaction-level records are stored against this address. The wallet record carries
                      an observed transaction count ({bundle.wallet.txCount}) only.
                    </EmptyNote>
                  )}
                </EntitySection>

                <div className="grid md:grid-cols-2 gap-4">
                  <EntitySection icon={<Boxes size={13} style={dw.critical} />} title={`Related wallets (${bundle.relatedWallets.length})`}>
                    {bundle.relatedWallets.length > 0 ? (
                      <div className="space-y-2">
                        {bundle.relatedWallets.map(item => (
                          <Link
                            key={item.id}
                            to={walletPath(item.id)}
                            className="block p-2.5 rounded-sm border font-mono text-[10px]"
                            style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}
                          >
                            <p className="break-all" style={dw.text}>{item.address}</p>
                            <p className="mt-0.5" style={dw.faint}>{item.id} · {item.txCount} tx · {item.confidence}%</p>
                          </Link>
                        ))}
                      </div>
                    ) : (
                      <EmptyNote>No other address is attributed to the same actor.</EmptyNote>
                    )}
                  </EntitySection>

                  <EntitySection icon={<Users size={13} style={dw.critical} />} title={`Clusters & exchanges`}>
                    <div className="space-y-2">
                      {bundle.clusters.length > 0 ? bundle.clusters.map(cluster => (
                        <div key={cluster.id} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                          <p style={dw.text}>{cluster.id} · {cluster.method}</p>
                          <p className="mt-0.5" style={dw.muted}>{cluster.reasoning}</p>
                          <p className="mt-0.5" style={dw.faint}>{cluster.confidence}% · {cluster.totalTransactions} tx</p>
                        </div>
                      )) : <EmptyNote>No wallet cluster is recorded for this address.</EmptyNote>}
                      {bundle.exchanges.length > 0 ? bundle.exchanges.map(exchange => (
                        <div key={exchange.id} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                          <p className="flex items-center gap-1.5" style={dw.text}><Landmark size={11} /> {exchange.name}</p>
                          <p className="mt-0.5" style={dw.faint}>{exchange.type} · {exchange.jurisdiction ?? 'unknown'} · {exchange.confidence}%</p>
                        </div>
                      )) : <EmptyNote>No exchange association is recorded for this address.</EmptyNote>}
                    </div>
                  </EntitySection>
                </div>

                <EntitySection
                  icon={<Activity size={13} style={dw.critical} />}
                  title={`Flow statistics${chain ? ` · ${chain.stats.total} recorded` : ''}`}
                  aside={<span className="font-mono text-[9px] uppercase" style={dw.faint}>COMPUTED FROM STORED RECORDS</span>}
                >
                  {chain && chain.stats.total > 0 ? (
                    <div className="space-y-3">
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                        <MetaCell label="Net flow" value={`${chain.stats.net > 0 ? '+' : ''}${chain.stats.net} ${chain.stats.currency}`} />
                        <MetaCell label="In / Out" value={`${chain.stats.incoming} / ${chain.stats.outgoing}`} />
                        <MetaCell label="Active days" value={`${chain.stats.activeDays}`} />
                        <MetaCell label="Self-transfers" value={`${chain.stats.selfTransfers}`} />
                      </div>
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                        <MetaCell label="First activity" value={new Date(chain.stats.firstActivity).toLocaleDateString()} />
                        <MetaCell label="Last activity" value={new Date(chain.stats.lastActivity).toLocaleDateString()} />
                        <MetaCell
                          label="Interval"
                          value={chain.stats.medianIntervalHours ? `${chain.stats.medianIntervalHours}h median` : 'single event'}
                        />
                        <MetaCell label="Fees" value={`${chain.stats.totalFees} ${chain.stats.currency}`} />
                      </div>
                      {chain.stats.networks.length > 1 && (
                        <p className="font-mono text-[9px] leading-relaxed" style={dw.faint}>
                          Transactions span {chain.stats.networks.length} recorded networks ({chain.stats.networks.join(', ')}).
                          Addresses do not move between networks, so this indicates more than one record was merged under this identifier.
                        </p>
                      )}
                      {chain.activity.length > 0 && (
                        <div>
                          <p className="font-mono text-[9px] tracking-widest uppercase mb-1.5" style={dw.muted}>
                            Activity by day (oldest → newest)
                          </p>
                          <div className="flex items-end gap-[2px] h-14">
                            {chain.activity.map(bucket => {
                              const peak = Math.max(...chain.activity.map(b => b.count), 1);
                              return (
                                <div
                                  key={bucket.date}
                                  title={`${bucket.date}: ${bucket.count} tx (${bucket.inbound} in / ${bucket.outbound} out)`}
                                  className="flex-1 min-w-[3px] rounded-t-[1px]"
                                  style={{
                                    height: `${Math.max((bucket.count / peak) * 100, 3)}%`,
                                    backgroundColor: bucket.outbound > bucket.inbound ? 'var(--tw-crimson)' : 'var(--tw-moss)',
                                    opacity: 0.75,
                                  }}
                                />
                              );
                            })}
                          </div>
                        </div>
                      )}
                    </div>
                  ) : (
                    <EmptyNote>
                      No transaction-level records are stored, so no flow statistics can be computed. The wallet
                      record carries an observed count of {bundle.wallet.txCount}, which is an aggregate only.
                    </EmptyNote>
                  )}
                </EntitySection>

                <div className="grid md:grid-cols-2 gap-4">
                  <EntitySection
                    icon={<ShieldAlert size={13} style={chain?.indicators.length ? dw.critical : dw.muted} />}
                    title={`Privacy indicators (${chain?.indicators.length ?? 0})`}
                  >
                    {chain && chain.indicators.length > 0 ? (
                      <div className="space-y-2">
                        {chain.indicators.map(indicator => (
                          <div key={indicator.id} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                            <div className="flex items-center justify-between gap-2">
                              <span style={dw.medium}>{indicator.label}</span>
                              <span style={dw.faint}>{indicator.confidence}%</span>
                            </div>
                            <p className="mt-1 leading-relaxed" style={dw.muted}>{indicator.reason}</p>
                            <p className="mt-1" style={dw.faint}>source: {indicator.source} · {indicator.transactionIds.length} tx</p>
                            <p className="mt-1.5 pt-1.5 border-t leading-relaxed" style={{ ...dw.faint, borderColor: 'var(--tw-border-mid)' }}>
                              {indicator.caveat}
                            </p>
                          </div>
                        ))}
                        <p className="font-mono text-[9px] leading-relaxed" style={dw.faint}>
                          These are pattern indicators computed from records the model already holds. They are not
                          a finding of criminal activity, and privacy-seeking behaviour is lawful in itself.
                        </p>
                      </div>
                    ) : (
                      <EmptyNote>
                        No stored transaction triggers a privacy indicator for this address. Absence of an
                        indicator is not evidence of legitimate use.
                      </EmptyNote>
                    )}
                  </EntitySection>

                  <EntitySection
                    icon={<Landmark size={13} style={dw.critical} />}
                    title={`Service exposure (${chain?.services.length ?? 0})`}
                    aside={<span className="font-mono text-[9px] uppercase" style={dw.faint}>ATTRIBUTION, NOT OWNERSHIP</span>}
                  >
                    {chain && chain.services.length > 0 ? (
                      <div className="space-y-2">
                        {chain.services.map(link => (
                          <div key={link.exchange.id} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                            <p className="flex items-center gap-1.5" style={dw.text}>
                              <Landmark size={11} /> {link.exchange.name}
                            </p>
                            <p className="mt-0.5" style={dw.faint}>
                              {link.exchange.type} · {link.exchange.jurisdiction ?? 'unknown'} · {link.confidence}% · {link.transactionIds.length} tx
                            </p>
                            <p className="mt-1" style={dw.muted}>
                              {link.exchange.kycRequired
                                ? 'KYC on record: this service can identify the account holder, which is a lead for a lawful request rather than an open identity.'
                                : 'No KYC is recorded for this service, so the address cannot be resolved to a person from public records.'}
                            </p>
                          </div>
                        ))}
                        <p className="font-mono text-[9px] leading-relaxed" style={dw.faint}>
                          A transaction touching a service address shows value passed through that service. It does
                          not show who controls either address, and it is not proof of a custodial relationship.
                        </p>
                      </div>
                    ) : (
                      <EmptyNote>No stored transaction touches a recorded service address.</EmptyNote>
                    )}
                  </EntitySection>
                </div>

                {chain && chain.counterparties.length > 0 && (
                  <EntitySection
                    icon={<ArrowLeftRight size={13} style={dw.critical} />}
                    title={`Counterparties (${chain.counterparties.length})`}
                    aside={<span className="font-mono text-[9px] uppercase" style={dw.faint}>RANKED BY INTERACTION COUNT</span>}
                  >
                    <div className="space-y-1.5">
                      {chain.counterparties.slice(0, 10).map(entry => (
                        <div
                          key={entry.address}
                          className="flex items-center justify-between gap-3 p-2 rounded-sm border font-mono text-[10px]"
                          style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}
                        >
                          <span className="truncate" style={dw.text} title={entry.address}>{entry.address}</span>
                          <span className="shrink-0 flex items-center gap-2" style={dw.faint}>
                            {entry.directions.map(dir => (
                              <span key={dir} style={dir === 'IN' ? dw.moss : dw.medium}>{dir}</span>
                            ))}
                            <span>×{entry.count}</span>
                          </span>
                        </div>
                      ))}
                      {chain.counterparties.length > 10 && (
                        <p className="font-mono text-[9px]" style={dw.faint}>
                          {chain.counterparties.length - 10} further counterparties are stored but not listed here.
                        </p>
                      )}
                    </div>
                  </EntitySection>
                )}

                <EntitySection icon={<Layers size={13} style={dw.critical} />} title={`Why linked? (${bundle.whyLinked.length})`}>
                  {bundle.whyLinked.length > 0 ? (
                    <div className="space-y-2">
                      {bundle.whyLinked.map((entry, index) => (
                        <div key={index} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                          <span style={dw.burg}>{entry.indicator}</span>
                          <p className="mt-1 leading-relaxed" style={dw.muted}>{entry.detail}</p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <EmptyNote>No stored link explains this address yet.</EmptyNote>
                  )}
                </EntitySection>

                <div className="grid md:grid-cols-2 gap-4">
                  <EntitySection icon={<Network size={13} style={dw.critical} />} title={`Relationships (${bundle.relationships.length})`}>
                    {bundle.relationships.length > 0 ? (
                      <div className="space-y-2">
                        {bundle.relationships.map(rel => (
                          <div key={rel.id} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                            <div className="flex items-center justify-between gap-2">
                              <RelationshipChip type={rel.type} confidence={rel.confidence} />
                              <span style={dw.faint}>{rel.id}</span>
                            </div>
                            <p className="mt-1" style={dw.text}>{rel.sourceEntity} → {rel.targetEntity}</p>
                            <p className="mt-0.5" style={dw.muted}>{rel.explanation}</p>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <EmptyNote>No relationship references this address.</EmptyNote>
                    )}
                  </EntitySection>

                  <EntitySection icon={<Database size={13} style={dw.critical} />} title={`Evidence (${bundle.evidence.length})`}>
                    {bundle.evidence.length > 0 ? (
                      <div className="space-y-2">
                        {bundle.evidence.slice(0, 6).map(item => (
                          <div key={item.id} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                            <div className="flex items-center justify-between">
                              <span style={dw.burg}>{item.id} · {item.evidenceType.replace(/_/g, ' ')}</span>
                              <span style={dw.faint}>{new Date(item.timestamp).toLocaleDateString()}</span>
                            </div>
                            <p className="mt-1 leading-relaxed" style={dw.muted}>{item.provenance}</p>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <EmptyNote>No evidence is linked to this address.</EmptyNote>
                    )}
                    {bundle.actors[0] && <EntityLink to={`${ENTITY_PATH.evidence}?actor=${bundle.actors[0].id}`}>Open evidence locker →</EntityLink>}
                  </EntitySection>
                </div>

                <div className="grid md:grid-cols-2 gap-4">
                  <EntitySection icon={<Globe size={13} style={dw.critical} />} title={`Sources (${bundle.sources.length})`}>
                    {bundle.sources.length > 0 ? bundle.sources.map(source => (
                      <Link key={source.id} to={ENTITY_PATH.sources} className="block p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                        <p style={dw.text}>{source.name}</p>
                        <p style={dw.faint}>{source.type} · R{source.reliabilityScore}</p>
                      </Link>
                    )) : (
                      <EmptyNote>No source is recorded against this address.</EmptyNote>
                    )}
                  </EntitySection>

                  <div className="space-y-4">
                    <EntitySection icon={<Clock size={13} style={dw.critical} />} title={`Timeline (${bundle.timeline.length} events)`}>
                      {bundle.timeline.length > 0 ? bundle.timeline.slice(0, 5).map(event => (
                        <div key={event.id} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                          <div className="flex items-center justify-between">
                            <span style={dw.text}>{event.title}</span>
                            <span style={dw.faint}>{new Date(event.time).toLocaleDateString()}</span>
                          </div>
                          <p className="mt-0.5" style={dw.muted}>{event.actorId}</p>
                        </div>
                      )) : null}
                      {bundle.timeline.length === 0 && <EmptyNote>No timeline event is tied to this address.</EmptyNote>}
                      {bundle.actors[0] && <EntityLink to={`${ENTITY_PATH.timeline}?actor=${bundle.actors[0].id}`}>Open full timeline →</EntityLink>}
                    </EntitySection>

                    <EntitySection icon={<FileText size={13} style={dw.critical} />} title={`Investigations (${bundle.investigations.length})`}>
                      {bundle.investigations.length > 0 ? bundle.investigations.map(inv => (
                        <Link
                          key={inv.id}
                          to={`${ENTITY_PATH.investigations}/${inv.id}`}
                          className="block p-2.5 rounded-sm border font-mono text-[10px]"
                          style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}
                        >
                          <p style={dw.text}>{inv.title}</p>
                          <p className="mt-0.5" style={dw.faint}>{inv.id} · {inv.status} · {inv.confidence}%</p>
                        </Link>
                      )) : (
                        <EmptyNote>This address is not yet part of an investigation.</EmptyNote>
                      )}
                    </EntitySection>
                  </div>
                </div>
              </>
            ) : (
              <EmptySelection icon={<Wallet size={32} />} message="Select a wallet record to open its cryptocurrency dossier." />
            )}
          </div>
        </div>

        <ProtectionModulePanel entityType="WALLET" />
      </div>
    </motion.div>
  );
}
