import { useMemo } from 'react';
import { motion } from 'framer-motion';
import { useNavigate, useParams, Link } from 'react-router-dom';
import { Wallet, ChevronLeft, Users, Database, Clock, Globe, Layers, ArrowLeftRight, Key, Network, ShieldAlert } from 'lucide-react';
import { dw, sectionStyle } from '../../lib/darkweb/styles';
import { useIntelligence } from '../../lib/intelligence/IntelligenceContext';
import { walletBundle, walletPath, actorPath, handlePath, pgpPath, ENTITY_PATH } from '../../lib/intelligence/entityBundles';
import { cryptoBundle } from '../../lib/intelligence/crypto';
import { ConfidenceBar } from '../../components/ui/ConfidenceBar';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { RelationshipChip } from '../../components/darkweb/RelationshipChip';
import { EntityLink, EntitySection, EmptyNote, MetaCell } from '../../components/darkweb/EntityWorkspace';
import { MonitorEntityButton } from '../../components/darkweb/MonitorEntityButton';
import { ProtectionPanel } from '../../components/darkweb/ProtectionPanel';

// ============================================================
// Wallet dossier — the single-record view of the same bundle the
// Crypto Wallet Intelligence list renders, off the same centralized
// wallet record and its existing backend id.
// ============================================================
export default function WalletProfilePage() {
  const { id } = useParams<{ id: string }>();
  const { dataset } = useIntelligence();
  const navigate = useNavigate();
  const bundle = useMemo(() => (id ? walletBundle(dataset, id) : null), [dataset, id]);
  const chain = useMemo(() => (id ? cryptoBundle(dataset, id) : null), [dataset, id]);

  if (!bundle) {
    return (
      <div className="min-h-screen page-enter" style={sectionStyle()}>
        <div className="max-w-3xl mx-auto px-6 lg:px-10 py-16 text-center" style={dw.text}>
          <Wallet size={40} className="mx-auto mb-4" style={dw.muted} />
          <h2 className="font-serif text-2xl mb-2">Wallet Not Found</h2>
          <p className="font-mono text-xs mb-4" style={dw.muted}>No wallet record matches “{id}”.</p>
          <button
            onClick={() => navigate('/app/darkweb/wallets')}
            className="font-mono text-xs px-4 py-2 rounded-sm border"
            style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
          >
            ← Back to Crypto Wallet Intelligence
          </button>
        </div>
      </div>
    );
  }

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        <button onClick={() => navigate('/app/darkweb/wallets')} className="font-mono text-[10px] flex items-center gap-1" style={dw.muted}>
          <ChevronLeft size={12} /> Back to Crypto Wallet Intelligence
        </button>

        <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b pb-5" style={{ borderColor: 'var(--tw-border-mid)' }}>
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Wallet size={16} style={dw.info} />
              <span className="font-mono text-[10px] tracking-wider" style={dw.burg}>{bundle.wallet.id}</span>
              <DemoLabel />
              <MonitorEntityButton entityType="WALLET" entityId={bundle.wallet.id} entityLabel={`${bundle.wallet.address.slice(0, 10)}…`} targetType="WALLET" />
            </div>
            <h1 className="font-mono text-xl font-bold break-all" style={dw.text}>{bundle.wallet.address}</h1>
            <p className="text-sm" style={dw.muted}>
              Cryptocurrency wallet on <span className="font-mono" style={dw.text}>{bundle.network}</span>.
              {bundle.wallet.txCount} transaction{bundle.wallet.txCount === 1 ? '' : 's'} observed.
              First seen {new Date(bundle.wallet.firstSeen).toLocaleDateString()},
              last seen {new Date(bundle.wallet.lastSeen).toLocaleDateString()}.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {bundle.actors.map(actor => (
              <Link
                key={actor.id}
                to={actorPath(actor.id)}
                className="font-mono text-[10px] tracking-wider uppercase px-2.5 py-1.5 rounded-sm border"
                style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-burgundy)' }}
              >
                {actor.id} →
              </Link>
            ))}
            {bundle.relatedWallets.length > 0 && (
              <Link
                to={walletPath(bundle.relatedWallets[0].id)}
                className="font-mono text-[10px] tracking-wider uppercase px-2.5 py-1.5 rounded-sm border"
                style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}
              >
                Cluster sibling →
              </Link>
            )}
          </div>
        </div>

        <div className="grid md:grid-cols-3 gap-6">
          <div className="col-span-2 space-y-6">
            <div className="rounded-sm border p-5 space-y-4" style={dw.panel}>
              <p className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>Cryptocurrency posture</p>
              <div className="grid sm:grid-cols-2 gap-3 p-3 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)' }}>
                <MetaCell label="Network" value={bundle.network} />
                <MetaCell label="Transactions observed" value={bundle.wallet.txCount} />
                <MetaCell label="Related wallets" value={bundle.relatedWallets.length} />
                <MetaCell label="Provenance" value={bundle.wallet.dataState?.replace(/_/g, ' ') ?? 'Observed'} />
              </div>
              <ConfidenceBar value={bundle.wallet.confidence} />
            </div>

            <ProtectionPanel entityType="WALLET" entityId={bundle.wallet.id} title="Threat Protection & Response" />

            <EntitySection
              icon={<ArrowLeftRight size={13} style={dw.critical} />}
              title={`Related transactions (${bundle.transactions.length})`}
              aside={<span className="font-mono text-[9px] uppercase" style={dw.faint}>RECORDED IN MODEL</span>}
            >
              {bundle.transactions.length > 0 ? (
                <div className="space-y-2">
                  {bundle.transactions.map(tx => (
                    <div key={tx.id} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                      <div className="flex items-center justify-between gap-2">
                        <span style={tx.direction === 'IN' ? dw.moss : dw.medium}>{tx.direction} · {tx.amount} {tx.currency}</span>
                        <span style={dw.faint}>{new Date(tx.timestamp).toLocaleString()}</span>
                      </div>
                      <p className="mt-1 break-all" style={dw.text}>{tx.hash}</p>
                      <p className="mt-0.5" style={dw.muted}>
                        {tx.fromAddress.slice(0, 14)}… → {tx.toAddress.slice(0, 14)}… · {tx.status}
                      </p>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyNote>
                  No transaction-level records are stored against this address. The wallet record carries an
                  observed transaction count ({bundle.wallet.txCount}) only — this page never executes a transaction.
                </EmptyNote>
              )}
            </EntitySection>

            <EntitySection
              icon={<ShieldAlert size={13} style={dw.critical} />}
              title="Address validation & flow analysis"
              aside={<span className="font-mono text-[9px] uppercase" style={dw.faint}>READ-ONLY · COMPUTED</span>}
            >
              {chain ? (
                <div className="space-y-3">
                  <div
                    className="p-3 rounded-sm border font-mono text-[10px] space-y-1.5"
                    style={{
                      backgroundColor: 'var(--tw-panel-alt)',
                      borderColor: 'var(--tw-border-mid)',
                    }}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span
                        style={
                          chain.addressCheck.verdict === 'VALID' ? dw.moss
                            : chain.addressCheck.verdict === 'FORMAT_UNKNOWN' ? dw.faint
                              : dw.critical
                        }
                      >
                        {chain.addressCheck.verdict.replace(/_/g, ' ')}
                        {chain.addressCheck.detected ? ` · ${chain.addressCheck.detected}` : ''}
                      </span>
                      <span style={dw.faint}>recorded as: {chain.declaredNetwork}</span>
                    </div>
                    <p className="leading-relaxed" style={dw.muted}>{chain.addressCheck.detail}</p>
                    {chain.networkMismatch && (
                      <p className="leading-relaxed" style={dw.critical}>
                        The recorded network and the address format disagree. One address cannot exist on two
                        networks, so one of these fields is wrong.
                      </p>
                    )}
                  </div>

                  {chain.stats.total > 0 ? (
                    <>
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                        <MetaCell label="Net flow" value={`${chain.stats.net > 0 ? '+' : ''}${chain.stats.net} ${chain.stats.currency}`} />
                        <MetaCell label="In / Out" value={`${chain.stats.incoming} / ${chain.stats.outgoing}`} />
                        <MetaCell label="Active days" value={String(chain.stats.activeDays)} />
                        <MetaCell label="Fees" value={`${chain.stats.totalFees} ${chain.stats.currency}`} />
                      </div>
                      <p className="font-mono text-[9px] leading-relaxed" style={dw.faint}>
                        Computed from the {chain.stats.total} stored transaction record(s), spanning{' '}
                        {new Date(chain.stats.firstActivity).toLocaleDateString()} to{' '}
                        {new Date(chain.stats.lastActivity).toLocaleDateString()}. Statistics describe only the
                        transactions this model has recorded, which is not the address&rsquo;s complete history.
                      </p>
                    </>
                  ) : (
                    <EmptyNote>
                      No stored transactions, so no flow statistics were computed. An aggregate count alone
                      cannot be analysed.
                    </EmptyNote>
                  )}

                  {chain.indicators.length > 0 && (
                    <div className="space-y-2">
                      {chain.indicators.map(indicator => (
                        <div key={indicator.id} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                          <div className="flex items-center justify-between gap-2">
                            <span style={dw.medium}>{indicator.label}</span>
                            <span style={dw.faint}>{indicator.confidence}%</span>
                          </div>
                          <p className="mt-1 leading-relaxed" style={dw.muted}>{indicator.reason}</p>
                          <p className="mt-1.5 pt-1.5 border-t leading-relaxed" style={{ ...dw.faint, borderColor: 'var(--tw-border-mid)' }}>
                            {indicator.caveat}
                          </p>
                        </div>
                      ))}
                    </div>
                  )}

                  {chain.services.length > 0 && (
                    <div>
                      <p className="font-mono text-[9px] tracking-widest uppercase mb-1.5" style={dw.muted}>Service exposure</p>
                      <div className="space-y-1.5">
                        {chain.services.map(link => (
                          <div key={link.exchange.id} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                            <p style={dw.text}>{link.exchange.name} · {link.exchange.type}</p>
                            <p className="mt-0.5" style={dw.faint}>
                              {link.exchange.jurisdiction ?? 'unknown'} · {link.confidence}% · {link.transactionIds.length} tx
                            </p>
                            <p className="mt-1 leading-relaxed" style={dw.muted}>
                              {link.exchange.kycRequired
                                ? 'KYC is recorded, so a lawful process could identify the account holder. This is a lead, not an open identity.'
                                : 'No KYC is recorded, so this address cannot be tied to a person from public records.'}
                            </p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {chain.counterparties.length > 0 && (
                    <div>
                      <p className="font-mono text-[9px] tracking-widest uppercase mb-1.5" style={dw.muted}>
                        Top counterparties ({chain.counterparties.length} total)
                      </p>
                      <div className="space-y-1">
                        {chain.counterparties.slice(0, 8).map(entry => (
                          <div key={entry.address} className="flex items-center justify-between gap-3 p-2 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                            <span className="truncate" style={dw.text} title={entry.address}>{entry.address}</span>
                            <span className="shrink-0 flex items-center gap-2" style={dw.faint}>
                              {entry.directions.map(dir => (
                                <span key={dir} style={dir === 'IN' ? dw.moss : dw.medium}>{dir}</span>
                              ))}
                              <span>×{entry.count}</span>
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <EmptyNote>This wallet record is no longer present in the central model.</EmptyNote>
              )}
            </EntitySection>

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

            <EntitySection icon={<Database size={13} style={dw.critical} />} title={`Evidence (${bundle.evidence.length})`}>
              {bundle.evidence.length > 0 ? (
                <div className="space-y-2">
                  {bundle.evidence.map(item => (
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

          <div className="space-y-4">
            <EntitySection icon={<Users size={13} style={dw.critical} />} title={`Attributed actors (${bundle.actors.length})`}>
              {bundle.actors.length > 0 ? bundle.actors.map(actor => (
                <Link key={actor.id} to={actorPath(actor.id)} className="block p-2.5 rounded-sm border" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                  <p className="font-mono text-sm" style={dw.burg}>{actor.aliases[0] ?? actor.id}</p>
                  <p className="font-mono text-[9px]" style={dw.faint}>{actor.id} · {actor.status} · {actor.confidenceScore}%</p>
                </Link>
              )) : (
                <EmptyNote>Unattributed — no actor claims this address yet.</EmptyNote>
              )}
            </EntitySection>

            <EntitySection icon={<Wallet size={13} style={dw.critical} />} title={`Related wallets (${bundle.relatedWallets.length})`}>
              {bundle.relatedWallets.length > 0 ? bundle.relatedWallets.map(item => (
                <Link key={item.id} to={walletPath(item.id)} className="block p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                  <p className="break-all" style={dw.text}>{item.address}</p>
                  <p className="mt-0.5" style={dw.faint}>{item.id} · {item.txCount} tx</p>
                </Link>
              )) : (
                <EmptyNote>No other address is attributed to the same actor.</EmptyNote>
              )}
            </EntitySection>

            <EntitySection icon={<Key size={13} style={dw.critical} />} title={`Related handles (${bundle.handles.length})`}>
              {bundle.handles.length > 0 ? bundle.handles.map(handle => (
                <Link key={handle.id} to={handlePath(handle.id)} className="block p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                  <p style={dw.text}>@{handle.value}</p>
                  <p style={dw.faint}>{handle.platform} · {handle.id}</p>
                </Link>
              )) : (
                <EmptyNote>No handle is associated with this address.</EmptyNote>
              )}
            </EntitySection>

            <EntitySection icon={<Network size={13} style={dw.critical} />} title={`PGP & relationships`}>
              <div className="space-y-2">
                {bundle.pgpKeys.map(key => (
                  <Link key={key.id} to={pgpPath(key.id)} className="block p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                    <p className="break-all" style={dw.text}>{key.fingerprint}</p>
                    <p style={dw.faint}>{key.id} · {key.confidence}%</p>
                  </Link>
                ))}
                {bundle.pgpKeys.length === 0 && <EmptyNote>No PGP key is associated with this address.</EmptyNote>}
                {bundle.relationships.map(rel => (
                  <div key={rel.id} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                    <div className="flex items-center justify-between gap-2">
                      <RelationshipChip type={rel.type} confidence={rel.confidence} />
                      <span style={dw.faint}>{rel.id}</span>
                    </div>
                    <p className="mt-1" style={dw.text}>{rel.sourceEntity} → {rel.targetEntity}</p>
                    <p className="mt-0.5" style={dw.muted}>{rel.explanation}</p>
                  </div>
                ))}
                {bundle.relationships.length === 0 && <EmptyNote>No relationship references this address.</EmptyNote>}
              </div>
            </EntitySection>

            <EntitySection icon={<Globe size={13} style={dw.critical} />} title={`Sources (${bundle.sources.length})`}>
              {bundle.sources.length > 0 ? bundle.sources.map(source => (
                <Link key={source.id} to={ENTITY_PATH.sources} className="block p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                  <p style={dw.text}>{source.name}</p>
                  <p style={dw.faint}>{source.type} · R{source.reliabilityScore}</p>
                </Link>
              )) : (
                <EmptyNote>No source is recorded against this address.</EmptyNote>
              )}
              <EntityLink to={`${ENTITY_PATH.timeline}?actor=${bundle.actors[0]?.id ?? ''}`}>Open timeline →</EntityLink>
              <EntityLink to={`${ENTITY_PATH.investigations}`} accent="var(--tw-text-muted)">
                <Clock size={10} /> Investigations
              </EntityLink>
            </EntitySection>
          </div>
        </div>
      </div>
    </motion.div>
  );
}
