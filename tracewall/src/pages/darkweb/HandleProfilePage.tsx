import { useMemo } from 'react';
import { motion } from 'framer-motion';
import { useNavigate, useParams, Link } from 'react-router-dom';
import { Users, ChevronLeft, Key, Wallet, Server, Database, Globe, Layers, Fingerprint, ArrowRight } from 'lucide-react';
import { dw, sectionStyle } from '../../lib/darkweb/styles';
import { useIntelligence } from '../../lib/intelligence/IntelligenceContext';
import { handleBundle, actorPath, pgpPath, walletPath, ENTITY_PATH } from '../../lib/intelligence/entityBundles';
import { ConfidenceBar } from '../../components/ui/ConfidenceBar';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { EntityLink, EntitySection, EmptyNote, MetaCell } from '../../components/darkweb/EntityWorkspace';
import { MonitorEntityButton } from '../../components/darkweb/MonitorEntityButton';
import { ProtectionPanel } from '../../components/darkweb/ProtectionPanel';

// ============================================================
// Handle dossier — the single-record view of the same bundle the
// Handle Intelligence list renders. Both read the identical central
// handle record, so the two can never drift apart.
// ============================================================
export default function HandleProfilePage() {
  const { id } = useParams<{ id: string }>();
  const { dataset } = useIntelligence();
  const navigate = useNavigate();
  const bundle = useMemo(() => (id ? handleBundle(dataset, id) : null), [dataset, id]);

  if (!bundle) {
    return (
      <div className="min-h-screen page-enter" style={sectionStyle()}>
        <div className="max-w-3xl mx-auto px-6 lg:px-10 py-16 text-center" style={dw.text}>
          <Users size={40} className="mx-auto mb-4" style={dw.muted} />
          <h2 className="font-serif text-2xl mb-2">Handle Not Found</h2>
          <p className="font-mono text-xs mb-4" style={dw.muted}>No handle record matches “{id}”.</p>
          <button
            onClick={() => navigate('/app/darkweb/handles')}
            className="font-mono text-xs px-4 py-2 rounded-sm border"
            style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
          >
            ← Back to Handle Intelligence
          </button>
        </div>
      </div>
    );
  }

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        <button onClick={() => navigate('/app/darkweb/handles')} className="font-mono text-[10px] flex items-center gap-1" style={dw.muted}>
          <ChevronLeft size={12} /> Back to Handle Intelligence
        </button>

        <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b pb-5" style={{ borderColor: 'var(--tw-border-mid)' }}>
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Users size={16} style={dw.critical} />
              <span className="font-mono text-[10px] tracking-wider" style={dw.burg}>{bundle.handle.id}</span>
              <DemoLabel />
              <MonitorEntityButton entityType="HANDLE" entityId={bundle.handle.id} entityLabel={`@${bundle.handle.value}`} targetType="HANDLE" />
            </div>
            <h1 className="font-mono text-3xl break-all" style={dw.text}>@{bundle.handle.value}</h1>
            <p className="text-sm" style={dw.muted}>
              Identity artifact on <span className="font-mono" style={dw.text}>{bundle.handle.platform}</span>.
              First seen {new Date(bundle.handle.firstSeen).toLocaleDateString()},
              last seen {new Date(bundle.handle.lastSeen).toLocaleDateString()}.
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
                {actor.id} <ArrowRight size={10} className="inline" />
              </Link>
            ))}
            <Link
              to={`${ENTITY_PATH.correlation}?handle=${encodeURIComponent(bundle.handle.value)}`}
              className="font-mono text-[10px] tracking-wider uppercase px-2.5 py-1.5 rounded-sm border"
              style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}
            >
              <Fingerprint size={11} className="inline mr-1" /> Correlate
            </Link>
          </div>
        </div>

        <div className="grid md:grid-cols-3 gap-6">
          <div className="col-span-2 space-y-6">
            <div className="rounded-sm border p-5 space-y-4" style={dw.panel}>
              <p className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>Identity correlation</p>
              <div className="grid sm:grid-cols-2 gap-3 p-3 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)' }}>
                <MetaCell label="Normalized form" value={`@${bundle.handle.normalized}`} />
                <MetaCell label="Platforms seen" value={bundle.platforms.join(', ') || '—'} />
                <MetaCell label="Cross-platform reuse" value={`${bundle.aliasHandles.length} alias record(s)`} />
                <MetaCell label="Provenance" value={bundle.handle.dataState?.replace(/_/g, ' ') ?? 'Observed'} />
              </div>
              <ConfidenceBar value={bundle.handle.confidence} />
            </div>

            <ProtectionPanel entityType="HANDLE" entityId={bundle.handle.id} title="Threat Protection & Response" />

            <EntitySection icon={<Layers size={13} style={dw.critical} />} title={`Why linked? (${bundle.whyLinked.length})`}>
              {bundle.whyLinked.length > 0 ? (
                <div className="space-y-2">
                  {bundle.whyLinked.map((entry, index) => (
                    <div key={index} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                      <div className="flex items-center justify-between">
                        <span style={dw.burg}>{entry.indicator}</span>
                        <span style={dw.faint}>{entry.source}</span>
                      </div>
                      <p className="mt-1 leading-relaxed" style={dw.muted}>{entry.detail}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyNote>No stored relationship explains this identity yet.</EmptyNote>
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
                <EmptyNote>No evidence linked to this handle.</EmptyNote>
              )}
              {bundle.actors[0] && <EntityLink to={`${ENTITY_PATH.evidence}?actor=${bundle.actors[0].id}`}>Open evidence locker →</EntityLink>}
            </EntitySection>

            <EntitySection icon={<Globe size={13} style={dw.critical} />} title={`Sources (${bundle.sources.length})`}>
              {bundle.sources.length > 0 ? (
                <div className="space-y-2">
                  {bundle.sources.map(source => (
                    <Link key={source.id} to={ENTITY_PATH.sources} className="block p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                      <p style={dw.text}>{source.name}</p>
                      <p style={dw.faint}>{source.type} · R{source.reliabilityScore} · {source.status}</p>
                    </Link>
                  ))}
                </div>
              ) : (
                <EmptyNote>No source is recorded against this handle.</EmptyNote>
              )}
            </EntitySection>
          </div>

          <div className="space-y-4">
            <EntitySection icon={<Users size={13} style={dw.critical} />} title={`Associated actor (${bundle.actors.length})`}>
              {bundle.actors.length > 0 ? (
                <div className="space-y-2">
                  {bundle.actors.map(actor => (
                    <Link key={actor.id} to={actorPath(actor.id)} className="block p-2.5 rounded-sm border" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                      <p className="font-mono text-sm" style={dw.burg}>{actor.aliases[0] ?? actor.id}</p>
                      <p className="font-mono text-[9px]" style={dw.faint}>{actor.id} · {actor.status} · {actor.confidenceScore}%</p>
                    </Link>
                  ))}
                </div>
              ) : (
                <EmptyNote>Unattributed — no actor claims this handle yet.</EmptyNote>
              )}
            </EntitySection>

            <EntitySection icon={<Key size={13} style={dw.critical} />} title={`PGP associations (${bundle.pgpKeys.length})`}>
              {bundle.pgpKeys.length > 0 ? bundle.pgpKeys.map(key => (
                <Link key={key.id} to={pgpPath(key.id)} className="block p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                  <p className="break-all" style={dw.text}>{key.fingerprint}</p>
                  <p className="mt-0.5" style={dw.faint}>{key.id} · {key.confidence}%</p>
                </Link>
              )) : <EmptyNote>No PGP key associated.</EmptyNote>}
            </EntitySection>

            <EntitySection icon={<Wallet size={13} style={dw.critical} />} title={`Wallet associations (${bundle.wallets.length})`}>
              {bundle.wallets.length > 0 ? bundle.wallets.map(wallet => (
                <Link key={wallet.id} to={walletPath(wallet.id)} className="block p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                  <p className="break-all" style={dw.text}>{wallet.address}</p>
                  <p className="mt-0.5" style={dw.faint}>{wallet.id} · {wallet.txCount} tx</p>
                </Link>
              )) : <EmptyNote>No wallet associated.</EmptyNote>}
            </EntitySection>

            <EntitySection icon={<Server size={13} style={dw.critical} />} title={`Infrastructure (${bundle.infrastructure.length})`}>
              {bundle.infrastructure.length > 0 ? (
                <div className="space-y-1">
                  {bundle.infrastructure.map(infra => (
                    <Link key={infra.id} to={ENTITY_PATH.infrastructure} className="block p-2 rounded-sm border font-mono text-[10px] break-all" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                      <span style={dw.text}>{infra.value}</span>
                      <span className="ml-1" style={dw.faint}>{infra.type}</span>
                    </Link>
                  ))}
                </div>
              ) : (
                <EmptyNote>No infrastructure associated.</EmptyNote>
              )}
            </EntitySection>
          </div>
        </div>
      </div>
    </motion.div>
  );
}
