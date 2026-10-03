import { useMemo } from 'react';
import { motion } from 'framer-motion';
import { useNavigate, useParams, Link } from 'react-router-dom';
import {
  FileJson, ChevronLeft, Database, Clock, Network, Globe, Layers,
  Fingerprint, Key, Wallet, Server, Users,
} from 'lucide-react';
import { dw, sectionStyle } from '../../lib/darkweb/styles';
import { useIntelligence } from '../../lib/intelligence/IntelligenceContext';
import { observationBundle, observationPath, actorPath, handlePath, pgpPath, walletPath, ENTITY_PATH } from '../../lib/intelligence/entityBundles';
import { ConfidenceBar } from '../../components/ui/ConfidenceBar';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { RelationshipChip } from '../../components/darkweb/RelationshipChip';
import { EntityLink, EntitySection, EmptyNote, MetaCell } from '../../components/darkweb/EntityWorkspace';
import { MonitorEntityButton } from '../../components/darkweb/MonitorEntityButton';
import { ProtectionPanel } from '../../components/darkweb/ProtectionPanel';

// ============================================================
// Observation record — the single-record view of the same
// four-stage pipeline the Observation Intelligence list renders,
// off the same centralized observation record.
// ============================================================

const ENTITY_ICON = {
  Handle: Users,
  PGP: Key,
  Wallet,
  Infrastructure: Server,
  Actor: Users,
  Source: Globe,
} as const;

export default function ObservationPage() {
  const { id } = useParams<{ id: string }>();
  const { dataset } = useIntelligence();
  const navigate = useNavigate();
  const bundle = useMemo(() => (id ? observationBundle(dataset, id) : null), [dataset, id]);

  if (!bundle) {
    return (
      <div className="min-h-screen page-enter" style={sectionStyle()}>
        <div className="max-w-3xl mx-auto px-6 lg:px-10 py-16 text-center" style={dw.text}>
          <FileJson size={40} className="mx-auto mb-4" style={dw.muted} />
          <h2 className="font-serif text-2xl mb-2">Observation Not Found</h2>
          <p className="font-mono text-xs mb-4" style={dw.muted}>No observation record matches “{id}”.</p>
          <button
            onClick={() => navigate('/app/darkweb/observations')}
            className="font-mono text-xs px-4 py-2 rounded-sm border"
            style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
          >
            ← Back to Observation Intelligence
          </button>
        </div>
      </div>
    );
  }

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        <button onClick={() => navigate('/app/darkweb/observations')} className="font-mono text-[10px] flex items-center gap-1" style={dw.muted}>
          <ChevronLeft size={12} /> Back to Observation Intelligence
        </button>

        <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b pb-5" style={{ borderColor: 'var(--tw-border-mid)' }}>
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <FileJson size={16} style={dw.critical} />
              <span className="font-mono text-[10px] tracking-wider" style={dw.burg}>{bundle.observation.id}</span>
              <DemoLabel />
              <MonitorEntityButton entityType="OBSERVATION" entityId={bundle.observation.id} entityLabel={bundle.observation.observationType.replace(/_/g, ' ')} targetType="OBSERVATION" />
            </div>
            <h1 className="font-serif text-3xl" style={dw.text}>
              {bundle.observation.observationType.replace(/_/g, ' ')}
            </h1>
            <p className="text-sm" style={dw.muted}>
              Collected {new Date(bundle.observation.timestamp).toLocaleString()} from{' '}
              <span className="font-mono" style={dw.text}>{bundle.observation.source}</span>
              {bundle.observation.platform ? <> on <span className="font-mono" style={dw.text}>{bundle.observation.platform}</span></> : null}.
            </p>
          </div>
          <Link
            to={observationPath(bundle.observation.id)}
            className="font-mono text-[10px] tracking-wider uppercase px-2.5 py-1.5 rounded-sm border self-start"
            style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-burgundy)' }}
          >
            Canonical record
          </Link>
        </div>

        <div className="grid md:grid-cols-3 gap-6">
          <div className="col-span-2 space-y-6">
            <div className="rounded-sm border p-5 space-y-4" style={dw.panel}>
              <p className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>Collection metadata</p>
              <div className="grid sm:grid-cols-2 gap-3 p-3 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)' }}>
                <MetaCell label="Collection timestamp" value={new Date(bundle.observation.timestamp).toLocaleString()} />
                <MetaCell label="Processing status" value={bundle.processingStatus.label} />
                <MetaCell label="Source" value={bundle.observation.source} />
                <MetaCell label="Platform" value={bundle.observation.platform ?? '—'} />
              </div>
              <ConfidenceBar value={bundle.observation.confidence} />
              <p className="font-mono text-[9px]" style={dw.faint}>{bundle.processingStatus.detail}</p>
            </div>

            <ProtectionPanel entityType="OBSERVATION" entityId={bundle.observation.id} title="Threat Protection & Response" />

            <EntitySection icon={<FileJson size={13} style={dw.critical} />} title="1 · Raw observation — verbatim capture">
              <div className="p-4 rounded-sm border" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                <pre className="font-mono text-xs whitespace-pre-wrap break-words" style={dw.text}>{bundle.observation.content}</pre>
              </div>
              {bundle.observation.notes && (
                <div>
                  <span className="font-mono text-[9px] uppercase block mb-1" style={dw.faint}>Analyst notes</span>
                  <p className="font-mono text-[10px] leading-relaxed" style={dw.muted}>{bundle.observation.notes}</p>
                </div>
              )}
            </EntitySection>

            <EntitySection
              icon={<Fingerprint size={13} style={dw.critical} />}
              title={`2 · Extracted intelligence — entities named by the raw text (${bundle.extracted.length})`}
            >
              {bundle.extracted.length > 0 ? (
                <div className="space-y-2">
                  {bundle.extracted.map(entity => {
                    const Icon = ENTITY_ICON[entity.kind];
                    const isNormalized = bundle.normalized.some(item => item.id === entity.id && item.kind === entity.kind);
                    return (
                      <Link
                        key={`${entity.kind}-${entity.id}`}
                        to={entity.path}
                        className="block p-2.5 rounded-sm border font-mono text-[10px]"
                        style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="flex items-center gap-1.5 min-w-0" style={dw.text}>
                            <Icon size={11} style={dw.brass} />
                            <span className="truncate">{entity.label}</span>
                          </span>
                          <span className="shrink-0 uppercase" style={isNormalized ? dw.moss : dw.faint}>
                            {isNormalized ? 'normalized' : 'unresolved'}
                          </span>
                        </div>
                        <p className="mt-0.5" style={dw.faint}>{entity.kind} · matches {entity.id}</p>
                      </Link>
                    );
                  })}
                </div>
              ) : (
                <EmptyNote>No stored entity is named in this observation's raw text.</EmptyNote>
              )}
            </EntitySection>

            <EntitySection
              icon={<Layers size={13} style={dw.critical} />}
              title={`3 · Normalized entity — already held in the central model (${bundle.normalized.length})`}
            >
              {bundle.normalized.length > 0 ? (
                <div className="space-y-2">
                  {bundle.normalized.map(entity => (
                    <Link
                      key={`${entity.kind}-${entity.id}`}
                      to={entity.path}
                      className="block p-2.5 rounded-sm border font-mono text-[10px]"
                      style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="truncate" style={dw.text}>{entity.label}</span>
                        <span style={dw.moss}>NORMALIZED</span>
                      </div>
                      <p className="mt-0.5 break-all" style={dw.faint}>{entity.kind} · canonical form {entity.normalized}</p>
                    </Link>
                  ))}
                </div>
              ) : (
                <EmptyNote>
                  Nothing here is normalized into a central entity yet — an extracted string is a lead, not an
                  entity, until Add Intelligence records it.
                </EmptyNote>
              )}
            </EntitySection>

            <EntitySection
              icon={<Network size={13} style={dw.critical} />}
              title={`4 · Correlated intelligence (${bundle.evidence.length + bundle.timeline.length + bundle.relationships.length} records)`}
            >
              <div className="grid sm:grid-cols-2 gap-3">
                <div className="space-y-2">
                  <span className="font-mono text-[9px] uppercase block" style={dw.faint}>Related actor</span>
                  {bundle.actor ? (
                    <Link to={actorPath(bundle.actor.id)} className="block p-2.5 rounded-sm border" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                      <p className="font-mono text-sm" style={dw.burg}>{bundle.actor.aliases[0] ?? bundle.actor.id}</p>
                      <p className="font-mono text-[9px]" style={dw.faint}>{bundle.actor.id} · {bundle.actor.status}</p>
                    </Link>
                  ) : <EmptyNote>Unattributed.</EmptyNote>}

                  <span className="font-mono text-[9px] uppercase block pt-1" style={dw.faint}>Related handle</span>
                  {bundle.handle ? (
                    <Link to={handlePath(bundle.handle.id)} className="block p-2.5 rounded-sm border" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                      <p className="font-mono text-xs" style={dw.text}>@{bundle.handle.value}</p>
                      <p className="font-mono text-[9px]" style={dw.faint}>{bundle.handle.id} · {bundle.handle.platform}</p>
                    </Link>
                  ) : <EmptyNote>No linked handle.</EmptyNote>}
                </div>

                <div className="space-y-2">
                  <span className="font-mono text-[9px] uppercase block" style={dw.faint}>Related PGP</span>
                  {bundle.pgpKeys.length > 0 ? bundle.pgpKeys.map(key => (
                    <Link key={key.id} to={pgpPath(key.id)} className="block p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                      <p className="break-all" style={dw.text}>{key.fingerprint}</p>
                      <p style={dw.faint}>{key.id}</p>
                    </Link>
                  )) : <EmptyNote>None named.</EmptyNote>}

                  <span className="font-mono text-[9px] uppercase block pt-1" style={dw.faint}>Related wallet</span>
                  {bundle.wallets.length > 0 ? bundle.wallets.map(wallet => (
                    <Link key={wallet.id} to={walletPath(wallet.id)} className="block p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                      <p className="break-all" style={dw.text}>{wallet.address}</p>
                      <p style={dw.faint}>{wallet.id}</p>
                    </Link>
                  )) : <EmptyNote>None named.</EmptyNote>}

                  <span className="font-mono text-[9px] uppercase block pt-1" style={dw.faint}>Related infrastructure</span>
                  {bundle.infrastructure.length > 0 ? bundle.infrastructure.map(infra => (
                    <Link key={infra.id} to={ENTITY_PATH.infrastructure} className="block p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                      <p className="break-all" style={dw.text}>{infra.value}</p>
                      <p style={dw.faint}>{infra.id}</p>
                    </Link>
                  )) : <EmptyNote>None named.</EmptyNote>}
                </div>
              </div>
            </EntitySection>
          </div>

          <div className="space-y-4">
            <EntitySection icon={<Globe size={13} style={dw.critical} />} title="Source">
              {bundle.source ? (
                <Link to={ENTITY_PATH.sources} className="block p-2.5 rounded-sm border" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                  <p className="font-mono text-xs" style={dw.text}>{bundle.source.name}</p>
                  <p className="font-mono text-[9px]" style={dw.faint}>{bundle.source.type} · R{bundle.source.reliabilityScore} · {bundle.source.status}</p>
                </Link>
              ) : (
                <EmptyNote>{bundle.observation.source} is not matched to a registered source record.</EmptyNote>
              )}
              <MetaCell label="Platform" value={bundle.observation.platform ?? '—'} />
            </EntitySection>

            <EntitySection icon={<Database size={13} style={dw.critical} />} title={`Related evidence (${bundle.evidence.length})`}>
              {bundle.evidence.length > 0 ? bundle.evidence.map(item => (
                <div key={item.id} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                  <div className="flex items-center justify-between">
                    <span style={dw.burg}>{item.id}</span>
                    <span style={dw.faint}>{item.evidenceType.replace(/_/g, ' ')}</span>
                  </div>
                  <p className="mt-1 leading-relaxed" style={dw.muted}>{item.provenance}</p>
                </div>
              )) : (
                <EmptyNote>No evidence references this observation yet.</EmptyNote>
              )}
              <EntityLink to={ENTITY_PATH.evidence}>Open evidence locker →</EntityLink>
            </EntitySection>

            <EntitySection icon={<Clock size={13} style={dw.critical} />} title={`Timeline contribution (${bundle.timeline.length})`}>
              {bundle.timeline.length > 0 ? bundle.timeline.slice(0, 5).map(event => (
                <div key={event.id} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                  <div className="flex items-center justify-between">
                    <span style={dw.text}>{event.title}</span>
                    <span style={dw.faint}>{new Date(event.time).toLocaleDateString()}</span>
                  </div>
                  <p className="mt-0.5" style={dw.muted}>{event.actorId}</p>
                </div>
              )) : (
                <EmptyNote>Recording an observation against an actor also writes a timeline event — this one is unattributed.</EmptyNote>
              )}
              {bundle.actor && <EntityLink to={`${ENTITY_PATH.timeline}?actor=${bundle.actor.id}`}>Open full timeline →</EntityLink>}
            </EntitySection>

            <EntitySection icon={<Network size={13} style={dw.critical} />} title={`Relationships (${bundle.relationships.length})`}>
              {bundle.relationships.length > 0 ? bundle.relationships.slice(0, 6).map(rel => (
                <div key={rel.id} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                  <div className="flex items-center justify-between gap-2">
                    <RelationshipChip type={rel.type} confidence={rel.confidence} />
                    <span style={dw.faint}>{rel.id}</span>
                  </div>
                  <p className="mt-1" style={dw.text}>{rel.sourceEntity} → {rel.targetEntity}</p>
                </div>
              )) : (
                <EmptyNote>No relationship is derived from this observation yet.</EmptyNote>
              )}
              <EntityLink to={ENTITY_PATH.graph}>Open relationship graph →</EntityLink>
            </EntitySection>

            <EntitySection icon={<Network size={13} style={dw.critical} />} title="Related investigation">
              {bundle.investigation ? (
                <Link
                  to={`${ENTITY_PATH.investigations}/${bundle.investigation.id}`}
                  className="block p-2.5 rounded-sm border font-mono text-[10px]"
                  style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}
                >
                  <p style={dw.text}>{bundle.investigation.title}</p>
                  <p className="mt-0.5" style={dw.faint}>{bundle.investigation.id} · {bundle.investigation.status}</p>
                </Link>
              ) : (
                <EmptyNote>This observation is not yet attached to an investigation.</EmptyNote>
              )}
            </EntitySection>
          </div>
        </div>
      </div>
    </motion.div>
  );
}
