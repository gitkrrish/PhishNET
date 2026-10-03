import { useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
  FileJson, Search, Database, Clock, Network, FileText, Globe,
  Layers, Key, Wallet, Server, Users, Fingerprint, ArrowRight, Tags,
} from 'lucide-react';
import { dw, sectionStyle } from '../../lib/darkweb/styles';
import { useIntelligence } from '../../lib/intelligence/IntelligenceContext';
import { observationBundle, observationPath, actorPath, handlePath, pgpPath, walletPath, ENTITY_PATH } from '../../lib/intelligence/entityBundles';
import { ConfidenceBar } from '../../components/ui/ConfidenceBar';
import { RelationshipChip } from '../../components/darkweb/RelationshipChip';
import {
  EntityLink, EntityPageHeader, EntityRow, EntitySection,
  EmptyNote, EmptySelection, MetaCell, RecordEntityLink,
  entityInputClass, entityInputStyle, selectStyle,
} from '../../components/darkweb/EntityWorkspace';
import { ProtectionModulePanel } from '../../components/darkweb/ProtectionModulePanel';

// ============================================================
// Raw Intelligence Observation.
//
// The observation is the atomic unit of collection, so this
// workspace is laid out as a four-stage intelligence pipeline and
// never blurs the stages:
//
//   1. RAW OBSERVATION       verbatim captured text, as received
//   2. EXTRACTED INTELLIGENCE entities named by that text
//   3. NORMALIZED ENTITY     the subset that already exists in the
//                            central model under a canonical form
//   4. CORRELATED INTELLIGENCE actor, handle, evidence, timeline,
//                            relationships and investigation
//
// Only the central observation record is read. This page creates
// nothing and stores nothing.
// ============================================================

const STAGES = [
  { key: 'raw', label: 'Raw observation', icon: FileJson, color: 'var(--tw-text-muted)' },
  { key: 'extracted', label: 'Extracted intelligence', icon: Fingerprint, color: 'var(--tw-brass)' },
  { key: 'normalized', label: 'Normalized entity', icon: Layers, color: 'var(--tw-info)' },
  { key: 'correlated', label: 'Correlated intelligence', icon: Network, color: 'var(--tw-burgundy)' },
] as const;

type StageKey = (typeof STAGES)[number]['key'];

const ENTITY_ICON = {
  Handle: Users,
  PGP: Key,
  Wallet,
  Infrastructure: Server,
  Actor: Users,
  Source: Globe,
} as const;

export default function ObservationIntelligencePage() {
  const { dataset } = useIntelligence();
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [stage, setStage] = useState<StageKey>('raw');

  const types = useMemo(
    () => Array.from(new Set(dataset.observations.map(obs => obs.observationType))).sort(),
    [dataset.observations],
  );

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    return dataset.observations
      .filter(obs => {
        if (typeFilter !== 'all' && obs.observationType !== typeFilter) return false;
        if (!query) return true;
        return (
          obs.content.toLowerCase().includes(query) ||
          obs.id.toLowerCase().includes(query) ||
          obs.source.toLowerCase().includes(query) ||
          (obs.platform ?? '').toLowerCase().includes(query) ||
          obs.tags.some(tag => tag.toLowerCase().includes(query))
        );
      })
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }, [dataset.observations, search, typeFilter]);

  const selectedRef = selectedId ?? filtered[0]?.id ?? dataset.observations[0]?.id ?? null;
  const bundle = useMemo(
    () => (selectedRef ? observationBundle(dataset, selectedRef) : null),
    [dataset, selectedRef],
  );

  const stageValue = useMemo(() => {
    if (!bundle) return { extracted: 0, normalized: 0, correlated: 0 };
    return {
      extracted: bundle.extracted.length,
      normalized: bundle.normalized.length,
      correlated:
        (bundle.actor ? 1 : 0) +
        (bundle.handle ? 1 : 0) +
        bundle.pgpKeys.length +
        bundle.wallets.length +
        bundle.infrastructure.length +
        bundle.evidence.length +
        bundle.timeline.length +
        bundle.relationships.length +
        (bundle.investigation ? 1 : 0),
    };
  }, [bundle]);

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">

        <EntityPageHeader
          icon={<FileJson size={18} style={dw.critical} />}
          eyebrow="Raw Intelligence Collection"
          title="Observation Intelligence"
          byline="Every raw observation recorded through Add Intelligence, shown as the four-stage pipeline it actually is: verbatim capture, entities named by that text, the subset already normalized into the central model, and the correlated actor, evidence, timeline and investigation the observation now feeds. The stages are never merged — an extracted string is not an entity until the model holds it."
          stats={[
            { label: 'Observations', value: dataset.observations.length },
            { label: 'Correlated to actor', value: dataset.observations.filter(obs => obs.actorId).length, color: dw.burg },
            { label: 'Unprocessed', value: dataset.observations.filter(obs => !obs.actorId && !obs.handleId).length, color: dw.muted },
          ]}
        />

        <div className="flex flex-col md:flex-row gap-3 items-center justify-between">
          <div className="relative w-full md:w-80">
            <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: 'var(--tw-text-faint)' }} />
            <input
              value={search}
              onChange={event => setSearch(event.target.value)}
              placeholder="Search raw text, id, source or tag…"
              className={entityInputClass}
              style={entityInputStyle}
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[10px]" style={dw.faint}>TYPE:</span>
            <select
              value={typeFilter}
              onChange={event => setTypeFilter(event.target.value)}
              className="font-mono text-[10px] px-2 py-1.5 rounded-sm focus:outline-none"
              style={selectStyle}
            >
              <option value="all">ALL TYPES</option>
              {types.map(type => <option key={type} value={type}>{type.replace(/_/g, ' ')}</option>)}
            </select>
            <RecordEntityLink to="/app/darkweb/add" label="+ Record observation" />
          </div>
        </div>

        <div className="grid lg:grid-cols-12 gap-6">
          <div className="lg:col-span-5 space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>OBSERVATION LOG ({filtered.length})</span>
              <span className="font-mono text-[9px]" style={dw.faint}>NEWEST FIRST</span>
            </div>
            <div className="space-y-2 max-h-[620px] overflow-y-auto pr-1">
              {filtered.map(obs => (
                <EntityRow key={obs.id} selected={bundle?.observation.id === obs.id} onClick={() => setSelectedId(obs.id)}>
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5 mb-1">
                        <span className="font-mono text-[9px] uppercase px-1 py-0.5 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)', color: 'var(--tw-text-muted)' }}>
                          {obs.id}
                        </span>
                        <span className="font-mono text-[9px] uppercase" style={dw.brass}>
                          {obs.observationType.replace(/_/g, ' ')}
                        </span>
                      </div>
                      <p className="font-mono text-[10px] line-clamp-2" style={dw.text}>{obs.content}</p>
                    </div>
                    <span className="font-mono text-[9px] shrink-0" style={dw.faint}>{obs.confidence}%</span>
                  </div>
                  <div className="flex items-center justify-between mt-2 pt-2 border-t font-mono text-[9px]" style={{ borderColor: 'var(--tw-border-mid)' }}>
                    <span style={dw.muted}>{obs.source}</span>
                    <span style={obs.actorId ? dw.burg : dw.faint}>{obs.actorId ?? 'uncorrelated'}</span>
                  </div>
                </EntityRow>
              ))}
              {filtered.length === 0 && (
                <p className="font-mono text-[10px] p-4 rounded-sm border" style={{ ...dw.panel, ...dw.muted }}>
                  No observation matches the current filter.
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
                        <span className="font-mono text-[10px] tracking-wider uppercase" style={dw.burg}>{bundle.observation.id}</span>
                        <span className="font-mono text-[9px] px-1.5 py-0.5 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)', color: 'var(--tw-text-muted)' }}>
                          {bundle.observation.observationType.replace(/_/g, ' ')}
                        </span>
                      </div>
                      <p className="text-sm mt-1" style={dw.muted}>
                        Collected {new Date(bundle.observation.timestamp).toLocaleString()} from{' '}
                        <span className="font-mono" style={dw.text}>{bundle.observation.source}</span>
                        {bundle.observation.platform ? <> on <span className="font-mono" style={dw.text}>{bundle.observation.platform}</span></> : null}.
                      </p>
                    </div>
                    <Link
                      to={observationPath(bundle.observation.id)}
                      className="font-mono text-[10px] tracking-wider uppercase px-2.5 py-1.5 rounded-sm border shrink-0"
                      style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-burgundy)' }}
                    >
                      Open record
                    </Link>
                  </div>

                  <div className="grid sm:grid-cols-3 gap-3 p-3 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)' }}>
                    <MetaCell label="Collection timestamp" value={new Date(bundle.observation.timestamp).toLocaleString()} />
                    <MetaCell label="Processing status" value={bundle.processingStatus.label} />
                    <MetaCell label="Analyst / provenance" value={bundle.observation.analyst || bundle.observation.dataState} />
                  </div>

                  <div className="space-y-1">
                    <ConfidenceBar value={bundle.observation.confidence} />
                    <p className="font-mono text-[9px]" style={dw.faint}>
                      {bundle.processingStatus.detail}
                    </p>
                  </div>

                  {bundle.observation.tags.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1.5">
                      <Tags size={11} style={dw.faint} />
                      {bundle.observation.tags.map(tag => (
                        <span key={tag} className="font-mono text-[9px] px-1.5 py-0.5 rounded-sm border" style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}>
                          {tag}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                {/* The four stages, kept visibly separate. */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                  {STAGES.map(item => {
                    const Icon = item.icon;
                    const active = stage === item.key;
                    const count =
                      item.key === 'raw' ? 1 :
                      item.key === 'extracted' ? stageValue.extracted :
                      item.key === 'normalized' ? stageValue.normalized :
                      stageValue.correlated;
                    return (
                      <button
                        key={item.key}
                        type="button"
                        onClick={() => setStage(item.key)}
                        className="p-3 rounded-sm border text-left transition-all"
                        style={{
                          backgroundColor: active ? 'var(--tw-panel-alt)' : 'var(--tw-panel)',
                          borderColor: active ? item.color : 'var(--tw-border-mid)',
                          borderLeftWidth: active ? '3px' : '1px',
                          borderLeftColor: active ? item.color : 'var(--tw-border-mid)',
                        }}
                      >
                        <div className="flex items-center gap-1.5">
                          <Icon size={12} style={{ color: item.color }} />
                          <span className="font-mono text-[9px] uppercase" style={dw.muted}>{item.label}</span>
                        </div>
                        <p className="font-mono text-lg mt-1" style={count ? dw.text : dw.faint}>{count}</p>
                      </button>
                    );
                  })}
                </div>

                {stage === 'raw' && (
                  <EntitySection icon={<FileJson size={13} style={dw.critical} />} title="Raw observation — verbatim capture">
                    <div className="p-4 rounded-sm border" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                      <pre className="font-mono text-xs whitespace-pre-wrap break-words" style={dw.text}>{bundle.observation.content}</pre>
                    </div>
                    {bundle.observation.notes && (
                      <div>
                        <span className="font-mono text-[9px] uppercase block mb-1" style={dw.faint}>Analyst notes</span>
                        <p className="font-mono text-[10px] leading-relaxed" style={dw.muted}>{bundle.observation.notes}</p>
                      </div>
                    )}
                    <p className="font-mono text-[9px] leading-relaxed" style={dw.faint}>
                      This text is stored exactly as captured. Nothing below is inferred from it until the next stage.
                    </p>
                  </EntitySection>
                )}

                {stage === 'extracted' && (
                  <EntitySection
                    icon={<Fingerprint size={13} style={dw.critical} />}
                    title={`Extracted intelligence — entities named by this text (${bundle.extracted.length})`}
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
                    <p className="font-mono text-[9px] leading-relaxed" style={dw.faint}>
                      Extraction is a read of the raw text against records the model already holds. An
                      unresolved string is a lead, not an entity.
                    </p>
                  </EntitySection>
                )}

                {stage === 'normalized' && (
                  <EntitySection
                    icon={<Layers size={13} style={dw.critical} />}
                    title={`Normalized entity — held in the central model (${bundle.normalized.length})`}
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
                        Nothing in this observation has been normalized into a central entity yet. Record the
                        handle, key, wallet or infrastructure it names and it will appear here on the next read.
                      </EmptyNote>
                    )}
                  </EntitySection>
                )}

                {stage === 'correlated' && (
                  <div className="space-y-4">
                    <div className="grid md:grid-cols-2 gap-4">
                      <EntitySection icon={<Users size={13} style={dw.critical} />} title="Related actor & handle">
                        <div className="space-y-2">
                          {bundle.actor ? (
                            <Link to={actorPath(bundle.actor.id)} className="block p-2.5 rounded-sm border" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                              <p className="font-mono text-sm" style={dw.burg}>{bundle.actor.aliases[0] ?? bundle.actor.id}</p>
                              <p className="font-mono text-[9px]" style={dw.faint}>{bundle.actor.id} · {bundle.actor.status}</p>
                            </Link>
                          ) : (
                            <EmptyNote>No actor is attributed to this observation yet.</EmptyNote>
                          )}
                          {bundle.handle ? (
                            <Link to={handlePath(bundle.handle.id)} className="block p-2.5 rounded-sm border" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                              <p className="font-mono text-xs" style={dw.text}>@{bundle.handle.value}</p>
                              <p className="font-mono text-[9px]" style={dw.faint}>{bundle.handle.id} · {bundle.handle.platform}</p>
                            </Link>
                          ) : (
                            <EmptyNote>No handle is linked to this observation yet.</EmptyNote>
                          )}
                        </div>
                      </EntitySection>

                      <EntitySection icon={<Globe size={13} style={dw.critical} />} title="Source & platform">
                        <div className="space-y-2">
                          {bundle.source ? (
                            <Link to={ENTITY_PATH.sources} className="block p-2.5 rounded-sm border" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                              <p className="font-mono text-xs" style={dw.text}>{bundle.source.name}</p>
                              <p className="font-mono text-[9px]" style={dw.faint}>{bundle.source.type} · R{bundle.source.reliabilityScore} · {bundle.source.status}</p>
                            </Link>
                          ) : (
                            <EmptyNote>{bundle.observation.source} is not matched to a registered source record.</EmptyNote>
                          )}
                          <MetaCell label="Platform" value={bundle.observation.platform ?? '—'} />
                          <MetaCell label="Source label" value={bundle.observation.source} />
                        </div>
                      </EntitySection>
                    </div>

                    <div className="grid md:grid-cols-3 gap-4">
                      <EntitySection icon={<Key size={13} style={dw.critical} />} title={`Related PGP (${bundle.pgpKeys.length})`}>
                        {bundle.pgpKeys.length > 0 ? bundle.pgpKeys.map(key => (
                          <Link key={key.id} to={pgpPath(key.id)} className="block p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                            <p className="break-all" style={dw.text}>{key.fingerprint}</p>
                            <p style={dw.faint}>{key.id} · {key.confidence}%</p>
                          </Link>
                        )) : <EmptyNote>No PGP key is named in this observation.</EmptyNote>}
                      </EntitySection>

                      <EntitySection icon={<Wallet size={13} style={dw.critical} />} title={`Related wallets (${bundle.wallets.length})`}>
                        {bundle.wallets.length > 0 ? bundle.wallets.map(wallet => (
                          <Link key={wallet.id} to={walletPath(wallet.id)} className="block p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                            <p className="break-all" style={dw.text}>{wallet.address}</p>
                            <p style={dw.faint}>{wallet.id} · {wallet.txCount} tx</p>
                          </Link>
                        )) : <EmptyNote>No wallet is named in this observation.</EmptyNote>}
                      </EntitySection>

                      <EntitySection icon={<Server size={13} style={dw.critical} />} title={`Related infrastructure (${bundle.infrastructure.length})`}>
                        {bundle.infrastructure.length > 0 ? bundle.infrastructure.map(infra => (
                          <Link key={infra.id} to={ENTITY_PATH.infrastructure} className="block p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                            <p className="break-all" style={dw.text}>{infra.value}</p>
                            <p style={dw.faint}>{infra.id} · {infra.type}</p>
                          </Link>
                        )) : <EmptyNote>No infrastructure is named in this observation.</EmptyNote>}
                      </EntitySection>
                    </div>

                    <div className="grid md:grid-cols-2 gap-4">
                      <EntitySection icon={<Database size={13} style={dw.critical} />} title={`Related evidence (${bundle.evidence.length})`}>
                        {bundle.evidence.length > 0 ? bundle.evidence.map(item => (
                          <div key={item.id} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                            <div className="flex items-center justify-between">
                              <span style={dw.burg}>{item.id} · {item.evidenceType.replace(/_/g, ' ')}</span>
                              <span style={dw.faint}>{new Date(item.timestamp).toLocaleDateString()}</span>
                            </div>
                            <p className="mt-1 leading-relaxed" style={dw.muted}>{item.provenance}</p>
                          </div>
                        )) : (
                          <EmptyNote>No evidence references this observation yet.</EmptyNote>
                        )}
                        <EntityLink to={ENTITY_PATH.evidence}>Open evidence locker →</EntityLink>
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
                    </div>

                    <div className="grid md:grid-cols-2 gap-4">
                      <EntitySection icon={<Clock size={13} style={dw.critical} />} title={`Timeline contribution (${bundle.timeline.length} events)`}>
                        {bundle.timeline.length > 0 ? bundle.timeline.slice(0, 5).map(event => (
                          <div key={event.id} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                            <div className="flex items-center justify-between">
                              <span style={dw.text}>{event.title}</span>
                              <span style={dw.faint}>{new Date(event.time).toLocaleDateString()}</span>
                            </div>
                            <p className="mt-0.5" style={dw.muted}>{event.actorId} · {event.type.replace(/_/g, ' ')}</p>
                          </div>
                        )) : (
                          <EmptyNote>Recording an observation against an actor also writes a timeline event — this one is unattributed.</EmptyNote>
                        )}
                        {bundle.actor && <EntityLink to={`${ENTITY_PATH.timeline}?actor=${bundle.actor.id}`}>Open full timeline →</EntityLink>}
                      </EntitySection>

                      <EntitySection icon={<FileText size={13} style={dw.critical} />} title="Related investigation">
                        {bundle.investigation ? (
                          <Link
                            to={`${ENTITY_PATH.investigations}/${bundle.investigation.id}`}
                            className="block p-2.5 rounded-sm border font-mono text-[10px]"
                            style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}
                          >
                            <div className="flex items-center justify-between">
                              <span style={dw.text}>{bundle.investigation.title}</span>
                              <span style={bundle.investigation.status === 'ACTIVE' ? dw.moss : dw.faint}>{bundle.investigation.status}</span>
                            </div>
                            <p className="mt-0.5 flex items-center gap-1" style={dw.burg}>
                              {bundle.investigation.id} <ArrowRight size={9} />
                            </p>
                          </Link>
                        ) : (
                          <EmptyNote>This observation is not yet attached to an investigation.</EmptyNote>
                        )}
                      </EntitySection>
                    </div>
                  </div>
                )}
              </>
            ) : (
              <EmptySelection icon={<FileJson size={32} />} message="Select an observation to open its raw intelligence record." />
            )}
          </div>
        </div>

        <ProtectionModulePanel entityType="OBSERVATION" />
      </div>
    </motion.div>
  );
}
