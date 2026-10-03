import { useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
  Users, Search, Key, Wallet, Database, Clock, Layers,
  Network, FileText, Globe, Fingerprint,
} from 'lucide-react';
import { dw, sectionStyle } from '../../lib/darkweb/styles';
import { useIntelligence } from '../../lib/intelligence/IntelligenceContext';
import { handleBundle, handlePath, actorPath, pgpPath, walletPath, ENTITY_PATH } from '../../lib/intelligence/entityBundles';
import { ConfidenceBar } from '../../components/ui/ConfidenceBar';
import { RelationshipChip } from '../../components/darkweb/RelationshipChip';
import {
  EntityLink, EntityPageHeader, EntityRow, EntitySection,
  EmptyNote, EmptySelection, MetaCell, RecordEntityLink,
  entityInputClass, entityInputStyle, selectStyle,
} from '../../components/darkweb/EntityWorkspace';
import { ProtectionModulePanel } from '../../components/darkweb/ProtectionModulePanel';

// ============================================================
// Handle Intelligence — identity / alias exploration.
//
// A handle is the weakest identifier in the set, so this workspace is
// built around reuse: the same normalized string on several
// platforms, the actors it resolves to, and the cryptographic and
// financial identities that make that reuse attributable.
//
// Read-only. Every value comes from the centralized handle record
// through the shared entity bundle; this page creates nothing.
// ============================================================
export default function HandleIntelligencePage() {
  const { dataset } = useIntelligence();
  const [search, setSearch] = useState('');
  const [platformFilter, setPlatformFilter] = useState<string>('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const platforms = useMemo(
    () => Array.from(new Set(dataset.handles.map(handle => handle.platform))).sort(),
    [dataset.handles],
  );

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    return dataset.handles.filter(handle => {
      if (platformFilter !== 'all' && handle.platform !== platformFilter) return false;
      if (!query) return true;
      return (
        handle.value.toLowerCase().includes(query) ||
        (handle.normalized ?? '').toLowerCase().includes(query) ||
        handle.id.toLowerCase().includes(query) ||
        (handle.actorId ?? '').toLowerCase().includes(query)
      );
    });
  }, [dataset.handles, search, platformFilter]);

  // Reuse counts are the analytical point of the page, so they are
  // computed once for the whole model rather than per row.
  const reuseCount = useMemo(() => {
    const tally = new Map<string, number>();
    for (const handle of dataset.handles) {
      const key = (handle.normalized || handle.value).toLowerCase();
      tally.set(key, (tally.get(key) ?? 0) + 1);
    }
    return tally;
  }, [dataset.handles]);

  const reusedIdentities = useMemo(
    () => [...reuseCount.values()].filter(count => count > 1).length,
    [reuseCount],
  );

  const selectedRef = selectedId ?? filtered[0]?.id ?? dataset.handles[0]?.id ?? null;
  const bundle = useMemo(
    () => (selectedRef ? handleBundle(dataset, selectedRef) : null),
    [dataset, selectedRef],
  );

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">

        <EntityPageHeader
          icon={<Users size={18} style={dw.critical} />}
          eyebrow="Identity Explorer"
          title="Handle Intelligence"
          byline="Every handle, alias and username recorded through Add Intelligence. A handle is a reusable string, so the analysis is about reuse: the same normalized identity across platforms, the actor it resolves to, and the PGP keys and wallets that make the reuse attributable."
          stats={[
            { label: 'Handles', value: dataset.handles.length },
            { label: 'Reused identities', value: reusedIdentities, color: dw.burg },
            { label: 'Unattributed', value: dataset.handles.filter(handle => !handle.actorId).length, color: dw.muted },
          ]}
        />

        <div className="flex flex-col md:flex-row gap-3 items-center justify-between">
          <div className="relative w-full md:w-80">
            <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: 'var(--tw-text-faint)' }} />
            <input
              value={search}
              onChange={event => setSearch(event.target.value)}
              placeholder="Search handle, alias, id or actor…"
              className={entityInputClass}
              style={entityInputStyle}
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[10px]" style={dw.faint}>PLATFORM:</span>
            <select
              value={platformFilter}
              onChange={event => setPlatformFilter(event.target.value)}
              className="font-mono text-[10px] px-2 py-1.5 rounded-sm focus:outline-none"
              style={selectStyle}
            >
              <option value="all">ALL PLATFORMS</option>
              {platforms.map(platform => <option key={platform} value={platform}>{platform}</option>)}
            </select>
            <RecordEntityLink to="/app/darkweb/add" label="+ Record handle" />
          </div>
        </div>

        <div className="grid lg:grid-cols-12 gap-6">
          <div className="lg:col-span-5 space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>HANDLE RECORDS ({filtered.length})</span>
              <span className="font-mono text-[9px]" style={dw.faint}>CLICK TO INSPECT</span>
            </div>
            <div className="space-y-2 max-h-[620px] overflow-y-auto pr-1">
              {filtered.map(handle => {
                const reuse = reuseCount.get((handle.normalized || handle.value).toLowerCase()) ?? 1;
                return (
                  <EntityRow key={handle.id} selected={bundle?.handle.id === handle.id} onClick={() => setSelectedId(handle.id)}>
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="flex items-center gap-1.5 mb-1">
                          <span className="font-mono text-[9px] uppercase px-1 py-0.5 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)', color: 'var(--tw-text-muted)' }}>
                            {handle.id}
                          </span>
                          {reuse > 1 && (
                            <span className="font-mono text-[9px] uppercase px-1 py-0.5 rounded-sm" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-burgundy) 15%, transparent)', color: 'var(--tw-burgundy)' }}>
                              REUSED ×{reuse}
                            </span>
                          )}
                        </div>
                        <p className="font-mono text-xs font-medium truncate" style={dw.text}>@{handle.value}</p>
                      </div>
                      <span className="font-mono text-[9px] shrink-0" style={dw.faint}>{handle.confidence}%</span>
                    </div>
                    <div className="flex items-center justify-between mt-2 pt-2 border-t font-mono text-[9px]" style={{ borderColor: 'var(--tw-border-mid)' }}>
                      <span style={dw.muted}>{handle.platform}</span>
                      <span style={handle.actorId ? dw.burg : dw.faint}>{handle.actorId ?? 'unattributed'}</span>
                    </div>
                  </EntityRow>
                );
              })}
              {filtered.length === 0 && (
                <p className="font-mono text-[10px] p-4 rounded-sm border" style={{ ...dw.panel, ...dw.muted }}>
                  No handle matches the current filter.
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
                        <span className="font-mono text-[10px] tracking-wider uppercase" style={dw.burg}>{bundle.handle.id}</span>
                        <span className="font-mono text-[9px] px-1.5 py-0.5 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)', color: 'var(--tw-text-muted)' }}>
                          {bundle.handle.platform}
                        </span>
                        {bundle.handle.dataState && (
                          <span className="font-mono text-[9px] uppercase" style={dw.faint}>{bundle.handle.dataState.replace(/_/g, ' ')}</span>
                        )}
                      </div>
                      <h2 className="font-mono text-xl font-bold mt-1 break-all" style={dw.text}>@{bundle.handle.value}</h2>
                      <p className="font-mono text-[10px] mt-0.5" style={dw.muted}>
                        Normalizes to <span style={dw.text}>@{bundle.handle.normalized}</span>
                      </p>
                    </div>
                    <Link
                      to={handlePath(bundle.handle.id)}
                      className="font-mono text-[10px] tracking-wider uppercase px-2.5 py-1.5 rounded-sm border shrink-0"
                      style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-burgundy)' }}
                    >
                      Open dossier
                    </Link>
                  </div>

                  <div className="grid sm:grid-cols-3 gap-3 p-3 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)' }}>
                    <MetaCell label="First seen" value={new Date(bundle.handle.firstSeen).toLocaleDateString()} />
                    <MetaCell label="Last seen" value={new Date(bundle.handle.lastSeen).toLocaleDateString()} />
                    <MetaCell label="Source" value={bundle.handle.sourceId || bundle.handle.source || '—'} />
                  </div>

                  <div className="space-y-1">
                    <ConfidenceBar value={bundle.handle.confidence} />
                    <p className="font-mono text-[9px]" style={dw.faint}>
                      Attribution confidence carried on the handle record itself.
                    </p>
                  </div>

                  <div className="flex flex-wrap gap-2 pt-1">
                    {bundle.actors.map(actor => (
                      <EntityLink key={actor.id} to={actorPath(actor.id)}>
                        <Users size={10} /> {actor.id} — {actor.aliases[0] ?? actor.id}
                      </EntityLink>
                    ))}
                    {bundle.pgpKeys.map(key => (
                      <EntityLink key={key.id} to={pgpPath(key.id)} accent="var(--tw-brass)">
                        <Key size={10} /> {key.id}
                      </EntityLink>
                    ))}
                    {bundle.wallets.map(wallet => (
                      <EntityLink key={wallet.id} to={walletPath(wallet.id)} accent="var(--tw-info)">
                        <Wallet size={10} /> {wallet.id}
                      </EntityLink>
                    ))}
                    <EntityLink to={`${ENTITY_PATH.correlation}?handle=${encodeURIComponent(bundle.handle.value)}`}>
                      <Fingerprint size={10} /> Identity correlation
                    </EntityLink>
                    <EntityLink to={`${ENTITY_PATH.graph}?focus=${encodeURIComponent(bundle.handle.id)}`}>
                      <Network size={10} /> Graph
                    </EntityLink>
                  </div>
                </div>

                <EntitySection icon={<Layers size={13} style={dw.critical} />} title={`Why linked? (${bundle.whyLinked.length})`}>
                  {bundle.whyLinked.length > 0 ? (
                    <div className="space-y-2">
                      {bundle.whyLinked.map((entry, index) => (
                        <div key={index} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                          <div className="flex items-center justify-between gap-2">
                            <span style={dw.burg}>{entry.indicator}</span>
                            <span style={dw.faint}>{entry.source}</span>
                          </div>
                          <p className="mt-1 leading-relaxed" style={dw.muted}>{entry.detail}</p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <EmptyNote>No stored relationship or shared identity explains this handle yet.</EmptyNote>
                  )}
                </EntitySection>

                <div className="grid md:grid-cols-2 gap-4">
                  <EntitySection icon={<Users size={13} style={dw.critical} />} title={`Aliases & platform reuse (${bundle.aliasHandles.length})`}>
                    {bundle.aliasHandles.length > 0 ? (
                      <div className="space-y-2">
                        {bundle.aliasHandles.map(alias => (
                          <button
                            key={alias.id}
                            type="button"
                            onClick={() => setSelectedId(alias.id)}
                            className="w-full p-2.5 rounded-sm border text-left font-mono text-[10px]"
                            style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}
                          >
                            <div className="flex items-center justify-between">
                              <span style={dw.text}>@{alias.value}</span>
                              <span style={dw.faint}>{alias.platform}</span>
                            </div>
                            <div className="flex items-center justify-between mt-1">
                              <span style={dw.muted}>{alias.id}</span>
                              <span style={dw.faint}>
                                {new Date(alias.firstSeen).toLocaleDateString()} → {new Date(alias.lastSeen).toLocaleDateString()}
                              </span>
                            </div>
                          </button>
                        ))}
                      </div>
                    ) : (
                      <EmptyNote>This identity appears on a single platform — no cross-platform reuse recorded.</EmptyNote>
                    )}
                    {bundle.platforms.length > 1 && (
                      <div className="pt-1">
                        <span className="font-mono text-[9px] uppercase block mb-1" style={dw.faint}>Platforms</span>
                        <div className="flex flex-wrap gap-1">
                          {bundle.platforms.map(platform => (
                            <span key={platform} className="font-mono text-[9px] px-1.5 py-0.5 rounded-sm border" style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}>
                              {platform}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </EntitySection>

                  <EntitySection icon={<Database size={13} style={dw.critical} />} title={`Related evidence (${bundle.evidence.length})`}>
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
                      <EmptyNote>No evidence is linked to this identity yet.</EmptyNote>
                    )}
                    {bundle.actors[0] && (
                      <EntityLink to={`${ENTITY_PATH.evidence}?actor=${bundle.actors[0].id}`}>Open evidence locker →</EntityLink>
                    )}
                  </EntitySection>
                </div>

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
                            <p className="mt-0.5 leading-relaxed" style={dw.muted}>{rel.explanation}</p>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <EmptyNote>No relationship references this handle.</EmptyNote>
                    )}
                  </EntitySection>

                  <EntitySection icon={<Clock size={13} style={dw.critical} />} title={`Activity (${bundle.timeline.length} events)`}>
                    {bundle.timeline.length > 0 ? (
                      <div className="space-y-2">
                        {bundle.timeline.slice(0, 6).map(event => (
                          <div key={event.id} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                            <div className="flex items-center justify-between">
                              <span style={dw.text}>{event.title}</span>
                              <span style={dw.faint}>{new Date(event.time).toLocaleDateString()}</span>
                            </div>
                            <p className="mt-0.5" style={dw.muted}>{event.type.replace(/_/g, ' ')} — {event.actorId}</p>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <EmptyNote>No timeline event is attributed to this handle.</EmptyNote>
                    )}
                    {bundle.actors[0] && (
                      <EntityLink to={`${ENTITY_PATH.timeline}?actor=${bundle.actors[0].id}`}>Open full timeline →</EntityLink>
                    )}
                  </EntitySection>
                </div>

                <EntitySection icon={<FileText size={13} style={dw.critical} />} title={`Investigations (${bundle.investigations.length})`}>
                  {bundle.investigations.length > 0 ? (
                    <div className="space-y-2">
                      {bundle.investigations.map(inv => (
                        <Link
                          key={inv.id}
                          to={`${ENTITY_PATH.investigations}/${inv.id}`}
                          className="block p-2.5 rounded-sm border font-mono text-[10px]"
                          style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}
                        >
                          <div className="flex items-center justify-between">
                            <span style={dw.text}>{inv.title}</span>
                            <span style={inv.status === 'ACTIVE' ? dw.moss : dw.faint}>{inv.status}</span>
                          </div>
                          <p className="mt-0.5" style={dw.muted}>
                            {inv.id} · seeded from {inv.seedActorId} · {inv.confidence}% confidence
                          </p>
                        </Link>
                      ))}
                    </div>
                  ) : (
                    <EmptyNote>This handle is not yet part of an investigation.</EmptyNote>
                  )}
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
              </>
            ) : (
              <EmptySelection icon={<Users size={32} />} message="Select a handle record to open its identity dossier." />
            )}
          </div>
        </div>

        <ProtectionModulePanel entityType="HANDLE" />
      </div>
    </motion.div>
  );
}
