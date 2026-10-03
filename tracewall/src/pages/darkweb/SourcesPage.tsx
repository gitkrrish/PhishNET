import { useState, useMemo } from 'react';
import { Search, Database, Server, Wifi, Globe, AlertTriangle, Filter, Activity, ShieldCheck, Clock, ExternalLink } from 'lucide-react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import { dw, sectionStyle } from '../../lib/darkweb/styles';
import { useIntelligenceData, useIntelligence } from '../../lib/intelligence/IntelligenceContext';
import { collectionOverview } from '../../lib/intelligence/sources';
import { MetaCell } from '../../components/darkweb/EntityWorkspace';
import { ConfidenceBar } from '../../components/ui/ConfidenceBar';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { MonitorEntityButton } from '../../components/darkweb/MonitorEntityButton';
import { ProtectionModulePanel } from '../../components/darkweb/ProtectionModulePanel';

export default function SourcesPage() {
  const { darkWebSources, darkWebEvidence, darkWebObservations, darkWebActorsById } = useIntelligenceData();
  const { dataset } = useIntelligence();
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<string | 'all'>('all');
  const [statusFilter, setStatusFilter] = useState<string | 'all'>('all');
  const [selectedSourceId, setSelectedSourceId] = useState<string | null>(darkWebSources[0]?.id || null);

  const types = Array.from(new Set(darkWebSources.map(s => s.type)));
  const statuses = Array.from(new Set(darkWebSources.map(s => s.status)));

  const filtered = useMemo(() => {
    return darkWebSources.filter(s => {
      const q = search.toLowerCase();
      if (q && !(s.name.toLowerCase().includes(q) || s.description.toLowerCase().includes(q) || (s.onionAddress ?? '').toLowerCase().includes(q))) return false;
      if (typeFilter !== 'all' && s.type !== typeFilter) return false;
      if (statusFilter !== 'all' && s.status !== statusFilter) return false;
      return true;
    });
  }, [search, typeFilter, statusFilter, darkWebSources]);

  const selectedSource = useMemo(() => {
    return darkWebSources.find(s => s.id === selectedSourceId) || filtered[0] || null;
  }, [selectedSourceId, filtered, darkWebSources]);

  // Derived intelligence from this source
  const sourceEvidence = useMemo(() => {
    if (!selectedSource) return [];
    return darkWebEvidence.filter(e => e.source.toLowerCase().includes(selectedSource.name.toLowerCase()));
  }, [selectedSource, darkWebEvidence]);

  const sourceObservations = useMemo(() => {
    if (!selectedSource) return [];
    return darkWebObservations.filter(o => o.source.toLowerCase().includes(selectedSource.name.toLowerCase()));
  }, [selectedSource, darkWebObservations]);

  const totalIndicators = darkWebSources.reduce((acc, s) => acc + s.indicatorCount, 0);

  // Collection health is derived from the records themselves, so a source
  // whose own fields contradict each other is visible rather than trusted.
  const overview = useMemo(
    () => collectionOverview(darkWebSources, { evidence: darkWebEvidence }),
    [darkWebSources, darkWebEvidence],
  );
  const healthById = useMemo(
    () => Object.fromEntries(overview.sources.map(s => [s.id, s])),
    [overview],
  );
  const selectedHealth = selectedSource ? healthById[selectedSource.id] ?? null : null;

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">

        {/* Console Header */}
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b pb-5" style={{ borderColor: 'var(--tw-border-mid)' }}>
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Globe size={18} style={dw.critical} />
              <span className="font-mono text-[10px] tracking-widest uppercase" style={dw.burg}>SOURCE HEALTH CONSOLE</span>
              <DemoLabel />
            </div>
            <h1 className="font-serif text-3xl" style={dw.text}>Dark Web Source Intelligence</h1>
            <p className="text-xs max-w-2xl" style={dw.muted}>
              Operational console for continuous dark-web feeds, leak platforms, marketplaces, and messaging relays. Reliability ratings dynamically weight intelligence confidence.
            </p>
          </div>

          <div className="flex gap-2">
            <div className="rounded-sm border px-3 py-1.5 text-center" style={dw.panel}>
              <p className="font-mono text-[9px] uppercase" style={dw.faint}>ACTIVE FEEDS</p>
              <p className="font-mono text-sm" style={dw.moss}>{darkWebSources.filter(s => s.status === 'ACTIVE').length}</p>
            </div>
            <div className="rounded-sm border px-3 py-1.5 text-center" style={dw.panel}>
              <p className="font-mono text-[9px] uppercase" style={dw.faint}>TOTAL HARVEST</p>
              <p className="font-mono text-sm" style={dw.text}>{totalIndicators} IOCs</p>
            </div>
          </div>
        </div>

        {/* Search & Control Filter Bar */}
        <div className="flex flex-col md:flex-row gap-3 items-center justify-between">
          <div className="relative w-full md:w-80">
            <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: 'var(--tw-text-faint)' }} />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search sources, onion targets, descriptions…"
              className="w-full font-mono text-[11px] pl-8 pr-2 py-1.5 rounded-sm focus:outline-none"
              style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }}
            />
          </div>

          <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
            <select
              value={typeFilter}
              onChange={e => setTypeFilter(e.target.value)}
              className="font-mono text-[10px] px-2 py-1.5 rounded-sm focus:outline-none"
              style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }}
            >
              <option value="all">ALL TYPES</option>
              {types.map(t => <option key={t} value={t}>{t}</option>)}
            </select>

            <select
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
              className="font-mono text-[10px] px-2 py-1.5 rounded-sm focus:outline-none"
              style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }}
            >
              <option value="all">ALL STATUSES</option>
              {statuses.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
        </div>

        {/* Collection-wide health, before the per-source detail. */}
        <div className="rounded-sm border p-4 space-y-3" style={dw.panel}>
          <div className="flex items-center justify-between flex-wrap gap-2">
            <p className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>Collection health</p>
            <span className="font-mono text-[9px]" style={dw.faint}>
              AS OF {new Date(overview.asOf).toLocaleString()}
            </span>
          </div>

          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <MetaCell
              label="Collectable now"
              value={`${overview.total - overview.uncollectable}/${overview.total}`}
              color={overview.uncollectable ? dw.critical.color : dw.moss.color}
            />
            <MetaCell label="Access classes" value={Object.keys(overview.byAccessClass).length} />
            <MetaCell
              label="Lossy coverage"
              value={overview.lossyTypes.length ? overview.lossyTypes.length : 'none'}
              color={overview.lossyTypes.length ? dw.medium.color : undefined}
            />
            <MetaCell
              label="Record defects"
              value={overview.findingCodes.filter(c => c.severity === 'critical' || c.severity === 'warn').length}
              color={overview.findingCodes.some(c => c.severity === 'critical') ? dw.critical.color : undefined}
            />
          </div>

          <p className="font-mono text-[10px] leading-relaxed" style={dw.muted}>
            {overview.uncollectable} of {overview.total} sources carry fields that mean they cannot currently be
            collected from. This is a statement about these records, not about the services themselves: nothing here
            connected to, probed or contacted any source.
          </p>

          {overview.lossyTypes.length > 0 && (
            <p className="font-mono text-[9px] leading-relaxed" style={dw.medium}>
              Coverage gaps are not equally costly. {overview.lossyTypes.join(' and ')} sources do not retain what
              they publish, so a collection failure on those classes is permanent rather than retryable — which
              makes a gap there much harder to explain later than one on a forum or a feed.
            </p>
          )}

          {overview.findingCodes.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {overview.findingCodes.map(code => (
                <span
                  key={code.code}
                  className="font-mono text-[9px] px-1.5 py-0.5 rounded-sm border"
                  style={{
                    backgroundColor: 'var(--tw-panel-alt)',
                    borderColor: 'var(--tw-border-mid)',
                    color: code.severity === 'critical' || code.severity === 'warn' ? 'var(--tw-critical)' : 'var(--tw-text-muted)',
                  }}
                >
                  {code.code} ×{code.count}
                </span>
              ))}
            </div>
          )}

          <div className="p-2.5 rounded-sm border font-mono text-[9px] leading-relaxed space-y-1" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
            {overview.caveats.map(caveat => <p key={caveat} style={dw.faint}>· {caveat}</p>)}
          </div>
        </div>

        {/* Console 2-Column Specialized Layout */}
        <div className="grid lg:grid-cols-12 gap-6">

          {/* Left Column: Source Feed Operational Grid */}
          <div className="lg:col-span-5 space-y-3">
            <span className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>SOURCE FEEDS & COLLECTORS ({filtered.length})</span>

            <div className="space-y-2 max-h-[620px] overflow-y-auto pr-1">
              {filtered.map(source => {
                const isSelected = selectedSource?.id === source.id;
                const statusColor = source.status === 'ACTIVE' ? 'var(--tw-moss)' : 'var(--tw-medium)';
                const health = healthById[source.id];

                return (
                  <div
                    key={source.id}
                    onClick={() => setSelectedSourceId(source.id)}
                    className="p-3 rounded-sm border cursor-pointer transition-all"
                    style={{
                      backgroundColor: isSelected ? 'var(--tw-panel-alt)' : 'var(--tw-panel)',
                      borderColor: isSelected ? 'var(--tw-burgundy)' : 'var(--tw-border-mid)',
                      borderLeftWidth: isSelected ? '3px' : '1px',
                      borderLeftColor: isSelected ? 'var(--tw-burgundy)' : 'var(--tw-border-mid)',
                    }}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="flex items-center gap-1.5 mb-1 flex-wrap">
                          <span className="font-mono text-[9px] uppercase px-1 py-0.5 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)', color: 'var(--tw-text-muted)' }}>
                            {source.type}
                          </span>
                          <span className="font-mono text-[9px] uppercase" style={{ color: statusColor }}>
                            ● {source.status}
                          </span>
                          {health && (
                            <span
                              className="font-mono text-[9px] uppercase px-1 py-0.5 rounded-sm"
                              style={{
                                backgroundColor: health.worstSeverity === 'critical' || health.worstSeverity === 'warn'
                                  ? 'color-mix(in srgb, var(--tw-critical) 18%, transparent)'
                                  : 'var(--tw-canvas-mid)',
                                color: health.worstSeverity === 'critical' || health.worstSeverity === 'warn'
                                  ? 'var(--tw-critical)'
                                  : 'var(--tw-text-muted)',
                              }}
                              title={health.findings[0]?.detail}
                            >
                              {health.verdict}
                            </span>
                          )}
                          {health && !health.access.prerequisitesMet && (
                            <span className="font-mono text-[9px] uppercase px-1 py-0.5 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)', color: 'var(--tw-medium)' }}>
                              NO ACCESS
                            </span>
                          )}
                        </div>
                        <p className="font-serif text-sm font-bold truncate" style={dw.text}>{source.name}</p>
                      </div>
                      <div className="text-right shrink-0">
                        <span className="font-mono text-[10px] font-bold" style={dw.text}>R{source.reliabilityScore}</span>
                        <p className="font-mono text-[8px]" style={dw.faint}>RELIABILITY</p>
                      </div>
                    </div>

                    <p className="font-mono text-[10px] line-clamp-1 mt-1" style={dw.muted}>{source.description}</p>

                    <div className="flex items-center justify-between mt-2 pt-2 border-t font-mono text-[9px]" style={{ borderColor: 'var(--tw-border-mid)' }}>
                      <span style={dw.faint}>{source.actorCount} ACTORS TRACKED</span>
                      <span style={dw.muted}>{source.indicatorCount} INDICATORS</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right Column: Source Inspection & Health Diagnostics Panel */}
          <div className="lg:col-span-7 space-y-4">
            {selectedSource ? (
              <>
                {selectedHealth && (
                  <div className="rounded-sm border p-4 space-y-3" style={dw.panel}>
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <p className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>
                        Access &amp; collection health
                      </p>
                      <span
                        className="font-mono text-[9px] uppercase px-1.5 py-0.5 rounded-sm"
                        style={{
                          backgroundColor: selectedHealth.access.prerequisitesMet ? 'var(--tw-canvas-mid)' : 'color-mix(in srgb, var(--tw-critical) 18%, transparent)',
                          color: selectedHealth.access.prerequisitesMet ? 'var(--tw-text-muted)' : 'var(--tw-critical)',
                        }}
                      >
                        {selectedHealth.verdict}
                      </span>
                    </div>

                    <div className="grid sm:grid-cols-3 gap-3">
                      <MetaCell label="Access class" value={selectedHealth.access.label} />
                      <MetaCell
                        label="Persistence"
                        value={selectedHealth.access.persistence.replace(/_/g, ' ')}
                        color={selectedHealth.access.persistence === 'REAL_TIME_ONLY' || selectedHealth.access.persistence === 'TRANSIENT' ? dw.medium.color : undefined}
                      />
                      <MetaCell
                        label="Days since seen"
                        value={selectedHealth.daysSinceLastObserved ?? 'unreadable'}
                        color={(selectedHealth.daysSinceLastObserved ?? 0) > 30 ? dw.critical.color : undefined}
                      />
                    </div>

                    <div>
                      <p className="font-mono text-[9px] tracking-widest uppercase mb-1" style={dw.muted}>Required before collection</p>
                      <ul className="space-y-0.5">
                        {selectedHealth.access.requirements.map(requirement => (
                          <li key={requirement} className="font-mono text-[10px] flex items-start gap-1.5" style={dw.muted}>
                            <span style={dw.faint}>·</span>{requirement}
                          </li>
                        ))}
                      </ul>
                    </div>

                    <p className="font-mono text-[10px] leading-relaxed" style={dw.text}>
                      <span style={dw.brass}>If collection fails: </span>
                      {selectedHealth.access.onFailure}
                    </p>

                    {selectedHealth.findings.length > 0 && (
                      <div className="space-y-1.5">
                        {selectedHealth.findings.map(finding => (
                          <div key={finding.code} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                            <span style={finding.severity === 'critical' ? dw.critical : finding.severity === 'warn' ? dw.medium : dw.info}>
                              {finding.label}
                            </span>
                            <p className="mt-1 leading-relaxed" style={dw.muted}>{finding.detail}</p>
                          </div>
                        ))}
                      </div>
                    )}

                    {selectedHealth.evidenceCount === 0 && (
                      <p className="font-mono text-[9px]" style={dw.faint}>
                        No evidence record in this model cites this source, so its coverage rests on the summary
                        counters alone.
                      </p>
                    )}
                  </div>
                )}
                {/* Source Detailed Posture & Reliability Card */}
                <div className="rounded-sm border p-5 space-y-4" style={dw.panel}>
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[10px] tracking-wider uppercase" style={dw.burg}>{selectedSource.id}</span>
                        <span className="font-mono text-[9px] px-1.5 py-0.5 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)', color: 'var(--tw-text-muted)' }}>{selectedSource.type}</span>
                      </div>
                      <h2 className="font-serif text-xl font-bold mt-1" style={dw.text}>{selectedSource.name}</h2>
                      {selectedSource.onionAddress && (
                        <p className="font-mono text-[10px] mt-0.5" style={dw.muted}>
                          ONION TARGET: <span style={dw.text}>{selectedSource.onionAddress}</span>
                        </p>
                      )}
                    </div>

                    <div className="text-right">
                      <span className="font-mono text-[9px] uppercase" style={dw.faint}>HEALTH STATUS</span>
                      <p className="font-mono text-xs font-bold" style={{ color: selectedSource.status === 'ACTIVE' ? 'var(--tw-moss)' : 'var(--tw-medium)' }}>
                        {selectedSource.status}
                      </p>
                      <div className="mt-2">
                        <MonitorEntityButton
                          entityType="SOURCE"
                          entityId={selectedSource.id}
                          entityLabel={selectedSource.name}
                          targetType="SOURCE"
                        />
                      </div>
                    </div>
                  </div>

                  <p className="text-xs" style={dw.muted}>{selectedSource.description}</p>

                  {/* Reliability Score Bar */}
                  <div className="space-y-1 p-3 rounded-sm border" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                    <div className="flex justify-between font-mono text-[10px]">
                      <span style={dw.faint}>RELIABILITY WEIGHTING (ADMIRALTY RATING)</span>
                      <span style={dw.text}>R{selectedSource.reliabilityScore} / 100</span>
                    </div>
                    <ConfidenceBar value={selectedSource.reliabilityScore} label={false} />
                    <p className="font-mono text-[8px]" style={dw.faint}>
                      Evidence harvested from this collector inherits an R{selectedSource.reliabilityScore} baseline integrity score.
                    </p>
                  </div>

                  {/* Operational Metrics Matrix */}
                  <div className="grid grid-cols-3 gap-2 text-center font-mono text-[10px]">
                    <div className="p-2 border rounded-sm" style={{ borderColor: 'var(--tw-border-mid)' }}>
                      <span style={dw.faint} className="block text-[8px]">ACTIVITY LEVEL</span>
                      <span style={dw.text}>{selectedSource.activityLevel}</span>
                    </div>
                    <div className="p-2 border rounded-sm" style={{ borderColor: 'var(--tw-border-mid)' }}>
                      <span style={dw.faint} className="block text-[8px]">LAST HARVEST</span>
                      <span style={dw.text}>{new Date(selectedSource.lastObserved).toLocaleDateString()}</span>
                    </div>
                    <div className="p-2 border rounded-sm" style={{ borderColor: 'var(--tw-border-mid)' }}>
                      <span style={dw.faint} className="block text-[8px]">FIRST SEEN</span>
                      <span style={dw.text}>{new Date(selectedSource.firstObserved).toLocaleDateString()}</span>
                    </div>
                  </div>

                  {/* Contextual Navigation */}
                  <div className="flex gap-2 pt-2">
                    <Link
                      to={`/app/darkweb/evidence?source=${encodeURIComponent(selectedSource.name)}`}
                      className="font-mono text-[10px] px-3 py-1.5 rounded-sm border flex items-center gap-1.5"
                      style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-burgundy)' }}
                    >
                      <Database size={11} /> VIEW HARVESTED EVIDENCE ({sourceEvidence.length})
                    </Link>
                  </div>
                </div>

                {/* Harvested Evidence and Raw Observations from this Source */}
                <div className="rounded-sm border p-4 space-y-3" style={dw.panel}>
                  <p className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>RECENT INTEL EXTRACTED FROM SOURCE</p>

                  {sourceEvidence.length > 0 ? (
                    <div className="space-y-2">
                      {sourceEvidence.map(ev => (
                        <div key={ev.id} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                          <div className="flex items-center justify-between">
                            <span style={dw.burg}>{ev.id} · {ev.evidenceType}</span>
                            <span style={dw.faint}>{new Date(ev.timestamp).toLocaleDateString()}</span>
                          </div>
                          <p className="mt-1" style={dw.text}>{ev.provenance}</p>
                          {ev.relatedActor && (
                            <Link to={`/app/darkweb/actors/${ev.relatedActor}`} className="inline-block mt-1 font-mono text-[9px]" style={dw.moss}>
                              Attributed to: {ev.relatedActor} →
                            </Link>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="font-mono text-[10px]" style={dw.faint}>No direct evidence captures on file for this specific filter.</p>
                  )}
                </div>
              </>
            ) : (
              <div className="p-12 text-center rounded-sm border" style={dw.panel}>
                <Globe size={32} className="mx-auto mb-2" style={dw.muted} />
                <p className="font-mono text-xs" style={dw.muted}>Select a dark-web feed source to inspect collection telemetry.</p>
              </div>
            )}
          </div>

        </div>

        <ProtectionModulePanel entityType="SOURCE" />
      </div>
    </motion.div>
  );
}
