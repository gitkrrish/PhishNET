import { useState, useMemo } from 'react';
import { Search, Server, Globe, Wifi, Database, Shield, Link2, Clock, AlertTriangle } from 'lucide-react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import { dw, sectionStyle } from '../../lib/darkweb/styles';
import { useIntelligenceData, useIntelligence } from '../../lib/intelligence/IntelligenceContext';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { ConfidenceBar } from '../../components/ui/ConfidenceBar';
import { MonitorEntityButton } from '../../components/darkweb/MonitorEntityButton';
import { ProtectionModulePanel } from '../../components/darkweb/ProtectionModulePanel';

/**
 * Infrastructure rows carry a topology kind; each maps to the monitoring
 * target type whose conditions actually apply to it, so a domain monitor
 * watches DNS and certificate changes rather than onion availability.
 */
function infraTargetType(type: string): string {
  const kind = String(type || '').toUpperCase();
  if (kind.includes('ONION')) return 'ONION';
  if (kind.includes('IP')) return 'IP';
  if (kind.includes('DOMAIN')) return 'DOMAIN';
  return 'INFRASTRUCTURE';
}

export default function DarkWebInfrastructurePage() {
  const { darkWebInfrastructure, darkWebActorsById, darkWebRelationships, darkWebTimeline } = useIntelligenceData();
  const { dataset } = useIntelligence();
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<string | 'all'>('all');
  const [selectedInfraId, setSelectedInfraId] = useState<string | null>(darkWebInfrastructure[0]?.id || null);

  const types = Array.from(new Set(darkWebInfrastructure.map(i => i.type)));

  const filtered = useMemo(() => {
    let items = darkWebInfrastructure;
    const q = search.toLowerCase();
    if (q) items = items.filter(i => i.value.toLowerCase().includes(q) || i.hostingProvider?.toLowerCase().includes(q) || i.asn?.toLowerCase().includes(q));
    if (typeFilter !== 'all') items = items.filter(i => i.type === typeFilter);
    return items;
  }, [search, typeFilter, darkWebInfrastructure]);

  const selectedInfra = useMemo(() => {
    return darkWebInfrastructure.find(i => i.id === selectedInfraId) || filtered[0] || null;
  }, [selectedInfraId, filtered, darkWebInfrastructure]);

  // Topology associations for the selected infrastructure
  const associatedActors = useMemo(() => {
    if (!selectedInfra) return [];
    return selectedInfra.actorIds.map(id => darkWebActorsById[id]).filter(Boolean);
  }, [selectedInfra, darkWebActorsById]);

  const relatedRelationships = useMemo(() => {
    if (!selectedInfra) return [];
    return darkWebRelationships.filter(r =>
      r.sourceEntity === selectedInfra.value ||
      r.targetEntity === selectedInfra.value ||
      selectedInfra.actorIds.some(aid => aid === r.sourceEntity || aid === r.targetEntity)
    );
  }, [selectedInfra, darkWebRelationships]);

  const relatedTimelineEvents = useMemo(() => {
    if (!selectedInfra) return [];
    return darkWebTimeline.filter(t =>
      selectedInfra.actorIds.includes(t.actorId) &&
      (t.type === 'INFRASTRUCTURE_CHANGE' || t.description.toLowerCase().includes(selectedInfra.value.toLowerCase()))
    );
  }, [selectedInfra, darkWebTimeline]);

  const shared = darkWebInfrastructure.filter(i => i.actorIds.length >= 2);

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">

        {/* Workspace Header */}
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b pb-5" style={{ borderColor: 'var(--tw-border-mid)' }}>
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Server size={18} style={dw.critical} />
              <span className="font-mono text-[10px] tracking-widest uppercase" style={dw.burg}>ATTACK-SURFACE WORKSPACE</span>
              <DemoLabel />
            </div>
            <h1 className="font-serif text-3xl" style={dw.text}>Infrastructure Intelligence</h1>
            <p className="text-xs max-w-2xl" style={dw.muted}>
              Correlate adversary servers, domains, TLS certificates, and hosting topologies. Map clear-to-dark relay chains and shared hosting footprints across threat actors.
            </p>
          </div>

          <div className="flex gap-2">
            <div className="rounded-sm border px-3 py-1.5 text-center" style={dw.panel}>
              <p className="font-mono text-[9px] uppercase" style={dw.faint}>Monitored Nodes</p>
              <p className="font-mono text-sm" style={dw.text}>{darkWebInfrastructure.length}</p>
            </div>
            <div className="rounded-sm border px-3 py-1.5 text-center" style={dw.panel}>
              <p className="font-mono text-[9px] uppercase" style={dw.faint}>Shared Pivot Nodes</p>
              <p className="font-mono text-sm" style={dw.burg}>{shared.length}</p>
            </div>
          </div>
        </div>

        {/* Search & Filter Control Bar */}
        <div className="flex flex-col md:flex-row gap-3 items-center justify-between">
          <div className="relative w-full md:w-80">
            <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: 'var(--tw-text-faint)' }} />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search domains, IPs, TLS, ASN, hosters…"
              className="w-full font-mono text-[11px] pl-8 pr-2 py-1.5 rounded-sm focus:outline-none"
              style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }}
            />
          </div>

          <div className="flex items-center gap-2 w-full md:w-auto">
            <span className="font-mono text-[10px]" style={dw.faint}>TYPE:</span>
            <select
              value={typeFilter}
              onChange={e => setTypeFilter(e.target.value)}
              className="font-mono text-[10px] px-2 py-1.5 rounded-sm focus:outline-none"
              style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }}
            >
              <option value="all">ALL TOPOLOGIES</option>
              {types.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
          </div>
        </div>

        {/* 2-Column Specialized Investigation Layout */}
        <div className="grid lg:grid-cols-12 gap-6">

          {/* Left Column: Infrastructure Inventory & Pivot List */}
          <div className="lg:col-span-5 space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>TOPOLOGY ARTIFACTS ({filtered.length})</span>
              <span className="font-mono text-[9px]" style={dw.faint}>CLICK TO INSPECT TOPOLOGY</span>
            </div>

            <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
              {filtered.map(item => {
                const isSelected = selectedInfra?.id === item.id;
                const isShared = item.actorIds.length > 1;

                return (
                  <div
                    key={item.id}
                    onClick={() => setSelectedInfraId(item.id)}
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
                        <div className="flex items-center gap-1.5 mb-1">
                          <span className="font-mono text-[9px] uppercase px-1 py-0.5 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)', color: 'var(--tw-text-muted)' }}>
                            {item.type}
                          </span>
                          {isShared && (
                            <span className="font-mono text-[9px] uppercase px-1 py-0.5 rounded-sm" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-burgundy) 15%, transparent)', color: 'var(--tw-burgundy)' }}>
                              PIVOT ({item.actorIds.length} ACTORS)
                            </span>
                          )}
                        </div>
                        <p className="font-mono text-xs font-medium truncate" style={dw.text}>{item.value}</p>
                      </div>
                      <span className="font-mono text-[9px] shrink-0" style={dw.faint}>
                        {item.country || item.asn || '—'}
                      </span>
                    </div>

                    <div className="flex items-center justify-between mt-2 pt-2 border-t font-mono text-[9px]" style={{ borderColor: 'var(--tw-border-mid)' }}>
                      <span style={dw.muted}>{item.hostingProvider || item.registrar || 'Self-hosted'}</span>
                      <div className="flex gap-1">
                        {item.actorIds.map(a => (
                          <span key={a} style={dw.burg}>{a}</span>
                        ))}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right Column: Deep Infrastructure Dossier / Topology View */}
          <div className="lg:col-span-7 space-y-4">
            {selectedInfra ? (
              <>
                {/* Active Topology Node Summary */}
                <div className="rounded-sm border p-5 space-y-4" style={dw.panel}>
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[10px] tracking-wider uppercase" style={dw.burg}>{selectedInfra.id}</span>
                        <span className="font-mono text-[9px] px-1.5 py-0.5 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)', color: 'var(--tw-text-muted)' }}>{selectedInfra.type}</span>
                      </div>
                      <h2 className="font-mono text-lg font-bold mt-1 break-all" style={dw.text}>{selectedInfra.value}</h2>
                    </div>

                    <div className="text-right">
                      <span className="font-mono text-[9px] uppercase" style={dw.faint}>CONFIDENCE</span>
                      <p className="font-mono text-sm" style={dw.moss}>92% VERIFIED</p>
                      <div className="mt-2">
                        <MonitorEntityButton
                          entityType="INFRASTRUCTURE"
                          entityId={selectedInfra.id}
                          entityLabel={selectedInfra.value}
                          targetType={infraTargetType(selectedInfra.type)}
                        />
                      </div>
                    </div>
                  </div>

                  {/* Technical Metadata Matrix */}
                  <div className="grid sm:grid-cols-3 gap-3 p-3 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)' }}>
                    <div>
                      <span className="font-mono text-[9px] uppercase block" style={dw.faint}>HOSTING PROVIDER</span>
                      <span className="font-mono text-xs" style={dw.text}>{selectedInfra.hostingProvider || '—'}</span>
                    </div>
                    <div>
                      <span className="font-mono text-[9px] uppercase block" style={dw.faint}>AUTONOMOUS SYSTEM</span>
                      <span className="font-mono text-xs" style={dw.text}>{selectedInfra.asn || '—'}</span>
                    </div>
                    <div>
                      <span className="font-mono text-[9px] uppercase block" style={dw.faint}>LOCATION / GEOGRAPHY</span>
                      <span className="font-mono text-xs" style={dw.text}>{selectedInfra.country ? `Region (${selectedInfra.country})` : '—'}</span>
                    </div>
                  </div>

                  {selectedInfra.tlsIssuer && (
                    <div className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                      <span style={dw.faint}>TLS ISSUER / FINGERPRINT: </span>
                      <span style={dw.text}>{selectedInfra.tlsIssuer}</span>
                    </div>
                  )}

                  {/* Cross-Module Navigation Action Bar */}
                  <div className="flex flex-wrap items-center gap-2 pt-2">
                    <Link
                      to={`/app/darkweb/graph?focus=${encodeURIComponent(selectedInfra.value)}`}
                      className="font-mono text-[10px] tracking-wider uppercase px-2.5 py-1.5 rounded-sm border flex items-center gap-1.5"
                      style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-burgundy)' }}
                    >
                      <Link2 size={11} /> GRAPH TOPOLOGY
                    </Link>
                    <Link
                      to={`/app/darkweb/correlation`}
                      className="font-mono text-[10px] tracking-wider uppercase px-2.5 py-1.5 rounded-sm border flex items-center gap-1.5"
                      style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}
                    >
                      <Shield size={11} /> CORRELATE INFRA
                    </Link>
                  </div>
                </div>

                {/* Topology & Actor Association Graph Representation */}
                <div className="rounded-sm border p-4 space-y-3" style={dw.panel}>
                  <p className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>TOPOLOGY LINKAGE MAP</p>

                  <div className="p-4 rounded-sm border space-y-4" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                    <div className="flex items-center justify-between text-xs font-mono">
                      <div className="flex items-center gap-2">
                        <Server size={14} style={dw.burg} />
                        <span style={dw.text}>{selectedInfra.value}</span>
                      </div>
                      <span style={dw.faint}>[THIS NODE]</span>
                    </div>

                    <div className="pl-4 border-l-2 space-y-3" style={{ borderColor: 'var(--tw-burgundy)' }}>
                      {associatedActors.map(actor => (
                        <div key={actor.id} className="flex items-center justify-between bg-black/10 p-2 rounded-sm">
                          <div className="space-y-0.5">
                            <span className="font-mono text-[9px] uppercase" style={dw.faint}>OPERATED / LEASED BY</span>
                            <div className="flex items-center gap-1.5">
                              <Link to={`/app/darkweb/actors/${actor.id}`} className="font-mono text-xs font-bold hover:underline" style={dw.burg}>
                                {actor.id} ({actor.aliases[0]})
                              </Link>
                              <span className="font-mono text-[9px]" style={dw.moss}>[{actor.status}]</span>
                            </div>
                          </div>
                          <Link to={`/app/darkweb/actors/${actor.id}`} className="font-mono text-[9px] px-2 py-1 rounded-sm border" style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}>
                            VIEW DOSSIER →
                          </Link>
                        </div>
                      ))}

                      {relatedRelationships.map(r => (
                        <div key={r.id} className="text-[10px] font-mono p-2 rounded-sm border" style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border-mid)' }}>
                          <div className="flex items-center justify-between">
                            <span style={dw.burg}>{r.type}</span>
                            <span style={dw.faint}>{r.confidence}% CONF</span>
                          </div>
                          <p className="mt-1" style={dw.muted}>{r.explanation}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Infrastructure Timeline History */}
                <div className="rounded-sm border p-4 space-y-3" style={dw.panel}>
                  <div className="flex items-center gap-1.5">
                    <Clock size={13} style={dw.critical} />
                    <p className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>INFRASTRUCTURE ACTIVITY TIMELINE</p>
                  </div>

                  {relatedTimelineEvents.length > 0 ? (
                    <div className="space-y-2">
                      {relatedTimelineEvents.map(event => (
                        <div key={event.id} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                          <div className="flex items-center justify-between">
                            <span style={dw.text}>{event.title}</span>
                            <span style={dw.faint}>{new Date(event.time).toLocaleDateString()}</span>
                          </div>
                          <p className="mt-1" style={dw.muted}>{event.description}</p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="font-mono text-[10px]" style={dw.faint}>No direct timeline disruptions recorded for this node.</p>
                  )}
                </div>
              </>
            ) : (
              <div className="p-12 text-center rounded-sm border" style={dw.panel}>
                <Server size={32} className="mx-auto mb-2" style={dw.muted} />
                <p className="font-mono text-xs" style={dw.muted}>Select an infrastructure entity to load its attack-surface topology.</p>
              </div>
            )}
          </div>

        </div>

        <ProtectionModulePanel entityType="INFRASTRUCTURE" />
      </div>
    </motion.div>
  );
}
