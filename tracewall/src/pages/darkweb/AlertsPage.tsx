import { useState, useMemo, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useLocation } from 'react-router-dom';
import {
  AlertTriangle,
  Bell,
  Search,
  ChevronRight,
  Calendar,
  Radar,
  Activity,
  Database,
  ShieldCheck,
} from 'lucide-react';
import { dw, sectionStyle } from '../../lib/darkweb/styles';
import { useIntelligenceData } from '../../lib/intelligence/IntelligenceContext';
import { type Alert } from '../../data/darkWebData';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { ConfidenceBar } from '../../components/ui/ConfidenceBar';
import { SeverityBadge } from '../../components/ui/SeverityBadge';
import { ExposureLedgerWithNetwork } from '../../components/darkweb/ExposureLedger';
import { ProtectionModulePanel } from '../../components/darkweb/ProtectionModulePanel';

type MonitoringTab = 'alerts' | 'exposure' | 'sources';

const TABS: Array<{ key: MonitoringTab; label: string; icon: typeof Bell }> = [
  { key: 'alerts', label: 'Dark Web Alerts', icon: Bell },
  { key: 'exposure', label: 'Exposure Monitoring', icon: ShieldCheck },
  { key: 'sources', label: 'Source Health', icon: Radar },
];

export default function DarkWebAlertsPage() {
  const location = useLocation();
  const { darkWebAlerts, darkWebActorsById, darkWebSources, darkWebMonitoring } = useIntelligenceData();
  const [tab, setTab] = useState<MonitoringTab>('alerts');
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<string | 'all'>('all');
  const [statusFilter, setStatusFilter] = useState<string | 'all'>('all');
  const [severityFilter, setSeverityFilter] = useState<string | 'all'>('all');

  // `/app/darkweb/exposure` is the deep link into the exposure sub-view, so
  // both paths land on the same component with the right tab preselected.
  useEffect(() => {
    if (location.pathname === '/app/darkweb/exposure') setTab('exposure');
  }, [location.pathname]);

  const types = Array.from(new Set(darkWebAlerts.map(a => a.type)));

  const filtered = useMemo(() => {
    let items = darkWebAlerts;
    const q = search.toLowerCase();
    if (q) items = items.filter(a => a.id.toLowerCase().includes(q) || a.title.toLowerCase().includes(q) || a.reason.toLowerCase().includes(q));
    if (typeFilter !== 'all') items = items.filter(a => a.type === typeFilter);
    if (statusFilter !== 'all') items = items.filter(a => a.status === statusFilter);
    if (severityFilter !== 'all') items = items.filter(a => a.severity === severityFilter);
    return items.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }, [search, typeFilter, statusFilter, severityFilter, darkWebAlerts]);

  const openBySeverity = darkWebAlerts.filter(a => a.status === 'OPEN').reduce((acc: Record<string, number>, a) => { acc[a.severity] = (acc[a.severity] ?? 0) + 1; return acc; }, {});

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-6xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        <div className="flex items-center justify-between"><div className="flex items-center gap-2"><Bell size={16} style={dw.critical} /><h1 className="font-serif text-3xl" style={dw.text}>Monitoring &amp; Alerts</h1></div><DemoLabel /></div>
        <p className="text-sm max-w-2xl leading-relaxed" style={dw.muted}>
          Continuous collection that keeps Dark Web Intelligence current — new actors, new handles, persona
          migration, infrastructure changes, relationship changes and credential exposure. Monitoring is how
          the intelligence stays updated, not a separate product.
        </p>

        {/* Collection status strip */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { label: 'Sources Monitored', val: darkWebMonitoring.sourcesMonitored, color: 'var(--tw-text)' },
            { label: 'New Indicators', val: darkWebMonitoring.newIndicators, color: 'var(--tw-high)' },
            { label: 'New Actors', val: darkWebMonitoring.newActors, color: 'var(--tw-critical)' },
            { label: 'New Relationships', val: darkWebMonitoring.newRelationships, color: 'var(--tw-medium)' },
          ].map(c => (
            <div key={c.label} className="p-3 rounded-sm border text-center" style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)' }}>
              <p className="font-mono text-2xl font-light" style={{ color: c.color }}>{c.val}</p>
              <p className="font-mono text-[10px] uppercase tracking-wider" style={dw.muted}>{c.label}</p>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div>
          <div className="flex items-center overflow-x-auto" style={{ backgroundColor: 'var(--tw-panel-alt)' }}>
            {TABS.map(item => {
              const Icon = item.icon;
              const active = tab === item.key;
              return (
                <button
                  key={item.key}
                  type="button"
                  onClick={() => setTab(item.key)}
                  className="px-4 py-3 font-mono text-xs border-b-2 flex items-center gap-1.5 whitespace-nowrap transition-colors"
                  style={{
                    borderBottomColor: active ? 'var(--tw-burgundy)' : 'transparent',
                    color: active ? 'var(--tw-burgundy)' : 'var(--tw-text-muted)',
                  }}
                >
                  <Icon size={12} />
                  {item.label}
                </button>
              );
            })}
          </div>

          <div className="p-5 space-y-6">
            {tab === 'alerts' && (
              <div className="space-y-6">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {Object.entries(openBySeverity).map(([sev, count]) => (
                    <div key={sev} className="p-3 rounded-sm border text-center" style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)' }}>
                      <p className="font-mono text-[10px] uppercase" style={{ color: severityColorVar(sev) }}>{sev} ({count})</p>
                    </div>
                  ))}
                </div>

                <p className="text-sm" style={dw.muted}>{filtered.length} of {darkWebAlerts.length} alerts. {darkWebAlerts.filter(a => a.status === 'OPEN').length} open · {darkWebAlerts.filter(a => a.status === 'ACKNOWLEDGED').length} acknowledged.</p>

                <div className="flex flex-col md:flex-row gap-3">
                  <div className="relative w-full md:w-64">
                    <Search size={12} className="absolute left-2 top-1/2 -translate-y-1/2" style={{ color: 'var(--tw-text-faint)' }} />
                    <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search alerts…"
                      className="w-full font-mono text-[11px] pl-7 pr-2 py-1.5 rounded-sm focus:outline-none"
                      style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }} />
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)} className="font-mono text-[10px] px-2 py-1 rounded-sm" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }}>
                      <option value="all">All Types</option>{types.map(t => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
                    </select>
                    <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)} className="font-mono text-[10px] px-2 py-1 rounded-sm" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }}>
                      <option value="all">All Severities</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option>
                    </select>
                    <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)} className="font-mono text-[10px] px-2 py-1 rounded-sm" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }}>
                      <option value="all">All Statuses</option><option value="OPEN">Open</option><option value="ACKNOWLEDGED">Acknowledged</option><option value="RESOLVED">Resolved</option><option value="DISMISSED">Dismissed</option>
                    </select>
                  </div>
                </div>

                <div className="rounded-sm border" style={dw.panel}>
                  {filtered.length === 0 ? (
                    <div className="p-8 text-center" style={dw.muted}>
                      <Bell size={28} className="mx-auto mb-2" />
                      <p>No alerts match the selected filters.</p>
                    </div>
                  ) : (
                    <div className="divide-y" style={{ borderColor: 'var(--tw-border-mid)' }}>
                      {filtered.map((a: Alert) => (
                        <AlertRow
                          key={a.id}
                          alert={a}
                          actorName={a.actorId && darkWebActorsById[a.actorId]
                            ? `${darkWebActorsById[a.actorId].id} (${darkWebActorsById[a.actorId].aliases[0]})`
                            : undefined}
                        />
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {tab === 'exposure' && <ExposureLedgerWithNetwork />}

            {tab === 'sources' && (
              <div className="space-y-6">
                <div className="rounded-sm border p-4" style={dw.panel}>
                  <div className="flex items-center gap-2 mb-2" style={dw.muted}>
                    <Activity size={13} /> Collection Cycle
                  </div>
                  <div className="grid md:grid-cols-3 gap-4 text-[11px]">
                    <div>
                      <p className="font-mono text-[10px] uppercase" style={dw.faint}>Status</p>
                      <p className="font-mono" style={dw.low}>{darkWebMonitoring.status}</p>
                    </div>
                    <div>
                      <p className="font-mono text-[10px] uppercase" style={dw.faint}>Last collection</p>
                      <p className="font-mono" style={dw.text}>{new Date(darkWebMonitoring.lastCollection).toLocaleString()}</p>
                    </div>
                    <div>
                      <p className="font-mono text-[10px] uppercase" style={dw.faint}>Next collection</p>
                      <p className="font-mono" style={dw.text}>{new Date(darkWebMonitoring.nextCollection).toLocaleString()}</p>
                    </div>
                  </div>
                </div>

                <div className="rounded-sm border" style={dw.panel}>
                  <div className="px-5 py-3 border-b" style={dw.borderMid}>
                    <div className="flex items-center gap-2" style={dw.muted}>
                      <Database size={13} /> Source Health — {darkWebSources.length} sources
                    </div>
                  </div>
                  <table className="w-full text-[10px] font-mono">
                    <thead>
                      <tr style={dw.canvasMid}>
                        <th className="text-left p-2" style={dw.text}>Source</th>
                        <th className="text-left p-2" style={dw.text}>Type</th>
                        <th className="text-left p-2" style={dw.text}>Reliability</th>
                        <th className="text-left p-2" style={dw.text}>Activity</th>
                        <th className="text-left p-2" style={dw.text}>Status</th>
                        <th className="text-left p-2" style={dw.text}>Last observed</th>
                        <th className="text-left p-2" style={dw.text}>Actors</th>
                        <th className="text-left p-2" style={dw.text}>Indicators</th>
                      </tr>
                    </thead>
                    <tbody>
                      {darkWebSources.map(source => (
                        <tr key={source.id} className="border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
                          <td className="p-2" style={dw.text}>{source.name}</td>
                          <td className="p-2" style={dw.muted}>{source.type}</td>
                          <td className="p-2" style={dw.text}>R{source.reliabilityScore}</td>
                          <td className="p-2" style={dw.muted}>{source.activityLevel}</td>
                          <td className="p-2" style={source.status === 'ACTIVE' ? dw.low : dw.medium}>{source.status}</td>
                          <td className="p-2" style={dw.muted}>{new Date(source.lastObserved).toLocaleDateString()}</td>
                          <td className="p-2" style={dw.text}>{source.actorCount}</td>
                          <td className="p-2" style={dw.text}>{source.indicatorCount}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <div className="rounded-sm border p-4" style={dw.panel}>
                  <div className="flex items-center gap-2 mb-3" style={dw.muted}>
                    <AlertTriangle size={13} /> Collection Reliability
                  </div>
                  {darkWebSources
                    .slice()
                    .sort((a, b) => b.reliabilityScore - a.reliabilityScore)
                    .map(source => (
                      <div key={source.id} className="flex items-center gap-3 mb-2">
                        <span className="font-mono text-[10px] w-40 shrink-0 truncate" style={dw.text}>{source.name}</span>
                        <span className="flex-1">
                          <ConfidenceBar value={source.reliabilityScore} label={false} />
                        </span>
                        <span className="font-mono text-[10px] w-8 text-right" style={dw.muted}>R{source.reliabilityScore}</span>
                      </div>
                    ))}
                </div>
              </div>
            )}
          </div>
        </div>
        <ProtectionModulePanel entityType="ACTOR" />
      </div>
    </motion.div>
  );
}

function severityColorVar(sev: string): string {
  const m: Record<string, string> = { CRITICAL: 'var(--tw-critical)', HIGH: 'var(--tw-high)', MEDIUM: 'var(--tw-medium)', LOW: 'var(--tw-low)', INFO: 'var(--tw-info)' };
  return m[sev] ?? m.INFO;
}

function AlertRow({ alert, actorName }: { alert: Alert; actorName?: string }) {
  const statusColor = {
    OPEN: 'var(--tw-critical)', ACKNOWLEDGED: 'var(--tw-medium)', RESOLVED: 'var(--tw-low)', DISMISSED: 'var(--tw-dust)'
  }[alert.status];
  return (
    <div className="p-4 border-b flex items-start justify-between gap-3">
      <div className="space-y-1.5 flex-1">
        <div className="flex items-center gap-2 flex-wrap">
          <SeverityBadge severity={alert.severity} />
          <span className="font-mono text-[9px] uppercase px-1.5 py-0.25 rounded-sm" style={{ color: statusColor, backgroundColor: 'color-mix(in srgb, var(--tw-dust) 18%, transparent)' }}>{alert.status}</span>
          <span className="font-mono text-[9px]" style={dw.burg}>{alert.type.replace(/_/g, ' ')}</span>
        </div>
        <p className="text-sm font-medium" style={dw.text}>{alert.title}</p>
        <p className="font-mono text-[10px]" style={dw.muted}>{alert.reason}</p>
          {actorName && <p className="font-mono text-[9px]" style={dw.info}>Actor: {actorName}</p>}
        <div className="mt-1"><ConfidenceBar value={alert.confidence} label={false} /></div>
        <div className="flex gap-2 text-[10px]" style={dw.faint}>
          <Calendar size={9} /> {new Date(alert.timestamp).toLocaleString()} · Evidence: {alert.evidenceIds.length}
        </div>
      </div>
      <ChevronRight size={14} style={dw.muted} />
    </div>
  );
}
