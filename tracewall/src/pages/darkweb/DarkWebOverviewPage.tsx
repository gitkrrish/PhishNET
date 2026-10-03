import { Link, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useMemo } from 'react';
import { PlayCircle, Activity, BarChart2, Database, AlertTriangle, Globe, Network, Users, GitCompare, Sparkles, BellRing, FolderKanban, Share2, Archive, Clock, Server, RadioTower, Radar, FileText } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar } from 'recharts';
import { dw, sectionStyle } from '../../lib/darkweb/styles';
import { StatCard } from '../../components/darkweb/StatCard';
import { useIntelligenceData } from '../../lib/intelligence/IntelligenceContext';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { SeverityBadge } from '../../components/ui/SeverityBadge';
import { ConfidenceBar } from '../../components/ui/ConfidenceBar';

const PIE_COLORS = ['#731F32', '#9A7230', '#835518', '#3E4B56', '#8C2C2C', '#3D5939', '#8B1E30'];

const WORKSPACES = [
  { label: 'Threat Actors',       hint: 'Central entity — profiles, handles, keys, wallets', to: '/app/darkweb/actors',         icon: Users,        tone: 'var(--tw-burgundy)' },
  { label: 'Identity Correlation', hint: 'Match a handle, key, wallet or behavior', to: '/app/darkweb/correlation',     icon: GitCompare,   tone: 'var(--tw-high)' },
  { label: 'AI Analysis',          hint: 'Explainable insights, extraction, discovery', to: '/app/darkweb/ai',             icon: Sparkles,     tone: 'var(--tw-medium)' },
  { label: 'Monitoring & Alerts',  hint: 'Alerts, exposure ledger, source health', to: '/app/darkweb/alerts',         icon: BellRing,     tone: 'var(--tw-critical)' },
  { label: 'Investigations',       hint: 'Run an investigation end to end', to: '/app/darkweb/investigations',     icon: FolderKanban, tone: 'var(--tw-info)' },
  { label: 'Relationship Graph',   hint: 'One relationship dataset, graphed', to: '/app/darkweb/graph',             icon: Share2,       tone: 'var(--tw-moss)' },
  { label: 'Evidence Locker',      hint: 'Chain of custody for collected evidence', to: '/app/darkweb/evidence',      icon: Archive,      tone: 'var(--tw-brass)' },
  { label: 'Timeline',             hint: 'Collection and change history', to: '/app/darkweb/timeline',             icon: Clock,        tone: 'var(--tw-text-muted)' },
  { label: 'Infrastructure',       hint: 'Hosts, wallets, relays, onion services', to: '/app/darkweb/infrastructure', icon: Server,       tone: 'var(--tw-info)' },
  { label: 'Sources',              hint: 'Coverage, reliability and collection', to: '/app/darkweb/sources',        icon: RadioTower,   tone: 'var(--tw-low)' },
  { label: 'Threat Intelligence',  hint: 'Enriched external intelligence overlay', to: '/app/intelligence',   icon: Radar,        tone: 'var(--tw-burgundy)' },
  { label: 'Reports & Evidence',   hint: 'Export JSON, CSV and PDF', to: '/app/reports',                                icon: FileText,     tone: 'var(--tw-brass)' },
];

export default function DarkWebOverviewPage() {
  const navigate = useNavigate();
  const {
    darkWebActors,
    darkWebAlerts,
    darkWebInvestigations,
    darkWebSources,
    darkWebRelationships,
    darkWebEvidence,
    darkWebMonitoring,
    darkWebTimeline,
  } = useIntelligenceData();

  const { activeActors, newHandles, personaMigrations, highConfRels, openAlerts, timelineChartData, actorActivityData, pieData } = useMemo(() => {
    const activityTrend = darkWebTimeline.reduce((acc: Record<string, number>, e) => {
      const d = new Date(e.time).toLocaleDateString();
      acc[d] = (acc[d] ?? 0) + 1;
      return acc;
    }, {});
    const sourceTypeData = darkWebSources.reduce((acc: Record<string, number>, s) => {
      acc[s.type] = (acc[s.type] ?? 0) + 1;
      return acc;
    }, {});
    return {
      activeActors: darkWebActors.filter(a => a.status === 'ACTIVE').length,
      newHandles: new Set(darkWebActors.flatMap(a => a.handles)).size,
      personaMigrations: darkWebRelationships.filter(r => r.type === 'PERSONA_MIGRATION').length,
      highConfRels: darkWebRelationships.filter(r => r.confidence >= 75).length,
      openAlerts: darkWebAlerts.filter(a => a.status === 'OPEN' || a.status === 'ACKNOWLEDGED').length,
      timelineChartData: Object.entries(activityTrend).map(([date, count]) => ({ date, count })).sort((a, b) => a.date.localeCompare(b.date)),
      actorActivityData: darkWebActors.map(a => ({ name: a.id, activity: a.behavioralProfile.postingFrequency, confidence: a.confidenceScore })),
      pieData: Object.entries(sourceTypeData).map(([type, count]) => ({ type, count })),
    };
  }, [darkWebActors, darkWebAlerts, darkWebRelationships, darkWebSources, darkWebTimeline]);

  const recentAlerts = useMemo(() => darkWebAlerts.slice(0, 5), [darkWebAlerts]);
  const recentInvestigations = useMemo(() => darkWebInvestigations.slice(0, 3), [darkWebInvestigations]);

  return (
    <div className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-8">
        {/* Header */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col md:flex-row md:items-end justify-between gap-4">
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={dw.muted}>{darkWebMonitoring.lastCollection}</p>
              <span className="font-mono text-[10px] px-2 py-0.5 rounded-sm" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-low) 18%, transparent)', color: 'var(--tw-low)' }}>{darkWebMonitoring.status}</span>
              <DemoLabel />
            </div>
            <h1 className="font-serif text-3xl" style={dw.text}>Dark Web Intelligence</h1>
            <p className="text-sm max-w-xl leading-relaxed" style={dw.muted}>The central dark web threat intelligence and investigation hub. Every workflow — actors, correlation, AI analysis, monitoring, evidence and investigations — resolves to a threat actor. Monitoring {darkWebMonitoring.sourcesMonitored} sources · {darkWebMonitoring.newActors} new actors · {darkWebMonitoring.newRelationships} new relationships.</p>
          </div>
          <button onClick={() => navigate('/app/darkweb/demo')} type="button"
            className="flex items-center gap-2 font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm transition-colors">
            <PlayCircle size={13} /> SIH Demo Investigation
          </button>
        </motion.div>

        {/* Stats grid */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard title="Monitored Actors" value={darkWebActors.length} icon="actors" tone="critical" subtitle={`${activeActors} active`} />
          <StatCard title="Active Actors" value={activeActors} icon="activity" tone="high" subtitle={`${newHandles} handles`} />
          <StatCard title="High-Confidence Relationships" value={highConfRels} icon="trend" tone="medium" subtitle={`${personaMigrations} migrations`} />
          <StatCard title="Open Alerts" value={openAlerts} icon="shield" tone="critical" subtitle={`${darkWebEvidence.length} evidence items`} />
        </div>

        {/* Central workflow entry points */}
        <div className="rounded-sm border p-5" style={dw.panel}>
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2" style={dw.muted}><Network size={13} />Investigation Workspaces</div>
            <span className="font-mono text-[10px]" style={dw.faint}>Start from any workspace — every finding resolves to a threat actor</span>
          </div>
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {WORKSPACES.map(ws => (
              <Link key={ws.to} to={ws.to} className="rounded-sm border p-3 transition-colors"
                style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)', textDecoration: 'none' }}
                onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'var(--tw-hover)')}
                onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'var(--tw-canvas-mid)')}
              >
                <div className="flex items-center gap-2">
                  <ws.icon size={13} style={{ color: ws.tone }} />
                  <span className="text-xs font-medium" style={dw.text}>{ws.label}</span>
                </div>
                <p className="font-mono text-[10px] mt-1 leading-relaxed" style={dw.faint}>{ws.hint}</p>
              </Link>
            ))}
          </div>
        </div>

        <div className="grid lg:grid-cols-3 gap-6">
          {/* Left: charts */}
          <div className="lg:col-span-2 space-y-6">
            <div className="rounded-sm border p-5" style={dw.panel}>
              <div className="flex items-center gap-2 mb-3" style={dw.muted}><Activity size={13} /> Activity Trend</div>
              <ResponsiveContainer width="100%" height={190}>
                <LineChart data={timelineChartData}>
                  <XAxis dataKey="date" tick={{ fontSize: 9, fill: 'var(--tw-text-muted)' }} axisLine={{ stroke: 'var(--tw-border)' }} />
                  <YAxis tick={{ fontSize: 9, fill: 'var(--tw-text-muted)' }} axisLine={false} />
                  <Tooltip contentStyle={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)', color: 'var(--tw-text)' }} />
                  <Line type="monotone" dataKey="count" stroke="var(--tw-burgundy)" strokeWidth={2} dot={{ r: 3 }} />
                </LineChart>
              </ResponsiveContainer>
            </div>

            <div className="grid md:grid-cols-2 gap-6">
              <div className="rounded-sm border p-5" style={dw.panel}>
                <div className="flex items-center gap-2 mb-3" style={dw.muted}><BarChart2 size={13} /> Actor Activity</div>
                <ResponsiveContainer width="100%" height={160}>
                  <BarChart data={actorActivityData}>
                    <XAxis dataKey="name" tick={{ fontSize: 9, fill: 'var(--tw-text-muted)' }} axisLine={false} />
                    <YAxis tick={{ fontSize: 9, fill: 'var(--tw-text-muted)' }} />
                    <Tooltip contentStyle={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)', color: 'var(--tw-text)' }} />
                    <Bar dataKey="confidence" fill="var(--tw-burgundy)" radius={[3, 3, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <div className="rounded-sm border p-5" style={dw.panel}>
                <div className="flex items-center gap-2 mb-3" style={dw.muted}><Database size={13} /> Source Reliability</div>
                <ResponsiveContainer width="100%" height={160}>
                  <PieChart>
                    <Pie data={pieData} dataKey="count" nameKey="type" cx="50%" cy="50%" outerRadius={55} label={({ type: _t, count }: any) => `${count}`} labelLine={false}>
                      {pieData.map((_, i) => <Cell key={`c-${i}`} fill={PIE_COLORS[i % PIE_COLORS.length].replace('var(', '#').replace(')', '')} />)}
                    </Pie>
                    <Tooltip contentStyle={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)', color: 'var(--tw-text)' }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          {/* Right: alert feed + recent investigations */}
          <div className="space-y-6">
            <div className="rounded-sm border p-5" style={dw.panel}>
              <div className="flex items-center gap-2 mb-3" style={dw.muted}><AlertTriangle size={13} />Alert Feed</div>
              <div className="space-y-2.5">
                {recentAlerts.map(a => (
                  <Link key={a.id} to={`/app/darkweb/alerts`} className="block" style={{ textDecoration: 'none' }}>
                    <div className="p-3 rounded-sm border transition-colors" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                      <div className="flex items-start justify-between gap-2">
                        <div className="space-y-0.5">
                          <p className="font-mono text-[10px] tracking-wider" style={dw.burg}>{a.id}</p>
                          <p className="text-xs font-medium" style={dw.text}>{a.title}</p>
                          <p className="font-mono text-[10px]" style={dw.faint}>{new Date(a.timestamp).toLocaleString()}</p>
                        </div>
                        <SeverityBadge severity={a.severity} />
                      </div>
                      <p className="font-mono text-[10px] mt-1" style={dw.muted}>{a.reason}</p>
                      <div className="mt-1.5"><ConfidenceBar value={a.confidence} label={false} /></div>
                    </div>
                  </Link>
                ))}
              </div>
            </div>

            <div className="rounded-sm border p-5" style={dw.panel}>
              <div className="flex items-center justify-between mb-3" style={dw.muted}><Database size={13} /><span className="font-mono text-[10px]">Recent Investigations</span></div>
              <div className="space-y-2.5">
                {recentInvestigations.map(inv => (
                  <Link key={inv.id} to={`/app/darkweb/investigations/${inv.id}`} className="block" style={{ textDecoration: 'none' }}>
                    <div className="p-3 rounded-sm border transition-colors" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                      <p className="font-mono text-[10px] tracking-wider" style={dw.burg}>{inv.id}</p>
                      <p className="text-xs font-medium" style={dw.text}>{inv.title}</p>
                      <div className="mt-1.5"><ConfidenceBar value={inv.confidence} label={false} /></div>
                    </div>
                  </Link>
                ))}
                <Link to="/app/darkweb/investigations" className="block text-center font-mono text-[10px] py-2" style={dw.burg}>View all investigations →</Link>
              </div>
            </div>

            <div className="rounded-sm border p-5" style={dw.panel}>
              <div className="flex items-center gap-2 mb-3" style={dw.muted}><Globe size={13} />Infrastructure Changes</div>
              <div className="space-y-2 text-[11px]">
                <div><span style={dw.text}>ghostwire-relay.net</span><span className="font-mono" style={dw.faint}> · NEW · ACTOR-001/003</span></div>
                <div><span style={dw.text}>185.220.101.47</span><span className="font-mono" style={dw.faint}> · SHARED · ACTOR-001/002</span></div>
                <div><span style={dw.text}>pulsar-drop.onion</span><span className="font-mono" style={dw.faint}> · UPDATED · ACTOR-004</span></div>
              </div>
            </div>
          </div>
        </div>

        {/* Source status table */}
        <div className="rounded-sm border p-5" style={dw.panel}>
          <div className="flex items-center justify-between mb-3" style={dw.muted}><Database size={13} />Source Status</div>
          <table className="w-full text-[10px] font-mono">
            <thead>
              <tr style={dw.canvasMid}><th className="text-left p-2" style={dw.text}>Source</th><th className="text-left p-2" style={dw.text}>Type</th><th className="text-left p-2" style={dw.text}>Reliability</th><th className="text-left p-2" style={dw.text}>Status</th><th className="text-left p-2" style={dw.text}>Actors</th></tr>
            </thead>
            <tbody>
              {darkWebSources.map(s => (
                <tr key={s.id} className="border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <td className="p-2" style={dw.text}>{s.name}</td>
                  <td className="p-2" style={dw.muted}>{s.type}</td>
                  <td className="p-2" style={dw.text}>R{s.reliabilityScore}</td>
                  <td className="p-2"><span className="font-mono text-[9px] px-1.5 py-0.25 rounded-sm" style={{ color: s.status === 'ACTIVE' ? 'var(--tw-low)' : 'var(--tw-medium)', backgroundColor: 'color-mix(in srgb, var(--tw-low) 18%, transparent)' }}>{s.status}</span></td>
                  <td className="p-2" style={dw.text}>{s.actorCount}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
