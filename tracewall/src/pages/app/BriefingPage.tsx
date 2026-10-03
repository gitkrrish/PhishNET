import { Link, useNavigate } from 'react-router-dom';
import { ArrowRight, Clock, AlertTriangle, User, PlayCircle, X, ChevronLeft, ChevronRight, Network } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useMemo, useState } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, Legend
} from 'recharts';
import { currentAnalyst } from '../../data/mockData';
import { useIntelligenceData, useProtection } from '../../lib/intelligence/IntelligenceContext';
import { useMonitoringPolling, monitoringStats } from '../../lib/intelligence/monitoring';
import { generateInvestigationSummary } from '../../lib/darkweb/aiEngine';
import { SeverityBadge } from '../../components/ui/SeverityBadge';
import { DemoLabel } from '../../components/ui/DemoLabel';
import ThreatEvidenceNetwork from '../../components/3d/LazyThreatEvidenceNetwork';

const S = {
  panel:        { backgroundColor: 'var(--tw-panel)',     border: '1px solid var(--tw-border)' },
  panelAlt:     { backgroundColor: 'var(--tw-panel-alt)' },
  text:         { color: 'var(--tw-text)' },
  muted:        { color: 'var(--tw-text-muted)' },
  faint:        { color: 'var(--tw-text-faint)' },
  burg:         { color: 'var(--tw-burgundy)' },
  borderMid:    { borderColor: 'var(--tw-border-mid)' },
  canvas:       { backgroundColor: 'var(--tw-canvas)' },
  canvasMid:    { backgroundColor: 'var(--tw-canvas-mid)' },
};

// Monthly collection activity, grouped from the dark web timeline.
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/**
 * Command-center metrics, derived from the live intelligence dataset on every
 * render. The returned object is memoised on the collections it reads, so the
 * numbers update as soon as any mutation lands in the central model.
 */
function useDarkWebBriefing() {
  const {
    darkWebActors,
    darkWebAlerts,
    darkWebEvidence,
    darkWebHandles,
    darkWebInfrastructure,
    darkWebInvestigations,
    darkWebPgpKeys,
    darkWebRelationships,
    darkWebSources,
    darkWebTimeline,
    darkWebWallets,
    darkWebMonitoring,
  } = useIntelligenceData();

  return useMemo(() => {
    const activeActors = darkWebActors.filter(a => a.status === 'ACTIVE');
    const dormantActors = darkWebActors.filter(a => a.status !== 'ACTIVE');
    const activeInvestigations = darkWebInvestigations.filter(i => i.status !== 'COMPLETED');
    const newIdentities = darkWebHandles.length + darkWebPgpKeys.length + darkWebWallets.length;
    const highConfidenceRels = darkWebRelationships.filter(r => r.confidence >= 75);
    const openAlerts = darkWebAlerts.filter(a => a.status === 'OPEN' || a.status === 'ACKNOWLEDGED');

    const topInvestigation = darkWebInvestigations[0] ?? null;
    const investigationSummary = topInvestigation ? generateInvestigationSummary(topInvestigation.id) : null;
    const seedActor = darkWebActors.find(a => a.id === topInvestigation?.seedActorId) ?? darkWebActors[0] ?? null;

    const evidencePoints = (topInvestigation?.steps ?? [])
      .flatMap(step => step.relationshipIds)
      .filter((id, i, a) => a.indexOf(id) === i)
      .map(id => darkWebRelationships.find(r => r.id === id))
      .filter(Boolean)
      .slice(0, 4)
      .map(rel => `${rel!.sourceEntity} → ${rel!.targetEntity} — ${rel!.type.replace(/_/g, ' ').toLowerCase()} at ${rel!.confidence}% confidence`);

    const investigationTags = seedActor
      ? [
          ...seedActor.handles.slice(0, 2),
          ...seedActor.pgpFingerprints.slice(0, 1).map(fp => `PGP ${fp.slice(0, 12)}…`),
          ...seedActor.walletAddrs.slice(0, 1).map(w => `Wallet ${w.slice(0, 12)}…`),
        ]
      : [];

    const attributionQueue = activeActors
      .filter(actor => openAlerts.some(alert => alert.actorId === actor.id) || actor.status === 'ACTIVE')
      .slice(0, 4)
      .map(actor => ({
        id: actor.id,
        title: actor.aliases[0],
        detail: `${actor.id} · ${actor.status} · ${actor.confidenceScore}% confidence`,
        score: actor.confidenceScore,
        severity: actor.confidenceScore >= 90 ? 'CRITICAL' : actor.confidenceScore >= 75 ? 'HIGH' : 'MEDIUM',
        to: `/app/darkweb/actors/${actor.id}`,
      }));

    const buckets: Record<string, { hour: string; activity: number; identity: number; infrastructure: number }> = {};
    for (const event of darkWebTimeline) {
      const date = new Date(event.time);
      const key = `${date.getFullYear()}-${date.getMonth()}`;
      buckets[key] ??= { hour: `${MONTHS[date.getMonth()]} ${String(date.getFullYear()).slice(2)}`, activity: 0, identity: 0, infrastructure: 0 };
      buckets[key].activity += 1;
      if (['FIRST_SEEN', 'FIRST_SEEN_NEW', 'PERSONA_MIGRATION', 'HANDLE_CHANGE', 'RELATIONSHIP_FORMATION'].includes(event.type)) {
        buckets[key].identity += 1;
      }
      if (['INFRASTRUCTURE_CHANGE', 'PLATFORM_ACTIVITY'].includes(event.type)) {
        buckets[key].infrastructure += 1;
      }
    }
    const activityTimeline = Object.entries(buckets)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([, value]) => value);

    const postureCounts = {
      actors: darkWebActors.length,
      dormant: dormantActors.length,
      investigations: activeInvestigations.length,
      identities: newIdentities,
      infrastructure: darkWebInfrastructure.length,
      correlations: highConfidenceRels.length,
      evidence: darkWebEvidence.length,
    };

    const postureSummary = `${postureCounts.actors} threat actors under continuous observation across ${darkWebSources.length} dark web sources. ${postureCounts.investigations} active investigation · ${postureCounts.identities} correlated identities · ${postureCounts.correlations} high-confidence relationships · ${postureCounts.evidence} evidence items. Last collection ${new Date(darkWebMonitoring.lastCollection).toLocaleString()}.`;

    return {
      darkWebHandles,
      darkWebPgpKeys,
      darkWebWallets,
      darkWebInfrastructure,
      darkWebRelationships,
      darkWebEvidence,
      darkWebMonitoring,
      activeActors,
      dormantActors,
      openAlerts,
      topInvestigation,
      investigationSummary,
      seedActor,
      evidencePoints,
      investigationTags,
      recentAlerts: darkWebAlerts.slice(0, 3),
      attributionQueue,
      activityTimeline,
      postureCounts,
      postureSummary,
    };
  }, [
    darkWebActors,
    darkWebAlerts,
    darkWebEvidence,
    darkWebHandles,
    darkWebInfrastructure,
    darkWebInvestigations,
    darkWebMonitoring,
    darkWebPgpKeys,
    darkWebRelationships,
    darkWebSources,
    darkWebTimeline,
    darkWebWallets,
  ]);
}

function ThreatPosturePill({ posture }: { posture: string }) {
  const map: Record<string, string> = {
    ELEVATED: 'var(--tw-medium)',
    CRITICAL: 'var(--tw-critical)',
    HIGH: 'var(--tw-high)',
    NORMAL:   'var(--tw-low)',
  };
  const color = map[posture] || map.NORMAL;
  return (
    <span
      className="font-mono text-[10px] tracking-widest uppercase px-3 py-1 rounded-sm border"
      style={{
        color,
        borderColor: `color-mix(in srgb, ${color} 35%, transparent)`,
        backgroundColor: `color-mix(in srgb, ${color} 18%, transparent)`,
      }}
    >
      {posture}
    </span>
  );
}

export default function BriefingPage() {
  const [demoOpen, setDemoOpen] = useState(false);
  const [demoStep, setDemoStep] = useState(0);
  const navigate = useNavigate();
  const { posture } = useProtection();
  const {
    darkWebHandles,
    darkWebPgpKeys,
    darkWebWallets,
    darkWebInfrastructure,
    darkWebRelationships,
    darkWebEvidence,
    darkWebMonitoring,
    activeActors,
    dormantActors,
    openAlerts,
    topInvestigation,
    investigationSummary,
    seedActor,
    evidencePoints,
    investigationTags,
    recentAlerts,
    attributionQueue,
    activityTimeline,
    postureCounts,
    postureSummary,
  } = useDarkWebBriefing();

  const demoSteps = [
    { title: 'Welcome to Viper Trace', body: 'Viper Trace is a dark web threat intelligence and investigation platform. This tour walks the central workflow: collection → analysis → correlation → investigation → evidence → alerts → reporting.' },
    { title: 'Command Center', body: 'This page is the command center. It prioritises the highest-confidence dark web investigation, surfaces new identities, infrastructure changes and high-confidence correlations, and links straight into the Dark Web Intelligence hub.' },
    { title: 'Dark Web Intelligence — the core', body: 'Open Dark Web Intelligence (Network icon in the section bar). It is the central hub: threat actors, sources, monitoring, correlation, infrastructure, relationships, timeline, evidence, investigations, AI analysis and reports all hang off it.' },
    { title: 'Threat Actors are the central entity', body: 'Open the seed actor. Everything else connects back to it — identities, handles, PGP keys, wallets, platforms, infrastructure, behavior, stylometry, relationships, evidence, timeline and AI findings. An actor profile is an investigation in itself.' },
    { title: 'Identity Correlation', body: 'Open Identity Correlation to work a single handle. Handle matching, PGP and wallet correlation, infrastructure overlap, behavioral and stylometric similarity, entity resolution and anomaly detection all run against the same dataset.' },
    { title: 'Monitoring & Alerts', body: 'Monitoring lives inside Dark Web Intelligence. The alerts tab covers new actors, persona migration, infrastructure changes and correlation changes. The exposure tab monitors authorised organisational credential exposure.' },
    { title: 'AI Investigation Insights', body: 'Open AI Analysis. Extraction, persona similarity, relationship discovery and evidence summarization are contextual to the actor you are investigating, and every claim cites the records it came from.' },
    { title: 'Evidence & Investigations', body: 'Collected evidence is filed in the evidence locker and attached to investigations. The relationship graph, timeline and evidence all read from one relationship dataset — there is no second graph.' },
    { title: 'Response & Alerts', body: 'Promote a finding into Response & Alerts when action is required: acknowledge, assign, escalate, resolve. High-impact actions run through the Decision Desk and are audit-logged.' },
    { title: 'Reports & Evidence', body: 'Reports are generated from the investigation. Export JSON, CSV or PDF. The report carries the investigation story, source reliability, confidence and AI findings.' },
    { title: 'You\'re Ready', body: 'Start from the command center, or search anything with ⌘K. Everything routes back to a threat actor. Contact your administrator for role or permission changes.' },
  ];

  const startDemo = () => { setDemoOpen(true); setDemoStep(0); };
  const nextStep = () => { if (demoStep < demoSteps.length - 1) setDemoStep(demoStep + 1); else setDemoOpen(false); };
  const prevStep = () => { if (demoStep > 0) setDemoStep(demoStep - 1); else setDemoOpen(false); };
  const skipDemo = () => setDemoOpen(false);
  const goToSection = (path: string) => { setDemoOpen(false); navigate(path); };

  return (
    <div className="min-h-screen" style={S.canvas}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-8">

        {/* Header */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
          className="flex flex-col md:flex-row md:items-end justify-between gap-4"
        >
          <div className="space-y-2">
            <div className="flex items-center gap-3">
               <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={S.muted}>
                 {new Date(darkWebMonitoring.lastCollection).toLocaleString()}
               </p>
               <ThreatPosturePill posture={openAlerts.length > 3 ? 'CRITICAL' : posture.critical > 0 ? 'CRITICAL' : posture.high > 0 ? 'HIGH' : 'ELEVATED'} />
               <DemoLabel />
            </div>
            <h1 className="font-serif text-3xl" style={S.text}>Dark Web Command Center</h1>
            <p className="text-sm max-w-xl leading-relaxed" style={S.muted}>{postureSummary}</p>
          </div>
          <div className="flex items-center gap-2 text-xs" style={S.muted}>
            <User size={13} />
            <span className="font-mono">{currentAnalyst.name} · {currentAnalyst.shift}</span>
          </div>
          <button onClick={startDemo}
            className="flex items-center gap-2 font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm transition-colors"
            style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
          >
            <PlayCircle size={13} /> Guided Tour
          </button>
        </motion.div>

        {/* Dark web metrics */}
        <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
          {[
            { label: 'Threat Actors',        val: postureCounts.actors,          sub: `${activeActors.length} active · ${dormantActors.length} dormant`, color: 'var(--tw-burgundy)' },
            { label: 'Active Investigations', val: postureCounts.investigations,  sub: topInvestigation ? `${topInvestigation.analyst} · ${topInvestigation.id}` : 'No active investigation', color: 'var(--tw-critical)' },
            { label: 'New Identities',        val: postureCounts.identities,      sub: `${darkWebHandles.length} handles · ${darkWebPgpKeys.length} PGP · ${darkWebWallets.length} wallets`, color: 'var(--tw-high)' },
            { label: 'New Infrastructure',    val: postureCounts.infrastructure,  sub: `${darkWebInfrastructure.filter(i => i.actorIds.length > 1).length} shared across actors`, color: 'var(--tw-info)' },
            { label: 'High-Confidence Correlations', val: postureCounts.correlations, sub: `${darkWebRelationships.filter(r => r.type === 'PERSONA_MIGRATION').length} persona migrations`, color: 'var(--tw-medium)' },
            { label: 'New Evidence',          val: postureCounts.evidence,        sub: `${darkWebEvidence.filter(e => e.reliability >= 85).length} at R85+ reliability`, color: 'var(--tw-low)' },
          ].map(c => (
            <Link key={c.label} to="/app/darkweb" className="rounded-sm p-4 block transition-colors"
              style={S.panel}
              onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'var(--tw-hover)')}
              onMouseLeave={e => (e.currentTarget.style.backgroundColor = '')}
            >
              <div className="font-mono text-3xl font-light" style={{ color: c.color }}>{c.val}</div>
              <p className="font-mono text-[10px] uppercase tracking-wider mt-0.5" style={S.muted}>{c.label}</p>
              <p className="font-mono text-[9px] mt-1 leading-relaxed" style={S.faint}>{c.sub}</p>
            </Link>
          ))}
        </div>

        {/* Two-column layout */}
        <div className="grid lg:grid-cols-3 gap-6">
          {/* Left: Priority Investigation */}
          <div className="lg:col-span-2 space-y-5">

            {/* Priority card */}
            {topInvestigation ? (
            <div className="rounded-sm overflow-hidden" style={S.panel}>
              <div className="px-5 py-3 border-b flex items-center justify-between" style={S.borderMid}>
                <div className="flex items-center gap-2">
                  <AlertTriangle size={13} style={S.burg} />
                  <span className="font-mono text-[10px] tracking-[0.2em] uppercase" style={S.muted}>
                    Priority Dark Web Investigation
                  </span>
                </div>
                <SeverityBadge severity={topInvestigation.status === 'ACTIVE' ? 'HIGH' : 'MEDIUM'} />
              </div>
              <div className="p-6 space-y-5">
                <div className="flex items-start justify-between gap-4">
                  <div className="space-y-1">
                    <p className="font-mono text-[10px]" style={S.muted}>{topInvestigation.id}</p>
                    <h2 className="font-serif text-2xl" style={S.text}>{topInvestigation.title}</h2>
                  </div>
                  <div className="text-right shrink-0">
                    <div className="font-mono text-4xl font-light" style={S.burg}>{topInvestigation.confidence}</div>
                    <div className="font-mono text-[10px] tracking-wider" style={S.muted}>/ 100 CONFIDENCE</div>
                  </div>
                </div>
                <p className="text-sm leading-relaxed" style={S.muted}>{investigationSummary?.detail.executiveSummary ?? 'No investigation summary available for the current dataset.'}</p>
                <div className="space-y-2 border-t pt-4" style={S.borderMid}>
                  <p className="font-mono text-[10px] tracking-[0.15em] uppercase" style={S.muted}>Strongest Evidence Points</p>
                  {evidencePoints.map((ep, i) => (
                    <div key={i} className="flex items-start gap-3">
                      <span className="evidence-num shrink-0">{String(i + 1).padStart(2, '0')}</span>
                      <p className="text-sm" style={S.text}>{ep}</p>
                    </div>
                  ))}
                </div>
                <div className="flex flex-wrap gap-2 items-center justify-between pt-2">
                  <div className="flex gap-2 flex-wrap">
                    {investigationTags.map(tag => (
                      <span key={tag}
                        className="font-mono text-[10px] px-2 py-0.5 rounded-sm"
                        style={{ backgroundColor: 'var(--tw-panel-alt)', color: 'var(--tw-text-muted)' }}
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                  <Link to={`/app/darkweb/investigations/${topInvestigation.id}`}
                    className="flex items-center gap-1.5 font-mono text-xs transition-colors"
                    style={S.burg}
                  >
                    Open Investigation <ArrowRight size={12} />
                  </Link>
                </div>
              </div>
            </div>
            ) : (
              <div className="rounded-sm p-6 text-center" style={S.panel}>
                <p className="font-mono text-[10px] tracking-[0.2em] uppercase mb-2" style={S.muted}>No investigation available</p>
                <p className="text-sm" style={S.faint}>
                  The central model holds no investigation. Create one, or load the synthetic demo dataset to populate the command center.
                </p>
                <Link to="/app/darkweb/investigations" className="inline-block mt-3 font-mono text-xs px-4 py-2 rounded-sm border" style={S.burg}>
                  Go to Investigations <ArrowRight size={12} className="inline" />
                </Link>
              </div>
            )}

            {/* Activity timeline chart */}
            <div className="rounded-sm overflow-hidden" style={S.panel}>
              <div className="px-5 py-3 border-b flex items-center justify-between" style={S.borderMid}>
                <span className="font-mono text-[10px] tracking-[0.2em] uppercase" style={S.muted}>Collection Activity Trend</span>
                <DemoLabel />
              </div>
              <div className="p-5">
                <ResponsiveContainer width="100%" height={180}>
                  <AreaChart data={activityTimeline} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
                    <XAxis dataKey="hour"
                      tick={{ fontSize: 9, fontFamily: 'IBM Plex Mono', fill: 'var(--tw-text-muted)' }}
                      axisLine={false} tickLine={false} interval={0}
                    />
                    <YAxis
                      tick={{ fontSize: 9, fontFamily: 'IBM Plex Mono', fill: 'var(--tw-text-muted)' }}
                      axisLine={false} tickLine={false}
                    />
                    <Tooltip
                      contentStyle={{
                        background: 'var(--tw-panel)',
                        border: '1px solid var(--tw-border)',
                        borderRadius: 2,
                        fontFamily: 'IBM Plex Mono',
                        fontSize: 11,
                        color: 'var(--tw-text)',
                      }}
                    />
                    <Legend wrapperStyle={{ fontSize: 10, fontFamily: 'IBM Plex Mono' }} />
                    <Area type="monotone" dataKey="activity"      stroke="var(--tw-critical)" fill="var(--tw-critical)" fillOpacity={0.08} strokeWidth={1.5} />
                    <Area type="monotone" dataKey="identity"      stroke="var(--tw-brass)"    fill="var(--tw-brass)"    fillOpacity={0.08} strokeWidth={1.5} />
                    <Area type="monotone" dataKey="infrastructure" stroke="var(--tw-moss)"     fill="var(--tw-moss)"     fillOpacity={0.08} strokeWidth={1.5} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Attribution queue */}
            <div className="rounded-sm overflow-hidden" style={S.panel}>
              <div className="px-5 py-3 border-b flex items-center justify-between" style={S.borderMid}>
                <span className="font-mono text-[10px] tracking-[0.2em] uppercase" style={S.muted}>Attribution Queue</span>
                <Link to="/app/darkweb/actors" className="font-mono text-[10px] transition-colors" style={S.burg}>View all →</Link>
              </div>
              <div>
                {attributionQueue.map(entry => (
                  <Link key={entry.id} to={entry.to}
                    className="flex items-center gap-4 px-5 py-4 border-b transition-colors group"
                    style={{ borderColor: 'var(--tw-border-mid)' }}
                    onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'var(--tw-hover)')}
                    onMouseLeave={e => (e.currentTarget.style.backgroundColor = '')}
                  >
                    <div className="w-10 text-center shrink-0">
                      <div className="font-mono text-lg font-light" style={S.burg}>{entry.score}</div>
                      <div className="font-mono text-[8px]" style={S.muted}>CONF</div>
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate" style={S.text}>{entry.title}</p>
                      <p className="font-mono text-[10px]" style={S.muted}>{entry.detail}</p>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <SeverityBadge severity={entry.severity} />
                    </div>
                  </Link>
                ))}
              </div>
            </div>
          </div>

          {/* Right column */}
          <div className="space-y-5">
            {/* Threat Evidence Network */}
            <ThreatEvidenceNetwork pageType="dashboard" />

            {/* Counters */}
            <div className="grid grid-cols-2 gap-3">
                {[
                   { label: 'Threat Actors',    val: postureCounts.actors,         color: 'var(--tw-critical)' },
                   { label: 'Open Alerts',      val: openAlerts.length,           color: 'var(--tw-medium)' },
                   { label: 'Identities',       val: postureCounts.identities,    color: 'var(--tw-high)' },
                   { label: 'High-Confidence',  val: postureCounts.correlations,  color: 'var(--tw-moss)' },
                   { label: 'Critical Risk',     val: posture.critical + posture.high, color: posture.critical > 0 ? 'var(--tw-critical)' : 'var(--tw-high)' },
                 ].map(c => (
                <div key={c.label} className="rounded-sm p-4" style={S.panel}>
                  <div className="font-mono text-2xl font-light" style={{ color: c.color }}>{c.val}</div>
                  <p className="font-mono text-[10px] uppercase tracking-wider mt-0.5" style={S.muted}>{c.label}</p>
                </div>
              ))}
            </div>

            {/* Alerts */}
            <div className="rounded-sm overflow-hidden" style={S.panel}>
              <div className="px-4 py-3 border-b flex items-center justify-between" style={S.borderMid}>
                <span className="font-mono text-[10px] tracking-[0.2em] uppercase" style={S.muted}>Recent Dark Web Alerts</span>
                <Link to="/app/darkweb/alerts" className="font-mono text-[10px]" style={S.burg}>All →</Link>
              </div>
              <div>
                {recentAlerts.map(alert => (
                  <Link key={alert.id} to="/app/darkweb/alerts" className="block px-4 py-3 space-y-1 border-b transition-colors"
                    style={{ borderColor: 'var(--tw-border-mid)' }}
                    onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'var(--tw-hover)')}
                    onMouseLeave={e => (e.currentTarget.style.backgroundColor = '')}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <p className="text-xs font-medium leading-snug" style={S.text}>{alert.title}</p>
                      <SeverityBadge severity={alert.severity} className="shrink-0" />
                    </div>
                    <p className="font-mono text-[10px]" style={S.muted}>{alert.id} · {alert.type.replace(/_/g, ' ')}</p>
                    <p className="text-[10px] leading-relaxed line-clamp-2" style={S.muted}>{alert.reason}</p>
                  </Link>
                ))}
              </div>
            </div>

            {/* 24x7 monitoring posture — read from the backend monitor registry */}
            <DashboardMonitoringPanel />

            {/* Exposure watch */}
            <div className="rounded-sm overflow-hidden" style={S.panel}>
              <div className="px-4 py-3 border-b flex items-center justify-between" style={S.borderMid}>
                <span className="font-mono text-[10px] tracking-[0.2em] uppercase" style={S.muted}>Exposure Watch</span>
                <Link to="/app/darkweb/exposure" className="font-mono text-[10px]" style={S.burg}>Ledger →</Link>
              </div>
              <div className="p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs" style={S.text}>a••••@secureops.in</span>
                  <span className="font-mono text-[10px] px-2 py-0.5 rounded-sm border"
                    style={{ backgroundColor: 'color-mix(in srgb, var(--tw-critical) 18%, transparent)', color: 'var(--tw-critical)', borderColor: 'color-mix(in srgb, var(--tw-critical) 40%, transparent)' }}
                  >
                    Unresolved
                  </span>
                </div>
                <p className="text-[10px]" style={S.muted}>Credential-pair indicator · Finance dept. · Awaiting approval</p>
                <Link to="/app/darkweb/exposure" className="font-mono text-[10px]" style={S.burg}>Review record EXP-00481 →</Link>
              </div>
            </div>

            {/* Quick actions */}
            <div className="rounded-sm overflow-hidden" style={S.panel}>
              <div className="px-4 py-3 border-b" style={S.borderMid}>
                <span className="font-mono text-[10px] tracking-[0.2em] uppercase" style={S.muted}>Quick Actions</span>
              </div>
              <div className="p-3 space-y-1">
                 {[
                   { label: 'Open Dark Web Intelligence', to: '/app/darkweb' },
                   { label: 'Correlate an Identity',       to: '/app/darkweb/correlation' },
                   { label: 'Start an Investigation',      to: '/app/darkweb/investigations' },
                   { label: 'Review Alerts',               to: '/app/darkweb/alerts' },
                   { label: 'Protection & Response',       to: '/app/darkweb/actors' },
                 ].map(action => (
                  <Link key={action.label} to={action.to}
                    className="flex items-center justify-between w-full px-3 py-2.5 text-xs rounded-sm transition-colors"
                    style={{ color: 'var(--tw-text)' }}
                    onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'var(--tw-hover)')}
                    onMouseLeave={e => (e.currentTarget.style.backgroundColor = '')}
                  >
                    {action.label}
                    <ArrowRight size={11} style={S.muted} />
                  </Link>
                ))}
              </div>
            </div>

            {/* Shift */}
            <div className="flex items-center gap-2 px-4 py-3 rounded-sm"
              style={{ backgroundColor: 'var(--tw-canvas-mid)', border: '1px solid var(--tw-border)' }}
            >
              <Clock size={12} style={S.muted} />
              <span className="font-mono text-[10px]" style={S.muted}>{currentAnalyst.shift}</span>
            </div>
          </div>
        </div>

        {/* Full-width timeline */}
        <div className="rounded-sm overflow-hidden" style={S.panel}>
          <div className="px-5 py-3 border-b flex items-center justify-between" style={S.borderMid}>
            <span className="font-mono text-[10px] tracking-[0.2em] uppercase" style={S.muted}>
              Collection Timeline — Identity vs Infrastructure
            </span>
            <Link to="/app/darkweb/timeline" className="font-mono text-[10px] flex items-center gap-1" style={S.burg}>
              Full timeline <Network size={10} />
            </Link>
          </div>
          <div className="p-5">
            <ResponsiveContainer width="100%" height={120}>
              <BarChart data={activityTimeline} margin={{ top: 4, right: 4, bottom: 0, left: -20 }} barSize={6}>
                <XAxis dataKey="hour"
                  tick={{ fontSize: 9, fontFamily: 'IBM Plex Mono', fill: 'var(--tw-text-muted)' }}
                  axisLine={false} tickLine={false} interval={0}
                />
                <YAxis tick={{ fontSize: 9, fontFamily: 'IBM Plex Mono', fill: 'var(--tw-text-muted)' }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: 'var(--tw-panel)', border: '1px solid var(--tw-border)', borderRadius: 2, fontFamily: 'IBM Plex Mono', fontSize: 11, color: 'var(--tw-text)' }} />
                <Legend wrapperStyle={{ fontSize: 10, fontFamily: 'IBM Plex Mono' }} />
                <Bar dataKey="activity"       fill="var(--tw-critical)" fillOpacity={0.7} />
                <Bar dataKey="identity"       fill="var(--tw-brass)"    fillOpacity={0.7} />
                <Bar dataKey="infrastructure" fill="var(--tw-moss)"     fillOpacity={0.7} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Guided Demo Overlay */}
        <AnimatePresence>
          {demoOpen && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="fixed inset-0 z-[100] flex items-center justify-center p-4"
              style={{ backgroundColor: 'rgba(0,0,0,0.6)' }}
            >
              <div className="rounded-sm overflow-hidden shadow-2xl max-w-lg w-full"
                style={{ backgroundColor: 'var(--tw-panel)', border: '1px solid var(--tw-border)' }}
              >
                <div className="px-6 py-4 border-b flex items-center justify-between" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <div className="flex items-center gap-2">
                    <PlayCircle size={14} style={{ color: 'var(--tw-burgundy)' }} />
                    <span className="font-mono text-xs tracking-widest uppercase" style={{ color: 'var(--tw-burgundy)' }}>
                      Guided Tour — Step {demoStep + 1} of {demoSteps.length}
                    </span>
                  </div>
                  <button onClick={skipDemo} className="p-1 rounded-sm" style={{ color: 'var(--tw-text-muted)' }}>
                    <X size={14} />
                  </button>
                </div>
                <div className="p-6 space-y-4">
                  <div className="flex items-center gap-2">
                    {demoSteps.map((_, i) => (
                      <div key={i} className="flex-1 h-1 rounded-full"
                        style={{
                          backgroundColor: i <= demoStep ? 'var(--tw-burgundy)' : 'var(--tw-border-mid)',
                          transition: 'background-color 0.2s',
                        }}
                      />
                    ))}
                  </div>
                  <h3 className="font-serif text-xl" style={{ color: 'var(--tw-text)' }}>{demoSteps[demoStep].title}</h3>
                  <p className="text-sm leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>{demoSteps[demoStep].body}</p>
                  {demoStep === 1 && (
                    <button onClick={() => goToSection('/app/darkweb')}
                      className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm transition-colors"
                      style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
                    >
                      Open Dark Web Intelligence →
                    </button>
                  )}
                  {demoStep === 2 && (
                    <button onClick={() => goToSection('/app/darkweb')}
                      className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm transition-colors"
                      style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
                    >
                      Open Dark Web Intelligence →
                    </button>
                  )}
                  {demoStep === 3 && seedActor && (
                    <button onClick={() => goToSection(`/app/darkweb/actors/${seedActor.id}`)}
                      className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                      style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
                    >
                      Open {seedActor.id} →
                    </button>
                  )}
                  {demoStep === 4 && (
                    <button onClick={() => goToSection('/app/darkweb/correlation')}
                      className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                      style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
                    >
                      Open Identity Correlation →
                    </button>
                  )}
                  {demoStep === 5 && (
                    <button onClick={() => goToSection('/app/darkweb/alerts')}
                      className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                      style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
                    >
                      Open Monitoring &amp; Alerts →
                    </button>
                  )}
                  {demoStep === 6 && (
                    <button onClick={() => goToSection('/app/darkweb/ai')}
                      className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                      style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
                    >
                      Open AI Analysis →
                    </button>
                  )}
                  {demoStep === 7 && (
                    <button onClick={() => goToSection('/app/darkweb/evidence')}
                      className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                      style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
                    >
                      Open Evidence Locker →
                    </button>
                  )}
                  {demoStep === 8 && (
                    <button onClick={() => goToSection('/app/decisions')}
                      className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                      style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
                    >
                      Open Decision Desk →
                    </button>
                  )}
                  {demoStep === 9 && (
                    <button onClick={() => goToSection('/app/reports')}
                      className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm transition-colors"
                      style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
                    >
                      Open Reports →
                    </button>
                  )}
                </div>
                <div className="px-6 py-3 border-t flex items-center justify-between" style={{ borderColor: 'var(--tw-border-mid)', backgroundColor: 'var(--tw-panel-alt)' }}>
                  <button onClick={prevStep} disabled={demoStep === 0}
                    className="flex items-center gap-1 font-mono text-xs transition-colors disabled:opacity-40"
                    style={{ color: 'var(--tw-text-muted)' }}
                  >
                    <ChevronLeft size={12} /> Back
                  </button>
                  <button onClick={nextStep}
                    className="flex items-center gap-1 font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm transition-colors"
                    style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
                  >
                    {demoStep === demoSteps.length - 1 ? 'Finish' : 'Next'} <ChevronRight size={12} />
                  </button>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}

// ============================================================
// Dashboard — 24x7 monitoring posture.
//
// This panel is a read-only summary of the backend monitor registry, so
// the command center shows the same monitors the Monitoring workspace
// does. It deliberately surfaces "awaiting data" and "source
// unavailable" rather than folding them into a single green number:
// a monitor that cannot reach its sources is not watching anything.
function DashboardMonitoringPanel() {
  const { value: stats } = useMonitoringPolling(monitoringStats, 30000);

  if (!stats || stats.totalMonitors === 0) return null;

  const figures = [
    { label: 'Active', value: stats.activeMonitors, color: 'var(--tw-low)' },
    { label: 'Paused', value: stats.pausedMonitors, color: 'var(--tw-medium)' },
    { label: 'Awaiting data', value: stats.awaitingDataMonitors, color: 'var(--tw-info)' },
    { label: 'Source unavailable', value: stats.sourceUnavailableMonitors, color: 'var(--tw-high)' },
    { label: 'Open alerts', value: stats.openAlerts, color: 'var(--tw-critical)' },
  ];

  return (
    <div className="rounded-sm overflow-hidden" style={S.panel}>
      <div className="px-4 py-3 border-b flex items-center justify-between" style={S.borderMid}>
        <span className="font-mono text-[10px] tracking-[0.2em] uppercase" style={S.muted}>24×7 Monitoring</span>
        <Link to="/app/monitoring/monitors" className="font-mono text-[10px]" style={S.burg}>Monitors →</Link>
      </div>
      <div className="p-4 space-y-3">
        <div className="grid grid-cols-3 sm:grid-cols-5 gap-3">
          {figures.map(figure => (
            <div key={figure.label}>
              <p className="font-mono text-lg font-light" style={{ color: figure.color }}>{figure.value}</p>
              <p className="font-mono text-[9px] uppercase tracking-wider" style={S.faint}>{figure.label}</p>
            </div>
          ))}
        </div>
        {stats.nextChecks.length > 0 && (
          <p className="font-mono text-[10px]" style={S.faint}>
            Next check {new Date(stats.nextChecks[0].nextCheck!).toLocaleString()} · {stats.nextChecks[0].capability?.intervalLabel} interval
            {stats.nextChecks[0].capability && !stats.nextChecks[0].capability.continuous ? ' (not continuous)' : ''}
          </p>
        )}
      </div>
    </div>
  );
}


