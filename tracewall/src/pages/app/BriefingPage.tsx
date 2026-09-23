import { Link, useNavigate } from 'react-router-dom';
import { ArrowRight, Clock, AlertTriangle, User, PlayCircle, X, ChevronLeft, ChevronRight } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useState } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, Legend
} from 'recharts';
import { dailyBriefing, currentAnalyst, investigations, alerts, activityTimeline } from '../../data/mockData';
import { SeverityBadge } from '../../components/ui/SeverityBadge';
import { DemoLabel } from '../../components/ui/DemoLabel';
import ThreatEvidenceNetwork from '../../components/3d/ThreatEvidenceNetwork';

const topInvestigation = investigations[0];
const recentAlerts = alerts.slice(0, 3);

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

function ThreatPosturePill({ posture }: { posture: string }) {
  const map: Record<string, string> = {
    ELEVATED: 'var(--tw-medium)',
    CRITICAL: 'var(--tw-critical)',
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

  const demoSteps = [
    { title: 'Welcome to PhishNet', body: 'This guided tour walks through a complete investigation workflow: from email analysis to dark-web exposure, case review, response approval, audit logging, and report generation.' },
    { title: 'Start: Priority Investigation', body: 'The Priority Investigation card shows your highest-risk case (INV-2026-0041). This case is linked to a BEC invoice-diversion campaign. Click to open the case, or continue the tour to Email Analysis.' },
    { title: 'Email Analysis: Choose Demo Invoice-Fraud Email', body: 'Navigate to Email Analysis and select the "SecureOps — Invoice Diversion (BEC)" demo email. This simulates a real analyst workflow for suspicious message intake.' },
    { title: 'Watch Simulated Analysis Progress', body: 'The analysis runs through 10 stages: parsing headers, validating SPF/DKIM/DMARC, extracting IOCs, analysing URLs, checking attachments, enriching intelligence, correlating infrastructure, checking exposure records, generating AI explanation, and preparing forensic evidence.' },
    { title: 'Review Results: Risk, Auth, Headers, Relay, Domain', body: 'After analysis, switch between tabs: Verdict (risk score 92/100), Identity (sender mismatches), Authentication (SPF/DKIM/DMARC results), Relay Path (5 hops with reliability tags), Domain Intel (lookalike domain, 11-day age), and Social Engineering (urgency/secrecy/authority patterns).' },
    { title: 'Dark-Web Monitor: Masked Exposure', body: 'Open the Exposure Ledger (/app/exposure). Record EXP-00481 shows a masked Finance credential (a••••@secureops.in) from a combo-list breach. View confidence (92%), severity (HIGH), and recommended actions including forced password reset — all with plaintext secrets redacted.' },
    { title: 'Open Related Case', body: 'Navigate to Cases (/app/cases/INV-2026-0041). The case timeline shows evidence collection, analyst assignment, campaign correlation (CAMP-2026-017), and exposure linkage (EXP-00481). Tabs: Timeline, Tasks, Notes, Evidence.' },
    { title: 'Preview Response Actions & Approval', body: 'Open Decision Desk (/app/decisions). Review recommended actions: Quarantine Email (auto), Block Sender Domain (approval), Verify Payment Instructions, Submit to Sandbox, Block Malicious URLs (auto), Alert Finance Dept. High-impact actions require reason and confirmation; all are audit-logged.' },
    { title: 'Audit Log Entry', body: 'Open Audit Log (/app/audit). Every executed action appears with Event ID, timestamp, actor, action, target, outcome, and IP. The log is tamper-evident and read-only. Sensitive identifiers are masked in display.' },
    { title: 'Generate Report Preview', body: 'Open Reports (/app/reports). Click "Generate Dossier" to compile a forensic investigation dossier (RPT-2026-0041-A) with all sections: scope, executive assessment, email identity, auth results, relay timeline, domain intel, risk breakdown, dark-web exposure, campaign relationships, IOCs, recommended actions, evidence, chain of custody, limitations, and analyst approval. Export JSON or Print/PDF.' },
    { title: 'You\'re Ready', body: 'You\'ve completed the end-to-end investigation workflow tour. The audit log records every sensitive action. Contact your administrator for role or permission changes.' },
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
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={S.muted}>{dailyBriefing.date}</p>
              <ThreatPosturePill posture={dailyBriefing.threatPosture} />
              <DemoLabel />
            </div>
            <h1 className="font-serif text-3xl" style={S.text}>Daily Briefing</h1>
            <p className="text-sm max-w-xl leading-relaxed" style={S.muted}>{dailyBriefing.postureSummary}</p>
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

        {/* Two-column layout */}
        <div className="grid lg:grid-cols-3 gap-6">
          {/* Left: Priority Investigation */}
          <div className="lg:col-span-2 space-y-5">

            {/* Priority card */}
            <div className="rounded-sm overflow-hidden" style={S.panel}>
              <div className="px-5 py-3 border-b flex items-center justify-between" style={S.borderMid}>
                <div className="flex items-center gap-2">
                  <AlertTriangle size={13} style={S.burg} />
                  <span className="font-mono text-[10px] tracking-[0.2em] uppercase" style={S.muted}>
                    Priority Investigation
                  </span>
                </div>
                <SeverityBadge severity={topInvestigation.severity} />
              </div>
              <div className="p-6 space-y-5">
                <div className="flex items-start justify-between gap-4">
                  <div className="space-y-1">
                    <p className="font-mono text-[10px]" style={S.muted}>{topInvestigation.id}</p>
                    <h2 className="font-serif text-2xl" style={S.text}>{topInvestigation.title}</h2>
                  </div>
                  <div className="text-right shrink-0">
                    <div className="font-mono text-4xl font-light" style={S.burg}>{topInvestigation.riskScore}</div>
                    <div className="font-mono text-[10px] tracking-wider" style={S.muted}>/ 100 RISK</div>
                  </div>
                </div>
                <p className="text-sm leading-relaxed" style={S.muted}>{topInvestigation.aiSummary}</p>
                <div className="space-y-2 border-t pt-4" style={S.borderMid}>
                  <p className="font-mono text-[10px] tracking-[0.15em] uppercase" style={S.muted}>Strongest Evidence Points</p>
                  {topInvestigation.evidencePoints.map((ep, i) => (
                    <div key={i} className="flex items-start gap-3">
                      <span className="evidence-num shrink-0">{String(i + 1).padStart(2, '0')}</span>
                      <p className="text-sm" style={S.text}>{ep}</p>
                    </div>
                  ))}
                </div>
                <div className="flex flex-wrap gap-2 items-center justify-between pt-2">
                  <div className="flex gap-2 flex-wrap">
                    {topInvestigation.tags.map(tag => (
                      <span key={tag}
                        className="font-mono text-[10px] px-2 py-0.5 rounded-sm"
                        style={{ backgroundColor: 'var(--tw-panel-alt)', color: 'var(--tw-text-muted)' }}
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                  <Link to={`/app/cases/${topInvestigation.id}`}
                    className="flex items-center gap-1.5 font-mono text-xs transition-colors"
                    style={S.burg}
                  >
                    Open Investigation <ArrowRight size={12} />
                  </Link>
                </div>
              </div>
            </div>

            {/* Activity timeline chart */}
            <div className="rounded-sm overflow-hidden" style={S.panel}>
              <div className="px-5 py-3 border-b flex items-center justify-between" style={S.borderMid}>
                <span className="font-mono text-[10px] tracking-[0.2em] uppercase" style={S.muted}>Today's Threat Activity</span>
                <DemoLabel />
              </div>
              <div className="p-5">
                <ResponsiveContainer width="100%" height={180}>
                  <AreaChart data={activityTimeline} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
                    <XAxis dataKey="hour"
                      tick={{ fontSize: 9, fontFamily: 'IBM Plex Mono', fill: 'var(--tw-text-muted)' }}
                      axisLine={false} tickLine={false} interval={2}
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
                    <Area type="monotone" dataKey="phishing" stroke="var(--tw-critical)" fill="var(--tw-critical)" fillOpacity={0.08} strokeWidth={1.5} />
                    <Area type="monotone" dataKey="bec"      stroke="var(--tw-brass)"    fill="var(--tw-brass)"    fillOpacity={0.08} strokeWidth={1.5} />
                    <Area type="monotone" dataKey="malware"  stroke="var(--tw-moss)"     fill="var(--tw-moss)"     fillOpacity={0.08} strokeWidth={1.5} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Investigation queue */}
            <div className="rounded-sm overflow-hidden" style={S.panel}>
              <div className="px-5 py-3 border-b flex items-center justify-between" style={S.borderMid}>
                <span className="font-mono text-[10px] tracking-[0.2em] uppercase" style={S.muted}>Investigation Queue</span>
                <Link to="/app/cases" className="font-mono text-[10px] transition-colors" style={S.burg}>View all →</Link>
              </div>
              <div>
                {investigations.map(inv => (
                  <Link key={inv.id} to={`/app/cases/${inv.id}`}
                    className="flex items-center gap-4 px-5 py-4 border-b transition-colors group"
                    style={{ borderColor: 'var(--tw-border-mid)' }}
                    onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'var(--tw-hover)')}
                    onMouseLeave={e => (e.currentTarget.style.backgroundColor = '')}
                  >
                    <div className="w-10 text-center shrink-0">
                      <div className="font-mono text-lg font-light" style={S.burg}>{inv.riskScore}</div>
                      <div className="font-mono text-[8px]" style={S.muted}>RISK</div>
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate" style={S.text}>{inv.title}</p>
                      <p className="font-mono text-[10px]" style={S.muted}>{inv.id} · {inv.assignedTo}</p>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <SeverityBadge severity={inv.severity} />
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
                { label: 'Investigations', val: dailyBriefing.investigationsRequiringAttention, color: 'var(--tw-critical)' },
                { label: 'Pending Decisions', val: dailyBriefing.pendingDecisions,              color: 'var(--tw-medium)' },
                { label: 'Open Exposures',   val: dailyBriefing.openExposures,                  color: 'var(--tw-high)' },
                { label: 'Analyst Queue',    val: 3,                                             color: 'var(--tw-moss)' },
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
                <span className="font-mono text-[10px] tracking-[0.2em] uppercase" style={S.muted}>Today's Alerts</span>
                <Link to="/app/alerts" className="font-mono text-[10px]" style={S.burg}>All →</Link>
              </div>
              <div>
                {recentAlerts.map(alert => (
                  <div key={alert.id} className="px-4 py-3 space-y-1 border-b transition-colors cursor-pointer"
                    style={{ borderColor: 'var(--tw-border-mid)' }}
                    onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'var(--tw-hover)')}
                    onMouseLeave={e => (e.currentTarget.style.backgroundColor = '')}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <p className="text-xs font-medium leading-snug" style={S.text}>{alert.title}</p>
                      <SeverityBadge severity={alert.severity} className="shrink-0" />
                    </div>
                    <p className="font-mono text-[10px]" style={S.muted}>{alert.id}</p>
                    <p className="text-[10px] leading-relaxed line-clamp-2" style={S.muted}>{alert.recommendation}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Exposure watch */}
            <div className="rounded-sm overflow-hidden" style={S.panel}>
              <div className="px-4 py-3 border-b flex items-center justify-between" style={S.borderMid}>
                <span className="font-mono text-[10px] tracking-[0.2em] uppercase" style={S.muted}>Exposure Watch</span>
                <Link to="/app/exposure" className="font-mono text-[10px]" style={S.burg}>Ledger →</Link>
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
                <Link to="/app/exposure" className="font-mono text-[10px]" style={S.burg}>Review record EXP-00481 →</Link>
              </div>
            </div>

            {/* Quick actions */}
            <div className="rounded-sm overflow-hidden" style={S.panel}>
              <div className="px-4 py-3 border-b" style={S.borderMid}>
                <span className="font-mono text-[10px] tracking-[0.2em] uppercase" style={S.muted}>Quick Actions</span>
              </div>
              <div className="p-3 space-y-1">
                {[
                  { label: 'Investigate New Email', to: '/app/investigate' },
                  { label: 'Open Exposure Ledger',  to: '/app/exposure' },
                  { label: 'View Campaigns',         to: '/app/campaigns' },
                  { label: 'Generate Report',        to: '/app/reports' },
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
            <span className="font-mono text-[10px] tracking-[0.2em] uppercase" style={S.muted}>Investigation Timeline — Today</span>
            <DemoLabel />
          </div>
          <div className="p-5">
            <ResponsiveContainer width="100%" height={120}>
              <BarChart data={activityTimeline.slice(6)} margin={{ top: 4, right: 4, bottom: 0, left: -20 }} barSize={6}>
                <XAxis dataKey="hour"
                  tick={{ fontSize: 9, fontFamily: 'IBM Plex Mono', fill: 'var(--tw-text-muted)' }}
                  axisLine={false} tickLine={false}
                />
                <YAxis tick={{ fontSize: 9, fontFamily: 'IBM Plex Mono', fill: 'var(--tw-text-muted)' }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: 'var(--tw-panel)', border: '1px solid var(--tw-border)', borderRadius: 2, fontFamily: 'IBM Plex Mono', fontSize: 11, color: 'var(--tw-text)' }} />
                <Legend wrapperStyle={{ fontSize: 10, fontFamily: 'IBM Plex Mono' }} />
                <Bar dataKey="phishing" fill="var(--tw-critical)" fillOpacity={0.7} />
                <Bar dataKey="bec"      fill="var(--tw-brass)"    fillOpacity={0.7} />
                <Bar dataKey="malware"  fill="var(--tw-moss)"     fillOpacity={0.7} />
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
                    <button onClick={() => goToSection('/app/cases/' + investigations[0].id)}
                      className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm transition-colors"
                      style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
                    >
                      Open Case INV-2026-0041 →
                    </button>
                  )}
                  {demoStep === 2 && (
                    <button onClick={() => goToSection('/app/investigate')}
                      className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm transition-colors"
                      style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
                    >
                      Open Email Analysis →
                    </button>
                  )}
                  {demoStep === 5 && (
                    <button onClick={() => goToSection('/app/exposure')}
                      className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                      style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
                    >
                      Open Exposure Ledger →
                    </button>
                  )}
                  {demoStep === 6 && (
                    <button onClick={() => goToSection('/app/cases/' + investigations[0].id)}
                      className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                      style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
                    >
                      Open Case INV-2026-0041 →
                    </button>
                  )}
                  {demoStep === 7 && (
                    <button onClick={() => goToSection('/app/decisions')}
                      className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                      style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
                    >
                      Open Decision Desk →
                    </button>
                  )}
                  {demoStep === 8 && (
                    <button onClick={() => goToSection('/app/audit')}
                      className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                      style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
                    >
                      Open Audit Log →
                    </button>
                  )}
                  {demoStep === 9 && (
                    <button onClick={() => goToSection('/app/reports')}
                      className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                      style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
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
