// ============================================================
// VIPER TRACE — Landing page.
//
// VIPER TRACE is a Dark Web Threat Intelligence & Investigation
// Platform. Every figure on this page is read from the same central
// intelligence model the application uses, so the product story and
// the product data can never drift apart. The forensic tools
// (Email Analyzer, File Analysis, URL Analysis, Infrastructure
// Analysis) are presented lower down as supporting capabilities.
// ============================================================
import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield, ArrowRight, FileText, Network, BarChart3, BookOpen, Sun, Moon,
  Key, Server, Link2, Database, Users, Fingerprint, FileSearch, Link as LinkIcon,
} from 'lucide-react';
import { motion } from 'framer-motion';
import { useTheme } from '../context/ThemeContext';
import { lazy, Suspense } from 'react';
import { ThreeDErrorBoundary } from '../components/3d/ThreeDErrorBoundary';
import { useIntelligence, useIntelligenceData } from '../lib/intelligence/IntelligenceContext';
import { shortFingerprint } from '../lib/intelligence/normalize';
import { HOME_PATH } from '../lib/darkweb/navConfig';

// Lazy load the 3D component
const ThreatNetwork3D = lazy(() => import('../components/3d/ThreatNetwork3D').then(m => ({ default: m.default })));

/**
 * Flat rendering of the same actor relationship model the 3D canvas draws.
 * Used wherever the canvas is unavailable, so the diagram itself is never lost.
 */
function ActorCanvasDiagram() {
  return (
    <svg viewBox="0 0 400 200" className="w-full h-full">
      <line x1="200" y1="100" x2="80"  y2="50"  stroke="var(--tw-border-strong)" strokeWidth="1" strokeDasharray="4,3" />
      <line x1="200" y1="100" x2="320" y2="50"  stroke="var(--tw-border-strong)" strokeWidth="1" />
      <line x1="200" y1="100" x2="80"  y2="155" stroke="var(--tw-border-strong)" strokeWidth="1" />
      <line x1="200" y1="100" x2="320" y2="155" stroke="var(--tw-border-strong)" strokeWidth="1" strokeDasharray="4,3" />
      <line x1="80"  y1="50"  x2="30"  y2="100" stroke="var(--tw-border-strong)" strokeWidth="1" strokeDasharray="2,4" />
      <line x1="320" y1="50"  x2="370" y2="100" stroke="var(--tw-border-strong)" strokeWidth="1" />
      <rect x="168" y="84"  width="64" height="32" rx="2" fill="var(--tw-burgundy)" fillOpacity="0.22" stroke="var(--tw-burgundy)" strokeWidth="1.5" />
      <text x="200" y="104" textAnchor="middle" fill="var(--tw-burgundy)" fontSize="9" fontFamily="IBM Plex Mono">ACTOR</text>
      <rect x="40"  y="34"  width="80" height="30" rx="2" fill="var(--tw-medium)" fillOpacity="0.18" stroke="var(--tw-medium)" strokeWidth="1" />
      <text x="80"  y="53"  textAnchor="middle" fill="var(--tw-medium)" fontSize="8" fontFamily="IBM Plex Mono">HANDLE</text>
      <rect x="280" y="34"  width="80" height="30" rx="2" fill="var(--tw-medium)" fillOpacity="0.18" stroke="var(--tw-medium)" strokeWidth="1" />
      <text x="320" y="53"  textAnchor="middle" fill="var(--tw-medium)" fontSize="8" fontFamily="IBM Plex Mono">PGP</text>
      <rect x="40"  y="139" width="80" height="30" rx="2" fill="var(--tw-low)" fillOpacity="0.18" stroke="var(--tw-low)" strokeWidth="1" />
      <text x="80"  y="158" textAnchor="middle" fill="var(--tw-low)" fontSize="8" fontFamily="IBM Plex Mono">WALLET</text>
      <rect x="280" y="139" width="80" height="30" rx="2" fill="var(--tw-dust)" fillOpacity="0.18" stroke="var(--tw-dust)" strokeWidth="1" />
      <text x="320" y="158" textAnchor="middle" fill="var(--tw-dust)" fontSize="8" fontFamily="IBM Plex Mono">INFRA</text>
      <rect x="0"   y="84"  width="60" height="30" rx="2" fill="var(--tw-critical)" fillOpacity="0.18" stroke="var(--tw-critical)" strokeWidth="1" />
      <text x="30"  y="103" textAnchor="middle" fill="var(--tw-critical)" fontSize="7.5" fontFamily="IBM Plex Mono">EVIDENCE</text>
      <rect x="340" y="84"  width="60" height="30" rx="2" fill="var(--tw-brass)" fillOpacity="0.22" stroke="var(--tw-brass)" strokeWidth="1" />
      <text x="370" y="103" textAnchor="middle" fill="var(--tw-brass)" fontSize="8" fontFamily="IBM Plex Mono">CASE</text>
    </svg>
  );
}

const features = [
  { icon: Users,     title: 'Threat Actor Intelligence',    description: 'One resolved record per actor — aliases, handles, platforms, status, activity and confidence, assembled from every source that observed them.' },
  { icon: Fingerprint,title: 'Identity & Handle Correlation', description: 'Link handles observed on separate platforms, normalise case and padding, and surface reuse indicators instead of assuming a shared identity.' },
  { icon: Key,       title: 'PGP & Wallet Correlation',     description: 'Correlate cryptographic fingerprints and cryptocurrency addresses across actors, with confidence and the counter-indicators recorded alongside.' },
  { icon: Network,   title: 'Relationship Graph',          description: 'Explore every stored relationship between actors, handles, keys, wallets and infrastructure in an interactive evidence graph.' },
  { icon: Server,    title: 'Infrastructure Intelligence',  description: 'Attribute domains, hosts, certificates and address space to actors, and separate observed ownership from inference.' },
  { icon: Link2,     title: 'Persona Migration Detection',  description: 'Detect when an identity is abandoned and a new persona appears, and grade the transition on the evidence that supports it.' },
  { icon: BarChart3, title: 'Behavioral & Stylometric Analysis', description: 'Compare posting cadence, active hours, vocabulary and recurring phrasing to assess whether two personas may be the same operator.' },
  { icon: Database,  title: 'Evidence & Investigation',     description: 'Every record keeps its provenance, source reliability and chain of custody, so an investigation can always be traced back to collection.' },
  { icon: FileText,  title: 'AI Investigation Assistant',   description: 'Synthesise stored records into an assessment that shows its supporting indicators, its confidence, and what the evidence cannot prove.' },
];

const steps = [
  { num: '01', label: 'Discover', desc: 'Find threat actors, handles, identities, platforms and indicators across collected sources.' },
  { num: '02', label: 'Correlate', desc: 'Connect handles, PGP fingerprints, wallets, infrastructure and identities.' },
  { num: '03', label: 'Analyze',   desc: 'Analyse behavior, stylometry, timelines and anomalies for each actor.' },
  { num: '04', label: 'Investigate', desc: 'Explore relationships, evidence and investigation cases.' },
  { num: '05', label: 'Report',    desc: 'Generate evidence-backed investigation reports and intelligence summaries.' },
];

/** The lifecycle the platform is built around, in one line. */
const pipeline = [
  'Dark Web', 'Collect', 'Correlate', 'Analyze', 'Investigate', 'Evidence', 'Alert', 'Report',
];

/** The intelligence chain, resolved end to end, with live record counts. */
const chain = [
  { key: 'actors',           label: 'Threat Actor',     detail: 'The central entity under investigation' },
  { key: 'handles',          label: 'Identities',       detail: 'Handles observed across platforms' },
  { key: 'pgpWallets',       label: 'PGP / Wallet',     detail: 'Cryptographic and payment identifiers' },
  { key: 'infrastructure',   label: 'Infrastructure',   detail: 'Domains, hosts, certificates, address space' },
  { key: 'relationships',    label: 'Relationships',    detail: 'Every asserted link, with confidence' },
  { key: 'evidence',         label: 'Evidence',         detail: 'Provenance, reliability, chain of custody' },
  { key: 'investigations',   label: 'Investigation',    detail: 'Cases built from connected intelligence' },
] as const;

const supportingTools = [
  { icon: FileSearch, title: 'Email Analyzer',      to: '/app/investigate',    description: 'Analyse suspicious emails, headers, authentication results and links.' },
  { icon: FileText,   title: 'File Analysis',       to: '/app/file-analysis',  description: 'Analyse files and attachments for malicious artifacts.' },
  { icon: LinkIcon,   title: 'URL Analysis',        to: '/app/url-analysis',   description: 'Analyse URLs, redirect chains and destination hosts.' },
  { icon: Server,     title: 'Infrastructure Analysis', to: '/app/infrastructure', description: 'Enrich IP and domain indicators for attribution context.' },
];

const fade = { hidden: { opacity: 0, y: 20 }, show: { opacity: 1, y: 0 } };

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: 'var(--tw-critical)',
  HIGH: 'var(--tw-critical)',
  MEDIUM: 'var(--tw-medium)',
  LOW: 'var(--tw-dust)',
  INFO: 'var(--tw-text-muted)',
};

export default function LandingPage() {
  const { isDark, toggleTheme } = useTheme();
  const { dataset, metrics, getActorBundle, getWhyLinked, getEvidenceChain } = useIntelligence();
  const { darkWebActors, darkWebSources } = useIntelligenceData();

  /**
   * A small, real snapshot of the central model: the actor involved in the
   * strongest stored relationship, the relationship itself, the evidence it
   * rests on, and that actor's timeline. Nothing here is invented, and every
   * field degrades to an em dash when the model holds no such record.
   */
  const snapshot = useMemo(() => {
    const actorLinks = dataset.relationships.filter(
      rel => dataset.lookups.actorsById[rel.sourceEntity] && dataset.lookups.actorsById[rel.targetEntity],
    );
    const link = [...actorLinks].sort((a, b) => b.confidence - a.confidence)[0] ?? dataset.relationships[0] ?? null;
    const actorId = link && dataset.lookups.actorsById[link.sourceEntity] ? link.sourceEntity : dataset.actors[0]?.id;
    const bundle = actorId ? getActorBundle(actorId) : null;
    const why = link ? getWhyLinked(link.sourceEntity, link.targetEntity) : null;
    const evidenceId = bundle?.evidence[0]?.id ?? dataset.evidence[0]?.id;
    const chainSteps = evidenceId ? getEvidenceChain(evidenceId) : [];
    const timeline = [...(bundle?.timeline ?? [])].sort(
      (a, b) => new Date(a.time).getTime() - new Date(b.time).getTime(),
    );
    const alerts = [...dataset.alerts]
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, 3);
    return { actorId, bundle, link, why, evidenceId, chainSteps, timeline, alerts };
  }, [dataset, getActorBundle, getWhyLinked, getEvidenceChain]);

  const actor = snapshot.bundle?.actor ?? darkWebActors[0];
  const handleValues = snapshot.bundle?.handles.map(item => item.value) ?? actor?.handles ?? [];
  const pgp = snapshot.bundle?.pgpKeys[0]?.fingerprint ?? actor?.pgpFingerprints[0];
  const wallet = snapshot.bundle?.wallets[0]?.address ?? actor?.walletAddrs[0];
  const infra = snapshot.bundle?.infrastructure[0]?.value ?? actor?.domains[0];
  const platform = snapshot.bundle?.handles[0]?.platform ?? actor?.platforms[0];
  const evidenceReliability = snapshot.bundle?.evidence[0]?.reliability ?? 0;
  const source = snapshot.bundle?.evidence[0]?.source ?? darkWebSources[0]?.name;

  const chainCounts = useMemo<Record<string, number>>(() => ({
    actors: dataset.actors.length,
    handles: dataset.handles.length,
    pgpWallets: dataset.pgpKeys.length + dataset.wallets.length,
    infrastructure: dataset.infrastructure.length,
    relationships: dataset.relationships.length,
    evidence: dataset.evidence.length,
    investigations: dataset.investigations.length,
  }), [dataset]);

  const entityRows = [
    { num: '01', label: 'Threat Actor',    val: actor?.id ?? '—',                                    flag: false },
    { num: '02', label: 'Known Handle',    val: handleValues[0] ?? '—',                              flag: false },
    { num: '03', label: 'Platform',        val: platform ?? '—',                                      flag: false },
    { num: '04', label: 'PGP',             val: pgp ? shortFingerprint(pgp) : '—',                   flag: true },
    { num: '05', label: 'Wallet',          val: wallet ? `${wallet.slice(0, 16)}…` : '—',             flag: false },
    { num: '06', label: 'Infrastructure',  val: infra ?? '—',                                        flag: false },
  ];

  return (
    <div className="min-h-screen" style={{ backgroundColor: 'var(--tw-canvas-warm)', color: 'var(--tw-text)' }}>

      {/* ── Masthead ─────────────────────────────────────── */}
      <header className="sticky top-0 z-50 border-b backdrop-blur-sm"
        style={{ backgroundColor: 'color-mix(in srgb, var(--tw-canvas-warm) 92%, transparent)', borderColor: 'var(--tw-border)' }}
      >
        <div className="max-w-7xl mx-auto px-6 lg:px-10 h-14 flex items-center gap-6">
          <Link to="/" className="flex items-center gap-2 shrink-0">
            <div className="w-7 h-7 rounded-sm flex items-center justify-center" style={{ backgroundColor: 'var(--tw-burgundy)' }}>
              <Shield size={14} style={{ color: '#FBFAF6' }} />
            </div>
            <span className="font-mono text-sm font-medium tracking-[0.14em] uppercase" style={{ color: 'var(--tw-text)' }}>Viper Trace</span>
          </Link>
          <nav className="hidden md:flex items-center gap-6 ml-6">
            {[
              { label: 'Product', to: '/product' },
              { label: 'Features', to: '/features' },
              { label: 'How It Works', to: '/how-it-works' },
              { label: 'Security', to: '/security' },
            ].map(item => (
              <Link key={item.label} to={item.to} className="font-sans text-sm" style={{ color: 'var(--tw-text-muted)' }}>{item.label}</Link>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-3">
            <Link to="/signin" className="hidden md:block font-sans text-sm" style={{ color: 'var(--tw-text-muted)' }}>Sign In</Link>
            <button onClick={toggleTheme} aria-label="Toggle theme" className="p-2 rounded-sm" style={{ color: 'var(--tw-text-muted)' }}>
              {isDark ? <Sun size={16} /> : <Moon size={16} />}
            </button>
            <Link to="/app/briefing" className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm"
              style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
            >
              Request Access
            </Link>
          </div>
        </div>
      </header>

      {/* ── Hero ──────────────────────────────────────────── */}
      <section className="max-w-7xl mx-auto px-6 lg:px-10 pt-20 pb-16">
        <motion.div className="max-w-3xl" initial="hidden" animate="show"
          variants={{ show: { transition: { staggerChildren: 0.1 } } }}
        >
          <motion.div variants={fade} className="mb-4">
            <span className="font-mono text-[10px] tracking-[0.2em] uppercase px-3 py-1 rounded-sm border"
              style={{ color: 'var(--tw-burgundy)', borderColor: 'color-mix(in srgb, var(--tw-burgundy) 40%, transparent)' }}
            >
              Dark Web Threat Intelligence &amp; Investigation Platform
            </span>
          </motion.div>
          <motion.h1 variants={fade} className="font-serif text-5xl lg:text-6xl leading-tight mb-6" style={{ color: 'var(--tw-text)' }}>
            Every hidden identity<br />
            <em style={{ color: 'var(--tw-burgundy)' }}>leaves a trail.</em>
          </motion.h1>
          <motion.p variants={fade} className="font-sans text-lg leading-relaxed max-w-2xl mb-8" style={{ color: 'var(--tw-text-muted)' }}>
            Discover, correlate and investigate threat actors, identities, handles, PGP fingerprints,
            cryptocurrency indicators, infrastructure, relationships and evidence across collected
            dark-web intelligence sources.
          </motion.p>
          <motion.div variants={fade} className="flex flex-wrap gap-3">
            <Link to={HOME_PATH}
              className="flex items-center gap-2 font-mono text-xs tracking-widest uppercase px-5 py-3 rounded-sm"
              style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
            >
              Start Investigation <ArrowRight size={14} />
            </Link>
            <Link to="/app/darkweb/demo"
              className="flex items-center gap-2 font-mono text-xs tracking-widest uppercase px-5 py-3 rounded-sm border"
              style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text)' }}
            >
              View Demo Investigation
            </Link>
          </motion.div>
        </motion.div>
      </section>

      {/* ── Investigation Canvas Preview ──────────────────── */}
      <section className="max-w-7xl mx-auto px-6 lg:px-10 pb-20">
        <motion.div initial={{ opacity: 0, y: 30 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ duration: 0.5 }}
          className="rounded-sm overflow-hidden border"
          style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border)' }}
        >
          {/* Toolbar */}
          <div className="flex items-center gap-3 px-5 py-3 border-b"
            style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border)' }}
          >
            <span className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>Investigation Canvas</span>
            <span className="font-mono text-[10px] tracking-[0.15em] uppercase" style={{ color: 'var(--tw-text-faint)' }}>
              {actor ? `${actor.id} · ${actor.aliases[0]}` : 'No actor in the central model'}
            </span>
            <span className="demo-badge ml-auto">Simulated Demo Data</span>
          </div>

          <div className="grid lg:grid-cols-3 divide-y lg:divide-y-0 lg:divide-x" style={{ borderColor: 'var(--tw-border-mid)' }}>
            {/* Zone 1 */}
            <div className="p-5 space-y-3">
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>Entity Resolution</p>
              <div className="space-y-3">
                {entityRows.map(row => (
                  <div key={row.num} className="flex items-start gap-2">
                    <span className="evidence-num mt-0.5">{row.num}</span>
                    <div>
                      <p className="font-mono text-[10px] uppercase tracking-wider" style={{ color: 'var(--tw-text-muted)' }}>{row.label}</p>
                      <p className="font-mono text-xs" style={{ color: row.flag ? 'var(--tw-burgundy)' : 'var(--tw-text)' }}>{row.val}</p>
                      {row.flag && <p className="text-[10px] mt-0.5" style={{ color: 'var(--tw-medium)' }}>⚠ Cryptographic identity — strong correlation indicator</p>}
                    </div>
                  </div>
                ))}
              </div>
              <div className="mt-3 p-3 rounded-sm border-l-2" style={{ borderLeftColor: 'var(--tw-burgundy)', backgroundColor: 'var(--tw-panel)' }}>
                <p className="text-xs leading-relaxed" style={{ color: 'var(--tw-text)' }}>
                  {snapshot.link
                    ? snapshot.link.explanation
                    : 'No relationship is stored for this actor yet. Record intelligence to build one.'}
                </p>
                {snapshot.link && (
                  <p className="text-[10px] mt-1.5 font-mono" style={{ color: 'var(--tw-burgundy)' }}>
                    ↳ {snapshot.link.type.replace(/_/g, ' ').toLowerCase()} · {snapshot.link.id}
                  </p>
                )}
              </div>
            </div>

            {/* Zone 2 */}
            <div className="p-5 space-y-3">
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>Intelligence Indicators</p>
              {[
                { label: 'Actor confidence',   value: actor?.confidenceScore ?? 0 },
                { label: 'Link confidence',    value: snapshot.link?.confidence ?? 0 },
                { label: 'Source reliability', value: evidenceReliability },
                { label: 'Identity overlap',   value: snapshot.why?.confidence ?? 0 },
              ].map(item => (
                <div key={item.label} className="py-2 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <div className="flex items-center justify-between">
                    <p className="font-mono text-xs" style={{ color: 'var(--tw-text)' }}>{item.label}</p>
                    <span className="font-mono text-[10px] tracking-wider" style={{ color: 'var(--tw-text-muted)' }}>{item.value}%</span>
                  </div>
                  <div className="confidence-bar mt-1.5"><div className="confidence-fill" style={{ width: `${Math.max(0, Math.min(100, item.value))}%` }} /></div>
                </div>
              ))}
              <div className="pt-1 space-y-1">
                <p className="font-mono text-[10px] tracking-[0.15em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>Collected From</p>
                <p className="font-mono text-xs" style={{ color: 'var(--tw-text)' }}>{source ?? '—'}</p>
                <p className="text-[10px]" style={{ color: 'var(--tw-text-muted)' }}>
                  {darkWebSources.length} registered source{darkWebSources.length === 1 ? '' : 's'} · {metrics.observations} observation{metrics.observations === 1 ? '' : 's'}
                </p>
              </div>
            </div>

            {/* Zone 3 */}
            <div className="p-5 space-y-3">
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>Actor Timeline</p>
              <div className="space-y-0">
                {snapshot.timeline.slice(0, 4).map((event, i, list) => (
                  <div key={event.id} className="flex gap-3">
                    <div className="flex flex-col items-center">
                      <div className="w-5 h-5 rounded-sm flex items-center justify-center text-[9px] font-mono font-medium text-[#FBFAF6] shrink-0"
                        style={{ backgroundColor: 'var(--tw-low)' }}
                      >
                        {i + 1}
                      </div>
                      {i < list.length - 1 && <div className="w-px h-5" style={{ backgroundColor: 'var(--tw-border-strong)' }} />}
                    </div>
                    <div className="pb-3">
                      <p className="font-mono text-xs" style={{ color: 'var(--tw-text)' }}>{event.title}</p>
                      <p className="font-mono text-[10px]" style={{ color: 'var(--tw-text-muted)' }}>
                        {event.type.replace(/_/g, ' ').toLowerCase()} · {event.time.slice(0, 10)} · {event.confidence}%
                      </p>
                    </div>
                  </div>
                ))}
                {!snapshot.timeline.length && (
                  <p className="font-mono text-[10px]" style={{ color: 'var(--tw-text-muted)' }}>No timeline events recorded for this actor.</p>
                )}
              </div>
              <div className="mt-2 pt-2 border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
                <span className="font-mono text-[10px] -rotate-1 inline-block px-3 py-1 border-2 tracking-widest uppercase rounded-sm"
                  style={{ borderColor: 'var(--tw-critical)', color: 'var(--tw-critical)' }}
                >
                  {actor?.status ?? 'Unknown'}
                </span>
                <span className="font-mono text-[10px] ml-2" style={{ color: 'var(--tw-text-muted)' }}>
                  {snapshot.bundle?.relationships.length ?? 0} relationships · {snapshot.bundle?.evidence.length ?? 0} evidence items
                </span>
              </div>
            </div>
          </div>
        </motion.div>
      </section>

      {/* ── From Signal to Investigation ──────────────────── */}
      <section className="border-y" style={{ borderColor: 'var(--tw-border)', backgroundColor: 'var(--tw-canvas-mid)' }}>
        <div className="max-w-7xl mx-auto px-6 lg:px-10 py-16">
          <p className="font-mono text-[10px] tracking-[0.2em] uppercase mb-10" style={{ color: 'var(--tw-text-muted)' }}>From signal to investigation</p>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-6">
            {steps.map((step, i) => (
              <motion.div key={step.num} initial={{ opacity: 0, y: 16 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.08 }} className="space-y-2">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10px] font-medium" style={{ color: 'var(--tw-burgundy)' }}>{step.num}</span>
                  <div className="h-px flex-1" style={{ backgroundColor: 'var(--tw-border-strong)' }} />
                </div>
                <p className="font-serif text-lg" style={{ color: 'var(--tw-text)' }}>{step.label}</p>
                <p className="text-xs leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>{step.desc}</p>
              </motion.div>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-2 mt-12 pt-8 border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
            {pipeline.map((stage, i) => (
              <span key={stage} className="flex items-center gap-2">
                <span className="font-mono text-[10px] tracking-[0.15em] uppercase"
                  style={{ color: i === 0 ? 'var(--tw-burgundy)' : 'var(--tw-text-muted)' }}
                >
                  {stage}
                </span>
                {i < pipeline.length - 1 && <span className="font-mono text-[10px]" style={{ color: 'var(--tw-border-strong)' }}>↓</span>}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* ── Capabilities ──────────────────────────────────── */}
      <section className="max-w-7xl mx-auto px-6 lg:px-10 py-20">
        <div className="mb-12">
          <p className="font-mono text-[10px] tracking-[0.2em] uppercase mb-3" style={{ color: 'var(--tw-text-muted)' }}>Capabilities</p>
          <h2 className="font-serif text-4xl" style={{ color: 'var(--tw-text)' }}>Connected intelligence,<br />not disconnected alerts.</h2>
        </div>
        <div className="grid md:grid-cols-2 lg:grid-cols-3 border" style={{ borderColor: 'var(--tw-border)' }}>
          {features.map((f, i) => {
            const Icon = f.icon;
            return (
              <motion.div key={f.title} initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} viewport={{ once: true }} transition={{ delay: i * 0.06 }}
                className="p-7 space-y-3 border-b border-r transition-colors"
                style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)' }}
                onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'var(--tw-panel-alt)')}
                onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'var(--tw-panel)')}
              >
                <div className="w-8 h-8 border rounded-sm flex items-center justify-center" style={{ borderColor: 'var(--tw-border-strong)' }}>
                  <Icon size={16} style={{ color: 'var(--tw-burgundy)' }} />
                </div>
                <h3 className="font-serif text-xl" style={{ color: 'var(--tw-text)' }}>{f.title}</h3>
                <p className="text-sm leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>{f.description}</p>
              </motion.div>
            );
          })}
        </div>
      </section>

      {/* ── Dark Web Intelligence Ecosystem ───────────────── */}
      <section style={{ backgroundColor: 'var(--tw-canvas)', borderTop: '1px solid var(--tw-border)', borderBottom: '1px solid var(--tw-border)' }}>
        <div className="max-w-7xl mx-auto px-6 lg:px-10 py-20">
          <div className="grid lg:grid-cols-2 gap-12 items-center">
            <div className="space-y-5">
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-brass)' }}>Dark Web Intelligence</p>
              <h2 className="font-serif text-4xl leading-tight" style={{ color: 'var(--tw-text)' }}>
                One model, resolved from<br />actor to evidence.
              </h2>
              <p className="text-sm leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>
                Every collection, correlation and evidence item is written to the same central model, so a
                handle, a PGP fingerprint, a wallet and a hosting address all resolve into one investigation
                instead of separate findings. Counts below are the live records held by the platform.
              </p>
              <div className="rounded-sm p-4 border" style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)' }}>
                {chain.map((row, i) => (
                  <div key={row.key} className="flex items-center gap-3"
                    style={{ borderTop: i === 0 ? 'none' : '1px solid var(--tw-border-mid)', paddingTop: i === 0 ? 0 : 8, paddingBottom: 8 }}
                  >
                    <div className="w-1.5 h-1.5 rounded-full shrink-0" style={{ backgroundColor: 'var(--tw-burgundy)' }} />
                    <div className="min-w-0">
                      <p className="font-mono text-[10px] tracking-[0.15em] uppercase" style={{ color: 'var(--tw-text)' }}>{row.label}</p>
                      <p className="text-[10px] leading-snug" style={{ color: 'var(--tw-text-faint)' }}>{row.detail}</p>
                    </div>
                    <span className="ml-auto font-mono text-sm" style={{ color: 'var(--tw-brass)' }}>{chainCounts[row.key]}</span>
                  </div>
                ))}
              </div>
              <Link to="/app/darkweb"
                className="inline-flex items-center gap-2 font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                style={{ borderColor: 'color-mix(in srgb, var(--tw-brass) 50%, transparent)', color: 'var(--tw-brass)' }}
              >
                Open Dark Web Intelligence <ArrowRight size={12} />
              </Link>
            </div>

            {/* Threat actor profile */}
            <div className="rounded-sm p-5 space-y-4 border" style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)' }}>
              <div className="flex items-center justify-between">
                <span className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>Threat Actor Profile</span>
                <span className="demo-badge">Simulated Demo Data</span>
              </div>
              <div className="flex items-baseline gap-3">
                <span className="font-mono text-2xl" style={{ color: 'var(--tw-text)' }}>{actor?.id ?? '—'}</span>
                <span className="font-mono text-[10px] tracking-widest uppercase px-2 py-0.5 rounded-sm border"
                  style={{ color: actor?.status === 'ACTIVE' ? 'var(--tw-critical)' : 'var(--tw-text-muted)', borderColor: 'var(--tw-border-strong)' }}
                >
                  {actor?.status ?? 'Unknown'}
                </span>
              </div>
              <div className="border-t pt-4 space-y-3" style={{ borderColor: 'var(--tw-border-mid)' }}>
                {[
                  { label: 'Aliases',       val: actor?.aliases.slice(0, 2).join(', ') || '—' },
                  { label: 'Known Handles',val: handleValues.slice(0, 3).join(', ') || '—' },
                  { label: 'Platforms',    val: (actor?.platforms ?? []).slice(0, 2).join(', ') || '—' },
                  { label: 'PGP',          val: pgp ? shortFingerprint(pgp) : '—' },
                  { label: 'Wallet',       val: wallet ? `${wallet.slice(0, 12)}…` : '—' },
                  { label: 'Infrastructure', val: infra || '—' },
                  { label: 'Relationships', val: String(snapshot.bundle?.relationships.length ?? 0) },
                  { label: 'Evidence',     val: String(snapshot.bundle?.evidence.length ?? 0) },
                ].map(row => (
                  <div key={row.label} className="flex items-start justify-between gap-4">
                    <span className="font-mono text-[10px] uppercase tracking-wider shrink-0" style={{ color: 'var(--tw-text-muted)' }}>{row.label}</span>
                    <span className="font-mono text-xs text-right" style={{ color: 'var(--tw-text)' }}>{row.val}</span>
                  </div>
                ))}
              </div>
              <div className="border-t pt-3 space-y-1" style={{ borderColor: 'var(--tw-border-mid)' }}>
                <div className="flex items-center justify-between">
                  <p className="font-mono text-[10px] tracking-wider uppercase" style={{ color: 'var(--tw-text-muted)' }}>Confidence</p>
                  <p className="font-mono text-xs" style={{ color: 'var(--tw-text)' }}>{actor?.confidenceScore ?? 0}%</p>
                </div>
                <div className="confidence-bar mt-1.5"><div className="confidence-fill" style={{ width: `${actor?.confidenceScore ?? 0}%` }} /></div>
                <p className="text-[10px] mt-1" style={{ color: 'var(--tw-text-muted)' }}>Graded on collected evidence — not a claim of real-world identity.</p>
              </div>
              <Link to={actor ? `/app/darkweb/actors/${actor.id}` : '/app/darkweb/actors'}
                className="font-mono text-[10px] uppercase tracking-widest border px-3 py-1 rounded-sm inline-block"
                style={{ borderColor: 'color-mix(in srgb, var(--tw-medium) 50%, transparent)', color: 'var(--tw-medium)' }}
              >
                Open Actor Profile
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* ── Relationship Canvas + AI Insight ──────────────── */}
      <section className="max-w-7xl mx-auto px-6 lg:px-10 py-20">
        <div className="grid lg:grid-cols-2 gap-12 items-center">
          {/* 3D/2D Relationship Canvas */}
          <div className="rounded-sm p-6 h-72 relative overflow-hidden border" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border)' }}>
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase mb-4" style={{ color: 'var(--tw-text-muted)' }}>Relationship Canvas</p>
            <ThreeDErrorBoundary fallback={<ActorCanvasDiagram />}>
              <Suspense fallback={<ActorCanvasDiagram />}>
                <ThreatNetwork3D />
              </Suspense>
            </ThreeDErrorBoundary>
            <span className="demo-badge absolute bottom-3 right-3">Simulated Demo Data</span>
          </div>

          <div className="space-y-5">
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>AI Investigation Insight</p>
            <h2 className="font-serif text-4xl leading-tight" style={{ color: 'var(--tw-text)' }}>AI that shows its reasoning,<br />beside the evidence.</h2>
            <p className="text-sm leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>
              Every correlation carries an explanation built from stored records. Viper Trace shows the
              supporting indicators, the counter-indicators, and the limits of the claim — it never presents
              a weak indicator as a confirmed real-world identity.
            </p>
            <div className="rounded-sm p-4 space-y-2 border" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border)' }}>
              <p className="font-mono text-[10px] tracking-[0.15em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>
                Assessment {snapshot.link ? `· ${snapshot.link.sourceEntity} → ${snapshot.link.targetEntity}` : ''}
              </p>
              <p className="text-sm font-medium" style={{ color: 'var(--tw-text)' }}>
                {snapshot.why?.exists
                  ? 'Possible relationship between these two records.'
                  : 'No relationship is stored between these records yet.'}
              </p>
              <div className="space-y-1 pt-1">
                {(snapshot.why?.indicators.length ? snapshot.why.indicators : ['No shared indicator recorded'])
                  .map(indicator => (
                    <div key={indicator} className="flex items-start gap-2">
                      <div className="w-1 h-1 rounded-full mt-1.5 shrink-0" style={{ backgroundColor: 'var(--tw-burgundy)' }} />
                      <p className="text-xs" style={{ color: 'var(--tw-text-muted)' }}>{indicator}</p>
                    </div>
                  ))}
              </div>
              {!!snapshot.why?.against.length && (
                <div className="space-y-1 pt-1">
                  <p className="font-mono text-[10px] tracking-[0.15em] uppercase" style={{ color: 'var(--tw-text-faint)' }}>Counter-indicators</p>
                  {snapshot.why.against.map(item => (
                    <div key={item} className="flex items-start gap-2">
                      <div className="w-1 h-1 rounded-full mt-1.5 shrink-0" style={{ backgroundColor: 'var(--tw-dust)' }} />
                      <p className="text-xs" style={{ color: 'var(--tw-text-faint)' }}>{item}</p>
                    </div>
                  ))}
                </div>
              )}
              <p className="font-mono text-[10px] pt-1" style={{ color: 'var(--tw-medium)' }}>
                Confidence: {snapshot.why?.confidence ?? 0}% · Correlation indicates association in the collected
                data, not confirmed real-world attribution.
              </p>
              <p className="font-mono text-[10px] tracking-[0.15em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>Why Linked?</p>
              <p className="text-xs" style={{ color: 'var(--tw-text-faint)' }}>
                {snapshot.why?.computedFrom.length
                  ? `Computed from ${snapshot.why.computedFrom.join(', ')}.`
                  : 'Computed from stored records only.'}
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ── Evidence Locker + Timeline ───────────────────── */}
      <section className="border-y" style={{ borderColor: 'var(--tw-border)', backgroundColor: 'var(--tw-canvas-mid)' }}>
        <div className="max-w-7xl mx-auto px-6 lg:px-10 py-20">
          <div className="mb-12">
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase mb-3" style={{ color: 'var(--tw-text-muted)' }}>Evidence &amp; Timeline</p>
            <h2 className="font-serif text-4xl" style={{ color: 'var(--tw-text)' }}>Provenance, from source<br />to investigation.</h2>
          </div>
          <div className="grid lg:grid-cols-2 gap-12">
            {/* Evidence chain */}
            <div className="rounded-sm p-5 space-y-4 border" style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)' }}>
              <div className="flex items-center justify-between">
                <span className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>Evidence Locker</span>
                <span className="demo-badge">Simulated Demo Data</span>
              </div>
              <div className="space-y-3">
                {snapshot.chainSteps.map(step => (
                  <div key={step.step} className="flex items-start gap-2">
                    <span className="evidence-num mt-0.5">{String(step.step).padStart(2, '0')}</span>
                    <div className="min-w-0">
                      <p className="font-mono text-[10px] uppercase tracking-wider" style={{ color: 'var(--tw-text-muted)' }}>{step.label}</p>
                      <p className="font-mono text-xs" style={{ color: 'var(--tw-text)' }}>{step.record}</p>
                      <p className="text-[10px] leading-snug" style={{ color: 'var(--tw-text-faint)' }}>{step.detail}</p>
                    </div>
                  </div>
                ))}
                {!snapshot.chainSteps.length && (
                  <p className="font-mono text-[10px]" style={{ color: 'var(--tw-text-muted)' }}>No evidence record is held in the central model.</p>
                )}
              </div>
              <Link to="/app/darkweb/evidence"
                className="font-mono text-[10px] uppercase tracking-widest border px-3 py-1 rounded-sm inline-block"
                style={{ borderColor: 'color-mix(in srgb, var(--tw-medium) 50%, transparent)', color: 'var(--tw-medium)' }}
              >
                Open Evidence Locker
              </Link>
            </div>

            {/* Timeline */}
            <div className="rounded-sm p-5 space-y-4 border" style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)' }}>
              <div className="flex items-center justify-between">
                <span className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>Timeline Intelligence</span>
                <span className="font-mono text-[10px]" style={{ color: 'var(--tw-text-faint)' }}>
                  {metrics.relationships} relationships · {metrics.evidence} evidence
                </span>
              </div>
              <div className="space-y-0">
                {snapshot.timeline.slice(0, 6).map((event, i, list) => (
                  <div key={event.id} className="flex gap-3">
                    <div className="flex flex-col items-center">
                      <div className="w-5 h-5 rounded-sm flex items-center justify-center text-[9px] font-mono font-medium text-[#FBFAF6] shrink-0"
                        style={{ backgroundColor: 'var(--tw-low)' }}
                      >
                        {i + 1}
                      </div>
                      {i < list.length - 1 && <div className="w-px flex-1 min-h-4" style={{ backgroundColor: 'var(--tw-border-strong)' }} />}
                    </div>
                    <div className="pb-3">
                      <p className="font-mono text-xs" style={{ color: 'var(--tw-text)' }}>{event.title}</p>
                      <p className="text-[10px] leading-snug" style={{ color: 'var(--tw-text-muted)' }}>{event.description}</p>
                      <p className="font-mono text-[10px]" style={{ color: 'var(--tw-text-faint)' }}>
                        {event.time.slice(0, 10)} · {event.type.replace(/_/g, ' ').toLowerCase()} · {event.confidence}%
                      </p>
                    </div>
                  </div>
                ))}
                {!snapshot.timeline.length && (
                  <p className="font-mono text-[10px]" style={{ color: 'var(--tw-text-muted)' }}>No timeline events recorded for this actor.</p>
                )}
              </div>
              <Link to="/app/darkweb/timeline"
                className="font-mono text-[10px] uppercase tracking-widest border px-3 py-1 rounded-sm inline-block"
                style={{ borderColor: 'color-mix(in srgb, var(--tw-medium) 50%, transparent)', color: 'var(--tw-medium)' }}
              >
                Open Full Timeline
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* ── Continuous Intelligence / Alerts ──────────────── */}
      <section className="max-w-7xl mx-auto px-6 lg:px-10 py-20">
        <div className="grid lg:grid-cols-2 gap-12 items-center">
          <div className="space-y-5">
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-brass)' }}>Continuous Intelligence</p>
            <h2 className="font-serif text-4xl leading-tight" style={{ color: 'var(--tw-text)' }}>
              New identities, indicators and<br />persona shifts, as they are collected.
            </h2>
            <p className="text-sm leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>
              Collection is part of the intelligence model, not a separate product. Each new handle, indicator
              or correlation raises an alert that names the actor, the supporting records and the confidence
              behind it, and every alert carries the evidence that produced it.
            </p>
            <div className="flex flex-wrap gap-3">
              <Link to="/app/darkweb/alerts"
                className="inline-flex items-center gap-2 font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                style={{ borderColor: 'color-mix(in srgb, var(--tw-brass) 50%, transparent)', color: 'var(--tw-brass)' }}
              >
                Monitoring &amp; Alerts <ArrowRight size={12} />
              </Link>
              <Link to="/app/darkweb/exposure"
                className="inline-flex items-center gap-2 font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text)' }}
              >
                Exposure Ledger
              </Link>
            </div>
          </div>

          <div className="space-y-3">
            {snapshot.alerts.map(alert => (
              <div key={alert.id} className="rounded-sm p-4 space-y-2 border" style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)' }}>
                <div className="flex items-center gap-3">
                  <span className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>Dark Web Intelligence Alert</span>
                  <span className="font-mono text-[10px] px-2 py-0.5 rounded-sm border tracking-widest uppercase ml-auto"
                    style={{ color: SEVERITY_COLOR[alert.severity] ?? 'var(--tw-text-muted)', borderColor: 'var(--tw-border-strong)' }}
                  >
                    {alert.severity}
                  </span>
                </div>
                <p className="text-sm font-medium" style={{ color: 'var(--tw-text)' }}>{alert.title}</p>
                <p className="text-xs leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>{alert.reason}</p>
                <p className="font-mono text-[10px]" style={{ color: 'var(--tw-text-faint)' }}>
                  {alert.actorId ? `Associated with ${alert.actorId}` : 'Not attributed to an actor'} · Confidence {alert.confidence}% · {alert.status.toLowerCase()}
                </p>
              </div>
            ))}
            {!snapshot.alerts.length && (
              <div className="rounded-sm p-4 border" style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)' }}>
                <p className="font-mono text-[10px]" style={{ color: 'var(--tw-text-muted)' }}>No alerts are open in the central model.</p>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* ── Supporting Analysis Tools ─────────────────────── */}
      <section className="border-y" style={{ borderColor: 'var(--tw-border)', backgroundColor: 'var(--tw-canvas)' }}>
        <div className="max-w-7xl mx-auto px-6 lg:px-10 py-16">
          <div className="mb-10">
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase mb-3" style={{ color: 'var(--tw-text-muted)' }}>Supporting Analysis Tools</p>
            <h2 className="font-serif text-3xl" style={{ color: 'var(--tw-text)' }}>
              Additional forensic and analytical capabilities that support<br />broader threat investigations.
            </h2>
          </div>
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 border" style={{ borderColor: 'var(--tw-border)' }}>
            {supportingTools.map(tool => {
              const Icon = tool.icon;
              return (
                <Link key={tool.title} to={tool.to}
                  className="p-6 space-y-2 border-b border-r transition-colors"
                  style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)' }}
                  onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'var(--tw-panel-alt)')}
                  onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'var(--tw-panel)')}
                >
                  <div className="w-8 h-8 border rounded-sm flex items-center justify-center" style={{ borderColor: 'var(--tw-border-strong)' }}>
                    <Icon size={16} style={{ color: 'var(--tw-text-muted)' }} />
                  </div>
                  <h3 className="font-serif text-lg" style={{ color: 'var(--tw-text)' }}>{tool.title}</h3>
                  <p className="text-xs leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>{tool.description}</p>
                </Link>
              );
            })}
          </div>
        </div>
      </section>

      {/* ── Privacy and Compliance ────────────────────────── */}
      <section className="border-b" style={{ borderColor: 'var(--tw-border)', backgroundColor: 'var(--tw-canvas-mid)' }}>
        <div className="max-w-7xl mx-auto px-6 lg:px-10 py-14">
          <div className="grid md:grid-cols-4 gap-8">
            {[
              { label: 'Privacy by Design',   desc: 'Data minimisation, configurable retention, and identity masking built in from the start.' },
              { label: 'Evidence Integrity',  desc: 'Original evidence is immutable. Every access is logged. Chain-of-custody records are tamper-evident.' },
              { label: 'Role-Based Access',   desc: 'Admin, Analyst, Investigator, Viewer, and Auditor roles with fine-grained permission controls.' },
              { label: 'Authorised Use Only', desc: 'Collection restricted to verified organisational assets. Individual private persons are never tracked without authorisation.' },
            ].map(c => (
              <div key={c.label}>
                <p className="font-mono text-[10px] tracking-[0.2em] uppercase mb-2" style={{ color: 'var(--tw-text-muted)' }}>{c.label}</p>
                <p className="text-sm leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>{c.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA ───────────────────────────────────────────── */}
      <section className="max-w-7xl mx-auto px-6 lg:px-10 py-20 text-center">
        <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} className="space-y-5">
          <h2 className="font-serif text-5xl" style={{ color: 'var(--tw-text)' }}>Start a dark web investigation.</h2>
          <p className="text-lg max-w-xl mx-auto" style={{ color: 'var(--tw-text-muted)' }}>
            Explore threat actors, correlate identities, trace infrastructure, examine evidence and build an
            investigation from connected intelligence.
          </p>
          <div className="flex flex-wrap justify-center gap-3 pt-2">
            <Link to={HOME_PATH} className="font-mono text-xs tracking-widest uppercase px-6 py-3 rounded-sm"
              style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
            >
              Start Investigation
            </Link>
            <Link to="/app/darkweb/demo" className="font-mono text-xs tracking-widest uppercase px-6 py-3 rounded-sm border"
              style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text)' }}
            >
              View Demo Investigation
            </Link>
          </div>
        </motion.div>
      </section>

      {/* ── Footer ────────────────────────────────────────── */}
      <footer className="border-t" style={{ borderColor: 'var(--tw-border)', backgroundColor: 'var(--tw-canvas-mid)' }}>
        <div className="max-w-7xl mx-auto px-6 lg:px-10 py-10">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 rounded-sm flex items-center justify-center" style={{ backgroundColor: 'var(--tw-burgundy)' }}>
                <Shield size={12} style={{ color: '#FBFAF6' }} />
              </div>
              <span className="font-mono text-sm tracking-[0.14em] uppercase" style={{ color: 'var(--tw-text)' }}>Viper Trace</span>
              <span className="font-sans text-xs ml-2" style={{ color: 'var(--tw-text-muted)' }}>Evidence Before Assumption.</span>
            </div>
            <div className="flex items-center gap-6">
              {[
                { label: 'Privacy Policy', to: '/privacy-policy' },
                { label: 'Terms of Use', to: '/terms-of-use' },
                { label: 'Documentation', to: '/documentation' },
                { label: 'Authorised Use Policy', to: '/authorised-use-policy' },
              ].map(item => (
                <Link key={item.label} to={item.to} className="font-sans text-xs" style={{ color: 'var(--tw-text-muted)' }}>{item.label}</Link>
              ))}
            </div>
          </div>
          <div className="mt-8 pt-6 border-t flex flex-col md:flex-row justify-between gap-2" style={{ borderColor: 'var(--tw-border-mid)' }}>
            <p className="font-mono text-[10px]" style={{ color: 'var(--tw-text-faint)' }}>
              VIPER TRACE is a Dark Web Threat Intelligence &amp; Investigation platform for authorized cybersecurity research and defensive intelligence.
            </p>
            <div className="flex items-center gap-2">
              <BookOpen size={11} style={{ color: 'var(--tw-text-faint)' }} />
              <p className="font-mono text-[10px]" style={{ color: 'var(--tw-text-faint)' }}>All demonstration data is simulated and fictional.</p>
            </div>
          </div>
        </div>
      </footer>

    </div>
  );
}










