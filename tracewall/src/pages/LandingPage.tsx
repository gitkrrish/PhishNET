import { Link } from 'react-router-dom';
import { Shield, ArrowRight, FileText, Network, Globe, Eye, BarChart3, BookOpen, Sun, Moon } from 'lucide-react';
import { motion } from 'framer-motion';
import { useTheme } from '../context/ThemeContext';
import { lazy, Suspense } from 'react';
import { ThreeDErrorBoundary } from '../components/3d/ThreeDErrorBoundary';

// Lazy load the 3D component
const ThreatNetwork3D = lazy(() => import('../components/3d/ThreatNetwork3D').then(m => ({ default: m.default })));

const features = [
  { icon: FileText,  title: 'Header Forensics',        description: 'Reconstruct the complete email relay path. Verify each hop, detect timing anomalies, and distinguish reliable technical evidence from sender-controlled fields.' },
  { icon: Shield,    title: 'Authentication Analysis',  description: 'Evaluate SPF, DKIM, and DMARC results with plain-language explanations. Understand what each check means — and what it cannot prove.' },
  { icon: Network,   title: 'Relationship Canvas',      description: 'Map connections between sender domains, IP addresses, URLs, campaigns, and exposure events in an interactive evidence graph.' },
  { icon: Globe,     title: 'Infrastructure Assessment',description: 'Estimate probable source infrastructure with honest confidence levels. Acknowledge VPNs, proxies, cloud relays, and the limits of geolocation.' },
  { icon: Eye,       title: 'Exposure Ledger',          description: 'Monitor authorised organisational assets for credential exposure indicators. Privacy-preserving matching — plaintext secrets are never stored or displayed.' },
  { icon: BarChart3, title: 'Forensic Dossier',         description: 'Generate a numbered, evidenced investigation report that clearly separates observed fact, correlated evidence, AI assessment, and analyst conclusion.' },
];

const steps = [
  { num: '01', label: 'Capture',   desc: 'Upload a raw email, paste headers, or select a forensic sample.' },
  { num: '02', label: 'Verify',    desc: 'Validate sender identity signals — SPF, DKIM, DMARC, and relay path.' },
  { num: '03', label: 'Trace',     desc: 'Follow the infrastructure trail from relay to estimated origin.' },
  { num: '04', label: 'Correlate', desc: 'Connect indicators to campaigns, exposures, and historical cases.' },
  { num: '05', label: 'Contain',   desc: 'Execute approved defensive actions with full audit records.' },
];

const fade = { hidden: { opacity: 0, y: 20 }, show: { opacity: 1, y: 0 } };

export default function LandingPage() {
  const { isDark, toggleTheme } = useTheme();

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
            <span className="font-mono text-sm font-medium tracking-[0.14em] uppercase" style={{ color: 'var(--tw-text)' }}>PhishNet</span>
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
              Forensic Intelligence Workspace
            </span>
          </motion.div>
          <motion.h1 variants={fade} className="font-serif text-5xl lg:text-6xl leading-tight mb-6" style={{ color: 'var(--tw-text)' }}>
            Every suspicious email<br />
            <em style={{ color: 'var(--tw-burgundy)' }}>leaves a trail.</em>
          </motion.h1>
          <motion.p variants={fade} className="font-sans text-lg leading-relaxed max-w-2xl mb-8" style={{ color: 'var(--tw-text-muted)' }}>
            Trace the evidence, connect the infrastructure, and respond before a single message becomes a
            larger incident. Built for analysts who follow evidence — not assumptions.
          </motion.p>
          <motion.div variants={fade} className="flex flex-wrap gap-3">
            <Link to="/app/investigate"
              className="flex items-center gap-2 font-mono text-xs tracking-widest uppercase px-5 py-3 rounded-sm"
              style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
            >
              Start Investigating <ArrowRight size={14} />
            </Link>
            <Link to="/app/briefing"
              className="flex items-center gap-2 font-mono text-xs tracking-widest uppercase px-5 py-3 rounded-sm border"
              style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text)' }}
            >
              Open Daily Briefing
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
            <span className="demo-badge ml-auto">Simulated Demo Data</span>
          </div>

          <div className="grid lg:grid-cols-3 divide-y lg:divide-y-0 lg:divide-x" style={{ borderColor: 'var(--tw-border-mid)' }}>
            {/* Zone 1 */}
            <div className="p-5 space-y-3">
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>Forensic Document</p>
              <div className="space-y-3">
                {[
                  { num: '01', label: 'Subject', val: 'URGENT: Updated Banking Details for Invoice #INV-5591', flag: false },
                  { num: '02', label: 'From', val: 'finance@secureops-finance.in', flag: false },
                  { num: '03', label: 'Reply-To', val: 'payments@secure-ops-pay.net', flag: true },
                ].map(row => (
                  <div key={row.num} className="flex items-start gap-2">
                    <span className="evidence-num mt-0.5">{row.num}</span>
                    <div>
                      <p className="font-mono text-[10px] uppercase tracking-wider" style={{ color: 'var(--tw-text-muted)' }}>{row.label}</p>
                      <p className="font-mono text-xs" style={{ color: row.flag ? 'var(--tw-burgundy)' : 'var(--tw-text)' }}>{row.val}</p>
                      {row.flag && <p className="text-[10px] mt-0.5" style={{ color: 'var(--tw-medium)' }}>⚠ Mismatch with envelope sender</p>}
                    </div>
                  </div>
                ))}
              </div>
              <div className="mt-3 p-3 rounded-sm border-l-2" style={{ borderLeftColor: 'var(--tw-burgundy)', backgroundColor: 'var(--tw-panel)' }}>
                <p className="text-xs leading-relaxed" style={{ color: 'var(--tw-text)' }}>
                  "Please <span className="annotation-underline">do not discuss this with anyone</span> outside the finance team."
                </p>
                <p className="text-[10px] mt-1.5 font-mono" style={{ color: 'var(--tw-burgundy)' }}>↳ Secrecy request — BEC pattern</p>
              </div>
            </div>

            {/* Zone 2 */}
            <div className="p-5 space-y-3">
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>Technical Evidence</p>
              {[
                { label: 'SPF',   result: 'FAIL', detail: 'Not authorised by claimed domain' },
                { label: 'DKIM',  result: 'NONE', detail: 'No signature present' },
                { label: 'DMARC', result: 'FAIL', detail: 'Policy: quarantine — unmet' },
              ].map(item => (
                <div key={item.label} className="flex items-center justify-between py-2 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <div>
                    <p className="font-mono text-xs" style={{ color: 'var(--tw-text)' }}>{item.label}</p>
                    <p className="text-[10px]" style={{ color: 'var(--tw-text-muted)' }}>{item.detail}</p>
                  </div>
                  <span className="font-mono text-[10px] tracking-wider px-2 py-0.5 rounded-sm border"
                    style={{
                      color: item.result === 'FAIL' ? 'var(--tw-critical)' : 'var(--tw-text-muted)',
                      borderColor: item.result === 'FAIL' ? 'color-mix(in srgb, var(--tw-critical) 40%, transparent)' : 'var(--tw-border)',
                      backgroundColor: item.result === 'FAIL' ? 'color-mix(in srgb, var(--tw-critical) 18%, transparent)' : 'var(--tw-panel-alt)',
                    }}
                  >
                    {item.result}
                  </span>
                </div>
              ))}
              <div className="pt-1 space-y-1">
                <p className="font-mono text-[10px] tracking-[0.15em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>Domain Age</p>
                <div className="flex items-center gap-2">
                  <div className="confidence-bar flex-1"><div className="confidence-fill" style={{ width: '11%' }} /></div>
                  <span className="font-mono text-xs" style={{ color: 'var(--tw-critical)' }}>11 days</span>
                </div>
                <p className="text-[10px]" style={{ color: 'var(--tw-text-muted)' }}>Newly registered — high suspicion</p>
              </div>
            </div>

            {/* Zone 3 */}
            <div className="p-5 space-y-3">
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>Relay Timeline</p>
              <div className="space-y-0">
                {[
                  { hop: 1, host: 'mail.secureops-finance.in', country: 'DE', type: 'SENDER',    reliable: false },
                  { hop: 2, host: 'mailing-relay-eu4.net',     country: 'PL', type: 'RELAY',     reliable: true  },
                  { hop: 3, host: 'smtp-out.eu-mail-hub.com',  country: 'NL', type: 'RELAY',     reliable: null  },
                  { hop: 4, host: 'mx1.secureops.in',          country: 'IN', type: 'RECIPIENT', reliable: true  },
                ].map((hop, i) => (
                  <div key={i} className="flex gap-3">
                    <div className="flex flex-col items-center">
                      <div className="w-5 h-5 rounded-sm flex items-center justify-center text-[9px] font-mono font-medium text-[#FBFAF6] shrink-0"
                        style={{
                          backgroundColor: hop.reliable === false ? 'var(--tw-medium)' : hop.reliable === true ? 'var(--tw-low)' : 'var(--tw-dust)',
                        }}
                      >
                        {hop.hop}
                      </div>
                      {i < 3 && <div className="w-px h-5" style={{ backgroundColor: 'var(--tw-border-strong)' }} />}
                    </div>
                    <div className="pb-3">
                      <p className="font-mono text-xs" style={{ color: 'var(--tw-text)' }}>{hop.host}</p>
                      <p className="font-mono text-[10px]" style={{ color: 'var(--tw-text-muted)' }}>
                        {hop.country} · {hop.type}{hop.reliable === false && ' · sender-controlled'}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
              <div className="mt-2 pt-2 border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
                <span className="font-mono text-[10px] -rotate-1 inline-block px-3 py-1 border-2 tracking-widest uppercase rounded-sm"
                  style={{ borderColor: 'var(--tw-critical)', color: 'var(--tw-critical)' }}
                >
                  High Risk
                </span>
                <span className="font-mono text-[10px] ml-2" style={{ color: 'var(--tw-text-muted)' }}>Score: 87/100</span>
              </div>
            </div>
          </div>
        </motion.div>
      </section>

      {/* ── From Message to Evidence ──────────────────────── */}
      <section className="border-y" style={{ borderColor: 'var(--tw-border)', backgroundColor: 'var(--tw-canvas-mid)' }}>
        <div className="max-w-7xl mx-auto px-6 lg:px-10 py-16">
          <p className="font-mono text-[10px] tracking-[0.2em] uppercase mb-10" style={{ color: 'var(--tw-text-muted)' }}>From message to evidence</p>
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
        </div>
      </section>

      {/* ── Features ──────────────────────────────────────── */}
      <section className="max-w-7xl mx-auto px-6 lg:px-10 py-20">
        <div className="mb-12">
          <p className="font-mono text-[10px] tracking-[0.2em] uppercase mb-3" style={{ color: 'var(--tw-text-muted)' }}>Capabilities</p>
          <h2 className="font-serif text-4xl" style={{ color: 'var(--tw-text)' }}>An investigation toolkit,<br />not a dashboard.</h2>
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

      {/* ── Exposure Ledger Preview ───────────────────────── */}
      <section style={{ backgroundColor: 'var(--tw-canvas)', borderTop: '1px solid var(--tw-border)', borderBottom: '1px solid var(--tw-border)' }}>
        <div className="max-w-7xl mx-auto px-6 lg:px-10 py-20">
          <div className="grid lg:grid-cols-2 gap-12 items-center">
            <div className="space-y-5">
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-brass)' }}>Exposure Ledger</p>
              <h2 className="font-serif text-4xl leading-tight" style={{ color: 'var(--tw-text)' }}>
                Monitor credential exposure with<br />privacy-first precision.
              </h2>
              <p className="text-sm leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>
                PhishNet monitors authorised organisational assets for exposure indicators in intelligence feeds.
                Plaintext secrets are never stored, displayed, or purchased. Results use privacy-preserving matching.
              </p>
              <Link to="/app/exposure"
                className="inline-flex items-center gap-2 font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                style={{ borderColor: 'color-mix(in srgb, var(--tw-brass) 50%, transparent)', color: 'var(--tw-brass)' }}
              >
                Open Exposure Ledger <ArrowRight size={12} />
              </Link>
            </div>

            {/* Ledger card */}
            <div className="rounded-sm p-5 space-y-4 border" style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)' }}>
              <div className="flex items-center justify-between">
                <span className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>Exposure Record</span>
                <span className="demo-badge">Simulated Demo Data</span>
              </div>
              <div className="border-t pt-4 space-y-3" style={{ borderColor: 'var(--tw-border-mid)' }}>
                {[
                  { label: 'Record ID',     val: 'EXP-00481',                    redact: false },
                  { label: 'Identity',      val: 'a••••@secureops.in',           redact: false },
                  { label: 'Exposure Type', val: 'Credential-pair indicator',    redact: false },
                  { label: 'Secret',        val: 'REDACTED',                     redact: true  },
                  { label: 'Severity',      val: 'HIGH',                         redact: false, chip: true },
                ].map(row => (
                  <div key={row.label} className="flex items-start justify-between">
                    <span className="font-mono text-[10px] uppercase tracking-wider" style={{ color: 'var(--tw-text-muted)' }}>{row.label}</span>
                    {row.redact ? (
                      <span className="font-mono text-xs px-4 rounded-sm select-none" style={{ backgroundColor: 'var(--tw-text)', color: 'transparent' }}>
                        REDACTED
                      </span>
                    ) : row.chip ? (
                      <span className="font-mono text-[10px] px-2 py-0.5 rounded-sm border tracking-widest uppercase"
                        style={{ color: 'var(--tw-critical)', borderColor: 'color-mix(in srgb, var(--tw-critical) 40%, transparent)', backgroundColor: 'color-mix(in srgb, var(--tw-critical) 18%, transparent)' }}
                      >
                        {row.val}
                      </span>
                    ) : (
                      <span className="font-mono text-xs" style={{ color: 'var(--tw-text)' }}>{row.val}</span>
                    )}
                  </div>
                ))}
              </div>
              <div className="border-t pt-3 space-y-1" style={{ borderColor: 'var(--tw-border-mid)' }}>
                <p className="font-mono text-[10px] tracking-wider uppercase" style={{ color: 'var(--tw-text-muted)' }}>Recommended Response</p>
                {['Force password reset', 'Revoke active sessions', 'Review sign-in activity'].map(r => (
                  <div key={r} className="flex items-center gap-2 py-0.5">
                    <div className="w-1 h-1 rounded-full" style={{ backgroundColor: 'var(--tw-brass)' }} />
                    <span className="text-xs" style={{ color: 'var(--tw-text-muted)' }}>{r}</span>
                  </div>
                ))}
              </div>
              <span className="font-mono text-[10px] uppercase tracking-widest border px-3 py-1 rounded-sm inline-block"
                style={{ borderColor: 'color-mix(in srgb, var(--tw-medium) 50%, transparent)', color: 'var(--tw-medium)' }}
              >
                Awaiting Approval
              </span>
            </div>
          </div>
        </div>
      </section>

      {/* ── Intelligence Graph Preview ────────────────────── */}
      <section className="max-w-7xl mx-auto px-6 lg:px-10 py-20">
        <div className="grid lg:grid-cols-2 gap-12 items-center">
          {/* 3D/2D Relationship Canvas */}
          <div className="rounded-sm p-6 h-72 relative overflow-hidden border" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border)' }}>
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase mb-4" style={{ color: 'var(--tw-text-muted)' }}>Relationship Canvas</p>
            <ThreeDErrorBoundary fallback={
              <svg viewBox="0 0 400 200" className="w-full h-full">
                <line x1="200" y1="100" x2="80"  y2="50"  stroke="var(--tw-border-strong)" strokeWidth="1" strokeDasharray="4,3" />
                <line x1="200" y1="100" x2="320" y2="50"  stroke="var(--tw-border-strong)" strokeWidth="1" />
                <line x1="200" y1="100" x2="80"  y2="155" stroke="var(--tw-border-strong)" strokeWidth="1" />
                <line x1="200" y1="100" x2="320" y2="155" stroke="var(--tw-border-strong)" strokeWidth="1" strokeDasharray="4,3" />
                <line x1="80"  y1="50"  x2="30"  y2="100" stroke="var(--tw-border-strong)" strokeWidth="1" strokeDasharray="2,4" />
                <line x1="320" y1="50"  x2="370" y2="100" stroke="var(--tw-border-strong)" strokeWidth="1" />
                <rect x="168" y="84"  width="64" height="32" rx="2" fill="var(--tw-burgundy)" fillOpacity="0.22" stroke="var(--tw-burgundy)" strokeWidth="1.5" />
                <text x="200" y="104" textAnchor="middle" fill="var(--tw-burgundy)" fontSize="9" fontFamily="IBM Plex Mono">SENDER</text>
                <rect x="40"  y="34"  width="80" height="30" rx="2" fill="var(--tw-medium)" fillOpacity="0.18" stroke="var(--tw-medium)" strokeWidth="1" />
                <text x="80"  y="53"  textAnchor="middle" fill="var(--tw-medium)" fontSize="8" fontFamily="IBM Plex Mono">LOOKALIKE</text>
                <rect x="280" y="34"  width="80" height="30" rx="2" fill="var(--tw-medium)" fillOpacity="0.18" stroke="var(--tw-medium)" strokeWidth="1" />
                <text x="320" y="53"  textAnchor="middle" fill="var(--tw-medium)" fontSize="8" fontFamily="IBM Plex Mono">REPLY-TO</text>
                <rect x="40"  y="139" width="80" height="30" rx="2" fill="var(--tw-low)" fillOpacity="0.18" stroke="var(--tw-low)" strokeWidth="1" />
                <text x="80"  y="158" textAnchor="middle" fill="var(--tw-low)" fontSize="8" fontFamily="IBM Plex Mono">RELAY · DE</text>
                <rect x="280" y="139" width="80" height="30" rx="2" fill="var(--tw-dust)" fillOpacity="0.18" stroke="var(--tw-dust)" strokeWidth="1" />
                <text x="320" y="158" textAnchor="middle" fill="var(--tw-dust)" fontSize="8" fontFamily="IBM Plex Mono">RELAY · PL</text>
                <rect x="0"   y="84"  width="60" height="30" rx="2" fill="var(--tw-critical)" fillOpacity="0.18" stroke="var(--tw-critical)" strokeWidth="1" />
                <text x="30"  y="103" textAnchor="middle" fill="var(--tw-critical)" fontSize="7.5" fontFamily="IBM Plex Mono">CAMPAIGN</text>
                <rect x="340" y="84"  width="60" height="30" rx="2" fill="var(--tw-brass)" fillOpacity="0.22" stroke="var(--tw-brass)" strokeWidth="1" />
                <text x="370" y="103" textAnchor="middle" fill="var(--tw-brass)" fontSize="7.5" fontFamily="IBM Plex Mono">EXPOSURE</text>
              </svg>
            }>
              <Suspense fallback={
                <svg viewBox="0 0 400 200" className="w-full h-full">
                  <line x1="200" y1="100" x2="80"  y2="50"  stroke="var(--tw-border-strong)" strokeWidth="1" strokeDasharray="4,3" />
                  <line x1="200" y1="100" x2="320" y2="50"  stroke="var(--tw-border-strong)" strokeWidth="1" />
                  <line x1="200" y1="100" x2="80"  y2="155" stroke="var(--tw-border-strong)" strokeWidth="1" />
                  <line x1="200" y1="100" x2="320" y2="155" stroke="var(--tw-border-strong)" strokeWidth="1" strokeDasharray="4,3" />
                  <line x1="80"  y1="50"  x2="30"  y2="100" stroke="var(--tw-border-strong)" strokeWidth="1" strokeDasharray="2,4" />
                  <line x1="320" y1="50"  x2="370" y2="100" stroke="var(--tw-border-strong)" strokeWidth="1" />
                  <rect x="168" y="84"  width="64" height="32" rx="2" fill="var(--tw-burgundy)" fillOpacity="0.22" stroke="var(--tw-burgundy)" strokeWidth="1.5" />
                  <text x="200" y="104" textAnchor="middle" fill="var(--tw-burgundy)" fontSize="9" fontFamily="IBM Plex Mono">SENDER</text>
                  <rect x="40"  y="34"  width="80" height="30" rx="2" fill="var(--tw-medium)" fillOpacity="0.18" stroke="var(--tw-medium)" strokeWidth="1" />
                  <text x="80"  y="53"  textAnchor="middle" fill="var(--tw-medium)" fontSize="8" fontFamily="IBM Plex Mono">LOOKALIKE</text>
                  <rect x="280" y="34"  width="80" height="30" rx="2" fill="var(--tw-medium)" fillOpacity="0.18" stroke="var(--tw-medium)" strokeWidth="1" />
                  <text x="320" y="53"  textAnchor="middle" fill="var(--tw-medium)" fontSize="8" fontFamily="IBM Plex Mono">REPLY-TO</text>
                  <rect x="40"  y="139" width="80" height="30" rx="2" fill="var(--tw-low)" fillOpacity="0.18" stroke="var(--tw-low)" strokeWidth="1" />
                  <text x="80"  y="158" textAnchor="middle" fill="var(--tw-low)" fontSize="8" fontFamily="IBM Plex Mono">RELAY · DE</text>
                  <rect x="280" y="139" width="80" height="30" rx="2" fill="var(--tw-dust)" fillOpacity="0.18" stroke="var(--tw-dust)" strokeWidth="1" />
                  <text x="320" y="158" textAnchor="middle" fill="var(--tw-dust)" fontSize="8" fontFamily="IBM Plex Mono">RELAY · PL</text>
                  <rect x="0"   y="84"  width="60" height="30" rx="2" fill="var(--tw-critical)" fillOpacity="0.18" stroke="var(--tw-critical)" strokeWidth="1" />
                  <text x="30"  y="103" textAnchor="middle" fill="var(--tw-critical)" fontSize="7.5" fontFamily="IBM Plex Mono">CAMPAIGN</text>
                  <rect x="340" y="84"  width="60" height="30" rx="2" fill="var(--tw-brass)" fillOpacity="0.22" stroke="var(--tw-brass)" strokeWidth="1" />
                  <text x="370" y="103" textAnchor="middle" fill="var(--tw-brass)" fontSize="7.5" fontFamily="IBM Plex Mono">EXPOSURE</text>
                </svg>
              }>
                <ThreatNetwork3D />
              </Suspense>
            </ThreeDErrorBoundary>
            <span className="demo-badge absolute bottom-3 right-3">Simulated Demo Data</span>
          </div>

          <div className="space-y-5">
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>Inline Intelligence</p>
            <h2 className="font-serif text-4xl leading-tight" style={{ color: 'var(--tw-text)' }}>AI insights beside every piece of evidence.</h2>
            <p className="text-sm leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>
              PhishNet surfaces AI assessments directly alongside the technical evidence they explain. No chatbot.
              Every conclusion shows its reasoning, confidence, and limits.
            </p>
            <div className="rounded-sm p-4 space-y-2 border" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border)' }}>
              <p className="font-mono text-[10px] tracking-[0.15em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>Assessment</p>
              <p className="text-sm font-medium" style={{ color: 'var(--tw-text)' }}>"Likely invoice-diversion attempt."</p>
              <div className="space-y-1 pt-1">
                {['Reply-To domain differs from sender domain.', 'Sender domain registered 11 days ago.', 'Urgent payment language with secrecy request.'].map(e => (
                  <div key={e} className="flex items-start gap-2">
                    <div className="w-1 h-1 rounded-full mt-1.5 shrink-0" style={{ backgroundColor: 'var(--tw-burgundy)' }} />
                    <p className="text-xs" style={{ color: 'var(--tw-text-muted)' }}>{e}</p>
                  </div>
                ))}
              </div>
              <p className="font-mono text-[10px] pt-1" style={{ color: 'var(--tw-medium)' }}>
                Confidence: High · Exact sender identity cannot be established from available evidence.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ── Privacy and Compliance ────────────────────────── */}
      <section className="border-y" style={{ borderColor: 'var(--tw-border)', backgroundColor: 'var(--tw-canvas-mid)' }}>
        <div className="max-w-7xl mx-auto px-6 lg:px-10 py-14">
          <div className="grid md:grid-cols-4 gap-8">
            {[
              { label: 'Privacy by Design',   desc: 'Data minimisation, configurable retention, and email-address masking built in from the start.' },
              { label: 'Evidence Integrity',  desc: 'Original evidence is immutable. Every access is logged. Chain-of-custody records are tamper-evident.' },
              { label: 'Role-Based Access',   desc: 'Admin, Analyst, Investigator, Viewer, and Auditor roles with fine-grained permission controls.' },
              { label: 'Authorised Use Only', desc: 'Monitoring restricted to verified organisational assets. Individual private persons are never tracked without authorisation.' },
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
          <h2 className="font-serif text-5xl" style={{ color: 'var(--tw-text)' }}>Start with the evidence.</h2>
          <p className="text-lg max-w-xl mx-auto" style={{ color: 'var(--tw-text-muted)' }}>
            Open an investigation, follow the relay, examine the infrastructure — and let the evidence guide the response.
          </p>
          <div className="flex flex-wrap justify-center gap-3 pt-2">
            <Link to="/app/briefing" className="font-mono text-xs tracking-widest uppercase px-6 py-3 rounded-sm"
              style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
            >
              Open Daily Briefing
            </Link>
            <Link to="/app/investigate" className="font-mono text-xs tracking-widest uppercase px-6 py-3 rounded-sm border"
              style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text)' }}
            >
              Investigate an Email
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
              <span className="font-mono text-sm tracking-[0.14em] uppercase" style={{ color: 'var(--tw-text)' }}>PhishNet</span>
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
              PhishNet is a forensic investigation platform for authorised security personnel only.
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
