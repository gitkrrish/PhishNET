import { useState, useEffect, useCallback, useRef } from 'react';
import { analyzeEmail as analyzeEmailWithBackend, analyzeEmailFile, generateHash } from '../../lib/mockBackend';
import { Upload, ChevronDown, ChevronUp, AlertTriangle, CheckCircle, Eye, EyeOff, Copy, Flag, FileText, Download, FileCheck } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { demoEmail, authResults, relayHops, riskScoreBreakdown, domainIntel, asteronEmails, asteronCampaign, attachmentAnalysis, ipIntelligence, currentAnalyst } from '../../data/mockData';
import { EvidenceStamp } from '../../components/ui/EvidenceStamp';
import { SeverityBadge } from '../../components/ui/SeverityBadge';
import { AuthBadge } from '../../components/ui/AuthBadge';
import { ConfidenceBar } from '../../components/ui/ConfidenceBar';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { tv } from '../../lib/styles';
import clsx from 'clsx';
import { lazy, Suspense } from 'react';
import { ThreeDErrorBoundary } from '../../components/3d/ThreeDErrorBoundary';
import ThreatEvidenceNetwork from '../../components/3d/ThreatEvidenceNetwork';

// Lazy load the 3D components
const AnalysisProgress3D = lazy(() => import('../../components/3d/AnalysisProgress3D').then(m => ({ default: m.default })));
const RelayPath3D = lazy(() => import('../../components/3d/RelayPath3D').then(m => ({ default: m.default })));

type Step = 'intake' | 'analyzing' | 'results';

const analysisSteps = [
  'Parsing email headers…',
  'Validating authentication records…',
  'Extracting indicators of compromise…',
  'Analysing URLs and redirect chains…',
  'Checking attachment metadata…',
  'Enriching threat intelligence…',
  'Correlating related infrastructure…',
  'Checking authorised exposure records…',
  'Generating AI explanation…',
  'Preparing forensic evidence…',
];

// ── Types ───────────────────────────────────────────────────────
type InputMethod = 'demo' | 'paste' | 'upload' | 'headers' | 'message-id';
type AuthResult = 'PASS' | 'FAIL' | 'SOFTFAIL' | 'NONE' | 'NEUTRAL' | 'UNAVAILABLE' | 'CANNOT_VERIFY';
type Reliability = 'VERIFIED' | 'SENDER_CONTROLLED' | 'INFERRED' | 'UNAVAILABLE';

interface ParsedHeader {
  name: string;
  value: string;
  suspicious?: boolean;
  reason?: string;
}

interface EmailData {
  id: string;
  subject: string;
  from: { display: string; address: string; domain: string };
  replyTo: string;
  returnPath: string;
  envelopeSender: string;
  to: string;
  messageId: string;
  date: string;
  attachments: Array<{ name: string; size: string; suspicious?: boolean; hash?: string; sha256?: string; macro?: boolean }>;
  urls: Array<{ url: string; risk: string; shortener?: boolean }>;
  body: string;
  suspiciousPhrases?: Array<{ text: string; reason: string; confidence: number }>;
  authResults?: any;
  authentication?: any;
  domainIntel?: any;
  providers?: {
    dns?: { state?: string };
    virusTotal?: { state?: string; detail?: string };
    abuseIpDb?: { state?: string; detail?: string };
    ipWhois?: { state?: string; detail?: string };
  };
  relayHops?: any[];
  indicators?: string[];
  recommendedActions?: string[];
  classification?: string;
  riskScore?: number;
  riskFactors?: Array<{ label: string; contribution: number; category: string }>;
  severity?: string;
  verdict?: string;
  confidence?: string;
  confidenceScore?: number;
  researchScore?: number;
  researchFactors?: Array<{ label: string; contribution: number }>;
  inputHash?: string;
  disclaimer?: string;
  hash?: string;
  uploadedFile?: string;
  uploadedFileSize?: number;
  uploadedAt?: string;
}

interface DemoEmailOption {
  id: string;
  label: string;
  email: EmailData;
  org: string;
}

interface URLAnalysis {
  original: string;
  redirectChain: string[];
  finalDomain: string;
  parameters: Record<string, string>;
  reputation: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN';
  domainAge: string;
  firstSeen: string;
  lastSeen: string;
}

interface AttachmentDetail {
  filename: string;
  fileType: string;
  size: string;
  hash: string;
  macroPresent: boolean;
  scriptPresent: boolean;
  sandboxResult: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'PENDING';
  riskScore: number;
  recommendation: string;
  matchedTemplate?: string;
}

interface IPDetail {
  ip: string;
  asn: string;
  asnName: string;
  isp: string;
  hostingProvider: string;
  country: string;
  region: string;
  city: string;
  isVpn: boolean;
  isTor: boolean;
  isProxy: boolean;
  isCloud: boolean;
  isOpenRelay: boolean;
  reputation: 'POOR' | 'NEUTRAL' | 'GOOD';
  firstSeen: string;
  lastSeen: string;
  abuseReports: number;
  note: string;
  isPrivate: boolean;
}

// ── Demo emails registry ───────────────────────────────────────
const demoEmailOptions: DemoEmailOption[] = [
  {
    id: 'secureops',
    label: 'SecureOps — Invoice Diversion (BEC)',
    email: demoEmail,
    org: 'SecureOps Intelligence Unit',
  },
  {
    id: 'asteron-001',
    label: 'Asteron — Urgent Vendor Payment (BEC)',
    email: asteronEmails[0],
    org: 'Asteron Institute of Technology',
  },
  {
    id: 'asteron-002',
    label: 'Asteron — Credential Harvesting',
    email: asteronEmails[1],
    org: 'Asteron Institute of Technology',
  },
  {
    id: 'asteron-003',
    label: 'Asteron — Macro-Enabled Attachment',
    email: asteronEmails[2],
    org: 'Asteron Institute of Technology',
  },
  {
    id: 'asteron-004',
    label: 'Asteron — Executive Impersonation',
    email: asteronEmails[3],
    org: 'Asteron Institute of Technology',
  },
];

// ── Header parsing helper ───────────────────────────────────────
function parseRawHeaders(raw: string): ParsedHeader[] {
  const lines = raw.split('\n');
  const headers: ParsedHeader[] = [];
  let currentHeader: ParsedHeader | null = null;
  
  for (const line of lines) {
    if (/^\s/.test(line) && currentHeader) {
      currentHeader.value += ' ' + line.trim();
    } else {
      if (currentHeader) headers.push(currentHeader);
      const match = line.match(/^([^:]+):\s*(.*)$/);
      if (match) {
        currentHeader = { name: match[1].trim(), value: match[2].trim() };
      }
    }
  }
  if (currentHeader) headers.push(currentHeader);
  
  // Mark suspicious headers
  return headers.map(h => {
    const suspicious = ['received', 'x-originating-ip', 'x-mailer', 'x-priority', 'x-ms-exchange'].some(s => h.name.toLowerCase().includes(s));
    return { ...h, suspicious, reason: suspicious ? 'Commonly spoofed or indicative of relay path' : undefined };
  });
}

// ── URL analysis helper ────────────────────────────────────────
function analyzeURLs(email: EmailData): URLAnalysis[] {
  return email.urls.map(u => {
    const url = new URL(u.url);
    const params: Record<string, string> = {};
    url.searchParams.forEach((v, k) => { params[k] = v; });
    return {
      original: u.url,
      redirectChain: u.shortener ? [u.url, `https://${url.hostname}/resolved`] : [u.url],
      finalDomain: url.hostname,
      parameters: params,
      reputation: u.risk === 'HIGH' ? 'SUSPICIOUS' : 'CLEAN',
      domainAge: 'Recently registered',
      firstSeen: '2026-09-01',
      lastSeen: '2026-09-13',
    };
  });
}

// ── BEC detection helper ───────────────────────────────────────
function detectBEC(email: EmailData): { detected: boolean; patterns: string[]; confidence: number } {
  const patterns: string[] = [];
  let score = 0;
  
  if (email.from.domain !== email.replyTo.split('@')[1]) {
    patterns.push('Reply-To domain mismatch');
    score += 25;
  }
  if (email.from.domain !== email.returnPath.split('@')[1]) {
    patterns.push('Return-Path domain mismatch');
    score += 15;
  }
  if (email.suspiciousPhrases?.some(p => p.reason.toLowerCase().includes('urgency'))) {
    patterns.push('Urgency language');
    score += 15;
  }
  if (email.suspiciousPhrases?.some(p => p.reason.toLowerCase().includes('secrecy'))) {
    patterns.push('Secrecy request');
    score += 20;
  }
  if (email.suspiciousPhrases?.some(p => p.reason.toLowerCase().includes('authority'))) {
    patterns.push('Authority impersonation');
    score += 20;
  }
  if (email.suspiciousPhrases?.some(p => p.reason.toLowerCase().includes('payment') || p.reason.toLowerCase().includes('diversion'))) {
    patterns.push('Payment diversion language');
    score += 20;
  }
  
  return { detected: score >= 50, patterns, confidence: Math.min(score, 95) };
}

// ── Campaign correlation helper ────────────────────────────────
function correlateCampaign(email: EmailData) {
  const campaign = asteronCampaign;
  const matched = email.id.startsWith('ASTR') ? campaign : 
    (email.id.includes('0041') ? {
      id: 'CAMP-2026-017',
      name: 'Operation Ledger Shift',
      riskLevel: 'HIGH' as const,
      relatedEmails: 4,
      firstSeen: '2026-09-01',
      lastSeen: '2026-09-13',
      targetedDepartments: ['Finance', 'Accounts Payable'],
      relatedDomains: ['secureops-finance.in', 'secure-ops-pay.net', 'secureops-payments.com'],
      relatedIPs: ['185.220.101.47', '45.142.212.83'],
      relatedCases: ['INV-2026-0041'],
      confidence: 88,
      aiSummary: 'Co-ordinated invoice-diversion campaign targeting financial processing departments. Four messages share sender infrastructure, lookalike domain pattern, and identical payment-redirection language. Probable goal: divert outgoing payments to attacker-controlled accounts.',
      containmentActions: [
        'Block all sender domains at mail gateway',
        'Alert Finance department via out-of-band channel',
        'Verify all pending payment instructions independently',
        'Add relay IPs to monitoring watchlist',
      ],
      tags: ['BEC', 'Invoice Fraud', 'Lookalike Domain', 'Finance Target'],
    } : null);
  
  return matched;
}

// ── AI Explanation helper ──────────────────────────────────────
function generateAIExplanation(email: EmailData, bec: ReturnType<typeof detectBEC>) {
  const auth = email.authResults || authResults;
  const authFailures = [auth.spf, auth.dkim, auth.dmarc].filter(r => r.result === 'FAIL').length;
  
  let explanation = `This email `;
  if (bec.detected) {
    explanation += `exhibits strong Business Email Compromise indicators (${bec.confidence}% confidence). `;
  } else {
    explanation += `shows some suspicious characteristics but does not meet the threshold for high-confidence BEC classification. `;
  }
  
  if (authFailures > 0) {
    explanation += `Authentication failures (${authFailures}/3 checks failed) indicate the message was not sent from authorised infrastructure. `;
  } else if (auth.spf?.result === 'PASS' && auth.dkim?.result === 'PASS' && auth.dmarc?.result === 'PASS') {
    explanation += `All authentication checks pass, which is consistent with a compromised legitimate account — a common BEC attack vector. `;
  }
  
  if (email.attachments.some(a => a.macro || a.suspicious)) {
    explanation += `The message contains suspicious attachments that may deliver malware. `;
  }
  
  if (email.urls.some(u => u.risk === 'HIGH' || u.shortener)) {
    explanation += `High-risk URLs with redirect chains were detected. `;
  }
  
  explanation += `Exact sender identity cannot be established from available evidence alone.`;
  
  return explanation;
}

// ── Recommended actions helper ─────────────────────────────────
function getRecommendedActions(email: EmailData, bec: ReturnType<typeof detectBEC>) {
  const actions = [
    { id: 'quarantine', title: 'Quarantine Email', reason: 'Prevent further interaction with this message', impact: 'Removes email from recipient mailbox', risk: 'LOW' as const, auto: true },
    { id: 'block-domain', title: 'Block Sender Domain', reason: 'Prevent future messages from this infrastructure', impact: `Blocks ${email.from.domain} organisation-wide`, risk: 'MEDIUM' as const, auto: false },
    { id: 'verify-payment', title: 'Verify Payment Instructions', reason: 'Confirm banking details through independent channel', impact: 'Out-of-band verification required', risk: 'LOW' as const, auto: false },
  ];
  
  if (email.attachments.some(a => a.macro)) {
    actions.push({ id: 'sandbox', title: 'Submit Attachment to Sandbox', reason: 'Analyse macro behavior in isolated environment', impact: 'Dynamic analysis of suspicious file', risk: 'LOW' as const, auto: false });
  }
  
  if (email.urls.some(u => u.risk === 'HIGH')) {
    actions.push({ id: 'block-url', title: 'Block Malicious URLs', reason: 'Prevent access to credential harvesting or payment diversion sites', impact: 'Adds URLs to proxy/gateway blocklist', risk: 'LOW' as const, auto: true });
  }
  
  if (bec.detected) {
    actions.push({ id: 'alert-staff', title: 'Alert Targeted Department', reason: 'Warn potential victims via out-of-band channel', impact: 'Reduces likelihood of successful fraud', risk: 'LOW' as const, auto: false });
  }
  
  return actions;
}

// ── Analysis progress animation ──────────────────────────────
function AnalysisProgress({ onComplete }: { onComplete: () => void }) {
  const [step, setStep] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setStep(prev => {
        if (prev >= analysisSteps.length - 1) {
          clearInterval(interval);
          setTimeout(onComplete, 400);
          return prev;
        }
        return prev + 1;
      });
    }, 400);
    return () => clearInterval(interval);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const progress = ((step + 1) / analysisSteps.length) * 100;

  return (
    <div className="min-h-[50vh] flex flex-col items-center justify-center gap-6 p-10" style={tv.canvas}>
      <div className="w-full max-w-md space-y-4">
        <div className="text-center">
          <p className="font-mono text-[10px] tracking-[0.2em] uppercase mb-2" style={tv.muted}>Analysis in Progress</p>
          <p className="font-serif text-xl" style={tv.text}>Examining Evidence</p>
        </div>
        
        {/* 3D Progress Visualization */}
        <div className="h-40 w-full rounded-sm overflow-hidden border" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border)' }}>
          <ThreeDErrorBoundary fallback={
            <div className="w-full h-full flex items-center justify-center">
              <div className="h-0.5 w-48 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--tw-border-mid)' }}>
                <motion.div
                  className="h-full rounded-full"
                  style={{ backgroundColor: 'var(--tw-burgundy)' }}
                  animate={{ width: `${progress}%` }}
                  transition={{ duration: 0.3 }}
                />
              </div>
            </div>
          }>
            <Suspense fallback={
              <div className="w-full h-full flex items-center justify-center">
                <div className="h-0.5 w-48 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--tw-border-mid)' }}>
                  <motion.div
                    className="h-full rounded-full"
                    style={{ backgroundColor: 'var(--tw-burgundy)' }}
                    animate={{ width: `${progress}%` }}
                    transition={{ duration: 0.3 }}
                  />
                </div>
              </div>
            }>
              <AnalysisProgress3D steps={analysisSteps} currentStep={step} />
            </Suspense>
          </ThreeDErrorBoundary>
        </div>

        <div className="space-y-2">
          {analysisSteps.map((s, i) => (
            <div key={i} className={clsx('flex items-center gap-2 text-xs transition-all duration-300')}>
              {i < step ? (
                <CheckCircle size={11} className="shrink-0" style={tv.low} />
              ) : i === step ? (
                <div className="w-2.5 h-2.5 border rounded-full shrink-0 animate-pulse"
                  style={{ borderColor: 'var(--tw-burgundy)' }}
                />
              ) : (
                <div className="w-2.5 h-2.5 border rounded-full shrink-0"
                  style={{ borderColor: 'var(--tw-border-strong)' }}
                />
              )}
              <span className="font-mono"
                style={{ color: i < step ? 'var(--tw-low)' : i === step ? 'var(--tw-text)' : 'var(--tw-text-faint)' }}
              >
                {s}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Relay hop row ─────────────────────────────────────────────
function RelayHop({ hop, isLast }: { hop: typeof relayHops[0]; isLast: boolean }) {
  const [expanded, setExpanded] = useState(false);

  const relStyles = {
    VERIFIED:         { color: 'var(--tw-low)',    label: 'Verified' },
    SENDER_CONTROLLED:{ color: 'var(--tw-medium)', label: 'Sender-controlled' },
    INFERRED:         { color: 'var(--tw-dust)',   label: 'Inferred' },
    UNAVAILABLE:      { color: 'var(--tw-text-faint)', label: 'Unavailable' },
  };
  const rel = relStyles[hop.reliability as keyof typeof relStyles] || relStyles.UNAVAILABLE;

  return (
    <div className="flex gap-4">
      {/* Timeline rail */}
      <div className="flex flex-col items-center shrink-0 w-8">
        <div className="w-6 h-6 rounded-sm flex items-center justify-center text-[9px] font-mono font-medium text-[#FBFAF6]"
          style={{ backgroundColor: rel.color }}
        >
          {hop.num}
        </div>
        {!isLast && (
          <div className="w-px flex-1 min-h-6 mt-1"
            style={{
              borderLeft: hop.reliability === 'VERIFIED'
                ? `1px solid var(--tw-border-strong)`
                : `1px dashed var(--tw-border-strong)`,
            }}
          />
        )}
      </div>

      {/* Content */}
      <div className="flex-1 pb-5">
        <button onClick={() => setExpanded(!expanded)} className="w-full text-left">
          <div className="flex items-start justify-between gap-2">
            <div className="space-y-0.5">
              <div className="flex items-center gap-2">
                <p className="font-mono text-xs font-medium" style={tv.text}>{hop.hostname}</p>
                <span className="font-mono text-[9px]" style={{ color: rel.color }}>{rel.label}</span>
              </div>
              <p className="font-mono text-[10px]" style={tv.muted}>
                {hop.ip} · {hop.countryName} · {hop.asnName}
              </p>
            </div>
            <div className="flex items-center gap-2">
              {hop.isCloud && (
                <span className="font-mono text-[9px] px-1.5 py-0.5 rounded-sm"
                  style={{ backgroundColor: 'var(--tw-panel-alt)', color: 'var(--tw-text-muted)' }}
                >
                  Cloud
                </span>
              )}
              {expanded
                ? <ChevronUp size={13} style={tv.faint} />
                : <ChevronDown size={13} style={tv.faint} />
              }
            </div>
          </div>
        </button>

        <AnimatePresence>
          {expanded && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="overflow-hidden"
            >
              <div className="mt-3 p-3 rounded-sm space-y-2 border"
                style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border)' }}
              >
                {[
                  { label: 'IP Address', val: hop.ip },
                  { label: 'ASN',        val: `${hop.asn} · ${hop.asnName}` },
                  { label: 'Country',    val: `${hop.countryName} (${hop.country})` },
                  { label: 'Timestamp', val: hop.timestamp },
                  { label: 'Reliability', val: rel.label },
                ].map(row => (
                  <div key={row.label} className="flex items-start gap-4">
                    <span className="font-mono text-[10px] uppercase tracking-wider w-24 shrink-0" style={tv.muted}>{row.label}</span>
                    <span className="font-mono text-xs" style={tv.text}>{row.val}</span>
                  </div>
                ))}
                {hop.note && (
                  <p className="font-mono text-[10px] pt-1 border-t" style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-medium)' }}>
                    ℹ {hop.note}
                  </p>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}

// ── Email body with NLP annotations ──────────────────────────
function SuspiciousBody({ email }: { email: EmailData }) {
  const [showMask, setShowMask] = useState(false);

  const segments: { text: string; suspicious: boolean; reason?: string; confidence?: number }[] = [];
  let remaining = email.body;
  (email.suspiciousPhrases || []).forEach(phrase => {
    const idx = remaining.indexOf(phrase.text);
    if (idx !== -1) {
      if (idx > 0) segments.push({ text: remaining.slice(0, idx), suspicious: false });
      segments.push({ text: phrase.text, suspicious: true, reason: phrase.reason, confidence: phrase.confidence });
      remaining = remaining.slice(idx + phrase.text.length);
    }
  });
  if (remaining) segments.push({ text: remaining, suspicious: false });

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Message Body</p>
        <button onClick={() => setShowMask(!showMask)}
          className="flex items-center gap-1.5 font-mono text-[10px] transition-colors"
          style={tv.muted}
        >
          {showMask ? <EyeOff size={11} /> : <Eye size={11} />}
          {showMask ? 'Unmask body' : 'Mask body'}
        </button>
      </div>

      {showMask ? (
        <div className="p-4 rounded-sm" style={{ backgroundColor: 'var(--tw-text)' }}>
          <p className="font-mono text-xs" style={tv.muted}>[Message body redacted per analyst preference]</p>
        </div>
      ) : (
        <div className="p-4 rounded-sm border" style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)' }}>
          <p className="text-sm leading-relaxed whitespace-pre-wrap font-sans" style={tv.text}>
            {segments.map((seg, i) =>
              seg.suspicious ? (
                <span key={i} className="relative group">
                  <span className="annotation-underline cursor-help">{seg.text}</span>
                  <span className="absolute bottom-full left-0 mb-2 w-52 p-2 text-[10px] font-mono rounded-sm
                    opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-10 leading-relaxed"
                    style={{ backgroundColor: 'var(--tw-text)', color: 'var(--tw-canvas-warm)' }}
                  >
                    {seg.reason}
                    <br />
                    <span style={{ color: 'var(--tw-brass)' }}>Confidence: {seg.confidence}%</span>
                  </span>
                </span>
              ) : (
                <span key={i}>{seg.text}</span>
              )
            )}
          </p>
        </div>
      )}

      <div className="space-y-2">
        {(email.suspiciousPhrases || []).map((p, i) => (
          <div key={i} className="flex items-start gap-3 p-2.5 rounded-sm border"
            style={{
              backgroundColor: `color-mix(in srgb, var(--tw-critical) 18%, transparent)`,
              borderColor: `color-mix(in srgb, var(--tw-critical) 40%, transparent)`,
            }}
          >
            <span className="evidence-num shrink-0">{String(i + 1).padStart(2, '0')}</span>
            <div className="flex-1 min-w-0">
              <p className="font-mono text-xs truncate" style={tv.burg}>"{p.text}"</p>
              <p className="text-xs mt-0.5" style={tv.muted}>{p.reason}</p>
            </div>
            <span className="font-mono text-[10px] shrink-0" style={tv.medium}>{p.confidence}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────
export default function InvestigatePage() {
  const [step, setStep] = useState<Step>('intake');
  const [inputMethod, setInputMethod] = useState<InputMethod>('demo');
  const [pastedEmail, setPastedEmail] = useState('');
  const [activeSection, setActiveSection] = useState<string>('verdict');
  const [acknowledged, setAcknowledged] = useState(false);
  const [selectedDemoId, setSelectedDemoId] = useState<string>('secureops');
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [showRawHeaders, setShowRawHeaders] = useState(false);
  const [redactBody, setRedactBody] = useState(false);
  const [emailData, setEmailData] = useState<EmailData | null>(null);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const analysisInFlight = useRef(false);
  const [relayViewMode, setRelayViewMode] = useState<'list' | '3d'>('list');

  const currentDemo = demoEmailOptions.find(d => d.id === selectedDemoId);
  const activeEmail: EmailData = (emailData || currentDemo?.email || {
    ...demoEmail,
    authResults,
    relayHops,
    indicators: [],
    recommendedActions: [],
    classification: 'Business Email Compromise',
    riskScore: riskScoreBreakdown.total,
    severity: 'HIGH',
  }) as EmailData;

  const validateFile = useCallback((file: File): boolean => {
    const validTypes = ['.eml', '.msg', '.txt'];
    const validMimes = ['message/rfc822', 'application/vnd.ms-outlook', 'text/plain'];
    const ext = file.name.toLowerCase().slice(file.name.lastIndexOf('.'));
    if (!validTypes.includes(ext) && !validMimes.includes(file.type)) {
      setUploadError('Invalid file type. Accepted: .eml, .msg, .txt (email headers)');
      return false;
    }
    if (file.size > 10 * 1024 * 1024) {
      setUploadError('File too large. Maximum size: 10 MB');
      return false;
    }
    setUploadError(null);
    return true;
  }, []);

  const handleFileDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
    const file = e.dataTransfer.files[0];
    if (file && validateFile(file)) {
      setUploadedFile(file);
      setInputMethod('upload');
    }
  }, [validateFile]);

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file && validateFile(file)) {
      setUploadedFile(file);
      setInputMethod('upload');
    }
  }, [validateFile]);

  const loadDemoEmail = useCallback((demoId: string) => {
    const demo = demoEmailOptions.find(d => d.id === demoId);
    if (demo) {
      setSelectedDemoId(demoId);
      setEmailData(demo.email);
      setInputMethod('demo');
    }
  }, []);

  const startAnalysis = useCallback(async () => {
    if (!acknowledged || analysisInFlight.current) return;

    if (inputMethod !== 'demo') {
      let rawEmail = pastedEmail;
      if (inputMethod === 'upload' && uploadedFile) rawEmail = await uploadedFile.text();
      if ((inputMethod === 'paste' || inputMethod === 'headers' || inputMethod === 'message-id') && !rawEmail.trim()) {
        setAnalysisError('Please provide email content or headers');
        return;
      }
      if (inputMethod === 'upload' && !uploadedFile) {
        setAnalysisError('Please select an email file');
        return;
      }
      setAnalysisError(null);
      analysisInFlight.current = true;
      setIsAnalyzing(true);
      setStep('analyzing');
      try {
        const analysisId = `ANL-${crypto.randomUUID()}`;
        const result = inputMethod === 'upload' && uploadedFile
          ? await analyzeEmailFile(uploadedFile, analysisId)
          : await analyzeEmailWithBackend(rawEmail, analysisId, inputMethod);
        setEmailData(result as EmailData);
        setIsAnalyzing(false);
        setStep('results');
      } catch (error) {
        setIsAnalyzing(false);
        setStep('intake');
        setAnalysisError(error instanceof Error ? error.message : 'Email analysis failed');
      } finally {
        analysisInFlight.current = false;
      }
      return;
    }
    
    let data: EmailData | null = null;
    let fileHash = '';
    
    if (inputMethod === 'demo') {
      data = currentDemo?.email || demoEmail;
    } else if (inputMethod === 'paste' && pastedEmail.trim()) {
      // Parse pasted content as raw email
      const headers = parseRawHeaders(pastedEmail);
      data = {
        id: `EMAIL-${Date.now()}`,
        subject: headers.find(h => h.name.toLowerCase() === 'subject')?.value || 'Unknown Subject',
        from: { display: headers.find(h => h.name.toLowerCase() === 'from')?.value || 'Unknown', address: 'unknown@example.com', domain: 'example.com' },
        replyTo: headers.find(h => h.name.toLowerCase() === 'reply-to')?.value || '',
        returnPath: headers.find(h => h.name.toLowerCase() === 'return-path')?.value || '',
        envelopeSender: headers.find(h => h.name.toLowerCase() === 'envelope-sender')?.value || '',
        to: headers.find(h => h.name.toLowerCase() === 'to')?.value || '',
        messageId: headers.find(h => h.name.toLowerCase() === 'message-id')?.value || '',
        date: headers.find(h => h.name.toLowerCase() === 'date')?.value || new Date().toISOString(),
        attachments: [],
        urls: [],
        body: pastedEmail.split('\n\n').slice(-1)[0] || '',
        suspiciousPhrases: [],
      };
      // Compute hash of pasted content
      const blob = new Blob([pastedEmail], { type: 'text/plain' });
      fileHash = await generateHash(new File([blob], 'pasted-email.txt', { type: 'text/plain' }));
    } else if (inputMethod === 'headers' && pastedEmail.trim()) {
      const headers = parseRawHeaders(pastedEmail);
      data = {
        id: `EMAIL-${Date.now()}`,
        subject: headers.find(h => h.name.toLowerCase() === 'subject')?.value || 'Unknown Subject',
        from: { display: headers.find(h => h.name.toLowerCase() === 'from')?.value || 'Unknown', address: '', domain: '' },
        replyTo: headers.find(h => h.name.toLowerCase() === 'reply-to')?.value || '',
        returnPath: headers.find(h => h.name.toLowerCase() === 'return-path')?.value || '',
        envelopeSender: headers.find(h => h.name.toLowerCase() === 'envelope-sender')?.value || '',
        to: headers.find(h => h.name.toLowerCase() === 'to')?.value || '',
        messageId: headers.find(h => h.name.toLowerCase() === 'message-id')?.value || '',
        date: headers.find(h => h.name.toLowerCase() === 'date')?.value || new Date().toISOString(),
        attachments: [],
        urls: [],
        body: '',
        suspiciousPhrases: [],
      };
      const blob = new Blob([pastedEmail], { type: 'text/plain' });
      fileHash = await generateHash(new File([blob], 'headers.txt', { type: 'text/plain' }));
    } else if (inputMethod === 'upload' && uploadedFile) {
      // Simulate file parsing with hash generation
      fileHash = await generateHash(uploadedFile);
      const baseEmail = currentDemo?.email || demoEmail;
      data = {
        ...baseEmail,
        id: `EMAIL-${Date.now()}`,
        hash: fileHash,
        uploadedFile: uploadedFile.name,
        uploadedFileSize: uploadedFile.size,
        uploadedAt: new Date().toISOString(),
        subject: baseEmail.subject,
      };
    } else if (inputMethod === 'message-id' && pastedEmail.trim()) {
      // Simulate internal message ID lookup
      data = currentDemo?.email || demoEmail;
    }
    
    if (data) {
      if (fileHash) {
        data.hash = fileHash;
      }
      setEmailData(data);
      setAnalysisError(null);
      setIsAnalyzing(true);
      setStep('analyzing');
      // Simulate analysis completion
      setTimeout(() => {
        setIsAnalyzing(false);
        setStep('results');
      }, 3000);
    } else {
      setAnalysisError('Please provide valid email content or select a demo email');
    }
  }, [acknowledged, inputMethod, pastedEmail, uploadedFile, currentDemo]);

  const resetAnalysis = useCallback(() => {
    setStep('intake');
    setEmailData(null);
    setPastedEmail('');
    setUploadedFile(null);
    setUploadError(null);
    setAnalysisError(null);
    setShowRawHeaders(false);
    setRedactBody(false);
  }, []);

  // ── Intake ───────────────────────────────────────────────────
  if (step === 'intake') {
    return (
      <div className="min-h-screen" style={tv.canvas}>
        <div className="max-w-4xl mx-auto px-6 lg:px-10 py-10 space-y-8">
          <div className="space-y-2">
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Email Investigation</p>
            <h1 className="font-serif text-3xl" style={tv.text}>Submit Evidence for Analysis</h1>
          </div>

          {/* Privacy notice */}
          <div className="rounded-sm p-5 space-y-3"
            style={{ backgroundColor: 'var(--tw-canvas-mid)', border: '1px solid var(--tw-border)' }}
          >
            <div className="flex items-start gap-3">
              <AlertTriangle size={15} className="mt-0.5 shrink-0" style={tv.medium} />
              <div className="space-y-2">
                <p className="font-mono text-[10px] tracking-[0.15em] uppercase" style={tv.medium}>Authorised Use Notice</p>
                <p className="text-xs leading-relaxed" style={tv.muted}>
                  This platform is restricted to authorised security analysts operating within the scope of their role.
                  Email content is processed per the organisation's data-handling policy. Do not submit emails
                  containing personal data beyond what is required for the investigation.
                </p>
                <p className="text-xs leading-relaxed" style={tv.muted}>
                  Analysis results are investigative assessments and are not legal conclusions. IP geolocation
                  represents estimated infrastructure locations — not the physical location or identity of any person.
                </p>
                <label className="flex items-center gap-2 cursor-pointer pt-1">
                  <input type="checkbox" checked={acknowledged} onChange={e => setAcknowledged(e.target.checked)}
                    style={{ accentColor: 'var(--tw-burgundy)' }}
                    className="w-3.5 h-3.5"
                  />
                  <span className="text-xs" style={tv.text}>
                    I am an authorised analyst and understand the scope and limitations of this tool.
                  </span>
                </label>
              </div>
            </div>
          </div>

          {/* Input method */}
          <div className="space-y-4">
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Input Method</p>
            <div className="flex gap-2 flex-wrap">
              {[
                { id: 'demo', label: 'Demo Email' },
                { id: 'paste', label: 'Paste Raw Email' },
                { id: 'headers', label: 'Paste Headers Only' },
                { id: 'upload', label: 'Upload .eml File' },
                { id: 'message-id', label: 'Internal Message ID' },
              ].map(m => (
                <button key={m.id} onClick={() => setInputMethod(m.id as InputMethod)}
                  className="font-mono text-xs tracking-wide px-4 py-2 rounded-sm border transition-colors"
                  style={inputMethod === m.id
                    ? { backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6', borderColor: 'var(--tw-burgundy)' }
                    : { backgroundColor: 'transparent', color: 'var(--tw-text-muted)', borderColor: 'var(--tw-border-strong)' }
                  }
                >
                  {m.label}
                </button>
              ))}
            </div>

            {inputMethod === 'demo' && (
              <div className="p-4 rounded-sm border space-y-3"
                style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border)' }}
              >
                <div className="flex items-center justify-between">
                  <DemoLabel />
                  <select value={selectedDemoId} onChange={e => loadDemoEmail(e.target.value)}
                    className="font-mono text-xs px-3 py-1.5 rounded-sm border focus:outline-none" style={tv.input}
                  >
                    {demoEmailOptions.map(d => <option key={d.id} value={d.id}>{d.label}</option>)}
                  </select>
                </div>
                <div className="space-y-1">
                  <p className="text-sm font-medium" style={tv.text}>{currentDemo?.email.subject}</p>
                  <p className="font-mono text-xs" style={tv.muted}>From: {currentDemo?.email.from.display}</p>
                  <p className="font-mono text-xs" style={tv.muted}>Date: {currentDemo?.email.date}</p>
                  <p className="font-mono text-xs" style={tv.muted}>Organisation: {currentDemo?.org}</p>
                  <p className="text-xs italic" style={tv.faint}>
                    This is a fictional demonstration email. No real organisation is represented.
                  </p>
                </div>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" checked={redactBody} onChange={e => setRedactBody(e.target.checked)}
                    style={{ accentColor: 'var(--tw-burgundy)' }} className="w-3.5 h-3.5" />
                  <span className="text-xs" style={tv.text}>Redact message body in analysis view</span>
                </label>
              </div>
            )}

            {inputMethod === 'paste' && (
              <div className="space-y-2">
                <textarea value={pastedEmail} onChange={e => setPastedEmail(e.target.value)}
                  placeholder="Paste the full raw email content (headers + body) here…"
                  className="w-full h-52 p-4 font-mono text-xs rounded-sm focus:outline-none resize-none placeholder:opacity-40"
                  style={tv.input}
                />
                <label className="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" checked={redactBody} onChange={e => setRedactBody(e.target.checked)}
                    style={{ accentColor: 'var(--tw-burgundy)' }} className="w-3.5 h-3.5" />
                  <span className="text-xs" style={tv.text}>Redact message body in analysis view</span>
                </label>
              </div>
            )}

            {inputMethod === 'headers' && (
              <div className="space-y-2">
                <textarea value={pastedEmail} onChange={e => setPastedEmail(e.target.value)}
                  placeholder="Paste email headers only (Received, From, To, Subject, Message-ID, etc.)…"
                  className="w-full h-40 p-4 font-mono text-xs rounded-sm focus:outline-none resize-none placeholder:opacity-40"
                  style={tv.input}
                />
                <p className="font-mono text-[10px]" style={tv.faint}>Headers will be parsed for relay path, authentication, and timestamp analysis. Body content will not be available.</p>
              </div>
            )}

            {inputMethod === 'upload' && (
              <div className="space-y-3">
                <div
                  className={`border-2 border-dashed rounded-sm p-10 text-center transition-colors ${dragActive ? 'bg-[color-mix(in_srgb,_var(--tw-burgundy),_transparent)]' : ''}`}
                  style={{ borderColor: dragActive ? 'var(--tw-burgundy)' : 'var(--tw-border-strong)' }}
                  onDragOver={e => { e.preventDefault(); setDragActive(true); }}
                  onDragLeave={e => { e.preventDefault(); setDragActive(false); }}
                  onDrop={handleFileDrop}
                >
                  <input type="file" id="email-upload" accept=".eml,.msg,.txt" onChange={handleFileSelect} className="hidden" />
                  <label htmlFor="email-upload" className="cursor-pointer">
                    <Upload size={20} className="mx-auto mb-3" style={tv.faint} />
                    <p className="text-sm" style={tv.muted}>Drop an .eml file here or click to browse</p>
                    <p className="font-mono text-[10px] mt-1" style={tv.faint}>Accepted: .eml, .msg, .txt (email headers) · Max 10 MB</p>
                  </label>
                </div>
                {uploadError && (
                  <p className="font-mono text-xs text-center" style={{ color: 'var(--tw-critical)' }}>{uploadError}</p>
                )}
                {uploadedFile && (
                  <div className="p-3 rounded-sm border flex items-center justify-between"
                    style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border)' }}
                  >
                    <div className="flex items-center gap-3">
                      <FileText size={16} style={tv.text} />
                      <div>
                        <p className="font-mono text-xs" style={tv.text}>{uploadedFile.name}</p>
                        <p className="font-mono text-[10px]" style={tv.muted}>{(uploadedFile.size / 1024).toFixed(1)} KB</p>
                      </div>
                    </div>
                    <button onClick={() => { setUploadedFile(null); setInputMethod('demo'); }}
                      className="font-mono text-[10px] text-red-500 hover:underline">Remove</button>
                  </div>
                )}
                <label className="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" checked={redactBody} onChange={e => setRedactBody(e.target.checked)}
                    style={{ accentColor: 'var(--tw-burgundy)' }} className="w-3.5 h-3.5" />
                  <span className="text-xs" style={tv.text}>Redact message body in analysis view</span>
                </label>
              </div>
            )}

            {inputMethod === 'message-id' && (
              <div className="space-y-2">
                <input type="text" value={pastedEmail} onChange={e => setPastedEmail(e.target.value)}
                  placeholder="Enter internal Message-ID (e.g., <20260912.091437.FIN5591@secureops-finance.in>)"
                  className="w-full p-4 font-mono text-xs rounded-sm focus:outline-none placeholder:opacity-40" style={tv.input}
                />
                <p className="font-mono text-[10px]" style={tv.faint}>Looks up the email in the internal evidence store by Message-ID. Requires appropriate access permissions.</p>
              </div>
            )}
          </div>

          {analysisError && (
            <div className="rounded-sm p-4 flex items-center gap-3"
              style={{ backgroundColor: 'color-mix(in srgb, var(--tw-critical) 15%, transparent)', border: '1px solid var(--tw-critical)' }}
            >
              <AlertTriangle size={14} style={tv.critical} />
              <p className="text-xs" style={{ color: 'var(--tw-critical)' }}>{analysisError}</p>
            </div>
          )}

          <button onClick={startAnalysis} disabled={!acknowledged || isAnalyzing}
            className="font-mono text-xs tracking-widest uppercase px-6 py-3 rounded-sm transition-colors disabled:opacity-40 w-full"
            style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
          >
            {isAnalyzing ? 'Analysing…' : 'Begin Analysis →'}
          </button>
        </div>
      </div>
    );
  }

  if (step === 'analyzing') {
    return <AnalysisProgress onComplete={() => undefined} />;
  }

  // ── Derived analysis data ────────────────────────────────────
  const parsedHeaders = activeEmail.authResults ? parseRawHeaders(
    `Received: from ${activeEmail.from.domain} (${activeEmail.from.address})
From: ${activeEmail.from.display}
To: ${activeEmail.to}
Subject: ${activeEmail.subject}
Message-ID: ${activeEmail.messageId}
Date: ${activeEmail.date}
Reply-To: ${activeEmail.replyTo}
Return-Path: ${activeEmail.returnPath}
Envelope-Sender: ${activeEmail.envelopeSender}
` + (activeEmail.authResults ? 
`Authentication-Results: ${activeEmail.from.domain}; spf=${activeEmail.authResults.spf?.result?.toLowerCase()}; dkim=${activeEmail.authResults.dkim?.result?.toLowerCase()}; dmarc=${activeEmail.authResults.dmarc?.result?.toLowerCase()}` : '')
  ) : parseRawHeaders(
    `Received: from ${activeEmail.from.domain} (${activeEmail.from.address})
From: ${activeEmail.from.display}
To: ${activeEmail.to}
Subject: ${activeEmail.subject}
Message-ID: ${activeEmail.messageId}
Date: ${activeEmail.date}
Reply-To: ${activeEmail.replyTo}
Return-Path: ${activeEmail.returnPath}
Envelope-Sender: ${activeEmail.envelopeSender}
`
  );

  const urlAnalysis = analyzeURLs(activeEmail);
  const becDetection = detectBEC(activeEmail);
  const campaignCorrelation = correlateCampaign(activeEmail);
  const aiExplanation = generateAIExplanation(activeEmail, becDetection);
  const recommendedActions = getRecommendedActions(activeEmail, becDetection);
  const liveEmail = inputMethod !== 'demo';
  const authData = activeEmail.authResults || (liveEmail ? {
    spf: { result: 'UNAVAILABLE', detail: 'Authentication data unavailable' },
    dkim: { result: 'UNAVAILABLE', detail: 'Authentication data unavailable' },
    dmarc: { result: 'UNAVAILABLE', detail: 'Authentication data unavailable' },
  } : authResults);
  const authentication = activeEmail.authentication || (liveEmail ? {
    observed: { authenticationResults: { present: false, spf: 'NOT OBSERVED', dkim: 'NOT OBSERVED', dmarc: 'NOT OBSERVED' } },
    spf: { status: 'NOT EVALUATED', evidence: 'Authentication evidence unavailable' },
    dkim: { status: 'NOT EVALUATED', evidence: 'Authentication evidence unavailable' },
    dmarc: { status: 'NOT EVALUATED', evidence: 'Authentication evidence unavailable' },
    spfAlignment: { status: 'NOT EVALUATED', evidence: 'Alignment unavailable' },
    dkimAlignment: { status: 'NOT EVALUATED', evidence: 'Alignment unavailable' },
    dmarcPolicy: { status: 'LOOKUP UNAVAILABLE', policy: 'Unavailable', evidence: 'Policy lookup unavailable' },
    authorizedSender: { status: 'NOT EVALUATED', reason: 'Sender authorization unavailable', evidence: 'Authorization unavailable' },
  } : { observed: { authenticationResults: {} }, spf: authResults.spf, dkim: authResults.dkim, dmarc: authResults.dmarc, spfAlignment: { status: 'NOT EVALUATED', evidence: 'Demo alignment data unavailable' }, dkimAlignment: { status: 'NOT EVALUATED', evidence: 'Demo alignment data unavailable' }, dmarcPolicy: { status: 'NOT EVALUATED', policy: 'Unavailable', evidence: 'Demo policy data unavailable' }, authorizedSender: { status: 'NOT EVALUATED', reason: 'Demo sender authorization data unavailable', evidence: 'Demo authorization data unavailable' } });
  const relayData = activeEmail.relayHops || (liveEmail ? [] : relayHops);
  const displayDomainIntel = liveEmail ? activeEmail.domainIntel || {
    senderDomain: activeEmail.from.domain || 'Unavailable', legitimateDomain: 'Not evaluated', similarityScore: 'Not evaluated', registeredDaysAgo: 'Not evaluated', registrationDate: 'Not available', registrar: 'Not available', ipReputation: 'Not evaluated', hostingProvider: 'Not available', firstSeen: 'Not available', lastSeen: 'Not available', homoglyphs: [], relatedDomains: [], spfRecord: 'Unavailable', dmarcRecord: 'Unavailable', mxRecords: [], nameservers: [],
  } : domainIntel;
  const displayRiskScore = liveEmail ? activeEmail.riskScore ?? 0 : activeEmail.riskScore ?? riskScoreBreakdown.total;
  const displayVerdict = liveEmail ? activeEmail.verdict || 'UNAVAILABLE' : activeEmail.verdict || (displayRiskScore >= 70 ? 'HIGH RISK' : riskScoreBreakdown.verdict);
  const displayConfidence = activeEmail.confidence || (liveEmail ? 'UNAVAILABLE' : riskScoreBreakdown.confidence);
  const displayConfidenceScore = liveEmail ? activeEmail.confidenceScore ?? 0 : 88;
  const displayResearchScore = liveEmail ? activeEmail.researchScore ?? 0 : 88;
  const displayRiskFactors = liveEmail
    ? (activeEmail.riskFactors || []).map((factor, index) => ({ ...factor, num: index + 1 }))
    : riskScoreBreakdown.factors;
  const attachmentDetails = activeEmail.attachments.map((a, i) => {
    if (liveEmail) return { filename: a.name, fileType: a.name.split('.').pop()?.toUpperCase() || 'UNKNOWN', size: a.size, hash: a.sha256 || '', macroPresent: false, scriptPresent: false, sandboxResult: 'PENDING' as const, riskScore: 0, recommendation: 'No execution performed; reputation data is shown separately.' };
    const match = attachmentAnalysis.find(at => at.emailId === activeEmail.id) || attachmentAnalysis[0];
    return { ...match, filename: a.name, fileType: a.name.split('.').pop()?.toUpperCase() || 'UNKNOWN', size: a.size } as AttachmentDetail;
  });
  const ipDetails = relayData
    .filter(h => !h.ip.startsWith('10.') && !h.ip.startsWith('192.168.') && !h.ip.startsWith('172.'))
    .map(h => {
        const match = liveEmail ? undefined : ipIntelligence.find(ip => ip.ip === h.ip);
      return match || {
        ip: h.ip,
        asn: h.asn,
        asnName: h.asnName,
        isp: h.provider,
        hostingProvider: h.provider,
        country: h.countryName,
        region: '',
        city: '',
        isVpn: h.isVpn,
        isTor: h.isTor,
        isProxy: false,
        isCloud: h.isCloud,
        isOpenRelay: false,
        reputation: 'NEUTRAL' as const,
        firstSeen: h.timestamp ? h.timestamp.split('T')[0] : 'Not available',
        lastSeen: h.timestamp ? h.timestamp.split('T')[0] : 'Not available',
        abuseReports: 0,
        note: 'Limited intelligence available',
        isPrivate: false,
      } as IPDetail;
    });

  // ── Results ──────────────────────────────────────────────────
  const sections = [
    { id: 'verdict',  label: 'Verdict' },
    { id: 'identity', label: 'Identity' },
    { id: 'auth',     label: 'Authentication' },
    { id: 'relay',    label: 'Relay Path' },
    { id: 'domain',   label: 'Domain Intel' },
    { id: 'nlp',      label: 'Social Engineering' },
  ];

  return (
    <div className="min-h-screen" style={tv.canvas}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="space-y-1">
            <div className="flex items-center gap-3">
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>
                Analysis Complete · {activeEmail.id}
              </p>
              {!liveEmail && <DemoLabel />}
            </div>
            <h1 className="font-serif text-2xl" style={tv.text}>{activeEmail.subject}</h1>
            {activeEmail.hash && (
              <p className="font-mono text-[10px]" style={tv.muted}>SHA-256: {activeEmail.hash.slice(0, 32)}...</p>
            )}
            {liveEmail && activeEmail.inputHash && (
              <p className="font-mono text-[10px]" style={tv.muted}>Input fingerprint: {activeEmail.inputHash.slice(0, 32)}...</p>
            )}
          </div>
          <div className="flex gap-2">
            <button onClick={() => {
              const jsonData = {
                email: activeEmail,
                analysis: {
                  riskScore: displayRiskScore,
                  verdict: displayVerdict,
                  confidence: displayConfidence,
                  authResults: authData,
                  relayHops: relayData,
                  urlAnalysis: urlAnalysis,
                  becDetection: becDetection,
                  campaignCorrelation: campaignCorrelation,
                  aiExplanation: aiExplanation,
                  recommendedActions: recommendedActions,
                },
                evidence: {
                  hash: activeEmail.hash,
                  uploadedAt: activeEmail.uploadedAt,
                  uploadedFile: activeEmail.uploadedFile,
                },
                generatedAt: new Date().toISOString(),
                label: liveEmail ? 'Email Analysis Result' : 'Simulated Analysis Result',
              };
              const blob = new Blob([JSON.stringify(jsonData, null, 2)], { type: 'application/json' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = `${activeEmail.id}-analysis.json`;
              a.click();
              URL.revokeObjectURL(url);
            }}
              className="font-mono text-xs border px-3 py-2 rounded-sm transition-colors flex items-center gap-2"
              style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
            >
              <Download size={12} /> Export JSON
            </button>
            <button onClick={() => window.print()}
              className="font-mono text-xs border px-3 py-2 rounded-sm transition-colors flex items-center gap-2"
              style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
            >
              <FileText size={12} /> Print Report
            </button>
            <button onClick={() => {
              // Create a new case from this analysis
              const caseId = `CASE-${Date.now()}`;
              const newCase = {
                id: caseId,
                title: `Investigation: ${activeEmail.subject.slice(0, 50)}...`,
                severity: displayRiskScore > 75 ? 'HIGH' : 'MEDIUM',
                status: 'Investigating',
                assignedTo: currentAnalyst.name,
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString(),
                relatedEmails: [activeEmail.id],
                relatedCampaign: campaignCorrelation?.id || null,
                exposureRecords: [],
                timelineEvents: [
                  { time: new Date().toISOString(), actor: currentAnalyst.name, event: 'Case created from email analysis', type: 'ANALYST' },
                  { time: new Date().toISOString(), actor: 'System', event: `Email ${activeEmail.id} ingested with risk score ${displayRiskScore}`, type: 'SYSTEM' },
                ],
                notes: [],
                tasks: [
                  { id: 'T1', text: 'Review sender identity and authentication results', done: false },
                  { id: 'T2', text: 'Verify URLs and attachments in sandbox', done: false },
                  { id: 'T3', text: 'Check for related exposure records', done: false },
                ],
              };
              // Store in localStorage for demo purposes
              try {
                const existingCases = JSON.parse(localStorage.getItem('tracewall-cases') || '[]');
                existingCases.unshift(newCase);
                localStorage.setItem('tracewall-cases', JSON.stringify(existingCases));
                alert(`Case ${caseId} created successfully. Navigate to Cases page to view.`);
              } catch (e) {
                alert(`Case ${caseId} would be created (demo mode)`);
              }
            }}
              className="font-mono text-xs border px-3 py-2 rounded-sm transition-colors flex items-center gap-2"
              style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
            >
              <FileCheck size={12} /> Create Case
            </button>
            <button onClick={() => setStep('intake')}
              className="font-mono text-xs border px-3 py-2 rounded-sm transition-colors"
              style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
            >
              New Analysis
            </button>
          </div>
        </div>

        {/* Threat Evidence Network */}
        {!liveEmail && <ThreatEvidenceNetwork pageType="email" />}

        {/* Section tabs */}
        <div className="flex gap-0 overflow-x-auto border-b mb-7" style={{ borderColor: 'var(--tw-border-mid)' }}>
          {sections.map(s => (
            <button key={s.id} onClick={() => setActiveSection(s.id)}
              className="font-mono text-xs px-4 py-2.5 border-b-2 shrink-0 transition-colors"
              style={{
                borderBottomColor: activeSection === s.id ? 'var(--tw-burgundy)' : 'transparent',
                color: activeSection === s.id ? 'var(--tw-burgundy)' : 'var(--tw-text-muted)',
              }}
            >
              {s.label}
            </button>
          ))}
        </div>

        {/* ── Verdict ───────────────────────── */}
        {activeSection === 'verdict' && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="grid lg:grid-cols-3 gap-6">
            <div className="lg:col-span-1 space-y-5">
              <div className="rounded-sm p-6 space-y-5 text-center" style={tv.panelBorder}>
                <EvidenceStamp verdict={displayVerdict} size="lg" className="mx-auto" />
                <div>
                  <div className="font-mono text-6xl font-light" style={tv.burg}>{displayRiskScore}</div>
                  <div className="font-mono text-xs tracking-wider" style={tv.muted}>/ 100 RISK SCORE</div>
                </div>
                <ConfidenceBar value={displayConfidenceScore} />
                <p className="font-mono text-[10px]" style={tv.muted}>Confidence: {displayConfidence}</p>
                <p className="font-mono text-[10px]" style={tv.muted}>Research Score: {displayResearchScore}/100</p>
                <p className="text-[10px] italic leading-relaxed" style={tv.faint}>{liveEmail ? activeEmail.disclaimer : riskScoreBreakdown.disclaimer}</p>
              </div>

              {/* Analyst override */}
              <div className="rounded-sm p-4 space-y-2" style={tv.panelBorder}>
                <p className="font-mono text-[10px] tracking-[0.15em] uppercase" style={tv.muted}>Analyst Override</p>
                <select className="w-full font-mono text-xs rounded-sm px-3 py-2 focus:outline-none" style={tv.input}>
                  <option value="">— Select override verdict —</option>
                  <option>Legitimate</option>
                  <option>False Positive</option>
                  <option>Escalate to Critical</option>
                </select>
                <textarea placeholder="Reason for override…"
                  className="w-full font-mono text-xs rounded-sm px-3 py-2 focus:outline-none h-20 resize-none placeholder:opacity-40"
                  style={tv.input}
                />
                <button onClick={() => alert('Override submitted for review (demo mode)')}
                  className="font-mono text-[10px] tracking-widest uppercase px-4 py-2 border rounded-sm w-full transition-colors"
                  style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
                >
                  Submit Override
                </button>
              </div>
            </div>

            {/* Risk factors */}
            <div className="lg:col-span-2 space-y-4">
              <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
                <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Risk Score Breakdown</p>
                </div>
                {displayRiskFactors.map((f, i) => (
                  <div key={i} className="flex items-center gap-4 px-5 py-3 border-b last:border-0"
                    style={{ borderColor: 'var(--tw-border-mid)' }}
                  >
                    <span className="evidence-num shrink-0">{String(i + 1).padStart(2, '0')}</span>
                    <div className="flex-1">
                      <p className="text-sm" style={tv.text}>{f.label}</p>
                      <p className="font-mono text-[10px]" style={tv.muted}>{f.category}</p>
                    </div>
                    <span className="font-mono text-sm" style={tv.burg}>+{f.contribution}</span>
                    <div className="w-32 hidden md:block">
                      <div className="confidence-bar">
                        <div className="confidence-fill" style={{ width: `${(f.contribution / 30) * 100}%` }} />
                      </div>
                    </div>
                  </div>
                ))}
                <div className="flex items-center gap-4 px-5 py-3"
                  style={{ backgroundColor: 'var(--tw-panel-alt)' }}
                >
                  <div className="flex-1 pl-8">
                    <p className="font-mono text-sm font-medium" style={tv.text}>Total Risk Score</p>
                  </div>
                  <span className="font-mono text-xl" style={tv.burg}>{displayRiskScore}/100</span>
                </div>
              </div>

              {/* Threat classification */}
              <div className="rounded-sm p-5 space-y-3" style={tv.panelBorder}>
                <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Threat Classification</p>
                <div className="flex flex-wrap gap-2">
                  {(liveEmail ? [activeEmail.classification || 'Requires analyst review'] : ['Business Email Compromise', 'Invoice Fraud', 'Social Engineering', 'Domain Impersonation']).map(t => (
                    <span key={t}
                      className="font-mono text-xs px-3 py-1 rounded-sm border"
                      style={{
                        color: 'var(--tw-critical)',
                        borderColor: `color-mix(in srgb, var(--tw-critical) 40%, transparent)`,
                        backgroundColor: `color-mix(in srgb, var(--tw-critical) 18%, transparent)`,
                      }}
                    >
                      {t}
                    </span>
                  ))}
                </div>
                <p className="text-xs leading-relaxed" style={tv.muted}>
                  {liveEmail
                    ? 'Classification is limited to indicators extracted from this submitted message and the available external services.'
                    : 'This message exhibits characteristics consistent with a Business Email Compromise invoice-diversion attempt.'}
                </p>
              </div>
            </div>
          </motion.div>
        )}

        {/* ── Identity ──────────────────────── */}
        {activeSection === 'identity' && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="grid lg:grid-cols-2 gap-6">
            <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
              <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Sender Identity</p>
              </div>
              {[
                { label: 'Display Name',    val: activeEmail.from.display || 'Unavailable', flag: false },
                { label: 'From Address',    val: activeEmail.from.address,      flag: false },
                { label: 'Reply-To',        val: activeEmail.replyTo,           flag: Boolean(activeEmail.replyTo && activeEmail.from.domain && !activeEmail.replyTo.includes(activeEmail.from.domain)), flagReason: 'Does not match From domain' },
                { label: 'Return-Path',     val: activeEmail.returnPath,        flag: Boolean(activeEmail.returnPath), flagReason: 'Return-Path observed in message' },
                { label: 'Envelope Sender', val: activeEmail.envelopeSender,    flag: Boolean(activeEmail.envelopeSender), flagReason: 'Envelope sender observed in message' },
                { label: 'Sender Domain',   val: activeEmail.from.domain,       flag: false },
              ].map(row => (
                <div key={row.label} className="flex items-start gap-4 px-5 py-3 border-b last:border-0"
                  style={{ borderColor: 'var(--tw-border-mid)' }}
                >
                  <span className="font-mono text-[10px] uppercase tracking-wider w-28 shrink-0 pt-0.5" style={tv.muted}>{row.label}</span>
                  <div className="flex-1">
                    <p className="font-mono text-xs"
                      style={{ color: row.flag ? 'var(--tw-burgundy)' : 'var(--tw-text)' }}
                    >
                      {row.val}
                    </p>
                    {row.flag && row.flagReason && (
                      <p className="text-[10px] mt-0.5 flex items-center gap-1" style={tv.medium}>
                        <AlertTriangle size={10} /> {row.flagReason}
                      </p>
                    )}
                  </div>
                  {row.flag && <Flag size={12} className="shrink-0 mt-0.5" style={tv.burg} />}
                </div>
              ))}
            </div>

            <div className="space-y-4">
              <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
                <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Message Metadata</p>
                </div>
                {[
                  { label: 'Subject',     val: activeEmail.subject },
                  { label: 'Message-ID',  val: activeEmail.messageId },
                  { label: 'Date',        val: activeEmail.date },
                  { label: 'Attachments', val: `${activeEmail.attachments.length} file(s)` },
                  { label: 'URLs',        val: `${activeEmail.urls.length} extracted` },
                ].map(row => (
                  <div key={row.label} className="flex items-start gap-4 px-5 py-3 border-b last:border-0"
                    style={{ borderColor: 'var(--tw-border-mid)' }}
                  >
                    <span className="font-mono text-[10px] uppercase tracking-wider w-28 shrink-0 pt-0.5" style={tv.muted}>{row.label}</span>
                    <p className="font-mono text-xs flex-1" style={tv.text}>{row.val}</p>
                    <button onClick={() => navigator.clipboard?.writeText(row.val)} className="ml-auto shrink-0">
                      <Copy size={11} style={tv.faint} />
                    </button>
                  </div>
                ))}
              </div>

              {/* URL list */}
              <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
                <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Extracted URLs</p>
                </div>
                {activeEmail.urls.map((u, i) => (
                  <div key={i} className="flex items-center gap-3 px-5 py-3 border-b last:border-0"
                    style={{ borderColor: 'var(--tw-border-mid)' }}
                  >
                    <span className="evidence-num shrink-0">{String(i + 1).padStart(2, '0')}</span>
                    <p className="font-mono text-xs flex-1 truncate" style={tv.text}>{u.url}</p>
                    <span className="font-mono text-[9px] px-2 py-0.5 rounded-sm border"
                      style={u.risk === 'HIGH'
                        ? { backgroundColor: `color-mix(in srgb, var(--tw-critical) 18%, transparent)`, color: 'var(--tw-critical)', borderColor: `color-mix(in srgb, var(--tw-critical) 40%, transparent)` }
                        : { backgroundColor: `color-mix(in srgb, var(--tw-low) 18%, transparent)`, color: 'var(--tw-low)', borderColor: `color-mix(in srgb, var(--tw-low) 40%, transparent)` }
                      }
                    >
                      {u.risk}
                    </span>
                    {u.shortener && (
                      <span className="font-mono text-[9px] px-2 py-0.5 rounded-sm border"
                        style={{ backgroundColor: `color-mix(in srgb, var(--tw-medium) 18%, transparent)`, color: 'var(--tw-medium)', borderColor: `color-mix(in srgb, var(--tw-medium) 40%, transparent)` }}
                      >
                        Shortener
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        )}

        {/* ── Authentication ────────────────── */}
        {activeSection === 'auth' && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-5">
            <div className="grid md:grid-cols-3 gap-4">
              <AuthBadge result={authentication.spf.status} label="SPF" detail={authentication.spf.evidence} explanation={authentication.spf.evidence} />
              <AuthBadge result={authentication.dkim.status} label="DKIM" detail={authentication.dkim.evidence} explanation={authentication.dkim.evidence} />
              <AuthBadge result={authentication.dmarc.status} label="DMARC" detail={authentication.dmarc.evidence} explanation={authentication.dmarc.evidence} />
            </div>
            {liveEmail && activeEmail.providers && (
              <div className="grid md:grid-cols-4 gap-4">
                <AuthBadge result={activeEmail.providers.dns?.state || 'Unavailable'} label="DNS" detail="Configured resolver lookups" />
                <AuthBadge result={activeEmail.providers.virusTotal?.state || 'Unavailable'} label="VirusTotal" detail={activeEmail.providers.virusTotal?.detail || 'URL reputation provider'} />
                <AuthBadge result={activeEmail.providers.abuseIpDb?.state || 'Unavailable'} label="AbuseIPDB" detail={activeEmail.providers.abuseIpDb?.detail || 'IP reputation provider'} />
                <AuthBadge result={activeEmail.providers.ipWhois?.state || 'Unavailable'} label="IP WHOIS" detail={activeEmail.providers.ipWhois?.detail || 'RDAP network intelligence'} />
              </div>
            )}
            <div className="grid md:grid-cols-2 gap-4">
              {[
                { label: 'SPF Alignment', result: authentication.spfAlignment.status, detail: authentication.spfAlignment.evidence },
                { label: 'DKIM Alignment', result: authentication.dkimAlignment.status, detail: authentication.dkimAlignment.evidence },
                { label: 'DMARC Policy', result: authentication.dmarcPolicy.status, detail: `${authentication.dmarcPolicy.policy} — ${authentication.dmarcPolicy.evidence}` },
                { label: 'Authorised Sender', result: authentication.authorizedSender.status, detail: `${authentication.authorizedSender.reason} ${authentication.authorizedSender.evidence}` },
              ].map(item => (
                <AuthBadge key={item.label} result={item.result} label={item.label} detail={item.detail} />
              ))}
            </div>
            {authentication.observed?.authenticationResults?.present && (
              <div className="rounded-sm p-4" style={tv.panelBorder}>
                <p className="font-mono text-[10px] tracking-[0.15em] uppercase" style={tv.muted}>Observed Authentication-Results</p>
                <p className="font-mono text-xs mt-2" style={tv.text}>
                  SPF {authentication.observed.authenticationResults.spf} · DKIM {authentication.observed.authenticationResults.dkim} · DMARC {authentication.observed.authenticationResults.dmarc}
                </p>
                <p className="text-xs mt-2" style={tv.muted}>Reported by the supplied header; not independent verification.</p>
              </div>
            )}
            <div className="rounded-sm p-4 flex items-start gap-3"
              style={{ backgroundColor: 'var(--tw-canvas-mid)', border: '1px solid var(--tw-border)' }}
            >
              <AlertTriangle size={14} className="mt-0.5 shrink-0" style={tv.medium} />
              <p className="text-xs leading-relaxed" style={tv.muted}>{authData.note || 'Authentication results reflect observed headers and configured DNS/reputation services.'}</p>
            </div>
          </motion.div>
        )}

        {/* ── Relay Path ────────────────────── */}
        {activeSection === 'relay' && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">
            <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
              <div className="px-5 py-3 border-b flex items-center justify-between" style={{ borderColor: 'var(--tw-border-mid)' }}>
                <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Email Relay Timeline</p>
                <div className="flex items-center gap-3">
                  {!liveEmail && <DemoLabel />}
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => setRelayViewMode('list')}
                      className={`font-mono text-[10px] px-2 py-1 rounded-sm transition-colors ${
                        relayViewMode === 'list' ? 'bg-[var(--tw-burgundy)] text-[#FBFAF6]' : 'text-[var(--tw-text-muted)]'
                      }`}
                    >
                      List
                    </button>
                    <button
                      onClick={() => setRelayViewMode('3d')}
                      className={`font-mono text-[10px] px-2 py-1 rounded-sm transition-colors ${
                        relayViewMode === '3d' ? 'bg-[var(--tw-burgundy)] text-[#FBFAF6]' : 'text-[var(--tw-text-muted)]'
                      }`}
                    >
                      3D
                    </button>
                  </div>
                </div>
              </div>
              {relayViewMode === 'list' ? (
                <div className="p-5">
                  {relayData.map((hop, i) => (
                    <RelayHop key={hop.num} hop={hop} isLast={i === relayData.length - 1} />
                  ))}
                </div>
              ) : (
                <div style={{ height: 300, backgroundColor: 'var(--tw-panel)' }}>
                  <ThreeDErrorBoundary fallback={
                    <div className="w-full h-full flex items-center justify-center">
                      <p className="font-mono text-xs" style={{ color: 'var(--tw-text-muted)' }}>
                        3D view unavailable - using list view
                      </p>
                    </div>
                  }>
                    <Suspense fallback={
                      <div className="w-full h-full flex items-center justify-center">
                        <div className="flex items-center gap-2">
                          <div className="w-4 h-4 border-2 border-[var(--tw-burgundy)] border-t-transparent rounded-full animate-spin" />
                          <span className="font-mono text-xs" style={{ color: 'var(--tw-text-muted)' }}>
                            Loading 3D view…
                          </span>
                        </div>
                      </div>
                    }>
                      <RelayPath3D hops={relayData} />
                    </Suspense>
                  </ThreeDErrorBoundary>
                </div>
              )}
            </div>
            
            <div className="grid lg:grid-cols-2 gap-6">
              <div className="space-y-4">
                {/* Legend */}
                <div className="rounded-sm p-4 space-y-3" style={tv.panelBorder}>
                  <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Reliability Legend</p>
                  {[
                    { color: 'var(--tw-low)',    label: 'Verified · Technically confirmed'  },
                    { color: 'var(--tw-medium)', label: 'Sender-controlled · Cannot verify' },
                    { color: 'var(--tw-dust)',   label: 'Inferred · Low confidence'         },
                    { color: 'var(--tw-text-faint)', label: 'Unavailable'                   },
                  ].map(item => (
                    <div key={item.label} className="flex items-center gap-3">
                      <div className="w-4 h-4 rounded-sm shrink-0" style={{ backgroundColor: item.color }} />
                      <span className="text-xs" style={tv.muted}>{item.label}</span>
                    </div>
                  ))}
                </div>
              </div>
              {/* Limitation notice */}
              <div className="rounded-sm p-4 space-y-2"
                style={{ backgroundColor: 'var(--tw-canvas-mid)', border: '1px solid var(--tw-border)' }}
              >
                <p className="font-mono text-[10px] tracking-[0.15em] uppercase" style={tv.muted}>Important Limitation</p>
                <p className="text-xs leading-relaxed" style={tv.muted}>
                  Sender-controlled headers cannot be independently verified. Cloud servers and relay nodes
                  may not represent the attacker's actual location. A compromised system may be used as a relay.
                </p>
                <p className="font-mono text-[10px]" style={tv.medium}>
                  Estimated Infrastructure Location — not proof of identity.
                </p>
              </div>
            </div>
          </motion.div>
        )}

        {/* ── Domain Intelligence ───────────── */}
        {activeSection === 'domain' && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="grid lg:grid-cols-2 gap-6">
            <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
              <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>
                  Domain Intelligence — {displayDomainIntel.senderDomain}
                </p>
              </div>
              {[
                { label: 'Sender Domain',    val: displayDomainIntel.senderDomain,              flag: true  },
                { label: 'Legitimate Domain',val: displayDomainIntel.legitimateDomain,          flag: false },
                { label: 'Similarity Score', val: `${displayDomainIntel.similarityScore}${liveEmail ? '' : '% — Lookalike'}`, flag: !liveEmail },
                { label: 'Domain Age',       val: `${displayDomainIntel.registeredDaysAgo}${liveEmail ? '' : ' days'}`, flag: !liveEmail },
                { label: 'Registered',       val: displayDomainIntel.registrationDate,          flag: false },
                { label: 'Registrar',        val: displayDomainIntel.registrar,                 flag: false },
                { label: 'IP Reputation',    val: displayDomainIntel.ipReputation,              flag: !liveEmail },
                { label: 'Hosting',          val: displayDomainIntel.hostingProvider,           flag: false },
                { label: 'First Seen',       val: displayDomainIntel.firstSeen,                 flag: false },
                { label: 'Last Seen',        val: displayDomainIntel.lastSeen,                  flag: false },
              ].map(row => (
                <div key={row.label} className="flex items-start gap-4 px-5 py-2.5 border-b last:border-0"
                  style={{ borderColor: 'var(--tw-border-mid)' }}
                >
                  <span className="font-mono text-[10px] uppercase tracking-wider w-32 shrink-0 pt-0.5" style={tv.muted}>{row.label}</span>
                  <p className="font-mono text-xs"
                    style={{ color: row.flag ? 'var(--tw-burgundy)' : 'var(--tw-text)' }}
                  >
                    {row.val}
                  </p>
                </div>
              ))}
            </div>

            <div className="space-y-4">
              {/* Impersonation indicators */}
              <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
                <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Domain Impersonation Indicators</p>
                </div>
                {displayDomainIntel.homoglyphs.map((h: any, i: number) => (
                  <div key={i} className="p-4 space-y-1">
                    <div className="flex items-center gap-3">
                      <p className="font-mono text-xs" style={tv.low}>{h.original}</p>
                      <span style={tv.faint}>→</span>
                      <p className="font-mono text-xs" style={tv.burg}>{h.variant}</p>
                    </div>
                    <p className="text-xs" style={tv.muted}>{h.technique}</p>
                  </div>
                ))}
              </div>

              {/* Related domains */}
              <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
                <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Related Suspicious Domains</p>
                </div>
                {displayDomainIntel.relatedDomains.map((d: string, i: number) => (
                  <div key={i} className="flex items-center gap-3 px-5 py-2.5 border-b last:border-0"
                    style={{ borderColor: 'var(--tw-border-mid)' }}
                  >
                    <span className="evidence-num shrink-0">{String(i + 1).padStart(2, '0')}</span>
                    <p className="font-mono text-xs" style={tv.text}>{d}</p>
                    <span className="font-mono text-[9px] px-2 py-0.5 rounded-sm ml-auto border"
                      style={{ backgroundColor: `color-mix(in srgb, var(--tw-medium) 18%, transparent)`, color: 'var(--tw-medium)', borderColor: `color-mix(in srgb, var(--tw-medium) 40%, transparent)` }}
                    >
                      Suspicious
                    </span>
                  </div>
                ))}
              </div>

              {/* DNS Records */}
              <div className="rounded-sm p-4 space-y-3" style={tv.panelBorder}>
                <p className="font-mono text-[10px] tracking-[0.2em] uppercase mb-2" style={tv.muted}>DNS Records</p>
                {[
                  { type: 'SPF',   val: displayDomainIntel.spfRecord                    },
                  { type: 'DMARC', val: displayDomainIntel.dmarcRecord                  },
                  { type: 'MX',    val: displayDomainIntel.mxRecords.join(', ')         },
                  { type: 'NS',    val: displayDomainIntel.nameservers.join(', ')       },
                ].map(r => (
                  <div key={r.type} className="space-y-0.5">
                    <span className="font-mono text-[10px]" style={tv.muted}>{r.type}</span>
                    <p className="font-mono text-[10px] px-2 py-1 rounded-sm break-all"
                      style={{ backgroundColor: 'var(--tw-panel-alt)', color: 'var(--tw-text)' }}
                    >
                      {r.val}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        )}

        {/* ── Social Engineering / NLP ──────── */}
        {activeSection === 'nlp' && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="grid lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2">
              <SuspiciousBody email={activeEmail} />
            </div>
            <div className="space-y-4">
              <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
                <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Detected Patterns</p>
                </div>
                {(liveEmail ? (activeEmail.suspiciousPhrases || []).map(phrase => ({ pattern: phrase.text, count: 1, severity: 'MEDIUM' })) : [
                  { pattern: 'Urgency Trigger', count: 2, severity: 'HIGH' },
                  { pattern: 'Authority Impersonation', count: 1, severity: 'CRITICAL' },
                  { pattern: 'Secrecy Request', count: 1, severity: 'CRITICAL' },
                  { pattern: 'Payment Diversion Language', count: 2, severity: 'HIGH' },
                  { pattern: 'Reply-To Redirect', count: 1, severity: 'HIGH' },
                ]).map((p, index) => (
                  <div key={`${p.pattern}-${index}`} className="flex items-center gap-3 px-4 py-3 border-b last:border-0"
                    style={{ borderColor: 'var(--tw-border-mid)' }}
                  >
                    <div className="flex-1">
                      <p className="text-xs" style={tv.text}>{p.pattern}</p>
                      <p className="font-mono text-[10px]" style={tv.muted}>{p.count} instance(s)</p>
                    </div>
                    <SeverityBadge severity={p.severity} />
                  </div>
                ))}
              </div>

              <div className="rounded-sm p-4 space-y-2"
                style={{ backgroundColor: 'var(--tw-canvas-mid)', border: '1px solid var(--tw-border)' }}
              >
                <p className="font-mono text-[10px] tracking-[0.15em] uppercase" style={tv.muted}>AI Assessment</p>
                <p className="text-xs font-medium leading-relaxed" style={tv.text}>
                  {liveEmail ? aiExplanation : 'Likely invoice-diversion attempt using BEC social engineering patterns.'}
                </p>
                <p className="text-xs leading-relaxed" style={tv.muted}>
                  {liveEmail ? 'This assessment is derived from the submitted message and the evidence available to the analysis.' : 'The message combines authority impersonation, urgency, a secrecy directive, and a reply-to redirect — all hallmarks of an invoice-fraud campaign.'}
                </p>
                <p className="font-mono text-[10px]" style={tv.medium}>Confidence: {displayConfidence}</p>
              </div>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
}
