import { useState, useCallback, useEffect } from 'react';
import { Link, ExternalLink, AlertTriangle, CheckCircle, Download, Hash, Shield, FileCheck, Copy } from 'lucide-react';
import { motion } from 'framer-motion';
import { tv } from '../../lib/styles';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { SeverityBadge } from '../../components/ui/SeverityBadge';
import { EvidenceStamp } from '../../components/ui/EvidenceStamp';
import { asteronUrlAnalysis } from '../../data/mockData';
import ThreatEvidenceNetwork from '../../components/3d/ThreatEvidenceNetwork';

interface URLAnalysisResult {
  id: string;
  originalUrl: string;
  extractedUrl: string;
  shortenedUrl: string | null;
  redirectChain: Array<{ from: string; to: string; status: number }>;
  finalDomain: string;
  suspiciousParams: string[];
  reputation: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN';
  domainAge: number;
  firstSeen: string;
  lastSeen: string;
  riskScore: number;
  verdict: string;
  confidence: string;
  severity: string;
  domainIntel: {
    lookalikeOf?: string;
    similarityScore?: number;
    registrar?: string;
    hostingProvider?: string;
    country?: string;
    tlsInfo?: {
      valid: boolean;
      issuer: string;
      expires: string;
    };
  };
  phishingIndicators: string[];
  relatedEmail?: string;
  recommendedAction: string;
  disclaimer: string;
}

const demoUrlAnalysis: URLAnalysisResult = {
  id: 'URL-2026-001',
  originalUrl: 'https://asteron-billing.example/confirm-payment',
  extractedUrl: 'https://asteron-billing.example/confirm-payment',
  shortenedUrl: null,
  redirectChain: [
    { from: 'https://asteron-billing.example/confirm-payment', to: 'https://asteron-billing.example/confirm-payment', status: 200 },
  ],
  finalDomain: 'asteron-billing.example',
  suspiciousParams: ['redirect_uri', 'token'],
  reputation: 'SUSPICIOUS',
  domainAge: 11,
  firstSeen: '2026-08-28',
  lastSeen: '2026-09-08',
  riskScore: 78,
  verdict: 'SUSPICIOUS',
  confidence: 'HIGH',
  severity: 'HIGH',
  domainIntel: {
    lookalikeOf: 'asteron.example',
    similarityScore: 91,
    registrar: 'GoDaddy LLC',
    hostingProvider: 'Linode LLC (SG)',
    country: 'Singapore',
    tlsInfo: {
      valid: true,
      issuer: "Let's Encrypt",
      expires: '2026-11-28',
    },
  },
  phishingIndicators: [
    'Lookalike domain (91% similarity to legitimate)',
    'Recently registered domain (11 days)',
    'Suspicious URL parameters detected',
    'Domain hosted on cloud infrastructure',
    'No prior reputation history',
  ],
  relatedEmail: 'ASTR-EMAIL-001',
  recommendedAction: 'Block domain at mail gateway. Alert users not to interact with this URL. Correlate with related email investigation.',
  disclaimer: 'Simulated URL analysis for demo purposes only. No actual network requests were made to this URL.',
};

const demoUrls = [
  {
    id: 'demo-1',
    label: 'https://asteron-billing.example/confirm-payment',
    description: 'Lookalike domain with suspicious redirect behavior',
    risk: 'HIGH',
  },
  {
    id: 'demo-2',
    label: 'https://tinyurl.com/astpay2026',
    description: 'URL shortener redirecting to suspicious domain',
    risk: 'HIGH',
  },
  {
    id: 'demo-3',
    label: 'https://docs.asteron.example/policy',
    description: 'Legitimate organizational URL (clean)',
    risk: 'LOW',
  },
];

const analysisSteps = [
  'Validating URL format...',
  'Extracting and normalizing URL...',
  'Checking for URL shorteners...',
  'Analyzing redirect chain...',
  'Enriching domain intelligence...',
  'Checking domain reputation...',
  'Analyzing suspicious parameters...',
  'Checking for homoglyphs and lookalikes...',
  'Querying threat intelligence feeds...',
  'Generating risk assessment...',
];

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
  }, [onComplete]);

  const progress = ((step + 1) / analysisSteps.length) * 100;

  return (
    <div className="min-h-[50vh] flex flex-col items-center justify-center gap-6 p-10" style={tv.canvas}>
      <div className="w-full max-w-sm space-y-4">
        <div className="text-center">
          <p className="font-mono text-[10px] tracking-[0.2em] uppercase mb-2" style={tv.muted}>Analysis in Progress</p>
          <p className="font-serif text-xl" style={tv.text}>Analyzing URL</p>
        </div>
        <div className="h-0.5 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--tw-border-mid)' }}>
          <motion.div
            className="h-full rounded-full"
            style={{ backgroundColor: 'var(--tw-burgundy)' }}
            animate={{ width: `${progress}%` }}
            transition={{ duration: 0.3 }}
          />
        </div>
        <div className="space-y-2">
          {analysisSteps.map((s, i) => (
            <div key={i} className="flex items-center gap-2 text-xs transition-all duration-300">
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

export default function UrlAnalysisPage() {
  const [step, setStep] = useState<'intake' | 'analyzing' | 'results'>('intake');
  const [inputMethod, setInputMethod] = useState<'paste' | 'demo'>('paste');
  const [pastedUrl, setPastedUrl] = useState('');
  const [selectedDemoId, setSelectedDemoId] = useState('demo-1');
  const [analysisResult, setAnalysisResult] = useState<URLAnalysisResult | null>(null);
  const [urlError, setUrlError] = useState<string | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);

  const validateUrl = useCallback((url: string): boolean => {
    try {
      const urlObj = new URL(url);
      if (!['http:', 'https:'].includes(urlObj.protocol)) {
        setUrlError('Only HTTP and HTTPS URLs are supported');
        return false;
      }
      setUrlError(null);
      return true;
    } catch {
      setUrlError('Invalid URL format');
      return false;
    }
  }, []);

  const startAnalysis = useCallback(() => {
    if (!acknowledged) return;

    let result: URLAnalysisResult | null = null;

    if (inputMethod === 'demo') {
      const demoData = asteronUrlAnalysis.find(u => u.id === 'URL-AST-001') || demoUrlAnalysis;
      result = {
        ...demoData,
        reputation: demoData.reputation as URLAnalysisResult['reputation'],
        id: `URL-${Date.now()}`,
        riskScore: demoData.reputation === 'SUSPICIOUS' ? 78 : 25,
        verdict: demoData.reputation === 'SUSPICIOUS' ? 'SUSPICIOUS' : 'CLEAN',
        confidence: 'HIGH',
        severity: demoData.reputation === 'SUSPICIOUS' ? 'HIGH' : 'LOW',
        domainIntel: demoData.domainIntel || {
          lookalikeOf: undefined,
          similarityScore: undefined,
          registrar: 'Unknown',
          hostingProvider: 'Unknown',
          country: 'Unknown',
          tlsInfo: {
            valid: false,
            issuer: 'Unknown',
            expires: 'Unknown',
          },
        },
        phishingIndicators: demoData.phishingIndicators || [],
        recommendedAction: demoData.recommendedAction || 'Review URL manually',
      };
    } else if (inputMethod === 'paste' && pastedUrl.trim()) {
      if (!validateUrl(pastedUrl)) return;
      
      // Simulate analysis for pasted URL
      result = {
        ...demoUrlAnalysis,
        id: `URL-${Date.now()}`,
        originalUrl: pastedUrl,
        extractedUrl: pastedUrl,
        riskScore: 50 + Math.floor(Math.random() * 40),
      };
    }

    if (result) {
      setAnalysisResult(result);
      setStep('analyzing');
      setTimeout(() => {
        setStep('results');
      }, 4000);
    }
  }, [acknowledged, inputMethod, pastedUrl, validateUrl]);

  const resetAnalysis = useCallback(() => {
    setStep('intake');
    setAnalysisResult(null);
    setPastedUrl('');
    setUrlError(null);
    setAcknowledged(false);
  }, []);

  if (step === 'intake') {
    return (
      <div className="min-h-screen" style={tv.canvas}>
        <div className="max-w-4xl mx-auto px-6 lg:px-10 py-10 space-y-8">
          <div className="space-y-2">
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>URL Analysis</p>
            <h1 className="font-serif text-3xl" style={tv.text}>Submit URL for Analysis</h1>
          </div>

          {/* Privacy notice */}
          <div className="rounded-sm p-5 space-y-3"
            style={{ backgroundColor: 'var(--tw-canvas-mid)', border: '1px solid var(--tw-border)' }}
          >
            <div className="flex items-start gap-3">
              <AlertTriangle size={15} className="mt-0.5 shrink-0" style={tv.medium} />
              <div className="space-y-2">
                <p className="font-mono text-[10px] tracking-[0.15em] uppercase" style={tv.medium}>Safety Notice</p>
                <p className="text-xs leading-relaxed" style={tv.muted}>
                  This tool performs static analysis and enrichment using threat intelligence feeds.
                  URLs are NOT automatically visited from the frontend. High-risk URLs are identified without
                  executing potentially malicious content.
                </p>
                <label className="flex items-center gap-2 cursor-pointer pt-1">
                  <input type="checkbox" checked={acknowledged} onChange={e => setAcknowledged(e.target.checked)}
                    style={{ accentColor: 'var(--tw-burgundy)' }}
                    className="w-3.5 h-3.5"
                  />
                  <span className="text-xs" style={tv.text}>
                    I understand that URLs will not be automatically visited.
                  </span>
                </label>
              </div>
            </div>
          </div>

          {/* Input method */}
          <div className="space-y-4">
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Input Method</p>
            <div className="flex gap-2">
              {[
                { id: 'paste', label: 'Paste URL' },
                { id: 'demo', label: 'Demo URL' },
              ].map(m => (
                <button key={m.id} onClick={() => setInputMethod(m.id as 'paste' | 'demo')}
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

            {inputMethod === 'paste' && (
              <div className="space-y-2">
                <input
                  type="text"
                  value={pastedUrl}
                  onChange={e => setPastedUrl(e.target.value)}
                  placeholder="https://example.com/suspicious-link"
                  className="w-full p-4 font-mono text-xs rounded-sm focus:outline-none placeholder:opacity-40"
                  style={tv.input}
                />
                {urlError && (
                  <p className="font-mono text-xs" style={{ color: 'var(--tw-critical)' }}>{urlError}</p>
                )}
              </div>
            )}

            {inputMethod === 'demo' && (
              <div className="p-4 rounded-sm border space-y-3"
                style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border)' }}
              >
                <div className="flex items-center justify-between">
                  <DemoLabel />
                  <select value={selectedDemoId} onChange={e => setSelectedDemoId(e.target.value)}
                    className="font-mono text-xs px-3 py-1.5 rounded-sm border focus:outline-none" style={tv.input}
                  >
                    {demoUrls.map(d => <option key={d.id} value={d.id}>{d.label}</option>)}
                  </select>
                </div>
                <div className="space-y-1">
                  <p className="text-sm font-medium" style={tv.text}>{demoUrls.find(d => d.id === selectedDemoId)?.label}</p>
                  <p className="font-mono text-xs" style={tv.muted}>{demoUrls.find(d => d.id === selectedDemoId)?.description}</p>
                  <span className={`font-mono text-[10px] px-2 py-0.5 rounded-sm ${
                    demoUrls.find(d => d.id === selectedDemoId)?.risk === 'HIGH'
                      ? 'bg-[color-mix(in_srgb,var(--tw-critical),transparent)] text-[var(--tw-critical)]'
                      : 'bg-[color-mix(in_srgb,var(--tw-low),transparent)] text-[var(--tw-low)]'
                  }`}>
                    Risk: {demoUrls.find(d => d.id === selectedDemoId)?.risk}
                  </span>
                </div>
              </div>
            )}
          </div>

          <button onClick={startAnalysis} disabled={!acknowledged || (inputMethod === 'paste' && !pastedUrl.trim())}
            className="font-mono text-xs tracking-widest uppercase px-6 py-3 rounded-sm transition-colors disabled:opacity-40 w-full"
            style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
          >
            Begin Analysis →
          </button>
        </div>
      </div>
    );
  }

  if (step === 'analyzing') {
    return <AnalysisProgress onComplete={() => setStep('results')} />;
  }

  if (!analysisResult) return null;

  return (
    <div className="min-h-screen" style={tv.canvas}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="space-y-1">
            <div className="flex items-center gap-3">
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>
                Analysis Complete · {analysisResult.id}
              </p>
              <DemoLabel />
            </div>
            <h1 className="font-serif text-2xl" style={tv.text}>{analysisResult.originalUrl}</h1>
          </div>
          <div className="flex gap-2">
            <button onClick={() => {
              const blob = new Blob([JSON.stringify(analysisResult, null, 2)], { type: 'application/json' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = `${analysisResult.id}-analysis.json`;
              a.click();
              URL.revokeObjectURL(url);
            }}
              className="font-mono text-xs border px-3 py-2 rounded-sm transition-colors flex items-center gap-2"
              style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
            >
              <Download size={12} /> Export JSON
            </button>
            <button onClick={() => {
              const caseId = `CASE-${Date.now()}`;
              alert(`Case ${caseId} would be created from this URL analysis (demo mode)`);
            }}
              className="font-mono text-xs border px-3 py-2 rounded-sm transition-colors flex items-center gap-2"
              style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
            >
              <FileCheck size={12} /> Create Case
            </button>
            <button onClick={resetAnalysis}
              className="font-mono text-xs border px-3 py-2 rounded-sm transition-colors"
              style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
            >
              New Analysis
            </button>
          </div>
        </div>

        {/* Threat Evidence Network */}
        <ThreatEvidenceNetwork pageType="url" />

        {/* Verdict */}
        <div className="grid lg:grid-cols-3 gap-6 mb-6">
          <div className="lg:col-span-1 space-y-4">
            <div className="rounded-sm p-6 space-y-4 text-center" style={tv.panelBorder}>
              <EvidenceStamp verdict={analysisResult.verdict} size="lg" className="mx-auto" />
              <div>
                <div className="font-mono text-6xl font-light" style={tv.burg}>{analysisResult.riskScore}</div>
                <div className="font-mono text-xs tracking-wider" style={tv.muted}>/ 100 RISK SCORE</div>
              </div>
              <SeverityBadge severity={analysisResult.severity} />
              <p className="font-mono text-[10px]" style={tv.muted}>Confidence: {analysisResult.confidence}</p>
            </div>
          </div>

          <div className="lg:col-span-2 space-y-4">
            <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
              <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Phishing Indicators</p>
              </div>
              {analysisResult.phishingIndicators.map((indicator, i) => (
                <div key={i} className="flex items-center gap-3 px-5 py-3 border-b last:border-0"
                  style={{ borderColor: 'var(--tw-border-mid)' }}
                >
                  <span className="evidence-num shrink-0">{String(i + 1).padStart(2, '0')}</span>
                  <p className="text-sm" style={tv.text}>{indicator}</p>
                </div>
              ))}
            </div>

            <div className="rounded-sm p-4 space-y-2" style={tv.panelBorder}>
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Recommended Action</p>
              <p className="text-sm leading-relaxed" style={tv.text}>{analysisResult.recommendedAction}</p>
            </div>
          </div>
        </div>

        {/* URL Details */}
        <div className="grid lg:grid-cols-2 gap-6 mb-6">
          <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
            <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>URL Details</p>
            </div>
            {[
              { label: 'Original URL', val: analysisResult.originalUrl },
              { label: 'Extracted URL', val: analysisResult.extractedUrl },
              { label: 'Final Domain', val: analysisResult.finalDomain },
              { label: 'Shortened URL', val: analysisResult.shortenedUrl || 'None' },
              { label: 'Reputation', val: analysisResult.reputation },
              { label: 'Domain Age', val: `${analysisResult.domainAge} days` },
            ].map(row => (
              <div key={row.label} className="flex items-start gap-4 px-5 py-3 border-b last:border-0"
                style={{ borderColor: 'var(--tw-border-mid)' }}
              >
                <span className="font-mono text-[10px] uppercase tracking-wider w-28 shrink-0 pt-0.5" style={tv.muted}>{row.label}</span>
                <div className="flex-1 flex items-center gap-2">
                  <p className="font-mono text-xs" style={tv.text}>{row.val}</p>
                  {row.label === 'Original URL' && (
                    <button onClick={() => navigator.clipboard?.writeText(row.val)} className="shrink-0">
                      <Copy size={11} style={tv.faint} />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>

          <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
            <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Redirect Chain</p>
            </div>
            <div className="p-5 space-y-3">
              {analysisResult.redirectChain.map((hop, i) => (
                <div key={i} className="flex items-center gap-3">
                  <div className="w-6 h-6 rounded-full flex items-center justify-center text-[9px] font-mono shrink-0"
                    style={{ backgroundColor: 'var(--tw-panel-alt)', color: 'var(--tw-text-muted)' }}
                  >
                    {i + 1}
                  </div>
                  <div className="flex-1 space-y-0.5">
                    <p className="font-mono text-xs" style={tv.text}>{hop.from}</p>
                    <div className="flex items-center gap-2">
                      <ExternalLink size={10} style={tv.muted} />
                      <p className="font-mono text-xs" style={tv.muted}>{hop.to}</p>
                    </div>
                  </div>
                  <span className={`font-mono text-[10px] px-2 py-0.5 rounded-sm ${
                    hop.status >= 300 && hop.status < 400
                      ? 'bg-[color-mix(in_srgb,var(--tw-medium),transparent)] text-[var(--tw-medium)]'
                      : hop.status >= 400
                      ? 'bg-[color-mix(in_srgb,var(--tw-critical),transparent)] text-[var(--tw-critical)]'
                      : 'bg-[color-mix(in_srgb,var(--tw-low),transparent)] text-[var(--tw-low)]'
                  }`}>
                    {hop.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Domain Intelligence */}
        <div className="rounded-sm overflow-hidden mb-6" style={tv.panelBorder}>
          <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Domain Intelligence — {analysisResult.finalDomain}</p>
          </div>
          <div className="grid md:grid-cols-2 divide-y md:divide-y-0 md:divide-x" style={{ borderColor: 'var(--tw-border-mid)' }}>
            <div className="p-5 space-y-3">
              {[
                { label: 'Lookalike Of', val: analysisResult.domainIntel.lookalikeOf || 'None detected' },
                { label: 'Similarity Score', val: analysisResult.domainIntel.similarityScore ? `${analysisResult.domainIntel.similarityScore}%` : 'N/A' },
                { label: 'Registrar', val: analysisResult.domainIntel.registrar || 'Unknown' },
                { label: 'Hosting Provider', val: analysisResult.domainIntel.hostingProvider || 'Unknown' },
                { label: 'Country', val: analysisResult.domainIntel.country || 'Unknown' },
              ].map(row => (
                <div key={row.label} className="space-y-0.5">
                  <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>{row.label}</p>
                  <p className="font-mono text-xs" style={tv.text}>{row.val}</p>
                </div>
              ))}
            </div>
            <div className="p-5 space-y-3">
              {analysisResult.domainIntel.tlsInfo && (
                <>
                  <p className="font-mono text-[10px] uppercase tracking-wider mb-2" style={tv.muted}>TLS Information</p>
                  {[
                    { label: 'Valid Certificate', val: analysisResult.domainIntel.tlsInfo.valid ? 'Yes' : 'No' },
                    { label: 'Issuer', val: analysisResult.domainIntel.tlsInfo.issuer },
                    { label: 'Expires', val: analysisResult.domainIntel.tlsInfo.expires },
                  ].map(row => (
                    <div key={row.label} className="space-y-0.5">
                      <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>{row.label}</p>
                      <p className="font-mono text-xs" style={tv.text}>{row.val}</p>
                    </div>
                  ))}
                </>
              )}
              <div className="pt-2 border-t space-y-2" style={{ borderColor: 'var(--tw-border-mid)' }}>
                <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Suspicious Parameters</p>
                {analysisResult.suspiciousParams.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {analysisResult.suspiciousParams.map((param, i) => (
                      <span key={i} className="font-mono text-xs px-2 py-0.5 rounded-sm"
                        style={{ backgroundColor: 'var(--tw-panel-alt)', color: 'var(--tw-text-muted)' }}
                      >
                        {param}
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="font-mono text-xs" style={tv.faint}>None detected</p>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Related Evidence */}
        {analysisResult.relatedEmail && (
          <div className="rounded-sm p-4 mb-6 flex items-center justify-between"
            style={{ backgroundColor: 'var(--tw-panel-alt)', border: '1px solid var(--tw-border)' }}
          >
            <div className="flex items-center gap-3">
              <Hash size={14} style={tv.muted} />
              <div>
                <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Related Email</p>
                <p className="font-mono text-xs" style={tv.text}>{analysisResult.relatedEmail}</p>
              </div>
            </div>
            <Link to="/app/investigate" className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
              style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
            >
              View Email →
            </Link>
          </div>
        )}

        {/* Disclaimer */}
        <div className="rounded-sm p-4 flex items-start gap-3"
          style={{ backgroundColor: 'var(--tw-canvas-mid)', border: '1px solid var(--tw-border)' }}
        >
          <Shield size={14} className="mt-0.5 shrink-0" style={tv.medium} />
          <p className="text-xs leading-relaxed" style={tv.muted}>
            Simulated URL Analysis Result. No actual network requests were made to this URL.
            Analysis is based on static enrichment using threat intelligence feeds and pattern matching.
            {analysisResult.disclaimer}
          </p>
        </div>
      </div>
    </div>
  );
}