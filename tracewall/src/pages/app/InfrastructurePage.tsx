import { useState, useCallback, useEffect, useMemo } from 'react';
import { Globe, MapPin, Server, AlertTriangle, CheckCircle, Download, Shield, FileCheck, Copy, ExternalLink, Activity, Database, Wifi, ShieldAlert, Network, Brain } from 'lucide-react';
import { motion } from 'framer-motion';
import { tv } from '../../lib/styles';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { SeverityBadge } from '../../components/ui/SeverityBadge';
import { EvidenceStamp } from '../../components/ui/EvidenceStamp';
import { asteronIpIntel, asteronDomainIntel } from '../../data/mockData';
import IPLocationMap from '../../components/maps/IPLocationMap';
import { request as apiRequest } from '../../lib/mockBackend';

export interface ProviderStatusItem {
  name: string;
  status: 'SUCCESS' | 'UNAVAILABLE' | 'FAILED' | 'NOT CONFIGURED';
  detail?: string | null;
  data?: any;
}

function safeText(value: unknown, fallback = 'N/A'): string {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) return value.map(item => safeText(item, '')).filter(Boolean).join(', ') || fallback;
  if (value && typeof value === 'object') {
    const structured = value as { source?: unknown; detail?: unknown; text?: unknown; message?: unknown };
    if (structured.source || structured.detail) {
      return [structured.source, structured.detail].map(item => safeText(item, '')).filter(Boolean).join(': ') || fallback;
    }
    if (structured.text || structured.message) return safeText(structured.text || structured.message, fallback);
    try {
      return JSON.stringify(value);
    } catch {
      return fallback;
    }
  }
  return fallback;
}

function isValidIpInput(value: string): boolean {
  if (value.includes(':')) return /^[0-9a-f:]+$/i.test(value) && value.includes('::');
  const octets = value.split('.');
  return octets.length === 4 && octets.every(octet => /^(0|[1-9]\d{0,2})$/.test(octet) && Number(octet) <= 255);
}

interface AnonymizationInfo {
  vpn: { status: string; confidence: number; sources: string[] };
  proxy: { status: string; confidence: number; sources: string[] };
  tor: { status: string; confidence: number; sources: string[] };
  tunneling: { status: string; confidence: number };
  hosting: { status: string };
}

interface FraudInfo {
  score: number | null;
  status: string;
  indicators: string[];
}

interface ReputationInfo {
  riskScore: number;
  reputation: string;
  confidence: string;
}

interface AIAssessment {
  overallAssessment?: string;
  majorRiskIndicators?: string[];
  vpnProxyTorInterpretation?: string;
  fraudIndicators?: string[];
  abuseIndicators?: string[];
  threatIntelligence?: string;
  importantEvidence?: string[];
  recommendedAction?: string;
  confidence?: string;
  uncertainty?: string;
  raw?: string;
}

interface IPAnalysisResult {
  id: string;
  ip: string;
  asn: string;
  asnName: string;
  isp: string;
  hostingProvider: string;
  country: string;
  region: string;
  city: string;
  latitude?: number | null;
  longitude?: number | null;
  isVpn: boolean;
  isTor: boolean;
  isProxy: boolean;
  isCloud: boolean;
  isOpenRelay: boolean;
  reputation: 'POOR' | 'NEUTRAL' | 'GOOD';
  firstSeen: string;
  lastSeen: string;
  abuseReports: number;
  abuseConfidenceScore?: number;
  vtMaliciousDetections?: number;
  vtSuspiciousDetections?: number;
  otxPulseCount?: number;
  hostnames?: string[];
  riskScore: number;
  verdict: string;
  confidence: string;
  severity: string;
  providers?: ProviderStatusItem[];
  anonymization?: AnonymizationInfo;
  fraud?: FraudInfo;
  reputationInfo?: ReputationInfo;
  aiAssessment?: AIAssessment;
  evidence?: string[];
  disclaimer: string;
}

interface DomainAnalysisResult {
  id: string;
  domain: string;
  parentDomain: string;
  similarityScore: number;
  registeredDaysAgo: number;
  registrationDate: string;
  registrar: string;
  nameservers: string[];
  mxRecords: string[];
  spfRecord: string;
  dmarcRecord: string;
  aRecords?: string[];
  hostingProvider: string;
  ipReputation: string;
  firstSeen: string;
  lastSeen: string;
  relatedDomains: string[];
  vtMaliciousDetections?: number;
  vtSuspiciousDetections?: number;
  otxPulseCount?: number;
  riskScore: number;
  verdict: string;
  confidence: string;
  severity: string;
  providers?: ProviderStatusItem[];
  evidence?: string[];
  disclaimer: string;
}

const demoIPAnalysis: IPAnalysisResult = {
  id: 'IP-2026-001',
  ip: '203.0.113.42',
  asn: 'AS63949',
  asnName: 'Linode LLC',
  isp: 'Linode',
  hostingProvider: 'Linode',
  country: 'Singapore',
  region: 'Central Region',
  city: 'Singapore',
  latitude: 1.3521,
  longitude: 103.8198,
  isVpn: false,
  isTor: false,
  isProxy: false,
  isCloud: true,
  isOpenRelay: false,
  reputation: 'NEUTRAL',
  firstSeen: '2026-08-28',
  lastSeen: '2026-09-08',
  abuseReports: 1,
  riskScore: 45,
  verdict: 'NEUTRAL',
  confidence: 'MEDIUM',
  severity: 'MEDIUM',
  disclaimer: 'Estimated infrastructure location only. Demo mode.',
};

const demoDomainAnalysis: DomainAnalysisResult = {
  id: 'DOM-2026-001',
  domain: 'asteron-billing.example',
  parentDomain: 'asteron.example',
  similarityScore: 91,
  registeredDaysAgo: 11,
  registrationDate: '2026-08-18',
  registrar: 'GoDaddy LLC',
  nameservers: ['ns1.linode.example', 'ns2.linode.example'],
  mxRecords: ['mail.asteron-billing.example'],
  spfRecord: 'v=spf1 include:mailer-relay-sg3.example ~all',
  dmarcRecord: 'v=DMARC1; p=none;',
  hostingProvider: 'Linode LLC (SG)',
  ipReputation: 'NEUTRAL',
  firstSeen: '2026-08-28',
  lastSeen: '2026-09-08',
  relatedDomains: ['asteron-login.example', 'asteron-docs.example'],
  riskScore: 72,
  verdict: 'SUSPICIOUS',
  confidence: 'HIGH',
  severity: 'HIGH',
  disclaimer: 'Simulated WHOIS and DNS data for demo purposes only.',
};

const demoIPs = [
  {
    id: 'demo-ip-1',
    label: '203.0.113.42 (Linode SG)',
    description: 'Cloud hosting infrastructure in Singapore',
    risk: 'MEDIUM',
  },
  {
    id: 'demo-ip-2',
    label: '203.0.113.81 (AWS US)',
    description: 'Amazon Web Services infrastructure',
    risk: 'MEDIUM',
  },
];

const demoDomains = [
  {
    id: 'demo-dom-1',
    label: 'asteron-billing.example',
    description: 'Lookalike domain with 91% similarity',
    risk: 'HIGH',
  },
  {
    id: 'demo-dom-2',
    label: 'asteron.example',
    description: 'Legitimate organizational domain',
    risk: 'LOW',
  },
];

const analysisSteps = [
  'Validating input format...',
  'Querying IP/Domain databases...',
  'Enriching geolocation data...',
  'Checking AbuseIPDB reputation...',
  'Querying VirusTotal threat engines...',
  'Fetching AlienVault OTX pulse intelligence...',
  'Checking IPWhois & IPinfo registry data...',
  'Resolving DNS & reverse PTR records...',
  'Querying IPQualityScore fraud intelligence...',
  'Checking ProxyCheck anonymization detection...',
  'Calculating evidence risk assessment...',
  'Generating AI assessment (Llama 3)...',
  'Generating analysis report...',
];

function AnalysisProgress({ onComplete }: { onComplete: () => void }) {
  const [step, setStep] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setStep(prev => {
        if (prev >= analysisSteps.length - 1) {
          clearInterval(interval);
          setTimeout(onComplete, 300);
          return prev;
        }
        return prev + 1;
      });
    }, 350);
    return () => clearInterval(interval);
  }, [onComplete]);

  const progress = ((step + 1) / analysisSteps.length) * 100;

  return (
    <div className="min-h-[50vh] flex flex-col items-center justify-center gap-6 p-10" style={tv.canvas}>
      <div className="w-full max-w-sm space-y-4">
        <div className="text-center">
          <p className="font-mono text-[10px] tracking-[0.2em] uppercase mb-2" style={tv.muted}>Analysis in Progress</p>
          <p className="font-serif text-xl" style={tv.text}>Enriching Infrastructure</p>
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

export default function InfrastructurePage() {
  const [step, setStep] = useState<'intake' | 'analyzing' | 'results'>('intake');
  const [analysisType, setAnalysisType] = useState<'ip' | 'domain'>('ip');
  const [inputMethod, setInputMethod] = useState<'paste' | 'demo'>('paste');
  const [pastedInput, setPastedInput] = useState('');
  const [selectedDemoId, setSelectedDemoId] = useState('demo-ip-1');
  const [analysisResult, setAnalysisResult] = useState<IPAnalysisResult | DomainAnalysisResult | null>(null);
  const [inputError, setInputError] = useState<string | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [isLiveResult, setIsLiveResult] = useState(false);

  const startAnalysis = useCallback(async () => {
    if (!acknowledged) return;
    setInputError(null);

    if (inputMethod === 'demo') {
      setIsLiveResult(false);
      let result: IPAnalysisResult | DomainAnalysisResult | null = null;
      if (analysisType === 'ip') {
        const demoData = asteronIpIntel[0] || demoIPAnalysis;
        result = { 
          ...demoData, 
          id: `IP-${Date.now()}`, 
          riskScore: demoData.reputation === 'POOR' ? 65 : 35, 
          verdict: demoData.reputation === 'POOR' ? 'SUSPICIOUS' : 'NEUTRAL', 
          confidence: 'MEDIUM', 
          severity: demoData.reputation === 'POOR' ? 'HIGH' : 'MEDIUM',
          reputation: demoData.reputation as IPAnalysisResult['reputation'],
          hostingProvider: demoData.hostingProvider || demoData.provider || 'Unknown',
          abuseReports: demoData.abuseReports || 0,
          evidence: Array.isArray((demoData as any).evidence)
            ? (demoData as any).evidence
            : (demoData as any).evidence
              ? [(demoData as any).evidence]
              : [],
        };
      } else {
        const demoData = asteronDomainIntel[0] || demoDomainAnalysis;
        result = {
          ...demoData,
          id: `DOM-${Date.now()}`,
          riskScore: demoData.reputation === 'SUSPICIOUS' ? 72 : 35,
          verdict: demoData.reputation === 'SUSPICIOUS' ? 'SUSPICIOUS' : 'NEUTRAL',
          confidence: 'HIGH',
          severity: demoData.reputation === 'SUSPICIOUS' ? 'HIGH' : 'MEDIUM',
          evidence: Array.isArray((demoData as any).evidence)
            ? (demoData as any).evidence
            : (demoData as any).evidence
              ? [(demoData as any).evidence]
              : [],
        };
      }
      setAnalysisResult(result);
      setStep('analyzing');
      setTimeout(() => setStep('results'), 1500);
      return;
    }

    if (inputMethod === 'paste' && pastedInput.trim()) {
      if (analysisType === 'ip' && !isValidIpInput(pastedInput.trim())) {
        setInputError(`Invalid IP address format: "${pastedInput.trim()}"`);
        return;
      }
      setStep('analyzing');
      try {
        if (analysisType === 'ip') {
          const data = await apiRequest('/analyze/ip', { method: 'POST', body: JSON.stringify({ ip: pastedInput.trim() }) });
          setIsLiveResult(true);
          setAnalysisResult(data);
          setStep('results');
        } else {
          const data = await apiRequest('/analyze/domain', { method: 'POST', body: JSON.stringify({ domain: pastedInput.trim() }) });
          setIsLiveResult(true);
          setAnalysisResult(data);
          setStep('results');
        }
      } catch (err: any) {
        setStep('intake');
        setInputError(err.message || 'Failed to complete analysis');
      }
    }
  }, [acknowledged, analysisType, inputMethod, pastedInput]);

  const resetAnalysis = useCallback(() => {
    setStep('intake');
    setAnalysisResult(null);
    setPastedInput('');
    setInputError(null);
    setAcknowledged(false);
    setIsLiveResult(false);
  }, []);

  const isIP = analysisResult ? 'ip' in analysisResult || (analysisResult as any).targetType === 'ip' : false;
  const mapRecords = useMemo(() => {
    if (!isIP || !analysisResult) return [];
    const ipRes = analysisResult as IPAnalysisResult;
    return [{
      ip: ipRes.ip,
      country: ipRes.country,
      region: ipRes.region,
      city: ipRes.city,
      latitude: Number.isFinite(ipRes.latitude) ? ipRes.latitude! : undefined,
      longitude: Number.isFinite(ipRes.longitude) ? ipRes.longitude! : undefined,
      asn: ipRes.asn,
      asnName: ipRes.asnName,
      isp: ipRes.isp,
      hostingProvider: ipRes.hostingProvider,
      reputation: ipRes.reputation,
      riskScore: ipRes.riskScore,
      verdict: ipRes.verdict,
    }];
  }, [analysisResult, isIP]);

  if (step === 'intake') {
    return (
      <div className="min-h-screen" style={tv.canvas}>
        <div className="max-w-4xl mx-auto px-6 lg:px-10 py-10 space-y-8">
          <div className="space-y-2">
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Infrastructure Analysis</p>
            <h1 className="font-serif text-3xl" style={tv.text}>IP & Domain Intelligence</h1>
          </div>

          {/* Privacy notice */}
          <div className="rounded-sm p-5 space-y-3"
            style={{ backgroundColor: 'var(--tw-canvas-mid)', border: '1px solid var(--tw-border)' }}
          >
            <div className="flex items-start gap-3">
              <AlertTriangle size={15} className="mt-0.5 shrink-0" style={tv.medium} />
              <div className="space-y-2">
                <p className="font-mono text-[10px] tracking-[0.15em] uppercase" style={tv.medium}>Important Limitation</p>
                <p className="text-xs leading-relaxed" style={tv.muted}>
                  IP geolocation represents estimated infrastructure locations — not the physical location or identity of any person.
                  Cloud servers and hosting providers may not represent the attacker's actual location.
                  A compromised system may be used as a relay.
                </p>
                <label className="flex items-center gap-2 cursor-pointer pt-1">
                  <input type="checkbox" checked={acknowledged} onChange={e => setAcknowledged(e.target.checked)}
                    style={{ accentColor: 'var(--tw-burgundy)' }}
                    className="w-3.5 h-3.5"
                  />
                  <span className="text-xs" style={tv.text}>
                    I understand the limitations of geolocation data.
                  </span>
                </label>
              </div>
            </div>
          </div>

          {/* Analysis type */}
          <div className="space-y-4">
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Analysis Type</p>
            <div className="flex gap-2">
              {[
                { id: 'ip', label: 'IP Address', icon: Server },
                { id: 'domain', label: 'Domain', icon: Globe },
              ].map(m => (
                <button key={m.id} onClick={() => { setAnalysisType(m.id as 'ip' | 'domain'); setInputError(null); }}
                  className="font-mono text-xs tracking-wide px-4 py-2 rounded-sm border transition-colors flex items-center gap-2"
                  style={analysisType === m.id
                    ? { backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6', borderColor: 'var(--tw-burgundy)' }
                    : { backgroundColor: 'transparent', color: 'var(--tw-text-muted)', borderColor: 'var(--tw-border-strong)' }
                  }
                >
                  <m.icon size={12} />
                  {m.label}
                </button>
              ))}
            </div>

            {/* Input method */}
            <div className="space-y-2">
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Input Method</p>
              <div className="flex gap-2">
                {[
                  { id: 'paste', label: 'Live Analysis' },
                  { id: 'demo', label: 'Demo' },
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
                    value={pastedInput}
                    onChange={e => setPastedInput(e.target.value)}
                    placeholder={analysisType === 'ip' ? '8.8.8.8' : 'google.com'}
                    className="w-full p-4 font-mono text-xs rounded-sm focus:outline-none placeholder:opacity-40"
                    style={tv.input}
                  />
                  {inputError && (
                    <p className="font-mono text-xs" style={{ color: 'var(--tw-critical)' }}>{inputError}</p>
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
                      {(analysisType === 'ip' ? demoIPs : demoDomains).map(d => <option key={d.id} value={d.id}>{d.label}</option>)}
                    </select>
                  </div>
                  <div className="space-y-1">
                    <p className="text-sm font-medium" style={tv.text}>
                      {(analysisType === 'ip' ? demoIPs : demoDomains).find(d => d.id === selectedDemoId)?.label}
                    </p>
                    <p className="font-mono text-xs" style={tv.muted}>
                      {(analysisType === 'ip' ? demoIPs : demoDomains).find(d => d.id === selectedDemoId)?.description}
                    </p>
                    <span className={`font-mono text-[10px] px-2 py-0.5 rounded-sm ${
                      (analysisType === 'ip' ? demoIPs : demoDomains).find(d => d.id === selectedDemoId)?.risk === 'HIGH'
                        ? 'bg-[color-mix(in_srgb,var(--tw-critical),transparent)] text-[var(--tw-critical)]'
                        : 'bg-[color-mix(in_srgb,var(--tw-low),transparent)] text-[var(--tw-low)]'
                    }`}>
                      Risk: {(analysisType === 'ip' ? demoIPs : demoDomains).find(d => d.id === selectedDemoId)?.risk}
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>

          <button onClick={startAnalysis} disabled={!acknowledged || (inputMethod === 'paste' && !pastedInput.trim())}
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
    return <AnalysisProgress onComplete={() => {}} />;
  }

  if (!analysisResult) return null;

  return (
    <div className="min-h-screen" style={tv.canvas}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="space-y-1">
            <div className="flex items-center gap-3">
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>
                Analysis Complete · {analysisResult.id}
              </p>
              {isLiveResult ? (
                <span className="font-mono text-[9px] uppercase px-2 py-0.5 rounded-sm border"
                  style={{ backgroundColor: 'color-mix(in srgb, var(--tw-low) 18%, transparent)', borderColor: 'var(--tw-low)', color: 'var(--tw-low)' }}
                >
                  LIVE DATA
                </span>
              ) : (
                <DemoLabel />
              )}
            </div>
            <h1 className="font-serif text-2xl" style={tv.text}>
              {isIP ? `IP: ${(analysisResult as IPAnalysisResult).ip}` : `Domain: ${(analysisResult as DomainAnalysisResult).domain}`}
            </h1>
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
              alert(`Case ${caseId} created from infrastructure analysis.`);
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

        {/* IP location map */}
        {isIP && (
          <IPLocationMap
            records={mapRecords}
            selectedIp={(analysisResult as IPAnalysisResult).ip}
          />
        )}

        {/* Verdict & Indicators */}
        <div className="grid lg:grid-cols-3 gap-6">
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
            {isIP ? (
              <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
                <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Infrastructure Indicators</p>
                </div>
                <div className="p-5 grid grid-cols-2 sm:grid-cols-3 gap-4">
                  {[
                    { label: 'VPN', val: (analysisResult as IPAnalysisResult).isVpn ? 'Yes' : 'No' },
                    { label: 'Tor Exit Node', val: (analysisResult as IPAnalysisResult).isTor ? 'Yes' : 'No' },
                    { label: 'Proxy', val: (analysisResult as IPAnalysisResult).isProxy ? 'Yes' : 'No' },
                    { label: 'Cloud Host', val: (analysisResult as IPAnalysisResult).isCloud ? 'Yes' : 'No' },
                    { label: 'Abuse Reports', val: (analysisResult as IPAnalysisResult).abuseReports.toString() },
                    { label: 'VT Detections', val: (analysisResult as IPAnalysisResult).vtMaliciousDetections !== undefined ? `${(analysisResult as IPAnalysisResult).vtMaliciousDetections} engines` : 'N/A' },
                  ].map(item => (
                    <div key={item.label} className="space-y-0.5">
                      <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>{item.label}</p>
                      <p className="font-mono text-xs font-medium" style={tv.text}>{item.val}</p>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
                <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Domain Indicators</p>
                </div>
                <div className="p-5 grid grid-cols-2 sm:grid-cols-3 gap-4">
                  {[
                    { label: 'Domain Age', val: (analysisResult as DomainAnalysisResult).registeredDaysAgo > 0 ? `${(analysisResult as DomainAnalysisResult).registeredDaysAgo} days` : 'Unknown' },
                    { label: 'Registrar', val: (analysisResult as DomainAnalysisResult).registrar },
                    { label: 'Hosting / Resolved', val: (analysisResult as DomainAnalysisResult).hostingProvider },
                    { label: 'VT Detections', val: (analysisResult as DomainAnalysisResult).vtMaliciousDetections !== undefined ? `${(analysisResult as DomainAnalysisResult).vtMaliciousDetections} engines` : 'N/A' },
                    { label: 'OTX Threat Pulses', val: (analysisResult as DomainAnalysisResult).otxPulseCount !== undefined ? (analysisResult as DomainAnalysisResult).otxPulseCount!.toString() : 'N/A' },
                    { label: 'IP Reputation', val: (analysisResult as DomainAnalysisResult).ipReputation },
                  ].map(item => (
                    <div key={item.label} className="space-y-0.5">
                      <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>{item.label}</p>
                      <p className="font-mono text-xs font-medium" style={tv.text}>{item.val}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Provider Intelligence Status Panel */}
        {analysisResult.providers && analysisResult.providers.length > 0 && (
          <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
            <div className="px-5 py-3 border-b flex items-center justify-between" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <div className="flex items-center gap-2">
                <Activity size={13} style={tv.burg} />
                <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Provider Intelligence Feeds</p>
              </div>
              <span className="font-mono text-[10px]" style={tv.muted}>
                {analysisResult.providers.filter(p => p.status === 'SUCCESS').length} / {analysisResult.providers.length} Connected
              </span>
            </div>
            <div className="p-5 grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {analysisResult.providers.map(p => (
                <div key={p.name} className="p-3 rounded-sm border space-y-1" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-medium" style={tv.text}>{p.name}</span>
                    <span className={`font-mono text-[9px] px-1.5 py-0.5 rounded-sm uppercase ${
                      p.status === 'SUCCESS' ? 'bg-[color-mix(in_srgb,var(--tw-low),transparent)] text-[var(--tw-low)]' :
                      p.status === 'NOT CONFIGURED' ? 'bg-[color-mix(in_srgb,var(--tw-medium),transparent)] text-[var(--tw-medium)]' :
                      'bg-[color-mix(in_srgb,var(--tw-critical),transparent)] text-[var(--tw-critical)]'
                    }`}>
                      {p.status}
                    </span>
                  </div>
                  {p.detail && (
                    <p className="font-mono text-[10px]" style={tv.muted}>{safeText(p.detail)}</p>
                  )}
                  {p.data && p.name === 'AbuseIPDB' && (
                    <p className="font-mono text-[10px]" style={tv.text}>
                      Abuse Confidence: {p.data.abuseConfidenceScore}% · Reports: {p.data.totalReports}
                    </p>
                  )}
                  {p.data && p.name === 'VirusTotal' && (
                    <p className="font-mono text-[10px]" style={tv.text}>
                      Malicious: {p.data.stats?.malicious ?? 0} · Suspicious: {p.data.stats?.suspicious ?? 0} · Harmless: {p.data.stats?.harmless ?? 0}
                    </p>
                  )}
                  {p.data && p.name === 'OTX' && (
                    <p className="font-mono text-[10px]" style={tv.text}>
                      Threat Pulses: {p.data.pulseCount ?? 0}
                    </p>
                  )}
                  {p.data && p.name === 'IPWhois' && (
                    <p className="font-mono text-[10px]" style={tv.text}>
                      ISP: {p.data.isp || 'N/A'} · Location: {[p.data.city, p.data.country].filter(Boolean).join(', ')}
                    </p>
                  )}
                  {p.data && p.name === 'IPinfo' && (
                    <p className="font-mono text-[10px]" style={tv.text}>
                      Org: {p.data.org || 'N/A'} · Coordinates: {p.data.latitude ? `${p.data.latitude}, ${p.data.longitude}` : 'N/A'}
                    </p>
                  )}
                  {p.data && p.name === 'IPQualityScore' && (
                    <p className="font-mono text-[10px]" style={tv.text}>
                      Fraud Score: {p.data.fraudScore ?? 'N/A'} · VPN: {p.data.vpn ? 'Yes' : 'No'} · Proxy: {p.data.proxy ? 'Yes' : 'No'} · Tor: {p.data.tor ? 'Yes' : 'No'}
                    </p>
                  )}
                  {p.data && p.name === 'ProxyCheck' && (
                    <p className="font-mono text-[10px]" style={tv.text}>
                      Proxy: {p.data.proxy ? 'Yes' : 'No'} · Risk: {p.data.risk ?? 0} · Type: {p.data.type || 'N/A'}
                    </p>
                  )}
                  {p.data && p.name === 'Llama3 (Groq)' && (
                    <p className="font-mono text-[10px]" style={tv.text}>
                      AI Assessment: {p.data.overallAssessment ? p.data.overallAssessment.slice(0, 60) + '...' : 'See AI Assessment section'}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Anonymization / VPN / Proxy / Tor Indicators (IP only) */}
        {isIP && (analysisResult as IPAnalysisResult).anonymization && (
          <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
            <div className="px-5 py-3 border-b flex items-center gap-2" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <ShieldAlert size={13} style={tv.medium} />
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Anonymization & Proxy Detection</p>
            </div>
            <div className="p-5 grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {[
                { label: 'VPN', val: (analysisResult as IPAnalysisResult).isVpn ? 'Yes' : 'No', status: (analysisResult as IPAnalysisResult).anonymization!.vpn.status, confidence: (analysisResult as IPAnalysisResult).anonymization!.vpn.confidence, sources: (analysisResult as IPAnalysisResult).anonymization!.vpn.sources, icon: Wifi },
                { label: 'Proxy', val: (analysisResult as IPAnalysisResult).isProxy ? 'Yes' : 'No', status: (analysisResult as IPAnalysisResult).anonymization!.proxy.status, confidence: (analysisResult as IPAnalysisResult).anonymization!.proxy.confidence, sources: (analysisResult as IPAnalysisResult).anonymization!.proxy.sources, icon: Network },
                { label: 'Tor Exit Node', val: (analysisResult as IPAnalysisResult).isTor ? 'Yes' : 'No', status: (analysisResult as IPAnalysisResult).anonymization!.tor.status, confidence: (analysisResult as IPAnalysisResult).anonymization!.tor.confidence, sources: (analysisResult as IPAnalysisResult).anonymization!.tor.sources, icon: Database },
                { label: 'Hosting/Cloud', val: (analysisResult as IPAnalysisResult).isCloud ? 'Yes' : 'No', status: (analysisResult as IPAnalysisResult).anonymization!.hosting.status, confidence: 0, sources: [], icon: Server },
              ].map(item => {
                const isDetected = item.val === 'Yes';
                const statusColor = isDetected
                  ? 'bg-[color-mix(in_srgb,var(--tw-critical),transparent)] text-[var(--tw-critical)]'
                  : 'bg-[color-mix(in_srgb,var(--tw-low),transparent)] text-[var(--tw-low)]';
                return (
                  <div key={item.label} className="p-3 rounded-sm border space-y-2" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-medium flex items-center gap-1.5" style={tv.text}>
                        <item.icon size={12} />
                        {item.label}
                      </span>
                      <span className={`font-mono text-[9px] px-1.5 py-0.5 rounded-sm uppercase ${statusColor}`}>
                        {item.val}
                      </span>
                    </div>
                    <p className="font-mono text-[10px]" style={tv.muted}>Status: <span style={tv.text}>{item.status}</span></p>
                    {item.confidence > 0 && (
                      <p className="font-mono text-[10px]" style={tv.muted}>Confidence: <span style={tv.text}>{item.confidence}%</span></p>
                    )}
                    {item.sources && item.sources.length > 0 && (
                      <p className="font-mono text-[10px]" style={tv.muted}>Sources: <span style={tv.text}>{item.sources.join(', ')}</span></p>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Fraud Intelligence (IP only) */}
        {isIP && (analysisResult as IPAnalysisResult).fraud && (
          <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
            <div className="px-5 py-3 border-b flex items-center gap-2" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <Shield size={13} style={tv.medium} />
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Fraud Intelligence</p>
            </div>
            <div className="p-5 space-y-4">
              {(analysisResult as IPAnalysisResult).fraud!.score !== null ? (
                <>
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs" style={tv.muted}>IPQualityScore Fraud Score</span>
                    <div className="flex items-center gap-3">
                      <div className="relative w-24 h-4 bg-[color-mix(in_srgb,var(--tw-border),transparent)] rounded-sm overflow-hidden">
                        <div className="h-full rounded-sm"
                          style={{
                            width: `${(analysisResult as IPAnalysisResult).fraud!.score}%`,
                            backgroundColor: (analysisResult as IPAnalysisResult).fraud!.score! >= 67 ? 'var(--tw-critical)' : (analysisResult as IPAnalysisResult).fraud!.score! >= 33 ? 'var(--tw-medium)' : 'var(--tw-low)'
                          }}
                        />
                      </div>
                      <span className="font-mono text-lg font-medium" style={tv.text}>{(analysisResult as IPAnalysisResult).fraud!.score}</span>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                    <div className="p-3 rounded-sm border" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                      <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Fraud Status</p>
                      <p className="font-mono text-sm font-medium mt-0.5" style={tv.text}>{(analysisResult as IPAnalysisResult).fraud!.status}</p>
                    </div>
                    <div className="p-3 rounded-sm border" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                      <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>ProxyCheck Risk</p>
                      <p className="font-mono text-sm font-medium mt-0.5" style={tv.text}>{(analysisResult as IPAnalysisResult).providers?.find(p => p.name === 'ProxyCheck')?.data?.risk ?? 'N/A'}</p>
                    </div>
                    <div className="p-3 rounded-sm border" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                      <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Connection Type</p>
                      <p className="font-mono text-sm font-medium mt-0.5" style={tv.text}>{(analysisResult as IPAnalysisResult).providers?.find(p => p.name === 'IPQualityScore')?.data?.connectionType || 'N/A'}</p>
                    </div>
                    <div className="p-3 rounded-sm border" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                      <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Bot Detection</p>
                      <p className="font-mono text-sm font-medium mt-0.5" style={tv.text}>{(analysisResult as IPAnalysisResult).providers?.find(p => p.name === 'IPQualityScore')?.data?.bot ? 'Yes' : 'No'}</p>
                    </div>
                  </div>
                </>
              ) : (
                <p className="font-mono text-xs" style={tv.muted}>Fraud intelligence not available for this IP.</p>
              )}
              {(analysisResult as IPAnalysisResult).fraud!.indicators && (analysisResult as IPAnalysisResult).fraud!.indicators.length > 0 && (
                <div className="space-y-1">
                  <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Fraud Indicators</p>
                  <div className="flex flex-wrap gap-1.5">
                    {(analysisResult as IPAnalysisResult).fraud!.indicators.map((ind, i) => (
                      <span key={i} className="font-mono text-[10px] px-2 py-0.5 rounded-sm"
                        style={{ backgroundColor: 'color-mix(in srgb, var(--tw-critical) 15%, transparent)', color: 'var(--tw-critical)' }}
                      >
                        {ind}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Reputation & Confidence (IP only) */}
        {isIP && (analysisResult as IPAnalysisResult).reputationInfo && (
          <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
            <div className="px-5 py-3 border-b flex items-center gap-2" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <Activity size={13} style={tv.burg} />
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Reputation & Confidence</p>
            </div>
            <div className="p-5 grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="p-4 rounded-sm border text-center" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Reputation</p>
                <p className={`font-mono text-xl font-medium mt-1 ${
                  (analysisResult as IPAnalysisResult).reputationInfo!.reputation === 'POOR' ? 'text-[var(--tw-critical)]' :
                  (analysisResult as IPAnalysisResult).reputationInfo!.reputation === 'GOOD' ? 'text-[var(--tw-low)]' :
                  'text-[var(--tw-medium)]'
                }`}>
                  {(analysisResult as IPAnalysisResult).reputationInfo!.reputation}
                </p>
              </div>
              <div className="p-4 rounded-sm border text-center" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Assessment Confidence</p>
                <p className={`font-mono text-xl font-medium mt-1 ${
                  (analysisResult as IPAnalysisResult).reputationInfo!.confidence === 'HIGH' ? 'text-[var(--tw-low)]' :
                  (analysisResult as IPAnalysisResult).reputationInfo!.confidence === 'MEDIUM' ? 'text-[var(--tw-medium)]' :
                  'text-[var(--tw-critical)]'
                }`}>
                  {(analysisResult as IPAnalysisResult).reputationInfo!.confidence}
                </p>
              </div>
              <div className="p-4 rounded-sm border text-center" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Evidence Providers</p>
                <p className="font-mono text-xl font-medium mt-1" style={tv.text}>
                  {analysisResult.providers?.filter(p => p.status === 'SUCCESS').length ?? 0} / {analysisResult.providers?.length ?? 0}
                </p>
              </div>
            </div>
          </div>
        )}

        {/* AI Assessment (IP only, from Llama 3) */}
        {isIP && (() => {
          const aiAssessment = (analysisResult as IPAnalysisResult).aiAssessment;
          if (!aiAssessment || !aiAssessment.overallAssessment) return null;
          return (
            <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
              <div className="px-5 py-3 border-b flex items-center gap-2" style={{ borderColor: 'var(--tw-border-mid)' }}>
                <Brain size={13} style={tv.burg} />
                <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>AI Assessment (Llama 3)</p>
              </div>
              <div className="p-5 space-y-4">
                <div className="rounded-sm p-4"
                  style={{ backgroundColor: 'var(--tw-canvas-mid)', border: '1px solid var(--tw-border)' }}
                >
                  <p className="font-mono text-xs leading-relaxed" style={tv.text}>
                    {safeText(aiAssessment.overallAssessment)}
                  </p>
                </div>

                <div className="grid lg:grid-cols-2 gap-6">
                  {aiAssessment.majorRiskIndicators && aiAssessment.majorRiskIndicators.length > 0 && (
                    <div className="space-y-2">
                      <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Major Risk Indicators</p>
                      <div className="space-y-1">
                        {aiAssessment.majorRiskIndicators.map((ind, i) => (
                          <div key={i} className="flex items-start gap-2 text-xs font-mono" style={tv.text}>
                            <span style={{ color: 'var(--tw-critical)' }}>›</span>
                            <span>{safeText(ind)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {aiAssessment.vpnProxyTorInterpretation && (
                    <div className="space-y-2">
                      <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>VPN / Proxy / Tor Interpretation</p>
                      <p className="font-mono text-xs leading-relaxed" style={tv.text}>
                        {safeText(aiAssessment.vpnProxyTorInterpretation)}
                      </p>
                    </div>
                  )}
                  {aiAssessment.fraudIndicators && aiAssessment.fraudIndicators.length > 0 && (
                    <div className="space-y-2">
                      <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Fraud Indicators</p>
                      <div className="space-y-1">
                        {aiAssessment.fraudIndicators.map((ind, i) => (
                          <div key={i} className="flex items-start gap-2 text-xs font-mono" style={tv.text}>
                            <span style={{ color: 'var(--tw-critical)' }}>›</span>
                            <span>{safeText(ind)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {aiAssessment.abuseIndicators && aiAssessment.abuseIndicators.length > 0 && (
                    <div className="space-y-2">
                      <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Abuse Indicators</p>
                      <div className="space-y-1">
                        {aiAssessment.abuseIndicators.map((ind, i) => (
                          <div key={i} className="flex items-start gap-2 text-xs font-mono" style={tv.text}>
                            <span style={{ color: 'var(--tw-critical)' }}>›</span>
                            <span>{safeText(ind)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {aiAssessment.threatIntelligence && (
                    <div className="space-y-2">
                      <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Threat Intelligence</p>
                      <p className="font-mono text-xs leading-relaxed" style={tv.text}>
                        {safeText(aiAssessment.threatIntelligence)}
                      </p>
                    </div>
                  )}
                  {aiAssessment.importantEvidence && aiAssessment.importantEvidence.length > 0 && (
                    <div className="space-y-2">
                      <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Important Evidence</p>
                      <div className="space-y-1">
                        {aiAssessment.importantEvidence.map((ev, i) => (
                          <div key={i} className="flex items-start gap-2 text-xs font-mono" style={tv.text}>
                            <span style={{ color: 'var(--tw-burgundy)' }}>›</span>
                            <span>{safeText(ev)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                <div className="grid lg:grid-cols-3 gap-4">
                  {aiAssessment.recommendedAction && (
                    <div className="p-3 rounded-sm border"
                      style={{ backgroundColor: 'color-mix(in srgb, var(--tw-medium) 12%, transparent)', borderColor: 'var(--tw-border-mid)' }}
                    >
                      <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Recommended Action</p>
                      <p className="font-mono text-xs mt-1 leading-relaxed" style={tv.text}>
                        {safeText(aiAssessment.recommendedAction)}
                      </p>
                    </div>
                  )}
                  {aiAssessment.confidence && (
                    <div className="p-3 rounded-sm border"
                      style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}
                    >
                      <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>AI Confidence</p>
                      <p className="font-mono text-sm font-medium mt-0.5" style={tv.text}>
                        {safeText(aiAssessment.confidence)}
                      </p>
                    </div>
                  )}
                  {aiAssessment.uncertainty && (
                    <div className="p-3 rounded-sm border"
                      style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}
                    >
                      <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Uncertainty</p>
                      <p className="font-mono text-xs mt-1 leading-relaxed" style={tv.muted}>
                        {safeText(aiAssessment.uncertainty)}
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          );
        })()}

        {/* Traceable Evidence */}
        {analysisResult.evidence && analysisResult.evidence.length > 0 && (
          <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
            <div className="px-5 py-3 border-b flex items-center gap-2" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <Database size={13} style={tv.medium} />
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Traceable Intelligence Findings</p>
            </div>
            <div className="p-5 space-y-2">
              {analysisResult.evidence.map((ev, i) => (
                <div key={i} className="flex items-start gap-2 text-xs font-mono" style={tv.text}>
                  <span className="text-[var(--tw-burgundy)] font-bold">›</span>
                  <span>{safeText(ev)}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Detailed Analysis */}
        <div className="grid lg:grid-cols-2 gap-6">
          {isIP ? (
            <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
              <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>IP Details</p>
              </div>
              {[
                { label: 'IP Address', val: (analysisResult as IPAnalysisResult).ip },
                { label: 'ASN', val: `${(analysisResult as IPAnalysisResult).asn || 'N/A'} · ${(analysisResult as IPAnalysisResult).asnName || 'N/A'}` },
                { label: 'ISP', val: (analysisResult as IPAnalysisResult).isp },
                { label: 'Hosting Provider', val: (analysisResult as IPAnalysisResult).hostingProvider },
                { label: 'Country', val: (analysisResult as IPAnalysisResult).country },
                { label: 'Region', val: (analysisResult as IPAnalysisResult).region },
                { label: 'City', val: (analysisResult as IPAnalysisResult).city },
                { label: 'Hostnames / PTR', val: (analysisResult as IPAnalysisResult).hostnames?.join(', ') || 'None found' },
                { label: 'Reputation', val: (analysisResult as IPAnalysisResult).reputation },
                { label: 'First Seen', val: (analysisResult as IPAnalysisResult).firstSeen },
              ].map(row => (
                <div key={row.label} className="flex items-start gap-4 px-5 py-3 border-b last:border-0"
                  style={{ borderColor: 'var(--tw-border-mid)' }}
                >
                  <span className="font-mono text-[10px] uppercase tracking-wider w-32 shrink-0 pt-0.5" style={tv.muted}>{row.label}</span>
                  <div className="flex-1 flex items-center gap-2">
                    <p className="font-mono text-xs" style={tv.text}>{row.val}</p>
                    {row.label === 'IP Address' && (
                      <button onClick={() => navigator.clipboard?.writeText(row.val)} className="shrink-0">
                        <Copy size={11} style={tv.faint} />
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
              <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Domain Details</p>
              </div>
              {[
                { label: 'Domain', val: (analysisResult as DomainAnalysisResult).domain },
                { label: 'Parent Domain', val: (analysisResult as DomainAnalysisResult).parentDomain },
                { label: 'Registration Date', val: (analysisResult as DomainAnalysisResult).registrationDate },
                { label: 'Registrar', val: (analysisResult as DomainAnalysisResult).registrar },
                { label: 'Hosting / Resolved', val: (analysisResult as DomainAnalysisResult).hostingProvider },
                { label: 'First Seen', val: (analysisResult as DomainAnalysisResult).firstSeen },
                { label: 'Last Seen', val: (analysisResult as DomainAnalysisResult).lastSeen },
              ].map(row => (
                <div key={row.label} className="flex items-start gap-4 px-5 py-3 border-b last:border-0"
                  style={{ borderColor: 'var(--tw-border-mid)' }}
                >
                  <span className="font-mono text-[10px] uppercase tracking-wider w-32 shrink-0 pt-0.5" style={tv.muted}>{row.label}</span>
                  <div className="flex-1 flex items-center gap-2">
                    <p className="font-mono text-xs" style={tv.text}>{row.val}</p>
                    {row.label === 'Domain' && (
                      <button onClick={() => navigator.clipboard?.writeText(row.val)} className="shrink-0">
                        <Copy size={11} style={tv.faint} />
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          {isIP ? (
            <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
              <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Geolocation</p>
              </div>
              <div className="p-5 space-y-4">
                <div className="flex items-center gap-3 p-4 rounded-sm border"
                  style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border)' }}
                >
                  <MapPin size={16} style={tv.muted} />
                  <div>
                    <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Estimated Location</p>
                    <p className="text-sm" style={tv.text}>
                      {(analysisResult as IPAnalysisResult).city}, {(analysisResult as IPAnalysisResult).region}, {(analysisResult as IPAnalysisResult).country}
                    </p>
                    {(analysisResult as IPAnalysisResult).latitude !== undefined && (analysisResult as IPAnalysisResult).latitude !== null && (
                      <p className="font-mono text-[10px] mt-1" style={tv.muted}>
                        Coordinates: {(analysisResult as IPAnalysisResult).latitude}, {(analysisResult as IPAnalysisResult).longitude}
                      </p>
                    )}
                  </div>
                </div>
                <div className="rounded-sm p-4 space-y-2"
                  style={{ backgroundColor: 'var(--tw-canvas-mid)', border: '1px solid var(--tw-border)' }}
                >
                  <p className="font-mono text-[10px] leading-relaxed" style={tv.muted}>
                    This represents estimated infrastructure location — not proof of any person's physical location.
                    Cloud servers and hosting providers may not represent the attacker's actual location.
                  </p>
                </div>
              </div>
            </div>
          ) : (
            <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
              <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>DNS Records</p>
              </div>
              <div className="p-5 space-y-3">
                {[
                  { type: 'A Records', val: (analysisResult as DomainAnalysisResult).aRecords?.join(', ') || 'None found' },
                  { type: 'SPF Record', val: (analysisResult as DomainAnalysisResult).spfRecord },
                  { type: 'DMARC Record', val: (analysisResult as DomainAnalysisResult).dmarcRecord },
                  { type: 'MX Records', val: (analysisResult as DomainAnalysisResult).mxRecords.join(', ') || 'None found' },
                  { type: 'Nameservers', val: (analysisResult as DomainAnalysisResult).nameservers.join(', ') || 'None found' },
                ].map(record => (
                  <div key={record.type} className="space-y-1">
                    <p className="font-mono text-[10px]" style={tv.muted}>{record.type}</p>
                    <p className="font-mono text-[10px] px-2 py-1 rounded-sm break-all"
                      style={{ backgroundColor: 'var(--tw-panel-alt)', color: 'var(--tw-text)' }}
                    >
                      {record.val}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Related Tags / Domains */}
        {!isIP && (analysisResult as DomainAnalysisResult).relatedDomains && (analysisResult as DomainAnalysisResult).relatedDomains.length > 0 && (
          <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
            <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Associated Category / Threat Tags</p>
            </div>
            <div className="p-5">
              <div className="flex flex-wrap gap-2">
                {(analysisResult as DomainAnalysisResult).relatedDomains.map((domain, i) => (
                  <span key={i} className="font-mono text-xs px-3 py-1.5 rounded-sm border flex items-center gap-2"
                    style={{ borderColor: 'color-mix(in srgb, var(--tw-medium) 35%, transparent)', backgroundColor: 'color-mix(in srgb, var(--tw-medium) 18%, transparent)', color: 'var(--tw-medium)' }}
                  >
                    <ExternalLink size={10} />
                    {domain}
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Disclaimer */}
        <div className="rounded-sm p-4 flex items-start gap-3"
          style={{ backgroundColor: 'var(--tw-canvas-mid)', border: '1px solid var(--tw-border)' }}
        >
          <Shield size={14} className="mt-0.5 shrink-0" style={tv.medium} />
          <p className="text-xs leading-relaxed" style={tv.muted}>
            Infrastructure Analysis Report. {analysisResult.disclaimer}
          </p>
        </div>
      </div>
    </div>
  );
}