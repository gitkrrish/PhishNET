import { useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { ReactFlow, Background, Controls, Handle, Position, type NodeProps } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { threatGraphNodes, threatGraphEdges, campaigns } from '../../data/mockData';
import { SeverityBadge } from '../../components/ui/SeverityBadge';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { tv } from '../../lib/styles';
import { Plus, Hash, Globe, ExternalLink, FileText, FileCheck, AlertTriangle, CheckCircle, X, Box } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { lazy, Suspense } from 'react';
import { ThreeDErrorBoundary } from '../../components/3d/ThreeDErrorBoundary';
import ThreatEvidenceNetwork from '../../components/3d/ThreatEvidenceNetwork';

// Lazy load the 3D component
const IntelligenceGraph3D = lazy(() => import('../../components/3d/IntelligenceGraph3D').then(m => ({ default: m.default })));

// Node colors — these use fixed hex because they are graph-node fills,
// not UI chrome. They look fine in both light and dark mode.
const nodeTypeConfig: Record<string, { bg: string; border: string; label: string }> = {
  email:    { bg: '#7E1D2F', border: '#7E1D2F', label: 'Email'    },
  domain:   { bg: '#A47535', border: '#A47535', label: 'Domain'   },
  ip:       { bg: '#596E5B', border: '#596E5B', label: 'IP'       },
  url:      { bg: '#657581', border: '#657581', label: 'URL'      },
  campaign: { bg: '#481521', border: '#7E1D2F', label: 'Campaign' },
  exposure: { bg: '#B18A4A', border: '#B18A4A', label: 'Exposure' },
};

function EvidenceNode({ data }: NodeProps) {
  const cfg = nodeTypeConfig[data.type as string] || nodeTypeConfig.domain;
  return (
    <div style={{
      background: cfg.bg + '22',
      border: `1.5px solid ${cfg.border}70`,
      borderRadius: 3,
      padding: '6px 10px',
      minWidth: 120,
      maxWidth: 200,
      fontFamily: 'IBM Plex Mono',
      fontSize: 10,
    }}>
      <Handle type="target" position={Position.Left} style={{ background: cfg.border, width: 6, height: 6 }} />
      <div style={{ color: cfg.border, fontSize: 8, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 2 }}>
        {cfg.label}{data.subtype ? ` · ${data.subtype}` : ''}
      </div>
      <div style={{ color: 'var(--tw-text)', fontSize: 10 }}>{data.label as string}</div>
      {(data as { age?: string }).age && (
        <div style={{ color: 'var(--tw-medium)', fontSize: 9, marginTop: 2 }}>
          Age: {(data as { age: string }).age}
        </div>
      )}
      {(data as { country?: string }).country && (
        <div style={{ color: 'var(--tw-text-muted)', fontSize: 9, marginTop: 2 }}>
          Country: {(data as { country: string }).country}
        </div>
      )}
      <Handle type="source" position={Position.Right} style={{ background: cfg.border, width: 6, height: 6 }} />
    </div>
  );
}

const LAYOUT: Record<string, { x: number; y: number }> = {
  n1:  { x: 280,  y: 200  },
  n2:  { x: 60,   y: 60   },
  n3:  { x: 60,   y: 320  },
  n4:  { x: -180, y: 30   },
  n5:  { x: -180, y: 190  },
  n6:  { x: 60,   y: 470  },
  n7:  { x: 60,   y: 570  },
  n8:  { x: 520,  y: 190  },
  n9:  { x: 520,  y: 350  },
  n10: { x: 280,  y: -50  },
};

const flowNodes = threatGraphNodes.map(n => ({
  id: n.id,
  type: 'evidence',
  position: LAYOUT[n.id] || { x: 0, y: 0 },
  data: { ...n },
}));

const flowEdges = threatGraphEdges.map(e => ({
  id: e.id,
  source: e.source,
  target: e.target,
  label: e.label,
  style: { stroke: 'var(--tw-border-strong)', strokeWidth: 1 },
  labelStyle: { fill: 'var(--tw-text-muted)', fontSize: 9, fontFamily: 'IBM Plex Mono' },
  type: 'smoothstep',
}));

const nodeTypes = { evidence: EvidenceNode };

const iocTypes = [
  { id: 'email', label: 'Email Address', icon: FileText },
  { id: 'domain', label: 'Domain', icon: Globe },
  { id: 'ip', label: 'IP Address', icon: Hash },
  { id: 'url', label: 'URL', icon: ExternalLink },
  { id: 'hash', label: 'File Hash', icon: Hash },
  { id: 'asn', label: 'ASN', icon: Hash },
];

export default function IntelligencePage() {
  const [showAddIoc, setShowAddIoc] = useState(false);
  const [selectedIocType, setSelectedIocType] = useState('domain');
  const [iocValue, setIocValue] = useState('');
  const [iocError, setIocError] = useState<string | null>(null);
  const [enriching, setEnriching] = useState(false);
  const [enrichedIoc, setEnrichedIoc] = useState<any>(null);
  const [, setCustomIocs] = useState<any[]>([]);
  const [graphMode, setGraphMode] = useState<'2d' | '3d'>('2d');

  const validateIOC = useCallback((value: string, type: string): boolean => {
    if (!value.trim()) {
      setIocError('Value cannot be empty');
      return false;
    }

    switch (type) {
      case 'email':
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(value)) {
          setIocError('Invalid email format');
          return false;
        }
        break;
      case 'domain':
        const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;
        if (!domainRegex.test(value)) {
          setIocError('Invalid domain format');
          return false;
        }
        break;
      case 'ip':
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        if (!ipRegex.test(value)) {
          setIocError('Invalid IP address format');
          return false;
        }
        break;
      case 'url':
        try {
          new URL(value);
        } catch {
          setIocError('Invalid URL format');
          return false;
        }
        break;
      case 'hash':
        const hashRegex = /^[a-fA-F0-9]{32,64}$/;
        if (!hashRegex.test(value)) {
          setIocError('Invalid hash format (expected 32-64 hex characters)');
          return false;
        }
        break;
      case 'asn':
        const asnRegex = /^AS\d+$/;
        if (!asnRegex.test(value)) {
          setIocError('Invalid ASN format (expected AS followed by numbers)');
          return false;
        }
        break;
    }

    setIocError(null);
    return true;
  }, []);

  const enrichIOC = useCallback(() => {
    if (!validateIOC(iocValue, selectedIocType)) return;

    setEnriching(true);
    setEnrichedIoc(null);

    // Simulate enrichment
    setTimeout(() => {
      const mockResult = {
        id: `IOC-${Date.now()}`,
        type: selectedIocType,
        value: iocValue,
        riskScore: 40 + Math.floor(Math.random() * 50),
        verdict: Math.random() > 0.5 ? 'SUSPICIOUS' : 'CLEAN',
        confidence: 'MEDIUM',
        firstSeen: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
        lastSeen: new Date().toISOString().split('T')[0],
        relatedCampaigns: Math.random() > 0.7 ? ['CAMP-2026-014'] : [],
        relatedCases: Math.random() > 0.8 ? ['CASE-2026-0142'] : [],
        source: 'Threat Intelligence Feed',
        enriched: true,
      };

      setEnrichedIoc(mockResult);
      setCustomIocs(prev => [mockResult, ...prev]);
      setEnriching(false);
    }, 2000);
  }, [iocValue, selectedIocType, validateIOC]);

  return (
    <div className="min-h-screen" style={tv.canvas}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-8">

        {/* Header */}
        <div className="flex items-end justify-between gap-4">
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>AI Threat Intelligence</p>
              <DemoLabel />
            </div>
            <h1 className="font-serif text-3xl" style={tv.text}>Evidence Relationship Canvas</h1>
            <p className="text-sm max-w-xl leading-relaxed" style={tv.muted}>
              Relationships between indicators, campaigns, and exposure events. Every connection includes its
              evidence source, confidence, and reasoning.
            </p>
          </div>
          <button
            onClick={() => setShowAddIoc(!showAddIoc)}
            className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors flex items-center gap-2"
            style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
          >
            <Plus size={12} /> Add IOC
          </button>
        </div>

        {/* Add IOC Form */}
        <AnimatePresence>
          {showAddIoc && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="rounded-sm overflow-hidden border"
              style={{ borderColor: 'var(--tw-border)' }}
            >
              <div className="p-5 space-y-4" style={{ backgroundColor: 'var(--tw-panel-alt)' }}>
                <div className="flex items-center justify-between">
                  <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Add Indicator of Compromise</p>
                  <button onClick={() => setShowAddIoc(false)} className="p-1 rounded-sm hover:bg-[var(--tw-hover)]">
                    <X size={14} style={tv.faint} />
                  </button>
                </div>
                
                <div className="grid md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>IOC Type</label>
                    <div className="flex flex-wrap gap-2">
                      {iocTypes.map(type => (
                        <button
                          key={type.id}
                          onClick={() => setSelectedIocType(type.id)}
                          className="font-mono text-xs px-3 py-1.5 rounded-sm border transition-colors flex items-center gap-1.5"
                          style={selectedIocType === type.id
                            ? { backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6', borderColor: 'var(--tw-burgundy)' }
                            : { backgroundColor: 'transparent', color: 'var(--tw-text-muted)', borderColor: 'var(--tw-border-strong)' }
                          }
                        >
                          <type.icon size={11} />
                          {type.label}
                        </button>
                      ))}
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <label className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Value</label>
                    <input
                      type="text"
                      value={iocValue}
                      onChange={e => setIocValue(e.target.value)}
                      placeholder={selectedIocType === 'email' ? 'user@example.com' : 
                               selectedIocType === 'domain' ? 'example.com' :
                               selectedIocType === 'ip' ? '192.168.1.1' :
                               selectedIocType === 'url' ? 'https://example.com' :
                               selectedIocType === 'hash' ? 'a1b2c3d4...' :
                               'AS12345'}
                      className="w-full font-mono text-xs px-3 py-2 rounded-sm focus:outline-none placeholder:opacity-40"
                      style={tv.input}
                    />
                    {iocError && (
                      <p className="font-mono text-[10px]" style={{ color: 'var(--tw-critical)' }}>{iocError}</p>
                    )}
                  </div>
                </div>
                
                <div className="flex gap-2">
                  <button
                    onClick={enrichIOC}
                    disabled={enriching || !iocValue.trim()}
                    className="flex-1 font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm transition-colors disabled:opacity-40"
                    style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
                  >
                    {enriching ? 'Enriching…' : 'Enrich IOC'}
                  </button>
                  <button
                    onClick={() => setShowAddIoc(false)}
                    className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                    style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
                  >
                    Cancel
                  </button>
                </div>
                
                {enrichedIoc && (
                  <div className={`rounded-sm p-4 border ${
                    enrichedIoc.verdict === 'SUSPICIOUS'
                      ? 'border-[color-mix(in_srgb,var(--tw-critical),transparent)]'
                      : 'border-[color-mix(in_srgb,var(--tw-low),transparent)]'
                  }`} style={{
                    backgroundColor: enrichedIoc.verdict === 'SUSPICIOUS'
                      ? 'color-mix(in srgb, var(--tw-critical) 18%, transparent)'
                      : 'color-mix(in srgb, var(--tw-low) 18%, transparent)'
                  }}>
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex items-start gap-2">
                        {enrichedIoc.verdict === 'SUSPICIOUS' ? (
                          <AlertTriangle size={14} className="mt-0.5 shrink-0" style={{ color: 'var(--tw-critical)' }} />
                        ) : (
                          <CheckCircle size={14} className="mt-0.5 shrink-0" style={{ color: 'var(--tw-low)' }} />
                        )}
                        <div className="space-y-1">
                          <p className="font-mono text-xs" style={tv.text}>{enrichedIoc.value}</p>
                          <p className="font-mono text-[10px]" style={tv.muted}>
                            Risk Score: {enrichedIoc.riskScore}/100 · Verdict: {enrichedIoc.verdict}
                          </p>
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <button onClick={() => {
                          const caseId = `CASE-${Date.now()}`;
                          alert(`IOC would be added to case ${caseId} (demo mode)`);
                        }}
                          className="font-mono text-[10px] px-2 py-1 rounded-sm border transition-colors flex items-center gap-1"
                          style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
                        >
                          <FileCheck size={10} /> Add to Case
                        </button>
                        <button onClick={() => {
                          alert(`IOC would be added to campaign (demo mode)`);
                        }}
                          className="font-mono text-[10px] px-2 py-1 rounded-sm border transition-colors"
                          style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
                        >
                          Add to Campaign
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Threat Evidence Network */}
        <ThreatEvidenceNetwork pageType="intelligence" />

        {/* AI Assessment + feedback */}
        <div className="grid lg:grid-cols-3 gap-4">
          {/* Main assessment */}
          <div className="lg:col-span-2 rounded-sm p-5 space-y-4" style={tv.panelBorder}>
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Inline Intelligence Assessment</p>
            <p className="font-serif text-xl" style={tv.text}>"Likely invoice-diversion attempt."</p>
            <div className="space-y-2">
              {[
                'Reply-To domain differs from sender domain — consistent with BEC redirect strategy.',
                "Sender domain registered 11 days ago — resembles the organisation's finance domain.",
                'Similar wording pattern appears in two previous messages across the campaign.',
                'The linked URL redirects to a domain first observed 9 days ago.',
                'Infrastructure overlaps with campaign CAMP-2026-017.',
              ].map((e, i) => (
                <div key={i} className="flex items-start gap-3 py-1.5 border-b last:border-0" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <span className="evidence-num shrink-0">{String(i + 1).padStart(2, '0')}</span>
                  <p className="text-sm" style={tv.muted}>{e}</p>
                </div>
              ))}
            </div>
            <div className="pt-2 border-t space-y-1" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <div className="flex items-center gap-3">
                <span className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Confidence</span>
                <span className="font-mono text-xs" style={tv.text}>High (88%)</span>
              </div>
              <p className="text-xs font-mono" style={tv.medium}>
                Limitation: Exact sender identity cannot be established from available evidence.
                Attribution requires corroborating evidence beyond infrastructure indicators.
              </p>
            </div>
          </div>

          {/* Side cards */}
          <div className="space-y-4">
            {/* Contradictory evidence */}
            <div className="rounded-sm p-4 space-y-3" style={tv.panelBorder}>
              <p className="font-mono text-[10px] tracking-[0.15em] uppercase" style={tv.muted}>Contradictory Evidence</p>
              {[
                'Attachment scanned clean — no macro detected.',
                'Sending IP has no prior abuse reports in available feeds.',
              ].map((ce, i) => (
                <div key={i} className="flex items-start gap-2 text-xs" style={tv.muted}>
                  <span className="mt-0.5 shrink-0" style={tv.low}>—</span>
                  {ce}
                </div>
              ))}
            </div>

            {/* Analyst feedback */}
            <div className="rounded-sm p-4 space-y-2" style={tv.panelBorder}>
              <p className="font-mono text-[10px] tracking-[0.15em] uppercase" style={tv.muted}>Analyst Feedback</p>
              {[
                { label: 'Correct Detection', id: 'correct' },
                { label: 'False Positive',    id: 'fp'      },
                { label: 'Missed Threat',     id: 'miss'    },
              ].map(f => (
                <label key={f.id} className="flex items-center gap-2 cursor-pointer">
                  <input type="radio" name="feedback" value={f.id} style={{ accentColor: 'var(--tw-burgundy)' }} />
                  <span className="text-xs" style={tv.muted}>{f.label}</span>
                </label>
              ))}
              <button
                className="w-full font-mono text-[10px] tracking-widest uppercase px-3 py-1.5 rounded-sm border mt-1 transition-colors"
                style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
                onMouseEnter={e => {
                  e.currentTarget.style.borderColor = 'var(--tw-burgundy)';
                  e.currentTarget.style.color = 'var(--tw-burgundy)';
                }}
                onMouseLeave={e => {
                  e.currentTarget.style.borderColor = 'var(--tw-border-strong)';
                  e.currentTarget.style.color = 'var(--tw-text-muted)';
                }}
              >
                Submit Feedback
              </button>
            </div>
          </div>
        </div>

        {/* Relationship Graph */}
        <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
          <div className="px-5 py-3 border-b flex items-center justify-between" style={{ borderColor: 'var(--tw-border-mid)' }}>
            <span className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Indicator Relationship Graph</span>
            <div className="flex items-center gap-3">
              <DemoLabel />
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setGraphMode('2d')}
                  className={`font-mono text-[10px] px-2 py-1 rounded-sm transition-colors ${
                    graphMode === '2d' ? 'bg-[var(--tw-burgundy)] text-[#FBFAF6]' : 'text-[var(--tw-text-muted)]'
                  }`}
                >
                  2D
                </button>
                <button
                  onClick={() => setGraphMode('3d')}
                  className={`font-mono text-[10px] px-2 py-1 rounded-sm transition-colors ${
                    graphMode === '3d' ? 'bg-[var(--tw-burgundy)] text-[#FBFAF6]' : 'text-[var(--tw-text-muted)]'
                  }`}
                >
                  3D
                </button>
              </div>
            </div>
          </div>
          {graphMode === '2d' ? (
            <div style={{ height: 500, backgroundColor: 'var(--tw-panel)' }}>
              <ReactFlow
                nodes={flowNodes}
                edges={flowEdges}
                nodeTypes={nodeTypes}
                fitView
                proOptions={{ hideAttribution: true }}
              >
                <Background color="var(--tw-border-mid)" gap={24} size={1} />
                <Controls
                  showInteractive={false}
                  style={{
                    background: 'var(--tw-panel)',
                    border: '1px solid var(--tw-border-mid)',
                    borderRadius: 2,
                  }}
                />
              </ReactFlow>
            </div>
          ) : (
            <div style={{ height: 500, backgroundColor: 'var(--tw-panel)' }}>
              <ThreeDErrorBoundary fallback={
                <div className="w-full h-full flex items-center justify-center">
                  <p className="font-mono text-xs" style={{ color: 'var(--tw-text-muted)' }}>
                    3D view unavailable - using 2D fallback
                  </p>
                </div>
              }>
                <Suspense fallback={
                  <div className="w-full h-full flex items-center justify-center">
                    <div className="flex items-center gap-2">
                      <Box size={16} className="animate-spin" style={{ color: 'var(--tw-burgundy)' }} />
                      <span className="font-mono text-xs" style={{ color: 'var(--tw-text-muted)' }}>
                        Loading 3D view…
                      </span>
                    </div>
                  </div>
                }>
                  <IntelligenceGraph3D
                    nodes={threatGraphNodes.map(n => ({
                      ...n,
                      x: (LAYOUT[n.id] || { x: 0, y: 0 }).x,
                      y: (LAYOUT[n.id] || { x: 0, y: 0 }).y,
                      z: 0,
                      color: nodeTypeConfig[n.type as string]?.bg || '#657581',
                    }))}
                    edges={threatGraphEdges}
                  />
                </Suspense>
              </ThreeDErrorBoundary>
            </div>
          )}
          {/* Legend */}
          <div className="px-5 py-3 border-t flex flex-wrap gap-4" style={{ borderColor: 'var(--tw-border-mid)' }}>
            {Object.entries(nodeTypeConfig).map(([type, cfg]) => (
              <div key={type} className="flex items-center gap-1.5">
                <div className="w-3 h-3 rounded-sm" style={{ background: cfg.bg }} />
                <span className="font-mono text-[10px]" style={tv.muted}>{cfg.label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Active Campaigns */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Active Campaigns</p>
            <Link to="/app/campaigns" className="font-mono text-[10px]" style={tv.burg}>View all →</Link>
          </div>
          <div className="grid lg:grid-cols-2 gap-4">
            {campaigns.map(c => (
              <div key={c.id} className="rounded-sm overflow-hidden" style={tv.panelBorder}>
                <div className="px-5 py-4 border-b flex items-start justify-between gap-3" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <div>
                    <p className="font-mono text-[10px]" style={tv.muted}>{c.id}</p>
                    <p className="font-serif text-lg mt-0.5" style={tv.text}>{c.name}</p>
                  </div>
                  <SeverityBadge severity={c.riskLevel} />
                </div>
                <div className="p-5 space-y-3">
                  <p className="text-sm leading-relaxed" style={tv.muted}>{c.aiSummary}</p>
                  <div className="grid grid-cols-3 gap-3 text-center">
                    {[
                      { label: 'Emails',     val: c.relatedEmails      },
                      { label: 'Domains',    val: c.relatedDomains.length },
                      { label: 'Confidence', val: `${c.confidence}%`  },
                    ].map(m => (
                      <div key={m.label}>
                        <div className="font-mono text-xl font-light" style={tv.burg}>{m.val}</div>
                        <div className="font-mono text-[9px] uppercase tracking-wider" style={tv.muted}>{m.label}</div>
                      </div>
                    ))}
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {c.tags.map(tag => (
                      <span key={tag}
                        className="font-mono text-[10px] px-2 py-0.5 rounded-sm"
                        style={{ backgroundColor: 'var(--tw-panel-alt)', color: 'var(--tw-text-muted)' }}
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
}
