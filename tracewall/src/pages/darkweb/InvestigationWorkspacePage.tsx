import { useState, type ReactElement } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield, Database, BarChart2, FileText, Sparkle, Download, ChevronLeft } from 'lucide-react';
import { dw, sectionStyle } from '../../lib/darkweb/styles';
import { useIntelligenceData } from '../../lib/intelligence/IntelligenceContext';
import { type Investigation } from '../../data/darkWebData';
import { InvestigationStory } from '../../components/darkweb/InvestigationStory';
import { AiAssistant } from '../../components/darkweb/AiAssistant';
import { ConfidenceBar } from '../../components/ui/ConfidenceBar';
import { ConfidenceRing } from '../../components/darkweb/ConfidenceRing';
import { EvidenceItem } from '../../components/darkweb/EvidenceItem';
import { ExportMenu } from '../../components/darkweb/ExportMenu';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { generateInvestigationSummary } from '../../lib/darkweb/aiEngine';
import { ProtectionPanel } from '../../components/darkweb/ProtectionPanel';
import { lazy, Suspense } from 'react';

const RelationshipGraph = lazy(() => import('../../components/darkweb/RelationshipGraph').then(m => ({ default: m.RelationshipGraph })));

export default function InvestigationWorkspacePage() {
  const { id } = useParams<{ id: string }>();
  const { darkWebInvestigationById, darkWebActorsById, darkWebEvidenceById, darkWebEvidence } = useIntelligenceData();
  const invCandidate = id ? (darkWebInvestigationById[id] ?? null) : null;
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('Overview');

  if (!invCandidate) {
    return (
      <div className="min-h-screen page-enter" style={sectionStyle()}>
        <div className="max-w-3xl mx-auto px-6 lg:px-10 py-16 text-center" style={dw.text}>
          <Shield size={40} className="mx-auto mb-4" style={dw.muted} />
          <h2 className="font-serif text-2xl mb-2">Investigation Not Found</h2>
          <p style={dw.muted}>The requested investigation does not exist.</p>
          <button onClick={() => navigate('/app/darkweb/investigations')} className="mt-4 font-mono text-xs px-4 py-2 rounded-sm border" style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}>← Back to Investigations</button>
        </div>
      </div>
    );
  }
  const inv = invCandidate;

  const actor = darkWebActorsById[inv.seedActorId];
  const summary = generateInvestigationSummary(inv.id);
  const tabs = ['Overview', 'Story', 'Graph', 'Evidence', 'AI Assistant', 'Report'];
  
  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        <button onClick={() => navigate(-1)} className="font-mono text-[10px] flex items-center gap-1" style={dw.muted}><ChevronLeft size={12} /> Back</button>

        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="space-y-2">
            <div className="flex items-center gap-2 flex-wrap"><Shield size={14} style={dw.critical} /><span className="font-mono text-[10px] tracking-wider" style={dw.burg}>{inv.id}</span><DemoLabel /></div>
            <h1 className="font-serif text-3xl" style={dw.text}>{inv.title}</h1>
            <p className="text-sm max-w-2xl" style={dw.muted}>{inv.description}</p>
          </div>
          <ExportMenu type="investigation" id={inv.id} />
        </div>

        <div className="rounded-sm border overflow-x-auto" style={dw.panel}>
          <div className="flex items-center" style={{ backgroundColor: 'var(--tw-panel-alt)' }}>
            {tabs.map(t => (
              <button key={t} onClick={() => setActiveTab(t)} type="button"
                className="flex items-center gap-1.5 px-4 py-3 font-mono text-xs border-b-2 transition-all"
                style={{ borderBottomColor: activeTab === t ? 'var(--tw-burgundy)' : 'transparent', color: activeTab === t ? 'var(--tw-burgundy)' : 'var(--tw-text-muted)' }}>
                {tabIcon(t)} {t}
              </button>
            ))}
          </div>
          <div className="p-5">
            {activeTab === 'Overview' && renderOverview()}
            {activeTab === 'Story' && <InvestigationStory investigation={inv} />}
            {activeTab === 'Graph' && (
              <Suspense fallback={<div style={dw.muted}>Loading graph…</div>}>
                <RelationshipGraph seed={inv.seedActorId} heightClass="h-[560px]" />
              </Suspense>
            )}
            {activeTab === 'Evidence' && renderEvidence()}
            {activeTab === 'AI Assistant' && <AiAssistant contextActorId={inv.seedActorId} />}
            {activeTab === 'Report' && renderReport()}
          </div>
        </div>
      </div>
    </motion.div>
  );

  function renderOverview() {
    return (
      <div className="space-y-6">
        <ProtectionPanel entityType="INVESTIGATION" entityId={inv.id} title="Threat Protection & Response" />
        <div className="flex items-center gap-8">
          <ConfidenceRing value={inv.confidence} label="Overall" sublabel="confidence" />
          <div className="space-y-1">
            <p className="font-mono text-xs" style={dw.muted}>Status: <b style={{ color: inv.status === 'ACTIVE' ? 'var(--tw-critical)' : 'var(--tw-medium)' }}>{inv.status}</b></p>
            <p className="font-mono text-xs" style={dw.muted}>Analyst: <b style={dw.text}>{inv.analyst}</b></p>
            <p className="font-mono text-xs" style={dw.muted}>Seed Actor: <b style={dw.burg}>{inv.seedActorId}</b> {actor && `(${actor.aliases[0]})`}</p>
          </div>
        </div>

        <ConfidenceBar value={inv.confidence} />

        <div className="rounded-sm border p-4" style={dw.panel}>
          <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Confidence Breakdown</p>
          <div className="space-y-2">{summary.detail.confidenceBreakdown.map(c => (
            <div key={c.label} className="space-y-1">
              <div className="flex justify-between font-mono text-[10px]"><span style={dw.text}>{c.label}</span><span style={dw.muted}>{c.value}%</span></div>
              <div className="w-full"><ConfidenceBar value={c.value} label={false} /></div>
            </div>
          ))}
          </div>
        </div>

        <div className="rounded-sm border p-4" style={dw.panel}>
          <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Key Findings</p>
          <ul className="list-disc list-inside space-y-1 text-sm" style={dw.muted}>{summary.detail.keyFindings.map((f, i) => <li key={i}>{f}</li>)}</ul>
        </div>
      </div>
    );
  }

  function renderEvidence() {
    const ev = inv.steps.flatMap(s => s.evidenceIds).filter((v, i, a) => a.indexOf(v) === i).map(id => darkWebEvidenceById[id]).filter(Boolean);
    return (
      <div className="space-y-3">
        {ev.map(e => <EvidenceItem key={e!.id} evidence={e!} siblings={darkWebEvidence} />)}
        {ev.length === 0 && <p style={dw.muted}>No evidence linked to this investigation.</p>}
      </div>
    );
  }

  function renderReport() {
    const detail = summary.detail;
    return (
      <div className="space-y-5">
        <div className="rounded-sm border p-5" style={dw.panel}>
          <h2 className="font-serif text-xl mb-2" style={dw.text}>Investigation Dossier — {inv.id}</h2>
          <p className="text-sm" style={dw.muted}>{detail.executiveSummary}</p>
        </div>
        <div className="grid md:grid-cols-2 gap-4">
          <div className="rounded-sm border p-4" style={dw.panel}>
            <p className="font-mono text-[10px] uppercase" style={dw.muted}>Analyst</p>
            <p className="font-mono text-sm" style={dw.text}>{inv.analyst}</p>
          </div>
          <div className="rounded-sm border p-4" style={dw.panel}>
            <p className="font-mono text-[10px] uppercase" style={dw.muted}>Evidence / Relationships</p>
            <p className="font-mono text-sm" style={dw.text}>{detail.evidenceCount} items · {detail.relationshipCount} relationships</p>
          </div>
        </div>
        <div className="rounded-sm border p-4" style={dw.panel}>
          <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Limitations</p>
          <p className="text-sm" style={dw.muted}>{detail.disclaimer}</p>
        </div>
        <ExportMenu type="investigation" id={inv.id} />
      </div>
    );
  }
}

function tabIcon(t: string) {
   const map: Record<string, ReactElement> = {
    Overview: <BarChart2 size={12} />, Story: <FileText size={12} />, Graph: <Database size={12} />,
    Evidence: <Database size={12} />, 'AI Assistant': <Sparkle size={12} />, Report: <Download size={12} />,
  };
  return map[t] ?? <FileText size={12} />;
}
