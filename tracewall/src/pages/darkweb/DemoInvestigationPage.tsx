import { useState } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Play, Pause, SkipBack, SkipForward, ChevronLeft } from 'lucide-react';
import { dw, sectionStyle } from '../../lib/darkweb/styles';
import { useIntelligenceData } from '../../lib/intelligence/IntelligenceContext';
import { DARKWEB_DEMO_LABEL } from '../../data/darkWebData';
import { InvestigationStory } from '../../components/darkweb/InvestigationStory';
import { AiAssistant } from '../../components/darkweb/AiAssistant';
import { ConfidenceRing } from '../../components/darkweb/ConfidenceRing';
import { ExportMenu } from '../../components/darkweb/ExportMenu';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { generateInvestigationSummary } from '../../lib/darkweb/aiEngine';
import { CorrelationMatrix } from '../../components/darkweb/CorrelationMatrix';
import { lazy, Suspense } from 'react';

const RelationshipGraph = lazy(() => import('../../components/darkweb/RelationshipGraph').then(m => ({ default: m.RelationshipGraph })));

export default function DemoInvestigationPage() {
  const { darkWebInvestigations, darkWebActorsById } = useIntelligenceData();
  const inv = darkWebInvestigations[0];
  const [playing, setPlaying] = useState(true);
  const [stepIdx, setStepIdx] = useState(0);
  const totalSteps = inv?.steps.length ?? 0;

  if (!inv) {
    return (
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
        <div className="max-w-3xl mx-auto px-6 lg:px-10 py-16 text-center space-y-4" style={dw.text}>
          <Play size={40} className="mx-auto" style={dw.muted} />
          <h2 className="font-serif text-2xl">No demo investigation available</h2>
          <p className="text-sm" style={dw.muted}>
            The central intelligence model holds no investigation. Load the synthetic demo dataset to run the guided walkthrough.
          </p>
          <Link to="/app/settings" className="inline-block font-mono text-xs px-4 py-2 rounded-sm border" style={dw.panelAlt}>Open data settings</Link>
        </div>
      </motion.div>
    );
  }

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        <Link to="/app/darkweb/investigations" className="font-mono text-xs flex items-center gap-1" style={dw.muted}><ChevronLeft size={12} /> Back to Investigations</Link>

        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-2"><Play size={16} style={dw.critical} /><h1 className="font-serif text-3xl" style={dw.text}>Demo Investigation: {inv.title}</h1></div>
          <div className="flex items-center gap-2"><DemoLabel /><ExportMenu type="investigation" id={inv.id} /></div>
        </div>

        <p className="text-sm max-w-2xl" style={dw.muted}>Automated walkthrough of a synthetic persona-correlation investigation. Confidence scores are analytical indicators derived from the local dataset only.</p>

        <div className="flex items-center justify-between rounded-sm border p-4" style={dw.panel}>
          <div className="flex items-center gap-2 font-mono text-xs" style={dw.muted}>
            Step {stepIdx + 1} of {totalSteps} · <span style={dw.burg}>{inv.steps[stepIdx]?.type?.replace('_', ' ') ?? 'Analysis'}</span>
          </div>
          <div className="flex items-center gap-1">
            <button onClick={() => setStepIdx(s => Math.max(0, s - 1))} className="p-1 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)', color: 'var(--tw-text-muted)' }}><SkipBack size={12} /></button>
            <button onClick={() => setPlaying(!playing)} className="p-1 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)', color: 'var(--tw-burgundy)' }}>{playing ? <Pause size={12} /> : <Play size={12} />}</button>
            <button onClick={() => setStepIdx(s => Math.min(totalSteps - 1, s + 1))} className="p-1 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)', color: 'var(--tw-text-muted)' }}><SkipForward size={12} /></button>
          </div>
        </div>

        <div className="rounded-sm border p-4" style={dw.panel}>
          <div className="flex items-center gap-6 mb-3"><ConfidenceRing value={inv.confidence} label="Investigation" sublabel="confidence" />
            <div className="font-mono text-xs space-y-1" style={dw.muted}>
              <p>Analyst: <span style={dw.text}>{inv.analyst}</span></p>
              <p>Seed Actor: <span style={dw.burg}>{inv.seedActorId}</span> {darkWebActorsById[inv.seedActorId] && `(${darkWebActorsById[inv.seedActorId]?.aliases[0]})`}</p>
              <p>Status: <span style={{ color: inv.status === 'ACTIVE' ? 'var(--tw-critical)' : 'var(--tw-medium)' }}>{inv.status}</span></p>
            </div>
          </div>

          <InvestigationStory investigation={inv} />

          <div className="mt-6 h-[360px] rounded-sm border" style={dw.canvasMid}>
            <Suspense fallback={<div className="p-4 font-mono text-xs" style={dw.muted}>Loading graph…</div>}>
              <RelationshipGraph seed={inv.seedActorId} heightClass="h-full" />
            </Suspense>
          </div>
        </div>

        <Suspense fallback={<div style={dw.muted}>Loading AI assistant…</div>}>
          <AiAssistant contextActorId={inv.seedActorId} investigationId={inv.id} />
        </Suspense>

        <div className="rounded-sm border p-4" style={dw.panel}>
          <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Correlation Matrix</p>
          <CorrelationMatrix actorIds={inv.steps.flatMap(s => s.actorIds).filter((v, i, a) => a.indexOf(v) === i)} />
        </div>

        <div className="rounded-sm border p-4" style={dw.panel}>
          <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Demo Note</p>
          <p className="text-sm" style={dw.muted}>{DARKWEB_DEMO_LABEL} This demonstration uses synthetic actors, handles, infrastructure, and evidence. No real credentials or illicit services are referenced. {generateInvestigationSummary(inv.id).detail.disclaimer}</p>
        </div>
      </div>
    </motion.div>
  );
}
