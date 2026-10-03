import { useState } from 'react';
import { Activity, ChevronLeft, ChevronRight, Play, ExternalLink, FileText, Shield, MousePointer, Key, Wallet, Globe, Database } from 'lucide-react';
import { type Investigation } from '../../data/darkWebData';
import { useIntelligenceData } from '../../lib/intelligence/IntelligenceContext';
import { EvidenceStamp } from '../ui/EvidenceStamp';
import { confidenceColor } from '../../lib/darkweb/graphData';
import { dw } from '../../lib/darkweb/styles';

const stepIcons: Record<number, any> = { 1: MousePointer, 2: Database, 3: Key, 4: Wallet, 5: Globe, 6: Activity, 7: Shield, 8: Database, 9: FileText };

interface InvestigationStoryProps {
  investigation: Investigation;
}

export function InvestigationStory({ investigation }: InvestigationStoryProps) {
  const [step, setStep] = useState(0);
  const { darkWebEvidenceById, darkWebRelationshipsById } = useIntelligenceData();
  const steps = investigation.steps;
  const current = steps[step];
  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h3 className="font-serif text-xl" style={dw.text}>Investigation Story — {investigation.id}</h3>
        <div className="font-mono text-xs" style={dw.muted}>Step {step + 1} of {steps.length}</div>
      </div>

      <div className="flex items-center gap-2 overflow-x-auto py-2">
        {steps.map((s, i) => {
          const Icon = stepIcons[s.step] ?? Activity;
          const active = i === step;
          return (
            <button key={s.step} onClick={() => setStep(i)} type="button"
              className="flex flex-col items-center gap-1 shrink-0 px-3 py-2 rounded-sm border transition-all"
              style={{
                backgroundColor: active ? 'var(--tw-burgundy)' : 'var(--tw-panel)',
                borderColor: active ? 'var(--tw-burgundy)' : 'var(--tw-border)',
                color: active ? '#FBFAF6' : 'var(--tw-text-muted)',
              }}>
              <Icon size={16} />
              <span className="font-mono text-[9px]">{s.title}</span>
            </button>
          );
        })}
      </div>

      <div className="rounded-sm border p-5" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border)' }}>
        <div className="flex items-start gap-3">
          <div style={{ color: 'var(--tw-burgundy)' }}>{<Play size={18} />}</div>
          <div className="space-y-2">
            <p className="font-serif text-lg" style={dw.text}>{current.title}</p>
            <p className="text-sm" style={dw.muted}>{current.description}</p>
            <div className="flex items-center gap-2 text-xs">
              <span style={{ color: confidenceColor(current.confidence) }}>{current.confidence}% confidence</span>
              <EvidenceStamp verdict={current.confidence >= 90 ? 'HIGH RISK' : current.confidence >= 75 ? 'SUSPICIOUS' : 'REVIEW'} size="sm" />
            </div>
          </div>
        </div>

        <div className="mt-4 grid md:grid-cols-2 gap-4">
          <div>
            <p className="font-mono text-[10px] tracking-widest uppercase" style={dw.faint}>Evidence</p>
            <div className="mt-1 space-y-1.5">
              {current.evidenceIds.map(eid => {
                const ev = darkWebEvidenceById[eid];
                return ev ? (
                  <div key={eid} className="text-[10px] p-2 rounded-sm border" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                    <span style={dw.burg}>{ev.id}</span> · <span style={dw.text}>{ev.provenance.slice(0, 70)}</span>
                  </div>
                ) : null;
              })}
            </div>
          </div>
          <div>
            <p className="font-mono text-[10px] tracking-widest uppercase" style={dw.faint}>Relationships</p>
            <div className="mt-1 space-y-1.5">
              {current.relationshipIds.map(rid => {
                const rel = darkWebRelationshipsById[rid];
                return rel ? (
                  <div key={rid} className="text-[10px] p-2 rounded-sm border flex justify-between" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                    <span style={dw.text}>{rel.sourceEntity} → {rel.targetEntity}</span>
                    <span style={{ color: confidenceColor(rel.confidence) }}>{rel.type.replace('_', ' ')} ({rel.confidence}%)</span>
                  </div>
                ) : null;
              })}
            </div>
          </div>
        </div>

        <div className="mt-4 flex gap-2">
          <button type="button" onClick={() => setStep(Math.max(0, step - 1))} disabled={step === 0}
            className="font-mono text-[10px] px-3 py-1.5 rounded-sm border flex items-center gap-1 disabled:opacity-40"
            style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)', color: 'var(--tw-text)' }}><ChevronLeft size={12} /> Previous</button>
          <button type="button" onClick={() => setStep(Math.min(steps.length - 1, step + 1))} disabled={step === steps.length - 1}
            className="font-mono text-[10px] px-3 py-1.5 rounded-sm border flex items-center gap-1 disabled:opacity-40"
            style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)', color: 'var(--tw-text)' }}>Next <ChevronRight size={12} /></button>
          {current.evidenceIds[0] && (
            <a href={`/app/darkweb/evidence`} className="font-mono text-[10px] px-3 py-1.5 rounded-sm border flex items-center gap-1"
              style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)', color: 'var(--tw-burgundy)' }}><ExternalLink size={11} /> View Evidence</a>
          )}
          {current.relationshipIds[0] && (
            <a href={`/app/darkweb/graph`} className="font-mono text-[10px] px-3 py-1.5 rounded-sm border flex items-center gap-1"
              style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)', color: 'var(--tw-burgundy)' }}><ExternalLink size={11} /> Open Graph</a>
          )}
        </div>
      </div>
    </div>
  );
}
