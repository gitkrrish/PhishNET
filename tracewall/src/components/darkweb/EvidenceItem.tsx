import { useState } from 'react';
import { ChevronDown, ChevronRight, Hash, Clock, Link2 } from 'lucide-react';
import { type Evidence } from '../../data/darkWebData';
import { dw } from '../../lib/darkweb/styles';
import { EvidenceStamp } from '../ui/EvidenceStamp';
import { evidenceAnalysis } from '../../lib/intelligence/evidence';
import { MetaCell } from './EntityWorkspace';

export function EvidenceItem({
  evidence,
  siblings = [],
}: {
  evidence: Evidence;
  /** Sibling records, used for cross-record findings such as shared digests. */
  siblings?: Array<{ id: string; hash: string; collectionTimestamp: string }>;
}) {
  const [open, setOpen] = useState(false);
  const analysis = evidenceAnalysis(evidence, siblings.length ? siblings : [evidence]);
  const { hashCheck, custody } = analysis;

  return (
    <div className="border-b last:border-0" style={{ borderColor: 'var(--tw-border-mid)' }}>
      <div className="p-4">
        <div className="flex items-start justify-between gap-3">
          <button
            onClick={() => setOpen(o => !o)}
            className="flex items-start gap-2 text-left flex-1"
            aria-expanded={open}
          >
            {open ? <ChevronDown size={13} className="mt-0.5 shrink-0" style={dw.faint} />
              : <ChevronRight size={13} className="mt-0.5 shrink-0" style={dw.faint} />}
            <div className="space-y-1 flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <p className="font-mono text-[10px] tracking-wider" style={dw.burg}>{evidence.id}</p>
                <EvidenceStamp verdict={evidence.evidenceType} size="sm" />
                {!hashCheck.structurallyValid && (
                  <span className="font-mono text-[9px] px-1.5 py-0.5 rounded-sm" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-critical) 18%, transparent)', color: 'var(--tw-critical)' }}>
                    DIGEST {hashCheck.verdict.replace(/_/g, ' ')}
                  </span>
                )}
              </div>
              <p className="font-mono text-xs" style={dw.muted}>{evidence.provenance}</p>
            </div>
          </button>
          <EvidenceStamp verdict={evidence.reliability >= 90 ? 'HIGH RISK' : evidence.reliability >= 75 ? 'SUSPICIOUS' : 'REVIEW'} size="sm" />
        </div>

        <div className="mt-2 grid grid-cols-2 gap-2 text-[11px]">
          <div><span style={dw.faint}>Source</span><p className="font-mono" style={dw.text}>{evidence.source} ({evidence.sourceType})</p></div>
          <div><span style={dw.faint}>Observed</span><p className="font-mono" style={dw.text}>{new Date(evidence.timestamp).toLocaleString()}</p></div>
          <div><span style={dw.faint}>Collected</span><p className="font-mono" style={dw.text}>{new Date(evidence.collectionTimestamp).toLocaleString()}</p></div>
          <div><span style={dw.faint}>Reliability</span><p className="font-mono" style={dw.text}>R{evidence.reliability} · {evidence.confidence}% conf</p></div>
          <div className="col-span-2"><span style={dw.faint}>Hash</span><p className="font-mono break-all flex items-start gap-1.5" style={dw.text}>
            <Hash size={11} className="mt-0.5 shrink-0" style={dw.faint} />{evidence.hash}
          </p></div>
        </div>
      </div>

      {open && (
        <div className="px-4 pb-4 space-y-3" style={{ borderTop: '1px solid var(--tw-border-mid)' }}>
          <div className="pt-3 grid sm:grid-cols-3 gap-3">
            <MetaCell
              label="Digest check"
              value={hashCheck.verdict.replace(/_/g, ' ')}
              color={hashCheck.structurallyValid ? dw.moss.color : dw.critical.color}
            />
            <MetaCell
              label="Observation → collection"
              value={custody.observationLagDays === null ? 'unreadable' : `${Math.round(custody.observationLagDays)} days`}
            />
            <MetaCell
              label="Same-minute batch"
              value={custody.collectionBatchSize > 1 ? `${custody.collectionBatchSize} items` : 'unique'}
            />
          </div>

          <p className="font-mono text-[9px] leading-relaxed" style={dw.faint}>{hashCheck.detail}</p>

          {analysis.provenance.length > 0 && (
            <div>
              <p className="font-mono text-[9px] tracking-widest uppercase mb-1.5" style={dw.muted}>Provenance path</p>
              <ol className="space-y-1">
                {analysis.provenance.map((segment, i) => (
                  <li key={i} className="flex items-start gap-2 font-mono text-[10px]">
                    <span className="shrink-0" style={dw.faint}>{segment.kind}</span>
                    <span style={dw.text}>
                      {segment.raw}
                      {segment.quotedTitle && <span style={dw.brass}> — “{segment.quotedTitle}”</span>}
                    </span>
                  </li>
                ))}
              </ol>
            </div>
          )}

          {(analysis.indicators.ipv4.length > 0 || analysis.indicators.domains.length > 0 || analysis.indicators.urls.length > 0) && (
            <div>
              <p className="font-mono text-[9px] tracking-widest uppercase mb-1.5" style={dw.muted}>Observables in provenance</p>
              <div className="flex flex-wrap gap-1.5">
                {[...analysis.indicators.ipv4, ...analysis.indicators.domains, ...analysis.indicators.urls].map(value => (
                  <span key={value} className="font-mono text-[9px] px-1.5 py-0.5 rounded-sm border" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-info)' }}>
                    {value}
                  </span>
                ))}
              </div>
              <p className="font-mono text-[9px] mt-1 leading-relaxed" style={dw.faint}>
                These come from the recorded provenance text, not from the evidence file, so they should be
                corroborated against infrastructure records before being treated as actor-controlled.
              </p>
            </div>
          )}

          {analysis.findings.length > 0 && (
            <div className="space-y-1.5">
              {analysis.findings.map(finding => (
                <div key={finding.label} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                  <span style={finding.tone === 'warn' ? dw.critical : finding.tone === 'ok' ? dw.moss : dw.brass}>{finding.label}</span>
                  <p className="mt-1 leading-relaxed" style={dw.muted}>{finding.detail}</p>
                </div>
              ))}
            </div>
          )}

          <div className="flex items-start gap-1.5 font-mono text-[9px] leading-relaxed" style={dw.faint}>
            <Clock size={10} className="mt-0.5 shrink-0" />
            <span>
              A collection timestamp records when a sweep ran, not when this item was individually captured, so
              it does not order items against one another.
            </span>
          </div>
          {analysis.duplicateIds.length > 0 && (
            <p className="font-mono text-[9px] flex items-start gap-1.5 leading-relaxed" style={dw.info}>
              <Link2 size={10} className="mt-0.5 shrink-0" />
              Same digest as {analysis.duplicateIds.join(', ')} — one file recorded from more than one source.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
