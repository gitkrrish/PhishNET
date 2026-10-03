// ============================================================
// PhishNet — ATT&CK Intelligence Workspace.
//
// A read-only view over the stored MITRE mappings. The grid always shows
// the full tactic set so an unobserved tactic is visible as a gap rather
// than silently omitted, and every mapping is presented with the evidence
// and the recorded confidence that support it.
// ============================================================
import { useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Crosshair, Layers, Users, Network, Database, FileText, Shield, Target, AlertTriangle,
} from 'lucide-react';
import { dw } from '../../lib/darkweb/styles';
import { useIntelligence } from '../../lib/intelligence/IntelligenceContext';
import {
  ATTACK_TACTICS,
  attackMatrix,
  tacticDistribution,
  actorCoverage,
  techniqueTimeline,
  attackBundle,
  type AttackCell,
} from '../../lib/intelligence/attack';
import {
  EntityPageHeader, EntitySection, EntityLink, EmptyNote, RecordEntityLink,
} from '../../components/darkweb/EntityWorkspace';
import { ConfidenceBar } from '../../components/ui/ConfidenceBar';
import { ProtectionModulePanel } from '../../components/darkweb/ProtectionModulePanel';

const actorPath = (id: string) => `/app/darkweb/actors/${id}`;
const handlePath = (id: string) => `/app/darkweb/handles/${id}`;
// Infrastructure and evidence have no per-record routes yet, so these resolve
// to their module list rather than to a URL that would not match any route.
const infraPath = () => '/app/darkweb/infrastructure';
const evidencePath = () => '/app/darkweb/evidence';
const addPath = '/app/darkweb/add?type=mitreTtp';

/** Returns a CSS colour string, so it can drive both `style` and icon `color`. */
function confidenceTint(value: number): string {
  if (value >= 80) return 'var(--tw-critical)';
  if (value >= 60) return 'var(--tw-medium)';
  if (value >= 40) return 'var(--tw-low)';
  return 'var(--tw-text-faint)';
}

export default function AttackWorkspacePage() {
  const { dataset } = useIntelligence();
  const [params, setParams] = useSearchParams();
  const [actorFilter, setActorFilter] = useState('ALL');
  const [onlyBacked, setOnlyBacked] = useState(false);

  // The URL is the single source of truth for the open technique, so a
  // centralized-search deep link (?technique=T1059.001) opens that mapping
  // directly and a refresh or a shared link reproduces the same view.
  const selected = params.get('technique')?.toUpperCase() ?? null;
  const select = (techniqueId: string | null) => {
    setParams(techniqueId ? { technique: techniqueId } : {}, { replace: true });
  };

  const records = useMemo(() => dataset.mitreTtps ?? [], [dataset.mitreTtps]);
  const visible = useMemo(
    () => records.filter(record => (actorFilter === 'ALL' || record.actorIds.includes(actorFilter))
      && (!onlyBacked || record.evidenceIds.length > 0)),
    [records, actorFilter, onlyBacked],
  );
  const matrix = useMemo(() => attackMatrix(visible), [visible]);
  const distribution = useMemo(() => tacticDistribution(visible), [visible]);
  const coverage = useMemo(() => actorCoverage(dataset), [dataset]);
  const timeline = useMemo(() => techniqueTimeline(visible), [visible]);
  const bundle = selected ? attackBundle(dataset, selected) : null;

  const unbacked = visible.filter(record => record.evidenceIds.length === 0).length;
  const observedTactics = distribution.filter(share => share.techniques > 0).length;

  return (
    <div className="p-6 space-y-4" style={dw.canvas}>
      <EntityPageHeader
        icon={<Crosshair size={18} style={dw.burg} />}
        eyebrow="MITRE ATT&CK INTELLIGENCE"
        title="ATT&CK Technique Coverage"
        byline="Every cell is a stored mapping an analyst recorded against a technique. Coverage is a measure of what has been observed and evidenced here — it is not a statement about an actor's full capability, and a technique is never inferred from plausibility alone."
        actions={<RecordEntityLink to={addPath} label="Record technique" />}
        stats={[
          { label: 'Techniques', value: visible.length },
          { label: 'Tactics observed', value: `${observedTactics}/${ATTACK_TACTICS.length}` },
          { label: 'Actors mapped', value: coverage.filter(c => c.techniques > 0).length },
          { label: 'Unbacked mappings', value: unbacked, color: unbacked ? dw.medium : dw.moss },
        ]}
      />

      {visible.length === 0 && (
        <div className="rounded-sm border p-6" style={dw.panel}>
          <EmptyNote>
            No stored technique matches this filter. Clear the filter, or record a technique through Add
            Intelligence to map an observed behaviour to ATT&CK.
          </EmptyNote>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <select
          value={actorFilter}
          onChange={e => setActorFilter(e.target.value)}
          className="font-mono text-[10px] px-2 py-1 rounded-sm"
          style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }}
        >
          <option value="ALL">All actors</option>
          {coverage.filter(c => c.techniques > 0).map(c => (
            <option key={c.actorId} value={c.actorId}>{c.actorId} — {c.label}</option>
          ))}
        </select>
        <button
          type="button"
          onClick={() => setOnlyBacked(v => !v)}
          className="font-mono text-[10px] tracking-widest uppercase px-2.5 py-1 rounded-sm border"
          style={{
            backgroundColor: 'var(--tw-panel-alt)',
            borderColor: 'var(--tw-border-mid)',
            color: onlyBacked ? 'var(--tw-burgundy)' : 'var(--tw-text-muted)',
          }}
        >
          Only evidence-backed
        </button>
        {onlyBacked && <span className="font-mono text-[9px]" style={dw.faint}>hiding {unbacked} mapping(s) with no evidence</span>}
      </div>

      <div className="grid lg:grid-cols-3 gap-4">
        {/* ── Matrix ── */}
        <div className="lg:col-span-2 space-y-2">
          <EntitySection icon={<Layers size={13} style={dw.burg} />} title="Technique matrix">
            <div className="space-y-1.5">
              {matrix.map(row => (
                <div key={row.tactic} className="grid grid-cols-[110px_1fr] gap-2 items-start">
                  <div className="pt-1.5">
                    <span className="font-mono text-[9px] tracking-wider uppercase" style={dw.muted}>
                      {row.label}
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {row.cells.length === 0 && (
                      <span className="font-mono text-[9px] px-2 py-1 rounded-sm border" style={{ borderColor: 'var(--tw-border)', color: 'var(--tw-text-faint)' }}>
                        not observed
                      </span>
                    )}
                    {row.cells.map(cell => (
                      <TechniqueChip key={cell.techniqueId} cell={cell} active={selected === cell.techniqueId} onSelect={select} />
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </EntitySection>
        </div>

        {/* ── Detail ── */}
        <div className="space-y-4">
          <EntitySection icon={<Target size={13} style={dw.burg} />} title={bundle ? bundle.technique.techniqueId : 'Technique detail'}>
            {!bundle && (
              <EmptyNote>
                Select a technique in the matrix to see its stored mapping, the evidence behind it and
                the entities it touches.
              </EmptyNote>
            )}
            {bundle && (
              <div className="space-y-3">
                <div>
                  <p className="font-mono text-sm font-bold" style={dw.text}>{bundle.technique.name}</p>
                  <p className="font-mono text-[9px] uppercase" style={dw.faint}>{bundle.tacticLabel}</p>
                </div>
                {bundle.technique.description && (
                  <p className="text-[11px] leading-relaxed" style={dw.muted}>{bundle.technique.description}</p>
                )}
                <div>
                  <p className="font-mono text-[9px] uppercase mb-1" style={dw.faint}>Attribution confidence</p>
                  <ConfidenceBar value={bundle.technique.confidence} />
                </div>
                <div className="grid grid-cols-2 gap-2 font-mono text-[10px]">
                  <div><span style={dw.faint}>First seen</span><br /><span style={dw.text}>{bundle.technique.firstSeen.slice(0, 10)}</span></div>
                  <div><span style={dw.faint}>Last seen</span><br /><span style={dw.text}>{bundle.technique.lastSeen.slice(0, 10)}</span></div>
                </div>
                <LinkGroup
                  icon={<Users size={10} />}
                  label="Actors"
                  empty="No actor attributed to this technique."
                  items={bundle.actors.map(a => ({ key: a.id, to: actorPath(a.id), label: `${a.id} — ${a.label}` }))}
                />
                <LinkGroup
                  icon={<Network size={10} />}
                  label="Handles"
                  empty="No handle linked."
                  items={bundle.handles.map(h => ({ key: h.id, to: handlePath(h.id), label: `${h.value} (${h.platform})` }))}
                />
                <LinkGroup
                  icon={<Database size={10} />}
                  label="Infrastructure"
                  empty="No infrastructure linked."
                  items={bundle.infrastructure.map(i => ({ key: i.id, to: infraPath(), label: `${i.type} ${i.value}` }))}
                />
                <LinkGroup
                  icon={<FileText size={10} />}
                  label="Evidence"
                  empty="No supporting evidence recorded — treat this mapping as asserted only."
                  items={bundle.evidence.map(e => ({ key: e.id, to: evidencePath(), label: `${e.id} · ${e.evidenceType} · ${e.source}` }))}
                />
                {bundle.relatedTechniqueIds.length > 0 && (
                  <div>
                    <p className="font-mono text-[9px] uppercase mb-1" style={dw.faint}>
                      Co-attributed techniques <span style={dw.moss}>(correlation hint, not causation)</span>
                    </p>
                    <div className="flex flex-wrap gap-1">
                      {bundle.relatedTechniqueIds.map(id => (
                        <button
                          key={id}
                          type="button"
                          onClick={() => select(id)}
                          className="font-mono text-[10px] px-2 py-1 rounded-sm border"
                          style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-burgundy)' }}
                        >
                          {id}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </EntitySection>

          <EntitySection icon={<Layers size={13} style={dw.burg} />} title="Tactic distribution">
            <div className="space-y-1">
              {distribution.filter(d => d.techniques > 0).map(share => (
                <div key={share.tactic} className="grid grid-cols-[92px_1fr_38px] gap-2 items-center">
                  <span className="font-mono text-[9px] uppercase" style={dw.muted}>{share.short}</span>
                  <div className="h-2 rounded-sm" style={{ backgroundColor: 'var(--tw-panel-alt)' }}>
                    <div
                      className="h-2 rounded-sm"
                      style={{ width: `${Math.max(share.share, 2)}%`, backgroundColor: 'var(--tw-burgundy)' }}
                    />
                  </div>
                  <span className="font-mono text-[9px] text-right" style={dw.faint}>{share.techniques}</span>
                </div>
              ))}
              {distribution.every(d => d.techniques === 0) && <EmptyNote>No techniques recorded yet.</EmptyNote>}
            </div>
          </EntitySection>
        </div>
      </div>

      {/* ── Actor coverage ── */}
      <EntitySection icon={<Shield size={13} style={dw.burg} />} title="Actor technique coverage">
        <div className="overflow-x-auto">
          <table className="w-full font-mono text-[10px]">
            <thead>
              <tr style={dw.faint}>
                <th className="text-left py-1 pr-3 font-normal">ACTOR</th>
                <th className="text-left py-1 pr-3 font-normal">TECHNIQUES</th>
                <th className="text-left py-1 pr-3 font-normal">TACTICS</th>
                <th className="text-left py-1 pr-3 font-normal">MEAN CONF.</th>
                <th className="text-left py-1 pr-3 font-normal">UNBACKED</th>
                <th className="text-left py-1 pr-3 font-normal">WINDOW</th>
              </tr>
            </thead>
            <tbody>
              {coverage.map(row => (
                <tr key={row.actorId} style={{ borderTop: '1px solid var(--tw-border)' }}>
                  <td className="py-1.5 pr-3">
                    <EntityLink to={actorPath(row.actorId)}>{row.actorId}</EntityLink>
                    <span className="ml-2" style={dw.muted}>{row.label}</span>
                  </td>
                  <td className="py-1.5 pr-3" style={dw.text}>{row.techniques || '—'}</td>
                  <td className="py-1.5 pr-3" style={dw.text}>{row.tactics || '—'}</td>
                  <td className="py-1.5 pr-3" style={{ color: confidenceTint(row.confidence) }}>{row.confidence || '—'}</td>
                  <td className="py-1.5 pr-3" style={row.unbacked ? dw.medium : dw.faint}>{row.unbacked || '0'}</td>
                  <td className="py-1.5 pr-3" style={dw.faint}>
                    {row.firstSeen ? `${row.firstSeen.slice(0, 10)} → ${row.lastSeen.slice(0, 10)}` : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <EmptyNote>
          Unbacked counts stored mappings that carry no evidence id. They are shown rather than hidden so a
          thin attribution surface stays visible.
        </EmptyNote>
      </EntitySection>

      {/* ── Technique timeline ── */}
      <EntitySection icon={<Layers size={13} style={dw.burg} />} title="Technique timeline">
        <div className="space-y-1">
          {timeline.map(entry => (
            <button
              key={entry.techniqueId}
              type="button"
              onClick={() => select(entry.techniqueId)}
              className="w-full text-left grid grid-cols-[90px_1fr_110px_60px] gap-2 items-center px-1 py-1 rounded-sm"
              style={{ backgroundColor: selected === entry.techniqueId ? 'var(--tw-panel-alt)' : 'transparent' }}
            >
              <span className="font-mono text-[10px]" style={dw.burg}>{entry.techniqueId}</span>
              <span className="font-mono text-[10px] truncate" style={dw.text}>{entry.name}</span>
              <span className="font-mono text-[9px]" style={dw.faint}>{entry.firstSeen.slice(0, 10)}</span>
              <span className="font-mono text-[9px] text-right" style={dw.faint}>{entry.spanDays}d</span>
            </button>
          ))}
          {timeline.length === 0 && <EmptyNote>No techniques recorded yet.</EmptyNote>}
        </div>
      </EntitySection>
      <ProtectionModulePanel entityType="MITRE_TTP" />
    </div>
  );
}

function TechniqueChip({ cell, active, onSelect }: { cell: AttackCell; active: boolean; onSelect: (id: string) => void }) {
  return (
    <button
      type="button"
      onClick={() => onSelect(cell.techniqueId)}
      title={`${cell.name} — confidence ${cell.confidence}${cell.evidenceIds.length ? `, ${cell.evidenceIds.length} evidence` : ', no evidence'}`}
      className="font-mono text-[9px] px-1.5 py-1 rounded-sm border"
      style={{
        borderColor: active ? 'var(--tw-burgundy)' : 'var(--tw-border-mid)',
        backgroundColor: active ? 'var(--tw-burgundy)' : 'var(--tw-panel-alt)',
        color: active ? 'var(--tw-canvas)' : confidenceTint(cell.confidence),
      }}
    >
      {cell.techniqueId}
      {cell.evidenceIds.length === 0 && <AlertTriangle size={8} className="inline ml-1 align-middle" />}
    </button>
  );
}

function LinkGroup({ icon, label, items, empty }: {
  icon: React.ReactNode;
  label: string;
  items: { key: string; to: string; label: string }[];
  empty: string;
}) {
  return (
    <div>
      <p className="font-mono text-[9px] uppercase mb-1 flex items-center gap-1" style={dw.faint}>{icon}{label}</p>
      {items.length === 0
        ? <span className="font-mono text-[9px]" style={dw.faint}>{empty}</span>
        : (
          <div className="flex flex-wrap gap-1">
            {items.map(item => <EntityLink key={item.key} to={item.to}>{item.label}</EntityLink>)}
          </div>
        )}
    </div>
  );
}
