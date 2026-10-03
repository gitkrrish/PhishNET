import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { Shield, ArrowRight } from 'lucide-react';
import { dw } from '../../lib/darkweb/styles';
import { useIntelligence, useProtection } from '../../lib/intelligence/IntelligenceContext';
import { moduleProtectionSummary } from '../../lib/intelligence/detections';
import { enforcementSummaryLine } from '../../lib/intelligence/enforcement';
import { protectionStatusLabel, protectionStatusTone } from '../../lib/intelligence/detections';

const TONE_COLOR: Record<string, string> = {
  critical: 'var(--tw-critical)',
  high: 'var(--tw-high)',
  medium: 'var(--tw-medium)',
  low: 'var(--tw-low)',
  ok: 'var(--tw-moss)',
  muted: 'var(--tw-text-muted)',
};

interface Props {
  /** The module's record type, e.g. ACTOR, HANDLE, INFRASTRUCTURE. */
  entityType: string;
  title?: string;
  /** How many highest-risk records to list inline. */
  limit?: number;
}

/**
 * The module-level protection surface.
 *
 * It sits inside the module that owns the records rather than in a separate
 * protection tool, and it reads the exact same derived records the entity
 * panels read — so a count on this panel and a status on a detail page can
 * never disagree. It rolls up; it does not create or duplicate anything.
 */
export function ProtectionModulePanel({ entityType, title, limit = 8 }: Props) {
  const { dataset } = useIntelligence();
  const { records } = useProtection();

  const summary = useMemo(() => {
    // `records` is the reactive snapshot of the protection ledger; reading it
    // here re-rolls the posture whenever an analyst records an action, so the
    // roll-up and the entity panels always report the same state.
    void records;
    return moduleProtectionSummary(dataset, entityType);
  }, [dataset, entityType, records]);

  const counters = [
    { label: 'CRITICAL', value: summary.critical, tone: 'critical' },
    { label: 'HIGH', value: summary.high, tone: 'high' },
    { label: 'MEDIUM', value: summary.medium, tone: 'medium' },
    { label: 'LOW', value: summary.low, tone: 'low' },
    { label: 'NO CURRENT RISK', value: summary.inactive, tone: 'muted' },
  ];

  const workflow = [
    { label: 'At risk', value: summary.atRiskCount, tone: 'critical' },
    { label: 'Monitored', value: summary.monitoredCount, tone: 'low' },
    { label: 'Verified protected', value: summary.protectedCount, tone: 'ok' },
    { label: 'Pending integration', value: summary.awaitingIntegrationCount, tone: 'medium' },
    { label: 'Open alerts', value: summary.openAlerts, tone: summary.openAlerts > 0 ? 'high' : 'ok' },
    { label: 'Linked evidence', value: summary.linkedEvidence, tone: 'ok' },
  ];

  const rows = summary.rows.slice(0, limit);

  return (
    <div className="rounded-sm border" style={dw.panel}>
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-3 border-b" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
        <div className="flex items-center gap-2">
          <Shield size={13} style={dw.burg} />
          <span className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>{title ?? `${summary.label} — protection & response`}</span>
        </div>
        <span className="font-mono text-[9px]" style={dw.faint}>
          {summary.total} record{summary.total === 1 ? '' : 's'} · recomputed {new Date(summary.generatedAt).toLocaleTimeString()}
        </span>
      </div>

      <div className="p-4 space-y-4">
        <div className="grid grid-cols-3 lg:grid-cols-6 gap-2 text-center">
          {counters.map(counter => (
            <div key={counter.label} className="rounded-sm border p-2" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
              <p className="font-mono text-lg" style={{ color: TONE_COLOR[counter.tone] }}>{counter.value}</p>
              <p className="font-mono text-[9px] uppercase tracking-wider" style={dw.faint}>{counter.label}</p>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-2 lg:grid-cols-6 gap-2 text-center">
          {workflow.map(item => (
            <div key={item.label} className="rounded-sm border p-2" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
              <p className="font-mono text-sm" style={{ color: TONE_COLOR[item.tone] }}>{item.value}</p>
              <p className="font-mono text-[9px] uppercase tracking-wider" style={dw.faint}>{item.label}</p>
            </div>
          ))}
        </div>

        <p className="font-mono text-[9px] leading-relaxed" style={dw.faint}>{enforcementSummaryLine()}</p>

        {rows.length > 0 && (
          <div className="space-y-1.5">
            <p className="font-mono text-[9px] tracking-widest uppercase" style={dw.muted}>
              Highest-risk records — open one to see its signals, evidence and response actions
            </p>
            <div className="overflow-x-auto">
              <table className="w-full text-[10px] font-mono">
                <thead>
                  <tr style={{ backgroundColor: 'var(--tw-canvas-mid)' }}>
                    <th className="text-left p-2" style={dw.text}>Record</th>
                    <th className="text-left p-2" style={dw.text}>Score</th>
                    <th className="text-left p-2" style={dw.text}>Risk</th>
                    <th className="text-left p-2" style={dw.text}>Protection</th>
                    <th className="text-left p-2" style={dw.text}>Leading signal</th>
                    <th className="text-left p-2" style={dw.text}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map(row => (
                    <tr key={row.entityId} className="border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
                      <td className="p-2" style={dw.text}>
                        {row.path ? (
                          <Link to={row.path} className="hover:underline inline-flex items-center gap-1">
                            {row.label.length > 22 ? `${row.label.slice(0, 22)}…` : row.label} <ArrowRight size={9} />
                          </Link>
                        ) : (
                          row.label
                        )}
                      </td>
                      <td className="p-2" style={dw.text}>{row.score ? row.score.value : '—'}</td>
                      <td className="p-2" style={{ color: TONE_COLOR[row.riskLevel === 'INACTIVE' ? 'muted' : row.riskLevel.toLowerCase()] }}>
                        {row.riskLevel}
                      </td>
                      <td className="p-2" style={{ color: TONE_COLOR[protectionStatusTone(row.status)] }}>
                        {protectionStatusLabel(row.status)}
                      </td>
                      <td className="p-2" style={dw.muted}>{row.topReason ? `${row.topReason.label} · ${row.topReason.detail}` : row.recommendation}</td>
                      <td className="p-2" style={dw.faint}>
                        {row.openActions === 0
                          ? '—'
                          : row.awaitingIntegration > 0
                            ? `${row.openActions} recorded · ${row.awaitingIntegration} pending`
                            : `${row.openActions} recorded`}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        <div className="flex flex-wrap gap-1.5">
          {[
            { to: '/app/darkweb/alerts', label: 'Monitoring & Alerts' },
            { to: '/app/darkweb/investigations', label: 'Investigations' },
            { to: '/app/darkweb/evidence', label: 'Evidence locker' },
            { to: '/app/darkweb/timeline', label: 'Timeline' },
          ].map(link => (
            <Link
              key={link.to}
              to={link.to}
              className="font-mono text-[9px] uppercase tracking-wider px-2 py-1 rounded-sm border hover:underline"
              style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}
            >
              {link.label}
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}