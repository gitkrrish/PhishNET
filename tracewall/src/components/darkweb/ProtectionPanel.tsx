import { useEffect, useMemo, useState } from 'react';
import { Shield, Radio } from 'lucide-react';
import { dw } from '../../lib/darkweb/styles';
import { useIntelligence, useProtection } from '../../lib/intelligence/IntelligenceContext';
import { protectionView } from '../../lib/intelligence/detections';
import { enforcementSummaryLine } from '../../lib/intelligence/enforcement';
import type { MonitoringStateRef } from '../../lib/intelligence/types-protection';
import { ThreatScoreBadge } from '../ui/ThreatScoreBadge';
import { RiskBadge } from '../ui/RiskBadge';
import { monitorsForEntity } from '../../lib/intelligence/monitoring';
import { ActionHistory, Caveats, FactGrid, ProtectionLinks, ResponseActions } from './ResponseActions';

interface ProtectionPanelProps {
  entityType: string;
  entityId: string;
  /** Overrides the module-derived label, for pages that already show it. */
  entityValue?: string;
  title?: string;
}

/**
 * The protection and response surface for one record, mounted inside the
 * module that already owns that record.
 *
 * It reads the same derived detection the module page shows and the same
 * response-action ledger the rest of the platform reads, so a status can
 * never disagree between pages. It creates no intelligence record of its
 * own: every value here is a read over an existing entity id.
 */
export function ProtectionPanel({ entityType, entityId, title = 'Protection & Response' }: ProtectionPanelProps) {
  const { dataset } = useIntelligence();
  const { records } = useProtection();
  const [monitoring, setMonitoring] = useState<MonitoringStateRef | null>(null);

  // Monitoring state is the one part that lives in the centralized backend,
  // so it is read from there rather than derived.
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const found = await monitorsForEntity(entityType, entityId);
        if (cancelled || found.length === 0) {
          if (!cancelled) setMonitoring(null);
          return;
        }
        const active = found.find(monitor => monitor.status === 'ACTIVE');
        const chosen = active ?? found[0];
        const label = chosen.runtimeState === 'SOURCE_UNAVAILABLE'
          ? 'SOURCE UNAVAILABLE'
          : chosen.runtimeState === 'ERROR'
            ? 'MONITOR ERROR'
            : chosen.status;
        setMonitoring({
          status: (chosen.status === 'ACTIVE' ? 'ACTIVE' : chosen.status === 'PAUSED' ? 'PAUSED' : 'DISABLED') as MonitoringStateRef['status'],
          label,
          detail: `${chosen.capability?.intervalLabel ?? 'scheduled'} interval · last check ${chosen.lastCheck ? new Date(chosen.lastCheck).toLocaleString() : 'never'} · next ${chosen.nextCheck ? new Date(chosen.nextCheck).toLocaleString() : 'unscheduled'}`,
        });
      } catch {
        // The backend is optional for this panel: without it the panel still
        // shows the derived detection and says monitoring is unknown.
        if (!cancelled) setMonitoring(null);
      }
    })();
    return () => { cancelled = true; };
  }, [entityType, entityId]);

  const view = useMemo(() => {
    // `records` is the reactive snapshot of the response-action ledger.
    // Reading it here is what re-runs this derivation after an analyst
    // records an action, so the panel's status cannot go stale.
    void records;
    return protectionView(dataset, entityType, entityId);
  }, [dataset, entityType, entityId, records]);

  if (!view) {
    return (
      <div className="rounded-sm border p-4" style={dw.panel}>
        <div className="flex items-center gap-2 mb-2">
          <Shield size={13} style={dw.burg} />
          <span className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>{title}</span>
        </div>
        <p className="font-mono text-[10px]" style={dw.faint}>
          No detection rule covers this record class, so nothing is reported here. That is an absence of coverage,
          not an absence of risk.
        </p>
      </div>
    );
  }

  const effective: MonitoringStateRef = monitoring ?? {
    status: 'NONE',
    label: 'NOT MONITORED',
    detail: 'No 24×7 monitor is bound to this record. Monitoring binds to this existing id, so nothing is duplicated when one is started.',
  };

  return (
    <div className="rounded-sm border" style={dw.panel}>
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-3 border-b" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
        <div className="flex items-center gap-2">
          <Shield size={13} style={dw.burg} />
          <span className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>{title}</span>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {view.score && <ThreatScoreBadge score={view.score} />}
          {view.score && <RiskBadge risk={view.score.riskLevel} dot={false} />}
        </div>
      </div>

      <div className="p-4 space-y-4">
        <div className="space-y-1">
          <p className="text-sm" style={dw.text}>{view.headline}</p>
          <p className="font-mono text-[10px] leading-relaxed" style={dw.muted}>{view.detectionSummary}</p>
        </div>

        {/* Detection reason — every score states what produced it */}
        {view.reasons.length > 0 && (
          <div className="space-y-1.5">
            <p className="font-mono text-[9px] tracking-widest uppercase" style={dw.muted}>Detection signals ({view.reasons.length})</p>
            <div className="space-y-1">
              {[...view.reasons].sort((a, b) => b.weight - a.weight).map((reason, index) => (
                // Index is part of the key so that two signals of the same kind
                // are both rendered. React silently drops or duplicates rows
                // that share a key, which would hide a detection from an
                // analyst rather than just mis-order it.
                <div key={`${reason.signal}-${reason.label}-${index}`} className="flex items-start justify-between gap-3 p-2 rounded-sm border" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                  <div className="min-w-0">
                    <span className="font-mono text-[10px]" style={dw.text}>{reason.label}</span>
                    <p className="font-mono text-[9px] leading-relaxed" style={dw.faint}>{reason.detail}</p>
                  </div>
                  <span className="font-mono text-[9px] shrink-0" style={dw.muted}>w{reason.weight}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Supporting intelligence */}
        <div className="space-y-2">
          <p className="font-mono text-[9px] tracking-widest uppercase" style={dw.muted}>Supporting intelligence</p>
          <FactGrid facts={view.facts} />
        </div>

        {/* Monitoring, alerts, evidence, investigation */}
        <div className="grid md:grid-cols-2 gap-3">
          <div className="p-2.5 rounded-sm border space-y-1" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
            <p className="font-mono text-[9px] uppercase tracking-wider flex items-center gap-1" style={dw.muted}>
              <Radio size={10} /> Monitoring status
            </p>
            <p className="font-mono text-[10px]" style={effective.status === 'ACTIVE' ? dw.moss : effective.status === 'NONE' ? dw.muted : dw.medium}>{effective.label}</p>
            <p className="font-mono text-[9px] leading-relaxed" style={dw.faint}>{effective.detail}</p>
          </div>

          <div className="p-2.5 rounded-sm border space-y-1" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
            <p className="font-mono text-[9px] uppercase tracking-wider" style={dw.muted}>Related alerts ({view.alerts.length})</p>
            {view.alerts.length === 0 ? (
              <p className="font-mono text-[9px]" style={dw.faint}>No open alert references this record.</p>
            ) : (
              view.alerts.map(alert => (
                <div key={alert.id} className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[9px] truncate" style={dw.text}>{alert.title}</span>
                  <span className="font-mono text-[9px] shrink-0" style={alert.severity === 'CRITICAL' ? dw.critical : dw.muted}>{alert.severity}</span>
                </div>
              ))
            )}
          </div>

          <div className="p-2.5 rounded-sm border space-y-1" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
            <p className="font-mono text-[9px] uppercase tracking-wider" style={dw.muted}>Supporting evidence ({view.evidence.length})</p>
            {view.evidence.length === 0 ? (
              <p className="font-mono text-[9px]" style={dw.faint}>No evidence is linked to this record.</p>
            ) : (
              view.evidence.slice(0, 4).map(item => (
                <div key={item.id} className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[9px]" style={dw.text}>{item.id} · {item.evidenceType.replace(/_/g, ' ')}</span>
                  <span className="font-mono text-[9px] shrink-0" style={dw.faint}>R{item.reliability}</span>
                </div>
              ))
            )}
          </div>

          <div className="p-2.5 rounded-sm border space-y-1" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
            <p className="font-mono text-[9px] uppercase tracking-wider" style={dw.muted}>Linked investigations ({view.investigations.length})</p>
            {view.investigations.length === 0 ? (
              <p className="font-mono text-[9px]" style={dw.faint}>No investigation currently scopes this record.</p>
            ) : (
              view.investigations.map(inv => (
                <div key={inv.id} className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[9px] truncate" style={dw.text}>{inv.id} · {inv.title}</span>
                  <span className="font-mono text-[9px] shrink-0" style={dw.faint}>{inv.status}</span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Recommended defensive action */}
        <div className="p-2.5 rounded-sm border" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-burgundy) 10%, transparent)', borderColor: 'var(--tw-border-mid)' }}>
          <p className="font-mono text-[9px] tracking-widest uppercase" style={dw.muted}>Recommended defensive action</p>
          <p className="font-mono text-[11px] mt-0.5" style={dw.burg}>{view.recommendation.label}</p>
          <p className="font-mono text-[9px] leading-relaxed mt-0.5" style={dw.muted}>{view.recommendation.detail}</p>
        </div>

        {/* Response actions */}
        <div className="space-y-2">
          <p className="font-mono text-[9px] tracking-widest uppercase" style={dw.muted}>Response actions</p>
          <p className="font-mono text-[9px] leading-relaxed" style={dw.faint}>{enforcementSummaryLine()}</p>
          <ResponseActions view={view} />
        </div>

        {/* Audit history */}
        <div className="space-y-2">
          <p className="font-mono text-[9px] tracking-widest uppercase" style={dw.muted}>Response history ({view.records.length})</p>
          <ActionHistory view={view} />
        </div>

        <Caveats caveats={view.caveats} />
        <ProtectionLinks view={view} />
      </div>
    </div>
  );
}