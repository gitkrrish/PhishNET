import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { CheckCircle2, ExternalLink, RefreshCw, Search } from 'lucide-react';

import {
  formatRelativeTime,
  monitorSeverityColor,
  monitoringHub,
  setAlertStatus,
  type MonitoringHubAlert,
  type MonitoringHubData,
} from '../../lib/intelligence/monitoring';
import { sectionStyle } from '../../lib/darkweb/styles';
import { chipStyle, tv } from '../../lib/styles';
import { ConfidenceBar } from '../../components/ui/ConfidenceBar';
import { EmptyNote, HubHeader, HubTabs, Notice, Panel, SeverityTag, hubEntityHref, hubToolFor } from './monitoringShared';

/**
 * The single alert view for everything 24x7 monitoring detects.
 *
 * These are the same alerts the per-tool alert centres show; the hub only
 * collects them and adds a direct route back to the entity and tool that
 * produced each one.
 */
export default function MonitoringAlertsPage() {
  const [hub, setHub] = useState<MonitoringHubData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('OPEN');
  const [severityFilter, setSeverityFilter] = useState('ALL');

  const load = useCallback(async () => {
    try {
      setHub(await monitoringHub(100));
      setError(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  }, []);

  useEffect(() => {
    void load();
    const timer = setInterval(() => void load(), 30000);
    return () => clearInterval(timer);
  }, [load]);

  const triage = async (alert: MonitoringHubAlert, status: string) => {
    setBusyId(alert.id);
    setError(null);
    setNotice(null);
    try {
      await setAlertStatus(alert.id, status);
      setNotice(`${alert.id} marked ${status}.`);
      await load();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setBusyId(null);
    }
  };

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return (hub?.alerts ?? []).filter(alert => {
      if (statusFilter !== 'ALL' && alert.status !== statusFilter) return false;
      if (severityFilter !== 'ALL' && alert.severity !== severityFilter) return false;
      if (!needle) return true;
      const haystack = [
        alert.id,
        alert.title,
        alert.reason,
        alert.severity,
        alert.status,
        alert.monitorId,
        alert.monitorName,
        alert.monitorTargetType,
        alert.monitorTargetValue,
        alert.monitorTargetId,
        alert.entityId,
        alert.entityType,
        ...(alert.triggerConditions ?? []).map(condition => `${condition.key} ${condition.label}`),
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      return haystack.includes(needle);
    });
  }, [hub, query, statusFilter, severityFilter]);

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        <HubHeader
          eyebrow="24×7 Monitoring"
          title="Monitoring Alerts"
          description="Every alert raised by the centralized monitoring engine, across all tools. Each alert links straight back to the monitor, the entity and the tool that produced it."
          actions={
            <button
              type="button"
              onClick={() => void load()}
              className="font-mono text-[10px] tracking-wider uppercase px-3 py-2 rounded-sm border flex items-center gap-1.5"
              style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}
            >
              <RefreshCw size={11} /> Refresh
            </button>
          }
        />

        <HubTabs active="alerts" />

        {error && <Notice kind="error" text={error} onClose={() => setError(null)} />}
        {notice && <Notice kind="info" text={notice} onClose={() => setNotice(null)} />}

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Object.entries(hub?.alertsBySeverity ?? {}).map(([severity, count]) => (
            <div key={severity} className="rounded-sm border px-4 py-3" style={tv.panelBorder}>
              <div className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>{severity}</div>
              <div className="font-serif text-2xl mt-1" style={{ color: monitorSeverityColor(severity) }}>{count}</div>
            </div>
          ))}
          {Object.keys(hub?.alertsBySeverity ?? {}).length === 0 && (
            <div className="md:col-span-4"><EmptyNote>No monitoring alert has been raised.</EmptyNote></div>
          )}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <label className="block space-y-1 md:col-span-1">
            <span className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>Search alerts</span>
            <span className="relative block">
              <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={tv.faint} />
              <input
                value={query}
                onChange={event => setQuery(event.target.value)}
                placeholder="Alert, entity, monitor, tool, condition, confidence…"
                className="w-full rounded-sm pl-8 pr-2 py-2 text-xs"
                style={tv.input}
              />
            </span>
          </label>
          <label className="block space-y-1">
            <span className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>Status</span>
            <select value={statusFilter} onChange={event => setStatusFilter(event.target.value)} className="w-full rounded-sm px-2 py-2 text-xs" style={tv.input}>
              <option value="ALL">All</option>
              {['OPEN', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'DISMISSED'].map(status => (
                <option key={status} value={status}>{status}</option>
              ))}
            </select>
          </label>
          <label className="block space-y-1">
            <span className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>Severity</span>
            <select value={severityFilter} onChange={event => setSeverityFilter(event.target.value)} className="w-full rounded-sm px-2 py-2 text-xs" style={tv.input}>
              <option value="ALL">All</option>
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'].map(severity => (
                <option key={severity} value={severity}>{severity}</option>
              ))}
            </select>
          </label>
        </div>

        <Panel title={`Alerts (${filtered.length})`} subtitle="Newest first, as raised by the monitoring engine">
          {filtered.length === 0 ? (
            <EmptyNote>
              No alert matches. Monitoring only raises an alert when the centralized intelligence tables actually change.
            </EmptyNote>
          ) : (
            <div className="space-y-3">
              {filtered.map(alert => {
                const tool = hubToolFor(alert.monitorTargetType ?? alert.entityType);
                const entityHref = hubEntityHref(alert.monitorTargetType ?? alert.entityType, alert.monitorTargetId ?? alert.entityId);
                const busy = busyId === alert.id;
                return (
                  <article key={alert.id} className="rounded-sm border p-3" style={tv.panelBorder}>
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="font-mono text-[10px]" style={tv.faint}>
                          {alert.id} · {formatRelativeTime(alert.raisedAt)} · {new Date(alert.raisedAt).toLocaleString()}
                        </div>
                        <h3 className="font-serif text-base mt-0.5" style={tv.text}>{alert.title}</h3>
                        <p className="text-xs mt-1" style={tv.muted}>{alert.reason}</p>
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        <SeverityTag severity={alert.severity} />
                        <span
                          className="font-mono text-[10px] tracking-widest uppercase px-2 py-0.5 rounded-sm border"
                          style={chipStyle(alert.status === 'OPEN' ? 'var(--tw-critical)' : 'var(--tw-dust)')}
                        >
                          {alert.status}
                        </span>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-3 text-xs">
                      <Meta label="Source tool" value={tool.label} sub={alert.monitorTargetType ?? alert.entityType ?? '—'} />
                      <Meta
                        label="Entity"
                        value={alert.monitorTargetValue ?? alert.monitorTargetId ?? alert.entityId ?? '—'}
                        sub={alert.monitorTargetId ?? alert.entityId ?? undefined}
                      />
                      <Meta label="Monitor" value={alert.monitorName ?? '—'} sub={alert.monitorId ?? undefined} />
                      <div>
                        <div className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>Confidence</div>
                        <ConfidenceBar value={alert.confidence} />
                      </div>
                    </div>

                    {alert.triggerConditions?.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-3">
                        {alert.triggerConditions.map(condition => (
                          <span
                            key={condition.key}
                            className="font-mono text-[10px] tracking-wider uppercase px-2 py-0.5 rounded-sm border"
                            style={chipStyle('var(--tw-burgundy)')}
                          >
                            {condition.label} · {condition.count}
                          </span>
                        ))}
                      </div>
                    )}

                    <div className="flex flex-wrap items-center gap-2 mt-3 text-[10px]" style={tv.faint}>
                      <span>{alert.evidenceIds.length} evidence record(s)</span>
                      <span>·</span>
                      <span>{alert.observationIds.length} observation(s)</span>
                      {alert.investigationId && (
                        <>
                          <span>·</span>
                          <Link to={`/app/darkweb/investigations/${alert.investigationId}`} style={{ color: 'var(--tw-burgundy)' }}>
                            Investigation {alert.investigationId}
                          </Link>
                        </>
                      )}
                    </div>

                    <div className="flex flex-wrap items-center gap-2 mt-3">
                      {entityHref && (
                        <Link
                          to={entityHref}
                          className="font-mono text-[10px] tracking-wider uppercase px-2.5 py-1 rounded-sm border flex items-center gap-1.5"
                          style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}
                        >
                          <ExternalLink size={10} /> Open entity
                        </Link>
                      )}
                      <Link
                        to={tool.toolPath}
                        className="font-mono text-[10px] tracking-wider uppercase px-2.5 py-1 rounded-sm border flex items-center gap-1.5"
                        style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}
                      >
                        <ExternalLink size={10} /> Open {tool.label}
                      </Link>
                      {alert.evidenceIds.length > 0 && (
                        <Link
                          to="/app/darkweb/evidence"
                          className="font-mono text-[10px] tracking-wider uppercase px-2.5 py-1 rounded-sm border"
                          style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}
                        >
                          Evidence
                        </Link>
                      )}
                      {alert.status === 'OPEN' && (
                        <>
                          <Action label="Acknowledge" busy={busy} onClick={() => void triage(alert, 'ACKNOWLEDGED')} />
                          <Action label="Resolve" busy={busy} onClick={() => void triage(alert, 'RESOLVED')} />
                        </>
                      )}
                      {alert.status !== 'OPEN' && alert.status !== 'RESOLVED' && (
                        <Action label="Reopen" busy={busy} onClick={() => void triage(alert, 'OPEN')} />
                      )}
                    </div>
                  </article>
                );
              })}
            </div>
          )}
        </Panel>
      </div>
    </motion.div>
  );
}

function Meta({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="min-w-0">
      <div className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>{label}</div>
      <div className="font-mono text-[11px] truncate mt-0.5" style={tv.text}>{value}</div>
      {sub && <div className="font-mono text-[10px] truncate" style={tv.faint}>{sub}</div>}
    </div>
  );
}

function Action({ label, onClick, busy }: { label: string; onClick: () => void; busy?: boolean }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={busy}
      className="font-mono text-[10px] tracking-wider uppercase px-2.5 py-1 rounded-sm border flex items-center gap-1.5 disabled:opacity-40"
      style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
    >
      {busy ? <RefreshCw size={10} className="animate-spin" /> : <CheckCircle2 size={10} />}
      {label}
    </button>
  );
}