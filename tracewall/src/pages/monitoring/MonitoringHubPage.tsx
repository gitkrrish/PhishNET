import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Activity, ArrowRight, Plus, RefreshCw } from 'lucide-react';

import {
  formatRelativeTime,
  monitorSeverityColor,
  monitoringCapabilities,
  monitoringHub,
  runAllDueMonitors,
  type MonitoringCapabilities,
  type MonitoringHubData,
} from '../../lib/intelligence/monitoring';
import { sectionStyle } from '../../lib/darkweb/styles';
import { chipStyle, tv } from '../../lib/styles';
import {
  AddMonitorDialog,
  Counter,
  EmptyNote,
  HubHeader,
  HubTabs,
  Notice,
  Panel,
  SeverityTag,
  hubToolFor,
} from './monitoringShared';

/**
 * The centralized 24x7 monitoring dashboard.
 *
 * Every figure here is read from the one centralized monitoring engine via
 * /intel/monitoring/hub, which rolls up the same monitor rows the individual
 * tools manage. Nothing on this page keeps its own copy of monitoring state.
 */
export default function MonitoringHubPage() {
  const [hub, setHub] = useState<MonitoringHubData | null>(null);
  const [capabilities, setCapabilities] = useState<MonitoringCapabilities | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [builderOpen, setBuilderOpen] = useState(false);

  const load = useCallback(async () => {
    try {
      const [nextHub, nextCapabilities] = await Promise.all([
        monitoringHub(25),
        monitoringCapabilities(),
      ]);
      setHub(nextHub);
      setCapabilities(nextCapabilities);
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

  const runDue = async () => {
    setRunning(true);
    setNotice(null);
    try {
      const result = await runAllDueMonitors();
      setNotice(`Ran ${result.checked} due monitor(s): ${result.triggered} triggered, ${result.errors} errored.`);
      await load();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setRunning(false);
    }
  };

  const stats = hub?.stats;
  const scheduler = hub?.scheduler;
  const health = stats
    ? stats.totalMonitors === 0
      ? { label: 'NO MONITORS', color: 'var(--tw-info)' }
      : stats.failedMonitors > 0
        ? { label: 'DEGRADED', color: 'var(--tw-critical)' }
        : stats.sourceUnavailableMonitors > 0
          ? { label: 'SOURCE ISSUES', color: 'var(--tw-high)' }
          : stats.activeMonitors === 0
            ? { label: 'IDLE', color: 'var(--tw-medium)' }
            : { label: 'HEALTHY', color: 'var(--tw-low)' }
    : { label: '—', color: 'var(--tw-text-faint)' };

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        <HubHeader
          eyebrow="24×7 Monitoring"
          title="Monitoring Hub"
          description="One centralized place to watch every monitor across Viper Trace. These are the same monitors the individual tools create and manage — this view aggregates the single centralized engine rather than replacing it."
          actions={
            <>
              <ActionRun busy={running} onClick={() => void runDue()} />
              <button
                type="button"
                onClick={() => setBuilderOpen(true)}
                disabled={!capabilities}
                className="font-mono text-[10px] tracking-wider uppercase px-3 py-2 rounded-sm border flex items-center gap-1.5 disabled:opacity-50"
                style={{ backgroundColor: 'var(--tw-burgundy)', borderColor: 'var(--tw-burgundy)', color: 'var(--tw-canvas)' }}
              >
                <Plus size={11} /> Add monitor
              </button>
            </>
          }
        />

        <HubTabs active="hub" />

        {error && <Notice kind="error" text={error} onClose={() => setError(null)} />}
        {notice && <Notice kind="info" text={notice} onClose={() => setNotice(null)} />}

        {/* Platform-wide monitoring status, all read from the backend. */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          <Counter label="Total monitors" value={stats?.totalMonitors ?? 0} to="/app/monitoring/monitors" />
          <Counter label="Active" value={stats?.activeMonitors ?? 0} color="var(--tw-low)" />
          <Counter label="Running" value={stats?.runningMonitors ?? 0} color="var(--tw-burgundy)" />
          <Counter label="Paused" value={stats?.pausedMonitors ?? 0} color="var(--tw-medium)" />
          <Counter label="Error" value={stats?.failedMonitors ?? 0} color="var(--tw-critical)" />
          <Counter label="Source unavailable" value={stats?.sourceUnavailableMonitors ?? 0} color="var(--tw-high)" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <Panel title="Monitoring health" subtitle="Scheduler and collection cadence, straight from the engine">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs" style={tv.muted}>Engine</span>
                <span className="font-mono text-[10px] tracking-widest uppercase px-2 py-0.5 rounded-sm border" style={chipStyle(health.color)}>
                  {health.label}
                </span>
              </div>
              <Row label="Scheduler" value={scheduler?.started ? 'Running' : 'Stopped'} />
              <Row label="Tick interval" value={`${Math.round((scheduler?.tickMs ?? 0) / 1000)}s`} />
              <Row label="Due for a check now" value={String(scheduler?.dueNow ?? 0)} />
              <Row label="Next due" value={scheduler?.nextDueAt ? formatRelativeTime(scheduler.nextDueAt) : 'nothing scheduled'} />
              <Row label="Snapshot taken" value={hub ? formatRelativeTime(hub.generatedAt) : '—'} />
              <p className="text-[10px] leading-relaxed pt-1" style={tv.faint}>
                The scheduler re-evaluates due monitors every tick. Per-monitor cadence is set by the slowest
                collection source each monitor is bound to, so the platform never claims continuous collection it
                cannot perform.
              </p>
            </div>
          </Panel>

          <Panel title="Alerts" subtitle="Raised by the monitoring engine">
            <div className="grid grid-cols-2 gap-3">
              <Counter label="Recent alerts" value={stats?.totalAlerts ?? 0} color="var(--tw-medium)" to="/app/monitoring/alerts" />
              <Counter label="Critical (open)" value={stats?.criticalAlerts ?? 0} color="var(--tw-critical)" to="/app/monitoring/alerts" />
              <Counter label="Open" value={stats?.openAlerts ?? 0} color="var(--tw-critical)" to="/app/monitoring/alerts" />
              <Counter label="Monitors triggered" value={stats?.recentlyTriggeredMonitors ?? 0} color="var(--tw-burgundy)" />
            </div>
          </Panel>

          <Panel title="Collection cadence" subtitle="Last and next check across active monitors">
            <div className="space-y-2">
              {(stats?.lastChecks ?? []).slice(0, 3).map(monitor => (
                <MonitorLine key={`last-${monitor.id}`} monitor={monitor} field="lastCheck" />
              ))}
              {(stats?.nextChecks ?? []).slice(0, 3).map(monitor => (
                <MonitorLine key={`next-${monitor.id}`} monitor={monitor} field="nextCheck" />
              ))}
              {stats && stats.lastChecks.length === 0 && stats.nextChecks.length === 0 && (
                <EmptyNote>No active monitor has been scheduled yet.</EmptyNote>
              )}
            </div>
          </Panel>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <Panel title="Monitors by tool" subtitle="Grouped by the registry target type each monitor watches">
            {(hub?.stats.byTool ?? []).length === 0 ? (
              <EmptyNote>
                No monitors configured yet. Use <strong>Add monitor</strong> to attach 24×7 monitoring to existing intelligence.
              </EmptyNote>
            ) : (
              <table className="w-full text-xs">
                <thead>
                  <tr style={tv.faint}>
                    <th className="text-left font-mono text-[10px] tracking-widest uppercase py-1">Tool</th>
                    <th className="text-right font-mono text-[10px] tracking-widest uppercase py-1">Total</th>
                    <th className="text-right font-mono text-[10px] tracking-widest uppercase py-1">Active</th>
                    <th className="text-right font-mono text-[10px] tracking-widest uppercase py-1">Paused</th>
                    <th className="text-right font-mono text-[10px] tracking-widest uppercase py-1">Alerts</th>
                    <th className="text-right font-mono text-[10px] tracking-widest uppercase py-1">Open</th>
                  </tr>
                </thead>
                <tbody>
                  {(hub?.stats.byTool ?? []).map(tool => (
                    <tr key={tool.key} className="border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
                      <td className="py-1.5">
                        <Link to="/app/monitoring/monitors" className="flex items-center gap-1.5" style={tv.text}>
                          {tool.label} <ArrowRight size={11} style={tv.faint} />
                        </Link>
                      </td>
                      <td className="text-right py-1.5 font-mono" style={tv.text}>{tool.total}</td>
                      <td className="text-right py-1.5 font-mono" style={{ color: 'var(--tw-low)' }}>{tool.active}</td>
                      <td className="text-right py-1.5 font-mono" style={{ color: 'var(--tw-medium)' }}>{tool.paused}</td>
                      <td className="text-right py-1.5 font-mono" style={{ color: 'var(--tw-medium)' }}>{tool.alerts}</td>
                      <td className="text-right py-1.5 font-mono" style={{ color: tool.error ? 'var(--tw-critical)' : 'var(--tw-text-faint)' }}>{tool.error}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>

          <Panel title="Monitors by severity" subtitle="Analyst-configured ceiling per monitor">
            {(hub?.stats.bySeverity ?? []).length === 0 ? (
              <EmptyNote>No monitors configured yet.</EmptyNote>
            ) : (
              <table className="w-full text-xs">
                <thead>
                  <tr style={tv.faint}>
                    <th className="text-left font-mono text-[10px] tracking-widest uppercase py-1">Severity</th>
                    <th className="text-right font-mono text-[10px] tracking-widest uppercase py-1">Monitors</th>
                    <th className="text-right font-mono text-[10px] tracking-widest uppercase py-1">Alerts</th>
                    <th className="pl-4 font-mono text-[10px] tracking-widest uppercase py-1">Distribution</th>
                  </tr>
                </thead>
                <tbody>
                  {(hub?.stats.bySeverity ?? []).map(entry => {
                    const max = Math.max(1, ...(hub?.stats.bySeverity ?? []).map(item => item.total));
                    return (
                      <tr key={entry.key} className="border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
                        <td className="py-1.5"><SeverityTag severity={entry.key} /></td>
                        <td className="text-right py-1.5 font-mono" style={tv.text}>{entry.total}</td>
                        <td className="text-right py-1.5 font-mono" style={{ color: 'var(--tw-burgundy)' }}>{entry.alerts}</td>
                        <td className="pl-4 py-1.5">
                          <span
                            className="block h-1.5 rounded-sm"
                            style={{
                              width: `${Math.round((entry.total / max) * 100)}%`,
                              minWidth: entry.total ? '6px' : 0,
                              backgroundColor: monitorSeverityColor(entry.key),
                            }}
                          />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </Panel>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <Panel
            title="Recent monitoring activity"
            subtitle="Real scheduler cycles, newest first"
            action={<Link to="/app/monitoring/health" className="font-mono text-[10px] tracking-widest uppercase" style={{ color: 'var(--tw-burgundy)' }}>Run history</Link>}
          >
            {(hub?.stats.recentEvents ?? []).length === 0 ? (
              <EmptyNote>No check has run yet. Monitors are evaluated as soon as they are created.</EmptyNote>
            ) : (
              <div className="space-y-1.5 max-h-80 overflow-y-auto">
                {(hub?.stats.recentEvents ?? []).map(event => {
                  const color = event.status === 'TRIGGERED'
                    ? 'var(--tw-burgundy)'
                    : event.status === 'ERROR'
                      ? 'var(--tw-critical)'
                      : event.status === 'SOURCE_UNAVAILABLE'
                        ? 'var(--tw-high)'
                        : 'var(--tw-low)';
                  return (
                    <div key={event.id} className="flex items-start justify-between gap-3 text-xs py-1 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                      <div className="min-w-0">
                        <div className="font-mono truncate" style={tv.text}>{event.monitorId}</div>
                        <div className="text-[11px]" style={tv.muted}>{event.message ?? `${event.observationsSeen} record(s) examined`}</div>
                      </div>
                      <div className="text-right shrink-0">
                        <div className="font-mono text-[10px] tracking-widest uppercase" style={{ color }}>{event.status}</div>
                        <div className="text-[10px]" style={tv.faint}>{formatRelativeTime(event.checkAt)}</div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </Panel>

          <Panel
            title="Recently detected intelligence"
            subtitle="Alerts raised by monitored change"
            action={<Link to="/app/monitoring/alerts" className="font-mono text-[10px] tracking-widest uppercase" style={{ color: 'var(--tw-burgundy)' }}>All alerts</Link>}
          >
            {(hub?.alerts ?? []).length === 0 ? (
              <EmptyNote>No monitoring alerts. Alerts appear only when the centralized tables actually change.</EmptyNote>
            ) : (
              <div className="space-y-2 max-h-80 overflow-y-auto">
                {(hub?.alerts ?? []).slice(0, 12).map(alert => (
                  <div key={alert.id} className="rounded-sm border p-2.5" style={tv.panelBorder}>
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="font-mono text-[10px] truncate" style={tv.faint}>{alert.id} · {alert.monitorTargetType ?? '—'}</div>
                        <div className="text-xs truncate" style={tv.text}>{alert.title}</div>
                      </div>
                      <div className="shrink-0 text-right">
                        <SeverityTag severity={alert.severity} />
                        <div className="text-[10px] mt-1" style={tv.faint}>{formatRelativeTime(alert.raisedAt)}</div>
                      </div>
                    </div>
                    {alert.monitorId && (
                      <div className="text-[10px] mt-1.5 truncate" style={tv.faint}>
                        {alert.monitorName} · {alert.monitorTargetValue ?? alert.monitorTargetId}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </div>

        <Panel title="What can be monitored" subtitle="Every monitorable tool the platform exposes">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
            {(hub?.catalog ?? []).map(entry => {
              const tool = hubToolFor(entry.key);
              return (
                <Link
                  key={entry.key}
                  to={`/app/monitoring/monitors?tool=${encodeURIComponent(entry.key)}`}
                  className="rounded-sm border px-3 py-2 flex items-center justify-between gap-2"
                  style={tv.panelBorder}
                >
                  <div className="min-w-0">
                    <div className="text-xs truncate" style={tv.text}>{entry.label}</div>
                    <div className="text-[10px] truncate" style={tv.faint}>
                      {tool.label} · {entry.conditionCount} condition{entry.conditionCount === 1 ? '' : 's'}
                    </div>
                  </div>
                  <span className="font-mono text-[10px] shrink-0" style={{ color: entry.monitors ? 'var(--tw-burgundy)' : 'var(--tw-text-faint)' }}>
                    {entry.monitors}
                  </span>
                </Link>
              );
            })}
          </div>
        </Panel>

        {capabilities && (
          <AddMonitorDialog
            open={builderOpen}
            capabilities={capabilities}
            onClose={() => setBuilderOpen(false)}
            onCreated={() => { setNotice('Monitor created and scheduled. It appears in All Monitors.'); void load(); }}
          />
        )}
      </div>
    </motion.div>
  );
}

function ActionRun({ busy, onClick }: { busy: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={busy}
      className="font-mono text-[10px] tracking-wider uppercase px-3 py-2 rounded-sm border flex items-center gap-1.5 disabled:opacity-50"
      style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}
    >
      {busy ? <RefreshCw size={11} className="animate-spin" /> : <Activity size={11} />}
      Run due now
    </button>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between text-xs">
      <span style={tv.muted}>{label}</span>
      <span className="font-mono" style={tv.text}>{value}</span>
    </div>
  );
}

function MonitorLine({ monitor, field }: { monitor: { id: string; name: string; status: string; runtimeState: string }; field: 'lastCheck' | 'nextCheck' }) {
  const stamp = (monitor as unknown as Record<string, string | null>)[field];
  return (
    <div className="flex items-center justify-between gap-2 text-xs">
      <Link to="/app/monitoring/monitors" className="truncate" style={tv.text}>{monitor.name}</Link>
      <span className="font-mono text-[10px] shrink-0" style={tv.faint}>
        {field === 'lastCheck' ? 'checked ' : 'next '}
        {formatRelativeTime(stamp)}
      </span>
    </div>
  );
}