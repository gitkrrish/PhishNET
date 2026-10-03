import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Activity, RefreshCw, Zap } from 'lucide-react';

import {
  UNREAD,
  figure,
  formatRelativeTime,
  listMonitors,
  monitoringCapabilities,
  monitoringHub,
  runAllDueMonitors,
  schedulerState,
  tickLabel,
  type Monitor,
  type MonitoringCapabilities,
  type MonitoringHubData,
} from '../../lib/intelligence/monitoring';
import { useIntelligenceData } from '../../lib/intelligence/IntelligenceContext';
import { sectionStyle } from '../../lib/darkweb/styles';
import { chipStyle, tv } from '../../lib/styles';
import { EmptyNote, HubHeader, HubTabs, Notice, Panel, StatusChip, hubToolFor } from './monitoringShared';

/**
 * Scheduler, source health and run history.
 *
 * This view states what the engine can actually do: which tick is running,
 * what each collection source really permits, and what every recent cycle
 * found. It deliberately does not present a source as continuous when its
 * access mode cannot support it.
 */
export default function MonitoringHealthPage() {
  const [hub, setHub] = useState<MonitoringHubData | null>(null);
  const [monitors, setMonitors] = useState<Monitor[]>([]);
  const [capabilities, setCapabilities] = useState<MonitoringCapabilities | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [order, setOrder] = useState<'recent' | 'upcoming'>('recent');

  const data = useIntelligenceData();

  const load = useCallback(async () => {
    try {
      const [nextHub, nextMonitors, nextCapabilities] = await Promise.all([
        monitoringHub(25),
        listMonitors(),
        monitoringCapabilities(),
      ]);
      setHub(nextHub);
      setMonitors(nextMonitors);
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
      setNotice(`Ran ${result.checked} due monitor(s): ${result.triggered} triggered, ${result.errors} errored, ${result.dueCount} were due.`);
      await load();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setRunning(false);
    }
  };

  const scheduler = hub?.scheduler;
  const runtimeStates = hub?.stats.byRuntimeState ?? {};

  const scheduled = useMemo(() => {
    const active = monitors.filter(monitor => monitor.status === 'ACTIVE');
    return order === 'recent'
      ? active.filter(monitor => monitor.lastCheck)
          .sort((a, b) => new Date(b.lastCheck!).getTime() - new Date(a.lastCheck!).getTime())
      : active.filter(monitor => monitor.nextCheck)
          .sort((a, b) => new Date(a.nextCheck!).getTime() - new Date(b.nextCheck!).getTime());
  }, [monitors, order]);

  const sourceRows = useMemo(() => {
    return data.darkWebSources.map(source => {
      const capability = capabilities?.sourceCapabilities[source.type];
      const bound = monitors.filter(monitor => (monitor.sources ?? []).includes(source.id));
      return { source, capability, boundCount: bound.length };
    });
  }, [data.darkWebSources, capabilities, monitors]);

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        <HubHeader
          eyebrow="24×7 Monitoring"
          title="Run History &amp; Health"
          description="The real state of the centralized monitoring engine: its scheduler, the collection cadence each source actually permits, and the outcome of every recent cycle."
          actions={
            <button
              type="button"
              onClick={() => void runDue()}
              disabled={running}
              className="font-mono text-[10px] tracking-wider uppercase px-3 py-2 rounded-sm border flex items-center gap-1.5 disabled:opacity-50"
              style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}
            >
              {running ? <RefreshCw size={11} className="animate-spin" /> : <Zap size={11} />}
              Run due now
            </button>
          }
        />

        <HubTabs active="health" />

        {error && <Notice kind="error" text={error} onClose={() => setError(null)} />}
        {notice && <Notice kind="info" text={notice} onClose={() => setNotice(null)} />}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <Panel title="Scheduler" subtitle="The single engine every monitor runs on">
            <div className="space-y-2 text-xs">
              <Row label="State" value={schedulerState(scheduler).label} color={schedulerState(scheduler).color} />
              <Row label="Tick interval" value={tickLabel(scheduler)} />
              <Row label="Due now" value={figure(scheduler?.dueNow)} />
              <Row label="Next due" value={scheduler ? (scheduler.nextDueAt ? formatRelativeTime(scheduler.nextDueAt) : 'nothing scheduled') : UNREAD} />
              <Row label="Snapshot" value={hub ? formatRelativeTime(hub.generatedAt) : '—'} />
              <p className="text-[10px] leading-relaxed pt-2" style={tv.faint}>
                Monitors are selected for a cycle by their persisted next-check time, so a restart resumes exactly where
                the last cycle stopped. There is no separate queue or worker store to fall out of step.
              </p>
            </div>
          </Panel>

          <Panel title="Runtime state" subtitle="Where every monitor currently sits">
            {Object.keys(runtimeStates).length === 0 ? (
              <EmptyNote>No monitors configured.</EmptyNote>
            ) : (
              <div className="space-y-2">
                {Object.entries(runtimeStates).map(([state, count]) => {
                  const total = monitors.length || 1;
                  const color =
                    state === 'ERROR' ? 'var(--tw-critical)'
                      : state === 'SOURCE_UNAVAILABLE' ? 'var(--tw-high)'
                        : state === 'RUNNING' ? 'var(--tw-burgundy)'
                          : state === 'AWAITING_DATA' ? 'var(--tw-info)'
                            : 'var(--tw-low)';
                  return (
                    <div key={state}>
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-mono text-[10px] tracking-widest uppercase" style={{ color }}>{state.replace(/_/g, ' ')}</span>
                        <span className="font-mono" style={tv.text}>{count}</span>
                      </div>
                      <span
                        className="block h-1.5 rounded-sm mt-1"
                        style={{ width: `${Math.max(4, Math.round((count / total) * 100))}%`, backgroundColor: color }}
                      />
                    </div>
                  );
                })}
              </div>
            )}
          </Panel>

          <Panel title="Lifecycle" subtitle="Analyst-controlled state, independent of runtime">
            <div className="space-y-2 text-xs">
              <Row label="Active" value={String(figure(hub?.stats.activeMonitors))} color="var(--tw-low)" />
              <Row label="Paused" value={String(figure(hub?.stats.pausedMonitors))} color="var(--tw-medium)" />
              <Row label="Disabled" value={String(figure(hub?.stats.disabledMonitors))} color="var(--tw-dust)" />
              <Row label="Awaiting data" value={String(figure(hub?.stats.awaitingDataMonitors))} color="var(--tw-info)" />
              <Row label="Failed" value={String(figure(hub?.stats.failedMonitors))} color="var(--tw-critical)" />
              <Row label="Source unavailable" value={String(figure(hub?.stats.sourceUnavailableMonitors))} color="var(--tw-high)" />
              <Row label="Total" value={String(figure(hub?.stats.totalMonitors))} />
            </div>
          </Panel>
        </div>

        <Panel title="Collection sources" subtitle="What each source's access mode actually permits">
          {sourceRows.length === 0 ? (
            <EmptyNote>No collection sources are recorded.</EmptyNote>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs min-w-[720px]">
                <thead>
                  <tr style={tv.faint}>
                    <th className="text-left font-mono text-[10px] tracking-widest uppercase py-1">Source</th>
                    <th className="text-left font-mono text-[10px] tracking-widest uppercase py-1">Type</th>
                    <th className="text-left font-mono text-[10px] tracking-widest uppercase py-1">Status</th>
                    <th className="text-right font-mono text-[10px] tracking-widest uppercase py-1">Real cadence</th>
                    <th className="text-left font-mono text-[10px] tracking-widest uppercase py-1">Continuous?</th>
                    <th className="text-right font-mono text-[10px] tracking-widest uppercase py-1">Monitors bound</th>
                  </tr>
                </thead>
                <tbody>
                  {sourceRows.map(({ source, capability, boundCount }) => (
                    <tr key={source.id} className="border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
                      <td className="py-1.5">
                        <div className="font-mono text-[11px]" style={tv.text}>{source.name}</div>
                        <div className="font-mono text-[10px]" style={tv.faint}>{source.id}</div>
                      </td>
                      <td className="py-1.5 font-mono text-[10px]" style={tv.muted}>{source.type}</td>
                      <td className="py-1.5">
                        <span
                          className="font-mono text-[10px] tracking-widest uppercase px-2 py-0.5 rounded-sm border"
                          style={chipStyle(source.status === 'ACTIVE' ? 'var(--tw-low)' : 'var(--tw-medium)')}
                        >
                          {source.status}
                        </span>
                      </td>
                      <td className="py-1.5 text-right font-mono text-[10px]" style={tv.text}>
                        {capability ? `${capability.seconds}s` : '—'}
                      </td>
                      <td className="py-1.5 text-[10px]" style={capability?.continuous ? { color: 'var(--tw-low)' } : tv.faint}>
                        {capability?.continuous ? 'Yes' : 'No — interval collection'}
                      </td>
                      <td className="py-1.5 text-right font-mono text-[10px]" style={tv.text}>{boundCount}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="text-[10px] leading-relaxed mt-3" style={tv.faint}>
            A monitor's effective interval is capped by the slowest source bound to it. Where a source cannot be polled
            continuously, the platform reports interval collection rather than implying live coverage.
          </p>
        </Panel>

        <Panel
          title="Scheduler cycles"
          subtitle={order === 'recent' ? 'Most recent check per active monitor' : 'Next scheduled check per active monitor'}
          action={
            <div className="flex gap-1">
              {(['recent', 'upcoming'] as const).map(value => (
                <button
                  key={value}
                  type="button"
                  onClick={() => setOrder(value)}
                  className="font-mono text-[10px] tracking-widest uppercase px-2.5 py-1 rounded-sm border"
                  style={{
                    borderColor: order === value ? 'var(--tw-burgundy)' : 'var(--tw-border-mid)',
                    color: order === value ? 'var(--tw-burgundy)' : 'var(--tw-text-faint)',
                  }}
                >
                  {value === 'recent' ? 'Recent' : 'Upcoming'}
                </button>
              ))}
            </div>
          }
        >
          {scheduled.length === 0 ? (
            <EmptyNote>No active monitor to schedule.</EmptyNote>
          ) : (
            <div className="space-y-1.5">
              {scheduled.map(monitor => {
                const tool = hubToolFor(monitor.targetType);
                return (
                  <div
                    key={monitor.id}
                    className="flex flex-wrap items-center justify-between gap-2 py-1.5 border-b"
                    style={{ borderColor: 'var(--tw-border-mid)' }}
                  >
                    <div className="min-w-0">
                      <Link to="/app/monitoring/monitors" className="font-mono text-[11px] truncate block" style={tv.text}>
                        {monitor.name}
                      </Link>
                      <div className="font-mono text-[10px]" style={tv.faint}>
                        {monitor.id} · {tool.label} · cadence {monitor.capability?.intervalLabel ?? '—'}
                        {monitor.effectiveFrequency === 'INTERVAL_CAPPED' ? ' (interval capped)' : ''}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <StatusChip monitor={monitor} />
                      <span className="font-mono text-[10px]" style={tv.muted}>
                        {order === 'recent' ? 'last' : 'next'} {formatRelativeTime(order === 'recent' ? monitor.lastCheck : monitor.nextCheck)}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>

        <Panel title="Recent cycle outcomes" subtitle="Newest first, straight from the run log">
          {(hub?.stats.recentEvents ?? []).length === 0 ? (
            <EmptyNote>No cycle has run yet.</EmptyNote>
          ) : (
            <div className="space-y-1.5 max-h-96 overflow-y-auto">
              {(hub?.stats.recentEvents ?? []).map(event => {
                const color =
                  event.status === 'TRIGGERED' ? 'var(--tw-burgundy)'
                    : event.status === 'ERROR' ? 'var(--tw-critical)'
                      : event.status === 'SOURCE_UNAVAILABLE' ? 'var(--tw-high)'
                        : 'var(--tw-low)';
                return (
                  <div
                    key={event.id}
                    className="flex flex-wrap items-start justify-between gap-2 py-1.5 border-b"
                    style={{ borderColor: 'var(--tw-border-mid)' }}
                  >
                    <div className="min-w-0">
                      <Link to="/app/monitoring/monitors" className="font-mono text-[11px]" style={tv.text}>{event.monitorId}</Link>
                      <div className="text-[10px]" style={tv.muted}>{event.message ?? `${event.observationsSeen} record(s) examined, no change`}</div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className="font-mono text-[10px] tracking-widest uppercase" style={{ color }}>{event.status.replace(/_/g, ' ')}</span>
                      <span className="font-mono text-[10px]" style={tv.faint}>{formatRelativeTime(event.checkAt)}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>

        <p className="text-[10px] flex items-center gap-1.5" style={tv.faint}>
          <Activity size={11} />
          All figures are read from the centralized monitoring engine at{' '}
          <span className="font-mono">/api/intel/monitoring/hub</span>. No monitoring state is held in the browser.
        </p>
      </div>
    </motion.div>
  );
}

function Row({ label, value, color }: { label: string; value: string | number; color?: string }) {
  return (
    <div className="flex items-center justify-between">
      <span style={tv.muted}>{label}</span>
      <span className="font-mono" style={{ color: color ?? 'var(--tw-text)' }}>{value}</span>
    </div>
  );
}