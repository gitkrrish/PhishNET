import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import {
  ExternalLink,
  Filter,
  Pause,
  Play,
  Plus,
  RefreshCw,
  Search,
  Trash2,
  X,
  Zap,
} from 'lucide-react';

import {
  analyzeMonitor,
  conditionLabel,
  deleteMonitor,
  formatRelativeTime,
  getMonitor,
  listMonitors,
  monitoringCapabilities,
  runMonitor,
  setMonitorStatus,
  updateMonitor,
  type Monitor,
  type MonitorCondition,
  type MonitorDetail,
  type MonitoringAnalysis,
  type MonitoringCapabilities,
} from '../../lib/intelligence/monitoring';
import { sectionStyle } from '../../lib/darkweb/styles';
import { chipStyle, tv } from '../../lib/styles';
import { useIntelligenceData } from '../../lib/intelligence/IntelligenceContext';
import {
  AddMonitorDialog,
  EmptyNote,
  HubHeader,
  HubTabs,
  Notice,
  Panel,
  SeverityTag,
  StatusChip,
  hubEntityHref,
  hubToolFor,
} from './monitoringShared';

/**
 * Every monitor on the platform in one list.
 *
 * The list is not a separate registry: it is the centralized monitor table
 * read through the same endpoint the dossier-level "Monitor 24x7" controls
 * write to, so a monitor added here is immediately visible to the tool that
 * owns its entity and vice versa.
 */
export default function MonitoringMonitorsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [monitors, setMonitors] = useState<Monitor[]>([]);
  const [capabilities, setCapabilities] = useState<MonitoringCapabilities | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [toolFilter, setToolFilter] = useState(searchParams.get('tool') ?? 'ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [builderOpen, setBuilderOpen] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [nextMonitors, nextCapabilities] = await Promise.all([listMonitors(), monitoringCapabilities()]);
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

  // "Monitors by tool" deep-links from the hub with ?tool=KEY.
  useEffect(() => {
    const next = searchParams.get('tool');
    if (next) setToolFilter(next);
  }, [searchParams]);

  const act = async (monitor: Monitor, action: 'pause' | 'resume' | 'disable' | 'enable' | 'delete' | 'run') => {
    setBusyId(monitor.id);
    setError(null);
    setNotice(null);
    try {
      if (action === 'delete') {
        await deleteMonitor(monitor.id);
        setNotice(`Monitor ${monitor.id} deleted.`);
      } else if (action === 'run') {
        const result = (await runMonitor(monitor.id)) as { status?: string; error?: string } | undefined;
        setNotice(result?.error ? `${monitor.id}: ${result.error}` : `${monitor.id} checked — ${result?.status ?? 'OK'}.`);
      } else {
        await setMonitorStatus(monitor.id, action);
        setNotice(`Monitor ${monitor.id} is now ${action === 'pause' ? 'PAUSED' : action === 'resume' ? 'ACTIVE' : action === 'disable' ? 'DISABLED' : 'ACTIVE'}.`);
      }
      await load();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setBusyId(null);
    }
  };

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return monitors.filter(monitor => {
      if (toolFilter !== 'ALL' && monitor.targetType !== toolFilter) return false;
      if (statusFilter !== 'ALL') {
        const state = monitor.runtimeState || 'AWAITING_DATA';
        if (statusFilter === 'ERROR' && state !== 'ERROR') return false;
        if (statusFilter === 'SOURCE_UNAVAILABLE' && state !== 'SOURCE_UNAVAILABLE') return false;
        if (statusFilter === 'RUNNING' && state !== 'RUNNING') return false;
        if (statusFilter === 'AWAITING_DATA' && state !== 'AWAITING_DATA') return false;
        if (statusFilter === monitor.status) return true;
        return false;
      }
      if (severityFilter !== 'ALL' && monitor.severity !== severityFilter) return false;
      if (!needle) return true;
      // Search spans monitor id, entity, tool, source, severity and status,
      // matching the columns the analyst can actually see in this table.
      const haystack = [
        monitor.id,
        monitor.name,
        monitor.targetType,
        monitor.targetId,
        monitor.targetValue,
        monitor.targetLabel,
        monitor.status,
        monitor.runtimeState,
        monitor.severity,
        ...(monitor.sources ?? []),
        ...(monitor.targets ?? []).flatMap(target => [target.entityId, target.entityValue, target.label]),
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      return haystack.includes(needle);
    });
  }, [monitors, query, toolFilter, statusFilter, severityFilter]);

  const tools = useMemo(() => {
    const keys = new Set(monitors.map(monitor => monitor.targetType));
    return [...keys].sort();
  }, [monitors]);

  const selectTool = (value: string) => {
    setToolFilter(value);
    if (value === 'ALL') searchParams.delete('tool');
    else searchParams.set('tool', value);
    setSearchParams(searchParams, { replace: true });
  };

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        <HubHeader
          eyebrow="24×7 Monitoring"
          title="All Monitors"
          description="Every monitor in Viper Trace regardless of which feature created it. Pause, resume, configure, run or open the related entity and original tool from here — all through the one centralized engine."
          actions={
            <>
              <button
                type="button"
                onClick={() => void load()}
                className="font-mono text-[10px] tracking-wider uppercase px-3 py-2 rounded-sm border flex items-center gap-1.5"
                style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}
              >
                <RefreshCw size={11} /> Refresh
              </button>
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

        <HubTabs active="monitors" />

        {error && <Notice kind="error" text={error} onClose={() => setError(null)} />}
        {notice && <Notice kind="info" text={notice} onClose={() => setNotice(null)} />}

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
          <label className="block space-y-1 md:col-span-2">
            <span className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>Search monitors</span>
            <span className="relative block">
              <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={tv.faint} />
              <input
                value={query}
                onChange={event => setQuery(event.target.value)}
                placeholder="Monitor id, entity, actor, handle, PGP, wallet, IP, domain, source, tool, status, severity…"
                className="w-full rounded-sm pl-8 pr-2 py-2 text-xs"
                style={tv.input}
              />
            </span>
          </label>
          <label className="block space-y-1">
            <span className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>Tool</span>
            <select value={toolFilter} onChange={event => selectTool(event.target.value)} className="w-full rounded-sm px-2 py-2 text-xs" style={tv.input}>
              <option value="ALL">All tools</option>
              {tools.map(key => (
                <option key={key} value={key}>{hubToolFor(key).label} ({key})</option>
              ))}
            </select>
          </label>
          <div className="grid grid-cols-2 gap-3">
            <label className="block space-y-1">
              <span className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>Status</span>
              <select value={statusFilter} onChange={event => setStatusFilter(event.target.value)} className="w-full rounded-sm px-2 py-2 text-xs" style={tv.input}>
                <option value="ALL">All</option>
                {capabilities?.statuses.map(status => <option key={status} value={status}>{status.replace(/_/g, ' ')}</option>)}
              </select>
            </label>
            <label className="block space-y-1">
              <span className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>Severity</span>
              <select value={severityFilter} onChange={event => setSeverityFilter(event.target.value)} className="w-full rounded-sm px-2 py-2 text-xs" style={tv.input}>
                <option value="ALL">All</option>
                {capabilities?.severities.map(entry => <option key={entry.key} value={entry.key}>{entry.key}</option>)}
              </select>
            </label>
          </div>
        </div>

        <Panel
          title={`Monitors (${filtered.length}${filtered.length !== monitors.length ? ` of ${monitors.length}` : ''})`}
          subtitle="Newest configuration last checked first by the centralized scheduler"
          action={
            <span className="flex items-center gap-1.5 font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>
              <Filter size={11} /> live
            </span>
          }
        >
          {filtered.length === 0 ? (
            <EmptyNote>
              {monitors.length === 0
                ? 'No monitors configured anywhere in the platform yet.'
                : 'No monitor matches the current search and filters.'}
            </EmptyNote>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs min-w-[880px]">
                <thead>
                  <tr style={tv.faint}>
                    <th className="text-left font-mono text-[10px] tracking-widest uppercase py-1">Monitor</th>
                    <th className="text-left font-mono text-[10px] tracking-widest uppercase py-1">Tool</th>
                    <th className="text-left font-mono text-[10px] tracking-widest uppercase py-1">Entity</th>
                    <th className="text-left font-mono text-[10px] tracking-widest uppercase py-1">Status</th>
                    <th className="text-left font-mono text-[10px] tracking-widest uppercase py-1">Last check</th>
                    <th className="text-left font-mono text-[10px] tracking-widest uppercase py-1">Next check</th>
                    <th className="text-left font-mono text-[10px] tracking-widest uppercase py-1">Severity</th>
                    <th className="text-right font-mono text-[10px] tracking-widest uppercase py-1">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(monitor => {
                    const entityHref = hubEntityHref(monitor.targetType, monitor.targetId);
                    const tool = hubToolFor(monitor.targetType);
                    const busy = busyId === monitor.id;
                    return (
                      <tr key={monitor.id} className="border-t align-top" style={{ borderColor: 'var(--tw-border-mid)' }}>
                        <td className="py-2 pr-2">
                          <button type="button" onClick={() => setSelectedId(monitor.id)} className="text-left" style={tv.text}>
                            <div className="font-mono text-[11px]">{monitor.name}</div>
                            <div className="font-mono text-[10px]" style={tv.faint}>
                              {monitor.id}
                              {monitor.monitorKind === 'CUSTOM' ? ' · multi-target' : ''}
                            </div>
                          </button>
                        </td>
                        <td className="py-2 pr-2">
                          <Link to={tool.toolPath} className="text-[11px]" style={{ color: 'var(--tw-burgundy)' }}>{tool.label}</Link>
                          <div className="font-mono text-[10px]" style={tv.faint}>{monitor.targetType}</div>
                        </td>
                        <td className="py-2 pr-2 max-w-[220px]">
                          {entityHref ? (
                            <Link to={entityHref} className="font-mono text-[11px] truncate block" style={tv.text}>{monitor.targetValue || monitor.targetLabel}</Link>
                          ) : (
                            <span className="font-mono text-[11px] truncate block" style={tv.text}>{monitor.targetValue || monitor.targetLabel}</span>
                          )}
                          <div className="font-mono text-[10px]" style={tv.faint}>{monitor.targetId}</div>
                        </td>
                        <td className="py-2 pr-2"><StatusChip monitor={monitor} /></td>
                        <td className="py-2 pr-2 font-mono text-[10px]" style={tv.muted}>{formatRelativeTime(monitor.lastCheck)}</td>
                        <td className="py-2 pr-2 font-mono text-[10px]" style={tv.muted}>{formatRelativeTime(monitor.nextCheck)}</td>
                        <td className="py-2 pr-2"><SeverityTag severity={monitor.severity} /></td>
                        <td className="py-2">
                          <div className="flex items-center justify-end gap-1 flex-wrap">
                            <RowAction icon={<Zap size={10} />} label="Run now" busy={busy} onClick={() => void act(monitor, 'run')} />
                            {monitor.status === 'ACTIVE' ? (
                              <RowAction icon={<Pause size={10} />} label="Pause" busy={busy} onClick={() => void act(monitor, 'pause')} />
                            ) : (
                              <RowAction icon={<Play size={10} />} label="Resume" busy={busy} onClick={() => void act(monitor, 'resume')} />
                            )}
                            {monitor.status === 'DISABLED' ? (
                              <RowAction icon={<Play size={10} />} label="Enable" busy={busy} onClick={() => void act(monitor, 'enable')} />
                            ) : (
                              <RowAction icon={<Pause size={10} />} label="Disable" busy={busy} onClick={() => void act(monitor, 'disable')} />
                            )}
                            <RowAction icon={<Trash2 size={10} />} label="Delete" busy={busy} onClick={() => void act(monitor, 'delete')} danger />
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        {capabilities && (
          <AddMonitorDialog
            open={builderOpen}
            capabilities={capabilities}
            onClose={() => setBuilderOpen(false)}
            onCreated={() => { setNotice('Monitor created and scheduled by the centralized engine.'); void load(); }}
          />
        )}

        <MonitorDetailDrawer
          monitorId={selectedId}
          capabilities={capabilities}
          onClose={() => setSelectedId(null)}
          onChanged={() => void load()}
        />
      </div>
    </motion.div>
  );
}

function RowAction({
  icon,
  label,
  onClick,
  busy,
  danger,
}: {
  icon: React.ReactNode;
  label: string;
  onClick: () => void;
  busy?: boolean;
  danger?: boolean;
}) {
  return (
    <button
      type="button"
      title={label}
      onClick={onClick}
      disabled={busy}
      className="font-mono text-[10px] tracking-wider uppercase px-1.5 py-1 rounded-sm border disabled:opacity-40"
      style={{
        borderColor: danger ? 'var(--tw-critical)' : 'var(--tw-border-mid)',
        color: danger ? 'var(--tw-critical)' : 'var(--tw-text-muted)',
        backgroundColor: 'transparent',
      }}
    >
      <span className="flex items-center gap-1">{busy ? <RefreshCw size={10} className="animate-spin" /> : icon}{label}</span>
    </button>
  );
}

/**
 * The monitor detail panel. Everything shown comes from the single detail
 * endpoint, so configuration, history, matches and alerts are the backend's
 * view rather than a second rendering assembled in the browser.
 */
function MonitorDetailDrawer({
  monitorId,
  capabilities,
  onClose,
  onChanged,
}: {
  monitorId: string | null;
  capabilities: MonitoringCapabilities | null;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [detail, setDetail] = useState<MonitorDetail | null>(null);
  const [analysis, setAnalysis] = useState<MonitoringAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [draftSeverity, setDraftSeverity] = useState('');
  const [draftFrequency, setDraftFrequency] = useState('');
  const [draftSources, setDraftSources] = useState<string[]>([]);
  const [draftConditions, setDraftConditions] = useState<string[]>([]);
  const { darkWebSources, darkWebTimeline, darkWebRelationships } = useIntelligenceData();

  const load = useCallback(async (id: string) => {
    try {
      const next = await getMonitor(id);
      setDetail(next);
      setDraftSeverity(next.severity);
      setDraftFrequency(next.frequency);
      setDraftSources(next.sources ?? []);
      setDraftConditions(next.conditions ?? []);
      setError(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  }, []);

  useEffect(() => {
    if (!monitorId) {
      setDetail(null);
      setAnalysis(null);
      setError(null);
      return;
    }
    void load(monitorId);
  }, [monitorId, load]);

  const save = async () => {
    if (!detail) return;
    setBusy(true);
    setError(null);
    try {
      await updateMonitor(detail.id, {
        severity: draftSeverity,
        frequency: draftFrequency,
        sources: draftSources,
        conditions: draftConditions,
      });
      await load(detail.id);
      onChanged();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  };

  const runAnalysis = async () => {
    if (!detail) return;
    setAnalyzing(true);
    setError(null);
    try {
      setAnalysis(await analyzeMonitor(detail.id, true));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setAnalyzing(false);
    }
  };

  const tool = hubToolFor(detail?.targetType);
  const entityHref = hubEntityHref(detail?.targetType, detail?.targetId);

  /**
   * Conditions the backend can actually evaluate for this monitor's target
   * type: the registry defaults for the type, plus anything already
   * configured, so saving configuration can never silently drop a condition
   * the monitor is currently running with.
   */
  const conditionChoices = useMemo(() => {
    if (!capabilities || !detail) return [];
    const spec = capabilities.targetTypes.find(entry => entry.key === detail.targetType);
    const keys = [...new Set([...(spec?.defaultConditions ?? []), ...(detail.conditions ?? [])])];
    return keys
      .map(key => capabilities.conditions[key])
      .filter((condition): condition is MonitorCondition => Boolean(condition));
  }, [capabilities, detail]);

  /** Timeline and relationship records already held against this entity. */
  const context = useMemo(() => {
    if (!detail || !detail.targetId || detail.targetId === 'MULTI') return { timeline: [], relationships: [] };
    const id = detail.targetId;
    const labels = [detail.targetValue, detail.targetLabel, id].filter(Boolean).map(String);
    const matches = (value: unknown) => labels.includes(String(value));
    return {
      timeline: darkWebTimeline
        .filter(event => matches(event.actorId) || labels.some(label => (event.description ?? '').includes(label)))
        .slice(0, 12),
      relationships: darkWebRelationships
        .filter(record => matches(record.sourceEntity) || matches(record.targetEntity))
        .slice(0, 12),
    };
  }, [detail, darkWebTimeline, darkWebRelationships]);

  return (
    <AnimatePresence>
      {monitorId && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-6"
          style={{ backgroundColor: 'color-mix(in srgb, var(--tw-canvas) 90%, transparent)' }}
          onClick={onClose}
        >
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 12 }}
            className="w-full max-w-4xl rounded-sm border my-8"
            style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border-strong)' }}
            onClick={event => event.stopPropagation()}
          >
            <header className="flex items-start justify-between gap-3 px-5 py-4 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <div>
                <div className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>{monitorId}</div>
                <h2 className="font-serif text-xl" style={tv.text}>{detail?.name ?? 'Monitor detail'}</h2>
                {detail && <div className="mt-1"><StatusChip monitor={detail} /> <SeverityTag severity={detail.severity} /></div>}
              </div>
              <button type="button" onClick={onClose} aria-label="Close" style={tv.faint}><X size={16} /></button>
            </header>

            <div className="px-5 py-4 space-y-4">
              {error && <Notice kind="error" text={error} onClose={() => setError(null)} />}
              {!detail && !error && <EmptyNote>Loading monitor…</EmptyNote>}

              {detail && (
                <>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                    <Detail label="Tool" value={tool.label} sub={detail.targetType} />
                    <Detail
                      label="Entity"
                      value={detail.targetValue || detail.targetLabel || detail.targetId}
                      sub={detail.targetId}
                    />
                    <Detail label="Monitoring type" value={detail.monitorKind === 'CUSTOM' ? 'Custom (multi-target)' : detail.targetType} />
                    <Detail label="Source cadence" value={detail.capability?.intervalLabel ?? '—'} sub={detail.effectiveFrequency} />
                    <Detail label="Created" value={new Date(detail.createdAt).toLocaleString()} sub={`by ${detail.createdBy}`} />
                    <Detail label="Last checked" value={formatRelativeTime(detail.lastCheck)} sub={detail.lastCheck ? new Date(detail.lastCheck).toLocaleString() : 'never'} />
                    <Detail label="Next check" value={formatRelativeTime(detail.nextCheck)} sub={detail.nextCheck ? new Date(detail.nextCheck).toLocaleString() : 'not scheduled'} />
                    <Detail label="Checks / triggers / alerts" value={`${detail.checkCount} / ${detail.triggerCount} / ${detail.alertCount}`} />
                  </div>

                  {detail.lastError && (
                    <Notice kind="error" text={`Last cycle failed: ${detail.lastError} (${detail.consecutiveFailures} consecutive failure(s))`} />
                  )}

                  <div className="flex flex-wrap gap-2">
                    {entityHref && (
                      <Link
                        to={entityHref}
                        className="font-mono text-[10px] tracking-wider uppercase px-3 py-2 rounded-sm border flex items-center gap-1.5"
                        style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}
                      >
                        <ExternalLink size={11} /> Open entity
                      </Link>
                    )}
                    <Link
                      to={tool.toolPath}
                      className="font-mono text-[10px] tracking-wider uppercase px-3 py-2 rounded-sm border flex items-center gap-1.5"
                      style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}
                    >
                      <ExternalLink size={11} /> Open {tool.label}
                    </Link>
                    <Link to="/app/darkweb/timeline" className="font-mono text-[10px] tracking-wider uppercase px-3 py-2 rounded-sm border" style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}>
                      Timeline
                    </Link>
                    <Link to="/app/darkweb/evidence" className="font-mono text-[10px] tracking-wider uppercase px-3 py-2 rounded-sm border" style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}>
                      Evidence
                    </Link>
                    <Link to="/app/darkweb/graph" className="font-mono text-[10px] tracking-wider uppercase px-3 py-2 rounded-sm border" style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}>
                      Relationships
                    </Link>
                    {detail.alerts.some(alert => alert.investigationId) && (
                      <Link
                        to={`/app/darkweb/investigations/${detail.alerts.find(alert => alert.investigationId)!.investigationId}`}
                        className="font-mono text-[10px] tracking-wider uppercase px-3 py-2 rounded-sm border"
                        style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
                      >
                        Open investigation
                      </Link>
                    )}
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="rounded-sm border p-3 space-y-2" style={tv.panelBorder}>
                      <div className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>Configure</div>
                      <label className="block space-y-1">
                        <span className="text-[10px]" style={tv.faint}>Severity ceiling</span>
                        <select value={draftSeverity} onChange={event => setDraftSeverity(event.target.value)} className="w-full rounded-sm px-2 py-1.5 text-xs" style={tv.input}>
                          {capabilities?.severities.map(entry => <option key={entry.key} value={entry.key}>{entry.key}</option>)}
                        </select>
                      </label>
                      <label className="block space-y-1">
                        <span className="text-[10px]" style={tv.faint}>Requested interval</span>
                        <select value={draftFrequency} onChange={event => setDraftFrequency(event.target.value)} className="w-full rounded-sm px-2 py-1.5 text-xs" style={tv.input}>
                          {capabilities?.frequencies.map(entry => <option key={entry.key} value={entry.key}>{entry.label}</option>)}
                        </select>
                      </label>
                      <div>
                        <div className="text-[10px] mb-1" style={tv.faint}>Collection sources</div>
                        <div className="flex flex-wrap gap-1">
                          {darkWebSources.length === 0 && <span className="text-[10px]" style={tv.faint}>No sources recorded.</span>}
                          {darkWebSources.map(source => (
                            <ToggleChip
                              key={source.id}
                              active={draftSources.includes(source.id)}
                              label={source.name}
                              title={capabilities?.sourceCapabilities[source.type]?.note ?? source.type}
                              onClick={() => setDraftSources(current =>
                                current.includes(source.id)
                                  ? current.filter(id => id !== source.id)
                                  : [...current, source.id])}
                            />
                          ))}
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] mb-1" style={tv.faint}>Monitoring conditions</div>
                        <div className="flex flex-wrap gap-1">
                          {conditionChoices.length === 0 && <span className="text-[10px]" style={tv.faint}>None available for this tool.</span>}
                          {conditionChoices.map(condition => (
                            <ToggleChip
                              key={condition.key}
                              active={draftConditions.includes(condition.key)}
                              label={condition.label}
                              title={condition.description}
                              onClick={() => setDraftConditions(current =>
                                current.includes(condition.key)
                                  ? current.filter(key => key !== condition.key)
                                  : [...current, condition.key])}
                            />
                          ))}
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={() => void save()}
                        disabled={busy}
                        className="font-mono text-[10px] tracking-wider uppercase px-3 py-1.5 rounded-sm border disabled:opacity-50"
                        style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}
                      >
                        {busy ? 'Saving…' : 'Save configuration'}
                      </button>
                      <p className="text-[10px] leading-relaxed" style={tv.faint}>
                        Sources set the real collection cadence: the slowest bound source caps the interval, and the
                        backend records the effective value rather than implying live coverage.
                      </p>
                    </div>

                    <div className="rounded-sm border p-3 space-y-1.5" style={tv.panelBorder}>
                      <div className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>Current configuration</div>
                      <div className="flex flex-wrap gap-1">
                        {(detail.conditions ?? []).length === 0 && <span className="text-[10px]" style={tv.faint}>No conditions recorded.</span>}
                        {(detail.conditions ?? []).map(key => (
                          <span
                            key={key}
                            className="font-mono text-[10px] tracking-wider uppercase px-2 py-0.5 rounded-sm border"
                            style={chipStyle('var(--tw-dust)')}
                          >
                            {conditionLabel(capabilities, key)}
                          </span>
                        ))}
                      </div>
                      {detail.capability?.sources?.length ? (
                        <div className="flex flex-wrap gap-1 pt-1">
                          {detail.capability.sources.map(source => (
                            <span key={source.id} className="font-mono text-[10px] tracking-wider uppercase px-2 py-0.5 rounded-sm border" style={chipStyle('var(--tw-info)')}>
                              {source.name}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <p className="text-[10px] pt-1" style={tv.faint}>No collection source bound.</p>
                      )}
                      {detail.capability?.intervalNote && (
                        <p className="text-[10px] leading-relaxed pt-1" style={tv.faint}>{detail.capability.intervalNote}</p>
                      )}
                      {detail.capability && !detail.capability.sourceAvailable && (
                        <p className="text-[10px] leading-relaxed" style={{ color: 'var(--tw-high)' }}>
                          {detail.capability.sourceNote}
                        </p>
                      )}
                    </div>
                  </div>

                  {detail.targets && detail.targets.length > 0 && (
                    <div className="rounded-sm border p-3" style={tv.panelBorder}>
                      <div className="font-mono text-[10px] tracking-widest uppercase mb-2" style={tv.faint}>Watched targets</div>
                      <div className="space-y-1">
                        {detail.targets.map(target => (
                          <div key={`${target.entityType}-${target.entityId}`} className="flex items-center justify-between gap-3 text-xs">
                            <span className="font-mono truncate" style={tv.text}>{target.label ?? target.entityValue ?? target.entityId}</span>
                            <span className="font-mono text-[10px]" style={tv.faint}>{target.entityType} · {target.entityId}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="rounded-sm border p-3" style={tv.panelBorder}>
                      <div className="font-mono text-[10px] tracking-widest uppercase mb-2" style={tv.faint}>Monitoring history</div>
                      {detail.recentEvents.length === 0 ? (
                        <EmptyNote>No cycles recorded yet.</EmptyNote>
                      ) : (
                        <div className="space-y-1 max-h-56 overflow-y-auto">
                          {detail.recentEvents.map(event => (
                            <div key={event.id} className="flex items-start justify-between gap-2 text-[11px] py-1 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                              <span className="truncate" style={tv.muted}>{event.message ?? `${event.observationsSeen} record(s)`}</span>
                              <span className="font-mono text-[10px] shrink-0" style={tv.faint}>{formatRelativeTime(event.checkAt)}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    <div className="rounded-sm border p-3" style={tv.panelBorder}>
                      <div className="font-mono text-[10px] tracking-widest uppercase mb-2" style={tv.faint}>Detected changes</div>
                      {detail.recentMatches.length === 0 ? (
                        <EmptyNote>No change has been detected for this monitor.</EmptyNote>
                      ) : (
                        <div className="space-y-1 max-h-56 overflow-y-auto">
                          {detail.recentMatches.map(match => (
                            <div key={match.id} className="text-[11px] py-1 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                              <div className="font-mono" style={tv.text}>{match.conditionLabel}</div>
                              <div className="text-[10px]" style={tv.faint}>
                                {match.detail?.count ?? 0} match(es) · {formatRelativeTime(match.createdAt)}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="rounded-sm border p-3" style={tv.panelBorder}>
                    <div className="flex items-center justify-between gap-2 mb-2">
                      <div className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>Alerts &amp; evidence ({detail.alerts.length})</div>
                    </div>
                    {detail.alerts.length === 0 ? (
                      <EmptyNote>This monitor has not raised an alert.</EmptyNote>
                    ) : (
                      <div className="space-y-2 max-h-56 overflow-y-auto">
                        {detail.alerts.map(alert => (
                          <div key={alert.id} className="text-[11px]">
                            <div className="flex items-center justify-between gap-2">
                              <span className="font-mono" style={tv.text}>{alert.title}</span>
                              <SeverityTag severity={alert.severity} />
                            </div>
                            <div className="text-[10px] mt-0.5" style={tv.faint}>
                              {formatRelativeTime(alert.raisedAt)} · confidence {alert.confidence} · {alert.evidenceIds.length} evidence · {alert.observationIds.length} observation(s)
                            </div>
                            {alert.investigationId && (
                              <Link to={`/app/darkweb/investigations/${alert.investigationId}`} className="font-mono text-[10px]" style={{ color: 'var(--tw-burgundy)' }}>
                                Investigation {alert.investigationId}
                              </Link>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="rounded-sm border p-3" style={tv.panelBorder}>
                      <div className="flex items-center justify-between gap-2 mb-2">
                        <div className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>
                          Timeline ({context.timeline.length})
                        </div>
                        <Link to="/app/darkweb/timeline" className="font-mono text-[10px] tracking-widest uppercase" style={{ color: 'var(--tw-burgundy)' }}>
                          Full timeline
                        </Link>
                      </div>
                      {context.timeline.length === 0 ? (
                        <EmptyNote>No timeline event is recorded against this entity.</EmptyNote>
                      ) : (
                        <div className="space-y-1 max-h-48 overflow-y-auto">
                          {context.timeline.map(event => (
                            <div key={event.id} className="py-1 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                              <div className="text-[11px]" style={tv.text}>{event.title}</div>
                              <div className="text-[10px]" style={tv.faint}>
                                {event.type} · {formatRelativeTime(event.time)}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    <div className="rounded-sm border p-3" style={tv.panelBorder}>
                      <div className="flex items-center justify-between gap-2 mb-2">
                        <div className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>
                          Relationships ({context.relationships.length})
                        </div>
                        <Link to={`/app/darkweb/graph?focus=${encodeURIComponent(detail?.targetId ?? '')}`} className="font-mono text-[10px] tracking-widest uppercase" style={{ color: 'var(--tw-burgundy)' }}>
                          Open graph
                        </Link>
                      </div>
                      {context.relationships.length === 0 ? (
                        <EmptyNote>No relationship is recorded against this entity.</EmptyNote>
                      ) : (
                        <div className="space-y-1 max-h-48 overflow-y-auto">
                          {context.relationships.map(record => (
                            <div key={record.id} className="py-1 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                              <div className="font-mono text-[11px] truncate" style={tv.text}>
                                {record.sourceEntity} → {record.targetEntity}
                              </div>
                              <div className="text-[10px]" style={tv.faint}>
                                {record.type} · confidence {record.confidence} · {record.evidenceIds.length} evidence
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="rounded-sm border p-3" style={tv.panelBorder}>
                    <div className="flex items-center justify-between gap-2 mb-2">
                      <div className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>AI analysis</div>
                      <button
                        type="button"
                        onClick={() => void runAnalysis()}
                        disabled={analyzing}
                        className="font-mono text-[10px] tracking-wider uppercase px-2 py-1 rounded-sm border disabled:opacity-50"
                        style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}
                      >
                        {analyzing ? 'Analysing…' : 'Analyse'}
                      </button>
                    </div>
                    {!analysis ? (
                      <p className="text-[10px]" style={tv.faint}>Run the monitoring analysis to summarise observed change, correlation and AI inference for this monitor.</p>
                    ) : (
                      <div className="space-y-2 text-[11px]">
                        <div>
                          <div className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>Observed</div>
                          <p style={tv.muted}>{analysis.observed.statement}</p>
                        </div>
                        {analysis.correlated.length > 0 && (
                          <div>
                            <div className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>Correlation</div>
                            {analysis.correlated.map((entry, index) => <p key={index} style={tv.muted}>• {entry.detail}</p>)}
                          </div>
                        )}
                        <div>
                          <div className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>AI inference</div>
                          <p style={tv.muted}>
                            {analysis.inference.available
                              ? analysis.inference.summary ?? analysis.inference.explanation ?? analysis.inference.note
                              : analysis.inference.note}
                          </p>
                        </div>
                        <div className="font-mono text-[10px]" style={tv.faint}>
                          Priority {analysis.priority.score} ({analysis.priority.band}) · {analysis.disclaimer}
                        </div>
                      </div>
                    )}
                  </div>
                </>
              )}
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

function ToggleChip({
  active,
  label,
  title,
  onClick,
}: {
  active: boolean;
  label: string;
  title?: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      title={title}
      onClick={onClick}
      className="font-mono text-[10px] tracking-wider uppercase px-2 py-0.5 rounded-sm border"
      style={active
        ? { ...chipStyle('var(--tw-burgundy)'), borderWidth: '1px', borderStyle: 'solid' }
        : { borderWidth: '1px', borderStyle: 'solid', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-faint)' }}
    >
      {label}
    </button>
  );
}

function Detail({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="rounded-sm border px-3 py-2" style={tv.panelBorder}>
      <div className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>{label}</div>
      <div className="font-mono text-[11px] mt-1 break-words" style={tv.text}>{value}</div>
      {sub && <div className="text-[10px] mt-0.5" style={tv.faint}>{sub}</div>}
    </div>
  );
}