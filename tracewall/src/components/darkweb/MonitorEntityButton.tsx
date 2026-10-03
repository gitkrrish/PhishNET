// ============================================================
// PhishNet — "Monitor 24×7" control shared by every entity page.
//
// One component, mounted on each entity workspace, so monitoring looks
// native to the platform: it uses the entity id that page already shows,
// posts to the centralized backend, and re-reads the result. No entity is
// ever duplicated, and no monitoring state is kept in the browser.
// ============================================================
import { useCallback, useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Radio, X, Loader2, Check, AlertTriangle, Pause, Play, Trash2 } from 'lucide-react';
import { dw } from '../../lib/darkweb/styles';
import { selectStyle } from '../darkweb/EntityWorkspace';
import { ConfidenceBar } from '../ui/ConfidenceBar';
import { useIntelligenceData } from '../../lib/intelligence/IntelligenceContext';
import {
  createMonitor,
  monitorsForEntity,
  monitoringCapabilities,
  setMonitorStatus,
  deleteMonitor,
  type Monitor,
  type MonitoringCapabilities,
} from '../../lib/intelligence/monitoring';

interface Props {
  /** The centralized entity id on this page. Monitoring binds to it. */
  entityType: string;
  entityId: string;
  entityLabel: string;
  /** The monitor profile to create, e.g. ACTOR or WALLET. */
  targetType: string;
  label?: string;
  compact?: boolean;
}

const FREQUENCIES = [
  { key: 'CONTINUOUS', label: 'Continuous (24x7)' },
  { key: 'EVERY_5_MIN', label: 'Every 5 minutes' },
  { key: 'EVERY_15_MIN', label: 'Every 15 minutes' },
  { key: 'EVERY_30_MIN', label: 'Every 30 minutes' },
  { key: 'HOURLY', label: 'Every hour' },
  { key: 'EVERY_6_HOURS', label: 'Every 6 hours' },
  { key: 'DAILY', label: 'Daily' },
];

const SEVERITIES = ['INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

export function MonitorEntityButton({ entityType, entityId, entityLabel, targetType, label = 'Monitor 24×7', compact }: Props) {
  const { darkWebSources } = useIntelligenceData();
  const [open, setOpen] = useState(false);
  const [capabilities, setCapabilities] = useState<MonitoringCapabilities | null>(null);
  const [existing, setExisting] = useState<Monitor[]>([]);
  const [selectedConditions, setSelectedConditions] = useState<string[]>([]);
  const [frequency, setFrequency] = useState('CONTINUOUS');
  const [severity, setSeverity] = useState('MEDIUM');
  const [sources, setSources] = useState<string[]>([]);
  const [availableSources, setAvailableSources] = useState<Array<{ id: string; name: string; type: string; seconds: number; continuous: boolean; note: string }>>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  /**
   * A monitor is stored under its registry target type, which is not always
   * the type name the page knows the entity by: the PGP dossier passes
   * PGP_KEY while monitors are created as PGP, and the infrastructure
   * dossier passes INFRASTRUCTURE while a monitor may be DOMAIN, IP or ONION.
   * Looking up only one spelling silently reported "no monitors" on exactly
   * those pages, so both are queried and merged.
   */
  const loadEntityMonitors = useCallback(async () => {
    const keys = [...new Set([targetType, entityType])].filter(Boolean);
    const results = await Promise.all(keys.map(key => monitorsForEntity(key, entityId)));
    const merged = new Map<string, Monitor>();
    for (const list of results) for (const monitor of list) merged.set(monitor.id, monitor);
    return [...merged.values()];
  }, [targetType, entityType, entityId]);

  const spec = useMemo(
    () => capabilities?.targetTypes.find(t => t.key === targetType) ?? null,
    [capabilities, targetType],
  );

  // Load capabilities and this entity's current monitors whenever the panel
  // opens, so the form always reflects what the backend actually supports.
  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    void (async () => {
      try {
        const caps = await monitoringCapabilities();
        if (cancelled) return;
        setCapabilities(caps);
        const targetSpec = caps.targetTypes.find(t => t.key === targetType);
        setSelectedConditions(targetSpec?.defaultConditions ?? []);
        const [monitors] = await Promise.all([loadEntityMonitors()]);
        if (cancelled) return;
        setExisting(monitors);
        setAvailableSources(
          darkWebSources.map(source => {
            const capability = caps.sourceCapabilities[source.type] ?? caps.sourceCapabilities.AUTHORISED_FEED;
            return { id: source.id, name: source.name, type: source.type, seconds: capability.seconds, continuous: capability.continuous, note: capability.note };
          }),
        );
      } catch (caught) {
        if (!cancelled) setError(caught instanceof Error ? caught.message : String(caught));
      }
    })();
    return () => { cancelled = true; };
  }, [open, loadEntityMonitors, targetType, darkWebSources]);

  const activeMonitor = existing.find(m => m.status === 'ACTIVE');
  const conditionsForTarget = useMemo(() => {
    if (!capabilities || !spec) return [];
    return spec.defaultConditions
      .map(key => capabilities.conditions[key])
      .filter((condition): condition is NonNullable<typeof condition> => Boolean(condition));
  }, [capabilities, spec]);

  // The honest interval: never faster than the slowest bound source.
  const interval = useMemo(() => {
    const bound = availableSources.filter(source => sources.includes(source.id));
    if (!bound.length) return null;
    const slowest = bound.reduce((worst, source) => (source.seconds > worst.seconds ? source : worst));
    return slowest;
  }, [availableSources, sources]);

  const submit = async () => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const created = await createMonitor({
        name: `${entityLabel} — ${spec?.label ?? targetType} monitoring`,
        targetType,
        targetId: entityId,
        targetValue: entityLabel,
        sources,
        frequency,
        severity,
        conditions: selectedConditions,
        notificationPref: 'IN_PLATFORM',
      });
      setNotice(
        `Monitor ${created.id} is ${created.status}. Next check ${
          created.capability?.intervalLabel ?? 'scheduled'
        }${created.capability && !created.capability.continuous ? ' (interval collection — the source does not support continuous polling)' : ''}.`,
      );
      setExisting(await loadEntityMonitors());
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  };

  const act = async (monitor: Monitor, action: 'pause' | 'resume' | 'disable' | 'enable' | 'delete') => {
    setBusy(true);
    setError(null);
    try {
      if (action === 'delete') await deleteMonitor(monitor.id);
      else await setMonitorStatus(monitor.id, action);
      setExisting(await loadEntityMonitors());
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  };

  const buttonLabel = activeMonitor ? 'Monitoring active' : label;

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="font-mono text-[10px] tracking-wider uppercase px-2.5 py-1.5 rounded-sm border flex items-center gap-1.5"
        style={{
          backgroundColor: 'var(--tw-panel-alt)',
          borderColor: activeMonitor ? 'var(--tw-burgundy)' : 'var(--tw-border-mid)',
          color: activeMonitor ? 'var(--tw-burgundy)' : 'var(--tw-text-muted)',
        }}
      >
        <Radio size={11} /> {buttonLabel}
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-6"
            style={{ backgroundColor: 'color-mix(in srgb, var(--tw-canvas) 88%, transparent)' }}
          >
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              className="w-full max-w-2xl rounded-sm border p-6 space-y-5 my-8"
              style={dw.panel}
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="font-mono text-[10px] tracking-widest uppercase" style={dw.burg}>24×7 Monitoring</p>
                  <h2 className="font-serif text-xl mt-1" style={dw.text}>Monitor {entityLabel}</h2>
                  <p className="font-mono text-[10px] mt-1" style={dw.muted}>
                    {entityType} · {entityId} — monitoring binds to this existing record; nothing is duplicated.
                  </p>
                </div>
                <button type="button" onClick={() => setOpen(false)} className="font-mono text-[10px]" style={dw.muted}>
                  <X size={14} />
                </button>
              </div>

              {/* Existing monitors on this entity */}
              {existing.length > 0 && (
                <div className="space-y-2">
                  <p className="font-mono text-[10px] uppercase tracking-wider" style={dw.muted}>Existing monitors</p>
                  {existing.map(monitor => (
                    <div key={monitor.id} className="p-3 rounded-sm border space-y-2" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-[11px]" style={dw.text}>{monitor.name}</span>
                        <span className="font-mono text-[9px] px-1.5 py-0.5 rounded-sm" style={{ color: monitor.status === 'ACTIVE' ? 'var(--tw-low)' : 'var(--tw-medium)', borderColor: 'var(--tw-border-mid)' }}>
                          {monitor.runtimeState === 'SOURCE_UNAVAILABLE' ? 'SOURCE UNAVAILABLE' : monitor.status}
                        </span>
                      </div>
                      <p className="font-mono text-[9px]" style={dw.faint}>
                        Last check {monitor.lastCheck ? new Date(monitor.lastCheck).toLocaleString() : 'never'} · Next check {monitor.nextCheck ? new Date(monitor.nextCheck).toLocaleString() : 'unscheduled'} ·{' '}
                        {monitor.capability?.intervalLabel} interval{monitor.capability && !monitor.capability.continuous ? ' (not continuous)' : ''}
                      </p>
                      {monitor.capability && !monitor.capability.continuous && (
                        <p className="font-mono text-[9px]" style={{ color: 'var(--tw-medium)' }}>{monitor.capability.intervalNote}</p>
                      )}
                      <div className="flex gap-2">
                        {monitor.status === 'ACTIVE' ? (
                          <TinyButton icon={<Pause size={9} />} label="Pause" onClick={() => void act(monitor, 'pause')} />
                        ) : (
                          <TinyButton icon={<Play size={9} />} label="Resume" onClick={() => void act(monitor, 'resume')} />
                        )}
                        {monitor.status !== 'DISABLED' && <TinyButton label="Disable" onClick={() => void act(monitor, 'disable')} />}
                        {monitor.status === 'DISABLED' && <TinyButton label="Enable" onClick={() => void act(monitor, 'enable')} />}
                        <TinyButton icon={<Trash2 size={9} />} label="Delete" onClick={() => void act(monitor, 'delete')} />
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Activation form */}
              {!compact && (
                <>
                  <div className="space-y-2">
                    <p className="font-mono text-[10px] uppercase tracking-wider" style={dw.muted}>Alert conditions</p>
                    <div className="grid sm:grid-cols-2 gap-2 max-h-52 overflow-y-auto pr-1">
                      {conditionsForTarget.map(condition => (
                        <label key={condition.key} className="flex items-start gap-2 p-2 rounded-sm border cursor-pointer" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                          <input
                            type="checkbox"
                            checked={selectedConditions.includes(condition.key)}
                            onChange={event => setSelectedConditions(current =>
                              event.target.checked ? [...current, condition.key] : current.filter(key => key !== condition.key))}
                            className="mt-0.5"
                          />
                          <span className="space-y-0.5">
                            <span className="block font-mono text-[10px]" style={dw.text}>{condition.label}</span>
                            <span className="block font-mono text-[9px] leading-snug" style={dw.faint}>{condition.description}</span>
                          </span>
                        </label>
                      ))}
                    </div>
                  </div>

                  <div className="grid sm:grid-cols-3 gap-3">
                    <Field label="Frequency">
                      <select value={frequency} onChange={event => setFrequency(event.target.value)} className="w-full font-mono text-[11px] px-2 py-1.5 rounded-sm" style={selectStyle}>
                        {FREQUENCIES.map(option => <option key={option.key} value={option.key}>{option.label}</option>)}
                      </select>
                    </Field>
                    <Field label="Severity ceiling">
                      <select value={severity} onChange={event => setSeverity(event.target.value)} className="w-full font-mono text-[11px] px-2 py-1.5 rounded-sm" style={selectStyle}>
                        {SEVERITIES.map(option => <option key={option} value={option}>{option.charAt(0) + option.slice(1).toLowerCase()}</option>)}
                      </select>
                    </Field>
                    <Field label="Notification">
                      <select className="w-full font-mono text-[11px] px-2 py-1.5 rounded-sm" style={selectStyle} defaultValue="IN_PLATFORM">
                        <option value="IN_PLATFORM">In-platform alerts</option>
                      </select>
                    </Field>
                  </div>

                  <div className="space-y-2">
                    <p className="font-mono text-[10px] uppercase tracking-wider" style={dw.muted}>Sources (authorised / public / synthetic only)</p>
                    {availableSources.length === 0 ? (
                      <p className="font-mono text-[10px]" style={dw.faint}>No sources are registered yet.</p>
                    ) : (
                      <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
                        {availableSources.map(source => (
                          <label key={source.id} className="flex items-start gap-2 p-2 rounded-sm border cursor-pointer" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                            <input
                              type="checkbox"
                              checked={sources.includes(source.id)}
                              onChange={event => setSources(current =>
                                event.target.checked ? [...current, source.id] : current.filter(id => id !== source.id))}
                              className="mt-0.5"
                            />
                            <span className="space-y-0.5">
                              <span className="block font-mono text-[10px]" style={dw.text}>{source.name} · {source.type}</span>
                              <span className="block font-mono text-[9px] leading-snug" style={source.continuous ? dw.low : dw.medium}>
                                {source.continuous ? 'Continuous' : `Interval collection — ${formatSeconds(source.seconds)}`}. {source.note}
                              </span>
                            </span>
                          </label>
                        ))}
                      </div>
                    )}
                  </div>

                  {interval && !interval.continuous && (
                    <div className="p-3 rounded-sm border" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-medium) 12%, transparent)', borderColor: 'var(--tw-medium)' }}>
                      <p className="font-mono text-[10px] flex items-start gap-1.5" style={dw.medium}>
                        <AlertTriangle size={11} className="mt-0.5 shrink-0" />
                        The selected sources cannot be polled continuously. This monitor will run every {formatSeconds(interval.seconds)} —
                        {interval.note}
                      </p>
                    </div>
                  )}

                  {notice && (
                    <p className="font-mono text-[10px] flex items-center gap-1.5" style={dw.low}>
                      <Check size={11} /> {notice}
                    </p>
                  )}
                  {error && (
                    <p className="font-mono text-[10px] flex items-center gap-1.5" style={dw.critical}>
                      <AlertTriangle size={11} /> {error}
                    </p>
                  )}

                  <div className="flex justify-end gap-2 pt-2" style={dw.borderMid}>
                    <button type="button" onClick={() => setOpen(false)} className="font-mono text-[10px] px-3 py-1.5 rounded-sm border" style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}>
                      Close
                    </button>
                    <button
                      type="button"
                      disabled={busy || selectedConditions.length === 0}
                      onClick={() => void submit()}
                      className="font-mono text-[10px] uppercase px-3 py-1.5 rounded-sm border flex items-center gap-1.5 disabled:opacity-50"
                      style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6', borderColor: 'var(--tw-burgundy)' }}
                    >
                      {busy ? <Loader2 size={11} className="animate-spin" /> : <Radio size={11} />} Start Monitoring
                    </button>
                  </div>
                </>
              )}
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="space-y-1">
      <span className="font-mono text-[9px] uppercase tracking-wider" style={{ color: 'var(--tw-text-faint)' }}>{label}</span>
      {children}
    </label>
  );
}

function TinyButton({ icon, label, onClick }: { icon?: React.ReactNode; label: string; onClick: () => void }) {
  return (
    <button type="button" onClick={onClick} className="font-mono text-[9px] uppercase px-1.5 py-0.5 rounded-sm border flex items-center gap-1" style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}>
      {icon} {label}
    </button>
  );
}

function formatSeconds(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h`;
  return `${Math.round(seconds / 86400)}d`;
}

/** Compact read-only indicator for pages that only show current state. */
export function MonitorStatusChip({ monitor }: { monitor: Monitor }) {
  const unavailable = monitor.runtimeState === 'SOURCE_UNAVAILABLE';
  const failed = monitor.runtimeState === 'ERROR';
  const color = failed ? 'var(--tw-critical)' : unavailable ? 'var(--tw-high)' : monitor.status === 'ACTIVE' ? 'var(--tw-low)' : 'var(--tw-medium)';
  const label = failed ? 'ERROR' : unavailable ? 'SOURCE UNAVAILABLE' : monitor.status;
  return (
    <span className="font-mono text-[9px] px-1.5 py-0.25 rounded-sm inline-flex items-center gap-1" style={{ color, borderColor: 'var(--tw-border-mid)' }}>
      <Radio size={9} /> {label}
    </span>
  );
}

/** Confidence + next-check line shared by the monitoring views. */
export function MonitorSchedule({ monitor }: { monitor: Monitor }) {
  const interval = monitor.capability?.intervalLabel ?? '—';
  return (
    <div className="space-y-1">
      <ConfidenceBar value={monitor.triggerCount > 0 ? 70 : 40} label={false} />
      <p className="font-mono text-[9px]" style={{ color: 'var(--tw-text-faint)' }}>
        {interval} interval{monitor.capability && !monitor.capability.continuous ? ' · not continuous' : ''} · next {monitor.nextCheck ? new Date(monitor.nextCheck).toLocaleString() : '—'}
      </p>
    </div>
  );
}
