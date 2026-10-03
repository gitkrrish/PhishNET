// ============================================================
// PhishNet — shared building blocks for the centralized 24x7
// Monitoring hub.
//
// Everything here is presentation plus navigation. The hub holds no
// monitoring state of its own: it renders what the centralized backend
// returns and calls the same endpoints the per-entity tools already call,
// so a monitor created from the hub and a monitor created from an actor
// dossier are the same record, managed by the same engine.
// ============================================================
import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import {
  Activity,
  AlertTriangle,
  Loader2,
  Plus,
  Radio,
  Shield,
  X,
} from 'lucide-react';

import {
  createMonitor,
  monitorSeverityColor,
  monitorStatus,
  type Monitor,
  type MonitorCondition,
  type MonitorInput,
  type MonitoringCapabilities,
  type TargetTypeSpec,
} from '../../lib/intelligence/monitoring';
import { useIntelligenceData } from '../../lib/intelligence/IntelligenceContext';
import { chipStyle, tv } from '../../lib/styles';

// ── Tool routing ────────────────────────────────────────────────
//
// A monitor stores a registry target type, not an originating page, so the
// hub derives "open the original tool" from that type. These are the same
// routes navConfig already declares; nothing new is registered.

export interface HubToolRoute {
  label: string;
  toolPath: string;
  entityPath?: (entityId: string) => string;
}

export const HUB_TOOL_ROUTES: Record<string, HubToolRoute> = {
  ACTOR: { label: 'Threat Actors', toolPath: '/app/darkweb/actors', entityPath: id => `/app/darkweb/actors/${encodeURIComponent(id)}` },
  PERSONA: { label: 'Threat Actors', toolPath: '/app/darkweb/actors', entityPath: id => `/app/darkweb/actors/${encodeURIComponent(id)}` },
  HANDLE: { label: 'Handle Intelligence', toolPath: '/app/darkweb/handles', entityPath: id => `/app/darkweb/handles/${encodeURIComponent(id)}` },
  ALIAS: { label: 'Handle Intelligence', toolPath: '/app/darkweb/handles', entityPath: id => `/app/darkweb/handles/${encodeURIComponent(id)}` },
  PGP: { label: 'PGP Intelligence', toolPath: '/app/darkweb/pgp-keys', entityPath: id => `/app/darkweb/pgp-keys/${encodeURIComponent(id)}` },
  PGP_KEY: { label: 'PGP Intelligence', toolPath: '/app/darkweb/pgp-keys', entityPath: id => `/app/darkweb/pgp-keys/${encodeURIComponent(id)}` },
  WALLET: { label: 'Crypto Wallet Intelligence', toolPath: '/app/darkweb/wallets', entityPath: id => `/app/darkweb/wallets/${encodeURIComponent(id)}` },
  INFRASTRUCTURE: { label: 'Infrastructure', toolPath: '/app/darkweb/infrastructure' },
  DOMAIN: { label: 'Infrastructure', toolPath: '/app/infrastructure' },
  IP: { label: 'Infrastructure', toolPath: '/app/infrastructure' },
  ONION: { label: 'Infrastructure', toolPath: '/app/darkweb/infrastructure' },
  SOURCE: { label: 'Source Intelligence', toolPath: '/app/darkweb/sources' },
  FORUM: { label: 'Source Intelligence', toolPath: '/app/darkweb/sources' },
  MARKETPLACE: { label: 'Source Intelligence', toolPath: '/app/darkweb/sources' },
  CHANNEL: { label: 'Source Intelligence', toolPath: '/app/darkweb/sources' },
  OBSERVATION: { label: 'Observation Intelligence', toolPath: '/app/darkweb/observations', entityPath: id => `/app/darkweb/observations/${encodeURIComponent(id)}` },
  EVIDENCE: { label: 'Evidence', toolPath: '/app/darkweb/evidence' },
  RELATIONSHIP: { label: 'Relationships', toolPath: '/app/darkweb/graph' },
  CVE: { label: 'ATT&CK Intelligence', toolPath: '/app/darkweb/attack' },
  VULNERABILITY: { label: 'ATT&CK Intelligence', toolPath: '/app/darkweb/attack' },
  ATTACK: { label: 'ATT&CK Intelligence', toolPath: '/app/darkweb/attack' },
  KEYWORD: { label: 'AI Analysis', toolPath: '/app/darkweb/ai' },
  ORGANIZATION: { label: 'AI Analysis', toolPath: '/app/darkweb/ai' },
  PRODUCT: { label: 'AI Analysis', toolPath: '/app/darkweb/ai' },
  EMAIL: { label: 'Email Analyzer', toolPath: '/app/investigate' },
  URL: { label: 'URL Analysis', toolPath: '/app/url-analysis' },
  FILE: { label: 'File Analysis', toolPath: '/app/file-analysis' },
  CUSTOM: { label: '24x7 Monitoring', toolPath: '/app/monitoring/monitors' },
};

export function hubToolFor(targetType: string | null | undefined): HubToolRoute {
  const key = String(targetType ?? '').toUpperCase();
  return HUB_TOOL_ROUTES[key] ?? { label: 'Monitoring Hub', toolPath: '/app/monitoring/monitors' };
}

/** Deep link to the dossier for a monitor's watched entity, when one exists. */
export function hubEntityHref(targetType: string | null | undefined, entityId: string | null | undefined): string | null {
  if (!entityId || entityId === 'MULTI') return null;
  const route = hubToolFor(targetType);
  return route.entityPath ? route.entityPath(entityId) : route.toolPath;
}

// ── Shared chrome ───────────────────────────────────────────────

export const HUB_TABS = [
  { key: 'hub', label: 'Monitoring Hub', path: '/app/monitoring/hub' },
  { key: 'monitors', label: 'All Monitors', path: '/app/monitoring/monitors' },
  { key: 'alerts', label: 'Monitoring Alerts', path: '/app/monitoring/alerts' },
  { key: 'health', label: 'Run History & Health', path: '/app/monitoring/health' },
] as const;

export function HubTabs({ active }: { active: string }) {
  return (
    <div className="flex flex-wrap gap-1 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
      {HUB_TABS.map(tab => {
        const isActive = tab.key === active;
        return (
          <Link
            key={tab.key}
            to={tab.path}
            className="font-mono text-[10px] tracking-widest uppercase px-3 py-2 -mb-px border-b-2"
            style={{
              color: isActive ? 'var(--tw-burgundy)' : 'var(--tw-text-muted)',
              borderBottomColor: isActive ? 'var(--tw-burgundy)' : 'transparent',
            }}
          >
            {tab.label}
          </Link>
        );
      })}
    </div>
  );
}

export function Panel({
  title,
  subtitle,
  action,
  children,
}: {
  title: string;
  subtitle?: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="rounded-sm border" style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)' }}>
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
        <div>
          <h2 className="font-mono text-[11px] tracking-widest uppercase" style={tv.text}>{title}</h2>
          {subtitle && <p className="text-[11px] mt-0.5" style={tv.faint}>{subtitle}</p>}
        </div>
        {action}
      </div>
      <div className="p-4">{children}</div>
    </section>
  );
}

export function Counter({
  label,
  value,
  color = 'var(--tw-text)',
  hint,
  to,
}: {
  label: string;
  value: string | number;
  color?: string;
  hint?: string;
  to?: string;
}) {
  const body = (
    <>
      <div className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>{label}</div>
      <div className="font-serif text-2xl mt-1" style={{ color }}>{value}</div>
      {hint && <div className="text-[10px] mt-0.5" style={tv.faint}>{hint}</div>}
    </>
  );
  const className = 'text-left rounded-sm border px-4 py-3';
  const style = { backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)' };
  if (to) {
    return <Link to={to} className={className} style={style}>{body}</Link>;
  }
  return <div className={className} style={style}>{body}</div>;
}

export function StatusChip({ monitor }: { monitor: Pick<Monitor, 'status' | 'runtimeState'> }) {
  const { label, color } = monitorStatus(monitor);
  return (
    <span
      className="font-mono text-[10px] tracking-widest uppercase px-2 py-0.5 rounded-sm border"
      style={chipStyle(color)}
    >
      {label}
    </span>
  );
}

export function SeverityTag({ severity }: { severity: string }) {
  return (
    <span
      className="font-mono text-[10px] tracking-widest uppercase px-2 py-0.5 rounded-sm border"
      style={chipStyle(monitorSeverityColor(severity))}
    >
      {severity}
    </span>
  );
}

export function ActionButton({
  label,
  onClick,
  icon,
  busy,
  accent,
  disabled,
  title,
}: {
  label: string;
  onClick: () => void;
  icon?: ReactNode;
  busy?: boolean;
  accent?: boolean;
  disabled?: boolean;
  title?: string;
}) {
  return (
    <button
      type="button"
      title={title}
      disabled={disabled || busy}
      onClick={onClick}
      className="font-mono text-[10px] tracking-wider uppercase px-3 py-2 rounded-sm border flex items-center gap-1.5 disabled:opacity-50"
      style={{
        backgroundColor: accent ? 'var(--tw-burgundy)' : 'var(--tw-panel-alt)',
        borderColor: accent ? 'var(--tw-burgundy)' : 'var(--tw-border-mid)',
        color: accent ? 'var(--tw-canvas)' : 'var(--tw-text-muted)',
      }}
    >
      {busy ? <Loader2 size={11} className="animate-spin" /> : icon}
      {label}
    </button>
  );
}

export function Notice({ kind, text, onClose }: { kind: 'info' | 'error'; text: string; onClose?: () => void }) {
  const color = kind === 'error' ? 'var(--tw-critical)' : 'var(--tw-info)';
  return (
    <div
      className="rounded-sm border px-3 py-2 flex items-start gap-2 text-xs"
      style={{ backgroundColor: `color-mix(in srgb, ${color} 10%, transparent)`, borderColor: color, color }}
    >
      {kind === 'error' ? <AlertTriangle size={13} className="mt-0.5 shrink-0" /> : <Activity size={13} className="mt-0.5 shrink-0" />}
      <span className="flex-1">{text}</span>
      {onClose && (
        <button type="button" onClick={onClose} aria-label="Dismiss">
          <X size={13} />
        </button>
      )}
    </div>
  );
}

export function EmptyNote({ children }: { children: ReactNode }) {
  return (
    <p className="text-xs py-6 text-center" style={tv.faint}>{children}</p>
  );
}

// ── Add Monitor ─────────────────────────────────────────────────

interface CandidateEntity {
  id: string;
  label: string;
  detail: string;
}

/**
 * Existing intelligence records, grouped by the target type the analyst
 * picked. These are the same centralized ids the dossiers use — the hub
 * never mints a monitoring-only entity, which is why the backend can
 * refuse a monitor bound to something that does not exist.
 */
function useEntityCandidates(targetType: string | null, spec: TargetTypeSpec | null): CandidateEntity[] {
  const data = useIntelligenceData();
  return useMemo(() => {
    if (!spec || spec.term === true || spec.custom === true) return [];
    const primary = spec.entityTypes[0];
    const short = (value: string) => value.length > 46 ? `${value.slice(0, 44)}…` : value;

    if (primary === 'ACTOR') {
      return data.darkWebActors.map(actor => ({
        id: actor.id,
        label: actor.aliases?.[0] ?? actor.id,
        detail: `${actor.id} · ${actor.status ?? 'UNKNOWN'}`,
      }));
    }
    if (primary === 'HANDLE' || primary === 'ALIAS') {
      return data.darkWebHandles.map(handle => ({
        id: handle.id,
        label: handle.value,
        detail: `${handle.id} · ${handle.platform ?? 'unknown platform'}`,
      }));
    }
    if (primary === 'PGP' || primary === 'PGP_KEY') {
      return data.darkWebPgpKeys.map(key => ({
        id: key.id,
        label: short(key.fingerprint ?? key.id),
        detail: `${key.id} · fingerprint`,
      }));
    }
    if (primary === 'WALLET') {
      return data.darkWebWallets.map(wallet => ({
        id: wallet.id,
        label: short(wallet.address ?? wallet.id),
        detail: `${wallet.id} · ${wallet.txCount ?? 0} transactions`,
      }));
    }
    if (primary === 'INFRASTRUCTURE') {
      // DOMAIN / IP / ONION are views over the one infrastructure table, so
      // the picker narrows to the subtype the analyst actually chose.
      return data.darkWebInfrastructure
        .filter(record => {
          if (targetType === 'IP') return String(record.type).toUpperCase() === 'IP';
          if (targetType === 'DOMAIN') return String(record.type).toUpperCase() === 'DOMAIN';
          if (targetType === 'ONION') return /onion|\.onion\b|\.i2p\b/i.test(record.value ?? '');
          return true;
        })
        .map(record => ({
          id: record.id,
          label: short(record.value ?? record.id),
          detail: `${record.id} · ${record.type}`,
        }));
    }
    if (primary === 'SOURCE' || primary === 'FORUM' || primary === 'MARKETPLACE' || primary === 'CHANNEL') {
      return data.darkWebSources.map(source => ({
        id: source.id,
        label: source.name,
        detail: `${source.id} · ${source.type}`,
      }));
    }
    if (primary === 'OBSERVATION') {
      return data.darkWebObservations.map(observation => ({
        id: observation.id,
        label: short(observation.content ?? observation.id),
        detail: `${observation.id} · ${observation.observationType ?? 'observation'}`,
      }));
    }
    if (primary === 'EVIDENCE') {
      return data.darkWebEvidence.map(record => ({
        id: record.id,
        label: short(record.hash ?? record.id),
        detail: `${record.id} · ${record.evidenceType ?? 'evidence'}`,
      }));
    }
    if (primary === 'RELATIONSHIP') {
      return data.darkWebRelationships.map(record => ({
        id: record.id,
        label: record.type ?? record.id,
        detail: `${record.id} · ${record.sourceEntity ?? '—'} → ${record.targetEntity ?? '—'}`,
      }));
    }
    return [];
  }, [spec, targetType, data]);
}

export function AddMonitorDialog({
  open,
  capabilities,
  onClose,
  onCreated,
}: {
  open: boolean;
  capabilities: MonitoringCapabilities;
  onClose: () => void;
  onCreated: (monitor: Monitor) => void;
}) {
  const data = useIntelligenceData();
  const [targetType, setTargetType] = useState('ACTOR');
  const [entityId, setEntityId] = useState('');
  const [termValue, setTermValue] = useState('');
  const [name, setName] = useState('');
  const [frequency, setFrequency] = useState('CONTINUOUS');
  const [severity, setSeverity] = useState('MEDIUM');
  const [selectedConditions, setSelectedConditions] = useState<string[]>([]);
  const [sources, setSources] = useState<string[]>([]);
  const [search, setSearch] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const spec = useMemo(
    () => capabilities.targetTypes.find(entry => entry.key === targetType) ?? null,
    [capabilities, targetType],
  );
  const candidates = useEntityCandidates(targetType, spec);

  // Reset the target-bound fields whenever the tool changes: a PGP
  // fingerprint carried over from a wallet row would bind to nothing.
  useEffect(() => {
    setEntityId('');
    setTermValue('');
    setSelectedConditions(spec?.defaultConditions ?? []);
  }, [targetType, spec]);

  const availableSources = useMemo(
    () => data.darkWebSources.map(source => ({
      id: source.id,
      name: source.name,
      type: source.type,
      capability: capabilities.sourceCapabilities[source.type],
    })),
    [data.darkWebSources, capabilities.sourceCapabilities],
  );

  // The honest interval: the slowest bound source caps the cadence, so the
  // dialog states that before the monitor is created rather than after.
  const boundSlowest = useMemo(() => {
    const bound = availableSources.filter(source => sources.includes(source.id) && source.capability);
    if (!bound.length) return null;
    return bound.reduce((worst, source) => (source.capability!.seconds > worst.capability!.seconds ? source : worst));
  }, [availableSources, sources]);

  const conditions = useMemo(() => {
    if (!spec) return [];
    return spec.defaultConditions
      .map(key => capabilities.conditions[key])
      .filter((condition): condition is MonitorCondition => Boolean(condition));
  }, [spec, capabilities.conditions]);

  const filteredCandidates = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return candidates.slice(0, 200);
    return candidates
      .filter(candidate => `${candidate.id} ${candidate.label} ${candidate.detail}`.toLowerCase().includes(needle))
      .slice(0, 200);
  }, [candidates, search]);

  const needsTerm = spec?.term === true;
  const missingTarget = needsTerm ? !termValue.trim() : !entityId;

  const submit = async () => {
    if (!spec || missingTarget) return;
    setBusy(true);
    setError(null);
    try {
      const chosen = candidates.find(candidate => candidate.id === entityId);
      const payload: MonitorInput = {
        name: name.trim() || (needsTerm ? `${termValue.trim()} — ${spec.label} monitoring` : `${chosen?.label ?? entityId} — ${spec.label} monitoring`),
        targetType: spec.key,
        sources,
        frequency,
        severity,
        conditions: selectedConditions,
        notificationPref: 'IN_PLATFORM',
      };
      if (needsTerm) {
        payload.targetId = termValue.trim();
        payload.targetValue = termValue.trim();
      } else {
        payload.targetId = entityId;
        payload.targetValue = chosen?.label ?? entityId;
      }
      const created = await createMonitor(payload);
      onCreated(created);
      onClose();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AnimatePresence>
      {open && (
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
            className="w-full max-w-3xl rounded-sm border my-8"
            style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border-strong)' }}
            onClick={event => event.stopPropagation()}
          >
            <header className="flex items-center justify-between gap-3 px-5 py-4 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <div className="flex items-center gap-2">
                <Radio size={16} style={{ color: 'var(--tw-burgundy)' }} />
                <h2 className="font-serif text-xl" style={tv.text}>Add Monitor</h2>
              </div>
              <button type="button" onClick={onClose} aria-label="Close" style={tv.faint}>
                <X size={16} />
              </button>
            </header>

            <div className="px-5 py-4 space-y-4">
              {error && <Notice kind="error" text={error} onClose={() => setError(null)} />}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <label className="block space-y-1">
                  <span className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>Tool / module</span>
                  <select
                    value={targetType}
                    onChange={event => setTargetType(event.target.value)}
                    className="w-full rounded-sm px-2 py-2 text-xs"
                    style={tv.input}
                  >
                    {capabilities.targetTypes
                      .filter(entry => entry.custom !== true)
                      .map(entry => (
                        <option key={entry.key} value={entry.key}>
                          {entry.label}{entry.term === true ? ' (term watch)' : ''}
                        </option>
                      ))}
                  </select>
                </label>

                <label className="block space-y-1">
                  <span className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>Monitor name (optional)</span>
                  <input
                    value={name}
                    onChange={event => setName(event.target.value)}
                    placeholder="Defaults to <entity> — <tool> monitoring"
                    className="w-full rounded-sm px-2 py-2 text-xs"
                    style={tv.input}
                  />
                </label>
              </div>

              {needsTerm ? (
                <label className="block space-y-1">
                  <span className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>
                    {spec?.termHint ? `${spec.label} to watch` : 'Term to watch'}
                  </span>
                  <input
                    value={termValue}
                    onChange={event => setTermValue(event.target.value)}
                    placeholder={spec?.termHint ?? 'e.g. CVE-2024-3094, T1059, acme'}
                    className="w-full rounded-sm px-2 py-2 text-xs"
                    style={tv.input}
                  />
                  <span className="text-[10px]" style={tv.faint}>
                    {spec?.key === 'EMAIL' || spec?.key === 'URL' || spec?.key === 'FILE'
                      ? 'An indicator watch. It follows new mentions of this exact value across observations and evidence — no separate indicator record is created.'
                      : 'Term watches follow new mentions across observations, evidence and sources. No stored entity is required.'}
                  </span>
                </label>
              ) : (
                <div className="space-y-1">
                  <span className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>
                    Entity / indicator ({candidates.length} available)
                  </span>
                  <input
                    value={search}
                    onChange={event => setSearch(event.target.value)}
                    placeholder="Search existing intelligence by id or value…"
                    className="w-full rounded-sm px-2 py-2 text-xs"
                    style={tv.input}
                  />
                  <div
                    className="rounded-sm border max-h-52 overflow-y-auto"
                    style={{ borderColor: 'var(--tw-border)', backgroundColor: 'var(--tw-panel-inset)' }}
                  >
                    {filteredCandidates.length === 0 ? (
                      <p className="text-xs p-3" style={tv.faint}>
                        No existing records of this type. Monitoring attaches to intelligence that already exists — add the
                        record first, then monitor it.
                      </p>
                    ) : (
                      filteredCandidates.map(candidate => {
                        const selected = candidate.id === entityId;
                        return (
                          <button
                            key={candidate.id}
                            type="button"
                            onClick={() => setEntityId(candidate.id)}
                            className="w-full text-left px-3 py-2 border-b flex items-center justify-between gap-3"
                            style={{
                              borderColor: 'var(--tw-border-mid)',
                              backgroundColor: selected ? 'color-mix(in srgb, var(--tw-burgundy) 12%, transparent)' : 'transparent',
                            }}
                          >
                            <span className="font-mono text-xs truncate" style={tv.text}>{candidate.label}</span>
                            <span className="font-mono text-[10px] truncate" style={tv.faint}>{candidate.detail}</span>
                          </button>
                        );
                      })
                    )}
                  </div>
                </div>
              )}

              <div>
                <span className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>
                  Monitoring conditions
                </span>
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {conditions.length === 0 && <span className="text-[10px]" style={tv.faint}>This tool has no default conditions.</span>}
                  {conditions.map(condition => {
                    const selected = selectedConditions.includes(condition.key);
                    return (
                      <button
                        key={condition.key}
                        type="button"
                        title={condition.description}
                        onClick={() => setSelectedConditions(current =>
                          current.includes(condition.key)
                            ? current.filter(key => key !== condition.key)
                            : [...current, condition.key],
                        )}
                        className="font-mono text-[10px] tracking-wider uppercase px-2 py-1 rounded-sm border"
                        style={selected
                          ? { ...chipStyle('var(--tw-burgundy)'), borderWidth: '1px', borderStyle: 'solid' }
                          : { borderWidth: '1px', borderStyle: 'solid', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-faint)' }}
                      >
                        {condition.label}
                      </button>
                    );
                  })}
                </div>
              </div>

              <div>
                <span className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>Collection sources</span>
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {availableSources.length === 0 && (
                    <span className="text-[10px]" style={tv.faint}>No sources recorded yet.</span>
                  )}
                  {availableSources.map(source => {
                    const selected = sources.includes(source.id);
                    return (
                      <button
                        key={source.id}
                        type="button"
                        title={source.capability?.note ?? source.type}
                        onClick={() => setSources(current =>
                          current.includes(source.id)
                            ? current.filter(id => id !== source.id)
                            : [...current, source.id],
                        )}
                        className="font-mono text-[10px] tracking-wider uppercase px-2 py-1 rounded-sm border"
                        style={selected
                          ? { ...chipStyle('var(--tw-dust)'), borderWidth: '1px', borderStyle: 'solid' }
                          : { borderWidth: '1px', borderStyle: 'solid', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-faint)' }}
                      >
                        {source.name}
                      </button>
                    );
                  })}
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <label className="block space-y-1">
                  <span className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>Requested interval</span>
                  <select
                    value={frequency}
                    onChange={event => setFrequency(event.target.value)}
                    className="w-full rounded-sm px-2 py-2 text-xs"
                    style={tv.input}
                  >
                    {capabilities.frequencies.map(entry => (
                      <option key={entry.key} value={entry.key}>{entry.label}</option>
                    ))}
                  </select>
                </label>
                <label className="block space-y-1">
                  <span className="font-mono text-[10px] tracking-widest uppercase" style={tv.faint}>Severity ceiling</span>
                  <select
                    value={severity}
                    onChange={event => setSeverity(event.target.value)}
                    className="w-full rounded-sm px-2 py-2 text-xs"
                    style={tv.input}
                  >
                    {capabilities.severities.map(entry => (
                      <option key={entry.key} value={entry.key}>{entry.label}</option>
                    ))}
                  </select>
                </label>
              </div>

              <div className="rounded-sm border px-3 py-2 text-[11px]" style={tv.notice}>
                {boundSlowest
                  ? `Effective cadence will be capped at ${boundSlowest.capability!.seconds}s by "${boundSlowest.name}". ${boundSlowest.capability!.continuous ? '' : boundSlowest.capability!.note}`
                  : 'No source bound: the monitor evaluates the centralized intelligence tables at the requested interval.'}
              </div>
            </div>

            <footer className="flex items-center justify-end gap-2 px-5 py-4 border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <ActionButton label="Cancel" onClick={onClose} />
              <ActionButton
                label="Create monitor"
                icon={<Plus size={11} />}
                accent
                busy={busy}
                disabled={missingTarget}
                onClick={() => void submit()}
              />
            </footer>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

/** Shared page header so all four hub views open identically. */
export function HubHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b pb-5" style={{ borderColor: 'var(--tw-border-mid)' }}>
      <div className="space-y-1">
        <div className="flex items-center gap-2">
          <Shield size={16} style={{ color: 'var(--tw-burgundy)' }} />
          <span className="font-mono text-[10px] tracking-widest uppercase" style={{ color: 'var(--tw-burgundy)' }}>
            {eyebrow}
          </span>
        </div>
        <h1 className="font-serif text-3xl" style={tv.text}>{title}</h1>
        <p className="text-xs max-w-3xl" style={tv.muted}>{description}</p>
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}