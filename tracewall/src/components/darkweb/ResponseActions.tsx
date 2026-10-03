// ============================================================
// PhishNet — Response actions, shared by every protection surface.
//
// One component renders the response workflow wherever it is mounted, so
// the same entity never shows two different action lists or two different
// statuses. It is deliberately explicit about three things an analyst has
// to be able to trust:
//
//   1. Whether an action can actually be performed here.
//   2. What the responsible integration said when it was performed.
//   3. That nothing is reported as protected until a control plane
//      confirmed it.
// ============================================================
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { AlertTriangle, CheckCircle2, Clock, Loader2, ShieldAlert, ShieldOff } from 'lucide-react';
import { dw } from '../../lib/darkweb/styles';
import type { ProtectionFact, ProtectionView, ResponseActionOption } from '../../lib/intelligence/types-protection';
import { useProtection } from '../../lib/intelligence/IntelligenceContext';
import {
  availabilityLabel,
  availabilityTone,
  runEnforcement,
  statusLabel,
  statusTone,
} from '../../lib/intelligence/enforcement';

const TONE_COLOR: Record<NonNullable<ProtectionFact['tone']>, string> = {
  critical: 'var(--tw-critical)',
  high: 'var(--tw-high)',
  medium: 'var(--tw-medium)',
  low: 'var(--tw-low)',
  ok: 'var(--tw-moss)',
  muted: 'var(--tw-text-muted)',
};

export function FactGrid({ facts }: { facts: ProtectionFact[] }) {
  return (
    <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-x-4 gap-y-2">
      {facts.map(fact => (
        <div key={fact.label} className="min-w-0">
          <span className="font-mono text-[9px] uppercase block" style={dw.faint}>{fact.label}</span>
          <span className="font-mono text-[11px] break-words" style={{ color: TONE_COLOR[fact.tone ?? 'muted'] }}>{fact.value}</span>
        </div>
      ))}
    </div>
  );
}

function ActionButton({ view, option }: { view: ProtectionView; option: ResponseActionOption }) {
  const { recordAction, createResponseLog, addResponseAction } = useProtection();
  const [busy, setBusy] = useState(false);
  const [awaitingApproval, setAwaitingApproval] = useState(false);
  const [outcome, setOutcome] = useState<string | null>(null);
  const [tone, setTone] = useState<ProtectionFact['tone']>('muted');

  // A configured integration means the request leaves this browser. That is
  // never done on a single unconfirmed click: the analyst has to name the
  // target and the destination control plane first.
  const sendsOutbound = option.availability === 'APPROVAL_REQUIRED' && option.requiresApproval === true;

  const run = async (approved: boolean) => {
    if (busy) return;
    if (sendsOutbound && !approved) {
      setAwaitingApproval(true);
      return;
    }
    setBusy(true);
    setAwaitingApproval(false);
    setOutcome(null);
    try {
      const attempt = await runEnforcement(option, {
        entityType: view.entityType,
        entityId: view.entityId,
        entityValue: view.entityLabel,
        performedBy: 'Analyst',
      });

      recordAction({
        entityType: view.entityType,
        entityId: view.entityId,
        entityValue: view.entityLabel,
        kind: option.kind,
        status: attempt.status,
        channel: attempt.channel,
        detail: attempt.detail,
        performedBy: 'Analyst',
        confirmedAt: attempt.confirmedAt,
      });

      // Keep the existing response ticket in step with the outcome, so the
      // response queue and this panel report the same history.
      const ticket = createResponseLog(
        view.entityId,
        `${option.label} — ${view.entityLabel}`,
        view.score?.responsePriority ?? 'MEDIUM',
        'Analyst',
      );
      addResponseAction(
        ticket.id,
        option.kind === 'BLOCK_IP' || option.kind === 'BLOCK_DOMAIN' || option.kind === 'BLOCK_URL' ? 'BLOCK' : 'MONITOR',
        `${statusLabel(attempt.status)} — ${attempt.detail}`,
        'Analyst',
      );

      setOutcome(attempt.detail);
      setTone(statusTone(attempt.status));
    } finally {
      setBusy(false);
    }
  };

  const unavailable = option.availability === 'UNSUPPORTED';

  return (
    <div className="p-2.5 rounded-sm border space-y-1.5" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
      <div className="flex items-start justify-between gap-2">
        <span className="font-mono text-[10px]" style={dw.text}>{option.label}</span>
        <span className="font-mono text-[9px] uppercase shrink-0" style={{ color: TONE_COLOR[availabilityTone(option.availability)] }}>
          {availabilityLabel(option.availability)}
        </span>
      </div>
      <p className="font-mono text-[9px] leading-relaxed" style={dw.faint}>{option.availabilityReason}</p>
      {outcome && (
        <p className="font-mono text-[9px] leading-relaxed flex items-start gap-1" style={{ color: TONE_COLOR[tone ?? 'muted'] }}>
          {tone === 'ok' ? <CheckCircle2 size={10} className="mt-0.5 shrink-0" /> : tone === 'critical' ? <ShieldOff size={10} className="mt-0.5 shrink-0" /> : <Clock size={10} className="mt-0.5 shrink-0" />}
          {outcome}
        </p>
      )}
      <button
        type="button"
        onClick={() => void run(false)}
        disabled={busy || unavailable}
        className="font-mono text-[9px] uppercase tracking-wider px-2 py-1 rounded-sm border flex items-center gap-1 disabled:opacity-40"
        style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-burgundy)' }}
      >
        {busy ? <Loader2 size={10} className="animate-spin" /> : option.availability === 'APPROVAL_REQUIRED' ? <ShieldAlert size={10} /> : <CheckCircle2 size={10} />}
        {busy ? 'Requesting' : option.availability === 'APPROVAL_REQUIRED' ? 'Request & verify' : 'Record action'}
      </button>
      {awaitingApproval && !busy && (
        <div className="p-2 rounded-sm border space-y-1.5" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-burgundy)' }}>
          <p className="font-mono text-[9px] leading-relaxed" style={dw.text}>
            This sends a request to <span className="font-semibold">{option.channel}</span> for{' '}
            <span className="font-semibold break-all">{view.entityLabel}</span>. The action is only reported as
            applied after the integration confirms the result.
          </p>
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={() => void run(true)}
              className="font-mono text-[9px] uppercase tracking-wider px-2 py-1 rounded-sm border"
              style={{ backgroundColor: 'var(--tw-burgundy)', borderColor: 'var(--tw-burgundy)', color: 'var(--tw-canvas)' }}
            >
              Authorize &amp; send
            </button>
            <button
              type="button"
              onClick={() => setAwaitingApproval(false)}
              className="font-mono text-[9px] uppercase tracking-wider px-2 py-1 rounded-sm border"
              style={{ backgroundColor: 'transparent', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-faint)' }}
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export function ResponseActions({ view }: { view: ProtectionView }) {
  if (view.actions.length === 0) {
    return (
      <p className="font-mono text-[10px]" style={dw.faint}>
        No response workflow applies to this record class. Monitoring and investigation still do.
      </p>
    );
  }

  const enforcing = view.actions.filter(option => option.channel !== null);
  const internal = view.actions.filter(option => option.channel === null);

  return (
    <div className="space-y-3">
      {enforcing.length > 0 && (
        <div className="space-y-2">
          <p className="font-mono text-[9px] tracking-widest uppercase" style={dw.muted}>Controls that change a system outside this platform</p>
          <div className="grid md:grid-cols-2 gap-2">
            {enforcing.map(option => <ActionButton key={option.kind} view={view} option={option} />)}
          </div>
        </div>
      )}
      {internal.length > 0 && (
        <div className="space-y-2">
          <p className="font-mono text-[9px] tracking-widest uppercase" style={dw.muted}>Workflows recorded inside the platform</p>
          <div className="grid md:grid-cols-2 gap-2">
            {internal.map(option => <ActionButton key={option.kind} view={view} option={option} />)}
          </div>
        </div>
      )}
    </div>
  );
}

export function ActionHistory({ view }: { view: ProtectionView }) {
  if (view.records.length === 0) {
    return <p className="font-mono text-[10px]" style={dw.faint}>No response action has been recorded against this record.</p>;
  }
  return (
    <div className="space-y-1.5">
      {view.records.map(record => (
        <div key={record.id} className="p-2.5 rounded-sm border" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
          <div className="flex items-center justify-between gap-2">
            <span className="font-mono text-[10px]" style={dw.text}>{record.kind.replace(/_/g, ' ').toLowerCase()}</span>
            <span className="font-mono text-[9px] uppercase" style={{ color: TONE_COLOR[statusTone(record.status)] }}>{statusLabel(record.status)}</span>
          </div>
          <p className="font-mono text-[9px] leading-relaxed mt-1" style={dw.muted}>{record.detail}</p>
          <p className="font-mono text-[9px] mt-1" style={dw.faint}>
            {record.performedBy} · {new Date(record.recordedAt).toLocaleString()}
            {record.confirmedAt ? ` · confirmed ${new Date(record.confirmedAt).toLocaleString()}` : ''}
          </p>
        </div>
      ))}
    </div>
  );
}

export function Caveats({ caveats }: { caveats: string[] }) {
  if (caveats.length === 0) return null;
  return (
    <div className="p-2.5 rounded-sm border space-y-1" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
      <p className="font-mono text-[9px] tracking-widest uppercase" style={dw.muted}>What this panel does not claim</p>
      {caveats.map(caveat => (
        <p key={caveat} className="font-mono text-[9px] leading-relaxed flex items-start gap-1" style={dw.faint}>
          <AlertTriangle size={9} className="mt-0.5 shrink-0" /> {caveat}
        </p>
      ))}
    </div>
  );
}

/** Cross-module links out of the protection surface. */
export function ProtectionLinks({ view }: { view: ProtectionView }) {
  const links: Array<{ to: string; label: string }> = [];
  if (view.entityPath) links.push({ to: view.entityPath, label: 'Open record' });
  links.push({ to: '/app/darkweb/alerts', label: 'Monitoring & Alerts' });
  links.push({ to: '/app/darkweb/investigations', label: 'Investigations' });
  links.push({ to: '/app/darkweb/evidence', label: 'Evidence locker' });
  links.push({ to: '/app/darkweb/timeline', label: 'Timeline' });

  return (
    <div className="flex flex-wrap gap-1.5">
      {links.map(link => (
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
  );
}