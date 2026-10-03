// ============================================================
// PhishNet — Shared primitives for the entity workspaces.
//
// The Handle, PGP, Wallet and Observation pages are different
// disciplines, so each keeps its own information architecture. They
// only share the small presentation pieces below, so all four read
// as one product instead of four separate products.
// ============================================================
import { Link } from 'react-router-dom';
import { dw } from '../../lib/darkweb/styles';
import { DemoLabel } from '../ui/DemoLabel';

export const entityInputClass = 'w-full font-mono text-[11px] pl-8 pr-2 py-1.5 rounded-sm focus:outline-none';

export const entityInputStyle = {
  backgroundColor: 'var(--tw-panel-alt)',
  borderColor: 'var(--tw-border-mid)',
  color: 'var(--tw-text)',
} as const;

export const selectStyle = {
  backgroundColor: 'var(--tw-panel-alt)',
  borderColor: 'var(--tw-border-mid)',
  color: 'var(--tw-text)',
  border: '1px solid var(--tw-border-mid)',
} as const;

/** One labelled fact in a dense metadata matrix. */
export function MetaCell({ label, value, color }: { label: string; value: React.ReactNode; color?: string }) {
  return (
    <div>
      <span className="font-mono text-[9px] uppercase block" style={dw.faint}>{label}</span>
      <span className="font-mono text-xs break-words" style={{ ...dw.text, ...(color ? { color } : {}) }}>{value ?? '—'}</span>
    </div>
  );
}

/** A titled block. Every workspace composes its layout from these. */
export function EntitySection({ icon, title, children, aside }: {
  icon?: React.ReactNode;
  title: string;
  children: React.ReactNode;
  aside?: React.ReactNode;
}) {
  return (
    <div className="rounded-sm border p-4 space-y-3" style={dw.panel}>
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-1.5" style={dw.muted}>
          {icon}
          <p className="font-mono text-[10px] tracking-widest uppercase">{title}</p>
        </div>
        {aside}
      </div>
      {children}
    </div>
  );
}

export function EmptyNote({ children }: { children: React.ReactNode }) {
  return <p className="font-mono text-[10px]" style={dw.faint}>{children}</p>;
}

/** A cross-module deep link rendered as a compact chip. */
export function EntityLink({ to, children, accent = 'var(--tw-burgundy)' }: {
  to: string;
  children: React.ReactNode;
  accent?: string;
}) {
  return (
    <Link
      to={to}
      className="font-mono text-[10px] px-2 py-1 rounded-sm border inline-flex items-center gap-1 hover:underline"
      style={{ borderColor: 'var(--tw-border-mid)', color: accent }}
    >
      {children}
    </Link>
  );
}

/** The "record this entity" action — always the Add Intelligence form. */
export function RecordEntityLink({ to, label }: { to: string; label: string }) {
  return (
    <Link
      to={to}
      className="font-mono text-[10px] tracking-wider uppercase px-2.5 py-1.5 rounded-sm border"
      style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-burgundy)' }}
    >
      {label}
    </Link>
  );
}

export function EntityPageHeader({ icon, eyebrow, title, byline, actions, stats }: {
  icon: React.ReactNode;
  eyebrow: string;
  title: string;
  byline: string;
  actions?: React.ReactNode;
  stats?: Array<{ label: string; value: React.ReactNode; color?: React.CSSProperties }>;
}) {
  return (
    <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b pb-5" style={{ borderColor: 'var(--tw-border-mid)' }}>
      <div className="space-y-1">
        <div className="flex items-center gap-2">
          {icon}
          <span className="font-mono text-[10px] tracking-widest uppercase" style={dw.burg}>{eyebrow}</span>
          <DemoLabel />
        </div>
        <h1 className="font-serif text-3xl" style={dw.text}>{title}</h1>
        <p className="text-xs max-w-2xl leading-relaxed" style={dw.muted}>{byline}</p>
      </div>
      {stats && stats.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {stats.map(stat => (
            <div key={stat.label} className="rounded-sm border px-3 py-1.5 text-center" style={dw.panel}>
              <p className="font-mono text-[9px] uppercase" style={dw.faint}>{stat.label}</p>
              <p className="font-mono text-sm" style={stat.color ?? dw.text}>{stat.value}</p>
            </div>
          ))}
        </div>
      )}
      {actions}
    </div>
  );
}

/** Selectable row used by every list column in the entity workspaces. */
export function EntityRow({ selected, onClick, children }: {
  selected: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <div
      onClick={onClick}
      className="p-3 rounded-sm border cursor-pointer transition-all"
      style={{
        backgroundColor: selected ? 'var(--tw-panel-alt)' : 'var(--tw-panel)',
        borderColor: selected ? 'var(--tw-burgundy)' : 'var(--tw-border-mid)',
        borderLeftWidth: selected ? '3px' : '1px',
        borderLeftColor: selected ? 'var(--tw-burgundy)' : 'var(--tw-border-mid)',
      }}
    >
      {children}
    </div>
  );
}

export function EmptySelection({ icon, message }: { icon: React.ReactNode; message: string }) {
  return (
    <div className="p-12 text-center rounded-sm border" style={dw.panel}>
      <div className="mb-2" style={dw.muted}>{icon}</div>
      <p className="font-mono text-xs" style={dw.muted}>{message}</p>
    </div>
  );
}

/** A list of stored records, or an honest empty state. */
export function StoredList<T>({ items, empty, children }: {
  items: T[];
  empty: string;
  children: (item: T) => React.ReactNode;
}) {
  if (items.length === 0) return <EmptyNote>{empty}</EmptyNote>;
  return <div className="space-y-2">{items.map((item, index) => <div key={index}>{children(item)}</div>)}</div>;
}
