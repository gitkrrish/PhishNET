import { useState, useEffect, useMemo } from 'react';
import { auditLog as mockAuditLog } from '../../data/mockData';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { Shield, RefreshCw, Loader2, AlertTriangle } from 'lucide-react';
import { tv, hoverHandlers } from '../../lib/styles';
import { listAudit } from '../../lib/intelligence/monitoring';

export default function AuditPage() {
  // The audit log is owned by the backend. It is read from GET /api/audit so
  // the page shows what the services actually recorded — every write, in the
  // order it happened — rather than a browser-local list that any other
  // session, or a restart, would not see.
  const [auditEntries, setAuditEntries] = useState<typeof mockAuditLog>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = async () => {
    try {
      const entries = await listAudit();
      setAuditEntries(entries as unknown as typeof mockAuditLog);
      setError(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
    const interval = setInterval(() => void refresh(), 10000);
    return () => clearInterval(interval);
  }, []);

  const allEntries = useMemo(() => auditEntries, [auditEntries]);

  return (
    <div className="min-h-screen" style={tv.canvas}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Audit & Compliance</p>
            <DemoLabel />
          </div>
          <h1 className="font-serif text-3xl" style={tv.text}>Audit Log</h1>
          <p className="text-sm" style={tv.muted}>Immutable record of all sensitive actions. Every entry includes actor, timestamp, target, and outcome.</p>
        </div>

        {/* Notice */}
        <div className="rounded-sm p-4 flex items-start gap-3" style={tv.notice}>
          <Shield size={14} className="shrink-0 mt-0.5" style={tv.muted} />
          <p className="text-xs leading-relaxed" style={tv.muted}>
            Every entry is written by the backend service that performed the action, not by the browser, so the log is
            the same on any session. Secrets are never recorded — only the action, the target and the outcome.
          </p>
          <button
            type="button"
            onClick={() => void refresh()}
            className="ml-auto font-mono text-[10px] px-2 py-1 rounded-sm border flex items-center gap-1 shrink-0"
            style={tv.panelBorder}
          >
            {loading ? <Loader2 size={10} className="animate-spin" /> : <RefreshCw size={10} />} Refresh
          </button>
        </div>

        {error && (
          <div className="rounded-sm p-3 flex items-center gap-2 font-mono text-[10px]" style={tv.notice}>
            <AlertTriangle size={12} /> Could not load the audit log: {error}
          </div>
        )}

        <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
          {/* Header row */}
          <div className="grid grid-cols-12 gap-2 px-5 py-2.5 border-b"
            style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}
          >
            {['Event ID', 'Time', 'Actor', 'Action', 'Target', 'Outcome', 'IP'].map((h) => (
              <span key={h}
                className={`font-mono text-[10px] uppercase tracking-wider ${
                  h === 'Action' ? 'col-span-3' : h === 'Target' ? 'col-span-2' : 'col-span-1'
                }`}
                style={tv.muted}
              >
                {h}
              </span>
            ))}
          </div>
          {allEntries.map(entry => {
            const outcomeColor = entry.outcome === 'SUCCESS' ? 'var(--tw-low)'
              : entry.outcome === 'PENDING_APPROVAL' ? 'var(--tw-medium)'
              : 'var(--tw-critical)';
            return (
              <div key={entry.id}
                className="grid grid-cols-12 gap-2 px-5 py-3 items-start border-b transition-colors"
                style={{ borderColor: 'var(--tw-border-mid)' }}
                {...hoverHandlers()}
              >
                <span className="font-mono text-[10px] col-span-1" style={tv.muted}>{entry.id}</span>
                <span className="font-mono text-[10px] col-span-1 tabular-nums" style={tv.muted}>
                  {new Date(entry.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </span>
                <span className="font-mono text-xs col-span-2" style={tv.text}>{entry.actor}</span>
                <span className="font-mono text-xs col-span-3" style={tv.text}>{entry.action}</span>
                <span className="font-mono text-xs col-span-2 truncate" style={tv.muted}>{entry.target}</span>
                <span className="font-mono text-[10px] col-span-1" style={{ color: outcomeColor }}>
                  {entry.outcome.replace('_', ' ')}
                </span>
                <span className="font-mono text-[10px] col-span-2" style={tv.faint}>{entry.ip}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
