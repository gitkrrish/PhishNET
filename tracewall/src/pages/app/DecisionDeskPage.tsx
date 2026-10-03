import { useState, useCallback } from 'react';
import { AlertTriangle, CheckCircle, ChevronDown, ChevronUp, Shield, Lock } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { responseActions, currentAnalyst, auditLog as mockAuditLog } from '../../data/mockData';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { tv } from '../../lib/styles';

const PERMISSION_LEVELS: Record<string, number> = {
  Viewer: 0,
  Auditor: 1,
  Analyst: 2,
  'Senior Investigator': 3,
  Administrator: 4,
};

function hasPermission(userRole: string, requiredPermission: string): boolean {
  const userLevel = PERMISSION_LEVELS[userRole] ?? 2;
  const requiredLevel = PERMISSION_LEVELS[requiredPermission] ?? 2;
  return userLevel >= requiredLevel;
}

function loadAuditEntries() {
  try {
    const raw = localStorage.getItem('tracewall-audit');
    if (raw) return JSON.parse(raw) as typeof mockAuditLog;
  } catch { /* ignore */ }
  return mockAuditLog;
}

function saveAuditEntry(entry: { id: string; time: string; actor: string; action: string; target: string; outcome: string; ip: string }) {
  try {
    const existing = loadAuditEntries();
    existing.unshift(entry);
    localStorage.setItem('tracewall-audit', JSON.stringify(existing));
  } catch { /* ignore */ }
}

function AuditConfirmDialog({ action, onConfirm, onCancel }: {
  action: typeof responseActions[0];
  onConfirm: (reason: string) => void;
  onCancel: () => void;
}) {
  const [reason, setReason] = useState('');
  const permissionOk = hasPermission(currentAnalyst.role, action.permission);

  return (
    <div className="space-y-3 pt-2 border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
      <div className="flex items-start gap-2 p-3 rounded-sm border"
        style={{ borderColor: `color-mix(in srgb, var(--tw-critical) 35%, transparent)`, backgroundColor: `color-mix(in srgb, var(--tw-critical) 18%, transparent)` }}
      >
        <AlertTriangle size={13} className="mt-0.5 shrink-0" style={tv.critical} />
        <div>
          <p className="text-xs font-medium" style={{ color: 'var(--tw-critical)' }}>
            Confirmation Required — {action.risk} Impact Action
          </p>
          <p className="text-xs" style={{ color: 'var(--tw-text-muted)' }}>
            {action.impact}. This action will be recorded in the audit log with actor, timestamp, and outcome.
            {!action.reversible && ' This action is irreversible.'}
          </p>
        </div>
      </div>
      {!permissionOk && (
        <div className="flex items-start gap-2 p-3 rounded-sm border"
          style={{ borderColor: `color-mix(in srgb, var(--tw-medium) 35%, transparent)`, backgroundColor: `color-mix(in srgb, var(--tw-medium) 18%, transparent)` }}
        >
          <Shield size={13} className="mt-0.5 shrink-0" style={tv.medium} />
          <p className="text-xs" style={{ color: 'var(--tw-medium)' }}>
            Permission Required: {action.permission} role or higher. Your current role: {currentAnalyst.role}.
          </p>
        </div>
      )}
      <div className="space-y-1">
        <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Reason (Required)</p>
        <textarea value={reason} onChange={e => setReason(e.target.value)}
          placeholder="Enter reason for this action…"
          className="w-full font-mono text-xs rounded-sm px-3 py-2 h-20 resize-none placeholder:opacity-40 focus:outline-none"
          style={tv.input}
        />
      </div>
      <div className="flex gap-2">
        <button
          onClick={() => { if (!reason.trim() || !permissionOk) return; onConfirm(reason); }}
          disabled={!reason.trim() || !permissionOk}
          className="flex-1 font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm transition-colors disabled:opacity-40"
          style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
        >
          Confirm & Execute
        </button>
        <button onClick={onCancel}
          className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
          style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

function ActionCard({ action }: { action: typeof responseActions[0] }) {
  const [expanded, setExpanded] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [reason, setReason] = useState('');
  const [showConfirm, setShowConfirm] = useState(false);

  const riskColor: Record<string, string> = {
    LOW:    'var(--tw-low)',
    MEDIUM: 'var(--tw-medium)',
    HIGH:   'var(--tw-critical)',
  };
  const rc = riskColor[action.risk] || riskColor.LOW;
  const permissionOk = hasPermission(currentAnalyst.role, action.permission);

  const handleExecute = useCallback((_reason: string) => {
    setConfirmed(true);
    saveAuditEntry({
      id: `AUD-${String(Date.now()).slice(-6)}`,
      time: new Date().toISOString(),
      actor: currentAnalyst.name,
      action: action.title,
      target: action.impact,
      outcome: 'SUCCESS',
      ip: '10.0.5.' + Math.floor(Math.random() * 254 + 1),
    });
  }, [action]);

  return (
    <div className="rounded-sm overflow-hidden border" style={{
      borderColor: confirmed ? `color-mix(in srgb, var(--tw-low) 35%, transparent)` : 'var(--tw-border)',
      backgroundColor: 'var(--tw-panel)',
    }}>
      <button onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-4 px-5 py-4 text-left transition-colors"
        style={{}}
        onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'var(--tw-hover)')}
        onMouseLeave={e => (e.currentTarget.style.backgroundColor = '')}
      >
        <span className="px-2 py-1 rounded-sm border font-mono text-[10px] tracking-widest uppercase shrink-0"
          style={{ color: rc, borderColor: `color-mix(in srgb, ${rc} 35%, transparent)`, backgroundColor: `color-mix(in srgb, ${rc} 18%, transparent)` }}
        >
          {action.risk}
        </span>
        <div className="flex-1">
          <p className="text-sm font-medium" style={tv.text}>{action.title}</p>
          <p className="text-xs" style={tv.muted}>{action.impact}</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {confirmed ? (
            <div className="flex items-center gap-1.5">
              <CheckCircle size={14} style={tv.low} />
              <span className="font-mono text-xs" style={tv.low}>Executed</span>
            </div>
          ) : action.requiresApproval ? (
            <span className="font-mono text-[10px] px-2 py-0.5 rounded-sm border"
              style={{ color: 'var(--tw-medium)', borderColor: `color-mix(in srgb, var(--tw-medium) 35%, transparent)`, backgroundColor: `color-mix(in srgb, var(--tw-medium) 10%, transparent)` }}
            >
              Requires Approval
            </span>
          ) : (
            <span className="font-mono text-[10px] px-2 py-0.5 rounded-sm border"
              style={{ color: 'var(--tw-low)', borderColor: `color-mix(in srgb, var(--tw-low) 35%, transparent)`, backgroundColor: `color-mix(in srgb, var(--tw-low) 10%, transparent)` }}
            >
              Ready
            </span>
          )}
          {expanded ? <ChevronUp size={14} style={tv.faint} /> : <ChevronDown size={14} style={tv.faint} />}
        </div>
      </button>

      <AnimatePresence>
        {expanded && (
          <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} className="overflow-hidden">
            <div className="px-5 pb-5 pt-2 border-t space-y-4" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <div className="grid md:grid-cols-2 gap-4">
                {[
                  { label: 'Action',               val: action.title },
                  { label: 'Reason',               val: action.reason },
                  { label: 'Impact',               val: action.impact },
                  { label: 'Reversible',           val: action.reversible ? 'Yes' : 'No — irreversible' },
                  { label: 'Permission Required',  val: action.permission },
                  { label: 'Risk Level',           val: action.risk },
                ].map(row => (
                  <div key={row.label} className="space-y-0.5">
                    <span className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>{row.label}</span>
                    <p className="font-mono text-xs" style={{ color: row.label === 'Reversible' && !action.reversible ? 'var(--tw-critical)' : 'var(--tw-text)' }}>
                      {row.val}
                    </p>
                  </div>
                ))}
                {!permissionOk && (
                  <div className="flex items-start gap-2 col-span-2">
                    <Lock size={13} className="mt-0.5 shrink-0" style={tv.medium} />
                    <p className="text-xs" style={{ color: 'var(--tw-medium)' }}>
                      Access Denied: Your role ({currentAnalyst.role}) does not meet the required permission ({action.permission}). Contact an administrator.
                    </p>
                  </div>
                )}
              </div>

              {!confirmed && (
                <div className="space-y-2 pt-2 border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  {action.requiresApproval && permissionOk && (
                    <>
                      <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Approval Reason (Required)</p>
                      <textarea value={reason} onChange={e => setReason(e.target.value)}
                        placeholder="Enter reason…"
                        className="w-full font-mono text-xs rounded-sm px-3 py-2 h-20 resize-none placeholder:opacity-40 focus:outline-none"
                        style={tv.input}
                      />
                    </>
                  )}
                  {action.risk === 'HIGH' && permissionOk && (
                    <div className="flex items-start gap-2 p-3 rounded-sm border"
                      style={{ borderColor: `color-mix(in srgb, var(--tw-critical) 35%, transparent)`, backgroundColor: `color-mix(in srgb, var(--tw-critical) 18%, transparent)` }}
                    >
                      <AlertTriangle size={13} className="mt-0.5 shrink-0" style={tv.critical} />
                      <p className="text-xs" style={tv.muted}>
                        High-impact action.{!action.reversible && ' Not reversible.'} Review all evidence before proceeding.
                      </p>
                    </div>
                  )}
                  {permissionOk && (
                    <div className="flex gap-2">
                      <button
                        onClick={() => {
                          if (action.risk === 'HIGH' || action.risk === 'MEDIUM') {
                            setShowConfirm(true);
                          } else {
                            setConfirmed(true);
                            saveAuditEntry({
                              id: `AUD-${String(Date.now()).slice(-6)}`,
                              time: new Date().toISOString(),
                              actor: currentAnalyst.name,
                              action: action.title,
                              target: action.impact,
                              outcome: 'SUCCESS',
                              ip: '10.0.5.' + Math.floor(Math.random() * 254 + 1),
                            });
                          }
                        }}
                        disabled={action.requiresApproval && !reason.trim()}
                        className="flex-1 font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm transition-colors disabled:opacity-40"
                        style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
                      >
                        {action.requiresApproval ? 'Approve & Execute' : 'Execute Action'}
                      </button>
                      <button onClick={() => setExpanded(false)}
                        className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                        style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
                      >
                        Cancel
                      </button>
                    </div>
                  )}
                  {!permissionOk && (
                    <div className="flex gap-2">
                      <button disabled
                        className="flex-1 font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm transition-colors disabled:opacity-40"
                        style={{ backgroundColor: 'var(--tw-border-strong)', color: 'var(--tw-text-faint)' }}
                      >
                        Access Denied
                      </button>
                    </div>
                  )}
                </div>
              )}
              {showConfirm && permissionOk && (
                <div className="pt-2 border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <AuditConfirmDialog action={action} onConfirm={handleExecute} onCancel={() => setShowConfirm(false)} />
                </div>
              )}
              {confirmed && (
                <div className="flex items-center gap-3 pt-2 border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <CheckCircle size={14} style={tv.low} />
                  <p className="text-sm" style={tv.low}>Action executed and recorded in audit log.</p>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export default function DecisionDeskPage() {
  return (
    <div className="min-h-screen" style={tv.canvas}>
      <div className="max-w-4xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Response Orchestration</p>
            <DemoLabel />
          </div>
          <h1 className="font-serif text-3xl" style={tv.text}>Decision Desk</h1>
          <p className="text-sm max-w-xl leading-relaxed" style={tv.muted}>
            Recommended defensive actions. High-impact actions require approval and a stated reason. All actions are logged.
          </p>
        </div>

        {/* Mode selector */}
        <div className="flex gap-3 p-4 rounded-sm items-center" style={{ ...tv.canvasMid, border: '1px solid var(--tw-border)' }}>
          {['Recommendation Mode', 'Controlled Automation'].map((mode, i) => (
            <button key={mode}
              className="font-mono text-[10px] tracking-wider px-3 py-1.5 rounded-sm border transition-colors"
              style={i === 0
                ? { backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6', borderColor: 'var(--tw-burgundy)' }
                : { backgroundColor: 'transparent', color: 'var(--tw-text-muted)', borderColor: 'var(--tw-border-strong)' }
              }
            >
              {mode}
            </button>
          ))}
          <p className="font-mono text-[10px] ml-2" style={tv.muted}>
            Recommendation Mode: AI suggests, analyst approves.
          </p>
        </div>

        <div className="space-y-3">
          {responseActions.map(action => <ActionCard key={action.id} action={action} />)}
        </div>

        <div className="p-4 rounded-sm" style={{ ...tv.canvasMid, border: '1px solid var(--tw-border)' }}>
          <p className="font-mono text-[10px] leading-relaxed" style={tv.muted}>
            All actions executed through the Decision Desk are recorded in the audit log with actor, timestamp, reason, and outcome.
            Dual-approval is required for domain-wide blocks, user account changes, and credential operations.
          </p>
        </div>
      </div>
    </div>
  );
}
