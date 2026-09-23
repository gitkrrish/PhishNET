import { alertsWithAssignment } from '../../data/mockData';
import { SeverityBadge } from '../../components/ui/SeverityBadge';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { Link } from 'react-router-dom';
import { tv, statusColor, hoverHandlers } from '../../lib/styles';
import { useState } from 'react';
import { User, Hash, AlertTriangle, XCircle, Filter, CheckCircle, UserPlus, ArrowUp } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { acknowledgeAlert, assignAlert, escalateAlert, dismissAlert, resolveAlert, createAuditEvent, DEMO_LABEL } from '../../lib/mockBackend';
import ThreatEvidenceNetwork from '../../components/3d/ThreatEvidenceNetwork';

type AlertFilter = 'all' | 'open' | 'pending' | 'resolved' | 'dismissed';

export default function AlertsPage() {
  const [filter, setFilter] = useState<AlertFilter>('all');
  const [selectedAlert, setSelectedAlert] = useState<typeof alertsWithAssignment[0] | null>(null);
  const [actionInProgress, setActionInProgress] = useState(false);
  const [actionResult, setActionResult] = useState<{ success: boolean; message: string } | null>(null);
  const [showAssignDialog, setShowAssignDialog] = useState(false);
  const [assignee, setAssignee] = useState('');
  const [showEscalateDialog, setShowEscalateDialog] = useState(false);
  const [escalationReason, setEscalationReason] = useState('');
  const [customAlerts, setCustomAlerts] = useState<any[]>([]);

  const allAlertsList = [...alertsWithAssignment, ...customAlerts];
  
  const filteredAlerts = allAlertsList.filter(alert => {
    switch (filter) {
      case 'open': return alert.status === 'OPEN' || alert.status === 'ACKNOWLEDGED';
      case 'pending': return alert.status === 'AWAITING_APPROVAL';
      case 'resolved': return alert.status === 'RESOLVED' || alert.status === 'CONTAINED';
      case 'dismissed': return (alert.status as string) === 'FALSE_POSITIVE';
      default: return true;
    }
  });

  const categoryCounts = {
    all: allAlertsList.length,
    open: allAlertsList.filter(a => a.status === 'OPEN' || a.status === 'ACKNOWLEDGED').length,
    pending: allAlertsList.filter(a => a.status === 'AWAITING_APPROVAL').length,
    resolved: allAlertsList.filter(a => a.status === 'RESOLVED' || a.status === 'CONTAINED').length,
    dismissed: allAlertsList.filter(a => (a.status as string) === 'FALSE_POSITIVE').length,
  };

  return (
    <div className="min-h-screen" style={tv.canvas}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        <div className="flex items-end justify-between gap-4">
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Alert Management</p>
              <DemoLabel />
            </div>
            <h1 className="font-serif text-3xl" style={tv.text}>Active Alerts</h1>
          </div>
          <div className="flex gap-2">
            {[
              { label: 'All', val: categoryCounts.all, key: 'all' as AlertFilter },
              { label: 'Open', val: categoryCounts.open, key: 'open' as AlertFilter },
              { label: 'Pending', val: categoryCounts.pending, key: 'pending' as AlertFilter },
              { label: 'Resolved', val: categoryCounts.resolved, key: 'resolved' as AlertFilter },
              { label: 'Dismissed', val: categoryCounts.dismissed, key: 'dismissed' as AlertFilter },
            ].map(c => (
              <button
                key={c.key}
                onClick={() => setFilter(c.key)}
                className="text-center px-4 py-2 rounded-sm transition-colors"
                style={{
                  ...tv.panelBorder,
                  backgroundColor: filter === c.key ? 'var(--tw-panel-alt)' : 'var(--tw-panel)',
                }}
              >
                <div className="font-mono text-xl font-light" style={tv.burg}>{c.val}</div>
                <div className="font-mono text-[9px] uppercase tracking-wider" style={tv.muted}>{c.label}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Threat Evidence Network */}
        <ThreatEvidenceNetwork pageType="alerts" />

        {/* Filter notice */}
        <div className="flex items-center gap-2 text-xs" style={tv.muted}>
          <Filter size={12} />
          <span>Showing: {filter === 'all' ? 'All alerts' : filter.charAt(0).toUpperCase() + filter.slice(1) + ' alerts'} ({filteredAlerts.length})</span>
        </div>

        {filteredAlerts.length === 0 ? (
          <div className="rounded-sm p-10 text-center" style={tv.panelBorder}>
            <AlertTriangle size={32} className="mx-auto mb-3" style={tv.faint} />
            <p className="font-mono text-sm" style={tv.muted}>No alerts found in this category.</p>
            <button
              onClick={() => setFilter('all')}
              className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border mt-4 transition-colors"
              style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
            >
              View All Alerts
            </button>
          </div>
        ) : (
          <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
            {filteredAlerts.map(alert => {
              const sc = statusColor(alert.status);
              return (
                <div 
                  key={alert.id} 
                  className="p-5 border-b transition-colors cursor-pointer" 
                  style={{ borderColor: 'var(--tw-border-mid)' }}
                  onClick={() => setSelectedAlert(alert)}
                  {...hoverHandlers()}
                >
                  <div className="flex items-start gap-4">
                    <div className="flex-1 space-y-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <p className="font-mono text-[10px]" style={tv.muted}>{alert.id}</p>
                        <SeverityBadge severity={alert.severity} />
                        <span className="font-mono text-[9px] px-2 py-0.5 rounded-sm border tracking-widest uppercase"
                          style={{ color: sc, borderColor: `color-mix(in srgb, ${sc} 35%, transparent)`, backgroundColor: `color-mix(in srgb, ${sc} 18%, transparent)` }}
                        >
                          {alert.status.replace('_', ' ')}
                        </span>
                        <span className="font-mono text-[10px] px-2 py-0.5 rounded-sm"
                          style={{ backgroundColor: 'var(--tw-panel-alt)', color: 'var(--tw-text-muted)' }}
                        >
                          {alert.category}
                        </span>
                      </div>
                      <h3 className="font-serif text-lg" style={tv.text}>{alert.title}</h3>
                      <p className="text-sm" style={tv.muted}>{alert.summary}</p>
                      <p className="font-mono text-[10px]" style={tv.medium}>Recommendation: {alert.recommendation}</p>
                      
                      {/* New fields: Assigned analyst and source */}
                      <div className="flex items-center gap-4 pt-2">
                        {alert.assignedTo && (
                          <div className="flex items-center gap-1.5 text-xs" style={tv.muted}>
                            <User size={11} />
                            <span>{alert.assignedTo}</span>
                          </div>
                        )}
                        {alert.source && (
                          <div className="flex items-center gap-1.5 text-xs" style={tv.muted}>
                            <Hash size={11} />
                            <span>{alert.source}</span>
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="flex flex-col gap-2 shrink-0">
                      <p className="font-mono text-[10px]" style={tv.faint}>{new Date(alert.created).toLocaleDateString()}</p>
                      {alert.relatedCase && (
                        <Link 
                          to={`/app/cases/${alert.relatedCase}`} 
                          className="font-mono text-[10px]"
                          style={tv.burg}
                          onClick={(e) => e.stopPropagation()}
                        >
                          {alert.relatedCase} →
                        </Link>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Alert detail modal/panel */}
        {selectedAlert && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
            <div className="rounded-sm overflow-hidden max-w-2xl w-full max-h-[90vh] overflow-y-auto" style={tv.panelBorder}>
              <div className="px-6 py-4 border-b flex items-center justify-between" style={{ borderColor: 'var(--tw-border-mid)' }}>
                <div className="space-y-1">
                  <p className="font-mono text-[10px]" style={tv.muted}>{selectedAlert.id}</p>
                  <h2 className="font-serif text-xl" style={tv.text}>{selectedAlert.title}</h2>
                </div>
                <button
                  onClick={() => setSelectedAlert(null)}
                  className="p-2 rounded-sm transition-colors"
                  style={{ color: 'var(--tw-text-muted)' }}
                >
                  <XCircle size={16} />
                </button>
              </div>
              <div className="p-6 space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  {[
                    { label: 'Severity', val: selectedAlert.severity },
                    { label: 'Category', val: selectedAlert.category },
                    { label: 'Status', val: selectedAlert.status.replace('_', ' ') },
                    { label: 'Created', val: new Date(selectedAlert.created).toLocaleString() },
                  ].map(row => (
                    <div key={row.label}>
                      <p className="font-mono text-[10px] uppercase tracking-wider mb-0.5" style={tv.muted}>{row.label}</p>
                      <p className="font-mono text-xs" style={tv.text}>{row.val}</p>
                    </div>
                  ))}
                </div>
                
                {selectedAlert.assignedTo && (
                  <div className="flex items-center gap-2 pt-2">
                    <User size={12} style={tv.muted} />
                    <span className="font-mono text-[10px]" style={tv.muted}>Assigned to: {selectedAlert.assignedTo}</span>
                  </div>
                )}
                
                {selectedAlert.source && (
                  <div className="flex items-center gap-2 pt-2">
                    <Hash size={12} style={tv.muted} />
                    <span className="font-mono text-[10px]" style={tv.muted}>Source: {selectedAlert.source}</span>
                  </div>
                )}

                <div className="pt-2 border-t space-y-2" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Summary</p>
                  <p className="text-sm leading-relaxed" style={tv.text}>{selectedAlert.summary}</p>
                </div>

                <div className="pt-2 border-t space-y-2" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Recommendation</p>
                  <p className="text-sm leading-relaxed" style={tv.text}>{selectedAlert.recommendation}</p>
                </div>

                {selectedAlert.relatedCase && (
                  <div className="pt-2 border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
                    <Link 
                      to={`/app/cases/${selectedAlert.relatedCase}`}
                      className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border inline-flex items-center gap-2"
                      style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text)' }}
                      onClick={() => setSelectedAlert(null)}
                    >
                      View Related Case →
                    </Link>
                  </div>
                )}

                <div className="flex gap-2 pt-4">
                  <button 
                    onClick={async () => {
                      if (!selectedAlert) return;
                      setActionInProgress(true);
                      try {
                        const result = await acknowledgeAlert(selectedAlert.id);
                        setActionResult({ success: result.success, message: 'Alert acknowledged successfully' });
                        await createAuditEvent('Alert Acknowledged', selectedAlert.id, 'SUCCESS');
                        // Update local state
                        setCustomAlerts(prev => prev.map(a => 
                          a.id === selectedAlert.id ? { ...a, status: 'ACKNOWLEDGED' as const } : a
                        ));
                      } catch (error) {
                        setActionResult({ success: false, message: 'Failed to acknowledge alert' });
                      } finally {
                        setActionInProgress(false);
                      }
                    }}
                    disabled={actionInProgress}
                    className="flex-1 font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm transition-colors disabled:opacity-40"
                    style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
                  >
                    {actionInProgress ? 'Processing…' : 'Acknowledge'}
                  </button>
                  <button 
                    onClick={() => setShowAssignDialog(true)}
                    className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors flex items-center gap-2"
                    style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
                  >
                    <UserPlus size={12} /> Assign
                  </button>
                  <button 
                    onClick={() => setShowEscalateDialog(true)}
                    className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors flex items-center gap-2"
                    style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
                  >
                    <ArrowUp size={12} /> Escalate
                  </button>
                </div>

                {/* Action Result */}
                {actionResult && (
                  <div className={`rounded-sm p-4 border ${
                    actionResult.success 
                      ? 'border-[color-mix(in_srgb,var(--tw-moss),transparent)]' 
                      : 'border-[color-mix(in_srgb,var(--tw-critical),transparent)]'
                  }`} style={{
                    backgroundColor: actionResult.success 
                      ? 'color-mix(in srgb, var(--tw-moss) 18%, transparent)' 
                      : 'color-mix(in srgb, var(--tw-critical) 18%, transparent)'
                  }}>
                    <div className="flex items-start gap-2">
                      {actionResult.success ? (
                        <CheckCircle size={14} className="mt-0.5 shrink-0" style={{ color: 'var(--tw-moss)' }} />
                      ) : (
                        <AlertTriangle size={14} className="mt-0.5 shrink-0" style={{ color: 'var(--tw-critical)' }} />
                      )}
                      <p className="text-xs leading-relaxed" style={tv.text}>{actionResult.message}</p>
                    </div>
                  </div>
                )}

                {/* Assign Dialog */}
                <AnimatePresence>
                  {showAssignDialog && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      className="mt-4 rounded-sm overflow-hidden border"
                      style={{ borderColor: 'var(--tw-border)' }}
                    >
                      <div className="p-4 space-y-3" style={{ backgroundColor: 'var(--tw-panel-alt)' }}>
                        <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Assign Alert</p>
                        <input
                          type="text"
                          value={assignee}
                          onChange={e => setAssignee(e.target.value)}
                          placeholder="Enter analyst name..."
                          className="w-full font-mono text-xs px-3 py-2 rounded-sm focus:outline-none placeholder:opacity-40"
                          style={tv.input}
                        />
                        <div className="flex gap-2">
                          <button
                            onClick={async () => {
                              if (!selectedAlert || !assignee.trim()) return;
                              setActionInProgress(true);
                              try {
                                const result = await assignAlert(selectedAlert.id, assignee);
                                setActionResult({ success: result.success, message: `Alert assigned to ${assignee}` });
                                setShowAssignDialog(false);
                                setAssignee('');
                                await createAuditEvent('Alert Assigned', selectedAlert.id, 'SUCCESS');
                              } catch (error) {
                                setActionResult({ success: false, message: 'Failed to assign alert' });
                              } finally {
                                setActionInProgress(false);
                              }
                            }}
                            disabled={actionInProgress || !assignee.trim()}
                            className="flex-1 font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm transition-colors disabled:opacity-40"
                            style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
                          >
                            {actionInProgress ? 'Assigning…' : 'Assign'}
                          </button>
                          <button
                            onClick={() => setShowAssignDialog(false)}
                            className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                            style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>

                {/* Escalate Dialog */}
                <AnimatePresence>
                  {showEscalateDialog && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      className="mt-4 rounded-sm overflow-hidden border"
                      style={{ borderColor: 'var(--tw-border)' }}
                    >
                      <div className="p-4 space-y-3" style={{ backgroundColor: 'var(--tw-panel-alt)' }}>
                        <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Escalate Alert</p>
                        <textarea
                          value={escalationReason}
                          onChange={e => setEscalationReason(e.target.value)}
                          placeholder="Reason for escalation..."
                          rows={2}
                          className="w-full font-mono text-xs px-3 py-2 rounded-sm focus:outline-none placeholder:opacity-40 resize-none"
                          style={tv.input}
                        />
                        <div className="flex gap-2">
                          <button
                            onClick={async () => {
                              if (!selectedAlert || !escalationReason.trim()) return;
                              setActionInProgress(true);
                              try {
                                const result = await escalateAlert(selectedAlert.id, escalationReason);
                                setActionResult({ success: result.success, message: 'Alert escalated successfully' });
                                setShowEscalateDialog(false);
                                setEscalationReason('');
                                await createAuditEvent('Alert Escalated', selectedAlert.id, 'SUCCESS');
                              } catch (error) {
                                setActionResult({ success: false, message: 'Failed to escalate alert' });
                              } finally {
                                setActionInProgress(false);
                              }
                            }}
                            disabled={actionInProgress || !escalationReason.trim()}
                            className="flex-1 font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm transition-colors disabled:opacity-40"
                            style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
                          >
                            {actionInProgress ? 'Escalating…' : 'Escalate'}
                          </button>
                          <button
                            onClick={() => setShowEscalateDialog(false)}
                            className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                            style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>

                {/* Additional Actions */}
                <div className="flex gap-2 pt-2">
                  <button 
                    onClick={async () => {
                      if (!selectedAlert) return;
                      setActionInProgress(true);
                      try {
                        const result = await dismissAlert(selectedAlert.id, 'Marked as false positive by analyst');
                        setActionResult({ success: result.success, message: 'Alert dismissed as false positive' });
                        await createAuditEvent('Alert Dismissed', selectedAlert.id, 'SUCCESS');
                      } catch (error) {
                        setActionResult({ success: false, message: 'Failed to dismiss alert' });
                      } finally {
                        setActionInProgress(false);
                      }
                    }}
                    disabled={actionInProgress}
                    className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors disabled:opacity-40"
                    style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
                  >
                    {actionInProgress ? 'Processing…' : 'Dismiss'}
                  </button>
                  <button 
                    onClick={async () => {
                      if (!selectedAlert) return;
                      setActionInProgress(true);
                      try {
                        const result = await resolveAlert(selectedAlert.id, 'Issue resolved and containment verified');
                        setActionResult({ success: result.success, message: 'Alert resolved successfully' });
                        await createAuditEvent('Alert Resolved', selectedAlert.id, 'SUCCESS');
                      } catch (error) {
                        setActionResult({ success: false, message: 'Failed to resolve alert' });
                      } finally {
                        setActionInProgress(false);
                      }
                    }}
                    disabled={actionInProgress}
                    className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors disabled:opacity-40"
                    style={{ borderColor: 'var(--tw-moss)', color: 'var(--tw-moss)' }}
                  >
                    {actionInProgress ? 'Processing…' : 'Resolve'}
                  </button>
                </div>

                {/* Demo Label */}
                <div className="pt-2 border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <p className="font-mono text-[10px]" style={tv.muted}>{DEMO_LABEL}</p>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
