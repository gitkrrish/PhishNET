import { useState } from 'react';
import { AlertTriangle, CheckCircle, Clock, Shield, Plus, X } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { exposureRecords } from '../../data/mockData';
import { SeverityBadge } from '../../components/ui/SeverityBadge';
import { ConfidenceBar } from '../../components/ui/ConfidenceBar';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { tv, statusColor } from '../../lib/styles';
import { lazy, Suspense } from 'react';
import { ThreeDErrorBoundary } from '../../components/3d/ThreeDErrorBoundary';
import ThreatEvidenceNetwork from '../../components/3d/ThreatEvidenceNetwork';

// Lazy load the 3D component
const RedactionEffect3D = lazy(() => import('../../components/3d/RedactionEffect3D').then(m => ({ default: m.default })));

function ExposureRecord({
  record, selected, onSelect,
}: {
  record: typeof exposureRecords[0]; selected: boolean; onSelect: () => void;
}) {
  const sc = statusColor(record.status);
  return (
    <button onClick={onSelect}
      className="w-full text-left p-5 border-b transition-colors"
      style={{
        borderColor: 'var(--tw-border-mid)',
        borderLeft: selected ? `2px solid var(--tw-burgundy)` : '2px solid transparent',
        backgroundColor: selected ? 'var(--tw-panel-alt)' : 'transparent',
      }}
    >
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="space-y-0.5">
          <p className="font-mono text-[10px] tracking-wider" style={tv.muted}>{record.id}</p>
          <p className="font-mono text-sm font-medium" style={tv.text}>{record.maskedIdentity}</p>
        </div>
        <SeverityBadge severity={record.severity} />
      </div>
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs" style={tv.muted}>{record.sourceCategory}</span>
        <span className="font-mono text-[9px] tracking-widest uppercase px-2 py-0.5 rounded-sm border"
          style={{ color: sc, borderColor: `color-mix(in srgb, ${sc} 35%, transparent)`, backgroundColor: `color-mix(in srgb, ${sc} 18%, transparent)` }}
        >
          {record.status.replace('_', ' ')}
        </span>
      </div>
      <p className="font-mono text-[10px] mt-1" style={tv.faint}>{record.exposureDate}</p>
      {record.department && (
        <p className="font-mono text-[10px] mt-1" style={tv.muted}>Dept: {record.department}</p>
      )}
    </button>
  );
}

function ExposureDetail({ record }: { record: typeof exposureRecords[0] }) {
  const [approvalOpen, setApprovalOpen] = useState(false);
  const [approvedActions, setApprovedActions] = useState<string[]>([]);
  const [checkingExposure, setCheckingExposure] = useState(false);
  const [exposureResult, setExposureResult] = useState<{ found: boolean; message: string } | null>(null);
  const sc = statusColor(record.status);

  const checkExposure = () => {
    setCheckingExposure(true);
    setExposureResult(null);
    // Simulate exposure check
    setTimeout(() => {
      setCheckingExposure(false);
      setExposureResult({
        found: record.status === 'AWAITING_APPROVAL',
        message: record.status === 'AWAITING_APPROVAL' 
          ? 'Potential exposure detected in simulated breach-monitoring feed. Severity: HIGH. Confidence: 72%.' 
          : 'No new exposure detected in current monitoring feeds.'
      });
    }, 1500);
  };

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Exposure Record</p>
            <DemoLabel />
          </div>
          <p className="font-mono text-[10px] tracking-wider" style={tv.burg}>{record.id}</p>
        </div>
        <span className="font-mono text-[9px] tracking-widest uppercase px-3 py-1 rounded-sm border"
          style={{ color: sc, borderColor: `color-mix(in srgb, ${sc} 35%, transparent)`, backgroundColor: `color-mix(in srgb, ${sc} 18%, transparent)` }}
        >
          {record.status.replace('_', ' ')}
        </span>
      </div>

      {/* Details */}
      <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
        <div className="px-5 py-3 border-b flex items-center gap-2" style={{ borderColor: 'var(--tw-border-mid)' }}>
          <Shield size={13} style={tv.muted} />
          <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Exposure Details</p>
        </div>
        {[
          { label: 'Masked Identity',    val: record.maskedIdentity,    sensitive: false },
          { label: 'Organisation Domain',val: record.domain,            sensitive: false },
          { label: 'Exposure Date',      val: record.exposureDate,      sensitive: false },
          { label: 'Source Category',    val: record.sourceCategory,    sensitive: false },
          { label: 'Data Type',          val: record.dataType,          sensitive: false },
          { label: 'Secret',             val: 'REDACTED',               sensitive: true  },
          { label: 'Department',         val: record.department,        sensitive: false },
          { label: 'Related Case',       val: record.relatedCase || 'None', sensitive: false },
        ].map(row => (
          <div key={row.label} className="flex items-center gap-4 px-5 py-2.5 border-b last:border-0"
            style={{ borderColor: 'var(--tw-border-mid)' }}
          >
            <span className="font-mono text-[10px] uppercase tracking-wider w-36 shrink-0" style={tv.muted}>{row.label}</span>
            {row.sensitive ? (
              <ThreeDErrorBoundary fallback={
                <span className="font-mono text-xs px-4 py-0.5 rounded-sm select-none"
                  style={{ backgroundColor: 'var(--tw-text)', color: 'transparent' }}
                >
                  REDACTED
                </span>
              }>
                <Suspense fallback={
                  <span className="font-mono text-xs px-4 py-0.5 rounded-sm select-none"
                    style={{ backgroundColor: 'var(--tw-text)', color: 'transparent' }}
                  >
                    REDACTED
                  </span>
                }>
                  <RedactionEffect3D>
                    <span className="font-mono text-xs px-4 py-0.5 rounded-sm select-none"
                      style={{ backgroundColor: 'var(--tw-text)', color: 'transparent' }}
                    >
                      REDACTED
                    </span>
                  </RedactionEffect3D>
                </Suspense>
              </ThreeDErrorBoundary>
            ) : (
              <span className="font-mono text-xs" style={tv.text}>{row.val}</span>
            )}
          </div>
        ))}
      </div>

      {/* Confidence + note */}
      <div className="rounded-sm p-4 space-y-3" style={tv.panelBorder}>
        <ConfidenceBar value={record.confidence} />
        <SeverityBadge severity={record.severity} />
        <p className="text-xs leading-relaxed" style={tv.muted}>{record.note}</p>
      </div>

      {/* Check Exposure Button */}
      <button
        onClick={checkExposure}
        disabled={checkingExposure}
        className="w-full font-mono text-xs tracking-widest uppercase px-4 py-3 rounded-sm border transition-colors disabled:opacity-40"
        style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
      >
        {checkingExposure ? 'Checking Exposure…' : 'Check Exposure Status'}
      </button>

      {/* Exposure Result */}
      {exposureResult && (
        <div className={`rounded-sm p-4 border ${
          exposureResult.found 
            ? 'border-[color-mix(in_srgb,var(--tw-critical),transparent)]' 
            : 'border-[color-mix(in_srgb,var(--tw-low),transparent)]'
        }`} style={{
          backgroundColor: exposureResult.found 
            ? 'color-mix(in srgb, var(--tw-critical) 18%, transparent)' 
            : 'color-mix(in srgb, var(--tw-low) 18%, transparent)'
        }}>
          <div className="flex items-start gap-2">
            {exposureResult.found ? (
              <AlertTriangle size={14} className="mt-0.5 shrink-0" style={{ color: 'var(--tw-critical)' }} />
            ) : (
              <CheckCircle size={14} className="mt-0.5 shrink-0" style={{ color: 'var(--tw-low)' }} />
            )}
            <p className="text-xs leading-relaxed" style={tv.text}>{exposureResult.message}</p>
          </div>
        </div>
      )}

      {/* Recommended actions */}
      <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
        <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
          <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Recommended Response Actions</p>
        </div>
        {record.recommendedActions.map((action, i) => {
          const isApproved = approvedActions.includes(action);
          return (
            <div key={i} className="flex items-center gap-4 px-5 py-3 border-b last:border-0"
              style={{ borderColor: 'var(--tw-border-mid)' }}
            >
              <span className="evidence-num shrink-0">{String(i + 1).padStart(2, '0')}</span>
              <p className="text-sm flex-1" style={tv.text}>{action}</p>
              {record.status === 'AWAITING_APPROVAL' && !isApproved ? (
                <button
                  onClick={() => setApprovedActions(p => [...p, action])}
                  className="font-mono text-[10px] tracking-widest uppercase px-3 py-1.5 rounded-sm border transition-colors shrink-0"
                  style={{ color: 'var(--tw-burgundy)', borderColor: 'var(--tw-burgundy)' }}
                >
                  Approve
                </button>
              ) : (
                <div className="flex items-center gap-1.5 shrink-0">
                  <CheckCircle size={12} style={tv.low} />
                  <span className="font-mono text-[10px]" style={tv.low}>{isApproved ? 'Approved' : 'Done'}</span>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Approval workflow */}
      {record.status === 'AWAITING_APPROVAL' && (
        <div className="rounded-sm overflow-hidden border" style={{ borderColor: `color-mix(in srgb, var(--tw-medium) 35%, transparent)` }}>
          <button onClick={() => setApprovalOpen(!approvalOpen)}
            className="w-full flex items-center gap-2 px-5 py-3 text-left"
            style={{ backgroundColor: `color-mix(in srgb, var(--tw-medium) 18%, transparent)` }}
          >
            <Clock size={13} style={tv.medium} />
            <span className="font-mono text-[10px] tracking-[0.15em] uppercase" style={tv.medium}>
              Approval Required — Awaiting Administrator
            </span>
          </button>
          <AnimatePresence>
            {approvalOpen && (
              <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} className="overflow-hidden">
                <div className="px-5 py-4 space-y-4" style={{ backgroundColor: 'var(--tw-panel)' }}>
                  <p className="text-xs leading-relaxed" style={tv.muted}>
                    High-impact actions require administrator approval. Approve individual actions above or submit a bulk approval.
                  </p>
                  <textarea placeholder="Approval reason and notes…"
                    className="w-full font-mono text-xs rounded-sm px-3 py-2 h-20 resize-none placeholder:opacity-40 focus:outline-none"
                    style={{ ...tv.input, borderRadius: 2 }}
                  />
                  <div className="flex gap-2">
                    <button
                      onClick={() => { setApprovalOpen(false); }}
                      className="flex-1 font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm transition-colors"
                      style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
                    >
                      Approve All Actions
                    </button>
                    <button
                      onClick={() => { setApprovalOpen(false); }}
                      className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                      style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
                    >
                      Escalate
                    </button>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}
    </div>
  );
}

export default function ExposurePage() {
  const [selectedRecord, setSelectedRecord] = useState(exposureRecords[0]);
  const [showAddTarget, setShowAddTarget] = useState(false);
  const [newTarget, setNewTarget] = useState({
    type: 'domain',
    value: '',
    organization: '',
    department: '',
    frequency: 'daily',
    riskSensitivity: 'medium',
    retentionPeriod: '90',
  });
  const [customRecords, setCustomRecords] = useState<any[]>([]);
  const [checkingNewTarget, setCheckingNewTarget] = useState(false);
  const [newTargetResult, setNewTargetResult] = useState<{ found: boolean; message: string } | null>(null);

  const allRecords = [...exposureRecords, ...customRecords];

  const handleAddTarget = () => {
    if (!newTarget.value.trim()) return;
    
    setCheckingNewTarget(true);
    setNewTargetResult(null);
    
    // Simulate target validation and exposure check
    setTimeout(() => {
      setCheckingNewTarget(false);
      const found = Math.random() > 0.5; // Random simulation
      setNewTargetResult({
        found,
        message: found 
          ? `Potential exposure detected for ${newTarget.type}: ${newTarget.value}. Severity: ${newTarget.riskSensitivity.toUpperCase()}.`
          : `No exposure detected for ${newTarget.type}: ${newTarget.value} in current monitoring feeds.`
      });

      if (found) {
        // Add to custom records
        const newRecord = {
          id: `EXP-${String(Date.now()).slice(-6)}`,
          maskedIdentity: newTarget.type === 'email' 
            ? `${newTarget.value[0]}••••@${newTarget.value.split('@')[1]}` 
            : newTarget.value.replace(/./g, (c, i) => i < 2 ? c : '•'),
          domain: newTarget.type === 'domain' ? newTarget.value : newTarget.organization,
          exposureDate: new Date().toISOString().split('T')[0],
          sourceCategory: 'Simulated breach-monitoring feed',
          dataType: newTarget.type === 'email' ? 'Email + Password indicator' : 'Asset identifier',
          passwordStatus: 'REDACTED',
          confidence: 65 + Math.floor(Math.random() * 30),
          severity: newTarget.riskSensitivity === 'high' ? 'HIGH' as const : 'MEDIUM' as const,
          department: newTarget.department,
          recommendedActions: [
            'Force password reset',
            'Revoke active sessions',
            'Review sign-in activity',
          ],
          relatedCase: null,
          status: 'AWAITING_APPROVAL' as const,
          note: 'Added via manual target monitoring. Simulated demo data only.',
        };
        setCustomRecords(prev => [...prev, newRecord]);
        setSelectedRecord(newRecord as any);
      }
    }, 2000);
  };

  return (
    <div className="min-h-screen" style={tv.canvas}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8">
        <div className="flex items-end justify-between mb-6 gap-4">
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Exposure Ledger</p>
              <DemoLabel />
            </div>
            <h1 className="font-serif text-3xl" style={tv.text}>Credential Exposure Monitor</h1>
            <p className="text-sm max-w-2xl leading-relaxed" style={tv.muted}>
              Authorised monitoring of organisational credential exposure indicators. Plaintext secrets are never stored, displayed, or purchased.
            </p>
          </div>
          <div className="flex gap-2 shrink-0">
            <button
              onClick={() => setShowAddTarget(!showAddTarget)}
              className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors flex items-center gap-2"
              style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
            >
              <Plus size={12} /> Add Target
            </button>
            {[
              { label: 'Total',     val: allRecords.length,                                      color: 'var(--tw-text)' },
              { label: 'Unresolved',val: allRecords.filter(r => r.status === 'AWAITING_APPROVAL').length, color: 'var(--tw-critical)' },
              { label: 'Remediated',val: allRecords.filter(r => r.status === 'REMEDIATED').length, color: 'var(--tw-low)' },
            ].map(c => (
              <div key={c.label} className="text-center px-4 py-3 rounded-sm min-w-[80px]" style={tv.panelBorder}>
                <div className="font-mono text-2xl font-light" style={{ color: c.color }}>{c.val}</div>
                <div className="font-mono text-[9px] uppercase tracking-wider" style={tv.muted}>{c.label}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Threat Evidence Network */}
        <ThreatEvidenceNetwork pageType="darkweb" />

        {/* Privacy notice */}
        <div className="rounded-sm p-4 mb-6 flex items-start gap-3" style={{ ...tv.canvasMid, border: '1px solid var(--tw-border)' }}>
          <AlertTriangle size={14} className="mt-0.5 shrink-0" style={tv.medium} />
          <div className="space-y-1">
            <p className="font-mono text-[10px] tracking-widest uppercase" style={tv.medium}>Privacy Notice</p>
            <p className="text-xs leading-relaxed" style={tv.muted}>
              Monitoring is restricted to verified and authorised organisational domains only.
              Plaintext passwords are never stored, displayed, or redistributed.
            </p>
          </div>
        </div>

        {/* Add Target Form */}
        <AnimatePresence>
          {showAddTarget && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="rounded-sm overflow-hidden border mb-6"
              style={{ borderColor: 'var(--tw-border)' }}
            >
              <div className="p-5 space-y-4" style={{ backgroundColor: 'var(--tw-panel-alt)' }}>
                <div className="flex items-center justify-between">
                  <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Add Monitoring Target</p>
                  <button onClick={() => setShowAddTarget(false)} className="p-1 rounded-sm hover:bg-[var(--tw-hover)]">
                    <X size={14} style={tv.faint} />
                  </button>
                </div>
                
                <div className="grid md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Target Type</label>
                    <select
                      value={newTarget.type}
                      onChange={e => setNewTarget({ ...newTarget, type: e.target.value })}
                      className="w-full font-mono text-xs rounded-sm px-3 py-2 focus:outline-none"
                      style={tv.input}
                    >
                      <option value="domain">Organization Domain</option>
                      <option value="email">Corporate Email Address</option>
                      <option value="username">Username</option>
                      <option value="brand">Brand Name</option>
                      <option value="asset">Asset Identifier</option>
                    </select>
                  </div>
                  
                  <div className="space-y-2">
                    <label className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Target Value</label>
                    <input
                      type="text"
                      value={newTarget.value}
                      onChange={e => setNewTarget({ ...newTarget, value: e.target.value })}
                      placeholder="e.g., example.com or user@example.com"
                      className="w-full font-mono text-xs rounded-sm px-3 py-2 focus:outline-none placeholder:opacity-40"
                      style={tv.input}
                    />
                  </div>
                  
                  <div className="space-y-2">
                    <label className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Organization</label>
                    <input
                      type="text"
                      value={newTarget.organization}
                      onChange={e => setNewTarget({ ...newTarget, organization: e.target.value })}
                      placeholder="e.g., Asteron Institute of Technology"
                      className="w-full font-mono text-xs rounded-sm px-3 py-2 focus:outline-none placeholder:opacity-40"
                      style={tv.input}
                    />
                  </div>
                  
                  <div className="space-y-2">
                    <label className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Department</label>
                    <input
                      type="text"
                      value={newTarget.department}
                      onChange={e => setNewTarget({ ...newTarget, department: e.target.value })}
                      placeholder="e.g., Finance"
                      className="w-full font-mono text-xs rounded-sm px-3 py-2 focus:outline-none placeholder:opacity-40"
                      style={tv.input}
                    />
                  </div>
                  
                  <div className="space-y-2">
                    <label className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Monitoring Frequency</label>
                    <select
                      value={newTarget.frequency}
                      onChange={e => setNewTarget({ ...newTarget, frequency: e.target.value })}
                      className="w-full font-mono text-xs rounded-sm px-3 py-2 focus:outline-none"
                      style={tv.input}
                    >
                      <option value="hourly">Hourly</option>
                      <option value="daily">Daily</option>
                      <option value="weekly">Weekly</option>
                    </select>
                  </div>
                  
                  <div className="space-y-2">
                    <label className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Risk Sensitivity</label>
                    <select
                      value={newTarget.riskSensitivity}
                      onChange={e => setNewTarget({ ...newTarget, riskSensitivity: e.target.value })}
                      className="w-full font-mono text-xs rounded-sm px-3 py-2 focus:outline-none"
                      style={tv.input}
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                    </select>
                  </div>
                </div>
                
                <div className="flex items-center gap-2 p-3 rounded-sm border"
                  style={{ borderColor: 'color-mix(in srgb, var(--tw-medium) 35%, transparent)', backgroundColor: 'color-mix(in srgb, var(--tw-medium) 18%, transparent)' }}
                >
                  <Shield size={12} style={tv.medium} />
                  <p className="text-xs" style={tv.muted}>
                    Monitoring is restricted to verified and authorised organisational assets only.
                    Mask email addresses and hash sensitive identifiers where possible.
                  </p>
                </div>
                
                <div className="flex gap-2">
                  <button
                    onClick={handleAddTarget}
                    disabled={checkingNewTarget || !newTarget.value.trim()}
                    className="flex-1 font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm transition-colors disabled:opacity-40"
                    style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
                  >
                    {checkingNewTarget ? 'Checking…' : 'Add & Check Exposure'}
                  </button>
                  <button
                    onClick={() => setShowAddTarget(false)}
                    className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                    style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
                  >
                    Cancel
                  </button>
                </div>
                
                {newTargetResult && (
                  <div className={`rounded-sm p-4 border ${
                    newTargetResult.found 
                      ? 'border-[color-mix(in_srgb,var(--tw-critical),transparent)]' 
                      : 'border-[color-mix(in_srgb,var(--tw-low),transparent)]'
                  }`} style={{
                    backgroundColor: newTargetResult.found 
                      ? 'color-mix(in srgb, var(--tw-critical) 18%, transparent)' 
                      : 'color-mix(in srgb, var(--tw-low) 18%, transparent)'
                  }}>
                    <div className="flex items-start gap-2">
                      {newTargetResult.found ? (
                        <AlertTriangle size={14} className="mt-0.5 shrink-0" style={{ color: 'var(--tw-critical)' }} />
                      ) : (
                        <CheckCircle size={14} className="mt-0.5 shrink-0" style={{ color: 'var(--tw-low)' }} />
                      )}
                      <p className="text-xs leading-relaxed" style={tv.text}>{newTargetResult.message}</p>
                    </div>
                  </div>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        <div className="grid lg:grid-cols-5 rounded-sm overflow-hidden" style={tv.panelBorder}>
          {/* Record list */}
          <div className="lg:col-span-2 border-r overflow-y-auto max-h-[70vh]"
            style={{ borderColor: 'var(--tw-border-mid)' }}
          >
            <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Exposure Records</p>
            </div>
            {allRecords.map(record => (
              <ExposureRecord key={record.id} record={record}
                selected={selectedRecord.id === record.id}
                onSelect={() => setSelectedRecord(record)}
              />
            ))}
          </div>
          {/* Detail */}
          <div className="lg:col-span-3 p-6 overflow-y-auto max-h-[70vh]">
            <ExposureDetail record={selectedRecord} />
          </div>
        </div>
      </div>
    </div>
  );
}
