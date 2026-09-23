import { useState, useEffect, useCallback } from 'react';
import { Shield, Lock, Bell, Database, Users, Eye, CheckCircle } from 'lucide-react';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { currentAnalyst } from '../../data/mockData';
import { tv } from '../../lib/styles';
import clsx from 'clsx';

const STORAGE_KEY = 'tracewall-settings';

interface SettingsState {
  profile: { displayName: string; role: string; shift: string };
  privacy: { autoMask: boolean; redactBodies: boolean; hashedMatching: boolean; restrictExport: boolean; consentRecords: boolean };
  security: { mfa: boolean; auditEvidenceViews: boolean; dualApproval: boolean; rateLimiting: boolean; sessionTimeout: string };
  notifications: { highRiskAlerts: boolean; exposureAlerts: boolean; campaignAlerts: boolean; approvalRequests: boolean; caseAssignment: boolean; dailyBriefing: boolean };
  retention: { emailArtifacts: string; closedCases: string; exposureRecords: string; auditLogs: string; draftReports: string };
  org: { orgName: string };
}

function loadSettings(): SettingsState {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      return { ...defaultSettings, ...parsed };
    }
  } catch { /* ignore */ }
  return structuredClone(defaultSettings);
}

function saveSettings(s: SettingsState) {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(s)); } catch { /* ignore */ }
}

const defaultSettings: SettingsState = {
  profile: { displayName: currentAnalyst.name, role: 'Senior Investigator', shift: currentAnalyst.shift },
  privacy: { autoMask: true, redactBodies: false, hashedMatching: true, restrictExport: true, consentRecords: true },
  security: { mfa: true, auditEvidenceViews: true, dualApproval: true, rateLimiting: true, sessionTimeout: '1 hour' },
  notifications: { highRiskAlerts: true, exposureAlerts: true, campaignAlerts: true, approvalRequests: true, caseAssignment: false, dailyBriefing: false },
  retention: { emailArtifacts: '90 days', closedCases: '1 year', exposureRecords: '6 months', auditLogs: 'Permanent', draftReports: '30 days' },
  org: { orgName: currentAnalyst.organization },
};

const sections = [
  { id: 'profile',       label: 'Profile & Role',    icon: Users },
  { id: 'privacy',       label: 'Privacy & Data',    icon: Eye },
  { id: 'security',      label: 'Security',          icon: Lock },
  { id: 'notifications', label: 'Notifications',     icon: Bell },
  { id: 'retention',     label: 'Data Retention',    icon: Database },
  { id: 'org',           label: 'Organisation',      icon: Shield },
];

function SettingRow({ label, description, children }: { label: string; description?: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-6 py-4 border-b last:border-0" style={{ borderColor: 'var(--tw-border-mid)' }}>
      <div className="space-y-0.5 max-w-xs">
        <p className="text-sm font-medium" style={tv.text}>{label}</p>
        {description && <p className="text-xs leading-relaxed" style={tv.muted}>{description}</p>}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button role="switch" aria-checked={checked} aria-label={label} onClick={() => onChange(!checked)}
      className="relative w-10 h-5 rounded-full transition-colors duration-200"
      style={{ backgroundColor: checked ? 'var(--tw-burgundy)' : 'var(--tw-border-strong)' }}
    >
      <span className={clsx('absolute top-0.5 w-4 h-4 bg-white rounded-full shadow-sm transition-transform duration-200',
        checked ? 'translate-x-5' : 'translate-x-0.5'
      )} />
    </button>
  );
}

function StyledInput({ value, onChange, width = 'w-48' }: { value: string; onChange: (v: string) => void; width?: string }) {
  return (
    <input value={value} onChange={e => onChange(e.target.value)}
      className={`font-mono text-xs rounded-sm px-3 py-2 focus:outline-none ${width}`}
      style={tv.input}
    />
  );
}

function StyledSelect({ value, onChange, children }: { value: string; onChange: (v: string) => void; children: React.ReactNode }) {
  return (
    <select value={value} onChange={e => onChange(e.target.value)}
      className="font-mono text-xs rounded-sm px-3 py-2 focus:outline-none"
      style={tv.input}
    >
      {children}
    </select>
  );
}

export default function SettingsPage() {
  const [activeSection, setActiveSection] = useState('profile');
  const [settings, setSettings] = useState<SettingsState>(() => loadSettings());
  const [unsaved, setUnsaved] = useState(false);
  const [saved, setSaved] = useState(false);

  const updateField = useCallback(<S extends keyof SettingsState>(section: S, key: keyof SettingsState[S], value: SettingsState[S][keyof SettingsState[S]]) => {
    setSettings(prev => {
      const next = { ...prev, [section]: { ...prev[section], [key]: value } };
      saveSettings(next);
      return next;
    });
    setUnsaved(true);
    setSaved(false);
  }, []);

  const handleSave = useCallback(() => {
    saveSettings(settings);
    setUnsaved(false);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }, [settings]);

  const handleDiscard = useCallback(() => {
    setSettings(loadSettings());
    setUnsaved(false);
  }, []);

  useEffect(() => {
    const handler = (e: Event) => {
      if (unsaved) { e.preventDefault(); (e as BeforeUnloadEvent).returnValue = ''; }
    };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  }, [unsaved]);

  const s = settings;

  return (
    <div className="min-h-screen" style={tv.canvas}>
      <div className="max-w-5xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Settings</p>
            <DemoLabel />
          </div>
          {unsaved && (
            <span className="font-mono text-[10px] px-2 py-1 rounded-sm border"
              style={{ color: 'var(--tw-medium)', borderColor: 'color-mix(in srgb, var(--tw-medium) 40%, transparent)', backgroundColor: 'color-mix(in srgb, var(--tw-medium) 15%, transparent)' }}
            >
              Unsaved changes
            </span>
          )}
          {saved && (
            <span className="font-mono text-[10px] px-2 py-1 rounded-sm border flex items-center gap-1"
              style={{ color: 'var(--tw-low)', borderColor: 'color-mix(in srgb, var(--tw-low) 40%, transparent)', backgroundColor: 'color-mix(in srgb, var(--tw-low) 15%, transparent)' }}
            >
              <CheckCircle size={10} /> Saved
            </span>
          )}
        </div>
        <h1 className="font-serif text-3xl" style={tv.text}>Platform Settings</h1>

        <div className="grid lg:grid-cols-4 rounded-sm overflow-hidden" style={tv.panelBorder}>
          <div className="lg:col-span-1 border-r" style={{ borderColor: 'var(--tw-border-mid)' }}>
            {sections.map(s2 => {
              const Icon = s2.icon;
              const active = activeSection === s2.id;
              return (
                <button key={s2.id} onClick={() => setActiveSection(s2.id)}
                  className="w-full flex items-center gap-3 px-4 py-3.5 text-left border-b border-l-2 transition-colors"
                  style={{
                    borderBottomColor: 'var(--tw-border-mid)',
                    borderLeftColor: active ? 'var(--tw-burgundy)' : 'transparent',
                    backgroundColor: active ? 'var(--tw-panel-alt)' : 'transparent',
                    color: active ? 'var(--tw-burgundy)' : 'var(--tw-text-muted)',
                  }}
                  onMouseEnter={e => { if (!active) e.currentTarget.style.backgroundColor = 'var(--tw-hover)'; }}
                  onMouseLeave={e => { if (!active) e.currentTarget.style.backgroundColor = ''; }}
                >
                  <Icon size={14} />
                  <span className="font-mono text-xs">{s2.label}</span>
                </button>
              );
            })}
          </div>

          <div className="lg:col-span-3 p-6">
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase mb-4" style={tv.muted}>
              {sections.find(s2 => s2.id === activeSection)?.label}
            </p>

            {activeSection === 'profile' && (
              <div>
                <SettingRow label="Display Name" description="Your name shown in case files and reports">
                  <StyledInput value={s.profile.displayName} onChange={v => updateField('profile', 'displayName', v)} />
                </SettingRow>
                <SettingRow label="Role" description="Your assigned platform role">
                  <StyledSelect value={s.profile.role} onChange={v => updateField('profile', 'role', v)}>
                    {['Senior Investigator', 'Analyst', 'Viewer', 'Auditor', 'Administrator'].map(r => <option key={r}>{r}</option>)}
                  </StyledSelect>
                </SettingRow>
                <SettingRow label="Organisation" description="Organisation scope for all investigations">
                  <span className="font-mono text-xs px-3 py-2 rounded-sm" style={{ backgroundColor: 'var(--tw-panel-alt)', color: 'var(--tw-text-muted)' }}>
                    {currentAnalyst.organization}
                  </span>
                </SettingRow>
                <SettingRow label="Shift" description="Your current working shift">
                  <StyledInput value={s.profile.shift} onChange={v => updateField('profile', 'shift', v)} width="w-56" />
                </SettingRow>
              </div>
            )}

            {activeSection === 'privacy' && (
              <div>
                {[
                  { key: 'autoMask' as const, label: 'Auto-mask email addresses', desc: 'Mask sender addresses in evidence panels by default', val: s.privacy.autoMask },
                  { key: 'redactBodies' as const, label: 'Redact message bodies', desc: 'Redact email body in reports and exports by default', val: s.privacy.redactBodies },
                  { key: 'hashedMatching' as const, label: 'Privacy-preserving exposure matching', desc: 'Use hashed matching — plaintext is never stored', val: s.privacy.hashedMatching },
                  { key: 'restrictExport' as const, label: 'Restrict evidence export', desc: 'Require manager approval before exporting case evidence', val: s.privacy.restrictExport },
                  { key: 'consentRecords' as const, label: 'Consent records', desc: 'Log analyst acknowledgment of authorised-use notice', val: s.privacy.consentRecords },
                ].map(n => (
                  <SettingRow key={n.key} label={n.label} description={n.desc}>
                    <Toggle checked={n.val} onChange={v => updateField('privacy', n.key, v)} label={n.label} />
                  </SettingRow>
                ))}
              </div>
            )}

            {activeSection === 'security' && (
              <div>
                {[
                  { key: 'mfa' as const, label: 'Multi-factor authentication', desc: 'Require MFA for all analyst sign-ins', val: s.security.mfa },
                  { key: 'auditEvidenceViews' as const, label: 'Audit all evidence views', desc: 'Log every access to exposure records', val: s.security.auditEvidenceViews },
                  { key: 'dualApproval' as const, label: 'Dual-approval for critical', desc: 'Require second approval for blocks and resets', val: s.security.dualApproval },
                  { key: 'rateLimiting' as const, label: 'Rate limiting', desc: 'Limit analysis submissions to prevent abuse', val: s.security.rateLimiting },
                ].map(n => (
                  <SettingRow key={n.key} label={n.label} description={n.desc}>
                    <Toggle checked={n.val} onChange={v => updateField('security', n.key, v)} label={n.label} />
                  </SettingRow>
                ))}
                <SettingRow label="Session timeout" description="Auto logout after inactivity">
                  <StyledSelect value={s.security.sessionTimeout} onChange={v => updateField('security', 'sessionTimeout', v)}>
                    {['30 minutes', '1 hour', '4 hours', '8 hours'].map(o => <option key={o}>{o}</option>)}
                  </StyledSelect>
                </SettingRow>
                <SettingRow label="Change password" description="Update your account password">
                  <button className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                    style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
                  >
                    Change Password
                  </button>
                </SettingRow>
              </div>
            )}

            {activeSection === 'notifications' && (
              <div>
                {[
                  { key: 'highRiskAlerts' as const, label: 'High-risk email alerts', desc: 'Notify when an email scores above 75', val: s.notifications.highRiskAlerts },
                  { key: 'exposureAlerts' as const, label: 'Credential exposure alerts', desc: 'Notify immediately on new exposure records', val: s.notifications.exposureAlerts },
                  { key: 'campaignAlerts' as const, label: 'Campaign correlation alerts', desc: 'Notify on new campaign cluster identification', val: s.notifications.campaignAlerts },
                  { key: 'approvalRequests' as const, label: 'Approval requests', desc: 'Notify when an action awaits your approval', val: s.notifications.approvalRequests },
                  { key: 'caseAssignment' as const, label: 'Case assignment', desc: 'Notify when a case is assigned to you', val: s.notifications.caseAssignment },
                  { key: 'dailyBriefing' as const, label: 'Daily briefing summary', desc: 'Send morning briefing email', val: s.notifications.dailyBriefing },
                ].map(n => (
                  <SettingRow key={n.key} label={n.label} description={n.desc}>
                    <Toggle checked={n.val} onChange={v => updateField('notifications', n.key, v)} label={n.label} />
                  </SettingRow>
                ))}
              </div>
            )}

            {activeSection === 'retention' && (
              <div>
                <div className="p-4 rounded-sm mb-4 flex items-start gap-2" style={{ backgroundColor: 'var(--tw-panel-alt)', border: '1px solid var(--tw-border)' }}>
                  <Shield size={13} className="mt-0.5 shrink-0" style={tv.medium} />
                  <p className="text-xs leading-relaxed" style={tv.muted}>
                    Audit logs are never automatically purged. All other artefacts follow the configured retention period.
                  </p>
                </div>
                {[
                  { key: 'emailArtifacts' as const, def: s.retention.emailArtifacts },
                  { key: 'closedCases' as const, def: s.retention.closedCases },
                  { key: 'exposureRecords' as const, def: s.retention.exposureRecords },
                  { key: 'auditLogs' as const, def: s.retention.auditLogs },
                  { key: 'draftReports' as const, def: s.retention.draftReports },
                ].map(r => (
                  <SettingRow key={r.key} label={r.key.replace(/([A-Z])/g, ' $1').replace(/^./, c => c.toUpperCase())}>
                    <StyledSelect value={s.retention[r.key]} onChange={v => updateField('retention', r.key, v)}>
                      {['30 days', '60 days', '90 days', '6 months', '1 year', 'Permanent'].map(o => <option key={o}>{o}</option>)}
                    </StyledSelect>
                  </SettingRow>
                ))}
              </div>
            )}

            {activeSection === 'org' && (
              <div>
                <SettingRow label="Organisation name" description="Display name for this tenant">
                  <StyledInput value={s.org.orgName} onChange={v => updateField('org', 'orgName', v)} width="w-56" />
                </SettingRow>
                <SettingRow label="Monitored domains" description="Domains authorised for exposure monitoring">
                  <div className="space-y-1.5">
                    {['secureops.in', 'secureops.com'].map(d => (
                      <span key={d} className="font-mono text-xs px-2 py-0.5 rounded-sm block"
                        style={{ backgroundColor: 'var(--tw-panel-alt)', color: 'var(--tw-text)' }}
                      >
                        {d}
                      </span>
                    ))}
                    <button className="font-mono text-[10px]" style={tv.burg}>+ Add domain</button>
                  </div>
                </SettingRow>
                <SettingRow label="Integrations" description="Connected security infrastructure">
                  <div className="space-y-1">
                    {[
                      { label: 'SIEM',              status: 'Integration Unavailable' },
                      { label: 'Identity Provider', status: 'Integration Unavailable' },
                      { label: 'SOAR',              status: 'Integration Unavailable' },
                      { label: 'Threat Feed',       status: 'Demo Mode' },
                    ].map(i => (
                      <div key={i.label} className="flex items-center gap-3">
                        <span className="font-mono text-[10px] w-28" style={tv.muted}>{i.label}</span>
                        <span className="font-mono text-[10px] px-2 py-0.5 rounded-sm"
                          style={{ backgroundColor: 'var(--tw-panel-alt)', color: 'var(--tw-text-faint)' }}
                        >
                          {i.status}
                        </span>
                      </div>
                    ))}
                  </div>
                </SettingRow>
              </div>
            )}

            <div className="flex gap-3 mt-6 pt-4 border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <button onClick={handleSave}
                className="font-mono text-xs tracking-widest uppercase px-5 py-2 rounded-sm transition-colors"
                style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
              >
                Save Changes
              </button>
              <button onClick={handleDiscard}
                className="font-mono text-xs tracking-widest uppercase px-5 py-2 rounded-sm border transition-colors"
                style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
              >
                Discard
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
