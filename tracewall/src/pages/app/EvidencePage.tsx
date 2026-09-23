import { relayHops, demoEmail, domainIntel, riskScoreBreakdown, asteronEmails, currentAnalyst } from '../../data/mockData';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { EvidenceStamp } from '../../components/ui/EvidenceStamp';
import { Copy, ShieldCheck, FileCheck, Eye, ExternalLink } from 'lucide-react';
import { tv, hoverHandlers } from '../../lib/styles';
import { useState, useEffect, useCallback, useMemo } from 'react';
import { Link } from 'react-router-dom';

const EVIDENCE_ACCESS_LOG = 'tracewall-evidence-access';

function logEvidenceAccess(item: { id: string; label: string; hash?: string }) {
  try {
    const raw = localStorage.getItem(EVIDENCE_ACCESS_LOG);
    const entries: Array<{ id: string; label: string; hash?: string; time: string; actor: string }> = raw ? JSON.parse(raw) : [];
    entries.unshift({ id: item.id, label: item.label, hash: item.hash, time: new Date().toISOString(), actor: currentAnalyst.name });
    localStorage.setItem(EVIDENCE_ACCESS_LOG, JSON.stringify(entries.slice(0, 500)));
  } catch { /* ignore */ }
}

function loadEvidenceAccessLog() {
  try {
    const raw = localStorage.getItem(EVIDENCE_ACCESS_LOG);
    return raw ? JSON.parse(raw) : [];
  } catch { return []; }
}

function computeSha256(text: string): Promise<string> {
  const encoder = new TextEncoder();
  return crypto.subtle.digest('SHA-256', encoder.encode(text)).then(buf => {
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  });
}

type EvidenceOrigin = 'Original' | 'Derived';

interface EvidenceItem {
  id: string;
  label: string;
  classification: string;
  origin: EvidenceOrigin;
  hash?: string;
  integrityStatus: 'Verified' | 'Pending' | 'Warning';
  uploadedBy: string;
  uploadedAt: string;
  relatedCase?: string;
  notes: string[];
  custodyTimeline: Array<{ time: string; actor: string; event: string }>;
  previewEmailId?: string;
}

function buildAsteronEvidence(): EvidenceItem[] {
  return [
    {
      id: 'ASTR-EVIDENCE-001',
      label: 'ASTR-EMAIL-001 · Vendor Payment Instructions',
      classification: 'Business Email Compromise',
      origin: 'Original',
      hash: 'b3f8a1c2d9e4f7a0b3c6d9e2f5a8b1c4d7e0f3a6b9c2d5e8f1a4b7c0d3e6f9a2',
      integrityStatus: 'Verified',
      uploadedBy: 'Demo Analyst',
      uploadedAt: '2026-08-28T14:30:21Z',
      relatedCase: 'CASE-2026-0142',
      notes: ['Critical severity. SPF/DKIM/DMARC all pass — consistent with compromised internal account.'],
      custodyTimeline: [
        { time: '2026-08-28T14:30:21Z', actor: 'System', event: 'Artifact ingested and classified as BEC' },
        { time: '2026-08-28T15:00:00Z', actor: 'Demo Analyst', event: 'Linked to CASE-2026-0142' },
        { time: '2026-09-01T08:45:00Z', actor: 'System', event: 'Correlated into campaign CMP-1024' },
      ],
      previewEmailId: 'ASTR-EMAIL-001',
    },
    {
      id: 'ASTR-EVIDENCE-002',
      label: 'ASTR-EMAIL-002 · Account Verification Phishing',
      classification: 'Credential Harvesting',
      origin: 'Original',
      hash: 'c4g9b2d3e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
      integrityStatus: 'Verified',
      uploadedBy: 'Demo Analyst',
      uploadedAt: '2026-09-01T08:22:15Z',
      relatedCase: 'CASE-2026-0142',
      notes: ['SPF FAIL, DKIM NONE, DMARC FAIL. Strong indicator of spoofed sender.'],
      custodyTimeline: [
        { time: '2026-09-01T08:22:15Z', actor: 'System', event: 'Artifact ingested — credential harvesting indicators detected' },
        { time: '2026-09-01T09:00:00Z', actor: 'Demo Analyst', event: 'Linked to CASE-2026-0142' },
      ],
      previewEmailId: 'ASTR-EMAIL-002',
    },
    {
      id: 'ASTR-EVIDENCE-003',
      label: 'ASTR-EMAIL-003 · Macro-Enabled Salary Document',
      classification: 'Suspicious Attachment',
      origin: 'Original',
      hash: 'e9a3f7c2d1b44e6855ab291c0f8e3d17492c1b8f5a2e0d9c6b4f3a7e8d1c059',
      integrityStatus: 'Verified',
      uploadedBy: 'Demo Analyst',
      uploadedAt: '2026-09-05T11:30:45Z',
      relatedCase: 'CASE-2026-0142',
      notes: ['Macro-enabled DOCM. Hash matches prior delivery template. Sandbox: SUSPICIOUS.'],
      custodyTimeline: [
        { time: '2026-09-05T11:30:45Z', actor: 'System', event: 'Attachment flagged — macro present' },
        { time: '2026-09-05T12:00:00Z', actor: 'Demo Analyst', event: 'Submitted for sandbox analysis' },
      ],
      previewEmailId: 'ASTR-EMAIL-003',
    },
    {
      id: 'ASTR-EVIDENCE-004',
      label: 'ASTR-EMAIL-004 · Executive Document Review Invitation',
      classification: 'Executive Impersonation',
      origin: 'Original',
      hash: 'f0a4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4',
      integrityStatus: 'Verified',
      uploadedBy: 'Demo Analyst',
      uploadedAt: '2026-09-08T17:15:22Z',
      relatedCase: 'CASE-2026-0142',
      notes: ['DKIM FAIL, SPF NEUTRAL, DMARC FAIL. Display-name spoofing confirmed.'],
      custodyTimeline: [
        { time: '2026-09-08T17:15:22Z', actor: 'System', event: 'Artifact ingested — executive impersonation indicators' },
        { time: '2026-09-08T18:00:00Z', actor: 'Demo Analyst', event: 'Linked to CASE-2026-0142 · Containment submitted' },
      ],
      previewEmailId: 'ASTR-EMAIL-004',
    },
    {
      id: 'ASTR-EVIDENCE-005',
      label: 'CMP-1024 · Operation Invoice Diversion Cluster',
      classification: 'Campaign Correlation',
      origin: 'Derived',
      hash: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
      integrityStatus: 'Verified',
      uploadedBy: 'System',
      uploadedAt: '2026-09-08T18:00:00Z',
      relatedCase: 'CASE-2026-0142',
      notes: ['AI-correlated campaign linking all four Asteron emails. Confidence: 91%.'],
      custodyTimeline: [
        { time: '2026-09-08T18:00:00Z', actor: 'System', event: 'Campaign generated from email correlation engine' },
      ],
    },
    {
      id: 'ASTR-EVIDENCE-006',
      label: 'EXP-ASTR-001 · a••••@asteron.example Credential Pair',
      classification: 'Credential Exposure',
      origin: 'Derived',
      hash: 'd7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8',
      integrityStatus: 'Pending',
      uploadedBy: 'System',
      uploadedAt: '2026-08-28T15:00:00Z',
      relatedCase: 'CASE-2026-0142',
      notes: ['Credential-pair indicator from simulated breach-monitoring feed. Plaintext secret redacted per privacy policy.'],
      custodyTimeline: [
        { time: '2026-08-28T15:00:00Z', actor: 'System', event: 'Dark-web monitor detected exposure' },
        { time: '2026-08-29T09:15:00Z', actor: 'Demo Analyst', event: 'Linked to CASE-2026-0142' },
      ],
    },
  ];
}

function EvidenceRow({ label, value, hash }: { label: string; value: string; hash?: string }) {
  return (
    <div className="flex items-start gap-4 px-5 py-3 border-b last:border-0 transition-colors group"
      style={{ borderColor: 'var(--tw-border-mid)' }}
      {...hoverHandlers()}
    >
      <div className="w-36 shrink-0">
        <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>{label}</p>
      </div>
      <div className="flex-1 min-w-0">
        <p className="font-mono text-xs break-all" style={tv.text}>{value}</p>
        {hash && <p className="font-mono text-[10px] mt-0.5 truncate" style={tv.faint}>SHA-256: {hash}</p>}
      </div>
      <button
        onClick={() => navigator.clipboard?.writeText(value)}
        className="shrink-0 opacity-0 group-hover:opacity-100 transition-opacity"
      >
        <Copy size={11} style={tv.muted} />
      </button>
    </div>
  );
}

function Card({ title, children, footer, origin }: { title: string; children: React.ReactNode; footer?: React.ReactNode; origin?: EvidenceOrigin }) {
  return (
    <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
      <div className="px-5 py-3 border-b flex items-center justify-between" style={{ borderColor: 'var(--tw-border-mid)' }}>
        <div className="flex items-center gap-2">
          <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>{title}</p>
          {origin && (
            <span className="font-mono text-[9px] px-1.5 py-0.5 rounded-sm border"
              style={{
                color: origin === 'Original' ? 'var(--tw-low)' : 'var(--tw-brass)',
                borderColor: `color-mix(in srgb, ${origin === 'Original' ? 'var(--tw-low)' : 'var(--tw-brass)'} 35%, transparent)`,
                backgroundColor: `color-mix(in srgb, ${origin === 'Original' ? 'var(--tw-low)' : 'var(--tw-brass)'} 10%, transparent)`,
              }}
            >
              {origin}
            </span>
          )}
        </div>
      </div>
      {children}
      {footer && (
        <div className="px-5 py-3 border-t" style={{ borderColor: 'var(--tw-border-mid)', backgroundColor: 'var(--tw-canvas-mid)' }}>
          {footer}
        </div>
      )}
    </div>
  );
}

function CustodyTimeline({ events }: { events: Array<{ time: string; actor: string; event: string }> }) {
  if (events.length === 0) return null;
  return (
    <div className="px-5 py-4 space-y-0">
      <p className="font-mono text-[10px] tracking-[0.2em] uppercase mb-3" style={tv.muted}>Chain of Custody</p>
      {events.map((ev, i) => (
        <div key={i} className="flex gap-3">
          <div className="flex flex-col items-center shrink-0">
            <div className="w-1.5 h-1.5 rounded-full mt-1" style={{ backgroundColor: 'var(--tw-burgundy)' }} />
            {i < events.length - 1 && <div className="w-px h-full mt-1" style={{ backgroundColor: 'var(--tw-border-mid)' }} />}
          </div>
          <div className="pb-3">
            <p className="font-mono text-[10px]" style={tv.faint}>{new Date(ev.time).toLocaleString()}</p>
            <p className="text-xs" style={tv.text}>{ev.event}</p>
            <p className="font-mono text-[9px]" style={tv.muted}>{ev.actor}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

export default function EvidencePage() {
  const [accessLog, setAccessLog] = useState(loadEvidenceAccessLog);
  const [verifyTarget, setVerifyTarget] = useState('');
  const [verifyResult, setVerifyResult] = useState<string | null>(null);
  const [verifyLoading, setVerifyLoading] = useState(false);
  const [previewItem, setPreviewItem] = useState<EvidenceItem | null>(null);
  const [previewEmailId, setPreviewEmailId] = useState<string | null>(null);
  const asteronEvidence = useMemo(() => buildAsteronEvidence(), []);

  useEffect(() => {
    logEvidenceAccess({ id: 'page-load', label: 'Evidence & Chain of Custody page' });
  }, []);

  const handleVerify = useCallback(async () => {
    if (!verifyTarget.trim()) return;
    setVerifyLoading(true);
    const hash = await computeSha256(verifyTarget);
    setVerifyResult(`SHA-256: ${hash}`);
    logEvidenceAccess({ id: 'verify-' + Date.now(), label: 'Hash verification: ' + verifyTarget.slice(0, 30), hash: hash.slice(0, 24) });
    setAccessLog(loadEvidenceAccessLog());
    setVerifyLoading(false);
  }, [verifyTarget]);

  const integrityColor = (status: string) => {
    switch (status) {
      case 'Verified': return 'var(--tw-low)';
      case 'Pending': return 'var(--tw-medium)';
      case 'Warning': return 'var(--tw-critical)';
      default: return 'var(--tw-dust)';
    }
  };

  const previewEmail = asteronEmails.find(e => e.id === previewEmailId);

  return (
    <div className="min-h-screen" style={tv.canvas}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-8">
        <div className="flex items-end justify-between gap-4">
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Evidence Repository</p>
              <DemoLabel />
            </div>
            <h1 className="font-serif text-3xl" style={tv.text}>Evidence & Chain of Custody</h1>
          </div>
        </div>

        {/* ═══ Demo Evidence Cards ═══ */}
        <div className="grid lg:grid-cols-2 gap-6">
          <Card title="Email Artifact" origin="Original"
            footer={
              <div className="flex items-center justify-between">
                <span className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Integrity Status</span>
                <span className="font-mono text-xs" style={tv.low}>✓ Verified</span>
              </div>
            }
          >
            <div className="flex items-center justify-between px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <span className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Classification</span>
              <span className="font-mono text-xs" style={tv.text}>Business Email Compromise</span>
            </div>
            <div className="flex items-center justify-between px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <span className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Verdict</span>
              <EvidenceStamp verdict="HIGH RISK" size="sm" />
            </div>
            <EvidenceRow label="Artifact ID" value={demoEmail.id} />
            <EvidenceRow label="Subject" value={demoEmail.subject} />
            <EvidenceRow label="From" value={demoEmail.from.address} />
            <EvidenceRow label="Reply-To" value={demoEmail.replyTo} />
            <EvidenceRow label="Message-ID" value={demoEmail.messageId} />
            <EvidenceRow label="Date" value={demoEmail.date} />
            <EvidenceRow label="SHA-256" value="a3f7c2d91b44e6805f29ac73d6e1b582...4d9a" />
            <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <p className="font-mono text-[10px] uppercase tracking-wider mb-1" style={tv.muted}>Related Case</p>
              <Link to="/app/cases/INV-2026-0041" className="font-mono text-xs hover:underline" style={tv.low}>INV-2026-0041</Link>
            </div>
            <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <p className="font-mono text-[10px] uppercase tracking-wider mb-1" style={tv.muted}>Uploaded By</p>
              <p className="font-mono text-xs" style={tv.text}>Dr. Priya Mehta · 2026-09-12 09:14 UTC</p>
            </div>
            <CustodyTimeline events={[
              { time: '2026-09-12T09:14:37Z', actor: 'System', event: 'Email artifact ingested and verified' },
              { time: '2026-09-12T09:45:00Z', actor: 'Dr. Priya Mehta', event: 'Linked to INV-2026-0041' },
            ]} />
          </Card>

          <Card title="Domain Intelligence Evidence" origin="Derived">
            <EvidenceRow label="Domain" value={domainIntel.senderDomain} />
            <EvidenceRow label="Lookalike of" value={domainIntel.legitimateDomain} />
            <EvidenceRow label="Similarity" value={`${domainIntel.similarityScore}%`} />
            <EvidenceRow label="Age" value={`${domainIntel.registeredDaysAgo} days`} />
            <EvidenceRow label="Registrar" value={domainIntel.registrar} />
            <EvidenceRow label="First Seen" value={domainIntel.firstSeen} />
            <EvidenceRow label="SPF Record" value={domainIntel.spfRecord} />
            <EvidenceRow label="DMARC Record" value={domainIntel.dmarcRecord} />
            <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <p className="font-mono text-[10px] uppercase tracking-wider mb-1" style={tv.muted}>Related Case</p>
              <Link to="/app/cases/INV-2026-0041" className="font-mono text-xs hover:underline" style={tv.low}>INV-2026-0041</Link>
            </div>
            <div className="px-5 py-3">
              <p className="font-mono text-[10px] uppercase tracking-wider mb-1" style={tv.muted}>Notes</p>
              <p className="text-xs leading-relaxed" style={tv.text}>Domain registered 11 days ago. SPF: v=spf1 include:mailing-relay-eu4.net ~all. DMARC: no policy. Homoglyph technique used.</p>
            </div>
          </Card>

          <Card title="Relay Infrastructure Evidence"
            footer={
              <p className="font-mono text-[10px]" style={tv.muted}>
                Limitation: Sender-controlled headers cannot be independently verified.
                Estimated infrastructure location — not proof of sender identity.
              </p>
            }
          >
            {relayHops.map(hop => (
              <EvidenceRow
                key={hop.num}
                label={`Hop ${hop.num} · ${hop.reliability}`}
                value={`${hop.ip} · ${hop.hostname} · ${hop.countryName}`}
              />
            ))}
            <div className="px-5 py-3">
              <p className="font-mono text-[10px] uppercase tracking-wider mb-1" style={tv.muted}>Related Case</p>
              <Link to="/app/cases/INV-2026-0041" className="font-mono text-xs hover:underline" style={tv.low}>INV-2026-0041</Link>
            </div>
          </Card>

          <Card title="Risk Score Evidence"
            footer={<p className="font-mono text-[10px]" style={tv.muted}>{riskScoreBreakdown.disclaimer}</p>}
          >
            <EvidenceRow label="Total Score" value={`${riskScoreBreakdown.total}/100`} />
            <EvidenceRow label="Verdict" value={riskScoreBreakdown.verdict} />
            <EvidenceRow label="Confidence" value={riskScoreBreakdown.confidence} />
            {riskScoreBreakdown.factors.map((f, i) => (
              <EvidenceRow key={i} label={`Factor ${i + 1}`} value={`${f.label} +${f.contribution} (${f.category})`} />
            ))}
            <div className="px-5 py-3">
              <p className="font-mono text-[10px] uppercase tracking-wider mb-1" style={tv.muted}>Related Case</p>
              <Link to="/app/cases/INV-2026-0041" className="font-mono text-xs hover:underline" style={tv.low}>INV-2026-0041</Link>
            </div>
          </Card>
        </div>

        {/* ═══ Asteron Evidence ═══ */}
        <div>
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-serif text-xl" style={tv.text}>Asteron Institute of Technology — Evidence</h2>
            <span className="font-mono text-[10px]" style={tv.muted}>{asteronEvidence.length} artifacts</span>
          </div>
          <div className="grid lg:grid-cols-2 gap-6">
            {asteronEvidence.map(item => (
              <Card key={item.id} title={item.label} origin={item.origin}
                footer={
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Integrity</span>
                    <span className="font-mono text-xs" style={{ color: integrityColor(item.integrityStatus) }}>
                      {item.integrityStatus === 'Verified' ? '✓ Verified' : item.integrityStatus === 'Pending' ? '⏳ Pending' : '⚠ Warning'}
                    </span>
                  </div>
                }
              >
                <div className="flex items-center justify-between px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <span className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Classification</span>
                  <span className="font-mono text-xs" style={tv.text}>{item.classification}</span>
                </div>
                <EvidenceRow label="Artifact ID" value={item.id} hash={item.hash?.slice(0, 40)} />
                <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <p className="font-mono text-[10px] uppercase tracking-wider mb-1" style={tv.muted}>Related Case</p>
                  <Link to={item.relatedCase ? `/app/cases/${item.relatedCase}` : '/app/cases'} className="font-mono text-xs hover:underline" style={tv.low}>
                    {item.relatedCase || 'None'}
                  </Link>
                </div>
                <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <p className="font-mono text-[10px] uppercase tracking-wider mb-1" style={tv.muted}>Uploaded By</p>
                  <p className="font-mono text-xs" style={tv.text}>
                    {item.uploadedBy} · {new Date(item.uploadedAt).toLocaleString()}
                  </p>
                </div>
                <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <p className="font-mono text-[10px] uppercase tracking-wider mb-1" style={tv.muted}>Notes</p>
                  {item.notes.map((n, i) => (
                    <p key={i} className="text-xs leading-relaxed" style={tv.text}>{n}</p>
                  ))}
                </div>
                <div className="flex items-center gap-2 px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <button onClick={() => { setPreviewItem(item); setPreviewEmailId(item.previewEmailId ?? null); }}
                    className="font-mono text-[10px] tracking-widest uppercase px-3 py-1.5 rounded-sm border"
                    style={{
                      borderColor: 'var(--tw-border-strong)',
                      color: 'var(--tw-text)',
                      backgroundColor: 'var(--tw-panel-alt)',
                    }}
                    {...hoverHandlers()}
                  >
                    <Eye size={10} className="inline mr-1" /> Preview
                  </button>
                </div>
                <CustodyTimeline events={item.custodyTimeline} />
              </Card>
            ))}
          </div>
        </div>

        {/* ═══ SHA-256 Hash Verifier ═══ */}
        <div className="grid lg:grid-cols-2 gap-6">
          <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
            <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>SHA-256 Hash Verifier</p>
            </div>
            <div className="p-5 space-y-3">
              <div className="flex gap-2">
                <input
                  value={verifyTarget}
                  onChange={e => { setVerifyTarget(e.target.value); setVerifyResult(null); }}
                  placeholder="Enter text to hash…"
                  className="flex-1 font-mono text-xs rounded-sm px-3 py-2 focus:outline-none placeholder:opacity-40"
                  style={tv.input}
                />
                <button
                  onClick={handleVerify}
                  disabled={!verifyTarget.trim() || verifyLoading}
                  className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm transition-colors disabled:opacity-40"
                  style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
                >
                  {verifyLoading ? '…' : 'Verify'}
                </button>
              </div>
              {verifyResult && (
                <div className="p-3 rounded-sm flex items-start gap-2"
                  style={{ backgroundColor: 'var(--tw-panel-alt)', border: '1px solid var(--tw-border)' }}
                >
                  <ShieldCheck size={13} className="mt-0.5 shrink-0" style={tv.low} />
                  <p className="font-mono text-[10px] break-all" style={tv.text}>{verifyResult}</p>
                </div>
              )}
              <p className="font-mono text-[10px]" style={tv.muted}>
                Verifies data integrity using Web Crypto API (SHA-256). Compare with stored hashes to detect tampering.
              </p>
            </div>
          </div>

          <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
            <div className="px-5 py-3 border-b flex items-center justify-between" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Evidence Access Log</p>
              <span className="font-mono text-[10px]" style={tv.faint}>{accessLog.length} entries</span>
            </div>
            <div className="max-h-80 overflow-y-auto">
              {accessLog.length === 0 ? (
                <div className="p-6 text-center">
                  <p className="font-mono text-xs" style={tv.muted}>No access recorded yet.</p>
                </div>
              ) : (
                accessLog.map((entry: any, i: number) => (
                  <div key={i} className="flex items-start gap-3 px-5 py-3 border-b transition-colors"
                    style={{ borderColor: 'var(--tw-border-mid)' }}
                    {...hoverHandlers()}
                  >
                    <FileCheck size={11} className="mt-0.5 shrink-0" style={tv.faint} />
                    <div className="flex-1 min-w-0">
                      <p className="font-mono text-xs truncate" style={tv.text}>{entry.label}</p>
                      <p className="font-mono text-[10px]" style={tv.muted}>
                        {entry.actor} · {new Date(entry.time).toLocaleString()}
                      </p>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ═══ Preview Modal ═══ */}
      {previewItem && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ backgroundColor: 'rgba(0,0,0,0.6)' }}
          onClick={() => { setPreviewItem(null); setPreviewEmailId(null); }}
        >
          <div className="rounded-sm p-6 max-w-2xl w-full space-y-4 max-h-[80vh] overflow-y-auto"
            style={{ backgroundColor: 'var(--tw-panel)', border: '1px solid var(--tw-border)' }}
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between">
              <h3 className="font-serif text-lg" style={tv.text}>Preview: {previewItem.label}</h3>
              <button onClick={() => { setPreviewItem(null); setPreviewEmailId(null); }}
                className="font-mono text-xs px-3 py-1 rounded-sm"
                style={{ color: 'var(--tw-muted)', border: '1px solid var(--tw-border)' }}
              >
                Close
              </button>
            </div>
            {previewEmail && previewItem.id.startsWith('ASTR-EVIDENCE') && (
              <div className="space-y-2">
                <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Email Preview</p>
                <div className="rounded-sm p-4 space-y-1.5" style={tv.panelBorder}>
                  <p className="font-mono text-xs" style={tv.text}><span style={tv.muted}>From:</span> {previewEmail.from.display}</p>
                  <p className="font-mono text-xs" style={tv.text}><span style={tv.muted}>To:</span> {previewEmail.to}</p>
                  <p className="font-mono text-xs" style={tv.text}><span style={tv.muted}>Subject:</span> {previewEmail.subject}</p>
                  <p className="font-mono text-[10px]" style={tv.muted}>{previewEmail.date}</p>
                  <div className="evidence-rule my-2" />
                  <p className="text-xs leading-relaxed whitespace-pre-line" style={tv.text}>{previewEmail.body.slice(0, 600)}{previewEmail.body.length > 600 ? '…' : ''}</p>
                </div>
              </div>
            )}
            <div className="space-y-2">
              <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Classification & Origin</p>
              <div className="flex items-center gap-3">
                <span className="font-mono text-xs px-2 py-0.5 rounded-sm border"
                  style={{
                    color: 'var(--tw-info)',
                    borderColor: 'color-mix(in srgb, var(--tw-info) 35%, transparent)',
                    backgroundColor: 'color-mix(in srgb, var(--tw-info) 10%, transparent)',
                  }}
                >
                  {previewItem.classification}
                </span>
                <span className="font-mono text-[10px] px-2 py-0.5 rounded-sm border"
                  style={{
                    color: previewItem.origin === 'Original' ? 'var(--tw-low)' : 'var(--tw-brass)',
                    borderColor: `color-mix(in srgb, ${previewItem.origin === 'Original' ? 'var(--tw-low)' : 'var(--tw-brass)'} 35%, transparent)`,
                    backgroundColor: `color-mix(in srgb, ${previewItem.origin === 'Original' ? 'var(--tw-low)' : 'var(--tw-brass)'} 10%, transparent)`,
                  }}
                >
                  {previewItem.origin}
                </span>
              </div>
            </div>
            {previewItem.notes.length > 0 && (
              <div className="space-y-1">
                <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Analyst Notes</p>
                {previewItem.notes.map((n, i) => (
                  <p key={i} className="text-xs" style={tv.text}>{n}</p>
                ))}
              </div>
            )}
            {previewItem.relatedCase && (
              <div>
                <p className="font-mono text-[10px] uppercase tracking-wider mb-1" style={tv.muted}>Related Case</p>
                <Link to={`/app/cases/${previewItem.relatedCase}`} className="font-mono text-xs hover:underline inline-flex items-center gap-1" style={tv.low}>
                  {previewItem.relatedCase} <ExternalLink size={10} />
                </Link>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
