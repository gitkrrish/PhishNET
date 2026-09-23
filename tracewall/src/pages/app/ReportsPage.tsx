import { useState } from 'react';
import { Download, Eye, Printer, Shield, Hash, Plus, X } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { cases, campaigns, exposureRecords, asteronCases, asteronCampaign, asteronExposure } from '../../data/mockData';
import { SeverityBadge } from '../../components/ui/SeverityBadge';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { tv, hoverHandlers } from '../../lib/styles';
import { generateReport, createAuditEvent, DEMO_LABEL } from '../../lib/mockBackend';
import ThreatEvidenceNetwork from '../../components/3d/ThreatEvidenceNetwork';

interface ReportSection {
  id: string;
  title: string;
  content: string;
  evidence?: string[];
}

interface ForensicReport {
  id: string;
  caseId: string;
  title: string;
  generatedAt: string;
  generatedBy: string;
  status: 'DRAFT' | 'FINAL' | 'APPROVED';
  sections: ReportSection[];
  relatedCase?: any;
  relatedCampaign?: any;
  relatedExposure?: any;
}

const mockReports: ForensicReport[] = [
  {
    id: 'RPT-2026-0041-A',
    caseId: 'INV-2026-0041',
    title: 'Invoice-Diversion Campaign Investigation Dossier',
    generatedAt: '2026-09-13T08:15:00Z',
    generatedBy: 'Dr. Priya Mehta',
    status: 'FINAL',
    sections: [
      {
        id: 'scope',
        title: 'Scope and Authorization',
        content: 'This forensic investigation dossier documents the analysis of EMAIL-2026-0041-A and related campaign infrastructure. Analysis was conducted under SecureOps Intelligence Unit case INV-2026-0041. All evidence was collected with authorisation from the Chief Information Security Officer.',
      },
      {
        id: 'executive',
        title: 'Executive Summary',
        content: 'A coordinated invoice-diversion campaign targeting the Finance department was detected. Four related emails share lookalike sender infrastructure and identical payment-redirection language. Risk score: 87/100. Recommended actions: quarantine emails, block sender domains, verify payment instructions independently.',
      },
      {
        id: 'metadata',
        title: 'Email Metadata',
        content: 'Message-ID: <20260912.091437.FIN5591@secureops-finance.in>. From: finance@secureops-finance.in. To: accounts.payable@secureops.in. Date: 2026-09-12T09:14:37+05:30. Subject: URGENT: Updated Banking Details for Invoice #INV-5591.',
      },
      {
        id: 'verdict',
        title: 'Threat Verdict and Risk Score',
        content: 'Verdict: HIGH RISK. Risk Score: 87/100. Confidence: HIGH. Classification: Business Email Compromise. Primary indicators: Reply-To domain mismatch, newly registered lookalike domain (11 days), urgent payment language, suspicious redirect chain.',
      },
      {
        id: 'auth',
        title: 'SPF, DKIM, and DMARC Results',
        content: 'SPF: FAIL — secureops-finance.in does not authorise mailing-relay-eu4.net. DKIM: NONE — No DKIM signature present. DMARC: FAIL — Neither SPF nor DKIM alignment passed. Note: Authentication failures are strong indicators but do not conclusively prove malicious intent.',
      },
      {
        id: 'headers',
        title: 'Header and Relay Analysis',
        content: '4 relay hops identified. Origin: mail.secureops-finance.in (185.220.101.47, DE). Relay: mailing-relay-eu4.net (45.142.212.83, PL). Secondary: smtp-out.eu-mail-hub.com (91.108.56.19, NL). Recipient: mx1.secureops.in (10.0.1.4, IN). Note: Sender-controlled headers cannot be independently verified.',
      },
      {
        id: 'geo',
        title: 'Geolocation and Infrastructure Findings',
        content: 'Estimated infrastructure locations: Germany (origin), Poland (relay), Netherlands (secondary relay), India (recipient). All IP addresses appear to be cloud hosting infrastructure. Location represents hosting infrastructure, not proof of attacker physical location.',
      },
      {
        id: 'domain',
        title: 'Domain and IP Intelligence',
        content: 'Sender domain: secureops-finance.in. Legitimate domain: secureops.in. Similarity: 83%. Age: 11 days. Registrar: GoDaddy LLC. Hosting: Hosting Solutions GmbH (DE). Reputation: POOR. Related domains: secure-ops-pay.net, secureops-payments.com.',
      },
      {
        id: 'url',
        title: 'URL Findings',
        content: '2 URLs extracted. High-risk: https://secureops-finance.in/verify-payment. Shortener: https://bit.ly/3xPayConf (redirects to high-risk domain). Redirect chain detected. Domain age: 11 days.',
      },
      {
        id: 'attachment',
        title: 'Attachment Findings',
        content: '1 attachment: Invoice_INV-5591_Updated.pdf (218 KB). Hash: a3f7c2d91b44e6805f29ac73d6e1b58209c4d9afb3e1c28f7d6a4b5e0192837. Macro: None. Sandbox: CLEAN. Risk score: 12/100. Recommendation: No immediate action required.',
      },
      {
        id: 'social',
        title: 'Social Engineering Findings',
        content: 'Detected patterns: Urgency (updated effective immediately), Authority (authorised by CFO), Secrecy (do not discuss with other departments), Pressure (time-sensitive request). Confidence in BEC classification: 92%.',
      },
      {
        id: 'exposure',
        title: 'Dark-Web Exposure Findings',
        content: 'Related exposure: EXP-00481 (a••••@secureops.in). Exposure type: Credential-pair indicator. Severity: HIGH. Confidence: 94%. Status: AWAITING_APPROVAL. Plaintext secret: REDACTED per privacy policy.',
      },
      {
        id: 'campaign',
        title: 'Campaign Relationships',
        content: 'Correlated to campaign CAMP-2026-017 (Operation Ledger Shift). 4 related emails. 2 lookalike domains. 3 suspicious URLs. 2 related IPs. Targeted departments: Finance, Accounts Payable. Campaign confidence: 88%.',
      },
      {
        id: 'iocs',
        title: 'Indicators of Compromise',
        content: 'Domains: secureops-finance.in, secure-ops-pay.net, secureops-payments.com. IPs: 185.220.101.47, 45.142.212.83. URLs: secureops-finance.in/verify-payment, bit.ly/3xPayConf. Email: finance@secureops-finance.in. File hash: a3f7c2d91b44e6805f29ac73d6e1b58209c4d9afb3e1c28f7d6a4b5e0192837.',
      },
      {
        id: 'actions',
        title: 'Recommended Actions',
        content: '1. Quarantine related emails (4). 2. Block sender domains at mail gateway. 3. Alert Finance department via out-of-band channel. 4. Verify all pending payment instructions independently. 5. Add relay IPs to monitoring watchlist. 6. Force password reset for exposed account.',
      },
      {
        id: 'evidence',
        title: 'Evidence List',
        content: 'EMAIL-2026-0041-A (original email artifact). Domain intelligence record. Relay path analysis. Authentication results. EXP-00481 (credential exposure record). Campaign correlation data CAMP-2026-017.',
      },
      {
        id: 'custody',
        title: 'Chain of Custody',
        content: '2026-09-12T09:14:37Z — Email ingested and flagged. 2026-09-12T09:45:00Z — Case opened by Dr. Priya Mehta. 2026-09-12T10:30:00Z — Domain intelligence retrieved. 2026-09-12T11:15:00Z — Campaign correlation completed. 2026-09-12T14:00:00Z — Exposure record linked. 2026-09-13T08:15:00Z — Report generated.',
      },
      {
        id: 'limitations',
        title: 'Limitations',
        content: 'Authentication failures do not conclusively prove malicious intent (compromised legitimate accounts can pass auth). Geolocation data represents hosting infrastructure, not attacker physical location. Risk score is an analytical assessment, not a legal conclusion. Exact sender identity cannot be established from available evidence alone.',
      },
      {
        id: 'approval',
        title: 'Analyst and Reviewer Sign-Off',
        content: 'Analyst: Dr. Priya Mehta (Senior Investigator). Date: 2026-09-13. Reviewer: Pending Security Team Lead approval. Status: FINAL — awaiting executive sign-off for remediation actions.',
      },
    ],
    relatedCase: cases[0],
    relatedCampaign: campaigns[0],
    relatedExposure: exposureRecords[0],
  },
  {
    id: 'RPT-ASTR-001',
    caseId: 'CASE-2026-0142',
    title: 'Asteron Institute of Technology — Multi-Vector Campaign Dossier',
    generatedAt: '2026-09-08T18:30:00Z',
    generatedBy: 'Demo Analyst',
    status: 'DRAFT',
    sections: [
      {
        id: 'scope',
        title: 'Scope and Authorization',
        content: 'This forensic investigation dossier documents the analysis of four Asteron Institute of Technology emails (ASTR-EMAIL-001 through ASTR-EMAIL-004) and correlated campaign infrastructure. Analysis was conducted under case CASE-2026-0142. All evidence is simulated for demonstration purposes only.',
      },
      {
        id: 'executive',
        title: 'Executive Summary',
        content: 'A coordinated multi-vector campaign targeting Asteron Institute of Technology across four distinct attack types: invoice diversion, credential harvesting, macro delivery, and executive impersonation. Four emails share overlapping infrastructure and targeting patterns. Finance, Procurement, and Executive Office departments are primary targets. Campaign confidence: 91%.',
      },
      {
        id: 'emails',
        title: 'Email Summary',
        content: 'ASTR-EMAIL-001: Invoice diversion (risk 91/100). ASTR-EMAIL-002: Credential harvesting (risk 86/100). ASTR-EMAIL-003: Macro delivery (risk 73/100). ASTR-EMAIL-004: Executive impersonation (risk 88/100). All emails use fictional .example domains and documentation-range IP addresses.',
      },
      {
        id: 'auth',
        title: 'Authentication Results Summary',
        content: 'ASTR-EMAIL-001: SPF PASS, DKIM PASS, DMARC PASS (compromised account indicator). ASTR-EMAIL-002: SPF FAIL, DKIM NONE, DMARC FAIL (spoofed sender). ASTR-EMAIL-003: SPF PASS, DKIM PASS, DMARC PASS (attachment risk remains). ASTR-EMAIL-004: SPF NEUTRAL, DKIM FAIL, DMARC FAIL (display-name spoofing).',
      },
      {
        id: 'infrastructure',
        title: 'Infrastructure Correlation',
        content: 'Related domains: asteron-billing.example, asteron-login.example, asteron-docs.example. Related IPs: 203.0.113.42 (Linode SG), 203.0.113.81 (AWS US). Hosting providers: Linode, Amazon AWS, DigitalOcean, Vultr. All IPs are fictional documentation-range addresses for demonstration.',
      },
      {
        id: 'campaign',
        title: 'Campaign Correlation',
        content: 'Campaign ID: CMP-1024 (Invoice Diversion Cluster). All four emails correlated into single campaign. First seen: 2026-08-28. Last seen: 2026-09-08. Targeted departments: Finance, Procurement, Executive Office. AI confidence: 91%.',
      },
      {
        id: 'exposure',
        title: 'Dark-Web Exposure',
        content: 'Related exposure: EXP-ASTR-001 (a••••@asteron.example). Exposure type: Credential-pair indicator. Severity: HIGH. Confidence: 72%. Status: AWAITING_APPROVAL. Plaintext secret: REDACTED per privacy policy. Source: Simulated breach-monitoring feed.',
      },
      {
        id: 'actions',
        title: 'Recommended Actions',
        content: '1. Block all campaign domains at mail gateway. 2. Alert Finance and Procurement departments via out-of-band channel. 3. Verify all pending payment instructions independently. 4. Warn staff not to open macro-enabled attachments. 5. Reset credentials for any staff who clicked suspicious URLs. 6. Submit all campaign IOCs to threat intelligence feed.',
      },
      {
        id: 'limitations',
        title: 'Limitations',
        content: 'All data in this report is simulated for demonstration purposes only. All domains are .example domains. All IP addresses are fictional documentation-range addresses (203.0.113.0/24). No real credentials were exposed. No real organisations were targeted.',
      },
      {
        id: 'approval',
        title: 'Analyst and Reviewer Sign-Off',
        content: 'Analyst: Demo Analyst (Security Analyst). Date: 2026-09-08. Reviewer: Pending approval. Status: DRAFT — requires review before finalisation.',
      },
    ],
    relatedCase: asteronCases[0],
    relatedCampaign: asteronCampaign,
    relatedExposure: asteronExposure,
  },
];

function ReportCard({ report, selected, onSelect }: { report: ForensicReport; selected: boolean; onSelect: () => void }) {
  const statusColor = (s: string) => {
    const map: Record<string, string> = {
      DRAFT: 'var(--tw-dust)',
      FINAL: 'var(--tw-moss)',
      APPROVED: 'var(--tw-low)',
    };
    return map[s] || map.DRAFT;
  };

  return (
    <button
      onClick={onSelect}
      className="w-full text-left p-5 border-b transition-colors"
      style={{
        borderColor: 'var(--tw-border-mid)',
        borderLeft: selected ? '2px solid var(--tw-burgundy)' : '2px solid transparent',
        backgroundColor: selected ? 'var(--tw-panel-alt)' : 'transparent',
      }}
      {...hoverHandlers()}
    >
      <div className="flex items-start justify-between gap-2 mb-2">
        <div className="space-y-0.5">
          <p className="font-mono text-[10px]" style={tv.muted}>{report.id}</p>
          <p className="font-mono text-sm font-medium" style={tv.text}>{report.title}</p>
        </div>
        <span className="font-mono text-[9px] px-2 py-0.5 rounded-sm border tracking-widest uppercase"
          style={{ color: statusColor(report.status), borderColor: `color-mix(in srgb, ${statusColor(report.status)} 35%, transparent)`, backgroundColor: `color-mix(in srgb, ${statusColor(report.status)} 18%, transparent)` }}
        >
          {report.status}
        </span>
      </div>
      <div className="flex items-center gap-2 text-xs" style={tv.muted}>
        <span>{report.caseId}</span>
        <span>·</span>
        <span>{new Date(report.generatedAt).toLocaleDateString()}</span>
      </div>
    </button>
  );
}

function ReportDetail({ report }: { report: ForensicReport }) {
  const [showJson, setShowJson] = useState(false);
  const [activeSection, setActiveSection] = useState(0);

  const reportJson = {
    meta: {
      id: report.id,
      caseId: report.caseId,
      title: report.title,
      generatedAt: report.generatedAt,
      generatedBy: report.generatedBy,
      status: report.status,
    },
    sections: report.sections,
    relatedCase: report.relatedCase,
    relatedCampaign: report.relatedCampaign,
    relatedExposure: report.relatedExposure,
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <p className="font-mono text-[10px]" style={tv.muted}>{report.id}</p>
            <DemoLabel />
          </div>
          <h2 className="font-serif text-xl" style={tv.text}>{report.title}</h2>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setShowJson(!showJson)}
            className="font-mono text-[10px] tracking-widest uppercase px-3 py-1.5 rounded-sm border transition-colors"
            style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
          >
            {showJson ? <Eye size={11} className="inline mr-1" /> : <Hash size={11} className="inline mr-1" />}
            {showJson ? 'Preview' : 'JSON'}
          </button>
          <button
            onClick={() => {
              const blob = new Blob([JSON.stringify(reportJson, null, 2)], { type: 'application/json' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = `${report.id}.json`;
              a.click();
              URL.revokeObjectURL(url);
            }}
            className="font-mono text-[10px] tracking-widest uppercase px-3 py-1.5 rounded-sm border transition-colors"
            style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
          >
            <Download size={11} className="inline mr-1" />
            Export
          </button>
          <button
            onClick={() => window.print()}
            className="font-mono text-[10px] tracking-widest uppercase px-3 py-1.5 rounded-sm border transition-colors"
            style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
          >
            <Printer size={11} className="inline mr-1" />
            Print
          </button>
        </div>
      </div>

      {/* Meta info */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Case ID', val: report.caseId },
          { label: 'Generated', val: new Date(report.generatedAt).toLocaleString() },
          { label: 'Generated By', val: report.generatedBy },
          { label: 'Status', val: report.status },
        ].map(row => (
          <div key={row.label}>
            <p className="font-mono text-[10px] uppercase tracking-wider mb-0.5" style={tv.muted}>{row.label}</p>
            <p className="font-mono text-xs" style={tv.text}>{row.val}</p>
          </div>
        ))}
      </div>

      {/* JSON View */}
      <AnimatePresence>
        {showJson && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="rounded-sm overflow-hidden"
            style={tv.panelBorder}
          >
            <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>JSON Export</p>
            </div>
            <pre className="p-5 overflow-x-auto text-xs font-mono" style={{ backgroundColor: 'var(--tw-panel-alt)', color: 'var(--tw-text)' }}>
              {JSON.stringify(reportJson, null, 2)}
            </pre>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Structured Report View */}
      {!showJson && (
        <div className="space-y-4">
          {/* Section navigation */}
          <div className="flex border-b gap-0 overflow-x-auto" style={{ borderColor: 'var(--tw-border-mid)' }}>
            {report.sections.map((section, i) => (
              <button
                key={section.id}
                onClick={() => setActiveSection(i)}
                className="font-mono text-xs px-4 py-2.5 border-b-2 whitespace-nowrap transition-colors"
                style={{
                  borderBottomColor: activeSection === i ? 'var(--tw-burgundy)' : 'transparent',
                  color: activeSection === i ? 'var(--tw-burgundy)' : 'var(--tw-text-muted)',
                }}
              >
                {section.title}
              </button>
            ))}
          </div>

          {/* Active section content */}
          <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
            <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>
                {report.sections[activeSection].title}
              </p>
            </div>
            <div className="p-5">
              <p className="text-sm leading-relaxed whitespace-pre-wrap" style={tv.text}>
                {report.sections[activeSection].content}
              </p>
              {report.sections[activeSection].evidence && report.sections[activeSection].evidence.length > 0 && (
                <div className="mt-4 pt-4 border-t space-y-2" style={{ borderColor: 'var(--tw-border-mid)' }}>
                  <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Related Evidence</p>
                  {report.sections[activeSection].evidence.map((ev, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs" style={tv.text}>
                      <Hash size={11} style={tv.muted} />
                      {ev}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Related case/campaign/exposure */}
          <div className="grid md:grid-cols-3 gap-4">
            {report.relatedCase && (
              <div className="rounded-sm p-4 space-y-2" style={tv.panelBorder}>
                <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Related Case</p>
                <p className="font-mono text-xs" style={tv.burg}>{report.relatedCase.id}</p>
                <p className="text-xs" style={tv.text}>{report.relatedCase.title}</p>
                <SeverityBadge severity={report.relatedCase.severity} />
              </div>
            )}
            {report.relatedCampaign && (
              <div className="rounded-sm p-4 space-y-2" style={tv.panelBorder}>
                <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Related Campaign</p>
                <p className="font-mono text-xs" style={tv.burg}>{report.relatedCampaign.id}</p>
                <p className="text-xs" style={tv.text}>{report.relatedCampaign.name}</p>
                <SeverityBadge severity={report.relatedCampaign.riskLevel} />
              </div>
            )}
            {report.relatedExposure && (
              <div className="rounded-sm p-4 space-y-2" style={tv.panelBorder}>
                <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Related Exposure</p>
                <p className="font-mono text-xs" style={tv.burg}>{report.relatedExposure.id}</p>
                <p className="text-xs" style={tv.text}>{report.relatedExposure.maskedIdentity}</p>
                <SeverityBadge severity={report.relatedExposure.severity} />
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function ReportsPage() {
  const [selectedReport, setSelectedReport] = useState(mockReports[0]);
  const [generating, setGenerating] = useState(false);
  const [showCreateReport, setShowCreateReport] = useState(false);
  const [newReport, setNewReport] = useState({
    caseId: '',
    reportType: 'Technical',
    redactionLevel: 'Standard',
    selectedSections: ['Executive Summary', 'Threat Verdict', 'Indicators of Compromise', 'Recommended Actions'],
  });
  const [customReports, setCustomReports] = useState<any[]>([]);

  const allReports = [...mockReports, ...customReports];

  const availableSections = [
    'Executive Summary',
    'Scope and Authorization',
    'Threat Verdict and Risk Score',
    'Email Metadata',
    'SPF, DKIM, and DMARC Results',
    'Header and Relay Analysis',
    'Geolocation and Infrastructure Findings',
    'Domain and IP Intelligence',
    'URL Findings',
    'Attachment Findings',
    'Social Engineering Findings',
    'Dark-Web Exposure Findings',
    'Campaign Relationships',
    'Indicators of Compromise',
    'Recommended Actions',
    'Evidence List',
    'Chain of Custody',
    'Limitations',
    'Analyst and Reviewer Sign-Off',
  ];

  const toggleSection = (section: string) => {
    setNewReport(prev => ({
      ...prev,
      selectedSections: prev.selectedSections.includes(section)
        ? prev.selectedSections.filter(s => s !== section)
        : [...prev.selectedSections, section],
    }));
  };

  const handleGenerateCustomReport = async () => {
    if (!newReport.caseId || newReport.selectedSections.length === 0) return;

    setGenerating(true);
    try {
      const report = await generateReport({
        caseId: newReport.caseId,
        sections: newReport.selectedSections,
        reportType: newReport.reportType,
        redactionLevel: newReport.redactionLevel,
      });

      const typedReport: ForensicReport = {
        ...report,
        status: 'DRAFT' as const,
      };

      setCustomReports(prev => [typedReport, ...prev]);
      setSelectedReport(typedReport);
      setShowCreateReport(false);
      setNewReport({
        caseId: '',
        reportType: 'Technical',
        redactionLevel: 'Standard',
        selectedSections: ['Executive Summary', 'Threat Verdict', 'Indicators of Compromise', 'Recommended Actions'],
      });

      await createAuditEvent('Report Generated', report.id, 'SUCCESS');
    } catch (error) {
      console.error('Failed to generate report:', error);
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div className="min-h-screen" style={tv.canvas}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8">
        <div className="flex items-end justify-between mb-6 gap-4">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Forensic Reports</p>
                <DemoLabel />
              </div>
              <button
                onClick={() => setShowCreateReport(!showCreateReport)}
                className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors flex items-center gap-2"
                style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
              >
                <Plus size={12} /> New Report
              </button>
            </div>
            <h1 className="font-serif text-3xl" style={tv.text}>Report Generation</h1>
            <p className="text-sm max-w-xl leading-relaxed" style={tv.muted}>
              Generate structured forensic investigation dossiers with full evidence chain, authentication results, and recommended actions.
            </p>
          </div>
        </div>

        {/* Threat Evidence Network */}
        <ThreatEvidenceNetwork pageType="reports" />

        {/* Create Report Form */}
        <AnimatePresence>
          {showCreateReport && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="rounded-sm overflow-hidden border mb-6"
              style={{ borderColor: 'var(--tw-border)' }}
            >
              <div className="p-5 space-y-4" style={{ backgroundColor: 'var(--tw-panel-alt)' }}>
                <div className="flex items-center justify-between">
                  <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Generate Custom Report</p>
                  <button onClick={() => setShowCreateReport(false)} className="p-1 rounded-sm hover:bg-[var(--tw-hover)]">
                    <X size={14} style={tv.faint} />
                  </button>
                </div>
                
                <div className="grid md:grid-cols-3 gap-4">
                  <div className="space-y-2">
                    <label className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Case ID</label>
                    <select
                      value={newReport.caseId}
                      onChange={e => setNewReport({ ...newReport, caseId: e.target.value })}
                      className="w-full font-mono text-xs px-3 py-2 rounded-sm focus:outline-none"
                      style={tv.input}
                    >
                      <option value="">Select a case...</option>
                      {[...cases, ...asteronCases].map(c => (
                        <option key={c.id} value={c.id}>{c.id} - {c.title}</option>
                      ))}
                    </select>
                  </div>
                  
                  <div className="space-y-2">
                    <label className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Report Type</label>
                    <select
                      value={newReport.reportType}
                      onChange={e => setNewReport({ ...newReport, reportType: e.target.value })}
                      className="w-full font-mono text-xs px-3 py-2 rounded-sm focus:outline-none"
                      style={tv.input}
                    >
                      <option value="Executive">Executive Report</option>
                      <option value="Technical">Technical Report</option>
                      <option value="Incident Response">Incident-Response Report</option>
                      <option value="Law Enforcement">Law-Enforcement Support</option>
                    </select>
                  </div>
                  
                  <div className="space-y-2">
                    <label className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Redaction Level</label>
                    <select
                      value={newReport.redactionLevel}
                      onChange={e => setNewReport({ ...newReport, redactionLevel: e.target.value })}
                      className="w-full font-mono text-xs px-3 py-2 rounded-sm focus:outline-none"
                      style={tv.input}
                    >
                      <option value="Minimal">Minimal</option>
                      <option value="Standard">Standard</option>
                      <option value="Strict">Strict</option>
                    </select>
                  </div>
                </div>
                
                <div className="space-y-2">
                  <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Report Sections ({newReport.selectedSections.length} selected)</p>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                    {availableSections.map(section => (
                      <label key={section} className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={newReport.selectedSections.includes(section)}
                          onChange={() => toggleSection(section)}
                          style={{ accentColor: 'var(--tw-burgundy)' }}
                          className="w-3.5 h-3.5"
                        />
                        <span className="text-xs" style={tv.text}>{section}</span>
                      </label>
                    ))}
                  </div>
                </div>
                
                <div className="flex gap-2">
                  <button
                    onClick={handleGenerateCustomReport}
                    disabled={generating || !newReport.caseId || newReport.selectedSections.length === 0}
                    className="flex-1 font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm transition-colors disabled:opacity-40"
                    style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
                  >
                    {generating ? 'Generating…' : 'Generate Report'}
                  </button>
                  <button
                    onClick={() => setShowCreateReport(false)}
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

        {/* Notice */}
        <div className="rounded-sm p-4 mb-6 flex items-start gap-3" style={{ ...tv.canvasMid, border: '1px solid var(--tw-border)' }}>
          <Shield size={14} className="mt-0.5 shrink-0" style={tv.muted} />
          <div className="space-y-1">
            <p className="font-mono text-[10px] tracking-widest uppercase" style={tv.muted}>Report Notice</p>
            <p className="text-xs leading-relaxed" style={tv.muted}>
              All reports include full chain of custody, evidence hashes, and analyst sign-off. Reports are immutable once marked FINAL.
              Export to JSON for SIEM integration or print to PDF for archiving.
            </p>
            <p className="font-mono text-[10px]" style={tv.muted}>{DEMO_LABEL}</p>
          </div>
        </div>

        <div className="grid lg:grid-cols-5 rounded-sm overflow-hidden min-h-[70vh]" style={tv.panelBorder}>
          {/* Report list */}
          <div className="lg:col-span-2 border-r overflow-y-auto" style={{ borderColor: 'var(--tw-border-mid)' }}>
            <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Generated Reports ({allReports.length})</p>
            </div>
            {allReports.map(report => (
              <ReportCard
                key={report.id}
                report={report}
                selected={selectedReport.id === report.id}
                onSelect={() => setSelectedReport(report)}
              />
            ))}
          </div>
          {/* Detail */}
          <div className="lg:col-span-3 p-6 overflow-y-auto">
            <ReportDetail report={selectedReport} />
          </div>
        </div>
      </div>
    </div>
  );
}
