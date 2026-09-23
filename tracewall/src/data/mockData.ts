// ============================================================
// PhishNet — Mock Data Layer
// All data is simulated for demonstration purposes only.
// ============================================================

export const DEMO_LABEL = 'Simulated Demo Data';

// ── Analyst / Session ────────────────────────────────────────
export const currentAnalyst = {
  id: 'analyst-001',
  name: 'Dr. Priya Mehta',
  role: 'Senior Investigator',
  organization: 'SecureOps Intelligence Unit',
  avatar: 'PM',
  shift: 'Day Shift · 08:00–16:00 IST',
};

// ── Daily Briefing ───────────────────────────────────────────
export const dailyBriefing = {
  date: 'Sunday, 13 September 2026',
  organization: 'SecureOps Intelligence Unit',
  threatPosture: 'ELEVATED',
  postureSummary:
    'Three investigations require review. One credential exposure remains uncontained. A probable invoice-diversion campaign is targeting the Finance department.',
  investigationsRequiringAttention: 3,
  pendingDecisions: 5,
  openExposures: 2,
};

// ── Investigations ────────────────────────────────────────────
export const investigations = [
  {
    id: 'INV-2026-0041',
    title: 'Invoice-Diversion Campaign — Finance Dept.',
    severity: 'HIGH' as const,
    status: 'Investigating' as const,
    assignedTo: 'Dr. Priya Mehta',
    createdAt: '2026-09-12T09:14:00Z',
    updatedAt: '2026-09-13T07:30:00Z',
    relatedEmails: 4,
    riskScore: 87,
    aiSummary:
      'Four related messages share a lookalike sender domain and identical reply-to infrastructure. The language pattern matches prior invoice-fraud templates. Targets appear concentrated in Finance and Accounts Payable.',
    evidencePoints: [
      'Reply-To domain differs from envelope sender domain',
      'Sender domain registered 11 days ago — resembles finance.secureops.in',
      'Urgent payment language with external bank account in body',
    ],
    primaryAction: 'Quarantine related emails · Verify payment instructions',
    tags: ['Invoice Fraud', 'BEC', 'Lookalike Domain'],
  },
  {
    id: 'INV-2026-0040',
    title: 'Executive Impersonation — CEO Credential Request',
    severity: 'CRITICAL' as const,
    status: 'Triage' as const,
    assignedTo: 'Rohan Varma',
    createdAt: '2026-09-12T14:22:00Z',
    updatedAt: '2026-09-13T06:55:00Z',
    relatedEmails: 2,
    riskScore: 92,
    aiSummary:
      'Message purports to originate from the CEO requesting urgent credential verification. Display name matches CEO; envelope sender routes through an unrelated European mail provider.',
    evidencePoints: [
      'Display name "CEO Arjun Sharma" does not match envelope sender',
      'SPF: FAIL — not authorized by the organisation domain',
      'Body contains credential harvesting link to newly registered domain',
    ],
    primaryAction: 'Block harvesting URL · Alert affected users',
    tags: ['Executive Impersonation', 'Credential Harvesting', 'SPF Fail'],
  },
  {
    id: 'INV-2026-0039',
    title: 'Suspicious Attachment — Macro-Enabled Document',
    severity: 'HIGH' as const,
    status: 'Contained' as const,
    assignedTo: 'Aisha Lindqvist',
    createdAt: '2026-09-11T11:05:00Z',
    updatedAt: '2026-09-12T16:40:00Z',
    relatedEmails: 1,
    riskScore: 74,
    aiSummary:
      'Single message with macro-enabled .docm attachment. Filename mimics an HR policy document. No sandbox execution confirmed but file hash matches a known delivery template.',
    evidencePoints: [
      'Attachment: HR_Policy_Update_Sept2026.docm — macro enabled',
      'File hash matches delivery template observed in prior campaign',
      'Sender domain registered 3 days prior to delivery',
    ],
    primaryAction: 'Quarantine attachment · Submit for sandbox analysis',
    tags: ['Malware Delivery', 'Macro', 'New Domain'],
  },
];

// ── Demo Email ────────────────────────────────────────────────
export const demoEmail = {
  id: 'EMAIL-2026-0041-A',
  subject: 'URGENT: Updated Banking Details for Invoice #INV-5591',
  from: {
    display: 'Finance Team <finance@secureops-finance.in>',
    address: 'finance@secureops-finance.in',
    domain: 'secureops-finance.in',
  },
  replyTo: 'payments@secure-ops-pay.net',
  returnPath: 'bounce@mailing-relay-eu4.net',
  envelopeSender: 'noreply@mailing-relay-eu4.net',
  to: 'accounts.payable@secureops.in',
  messageId: '<20260912.091437.FIN5591@secureops-finance.in>',
  date: '2026-09-12T09:14:37+05:30',
  attachments: [{ name: 'Invoice_INV-5591_Updated.pdf', size: '218 KB', suspicious: false }],
  urls: [
    { url: 'https://secureops-finance.in/verify-payment', risk: 'HIGH' },
    { url: 'https://bit.ly/3xPayConf', risk: 'HIGH', shortener: true },
    { url: 'https://docs.secureops.in/policy', risk: 'LOW' },
  ],
  body: `Dear Accounts Payable Team,

Please note that our banking details have been updated effective immediately. Kindly update your records and ensure the pending payment of ₹ 14,72,500 for Invoice #INV-5591 is transferred to the new account before end of business today.

NEW BANKING DETAILS:
Bank: First National Private Bank
Account Name: SecureOps Vendor Services
Account No: 9182736450
IFSC Code: FNPB0001892

This is a time-sensitive request authorised by the CFO. Please do not discuss this with anyone outside the finance team until the transfer is confirmed. Click below to confirm receipt of these instructions:

→ Confirm Receipt: https://secureops-finance.in/verify-payment

If you have questions, reply directly to this message.

Regards,
Finance Department
SecureOps Intelligence Unit`,
  suspiciousPhrases: [
    {
      text: 'updated effective immediately',
      reason: 'Urgency trigger — forces hasty action',
      confidence: 92,
    },
    {
      text: 'ensure the pending payment',
      reason: 'Directive language characteristic of payment diversion',
      confidence: 88,
    },
    {
      text: 'time-sensitive request authorised by the CFO',
      reason: 'Authority impersonation — CFO not in sender chain',
      confidence: 95,
    },
    {
      text: 'do not discuss this with anyone outside the finance team',
      reason: 'Secrecy request — classic BEC social engineering pattern',
      confidence: 97,
    },
    {
      text: 'reply directly to this message',
      reason: 'Redirects response to attacker-controlled reply-to address',
      confidence: 91,
    },
  ],
};

// ── Authentication Results ────────────────────────────────────
export const authResults = {
  spf: {
    result: 'FAIL' as const,
    detail: 'secureops-finance.in does not authorise mailing-relay-eu4.net',
    explanation:
      'The sending IP is not listed in the SPF record of the claimed sender domain. This suggests the message did not originate from an authorised mail server for that domain.',
  },
  dkim: {
    result: 'NONE' as const,
    detail: 'No DKIM signature present',
    explanation:
      'No DKIM signature was found in the message. Without a signature, the message body and headers cannot be cryptographically verified.',
  },
  dmarc: {
    result: 'FAIL' as const,
    policy: 'p=quarantine',
    detail: 'Neither SPF nor DKIM alignment passed',
    explanation:
      'DMARC policy requires alignment of either SPF or DKIM with the From domain. Both failed, indicating the message does not conform to the domain\'s published policy.',
  },
  note: 'Authentication failures are strong indicators but are not conclusive proof of malicious intent. A compromised legitimate server can pass authentication checks.',
};

// ── Relay Hops ────────────────────────────────────────────────
export const relayHops = [
  {
    num: 1,
    label: 'Origin (Sender-Controlled)',
    hostname: 'mail.secureops-finance.in',
    ip: '185.220.101.47',
    timestamp: '2026-09-12T03:44:37Z',
    asn: 'AS209588',
    asnName: 'Hosting Solutions GmbH',
    country: 'DE',
    countryName: 'Germany',
    reliability: 'SENDER_CONTROLLED' as const,
    note: 'Sender-provided — cannot be independently verified',
    isVpn: false,
    isTor: false,
    isCloud: true,
    provider: 'Hosting Solutions GmbH',
  },
  {
    num: 2,
    label: 'Relay Node',
    hostname: 'mailing-relay-eu4.net',
    ip: '45.142.212.83',
    timestamp: '2026-09-12T03:44:39Z',
    asn: 'AS47674',
    asnName: 'NetArt Group Ltd.',
    country: 'PL',
    countryName: 'Poland',
    reliability: 'VERIFIED' as const,
    note: 'Technically verified relay hop',
    isVpn: false,
    isTor: false,
    isCloud: false,
    provider: 'NetArt Group Ltd.',
  },
  {
    num: 3,
    label: 'Secondary Relay',
    hostname: 'smtp-out.eu-mail-hub.com',
    ip: '91.108.56.19',
    timestamp: '2026-09-12T03:44:52Z',
    asn: 'AS31898',
    asnName: 'Oracle Cloud Infrastructure',
    country: 'NL',
    countryName: 'Netherlands',
    reliability: 'INFERRED' as const,
    note: 'Cloud infrastructure — may not represent origin',
    isVpn: false,
    isTor: false,
    isCloud: true,
    provider: 'Oracle Cloud',
  },
  {
    num: 4,
    label: 'Recipient Mail Server',
    hostname: 'mx1.secureops.in',
    ip: '10.0.1.4',
    timestamp: '2026-09-12T09:14:37Z',
    asn: 'INTERNAL',
    asnName: 'SecureOps Internal Network',
    country: 'IN',
    countryName: 'India',
    reliability: 'VERIFIED' as const,
    note: 'Organisation mail server — trusted endpoint',
    isVpn: false,
    isTor: false,
    isCloud: false,
    provider: 'Internal',
  },
];

// ── Domain Intelligence ───────────────────────────────────────
export const domainIntel = {
  senderDomain: 'secureops-finance.in',
  legitimateDomain: 'secureops.in',
  similarityScore: 83,
  registeredDaysAgo: 11,
  registrar: 'GoDaddy LLC',
  registrationDate: '2026-09-01',
  nameservers: ['ns1.hosting-solutions.de', 'ns2.hosting-solutions.de'],
  mxRecords: ['mail.secureops-finance.in'],
  spfRecord: 'v=spf1 include:mailing-relay-eu4.net ~all',
  dmarcRecord: 'v=DMARC1; p=none;',
  homoglyphs: [
    { original: 'secureops.in', variant: 'secureops-finance.in', technique: 'Subdomain impersonation' },
  ],
  typosquatting: true,
  ipReputation: 'POOR',
  hostingProvider: 'Hosting Solutions GmbH (DE)',
  firstSeen: '2026-09-02',
  lastSeen: '2026-09-13',
  relatedDomains: ['secure-ops-pay.net', 'secureops-payments.com', 'secureops-verify.in'],
};

// ── Dark Web Exposures ────────────────────────────────────────
export const exposureRecords = [
  {
    id: 'EXP-00481',
    maskedIdentity: 'a••••@secureops.in',
    domain: 'secureops.in',
    exposureDate: '2026-08-29',
    sourceCategory: 'Credential-pair indicator',
    dataType: 'Email + Password hash',
    passwordStatus: 'REDACTED',
    confidence: 94,
    severity: 'HIGH' as const,
    department: 'Finance',
    recommendedActions: [
      'Force password reset',
      'Revoke active sessions',
      'Review sign-in activity',
      'Check mailbox forwarding rules',
      'Verify MFA status',
    ],
    relatedCase: 'INV-2026-0041',
    status: 'AWAITING_APPROVAL' as const,
    note: 'Credential-pair indicator detected in monitored intelligence feed. Plaintext secret is not stored or displayed per privacy policy.',
  },
  {
    id: 'EXP-00479',
    maskedIdentity: 'r••••@secureops.in',
    domain: 'secureops.in',
    exposureDate: '2026-08-15',
    sourceCategory: 'Combolists',
    dataType: 'Email + Password indicator',
    passwordStatus: 'REDACTED',
    confidence: 78,
    severity: 'HIGH' as const,
    department: 'Executive',
    recommendedActions: [
      'Force password reset',
      'Revoke active sessions',
      'Step-up MFA verification',
      'Review OAuth applications',
    ],
    relatedCase: 'INV-2026-0040',
    status: 'REMEDIATED' as const,
    note: 'Password reset confirmed. MFA re-enrolled. Case marked remediated.',
  },
  {
    id: 'EXP-00462',
    maskedIdentity: 'j••••@secureops.in',
    domain: 'secureops.in',
    exposureDate: '2026-07-04',
    sourceCategory: 'Forum leak indicator',
    dataType: 'Email address only',
    passwordStatus: 'N/A',
    confidence: 65,
    severity: 'MEDIUM' as const,
    department: 'Engineering',
    recommendedActions: ['Monitor account for suspicious activity', 'Recommend voluntary password rotation'],
    relatedCase: null,
    status: 'MONITORING' as const,
    note: 'Email address only — no credential pair confirmed. Monitoring for subsequent exposure.',
  },
];

// ── Campaigns ─────────────────────────────────────────────────
export const campaigns = [
  {
    id: 'CAMP-2026-017',
    name: 'Operation Ledger Shift',
    riskLevel: 'HIGH' as const,
    relatedEmails: 4,
    firstSeen: '2026-09-01',
    lastSeen: '2026-09-13',
    targetedDepartments: ['Finance', 'Accounts Payable'],
    relatedDomains: ['secureops-finance.in', 'secure-ops-pay.net', 'secureops-payments.com'],
    relatedIPs: ['185.220.101.47', '45.142.212.83'],
    relatedCases: ['INV-2026-0041'],
    confidence: 88,
    aiSummary:
      'Co-ordinated invoice-diversion campaign targeting financial processing departments. Four messages share sender infrastructure, lookalike domain pattern, and identical payment-redirection language. Probable goal: divert outgoing payments to attacker-controlled accounts.',
    containmentActions: [
      'Block all sender domains at mail gateway',
      'Alert Finance department via out-of-band channel',
      'Verify all pending payment instructions independently',
      'Add relay IPs to monitoring watchlist',
    ],
    tags: ['BEC', 'Invoice Fraud', 'Lookalike Domain', 'Finance Target'],
  },
  {
    id: 'CAMP-2026-014',
    name: 'Phantom Executive Series',
    riskLevel: 'CRITICAL' as const,
    relatedEmails: 7,
    firstSeen: '2026-08-20',
    lastSeen: '2026-09-12',
    targetedDepartments: ['HR', 'Executive', 'IT'],
    relatedDomains: ['arjun-sharma-ceo.com', 'secureops-leadership.in'],
    relatedIPs: ['194.165.16.3', '178.173.228.88'],
    relatedCases: ['INV-2026-0040'],
    confidence: 91,
    aiSummary:
      'Sustained executive impersonation campaign using fabricated display names matching C-suite personnel. Goal appears to be credential harvesting and access escalation. Observed across seven messages over 24 days.',
    containmentActions: [
      'Block phishing domains',
      'Alert impersonated executives',
      'Force credential reset for affected accounts',
      'Submit harvesting infrastructure to threat feeds',
    ],
    tags: ['Executive Impersonation', 'Credential Harvesting', 'Sustained Campaign'],
  },
];

// ── Cases ─────────────────────────────────────────────────────
export const cases = [
  {
    id: 'INV-2026-0041',
    title: 'Invoice-Diversion Campaign — Finance Dept.',
    severity: 'HIGH' as const,
    status: 'Investigating' as const,
    assignedTo: 'Dr. Priya Mehta',
    createdAt: '2026-09-12T09:14:00Z',
    updatedAt: '2026-09-13T07:30:00Z',
    relatedEmails: ['EMAIL-2026-0041-A', 'EMAIL-2026-0038-B', 'EMAIL-2026-0036-A', 'EMAIL-2026-0034-C'],
    relatedCampaign: 'CAMP-2026-017',
    exposureRecords: ['EXP-00481'],
    timelineEvents: [
      { time: '2026-09-12T09:14:00Z', actor: 'System', event: 'Email ingested and flagged for review', type: 'SYSTEM' },
      { time: '2026-09-12T09:45:00Z', actor: 'Dr. Priya Mehta', event: 'Case opened and triage begun', type: 'ANALYST' },
      { time: '2026-09-12T10:30:00Z', actor: 'Dr. Priya Mehta', event: 'Domain intelligence retrieved — 11-day old lookalike', type: 'EVIDENCE' },
      { time: '2026-09-12T11:15:00Z', actor: 'Dr. Priya Mehta', event: 'Related emails correlated into campaign CAMP-2026-017', type: 'ANALYST' },
      { time: '2026-09-12T14:00:00Z', actor: 'System', event: 'Credential exposure EXP-00481 linked to this case', type: 'SYSTEM' },
      { time: '2026-09-13T07:30:00Z', actor: 'Dr. Priya Mehta', event: 'Quarantine recommendation submitted — awaiting approval', type: 'DECISION' },
    ],
    notes: [
      { author: 'Dr. Priya Mehta', time: '2026-09-12T10:45:00Z', text: 'The reply-to domain secure-ops-pay.net appears to have been registered in the same 48-hour window as the sender domain. Likely the same operator.' },
    ],
    tasks: [
      { id: 'T1', text: 'Confirm affected recipient list with mail admin', done: true },
      { id: 'T2', text: 'Block lookalike domains at gateway', done: false },
      { id: 'T3', text: 'Notify Finance department via out-of-band channel', done: false },
      { id: 'T4', text: 'Verify payment instructions with CFO directly', done: false },
    ],
  },
];

// ── Alerts ────────────────────────────────────────────────────
export const alerts = [
  {
    id: 'ALERT-2026-0091',
    title: 'Probable Invoice-Diversion Campaign Detected',
    severity: 'HIGH' as const,
    category: 'Campaign',
    created: '2026-09-12T11:15:00Z',
    status: 'OPEN' as const,
    relatedCase: 'INV-2026-0041',
    summary: '4 related emails · 2 lookalike domains · 3 suspicious URLs · Finance department targeted · Confidence: High',
    recommendation: 'Verify payment instructions through an independent communication channel',
  },
  {
    id: 'ALERT-2026-0090',
    title: 'Corporate Email Exposure Detected',
    severity: 'HIGH' as const,
    category: 'Exposure',
    created: '2026-09-12T09:00:00Z',
    status: 'AWAITING_APPROVAL' as const,
    relatedCase: 'INV-2026-0041',
    summary: 'Identifier: a••••@secureops.in · Exposure type: Credential-pair indicator · Severity: High',
    recommendation: 'Force password reset, revoke active sessions, and review sign-in activity',
  },
  {
    id: 'ALERT-2026-0088',
    title: 'Executive Impersonation Message Blocked',
    severity: 'CRITICAL' as const,
    category: 'Impersonation',
    created: '2026-09-12T14:22:00Z',
    status: 'CONTAINED' as const,
    relatedCase: 'INV-2026-0040',
    summary: 'Display name matches CEO · SPF FAIL · Credential harvesting URL detected',
    recommendation: 'Alert impersonated executive and reset any potentially accessed credentials',
  },
];

// ── Audit Log ─────────────────────────────────────────────────
export const auditLog = [
  { id: 'AUD-0512', time: '2026-09-13T07:30:00Z', actor: 'Dr. Priya Mehta', action: 'Submitted quarantine recommendation', target: 'EMAIL-2026-0041-A', outcome: 'PENDING_APPROVAL', ip: '10.0.5.14' },
  { id: 'AUD-0511', time: '2026-09-13T07:28:00Z', actor: 'Dr. Priya Mehta', action: 'Viewed exposure record', target: 'EXP-00481', outcome: 'SUCCESS', ip: '10.0.5.14' },
  { id: 'AUD-0510', time: '2026-09-12T16:40:00Z', actor: 'Aisha Lindqvist', action: 'Marked case as Contained', target: 'INV-2026-0039', outcome: 'SUCCESS', ip: '10.0.5.22' },
  { id: 'AUD-0509', time: '2026-09-12T15:30:00Z', actor: 'Rohan Varma', action: 'Added IOC to SIEM', target: 'arjun-sharma-ceo.com', outcome: 'SUCCESS', ip: '10.0.5.31' },
  { id: 'AUD-0508', time: '2026-09-12T14:55:00Z', actor: 'Rohan Varma', action: 'Forced password reset', target: 'r••••@secureops.in', outcome: 'SUCCESS', ip: '10.0.5.31' },
  { id: 'AUD-0507', time: '2026-09-12T14:22:00Z', actor: 'System', action: 'Auto-flagged executive impersonation email', target: 'EMAIL-2026-0040-A', outcome: 'SUCCESS', ip: 'SYSTEM' },
  { id: 'AUD-0506', time: '2026-09-12T11:15:00Z', actor: 'Dr. Priya Mehta', action: 'Correlated emails into campaign', target: 'CAMP-2026-017', outcome: 'SUCCESS', ip: '10.0.5.14' },
  { id: 'AUD-0505', time: '2026-09-12T09:45:00Z', actor: 'Dr. Priya Mehta', action: 'Opened investigation case', target: 'INV-2026-0041', outcome: 'SUCCESS', ip: '10.0.5.14' },
];

// ── Threat Graph Nodes & Edges ────────────────────────────────
export const threatGraphNodes = [
  { id: 'n1', type: 'email', label: 'finance@secureops-finance.in', subtype: 'SENDER' },
  { id: 'n2', type: 'domain', label: 'secureops-finance.in', subtype: 'LOOKALIKE', age: '11 days' },
  { id: 'n3', type: 'domain', label: 'secure-ops-pay.net', subtype: 'REPLY-TO', age: '9 days' },
  { id: 'n4', type: 'ip', label: '185.220.101.47', subtype: 'ORIGIN', country: 'DE' },
  { id: 'n5', type: 'ip', label: '45.142.212.83', subtype: 'RELAY', country: 'PL' },
  { id: 'n6', type: 'url', label: 'secureops-finance.in/verify-payment', subtype: 'HIGH_RISK' },
  { id: 'n7', type: 'url', label: 'bit.ly/3xPayConf', subtype: 'SHORTENER' },
  { id: 'n8', type: 'campaign', label: 'Operation Ledger Shift', subtype: 'CAMPAIGN' },
  { id: 'n9', type: 'exposure', label: 'EXP-00481 · a••••@secureops.in', subtype: 'EXPOSURE' },
  { id: 'n10', type: 'domain', label: 'secureops.in', subtype: 'LEGITIMATE' },
];

export const threatGraphEdges = [
  { id: 'e1', source: 'n1', target: 'n2', label: 'Envelope sender domain' },
  { id: 'e2', source: 'n1', target: 'n3', label: 'Reply-To domain' },
  { id: 'e3', source: 'n2', target: 'n4', label: 'Resolves to' },
  { id: 'e4', source: 'n4', target: 'n5', label: 'Relay hop' },
  { id: 'e5', source: 'n2', target: 'n6', label: 'Hosts URL' },
  { id: 'e6', source: 'n7', target: 'n6', label: 'Redirects to' },
  { id: 'e7', source: 'n1', target: 'n8', label: 'Part of campaign' },
  { id: 'e8', source: 'n9', target: 'n8', label: 'Exposure linked' },
  { id: 'e9', source: 'n2', target: 'n10', label: 'Impersonates' },
  { id: 'e10', source: 'n3', target: 'n10', label: 'Impersonates' },
];

// ── Risk Score Breakdown ──────────────────────────────────────
export const riskScoreBreakdown = {
  total: 87,
  confidence: 'HIGH',
  verdict: 'HIGH RISK',
  factors: [
    { label: 'Reply-To domain mismatch', contribution: 18, category: 'Identity' },
    { label: 'Newly registered lookalike domain', contribution: 22, category: 'Domain' },
    { label: 'Urgent payment request language', contribution: 15, category: 'Social Engineering' },
    { label: 'Suspicious redirect chain', contribution: 20, category: 'URL' },
    { label: 'Related credential-exposure campaign', contribution: 12, category: 'Correlation' },
  ],
  disclaimer:
    'This score is an analytical assessment and is not a legal conclusion. A qualified analyst should review all evidence before action.',
};

// ── Response Actions ──────────────────────────────────────────
export const responseActions = [
  {
    id: 'ACT-001',
    title: 'Quarantine Related Emails',
    reason: 'Prevent further delivery of messages matching campaign indicators',
    impact: 'Removes 4 emails from recipient mailboxes',
    reversible: true,
    permission: 'Analyst',
    requiresApproval: false,
    risk: 'LOW' as const,
    status: 'PENDING' as const,
  },
  {
    id: 'ACT-002',
    title: 'Block Sender Domains at Gateway',
    reason: 'Prevent future delivery from lookalike domains',
    impact: 'Blocks secureops-finance.in and secure-ops-pay.net organisation-wide',
    reversible: true,
    permission: 'Analyst',
    requiresApproval: true,
    risk: 'MEDIUM' as const,
    status: 'AWAITING_APPROVAL' as const,
  },
  {
    id: 'ACT-003',
    title: 'Force Password Reset — Exposed Account',
    reason: 'Credential-pair indicator detected for a••••@secureops.in',
    impact: 'Forces immediate password change and session revocation for affected account',
    reversible: false,
    permission: 'Administrator',
    requiresApproval: true,
    risk: 'HIGH' as const,
    status: 'AWAITING_APPROVAL' as const,
  },
  {
    id: 'ACT-004',
    title: 'Add IOCs to SIEM',
    reason: 'Propagate campaign indicators to detection infrastructure',
    impact: 'Adds 5 IOCs (2 domains, 2 IPs, 1 URL hash) to SIEM watchlist',
    reversible: true,
    permission: 'Analyst',
    requiresApproval: false,
    risk: 'LOW' as const,
    status: 'PENDING' as const,
  },
];

// ── Timeline chart data ───────────────────────────────────────
export const activityTimeline = [
  { hour: '00:00', phishing: 0, bec: 0, malware: 0 },
  { hour: '01:00', phishing: 1, bec: 0, malware: 0 },
  { hour: '02:00', phishing: 0, bec: 0, malware: 1 },
  { hour: '03:00', phishing: 2, bec: 0, malware: 0 },
  { hour: '04:00', phishing: 1, bec: 1, malware: 0 },
  { hour: '05:00', phishing: 0, bec: 0, malware: 0 },
  { hour: '06:00', phishing: 3, bec: 1, malware: 0 },
  { hour: '07:00', phishing: 2, bec: 0, malware: 1 },
  { hour: '08:00', phishing: 4, bec: 2, malware: 0 },
  { hour: '09:00', phishing: 6, bec: 3, malware: 1 },
  { hour: '10:00', phishing: 5, bec: 2, malware: 2 },
  { hour: '11:00', phishing: 3, bec: 1, malware: 1 },
  { hour: '12:00', phishing: 2, bec: 0, malware: 0 },
  { hour: '13:00', phishing: 4, bec: 1, malware: 0 },
  { hour: '14:00', phishing: 7, bec: 4, malware: 1 },
];

// ============================================================
// ASTERON INSTITUTE OF TECHNOLOGY — Demo Organization
// All data below is simulated for demonstration purposes only.
// ============================================================

// ── Asteron Demo Organization ─────────────────────────────────
export const asteronOrg = {
  name: 'Asteron Institute of Technology',
  domain: 'asteron.example',
  departments: ['Finance', 'Administration', 'Human Resources', 'IT Security', 'Procurement', 'Executive Office'],
  analyst: { name: 'Demo Analyst', role: 'Security Analyst', avatar: 'DA' },
};

// ── Asteron Demo Emails (4) ───────────────────────────────────
export const asteronEmails = [
  {
    id: 'ASTR-EMAIL-001',
    subject: 'Urgent: Updated Vendor Payment Instructions',
    from: { display: 'Finance Director <finance.director@asteron.example>', address: 'finance.director@asteron.example', domain: 'asteron.example' },
    replyTo: 'payments-update@asteron-billing.example',
    returnPath: 'bounce@mailer-relay-sg3.example',
    envelopeSender: 'noreply@mailer-relay-sg3.example',
    to: 'procurement@asteron.example',
    messageId: '<20260828.143021.PAY8821@asteron.example>',
    date: '2026-08-28T14:30:21+05:30',
    classification: 'Business Email Compromise',
    riskScore: 91,
    severity: 'CRITICAL' as const,
    attachments: [{ name: 'Vendor_Payment_Instructions_Aug2026.pdf', size: '142 KB', suspicious: false, hash: 'b3f8a1c2...', macro: false }],
    urls: [
      { url: 'https://asteron-billing.example/confirm-payment', risk: 'HIGH' as const },
      { url: 'https://tinyurl.com/astpay2026', risk: 'HIGH' as const, shortener: true },
    ],
    body: `Dear Procurement Team,

Please be advised that our primary vendor has updated their banking details effective from today. Kindly process the outstanding payment of ₹ 28,50,000 (Invoice #VND-2026-0094) to the new account before close of business.

NEW ACCOUNT DETAILS:
Bank: Meridian Cooperative Bank
Account Name: AIT Vendor Services Pvt Ltd
Account No: 4471829304
IFSC: MRCB0002417

This instruction has been approved by the Finance Director. Please treat this as urgent and confidential — do not share these details with other departments until the payment is confirmed.

To confirm receipt of these instructions, click here:
https://asteron-billing.example/confirm-payment

Do not reply to this email if you have questions; contact the Finance Director directly on the internal directory.

Regards,
Finance Director
Asteron Institute of Technology`,
    suspiciousPhrases: [
      { text: 'effective from today', reason: 'Urgency trigger — pressures immediate action', confidence: 90 },
      { text: 'urgent and confidential', reason: 'Secrecy + urgency combination — BEC signature pattern', confidence: 96 },
      { text: 'do not share these details with other departments', reason: 'Explicit secrecy request to prevent verification', confidence: 98 },
      { text: 'Do not reply to this email', reason: 'Redirects contact away from this address — avoids detection', confidence: 87 },
    ],
    authResults: {
      spf: { result: 'PASS' as const, detail: 'asteron.example authorises this sending server', explanation: 'SPF passes — however, this may indicate a compromised internal account or authorised relay being abused. SPF pass alone does not confirm legitimacy.' },
      dkim: { result: 'PASS' as const, detail: 'DKIM signature verified for asteron.example', explanation: 'DKIM signature is valid. Note: a compromised legitimate account will produce a valid DKIM signature.' },
      dmarc: { result: 'PASS' as const, policy: 'p=quarantine', detail: 'SPF and DKIM alignment both pass', explanation: 'DMARC policy satisfied. Authentication success does not eliminate BEC risk when sender credentials may be compromised.' },
      note: 'All three authentication checks pass. This is consistent with a compromised legitimate account — a common BEC attack vector. Combine authentication results with behavioural and content analysis.',
    },
    relayHops: [
      { num: 1, label: 'Origin', hostname: 'mail.asteron.example', ip: '198.51.100.24', timestamp: '2026-08-28T09:00:12Z', asn: 'AS45609', asnName: 'BSNL-NIB', country: 'IN', countryName: 'India', reliability: 'SENDER_CONTROLLED' as const, note: 'Sender-controlled — unverifiable', isCloud: false, provider: 'BSNL' },
      { num: 2, label: 'Relay', hostname: 'relay-mail.example', ip: '203.0.113.42', timestamp: '2026-08-28T09:00:28Z', asn: 'AS63949', asnName: 'Linode', country: 'SG', countryName: 'Singapore', reliability: 'VERIFIED' as const, note: 'Technically verified hop', isCloud: true, provider: 'Linode' },
      { num: 3, label: 'Secondary Relay', hostname: 'cloud-relay.example', ip: '203.0.113.81', timestamp: '2026-08-28T09:00:45Z', asn: 'AS16509', asnName: 'Amazon AWS', country: 'US', countryName: 'United States', reliability: 'INFERRED' as const, note: 'Cloud relay — may not represent origin. All IPs are fictional documentation-range addresses for demonstration.', isCloud: true, provider: 'Amazon AWS' },
      { num: 4, label: 'Recipient', hostname: 'mx1.asteron.example', ip: '10.0.2.1', timestamp: '2026-08-28T14:30:21Z', asn: 'INTERNAL', asnName: 'Asteron Internal', country: 'IN', countryName: 'India', reliability: 'VERIFIED' as const, note: 'Organisation mail server', isCloud: false, provider: 'Internal' },
    ],
    indicators: ['Reply-To domain mismatch', 'Lookalike sender domain', 'Urgent payment request', 'Secrecy request', 'Suspicious URL', 'BEC pattern match'],
    recommendedActions: ['Quarantine email', 'Verify payment instructions via separate channel', 'Investigate mailbox rules', 'Open high-priority case'],
  },
  {
    id: 'ASTR-EMAIL-002',
    subject: 'Your account requires immediate verification',
    from: { display: 'Asteron IT Security <security-alert@asteron-login.example>', address: 'security-alert@asteron-login.example', domain: 'asteron-login.example' },
    replyTo: 'support@asteron-login.example',
    returnPath: 'bounce@bulk-mailer-eu.example',
    envelopeSender: 'noreply@bulk-mailer-eu.example',
    to: 'staff@asteron.example',
    messageId: '<20260901.082215.SEC4492@asteron-login.example>',
    date: '2026-09-01T08:22:15+05:30',
    classification: 'Credential Harvesting',
    riskScore: 86,
    severity: 'HIGH' as const,
    attachments: [],
    urls: [
      { url: 'https://asteron-login.example/verify-now', risk: 'HIGH' as const },
      { url: 'https://go.to/asteronverify', risk: 'HIGH' as const, shortener: true },
    ],
    body: `IMPORTANT SECURITY NOTICE

Your Asteron Institute of Technology account has been flagged for unusual sign-in activity. Immediate verification is required to prevent account suspension.

Please verify your account credentials within the next 2 hours to avoid disruption to your access.

→ VERIFY NOW: https://asteron-login.example/verify-now

If you do not verify, your account will be temporarily suspended until manual review is completed by the IT Security team.

This is an automated security notice. Do not ignore this message.

IT Security Team
Asteron Institute of Technology`,
    suspiciousPhrases: [
      { text: 'Immediate verification is required', reason: 'Urgency + fear — forces rapid credential entry', confidence: 94 },
      { text: 'within the next 2 hours', reason: 'Artificial deadline — prevents rational verification', confidence: 91 },
      { text: 'to avoid disruption to your access', reason: 'Fear trigger — threat of service loss', confidence: 89 },
      { text: 'Do not ignore this message', reason: 'Pressure language — characteristic of credential phishing', confidence: 88 },
    ],
    authResults: {
      spf: { result: 'FAIL' as const, detail: 'asteron-login.example not authorised for bulk-mailer-eu.example', explanation: 'SPF check fails — the sending IP is not authorised by the claimed sender domain.' },
      dkim: { result: 'NONE' as const, detail: 'No DKIM signature present', explanation: 'No DKIM signature found. Message body integrity cannot be verified.' },
      dmarc: { result: 'FAIL' as const, policy: 'p=reject', detail: 'Neither SPF nor DKIM alignment met', explanation: 'DMARC policy is p=reject and neither check passed. Message should have been rejected.' },
      note: 'All three checks fail. Strong indicator of spoofed or unauthorised sender.',
    },
    relayHops: [
      { num: 1, label: 'Origin (Sender-Controlled)', hostname: 'mail.asteron-login.example', ip: '203.0.113.99', timestamp: '2026-09-01T02:52:10Z', asn: 'AS20473', asnName: 'Choopa LLC', country: 'DE', countryName: 'Germany', reliability: 'SENDER_CONTROLLED' as const, note: 'Unverifiable sender-controlled header', isCloud: true, provider: 'Vultr' },
      { num: 2, label: 'Recipient', hostname: 'mx1.asteron.example', ip: '10.0.2.1', timestamp: '2026-09-01T08:22:15Z', asn: 'INTERNAL', asnName: 'Asteron Internal', country: 'IN', countryName: 'India', reliability: 'VERIFIED' as const, note: 'Recipient server', isCloud: false, provider: 'Internal' },
    ],
    indicators: ['Lookalike domain', 'Suspicious redirect URL', 'Credential request', 'Urgency language', 'SPF FAIL', 'DKIM missing'],
    recommendedActions: ['Block sender domain', 'Quarantine email', 'Warn staff not to click link', 'Report URL to threat intel'],
  },
  {
    id: 'ASTR-EMAIL-003',
    subject: 'Updated salary statement available',
    from: { display: 'Payroll Department <payroll@asteron.example>', address: 'payroll@asteron.example', domain: 'asteron.example' },
    replyTo: 'payroll@asteron.example',
    returnPath: 'payroll@asteron.example',
    envelopeSender: 'payroll@asteron.example',
    to: 'staff@asteron.example',
    messageId: '<20260905.113045.PAY7751@asteron.example>',
    date: '2026-09-05T11:30:45+05:30',
    classification: 'Suspicious Attachment',
    riskScore: 73,
    severity: 'HIGH' as const,
    attachments: [{ name: 'HR_Policy_Update_Sept2026.docm', size: '384 KB', suspicious: true, hash: 'e9a3f7c2d1b44e68...', macro: true }],
    urls: [],
    body: `Dear Team,

Please find attached the updated salary statement and HR policy document for September 2026.

Kindly open the document and enable macros if prompted, as the document contains interactive content required for the salary confirmation process.

Please complete the acknowledgement form within the document by end of week.

Regards,
Human Resources
Asteron Institute of Technology`,
    suspiciousPhrases: [
      { text: 'enable macros if prompted', reason: 'Explicit instruction to enable macros — malware delivery vector', confidence: 97 },
      { text: 'interactive content required', reason: 'Social engineering justification for macro execution', confidence: 93 },
    ],
    authResults: {
      spf: { result: 'PASS' as const, detail: 'asteron.example authorised sender', explanation: 'SPF passes. This may indicate a compromised internal account.' },
      dkim: { result: 'PASS' as const, detail: 'DKIM valid', explanation: 'DKIM signature valid. Does not rule out account compromise.' },
      dmarc: { result: 'PASS' as const, policy: 'p=quarantine', detail: 'Alignment satisfied', explanation: 'All auth checks pass. Attachment risk remains HIGH regardless of authentication.' },
      note: 'Authentication passes but attachment macro risk is HIGH. Do not rely on authentication alone when evaluating attachment-based threats.',
    },
    relayHops: [
      { num: 1, label: 'Internal Origin', hostname: 'mail.asteron.example', ip: '10.0.1.5', timestamp: '2026-09-05T06:00:40Z', asn: 'INTERNAL', asnName: 'Asteron Internal', country: 'IN', countryName: 'India', reliability: 'VERIFIED' as const, note: 'Internal mail server', isCloud: false, provider: 'Internal' },
      { num: 2, label: 'Recipient', hostname: 'mx1.asteron.example', ip: '10.0.2.1', timestamp: '2026-09-05T11:30:45Z', asn: 'INTERNAL', asnName: 'Asteron Internal', country: 'IN', countryName: 'India', reliability: 'VERIFIED' as const, note: 'Recipient server', isCloud: false, provider: 'Internal' },
    ],
    indicators: ['Macro-enabled attachment', 'Explicit macro execution instruction', 'Unusual attachment for payroll notification', 'Hash matches prior delivery template'],
    recommendedActions: ['Quarantine attachment', 'Submit to sandbox analysis', 'Warn staff not to enable macros', 'Check for similar attachments across mailboxes'],
  },
  {
    id: 'ASTR-EMAIL-004',
    subject: 'Invitation to review confidential document',
    from: { display: 'Executive Office <executive.office@asteron.example>', address: 'executive.office@asteron.example', domain: 'asteron.example' },
    replyTo: 'ceo-office@asteron-docs.example',
    returnPath: 'bounce@asteron-docs.example',
    envelopeSender: 'noreply@asteron-docs.example',
    to: 'department.heads@asteron.example',
    messageId: '<20260908.171522.EXEC3309@asteron.example>',
    date: '2026-09-08T17:15:22+05:30',
    classification: 'Executive Impersonation',
    riskScore: 88,
    severity: 'HIGH' as const,
    attachments: [],
    urls: [
      { url: 'https://bit.ly/3Qexecdoc', risk: 'HIGH' as const, shortener: true },
      { url: 'https://asteron-docs.example/board-review', risk: 'HIGH' as const },
    ],
    body: `Dear Department Heads,

The Director has requested your urgent and confidential review of a strategic document before the board meeting tomorrow.

Please access the document using the secure link below. You will be required to sign in with your Asteron credentials.

→ Review Document: https://bit.ly/3Qexecdoc

Please do not forward this link or discuss its contents with other staff members. The document relates to a confidential restructuring proposal.

Respond directly to this email to confirm you have reviewed it.

Office of the Executive Director
Asteron Institute of Technology`,
    suspiciousPhrases: [
      { text: 'urgent and confidential', reason: 'Urgency + secrecy combination — executive impersonation pattern', confidence: 95 },
      { text: 'You will be required to sign in with your Asteron credentials', reason: 'Credential harvesting instruction under executive authority', confidence: 97 },
      { text: 'do not forward this link or discuss its contents', reason: 'Isolation instruction — prevents verification', confidence: 93 },
      { text: 'Respond directly to this email', reason: 'Redirects response to attacker-controlled Reply-To', confidence: 90 },
    ],
    authResults: {
      spf: { result: 'NEUTRAL' as const, detail: 'asteron.example SPF record is neutral for this sender', explanation: 'SPF returns neutral — the sending IP is neither explicitly authorised nor prohibited.' },
      dkim: { result: 'FAIL' as const, detail: 'DKIM signature verification failed', explanation: 'DKIM signature present but failed verification — the message may have been tampered with in transit, or the signature was forged.' },
      dmarc: { result: 'FAIL' as const, policy: 'p=quarantine', detail: 'DKIM failure causes DMARC to fail', explanation: 'DMARC fails due to DKIM failure. SPF neutral does not satisfy alignment requirement.' },
      note: 'DKIM failure combined with Reply-To mismatch strongly suggests message manipulation or display-name spoofing.',
    },
    relayHops: [
      { num: 1, label: 'Origin (Sender-Controlled)', hostname: 'mail.asteron-docs.example', ip: '203.0.113.55', timestamp: '2026-09-08T11:45:10Z', asn: 'AS14061', asnName: 'DigitalOcean', country: 'SG', countryName: 'Singapore', reliability: 'SENDER_CONTROLLED' as const, note: 'Sender-controlled — unverifiable', isCloud: true, provider: 'DigitalOcean' },
      { num: 2, label: 'Recipient', hostname: 'mx1.asteron.example', ip: '10.0.2.1', timestamp: '2026-09-08T17:15:22Z', asn: 'INTERNAL', asnName: 'Asteron Internal', country: 'IN', countryName: 'India', reliability: 'VERIFIED' as const, note: 'Recipient server', isCloud: false, provider: 'Internal' },
    ],
    indicators: ['Display-name spoofing', 'Reply-To mismatch', 'Shortened URL', 'Credential harvesting', 'Secrecy request', 'DKIM FAIL'],
    recommendedActions: ['Block sender domain', 'Quarantine email', 'Alert impersonated executive', 'Submit URL to threat intel'],
  },
];

// ── Asteron Campaign ──────────────────────────────────────────
export const asteronCampaign = {
  id: 'CMP-1024',
  name: 'Invoice Diversion Cluster',
  riskLevel: 'CRITICAL' as const,
  relatedEmails: 4,
  firstSeen: '2026-08-28',
  lastSeen: '2026-09-08',
  targetedDepartments: ['Finance', 'Procurement', 'Executive Office'],
  relatedDomains: ['asteron-billing.example', 'asteron-login.example', 'asteron-docs.example'],
  relatedIPs: ['203.0.113.42', '203.0.113.81'],
  relatedUrls: ['asteron-billing.example/confirm-payment', 'asteron-login.example/verify-now', 'asteron-docs.example/board-review'],
  relatedCases: ['CASE-2026-0142'],
  relatedExposures: ['EXP-ASTR-001'],
  confidence: 91,
  status: 'Investigating' as const,
  aiSummary:
    'Co-ordinated multi-vector campaign targeting Asteron Institute of Technology across four distinct attack types: invoice diversion, credential harvesting, macro delivery, and executive impersonation. Four emails share overlapping infrastructure and targeting patterns. Finance, Procurement, and Executive Office departments are primary targets.',
  containmentActions: [
    'Block all asteron-billing.example, asteron-login.example, asteron-docs.example at gateway',
    'Alert Finance and Procurement departments via out-of-band channel',
    'Verify all pending payment instructions independently',
    'Warn staff not to open macro-enabled attachments',
    'Reset credentials for any staff who clicked suspicious URLs',
    'Submit all campaign IOCs to threat intelligence feed',
  ],
  tags: ['BEC', 'Invoice Fraud', 'Credential Harvesting', 'Macro Delivery', 'Executive Impersonation', 'Multi-Vector'],
};

// ── Asteron Exposure Record ────────────────────────────────────
export const asteronExposure = {
  id: 'EXP-ASTR-001',
  maskedIdentity: 'a••••@asteron.example',
  domain: 'asteron.example',
  exposureDate: '2026-08-28',
  sourceCategory: 'Simulated breach-monitoring feed',
  dataType: 'Credential-pair indicator',
  passwordStatus: 'REDACTED',
  confidence: 72,
  severity: 'HIGH' as const,
  department: 'Finance',
  recommendedActions: [
    'Force password reset',
    'Revoke active sessions',
    'Require MFA re-enrolment',
    'Review sign-in activity for past 30 days',
    'Check mailbox forwarding rules',
    'Verify no suspicious OAuth grants',
  ],
  relatedCase: 'CASE-2026-0142',
  status: 'AWAITING_APPROVAL' as const,
  note: 'Credential-pair indicator detected in simulated breach-monitoring feed. Plaintext secret is not stored or displayed per privacy policy. This is simulated demo data only.',
};

// ── Asteron Cases ─────────────────────────────────────────────
export const asteronCases = [
  {
    id: 'CASE-2026-0142',
    title: 'Invoice Diversion Campaign — Asteron Finance',
    severity: 'CRITICAL' as const,
    status: 'Investigating' as const,
    assignedTo: 'Demo Analyst',
    createdAt: '2026-08-28T15:00:00Z',
    updatedAt: '2026-09-08T17:30:00Z',
    relatedEmails: ['ASTR-EMAIL-001', 'ASTR-EMAIL-002', 'ASTR-EMAIL-003', 'ASTR-EMAIL-004'],
    relatedCampaign: 'CMP-1024',
    exposureRecords: ['EXP-ASTR-001'],
    timelineEvents: [
      { time: '2026-08-28T15:00:00Z', actor: 'System', event: 'ASTR-EMAIL-001 ingested and flagged — high risk score 91/100', type: 'SYSTEM' },
      { time: '2026-08-28T15:30:00Z', actor: 'Demo Analyst', event: 'Case opened — triage initiated for invoice diversion email', type: 'ANALYST' },
      { time: '2026-08-29T09:00:00Z', actor: 'System', event: 'Credential exposure EXP-ASTR-001 linked to case', type: 'SYSTEM' },
      { time: '2026-09-01T08:45:00Z', actor: 'System', event: 'ASTR-EMAIL-002 correlated into campaign CMP-1024', type: 'SYSTEM' },
      { time: '2026-09-05T12:00:00Z', actor: 'Demo Analyst', event: 'Macro attachment in ASTR-EMAIL-003 submitted for sandbox analysis', type: 'EVIDENCE' },
      { time: '2026-09-08T17:45:00Z', actor: 'System', event: 'ASTR-EMAIL-004 detected — executive impersonation correlated to campaign', type: 'SYSTEM' },
      { time: '2026-09-08T18:00:00Z', actor: 'Demo Analyst', event: 'Containment actions submitted for approval', type: 'DECISION' },
    ],
    notes: [
      { author: 'Demo Analyst', time: '2026-08-29T10:00:00Z', text: 'All four emails share relay infrastructure via cloud providers in Singapore and Germany. The domains were registered within a 12-day window. Likely the same operator.' },
    ],
    tasks: [
      { id: 'AT1', text: 'Block campaign domains at mail gateway', done: false },
      { id: 'AT2', text: 'Alert Finance and Procurement departments', done: false },
      { id: 'AT3', text: 'Verify payment instructions with Finance Director directly', done: false },
      { id: 'AT4', text: 'Sandbox analysis for ASTR-EMAIL-003 attachment', done: true },
      { id: 'AT5', text: 'Reset credentials for credential-exposure affected account', done: false },
    ],
  },
  {
    id: 'CASE-2026-0143',
    title: 'Corporate Credential Exposure — Asteron',
    severity: 'HIGH' as const,
    status: 'Awaiting Remediation' as const,
    assignedTo: 'Demo Analyst',
    createdAt: '2026-08-29T09:00:00Z',
    updatedAt: '2026-09-01T10:00:00Z',
    relatedEmails: ['ASTR-EMAIL-002'],
    relatedCampaign: 'CMP-1024',
    exposureRecords: ['EXP-ASTR-001'],
    timelineEvents: [
      { time: '2026-08-29T09:00:00Z', actor: 'System', event: 'Credential-pair indicator detected for a••••@asteron.example', type: 'SYSTEM' },
      { time: '2026-08-29T09:15:00Z', actor: 'Demo Analyst', event: 'Exposure record EXP-ASTR-001 reviewed and linked to CASE-2026-0142', type: 'ANALYST' },
      { time: '2026-08-29T10:00:00Z', actor: 'Demo Analyst', event: 'Password reset request submitted — awaiting administrator approval', type: 'DECISION' },
      { time: '2026-09-01T10:00:00Z', actor: 'System', event: 'Account remains active — awaiting remediation approval', type: 'SYSTEM' },
    ],
    notes: [
      { author: 'Demo Analyst', time: '2026-08-29T09:20:00Z', text: 'The exposed account belongs to the Finance department. Correlated with the credential harvesting email ASTR-EMAIL-002 targeting the same department.' },
    ],
    tasks: [
      { id: 'BT1', text: 'Force password reset for exposed account', done: false },
      { id: 'BT2', text: 'Revoke active sessions', done: false },
      { id: 'BT3', text: 'Verify MFA enrolment', done: false },
      { id: 'BT4', text: 'Review mailbox forwarding rules', done: false },
    ],
  },
];

// ── Missing Cases for existing investigations ─────────────────
// These populate the CasesPage detail panel for INV-2026-0040 and INV-2026-0039
export const additionalCases = [
  {
    id: 'INV-2026-0040',
    title: 'Executive Impersonation — CEO Credential Request',
    severity: 'CRITICAL' as const,
    status: 'Triage' as const,
    assignedTo: 'Rohan Varma',
    createdAt: '2026-09-12T14:22:00Z',
    updatedAt: '2026-09-13T06:55:00Z',
    relatedEmails: ['EMAIL-2026-0040-A', 'EMAIL-2026-0040-B'],
    relatedCampaign: 'CAMP-2026-014',
    exposureRecords: ['EXP-00479'],
    timelineEvents: [
      { time: '2026-09-12T14:22:00Z', actor: 'System', event: 'Email auto-flagged — executive impersonation indicators detected', type: 'SYSTEM' },
      { time: '2026-09-12T14:35:00Z', actor: 'Rohan Varma', event: 'Case opened — triage started', type: 'ANALYST' },
      { time: '2026-09-12T15:10:00Z', actor: 'Rohan Varma', event: 'Display-name spoofing confirmed — envelope sender mismatch', type: 'EVIDENCE' },
      { time: '2026-09-12T15:30:00Z', actor: 'Rohan Varma', event: 'Credential harvesting URL blocked at gateway', type: 'DECISION' },
      { time: '2026-09-13T06:55:00Z', actor: 'Rohan Varma', event: 'Correlated with Phantom Executive Series campaign', type: 'ANALYST' },
    ],
    notes: [
      { author: 'Rohan Varma', time: '2026-09-12T15:15:00Z', text: 'The display name "CEO Arjun Sharma" exactly matches the CEO listed in the organisational directory. Classic display-name spoof with an unrelated envelope sender.' },
    ],
    tasks: [
      { id: 'C1', text: 'Block credential harvesting domain', done: true },
      { id: 'C2', text: 'Alert CEO and IT Security', done: true },
      { id: 'C3', text: 'Verify no staff clicked the harvesting URL', done: false },
      { id: 'C4', text: 'Correlate with CAMP-2026-014', done: true },
    ],
  },
  {
    id: 'INV-2026-0039',
    title: 'Suspicious Attachment — Macro-Enabled Document',
    severity: 'HIGH' as const,
    status: 'Contained' as const,
    assignedTo: 'Aisha Lindqvist',
    createdAt: '2026-09-11T11:05:00Z',
    updatedAt: '2026-09-12T16:40:00Z',
    relatedEmails: ['EMAIL-2026-0039-A'],
    relatedCampaign: null,
    exposureRecords: [],
    timelineEvents: [
      { time: '2026-09-11T11:05:00Z', actor: 'System', event: 'Email with macro-enabled attachment flagged', type: 'SYSTEM' },
      { time: '2026-09-11T11:20:00Z', actor: 'Aisha Lindqvist', event: 'Case opened — attachment quarantined', type: 'ANALYST' },
      { time: '2026-09-11T13:00:00Z', actor: 'Aisha Lindqvist', event: 'Attachment hash matched known delivery template in threat feed', type: 'EVIDENCE' },
      { time: '2026-09-11T14:30:00Z', actor: 'Aisha Lindqvist', event: 'Sandbox analysis requested — pending', type: 'DECISION' },
      { time: '2026-09-12T16:40:00Z', actor: 'Aisha Lindqvist', event: 'Case marked Contained — no execution confirmed', type: 'ANALYST' },
    ],
    notes: [
      { author: 'Aisha Lindqvist', time: '2026-09-11T13:15:00Z', text: 'File hash e9a3f7c2...matches a template seen in two prior campaigns. No macro execution detected on target systems. Sandbox result: suspicious macro payload present but not triggered.' },
    ],
    tasks: [
      { id: 'D1', text: 'Quarantine attachment across mailboxes', done: true },
      { id: 'D2', text: 'Submit to sandbox analysis', done: true },
      { id: 'D3', text: 'Check if sender domain is newly registered', done: true },
      { id: 'D4', text: 'Verify no macro execution on recipient systems', done: true },
    ],
  },
];

// ── Updated alerts with assignedTo ────────────────────────────
export const alertsWithAssignment = [
  {
    id: 'ALERT-2026-0091',
    title: 'Probable Invoice-Diversion Campaign Detected',
    severity: 'HIGH' as const,
    category: 'Business Email Compromise',
    created: '2026-09-12T11:15:00Z',
    status: 'OPEN' as const,
    assignedTo: 'Dr. Priya Mehta',
    relatedCase: 'INV-2026-0041',
    summary: '4 related emails · 2 lookalike domains · 3 suspicious URLs · Finance department targeted · Confidence: High',
    recommendation: 'Verify payment instructions through an independent communication channel',
    source: 'AI Correlation Engine',
  },
  {
    id: 'ALERT-2026-0090',
    title: 'Corporate Email Exposure Detected',
    severity: 'HIGH' as const,
    category: 'Credential Exposure',
    created: '2026-09-12T09:00:00Z',
    status: 'AWAITING_APPROVAL' as const,
    assignedTo: 'Dr. Priya Mehta',
    relatedCase: 'INV-2026-0041',
    summary: 'Identifier: a••••@secureops.in · Exposure type: Credential-pair indicator · Severity: High',
    recommendation: 'Force password reset, revoke active sessions, and review sign-in activity',
    source: 'Dark-Web Monitor',
  },
  {
    id: 'ALERT-2026-0088',
    title: 'Executive Impersonation Message Blocked',
    severity: 'CRITICAL' as const,
    category: 'Executive Impersonation',
    created: '2026-09-12T14:22:00Z',
    status: 'CONTAINED' as const,
    assignedTo: 'Rohan Varma',
    relatedCase: 'INV-2026-0040',
    summary: 'Display name matches CEO · SPF FAIL · Credential harvesting URL detected',
    recommendation: 'Alert impersonated executive and reset any potentially accessed credentials',
    source: 'Email Analysis Engine',
  },
  {
    id: 'ALERT-2026-0087',
    title: 'Macro-Enabled Attachment Quarantined',
    severity: 'HIGH' as const,
    category: 'Suspicious Attachment',
    created: '2026-09-11T11:10:00Z',
    status: 'RESOLVED' as const,
    assignedTo: 'Aisha Lindqvist',
    relatedCase: 'INV-2026-0039',
    summary: 'HR_Policy_Update_Sept2026.docm · Macro payload detected · Hash matched prior delivery template',
    recommendation: 'Quarantine attachment and submit to sandbox for full analysis',
    source: 'Attachment Analysis Engine',
  },
  {
    id: 'ALERT-2026-0085',
    title: 'Lookalike Domain Registered — Asteron',
    severity: 'MEDIUM' as const,
    category: 'Lookalike Domain',
    created: '2026-09-02T07:00:00Z',
    status: 'ACKNOWLEDGED' as const,
    assignedTo: 'Demo Analyst',
    relatedCase: 'CASE-2026-0142',
    summary: 'asteron-billing.example registered 2026-08-28 · 91% similarity to asteron.example · Hosting: Linode SG',
    recommendation: 'Monitor for email abuse; block proactively at mail gateway',
    source: 'Domain Monitoring',
  },
];

// ── Attachment analysis detail ────────────────────────────────
export const attachmentAnalysis = [
  {
    id: 'ATT-001',
    filename: 'Invoice_INV-5591_Updated.pdf',
    fileType: 'PDF',
    size: '218 KB',
    hash: 'a3f7c2d91b44e6805f29ac73d6e1b58209c4d9afb3e1c28f7d6a4b5e0192837',
    macroPresent: false,
    scriptPresent: false,
    sandboxResult: 'CLEAN' as const,
    riskScore: 12,
    recommendation: 'No immediate action required. Monitor for delivery of follow-up messages.',
    emailId: 'EMAIL-2026-0041-A',
    firstSeen: '2026-09-12',
    source: 'SecureOps Mail Gateway',
  },
  {
    id: 'ATT-002',
    filename: 'HR_Policy_Update_Sept2026.docm',
    fileType: 'DOCM (Macro-Enabled Document)',
    size: '384 KB',
    hash: 'e9a3f7c2d1b44e6855ab291c0f8e3d17492c1b8f5a2e0d9c6b4f3a7e8d1c059',
    macroPresent: true,
    scriptPresent: true,
    sandboxResult: 'SUSPICIOUS' as const,
    riskScore: 82,
    recommendation: 'Do not open. Quarantine immediately. Submit to sandbox for full dynamic analysis.',
    emailId: 'EMAIL-2026-0039-A',
    firstSeen: '2026-09-11',
    source: 'SecureOps Mail Gateway',
    matchedTemplate: 'Macro delivery template — observed in CAMP-2026-014 and 2 prior campaigns',
  },
];

// ── IP Intelligence ────────────────────────────────────────────
export const ipIntelligence = [
  {
    ip: '185.220.101.47',
    asn: 'AS209588',
    asnName: 'Hosting Solutions GmbH',
    isp: 'Hosting Solutions GmbH',
    hostingProvider: 'Hosting Solutions GmbH',
    country: 'Germany',
    region: 'Bavaria',
    city: 'Munich',
    isVpn: false,
    isTor: false,
    isProxy: false,
    isCloud: true,
    isOpenRelay: false,
    reputation: 'POOR' as const,
    firstSeen: '2026-09-02',
    lastSeen: '2026-09-13',
    abuseReports: 3,
    note: 'Estimated infrastructure location only. This is not proof of any person\'s physical location.',
  },
  {
    ip: '45.142.212.83',
    asn: 'AS47674',
    asnName: 'NetArt Group Ltd.',
    isp: 'NetArt Group Ltd.',
    hostingProvider: 'NetArt Group Ltd.',
    country: 'Poland',
    region: 'Masovian',
    city: 'Warsaw',
    isVpn: false,
    isTor: false,
    isProxy: false,
    isCloud: false,
    isOpenRelay: true,
    reputation: 'POOR' as const,
    firstSeen: '2026-09-01',
    lastSeen: '2026-09-12',
    abuseReports: 7,
    note: 'Open relay indicator. Estimated infrastructure location only.',
  },
  {
    ip: '203.0.113.42',
    asn: 'AS63949',
    asnName: 'Linode LLC',
    isp: 'Linode',
    hostingProvider: 'Linode',
    country: 'Singapore',
    region: 'Central Region',
    city: 'Singapore',
    isVpn: false,
    isTor: false,
    isProxy: false,
    isCloud: true,
    isOpenRelay: false,
    reputation: 'NEUTRAL' as const,
    firstSeen: '2026-08-28',
    lastSeen: '2026-09-08',
    abuseReports: 1,
    note: 'Cloud hosting — location represents hosting infrastructure, not attacker origin. Fictional documentation-range IP for demo only.',
  },
];

// ============================================================
// ASTERON — Extended Demo Intelligence Records
// All data is simulated for demonstration purposes only.
// ============================================================

export const asteronDomainIntel = [
  {
    domain: 'asteron-billing.example',
    parentDomain: 'asteron.example',
    similarityScore: 91,
    registeredDaysAgo: 11,
    registrationDate: '2026-08-18',
    registrar: 'GoDaddy LLC',
    nameservers: ['ns1.linode.example', 'ns2.linode.example'],
    mxRecords: ['mail.asteron-billing.example'],
    spfRecord: 'v=spf1 include:mailer-relay-sg3.example ~all',
    dmarcRecord: 'v=DMARC1; p=none;',
    homoglyphs: [
      { original: 'asteron.example', variant: 'asteron-billing.example', technique: 'Subdomain impersonation' },
    ],
    typosquatting: false,
    relatedDomains: ['asteron-login.example', 'asteron-docs.example'],
    hostingProvider: 'Linode LLC (SG)',
    ipReputation: 'NEUTRAL',
    firstSeen: '2026-08-28',
    lastSeen: '2026-09-08',
    reputation: 'SUSPICIOUS',
    disclaimer: 'Simulated WHOIS and DNS data for demo purposes only.',
  },
  {
    domain: 'asteron-login.example',
    parentDomain: 'asteron.example',
    similarityScore: 93,
    registeredDaysAgo: 20,
    registrationDate: '2026-08-12',
    registrar: 'Namecheap Inc.',
    nameservers: ['ns1.vultr.example', 'ns2.vultr.example'],
    mxRecords: ['mail.asteron-login.example'],
    spfRecord: 'v=spf1 include:bulk-mailer-eu.example ~all',
    dmarcRecord: 'v=DMARC1; p=reject;',
    homoglyphs: [
      { original: 'asteron.example', variant: 'asteron-login.example', technique: 'Subdomain impersonation' },
    ],
    typosquatting: false,
    relatedDomains: ['asteron-billing.example', 'asteron-docs.example'],
    hostingProvider: 'Vultr GmbH (DE)',
    ipReputation: 'POOR',
    firstSeen: '2026-09-01',
    lastSeen: '2026-09-08',
    reputation: 'SUSPICIOUS',
    disclaimer: 'Simulated WHOIS and DNS data for demo purposes only.',
  },
  {
    domain: 'asteron-docs.example',
    parentDomain: 'asteron.example',
    similarityScore: 90,
    registeredDaysAgo: 14,
    registrationDate: '2026-08-25',
    registrar: 'Namecheap Inc.',
    nameservers: ['ns1.digitalocean.example', 'ns2.digitalocean.example'],
    mxRecords: ['mail.asteron-docs.example'],
    spfRecord: 'v=spf1 ~all',
    dmarcRecord: 'v=DMARC1; p=quarantine;',
    homoglyphs: [
      { original: 'asteron.example', variant: 'asteron-docs.example', technique: 'Subdomain impersonation' },
    ],
    typosquatting: false,
    relatedDomains: ['asteron-billing.example', 'asteron-login.example'],
    hostingProvider: 'DigitalOcean LLC (SG)',
    ipReputation: 'NEUTRAL',
    firstSeen: '2026-09-08',
    lastSeen: '2026-09-08',
    reputation: 'SUSPICIOUS',
    disclaimer: 'Simulated WHOIS and DNS data for demo purposes only.',
  },
];

// ── Asteron IP Intelligence ────────────────────────────────────
export const asteronIpIntel = [
  {
    ip: '203.0.113.42',
    asn: 'AS63949',
    asnName: 'Linode LLC',
    isp: 'Linode',
    provider: 'Linode',
    hostingProvider: 'Linode',
    abuseReports: 2,
    country: 'Singapore',
    region: 'Central Region',
    city: 'Singapore',
    isVpn: false,
    isTor: false,
    isProxy: false,
    isCloud: true,
    isOpenRelay: false,
    reputation: 'NEUTRAL',
    firstSeen: '2026-08-28',
    lastSeen: '2026-09-08',
    evidence: 'Mail gateway relay header · AS63949 registration',
    source: 'SecureOps IP Reputation Feed',
    disclaimer: 'Fictional documentation-range IP for demo only. Location represents hosting infrastructure, not attacker origin.',
  },
  {
    ip: '203.0.113.81',
    asn: 'AS16509',
    asnName: 'Amazon.com Inc.',
    isp: 'Amazon Web Services',
    provider: 'AWS',
    hostingProvider: 'Amazon Web Services',
    abuseReports: 1,
    country: 'United States',
    region: 'Virginia',
    city: 'Ashburn',
    isVpn: false,
    isTor: false,
    isProxy: false,
    isCloud: true,
    isOpenRelay: false,
    reputation: 'NEUTRAL',
    firstSeen: '2026-08-28',
    lastSeen: '2026-09-08',
    evidence: 'Secondary relay hop · AS16509 registration',
    source: 'SecureOps IP Reputation Feed',
    disclaimer: 'Fictional documentation-range IP for demo only. Location represents hosting infrastructure, not attacker origin.',
  },
  {
    ip: '203.0.113.99',
    asn: 'AS20473',
    asnName: 'Choopa LLC',
    isp: 'Vultr',
    provider: 'Vultr',
    hostingProvider: 'Vultr',
    abuseReports: 5,
    country: 'Germany',
    region: 'Bavaria',
    city: 'Munich',
    isVpn: false,
    isTor: false,
    isProxy: false,
    isCloud: true,
    isOpenRelay: false,
    reputation: 'POOR',
    firstSeen: '2026-09-01',
    lastSeen: '2026-09-08',
    evidence: 'Sender-controlled origin header · AS20473 registration',
    source: 'SecureOps IP Reputation Feed',
    disclaimer: 'Fictional documentation-range IP for demo only. Location represents hosting infrastructure, not attacker origin.',
  },
  {
    ip: '203.0.113.55',
    asn: 'AS14061',
    asnName: 'DigitalOcean LLC',
    isp: 'DigitalOcean',
    provider: 'DigitalOcean',
    hostingProvider: 'DigitalOcean',
    abuseReports: 3,
    country: 'Singapore',
    region: 'Central Region',
    city: 'Singapore',
    isVpn: false,
    isTor: false,
    isProxy: false,
    isCloud: true,
    isOpenRelay: false,
    reputation: 'NEUTRAL',
    firstSeen: '2026-09-08',
    lastSeen: '2026-09-08',
    evidence: 'Sender-controlled origin header · AS14061 registration',
    source: 'SecureOps IP Reputation Feed',
    disclaimer: 'Fictional documentation-range IP for demo only. Location represents hosting infrastructure, not attacker origin.',
  },
];

// ── Asteron URL Analysis ───────────────────────────────────────
export const asteronUrlAnalysis = [
  {
    id: 'URL-AST-001',
    originalUrl: 'https://asteron-billing.example/confirm-payment',
    domainIntel: {
      lookalikeOf: 'asteron.example',
      similarityScore: 91,
      registrar: 'GoDaddy LLC',
      hostingProvider: 'Linode LLC (SG)',
      country: 'Singapore',
      tlsInfo: {
        valid: true,
        issuer: "Let's Encrypt",
        expires: '2026-12-31',
      },
    },
    phishingIndicators: [
      'Lookalike domain (91% similarity to legitimate)',
      'Recently registered domain (11 days)',
      'Suspicious URL parameters detected',
      'Domain hosted on cloud infrastructure',
      'No prior reputation history',
    ],
    recommendedAction: 'Block domain at mail gateway. Alert users not to interact with this URL.',
    extractedUrl: 'https://asteron-billing.example/confirm-payment',
    shortenedUrl: null,
    redirectChain: [
      { from: 'https://asteron-billing.example/confirm-payment', to: 'https://asteron-billing.example/confirm-payment', status: 200 },
    ],
    finalDomain: 'asteron-billing.example',
    suspiciousParams: ['redirect_uri', 'token'],
    reputation: 'SUSPICIOUS',
    domainAge: 11,
    firstSeen: '2026-08-28',
    lastSeen: '2026-09-08',
    relatedEmail: 'ASTR-EMAIL-001',
    disclaimer: 'Simulated URL analysis for demo purposes only.',
  },
  {
    id: 'URL-AST-002',
    originalUrl: 'https://tinyurl.com/astpay2026',
    domainIntel: {
      lookalikeOf: 'asteron.example',
      similarityScore: 91,
      registrar: 'GoDaddy LLC',
      hostingProvider: 'Linode LLC (SG)',
      country: 'Singapore',
      tlsInfo: {
        valid: true,
        issuer: "Let's Encrypt",
        expires: '2026-12-31',
      },
    },
    phishingIndicators: [
      'Lookalike domain (91% similarity to legitimate)',
      'Recently registered domain (11 days)',
      'URL shortener redirect detected',
      'Suspicious URL parameters detected',
      'Domain hosted on cloud infrastructure',
    ],
    recommendedAction: 'Block domain at mail gateway. Alert users not to interact with this URL. Investigate URL shortener usage.',
    extractedUrl: 'https://asteron-billing.example/confirm-payment?ref=tiny',
    shortenedUrl: 'https://tinyurl.com/astpay2026',
    redirectChain: [
      { from: 'https://tinyurl.com/astpay2026', to: 'https://asteron-billing.example/confirm-payment?ref=tiny', status: 302 },
    ],
    finalDomain: 'asteron-billing.example',
    suspiciousParams: ['ref'],
    reputation: 'SUSPICIOUS',
    domainAge: 11,
    firstSeen: '2026-08-28',
    lastSeen: '2026-09-08',
    relatedEmail: 'ASTR-EMAIL-001',
    disclaimer: 'Simulated URL analysis for demo purposes only.',
  },
  {
    id: 'URL-AST-003',
    originalUrl: 'https://asteron-login.example/verify-now',
    domainIntel: {
      lookalikeOf: 'asteron.example',
      similarityScore: 93,
      registrar: 'Namecheap Inc.',
      hostingProvider: 'Vultr GmbH (DE)',
      country: 'Germany',
      tlsInfo: {
        valid: true,
        issuer: "Let's Encrypt",
        expires: '2026-11-15',
      },
    },
    phishingIndicators: [
      'Lookalike domain (93% similarity to legitimate)',
      'Recently registered domain (20 days)',
      'Suspicious URL parameters detected',
      'Domain hosted on cloud infrastructure',
      'No prior reputation history',
    ],
    recommendedAction: 'Block domain at mail gateway. Alert users not to interact with this URL.',
    extractedUrl: 'https://asteron-login.example/verify-now',
    shortenedUrl: null,
    redirectChain: [
      { from: 'https://asteron-login.example/verify-now', to: 'https://asteron-login.example/verify-now', status: 200 },
    ],
    finalDomain: 'asteron-login.example',
    suspiciousParams: ['u', 's'],
    reputation: 'SUSPICIOUS',
    domainAge: 20,
    firstSeen: '2026-09-01',
    lastSeen: '2026-09-08',
    relatedEmail: 'ASTR-EMAIL-002',
    disclaimer: 'Simulated URL analysis for demo purposes only.',
  },
  {
    id: 'URL-AST-004',
    originalUrl: 'https://go.to/asteronverify',
    domainIntel: {
      lookalikeOf: 'asteron.example',
      similarityScore: 93,
      registrar: 'Namecheap Inc.',
      hostingProvider: 'Vultr GmbH (DE)',
      country: 'Germany',
      tlsInfo: {
        valid: true,
        issuer: "Let's Encrypt",
        expires: '2026-11-15',
      },
    },
    phishingIndicators: [
      'Lookalike domain (93% similarity to legitimate)',
      'Recently registered domain (20 days)',
      'URL shortener redirect detected',
      'Suspicious URL parameters detected',
      'Domain hosted on cloud infrastructure',
    ],
    recommendedAction: 'Block domain at mail gateway. Alert users not to interact with this URL. Investigate URL shortener usage.',
    extractedUrl: 'https://asteron-login.example/verify-now?u=staff&s=bulk',
    shortenedUrl: 'https://go.to/asteronverify',
    redirectChain: [
      { from: 'https://go.to/asteronverify', to: 'https://asteron-login.example/verify-now?u=staff&s=bulk', status: 302 },
    ],
    finalDomain: 'asteron-login.example',
    suspiciousParams: ['u', 's'],
    reputation: 'SUSPICIOUS',
    domainAge: 20,
    firstSeen: '2026-09-01',
    lastSeen: '2026-09-08',
    relatedEmail: 'ASTR-EMAIL-002',
    disclaimer: 'Simulated URL analysis for demo purposes only.',
  },
  {
    id: 'URL-AST-005',
    originalUrl: 'https://bit.ly/3Qexecdoc',
    domainIntel: {
      lookalikeOf: 'asteron.example',
      similarityScore: 90,
      registrar: 'Namecheap Inc.',
      hostingProvider: 'DigitalOcean LLC (SG)',
      country: 'Singapore',
      tlsInfo: {
        valid: true,
        issuer: "Let's Encrypt",
        expires: '2026-10-20',
      },
    },
    phishingIndicators: [
      'Lookalike domain (90% similarity to legitimate)',
      'Recently registered domain (14 days)',
      'URL shortener redirect detected',
      'Suspicious URL parameters detected',
      'Domain hosted on cloud infrastructure',
    ],
    recommendedAction: 'Block domain at mail gateway. Alert users not to interact with this URL. Investigate URL shortener usage.',
    extractedUrl: 'https://asteron-docs.example/board-review?token=abc123',
    shortenedUrl: 'https://bit.ly/3Qexecdoc',
    redirectChain: [
      { from: 'https://bit.ly/3Qexecdoc', to: 'https://asteron-docs.example/board-review?token=abc123', status: 302 },
    ],
    finalDomain: 'asteron-docs.example',
    suspiciousParams: ['token'],
    reputation: 'SUSPICIOUS',
    domainAge: 14,
    firstSeen: '2026-09-08',
    lastSeen: '2026-09-08',
    relatedEmail: 'ASTR-EMAIL-004',
    disclaimer: 'Simulated URL analysis for demo purposes only.',
  },
  {
    id: 'URL-AST-006',
    originalUrl: 'https://asteron-docs.example/board-review',
    domainIntel: {
      lookalikeOf: 'asteron.example',
      similarityScore: 90,
      registrar: 'Namecheap Inc.',
      hostingProvider: 'DigitalOcean LLC (SG)',
      country: 'Singapore',
      tlsInfo: {
        valid: true,
        issuer: "Let's Encrypt",
        expires: '2026-10-20',
      },
    },
    phishingIndicators: [
      'Lookalike domain (90% similarity to legitimate)',
      'Recently registered domain (14 days)',
      'Suspicious URL parameters detected',
      'Domain hosted on cloud infrastructure',
      'No prior reputation history',
    ],
    recommendedAction: 'Block domain at mail gateway. Alert users not to interact with this URL.',
    extractedUrl: 'https://asteron-docs.example/board-review',
    shortenedUrl: null,
    redirectChain: [
      { from: 'https://asteron-docs.example/board-review', to: 'https://asteron-docs.example/board-review', status: 200 },
    ],
    finalDomain: 'asteron-docs.example',
    suspiciousParams: ['token'],
    reputation: 'SUSPICIOUS',
    domainAge: 14,
    firstSeen: '2026-09-08',
    lastSeen: '2026-09-08',
    relatedEmail: 'ASTR-EMAIL-004',
    disclaimer: 'Simulated URL analysis for demo purposes only.',
  },
];

// ── Asteron Attachment Analysis ────────────────────────────────
export const asteronAttachmentAnalysis = [
  {
    id: 'ATT-AST-001',
    filename: 'HR_Policy_Update_Sept2026.docm',
    fileType: 'DOCM (Macro-Enabled Document)',
    size: '384 KB',
    sizeBytes: 393216,
    hash: 'e9a3f7c2d1b44e6855ab291c0f8e3d17492c1b8f5a2e0d9c6b4f3a7e8d1c059',
    sha256: 'e9a3f7c2d1b44e6855ab291c0f8e3d17492c1b8f5a2e0d9c6b4f3a7e8d1c059',
    macro: true,
    macroLanguage: 'VBA',
    macroDescription: 'AutoOpen macro that writes to the ActiveDocument and invokes a remote HTTP request.',
    scriptPresent: true,
    scriptLanguage: 'VBScript',
    sandbox: 'PENDING',
    sandboxResult: 'SUSPICIOUS',
    sandboxDetail: 'Macro payload present but not triggered. Static analysis confirms embedded VBA with network call capability.',
    risk: 'HIGH',
    riskScore: 82,
    recommendation: 'Do not open. Quarantine immediately. Submit to sandbox for full dynamic analysis.',
    emailId: 'ASTR-EMAIL-003',
    firstSeen: '2026-09-05',
    lastSeen: '2026-09-05',
    matchedTemplate: 'Macro delivery template — observed in CAMP-2026-014 and 2 prior campaigns',
    source: 'Asteron Mail Gateway',
    disclaimer: 'No macro execution was performed. All analysis is simulated for demo purposes only.',
  },
  {
    id: 'ATT-AST-002',
    filename: 'Vendor_Payment_Instructions_Aug2026.pdf',
    fileType: 'PDF',
    size: '142 KB',
    sizeBytes: 145408,
    hash: 'b3f8a1c2d1b44e6805f29ac73d6e1b58209c4d9afb3e1c28f7d6a4b5e0192837',
    sha256: 'b3f8a1c2d1b44e6805f29ac73d6e1b58209c4d9afb3e1c28f7d6a4b5e0192837',
    macro: false,
    macroLanguage: null,
    macroDescription: null,
    scriptPresent: false,
    scriptLanguage: null,
    sandbox: 'COMPLETE',
    sandboxResult: 'CLEAN',
    sandboxDetail: 'No malicious indicators detected in static or dynamic analysis.',
    risk: 'LOW',
    riskScore: 12,
    recommendation: 'No immediate action required. Monitor for delivery of follow-up messages.',
    emailId: 'ASTR-EMAIL-001',
    firstSeen: '2026-08-28',
    lastSeen: '2026-08-28',
    matchedTemplate: null,
    source: 'Asteron Mail Gateway',
    disclaimer: 'Simulated attachment analysis for demo purposes only.',
  },
];
