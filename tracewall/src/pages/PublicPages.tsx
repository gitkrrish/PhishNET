import {
  ArrowRight, BookOpen, FileText, Lock, Shield, Sparkles,
  Users, Network, Database, Key, Server, Wallet, Globe, Fingerprint, Link2, Clock, BarChart3, FileSearch, Eye,
} from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { useState } from 'react';
import { signIn } from '../lib/mockBackend';

const pageShell = {
  maxWidth: '72rem',
  margin: '0 auto',
  padding: '5rem 1.5rem 6rem',
};

const sectionCard = {
  border: '1px solid var(--tw-border)',
  backgroundColor: 'var(--tw-panel)',
  borderRadius: '0.25rem',
  padding: '1.5rem',
};

function PageHeader({ title, eyebrow, intro }: { title: string; eyebrow: string; intro: string }) {
  return (
    <header style={pageShell}>
      <div style={{ maxWidth: '48rem' }}>
        <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>{eyebrow}</p>
        <h1 className="font-serif text-4xl md:text-5xl mt-4" style={{ color: 'var(--tw-text)' }}>{title}</h1>
        <p className="mt-4 text-base leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>{intro}</p>
      </div>
    </header>
  );
}

function PageBody({ children }: { children: React.ReactNode }) {
  return <div style={{ ...pageShell, paddingTop: 0 }}>{children}</div>;
}

function publicNavLink(to: string, label: string) {
  return (
    <Link to={to} className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border inline-flex items-center gap-2" style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text)' }}>
      {label} <ArrowRight size={12} />
    </Link>
  );
}

const ProductPillar = ({ icon: Icon, title, body }: { icon: typeof FileText; title: string; body: string }) => (
  <div style={sectionCard}>
    <div className="w-10 h-10 rounded-sm border flex items-center justify-center mb-4" style={{ borderColor: 'var(--tw-border-strong)' }}>
      <Icon size={18} style={{ color: 'var(--tw-burgundy)' }} />
    </div>
    <h2 className="font-serif text-2xl mb-2" style={{ color: 'var(--tw-text)' }}>{title}</h2>
    <p className="text-sm leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>{body}</p>
  </div>
);

const DetailCard = ({ eyebrow, title, body }: { eyebrow: string; title: string; body: string }) => (
  <div style={sectionCard}>
    <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>{eyebrow}</p>
    <h2 className="font-serif text-2xl mt-3 mb-2" style={{ color: 'var(--tw-text)' }}>{title}</h2>
    <p className="text-sm leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>{body}</p>
  </div>
);

const LockCard = ({ icon: Icon, title, body }: { icon: typeof Lock; title: string; body: string }) => (
  <div style={sectionCard}>
    <div className="w-10 h-10 rounded-sm border flex items-center justify-center mb-4" style={{ borderColor: 'var(--tw-border-strong)' }}>
      <Icon size={18} style={{ color: 'var(--tw-burgundy)' }} />
    </div>
    <h2 className="font-serif text-2xl mb-2" style={{ color: 'var(--tw-text)' }}>{title}</h2>
    <p className="text-sm leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>{body}</p>
  </div>
);

const SectionLabel = ({ children }: { children: React.ReactNode }) => (
  <p className="font-mono text-[10px] tracking-[0.2em] uppercase mt-14 mb-6" style={{ color: 'var(--tw-burgundy)' }}>{children}</p>
);

export function ProductPage() {
  return (
    <>
      <PageHeader
        title="Dark Web Threat Intelligence &amp; Investigation"
        eyebrow="Product"
        intro="Viper Trace is a Dark Web Threat Intelligence & Investigation Platform. It collects dark-web source intelligence, resolves it into threat actor entities, correlates identities and infrastructure across platforms, and carries every finding through to an evidence-backed investigation."
      />
      <PageBody>
        <div className="grid gap-6 md:grid-cols-3">
          <ProductPillar
            icon={Users}
            title="Threat Actor Intelligence"
            body="One resolved record per actor — aliases, handles, platforms, status, activity and confidence — assembled from every source that observed them, so an investigator starts from a person rather than from a list of alerts."
          />
          <ProductPillar
            icon={Network}
            title="Identity &amp; Indicator Correlation"
            body="Correlate handles and usernames across platforms, PGP fingerprints, cryptocurrency wallets, and hosting infrastructure. Every relationship is stored with its confidence, its supporting evidence and its counter-indicators."
          />
          <ProductPillar
            icon={Shield}
            title="Evidence-Backed Investigation"
            body="Each collection carries provenance, source reliability and timestamps. Investigations, analyst notes and reports are built from stored records, so an assessment can always be traced back to what was actually observed."
          />
        </div>

        <SectionLabel>Platform capabilities</SectionLabel>
        <div className="grid gap-6 md:grid-cols-3">
          <ProductPillar
            icon={Globe}
            title="Dark Web Source Collection"
            body="Register forums, marketplaces, paste sites, leak sites, messaging platforms, threat feeds and onion services. Each source carries a reliability score, activity level and collection status that feed every downstream confidence value."
          />
          <ProductPillar
            icon={Users}
            title="Threat Actor Profiles"
            body="Aliases, known handles, platforms, first and last seen, activity level, status, and the behavioural and stylometric profile derived from observed content."
          />
          <ProductPillar
            icon={Link2}
            title="Multi-Platform Identity Correlation"
            body="The same operator rarely reuses a handle. Cross-platform correlation links identities by normalised handle value, shared key material and shared indicators, and records the reasoning for every link."
          />
          <ProductPillar
            icon={Users}
            title="Handle &amp; Username Correlation"
            body="Handles are normalised before comparison, so case, padding and platform-specific formatting do not hide reuse. Each match is returned as a candidate with a similarity score, never as a silent assumption."
          />
          <ProductPillar
            icon={Key}
            title="PGP Key Correlation"
            body="Fingerprint reuse across actors is a high-value indicator and is recorded as an explicit relationship, alongside the counter-indicator that keys are copied and shared between collaborators."
          />
          <ProductPillar
            icon={Wallet}
            title="Cryptocurrency Wallet Correlation"
            body="Wallet addresses are normalised and compared across actors, with observation sources and transaction counts retained so a shared address can be weighed as evidence rather than proof."
          />
          <ProductPillar
            icon={Server}
            title="Infrastructure Correlation"
            body="Domains, hosts, certificates and address space are attributed to the actors that used them, and reused infrastructure is surfaced as shared-infrastructure relationships between those actors."
          />
          <ProductPillar
            icon={Globe}
            title="Clearnet–Dark Web Mapping"
            body="Map the clearnet presence associated with a dark-web actor — registered domains, hosting providers, certificates and network ownership — with the limits of inference stated for each mapping."
          />
          <ProductPillar
            icon={Link2}
            title="Persona Migration Detection"
            body="Detect an identity being abandoned and a new persona appearing, graded on shared keys, shared wallets, shared infrastructure and overlapping activity windows."
          />
          <ProductPillar
            icon={BarChart3}
            title="Behavioral Profiling"
            body="Posting cadence, active hours, platform preference and topic clusters build a behavioural profile that supports comparison between suspected personas."
          />
          <ProductPillar
            icon={Fingerprint}
            title="AI Stylometric Analysis"
            body="Sentence length, punctuation habits, capitalisation, vocabulary richness and recurring phrasing are compared between personas to assess whether the same writer is likely behind both."
          />
          <ProductPillar
            icon={Users}
            title="Entity Resolution"
            body="Handles, keys, wallets, hosts and evidence items are resolved to a single actor entity, so the same intelligence does not appear three times under three identifiers."
          />
          <ProductPillar
            icon={Network}
            title="Relationship Discovery"
            body="An interactive graph of every stored relationship between actors, identities, infrastructure and evidence, filterable by type and confidence."
          />
          <ProductPillar
            icon={Database}
            title="Evidence Collection"
            body="Posts, listings, leak records, messages, key material and infrastructure observations are retained with their source, timestamp, hash and reliability."
          />
          <ProductPillar
            icon={FileText}
            title="Investigation Management"
            body="Open an investigation against a seed actor, attach handles, keys, wallets, infrastructure, relationships and evidence, and keep the case history in one place."
          />
          <ProductPillar
            icon={BarChart3}
            title="Confidence Scoring"
            body="Actor confidence, relationship confidence and source reliability are stored on the records themselves, so a score is always traceable to the evidence behind it."
          />
          <ProductPillar
            icon={Eye}
            title="Explainable Attribution"
            body="Every link states why it exists: the shared indicators that produced it, the indicators that argue against it, and the records the explanation was computed from."
          />
          <ProductPillar
            icon={Sparkles}
            title="AI Investigation Assistant"
            body="Entity extraction, attribution suggestions and evidence synthesis run over the stored records. The assistant presents supporting indicators and confidence; it does not assert identity beyond the evidence."
          />
          <ProductPillar
            icon={Sparkles}
            title="Alerts"
            body="New actors, new handles, infrastructure changes, persona migrations and relationship changes raise alerts that name the actor, the supporting records and the confidence behind them."
          />
          <ProductPillar
            icon={FileText}
            title="Investigation Reports"
            body="Generate a numbered report that separates observed fact, correlated evidence, AI assessment and analyst conclusion, with the source references attached."
          />
        </div>

        <SectionLabel>Supporting analysis tools</SectionLabel>
        <div className="grid gap-6 md:grid-cols-2">
          {[
            ['Email Analyzer', 'Analyse suspicious emails, headers, authentication results and links when an investigation involves message-based delivery.'],
            ['File Analysis', 'Analyse files and attachments for malicious artifacts recovered during an investigation.'],
            ['URL Analysis', 'Analyse URLs, redirect chains and destination hosts observed in collected intelligence.'],
            ['Infrastructure Analysis', 'Enrich IP and domain indicators for attribution context.'],
          ].map(([title, body]) => (
            <DetailCard key={title} eyebrow="Supporting capability" title={title} body={body} />
          ))}
        </div>

        <div className="mt-10 flex flex-wrap gap-3">
          {publicNavLink('/app/darkweb', 'Open Dark Web Intelligence')}
          {publicNavLink('/app/darkweb/investigations', 'Start an investigation')}
        </div>
      </PageBody>
    </>
  );
}

export function FeaturesPage() {
  return (
    <>
      <PageHeader
        title="Dark Web Investigation Features"
        eyebrow="What it does"
        intro="Viper Trace is built for dark-web threat investigation: collect sources, resolve actors, correlate identities and infrastructure, and produce assessments an analyst can defend."
      />
      <PageBody>
        <div className="grid gap-6 md:grid-cols-2">
          {[
            ['Threat Actor Intelligence', 'A resolved record per actor — aliases, handles, platforms, status, activity level, first and last seen, and a confidence score derived from collected evidence.'],
            ['Dark Web Source Intelligence', 'Forums, marketplaces, paste sites, leak sites, messaging platforms, threat feeds and onion services, each with a reliability score, activity level and collection status.'],
            ['Identity Correlation', 'Correlate threat actor identities across dark-web platforms, resolving handles, cryptographic identities and payment identifiers to one entity.'],
            ['Handle Correlation', 'Normalise handles before comparison so case and platform formatting do not hide reuse, and return each match with a similarity score.'],
            ['PGP Correlation', 'Correlate PGP fingerprints, wallets, handles and infrastructure. A shared fingerprint is recorded as an explicit, evidence-backed relationship.'],
            ['Wallet Correlation', 'Correlate cryptocurrency wallet addresses across actors with observation sources retained, and weigh a shared address as evidence rather than proof.'],
            ['Infrastructure Correlation', 'Map dark-web and clearnet infrastructure associated with a threat actor — domains, hosts, certificates and address space.'],
            ['Relationship Graph', 'Explore every stored relationship between actors, handles, keys, wallets, infrastructure and evidence in an interactive graph.'],
            ['Persona Migration Detection', 'Detect an abandoned identity and a new persona appearing, graded on shared keys, wallets, infrastructure and activity overlap.'],
            ['Behavioral Analysis', 'Posting cadence, active hours, platform preference and topic clusters build a behavioural profile for comparison between personas.'],
            ['AI Stylometry', 'Compare sentence length, punctuation habits, capitalisation, vocabulary richness and recurring phrasing to assess whether one writer is behind two personas.'],
            ['Timeline Analysis', 'An ordered event history per actor and across the dataset — first seen, handle changes, infrastructure changes, persona migration and evidence collection.'],
            ['Entity Resolution', 'Resolve handles, keys, wallets, hosts and evidence items to a single actor entity so the same intelligence is not counted three times.'],
            ['Evidence Locker', 'Retain posts, listings, leak records, messages, key material and infrastructure observations with source, timestamp, hash and reliability.'],
            ['Explainable Attribution', 'Every relationship states why it exists, showing the shared indicators that produced it and the indicators that argue against it.'],
            ['Confidence Scoring', 'Actor confidence, relationship confidence and source reliability are stored on the records, so every score is traceable to its evidence.'],
            ['AI Investigation Assistant', 'Entity extraction, attribution suggestions and evidence synthesis over stored records, always showing its supporting indicators and limits.'],
            ['Autonomous Intelligence & Alerts', 'Detect new handles, new actors, infrastructure changes, persona migration and relationship changes, and raise an alert naming the supporting records.'],
            ['Investigation Management', 'Open a case against a seed actor, attach identities, infrastructure, relationships and evidence, and keep the investigation history in one place.'],
            ['Automated Reporting', 'Generate an evidence-backed report that separates observed fact, correlated evidence, AI assessment and analyst conclusion.'],
          ].map(([title, body]) => (
            <DetailCard key={title} eyebrow="Feature" title={title} body={body} />
          ))}
        </div>

        <SectionLabel>Supporting analysis tools</SectionLabel>
        <div className="grid gap-6 md:grid-cols-2">
          {[
            ['Email Analyzer', 'Message-level analysis available when an investigation involves email delivery.'],
            ['File Analysis', 'Artifact analysis for files recovered during an investigation.'],
            ['URL Analysis', 'Redirect chain and destination host analysis for observed URLs.'],
            ['Infrastructure Analysis', 'IP and domain enrichment for attribution context.'],
          ].map(([title, body]) => (
            <DetailCard key={title} eyebrow="Supporting capability" title={title} body={body} />
          ))}
        </div>

        <div className="mt-10 flex flex-wrap gap-3">
          {publicNavLink('/app/darkweb', 'Explore the intelligence model')}
          {publicNavLink('/app/briefing', 'See the briefing')}
        </div>
      </PageBody>
    </>
  );
}

export function HowItWorksPage() {
  return (
    <>
      <PageHeader
        title="A dark web investigation, end to end"
        eyebrow="How it works"
        intro="Viper Trace follows the investigator's path: dark web intelligence is collected, actors and identities are resolved, indicators are correlated, the result is analysed and verified, new activity is monitored, and the outcome is reported."
      />
      <PageBody>
        <p className="font-mono text-[10px] tracking-[0.2em] uppercase mb-6" style={{ color: 'var(--tw-text-muted)' }}>
          Dark web intelligence → correlation → analysis → investigation → evidence → alert → report
        </p>
        <div className="grid gap-6 md:grid-cols-4">
          {[
            ['01', 'Discover', 'Collect dark web intelligence and identify relevant sources, actors and indicators.'],
            ['02', 'Identify', 'Extract threat actors, handles, personas and entities from what was collected.'],
            ['03', 'Correlate', 'Connect handles, usernames, PGP fingerprints, wallets and infrastructure.'],
            ['04', 'Analyze', 'Analyse behavior, stylometry, activity patterns, timelines and anomalies.'],
            ['05', 'Investigate', 'Explore actor relationships, infrastructure relationships and network connections.'],
            ['06', 'Verify', 'Review evidence, source reliability, timestamps, provenance and cross-source corroboration.'],
            ['07', 'Monitor', 'Detect new handles, new actors, infrastructure changes, persona migration and relationship changes.'],
            ['08', 'Report', 'Generate evidence-backed investigation reports and intelligence summaries.'],
          ].map(([num, title, body]) => (
            <div key={num} style={sectionCard}>
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-burgundy)' }}>{num}</p>
              <h2 className="font-serif text-2xl mt-3 mb-2" style={{ color: 'var(--tw-text)' }}>{title}</h2>
              <p className="text-sm leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>{body}</p>
            </div>
          ))}
        </div>

        <SectionLabel>What each stage produces</SectionLabel>
        <div className="grid gap-6 md:grid-cols-3">
          <ProductPillar
            icon={Clock}
            title="A dated record"
            body="Collection timestamps and source reliability are captured with every observation, so a later conclusion can be checked against when and where it was seen."
          />
          <ProductPillar
            icon={Database}
            title="A resolvable entity"
            body="Handles, keys, wallets and hosts resolve to an actor, so the same identity is described once however many identifiers it uses."
          />
          <ProductPillar
            icon={FileText}
            title="A defensible conclusion"
            body="Confidence, supporting indicators and counter-indicators travel with the finding, so the report explains the assessment rather than only asserting it."
          />
        </div>

        <div className="mt-10 flex flex-wrap gap-3">
          {publicNavLink('/app/darkweb/investigations', 'Start an investigation')}
          {publicNavLink('/app/darkweb', 'Open Dark Web Intelligence')}
        </div>
      </PageBody>
    </>
  );
}

export function SecurityPage() {
  return (
    <>
      <PageHeader
        title="Security for dark web investigations"
        eyebrow="Controls"
        intro="A dark web intelligence platform holds sensitive, attributable data: threat actor records, investigation cases, evidence and analyst conclusions. Viper Trace protects that data with access boundaries, evidence integrity practices, and authorisation controls."
      />
      <PageBody>
        <div className="grid gap-6 md:grid-cols-2">
          <LockCard
            icon={Lock}
            title="Role-Based Access Control"
            body="Administrator, analyst, investigator, viewer and auditor roles, with permissions applied per module rather than granted platform-wide."
          />
          <LockCard
            icon={Users}
            title="Analyst Permissions"
            body="Recording intelligence, opening investigations, attaching evidence and generating reports are distinct permissions — read access to intelligence does not imply write access."
          />
          <LockCard
            icon={FileSearch}
            title="Investigation Access Control"
            body="Investigation cases, their attached evidence and their analyst notes are scoped to the case team, so unrelated cases cannot be browsed from a single workspace."
          />
          <LockCard
            icon={Shield}
            title="Evidence Integrity"
            body="Collected evidence is never edited in place. Corrections are added as new records, and the original observation remains readable exactly as it was captured."
          />
          <LockCard
            icon={Fingerprint}
            title="Evidence Hashing"
            body="Each evidence item carries a content hash so an analyst can confirm that the material being reviewed is the material that was collected."
          />
          <LockCard
            icon={Link2}
            title="Evidence Provenance"
            body="Every record states which source it came from, how it entered the model — observed, imported, analyst-added or AI-derived — and which analyst recorded it."
          />
          <LockCard
            icon={Clock}
            title="Source Timestamping"
            body="Collection and observation timestamps are retained separately from ingestion time, so a later report can distinguish when something was seen from when it was recorded."
          />
          <LockCard
            icon={BookOpen}
            title="Audit Logging"
            body="Every write, correlation, investigation change and export produces an audit event naming the actor, the entity, the change and the outcome."
          />
          <LockCard
            icon={Database}
            title="Data Validation"
            body="Records are validated and normalised on write. Identifiers are resolved against existing records, and duplicate candidates are surfaced to the analyst rather than silently merged."
          />
          <LockCard
            icon={FileText}
            title="Input Validation"
            body="Analyst-supplied fields — handles, fingerprints, addresses, domains, titles and pasted intelligence — are checked and normalised before they enter the model."
          />
          <LockCard
            icon={Lock}
            title="Secure Data Handling"
            body="Intelligence is held within the authorised environment, with retention controls and separation between collected data, analyst assessment and exported reports."
          />
          <LockCard
            icon={Eye}
            title="Privacy-Preserving Analysis"
            body="Exposure matching operates on correlated indicators rather than stored plaintext secrets, and credential material is redacted wherever it is displayed or reported."
          />
          <LockCard
            icon={Network}
            title="Secure API Architecture"
            body="The intelligence model is served through a single validated API layer, so access control, validation and audit behaviour are consistent across every module."
          />
          <LockCard
            icon={Shield}
            title="Administrative Controls"
            body="Source registration, collection status, retention settings and role assignment remain under administrative control and are themselves audited."
          />
          <LockCard
            icon={Globe}
            title="Authorised-Use Controls"
            body="Collection is restricted to verified organisational assets and approved sources. Individual private persons are not tracked without authorisation, and misuse is prohibited."
          />
          <LockCard
            icon={Users}
            title="Threat Actor Data Protection"
            body="Actor records, correlation results, investigation history and intelligence reports are treated as sensitive operational data with access limited to the assigned mission."
          />
        </div>
      </PageBody>
    </>
  );
}

export function SignInPage() {
  const navigate = useNavigate();
  const [email, setEmail] = useState('analyst@tracewall.demo');
  const [password, setPassword] = useState('demo-password');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError('');
    try {
      await signIn(email, password);
      navigate('/app/briefing');
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Unable to sign in');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <PageHeader title="Sign In" eyebrow="Access" intro="Authenticate to continue into the operations workspace and review the current security posture." />
      <PageBody>
        <div className="max-w-xl rounded-sm border p-8" style={sectionCard}>
          <form className="space-y-5" onSubmit={handleSubmit}>
            <div>
              <label className="block font-mono text-[10px] tracking-[0.2em] uppercase mb-2" style={{ color: 'var(--tw-text-muted)' }}>Email</label>
              <input value={email} onChange={event => setEmail(event.target.value)} className="w-full rounded-sm border px-3 py-2" style={{ borderColor: 'var(--tw-border)', backgroundColor: 'var(--tw-panel-alt)', color: 'var(--tw-text)' }} />
            </div>
            <div>
              <label className="block font-mono text-[10px] tracking-[0.2em] uppercase mb-2" style={{ color: 'var(--tw-text-muted)' }}>Password</label>
              <input type="password" value={password} onChange={event => setPassword(event.target.value)} className="w-full rounded-sm border px-3 py-2" style={{ borderColor: 'var(--tw-border)', backgroundColor: 'var(--tw-panel-alt)', color: 'var(--tw-text)' }} />
            </div>
            {error && <p className="text-sm" style={{ color: 'var(--tw-critical)' }}>{error}</p>}
            <div className="flex items-center justify-between gap-3">
              <Link to="/" className="font-sans text-sm" style={{ color: 'var(--tw-text-muted)' }}>Back to home</Link>
              <button type="submit" disabled={submitting} className="font-mono text-xs tracking-widest uppercase px-5 py-3 rounded-sm inline-flex items-center gap-2" style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}>
                {submitting ? 'Signing In...' : 'Continue'} <ArrowRight size={12} />
              </button>
            </div>
          </form>
        </div>
      </PageBody>
    </>
  );
}

export function PrivacyPolicyPage() {
  return (
    <>
      <PageHeader title="Privacy Policy" eyebrow="Legal" intro="Viper Trace processes authorisation-bound threat data in support of security operations and evidence handling within controlled organisational environments." />
      <PageBody>
        <div style={sectionCard}>
          <p className="text-sm leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>
            Personal data is limited to the minimum required for authorised security operations. Plaintext credentials are never retained for general viewing and are redacted in reporting interfaces. Access is only granted to authorised personnel operating within assigned workflows. Systems are configured to support operational necessity while preserving accountability, retention controls, and auditability.
          </p>
        </div>
      </PageBody>
    </>
  );
}

export function TermsOfUsePage() {
  return (
    <>
      <PageHeader title="Terms of Use" eyebrow="Legal" intro="The platform is intended for authorised security teams investigating approved organisational incidents and evidence sets." />
      <PageBody>
        <div style={sectionCard}>
          <p className="text-sm leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>
            Users must access Viper Trace only under valid organisational authority and within the scope of their role. Collected dark web intelligence, actor records, evidence and analysis output are treated as sensitive operational data. Unauthorised access, misuse, or disclosure is prohibited and may trigger disciplinary or legal action. All use must comply with organisational policy and applicable law.
          </p>
        </div>
      </PageBody>
    </>
  );
}

export function DocumentationPage() {
  return (
    <>
      <PageHeader title="Documentation" eyebrow="Reference" intro="Reference material for the Viper Trace workflow, controls, and evidence-handling standards used in dark web threat investigations." />
      <PageBody>
        <div className="grid gap-6 md:grid-cols-2">
          {[
            ['Investigation workflow', 'How to move from dark web collection to a defensible, evidence-backed investigation.'],
            ['Correlation interpretation', 'How to read handle, PGP, wallet and infrastructure correlation, including confidence and counter-indicators.'],
            ['Operating model', 'How analysts, reviewers, and responders coordinate under controlled approval conditions.'],
            ['Security controls', 'Role restrictions, retention practices, and evidence integrity boundaries in the platform.'],
          ].map(([title, body]) => (
            <LockCard key={title} icon={BookOpen} title={title} body={body} />
          ))}
        </div>
      </PageBody>
    </>
  );
}

export function AuthorisedUsePolicyPage() {
  return (
    <>
      <PageHeader title="Authorised Use Policy" eyebrow="Compliance" intro="Viper Trace exists to support authorised security investigation and response. It must not be used for general monitoring, personal surveillance, or non-approved activity." />
      <PageBody>
        <div style={sectionCard}>
          <p className="text-sm leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>
            This environment is restricted to approved security personnel and authorised incident-response responsibilities. System users are expected to operate within the scope of their assigned mission, preserve data minimisation principles, and comply with approvals for any external sharing or disclosure. Demonstration content remains fictional and does not represent real-world infrastructure or parties.
          </p>
        </div>
      </PageBody>
    </>
  );
}

export const pageList = {
  ProductPage,
  FeaturesPage,
  HowItWorksPage,
  SecurityPage,
  SignInPage,
  PrivacyPolicyPage,
  TermsOfUsePage,
  DocumentationPage,
  AuthorisedUsePolicyPage,
};

