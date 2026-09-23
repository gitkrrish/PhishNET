import { ArrowRight, BookOpen, FileText, Lock, Shield, Sparkles } from 'lucide-react';
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

export function ProductPage() {
  return (
    <>
      <PageHeader title="Product" eyebrow="Platform" intro="PhishNet combines evidence-first analysis, relationship mapping, and security workflow support in a single interface for authorised investigation teams." />
      <PageBody>
        <div className="grid gap-6 md:grid-cols-3">
          {[
            { icon: FileText, title: 'Email Forensics', body: 'Inspect headers, relay chains, and trust signals with a workflow designed for investigators rather than generic threat feeds.' },
            { icon: Sparkles, title: 'AI-Assisted Correlation', body: 'Link indicators, domains, URLs, and exposure events without sacrificing auditability or evidential context.' },
            { icon: Shield, title: 'Operational Safety', body: 'Every report retains confidence, limitations, and a clear evidence trail while remaining restricted to authorised users.' },
          ].map(({ icon: Icon, title, body }) => (
            <div key={title} style={sectionCard}>
              <div className="w-10 h-10 rounded-sm border flex items-center justify-center mb-4" style={{ borderColor: 'var(--tw-border-strong)' }}>
                <Icon size={18} style={{ color: 'var(--tw-burgundy)' }} />
              </div>
              <h2 className="font-serif text-2xl mb-2" style={{ color: 'var(--tw-text)' }}>{title}</h2>
              <p className="text-sm leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>{body}</p>
            </div>
          ))}
        </div>
        <div className="mt-10 flex flex-wrap gap-3">{publicNavLink('/app/investigate', 'Open Investigate')}</div>
      </PageBody>
    </>
  );
}

export function FeaturesPage() {
  return (
    <>
      <PageHeader title="Features" eyebrow="What it does" intro="PhishNet is built to help analysts move from suspicious mail to defensible action with the evidence already in front of them." />
      <PageBody>
        <div className="grid gap-6 md:grid-cols-2">
          {[
            ['Header Reconstruction', 'Rebuild the message path and identify which sender-controlled fields differ from the actual delivery chain.'],
            ['Infrastructure Assessment', 'Evaluate IPs, hosting providers, and newly registered infrastructure with confidence and caveats.'],
            ['Campaign Mapping', 'Correlate domains, URLs, and exposures into a single narrative that connects evidence to likely activity.'],
            ['Evidence-led Reporting', 'Produce an investigation dossier that separates observed fact, assessment, and recommended response.'],
          ].map(([title, body]) => (
            <div key={title} style={sectionCard}>
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>Feature</p>
              <h2 className="font-serif text-2xl mt-3 mb-2" style={{ color: 'var(--tw-text)' }}>{title}</h2>
              <p className="text-sm leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>{body}</p>
            </div>
          ))}
        </div>
        <div className="mt-10 flex flex-wrap gap-3">{publicNavLink('/app/briefing', 'See the briefing')}</div>
      </PageBody>
    </>
  );
}

export function HowItWorksPage() {
  return (
    <>
      <PageHeader title="How It Works" eyebrow="Flow" intro="From raw message to evidence-backed response, PhishNet guides analysts through verification, correlation, and containment." />
      <PageBody>
        <div className="grid gap-6 md:grid-cols-5">
          {[
            ['01', 'Capture', 'Upload an email, paste headers, or select a sample.'],
            ['02', 'Verify', 'Check SPF, DKIM, DMARC, relay path, and sender indications.'],
            ['03', 'Trace', 'Follow infrastructure and malicious lookalike activity.'],
            ['04', 'Correlate', 'Connect evidence with exposure and campaign intelligence.'],
            ['05', 'Respond', 'Prepare action with clear evidence and audit-ready notes.'],
          ].map(([num, title, body]) => (
            <div key={num} style={sectionCard}>
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-burgundy)' }}>{num}</p>
              <h2 className="font-serif text-2xl mt-3 mb-2" style={{ color: 'var(--tw-text)' }}>{title}</h2>
              <p className="text-sm leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>{body}</p>
            </div>
          ))}
        </div>
        <div className="mt-10 flex flex-wrap gap-3">{publicNavLink('/app/investigate', 'Start a case')}</div>
      </PageBody>
    </>
  );
}

export function SecurityPage() {
  return (
    <>
      <PageHeader title="Security" eyebrow="Controls" intro="PhishNet is designed for authorised security operations. It enforces access boundaries, privacy-preserving data handling, and evidence integrity practices." />
      <PageBody>
        <div className="grid gap-6 md:grid-cols-2">
          {[
            ['Authorised access', 'The platform is restricted to named analysts and permitted operational roles.'],
            ['Evidence integrity', 'Each access and change is preserved in context without altering the original record.'],
            ['Privacy-preserving matching', 'Exposure monitoring works on correlated indicators without exposing raw plaintext secrets.'],
            ['Role-based controls', 'Reporting, investigation, and responder workflows can be restricted by role and approval stage.'],
          ].map(([title, body]) => (
            <div key={title} style={sectionCard}>
              <div className="w-10 h-10 rounded-sm border flex items-center justify-center mb-4" style={{ borderColor: 'var(--tw-border-strong)' }}>
                <Lock size={18} style={{ color: 'var(--tw-burgundy)' }} />
              </div>
              <h2 className="font-serif text-2xl mb-2" style={{ color: 'var(--tw-text)' }}>{title}</h2>
              <p className="text-sm leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>{body}</p>
            </div>
          ))}
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
      <PageHeader title="Privacy Policy" eyebrow="Legal" intro="PhishNet processes authorisation-bound threat data in support of security operations and evidence handling within controlled organisational environments." />
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
            Users must access PhishNet only under valid organisational authority and within the scope of their role. Information, email content, and related indicators are treated as sensitive operational data. Unauthorised access, misuse, or disclosure is prohibited and may trigger disciplinary or legal action. All use must comply with organisational policy and applicable law.
          </p>
        </div>
      </PageBody>
    </>
  );
}

export function DocumentationPage() {
  return (
    <>
      <PageHeader title="Documentation" eyebrow="Reference" intro="Reference material for the PhishNet workflow, controls, and evidence-handling standards used in security investigations." />
      <PageBody>
        <div className="grid gap-6 md:grid-cols-2">
          {[
            ['Investigation workflow', 'How to move from suspicious message intake to evidence-based decisioning.'],
            ['Evidence interpretation', 'How to read header analysis, relay metadata, and technical trust checks in context.'],
            ['Operating model', 'How analysts, reviewers, and responders coordinate under controlled approval conditions.'],
            ['Security controls', 'Role restrictions, retention practices, and encryption boundaries in the platform.'],
          ].map(([title, body]) => (
            <div key={title} style={sectionCard}>
              <div className="w-10 h-10 rounded-sm border flex items-center justify-center mb-4" style={{ borderColor: 'var(--tw-border-strong)' }}>
                <BookOpen size={18} style={{ color: 'var(--tw-burgundy)' }} />
              </div>
              <h2 className="font-serif text-2xl mb-2" style={{ color: 'var(--tw-text)' }}>{title}</h2>
              <p className="text-sm leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>{body}</p>
            </div>
          ))}
        </div>
      </PageBody>
    </>
  );
}

export function AuthorisedUsePolicyPage() {
  return (
    <>
      <PageHeader title="Authorised Use Policy" eyebrow="Compliance" intro="PhishNet exists to support authorised security investigation and response. It must not be used for general monitoring, personal surveillance, or non-approved activity." />
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
