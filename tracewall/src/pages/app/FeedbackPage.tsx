import { useState, useEffect, useCallback, type ReactNode } from 'react';
import { tv } from '../../lib/styles';
import { DemoLabel } from '../../components/ui/DemoLabel';
import {
  submitFeedback,
  searchFeedback,
  listFeedback,
  listFeedbackCategories,
  moderateFeedback,
  type FeedbackRecord,
} from '../../lib/mockBackend';
import {
  MessageSquare,
  Search,
  Plus,
  Send,
  CheckCircle,
  AlertTriangle,
  Shield,
  Filter,
  Clock,
  Brain,
  Users,
  EyeOff,
  ShieldAlert,
} from 'lucide-react';

const FALLBACK_CATEGORIES = [
  'Cybercrime Incident',
  'Phishing',
  'Scam/Fraud',
  'Malware',
  'Ransomware',
  'Account Compromise',
  'Social Engineering',
  'Suspicious Email',
  'Suspicious Domain',
  'Suspicious IP',
  'Vulnerability/Weakness',
  'Security Solution',
  'Prevention Tip',
  'General Security Experience',
  'Other',
];

type Tab = 'browse' | 'submit' | 'moderation' | 'knowledge';

interface FormState {
  title: string;
  category: string;
  description: string;
  whatHappened: string;
  indicators: string[];
  impact: string;
  solution: string;
  prevention: string;
  technicalIndicators: string[];
  involvesCybercrime: boolean;
}

const EMPTY_FORM: FormState = {
  title: '',
  category: FALLBACK_CATEGORIES[0],
  description: '',
  whatHappened: '',
  indicators: [],
  impact: '',
  solution: '',
  prevention: '',
  technicalIndicators: [],
  involvesCybercrime: false,
};

const CATEGORY_ICONS: Record<string, typeof Search> = {
  Phishing: ShieldAlert,
  'Cybercrime Incident': ShieldAlert,
  Malware: ShieldAlert,
};

function TagInput({
  label,
  values,
  placeholder,
  onAdd,
  onRemove,
}: {
  label: string;
  values: string[];
  placeholder: string;
  onAdd: (value: string) => void;
  onRemove: (index: number) => void;
}) {
  const [value, setValue] = useState('');
  const add = () => {
    const trimmed = value.trim();
    if (trimmed && !values.includes(trimmed)) onAdd(trimmed);
    setValue('');
  };
  return (
    <div className="space-y-2">
      <label className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>
        {label}
      </label>
      <div className="flex gap-2">
        <input
          type="text"
          value={value}
          onChange={e => setValue(e.target.value)}
          onKeyDown={e => {
            if (e.key === 'Enter') {
              e.preventDefault();
              add();
            }
          }}
          placeholder={placeholder}
          className="flex-1 font-mono text-xs px-3 py-2 rounded-sm focus:outline-none placeholder:opacity-40"
          style={tv.input}
        />
        <button
          type="button"
          onClick={add}
          className="font-mono text-xs px-3 py-2 rounded-sm border transition-colors flex items-center gap-1"
          style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
        >
          <Plus size={11} /> Add
        </button>
      </div>
      {values.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {values.map((v, i) => (
            <span
              key={i}
              className="font-mono text-[10px] px-2 py-1 rounded-sm border flex items-center gap-1"
              style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}
            >
              {v}
              <button type="button" onClick={() => onRemove(i)} className="hover:text-[var(--tw-critical)]">
                ×
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function Field({
  label,
  required,
  children,
}: {
  label: string;
  required?: boolean;
  children: ReactNode;
}) {
  return (
    <div className="space-y-2">
      <label className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>
        {label}
        {required && <span style={{ color: 'var(--tw-critical)' }}> *</span>}
      </label>
      {children}
    </div>
  );
}

export default function FeedbackPage() {
  const [tab, setTab] = useState<Tab>('browse');
  const [categories, setCategories] = useState<string[]>(FALLBACK_CATEGORIES);
  const [browseFeed, setBrowseFeed] = useState<FeedbackRecord[]>([]);
  const [browseLoading, setBrowseLoading] = useState(true);
  const [browseError, setBrowseError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');

  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [submitResult, setSubmitResult] = useState<FeedbackRecord | null>(null);

  const [pendingFeed, setPendingFeed] = useState<FeedbackRecord[]>([]);
  const [pendingLoading, setPendingLoading] = useState(false);
  const [moderateNote, setModerateNote] = useState('');
  const [modAction, setModAction] = useState<{ id: string; status: string; error?: string } | null>(null);

  const loadBrowse = useCallback(async () => {
    setBrowseLoading(true);
    setBrowseError(null);
    try {
      const data = await searchFeedback({ q: query || undefined, category: categoryFilter || undefined });
      setBrowseFeed(data);
    } catch (e) {
      setBrowseError(e instanceof Error ? e.message : 'Failed to load community feedback');
    } finally {
      setBrowseLoading(false);
    }
  }, [query, categoryFilter]);

  useEffect(() => {
    listFeedbackCategories().then(setCategories).catch(() => setCategories(FALLBACK_CATEGORIES));
  }, []);

  useEffect(() => {
    if (tab === 'browse') loadBrowse();
  }, [tab, loadBrowse]);

  const loadPending = useCallback(async () => {
    setPendingLoading(true);
    try {
      const data = await listFeedback({ status: 'PENDING' });
      setPendingFeed(data);
    } catch {
      setPendingFeed([]);
    } finally {
      setPendingLoading(false);
    }
  }, []);

  useEffect(() => {
    if (tab === 'moderation') loadPending();
  }, [tab, loadPending]);

  const setField = (field: keyof FormState, value: unknown) =>
    setForm(prev => ({ ...prev, [field]: value }));

  const updateTags = (field: 'indicators' | 'technicalIndicators', values: string[]) =>
    setForm(prev => ({ ...prev, [field]: values }));

  const submit = async () => {
    if (!form.title.trim()) {
      setFormError('A title is required.');
      return;
    }
    if (form.title.trim().length > 200) {
      setFormError('Title is too long (max 200 characters).');
      return;
    }
    setFormError(null);
    setSubmitting(true);
    setSubmitResult(null);
    try {
      const created = await submitFeedback({
        title: form.title,
        category: form.category,
        description: form.description,
        whatHappened: form.whatHappened,
        indicators: form.indicators,
        impact: form.impact,
        solution: form.solution,
        prevention: form.prevention,
        technicalIndicators: form.technicalIndicators,
        involvesCybercrime: form.involvesCybercrime,
      });
      setSubmitResult(created);
      setForm(EMPTY_FORM);
    } catch (e) {
      setFormError(e instanceof Error ? e.message : 'Submission failed. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  const moderate = async (id: string, status: string) => {
    setModAction({ id, status });
    try {
      await moderateFeedback(id, { status, note: moderateNote || undefined });
      setModerateNote('');
      setPendingFeed(prev => prev.filter(item => item.id !== id));
      loadBrowse();
    } catch (e) {
      setModAction({ id, status, error: e instanceof Error ? e.message : 'Moderation action failed' });
    }
  };

  const resetForm = () => {
    setForm(EMPTY_FORM);
    setSubmitResult(null);
    setFormError(null);
  };

  const tabs: Array<{ id: Tab; label: string; icon: typeof Search }> = [
    { id: 'browse', label: 'Browse Community', icon: Users },
    { id: 'submit', label: 'Submit Feedback', icon: MessageSquare },
    { id: 'moderation', label: 'Moderation Queue', icon: ShieldAlert },
    { id: 'knowledge', label: 'AI Knowledge', icon: Brain },
  ];

  return (
    <div className="min-h-screen" style={tv.canvas}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        {/* Header */}
        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>AI Feedback</p>
            <DemoLabel />
          </div>
          <h1 className="font-serif text-3xl" style={tv.text}>AI Feedback</h1>
          <p className="text-sm max-w-2xl leading-relaxed" style={tv.muted}>
            Share real cybersecurity experiences — problems, incidents, suspicious messages, scrapes,
            solutions and prevention lessons — so other users can learn from them and avoid similar attacks.
          </p>
        </div>

        {/* Tab navigation */}
        <div className="flex flex-wrap items-center gap-1 rounded-sm border p-1" style={{ borderColor: 'var(--tw-border)', backgroundColor: 'var(--tw-panel)' }}>
          {tabs.map(t => {
            const Icon = t.icon;
            const active = tab === t.id;
            return (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className="font-mono text-xs px-3 py-1.5 rounded-sm transition-colors flex items-center gap-1.5"
                style={{
                  backgroundColor: active ? 'var(--tw-burgundy)' : 'transparent',
                  color: active ? '#FBFAF6' : 'var(--tw-text-muted)',
                }}
              >
                <Icon size={11} />
                {t.label}
              </button>
            );
          })}
        </div>

        {/* ── BROWSE COMMUNITY ───────────────────────────────────── */}
        {tab === 'browse' && (
          <div className="space-y-6">
            <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
              <div className="px-5 py-3 border-b flex flex-col md:flex-row md:items-center md:justify-between gap-3" style={{ borderColor: 'var(--tw-border-mid)' }}>
                <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>
                  Approved Community Knowledge
                  <span className="ml-2 normal-case tracking-normal" style={{ color: 'var(--tw-text-faint)' }}>
                    (sanitized · anonymized · moderation-approved)
                  </span>
                </p>
                <div className="flex items-center gap-2">
                  <div className="flex items-center gap-2 flex-1 md:w-64">
                    <Search size={13} style={tv.faint} />
                    <input
                      type="text"
                      value={query}
                      onChange={e => setQuery(e.target.value)}
                      placeholder="Search lessons, indicators, solutions…"
                      className="w-full font-mono text-xs px-2 py-1.5 rounded-sm focus:outline-none placeholder:opacity-40 bg-transparent"
                      style={{ color: 'var(--tw-text)' }}
                    />
                  </div>
                  <button
                    onClick={loadBrowse}
                    className="font-mono text-[10px] px-3 py-1.5 rounded-sm border transition-colors"
                    style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
                  >
                    Search
                  </button>
                </div>
              </div>

              <div className="px-5 py-3 border-b flex flex-wrap items-center gap-2" style={{ borderColor: 'var(--tw-border-mid)' }}>
                <Filter size={11} style={tv.faint} />
                {['', ...categories].map(cat => (
                  <button
                    key={cat || 'all'}
                    onClick={() => setCategoryFilter(cat)}
                    className="font-mono text-[10px] px-2 py-0.5 rounded-sm border transition-colors"
                    style={
                      categoryFilter === cat
                        ? { backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6', borderColor: 'var(--tw-burgundy)' }
                        : { borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }
                    }
                  >
                    {cat || 'All'}
                  </button>
                ))}
              </div>
            </div>

            {browseLoading ? (
              <div className="rounded-sm p-10 text-center" style={tv.panelBorder}>
                <div className="inline-flex items-center gap-2 font-mono text-xs" style={tv.muted}>
                  <Clock size={13} className="animate-spin" style={{ color: 'var(--tw-burgundy)' }} />
                  Loading community knowledge…
                </div>
              </div>
            ) : browseError ? (
              <div className="rounded-sm p-10 text-center space-y-3" style={tv.panelBorder}>
                <AlertTriangle size={28} className="mx-auto" style={{ color: 'var(--tw-medium)' }} />
                <p className="font-mono text-sm" style={tv.muted}>{browseError}</p>
                <p className="text-xs" style={tv.faint}>
                  Make sure the PhishNet backend is running (<span className="font-mono">npm run api</span>).
                </p>
              </div>
            ) : browseFeed.length === 0 ? (
              <div className="rounded-sm p-10 text-center space-y-3" style={tv.panelBorder}>
                <Users size={28} className="mx-auto" style={tv.faint} />
                <p className="font-mono text-sm" style={tv.muted}>No approved community knowledge yet.</p>
                <p className="text-xs max-w-md mx-auto leading-relaxed" style={tv.faint}>
                  Be the first to share a real cybersecurity experience. Submitted feedback becomes
                  searchable knowledge only after validation and privacy protection.
                </p>
                <button
                  onClick={() => setTab('submit')}
                  className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                  style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
                >
                  Share Feedback
                </button>
              </div>
            ) : (
              <div className="space-y-4">
                {browseFeed.map(item => {
                  const k = (item.knowledgeView as Record<string, unknown> | undefined) || item;
                  const Icon = CATEGORY_ICONS[item.category] || Shield;
                  return (
                    <div key={item.id} className="rounded-sm overflow-hidden" style={tv.panelBorder}>
                      <div className="px-5 py-4 border-b flex items-start justify-between gap-3" style={{ borderColor: 'var(--tw-border-mid)' }}>
                        <div className="space-y-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            <Icon size={12} style={{ color: 'var(--tw-burgundy)' }} />
                            <span className="font-mono text-[10px] px-2 py-0.5 rounded-sm"
                              style={{ backgroundColor: 'var(--tw-panel-alt)', color: 'var(--tw-text-muted)' }}>
                              {item.category}
                            </span>
                            <span className="font-mono text-[10px] px-2 py-0.5 rounded-sm border tracking-widest uppercase"
                              style={{ color: 'var(--tw-low)', borderColor: 'color-mix(in srgb, var(--tw-low) 35%, transparent)', backgroundColor: 'color-mix(in srgb, var(--tw-low) 18%, transparent)' }}>
                              Approved
                            </span>
                          </div>
                          <h3 className="font-serif text-xl" style={tv.text}>{k.title as string}</h3>
                          <p className="font-mono text-[10px]" style={tv.faint}>{item.id}</p>
                        </div>
                        {item.involvesCybercrime && (
                          <span className="font-mono text-[9px] px-2 py-0.5 rounded-sm border shrink-0" style={{
                            color: 'var(--tw-high)', borderColor: 'color-mix(in srgb, var(--tw-high) 40%, transparent)',
                          }}>
                            Cybercrime involvement
                          </span>
                        )}
                      </div>
                      <div className="p-5 space-y-4">
                        {(k.description as string) && (
                          <p className="text-sm leading-relaxed" style={tv.muted}>{k.description as string}</p>
                        )}
                        {(k.whatHappened as string) && (
                          <div className="space-y-1">
                            <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.faint}>What happened</p>
                            <p className="text-sm leading-relaxed" style={tv.text}>{k.whatHappened as string}</p>
                          </div>
                        )}
                        {Array.isArray(k.indicators) && (k.indicators as string[]).length > 0 && (
                          <div className="space-y-1.5">
                            <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.faint}>Indicators / observations</p>
                            <div className="flex flex-wrap gap-1.5">
                              {k.indicators.map((ind, i) => (
                                <span key={i} className="font-mono text-[10px] px-2 py-0.5 rounded-sm"
                                  style={{ backgroundColor: 'var(--tw-panel-inset)', color: 'var(--tw-text-muted)' }}>
                                  {ind}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                        <div className="grid md:grid-cols-2 gap-4 pt-1">
                          {(k.solution as string) && (
                            <div className="space-y-1">
                              <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.faint}>Solution / recovery</p>
                              <p className="text-xs leading-relaxed" style={tv.muted}>{k.solution as string}</p>
                            </div>
                          )}
                          {(k.prevention as string) && (
                            <div className="space-y-1">
                              <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.faint}>Prevention advice</p>
                              <p className="text-xs leading-relaxed" style={tv.muted}>{k.prevention as string}</p>
                            </div>
                          )}
                        </div>
                        {(k.impact as string) && (
                          <p className="text-xs" style={tv.faint}>Impact: {k.impact as string}</p>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* ── SUBMIT FEEDBACK ────────────────────────────────────── */}
        {tab === 'submit' && (
          <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
            <div className="px-5 py-3 border-b flex items-center justify-between" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Submit Cybersecurity Feedback</p>
            </div>

            <div className="p-5 space-y-5" style={{ backgroundColor: 'var(--tw-panel-alt)' }}>
              {submitResult ? (
                <div className="rounded-sm p-5 border space-y-4"
                  style={{ borderColor: 'color-mix(in srgb, var(--tw-moss) 50%, transparent)', backgroundColor: 'color-mix(in srgb, var(--tw-moss) 12%, transparent)' }}>
                  <div className="flex items-start gap-3">
                    <CheckCircle size={18} className="mt-0.5 shrink-0" style={{ color: 'var(--tw-low)' }} />
                    <div className="space-y-1">
                      <p className="font-mono text-sm" style={tv.text}>Feedback submitted successfully.</p>
                      <p className="text-sm" style={tv.muted}>
                        Your submission is <span className="font-mono" style={{ color: 'var(--tw-medium)' }}>PENDING</span> moderation.
                        It will be reviewed, sanitized and anonymized before it can appear in the community knowledge base.
                      </p>
                      <p className="font-mono text-[10px]" style={tv.faint}>Submission ID: {submitResult.id}</p>
                      <p className="font-mono text-[10px]" style={tv.faint}>
                        Category: {submitResult.category} · Submitted: {new Date(submitResult.createdAt).toLocaleString()}
                      </p>
                    </div>
                  </div>

                  {submitResult.redactionReport && submitResult.redactionReport.length > 0 && (
                    <div className="space-y-1.5">
                      <p className="font-mono text-[10px] uppercase tracking-wider" style={{ color: 'var(--tw-medium)' }}>
                        Privacy protection applied
                      </p>
                      {submitResult.redactionReport.map((entry, i) => (
                        <div key={i} className="font-mono text-[10px] flex flex-wrap gap-3" style={tv.muted}>
                          <span>{entry.field}</span>
                          {entry.findings.map((f, j) => (
                            <span key={j} style={{ color: 'var(--tw-wine)' }}>
                              {f.name} × {f.count}
                            </span>
                          ))}
                        </div>
                      ))}
                      <p className="text-xs pt-1 leading-relaxed" style={tv.faint}>
                        Sensitive values (credentials, contact details, etc.) were removed before storage.
                      </p>
                    </div>
                  )}

                  <div className="pt-1">
                    <button
                      onClick={resetForm}
                      className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                      style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
                    >
                      Submit Another
                    </button>
                  </div>
                </div>
              ) : (
                <div className="space-y-5">
                  <div className="grid md:grid-cols-2 gap-5">
                    <Field label="Category" required>
                      <select
                        value={form.category}
                        onChange={e => setField('category', e.target.value)}
                        className="w-full font-mono text-xs px-3 py-2 rounded-sm focus:outline-none"
                        style={tv.input}
                      >
                        {categories.map(c => (
                          <option key={c} value={c}>{c}</option>
                        ))}
                      </select>
                    </Field>
                    <Field label="Title" required>
                      <input
                        type="text"
                        value={form.title}
                        onChange={e => setField('title', e.target.value)}
                        placeholder="e.g., Fake Microsoft login page phishing email"
                        maxLength={200}
                        className="w-full font-mono text-xs px-3 py-2 rounded-sm focus:outline-none placeholder:opacity-40"
                        style={tv.input}
                      />
                    </Field>
                  </div>

                  <Field label="Summary / Description">
                    <textarea
                      value={form.description}
                      onChange={e => setField('description', e.target.value)}
                      rows={2}
                      placeholder="Short overview of the experience…"
                      className="w-full font-mono text-xs px-3 py-2 rounded-sm focus:outline-none placeholder:opacity-40 resize-none"
                      style={tv.input}
                    />
                  </Field>

                  <Field label="What happened">
                    <textarea
                      value={form.whatHappened}
                      onChange={e => setField('whatHappened', e.target.value)}
                      rows={4}
                      placeholder="How the attack started, what indicators were observed, what damage or risk was involved…"
                      className="w-full font-mono text-xs px-3 py-2 rounded-sm focus:outline-none placeholder:opacity-40 resize-none"
                      style={tv.input}
                    />
                  </Field>

                  <div className="grid md:grid-cols-2 gap-5">
                    <TagInput
                      label="Indicators / observations"
                      values={form.indicators}
                      placeholder="e.g., suspicious domain, sender address, phrase…"
                      onAdd={v => updateTags('indicators', [...form.indicators, v])}
                      onRemove={i => updateTags('indicators', form.indicators.filter((_, idx) => idx !== i))}
                    />
                    <TagInput
                      label="Technical indicators (optional)"
                      values={form.technicalIndicators}
                      placeholder="e.g., IP, domain, URL, hash…"
                      onAdd={v => updateTags('technicalIndicators', [...form.technicalIndicators, v])}
                      onRemove={i => updateTags('technicalIndicators', form.technicalIndicators.filter((_, idx) => idx !== i))}
                    />
                  </div>

                  <Field label="Impact">
                    <textarea
                      value={form.impact}
                      onChange={e => setField('impact', e.target.value)}
                      rows={2}
                      placeholder="What was at risk or affected…"
                      className="w-full font-mono text-xs px-3 py-2 rounded-sm focus:outline-none placeholder:opacity-40 resize-none"
                      style={tv.input}
                    />
                  </Field>

                  <div className="grid md:grid-cols-2 gap-5">
                    <Field label="Solution / recovery">
                      <textarea
                        value={form.solution}
                        onChange={e => setField('solution', e.target.value)}
                        rows={3}
                        placeholder="What worked to resolve or recover…"
                        className="w-full font-mono text-xs px-3 py-2 rounded-sm focus:outline-none placeholder:opacity-40 resize-none"
                        style={tv.input}
                      />
                    </Field>
                    <Field label="Prevention advice">
                      <textarea
                        value={form.prevention}
                        onChange={e => setField('prevention', e.target.value)}
                        rows={3}
                        placeholder="What should others watch for and avoid…"
                        className="w-full font-mono text-xs px-3 py-2 rounded-sm focus:outline-none placeholder:opacity-40 resize-none"
                        style={tv.input}
                      />
                    </Field>
                  </div>

                  <label className="flex items-start gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={form.involvesCybercrime}
                      onChange={e => setField('involvesCybercrime', e.target.checked)}
                      className="mt-0.5"
                      style={{ accentColor: 'var(--tw-burgundy)' }}
                    />
                    <span className="text-xs leading-relaxed" style={tv.muted}>
                      This experience involved a cybercrime incident (e.g., a phishing attack, scam, or account compromise).
                    </span>
                  </label>

                  <div className="rounded-sm p-4 border space-y-1.5" style={{ borderColor: 'var(--tw-border-mid)', backgroundColor: 'var(--tw-panel)' }}>
                    <p className="font-mono text-[10px] uppercase tracking-wider flex items-center gap-1.5" style={tv.medium}>
                      <ShieldAlert size={11} /> Important: community knowledge, not official reporting
                    </p>
                    <p className="text-xs leading-relaxed" style={tv.muted}>
                      AI Feedback is a community knowledge-sharing platform. Submitting feedback here does
                      <span className="font-mono" style={{ color: 'var(--tw-critical)' }}> NOT </span>
                      automatically report an incident to police, CERT, banks, or other authorities. For official
                      reporting, contact your local law-enforcement agency or national CERT directly.
                    </p>
                  </div>

                  {formError && (
                    <div className="rounded-sm p-3 border flex items-start gap-2"
                      style={{ borderColor: 'color-mix(in srgb, var(--tw-critical) 40%, transparent)', backgroundColor: 'color-mix(in srgb, var(--tw-critical) 12%, transparent)' }}>
                      <AlertTriangle size={14} className="mt-0.5 shrink-0" style={{ color: 'var(--tw-critical)' }} />
                      <p className="text-xs" style={tv.text}>{formError}</p>
                    </div>
                  )}

                  <div className="flex gap-2">
                    <button
                      onClick={submit}
                      disabled={submitting || !form.title.trim()}
                      className="flex-1 font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm transition-colors disabled:opacity-40 flex items-center justify-center gap-2"
                      style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
                    >
                      <Send size={12} />
                      {submitting ? 'Submitting…' : 'Submit Feedback'}
                    </button>
                    <button
                      onClick={resetForm}
                      className="font-mono text-xs tracking-widest uppercase px-4 py-2 rounded-sm border transition-colors"
                      style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
                    >
                      Clear
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── MODERATION QUEUE ───────────────────────────────────── */}
        {tab === 'moderation' && (
          <div className="space-y-6">
            <p className="text-xs leading-relaxed" style={tv.muted}>
              Review pending submissions before they can become community knowledge. Approval sanitizes and
              anonymizes the submission. Private or pending items are never shown in public search or the AI knowledge store.
            </p>

            {pendingLoading ? (
              <div className="rounded-sm p-10 text-center" style={tv.panelBorder}>
                <div className="inline-flex items-center gap-2 font-mono text-xs" style={tv.muted}>
                  <Clock size={13} className="animate-spin" style={{ color: 'var(--tw-burgundy)' }} />
                  Loading moderation queue…
                </div>
              </div>
            ) : pendingFeed.length === 0 ? (
              <div className="rounded-sm p-10 text-center space-y-2" style={tv.panelBorder}>
                <CheckCircle size={28} className="mx-auto" style={{ color: 'var(--tw-low)' }} />
                <p className="font-mono text-sm" style={tv.muted}>Moderation queue is empty.</p>
                <p className="text-xs" style={tv.faint}>No submissions are currently awaiting review.</p>
              </div>
            ) : (
              pendingFeed.map(item => (
                <div key={item.id} className="rounded-sm overflow-hidden" style={tv.panelBorder}>
                  <div className="px-5 py-4 border-b flex flex-wrap items-start justify-between gap-3" style={{ borderColor: 'var(--tw-border-mid)' }}>
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-[10px] px-2 py-0.5 rounded-sm"
                          style={{ backgroundColor: 'var(--tw-panel-alt)', color: 'var(--tw-text-muted)' }}>
                          {item.category}
                        </span>
                        <span className="font-mono text-[10px] px-2 py-0.5 rounded-sm border tracking-widest uppercase"
                          style={{ color: 'var(--tw-medium)', borderColor: 'color-mix(in srgb, var(--tw-medium) 35%, transparent)', backgroundColor: 'color-mix(in srgb, var(--tw-medium) 15%, transparent)' }}>
                          Pending
                        </span>
                        <span className="font-mono text-[10px]" style={tv.faint}>by {item.submittedByName}</span>
                      </div>
                      <h3 className="font-serif text-xl" style={tv.text}>{item.title}</h3>
                      <p className="font-mono text-[10px]" style={tv.faint}>
                        {item.id} · submitted {new Date(item.createdAt).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  <div className="p-5 space-y-4">
                    {item.description && <p className="text-sm leading-relaxed" style={tv.muted}>{item.description}</p>}
                    {item.whatHappened && (
                      <div className="space-y-1">
                        <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.faint}>What happened</p>
                        <p className="text-sm leading-relaxed" style={tv.text}>{item.whatHappened}</p>
                      </div>
                    )}
                    {item.indicators.length > 0 && (
                      <div className="flex flex-wrap gap-1.5">
                        {item.indicators.map((ind, i) => (
                          <span key={i} className="font-mono text-[10px] px-2 py-0.5 rounded-sm"
                            style={{ backgroundColor: 'var(--tw-panel-inset)', color: 'var(--tw-text-muted)' }}>
                            {ind}
                          </span>
                        ))}
                      </div>
                    )}
                    {item.redactionReport && item.redactionReport.length > 0 && (
                      <div className="rounded-sm p-3 border" style={{ borderColor: 'var(--tw-border-mid)' }}>
                        <p className="font-mono text-[10px] uppercase tracking-wider mb-1.5 flex items-center gap-1.5" style={tv.medium}>
                          <EyeOff size={11} /> Sensitive information already redacted
                        </p>
                        {item.redactionReport.map((entry, i) => (
                          <p key={i} className="font-mono text-[10px]" style={tv.muted}>
                            {entry.field}: {entry.findings.map(f => `${f.name} × ${f.count}`).join(', ')}
                          </p>
                        ))}
                      </div>
                    )}
                  </div>
                  <div className="px-5 py-3 border-t flex flex-wrap items-center gap-2" style={{ borderColor: 'var(--tw-border-mid)', backgroundColor: 'var(--tw-panel-alt)' }}>
                    <input
                      type="text"
                      value={moderateNote}
                      onChange={e => setModerateNote(e.target.value)}
                      placeholder="Moderator note (optional)…"
                      className="flex-1 min-w-40 font-mono text-xs px-3 py-2 rounded-sm focus:outline-none placeholder:opacity-40"
                      style={tv.input}
                    />
                    {[
                      { label: 'Approve', status: 'APPROVED', color: 'var(--tw-low)' },
                      { label: 'Reject', status: 'REJECTED', color: 'var(--tw-critical)' },
                      { label: 'Flag', status: 'FLAGGED', color: 'var(--tw-high)' },
                      { label: 'Private', status: 'PRIVATE', color: 'var(--tw-dust)' },
                    ].map(btn => (
                      <button
                        key={btn.status}
                        onClick={() => moderate(item.id, btn.status)}
                        disabled={modAction?.id === item.id}
                        className="font-mono text-[10px] tracking-widest uppercase px-3 py-1.5 rounded-sm border transition-colors disabled:opacity-40"
                        style={{ borderColor: btn.color, color: btn.color }}
                      >
                        {modAction?.id === item.id ? 'Updating…' : btn.label}
                      </button>
                    ))}
                  </div>
                  {modAction?.id === item.id && modAction.error && (
                    <p className="px-5 py-2 font-mono text-[10px]" style={{ color: 'var(--tw-critical)' }}>{modAction.error}</p>
                  )}
                </div>
              ))
            )}
          </div>
        )}

        {/* ── AI KNOWLEDGE ───────────────────────────────────────── */}
        {tab === 'knowledge' && (
          <div className="space-y-6">
            <div className="rounded-sm p-5 space-y-3" style={tv.panelBorder}>
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase flex items-center gap-2" style={tv.muted}>
                <Brain size={12} /> How the AI benefits
              </p>
              <p className="text-sm leading-relaxed" style={tv.muted}>
                The AI treats approved feedback as <span className="font-mono" style={tv.text}>retrieved knowledge</span>, not
                instructions. Only fully sanitized, anonymized, moderation-approved submissions enter the knowledge
                store. This is a retrieval/knowledge layer — it does not retrain the foundation model.
              </p>
              <div className="rounded-sm p-4 border font-mono text-[10px] leading-relaxed whitespace-pre-wrap"
                style={{ borderColor: 'var(--tw-border-mid)', backgroundColor: 'var(--tw-panel-inset)', color: 'var(--tw-text-muted)' }}>
{`Approved Feedback
  → Sanitized / Anonymized Knowledge
  → Validated Cybersecurity Knowledge Store
  → AI retrieves relevant lessons (context only)
  → AI provides better contextual guidance`}
              </div>
              <p className="text-xs" style={tv.faint}>
                <span className="font-mono">GET /api/feedback/knowledge</span> exposes this store. PENDING, REJECTED,
                FLAGGED and PRIVATE submissions are never exposed there — and any embedded instructions in user text are
                treated strictly as data.
              </p>
            </div>

            <div className="rounded-sm p-5 space-y-3" style={tv.panelBorder}>
              <div className="flex items-center justify-between">
                <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Knowledge Store Contents</p>
                <button
                  onClick={() => setTab('browse')}
                  className="font-mono text-[10px]" style={tv.burg}
                >
                  View in community browse →
                </button>
              </div>
              <p className="font-mono text-sm" style={tv.text}>
                {browseFeed.length} approved, sanitized item{browseFeed.length === 1 ? '' : 's'} in the knowledge layer.
              </p>
              <div className="flex flex-wrap gap-1.5">
                {browseFeed.slice(0, 24).map(item => (
                  <span key={item.id} className="font-mono text-[10px] px-2 py-0.5 rounded-sm"
                    style={{ backgroundColor: 'var(--tw-panel-inset)', color: 'var(--tw-text-muted)' }}>
                    {item.category}
                  </span>
                ))}
                {browseFeed.length === 0 && (
                  <span className="font-mono text-[10px]" style={tv.faint}>
                    Share and approve feedback to populate the knowledge store.
                  </span>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}