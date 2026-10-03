// ============================================================
// Add Intelligence — the analyst's single write surface.
//
// Every form calls one mutation from the central model. No form
// writes to a local list, and nothing is invented: a record the
// analyst did not supply (an alert, a timeline event, an audit
// entry, a correlation) is generated from the supplied evidence
// only.
//
// Eleven record types, eleven distinct intelligence workspaces —
// each module presents a purpose-built workflow (dossier, identity
// explorer, crypto identity, crypto intelligence, topology, source
// console, chain of custody, raw collection, chronology, case and
// link analysis) and each side panel reads live from the same
// centralized model.
// ============================================================
import { useMemo, useState, type ReactNode } from 'react';
import { motion } from 'framer-motion';
import {
  Activity,
  AlertTriangle,
  ArrowLeftRight,
  Box,
  Boxes,
  Check,
  Clock3,
  Crosshair,
  Database,
  Download,
  FileJson,
  Fingerprint,
  GitBranch,
  Globe,
  Key,
  Link2,
  Network,
  Plus,
  ScanLine,
  Search,
  Server,
  Shield,
  Trash2,
  Upload,
  User,
  Users,
  Wallet,
  X,
} from 'lucide-react';
import { dw, sectionStyle } from '../../lib/darkweb/styles';
import { useIntelligence } from '../../lib/intelligence/IntelligenceContext';
import type { MutationResult } from '../../lib/intelligence/mutations';
import { findDuplicates, normalizeHandle, normalizePgp } from '../../lib/intelligence/normalize';
import type {
  EvidenceRecord,
  InfrastructureRecord,
  Observation,
  RelationshipRecord,
  SourceRecord,
  TimelineRecord,
} from '../../lib/intelligence/types';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { ProtectionModulePanel } from '../../components/darkweb/ProtectionModulePanel';

/** Option lists are the record unions themselves, so a form can never offer a
 *  value the model would reject. */
const OBSERVATION_TYPES: Observation['observationType'][] = [
  'NEW_PLATFORM_ACTIVITY',
  'HANDLE_OBSERVED',
  'INFRASTRUCTURE_CHANGE',
  'PERSONA_CHANGE',
  'RELATIONSHIP_DISCOVERED',
  'NEW_EVIDENCE',
  'BEHAVIOR_ANOMALY',
];
const EVIDENCE_TYPES: EvidenceRecord['evidenceType'][] = [
  'FORUM_POST',
  'MARKETPLACE_LISTING',
  'PASTE',
  'LEAK_RECORD',
  'MESSAGE',
  'TRANSACTION',
  'PGP_KEY',
  'DOMAIN_REGISTRATION',
  'LOG',
  'ANALYSIS',
];
const RELATIONSHIP_TYPES: RelationshipRecord['type'][] = [
  'ASSOCIATED_WITH',
  'USES_HANDLE',
  'SHARED_HANDLE',
  'SHARED_PGP',
  'SHARED_WALLET',
  'SHARED_INFRASTRUCTURE',
  'OBSERVED_ON',
  'PERSONA_MIGRATION',
  'EVIDENCE_LINKED',
  'OBSERVED_AT_SOURCE',
  'SOURCE_REPORTED',
];
const TIMELINE_TYPES: TimelineRecord['type'][] = [
  'FIRST_SEEN',
  'LAST_SEEN',
  'HANDLE_CHANGE',
  'PLATFORM_ACTIVITY',
  'INFRASTRUCTURE_CHANGE',
  'PERSONA_MIGRATION',
  'RELATIONSHIP_FORMATION',
  'EVIDENCE_COLLECTION',
  'FIRST_SEEN_NEW',
];
const SOURCE_TYPES: SourceRecord['type'][] = [
  'FORUM',
  'MARKETPLACE',
  'PASTE',
  'LEAK_SITE',
  'MESSAGING',
  'THREAT_FEED',
  'ONION_SERVICE',
];
const INFRA_TYPES: InfrastructureRecord['type'][] = ['DOMAIN', 'IP', 'HOSTING', 'TLS', 'NAMESERVER'];

type FormKey =
  | 'actor'
  | 'handle'
  | 'pgp'
  | 'wallet'
  | 'infrastructure'
  | 'source'
  | 'evidence'
  | 'observation'
  | 'timeline'
  | 'investigation'
  | 'relationship'
  | 'mitreTtp'
  | 'cve'
  | 'walletTransaction'
  | 'walletCluster';

const FORMS: { key: FormKey; label: string; icon: React.ComponentType<{ size?: number }> }[] = [
  { key: 'actor', label: 'Actor', icon: User },
  { key: 'handle', label: 'Handle', icon: Users },
  { key: 'pgp', label: 'PGP', icon: Key },
  { key: 'wallet', label: 'Wallet', icon: Wallet },
  { key: 'infrastructure', label: 'Infrastructure', icon: Server },
  { key: 'source', label: 'Source', icon: Globe },
  { key: 'evidence', label: 'Evidence', icon: Database },
  { key: 'observation', label: 'Observation', icon: FileJson },
  { key: 'timeline', label: 'Timeline', icon: Clock3 },
  { key: 'investigation', label: 'Investigation', icon: Network },
  { key: 'relationship', label: 'Relationship', icon: Link2 },
  { key: 'mitreTtp', label: 'ATT&CK TTP', icon: Crosshair },
  { key: 'cve', label: 'CVE', icon: AlertTriangle },
  { key: 'walletTransaction', label: 'Transaction', icon: ArrowLeftRight },
  { key: 'walletCluster', label: 'Cluster', icon: Boxes },
];

const inputClass =
  'w-full font-mono text-[11px] px-2 py-1.5 rounded-sm focus:outline-none';
const inputStyle = {
  backgroundColor: 'var(--tw-panel-alt)',
  borderColor: 'var(--tw-border-mid)',
  color: 'var(--tw-text)',
} as const;

interface FieldProps {
  label: string;
  hint?: string;
  children: React.ReactNode;
}

function Field({ label, hint, children }: FieldProps) {
  return (
    <label className="block space-y-1">
      <span className="font-mono text-[9px] tracking-widest uppercase" style={dw.faint}>{label}</span>
      {children}
      {hint && <span className="block font-mono text-[9px]" style={dw.faint}>{hint}</span>}
    </label>
  );
}

function splitList(value: string): string[] {
  return value.split(/[,\n]/).map(item => item.trim()).filter(Boolean);
}

function useResult() {
  const [result, setResult] = useState<MutationResult<unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const reset = () => {
    setResult(null);
    setError(null);
  };
  return { result, error, setResult, setError, reset };
}

/** Renders the fan-out produced by one analyst action. */
function FanOut({ result }: { result: MutationResult<unknown> }) {
  const rows: [string, number][] = [
    ['Relationships', result.relationships.length],
    ['Alerts', result.alerts.length],
    ['Timeline events', result.timeline.length],
    ['Observations', result.observations.length],
    ['Audit events', result.audit.length],
    ['Duplicate candidates', result.duplicates.length],
  ];
  return (
    <div className="rounded-sm border p-4 space-y-3" style={dw.panel}>
      <div className="flex items-center gap-2" style={dw.moss}>
        <Check size={13} />
        <p className="font-mono text-[10px] tracking-widest uppercase">Recorded in the central model</p>
      </div>
      <p className="font-mono text-[10px]" style={dw.text}>
        {(result.record as { id?: string } | null)?.id ?? '—'}
      </p>
      <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
        {rows.map(([label, count]) => (
          <div key={label} className="rounded-sm border px-2 py-1.5" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
            <p className="font-mono text-[9px] uppercase" style={dw.faint}>{label}</p>
            <p className="font-mono text-sm" style={count ? dw.text : dw.faint}>{count}</p>
          </div>
        ))}
      </div>
      {result.duplicates.length > 0 && (
        <div className="space-y-1">
          <p className="font-mono text-[9px] tracking-widest uppercase" style={dw.medium}>Possible duplicates — review before merging</p>
          {result.duplicates.map(candidate => (
            <p key={`${candidate.entityType}-${candidate.existingId}`} className="font-mono text-[10px]" style={dw.muted}>
              {candidate.kind} {candidate.entityType} {candidate.existingId} — {candidate.detail} ({candidate.score}%)
            </p>
          ))}
        </div>
      )}
    </div>
  );
}

function ErrorNote({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <div className="rounded-sm border p-3 flex items-start gap-2"
      style={{ backgroundColor: 'color-mix(in srgb, var(--tw-critical) 10%, transparent)', borderColor: 'var(--tw-critical)' }}>
      <AlertTriangle size={13} style={dw.critical} />
      <p className="font-mono text-[10px]" style={dw.text}>{error}</p>
    </div>
  );
}

function SubmitBar({ label, onSubmit, error, onClear }: { label: string; onSubmit: () => void; error: string | null; onClear: () => void }) {
  return (
    <div className="flex flex-wrap items-center gap-3 pt-1">
      <button type="button" onClick={onSubmit}
        className="flex items-center gap-1.5 font-mono text-[10px] tracking-widest uppercase px-3 py-1.5 rounded-sm"
        style={dw.bgBurg}>
        <span className="text-white">&#9656;</span>
        <span style={{ color: '#FBFAF6' }}>{label}</span>
      </button>
      <button type="button" onClick={onClear}
        className="font-mono text-[10px] tracking-widest uppercase px-3 py-1.5 rounded-sm border"
        style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}>
        Reset form
      </button>
      <span className="flex-1" />
      <ErrorNote error={error} />
    </div>
  );
}

// ── Shared workspace scaffolding ────────────────────────────────
/** The analyst-side form area — distinct per module. */
function FormArea({ children }: { children: ReactNode }) {
  return <div className="col-span-3 space-y-4">{children}</div>;
}

/** The live model panel — reads only the central store, never hardcoded. */
function SidePanel({ accent, icon, title, children }: { accent: string; icon: ReactNode; title: string; children: ReactNode }) {
  return (
    <div className="col-span-2 rounded-sm border p-4 space-y-3 self-start" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
      <p className="font-mono text-[9px] tracking-widest uppercase flex items-center gap-1.5" style={{ color: accent }}>
        {icon} {title}
      </p>
      {children}
    </div>
  );
}

function ModuleFrame({
  accent,
  icon,
  eyebrow,
  title,
  byline,
  form,
  context,
}: {
  accent: string;
  icon: ReactNode;
  eyebrow: string;
  title: string;
  byline: string;
  form: ReactNode;
  context?: ReactNode;
}) {
  return (
    <div className="rounded-sm border overflow-hidden" style={dw.panel}>
      <div className="h-1" style={{ backgroundColor: accent }} />
      <div className="p-5 space-y-4">
        <div className="flex items-start gap-3">
          <div className="rounded-sm flex h-10 w-10 items-center justify-center shrink-0" style={{ border: `1px solid ${accent}` }}>
            <span style={{ color: accent }}>{icon}</span>
          </div>
          <div className="min-w-0">
            <p className="font-mono text-[9px] tracking-widest uppercase" style={{ color: accent }}>{eyebrow}</p>
            <h2 className="font-serif text-2xl" style={dw.text}>{title}</h2>
            <p className="text-xs mt-0.5" style={dw.muted}>{byline}</p>
          </div>
        </div>
        <div className="grid lg:grid-cols-5 gap-4">
          {form}
          {context}
        </div>
      </div>
    </div>
  );
}

function ConfidenceSlider({ label, value, onChange }: { label: string; value: number; onChange: (next: number) => void }) {
  return (
    <Field label={`${label} — ${value}`}>
      <input type="range" min={0} max={100} value={value} onChange={e => onChange(Number(e.target.value))} className="w-full" />
    </Field>
  );
}

function ActorSelect({ label, hint, value, onChange, allowNone = true }: {
  label: string;
  hint?: string;
  value: string;
  onChange: (next: string) => void;
  allowNone?: boolean;
}) {
  const { dataset } = useIntelligence();
  return (
    <Field label={label} hint={hint}>
      <select value={value} onChange={e => onChange(e.target.value)} className={inputClass} style={inputStyle}>
        {allowNone && <option value="">{label === 'Seed actor' ? 'Select an actor' : 'None — unattributed'}</option>}
        {dataset.actors.map(actor => (
          <option key={actor.id} value={actor.id}>{actor.id} — {actor.aliases[0] ?? actor.id}</option>
        ))}
      </select>
    </Field>
  );
}

function TagInput({ label, hint, placeholder, value, onChange }: {
  label: string;
  hint?: string;
  placeholder?: string;
  value: string;
  onChange: (next: string) => void;
}) {
  const items = splitList(value);
  return (
    <Field label={label} hint={hint}>
      <input value={value} onChange={e => onChange(e.target.value)} className={inputClass} style={inputStyle} placeholder={placeholder} />
      {items.length > 0 && (
        <div className="flex flex-wrap gap-1 pt-1.5">
          {items.map(item => (
            <span key={item} className="rounded-sm border px-1.5 py-0.5 font-mono text-[9px]" style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}>
              {item}
            </span>
          ))}
        </div>
      )}
    </Field>
  );
}

function reliabilityBand(reliability: number) {
  if (reliability >= 90) return { band: 'R9', label: 'Corroborated across multiple lawful collections' };
  if (reliability >= 75) return { band: 'R8', label: 'Consistent multi-collection provenance' };
  if (reliability >= 60) return { band: 'R6', label: 'Single dependable collection point' };
  if (reliability >= 40) return { band: 'R4', label: 'Unverified — seek corroboration' };
  return { band: 'R2', label: 'Low confidence — treat as leads only' };
}

// ── 1 · ACTOR — Threat Actor Dossier ────────────────────────────
interface WorkspaceProps {
  submit: (fn: () => MutationResult<unknown>, message: string) => void;
  error: string | null;
  clearResult: () => void;
  createActor: (input: Parameters<ReturnType<typeof useIntelligence>['createActor']>[0]) => MutationResult<unknown>;
  createHandle: (input: Parameters<ReturnType<typeof useIntelligence>['createHandle']>[0]) => MutationResult<unknown>;
  createPgp: (input: Parameters<ReturnType<typeof useIntelligence>['createPgp']>[0]) => MutationResult<unknown>;
  createWallet: (input: Parameters<ReturnType<typeof useIntelligence>['createWallet']>[0]) => MutationResult<unknown>;
  createInfrastructure: (input: Parameters<ReturnType<typeof useIntelligence>['createInfrastructure']>[0]) => MutationResult<unknown>;
  createSource: (input: Parameters<ReturnType<typeof useIntelligence>['createSource']>[0]) => MutationResult<unknown>;
  createEvidence: (input: Parameters<ReturnType<typeof useIntelligence>['createEvidence']>[0]) => MutationResult<unknown>;
  createObservation: (input: Parameters<ReturnType<typeof useIntelligence>['createObservation']>[0]) => MutationResult<unknown>;
  createTimelineEvent: (input: Parameters<ReturnType<typeof useIntelligence>['createTimelineEvent']>[0]) => MutationResult<unknown>;
  createInvestigation: (input: Parameters<ReturnType<typeof useIntelligence>['createInvestigation']>[0]) => MutationResult<unknown>;
  createRelationship: (input: Parameters<ReturnType<typeof useIntelligence>['createRelationship']>[0]) => MutationResult<unknown>;
  createMitreTtp: (input: Parameters<ReturnType<typeof useIntelligence>['createMitreTtp']>[0]) => MutationResult<unknown>;
  createCve: (input: Parameters<ReturnType<typeof useIntelligence>['createCve']>[0]) => MutationResult<unknown>;
  createWalletTransaction: (input: Parameters<ReturnType<typeof useIntelligence>['createWalletTransaction']>[0]) => MutationResult<unknown>;
  createWalletCluster: (input: Parameters<ReturnType<typeof useIntelligence>['createWalletCluster']>[0]) => MutationResult<unknown>;
}

function ActorWorkspace({ submit, error, clearResult, createActor }: WorkspaceProps) {
  const { dataset } = useIntelligence();
  const [form, setForm] = useState({ id: '', name: '', aliases: '', handles: '', platforms: '', confidence: 70, status: 'ACTIVE' });
  const names = splitList(form.aliases).map(normalizeHandle);
  const conflicts = names.length
    ? dataset.actors.filter(actor => actor.aliases.some(alias => names.includes(normalizeHandle(alias))))
    : [];
  const active = dataset.actors.filter(actor => actor.status === 'ACTIVE').length;
  const avg = dataset.actors.length
    ? Math.round(dataset.actors.reduce((sum, actor) => sum + actor.confidenceScore, 0) / dataset.actors.length)
    : 0;

  return (
    <ModuleFrame
      accent="var(--tw-burgundy)"
      icon={<User size={16} />}
      eyebrow="THREAT ACTOR DOSSIER"
      title="New Actor Dossier"
      byline="Opens a subject record under observation. Aliases, handles and platforms you list become structured identity artifacts the moment the dossier is saved."
      form={
        <FormArea>
          <div className="grid md:grid-cols-2 gap-3">
            <Field label="Actor ID" hint="Optional. Leave blank to allocate the next ACTOR-nnn.">
              <input value={form.id} onChange={e => setForm({ ...form, id: e.target.value })} className={inputClass} style={inputStyle} placeholder="ACTOR-005" />
            </Field>
            <Field label="Primary name">
              <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} className={inputClass} style={inputStyle} placeholder="ShadowFox" />
            </Field>
          </div>
          <TagInput label="Aliases" hint="Comma separated" placeholder="shadowfox, sf-admin" value={form.aliases} onChange={value => setForm({ ...form, aliases: value })} />
          <TagInput label="Handles" hint="Comma separated — each becomes a linked handle record" placeholder="shadowfox_88" value={form.handles} onChange={value => setForm({ ...form, handles: value })} />
          <TagInput label="Platforms" hint="Comma separated" placeholder="Forum, Marketplace" value={form.platforms} onChange={value => setForm({ ...form, platforms: value })} />
          <div className="grid md:grid-cols-2 gap-3">
            <ConfidenceSlider label="Confidence" value={form.confidence} onChange={value => setForm({ ...form, confidence: value })} />
            <Field label="Status">
              <select value={form.status} onChange={e => setForm({ ...form, status: e.target.value })} className={inputClass} style={inputStyle}>
                <option value="ACTIVE">ACTIVE</option>
                <option value="DORMANT">DORMANT</option>
                <option value="SUSPENDED">SUSPENDED</option>
              </select>
            </Field>
          </div>
          <SubmitBar
            label="Record actor"
            error={error}
            onClear={() => { setForm({ id: '', name: '', aliases: '', handles: '', platforms: '', confidence: 70, status: 'ACTIVE' }); clearResult(); }}
            onSubmit={() => submit(
              () => createActor({
                id: form.id || undefined,
                name: form.name || undefined,
                aliases: splitList(form.aliases),
                handles: splitList(form.handles),
                platforms: splitList(form.platforms),
                confidence: form.confidence,
                status: form.status as 'ACTIVE' | 'DORMANT' | 'SUSPENDED',
              }),
              'Actor rejected',
            )}
          />
        </FormArea>
      }
      context={
        <SidePanel accent="var(--tw-burgundy)" icon={<Search size={12} />} title="Model posture">
          <p className="font-mono text-[10px]" style={dw.text}>
            {dataset.actors.length} actors observed · {active} active · mean confidence {avg}%
          </p>
          {conflicts.length > 0 ? (
            <div className="space-y-1">
              <p className="font-mono text-[9px] tracking-widest uppercase" style={dw.medium}>Alias conflict in model</p>
              {conflicts.map(actor => (
                <p key={actor.id} className="font-mono text-[9px]" style={dw.muted}>{actor.id} already recorded as {actor.aliases[0]}</p>
              ))}
            </div>
          ) : (
            names.length > 0 && <p className="font-mono text-[9px]" style={dw.faint}>No alias conflict recorded — this dossier is unique in the model.</p>
          )}
        </SidePanel>
      }
    />
  );
}

// ── 2 · HANDLE — Identity Explorer ──────────────────────────────
function HandleWorkspace({ submit, error, clearResult, createHandle }: WorkspaceProps) {
  const { dataset, resolveValue } = useIntelligence();
  const [form, setForm] = useState({ handle: '', platform: 'Forum', actorId: '', confidence: 70 });
  const normalized = form.handle ? normalizeHandle(form.handle) : '';
  const resolution = form.handle.trim() ? resolveValue(form.handle.trim()) : null;

  return (
    <ModuleFrame
      accent="var(--tw-brass)"
      icon={<Users size={16} />}
      eyebrow="IDENTITY EXPLORER"
      title="Handle Identity"
      byline="A handle is an identity artifact — one string a subject uses across the dark web. Normalization proves how the model would write it, and resolution surfaces any actor already tied to it."
      form={
        <FormArea>
          <Field label="Handle" hint="Normalized automatically — case and padding are ignored.">
            <input value={form.handle} onChange={e => setForm({ ...form, handle: e.target.value })} className={inputClass} style={inputStyle} placeholder="ghostwire" />
          </Field>
          {form.handle && (
            <div className="rounded-sm border px-3 py-2" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
              <p className="font-mono text-[9px] tracking-widest uppercase" style={dw.faint}>Model normalization</p>
              <p className="font-mono text-sm mt-0.5" style={dw.text}>@{normalized || '…'}</p>
            </div>
          )}
          <div className="grid md:grid-cols-2 gap-3">
            <Field label="Platform">
              <input value={form.platform} onChange={e => setForm({ ...form, platform: e.target.value })} className={inputClass} style={inputStyle} placeholder="Forum" />
            </Field>
            <ConfidenceSlider label="Confidence" value={form.confidence} onChange={value => setForm({ ...form, confidence: value })} />
          </div>
          <ActorSelect label="Attributed actor" hint="Optional. Attributing the handle also links the actor." value={form.actorId} onChange={value => setForm({ ...form, actorId: value })} />
          <SubmitBar
            label="Record handle"
            error={error}
            onClear={() => { setForm({ handle: '', platform: 'Forum', actorId: '', confidence: 70 }); clearResult(); }}
            onSubmit={() => submit(
              () => createHandle({
                handle: form.handle,
                platform: form.platform,
                actorId: form.actorId || undefined,
                confidence: form.confidence,
              }),
              'Handle rejected',
            )}
          />
        </FormArea>
      }
      context={
        <SidePanel accent="var(--tw-brass)" icon={<Search size={12} />} title="Entity resolution">
          {resolution ? (
            <div className="space-y-2">
              <p className="font-mono text-[10px]" style={dw.text}>Resolves to {resolution.label}</p>
              <p className="font-mono text-[9px]" style={dw.moss}>confident at {resolution.confidence}%</p>
              {resolution.alternatives.length > 0 && (
                <div className="space-y-1">
                  <p className="font-mono text-[9px] tracking-widest uppercase" style={dw.faint}>Alternatives</p>
                  {resolution.alternatives.map((alternative, index) => (
                    <p key={index} className="font-mono text-[9px]" style={dw.muted}>{alternative.actorId} · {alternative.score}%</p>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div className="space-y-1">
              <p className="font-mono text-[9px]" style={dw.faint}>
                {form.handle.trim() ? 'No stored actor resolves to this handle yet — it becomes a fresh identity artifact.' : 'Start typing a handle to see live resolution against the model.'}
              </p>
              <p className="font-mono text-[9px]" style={dw.muted}>{dataset.handles.length} handles already in the model</p>
            </div>
          )}
        </SidePanel>
      }
    />
  );
}

// ── 3 · PGP — Cryptographic Identity ────────────────────────────
function PgpWorkspace({ submit, error, clearResult, createPgp }: WorkspaceProps) {
  const { dataset } = useIntelligence();
  const [form, setForm] = useState({ fingerprint: '', actorId: '', platform: '', confidence: 85 });
  const flat = normalizePgp(form.fingerprint);
  const grouped = flat.replace(/(.{4})/g, '$1 ').trim().slice(0, 25);
  const matches = findDuplicates(dataset, 'PGP', form.fingerprint);

  return (
    <ModuleFrame
      accent="var(--tw-moss)"
      icon={<Key size={16} />}
      eyebrow="CRYPTOGRAPHIC IDENTITY"
      title="PGP Fingerprint"
      byline="A PGP key is a sanctioned, long-lived identity. The fingerprint is grouped as the model reads it, and any existing key it matches is surfaced before the record is written."
      form={
        <FormArea>
          <Field label="Fingerprint" hint="Spaces are stripped. A fingerprint shared by two actors produces a SHARED_PGP relationship.">
            <input value={form.fingerprint} onChange={e => setForm({ ...form, fingerprint: e.target.value })} className={inputClass} style={inputStyle} placeholder="4A3B …" />
          </Field>
          {flat && (
            <div className="rounded-sm border px-3 py-2" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
              <p className="font-mono text-[9px] tracking-widest uppercase" style={dw.faint}>Fingerprint — {String(flat.length)} hex chars</p>
              <p className="font-mono text-sm mt-0.5" style={dw.moss}>{grouped || '…'}</p>
            </div>
          )}
          <div className="grid md:grid-cols-2 gap-3">
            <Field label="Observed on platform">
              <input value={form.platform} onChange={e => setForm({ ...form, platform: e.target.value })} className={inputClass} style={inputStyle} placeholder="Forum" />
            </Field>
            <ConfidenceSlider label="Confidence" value={form.confidence} onChange={value => setForm({ ...form, confidence: value })} />
          </div>
          <ActorSelect label="Attributed actor" value={form.actorId} onChange={value => setForm({ ...form, actorId: value })} />
          <SubmitBar
            label="Record PGP key"
            error={error}
            onClear={() => { setForm({ fingerprint: '', actorId: '', platform: '', confidence: 85 }); clearResult(); }}
            onSubmit={() => submit(
              () => createPgp({
                fingerprint: form.fingerprint,
                actorId: form.actorId || undefined,
                platform: form.platform || undefined,
                confidence: form.confidence,
              }),
              'PGP key rejected',
            )}
          />
        </FormArea>
      }
      context={
        <SidePanel accent="var(--tw-moss)" icon={<Fingerprint size={12} />} title="Key matching">
          {matches.length > 0 ? (
            <div className="space-y-1">
              <p className="font-mono text-[9px] tracking-widest uppercase" style={dw.medium}>Fingerprint already in model</p>
              {matches.map(match => (
                <p key={match.existingId} className="font-mono text-[9px]" style={dw.muted}>
                  {match.kind} {match.existingId} — {match.detail} ({match.score}%)
                </p>
              ))}
            </div>
          ) : (
            <div className="space-y-1">
              <p className="font-mono text-[9px]" style={dw.faint}>
                {flat ? 'No recorded key matches this fingerprint — it is cryptographically distinct in the model.' : 'Type a fingerprint to scan the key set.'}
              </p>
              <p className="font-mono text-[9px]" style={dw.muted}>{dataset.pgpKeys.length} keys in the model</p>
            </div>
          )}
        </SidePanel>
      }
    />
  );
}

// ── 4 · WALLET — Crypto Intelligence ────────────────────────────
function WalletWorkspace({ submit, error, clearResult, createWallet }: WorkspaceProps) {
  const { dataset } = useIntelligence();
  const [form, setForm] = useState({ address: '', network: 'BTC', actorId: '', confidence: 80 });
  const matches = findDuplicates(dataset, 'WALLET', form.address);
  const onNetwork = form.network ? dataset.wallets.filter(wallet => wallet.network === form.network).length : 0;

  return (
    <ModuleFrame
      accent="var(--tw-info)"
      icon={<Wallet size={16} />}
      eyebrow="CRYPTO INTELLIGENCE"
      title="Wallet Indicator"
      byline="A payment address is a linking indicator between identities. The address format is preserved exactly — case matters — and the network rollup shows how much of the model already lives there."
      form={
        <FormArea>
          <Field label="Address" hint="Normalized automatically. Addressing formats are preserved: bc1 / 1 / 3… are case-sensitive.">
            <input value={form.address} onChange={e => setForm({ ...form, address: e.target.value })} className={inputClass} style={inputStyle} placeholder="bc1q…" />
          </Field>
          {form.address && (
            <div className="rounded-sm border px-3 py-2" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
              <p className="font-mono text-[9px] tracking-widest uppercase" style={dw.faint}>Address readout</p>
              <p className="font-mono text-sm mt-0.5 break-all" style={dw.info}>{form.address} · {String(form.address.length)} chars</p>
            </div>
          )}
          <div className="grid md:grid-cols-2 gap-3">
            <Field label="Network">
              <input value={form.network} onChange={e => setForm({ ...form, network: e.target.value })} className={inputClass} style={inputStyle} placeholder="BTC" />
            </Field>
            <ConfidenceSlider label="Confidence" value={form.confidence} onChange={value => setForm({ ...form, confidence: value })} />
          </div>
          <ActorSelect label="Attributed actor" value={form.actorId} onChange={value => setForm({ ...form, actorId: value })} />
          <SubmitBar
            label="Record wallet"
            error={error}
            onClear={() => { setForm({ address: '', network: 'BTC', actorId: '', confidence: 80 }); clearResult(); }}
            onSubmit={() => submit(
              () => createWallet({
                address: form.address,
                network: form.network,
                actorId: form.actorId || undefined,
                confidence: form.confidence,
              }),
              'Wallet rejected',
            )}
          />
        </FormArea>
      }
      context={
        <SidePanel accent="var(--tw-info)" icon={<ScanLine size={12} />} title="Network posture">
          {form.network && <p className="font-mono text-[10px]" style={dw.text}>{onNetwork} wallet{onNetwork === 1 ? '' : 's'} on {form.network} in the model</p>}
          {matches.length > 0 ? (
            <div className="space-y-1">
              <p className="font-mono text-[9px] tracking-widest uppercase" style={dw.medium}>Address already recorded</p>
              {matches.map(match => (
                <p key={match.existingId} className="font-mono text-[9px]" style={dw.muted}>{match.detail} ({match.score}%)</p>
              ))}
            </div>
          ) : (
            <p className="font-mono text-[9px]" style={dw.faint}>{form.address ? 'No stored wallet matches this address.' : 'Type an address to scan the wallet set.'}</p>
          )}
        </SidePanel>
      }
    />
  );
}

// ── 5 · INFRASTRUCTURE — Attack Surface / Topology ──────────────
const INFRA_HINTS: Record<string, string> = {
  DOMAIN: 'Domains are normalized and become graph nodes.',
  IP: 'An address the subject operates from.',
  HOSTING: 'The hosting layer behind an operated domain.',
  TLS: 'Certificate identity — often reuses a key across domains.',
  NAMESERVER: 'Name-server control — shared infrastructure signal.',
};

function InfrastructureWorkspace({ submit, error, clearResult, createInfrastructure }: WorkspaceProps) {
  const { dataset } = useIntelligence();
  const [form, setForm] = useState({ type: 'DOMAIN', value: '', actorId: '', hostingProvider: '', asn: '', country: '', confidence: 75 });
  const matches = findDuplicates(dataset, 'INFRASTRUCTURE', form.value);
  const byType = dataset.infrastructure.reduce((tally, item) => {
    tally[item.type] = (tally[item.type] ?? 0) + 1;
    return tally;
  }, {} as Record<string, number>);

  return (
    <ModuleFrame
      accent="var(--tw-dust)"
      icon={<Server size={16} />}
      eyebrow="ATTACK SURFACE / TOPOLOGY"
      title="Infrastructure Indicator"
      byline="The machinery a subject operates — domains, addresses, hosting, certificates, name servers. Each type carries its own context, and the same infrastructure reused across actors is a linking signal."
      form={
        <FormArea>
          <Field label="Type">
            <select value={form.type} onChange={e => setForm({ ...form, type: e.target.value })} className={inputClass} style={inputStyle}>
              {INFRA_TYPES.map(type => <option key={type} value={type}>{type}</option>)}
            </select>
          </Field>
          <div className="rounded-sm border px-3 py-2" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
            <p className="font-mono text-[9px]" style={dw.faint}>{INFRA_HINTS[form.type] ?? ''}</p>
          </div>
          <Field label="Value" hint="Domains and addresses are normalized.">
            <input value={form.value} onChange={e => setForm({ ...form, value: e.target.value })} className={inputClass} style={inputStyle} placeholder="relay.example.net" />
          </Field>
          {form.type !== 'IP' && (
            <div className="grid md:grid-cols-2 gap-3">
              <Field label="Hosting provider">
                <input value={form.hostingProvider} onChange={e => setForm({ ...form, hostingProvider: e.target.value })} className={inputClass} style={inputStyle} placeholder="Example Hosting" />
              </Field>
              <Field label="Country">
                <input value={form.country} onChange={e => setForm({ ...form, country: e.target.value })} className={inputClass} style={inputStyle} placeholder="DE" />
              </Field>
              {form.type === 'DOMAIN' && (
                <Field label="ASN" hint="Netblock ownership sharpens attribution.">
                  <input value={form.asn} onChange={e => setForm({ ...form, asn: e.target.value })} className={inputClass} style={inputStyle} placeholder="AS64496" />
                </Field>
              )}
            </div>
          )}
          <div className="grid md:grid-cols-2 gap-3">
            <ActorSelect label="Attributed actor" value={form.actorId} onChange={value => setForm({ ...form, actorId: value })} />
            <ConfidenceSlider label="Confidence" value={form.confidence} onChange={value => setForm({ ...form, confidence: value })} />
          </div>
          <SubmitBar
            label="Record infrastructure"
            error={error}
            onClear={() => { setForm({ type: 'DOMAIN', value: '', actorId: '', hostingProvider: '', asn: '', country: '', confidence: 75 }); clearResult(); }}
            onSubmit={() => submit(
              () => createInfrastructure({
                type: form.type as InfrastructureRecord['type'],
                value: form.value,
                actorId: form.actorId || undefined,
                hostingProvider: form.hostingProvider || undefined,
                asn: form.asn || undefined,
                country: form.country || undefined,
                confidence: form.confidence,
              }),
              'Infrastructure rejected',
            )}
          />
        </FormArea>
      }
      context={
        <SidePanel accent="var(--tw-dust)" icon={<GitBranch size={12} />} title="Topology rollup">
          <p className="font-mono text-[10px]" style={dw.text}>{dataset.infrastructure.length} infrastructure items</p>
          <div className="flex flex-wrap gap-1">
            {INFRA_TYPES.map(type => (
              <span key={type} className="rounded-sm border px-1.5 py-0.5 font-mono text-[9px]" style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}>
                {type} · {byType[type] ?? 0}
              </span>
            ))}
          </div>
          {matches.length > 0 && (
            <div className="space-y-1">
              <p className="font-mono text-[9px] tracking-widest uppercase" style={dw.medium}>Possible repeat</p>
              {matches.map(match => (
                <p key={match.existingId} className="font-mono text-[9px]" style={dw.muted}>{match.detail} ({match.score}%)</p>
              ))}
            </div>
          )}
        </SidePanel>
      }
    />
  );
}

// ── 6 · SOURCE — Source Health Console ──────────────────────────
function SourceWorkspace({ submit, error, clearResult, createSource }: WorkspaceProps) {
  const { dataset } = useIntelligence();
  const [form, setForm] = useState({ name: '', type: 'FORUM', reference: '', reliability: 75 });
  const band = reliabilityBand(form.reliability);
  const active = dataset.sources.filter(source => source.status === 'ACTIVE').length;
  const byType = dataset.sources.reduce((tally, source) => {
    tally[source.type] = (tally[source.type] ?? 0) + 1;
    return tally;
  }, {} as Record<string, number>);

  return (
    <ModuleFrame
      accent="var(--tw-medium)"
      icon={<Globe size={16} />}
      eyebrow="SOURCE HEALTH CONSOLE"
      title="Register Source"
      byline="Registers a lawful collection point. Every source carries a reliability rating that weights the evidence collected through it — this is the trust anchor for the whole model."
      form={
        <FormArea>
          <div className="grid md:grid-cols-2 gap-3">
            <Field label="Source name">
              <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} className={inputClass} style={inputStyle} placeholder="Example Forum" />
            </Field>
            <Field label="Type">
              <select value={form.type} onChange={e => setForm({ ...form, type: e.target.value })} className={inputClass} style={inputStyle}>
                {SOURCE_TYPES.map(type => <option key={type} value={type}>{type}</option>)}
              </select>
            </Field>
          </div>
          <Field label="Reference" hint="Onion address or lawful collection reference.">
            <input value={form.reference} onChange={e => setForm({ ...form, reference: e.target.value })} className={inputClass} style={inputStyle} placeholder="http://…" />
          </Field>
          <div className="rounded-sm border px-3 py-2" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
            <div className="flex items-center justify-between">
              <span className="font-mono text-[9px] tracking-widest uppercase" style={dw.faint}>Reliability rating</span>
              <span className="font-mono text-xs" style={dw.text}>R{form.reliability}</span>
            </div>
            <input type="range" min={0} max={100} value={form.reliability} onChange={e => setForm({ ...form, reliability: Number(e.target.value) })} className="w-full mt-1" />
            <p className="font-mono text-[9px] mt-1" style={{ color: 'var(--tw-medium)' }}>{band.band} — {band.label}</p>
          </div>
          <SubmitBar
            label="Register source"
            error={error}
            onClear={() => { setForm({ name: '', type: 'FORUM', reference: '', reliability: 75 }); clearResult(); }}
            onSubmit={() => submit(
              () => createSource({
                name: form.name,
                type: form.type as SourceRecord['type'],
                reference: form.reference || undefined,
                reliability: form.reliability,
              }),
              'Source rejected',
            )}
          />
        </FormArea>
      }
      context={
        <SidePanel accent="var(--tw-medium)" icon={<Activity size={12} />} title="Collection health">
          <p className="font-mono text-[10px]" style={dw.text}>{dataset.sources.length} sources · {active} active</p>
          <div className="flex flex-wrap gap-1">
            {SOURCE_TYPES.map(type => (
              <span key={type} className="rounded-sm border px-1.5 py-0.5 font-mono text-[9px]" style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}>
                {type} · {byType[type] ?? 0}
              </span>
            ))}
          </div>
        </SidePanel>
      }
    />
  );
}

// ── 7 · EVIDENCE — Chain of Custody ─────────────────────────────
function EvidenceWorkspace({ submit, error, clearResult, createEvidence }: WorkspaceProps) {
  const { dataset } = useIntelligence();
  const [form, setForm] = useState({ evidenceType: 'FORUM_POST', source: '', relatedActor: '', description: '', reliability: 80, confidence: 75, hash: '' });
  const recent = [...dataset.evidence].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()).slice(0, 3);

  return (
    <ModuleFrame
      accent="var(--tw-high)"
      icon={<Box size={16} />}
      eyebrow="CHAIN OF CUSTODY"
      title="Evidence Intake"
      byline="Evidence is collected with provenance, integrity and a reliability weighting. A hash anchors the item; provenance and the actor attribution build the chain that investigations later follow."
      form={
        <FormArea>
          <div className="grid md:grid-cols-2 gap-3">
            <Field label="Evidence type">
              <select value={form.evidenceType} onChange={e => setForm({ ...form, evidenceType: e.target.value })} className={inputClass} style={inputStyle}>
                {EVIDENCE_TYPES.map(type => <option key={type} value={type}>{type}</option>)}
              </select>
            </Field>
            <Field label="Source" hint="Where this was collected from.">
              <input value={form.source} onChange={e => setForm({ ...form, source: e.target.value })} className={inputClass} style={inputStyle} placeholder="Example Forum thread #4812" />
            </Field>
          </div>
          <div className="grid md:grid-cols-2 gap-3">
            <ActorSelect label="Related actor" value={form.relatedActor} onChange={value => setForm({ ...form, relatedActor: value })} />
            <Field label="SHA-256" hint="Left blank, a hash is derived from the supplied content.">
              <input value={form.hash} onChange={e => setForm({ ...form, hash: e.target.value })} className={inputClass} style={inputStyle} placeholder="optional" />
            </Field>
          </div>
          <Field label="Description" hint="Provenance shown in the evidence locker.">
            <textarea value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} rows={3} className={inputClass} style={inputStyle} />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label={`Reliability — R${form.reliability}`}>
              <input type="range" min={0} max={100} value={form.reliability} onChange={e => setForm({ ...form, reliability: Number(e.target.value) })} className="w-full" />
            </Field>
            <ConfidenceSlider label="Confidence" value={form.confidence} onChange={value => setForm({ ...form, confidence: value })} />
          </div>
          <SubmitBar
            label="File evidence"
            error={error}
            onClear={() => { setForm({ evidenceType: 'FORUM_POST', source: '', relatedActor: '', description: '', reliability: 80, confidence: 75, hash: '' }); clearResult(); }}
            onSubmit={() => submit(
              () => createEvidence({
                evidenceType: form.evidenceType as EvidenceRecord['evidenceType'],
                source: form.source,
                relatedActor: form.relatedActor || undefined,
                description: form.description || undefined,
                hash: form.hash || undefined,
                reliability: form.reliability,
                confidence: form.confidence,
              }),
              'Evidence rejected',
            )}
          />
        </FormArea>
      }
      context={
        <SidePanel accent="var(--tw-high)" icon={<Box size={12} />} title="Evidence vault">
          <p className="font-mono text-[10px]" style={dw.text}>{dataset.evidence.length} items on file</p>
          {recent.length > 0 && (
            <div className="space-y-1.5">
              <p className="font-mono text-[9px] tracking-widest uppercase" style={dw.faint}>Latest captures</p>
              {recent.map(item => (
                <p key={item.id} className="font-mono text-[9px]" style={dw.muted}>{item.id} · {item.evidenceType.replace(/_/g, ' ').toLowerCase()} · {item.source}</p>
              ))}
            </div>
          )}
        </SidePanel>
      }
    />
  );
}

// ── 8 · OBSERVATION — Raw Intelligence Capture ──────────────────
function ObservationWorkspace({ submit, error, clearResult, createObservation }: WorkspaceProps) {
  const { dataset } = useIntelligence();
  const [form, setForm] = useState({ actorId: '', content: '', observationType: 'NEW_PLATFORM_ACTIVITY', source: 'Analyst', confidence: 70 });
  const recent = [...dataset.observations].slice(-3).reverse();

  return (
    <ModuleFrame
      accent="var(--tw-low)"
      icon={<FileJson size={16} />}
      eyebrow="RAW INTELLIGENCE CAPTURE"
      title="Record Observation"
      byline="An observation is a verbatim intelligence note. It is never summarized away — the content you enter is the content the model keeps, anchored to an actor and tagged by type and source."
      form={
        <FormArea>
          <Field label="Content" hint="Recorded verbatim — observations are never summarized away.">
            <textarea value={form.content} onChange={e => setForm({ ...form, content: e.target.value })} rows={5} className={inputClass} style={inputStyle} />
          </Field>
          {form.content && (
            <p className="font-mono text-[9px]" style={dw.faint}>{String(form.content.length)} characters captured verbatim</p>
          )}
          <div className="grid md:grid-cols-2 gap-3">
            <ActorSelect label="Related actor" value={form.actorId} onChange={value => setForm({ ...form, actorId: value })} />
            <Field label="Observation type">
              <select value={form.observationType} onChange={e => setForm({ ...form, observationType: e.target.value })} className={inputClass} style={inputStyle}>
                {OBSERVATION_TYPES.map(type => <option key={type} value={type}>{type}</option>)}
              </select>
            </Field>
            <Field label="Source">
              <input value={form.source} onChange={e => setForm({ ...form, source: e.target.value })} className={inputClass} style={inputStyle} />
            </Field>
            <ConfidenceSlider label="Confidence" value={form.confidence} onChange={value => setForm({ ...form, confidence: value })} />
          </div>
          <SubmitBar
            label="Record observation"
            error={error}
            onClear={() => { setForm({ actorId: '', content: '', observationType: 'NEW_PLATFORM_ACTIVITY', source: 'Analyst', confidence: 70 }); clearResult(); }}
            onSubmit={() => submit(
              () => createObservation({
                actorId: form.actorId || undefined,
                content: form.content,
                observationType: form.observationType as Observation['observationType'],
                source: form.source,
                confidence: form.confidence,
              }),
              'Observation rejected',
            )}
          />
        </FormArea>
      }
      context={
        <SidePanel accent="var(--tw-low)" icon={<FileJson size={12} />} title="Recent raw notes">
          {recent.length > 0 ? (
            <div className="space-y-1.5">
              {recent.map(obs => (
                <p key={obs.id} className="font-mono text-[9px]" style={dw.muted}>{obs.id} · {obs.observationType.replace(/_/g, ' ').toLowerCase()}</p>
              ))}
            </div>
          ) : (
            <p className="font-mono text-[9px]" style={dw.faint}>No observations captured yet.</p>
          )}
        </SidePanel>
      }
    />
  );
}

// ── 9 · TIMELINE — Chronological Workspace ──────────────────────
function TimelineWorkspace({ submit, error, clearResult, createTimelineEvent }: WorkspaceProps) {
  const { getTimeline } = useIntelligence();
  const [form, setForm] = useState({ actorId: '', type: 'PLATFORM_ACTIVITY', title: '', description: '', confidence: 70 });
  const events = form.actorId ? getTimeline(form.actorId).slice(0, 3) : [];

  return (
    <ModuleFrame
      accent="var(--tw-critical)"
      icon={<Clock3 size={16} />}
      eyebrow="CHRONOLOGICAL WORKSPACE"
      title="Timeline Event"
      byline="Anchors a moment in a subject's activity record. The chronology rail previews the selected actor's recent events so a new entry is placed in context, not in isolation."
      form={
        <FormArea>
          <ActorSelect label="Seed actor" value={form.actorId} onChange={value => setForm({ ...form, actorId: value })} allowNone={false} />
          <div className="grid md:grid-cols-2 gap-3">
            <Field label="Event type">
              <select value={form.type} onChange={e => setForm({ ...form, type: e.target.value })} className={inputClass} style={inputStyle}>
                {TIMELINE_TYPES.map(type => <option key={type} value={type}>{type}</option>)}
              </select>
            </Field>
            <ConfidenceSlider label="Confidence" value={form.confidence} onChange={value => setForm({ ...form, confidence: value })} />
          </div>
          <Field label="Title">
            <input value={form.title} onChange={e => setForm({ ...form, title: e.target.value })} className={inputClass} style={inputStyle} />
          </Field>
          <Field label="Description">
            <textarea value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} rows={3} className={inputClass} style={inputStyle} />
          </Field>
          <SubmitBar
            label="Add timeline event"
            error={error}
            onClear={() => { setForm({ actorId: '', type: 'PLATFORM_ACTIVITY', title: '', description: '', confidence: 70 }); clearResult(); }}
            onSubmit={() => submit(
              () => createTimelineEvent({
                actorId: form.actorId,
                type: form.type as TimelineRecord['type'],
                title: form.title,
                description: form.description || undefined,
                confidence: form.confidence,
              }),
              'Timeline event rejected',
            )}
          />
        </FormArea>
      }
      context={
        <SidePanel accent="var(--tw-critical)" icon={<Clock3 size={12} />} title="Chronology rail">
          {form.actorId ? (
            events.length > 0 ? (
              <div className="space-y-1.5">
                <p className="font-mono text-[9px] tracking-widest uppercase" style={dw.faint}>Recent events for {form.actorId}</p>
                {events.map(event => (
                  <p key={event.id} className="font-mono text-[9px]" style={dw.muted}>{event.type.replace(/_/g, ' ').toLowerCase()} · {new Date(event.time).toLocaleDateString()}</p>
                ))}
              </div>
            ) : (
              <p className="font-mono text-[9px]" style={dw.faint}>No timeline events recorded for this actor yet.</p>
            )
          ) : (
            <p className="font-mono text-[9px]" style={dw.faint}>Select an actor to preview their chronology.</p>
          )}
        </SidePanel>
      }
    />
  );
}

// ── 10 · INVESTIGATION — Case Workspace ─────────────────────────
function InvestigationWorkspace({ submit, error, clearResult, createInvestigation }: WorkspaceProps) {
  const { dataset } = useIntelligence();
  const [form, setForm] = useState({ title: '', description: '', seedActorId: '', analyst: 'Analyst' });
  const open = dataset.investigations.filter(investigation => investigation.status !== 'COMPLETED');

  return (
    <ModuleFrame
      accent="var(--tw-high)"
      icon={<Network size={16} />}
      eyebrow="CASE WORKSPACE"
      title="Open Investigation"
      byline="Opens a case that resolves to one seed actor. The case workspace will gather the subject's actors, identities, evidence and timeline from the central model as you attach records."
      form={
        <FormArea>
          <Field label="Title">
            <input value={form.title} onChange={e => setForm({ ...form, title: e.target.value })} className={inputClass} style={inputStyle} placeholder="Project HOLLOWMARK" />
          </Field>
          <ActorSelect label="Seed actor" hint="The central entity the investigation resolves to." value={form.seedActorId} onChange={value => setForm({ ...form, seedActorId: value })} allowNone={false} />
          <Field label="Analyst">
            <input value={form.analyst} onChange={e => setForm({ ...form, analyst: e.target.value })} className={inputClass} style={inputStyle} />
          </Field>
          <Field label="Description">
            <textarea value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} rows={3} className={inputClass} style={inputStyle} />
          </Field>
          <SubmitBar
            label="Open investigation"
            error={error}
            onClear={() => { setForm({ title: '', description: '', seedActorId: '', analyst: 'Analyst' }); clearResult(); }}
            onSubmit={() => submit(
              () => createInvestigation({
                title: form.title,
                description: form.description || undefined,
                seedActorId: form.seedActorId,
                analyst: form.analyst,
              }),
              'Investigation rejected',
            )}
          />
        </FormArea>
      }
      context={
        <SidePanel accent="var(--tw-high)" icon={<Network size={12} />} title="Case load">
          <p className="font-mono text-[10px]" style={dw.text}>{open.length} active case{open.length === 1 ? '' : 's'}</p>
          <p className="font-mono text-[9px]" style={dw.muted}>{dataset.evidence.length} evidence items available to attach</p>
        </SidePanel>
      }
    />
  );
}

// ── 11 · RELATIONSHIP — Link Analysis ───────────────────────────
function RelationshipWorkspace({ submit, error, clearResult, createRelationship }: WorkspaceProps) {
  const { dataset, typeOf, getWhyLinked } = useIntelligence();
  const [form, setForm] = useState({ sourceEntity: '', targetEntity: '', type: 'ASSOCIATED_WITH', confidence: 70, explanation: '' });
  const sourceType = form.sourceEntity.trim() ? typeOf(form.sourceEntity.trim()) : '';
  const targetType = form.targetEntity.trim() ? typeOf(form.targetEntity.trim()) : '';
  const linked = form.sourceEntity.trim() && form.targetEntity.trim()
    ? getWhyLinked(form.sourceEntity.trim(), form.targetEntity.trim())
    : null;

  return (
    <ModuleFrame
      accent="var(--tw-moss)"
      icon={<GitBranch size={16} />}
      eyebrow="LINK ANALYSIS"
      title="Assert Relationship"
      byline="Documents a directed edge between two model entities. Both ends are resolved against the model as you type, and WHY LINKED? shows what stored evidence already ties them together."
      form={
        <FormArea>
          <div className="grid md:grid-cols-2 gap-3">
            <Field label="Source entity" hint="An actor, handle, PGP, wallet or infrastructure ID.">
              <input value={form.sourceEntity} onChange={e => setForm({ ...form, sourceEntity: e.target.value })} className={inputClass} style={inputStyle} placeholder="ACTOR-001" />
            </Field>
            <Field label="Target entity">
              <input value={form.targetEntity} onChange={e => setForm({ ...form, targetEntity: e.target.value })} className={inputClass} style={inputStyle} placeholder="ACTOR-003" />
            </Field>
          </div>
          {(form.sourceEntity.trim() || form.targetEntity.trim()) && (
            <div className="flex items-center gap-2 rounded-sm border px-3 py-2" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
              <span className="font-mono text-[10px]" style={dw.text}>{form.sourceEntity.trim() || '…'}</span>
              <span className="font-mono text-[10px]" style={dw.moss}>→ [{sourceType || '?'}]</span>
              <span className="font-mono text-[10px]" style={dw.faint}>/</span>
              <span className="font-mono text-[10px]" style={dw.text}>{form.targetEntity.trim() || '…'}</span>
              <span className="font-mono text-[10px]" style={dw.moss}>[{targetType || '?'}]</span>
            </div>
          )}
          <div className="grid md:grid-cols-2 gap-3">
            <Field label="Relationship type">
              <select value={form.type} onChange={e => setForm({ ...form, type: e.target.value })} className={inputClass} style={inputStyle}>
                {RELATIONSHIP_TYPES.map(type => <option key={type} value={type}>{type}</option>)}
              </select>
            </Field>
            <ConfidenceSlider label="Confidence" value={form.confidence} onChange={value => setForm({ ...form, confidence: value })} />
          </div>
          <Field label="Explanation" hint="Shown verbatim in WHY LINKED? and in reports.">
            <textarea value={form.explanation} onChange={e => setForm({ ...form, explanation: e.target.value })} rows={3} className={inputClass} style={inputStyle} />
          </Field>
          <SubmitBar
            label="Assert relationship"
            error={error}
            onClear={() => { setForm({ sourceEntity: '', targetEntity: '', type: 'ASSOCIATED_WITH', confidence: 70, explanation: '' }); clearResult(); }}
            onSubmit={() => submit(
              () => createRelationship({
                sourceEntity: form.sourceEntity,
                targetEntity: form.targetEntity,
                type: form.type as RelationshipRecord['type'],
                confidence: form.confidence,
                explanation: form.explanation || undefined,
              }),
              'Relationship rejected',
            )}
          />
        </FormArea>
      }
      context={
        <SidePanel accent="var(--tw-moss)" icon={<Link2 size={12} />} title="WHY LINKED?">
          {linked ? (
            <div className="space-y-2">
              {linked.exists ? (
                <>
                  <p className="font-mono text-[10px]" style={dw.text}>Stored evidence links these entities at {linked.confidence}% confidence</p>
                  {linked.indicators.length > 0 && (
                    <div className="space-y-1">
                      {linked.indicators.map(indicator => (
                        <p key={indicator} className="font-mono text-[9px]" style={dw.muted}>· {indicator}</p>
                      ))}
                    </div>
                  )}
                </>
              ) : (
                <p className="font-mono text-[9px]" style={dw.faint}>No stored record ties these two entities yet — asserting now is the first evidence.</p>
              )}
            </div>
          ) : (
            <p className="font-mono text-[9px]" style={dw.faint}>Enter both entities to check what the model already links.</p>
          )}
          <p className="font-mono text-[9px]" style={dw.muted}>{dataset.relationships.length} relationships in the model</p>
        </SidePanel>
      }
    />
  );
}

// ── Extended intelligence workspaces ──────────────────────────────
// These write through the same central mutations as every other form, so a
// technique, CVE or transaction lands in the one intelligence graph and is
// immediately visible to search, relationships, timeline and AI analysis.

const MITRE_TACTICS = [
  'RECONNAISSANCE', 'RESOURCE_DEVELOPMENT', 'INITIAL_ACCESS', 'EXECUTION', 'PERSISTENCE',
  'PRIVILEGE_ESCALATION', 'DEFENSE_EVASION', 'CREDENTIAL_ACCESS', 'DISCOVERY',
  'LATERAL_MOVEMENT', 'COLLECTION', 'COMMAND_AND_CONTROL', 'EXFILTRATION', 'IMPACT',
] as const;

const MITRE_PLATFORMS = [
  'Windows', 'Linux', 'macOS', 'Android', 'iOS', 'Network', 'Cloud', 'Containers',
  'Firmware', 'Hardware', 'IoT',
] as const;

const MITRE_DATA_SOURCES = [
  'Process', 'File', 'Network Traffic', 'Registry', 'Command', 'Module', 'Script',
  'User Account', 'Process Tree', 'File System', 'Authentication', 'Cloud API', 'Email', 'Log',
] as const;

const BLOCKCHAIN_NETWORKS = [
  'BITCOIN', 'ETHEREUM', 'MONERO', 'LITECOIN', 'DASH', 'ZCASH', 'DOGECOIN',
  'BITCOIN_CASH', 'CARDANO', 'SOLANA', 'POLKADOT', 'RIPPLE', 'STELLAR', 'TRON',
  'BINANCE_SMART_CHAIN', 'OTHER',
] as const;

const CLUSTERING_METHODS = [
  'HEURISTIC', 'MULTI_SIG', 'ADDRESS_REUSE', 'TIME_BASED', 'AMOUNT_BASED',
  'EXCHANGE', 'SANCTIONS', 'AI_ANALYSIS', 'ANALYST', 'INTEL_SHARING', 'OTHER',
] as const;

const CVE_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;
const EXPLOITATION_STATUSES = [
  'ACTIVE', 'PATCHED', 'UNVERIFIED', 'PROOF_OF_CONCEPT', 'IN_THE_WILD',
  'DISCLOSURE', 'ZERO_DAY', 'RESEARCH', 'UNKNOWN',
] as const;

function MitreTtpWorkspace({ submit, error, clearResult, createMitreTtp }: WorkspaceProps) {
  const { dataset } = useIntelligence();
  const [form, setForm] = useState({
    techniqueId: '', name: '', description: '', tactic: 'INITIAL_ACCESS' as (typeof MITRE_TACTICS)[number],
    subTechniqueId: '', platforms: 'Windows', dataSources: 'Command', actorIds: '',
    infrastructureIds: '', handleIds: '', evidenceIds: '', confidence: 70,
  });
  const actors = dataset.actors;

  return (
    <ModuleFrame
      accent="var(--tw-burgundy)"
      icon={<Crosshair size={16} />}
      eyebrow="MITRE ATT&CK MAPPING"
      title="Record ATT&CK Technique"
      byline="Attaches an observed behaviour to an ATT&CK technique with the evidence that supports it. Techniques are never inferred from plausibility alone — evidence is optional but recorded confidence should reflect it."
      form={
        <FormArea>
          <div className="grid md:grid-cols-2 gap-3">
            <Field label="Technique ID" hint="e.g. T1059.001">
              <input value={form.techniqueId} onChange={e => setForm({ ...form, techniqueId: e.target.value })} className={inputClass} style={inputStyle} placeholder="T1059.001" />
            </Field>
            <Field label="Technique name">
              <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} className={inputClass} style={inputStyle} placeholder="PowerShell" />
            </Field>
          </div>
          <Field label="Description">
            <textarea value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} className={inputClass} style={inputStyle} rows={2} />
          </Field>
          <div className="grid md:grid-cols-3 gap-3">
            <Field label="Tactic">
              <select value={form.tactic} onChange={e => setForm({ ...form, tactic: e.target.value as typeof form.tactic })} className={inputClass} style={inputStyle}>
                {MITRE_TACTICS.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </Field>
            <Field label="Sub-technique ID">
              <input value={form.subTechniqueId} onChange={e => setForm({ ...form, subTechniqueId: e.target.value })} className={inputClass} style={inputStyle} placeholder="001" />
            </Field>
            <ConfidenceSlider label="Confidence" value={form.confidence} onChange={value => setForm({ ...form, confidence: value })} />
          </div>
          <TagInput label="Platforms" hint="Comma separated ATT&CK platforms" placeholder="Windows, Network" value={form.platforms} onChange={value => setForm({ ...form, platforms: value })} />
          <TagInput label="Data sources" hint="Comma separated detection data sources" placeholder="Command, Network Traffic" value={form.dataSources} onChange={value => setForm({ ...form, dataSources: value })} />
          <TagInput label="Actors" hint={`Comma separated — ${actors.length} recorded`} placeholder="ACTOR-001" value={form.actorIds} onChange={value => setForm({ ...form, actorIds: value })} />
          <TagInput label="Infrastructure" hint="Comma separated INF ids" placeholder="INF-001" value={form.infrastructureIds} onChange={value => setForm({ ...form, infrastructureIds: value })} />
          <TagInput label="Handles" hint="Comma separated HND ids" placeholder="HND-006" value={form.handleIds} onChange={value => setForm({ ...form, handleIds: value })} />
          <TagInput label="Evidence" hint="Comma separated EVID ids supporting this mapping" placeholder="EVID-003" value={form.evidenceIds} onChange={value => setForm({ ...form, evidenceIds: value })} />
          <SubmitBar
            label="Record technique"
            error={error}
            onClear={() => { setForm({ techniqueId: '', name: '', description: '', tactic: 'INITIAL_ACCESS', subTechniqueId: '', platforms: 'Windows', dataSources: 'Command', actorIds: '', infrastructureIds: '', handleIds: '', evidenceIds: '', confidence: 70 }); clearResult(); }}
            onSubmit={() => submit(
              () => createMitreTtp({
                techniqueId: form.techniqueId,
                name: form.name,
                description: form.description,
                tactic: form.tactic,
                subTechniqueId: form.subTechniqueId || undefined,
                platforms: splitList(form.platforms) as (typeof MITRE_PLATFORMS)[number][],
                dataSources: splitList(form.dataSources) as (typeof MITRE_DATA_SOURCES)[number][],
                permissionsRequired: ['User'],
                actorIds: splitList(form.actorIds),
                infrastructureIds: splitList(form.infrastructureIds),
                handleIds: splitList(form.handleIds),
                evidenceIds: splitList(form.evidenceIds),
                confidence: form.confidence,
              }),
              'Recording ATT&CK technique failed',
            )}
          />
        </FormArea>
      }
    />
  );
}

function CveWorkspace({ submit, error, clearResult, createCve }: WorkspaceProps) {
  const { dataset } = useIntelligence();
  const [form, setForm] = useState({
    cveId: '', title: '', description: '', severity: 'HIGH' as (typeof CVE_SEVERITIES)[number],
    cvssScore: 7.5, cvssVector: '', cweIds: '', affectedSoftware: '',
    publishedDate: '', exploitationStatus: 'UNVERIFIED' as (typeof EXPLOITATION_STATUSES)[number],
    actorIds: '', infrastructureIds: '', handleIds: '', evidenceIds: '',
    darkWebSources: '', confidence: 70,
  });
  const blank = { cveId: '', title: '', description: '', severity: 'HIGH' as const, cvssScore: 7.5, cvssVector: '', cweIds: '', affectedSoftware: '', publishedDate: '', exploitationStatus: 'UNVERIFIED' as const, actorIds: '', infrastructureIds: '', handleIds: '', evidenceIds: '', darkWebSources: '', confidence: 70 };

  return (
    <ModuleFrame
      accent="var(--tw-burgundy)"
      icon={<AlertTriangle size={16} />}
      eyebrow="VULNERABILITY INTELLIGENCE"
      title="Record CVE"
      byline="Stores exploitation intelligence observed in collected sources. Record the status you can evidence — an unverified dark-web claim stays UNVERIFIED rather than being promoted."
      form={
        <FormArea>
          <div className="grid md:grid-cols-2 gap-3">
            <Field label="CVE ID" hint="e.g. CVE-2026-90001">
              <input value={form.cveId} onChange={e => setForm({ ...form, cveId: e.target.value })} className={inputClass} style={inputStyle} placeholder="CVE-2026-90001" />
            </Field>
            <Field label="Title">
              <input value={form.title} onChange={e => setForm({ ...form, title: e.target.value })} className={inputClass} style={inputStyle} />
            </Field>
          </div>
          <Field label="Description">
            <textarea value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} className={inputClass} style={inputStyle} rows={2} />
          </Field>
          <div className="grid md:grid-cols-4 gap-3">
            <Field label="Severity">
              <select value={form.severity} onChange={e => setForm({ ...form, severity: e.target.value as typeof form.severity })} className={inputClass} style={inputStyle}>
                {CVE_SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </Field>
            <Field label="CVSS score">
              <input type="number" step="0.1" min="0" max="10" value={form.cvssScore} onChange={e => setForm({ ...form, cvssScore: Number(e.target.value) })} className={inputClass} style={inputStyle} />
            </Field>
            <Field label="Published">
              <input value={form.publishedDate} onChange={e => setForm({ ...form, publishedDate: e.target.value })} className={inputClass} style={inputStyle} placeholder="2026-01-20" />
            </Field>
            <Field label="Exploitation status">
              <select value={form.exploitationStatus} onChange={e => setForm({ ...form, exploitationStatus: e.target.value as typeof form.exploitationStatus })} className={inputClass} style={inputStyle}>
                {EXPLOITATION_STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </Field>
          </div>
          <Field label="CVSS vector">
            <input value={form.cvssVector} onChange={e => setForm({ ...form, cvssVector: e.target.value })} className={inputClass} style={inputStyle} placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" />
          </Field>
          <TagInput label="CWE ids" hint="Comma separated" placeholder="CWE-502" value={form.cweIds} onChange={value => setForm({ ...form, cweIds: value })} />
          <TagInput label="Affected software" hint="Comma separated products" placeholder="Synthetic Report Engine 4.x" value={form.affectedSoftware} onChange={value => setForm({ ...form, affectedSoftware: value })} />
          <TagInput label="Actors" hint={`Comma separated — ${dataset.actors.length} recorded`} placeholder="ACTOR-001" value={form.actorIds} onChange={value => setForm({ ...form, actorIds: value })} />
          <TagInput label="Infrastructure" placeholder="INF-001" value={form.infrastructureIds} onChange={value => setForm({ ...form, infrastructureIds: value })} />
          <TagInput label="Handles" placeholder="HND-006" value={form.handleIds} onChange={value => setForm({ ...form, handleIds: value })} />
          <TagInput label="Evidence" hint="Evidence supporting the exploitation claim" placeholder="EVID-003" value={form.evidenceIds} onChange={value => setForm({ ...form, evidenceIds: value })} />
          <TagInput label="Dark web sources" placeholder="SRC-FORUM-A" value={form.darkWebSources} onChange={value => setForm({ ...form, darkWebSources: value })} />
          <ConfidenceSlider label="Confidence" value={form.confidence} onChange={value => setForm({ ...form, confidence: value })} />
          <SubmitBar
            label="Record CVE"
            error={error}
            onClear={() => { setForm(blank); clearResult(); }}
            onSubmit={() => submit(
              () => createCve({
                cveId: form.cveId,
                title: form.title,
                description: form.description,
                severity: form.severity,
                cvssScore: form.cvssScore,
                cvssVector: form.cvssVector,
                cweIds: splitList(form.cweIds),
                categories: ['WEB_APPLICATION'],
                publishedDate: form.publishedDate || new Date().toISOString(),
                lastModifiedDate: new Date().toISOString(),
                affectedSoftware: splitList(form.affectedSoftware),
                actorIds: splitList(form.actorIds),
                infrastructureIds: splitList(form.infrastructureIds),
                handleIds: splitList(form.handleIds),
                evidenceIds: splitList(form.evidenceIds),
                exploitationStatus: form.exploitationStatus,
                darkWebSources: splitList(form.darkWebSources),
                confidence: form.confidence,
              }),
              'Recording CVE failed',
            )}
          />
        </FormArea>
      }
    />
  );
}

function WalletTransactionWorkspace({ submit, error, clearResult, createWalletTransaction }: WorkspaceProps) {
  const { dataset } = useIntelligence();
  const [form, setForm] = useState({
    walletId: dataset.wallets[0]?.id ?? '', hash: '', network: 'BITCOIN' as (typeof BLOCKCHAIN_NETWORKS)[number],
    timestamp: '', amount: 0, currency: 'BTC', fromAddress: '', toAddress: '', fee: 0,
    direction: 'IN' as 'IN' | 'OUT' | 'SELF', status: 'CONFIRMED' as 'PENDING' | 'CONFIRMED' | 'UNCONFIRMED' | 'DOUBLE_SPEND' | 'REPLACED' | 'FAILED',
    confirmations: 0, exchangeIds: '', clusterId: '', actorIds: '', handleIds: '',
    evidenceIds: '', isMixing: false, mixingService: '', confidence: 70,
  });
  const blank = { ...form, hash: '', timestamp: '', amount: 0, fromAddress: '', toAddress: '', fee: 0, confirmations: 0, exchangeIds: '', clusterId: '', actorIds: '', handleIds: '', evidenceIds: '', isMixing: false, mixingService: '' };

  return (
    <ModuleFrame
      accent="var(--tw-burgundy)"
      icon={<ArrowLeftRight size={16} />}
      eyebrow="CRYPTO INTELLIGENCE"
      title="Record Transaction"
      byline="Stores an observed transaction against a recorded wallet. Mixing and privacy-service flags are recorded as indicators with a reason — never as a claim of criminality, and never with any ability to move funds."
      form={
        <FormArea>
          <div className="grid md:grid-cols-2 gap-3">
            <Field label="Wallet" hint={`${dataset.wallets.length} recorded wallets`}>
              <select value={form.walletId} onChange={e => setForm({ ...form, walletId: e.target.value })} className={inputClass} style={inputStyle}>
                {dataset.wallets.map(w => <option key={w.id} value={w.id}>{w.id} — {w.address.slice(0, 20)}…</option>)}
              </select>
            </Field>
            <Field label="Transaction hash">
              <input value={form.hash} onChange={e => setForm({ ...form, hash: e.target.value })} className={inputClass} style={inputStyle} />
            </Field>
          </div>
          <div className="grid md:grid-cols-4 gap-3">
            <Field label="Network">
              <select value={form.network} onChange={e => setForm({ ...form, network: e.target.value as typeof form.network })} className={inputClass} style={inputStyle}>
                {BLOCKCHAIN_NETWORKS.map(n => <option key={n} value={n}>{n}</option>)}
              </select>
            </Field>
            <Field label="Timestamp">
              <input value={form.timestamp} onChange={e => setForm({ ...form, timestamp: e.target.value })} className={inputClass} style={inputStyle} placeholder="2026-06-14T22:03:00Z" />
            </Field>
            <Field label="Amount" hint="Base units (satoshis for BTC)">
              <input type="number" min="0" value={form.amount} onChange={e => setForm({ ...form, amount: Number(e.target.value) })} className={inputClass} style={inputStyle} />
            </Field>
            <Field label="Currency">
              <input value={form.currency} onChange={e => setForm({ ...form, currency: e.target.value })} className={inputClass} style={inputStyle} placeholder="BTC" />
            </Field>
          </div>
          <div className="grid md:grid-cols-2 gap-3">
            <Field label="From address">
              <input value={form.fromAddress} onChange={e => setForm({ ...form, fromAddress: e.target.value })} className={inputClass} style={inputStyle} />
            </Field>
            <Field label="To address">
              <input value={form.toAddress} onChange={e => setForm({ ...form, toAddress: e.target.value })} className={inputClass} style={inputStyle} />
            </Field>
          </div>
          <div className="grid md:grid-cols-4 gap-3">
            <Field label="Fee">
              <input type="number" min="0" value={form.fee} onChange={e => setForm({ ...form, fee: Number(e.target.value) })} className={inputClass} style={inputStyle} />
            </Field>
            <Field label="Direction">
              <select value={form.direction} onChange={e => setForm({ ...form, direction: e.target.value as typeof form.direction })} className={inputClass} style={inputStyle}>
                <option value="IN">IN</option><option value="OUT">OUT</option><option value="SELF">SELF</option>
              </select>
            </Field>
            <Field label="Status">
              <select value={form.status} onChange={e => setForm({ ...form, status: e.target.value as typeof form.status })} className={inputClass} style={inputStyle}>
                <option value="PENDING">PENDING</option><option value="CONFIRMED">CONFIRMED</option>
                <option value="UNCONFIRMED">UNCONFIRMED</option><option value="FAILED">FAILED</option>
              </select>
            </Field>
            <Field label="Confirmations">
              <input type="number" min="0" value={form.confirmations} onChange={e => setForm({ ...form, confirmations: Number(e.target.value) })} className={inputClass} style={inputStyle} />
            </Field>
          </div>
          <div className="grid md:grid-cols-2 gap-3">
            <Field label="Exchange ids" hint="Known service attribution">
              <input value={form.exchangeIds} onChange={e => setForm({ ...form, exchangeIds: e.target.value })} className={inputClass} style={inputStyle} placeholder="EXC-001, EXC-002" />
            </Field>
            <Field label="Cluster id">
              <input value={form.clusterId} onChange={e => setForm({ ...form, clusterId: e.target.value })} className={inputClass} style={inputStyle} placeholder="CLU-001" />
            </Field>
          </div>
          <TagInput label="Actors" hint={`Comma separated — ${dataset.actors.length} recorded`} placeholder="ACTOR-001" value={form.actorIds} onChange={value => setForm({ ...form, actorIds: value })} />
          <TagInput label="Handles" placeholder="HND-006" value={form.handleIds} onChange={value => setForm({ ...form, handleIds: value })} />
          <TagInput label="Evidence" placeholder="EVID-003" value={form.evidenceIds} onChange={value => setForm({ ...form, evidenceIds: value })} />
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={form.isMixing} onChange={e => setForm({ ...form, isMixing: e.target.checked })} />
            <span className="font-mono text-[9px] tracking-widest uppercase" style={dw.muted}>Privacy-service / mixing indicator</span>
          </label>
          {form.isMixing && (
            <Field label="Detection reason" hint="Required when the mixing indicator is set. State the observed pattern, not a conclusion.">
              <input value={form.mixingService} onChange={e => setForm({ ...form, mixingService: e.target.value })} className={inputClass} style={inputStyle} placeholder="Routed to a known privacy service" />
            </Field>
          )}
          <ConfidenceSlider label="Confidence" value={form.confidence} onChange={value => setForm({ ...form, confidence: value })} />
          <SubmitBar
            label="Record transaction"
            error={error}
            onClear={() => { setForm(blank); clearResult(); }}
            onSubmit={() => submit(
              () => createWalletTransaction({
                walletId: form.walletId,
                hash: form.hash,
                network: form.network,
                timestamp: form.timestamp || new Date().toISOString(),
                blockHeight: 0,
                amount: form.amount,
                currency: form.currency,
                fromAddress: form.fromAddress,
                toAddress: form.toAddress,
                fee: form.fee,
                direction: form.direction,
                status: form.status,
                confirmations: form.confirmations,
                exchangeIds: splitList(form.exchangeIds),
                clusterId: form.clusterId || undefined,
                actorIds: splitList(form.actorIds),
                handleIds: splitList(form.handleIds),
                evidenceIds: splitList(form.evidenceIds),
                isCoinbase: false,
                isMixing: form.isMixing,
                mixingService: form.isMixing ? form.mixingService : undefined,
                inputCount: 1,
                outputCount: 1,
                totalInput: form.amount + form.fee,
                totalOutput: form.amount,
                isFlagged: form.isMixing,
                flagReason: form.isMixing ? form.mixingService : undefined,
                confidence: form.confidence,
              }),
              'Recording transaction failed',
            )}
          />
        </FormArea>
      }
    />
  );
}

function WalletClusterWorkspace({ submit, error, clearResult, createWalletCluster }: WorkspaceProps) {
  const { dataset } = useIntelligence();
  const [form, setForm] = useState({
    walletIds: '', actorId: '', method: 'HEURISTIC' as (typeof CLUSTERING_METHODS)[number],
    reasoning: '', confidence: 70,
  });
  const blank = { walletIds: '', actorId: '', method: 'HEURISTIC' as const, reasoning: '', confidence: 70 };

  return (
    <ModuleFrame
      accent="var(--tw-burgundy)"
      icon={<Boxes size={16} />}
      eyebrow="WALLET CLUSTERING"
      title="Record Wallet Cluster"
      byline="Groups wallets an analyst judges to share control. The reasoning you record is shown alongside the grouping, so a cluster is never presented as a bare assertion."
      form={
        <FormArea>
          <TagInput label="Wallet addresses" hint={`Comma separated — ${dataset.wallets.length} recorded`} placeholder="bc1q… , bc1q…" value={form.walletIds} onChange={value => setForm({ ...form, walletIds: value })} />
          <Field label="Attributed actor" hint="Optional. Leave blank when control is not attributed.">
            <select value={form.actorId} onChange={e => setForm({ ...form, actorId: e.target.value })} className={inputClass} style={inputStyle}>
              <option value="">— unattributed —</option>
              {dataset.actors.map(a => <option key={a.id} value={a.id}>{a.id} — {a.aliases[0] ?? a.id}</option>)}
            </select>
          </Field>
          <div className="grid md:grid-cols-2 gap-3">
            <Field label="Clustering method">
              <select value={form.method} onChange={e => setForm({ ...form, method: e.target.value as typeof form.method })} className={inputClass} style={inputStyle}>
                {CLUSTERING_METHODS.map(m => <option key={m} value={m}>{m}</option>)}
              </select>
            </Field>
            <ConfidenceSlider label="Confidence" value={form.confidence} onChange={value => setForm({ ...form, confidence: value })} />
          </div>
          <Field label="Reasoning" hint="Required. State the evidence that supports shared control.">
            <textarea value={form.reasoning} onChange={e => setForm({ ...form, reasoning: e.target.value })} className={inputClass} style={inputStyle} rows={3} />
          </Field>
          <SubmitBar
            label="Record cluster"
            error={error}
            onClear={() => { setForm(blank); clearResult(); }}
            onSubmit={() => submit(
              () => createWalletCluster({
                walletIds: splitList(form.walletIds),
                actorId: form.actorId || undefined,
                method: form.method,
                reasoning: form.reasoning,
                confidence: form.confidence,
              }),
              'Recording wallet cluster failed',
            )}
          />
        </FormArea>
      }
    />
  );
}

// ── Page ────────────────────────────────────────────────────────
export default function AddIntelligencePage() {
  const {
    createActor,
    createHandle,
    createPgp,
    createWallet,
    createInfrastructure,
    createSource,
    createEvidence,
    createObservation,
    createTimelineEvent,
    createInvestigation,
    createRelationship,
    createMitreTtp,
    createCve,
    createWalletTransaction,
    createWalletCluster,
    dataset,
    loadDemo,
    resetDemo,
    clearData,
    exportData,
    importData,
    isDemoLoaded,
    storageKey,
  } = useIntelligence();

  const [form, setForm] = useState<FormKey>('actor');
  const { result, error, setResult, setError, reset } = useResult();
  const [importText, setImportText] = useState('');
  const [importError, setImportError] = useState<string | null>(null);
  const [importSummary, setImportSummary] = useState<string | null>(null);
  const [importResult, setImportResult] = useState<MutationResult<unknown> | null>(null);

  const datasetCounts = useMemo(() => [
    ['Actors', dataset.actors.length],
    ['Handles', dataset.handles.length],
    ['PGP keys', dataset.pgpKeys.length],
    ['Wallets', dataset.wallets.length],
    ['Infrastructure', dataset.infrastructure.length],
    ['Sources', dataset.sources.length],
    ['Observations', dataset.observations.length],
    ['Evidence', dataset.evidence.length],
    ['Relationships', dataset.relationships.length],
    ['Timeline', dataset.timeline.length],
    ['Investigations', dataset.investigations.length],
    ['Alerts', dataset.alerts.length],
    ['Audit events', dataset.audit.length],
  ] as [string, number][], [dataset]);

  const submit = (fn: () => MutationResult<unknown>, message: string) => {
    try {
      setResult(fn());
      setError(null);
    } catch (thrown) {
      setResult(null);
      setError(`${message}: ${thrown instanceof Error ? thrown.message : String(thrown)}`);
    }
  };

  const handleImport = () => {
    try {
      const parsed = JSON.parse(importText) as unknown;
      const { result: importMutationResult, summary } = importData(parsed);
      setImportError(null);
      setImportResult(importMutationResult);
      setImportSummary(summary.map(entry => `${entry.count} ${entry.collection}`).join(' · '));
    } catch (thrown) {
      setImportResult(null);
      setImportError(thrown instanceof SyntaxError ? `Invalid JSON: ${thrown.message}` : thrown instanceof Error ? thrown.message : 'Import failed.');
    }
  };

  const downloadJson = () => {
    const blob = new Blob([JSON.stringify(exportData(), null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'viper-trace-intelligence-dataset.json';
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const creators = {
    createActor,
    createHandle,
    createPgp,
    createWallet,
    createInfrastructure,
    createSource,
    createEvidence,
    createObservation,
    createTimelineEvent,
    createInvestigation,
    createRelationship,
    createMitreTtp,
    createCve,
    createWalletTransaction,
    createWalletCluster,
  };

  const workspaces: Partial<Record<FormKey, ReactNode>> = {
    actor: <ActorWorkspace submit={submit} error={error} clearResult={reset} {...creators} />,
    handle: <HandleWorkspace submit={submit} error={error} clearResult={reset} {...creators} />,
    pgp: <PgpWorkspace submit={submit} error={error} clearResult={reset} {...creators} />,
    wallet: <WalletWorkspace submit={submit} error={error} clearResult={reset} {...creators} />,
    infrastructure: <InfrastructureWorkspace submit={submit} error={error} clearResult={reset} {...creators} />,
    source: <SourceWorkspace submit={submit} error={error} clearResult={reset} {...creators} />,
    evidence: <EvidenceWorkspace submit={submit} error={error} clearResult={reset} {...creators} />,
    observation: <ObservationWorkspace submit={submit} error={error} clearResult={reset} {...creators} />,
    timeline: <TimelineWorkspace submit={submit} error={error} clearResult={reset} {...creators} />,
    investigation: <InvestigationWorkspace submit={submit} error={error} clearResult={reset} {...creators} />,
    relationship: <RelationshipWorkspace submit={submit} error={error} clearResult={reset} {...creators} />,
  mitreTtp: <MitreTtpWorkspace submit={submit} error={error} clearResult={reset} {...creators} />,
  cve: <CveWorkspace submit={submit} error={error} clearResult={reset} {...creators} />,
  walletTransaction: <WalletTransactionWorkspace submit={submit} error={error} clearResult={reset} {...creators} />,
  walletCluster: <WalletClusterWorkspace submit={submit} error={error} clearResult={reset} {...creators} />,
  };

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <Plus size={16} style={dw.critical} />
            <h1 className="font-serif text-3xl" style={dw.text}>Add Intelligence</h1>
          </div>
          <p className="text-sm max-w-2xl" style={dw.muted}>
            One write surface for the central model. Each submission records the record you supply and
            derives only what that evidence supports — relationships, alerts, timeline events and audit
            entries are generated for you, never invented. {isDemoLoaded ? <DemoLabel /> : null}
          </p>
        </div>

        <div className="grid lg:grid-cols-4 gap-6">
          {/* Record-type picker */}
          <div className="space-y-1">
            <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Record type</p>
            {FORMS.map(entry => {
              const Icon = entry.icon;
              const active = entry.key === form;
              return (
                <button key={entry.key} type="button" onClick={() => { setForm(entry.key); reset(); }}
                  className="w-full flex items-center gap-2 px-3 py-2 rounded-sm border text-left transition-colors"
                  style={{
                    backgroundColor: active ? 'var(--tw-canvas-mid)' : 'transparent',
                    borderColor: active ? 'var(--tw-burgundy)' : 'var(--tw-border-mid)',
                    color: active ? 'var(--tw-text)' : 'var(--tw-text-muted)',
                  }}>
                  <Icon size={13} />
                  <span className="font-mono text-[11px]">{entry.label}</span>
                </button>
              );
            })}

            <div className="rounded-sm border p-3 mt-4 space-y-2" style={dw.panel}>
              <p className="font-mono text-[9px] tracking-widest uppercase" style={dw.faint}>Central model</p>
              <div className="space-y-0.5">
                {datasetCounts.map(([label, count]) => (
                  <p key={label} className="flex items-center justify-between font-mono text-[10px]">
                    <span style={dw.muted}>{label}</span>
                    <span style={count ? dw.text : dw.faint}>{count}</span>
                  </p>
                ))}
              </div>
            </div>
          </div>

          {/* Workspace + result */}
          <div className="lg:col-span-3 space-y-4">
            {workspaces[form]}

            {result && <FanOut result={result} />}

            {/* Import / dataset controls */}
            <div className="rounded-sm border p-5 space-y-3" style={dw.panel}>
              <div className="flex items-center gap-2">
                <Upload size={13} style={dw.critical} />
                <p className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>Import intelligence</p>
              </div>
              <p className="text-xs" style={dw.muted}>
                Paste a dataset document. Imported records replace the central model, every id lookup is
                rebuilt, and the import is audit-logged — imported and typed records behave identically.
              </p>
              <textarea value={importText} onChange={e => setImportText(e.target.value)} rows={5}
                className="w-full font-mono text-[11px] p-2 rounded-sm focus:outline-none"
                style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }}
                placeholder='{ "actors": [ … ], "handles": [ … ], "relationships": [ … ] }' />
              <div className="flex flex-wrap items-center gap-3">
                <button type="button" onClick={handleImport}
                  className="flex items-center gap-1.5 font-mono text-[10px] tracking-widest uppercase px-3 py-1.5 rounded-sm"
                  style={dw.bgBurg}>
                  <span style={{ color: '#FBFAF6' }}>Import</span>
                </button>
                {importSummary && (
                  <p className="font-mono text-[10px]" style={dw.text}>Imported: {importSummary}</p>
                )}
              </div>
              <ErrorNote error={importError} />
              {importResult && <FanOut result={importResult} />}
            </div>

<div className="rounded-sm border p-5 space-y-3" style={dw.panel}>
              <div className="flex items-center gap-2">
                <Shield size={13} style={dw.critical} />
                <p className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>Dataset controls</p>
              </div>
              <p className="text-xs" style={dw.muted}>
                Stored locally under <span className="font-mono" style={dw.text}>{storageKey}</span>. These
                actions replace the whole model, so they are audit-logged.
              </p>
              <div className="flex flex-wrap gap-2">
                <button type="button" onClick={() => loadDemo()}
                  className="font-mono text-[10px] tracking-widest uppercase px-3 py-1.5 rounded-sm border"
                  style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }}>
                  Load synthetic demo
                </button>
                <button type="button" onClick={() => resetDemo()}
                  className="font-mono text-[10px] tracking-widest uppercase px-3 py-1.5 rounded-sm border"
                  style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }}>
                  Reset to demo
                </button>
                <button type="button" onClick={downloadJson}
                  className="flex items-center gap-1.5 font-mono text-[10px] tracking-widest uppercase px-3 py-1.5 rounded-sm border"
                  style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }}>
                  <Download size={11} /> Export JSON
                </button>
                <button type="button" onClick={() => clearData()}
                  className="flex items-center gap-1.5 font-mono text-[10px] tracking-widest uppercase px-3 py-1.5 rounded-sm border"
                  style={{ borderColor: 'var(--tw-critical)', color: 'var(--tw-critical)' }}>
                  <Trash2 size={11} /> Clear all intelligence
                </button>
              </div>
              <p className="font-mono text-[9px]" style={dw.faint}>
                <X size={9} className="inline" /> Clearing empties the model but keeps the schema, so every
                page stays usable and shows its empty state.
              </p>
            </div>
            <ProtectionModulePanel entityType="ACTOR" />
          </div>
        </div>
      </div>
    </motion.div>
  );
}
