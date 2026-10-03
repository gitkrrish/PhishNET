import { useState, useMemo, useEffect } from 'react';
import { Search, Filter, Database, Hash, ShieldCheck } from 'lucide-react';
import { motion } from 'framer-motion';
import { useSearchParams } from 'react-router-dom';
import { dw, sectionStyle } from '../../lib/darkweb/styles';
import { useIntelligenceData } from '../../lib/intelligence/IntelligenceContext';
import { validateEvidenceHash, duplicateDigests, analyseCustody } from '../../lib/intelligence/evidence';
import { MetaCell } from '../../components/darkweb/EntityWorkspace';
import { EvidenceItem } from '../../components/darkweb/EvidenceItem';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { ProtectionModulePanel } from '../../components/darkweb/ProtectionModulePanel';
import { ChainOfCustody } from '../../components/darkweb/ChainOfCustody';

// A single standing caveat, shown with the conclusions it limits.
function Finding({ tone, label, children }: {
  tone: 'ok' | 'warn' | 'info';
  label: string;
  children: React.ReactNode;
}) {
  const accent = tone === 'warn' ? dw.critical : tone === 'ok' ? dw.moss : dw.brass;
  return (
    <div className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
      <span style={accent}>{label}</span>
      <p className="mt-1 leading-relaxed" style={dw.muted}>{children}</p>
    </div>
  );
}

const TABS = [
  { key: 'locker', label: 'Locker' },
  { key: 'custody', label: 'Chain of Custody' },
] as const;

type TabKey = (typeof TABS)[number]['key'];

export default function EvidenceLockerPage() {
  const [searchParams] = useSearchParams();
  const { darkWebEvidence, darkWebActorsById } = useIntelligenceData();
  const actorParam = searchParams.get('actor');
  const evidenceParam = searchParams.get('evidence');
  const [tab, setTab] = useState<TabKey>(evidenceParam && darkWebEvidence.some(e => e.id === evidenceParam) ? 'custody' : 'locker');
  // Chain of custody is per evidence item, so the tab needs a selection.
  // Defaults to the first stored item so the panel is never blank.
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string>(
    evidenceParam ?? darkWebEvidence[0]?.id ?? ''
  );
  const [search, setSearch] = useState('');
  const [actorFilter, setActorFilter] = useState<string | 'all'>(
    actorParam && darkWebActorsById[actorParam] ? actorParam : 'all'
  );
  const [typeFilter, setTypeFilter] = useState<string | 'all'>('all');
  const [reliabilityMin, setReliabilityMin] = useState(0);

  // Deep link from a threat actor profile: /app/darkweb/evidence?actor=ACTOR-001
  useEffect(() => {
    if (actorParam && darkWebActorsById[actorParam]) setActorFilter(actorParam);
  }, [actorParam, darkWebActorsById]);

  // Deep link to one item's custody chain: ?evidence=EVID-001
  useEffect(() => {
    if (!evidenceParam) return;
    if (darkWebEvidence.some(e => e.id === evidenceParam)) {
      setSelectedEvidenceId(evidenceParam);
      setTab('custody');
    }
  }, [evidenceParam, darkWebEvidence]);

  const types = Array.from(new Set(darkWebEvidence.map(e => e.evidenceType)));
  const actors = Array.from(new Set(darkWebEvidence.map(e => e.relatedActor).filter(Boolean)));

  const filtered = useMemo(() => {
    let items = darkWebEvidence;
    const q = search.toLowerCase();
    if (q) items = items.filter(e => e.id.toLowerCase().includes(q) || e.provenance.toLowerCase().includes(q) || (e.source.toLowerCase().includes(q)));
    if (actorFilter !== 'all') items = items.filter(e => e.relatedActor === actorFilter);
    if (typeFilter !== 'all') items = items.filter(e => e.evidenceType === typeFilter);
    items = items.filter(e => e.reliability >= reliabilityMin);
    return items;
  }, [search, actorFilter, typeFilter, reliabilityMin, darkWebEvidence]);

  // Integrity is reported from the recorded digests, not assumed. A digest
  // that is well formed is an integrity *claim*; without the file it cannot
  // be recomputed, so nothing here claims the evidence is unaltered.
  const integrity = useMemo(() => {
    const digests = darkWebEvidence.map(e => validateEvidenceHash(e.hash));
    const malformed = darkWebEvidence.filter((_, i) => !digests[i].structurallyValid);
    const algorithms = Array.from(new Set(digests.map(d => d.algorithm).filter(Boolean))) as string[];
    const duplicates = duplicateDigests(darkWebEvidence);
    const custody = darkWebEvidence.map(e => analyseCustody(e, darkWebEvidence));
    const impossible = custody.filter(c => c.findings.some(f => f.label.includes('Observed after')));
    const batches = new Map<string, number>();
    for (const e of darkWebEvidence) {
      const key = e.collectionTimestamp.slice(0, 16);
      batches.set(key, (batches.get(key) ?? 0) + 1);
    }
    return {
      total: darkWebEvidence.length,
      wellFormed: digests.filter(d => d.structurallyValid).length,
      malformed: malformed.map(e => e.id),
      algorithms,
      duplicateGroups: duplicates.size,
      impossible: impossible.length,
      // An empty dataset has no batches, and Math.max() of nothing is
      // -Infinity. Report 0 rather than rendering a negative count.
      largestBatch: batches.size ? Math.max(...batches.values()) : 0,
      withContent: 0,
    };
  }, [darkWebEvidence]);

  const integrityCheck = () => {
    const unverified = darkWebEvidence.filter(e => e.reliability < 80);
    return `${darkWebEvidence.length - unverified.length}/${darkWebEvidence.length} items meet the R80+ reliability threshold`;
  };

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        <div className="flex items-center justify-between"><div className="flex items-center gap-2"><Database size={16} style={dw.critical} /><h1 className="font-serif text-3xl" style={dw.text}>Evidence Locker</h1></div><DemoLabel /></div>
        <p className="text-sm max-w-xl" style={dw.muted}>
          {filtered.length} of {darkWebEvidence.length} evidence items. {integrityCheck()}.{' '}
          {integrity.wellFormed}/{integrity.total} recorded digests are well formed
          {integrity.algorithms.length > 0 && ` (${integrity.algorithms.join(', ').toUpperCase()})`}.
          {' '}No evidence file is stored alongside these records, so no digest here can be recomputed and none
          of them demonstrates that the underlying content is unaltered.
        </p>

        {/* The two views answer different questions: the locker catalogues
            every item, the custody tab traces one item's handling. The
            filter controls below belong to the locker only, so they stay
            inside the locker branch rather than filtering a custody
            record that they cannot describe. */}
        <div role="tablist" aria-label="Evidence Locker views" className="flex gap-1 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
          {TABS.map(item => {
            const active = tab === item.key;
            return (
              <button
                key={item.key}
                role="tab"
                type="button"
                aria-selected={active}
                onClick={() => setTab(item.key)}
                className="font-mono text-[10px] tracking-widest uppercase px-3 py-2 -mb-px border-b-2 transition-colors"
                style={{
                  borderBottomColor: active ? 'var(--tw-burgundy)' : 'transparent',
                  color: active ? 'var(--tw-text)' : 'var(--tw-text-faint)',
                }}
              >
                {item.label}
              </button>
            );
          })}
        </div>

        {tab === 'custody' ? (
          <div className="space-y-4">
            <label className="block max-w-md">
              <span className="font-mono text-[9px] uppercase block mb-1" style={dw.faint}>Evidence item</span>
              <select
                value={selectedEvidenceId}
                onChange={e => setSelectedEvidenceId(e.target.value)}
                className="w-full font-mono text-[10px] px-2 py-1.5 rounded-sm focus:outline-none"
                style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)', borderWidth: '1px', borderStyle: 'solid' }}
              >
                {darkWebEvidence.map(e => (
                  <option key={e.id} value={e.id}>{e.id} · {e.evidenceType.replace(/_/g, ' ')} · R{e.reliability}</option>
                ))}
              </select>
            </label>
            {selectedEvidenceId ? (
              <ChainOfCustody
                evidenceId={selectedEvidenceId}
                evidenceLabel={darkWebEvidence.find(e => e.id === selectedEvidenceId)?.description}
              />
            ) : (
              <p className="font-mono text-[10px]" style={dw.muted}>No evidence item is available to trace.</p>
            )}
          </div>
        ) : (
          <>
        <div className="flex flex-col md:flex-row gap-3 items-end">
          <div className="relative w-full md:w-64">
            <Search size={12} className="absolute left-2 top-1/2 -translate-y-1/2" style={{ color: 'var(--tw-text-faint)' }} />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search evidence ID, source, provenance…"
              className="w-full font-mono text-[11px] pl-7 pr-2 py-1.5 rounded-sm focus:outline-none"
              style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }} />
          </div>
          <div className="flex flex-wrap gap-2">
            <select value={actorFilter} onChange={e => setActorFilter(e.target.value)} className="font-mono text-[10px] px-2 py-1 rounded-sm" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }}>
              <option value="all">All Actors</option>{actors.map(a => <option key={a!} value={a!}>{a!}</option>)}
            </select>
            <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)} className="font-mono text-[10px] px-2 py-1 rounded-sm" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }}>
              <option value="all">All Types</option>{types.map(t => <option key={t} value={t}>{t.replace('_', ' ')}</option>)}
            </select>
            <label className="flex items-center gap-1 font-mono text-[10px]" style={dw.muted}>
              <Filter size={11} /> R≥<input type="range" min="0" max="100" step="10" value={reliabilityMin} onChange={e => setReliabilityMin(Number(e.target.value))} className="w-20" style={{ accentColor: 'var(--tw-burgundy)' }} />
              {reliabilityMin}
            </label>
          </div>
        </div>

        <div className="rounded-sm border p-4 space-y-3" style={dw.panel}>
          <p className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>Integrity &amp; chain of custody</p>

          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <MetaCell
              label="Digests well formed"
              value={`${integrity.wellFormed}/${integrity.total}`}
              color={integrity.malformed.length ? dw.critical.color : dw.moss.color}
            />
            <MetaCell label="Digest algorithms" value={integrity.algorithms.length ? integrity.algorithms.join(', ').toUpperCase() : 'none recorded'} />
            <MetaCell label="Identical digests" value={`${integrity.duplicateGroups} group(s)`} />
            <MetaCell label="Impossible ordering" value={`${integrity.impossible} record(s)`} color={integrity.impossible ? dw.critical.color : undefined} />
          </div>

          {integrity.malformed.length > 0 && (
            <p className="font-mono text-[10px] leading-relaxed" style={dw.critical}>
              {integrity.malformed.length} record(s) carry a digest that is not a well-formed value for its stated
              algorithm: {integrity.malformed.join(', ')}. A digest of the wrong length cannot be a real digest,
              so these integrity claims are unusable until corrected.
            </p>
          )}

          <div className="space-y-1.5">
            <Finding tone="warn" label="No evidence content is stored">
              These records hold a provenance description and a digest, but no file. EXIF, OCR and raw-content
              inspection were therefore not possible, and the digest of each item cannot be recomputed against
              its original. Attaching the seized files is what would make this page evidence rather than a
              catalogue.
            </Finding>
            <Finding tone="info" label="Collection timestamps are batch timestamps">
              The largest collection batch holds {integrity.largestBatch} items sharing one minute. A collection
              timestamp records when a sweep ran, so it does not order items relative to one another and the
              order of the list below is not a chain of custody sequence.
            </Finding>
            <Finding tone="info" label="Observation and collection are different events">
              Each record carries both the time the content was observed and the time this model captured it.
              Where those differ by months, the earlier item was found retrospectively. That is a collection
              delay, not evidence of alteration.
            </Finding>
          </div>
        </div>

        <div className="rounded-sm border" style={dw.panel}>
          {filtered.length === 0 ? (
            <div className="p-8 text-center" style={dw.muted}>
              <ShieldCheck size={28} className="mx-auto mb-2" />
              <p>No evidence items match the selected filters.</p>
            </div>
          ) : (
            <div className="divide-y" style={{ borderColor: 'var(--tw-border-mid)' }}>
              {filtered.map(e => (
                <EvidenceItem
                  key={e.id}
                  evidence={e}
                  siblings={darkWebEvidence.map(x => ({ id: x.id, hash: x.hash, collectionTimestamp: x.collectionTimestamp }))}
                />
              ))}
            </div>
          )}
        </div>

        <div className="rounded-sm border p-4" style={dw.panel}>
          <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Evidence Chain Overview</p>
          <div className="flex flex-wrap gap-2">
            {darkWebEvidence.slice(0, 8).map(e => (
              <span key={e.id} className="font-mono text-[9px] px-2 py-0.5 rounded-sm border"
                style={{ backgroundColor: 'color-mix(in srgb, var(--tw-brass) 15%, transparent)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-brass)' }}>
                {e.id} · R{e.reliability} · <Hash size={9} className="inline" />
                {e.hash.slice(0, 6)}…
              </span>
            ))}
          </div>
          <p className="font-mono text-[9px] mt-1" style={dw.faint}>Provenance chain retained per item. Click an item for full details.</p>
        </div>
          </>
        )}
        <ProtectionModulePanel entityType="EVIDENCE" />
      </div>
    </motion.div>
  );
}
