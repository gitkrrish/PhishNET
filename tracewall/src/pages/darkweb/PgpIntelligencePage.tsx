import { useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
  Key, Search, Users, Database, Clock, Network, FileText, Globe,
  Fingerprint, Layers, ShieldCheck, Wallet,
} from 'lucide-react';
import { dw, sectionStyle } from '../../lib/darkweb/styles';
import { useIntelligence } from '../../lib/intelligence/IntelligenceContext';
import { pgpBundle, pgpPath, actorPath, handlePath, walletPath, ENTITY_PATH } from '../../lib/intelligence/entityBundles';
import { normalizePgp, shortFingerprint } from '../../lib/intelligence/normalize';
import { pgpAnalysis, type PgpAnalysisBundle } from '../../lib/intelligence/pgp';
import { ConfidenceBar } from '../../components/ui/ConfidenceBar';
import {
  EntityLink, EntityPageHeader, EntityRow, EntitySection,
  EmptyNote, EmptySelection, MetaCell, RecordEntityLink,
  entityInputClass, entityInputStyle,
} from '../../components/darkweb/EntityWorkspace';
import { ProtectionModulePanel } from '../../components/darkweb/ProtectionModulePanel';

// ============================================================
// PGP / Cryptographic Identity Intelligence.
//
// A PGP key is the strongest identity artifact the model holds: it
// is long-lived, deliberately published, and a subject who reuses it
// across platforms is asserting continuity. This workspace is
// therefore organised around the key and the actors it binds —
// with the handles, wallets and infrastructure that corroborate.
// ============================================================
// ============================================================
// Key analysis.
//
// A fingerprint can be checked. A name inside a key cannot be
// trusted, and neither can a key's continued validity — that needs
// a keyserver this page does not contact. The panel therefore shows
// what was verified, keeps unverifiable claims visibly unclaimed,
// and states the identity caveat wherever a UID is displayed.
// ============================================================
function PgpKeyAnalysis({ analysis }: { analysis: PgpAnalysisBundle }) {
  const { parse, fingerprintCheck } = analysis;
  const key = parse.primaryKey;

  return (
    <EntitySection
      icon={<ShieldCheck size={13} style={analysis.fingerprintMismatch ? dw.critical : dw.brass} />}
      title="Key material analysis"
      aside={
        <span className="font-mono text-[9px] uppercase" style={dw.faint}>
          {analysis.hasKeyMaterial ? 'PARSED FROM STORED BLOCK' : 'NO KEY BLOCK STORED'}
        </span>
      }
    >
      <div className="space-y-3">
        <div className="grid sm:grid-cols-2 gap-3 p-3 rounded-sm border" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
          <MetaCell
            label="Fingerprint structure"
            value={fingerprintCheck.verdict.replace(/_/g, ' ')}
            color={fingerprintCheck.verdict === 'VALID' ? dw.moss.color : dw.critical.color}
          />
          <MetaCell label="Long key ID" value={analysis.longKeyId ?? 'not derivable (needs 40 hex)'} />
        </div>
        <p className="font-mono text-[9px] leading-relaxed" style={dw.faint}>{fingerprintCheck.detail}</p>

        {analysis.findings.map(finding => (
          <div
            key={finding.label}
            className="p-2.5 rounded-sm border font-mono text-[10px]"
            style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}
          >
            <span style={finding.tone === 'warn' ? dw.critical : finding.tone === 'ok' ? dw.moss : dw.brass}>
              {finding.label}
            </span>
            <p className="mt-1 leading-relaxed" style={dw.muted}>{finding.detail}</p>
          </div>
        ))}

        {key && (
          <div className="grid sm:grid-cols-3 gap-3">
            <MetaCell label="Algorithm" value={key.algorithmName} />
            <MetaCell label="Key size" value={key.algorithmStrength} />
            <MetaCell label="Created" value={key.createdAt ? new Date(key.createdAt).toLocaleDateString() : 'unknown'} />
          </div>
        )}

        {key && (key.keyFlags.length > 0 || key.expiresAt) && (
          <div className="grid sm:grid-cols-2 gap-3">
            <MetaCell
              label="Usage flags"
              value={key.keyFlags.length ? key.keyFlags.join(', ') : 'none declared'}
            />
            <MetaCell
              label="Expiry"
              value={key.expiresAt
                ? `${new Date(key.expiresAt).toLocaleDateString()}${key.expired ? ' (EXPIRED)' : ''}`
                : 'no expiration declared'}
              color={key.expired ? dw.critical.color : undefined}
            />
          </div>
        )}

        {parse.subkeys.length > 0 && (
          <div>
            <p className="font-mono text-[9px] tracking-widest uppercase mb-1.5" style={dw.muted}>
              Subkeys ({parse.subkeys.length})
            </p>
            <div className="space-y-1.5">
              {parse.subkeys.map((sub, i) => (
                <div key={sub.keyId ?? i} className="p-2 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                  <div className="flex items-center justify-between gap-2">
                    <span style={dw.text}>{sub.algorithmName} · {sub.algorithmStrength}</span>
                    {sub.expired && <span style={dw.critical}>EXPIRED</span>}
                  </div>
                  {sub.keyId && <p className="mt-0.5 break-all" style={dw.faint}>{sub.keyId}</p>}
                  {sub.keyFlags.length > 0 && <p className="mt-0.5" style={dw.muted}>{sub.keyFlags.join(', ')}</p>}
                </div>
              ))}
            </div>
          </div>
        )}

        {parse.userIds.length > 0 && (
          <div>
            <p className="font-mono text-[9px] tracking-widest uppercase mb-1.5" style={dw.muted}>
              User IDs ({parse.userIds.length}) — self-asserted
              {parse.hasCertification ? ', certified' : ', UNCERTIFIED'}
            </p>
            <div className="space-y-1.5">
              {parse.userIds.map(uid => (
                <div key={uid.uid} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                  <p className="break-all" style={dw.text}>{uid.uid}</p>
                  <p className="mt-1 leading-relaxed" style={dw.faint}>
                    Anyone can publish a key carrying this exact label. A user ID is a claim the key makes about
                    itself, not a verified identity, and it must be corroborated independently before it is
                    treated as naming a person.
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

        {parse.signatures.length > 0 && (
          <div>
            <p className="font-mono text-[9px] tracking-widest uppercase mb-1.5" style={dw.muted}>
              Signatures ({parse.signatures.length})
            </p>
            <div className="space-y-1.5">
              {parse.signatures.map((sig, i) => (
                <div key={i} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                  <div className="flex items-center justify-between gap-2">
                    <span style={sig.revocationReason ? dw.critical : dw.text}>{sig.sigTypeName}</span>
                    <span style={dw.faint}>{sig.hashName}</span>
                  </div>
                  {sig.createdAt && <p className="mt-0.5" style={dw.faint}>{new Date(sig.createdAt).toLocaleString()}</p>}
                  {sig.revocationReason && <p className="mt-0.5" style={dw.critical}>{sig.revocationReason}</p>}
                </div>
              ))}
            </div>
            <p className="font-mono text-[9px] leading-relaxed mt-1.5" style={dw.faint}>
              Signature packets are decoded, not cryptographically verified. Confirming them would require the
              public key material and a full OpenPGP implementation, so this panel reports what each signature
              claims and never asserts that it is valid.
            </p>
          </div>
        )}

        <div className="p-2.5 rounded-sm border font-mono text-[9px] leading-relaxed space-y-1" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
          <p className="tracking-widest uppercase" style={dw.muted}>Standing caveats</p>
          {analysis.caveats.map(caveat => <p key={caveat} style={dw.faint}>· {caveat}</p>)}
        </div>
      </div>
    </EntitySection>
  );
}

export default function PgpIntelligencePage() {
  const { dataset } = useIntelligence();
  const [search, setSearch] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const filtered = useMemo(() => {
    const query = normalizePgp(search);
    const lower = search.trim().toLowerCase();
    if (!query && !lower) return dataset.pgpKeys;
    return dataset.pgpKeys.filter(key =>
      lower
        ? key.fingerprint.toLowerCase().includes(lower) ||
          key.id.toLowerCase().includes(lower) ||
          key.actorIds.some(id => id.toLowerCase().includes(lower)) ||
          key.sources.some(source => source.toLowerCase().includes(lower))
        : normalizePgp(key.fingerprint).includes(query),
    );
  }, [dataset.pgpKeys, search]);

  const selectedRef = selectedId ?? filtered[0]?.id ?? dataset.pgpKeys[0]?.id ?? null;
  const bundle = useMemo(
    () => (selectedRef ? pgpBundle(dataset, selectedRef) : null),
    [dataset, selectedRef],
  );

  const sharedKeys = dataset.pgpKeys.filter(key => key.actorIds.length > 1);

  // Key analysis reads the record directly so the structural check still runs
  // for keys the entity bundle does not otherwise resolve.
  const analysis = useMemo(
    () => (bundle ? pgpAnalysis(bundle.key as unknown as { id: string; fingerprint: string }) : null),
    [bundle],
  );

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">

        <EntityPageHeader
          icon={<Key size={18} style={dw.critical} />}
          eyebrow="Cryptographic Identity"
          title="PGP Intelligence"
          byline="Every cryptographic identity recorded through Add Intelligence. A PGP key is long-lived and deliberately published, so a fingerprint reused by two actors is the single strongest linking indicator the model holds — this workspace shows who a key binds, and what corroborates the binding."
          stats={[
            { label: 'PGP keys', value: dataset.pgpKeys.length },
            { label: 'Shared across actors', value: sharedKeys.length, color: dw.burg },
            { label: 'Unattributed', value: dataset.pgpKeys.filter(key => key.actorIds.length === 0).length, color: dw.muted },
          ]}
        />

        <div className="flex flex-col md:flex-row gap-3 items-center justify-between">
          <div className="relative w-full md:w-96">
            <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: 'var(--tw-text-faint)' }} />
            <input
              value={search}
              onChange={event => setSearch(event.target.value)}
              placeholder="Search fingerprint, key id, actor or source…"
              className={entityInputClass}
              style={entityInputStyle}
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {search.trim() && (
              <span className="font-mono text-[10px]" style={dw.faint}>
                NORMALIZED: <span style={dw.text}>{shortFingerprint(search) || '—'}</span>
              </span>
            )}
            <RecordEntityLink to="/app/darkweb/add" label="+ Record PGP key" />
          </div>
        </div>

        <div className="grid lg:grid-cols-12 gap-6">
          <div className="lg:col-span-5 space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>KEY STORE ({filtered.length})</span>
              <span className="font-mono text-[9px]" style={dw.faint}>CLICK TO INSPECT</span>
            </div>
            <div className="space-y-2 max-h-[620px] overflow-y-auto pr-1">
              {filtered.map(key => (
                <EntityRow key={key.id} selected={bundle?.key.id === key.id} onClick={() => setSelectedId(key.id)}>
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5 mb-1">
                        <span className="font-mono text-[9px] uppercase px-1 py-0.5 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)', color: 'var(--tw-text-muted)' }}>
                          {key.id}
                        </span>
                        {key.actorIds.length > 1 && (
                          <span className="font-mono text-[9px] uppercase px-1 py-0.5 rounded-sm" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-brass) 18%, transparent)', color: 'var(--tw-brass)' }}>
                            SHARED ×{key.actorIds.length}
                          </span>
                        )}
                      </div>
                      <p className="font-mono text-xs font-medium truncate" style={dw.text}>{shortFingerprint(key.fingerprint)}…</p>
                    </div>
                    <span className="font-mono text-[9px] shrink-0" style={dw.faint}>{key.confidence}%</span>
                  </div>
                  <div className="flex items-center justify-between mt-2 pt-2 border-t font-mono text-[9px]" style={{ borderColor: 'var(--tw-border-mid)' }}>
                    <span style={key.actorIds.length ? dw.burg : dw.faint}>
                      {key.actorIds.length ? key.actorIds.join(', ') : 'unattributed'}
                    </span>
                    <span style={dw.faint}>{key.sources.length} source(s)</span>
                  </div>
                </EntityRow>
              ))}
              {filtered.length === 0 && (
                <p className="font-mono text-[10px] p-4 rounded-sm border" style={{ ...dw.panel, ...dw.muted }}>
                  No key matches “{search}”.
                </p>
              )}
            </div>
          </div>

          <div className="lg:col-span-7 space-y-4">
            {bundle ? (
              <>
                <div className="rounded-sm border p-5 space-y-4" style={dw.panel}>
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[10px] tracking-wider uppercase" style={dw.burg}>{bundle.key.id}</span>
                        {bundle.key.dataState && (
                          <span className="font-mono text-[9px] uppercase" style={dw.faint}>{bundle.key.dataState.replace(/_/g, ' ')}</span>
                        )}
                      </div>
                      <h2 className="font-mono text-sm font-bold mt-1 break-all" style={dw.text}>{bundle.key.fingerprint}</h2>
                      <p className="font-mono text-[10px] mt-1" style={dw.brass}>
                        Key ID <span style={dw.text}>{shortFingerprint(bundle.key.fingerprint)}</span> ·{' '}
                        {normalizePgp(bundle.key.fingerprint).length} hex characters
                      </p>
                    </div>
                    <Link
                      to={pgpPath(bundle.key.id)}
                      className="font-mono text-[10px] tracking-wider uppercase px-2.5 py-1.5 rounded-sm border shrink-0"
                      style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-burgundy)' }}
                    >
                      Open dossier
                    </Link>
                  </div>

                  <div className="grid sm:grid-cols-3 gap-3 p-3 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)' }}>
                    <MetaCell label="First seen" value={new Date(bundle.key.firstSeen).toLocaleDateString()} />
                    <MetaCell label="Last seen" value={new Date(bundle.key.lastSeen).toLocaleDateString()} />
                    <MetaCell label="Attributed actors" value={bundle.key.actorIds.length || 'None'} />
                  </div>

                  <div className="space-y-1">
                    <ConfidenceBar value={bundle.key.confidence} />
                    <p className="font-mono text-[9px]" style={dw.faint}>Key confidence carried on the central PGP record.</p>
                  </div>

                  <div className="flex flex-wrap gap-2 pt-1">
                    {bundle.actors.map(actor => (
                      <EntityLink key={actor.id} to={actorPath(actor.id)}>
                        <Users size={10} /> {actor.id} — {actor.aliases[0] ?? actor.id}
                      </EntityLink>
                    ))}
                    {bundle.handles.map(handle => (
                      <EntityLink key={handle.id} to={handlePath(handle.id)}>
                        @{handle.value}
                      </EntityLink>
                    ))}
                    {bundle.wallets.map(wallet => (
                      <EntityLink key={wallet.id} to={walletPath(wallet.id)} accent="var(--tw-info)">
                        <Wallet size={10} /> {wallet.id}
                      </EntityLink>
                    ))}
                    <EntityLink to={`${ENTITY_PATH.graph}?focus=${encodeURIComponent(bundle.key.id)}`}>
                      <Network size={10} /> Graph
                    </EntityLink>
                    <EntityLink to={`${ENTITY_PATH.ai}?actor=${bundle.key.actorIds[0] ?? ''}`} accent="var(--tw-text-muted)">
                      <Fingerprint size={10} /> AI analysis
                    </EntityLink>
                  </div>
                </div>

                {analysis && <PgpKeyAnalysis analysis={analysis} />}

                <EntitySection
                  icon={<Layers size={13} style={dw.critical} />}
                  title={`Association map (${bundle.key.actorIds.length} actor${bundle.key.actorIds.length === 1 ? '' : 's'})`}
                >
                  <div className="p-4 rounded-sm border space-y-4" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                    <div className="flex items-center justify-between text-xs font-mono gap-3">
                      <div className="flex items-center gap-2 min-w-0">
                        <Key size={14} style={dw.brass} />
                        <span className="break-all" style={dw.text}>{bundle.key.fingerprint}</span>
                      </div>
                      <span className="shrink-0" style={dw.faint}>[KEY]</span>
                    </div>
                    <div className="pl-4 border-l-2 space-y-3" style={{ borderColor: 'var(--tw-brass)' }}>
                      {bundle.actors.map(actor => (
                        <div key={actor.id} className="flex items-center justify-between gap-3 bg-black/10 p-2 rounded-sm">
                          <div className="min-w-0">
                            <span className="font-mono text-[9px] uppercase" style={dw.faint}>SIGNED FOR / ATTRIBUTED TO</span>
                            <div className="flex items-center gap-1.5 flex-wrap">
                              <Link to={actorPath(actor.id)} className="font-mono text-xs font-bold hover:underline" style={dw.burg}>
                                {actor.id} ({actor.aliases[0]})
                              </Link>
                              <span className="font-mono text-[9px]" style={dw.moss}>[{actor.status}]</span>
                            </div>
                          </div>
                          <Link
                            to={actorPath(actor.id)}
                            className="font-mono text-[9px] px-2 py-1 rounded-sm border shrink-0"
                            style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}
                          >
                            VIEW DOSSIER →
                          </Link>
                        </div>
                      ))}
                      {bundle.handles.length > 0 && (
                        <div className="p-2 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border-mid)' }}>
                          <span style={dw.faint}>OBSERVED ALONGSIDE: </span>
                          <span style={dw.text}>{bundle.handles.map(handle => `@${handle.value} (${handle.platform})`).join(', ')}</span>
                        </div>
                      )}
                      {bundle.relationships.map(rel => (
                        <div key={rel.id} className="text-[10px] font-mono p-2 rounded-sm border" style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border-mid)' }}>
                          <div className="flex items-center justify-between">
                            <span style={dw.burg}>{rel.type.replace(/_/g, ' ')}</span>
                            <span style={dw.faint}>{rel.confidence}% CONF · {rel.id}</span>
                          </div>
                          <p className="mt-1" style={dw.muted}>{rel.explanation}</p>
                        </div>
                      ))}
                      {bundle.actors.length === 0 && bundle.relationships.length === 0 && (
                        <p className="font-mono text-[10px]" style={dw.faint}>
                          No actor attribution and no relationship reference this key yet.
                        </p>
                      )}
                    </div>
                  </div>
                </EntitySection>

                <EntitySection icon={<Layers size={13} style={dw.critical} />} title={`Why linked? (${bundle.whyLinked.length})`}>
                  {bundle.whyLinked.length > 0 ? (
                    <div className="space-y-2">
                      {bundle.whyLinked.map((entry, index) => (
                        <div key={index} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                          <span style={dw.burg}>{entry.indicator}</span>
                          <p className="mt-1 leading-relaxed" style={dw.muted}>{entry.detail}</p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <EmptyNote>No stored link explains this key yet.</EmptyNote>
                  )}
                </EntitySection>

                <div className="grid md:grid-cols-2 gap-4">
                  <EntitySection icon={<Globe size={13} style={dw.critical} />} title={`Sources & platforms (${bundle.sources.length})`}>
                    {bundle.sources.length > 0 ? (
                      <div className="space-y-2">
                        {bundle.sources.map(source => (
                          <Link key={source.id} to={ENTITY_PATH.sources} className="block p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                            <p style={dw.text}>{source.name}</p>
                            <p style={dw.faint}>{source.type} · R{source.reliabilityScore} · {source.status}</p>
                          </Link>
                        ))}
                      </div>
                    ) : (
                      <EmptyNote>No source recorded for this key.</EmptyNote>
                    )}
                    {bundle.platforms.length > 0 && (
                      <div className="pt-1">
                        <span className="font-mono text-[9px] uppercase block mb-1" style={dw.faint}>Platforms seen with this key</span>
                        <div className="flex flex-wrap gap-1">
                          {bundle.platforms.map(platform => (
                            <span key={platform} className="font-mono text-[9px] px-1.5 py-0.5 rounded-sm border" style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}>
                              {platform}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </EntitySection>

                  <EntitySection icon={<Database size={13} style={dw.critical} />} title={`Evidence (${bundle.evidence.length})`}>
                    {bundle.evidence.length > 0 ? (
                      <div className="space-y-2">
                        {bundle.evidence.slice(0, 6).map(item => (
                          <div key={item.id} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                            <div className="flex items-center justify-between">
                              <span style={dw.burg}>{item.id} · {item.evidenceType.replace(/_/g, ' ')}</span>
                              <span style={dw.faint}>{new Date(item.timestamp).toLocaleDateString()}</span>
                            </div>
                            <p className="mt-1 leading-relaxed" style={dw.muted}>{item.provenance}</p>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <EmptyNote>No evidence captured against this key.</EmptyNote>
                    )}
                    {bundle.actors[0] && <EntityLink to={`${ENTITY_PATH.evidence}?actor=${bundle.actors[0].id}`}>Open evidence locker →</EntityLink>}
                  </EntitySection>
                </div>

                <div className="grid md:grid-cols-2 gap-4">
                  <EntitySection icon={<Clock size={13} style={dw.critical} />} title={`Timeline (${bundle.timeline.length} events)`}>
                    {bundle.timeline.length > 0 ? (
                      <div className="space-y-2">
                        {bundle.timeline.slice(0, 6).map(event => (
                          <div key={event.id} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                            <div className="flex items-center justify-between">
                              <span style={dw.text}>{event.title}</span>
                              <span style={dw.faint}>{new Date(event.time).toLocaleDateString()}</span>
                            </div>
                            <p className="mt-0.5" style={dw.muted}>{event.actorId} · {event.type.replace(/_/g, ' ')}</p>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <EmptyNote>No timeline event is tied to this key.</EmptyNote>
                    )}
                    {bundle.actors[0] && <EntityLink to={`${ENTITY_PATH.timeline}?actor=${bundle.actors[0].id}`}>Open full timeline →</EntityLink>}
                  </EntitySection>

                  <EntitySection icon={<FileText size={13} style={dw.critical} />} title={`Related investigations (${bundle.investigations.length})`}>
                    {bundle.investigations.length > 0 ? (
                      <div className="space-y-2">
                        {bundle.investigations.map(inv => (
                          <Link
                            key={inv.id}
                            to={`${ENTITY_PATH.investigations}/${inv.id}`}
                            className="block p-2.5 rounded-sm border font-mono text-[10px]"
                            style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}
                          >
                            <div className="flex items-center justify-between">
                              <span style={dw.text}>{inv.title}</span>
                              <span style={inv.status === 'ACTIVE' ? dw.moss : dw.faint}>{inv.status}</span>
                            </div>
                            <p className="mt-0.5" style={dw.muted}>{inv.id} · {inv.confidence}% confidence</p>
                          </Link>
                        ))}
                      </div>
                    ) : (
                      <EmptyNote>This key is not yet part of an investigation.</EmptyNote>
                    )}
                  </EntitySection>
                </div>

                <EntitySection
                  icon={<ShieldCheck size={13} style={dw.critical} />}
                  title={`Observations naming this key (${bundle.observations.length})`}
                >
                  {bundle.observations.length > 0 ? (
                    <div className="space-y-2">
                      {bundle.observations.map(obs => (
                        <Link
                          key={obs.id}
                          to={`${ENTITY_PATH.observations}/${obs.id}`}
                          className="block p-2.5 rounded-sm border font-mono text-[10px]"
                          style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}
                        >
                          <div className="flex items-center justify-between">
                            <span style={dw.burg}>{obs.id} · {obs.observationType.replace(/_/g, ' ')}</span>
                            <span style={dw.faint}>{new Date(obs.timestamp).toLocaleDateString()}</span>
                          </div>
                          <p className="mt-0.5 line-clamp-2" style={dw.muted}>{obs.content}</p>
                        </Link>
                      ))}
                    </div>
                  ) : (
                    <EmptyNote>No raw observation references this key.</EmptyNote>
                  )}
                </EntitySection>
              </>
            ) : (
              <EmptySelection icon={<Key size={32} />} message="Select a PGP key to open its cryptographic identity dossier." />
            )}
          </div>
        </div>

        <ProtectionModulePanel entityType="PGP" />
      </div>
    </motion.div>
  );
}
