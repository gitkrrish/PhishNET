import { useMemo } from 'react';
import { motion } from 'framer-motion';
import { useNavigate, useParams, Link } from 'react-router-dom';
import { Key, ChevronLeft, Users, Database, Clock, Globe, Layers, Fingerprint, Network, Wallet } from 'lucide-react';
import { dw, sectionStyle } from '../../lib/darkweb/styles';
import { useIntelligence } from '../../lib/intelligence/IntelligenceContext';
import { pgpBundle, actorPath, handlePath, walletPath, ENTITY_PATH } from '../../lib/intelligence/entityBundles';
import { normalizePgp, shortFingerprint } from '../../lib/intelligence/normalize';
import { pgpAnalysis } from '../../lib/intelligence/pgp';
import { ConfidenceBar } from '../../components/ui/ConfidenceBar';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { RelationshipChip } from '../../components/darkweb/RelationshipChip';
import { EntityLink, EntitySection, EmptyNote, MetaCell } from '../../components/darkweb/EntityWorkspace';
import { MonitorEntityButton } from '../../components/darkweb/MonitorEntityButton';
import { ProtectionPanel } from '../../components/darkweb/ProtectionPanel';

// ============================================================
// PGP key dossier — the single-record view of the same bundle the
// PGP Intelligence list renders, off the same centralized key.
// ============================================================
/** Revocation is only knowable from key material; absence of it is not proof. */
function revocationLabel(revoked: boolean | null): string {
  if (revoked === true) return 'REVOCATION PRESENT IN MATERIAL';
  if (revoked === false) return 'none in stored material (not keyserver-confirmed)';
  return 'unknown — no key material';
}

export default function PgpProfilePage() {
  const { id } = useParams<{ id: string }>();
  const { dataset } = useIntelligence();
  const navigate = useNavigate();
  const bundle = useMemo(() => (id ? pgpBundle(dataset, id) : null), [dataset, id]);
  const analysis = useMemo(
    () => (bundle ? pgpAnalysis(bundle.key as unknown as { id: string; fingerprint: string }) : null),
    [bundle],
  );

  if (!bundle) {
    return (
      <div className="min-h-screen page-enter" style={sectionStyle()}>
        <div className="max-w-3xl mx-auto px-6 lg:px-10 py-16 text-center" style={dw.text}>
          <Key size={40} className="mx-auto mb-4" style={dw.muted} />
          <h2 className="font-serif text-2xl mb-2">PGP Key Not Found</h2>
          <p className="font-mono text-xs mb-4" style={dw.muted}>No PGP record matches “{id}”.</p>
          <button
            onClick={() => navigate('/app/darkweb/pgp-keys')}
            className="font-mono text-xs px-4 py-2 rounded-sm border"
            style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
          >
            ← Back to PGP Intelligence
          </button>
        </div>
      </div>
    );
  }

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="min-h-screen page-enter" style={sectionStyle()}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8 space-y-6">
        <button onClick={() => navigate('/app/darkweb/pgp-keys')} className="font-mono text-[10px] flex items-center gap-1" style={dw.muted}>
          <ChevronLeft size={12} /> Back to PGP Intelligence
        </button>

        <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b pb-5" style={{ borderColor: 'var(--tw-border-mid)' }}>
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Key size={16} style={dw.brass} />
              <span className="font-mono text-[10px] tracking-wider" style={dw.burg}>{bundle.key.id}</span>
              <DemoLabel />
              <MonitorEntityButton entityType="PGP_KEY" entityId={bundle.key.id} entityLabel={shortFingerprint(bundle.key.fingerprint)} targetType="PGP" />
            </div>
            <h1 className="font-mono text-xl font-bold break-all" style={dw.text}>{bundle.key.fingerprint}</h1>
            <p className="text-sm" style={dw.muted}>
              Cryptographic identity key observed on {bundle.sources.length} source{bundle.sources.length === 1 ? '' : 's'}.
              First seen {new Date(bundle.key.firstSeen).toLocaleDateString()},
              last seen {new Date(bundle.key.lastSeen).toLocaleDateString()}.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {bundle.actors.map(actor => (
              <Link
                key={actor.id}
                to={actorPath(actor.id)}
                className="font-mono text-[10px] tracking-wider uppercase px-2.5 py-1.5 rounded-sm border"
                style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-burgundy)' }}
              >
                {actor.id} →
              </Link>
            ))}
            <Link
              to={`${ENTITY_PATH.correlation}?handle=${bundle.handles[0]?.value ?? ''}`}
              className="font-mono text-[10px] tracking-wider uppercase px-2.5 py-1.5 rounded-sm border"
              style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}
            >
              <Fingerprint size={11} className="inline mr-1" /> Correlate
            </Link>
          </div>
        </div>

        <div className="grid md:grid-cols-3 gap-6">
          <div className="col-span-2 space-y-6">
            <div className="rounded-sm border p-5 space-y-4" style={dw.panel}>
              <p className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>Cryptographic identity</p>
              <div className="grid sm:grid-cols-2 gap-3 p-3 rounded-sm" style={{ backgroundColor: 'var(--tw-canvas-mid)' }}>
                <MetaCell label="Key ID" value={shortFingerprint(bundle.key.fingerprint)} />
                <MetaCell label="Fingerprint length" value={`${normalizePgp(bundle.key.fingerprint).length} hex characters`} />
                <MetaCell label="First seen" value={new Date(bundle.key.firstSeen).toLocaleDateString()} />
                <MetaCell label="Last seen" value={new Date(bundle.key.lastSeen).toLocaleDateString()} />
              </div>
              <ConfidenceBar value={bundle.key.confidence} />
            </div>

            <ProtectionPanel entityType="PGP" entityId={bundle.key.id} title="Threat Protection & Response" />

            {analysis && (
            <EntitySection
              icon={<Key size={13} style={analysis.fingerprintMismatch ? dw.critical : dw.brass} />}
              title="Key material analysis"
              aside={
                <span className="font-mono text-[9px] uppercase" style={dw.faint}>
                  {analysis.hasKeyMaterial ? 'PARSED FROM STORED BLOCK' : 'NO KEY BLOCK STORED'}
                </span>
              }
            >
              <div className="space-y-3">
                <div className="grid sm:grid-cols-3 gap-3">
                  <MetaCell
                    label="Fingerprint structure"
                    value={analysis.fingerprintCheck.verdict.replace(/_/g, ' ')}
                    color={analysis.fingerprintCheck.verdict === 'VALID' ? dw.moss.color : dw.critical.color}
                  />
                  <MetaCell label="Long key ID" value={analysis.longKeyId ?? 'not derivable'} />
                  <MetaCell label="Revocation" value={revocationLabel(analysis.parse.revoked)} />
                </div>
                <p className="font-mono text-[9px] leading-relaxed" style={dw.faint}>{analysis.fingerprintCheck.detail}</p>

                {analysis.findings.map(finding => (
                  <div key={finding.label} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                    <span style={finding.tone === 'warn' ? dw.critical : finding.tone === 'ok' ? dw.moss : dw.brass}>{finding.label}</span>
                    <p className="mt-1 leading-relaxed" style={dw.muted}>{finding.detail}</p>
                  </div>
                ))}

                {analysis.parse.primaryKey && (
                  <div className="grid sm:grid-cols-3 gap-3">
                    <MetaCell label="Algorithm" value={analysis.parse.primaryKey.algorithmName} />
                    <MetaCell label="Key size" value={analysis.parse.primaryKey.algorithmStrength} />
                    <MetaCell
                      label="Created"
                      value={analysis.parse.primaryKey.createdAt ? new Date(analysis.parse.primaryKey.createdAt).toLocaleDateString() : 'unknown'}
                    />
                  </div>
                )}

                {analysis.parse.userIds.length > 0 && (
                  <div>
                    <p className="font-mono text-[9px] tracking-widest uppercase mb-1.5" style={dw.muted}>
                      User IDs — self-asserted, {analysis.parse.hasCertification ? 'certified' : 'UNCERTIFIED'}
                    </p>
                    <div className="space-y-1.5">
                      {analysis.parse.userIds.map(uid => (
                        <div key={uid.uid} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                          <p className="break-all" style={dw.text}>{uid.uid}</p>
                          <p className="mt-1 leading-relaxed" style={dw.faint}>
                            A user ID is a claim the key makes about itself. It carries no proof of ownership and
                            must be corroborated independently before it is read as naming a person.
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="p-2.5 rounded-sm border font-mono text-[9px] leading-relaxed space-y-1" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                  <p className="tracking-widest uppercase" style={dw.muted}>Standing caveats</p>
                  {analysis.caveats.map(caveat => <p key={caveat} style={dw.faint}>· {caveat}</p>)}
                </div>
              </div>
            </EntitySection>
            )}

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

            <EntitySection icon={<Database size={13} style={dw.critical} />} title={`Evidence (${bundle.evidence.length})`}>
              {bundle.evidence.length > 0 ? (
                <div className="space-y-2">
                  {bundle.evidence.map(item => (
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

            <EntitySection icon={<Clock size={13} style={dw.critical} />} title={`Timeline (${bundle.timeline.length} events)`}>
              {bundle.timeline.length > 0 ? (
                <div className="space-y-2">
                  {bundle.timeline.map(event => (
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
          </div>

          <div className="space-y-4">
            <EntitySection icon={<Users size={13} style={dw.critical} />} title={`Attributed actors (${bundle.actors.length})`}>
              {bundle.actors.length > 0 ? bundle.actors.map(actor => (
                <Link key={actor.id} to={actorPath(actor.id)} className="block p-2.5 rounded-sm border" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                  <p className="font-mono text-sm" style={dw.burg}>{actor.aliases[0] ?? actor.id}</p>
                  <p className="font-mono text-[9px]" style={dw.faint}>{actor.id} · {actor.status} · {actor.confidenceScore}%</p>
                </Link>
              )) : (
                <EmptyNote>Unattributed — no actor claims this key yet.</EmptyNote>
              )}
            </EntitySection>

            <EntitySection icon={<Fingerprint size={13} style={dw.critical} />} title={`Associated handles (${bundle.handles.length})`}>
              {bundle.handles.length > 0 ? bundle.handles.map(handle => (
                <Link key={handle.id} to={handlePath(handle.id)} className="block p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                  <p style={dw.text}>@{handle.value}</p>
                  <p style={dw.faint}>{handle.platform} · {handle.id}</p>
                </Link>
              )) : (
                <EmptyNote>No handle is associated with this key.</EmptyNote>
              )}
            </EntitySection>

            <EntitySection icon={<Wallet size={13} style={dw.critical} />} title={`Associated wallets (${bundle.wallets.length})`}>
              {bundle.wallets.length > 0 ? bundle.wallets.map(wallet => (
                <Link key={wallet.id} to={walletPath(wallet.id)} className="block p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                  <p className="break-all" style={dw.text}>{wallet.address}</p>
                  <p style={dw.faint}>{wallet.id} · {wallet.txCount} tx</p>
                </Link>
              )) : (
                <EmptyNote>No wallet is associated with this key.</EmptyNote>
              )}
            </EntitySection>

            <EntitySection icon={<Globe size={13} style={dw.critical} />} title={`Sources (${bundle.sources.length})`}>
              {bundle.sources.length > 0 ? bundle.sources.map(source => (
                <Link key={source.id} to={ENTITY_PATH.sources} className="block p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                  <p style={dw.text}>{source.name}</p>
                  <p style={dw.faint}>{source.type} · R{source.reliabilityScore}</p>
                </Link>
              )) : (
                <EmptyNote>No source recorded for this key.</EmptyNote>
              )}
            </EntitySection>

            <EntitySection icon={<Network size={13} style={dw.critical} />} title={`Relationships (${bundle.relationships.length})`}>
              {bundle.relationships.length > 0 ? bundle.relationships.map(rel => (
                <div key={rel.id} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
                  <div className="flex items-center justify-between gap-2">
                    <RelationshipChip type={rel.type} confidence={rel.confidence} />
                    <span style={dw.faint}>{rel.id}</span>
                  </div>
                  <p className="mt-1" style={dw.text}>{rel.sourceEntity} → {rel.targetEntity}</p>
                  <p className="mt-0.5" style={dw.muted}>{rel.explanation}</p>
                </div>
              )) : (
                <EmptyNote>No relationship references this key.</EmptyNote>
              )}
            </EntitySection>
          </div>
        </div>
      </div>
    </motion.div>
  );
}
