// ============================================================
// PhishNet — Chain of custody panel for the Evidence Locker.
//
// Presents one evidence item as a chain of custody: the tracked
// lifecycle events, the evidence record attributes that custody
// depends on, and the result of the last integrity verification.
//
// The panel never softens the result. A digest that matches is shown
// as "consistent with the stored reference", not as proof of
// authenticity. An item with no custody log says so explicitly instead
// of rendering an empty timeline that could be mistaken for "nothing
// happened". Tracked events and audit-derived events are visually
// distinguished, because they carry different weight.
// ============================================================
import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldCheck,
  ShieldAlert,
  Info,
  Link2,
  History,
  Fingerprint,
  Clock,
  User,
  FileText,
  CircleDot,
  TriangleAlert,
} from 'lucide-react';
import { dw } from '../../lib/darkweb/styles';
import { MetaCell } from './EntityWorkspace';
import {
  CUSTODY_EVENT_TYPES,
  fetchCustodyChain,
  recordCustodyEvent,
  verifyEvidenceIntegrity,
  verificationTone,
  type CustodyChain,
  type VerificationOutcome,
} from '../../lib/intelligence/custody';

const TONE = {
  ok: { color: 'var(--tw-moss)', Icon: ShieldCheck },
  warn: { color: 'var(--tw-critical)', Icon: ShieldAlert },
  info: { color: 'var(--tw-info)', Icon: Info },
} as const;

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return 'not recorded';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'not recorded';
  return date.toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
}

function formatBytes(bytes: number | null): string {
  if (bytes === null || bytes === undefined || Number.isNaN(bytes)) return 'not recorded';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function Caveat({ tone, label, children }: { tone: 'ok' | 'warn' | 'info'; label: string; children: React.ReactNode }) {
  const { color } = TONE[tone];
  return (
    <div className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
      <span style={{ color }}>{label}</span>
      <p className="mt-1 leading-relaxed" style={dw.muted}>{children}</p>
    </div>
  );
}

export function ChainOfCustody({
  evidenceId,
  evidenceLabel,
}: {
  evidenceId: string;
  /** Shown while the first chain request is in flight. */
  evidenceLabel?: string;
}) {
  const [chain, setChain] = useState<CustodyChain | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [verification, setVerification] = useState<VerificationOutcome | null>(null);

  // Verification content is supplied explicitly by the analyst. Nothing
  // is hashed implicitly: this platform does not hold the evidence file,
  // so a digest cannot be recomputed from what it has stored.
  const [content, setContent] = useState('');
  const [useBase64, setUseBase64] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      setChain(await fetchCustodyChain(evidenceId));
    } catch (error) {
      // A failure here is reported as a failure. The evidence record
      // itself is unaffected and the rest of the page keeps working.
      setChain(null);
      setLoadError(error instanceof Error ? error.message : 'Chain of custody is unavailable');
    } finally {
      setLoading(false);
    }
  }, [evidenceId]);

  useEffect(() => {
    setVerification(null);
    setActionError(null);
    setContent('');
    void load();
  }, [load]);

  async function runVerification() {
    setBusy(true);
    setActionError(null);
    try {
      const result = await verifyEvidenceIntegrity(evidenceId, {
        content: content.trim() ? content : undefined,
        contentEncoding: useBase64 ? 'base64' : 'utf8',
        reason: content.trim() ? 'Analyst-supplied content digest check' : 'Verification requested with no content supplied',
      });
      setVerification(result.verification);
      setChain(result.chain);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Verification could not be completed');
    } finally {
      setBusy(false);
    }
  }

  async function recordAccessed() {
    setBusy(true);
    setActionError(null);
    try {
      const result = await recordCustodyEvent(evidenceId, {
        eventType: 'EVIDENCE_ACCESSED',
        action: 'Viewed in Evidence Locker',
        reason: 'Analyst opened the chain of custody view',
      });
      setChain(result.chain);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'The access event could not be recorded');
    } finally {
      setBusy(false);
    }
  }

  if (loading) {
    return (
      <div className="rounded-sm border p-4" style={dw.panel} aria-busy="true">
        <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Chain of custody</p>
        <p className="font-mono text-[10px]" style={dw.faint}>Loading custody history for {evidenceLabel ?? evidenceId}…</p>
      </div>
    );
  }

  if (loadError || !chain) {
    return (
      <div className="rounded-sm border p-4" style={dw.panel}>
        <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Chain of custody</p>
        <Caveat tone="warn" label="Chain of custody unavailable">
          {loadError ?? 'No chain could be read for this item.'} The evidence record itself is unchanged and remains
          readable in the list above. Tracking resumes as soon as the API is reachable.
        </Caveat>
      </div>
    );
  }

  const { evidence, events, trackedEvents, historicalEvents, historyStatus, trackingStartedAt } = chain;
  const lastOutcome = verification ?? (
    evidence.lastVerificationResult && evidence.lastVerificationResult !== 'NEVER_VERIFIED'
      ? ({
          result: evidence.lastVerificationResult,
          detail: evidence.lastVerificationDetail,
          algorithm: evidence.hashAlgorithm,
          storedHash: evidence.hash,
          verifiedAt: evidence.lastVerifiedAt ?? '',
          verifiedBy: evidence.lastVerifiedBy,
          verificationCount: evidence.verificationCount,
          disclaimer: chain.integrityDisclaimer,
        } as unknown as VerificationOutcome)
      : null
  );
  const tone = verificationTone(lastOutcome?.result ?? 'NOT_VERIFIABLE');

  return (
    <div className="rounded-sm border" style={dw.panel}>
      <div className="px-5 py-3 border-b flex flex-wrap items-center justify-between gap-2" style={dw.borderMid}>
        <div className="flex items-center gap-2" style={dw.muted}>
          <History size={13} />
          Chain of Custody
        </div>
        <span className="font-mono text-[10px]" style={dw.faint}>
          {evidence.id} · {trackedEvents.length} tracked event(s) · {historicalEvents.length} audit-derived
        </span>
      </div>

      <div className="p-5 space-y-5">
        {/* ── Record attributes custody depends on ── */}
        <section>
          <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Evidence record</p>
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <MetaCell label="Evidence ID" value={evidence.id} />
            <MetaCell label="Evidence type" value={String(evidence.evidenceType).replace(/_/g, ' ')} />
            <MetaCell label="Evidence name" value={evidence.name} />
            <MetaCell label="Current status" value={evidence.status} />
            <MetaCell label="Source" value={evidence.source || 'not recorded'} />
            <MetaCell label="Original collection" value={formatTimestamp(evidence.collectedAt)} />
            <MetaCell label="Observed" value={formatTimestamp(evidence.observedAt)} />
            <MetaCell label="Collection method" value={evidence.collectionMethod || 'not recorded'} />
            <MetaCell label="Collected by" value={evidence.collectedBy || 'not recorded'} />
            <MetaCell label="File" value={evidence.fileName ? `${evidence.fileName}${evidence.fileFormat ? ` (${evidence.fileFormat})` : ''}` : 'not recorded'} />
            <MetaCell label="File size" value={formatBytes(evidence.fileSize)} />
            <MetaCell label="Storage reference" value={evidence.storageReference || 'not recorded'} />
            <MetaCell label="Integrity status" value={evidence.integrityStatus || 'not recorded'} />
          </div>
          <div className="mt-3">
            <p className="font-mono text-[9px] tracking-widest uppercase mb-1" style={dw.faint}>Evidence provenance</p>
            <p className="font-mono text-[10px] leading-relaxed break-words" style={dw.text}>{evidence.provenance || 'not recorded'}</p>
            <p className="font-mono text-[9px] leading-relaxed mt-1 break-all" style={dw.faint}>
              <Fingerprint size={9} className="inline mr-1" />
              {evidence.hashAlgorithm}: {evidence.hash || 'no digest recorded'}
            </p>
          </div>
        </section>

        {/* ── Linked investigation ── */}
        <section>
          <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Linked investigation / case</p>
          {chain.investigations.length ? (
            <div className="flex flex-wrap gap-2">
              {chain.investigations.map(link => (
                <Link
                  key={`${link.investigationId}-${link.role}`}
                  to={`/app/darkweb/investigations/${link.investigationId}`}
                  className="font-mono text-[10px] px-2 py-1 rounded-sm border flex items-center gap-1"
                  style={{ borderColor: 'var(--tw-border-mid)', color: 'var(--tw-burgundy)', textDecoration: 'none' }}
                >
                  <Link2 size={10} /> {link.investigationId} · {link.role} · {formatTimestamp(link.linkedAt)}
                </Link>
              ))}
            </div>
          ) : (
            <p className="font-mono text-[10px]" style={dw.faint}>
              Not linked to an investigation. Related actor: {evidence.relatedActor || 'none recorded'}; related
              relationship: {evidence.relatedRelationship || 'none recorded'}.
            </p>
          )}
        </section>

        {/* ── Integrity verification ── */}
        <section>
          <p className="font-mono text-[10px] tracking-widest uppercase mb-2" style={dw.muted}>Integrity verification</p>

          <div className="rounded-sm border p-3 space-y-2" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
            <label className="block">
              <span className="font-mono text-[9px] tracking-widest uppercase" style={dw.faint}>Evidence content to hash (optional)</span>
              <textarea
                value={content}
                onChange={event => setContent(event.target.value)}
                rows={3}
                spellCheck={false}
                placeholder="Paste or type the evidence payload to recalculate its SHA-256. Leave empty to record an attempt that cannot be verified."
                className="w-full mt-1 font-mono text-[10px] p-2 rounded-sm focus:outline-none resize-y"
                style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)', borderWidth: '1px', borderStyle: 'solid' }}
              />
            </label>
            <div className="flex flex-wrap items-center gap-3">
              <label className="flex items-center gap-1.5 font-mono text-[10px]" style={dw.muted}>
                <input type="checkbox" checked={useBase64} onChange={event => setUseBase64(event.target.checked)} style={{ accentColor: 'var(--tw-burgundy)' }} />
                content is base64
              </label>
              <button
                type="button"
                onClick={runVerification}
                disabled={busy}
                className="font-mono text-[10px] px-2.5 py-1 rounded-sm border disabled:opacity-60"
                style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }}
              >
                {busy ? 'Verifying…' : 'Verify integrity'}
              </button>
              <button
                type="button"
                onClick={recordAccessed}
                disabled={busy}
                className="font-mono text-[10px] px-2.5 py-1 rounded-sm border disabled:opacity-60"
                style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }}
              >
                Record access event
              </button>
              <span className="font-mono text-[9px]" style={dw.faint}>
                verifications run: {evidence.verificationCount}
              </span>
            </div>
            {actionError && (
              <p className="font-mono text-[10px]" style={{ color: 'var(--tw-critical)' }}>{actionError}</p>
            )}
          </div>

          {lastOutcome ? (
            <div className="mt-2 space-y-1.5">
              <div className="flex flex-wrap items-center gap-2 font-mono text-[10px]">
                <span className="px-1.5 py-0.5 rounded-sm border uppercase" style={{ borderColor: TONE[tone].color, color: TONE[tone].color }}>
                  {String(lastOutcome.result).replace(/_/g, ' ')}
                </span>
                <span style={dw.muted}>{lastOutcome.detail}</span>
              </div>
              {lastOutcome.calculatedHash && (
                <p className="font-mono text-[9px] break-all" style={dw.faint}>
                  calculated {lastOutcome.algorithm || 'SHA-256'}: {lastOutcome.calculatedHash}
                </p>
              )}
              <Caveat tone={tone === 'ok' ? 'ok' : tone === 'warn' ? 'warn' : 'info'} label="What this result means">
                {lastOutcome.disclaimer ?? chain.integrityDisclaimer}
              </Caveat>
              {lastOutcome.verifiedAt && (
                <p className="font-mono text-[9px]" style={dw.faint}>
                  <Clock size={9} className="inline mr-1" />
                  {formatTimestamp(lastOutcome.verifiedAt)} by {lastOutcome.verifiedBy || 'unknown'}
                </p>
              )}
            </div>
          ) : (
            <Caveat tone="info" label="No verification has been run">
              {chain.verificationLimitation} {evidence.verificationCount === 0 && (
                <>The digest recorded on this item ({evidence.hashAlgorithm}) was written at ingest and has never been
                  recalculated against content, so it is an untested claim rather than a confirmed result.</>
              )}
            </Caveat>
          )}
        </section>

        {/* ── Event history ── */}
        <section>
          <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
            <p className="font-mono text-[10px] tracking-widest uppercase" style={dw.muted}>Event history</p>
            <span className="font-mono text-[9px]" style={dw.faint}>
              append-only · tracking since {formatTimestamp(trackingStartedAt)}
            </span>
          </div>

          {historyStatus === 'NO_HISTORY' ? (
            <Caveat tone="warn" label="No chain of custody history for this item">
              This evidence record existed before custody tracking was enabled, so no lifecycle events exist for it and
              none have been inferred. The record attributes above are the stored fields, not custody events. Handling
              from this point forward is tracked: the first event is written when an action is recorded on this item.
            </Caveat>
          ) : events.length === 0 ? (
            <Caveat tone="info" label="No events recorded">This item has no recorded custody events.</Caveat>
          ) : (
            <ol className="relative border-l pl-4 space-y-3" style={{ borderColor: 'var(--tw-border-mid)' }}>
              {events.map(event => {
                const isTracked = event.origin === 'TRACKED';
                const failed = event.eventType === 'INTEGRITY_VERIFICATION_FAILED';
                return (
                  <li key={event.id} className="relative">
                    <span
                      className="absolute -left-[21px] top-1"
                      style={{ color: failed ? 'var(--tw-critical)' : isTracked ? 'var(--tw-moss)' : 'var(--tw-brass)' }}
                    >
                      {failed ? <TriangleAlert size={11} /> : <CircleDot size={11} />}
                    </span>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-[10px]" style={dw.text}>{event.label}</span>
                      <span
                        className="font-mono text-[8px] px-1.5 py-0.5 rounded-sm uppercase border"
                        style={{
                          borderColor: isTracked ? 'var(--tw-border-mid)' : 'var(--tw-brass)',
                          color: isTracked ? 'var(--tw-text-faint)' : 'var(--tw-brass)',
                        }}
                      >
                        {isTracked ? 'tracked' : 'audit-derived'}
                      </span>
                      {event.investigationId && (
                        <Link to={`/app/darkweb/investigations/${event.investigationId}`} className="font-mono text-[9px]" style={dw.burg}>
                          {event.investigationId} →
                        </Link>
                      )}
                    </div>
                    <p className="font-mono text-[9px] mt-0.5" style={dw.faint}>
                      <Clock size={9} className="inline mr-1" />
                      {formatTimestamp(event.occurredAt)} · <User size={9} className="inline" /> {event.actor} · {event.source}
                    </p>
                    {event.action && event.action !== event.label && (
                      <p className="font-mono text-[10px] mt-0.5" style={dw.muted}>{event.action}</p>
                    )}
                    {(event.previousState || event.newState) && (
                      <p className="font-mono text-[9px] mt-0.5" style={dw.faint}>
                        state: {event.previousState || '—'} → {event.newState || '—'}
                      </p>
                    )}
                    {event.reason && <p className="font-mono text-[9px] mt-0.5 leading-relaxed" style={dw.muted}>{event.reason}</p>}
                    {event.integrityHash && (
                      <p className="font-mono text-[9px] mt-0.5 break-all" style={dw.faint}>
                        <Fingerprint size={9} className="inline mr-1" />
                        {event.verificationResult ? `${event.verificationResult} · ` : ''}{event.integrityHash}
                      </p>
                    )}
                    {event.auditId && (
                      <p className="font-mono text-[9px] mt-0.5" style={dw.faint}>audit reference: {event.auditId}</p>
                    )}
                  </li>
                );
              })}
            </ol>
          )}
        </section>

        {/* ── Standing limitations ── */}
        <section className="space-y-1.5">
          <Caveat tone="info" label="A matching digest is not proof of authenticity">
            <FileText size={9} className="inline mr-1" />
            {chain.integrityDisclaimer}
          </Caveat>
          <Caveat tone="info" label="What custody can and cannot show">
            {historyStatus === 'NO_HISTORY'
              ? 'A custody chain proves only what was recorded from the moment recording began. It cannot reconstruct handling that happened before tracking existed.'
              : 'A custody chain records handling events. It does not by itself establish that the original source was authentic, nor that a matching digest could not have been produced by a third party.'}
          </Caveat>
        </section>

        {CUSTODY_EVENT_TYPES.length > 0 && (
          <p className="font-mono text-[9px]" style={dw.faint}>
            Recorded event types: {CUSTODY_EVENT_TYPES.map(item => item.label).join(' · ')}. Events are appended by
            the API with server timestamps and cannot be edited or deleted.
          </p>
        )}
      </div>
    </div>
  );
}