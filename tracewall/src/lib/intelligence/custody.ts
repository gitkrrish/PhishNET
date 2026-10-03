// ============================================================
// PhishNet — Evidence chain of custody (client).
//
// Thin adapter over the append-only custody API. Three deliberate
// properties:
//
//  * Reads never write. Fetching a chain cannot create an event, so
//    opening an item cannot alter its own history.
//  * Every result is labelled with its origin. TRACKED means this
//    platform recorded the event; AUDIT_DERIVED means it came from the
//    pre-existing audit trail. Nothing is inferred, and an item with no
//    log reports NO_HISTORY rather than an invented sequence.
//  * When the API is unreachable the caller gets a real error, never
//    fabricated data. The rest of the Evidence Locker keeps working.
//
// The caller passes the SHA-256 digest it wants checked by supplying
// the content; the stored digest is never replaced.
// ============================================================
import { request } from '../mockBackend';

export type CustodyEventOrigin = 'TRACKED' | 'AUDIT_DERIVED';
export type HistoryStatus = 'TRACKED' | 'HISTORICAL_ONLY' | 'NO_HISTORY';

export interface CustodyEvent {
  id: string;
  evidenceId: string;
  eventType: string;
  label: string;
  occurredAt: string;
  actor: string;
  action: string;
  previousState: string;
  newState: string;
  reason: string;
  integrityHash: string;
  verificationResult: string;
  verificationReference: string;
  investigationId: string | null;
  source: string;
  origin: CustodyEventOrigin;
  auditId: string | null;
}

export interface CustodyEvidence {
  id: string;
  evidenceType: string;
  name: string;
  sourceId: string | null;
  sourceLabel: string | null;
  source: string;
  observedAt: string;
  collectedAt: string;
  collectionMethod: string;
  collectedBy: string;
  fileName: string;
  fileSize: number | null;
  fileFormat: string;
  hash: string;
  hashAlgorithm: string;
  integrityStatus: string;
  lastVerifiedAt: string | null;
  lastVerifiedBy: string;
  lastVerificationResult: string;
  lastVerificationDetail: string;
  verificationCount: number;
  status: string;
  storageReference: string;
  provenance: string;
  description: string;
  relatedActor: string | null;
  relatedHandle: string | null;
  relatedInfrastructure: string | null;
  relatedRelationship: string | null;
  dataState: string;
  analyst: string;
  createdAt: string;
  updatedAt: string;
  reliability: number;
  confidence: number;
}

export interface CustodyInvestigationLink {
  investigationId: string;
  entityType: string;
  role: string;
  linkedAt: string;
}

export interface CustodyChain {
  evidence: CustodyEvidence;
  investigations: CustodyInvestigationLink[];
  events: CustodyEvent[];
  trackedEvents: CustodyEvent[];
  historicalEvents: CustodyEvent[];
  trackingStartedAt: string | null;
  historyStatus: HistoryStatus;
  integrityDisclaimer: string;
  verificationLimitation: string;
}

export type VerificationResult = 'MATCH' | 'MISMATCH' | 'NOT_VERIFIABLE' | 'NO_REFERENCE';

export interface VerificationOutcome {
  evidenceId: string;
  result: VerificationResult;
  detail: string;
  algorithm: string;
  storedHash: string;
  calculatedHash: string;
  verifiedAt: string;
  verifiedBy: string;
  verificationCount: number;
  integrityStatus: string;
  custodyEventId: string;
  authenticityEstablished: boolean;
  disclaimer: string;
}

export const CUSTODY_EVENT_TYPES = [
  { type: 'EVIDENCE_COLLECTED', label: 'Collected' },
  { type: 'EVIDENCE_IMPORTED', label: 'Imported' },
  { type: 'EVIDENCE_REGISTERED', label: 'Registered' },
  { type: 'INTEGRITY_VERIFIED', label: 'Integrity verified' },
  { type: 'INTEGRITY_VERIFICATION_FAILED', label: 'Integrity verification failed' },
  { type: 'EVIDENCE_ACCESSED', label: 'Accessed' },
  { type: 'EVIDENCE_EXPORTED', label: 'Exported / transferred' },
  { type: 'LINKED_TO_INVESTIGATION', label: 'Linked to investigation' },
  { type: 'STATUS_CHANGED', label: 'Status changed' },
  { type: 'EVIDENCE_ARCHIVED', label: 'Archived' },
] as const;

export function fetchCustodyChain(evidenceId: string): Promise<CustodyChain> {
  return request<{ data: CustodyChain }>(`/intel/evidence/${encodeURIComponent(evidenceId)}/custody`).then(envelope => envelope.data);
}

/**
 * Recalculate the digest over the supplied content and compare it with
 * the digest already recorded on the item.
 *
 * `content` is the evidence payload. With no content the server answers
 * NOT_VERIFIABLE, because a digest that was never recomputed is not a
 * pass. The recorded digest is never rewritten on a mismatch.
 */
export function verifyEvidenceIntegrity(
  evidenceId: string,
  options: { content?: string; contentEncoding?: 'utf8' | 'base64'; reason?: string } = {},
): Promise<{ verification: VerificationOutcome; chain: CustodyChain }> {
  return request<{ data: { verification: VerificationOutcome; chain: CustodyChain } }>(
    `/intel/evidence/${encodeURIComponent(evidenceId)}/verify`,
    {
      method: 'POST',
      body: JSON.stringify({
        content: options.content,
        contentEncoding: options.contentEncoding ?? 'utf8',
        reason: options.reason,
      }),
    },
  ).then(envelope => envelope.data);
}

/** Append one custody event. The log is append-only: there is no edit. */
export function recordCustodyEvent(
  evidenceId: string,
  input: {
    eventType: string;
    action?: string;
    previousState?: string;
    newState?: string;
    reason?: string;
    integrityHash?: string;
    investigationId?: string | null;
  },
): Promise<{ event: CustodyEvent; chain: CustodyChain }> {
  return request<{ data: { event: CustodyEvent; chain: CustodyChain } }>(
    `/intel/evidence/${encodeURIComponent(evidenceId)}/custody`,
    { method: 'POST', body: JSON.stringify(input) },
  ).then(envelope => envelope.data);
}

export function fetchCustodyEventTypes(): Promise<Array<{ type: string; label: string }>> {
  return request<{ data: Array<{ type: string; label: string }> }>('/intel/custody/event-types').then(envelope => envelope.data);
}

/** SHA-256 of a string, hex encoded. Used to pre-check content locally. */
export async function sha256Hex(content: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(content));
  return Array.from(new Uint8Array(digest))
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
}

/** Result colour token, so the same result always reads the same way. */
export function verificationTone(result: VerificationResult | string): 'ok' | 'warn' | 'info' {
  if (result === 'MATCH') return 'ok';
  if (result === 'MISMATCH') return 'warn';
  return 'info';
}