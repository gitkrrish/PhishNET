// ============================================================
// PhishNet — Natural language search (client).
//
// Thin adapter over the two NL endpoints that answer against the
// stored intelligence model:
//
//   POST /intel/investigations/nl-search  case + investigation scope
//   POST /intel/ai/nl-search              whole-model scope
//
// Both endpoints parse the question into concrete operations, run
// those operations against real records, and return what matched with
// the reason each match qualified. The UI shows those operations next
// to the results: the point of the feature is that the answer is
// traceable to a filter, not that a model sounds confident.
//
// The two scopes return genuinely different shapes, so they are typed
// as a union rather than flattened into one loose object. A field the
// endpoint does not send does not exist on the client type, which
// stops the UI from rendering a section that was never answered.
//
// Properties this module preserves:
//
//  * No query means no request. Nothing is generated locally.
//  * An unsupported question is reported as unsupported, not
//    approximated with a fuzzy match.
//  * When nothing matched, that is the answer.
//  * `unfiltered` is passed straight through, so a question the parser
//    did not understand can be reported as such instead of presenting
//    the whole table as a result.
// ============================================================
import { request } from '../mockBackend';

export type NlScope = 'investigations' | 'ai';

export interface NlOperation {
  kind: string;
  /** Human-readable statement of what this operation filtered on. */
  label: string;
  applied: boolean;
  /** The filter value, e.g. an id list or a threshold. */
  value?: unknown;
}

export interface NlUnsupported {
  clause: string;
  reason: string;
}

/**
 * Entities the parser resolved, grouped by kind. This is a set of buckets
 * rather than a flat list, because one question can resolve several ids of
 * several kinds at once and the grouping is what the executor filters on.
 */
export interface NlEntities {
  actorIds: string[];
  handleIds: string[];
  handleValues: string[];
  walletIds: string[];
  walletAddresses: string[];
  pgpFingerprints: string[];
  infrastructureIds: string[];
  infrastructureValues: string[];
  evidenceIds: string[];
  relationshipIds: string[];
  investigationIds: string[];
  ipValues: string[];
  domainValues: string[];
  /** Ids that looked like records but do not exist; never used as filters. */
  unresolvedIds: string[];
}

/** Why a record matched. `observed` reads a stored field, `correlation` is a join. */
export interface NlReason {
  field: string;
  matched: string;
  kind: 'observed' | 'correlation';
}

/** Server-supplied in-app path for a source record. */
export interface NlNavigation {
  investigationPath?: string;
  evidencePath?: string;
  actorPath?: string;
  relationshipPath?: string;
  walletPath?: string;
  infrastructurePath?: string;
  [key: string]: string | undefined;
}

export interface NlEnvelope {
  query: string;
  scope: NlScope;
  operations: NlOperation[];
  unsupported: NlUnsupported[];
  entities: NlEntities;
  note: string;
  /** True when nothing in the question produced an applied filter. */
  unfiltered: boolean;
  total: number;
}

// ── Investigation scope ──────────────────────────────────────────

export interface NlInvestigationMatch {
  id: string;
  title: string;
  status: string;
  analyst: string;
  confidence: number;
  updatedAt: string;
  lastActivityAt: string | null;
  evidenceCount: number;
  unverifiedEvidenceCount: number;
  entityCount: number;
  reasons: NlReason[];
  navigation: NlNavigation;
  sourceRecords: {
    investigationId: string;
    evidenceIds: string[];
    relationshipIds: string[];
    actorIds: string[];
  };
}

export interface NlInvestigationsResponse extends NlEnvelope {
  scope: 'investigations';
  /** Stored investigations considered, so "0 of N" is reportable. */
  evaluated: number;
  matches: NlInvestigationMatch[];
  /** True when more matches existed than the response cap. */
  truncated: boolean;
}

// ── Whole-model scope ────────────────────────────────────────────

/** A statement read from stored records, or computed by joining them. */
export interface NlStatement {
  statement: string;
  sourceId: string;
  navigation: NlNavigation;
  /** Present on evidence statements: whether the digest was rechecked. */
  integrity?: { verified: boolean; result: string; storedHash?: string; lastVerifiedAt?: string | null };
}

export interface NlAiInvestigationRef {
  id: string;
  title: string;
  status: string;
  confidence: number;
  reasons: NlReason[];
  navigation: NlNavigation;
}

export interface NlAiResponse extends NlEnvelope {
  scope: 'ai';
  answerKind: 'ANSWER' | 'SUMMARY' | 'EXPLANATION' | 'NO_MATCH';
  /** Read directly from stored fields. */
  observed: NlStatement[];
  /** Produced by joining stored records. */
  correlation: NlStatement[];
  /** Always empty: no model is called, and `inferenceAvailable` says so. */
  inference: NlStatement[];
  /** False, so the UI states that no language model took part. */
  inferenceAvailable: boolean;
  matchedInvestigations: NlAiInvestigationRef[];
}

export type NlAnswer = NlInvestigationsResponse | NlAiResponse;

function post<T extends NlAnswer>(path: string, query: string, extra: Record<string, unknown> = {}): Promise<T> {
  const trimmed = query.trim();
  // Refuse locally rather than sending an empty question the server
  // would have to invent an answer to.
  if (!trimmed) return Promise.reject(new Error('Enter a question before searching.'));
  return request<{ data: T }>(path, {
    method: 'POST',
    body: JSON.stringify({ query: trimmed, ...extra }),
  }).then(envelope => envelope.data);
}

/** Case and investigation scope. */
export function searchInvestigationsNl(
  query: string,
  options: { status?: string; investigationId?: string } = {},
): Promise<NlInvestigationsResponse> {
  return post<NlInvestigationsResponse>('/intel/investigations/nl-search', query, options);
}

/** Whole-model scope, used by AI Analysis. */
export function searchIntelligenceNl(query: string): Promise<NlAiResponse> {
  return post<NlAiResponse>('/intel/ai/nl-search', query);
}

/** Question templates offered as examples, not filler suggestions. */
export const NL_EXAMPLES = [
  'Show open investigations linked to threat actors',
  'Which investigations have unverified evidence?',
  'Infrastructure shared between two threat actors',
  'Everything about actor ACT-001',
  'Investigations mentioning suspicious wallet addresses',
  'Open high-severity investigations in the last 7 days',
];

/** True when the question produced no applied filter at all. */
export function isUnparsed(answer: NlAnswer): boolean {
  return answer.unfiltered || answer.operations.every(operation => !operation.applied);
}

/** True when the question parsed but nothing in the model satisfies it. */
export function isEmptyResult(answer: NlAnswer): boolean {
  if (isUnparsed(answer)) return false;
  if (answer.scope === 'investigations') return answer.matches.length === 0;
  return answer.observed.length === 0 && answer.correlation.length === 0 && answer.inference.length === 0;
}