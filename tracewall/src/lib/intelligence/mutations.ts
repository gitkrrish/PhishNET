// ============================================================
// PhishNet — Central intelligence mutations.
//
// Every write goes through one of these functions. A single analyst
// action therefore fans out automatically across the whole platform:
//
//   add -> normalise -> duplicate check -> persist record
//      -> auto-relationship -> timeline event -> alert
//      -> audit event -> activity feed
//
// Relationship, timeline, alert and audit creation are all derived
// from the data actually supplied, never fabricated.
// ============================================================
import { updateDataset, replaceDataset, createAuditEvent, getDataset } from './dataset';
import type {
  IntelligenceDataset,
  ActorRecord,
  HandleRecord,
  PgpRecord,
  WalletRecord,
  InfrastructureRecord,
  SourceRecord,
  Observation,
  RelationshipRecord,
  EvidenceRecord,
  TimelineRecord,
  InvestigationRecord,
  AlertRecord,
  DataState,
  IntelligenceAuditEvent,
  // Extended entity types: MITRE ATT&CK, vulnerability and crypto records.
  MitreTtpRecord,
  MitreTactic,
  MitrePlatform,
  MitrePermission,
  MitreDataSource,
  CveRecordRecord,
  CveSeverity,
  CweType,
  VulnerabilityCategory,
  ExploitationStatus,
  WalletTransactionRecord,
  WalletClusterRecord,
  BlockchainNetwork,
  TransactionDirection,
  TransactionStatus,
  ClusteringMethod,
} from './types';
import type { DuplicateCandidate } from './normalize';
import {
  normalizeHandle,
  normalizeDomain,
  normalizePgp,
  normalizeWallet,
  normalizeTimestamp,
  normalizeConfidence,
  normalizeReliability,
  normalizeText,
  normalizeActorRef,
  normalizeSourceName,
  findDuplicates,
  nextId,
  shortFingerprint,
} from './normalize';

const ANALYST = 'Analyst';

export interface MutationResult<T> {
  record: T;
  duplicates: DuplicateCandidate[];
  relationships: RelationshipRecord[];
  alerts: AlertRecord[];
  timeline: TimelineRecord[];
  audit: IntelligenceAuditEvent[];
  observations: Observation[];
}

function emptyResult<T>(record: T, duplicates: DuplicateCandidate[] = []): MutationResult<T> {
  return { record, duplicates, relationships: [], alerts: [], timeline: [], audit: [], observations: [] };
}

/** An audit intent; `commit` turns it into a real, timestamped audit event. */
type AuditDescriptor = Omit<IntelligenceAuditEvent, 'id' | 'time' | 'actor' | 'ip'>;

interface DraftWrites {
  relationships?: RelationshipRecord[];
  alerts?: AlertRecord[];
  timeline?: TimelineRecord[];
  audit?: AuditDescriptor[];
  observations?: Observation[];
}

interface Context {
  now: string;
  actorRef: string;
  state: DataState;
  alloc: IdAllocator;
  /** Relationships already drafted in this same analyst action. */
  pendingRelationships: RelationshipRecord[];
}

/**
 * Ids are allocated per analyst action, so two relationships created by
 * the same write can never collide on `REL-001`.
 */
interface IdAllocator {
  taken: Set<string>;
}

function createContext(now: string, state: DataState): Context {
  return { now, actorRef: ANALYST, state, alloc: { taken: new Set() }, pendingRelationships: [] };
}

function allocId(alloc: IdAllocator, prefix: string, existing: Iterable<string>): string {
  for (const id of existing) alloc.taken.add(id);
  let counter = 1;
  let candidate = `${prefix}-${String(counter).padStart(3, '0')}`;
  while (alloc.taken.has(candidate)) {
    counter += 1;
    candidate = `${prefix}-${String(counter).padStart(3, '0')}`;
  }
  alloc.taken.add(candidate);
  return candidate;
}

function sameRelationship(rel: RelationshipRecord, draft: DraftRelationship): boolean {
  return (
    rel.type === draft.type &&
    ((rel.sourceEntity === draft.sourceEntity && rel.targetEntity === draft.targetEntity) ||
      (rel.sourceEntity === draft.targetEntity && rel.targetEntity === draft.sourceEntity))
  );
}

type DraftRelationship = Pick<RelationshipRecord, 'sourceEntity' | 'targetEntity' | 'type'>;

// ── shared write helpers ──────────────────────────────────────
/** Adds a relationship, skipping an identical existing one. */
function pushRelationship(
  dataset: IntelligenceDataset,
  draft: Partial<RelationshipRecord> & DraftRelationship,
  ctx: Context,
): { record: RelationshipRecord; isNew: boolean } {
  const existing =
    ctx.pendingRelationships.find(rel => sameRelationship(rel, draft)) ??
    dataset.relationships.find(rel => sameRelationship(rel, draft));
  if (existing) return { record: existing, isNew: false };

  const record: RelationshipRecord = {
    id: allocId(ctx.alloc, 'REL', dataset.relationships.map(rel => rel.id)),
    sourceEntity: draft.sourceEntity,
    targetEntity: draft.targetEntity,
    sourceType: draft.sourceType ?? 'Actor',
    targetType: draft.targetType ?? 'Actor',
    type: draft.type,
    confidence: draft.confidence ?? 70,
    evidenceIds: draft.evidenceIds ?? [],
    explanation: draft.explanation ?? '',
    firstObserved: draft.firstObserved ?? ctx.now,
    lastObserved: draft.lastObserved ?? ctx.now,
    supporting: draft.supporting ?? [],
    against: draft.against ?? [],
    dataState: ctx.state,
    analyst: ctx.actorRef,
    createdAt: ctx.now,
    sourceLabel: 'Automatic correlation',
  };
  ctx.pendingRelationships.push(record);
  return { record, isNew: true };
}

/** Fields the push helpers fill in themselves are optional on a draft. */
type AlertDraft = Omit<AlertRecord, 'id' | 'timestamp' | 'status' | 'evidenceIds'> &
  Partial<Pick<AlertRecord, 'id' | 'timestamp' | 'status' | 'evidenceIds'>>;

type ObservationDraft = Omit<
  Observation,
  'id' | 'dataState' | 'analyst' | 'evidenceIds' | 'tags' | 'notes' | 'platform' | 'handleId'
> &
  Partial<Pick<Observation, 'dataState' | 'analyst' | 'evidenceIds' | 'tags' | 'notes' | 'platform' | 'handleId'>>;

function pushAlert(
  dataset: IntelligenceDataset,
  draft: AlertDraft,
  ctx: Context,
): AlertRecord {
  return {
    id: draft.id ?? allocId(ctx.alloc, 'DW-ALERT', dataset.alerts.map(alert => alert.id)),
    type: draft.type,
    severity: draft.severity,
    title: draft.title,
    timestamp: draft.timestamp ?? ctx.now,
    actorId: draft.actorId ?? null,
    reason: draft.reason,
    evidenceIds: draft.evidenceIds ?? [],
    confidence: draft.confidence ?? 70,
    status: draft.status ?? 'OPEN',
    dataState: ctx.state,
    entityType: draft.entityType ?? (draft.actorId ? 'ACTOR' : 'UNKNOWN'),
    entityId: draft.entityId ?? draft.actorId ?? null,
  };
}

function pushTimeline(
  dataset: IntelligenceDataset,
  draft: Omit<TimelineRecord, 'id'> & Partial<Pick<TimelineRecord, 'id'>>,
  ctx: Context,
): TimelineRecord {
  return {
    id: draft.id ?? allocId(ctx.alloc, 'TL', dataset.timeline.map(event => event.id)),
    actorId: draft.actorId,
    time: draft.time ?? ctx.now,
    type: draft.type,
    title: draft.title,
    description: draft.description,
    confidence: draft.confidence ?? 70,
    dataState: ctx.state,
    analyst: ctx.actorRef,
    source: draft.source ?? 'Analyst',
    evidenceIds: draft.evidenceIds ?? [],
  };
}

function pushObservation(dataset: IntelligenceDataset, draft: ObservationDraft, ctx: Context): Observation {
  return {
    id: allocId(ctx.alloc, 'OBS', dataset.observations.map(obs => obs.id)),
    actorId: draft.actorId ?? null,
    handleId: draft.handleId ?? null,
    platform: draft.platform ?? null,
    observationType: draft.observationType,
    content: draft.content,
    timestamp: draft.timestamp ?? ctx.now,
    source: draft.source,
    confidence: draft.confidence,
    tags: draft.tags ?? [],
    notes: draft.notes ?? '',
    dataState: ctx.state,
    analyst: ctx.actorRef,
    evidenceIds: draft.evidenceIds ?? [],
  };
}

interface CommitOptions {
  /** Actors whose collections changed — merged into the dataset, never replacing it. */
  actorUpdates?: ActorRecord[];
  /** Records the caller already persisted, echoed back in the result. */
  persisted?: Partial<Record<'relationships' | 'alerts' | 'timeline' | 'observations', Array<{ id: string }>>>;
}

/** Adds only records whose id is not already stored, so nothing is written twice. */
function appendNew<T extends { id: string }>(stored: T[], incoming: T[]): T[] {
  const known = new Set(stored.map(item => item.id));
  const fresh: T[] = [];
  for (const item of incoming) {
    if (known.has(item.id)) continue;
    known.add(item.id);
    fresh.push(item);
  }
  return fresh;
}

/** Combines two record lists for a `MutationResult`, keeping one entry per id. */
function mergeById<T extends { id: string }>(primary: T[], echo: T[]): T[] {
  const seen = new Set(primary.map(item => item.id));
  return [...primary, ...echo.filter(item => !seen.has(item.id))];
}

/** Commit every derived artefact of one analyst action in a single write. */
function commit<T>(
  record: T,
  duplicates: DuplicateCandidate[],
  writes: DraftWrites,
  options: CommitOptions = {},
): MutationResult<T> {
  const actorUpdates = options.actorUpdates ?? [];
  const auditEvents = (writes.audit ?? []).map(descriptor =>
    createAuditEvent(
      descriptor.action,
      descriptor.entity,
      descriptor.entityId,
      descriptor.after,
      ANALYST,
      descriptor.source,
      descriptor.result,
      descriptor.before,
    ),
  );
  const primaryAction = writes.audit?.[0]?.action;

  const stored = getDataset();
  const persisted = options.persisted ?? {};
  // The caller already stored its primary record, so it is excluded from the
  // append (which would otherwise duplicate it) but is still echoed back in the
  // result so callers receive the record they created.
  const persistedRelationships = (persisted.relationships ?? []) as RelationshipRecord[];
  const persistedTimeline = (persisted.timeline ?? []) as TimelineRecord[];
  const persistedObservations = (persisted.observations ?? []) as Observation[];
  const persistedAlerts = (persisted.alerts ?? []) as AlertRecord[];

  const newRelationships = appendNew(stored.relationships, writes.relationships ?? []);
  const newTimeline = appendNew(stored.timeline, writes.timeline ?? []);
  const newObservations = appendNew(stored.observations, writes.observations ?? []);
  const newAlerts = appendNew(stored.alerts, writes.alerts ?? []);

  const resultRelationships = mergeById(newRelationships, persistedRelationships);
  const resultTimeline = mergeById(newTimeline, persistedTimeline);
  const resultObservations = mergeById(newObservations, persistedObservations);
  const resultAlerts = mergeById(newAlerts, persistedAlerts);

  updateDataset(draft => ({
    ...draft,
    actors: actorUpdates.length
      ? draft.actors.map(actor => actorUpdates.find(update => update.id === actor.id) ?? actor)
      : draft.actors,
    relationships: [...draft.relationships, ...newRelationships],
    alerts: [...newAlerts, ...draft.alerts],
    timeline: [...draft.timeline, ...newTimeline],
    observations: [...draft.observations, ...newObservations],
    audit: [...auditEvents, ...draft.audit],
    monitoring: {
      ...draft.monitoring,
      lastCollection: auditEvents[0]?.time ?? draft.monitoring.lastCollection,
      newActors: draft.monitoring.newActors + (primaryAction === 'ACTOR_CREATED' ? 1 : 0),
      newIndicators: draft.monitoring.newIndicators + (primaryAction === 'HANDLE_ADDED' ? 1 : 0),
      newRelationships: draft.monitoring.newRelationships + newRelationships.length,
      alerts: draft.monitoring.alerts + newAlerts.length,
    },
  }));

  return {
    record,
    duplicates,
    relationships: resultRelationships,
    alerts: resultAlerts,
    timeline: resultTimeline,
    audit: auditEvents,
    observations: resultObservations,
  };
}

// ── Threat Actor ──────────────────────────────────────────────
export interface ActorInput {
  id?: string;
  name?: string;
  aliases?: string[];
  handles?: string[];
  platforms?: string[];
  firstSeen?: string;
  lastSeen?: string;
  status?: 'ACTIVE' | 'DORMANT' | 'SUSPENDED';
  confidence?: number;
  tags?: string[];
  notes?: string;
}

export function addActor(input: ActorInput): MutationResult<ActorRecord> {
  const dataset = getDataset();
  const now = new Date().toISOString();
  const ctx: Context = createContext(now, 'ANALYST_ADDED');

  const requestedId = normalizeActorRef(input.id ?? '') || `ACTOR-${String(dataset.actors.length + 1).padStart(3, '0')}`;
  const id = dataset.lookups.actorsById[requestedId] ? allocId(ctx.alloc, 'ACTOR', dataset.actors.map(actor => actor.id)) : requestedId;
  const duplicates = findDuplicates(dataset, 'ACTOR', input.name ?? requestedId);

  const aliases = (input.aliases ?? []).map(normalizeText).filter(Boolean);
  if (input.name && !aliases.length) aliases.push(normalizeText(input.name));

  const firstSeen = normalizeTimestamp(input.firstSeen, now);
  const lastSeen = normalizeTimestamp(input.lastSeen, now);

  const actor: ActorRecord = {
    id,
    aliases,
    handles: (input.handles ?? []).map(normalizeHandle).filter(Boolean),
    pgpFingerprints: [],
    walletAddrs: [],
    domains: [],
    platforms: (input.platforms ?? []).map(normalizeText).filter(Boolean),
    firstSeen,
    lastSeen,
    activityLevel: 'MEDIUM',
    confidenceScore: normalizeConfidence(input.confidence, 70),
    status: input.status ?? 'ACTIVE',
    relatedActorIds: [],
    associatedEvidence: [],
    behavioralProfile: {
      activityFrequency: 'MEDIUM',
      activeHours: [],
      platformPreferences: (input.platforms ?? []).map(platform => ({ platform, weight: 50 })),
      postingFrequency: 0,
      topicClusters: input.tags ?? [],
      interactionPattern: 'Not yet profiled - behavioural collection pending.',
      personaTransitions: 0,
    },
    stylometricProfile: {
      avgSentenceLength: 0,
      punctuationPattern: 'No samples collected',
      capitalisationTendency: 'MEDIUM',
      vocabularyRichness: 0,
      recurringExpressions: [],
      sentenceStructure: 'No samples collected',
      languagePatterns: [],
      sampleText: '',
    },
    primaryMotivation: input.notes || 'Under assessment',
    isSynthetic: false,
    dataState: 'ANALYST_ADDED',
    analyst: ANALYST,
    tags: input.tags ?? [],
    notes: input.notes ?? '',
  };

  const writes: DraftWrites = {
    audit: [
      {
        action: 'ACTOR_CREATED',
        entity: 'Actor',
        entityId: id,
        before: 'n/a',
        after: `${id} - ${aliases[0] ?? id} (${actor.status})`,
        source: 'Central Intelligence Model',
        result: 'SUCCESS',
        outcome: 'SUCCESS',
      },
    ],
    timeline: [
      pushTimeline(
        dataset,
        {
          actorId: id,
          time: firstSeen,
          type: 'FIRST_SEEN',
          title: 'Threat Actor Recorded',
          description: `${id} entered the central intelligence model.`,
          confidence: actor.confidenceScore,
          source: 'Analyst',
        },
        ctx,
      ),
    ],
    alerts: [
      pushAlert(
        dataset,
        {
          type: 'NEW_ACTOR',
          severity: 'HIGH',
          title: `New Threat Actor Detected - ${id}`,
          actorId: id,
          reason: `Actor ${id} (${aliases[0] ?? 'unaliased'}) was added to the central intelligence model.`,
          confidence: actor.confidenceScore,
          entityType: 'ACTOR',
          entityId: id,
        },
        ctx,
      ),
    ],
  };

  updateDataset(draft => ({ ...draft, actors: [...draft.actors, actor] }));
  return commit(actor, duplicates, writes);
}

// ── Handle ────────────────────────────────────────────────────
export interface HandleInput {
  handle: string;
  platform: string;
  actorId?: string;
  firstSeen?: string;
  lastSeen?: string;
  source?: string;
  confidence?: number;
  notes?: string;
}

export function addHandle(input: HandleInput): MutationResult<HandleRecord> {
  const dataset = getDataset();
  const now = new Date().toISOString();
  const ctx: Context = createContext(now, 'ANALYST_ADDED');

  const value = normalizeText(input.handle);
  const normalized = normalizeHandle(value);
  const duplicates = findDuplicates(dataset, 'HANDLE', value, input.platform);
  const actorId = input.actorId ? normalizeActorRef(input.actorId) : null;
  const confidence = normalizeConfidence(input.confidence, 70);
  const firstSeen = normalizeTimestamp(input.firstSeen, now);
  const lastSeen = normalizeTimestamp(input.lastSeen, now);

  const handle: HandleRecord = {
    id: allocId(ctx.alloc, 'HND', dataset.handles.map(item => item.id)),
    value,
    platform: input.platform || 'Unspecified',
    sourceId: input.source || 'Analyst',
    firstSeen,
    lastSeen,
    confidence,
    normalized,
    actorId,
    dataState: 'ANALYST_ADDED',
    analyst: ANALYST,
    source: input.source,
    notes: input.notes ?? '',
  };

  const actorUpdates: ActorRecord[] = [];
  const relationships: RelationshipRecord[] = [];

  // Actor <-> Handle
  if (actorId) {
    const { record } = pushRelationship(
      dataset,
      {
        sourceEntity: actorId,
        targetEntity: handle.id,
        sourceType: 'Actor',
        targetType: 'Handle',
        type: 'USES_HANDLE',
        confidence,
        explanation: `${actorId} observed using handle "${value}" on ${handle.platform}.`,
        supporting: [`Handle observed on ${handle.platform}`, `First seen ${firstSeen.slice(0, 10)}`],
      },
      ctx,
    );
    relationships.push(record);

    const actor = dataset.lookups.actorsById[actorId];
    if (actor) {
      actorUpdates.push({
        ...actor,
        handles: actor.handles.includes(value) ? actor.handles : [...actor.handles, value],
        platforms: actor.platforms.includes(handle.platform) ? actor.platforms : [...actor.platforms, handle.platform],
        lastSeen: lastSeen > actor.lastSeen ? lastSeen : actor.lastSeen,
        firstSeen: firstSeen < actor.firstSeen ? firstSeen : actor.firstSeen,
      });
    }
  }

  // Same handle already seen on another platform -> cross-platform reuse link
  for (const existing of dataset.handles.filter(
    item => normalizeHandle(item.normalized || item.value) === normalized && item.id !== handle.id,
  )) {
    const { record } = pushRelationship(
      dataset,
      {
        sourceEntity: existing.id,
        targetEntity: handle.id,
        sourceType: 'Handle',
        targetType: 'Handle',
        type: 'SHARED_HANDLE',
        confidence: Math.min(90, Math.round((existing.confidence + confidence) / 2)),
        explanation: `Handle "${value}" observed on both ${existing.platform} and ${handle.platform} - a cross-platform reuse indicator.`,
        supporting: [`Identical normalized handle on ${existing.platform} and ${handle.platform}`],
        against: ['Platforms are independent identity systems'],
      },
      ctx,
    );
    relationships.push(record);
  }

  const writes: DraftWrites = {
    audit: [
      {
        action: 'HANDLE_ADDED',
        entity: 'Handle',
        entityId: handle.id,
        before: 'n/a',
        after: `${value} on ${handle.platform}${actorId ? ` linked to ${actorId}` : ''}`,
        source: input.source || 'Analyst',
        result: 'SUCCESS',
        outcome: 'SUCCESS',
      },
    ],
    timeline: actorId
      ? [
          pushTimeline(
            dataset,
            {
              actorId,
              time: firstSeen,
              type: 'HANDLE_CHANGE',
              title: `New Handle - ${value}`,
              description: `Handle "${value}" observed on ${handle.platform}.`,
              confidence,
              source: input.source ?? 'Analyst',
            },
            ctx,
          ),
        ]
      : [],
    alerts: [
      pushAlert(
        dataset,
        {
          type: 'NEW_HANDLE',
          severity: confidence >= 75 ? 'HIGH' : 'MEDIUM',
          title: `New Handle Detected - ${value}`,
          actorId,
          reason: `Handle "${value}" recorded on ${handle.platform}${actorId ? ` and linked to ${actorId}` : ''}.`,
          confidence,
          entityType: 'HANDLE',
          entityId: handle.id,
        },
        ctx,
      ),
    ],
    observations: actorId
      ? [
          pushObservation(
            dataset,
            {
              actorId,
              handleId: handle.id,
              platform: handle.platform,
              observationType: 'HANDLE_OBSERVED',
              content: `Handle "${value}" observed on ${handle.platform}.`,
              timestamp: firstSeen,
              source: input.source || 'Analyst',
              confidence,
              tags: ['handle', normalized],
              notes: input.notes ?? '',
            },
            ctx,
          ),
        ]
      : [],
    relationships,
  };

  updateDataset(draft => ({ ...draft, handles: [...draft.handles, handle] }));
  return commit(handle, duplicates, writes, { actorUpdates });
}

// ── PGP identity ──────────────────────────────────────────────
export interface PgpInput {
  fingerprint: string;
  handle?: string;
  actorId?: string;
  platform?: string;
  firstSeen?: string;
  lastSeen?: string;
  source?: string;
  confidence?: number;
  notes?: string;
}

export function addPgp(input: PgpInput): MutationResult<PgpRecord> {
  const dataset = getDataset();
  const now = new Date().toISOString();
  const ctx: Context = createContext(now, 'ANALYST_ADDED');

  const fingerprint = normalizeText(input.fingerprint).toUpperCase();
  const flat = normalizePgp(fingerprint);
  const duplicates = findDuplicates(dataset, 'PGP', fingerprint);
  const confidence = normalizeConfidence(input.confidence, 90);
  const firstSeen = normalizeTimestamp(input.firstSeen, now);
  const lastSeen = normalizeTimestamp(input.lastSeen, now);
  const handleValue = input.handle ? normalizeHandle(input.handle) : null;
  const handleRecord = handleValue
    ? (dataset.handles.find(item => normalizeHandle(item.normalized || item.value) === handleValue) ?? null)
    : null;
  const actorId = input.actorId ? normalizeActorRef(input.actorId) : (handleRecord?.actorId ?? null);

  const existing = dataset.pgpKeys.find(key => normalizePgp(key.fingerprint) === flat);
  const record: PgpRecord = existing
    ? {
        ...existing,
        actorIds: actorId && !existing.actorIds.includes(actorId) ? [...existing.actorIds, actorId] : existing.actorIds,
        firstSeen: firstSeen < existing.firstSeen ? firstSeen : existing.firstSeen,
        lastSeen: lastSeen > existing.lastSeen ? lastSeen : existing.lastSeen,
        confidence: Math.max(existing.confidence, confidence),
        handleIds: handleRecord ? [...new Set([...(existing.handleIds ?? []), handleRecord.id])] : existing.handleIds,
        dataState: existing.dataState === 'SYNTHETIC_DEMO' ? 'SYNTHETIC_DEMO' : 'ANALYST_ADDED',
        notes: input.notes ?? existing.notes ?? '',
      }
    : {
        id: allocId(ctx.alloc, 'PGP', dataset.pgpKeys.map(key => key.id)),
        fingerprint,
        actorIds: actorId ? [actorId] : [],
        firstSeen,
        lastSeen,
        sources: input.source ? [input.source] : [],
        confidence,
        handleIds: handleRecord ? [handleRecord.id] : [],
        dataState: 'ANALYST_ADDED',
        analyst: ANALYST,
        notes: input.notes ?? '',
      };

  const relationships: RelationshipRecord[] = [];
  const actorUpdates: ActorRecord[] = [];

  if (actorId) {
    const actor = dataset.lookups.actorsById[actorId];
    if (actor && !actor.pgpFingerprints.includes(fingerprint)) {
      actorUpdates.push({ ...actor, pgpFingerprints: [...actor.pgpFingerprints, fingerprint] });
    }

    for (const otherId of record.actorIds.filter(value => value !== actorId)) {
      const other = dataset.lookups.actorsById[otherId];
      if (!other) continue;
      if (!other.pgpFingerprints.includes(fingerprint)) {
        actorUpdates.push({ ...other, pgpFingerprints: [...other.pgpFingerprints, fingerprint] });
      }
      const ordered = [actorId, otherId].sort();
      const { record: rel } = pushRelationship(
        dataset,
        {
          sourceEntity: ordered[0],
          targetEntity: ordered[1],
          sourceType: 'Actor',
          targetType: 'Actor',
          type: 'SHARED_PGP',
          confidence,
          explanation: `${actorId} and ${otherId} publish the identical PGP fingerprint ${shortFingerprint(fingerprint)}.`,
          supporting: ['Identical PGP fingerprint', `First observed ${firstSeen.slice(0, 10)}`],
          against: ['PGP keys can be copied or shared between collaborators'],
        },
        ctx,
      );
      relationships.push(rel);
    }
  }

  if (handleRecord) {
    const { record: rel } = pushRelationship(
      dataset,
      {
        sourceEntity: handleRecord.id,
        targetEntity: record.id,
        sourceType: 'Handle',
        targetType: 'PGP',
        type: 'SHARED_PGP',
        confidence,
        explanation: `Handle "${handleRecord.value}" signed with PGP key ${shortFingerprint(fingerprint)}.`,
        supporting: [`Handle observed on ${handleRecord.platform}`],
      },
      ctx,
    );
    relationships.push(rel);
  }

  const writes: DraftWrites = {
    audit: [
      {
        action: 'PGP_ADDED',
        entity: 'PGP',
        entityId: record.id,
        before: existing ? `linked to ${existing.actorIds.join(', ') || 'nobody'}` : 'n/a',
        after: `${shortFingerprint(fingerprint)} linked to ${record.actorIds.join(', ') || 'unattributed'}`,
        source: input.source || 'Analyst',
        result: 'SUCCESS',
        outcome: 'SUCCESS',
      },
    ],
    timeline: actorId
      ? [
          pushTimeline(
            dataset,
            {
              actorId,
              time: firstSeen,
              type: 'PLATFORM_ACTIVITY',
              title: `PGP Key Observed - ${shortFingerprint(fingerprint)}`,
              description: `PGP fingerprint ${fingerprint} published by ${actorId}${input.platform ? ` on ${input.platform}` : ''}.`,
              confidence,
              source: input.source ?? 'Analyst',
            },
            ctx,
          ),
        ]
      : [],
    observations: actorId
      ? [
          pushObservation(
            dataset,
            {
              actorId,
              handleId: handleRecord?.id ?? null,
              platform: input.platform ?? null,
              observationType: 'NEW_PLATFORM_ACTIVITY',
              content: `PGP fingerprint ${shortFingerprint(fingerprint)} published by ${actorId}.`,
              timestamp: firstSeen,
              source: input.source || 'Analyst',
              confidence,
              tags: ['pgp', 'cryptographic-identity'],
            },
            ctx,
          ),
        ]
      : [],
    alerts:
      record.actorIds.length > 1
        ? [
            pushAlert(
              dataset,
              {
                type: 'HIGH_CONFIDENCE_CORRELATION',
                severity: 'HIGH',
                title: `PGP Correlation - ${record.actorIds.length} actors`,
                actorId: record.actorIds[0] ?? null,
                reason: `PGP key ${shortFingerprint(fingerprint)} links ${record.actorIds.join(' and ')}.`,
                confidence,
                entityType: 'PGP',
                entityId: record.id,
              },
              ctx,
            ),
          ]
        : [],
    relationships,
  };

  updateDataset(draft => ({
    ...draft,
    pgpKeys: existing ? draft.pgpKeys.map(key => (key.id === existing.id ? record : key)) : [...draft.pgpKeys, record],
  }));
  return commit(record, duplicates, writes, { actorUpdates });
}

// ── Wallet indicator ──────────────────────────────────────────
export interface WalletInput {
  address: string;
  network?: string;
  actorId?: string;
  handle?: string;
  source?: string;
  firstSeen?: string;
  lastSeen?: string;
  confidence?: number;
  notes?: string;
}

export function addWallet(input: WalletInput): MutationResult<WalletRecord> {
  const dataset = getDataset();
  const now = new Date().toISOString();
  const ctx: Context = createContext(now, 'ANALYST_ADDED');

  const address = normalizeWallet(input.address);
  const duplicates = findDuplicates(dataset, 'WALLET', address);
  const confidence = normalizeConfidence(input.confidence, 75);
  const firstSeen = normalizeTimestamp(input.firstSeen, now);
  const lastSeen = normalizeTimestamp(input.lastSeen, now);
  const handleValue = input.handle ? normalizeHandle(input.handle) : null;
  const handleRecord = handleValue
    ? (dataset.handles.find(item => normalizeHandle(item.normalized || item.value) === handleValue) ?? null)
    : null;
  const actorId = input.actorId ? normalizeActorRef(input.actorId) : (handleRecord?.actorId ?? null);

  const existing = dataset.wallets.find(wallet => normalizeWallet(wallet.address) === address);
  const record: WalletRecord = existing
    ? {
        ...existing,
        actorIds: actorId && !existing.actorIds.includes(actorId) ? [...existing.actorIds, actorId] : existing.actorIds,
        firstSeen: firstSeen < existing.firstSeen ? firstSeen : existing.firstSeen,
        lastSeen: lastSeen > existing.lastSeen ? lastSeen : existing.lastSeen,
        confidence: Math.max(existing.confidence, confidence),
        notes: input.notes ?? existing.notes ?? '',
      }
    : {
        id: allocId(ctx.alloc, 'WAL', dataset.wallets.map(wallet => wallet.id)),
        address,
        actorIds: actorId ? [actorId] : [],
        observedSources: input.source ? [input.source] : [],
        firstSeen,
        lastSeen,
        txCount: 0,
        confidence,
        network: input.network || 'Bitcoin (synthetic)',
        handleIds: handleRecord ? [handleRecord.id] : [],
        dataState: 'ANALYST_ADDED',
        analyst: ANALYST,
        notes: input.notes ?? '',
      };

  const relationships: RelationshipRecord[] = [];
  const actorUpdates: ActorRecord[] = [];

  if (actorId) {
    const actor = dataset.lookups.actorsById[actorId];
    if (actor && !actor.walletAddrs.includes(address)) {
      actorUpdates.push({ ...actor, walletAddrs: [...actor.walletAddrs, address] });
    }
    for (const otherId of record.actorIds.filter(value => value !== actorId)) {
      const other = dataset.lookups.actorsById[otherId];
      if (!other) continue;
      if (!other.walletAddrs.includes(address)) {
        actorUpdates.push({ ...other, walletAddrs: [...other.walletAddrs, address] });
      }
      const ordered = [actorId, otherId].sort();
      const { record: rel } = pushRelationship(
        dataset,
        {
          sourceEntity: ordered[0],
          targetEntity: ordered[1],
          sourceType: 'Actor',
          targetType: 'Actor',
          type: 'SHARED_WALLET',
          confidence,
          explanation: `${actorId} and ${otherId} reference the same wallet address.`,
          supporting: ['Identical wallet address', 'Co-observed in the same collection window'],
          against: ['Wallets can be custodial or deliberately shared'],
        },
        ctx,
      );
      relationships.push(rel);
    }
  }

  const writes: DraftWrites = {
    audit: [
      {
        action: 'WALLET_ADDED',
        entity: 'Wallet',
        entityId: record.id,
        before: existing ? `linked to ${existing.actorIds.join(', ') || 'nobody'}` : 'n/a',
        after: `${address.slice(0, 14)}... linked to ${record.actorIds.join(', ') || 'unattributed'}`,
        source: input.source || 'Analyst',
        result: 'SUCCESS',
        outcome: 'SUCCESS',
      },
    ],
    timeline: actorId
      ? [
          pushTimeline(
            dataset,
            {
              actorId,
              time: firstSeen,
              type: 'PLATFORM_ACTIVITY',
              title: 'Wallet Indicator Observed',
              description: `Wallet ${address.slice(0, 16)}... linked to ${actorId} (${record.network}).`,
              confidence,
              source: input.source ?? 'Analyst',
            },
            ctx,
          ),
        ]
      : [],
    alerts:
      record.actorIds.length > 1
        ? [
            pushAlert(
              dataset,
              {
                type: 'HIGH_CONFIDENCE_CORRELATION',
                severity: 'HIGH',
                title: `Shared Wallet - ${record.actorIds.length} actors`,
                actorId: record.actorIds[0] ?? null,
                reason: `Wallet ${address.slice(0, 14)}... is used by ${record.actorIds.join(' and ')}.`,
                confidence,
                entityType: 'WALLET',
                entityId: record.id,
              },
              ctx,
            ),
          ]
        : [],
    relationships,
  };

  updateDataset(draft => ({
    ...draft,
    wallets: existing ? draft.wallets.map(wallet => (wallet.id === existing.id ? record : wallet)) : [...draft.wallets, record],
  }));
  return commit(record, duplicates, writes, { actorUpdates });
}

// ── Infrastructure ────────────────────────────────────────────
export interface InfrastructureInput {
  type?: 'DOMAIN' | 'IP' | 'HOSTING' | 'TLS' | 'NAMESERVER';
  value: string;
  actorId?: string;
  source?: string;
  registrar?: string;
  hostingProvider?: string;
  asn?: string;
  country?: string;
  tlsIssuer?: string;
  nameserver?: string;
  firstSeen?: string;
  lastSeen?: string;
  confidence?: number;
  notes?: string;
}

function looksLikeIp(value: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(value) || value.includes(':');
}

export function addInfrastructure(input: InfrastructureInput): MutationResult<InfrastructureRecord> {
  const dataset = getDataset();
  const now = new Date().toISOString();
  const ctx: Context = createContext(now, 'ANALYST_ADDED');

  const value = normalizeDomain(input.value);
  const duplicates = findDuplicates(dataset, 'INFRASTRUCTURE', value);
  const actorId = input.actorId ? normalizeActorRef(input.actorId) : null;
  const confidence = normalizeConfidence(input.confidence, 80);
  const firstSeen = normalizeTimestamp(input.firstSeen, now);
  const lastSeen = normalizeTimestamp(input.lastSeen, now);
  const type = input.type ?? (looksLikeIp(value) ? 'IP' : 'DOMAIN');

  const existing = dataset.infrastructure.find(item => normalizeDomain(item.value) === value);
  const record: InfrastructureRecord = existing
    ? {
        ...existing,
        actorIds: actorId && !existing.actorIds.includes(actorId) ? [...existing.actorIds, actorId] : existing.actorIds,
        firstSeen: firstSeen < existing.firstSeen ? firstSeen : existing.firstSeen,
        lastSeen: lastSeen > existing.lastSeen ? lastSeen : existing.lastSeen,
        notes: input.notes ?? existing.notes ?? '',
      }
    : {
        id: allocId(ctx.alloc, 'INF', dataset.infrastructure.map(item => item.id)),
        type,
        value,
        actorIds: actorId ? [actorId] : [],
        firstSeen,
        lastSeen,
        registrar: input.registrar,
        hostingProvider: input.hostingProvider,
        asn: input.asn,
        country: input.country,
        tlsIssuer: input.tlsIssuer,
        dataState: 'ANALYST_ADDED',
        analyst: ANALYST,
        source: input.source,
        nameserver: input.nameserver,
        notes: input.notes ?? '',
      };

  const relationships: RelationshipRecord[] = [];
  const actorUpdates: ActorRecord[] = [];

  if (actorId) {
    const actor = dataset.lookups.actorsById[actorId];
    if (actor && type === 'DOMAIN' && !actor.domains.includes(value)) {
      actorUpdates.push({ ...actor, domains: [...actor.domains, value] });
    }
    for (const otherId of record.actorIds.filter(item => item !== actorId)) {
      const other = dataset.lookups.actorsById[otherId];
      if (!other) continue;
      if (type === 'DOMAIN' && !other.domains.includes(value)) {
        actorUpdates.push({ ...other, domains: [...other.domains, value] });
      }
      const ordered = [actorId, otherId].sort();
      const { record: rel } = pushRelationship(
        dataset,
        {
          sourceEntity: ordered[0],
          targetEntity: ordered[1],
          sourceType: 'Actor',
          targetType: 'Actor',
          type: 'SHARED_INFRASTRUCTURE',
          confidence,
          explanation: `${actorId} and ${otherId} both use ${type} ${value}.`,
          supporting: ['Shared infrastructure indicator', `Observed since ${firstSeen.slice(0, 10)}`],
          against: ['Shared infrastructure can be coincidental or relayed'],
        },
        ctx,
      );
      relationships.push(rel);
    }
  }

  const writes: DraftWrites = {
    audit: [
      {
        action: 'INFRASTRUCTURE_ADDED',
        entity: 'Infrastructure',
        entityId: record.id,
        before: existing ? `shared by ${existing.actorIds.join(', ') || 'nobody'}` : 'n/a',
        after: `${type} ${value} linked to ${record.actorIds.join(', ') || 'unattributed'}`,
        source: input.source || 'Analyst',
        result: 'SUCCESS',
        outcome: 'SUCCESS',
      },
    ],
    timeline: actorId
      ? [
          pushTimeline(
            dataset,
            {
              actorId,
              time: firstSeen,
              type: 'INFRASTRUCTURE_CHANGE',
              title: `New ${type} Observed`,
              description: `${type} ${value} associated with ${actorId}${input.hostingProvider ? ` (host: ${input.hostingProvider})` : ''}.`,
              confidence,
              source: input.source ?? 'Analyst',
            },
            ctx,
          ),
        ]
      : [],
    observations: actorId
      ? [
          pushObservation(
            dataset,
            {
              actorId,
              observationType: 'INFRASTRUCTURE_CHANGE',
              content: `${type} ${value} associated with ${actorId}.`,
              timestamp: firstSeen,
              source: input.source || 'Analyst',
              confidence,
              tags: ['infrastructure', type.toLowerCase()],
            },
            ctx,
          ),
        ]
      : [],
    alerts: [
      pushAlert(
        dataset,
        {
          type: 'INFRASTRUCTURE_CHANGE',
          severity: record.actorIds.length > 1 ? 'HIGH' : 'MEDIUM',
          title: `Infrastructure ${existing ? 'Update' : 'Discovered'} - ${value}`,
          actorId: record.actorIds[0] ?? null,
          reason: `${type} ${value} is now attributed to ${record.actorIds.join(', ') || 'no actor'}.`,
          confidence,
          entityType: 'INFRASTRUCTURE',
          entityId: record.id,
        },
        ctx,
      ),
    ],
    relationships,
  };

  updateDataset(draft => ({
    ...draft,
    infrastructure: existing
      ? draft.infrastructure.map(item => (item.id === existing.id ? record : item))
      : [...draft.infrastructure, record],
  }));
  return commit(record, duplicates, writes, { actorUpdates });
}

// ── Source ────────────────────────────────────────────────────
export type IntelligenceSourceType = IntelligenceDataset['sources'][number]['type'];

export interface SourceInput {
  name: string;
  type: IntelligenceSourceType;
  reference?: string;
  reliability?: number;
  collectionMethod?: string;
  status?: 'ACTIVE' | 'DORMANT' | 'SUSPENDED';
  firstSeen?: string;
  lastSeen?: string;
  notes?: string;
}

export function addSource(input: SourceInput): MutationResult<SourceRecord> {
  const dataset = getDataset();
  const now = new Date().toISOString();
  const ctx: Context = createContext(now, 'ANALYST_ADDED');

  const name = normalizeSourceName(input.name);
  const duplicates = findDuplicates(dataset, 'SOURCE', name);
  const reliability = normalizeReliability(input.reliability, 70);

  const record: SourceRecord = {
    id: allocId(ctx.alloc, 'SRC', dataset.sources.map(source => source.id)),
    name,
    type: input.type,
    firstObserved: normalizeTimestamp(input.firstSeen, now),
    lastObserved: normalizeTimestamp(input.lastSeen, now),
    reliabilityScore: reliability,
    activityLevel: 'MEDIUM',
    status: input.status ?? 'ACTIVE',
    actorCount: 0,
    indicatorCount: 0,
    collectionTimestamp: now,
    description: input.notes ?? 'Lawful / synthetic collection source registered by the analyst.',
    onionAddress: input.reference,
    isSynthetic: false,
    dataState: 'ANALYST_ADDED',
    analyst: ANALYST,
    reference: input.reference,
    collectionMethod: input.collectionMethod ?? 'LAWFUL_SIMULATED',
    notes: input.notes ?? '',
  };

  const writes: DraftWrites = {
    audit: [
      {
        action: 'SOURCE_ADDED',
        entity: 'Source',
        entityId: record.id,
        before: 'n/a',
        after: `${name} (${input.type}) reliability R${reliability}`,
        source: input.collectionMethod ?? 'LAWFUL_SIMULATED',
        result: 'SUCCESS',
        outcome: 'SUCCESS',
      },
    ],
  };

  updateDataset(draft => ({ ...draft, sources: [...draft.sources, record] }));
  return commit(record, duplicates, writes);
}

// ── Observation ───────────────────────────────────────────────
export interface ObservationInput {
  actorId?: string;
  handle?: string;
  platform?: string;
  observationType?: Observation['observationType'];
  content: string;
  timestamp?: string;
  source?: string;
  confidence?: number;
  tags?: string[];
  notes?: string;
}

function timelineTypeFor(type: Observation['observationType']): TimelineRecord['type'] {
  switch (type) {
    case 'HANDLE_OBSERVED':
      return 'HANDLE_CHANGE';
    case 'INFRASTRUCTURE_CHANGE':
      return 'INFRASTRUCTURE_CHANGE';
    case 'PERSONA_CHANGE':
      return 'PERSONA_MIGRATION';
    case 'RELATIONSHIP_DISCOVERED':
      return 'RELATIONSHIP_FORMATION';
    case 'NEW_EVIDENCE':
      return 'EVIDENCE_COLLECTION';
    default:
      return 'PLATFORM_ACTIVITY';
  }
}

function observationTitle(type: Observation['observationType'], content: string): string {
  const titles: Record<Observation['observationType'], string> = {
    HANDLE_OBSERVED: 'Handle Observed',
    NEW_PLATFORM_ACTIVITY: 'New Platform Activity',
    INFRASTRUCTURE_CHANGE: 'Infrastructure Change',
    PERSONA_CHANGE: 'Persona Change Detected',
    RELATIONSHIP_DISCOVERED: 'Relationship Discovered',
    NEW_EVIDENCE: 'New Evidence Recorded',
    BEHAVIOR_ANOMALY: 'Behaviour Anomaly',
  };
  return titles[type] ?? content.slice(0, 40);
}

export function addObservation(input: ObservationInput): MutationResult<Observation> {
  const dataset = getDataset();
  const now = new Date().toISOString();
  const ctx: Context = createContext(now, 'ANALYST_ADDED');

  const actorId = input.actorId ? normalizeActorRef(input.actorId) : null;
  const handleValue = input.handle ? normalizeHandle(input.handle) : null;
  const handleRecord = handleValue
    ? (dataset.handles.find(item => normalizeHandle(item.normalized || item.value) === handleValue) ?? null)
    : null;
  const resolvedActorId = actorId ?? handleRecord?.actorId ?? null;
  const confidence = normalizeConfidence(input.confidence, 70);
  const timestamp = normalizeTimestamp(input.timestamp, now);
  const type = input.observationType ?? 'NEW_PLATFORM_ACTIVITY';

  const record = pushObservation(
    dataset,
    {
      actorId: resolvedActorId,
      handleId: handleRecord?.id ?? null,
      platform: input.platform ?? handleRecord?.platform ?? null,
      observationType: type,
      content: normalizeText(input.content),
      timestamp,
      source: input.source || 'Analyst',
      confidence,
      tags: input.tags ?? [],
      notes: input.notes ?? '',
    },
    ctx,
  );

  const writes: DraftWrites = {
    audit: [
      {
        action: 'OBSERVATION_ADDED',
        entity: 'Observation',
        entityId: record.id,
        before: 'n/a',
        after: `${type.replace(/_/g, ' ').toLowerCase()}: ${record.content.slice(0, 120)}`,
        source: input.source || 'Analyst',
        result: 'SUCCESS',
        outcome: 'SUCCESS',
      },
    ],
    observations: [record],
    timeline: resolvedActorId
      ? [
          pushTimeline(
            dataset,
            {
              actorId: resolvedActorId,
              time: timestamp,
              type: timelineTypeFor(type),
              title: observationTitle(type, record.content),
              description: record.content,
              confidence,
              source: input.source ?? 'Analyst',
            },
            ctx,
          ),
        ]
      : [],
    alerts:
      type === 'BEHAVIOR_ANOMALY'
        ? [
            pushAlert(
              dataset,
              {
                type: 'ANOMALY_DETECTED',
                severity: 'MEDIUM',
                title: `Behaviour Anomaly - ${resolvedActorId ?? 'Unknown'}`,
                actorId: resolvedActorId,
                reason: record.content.slice(0, 200),
                confidence,
                entityType: 'OBSERVATION',
                entityId: record.id,
              },
              ctx,
            ),
          ]
        : [],
  };

  updateDataset(draft => ({ ...draft, observations: [...draft.observations, record] }));
  return commit(record, [], writes, { persisted: { observations: [record] } });
}

// ── Evidence ──────────────────────────────────────────────────
export interface EvidenceInput {
  id?: string;
  evidenceType: EvidenceRecord['evidenceType'];
  source: string;
  relatedActor?: string;
  relatedHandle?: string;
  relatedInfrastructure?: string;
  relatedRelationship?: string;
  timestamp?: string;
  collectionTimestamp?: string;
  description?: string;
  reliability?: number;
  confidence?: number;
  hash?: string;
  notes?: string;
}

function pseudoHash(seed: string): string {
  let hash = 0;
  for (let index = 0; index < seed.length; index++) {
    hash = (hash * 31 + seed.charCodeAt(index)) >>> 0;
  }
  const block = (offset: number) => hash.toString(16).padStart(8, '0').slice(0, 6) + String(offset).padStart(2, '0');
  return Array.from({ length: 8 }, (_, index) => block(index)).join('');
}

export function addEvidence(input: EvidenceInput): MutationResult<EvidenceRecord> {
  const dataset = getDataset();
  const now = new Date().toISOString();
  const ctx: Context = createContext(now, 'ANALYST_ADDED');

  const requestedId = normalizeText(input.id ?? '') || allocId(ctx.alloc, 'EVID', dataset.evidence.map(item => item.id));
  const duplicates = dataset.evidence
    .filter(item => item.id === requestedId)
    .map(item => ({
      kind: 'EXACT' as const,
      entityType: 'ACTOR' as const,
      existingId: item.id,
      existingLabel: `${item.id} - ${item.evidenceType}`,
      score: 100,
      detail: 'An evidence item with this ID already exists',
    }));

  const actorId = input.relatedActor ? normalizeActorRef(input.relatedActor) : null;
  const handleValue = input.relatedHandle ? normalizeHandle(input.relatedHandle) : null;
  const handleRecord = handleValue
    ? (dataset.handles.find(item => normalizeHandle(item.normalized || item.value) === handleValue) ?? null)
    : null;
  const infraValue = input.relatedInfrastructure ? normalizeDomain(input.relatedInfrastructure) : null;
  const infraRecord = infraValue
    ? (dataset.infrastructure.find(item => normalizeDomain(item.value) === infraValue) ?? null)
    : null;
  const resolvedActorId = actorId ?? handleRecord?.actorId ?? infraRecord?.actorIds[0] ?? null;
  const confidence = normalizeConfidence(input.confidence, 75);
  const reliability = normalizeReliability(input.reliability, 80);
  const timestamp = normalizeTimestamp(input.timestamp, now);
  const sourceRecord = dataset.sources.find(source => source.name === input.source || source.id === input.source);

  const record: EvidenceRecord = {
    id: requestedId,
    source: input.source,
    sourceType: sourceRecord?.type ?? 'FORUM',
    timestamp,
    collectionTimestamp: normalizeTimestamp(input.collectionTimestamp, now),
    hash: input.hash || `sha256:${pseudoHash(`${requestedId}|${timestamp}`)}`,
    relatedActor: resolvedActorId,
    relatedRelationship: input.relatedRelationship ?? null,
    evidenceType: input.evidenceType,
    reliability,
    confidence,
    provenance: input.description || `${input.evidenceType.replace(/_/g, ' ')} collected from ${input.source}`,
    isSynthetic: false,
    dataState: 'ANALYST_ADDED',
    analyst: ANALYST,
    relatedHandle: handleValue,
    relatedInfrastructure: infraValue,
    description: input.description ?? '',
    notes: input.notes ?? '',
  };

  const relationships: RelationshipRecord[] = [];
  const actorUpdates: ActorRecord[] = [];

  // Evidence <-> Actor
  if (resolvedActorId) {
    const actor = dataset.lookups.actorsById[resolvedActorId];
    if (actor && !actor.associatedEvidence.includes(record.id)) {
      actorUpdates.push({ ...actor, associatedEvidence: [...actor.associatedEvidence, record.id] });
    }
    const { record: rel } = pushRelationship(
      dataset,
      {
        sourceEntity: record.id,
        targetEntity: resolvedActorId,
        sourceType: 'Evidence',
        targetType: 'Actor',
        type: 'EVIDENCE_LINKED',
        confidence: reliability,
        explanation: `${record.id} (${record.evidenceType}) supports attribution for ${resolvedActorId}.`,
        supporting: [`Provenance: ${record.provenance}`, `Source reliability R${reliability}`],
        against: [],
        evidenceIds: [record.id],
      },
      ctx,
    );
    relationships.push(rel);
  }

  // Evidence <-> Source
  if (sourceRecord) {
    const { record: rel } = pushRelationship(
      dataset,
      {
        sourceEntity: sourceRecord.id,
        targetEntity: record.id,
        sourceType: 'Source',
        targetType: 'Evidence',
        type: 'OBSERVED_AT_SOURCE',
        confidence: reliability,
        explanation: `${record.id} was collected from ${sourceRecord.name} (${sourceRecord.type}).`,
        supporting: [`Collection timestamp ${record.collectionTimestamp}`],
      },
      ctx,
    );
    relationships.push(rel);
  }

  const writes: DraftWrites = {
    audit: [
      {
        action: 'EVIDENCE_ADDED',
        entity: 'Evidence',
        entityId: record.id,
        before: 'n/a',
        after: `${record.evidenceType} from ${record.source}${resolvedActorId ? ` linked to ${resolvedActorId}` : ''}`,
        source: record.source,
        result: 'SUCCESS',
        outcome: 'SUCCESS',
      },
    ],
    timeline: resolvedActorId
      ? [
          pushTimeline(
            dataset,
            {
              actorId: resolvedActorId,
              time: timestamp,
              type: 'EVIDENCE_COLLECTION',
              title: 'Evidence Collected',
              description: `${record.id} - ${record.provenance}`,
              confidence,
              source: record.source,
              evidenceIds: [record.id],
            },
            ctx,
          ),
        ]
      : [],
    observations: resolvedActorId
      ? [
          pushObservation(
            dataset,
            {
              actorId: resolvedActorId,
              handleId: handleRecord?.id ?? null,
              platform: handleRecord?.platform ?? null,
              observationType: 'NEW_EVIDENCE',
              content: `Evidence ${record.id} collected from ${record.source}.`,
              timestamp,
              source: record.source,
              confidence,
              tags: ['evidence', record.evidenceType.toLowerCase()],
              evidenceIds: [record.id],
            },
            ctx,
          ),
        ]
      : [],
    relationships,
  };

  updateDataset(draft => ({ ...draft, evidence: [...draft.evidence, record] }));
  return commit(record, duplicates, writes, { actorUpdates });
}

// ── Relationship ──────────────────────────────────────────────
export interface RelationshipInput {
  sourceEntity: string;
  targetEntity: string;
  type: RelationshipRecord['type'];
  confidence?: number;
  explanation?: string;
  evidenceIds?: string[];
}

export function entityTypeOf(dataset: IntelligenceDataset, entityId: string): string {
  if (dataset.lookups.actorsById[entityId]) return 'Actor';
  const handle = dataset.handles.find(
    item => item.id === entityId || normalizeHandle(item.normalized || item.value) === normalizeHandle(entityId),
  );
  if (handle) return 'Handle';
  if (dataset.pgpKeys.some(item => item.id === entityId || normalizePgp(item.fingerprint) === normalizePgp(entityId))) return 'PGP';
  if (dataset.wallets.some(item => item.id === entityId || item.address === entityId)) return 'Wallet';
  if (dataset.infrastructure.some(item => item.id === entityId || item.value === entityId)) return 'Infrastructure';
  if (dataset.evidence.some(item => item.id === entityId)) return 'Evidence';
  if (dataset.sources.some(item => item.id === entityId || item.name === entityId)) return 'Source';
  return 'Actor';
}

export function addRelationship(input: RelationshipInput): MutationResult<RelationshipRecord> {
  const dataset = getDataset();
  const now = new Date().toISOString();
  const ctx: Context = createContext(now, 'AI_DERIVED');

  const sourceEntity = normalizeText(input.sourceEntity);
  const targetEntity = normalizeText(input.targetEntity);
  const confidence = normalizeConfidence(input.confidence, 70);
  const { record, isNew } = pushRelationship(
    dataset,
    {
      sourceEntity,
      targetEntity,
      sourceType: entityTypeOf(dataset, sourceEntity),
      targetType: entityTypeOf(dataset, targetEntity),
      type: input.type,
      confidence,
      explanation:
        input.explanation ??
        `Analyst-established ${input.type.replace(/_/g, ' ').toLowerCase()} between ${sourceEntity} and ${targetEntity}.`,
      evidenceIds: input.evidenceIds ?? [],
    },
    ctx,
  );

  if (!isNew) return emptyResult(record);

  const actorId = dataset.lookups.actorsById[sourceEntity]?.id ?? dataset.lookups.actorsById[targetEntity]?.id ?? null;

  // Keep each actor's related-actor list consistent with the stored relationship.
  const actorUpdates: ActorRecord[] = [];
  const sourceActor = dataset.lookups.actorsById[sourceEntity];
  const targetActor = dataset.lookups.actorsById[targetEntity];
  if (sourceActor && targetActor && sourceActor.id !== targetActor.id) {
    if (!sourceActor.relatedActorIds.includes(targetActor.id)) {
      actorUpdates.push({ ...sourceActor, relatedActorIds: [...sourceActor.relatedActorIds, targetActor.id] });
    }
    if (!targetActor.relatedActorIds.includes(sourceActor.id)) {
      actorUpdates.push({ ...targetActor, relatedActorIds: [...targetActor.relatedActorIds, sourceActor.id] });
    }
  }

  const writes: DraftWrites = {
    audit: [
      {
        action: 'RELATIONSHIP_CREATED',
        entity: 'Relationship',
        entityId: record.id,
        before: 'n/a',
        after: `${record.sourceEntity} <-> ${record.targetEntity} (${record.type}, ${confidence}%)`,
        source: 'Correlation engine',
        result: 'SUCCESS',
        outcome: 'SUCCESS',
      },
    ],
    relationships: [record],
    timeline: actorId
      ? [
          pushTimeline(
            dataset,
            {
              actorId,
              time: now,
              type: 'RELATIONSHIP_FORMATION',
              title: 'Relationship Established',
              description: record.explanation,
              confidence,
              source: 'Correlation engine',
              evidenceIds: record.evidenceIds,
            },
            ctx,
          ),
        ]
      : [],
    observations: actorId
      ? [
          pushObservation(
            dataset,
            {
              actorId,
              observationType: 'RELATIONSHIP_DISCOVERED',
              content: record.explanation,
              timestamp: now,
              source: 'Correlation engine',
              confidence,
              tags: ['relationship', record.type.toLowerCase()],
              evidenceIds: record.evidenceIds,
            },
            ctx,
          ),
        ]
      : [],
    alerts:
      confidence >= 80
        ? [
            pushAlert(
              dataset,
              {
                type: input.type === 'PERSONA_MIGRATION' ? 'PERSONA_MIGRATION' : 'RELATIONSHIP_CHANGE',
                severity: 'HIGH',
                title: `${input.type.replace(/_/g, ' ')} - ${sourceEntity} to ${targetEntity}`,
                actorId,
                reason: record.explanation,
                confidence,
                entityType: 'RELATIONSHIP',
                entityId: record.id,
                evidenceIds: record.evidenceIds,
              },
              ctx,
            ),
          ]
        : [],
  };

  updateDataset(draft => ({ ...draft, relationships: [...draft.relationships, record] }));
  return commit(record, [], writes, { actorUpdates, persisted: { relationships: [record] } });
}

// ── Timeline event (analyst-authored) ─────────────────────────
export interface TimelineInput {
  actorId: string;
  type?: TimelineRecord['type'];
  title: string;
  description?: string;
  time?: string;
  confidence?: number;
  source?: string;
}

export function addTimelineEvent(input: TimelineInput): MutationResult<TimelineRecord> {
  const dataset = getDataset();
  const now = new Date().toISOString();
  const ctx: Context = createContext(now, 'ANALYST_ADDED');
  const confidence = normalizeConfidence(input.confidence, 70);

  const record = pushTimeline(
    dataset,
    {
      actorId: normalizeActorRef(input.actorId),
      time: normalizeTimestamp(input.time, now),
      type: input.type ?? 'PLATFORM_ACTIVITY',
      title: normalizeText(input.title),
      description: input.description ?? '',
      confidence,
      source: input.source ?? 'Analyst',
    },
    ctx,
  );

  const writes: DraftWrites = {
    audit: [
      {
        action: 'TIMELINE_EVENT_ADDED',
        entity: 'Timeline',
        entityId: record.id,
        before: 'n/a',
        after: `${record.title} at ${record.time}`,
        source: record.source ?? 'Analyst',
        result: 'SUCCESS',
        outcome: 'SUCCESS',
      },
    ],
    timeline: [record],
  };

  updateDataset(draft => ({ ...draft, timeline: [...draft.timeline, record] }));
  return commit(record, [], writes, { persisted: { timeline: [record] } });
}

// ── MITRE ATT&CK Mutations ─────────────────────────────────────────────

export interface MitreTtpInput {
  techniqueId: string;
  name: string;
  description: string;
  tactic: MitreTactic;
  subTechniqueId?: string;
  subTechnique?: string;
  platforms: MitrePlatform[];
  permissionsRequired: MitrePermission[];
  dataSources: MitreDataSource[];
  actorIds?: string[];
  infrastructureIds?: string[];
  handleIds?: string[];
  evidenceIds?: string[];
  confidence?: number;
  firstSeen?: string;
  lastSeen?: string;
  references?: string[];
  notes?: string;
}

export function addMitreTtp(input: MitreTtpInput): MutationResult<MitreTtpRecord> {
  const dataset = getDataset();
  const now = new Date().toISOString();
  const ctx: Context = createContext(now, 'ANALYST_ADDED');

  const techniqueId = normalizeText(input.techniqueId).toUpperCase();
  const duplicates = findDuplicates(dataset, 'MITRE_TTP', techniqueId);
  const confidence = normalizeConfidence(input.confidence, 75);
  const firstSeen = normalizeTimestamp(input.firstSeen, now);
  const lastSeen = normalizeTimestamp(input.lastSeen, now);

  const existing = dataset.mitreTtps.find(ttp => ttp.techniqueId === techniqueId);
  const record: MitreTtpRecord = existing
    ? {
        ...existing,
        actorIds: input.actorIds ? [...new Set([...existing.actorIds, ...input.actorIds.map(normalizeActorRef)])] : existing.actorIds,
        infrastructureIds: input.infrastructureIds ? [...new Set([...existing.infrastructureIds, ...input.infrastructureIds])] : existing.infrastructureIds,
        handleIds: input.handleIds ? [...new Set([...existing.handleIds, ...input.handleIds])] : existing.handleIds,
        evidenceIds: input.evidenceIds ? [...new Set([...existing.evidenceIds, ...input.evidenceIds])] : existing.evidenceIds,
        firstSeen: firstSeen < existing.firstSeen ? firstSeen : existing.firstSeen,
        lastSeen: lastSeen > existing.lastSeen ? lastSeen : existing.lastSeen,
        confidence: Math.max(existing.confidence, confidence),
        notes: input.notes ?? existing.notes ?? '',
      }
    : {
        id: allocId(ctx.alloc, 'MITRE', dataset.mitreTtps.map(ttp => ttp.id)),
        techniqueId,
        name: normalizeText(input.name),
        description: normalizeText(input.description),
        tactic: input.tactic,
        subTechniqueId: input.subTechniqueId ? normalizeText(input.subTechniqueId) : undefined,
        subTechnique: input.subTechnique ? normalizeText(input.subTechnique) : undefined,
        platforms: input.platforms,
        permissionsRequired: input.permissionsRequired,
        dataSources: input.dataSources,
        actorIds: input.actorIds ? input.actorIds.map(normalizeActorRef) : [],
        infrastructureIds: input.infrastructureIds ?? [],
        handleIds: input.handleIds ?? [],
        evidenceIds: input.evidenceIds ?? [],
        confidence,
        firstSeen,
        lastSeen,
        references: input.references ?? [],
        dataState: 'ANALYST_ADDED',
        analyst: ANALYST,
        notes: input.notes ?? '',
      };

  const relationships: RelationshipRecord[] = [];
  const actorUpdates: ActorRecord[] = [];

  // Create relationships between actors and this TTP
  if (input.actorIds) {
    for (const actorId of input.actorIds) {
      const { record: rel } = pushRelationship(
        dataset,
        {
          sourceEntity: actorId,
          targetEntity: record.id,
          sourceType: 'Actor',
          targetType: 'MitreTtp',
          type: 'USES_TTP',
          confidence,
          explanation: `${actorId} is known to use MITRE ATT&CK technique ${record.techniqueId} (${record.name}).`,
          supporting: [`First observed ${firstSeen.slice(0, 10)}`],
          evidenceIds: input.evidenceIds ?? [],
        },
        ctx,
      );
      relationships.push(rel);
    }
  }

  // Create relationships between infrastructure and this TTP
  if (input.infrastructureIds) {
    for (const infraId of input.infrastructureIds) {
      const { record: rel } = pushRelationship(
        dataset,
        {
          sourceEntity: infraId,
          targetEntity: record.id,
          sourceType: 'Infrastructure',
          targetType: 'MitreTtp',
          type: 'ASSOCIATED_WITH_TTP',
          confidence,
          explanation: `Infrastructure ${infraId} is associated with MITRE ATT&CK technique ${record.techniqueId} (${record.name}).`,
          supporting: [`First observed ${firstSeen.slice(0, 10)}`],
          evidenceIds: input.evidenceIds ?? [],
        },
        ctx,
      );
      relationships.push(rel);
    }
  }

  // Create relationships between handles and this TTP
  if (input.handleIds) {
    for (const handleId of input.handleIds) {
      const { record: rel } = pushRelationship(
        dataset,
        {
          sourceEntity: handleId,
          targetEntity: record.id,
          sourceType: 'Handle',
          targetType: 'MitreTtp',
          type: 'ASSOCIATED_WITH_TTP',
          confidence,
          explanation: `Handle ${handleId} is associated with MITRE ATT&CK technique ${record.techniqueId} (${record.name}).`,
          supporting: [`First observed ${firstSeen.slice(0, 10)}`],
          evidenceIds: input.evidenceIds ?? [],
        },
        ctx,
      );
      relationships.push(rel);
    }
  }

  const writes: DraftWrites = {
    audit: [
      {
        action: 'MITRE_TTP_ADDED',
        entity: 'MitreTtp',
        entityId: record.id,
        before: existing ? `linked to ${existing.actorIds.join(', ') || 'no actors'}` : 'n/a',
        after: `${record.techniqueId} linked to ${record.actorIds.join(', ') || 'no actors'}`,
        source: 'Analyst',
        result: 'SUCCESS',
        outcome: 'SUCCESS',
      },
    ],
    timeline: input.actorIds
      ? input.actorIds.map(actorId =>
          pushTimeline(
            dataset,
            {
              actorId,
              time: firstSeen,
              type: 'PLATFORM_ACTIVITY',
              title: `MITRE ATT&CK Technique Observed - ${record.techniqueId}`,
              description: `Actor ${actorId} is known to use MITRE ATT&CK technique ${record.techniqueId} (${record.name}).`,
              confidence,
              source: 'Analyst',
              evidenceIds: input.evidenceIds ?? [],
            },
            ctx,
          )
        )
      : [],
    alerts: input.actorIds && input.actorIds.length > 0
      ? [
          pushAlert(
            dataset,
            {
              type: 'HIGH_CONFIDENCE_CORRELATION',
              severity: 'HIGH',
              title: `MITRE ATT&CK Technique Correlation - ${record.actorIds.length} actors`,
              actorId: input.actorIds[0],
              reason: `MITRE ATT&CK technique ${record.techniqueId} is used by ${record.actorIds.join(' and ')}.`,
              confidence,
              entityType: 'MITRE_TTP',
              entityId: record.id,
              evidenceIds: input.evidenceIds ?? [],
            },
            ctx,
          ),
        ]
      : [],
    relationships,
  };

  updateDataset(draft => ({
    ...draft,
    mitreTtps: existing ? draft.mitreTtps.map(ttp => (ttp.id === existing.id ? record : ttp)) : [...draft.mitreTtps, record],
  }));
  return commit(record, duplicates, writes, { actorUpdates });
}

// ── Link Actor to MITRE TTP ─────────────────────────────────────────────
export function linkActorToMitreTtp(actorId: string, ttpId: string, confidence?: number, evidenceIds?: string[]): MutationResult<RelationshipRecord> {
  const dataset = getDataset();
  const now = new Date().toISOString();
  const ctx: Context = createContext(now, 'ANALYST_ADDED');

  const actor = dataset.lookups.actorsById[actorId];
  const ttp = dataset.lookups.mitreTtpsById[ttpId];

  if (!actor || !ttp) {
    throw new Error('Actor or MITRE TTP not found');
  }

  const { record, isNew } = pushRelationship(
    dataset,
    {
      sourceEntity: actorId,
      targetEntity: ttpId,
      sourceType: 'Actor',
      targetType: 'MitreTtp',
      type: 'USES_TTP',
      confidence: normalizeConfidence(confidence, 75),
      explanation: `${actorId} is known to use MITRE ATT&CK technique ${ttp.techniqueId} (${ttp.name}).`,
      evidenceIds: evidenceIds ?? [],
    },
    ctx,
  );

  if (!isNew) return emptyResult(record);

  const writes: DraftWrites = {
    audit: [
      {
        action: 'RELATIONSHIP_CREATED',
        entity: 'Relationship',
        entityId: record.id,
        before: 'n/a',
        after: `${actorId} <-> ${ttpId} (USES_TTP, ${record.confidence}%)`,
        source: 'Analyst',
        result: 'SUCCESS',
        outcome: 'SUCCESS',
      },
    ],
    relationships: [record],
    timeline: [
      pushTimeline(
        dataset,
        {
          actorId,
          time: now,
          type: 'PLATFORM_ACTIVITY',
          title: `MITRE ATT&CK Technique Observed - ${ttp.techniqueId}`,
          description: `Actor ${actorId} is known to use MITRE ATT&CK technique ${ttp.techniqueId} (${ttp.name}).`,
          confidence: record.confidence,
          source: 'Analyst',
          evidenceIds: evidenceIds ?? [],
        },
        ctx,
      ),
    ],
  };

  updateDataset(draft => ({ ...draft, relationships: [...draft.relationships, record] }));
  return commit(record, [], writes, { persisted: { relationships: [record] } });
}

// ── Vulnerability Mutations ─────────────────────────────────────────────

export interface CveInput {
  cveId: string;
  title: string;
  description: string;
  severity: CveSeverity;
  cvssScore: number;
  cvssVector: string;
  cweIds?: string[];
  cweTypes?: CweType[];
  categories?: VulnerabilityCategory[];
  publishedDate: string;
  lastModifiedDate: string;
  firstSeenInDarkWeb?: string;
  lastSeenInDarkWeb?: string;
  affectedSoftware: string[];
  affectedVersions?: string[];
  actorIds?: string[];
  infrastructureIds?: string[];
  handleIds?: string[];
  evidenceIds?: string[];
  exploitationStatus: ExploitationStatus;
  darkWebSources?: string[];
  references?: string[];
  confidence?: number;
  isSynthetic?: boolean;
  notes?: string;
}

export function addCve(input: CveInput): MutationResult<CveRecordRecord> {
  const dataset = getDataset();
  const now = new Date().toISOString();
  const ctx: Context = createContext(now, 'ANALYST_ADDED');

  const cveId = normalizeText(input.cveId).toUpperCase();
  const duplicates = findDuplicates(dataset, 'CVE', cveId);
  const confidence = normalizeConfidence(input.confidence, 75);
  const firstSeenInDarkWeb = input.firstSeenInDarkWeb ? normalizeTimestamp(input.firstSeenInDarkWeb, now) : undefined;
  const lastSeenInDarkWeb = input.lastSeenInDarkWeb ? normalizeTimestamp(input.lastSeenInDarkWeb, now) : undefined;

  const existing = dataset.cves.find(cve => cve.cveId === cveId);
  const record: CveRecordRecord = existing
    ? {
        ...existing,
        actorIds: input.actorIds ? [...new Set([...existing.actorIds, ...input.actorIds.map(normalizeActorRef)])] : existing.actorIds,
        infrastructureIds: input.infrastructureIds ? [...new Set([...existing.infrastructureIds, ...input.infrastructureIds])] : existing.infrastructureIds,
        handleIds: input.handleIds ? [...new Set([...existing.handleIds, ...input.handleIds])] : existing.handleIds,
        evidenceIds: input.evidenceIds ? [...new Set([...existing.evidenceIds, ...input.evidenceIds])] : existing.evidenceIds,
        firstSeenInDarkWeb: firstSeenInDarkWeb && firstSeenInDarkWeb < (existing.firstSeenInDarkWeb ?? now) ? firstSeenInDarkWeb : existing.firstSeenInDarkWeb,
        lastSeenInDarkWeb: lastSeenInDarkWeb && lastSeenInDarkWeb > (existing.lastSeenInDarkWeb ?? now) ? lastSeenInDarkWeb : existing.lastSeenInDarkWeb,
        confidence: Math.max(existing.confidence, confidence),
        notes: input.notes ?? existing.notes ?? '',
      }
    : {
        id: allocId(ctx.alloc, 'CVE', dataset.cves.map(cve => cve.id)),
        cveId,
        title: normalizeText(input.title),
        description: normalizeText(input.description),
        severity: input.severity,
        cvssScore: input.cvssScore,
        cvssVector: normalizeText(input.cvssVector),
        cweIds: input.cweIds ? input.cweIds.map(normalizeText) : [],
        cweTypes: input.cweTypes ?? [],
        categories: input.categories ?? [],
        publishedDate: normalizeTimestamp(input.publishedDate, now),
        lastModifiedDate: normalizeTimestamp(input.lastModifiedDate, now),
        firstSeenInDarkWeb,
        lastSeenInDarkWeb,
        affectedSoftware: input.affectedSoftware.map(normalizeText),
        affectedVersions: input.affectedVersions ? input.affectedVersions.map(normalizeText) : undefined,
        actorIds: input.actorIds ? input.actorIds.map(normalizeActorRef) : [],
        infrastructureIds: input.infrastructureIds ?? [],
        handleIds: input.handleIds ?? [],
        evidenceIds: input.evidenceIds ?? [],
        exploitationStatus: input.exploitationStatus,
        darkWebSources: input.darkWebSources ? input.darkWebSources.map(normalizeText) : [],
        references: input.references ? input.references.map(normalizeText) : [],
        confidence,
        isSynthetic: input.isSynthetic ?? false,
        dataState: 'ANALYST_ADDED',
        analyst: ANALYST,
        notes: input.notes ?? '',
      };

  const relationships: RelationshipRecord[] = [];
  const actorUpdates: ActorRecord[] = [];

  // Create relationships between actors and this CVE
  if (input.actorIds) {
    for (const actorId of input.actorIds) {
      const { record: rel } = pushRelationship(
        dataset,
        {
          sourceEntity: actorId,
          targetEntity: record.id,
          sourceType: 'Actor',
          targetType: 'Cve',
          type: 'EXPLOITS_CVE',
          confidence,
          explanation: `${actorId} is known to exploit CVE ${record.cveId} (${record.title}).`,
          supporting: [`First observed in dark web ${firstSeenInDarkWeb?.slice(0, 10) ?? 'unknown'}`],
          evidenceIds: input.evidenceIds ?? [],
        },
        ctx,
      );
      relationships.push(rel);
    }
  }

  // Create relationships between infrastructure and this CVE
  if (input.infrastructureIds) {
    for (const infraId of input.infrastructureIds) {
      const { record: rel } = pushRelationship(
        dataset,
        {
          sourceEntity: infraId,
          targetEntity: record.id,
          sourceType: 'Infrastructure',
          targetType: 'Cve',
          type: 'AFFECTED_BY_CVE',
          confidence,
          explanation: `Infrastructure ${infraId} is affected by CVE ${record.cveId} (${record.title}).`,
          supporting: [`First observed in dark web ${firstSeenInDarkWeb?.slice(0, 10) ?? 'unknown'}`],
          evidenceIds: input.evidenceIds ?? [],
        },
        ctx,
      );
      relationships.push(rel);
    }
  }

  // Create relationships between handles and this CVE
  if (input.handleIds) {
    for (const handleId of input.handleIds) {
      const { record: rel } = pushRelationship(
        dataset,
        {
          sourceEntity: handleId,
          targetEntity: record.id,
          sourceType: 'Handle',
          targetType: 'Cve',
          type: 'ASSOCIATED_WITH_CVE',
          confidence,
          explanation: `Handle ${handleId} is associated with CVE ${record.cveId} (${record.title}).`,
          supporting: [`First observed in dark web ${firstSeenInDarkWeb?.slice(0, 10) ?? 'unknown'}`],
          evidenceIds: input.evidenceIds ?? [],
        },
        ctx,
      );
      relationships.push(rel);
    }
  }

  const writes: DraftWrites = {
    audit: [
      {
        action: 'CVE_ADDED',
        entity: 'Cve',
        entityId: record.id,
        before: existing ? `linked to ${existing.actorIds.join(', ') || 'no actors'}` : 'n/a',
        after: `${record.cveId} linked to ${record.actorIds.join(', ') || 'no actors'}`,
        source: 'Analyst',
        result: 'SUCCESS',
        outcome: 'SUCCESS',
      },
    ],
    timeline: input.actorIds
      ? input.actorIds.map(actorId =>
          pushTimeline(
            dataset,
            {
              actorId,
              time: firstSeenInDarkWeb ?? now,
              type: 'PLATFORM_ACTIVITY',
              title: `CVE Exploitation Observed - ${record.cveId}`,
              description: `Actor ${actorId} is known to exploit CVE ${record.cveId} (${record.title}).`,
              confidence,
              source: 'Analyst',
              evidenceIds: input.evidenceIds ?? [],
            },
            ctx,
          )
        )
      : [],
    alerts: input.actorIds && input.actorIds.length > 0 && input.exploitationStatus === 'ACTIVE'
      ? [
          pushAlert(
            dataset,
            {
              type: 'HIGH_CONFIDENCE_CORRELATION',
              severity: 'HIGH',
              title: `CVE Exploitation Correlation - ${record.actorIds.length} actors`,
              actorId: input.actorIds[0],
              reason: `CVE ${record.cveId} is exploited by ${record.actorIds.join(' and ')}.`,
              confidence,
              entityType: 'CVE',
              entityId: record.id,
              evidenceIds: input.evidenceIds ?? [],
            },
            ctx,
          ),
        ]
      : [],
    relationships,
  };

  updateDataset(draft => ({
    ...draft,
    cves: existing ? draft.cves.map(cve => (cve.id === existing.id ? record : cve)) : [...draft.cves, record],
  }));
  return commit(record, duplicates, writes, { actorUpdates });
}

// ── Link CVE to Infrastructure ─────────────────────────────────────────────
export function linkCveToInfrastructure(cveId: string, infrastructureId: string, confidence?: number, evidenceIds?: string[]): MutationResult<RelationshipRecord> {
  const dataset = getDataset();
  const now = new Date().toISOString();
  const ctx: Context = createContext(now, 'ANALYST_ADDED');

  const cve = dataset.lookups.cvesById[cveId];
  const infrastructure = dataset.lookups.infraById[infrastructureId];

  if (!cve || !infrastructure) {
    throw new Error('CVE or Infrastructure not found');
  }

  const { record, isNew } = pushRelationship(
    dataset,
    {
      sourceEntity: infrastructureId,
      targetEntity: cveId,
      sourceType: 'Infrastructure',
      targetType: 'Cve',
      type: 'AFFECTED_BY_CVE',
      confidence: normalizeConfidence(confidence, 75),
      explanation: `Infrastructure ${infrastructureId} is affected by CVE ${cve.cveId} (${cve.title}).`,
      evidenceIds: evidenceIds ?? [],
    },
    ctx,
  );

  if (!isNew) return emptyResult(record);

  const writes: DraftWrites = {
    audit: [
      {
        action: 'RELATIONSHIP_CREATED',
        entity: 'Relationship',
        entityId: record.id,
        before: 'n/a',
        after: `${infrastructureId} <-> ${cveId} (AFFECTED_BY_CVE, ${record.confidence}%)`,
        source: 'Analyst',
        result: 'SUCCESS',
        outcome: 'SUCCESS',
      },
    ],
    relationships: [record],
    timeline: [
      pushTimeline(
        dataset,
        {
          actorId: infrastructure.actorIds[0] ?? null,
          time: now,
          type: 'INFRASTRUCTURE_CHANGE',
          title: `CVE Affected Infrastructure - ${cve.cveId}`,
          description: `Infrastructure ${infrastructureId} is affected by CVE ${cve.cveId} (${cve.title}).`,
          confidence: record.confidence,
          source: 'Analyst',
          evidenceIds: evidenceIds ?? [],
        },
        ctx,
      ),
    ],
  };

  updateDataset(draft => ({ ...draft, relationships: [...draft.relationships, record] }));
  return commit(record, [], writes, { persisted: { relationships: [record] } });
}

// ── Wallet Transaction Mutations ─────────────────────────────────────────────

export interface WalletTransactionInput {
  walletId: string;
  hash: string;
  network: BlockchainNetwork;
  timestamp: string;
  blockHeight: number;
  amount: number;
  currency: string;
  fromAddress: string;
  toAddress: string;
  fee: number;
  direction: TransactionDirection;
  status: TransactionStatus;
  confirmations: number;
  exchangeIds?: string[];
  clusterId?: string;
  actorIds?: string[];
  handleIds?: string[];
  evidenceIds?: string[];
  confidence?: number;
  isCoinbase: boolean;
  isMixing: boolean;
  mixingService?: string;
  inputCount: number;
  outputCount: number;
  totalInput: number;
  totalOutput: number;
  isFlagged: boolean;
  flagReason?: string;
  isSynthetic?: boolean;
  notes?: string;
}

export function addWalletTransaction(input: WalletTransactionInput): MutationResult<WalletTransactionRecord> {
  const dataset = getDataset();
  const now = new Date().toISOString();
  const ctx: Context = createContext(now, 'ANALYST_ADDED');

  const wallet = dataset.lookups.walletsById[input.walletId];
  if (!wallet) {
    throw new Error('Wallet not found');
  }

  const record: WalletTransactionRecord = {
    id: allocId(ctx.alloc, 'TX', dataset.walletTransactions.map(tx => tx.id)),
    walletId: input.walletId,
    hash: normalizeText(input.hash),
    network: input.network,
    timestamp: normalizeTimestamp(input.timestamp, now),
    blockHeight: input.blockHeight,
    amount: input.amount,
    currency: normalizeText(input.currency).toUpperCase(),
    fromAddress: normalizeWallet(input.fromAddress),
    toAddress: normalizeWallet(input.toAddress),
    fee: input.fee,
    direction: input.direction,
    status: input.status,
    confirmations: input.confirmations,
    exchangeIds: input.exchangeIds ? input.exchangeIds.map(normalizeText) : [],
    clusterId: input.clusterId ? normalizeText(input.clusterId) : undefined,
    actorIds: input.actorIds ? input.actorIds.map(normalizeActorRef) : [],
    handleIds: input.handleIds ?? [],
    evidenceIds: input.evidenceIds ?? [],
    confidence: normalizeConfidence(input.confidence, 75),
    isCoinbase: input.isCoinbase,
    isMixing: input.isMixing,
    mixingService: input.mixingService ? normalizeText(input.mixingService) : undefined,
    inputCount: input.inputCount,
    outputCount: input.outputCount,
    totalInput: input.totalInput,
    totalOutput: input.totalOutput,
    isFlagged: input.isFlagged,
    flagReason: input.flagReason ? normalizeText(input.flagReason) : undefined,
    isSynthetic: input.isSynthetic ?? false,
    dataState: 'ANALYST_ADDED',
    analyst: ANALYST,
    notes: input.notes ?? '',
  };

  const relationships: RelationshipRecord[] = [];
  const actorUpdates: ActorRecord[] = [];

  // Create relationships between actors and this transaction
  if (input.actorIds) {
    for (const actorId of input.actorIds) {
      const { record: rel } = pushRelationship(
        dataset,
        {
          sourceEntity: actorId,
          targetEntity: record.id,
          sourceType: 'Actor',
          targetType: 'WalletTransaction',
          type: 'ASSOCIATED_WITH_TRANSACTION',
          confidence: record.confidence,
          explanation: `${actorId} is associated with wallet transaction ${record.hash} on ${record.network}.`,
          evidenceIds: input.evidenceIds ?? [],
        },
        ctx,
      );
      relationships.push(rel);
    }
  }

  // Create relationships between handles and this transaction
  if (input.handleIds) {
    for (const handleId of input.handleIds) {
      const { record: rel } = pushRelationship(
        dataset,
        {
          sourceEntity: handleId,
          targetEntity: record.id,
          sourceType: 'Handle',
          targetType: 'WalletTransaction',
          type: 'ASSOCIATED_WITH_TRANSACTION',
          confidence: record.confidence,
          explanation: `Handle ${handleId} is associated with wallet transaction ${record.hash} on ${record.network}.`,
          evidenceIds: input.evidenceIds ?? [],
        },
        ctx,
      );
      relationships.push(rel);
    }
  }

  // Create relationships between exchanges and this transaction
  if (input.exchangeIds) {
    for (const exchangeId of input.exchangeIds) {
      const { record: rel } = pushRelationship(
        dataset,
        {
          sourceEntity: exchangeId,
          targetEntity: record.id,
          sourceType: 'Exchange',
          targetType: 'WalletTransaction',
          type: 'ASSOCIATED_WITH_TRANSACTION',
          confidence: record.confidence,
          explanation: `Exchange ${exchangeId} is associated with wallet transaction ${record.hash} on ${record.network}.`,
          evidenceIds: input.evidenceIds ?? [],
        },
        ctx,
      );
      relationships.push(rel);
    }
  }

  const writes: DraftWrites = {
    audit: [
      {
        action: 'WALLET_TRANSACTION_ADDED',
        entity: 'WalletTransaction',
        entityId: record.id,
        before: 'n/a',
        after: `${record.hash} on ${record.network} linked to wallet ${record.walletId}`,
        source: 'Analyst',
        result: 'SUCCESS',
        outcome: 'SUCCESS',
      },
    ],
    timeline: input.actorIds
      ? input.actorIds.map(actorId =>
          pushTimeline(
            dataset,
            {
              actorId,
              time: record.timestamp,
              type: 'PLATFORM_ACTIVITY',
              title: `Wallet Transaction Observed - ${record.hash.slice(0, 16)}...`,              description: `Actor ${actorId} is associated with wallet transaction ${record.hash} on ${record.network}.`,              confidence: record.confidence,
              source: 'Analyst',
              evidenceIds: input.evidenceIds ?? [],
            },
            ctx,
          )
        )
      : [],
    alerts: input.isFlagged
      ? [
          pushAlert(
            dataset,
            {
              type: 'ANOMALY_DETECTED',
              severity: 'HIGH',
              title: `Flagged Wallet Transaction - ${record.hash.slice(0, 16)}...`,              actorId: input.actorIds ? input.actorIds[0] : null,
              reason: `Wallet transaction ${record.hash} on ${record.network} has been flagged: ${record.flagReason ?? 'No reason provided'}.`,              confidence: record.confidence,
              entityType: 'WALLET_TRANSACTION',
              entityId: record.id,
              evidenceIds: input.evidenceIds ?? [],
            },
            ctx,
          ),
        ]
      : [],
    relationships,
  };

  updateDataset(draft => ({
    ...draft,
    walletTransactions: [...draft.walletTransactions, record],
  }));
  return commit(record, [], writes, { actorUpdates });
}

// ── Wallet Cluster Mutations ─────────────────────────────────────────────

export interface WalletClusterInput {
  walletIds: string[];
  actorId?: string;
  method: ClusteringMethod;
  reasoning: string;
  confidence?: number;
  firstSeen?: string;
  lastSeen?: string;
  isSynthetic?: boolean;
  notes?: string;
}

export function addWalletCluster(input: WalletClusterInput): MutationResult<WalletClusterRecord> {
  const dataset = getDataset();
  const now = new Date().toISOString();
  const ctx: Context = createContext(now, 'ANALYST_ADDED');

  const record: WalletClusterRecord = {
    id: allocId(ctx.alloc, 'CLUSTER', dataset.walletClusters.map(cluster => cluster.id)),
    walletIds: input.walletIds.map(normalizeWallet),
    actorId: input.actorId ? normalizeActorRef(input.actorId) : undefined,
    method: input.method,
    reasoning: normalizeText(input.reasoning),
    confidence: normalizeConfidence(input.confidence, 75),
    firstSeen: normalizeTimestamp(input.firstSeen, now),
    lastSeen: normalizeTimestamp(input.lastSeen, now),
    totalTransactions: 0,
    exchangeIds: [],
    evidenceIds: [],
    isSynthetic: input.isSynthetic ?? false,
    dataState: 'ANALYST_ADDED',
    analyst: ANALYST,
    notes: input.notes ?? '',
  };

  const relationships: RelationshipRecord[] = [];
  const actorUpdates: ActorRecord[] = [];

  // Create relationships between wallets and this cluster
  for (const walletId of input.walletIds) {
    const { record: rel } = pushRelationship(
      dataset,
      {
        sourceEntity: walletId,
        targetEntity: record.id,
        sourceType: 'Wallet',
        targetType: 'WalletCluster',
        type: 'PART_OF_CLUSTER',
        confidence: record.confidence,
        explanation: `Wallet ${walletId} is part of cluster ${record.id} identified by ${record.method}.`,
      },
      ctx,
    );
    relationships.push(rel);
  }

  // If actor is specified, create relationships between the actor and the cluster
  if (input.actorId) {
    const { record: rel } = pushRelationship(
      dataset,
      {
        sourceEntity: input.actorId,
        targetEntity: record.id,
        sourceType: 'Actor',
        targetType: 'WalletCluster',
        type: 'ASSOCIATED_WITH_CLUSTER',
        confidence: record.confidence,
        explanation: `Actor ${input.actorId} is associated with wallet cluster ${record.id} identified by ${record.method}.`,
      },
      ctx,
    );
    relationships.push(rel);
  }

  const writes: DraftWrites = {
    audit: [
      {
        action: 'WALLET_CLUSTER_ADDED',
        entity: 'WalletCluster',
        entityId: record.id,
        before: 'n/a',
        after: `Cluster ${record.id} with ${record.walletIds.length} wallets identified by ${record.method}`,
        source: 'Analyst',
        result: 'SUCCESS',
        outcome: 'SUCCESS',
      },
    ],
    timeline: input.actorId
      ? [
          pushTimeline(
            dataset,
            {
              actorId: input.actorId,
              time: record.firstSeen,
              type: 'PLATFORM_ACTIVITY',
              title: `Wallet Cluster Observed - ${record.id}`,              description: `Actor ${input.actorId} is associated with wallet cluster ${record.id} identified by ${record.method}.`,              confidence: record.confidence,
              source: 'Analyst',
            },
            ctx,
          ),
        ]
      : [],
    alerts: input.actorId
      ? [
          pushAlert(
            dataset,
            {
              type: 'HIGH_CONFIDENCE_CORRELATION',
              severity: 'HIGH',
              title: `Wallet Cluster Correlation - ${record.walletIds.length} wallets`,              actorId: input.actorId,
              reason: `Wallet cluster ${record.id} with ${record.walletIds.length} wallets is associated with actor ${input.actorId}.`,              confidence: record.confidence,
              entityType: 'WALLET_CLUSTER',
              entityId: record.id,
            },
            ctx,
          ),
        ]
      : [],
    relationships,
  };

  updateDataset(draft => ({
    ...draft,
    walletClusters: [...draft.walletClusters, record],
  }));
  return commit(record, [], writes, { actorUpdates });
}

// ── Link Wallet to Exchange ─────────────────────────────────────────────
export function linkWalletToExchange(walletId: string, exchangeId: string, confidence?: number, evidenceIds?: string[]): MutationResult<RelationshipRecord> {
  const dataset = getDataset();
  const now = new Date().toISOString();
  const ctx: Context = createContext(now, 'ANALYST_ADDED');

  const wallet = dataset.lookups.walletsById[walletId];
  const exchange = dataset.lookups.exchangesById[exchangeId];

  if (!wallet || !exchange) {
    throw new Error('Wallet or Exchange not found');
  }

  const { record, isNew } = pushRelationship(
    dataset,
    {
      sourceEntity: walletId,
      targetEntity: exchangeId,
      sourceType: 'Wallet',
      targetType: 'Exchange',
      type: 'ASSOCIATED_WITH_EXCHANGE',
      confidence: normalizeConfidence(confidence, 75),
      explanation: `Wallet ${walletId} is associated with exchange ${exchangeId}.`,
      evidenceIds: evidenceIds ?? [],
    },
    ctx,
  );

  if (!isNew) return emptyResult(record);

  const writes: DraftWrites = {
    audit: [
      {
        action: 'RELATIONSHIP_CREATED',
        entity: 'Relationship',
        entityId: record.id,
        before: 'n/a',
        after: `${walletId} <-> ${exchangeId} (ASSOCIATED_WITH_EXCHANGE, ${record.confidence}%)`,
        source: 'Analyst',
        result: 'SUCCESS',
        outcome: 'SUCCESS',
      },
    ],
    relationships: [record],
    timeline: [
      pushTimeline(
        dataset,
        {
          actorId: wallet.actorIds[0] ?? null,
          time: now,
          type: 'PLATFORM_ACTIVITY',
          title: `Wallet Exchange Association - ${exchangeId}`,          description: `Wallet ${walletId} is associated with exchange ${exchangeId}.`,          confidence: record.confidence,
          source: 'Analyst',
          evidenceIds: evidenceIds ?? [],
        },
        ctx,
      ),
    ],
  };

  updateDataset(draft => ({ ...draft, relationships: [...draft.relationships, record] }));
  return commit(record, [], writes, { persisted: { relationships: [record] } });
}

// ── Investigation ─────────────────────────────────────────────
export interface InvestigationInput {
  title: string;
  description?: string;
  seedActorId: string;
  entityIds?: string[];
  analyst?: string;
  status?: InvestigationRecord['status'];
}

export function addInvestigation(input: InvestigationInput): MutationResult<InvestigationRecord> {
  const dataset = getDataset();
  const now = new Date().toISOString();
  const ctx: Context = createContext(now, 'ANALYST_ADDED');
  const seedActorId = normalizeActorRef(input.seedActorId);
  const year = new Date().getUTCFullYear();
  const serial = dataset.investigations.length + 1;

  const record: InvestigationRecord = {
    id: `INV-${year}-${String(serial).padStart(3, '0')}`,
    title: normalizeText(input.title),
    description: input.description ?? '',
    status: input.status ?? 'ACTIVE',
    analyst: input.analyst ?? ANALYST,
    createdAt: now,
    updatedAt: now,
    seedActorId,
    steps: [],
    confidence: dataset.lookups.actorsById[seedActorId]?.confidenceScore ?? 60,
    dataState: 'ANALYST_ADDED',
    entityIds: [seedActorId, ...(input.entityIds ?? []).map(normalizeActorRef)],
  };

  const writes: DraftWrites = {
    audit: [
      {
        action: 'INVESTIGATION_CREATED',
        entity: 'Investigation',
        entityId: record.id,
        before: 'n/a',
        after: `${record.title} (seed actor ${seedActorId})`,
        source: 'Analyst',
        result: 'SUCCESS',
        outcome: 'SUCCESS',
      },
    ],
    timeline: [
      pushTimeline(
        dataset,
        {
          actorId: seedActorId,
          time: now,
          type: 'RELATIONSHIP_FORMATION',
          title: 'Investigation Opened',
          description: `${record.id} - ${record.title}`,
          confidence: record.confidence,
          source: 'Analyst',
        },
        ctx,
      ),
    ],
  };

  updateDataset(draft => ({ ...draft, investigations: [...draft.investigations, record] }));
  return commit(record, [], writes);
}

/** Attach an existing central record to an investigation. */
export function attachToInvestigation(
  investigationId: string,
  entityType: 'ACTOR' | 'HANDLE' | 'PGP' | 'WALLET' | 'INFRASTRUCTURE' | 'EVIDENCE' | 'RELATIONSHIP',
  entityId: string,
): MutationResult<InvestigationRecord | null> {
  const dataset = getDataset();
  const now = new Date().toISOString();
  const investigation = dataset.lookups.investigationsById[investigationId];
  if (!investigation) return emptyResult<InvestigationRecord | null>(null);

  const stepNumber = investigation.steps.length + 1;
  const actorIds =
    entityType === 'ACTOR'
      ? [normalizeActorRef(entityId)]
      : entityType === 'HANDLE'
        ? [dataset.handles.find(item => item.id === entityId)?.actorId].filter((value): value is string => !!value)
        : [];

  const updated: InvestigationRecord = {
    ...investigation,
    updatedAt: now,
    steps: [
      ...investigation.steps,
      {
        step: stepNumber,
        type: entityType,
        title: `${entityType.charAt(0)}${entityType.slice(1).toLowerCase()} added - ${entityId}`,
        description: `${entityType} ${entityId} attached to ${investigationId} from the central intelligence model.`,
        evidenceIds: entityType === 'EVIDENCE' ? [entityId] : [],
        relationshipIds: entityType === 'RELATIONSHIP' ? [entityId] : [],
        actorIds,
        confidence: 70,
      },
    ],
    entityIds: entityType === 'ACTOR' ? [...new Set([...(investigation.entityIds ?? []), entityId])] : investigation.entityIds,
  };

  const auditEvent = createAuditEvent('INVESTIGATION_CREATED', 'Investigation', investigationId, `${entityType} ${entityId} attached`, ANALYST, 'Investigation workspace');

  updateDataset(draft => ({
    ...draft,
    investigations: draft.investigations.map(item => (item.id === investigationId ? updated : item)),
    audit: [auditEvent, ...draft.audit],
  }));

  return {
    record: updated,
    duplicates: [],
    relationships: [],
    alerts: [],
    timeline: [],
    audit: [auditEvent],
    observations: [],
  };
}

// ── Analyst note ──────────────────────────────────────────────
export function addNote(entityType: string, entityId: string, text: string) {
  const dataset = getDataset();
  const note = {
    id: nextId('NOTE', dataset.notes.map(item => item.id)),
    entityType,
    entityId,
    author: ANALYST,
    createdAt: new Date().toISOString(),
    text: normalizeText(text),
  };
  updateDataset(draft => ({ ...draft, notes: [...draft.notes, note] }));
  return note;
}

// ── Dataset import ────────────────────────────────────────────
/** Every collection an import document may supply. */
const IMPORT_COLLECTIONS = [
  'actors',
  'handles',
  'pgpKeys',
  'wallets',
  'infrastructure',
  'sources',
  'observations',
  'relationships',
  'evidence',
  'timeline',
  'investigations',
  'alerts',
  'reports',
  'notes',
  // Extended intelligence collections — imported through the same single
  // write path so ATT&CK, CVE and crypto records are never second-class.
  'mitreTtps',
  'cves',
  'vulnerabilities',
  'walletTransactions',
  'walletClusters',
  'exchanges',
  'communicationChannels',
  'communicationMessages',
  'methodologies',
  'playbooks',
] as const;

type ImportCollection = (typeof IMPORT_COLLECTIONS)[number];

/**
 * Keeps only records that are objects carrying a usable `id`, so one bad row
 * cannot corrupt the import, and drops ids repeated inside the document.
 */
function readCollection<T extends { id: string }>(document: Record<string, unknown>, key: ImportCollection): T[] {
  const raw = document[key];
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  const accepted: T[] = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== 'object') continue;
    const id = (entry as { id?: unknown }).id;
    if (typeof id !== 'string' || !id.trim() || seen.has(id)) continue;
    seen.add(id);
    accepted.push(entry as T);
  }
  return accepted;
}

/** What an import actually accepted, per collection. */
export type DatasetImportSummary = { collection: ImportCollection; count: number }[];

/**
 * Imports a dataset document through the same single write path as every form:
 * the supplied collections replace the model, every id lookup is rebuilt and
 * the import is audit-logged, so imported records are indistinguishable from
 * typed ones. Nothing is inferred and nothing is merged with existing records.
 */
export function importDatasetJson(document: unknown): { dataset: IntelligenceDataset; summary: DatasetImportSummary; result: MutationResult<IntelligenceDataset> } {
  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    throw new Error('Import must be a single JSON object containing the dataset collections.');
  }
  const parsed = document as Record<string, unknown>;
  const template = getDataset();
  const summary: DatasetImportSummary = [];
  const collections = {} as Record<ImportCollection, unknown[]>;
  let accepted = 0;

  for (const key of IMPORT_COLLECTIONS) {
    const records = readCollection(parsed, key);
    collections[key] = records;
    if (records.length) {
      summary.push({ collection: key, count: records.length });
      accepted += records.length;
    }
  }
  if (!accepted) {
    throw new Error(`No importable records found. Supply at least one collection: ${IMPORT_COLLECTIONS.join(', ')}.`);
  }

  const auditEvent = createAuditEvent(
    'IMPORT_COMPLETED',
    'Dataset',
    'CENTRAL',
    `${summary.map(entry => `${entry.count} ${entry.collection}`).join(', ')}`,
    ANALYST,
    'JSON import',
  );

  const next = replaceDataset({
    ...template,
    ...(collections as Pick<IntelligenceDataset, ImportCollection>),
    isDemoLoaded: false,
    audit: [auditEvent],
    monitoring: {
      ...template.monitoring,
      lastCollection: auditEvent.time,
      sourcesMonitored: collections.sources.length,
      newActors: collections.actors.length,
      newIndicators: collections.handles.length,
      newRelationships: collections.relationships.length,
      alerts: collections.alerts.length,
    },
  } as IntelligenceDataset);

  return {
    dataset: next,
    summary,
    result: {
      record: next,
      duplicates: [],
      relationships: next.relationships,
      alerts: next.alerts,
      timeline: next.timeline,
      observations: next.observations,
      audit: [auditEvent],
    },
  };
}

