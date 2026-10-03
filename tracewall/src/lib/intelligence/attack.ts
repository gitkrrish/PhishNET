// ============================================================
// PhishNet — MITRE ATT&CK derivation.
//
// Pure read-side analysis over the central dataset. Nothing here writes,
// and nothing here infers a technique: every cell it returns exists as a
// stored record, and every attribution it reports is one the analyst (or
// the seed) already recorded against that technique.
//
// The module deliberately reports three separate things that are easy to
// conflate — the observed mapping, the supporting evidence, and the
// analyst's confidence in it — so the UI never presents a mapping as a
// confirmed capability.
// ============================================================
import type { IntelligenceDataset, MitreTtpRecord } from './types';
import type { MitreTactic } from './types-mitre';

/** ATT&CK enterprise tactics in kill-chain order. */
export const ATTACK_TACTICS: { id: MitreTactic; label: string; short: string }[] = [
  { id: 'RECONNAISSANCE', label: 'Reconnaissance', short: 'REC' },
  { id: 'RESOURCE_DEVELOPMENT', label: 'Resource Development', short: 'RSD' },
  { id: 'INITIAL_ACCESS', label: 'Initial Access', short: 'IA' },
  { id: 'EXECUTION', label: 'Execution', short: 'EXE' },
  { id: 'PERSISTENCE', label: 'Persistence', short: 'PER' },
  { id: 'PRIVILEGE_ESCALATION', label: 'Privilege Escalation', short: 'PRV' },
  { id: 'DEFENSE_EVASION', label: 'Defense Evasion', short: 'EVV' },
  { id: 'CREDENTIAL_ACCESS', label: 'Credential Access', short: 'CRD' },
  { id: 'DISCOVERY', label: 'Discovery', short: 'DSC' },
  { id: 'LATERAL_MOVEMENT', label: 'Lateral Movement', short: 'LAT' },
  { id: 'COLLECTION', label: 'Collection', short: 'COL' },
  { id: 'COMMAND_AND_CONTROL', label: 'Command and Control', short: 'C2' },
  { id: 'EXFILTRATION', label: 'Exfiltration', short: 'EXF' },
  { id: 'IMPACT', label: 'Impact', short: 'IMP' },
];

export interface AttackCell {
  techniqueId: string;
  name: string;
  subTechnique?: string;
  /** Actors the stored record attributes this technique to. */
  actorIds: string[];
  /** Evidence backing the mapping — empty means the record asserts it alone. */
  evidenceIds: string[];
  confidence: number;
  firstSeen: string;
  lastSeen: string;
}

export interface AttackRow {
  tactic: MitreTactic;
  label: string;
  short: string;
  cells: AttackCell[];
}

export interface TacticShare {
  tactic: MitreTactic;
  label: string;
  short: string;
  techniques: number;
  /** Share of all stored techniques, 0–100. */
  share: number;
  actorIds: string[];
}

/** All stored techniques as matrix cells, ordered by tactic then technique id. */
export function attackCells(records: MitreTtpRecord[]): AttackCell[] {
  return records
    .map(record => ({
      techniqueId: record.techniqueId,
      name: record.name,
      subTechnique: record.subTechnique,
      actorIds: [...record.actorIds],
      evidenceIds: [...record.evidenceIds],
      confidence: record.confidence,
      firstSeen: record.firstSeen,
      lastSeen: record.lastSeen,
    }))
    .sort((a, b) => a.techniqueId.localeCompare(b.techniqueId));
}

/**
 * The ATT&CK matrix. Tactics with no recorded technique are still returned
 * so the grid keeps its full shape — an empty tactic is information.
 */
export function attackMatrix(records: MitreTtpRecord[]): AttackRow[] {
  const cells = attackCells(records);
  return ATTACK_TACTICS.map(tactic => ({
    tactic: tactic.id,
    label: tactic.label,
    short: tactic.short,
    cells: cells.filter(cell => {
      const record = records.find(item => item.techniqueId === cell.techniqueId);
      return record?.tactic === tactic.id;
    }),
  }));
}

export function tacticDistribution(records: MitreTtpRecord[]): TacticShare[] {
  const total = records.length;
  return ATTACK_TACTICS.map(tactic => {
    const inTactic = records.filter(record => record.tactic === tactic.id);
    const actorIds = new Set(inTactic.flatMap(record => record.actorIds));
    return {
      tactic: tactic.id,
      label: tactic.label,
      short: tactic.short,
      techniques: inTactic.length,
      share: total ? Math.round((inTactic.length / total) * 100) : 0,
      actorIds: [...actorIds],
    };
  });
}

export interface ActorCoverage {
  actorId: string;
  label: string;
  techniques: number;
  tactics: number;
  /** Mean confidence across the actor's stored mappings. */
  confidence: number;
  /** Mappings with no supporting evidence — surfaced, not hidden. */
  unbacked: number;
  firstSeen: string;
  lastSeen: string;
  techniqueIds: string[];
}

/** Per-actor technique coverage across every stored mapping. */
export function actorCoverage(dataset: IntelligenceDataset): ActorCoverage[] {
  const records = dataset.mitreTtps ?? [];
  return dataset.actors
    .map(actor => {
      const mine = records.filter(record => record.actorIds.includes(actor.id));
      const confidences = mine.map(record => record.confidence);
      const dates = mine.flatMap(record => [record.firstSeen, record.lastSeen]).sort();
      return {
        actorId: actor.id,
        label: actor.aliases[0] ?? actor.id,
        techniques: mine.length,
        tactics: new Set(mine.map(record => record.tactic)).size,
        confidence: confidences.length
          ? Math.round(confidences.reduce((sum, value) => sum + value, 0) / confidences.length)
          : 0,
        unbacked: mine.filter(record => record.evidenceIds.length === 0).length,
        firstSeen: dates[0] ?? '',
        lastSeen: dates[dates.length - 1] ?? '',
        techniqueIds: mine.map(record => record.techniqueId).sort(),
      };
    })
    .sort((a, b) => b.techniques - a.techniques);
}

/** The stored mappings attributed to one actor, with the evidence each rests on. */
export function techniquesForActor(dataset: IntelligenceDataset, actorId: string): AttackCell[] {
  return attackCells((dataset.mitreTtps ?? []).filter(record => record.actorIds.includes(actorId)));
}

export interface TechniqueTimelineEntry {
  techniqueId: string;
  name: string;
  tactic: MitreTactic;
  firstSeen: string;
  lastSeen: string;
  /** How many days the technique stayed in the record. */
  spanDays: number;
  confidence: number;
}

const DAY_MS = 86_400_000;

export function techniqueTimeline(records: MitreTtpRecord[]): TechniqueTimelineEntry[] {
  return records
    .map(record => {
      const first = Date.parse(record.firstSeen);
      const last = Date.parse(record.lastSeen);
      return {
        techniqueId: record.techniqueId,
        name: record.name,
        tactic: record.tactic,
        firstSeen: record.firstSeen,
        lastSeen: record.lastSeen,
        spanDays: Number.isFinite(first) && Number.isFinite(last) && last >= first
          ? Math.round((last - first) / DAY_MS)
          : 0,
        confidence: record.confidence,
      };
    })
    .sort((a, b) => Date.parse(a.firstSeen) - Date.parse(b.firstSeen));
}

export interface AttackBundle {
  technique: MitreTtpRecord;
  tacticLabel: string;
  actors: { id: string; label: string }[];
  handles: { id: string; value: string; platform: string }[];
  infrastructure: { id: string; type: string; value: string }[];
  evidence: { id: string; evidenceType: string; source: string }[];
  /** Techniques sharing an actor with this one — a co-occurrence hint only. */
  relatedTechniqueIds: string[];
}

/** Everything one technique record connects to, resolved through central lookups. */
export function attackBundle(dataset: IntelligenceDataset, techniqueId: string): AttackBundle | null {
  const record = (dataset.mitreTtps ?? []).find(item => item.techniqueId === techniqueId);
  if (!record) return null;

  const coAttributed = (dataset.mitreTtps ?? []).filter(
    other => other.techniqueId !== record.techniqueId
      && other.actorIds.some(actorId => record.actorIds.includes(actorId)),
  );

  return {
    technique: record,
    tacticLabel: ATTACK_TACTICS.find(t => t.id === record.tactic)?.label ?? record.tactic,
    actors: record.actorIds
      .map(id => dataset.lookups.actorsById[id])
      .filter(Boolean)
      .map(actor => ({ id: actor.id, label: actor.aliases[0] ?? actor.id })),
    handles: record.handleIds
      .map(id => dataset.lookups.handlesById[id])
      .filter(Boolean)
      .map(handle => ({ id: handle.id, value: handle.value, platform: handle.platform })),
    infrastructure: record.infrastructureIds
      .map(id => dataset.lookups.infraById[id])
      .filter(Boolean)
      .map(infra => ({ id: infra.id, type: infra.type, value: infra.value })),
    evidence: record.evidenceIds
      .map(id => dataset.lookups.evidenceById[id])
      .filter(Boolean)
      .map(item => ({ id: item.id, evidenceType: item.evidenceType, source: item.source })),
    relatedTechniqueIds: coAttributed.map(item => item.techniqueId).sort(),
  };
}

/** CVEs the stored ATT&CK mappings do not explain — a coverage gap, not a verdict. */
export function unexplainedCves(dataset: IntelligenceDataset): string[] {
  const linked = new Set(
    (dataset.mitreTtps ?? []).flatMap(record => record.infrastructureIds),
  );
  return (dataset.cves ?? [])
    .filter(cve => !cve.infrastructureIds.some(id => linked.has(id)))
    .map(cve => cve.cveId)
    .sort();
}
