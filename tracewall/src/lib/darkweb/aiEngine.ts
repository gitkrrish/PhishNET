// ============================================================
// PhishNet — Dark Web AI Analysis Engine (client-side, dataset-derived)
//
// Every conclusion produced here is derived ONLY from the central
// intelligence dataset. No external service is called and no
// evidence is fabricated. Confidence is always explainable.
// ============================================================
import {
  threatActors, darkWebHandles, darkWebPgpKeys, darkWebWallets,
  darkWebInfrastructure, darkWebRelationships, darkWebEvidence,
  darkWebSources, darkWebTimeline, darkWebInvestigations, darkWebAlerts,
  darkWebActorsById, darkWebEvidenceById, darkWebRelationshipsById,
  darkWebHandlesById, darkWebInvestigationById, darkWebAlertById,
  type ThreatActor, type Handle, type PgpKey, type Wallet, type Infrastructure,
   type Relationship, type Evidence, type TimelineEvent, type Investigation,
   type Alert, type DarkWebSource, type InvestigationStep,
 } from './liveData';

// ── Small helpers ───────────────────────────────────────────────
function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  if (!m) return n; if (!n) return m;
  const prev = new Array(n + 1).fill(0);
  const curr = new Array(n + 1).fill(0);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    for (let j = 0; j <= n; j++) prev[j] = curr[j];
  }
  return prev[n];
}

function similarity(a: string, b: string): number {
  const max = Math.max(a.length, b.length);
  if (!max) return 1;
  return 1 - levenshtein(a, b) / max;
}

function confidenceLabel(v: number): string {
  if (v >= 90) return 'Very High';
  if (v >= 75) return 'High';
  if (v >= 60) return 'Medium';
  if (v >= 40) return 'Low';
  return 'Very Low';
}

// ── 1. Handle / username correlation ────────────────────────────
export interface HandleMatch {
  handleId: string;
  value: string;
  platform: string;
  source: string;
  matchType: 'EXACT' | 'NORMALIZED' | 'ALIAS_SIMILARITY' | 'HISTORICAL_REUSE' | 'SHARED_IDENTIFIER' | 'ACTIVITY_OVERLAP';
  confidence: number;
  actorId: string | null;
  why: string;
}

export function correlateHandles(query: string): HandleMatch[] {
  const q = query.toLowerCase().trim();
  if (!q) return [];
  const matches: HandleMatch[] = [];
  const actorByHandle: Record<string, string> = {};
  for (const actor of threatActors) {
    for (const h of actor.handles) actorByHandle[h.toLowerCase()] = actor.id;
  }
  for (const handle of darkWebHandles) {
    const norm = handle.normalized;
    if (norm === q) {
      matches.push({
        handleId: handle.id, value: handle.value, platform: handle.platform, source: handle.sourceId,
        matchType: 'EXACT', confidence: handle.confidence, actorId: actorByHandle[norm] ?? null,
        why: 'Exact normalized match (case-insensitive) against observed handle.',
      });
      continue;
    }
    if (norm.includes(q) || q.includes(norm)) {
      matches.push({
        handleId: handle.id, value: handle.value, platform: handle.platform, source: handle.sourceId,
        matchType: 'NORMALIZED', confidence: Math.round(handle.confidence * 0.85), actorId: actorByHandle[norm] ?? null,
        why: `Normalized handle contains the query. Similarity of normalized forms: ${(similarity(norm, q) * 100).toFixed(0)}%.`,
      });
      continue;
    }
    const sim = similarity(norm, q);
    if (sim >= 0.7) {
      matches.push({
        handleId: handle.id, value: handle.value, platform: handle.platform, source: handle.sourceId,
        matchType: 'ALIAS_SIMILARITY', confidence: Math.round(sim * 100), actorId: actorByHandle[norm] ?? null,
        why: `Alias similarity ${Math.round(sim * 100)}% (Levenshtein). Not an exact match — treat as candidate only.`,
      });
    }
  }
  // Historical reuse: same handle seen on multiple platforms
  const byNorm: Record<string, Handle[]> = {};
  for (const h of darkWebHandles) {
    const arr = byNorm[h.normalized] ?? (byNorm[h.normalized] = []);
    arr.push(h);
  }
  for (const norm in byNorm) {
    if (norm.includes(q) && byNorm[norm].length > 1) {
      for (const h of byNorm[norm]) {
        if (!matches.some(m => m.handleId === h.id)) {
          matches.push({
            handleId: h.id, value: h.value, platform: h.platform, source: h.sourceId,
            matchType: 'HISTORICAL_REUSE', confidence: 70, actorId: actorByHandle[norm] ?? null,
            why: `Handle reused across ${byNorm[norm].length} platforms (historical reuse indicator).`,
          });
        }
      }
    }
  }
  // Shared identifier: PGP / wallet / infra linked to actors using the handle
  const matchedActorIds = new Set(matches.map(m => m.actorId).filter(Boolean) as string[]);
  for (const mid of matchedActorIds) {
    const actor = darkWebActorsById[mid];
    if (actor) {
      actor.pgpFingerprints.forEach(fp => matches.push({
        handleId: `PGP-${fp.slice(0, 8)}`, value: fp, platform: 'PGP Key', source: 'Cross-platform',
        matchType: 'SHARED_IDENTIFIER', confidence: actor.confidenceScore, actorId: actor.id,
        why: `Shared PGP fingerprint ${fp} binds this handle to actor ${actor.id}.`,
      }));
      actor.walletAddrs.forEach(wa => matches.push({
        handleId: `WAL-${wa.slice(0, 12)}`, value: wa, platform: 'Wallet', source: 'Cross-platform',
        matchType: 'SHARED_IDENTIFIER', confidence: 80, actorId: actor.id,
        why: `Shared wallet address binds handle to actor ${actor.id}.`,
      }));
    }
  }
  return matches.sort((a, b) => b.confidence - a.confidence);
}

// ── 2. Multi-platform identity correlation matrix ───────────────
export interface IdentityRecord {
  platform: string;
  handle: string;
  sourceId: string;
  observedDate: string;
  confidence: number;
  sharedIndicators: string[];
  relationship: string | null;
}

export function identityCorrelationMatrix(handle: string): IdentityRecord[] {
  const norm = handle.toLowerCase().trim();
  const records: IdentityRecord[] = [];
  for (const h of darkWebHandles) {
    if (h.normalized !== norm) continue;
    const actor = threatActors.find(a => a.handles.some(x => x.toLowerCase() === norm));
    const shared: string[] = [];
    if (actor) {
      if (actor.pgpFingerprints.length) shared.push(`PGP (${actor.pgpFingerprints.length})`);
      if (actor.walletAddrs.length) shared.push(`Wallet (${actor.walletAddrs.length})`);
      if (actor.domains.length) shared.push(`Domain (${actor.domains.length})`);
    }
    const rel = darkWebRelationships.find(r => (r.sourceEntity === norm || r.targetEntity === norm) && (r.sourceType === 'Handle' || r.targetType === 'Handle'));
    records.push({
      platform: h.platform,
      handle: h.value,
      sourceId: h.sourceId,
      observedDate: h.lastSeen,
      confidence: h.confidence,
      sharedIndicators: shared,
      relationship: rel?.id ?? null,
    });
  }
  return records;
}

// ── 3. PGP correlation ───────────────────────────────────────────
export function searchPgp(fingerprint: string): { key: PgpKey; actor: ThreatActor | undefined }[] {
  const fp = fingerprint.replace(/\s+/g, '').toUpperCase();
  return darkWebPgpKeys
    .filter(k => k.fingerprint.replace(/\s+/g, '').toUpperCase().startsWith(fp.slice(0, 12)) || fp.includes(k.fingerprint.slice(0, 8)))
    .map(k => k.actorIds.map(id => ({ key: k, actor: darkWebActorsById[id] })).filter(x => x.actor))
    .flat();
}

// ── 4. Wallet correlation ────────────────────────────────────────
export function searchWallet(address: string): { wallet: Wallet; actor: ThreatActor | undefined }[] {
  return darkWebWallets
    .filter(w => w.address === address || w.address.startsWith(address.slice(0, 12)))
    .map(w => w.actorIds.map(id => ({ wallet: w, actor: darkWebActorsById[id] })).filter(x => x.actor))
    .flat();
}

// ── 5. Infrastructure correlation ──────────────────────────────
export function searchInfrastructure(value: string): { infra: Infrastructure; actor: ThreatActor | undefined }[] {
  const v = value.toLowerCase();
  return darkWebInfrastructure
    .filter(i => i.value.toLowerCase().includes(v))
    .map(i => i.actorIds.map(id => ({ infra: i, actor: darkWebActorsById[id] })).filter(x => x.actor))
    .flat();
}

// ── 6. Stylometric similarity ────────────────────────────────────
export interface StylometricResult {
  similarity: number;
  label: string;
  factors: Array<{ name: string; matched: boolean; detail: string }>;
}

export function stylometricSimilarity(a: ThreatActor, b: ThreatActor): StylometricResult {
  const sa = a.stylometricProfile, sb = b.stylometricProfile;
  const factors: Array<{ name: string; matched: boolean; detail: string }> = [];
  factors.push({ name: 'Average sentence length', matched: Math.abs(sa.avgSentenceLength - sb.avgSentenceLength) <= 4, detail: `${sa.avgSentenceLength} vs ${sb.avgSentenceLength} words` });
  factors.push({ name: 'Punctuation pattern', matched: sa.punctuationPattern === sb.punctuationPattern, detail: `${matchedText(sa.punctuationPattern, sb.punctuationPattern)}` });
  factors.push({ name: 'Capitalisation tendency', matched: sa.capitalisationTendency === sb.capitalisationTendency, detail: `${sa.capitalisationTendency} vs ${sb.capitalisationTendency}` });
  const vocabDiff = Math.abs(sa.vocabularyRichness - sb.vocabularyRichness);
  factors.push({ name: 'Vocabulary richness', matched: vocabDiff <= 0.1, detail: `${(sa.vocabularyRichness * 100).toFixed(0)}% vs ${(sb.vocabularyRichness * 100).toFixed(0)}%` });
  const sharedExpr = sa.recurringExpressions.filter(e => sb.recurringExpressions.includes(e));
  factors.push({ name: 'Recurring expressions', matched: sharedExpr.length >= 2, detail: `${sharedExpr.length} shared: ${sharedExpr.slice(0, 3).join(', ') || 'none'}` });
  factors.push({ name: 'Sentence structure', matched: sa.sentenceStructure === sb.sentenceStructure, detail: `${matchedText(sa.sentenceStructure, sb.sentenceStructure)}` });
  const sharedLang = sa.languagePatterns.filter(p => sb.languagePatterns.includes(p));
  factors.push({ name: 'Language patterns', matched: sharedLang.length >= 1, detail: `${sharedLang.length} shared patterns` });
  const matched = factors.filter(f => f.matched).length;
  const similarity = Math.round((matched / factors.length) * 100);
  return { similarity, label: confidenceLabel(similarity), factors };
}

function matchedText(a: string, b: string): string {
  return a === b ? 'match' : `${a} vs ${b}`;
}

// ── 7. Behavioral analysis ───────────────────────────────────────
export interface BehavioralResult {
  overall: number;
  factors: Array<{ name: string; matched: boolean; value: string }>;
}

export function behavioralAnalysis(a: ThreatActor, b: ThreatActor): BehavioralResult {
  const fa = a.behavioralProfile, fb = b.behavioralProfile;
  const factors: Array<{ name: string; matched: boolean; value: string }> = [];
  const sharedHours = fa.activeHours.filter(h => fb.activeHours.some(h2 => h2.hour === h.hour && Math.abs(h2.level - h.level) <= 20));
  factors.push({ name: 'Active hours overlap', matched: sharedHours.length >= 1, value: `${sharedHours.length} overlapping hour slot(s)` });
  const prefA = fa.platformPreferences[0]?.platform;
  const prefB = fb.platformPreferences.find(p => p.platform === prefA);
  factors.push({ name: 'Platform preference', matched: !!prefB, value: prefB ? `${(prefB.weight).toFixed(0)}% shared platform ${prefA}` : `no shared primary platform` });
  const topicOverlap = fa.topicClusters.filter(t => fb.topicClusters.includes(t));
  factors.push({ name: 'Topic clusters', matched: topicOverlap.length >= 1, value: `${topicOverlap.length} shared: ${topicOverlap.join(', ') || 'none'}` });
  factors.push({ name: 'Posting cadence', matched: Math.abs(fa.postingFrequency - fb.postingFrequency) <= 10, value: `${fa.postingFrequency}/wk vs ${fb.postingFrequency}/wk posts` });
  factors.push({ name: 'Interaction pattern', matched: fa.interactionPattern === fb.interactionPattern, value: `${matchedText(fa.interactionPattern, fb.interactionPattern)}` });
  const matched = factors.filter(f => f.matched).length;
  const overall = Math.round((matched / factors.length) * 100);
  return { overall, factors };
}

// ── 8. Entity resolution ─────────────────────────────────────────
export interface EntityResolution {
  primaryActorId: string;
  confidence: number;
  indicators: Array<{ source: string; value: string; weight: number }>;
  label: string;
  isSynthetic: boolean;
  disclaimer: string;
}

function resolveEntity(handle: string): EntityResolution {
  const handleMatches = correlateHandles(handle);
  const actorById: Record<string, number> = {};
  const indicators: Array<{ source: string; value: string; weight: number }> = [];
  for (const m of handleMatches) {
    if (m.actorId) {
      actorById[m.actorId] = (actorById[m.actorId] ?? 0) + m.confidence;
      indicators.push({ source: 'Handle', value: m.matchType, weight: m.confidence });
    }
  }
  // weight PGP / wallet / infra matches found on matched actors
  const candidateIds = Object.keys(actorById);
  for (const actor of candidateIds.map(id => darkWebActorsById[id]).filter(Boolean)) {
    if (actor.pgpFingerprints.length) indicators.push({ source: 'PGP', value: `${actor.pgpFingerprints.length} key(s)`, weight: 96 });
    if (actor.walletAddrs.length) indicators.push({ source: 'Wallet', value: `${actor.walletAddrs.length} wallet(s)`, weight: 90 });
    if (actor.domains.length) indicators.push({ source: 'Infrastructure', value: `${actor.domains.length} domain(s)`, weight: 80 });
  }
  const topId = candidateIds.reduce((best, id) => (actorById[id] > actorById[best] ? id : best), candidateIds[0] ?? '');
  const confidence = topId ? Math.min(100, Math.round(actorById[topId] / indicators.length)) : 0;
  return {
    primaryActorId: topId,
    confidence,
    indicators,
    label: 'Potential Entity (analytical construct, not confirmed identity)',
    isSynthetic: true,
    disclaimer: 'This is an analytical entity derived from synthetic indicators. It represents a high-confidence investigative hypothesis, not a proven real-world identity.',
  };
}
export { resolveEntity };

// ── 9. Relationship explanation ("Why Linked?") ─────────────────
export interface RelationshipExplanation {
  relationship: Relationship;
  supporting: string[];
  against: string[];
  finalConfidence: number;
  label: string;
  evidence: Evidence[];
}

export function explainRelationship(relId: string): RelationshipExplanation | null {
  const rel = darkWebRelationshipsById[relId];
  if (!rel) return null;
  const ev = rel.evidenceIds.map(id => darkWebEvidenceById[id]).filter(Boolean);
  return {
    relationship: rel,
    supporting: rel.supporting,
    against: rel.against,
    finalConfidence: rel.confidence,
    label: confidenceLabel(rel.confidence),
    evidence: ev,
  };
}

// ── 10. Anomaly detection ────────────────────────────────────────
export interface Anomaly {
  id: string;
  actorId: string;
  type: string;
  description: string;
  confidence: number;
  timestamp: string;
}

export function anomalyDetection(): Anomaly[] {
  const out: Anomaly[] = [];
  for (const actor of threatActors) {
    // dormant → re-emergent
    if (actor.status === 'DORMANT') {
      out.push({ id: `ANOM-${actor.id}-0`, actorId: actor.id, type: 'DORMANT_ENTITY', description: `${actor.id} remains dormant; monitor for re-emergence.`, confidence: 90, timestamp: actor.lastSeen });
    } else if (actor.activityLevel === 'HIGH' && actor.confidenceScore >= 90) {
      out.push({ id: `ANOM-${actor.id}-1`, actorId: actor.id, type: 'HIGH_VOLUME', description: `${actor.id} shows sustained high activity with elevated confidence — watch for escalation.`, confidence: actor.confidenceScore, timestamp: actor.lastSeen });
    }
  }
  // persona migration
  const migration = darkWebRelationships.filter(r => r.type === 'PERSONA_MIGRATION');
  for (const rel of migration) {
    out.push({ id: `ANOM-${rel.id}`, actorId: rel.targetEntity, type: 'PERSONA_MIGRATION', description: `Migration detected: ${rel.sourceEntity} → ${rel.targetEntity} (${rel.confidence}% confidence).`, confidence: rel.confidence, timestamp: rel.lastObserved });
  }
  return out;
}

// ── 11. Natural-language search → structured query ──────────────
export type StructuredQuery = { filter: string; value: string; results: unknown[] };

export function nlSearch(query: string): StructuredQuery[] {
  const q = query.toLowerCase().trim();
  const results: StructuredQuery[] = [];

  if (q.includes('actor') && (q.includes('share') || q.includes('&') || q.includes('infrastructure'))) {
    const infras = darkWebInfrastructure.filter(i => i.actorIds.length >= 2);
    results.push({ filter: 'shared_infrastructure', value: query, results: infras });
  }
  if (q.includes('confidence') && (q.includes('above') || q.includes('over') || q.includes('higher'))) {
    const m = q.match(/(\d+)/);
    const threshold = m ? Number(m[1]) : 75;
    const rels = darkWebRelationships.filter(r => r.confidence >= threshold);
    results.push({ filter: 'confidence_above', value: query, results: rels });
  }
  if (q.includes('active') && (q.includes('after') || q.includes('since'))) {
    const m = q.match(/(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s*(\d{4})/i);
    const date = m ? new Date(`${m[1]} ${m[2]}`).getTime() : 0;
    const actors = threatActors.filter(a => new Date(a.lastSeen).getTime() >= date);
    results.push({ filter: 'active_after', value: query, results: actors });
  }
  if (q.includes('relationship')) {
    results.push({ filter: 'relationships', value: query, results: darkWebRelationships });
  }
  const handleMatch = darkWebHandles.find(h => h.normalized === q.split('handle').pop()?.trim().toLowerCase().split(' ').pop() || similarity(h.normalized, q.replace('find actors associated with this handle', '').trim()) > 0.8);
  if (q.includes('handle') && handleMatch) {
    results.push({ filter: 'handle', value: handleMatch.value, results: correlateHandles(handleMatch.value) });
  }
  if (results.length === 0) {
    results.push({ filter: 'fuzzy', value: query, results: darkWebHandles.filter(h => similarity(h.normalized, q) > 0.5) });
  }
  return results;
}

// ── 12. Investigation assistant (Q&A from dataset) ───────────────
export function assistantAnswer(question: string, contextActorId?: string): { answer: string; sources: string[]; type: 'observed' | 'derived' | 'interpretation' } {
  const q = question.toLowerCase().trim();
  const actor = contextActorId ? darkWebActorsById[contextActorId] : undefined;

  if (q.includes('indicator') && (q.includes('associated') || q.includes('with'))) {
    if (!actor) return noAnswer(question);
    const indicators: string[] = [];
    if (actor.handles.length) indicators.push(`${actor.handles.length} handles: ${actor.handles.join(', ')}`);
    if (actor.pgpFingerprints.length) indicators.push(`${actor.pgpFingerprints.length} PGP keys: ${actor.pgpFingerprints.join(', ')}`);
    if (actor.walletAddrs.length) indicators.push(`${actor.walletAddrs.length} wallets: ${actor.walletAddrs.join(', ')}`);
    if (actor.domains.length) indicators.push(`${actor.domains.length} domains: ${actor.domains.join(', ')}`);
    return {
      answer: `Indicators associated with ${actor.id}: ${indicators.join('; ')}.`,
      sources: actor.associatedEvidence, type: 'observed',
    };
  }
  if (q.includes('why') && q.includes('link')) {
    if (!actor) return noAnswer(question);
    const rels = darkWebRelationships.filter(r => r.sourceEntity === actor.id || r.targetEntity === actor.id || r.sourceEntity === actor.handles[0] || r.targetEntity === actor.handles[0]);
    if (!rels.length) return noAnswer(question);
    const top = rels.sort((a, b) => b.confidence - a.confidence)[0];
    return {
      answer: `These entities are linked because: ${top.supporting.join('; ')}. Supporting evidence: ${top.evidenceIds.join(', ')}. Analytical confidence: ${top.confidence}%.`,
      sources: top.evidenceIds, type: 'derived',
    };
  }
  if (q.includes('changed') && q.includes('last 30 day')) {
    if (!actor) return noAnswer(question);
    const events = darkWebTimeline.filter(t => t.actorId === actor.id);
    return {
      answer: `${actor.id} timeline over the last 30 days: ${events.map(e => `${e.title} (${new Date(e.time).toLocaleDateString()})`).join('; ')}.`,
      sources: events.map(e => e.id), type: 'observed',
    };
  }
  if (q.includes('infrastructure') && (q.includes('share') || q.includes('common'))) {
    if (!actor) return noAnswer(question);
    const shared = darkWebInfrastructure.filter(i => i.actorIds.includes(actor.id) && i.actorIds.length > 1);
    return {
      answer: `Shared infrastructure for ${actor.id}: ${shared.map(i => `${i.type} ${i.value} (with actors ${i.actorIds.filter(a => a !== actor.id).join(', ')})`).join('; ') || 'none'}`,
      sources: shared.map(i => i.id), type: 'observed',
    };
  }
  if (q.includes('summarize') && q.includes('evidence')) {
    if (!actor) return noAnswer(question);
    const rels = darkWebRelationships.filter(r => r.sourceEntity === actor.id || r.targetEntity === actor.id);
    return {
      answer: `Evidence for ${actor.id}: ${actor.associatedEvidence.length} items across ${rels.length} relationships. Confidence score: ${actor.confidenceScore}%. Primary motivation: ${actor.primaryMotivation}.`,
      sources: actor.associatedEvidence, type: 'interpretation',
    };
  }
  if (q.includes('summary') && q.includes('investigation')) {
    const inv = contextActorId ? darkWebInvestigations.find(i => i.seedActorId === contextActorId) : darkWebInvestigations[0];
    if (!inv) return noAnswer(question);
    return { answer: generateInvestigationSummary(inv.id).summary, sources: [], type: 'interpretation' };
  }
  if (q.includes('what changed')) {
    const events = darkWebTimeline.filter(t => !contextActorId || t.actorId === contextActorId).slice(-6);
    return { answer: `Recent changes: ${events.map(e => `${e.title} on ${new Date(e.time).toLocaleDateString()}`).join('; ')}.`, sources: events.map(e => e.id), type: 'observed' };
  }
  return noAnswer(question);

  function noAnswer(_q: string) {
    return { answer: `I cannot answer that from the available dataset. Ask about indicators, link evidence, infrastructure, timeline changes, or summaries for a known actor (e.g. ACTOR-001).`, sources: [], type: 'observed' as const };
  }
}

// ── 13. Investigation summary generation ────────────────────────
export interface InvestigationSummary {
  investigation: Investigation;
  executiveSummary: string;
  keyFindings: string[];
  confidenceBreakdown: { label: string; value: number }[];
  evidenceCount: number;
  relationshipCount: number;
  steps: InvestigationStep[];
  disclaimer: string;
}

export function generateInvestigationSummary(invId: string): { summary: string; detail: InvestigationSummary } {
  const inv = darkWebInvestigationById[invId] ?? darkWebInvestigations[0];
  const actor = darkWebActorsById[inv.seedActorId];
  const relatedRels = inv.steps.flatMap(s => s.relationshipIds).filter((v, i, a) => a.indexOf(v) === i);
  const rels = relatedRels.map(id => darkWebRelationshipsById[id]).filter(Boolean);
  const allEvidence = inv.steps.flatMap(s => s.evidenceIds).filter((v, i, a) => a.indexOf(v) === i);
  const ev = allEvidence.map(id => darkWebEvidenceById[id]).filter(Boolean);
  const confidenceBreakdown: { label: string; value: number }[] = [
    { label: 'Handle similarity', value: 75 },
    { label: 'PGP correlation', value: 100 },
    { label: 'Infrastructure overlap', value: 84 },
    { label: 'Behavior similarity', value: 88 },
    { label: 'Stylometry', value: 88 },
    { label: 'Timeline overlap', value: 94 },
  ];
  const summary = `Investigation ${inv.id} ("${inv.title}") traces ${actor?.handles[0] ?? inv.seedActorId} across ${inv.steps.length} analytical steps. Seed actor ${inv.seedActorId} (${actor?.confidenceScore}% confidence). Overall assessment: ${inv.confidence}% confidence in the derived actor chain, supported by ${ev.length} evidence items and ${rels.length} relationships.`;
  const detail: InvestigationSummary = {
    investigation: inv,
    executiveSummary: summary,
    keyFindings: inv.steps.map(s => `Step ${s.step}: ${s.title} — ${s.description}`),
    confidenceBreakdown,
    evidenceCount: ev.length,
    relationshipCount: rels.length,
    steps: inv.steps,
    disclaimer: 'All findings are derived from synthetic demonstration data. Correlations are analytical hypotheses, not proof of real-world identity.',
  };
  return { summary, detail };
}

// ── Re-export dataset slices for pages ──────────────────────────
export {
  threatActors, darkWebHandles, darkWebPgpKeys, darkWebWallets,
  darkWebInfrastructure, darkWebRelationships, darkWebEvidence,
  darkWebSources, darkWebTimeline, darkWebInvestigations, darkWebAlerts,
  darkWebActorsById, darkWebEvidenceById, darkWebRelationshipsById,
  darkWebHandlesById, darkWebInvestigationById, darkWebAlertById,
  type ThreatActor, type Handle, type PgpKey, type Wallet, type Infrastructure,
   type Relationship, type Evidence, type TimelineEvent, type Investigation,
   type Alert, type DarkWebSource, type InvestigationStep,
 };
