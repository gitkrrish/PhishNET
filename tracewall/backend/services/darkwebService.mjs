import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const SEED_PATH = join(__dirname, '..', 'database', 'darkwebSeed.json');

let cache = null;

export async function loadDataset() {
  if (cache) return cache;
  const raw = await readFile(SEED_PATH, 'utf8');
  cache = JSON.parse(raw);
  return cache;
}

export function getActors() {
  return loadDataset().then(d => d.actors.map(stripSynthetic));
}

export function getActorById(id) {
  return loadDataset().then(d => {
    const actor = d.actors.find(a => a.id === id);
    return actor ? { id: actor.id, aliases: actor.aliases, confidenceScore: actor.confidenceScore, status: actor.status, activityLevel: actor.activityLevel, firstSeen: actor.firstSeen, lastSeen: actor.lastSeen, platforms: actor.platforms, relatedActorIds: actor.relatedActorIds, associatedEvidence: actor.associatedEvidence, primaryMotivation: actor.primaryMotivation } : null;
  });
}

export function getHandles() {
  return loadDataset().then(d => d.handles);
}

export function getRelationships() {
  return loadDataset().then(d => d.relationships);
}

export function getEvidence() {
  return loadDataset().then(d => d.evidence);
}

export function getTimeline(query = {}) {
  return loadDataset().then(d => {
    let items = d.timeline;
    if (query.actorId) items = items.filter(t => t.actorId === query.actorId);
    if (query.type) items = items.filter(t => t.type === query.type);
    if (query.from) items = items.filter(t => t.time >= query.from);
    if (query.to) items = items.filter(t => t.time <= query.to);
    return items.sort((a, b) => new Date(b.time) - new Date(a.time));
  });
}

export async function searchPgp(fingerprint) {
  const d = await loadDataset();
  const fp = (fingerprint || '').replace(/\s+/g, '').toUpperCase();
  return d.pgpKeys.filter(k => k.fingerprint.replace(/\s+/g, '').toUpperCase().startsWith(fp.slice(0, 12)) || fp.includes(k.fingerprint.replace(/\s+/g, '').slice(0, 8)));
}

export async function searchWallet(address) {
  const d = await loadDataset();
  const q = (address || '').toLowerCase();
  return d.wallets.filter(w => w.address.toLowerCase() === q || w.address.toLowerCase().startsWith(q.slice(0, 12)));
}

export async function searchInfrastructure(q) {
  const d = await loadDataset();
  const term = (q || '').toLowerCase();
  return d.infrastructure.filter(i => i.value.toLowerCase().includes(term) || (i.hostingProvider && i.hostingProvider.toLowerCase().includes(term)) || (i.asn && i.asn.toLowerCase().includes(term)));
}

export async function searchHandles(q) {
  const d = await loadDataset();
  const term = (q || '').toLowerCase();
  return d.handles.filter(h => h.value.toLowerCase().includes(term) || h.normalized.toLowerCase().includes(term));
}

export async function searchAll(q) {
  const d = await loadDataset();
  const term = (q || '').toLowerCase();
  const actors = d.actors.filter(a => a.id.toLowerCase().includes(term) || a.aliases.some(al => al.toLowerCase().includes(term)));
  return {
    actors,
    handles: d.handles.filter(h => h.value.toLowerCase().includes(term) || h.normalized.toLowerCase().includes(term)),
    relationships: d.relationships.filter(r => r.sourceEntity.toLowerCase().includes(term) || r.targetEntity.toLowerCase().includes(term) || r.type.toLowerCase().includes(term)),
    evidence: d.evidence.filter(e => e.id.toLowerCase().includes(term) || e.provenance.toLowerCase().includes(term)),
  };
}

export function getInvestigations() {
  return loadDataset().then(d => d.investigations);
}

export function getInvestigationById(id) {
  return loadDataset().then(d => d.investigations.find(i => i.id === id));
}

export function getAlerts() {
  return loadDataset().then(d => d.alerts);
}

export function getSources() {
  return loadDataset().then(d => d.sources);
}

export function getMonitoring() {
  return loadDataset().then(d => d.monitoring);
}

export function getReports() {
  return loadDataset().then(d => d.reports);
}

export function getConfidenceBreakdown() {
  return loadDataset().then(d => d.confidenceBreakdown);
}

export async function analyze(payload) {
  const d = await loadDataset();
  const { actorId, fingerprint, wallet, domain, investigationId } = payload || {};
  const actor = actorId ? d.actors.find(a => a.id === actorId) : null;
  let results = { summary: '', findings: [], confidence: 0, evidenceCount: 0, relationshipCount: 0 };

  if (investigationId) {
    const inv = d.investigations.find(i => i.id === investigationId);
    if (inv) {
      results.summary = `Investigation ${inv.id} ("${inv.title}") traces ${inv.steps.length} analytical steps from seed actor ${inv.seedActorId}.`;
      results.findings = inv.steps.map(s => `Step ${s.step}: ${s.title}`);
      results.confidence = inv.confidence;
      results.evidenceCount = new Set(inv.steps.flatMap(s => s.evidenceIds)).size;
      results.relationshipCount = new Set(inv.steps.flatMap(s => s.relationshipIds)).size;
      return results;
    }
  }

  if (actor) {
    results.summary = `${actor.id} (${actor.aliases[0]}) is ${actor.status} with ${actor.confidenceScore}% confidence. Motive: ${actor.primaryMotivation}.`;
    results.findings = [`Active on ${actor.platforms.length} platforms`, `Handles: ${actor.handles.join(', ')}`, `PGP fingerprints: ${actor.pgpFingerprints.length}`, `Wallets: ${actor.walletAddrs.length}`, `Associated evidence: ${actor.associatedEvidence.length}`];
    results.confidence = actor.confidenceScore;
    results.evidenceCount = actor.associatedEvidence.length;
    const rels = d.relationships.filter(r => r.sourceEntity === actor.id || r.targetEntity === actor.id || actor.handles.includes(r.sourceEntity) || actor.handles.includes(r.targetEntity));
    results.relationshipCount = rels.length;
    return results;
  }

  if (fingerprint) {
    const fp = fingerprint.replace(/\s+/g, '').toUpperCase();
    const keys = d.pgpKeys.filter(k => k.fingerprint.replace(/\s+/g, '').toUpperCase().startsWith(fp.slice(0, 12)));
    results.summary = `PGP search matched ${keys.length} key(s).`;
    results.findings = keys.map(k => `${k.id}: ${k.fingerprint} (actors: ${k.actorIds.join(', ')})`);
    results.confidence = 90;
    results.evidenceCount = keys.length;
    return results;
  }

  if (wallet) {
    const q = wallet.toLowerCase();
    const ws = d.wallets.filter(w => w.address.toLowerCase() === q || w.address.toLowerCase().startsWith(q.slice(0, 12)));
    results.summary = `Wallet search matched ${ws.length} wallet(s).`;
    results.findings = ws.map(w => `${w.id}: ${w.address} (actors: ${w.actorIds.join(', ')})`);
    results.confidence = 90;
    results.evidenceCount = ws.length;
    return results;
  }

  if (domain) {
    const ds = d.infrastructure.filter(i => i.value.toLowerCase().includes(domain.toLowerCase()));
    results.summary = `Domain/infra search matched ${ds.length} item(s).`;
    results.findings = ds.map(i => `${i.id}: ${i.value} (${i.type}) actors: ${i.actorIds.join(', ')}`);
    results.confidence = 85;
    results.evidenceCount = ds.length;
    return results;
  }

  results.summary = 'No matching analysis target. Provide actorId, fingerprint, wallet, domain, or investigationId.';
  return results;
}

function stripSynthetic(actor) {
  const { isSynthetic, ...rest } = actor;
  return rest;
}
