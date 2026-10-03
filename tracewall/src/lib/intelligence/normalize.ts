// ============================================================
// PhishNet — Intelligence normalization & duplicate detection.
//
// Different inputs refer to the same thing: "GhostWire", "ghostwire"
// and "GHOSTWIRE" are one handle; "7E3F-A1B2…" and "7e3fa1b2…" are
// one key. Import and analyst entry both flow through here so the
// central dataset never grows ambiguous duplicates.
//
// Original observed values are always preserved on the record —
// normalization only powers matching and searching.
// ============================================================
import type { IntelligenceDataset, DataState } from './types';

export function normalizeHandle(value: string): string {
  return (value || '').trim().replace(/^@+/, '').toLowerCase();
}

export function normalizeDomain(value: string): string {
  return (value || '').trim().toLowerCase().replace(/\s+/g, '').replace(/\.$/, '');
}

export function normalizePgp(value: string): string {
  return (value || '').replace(/\s+/g, '').replace(/-/g, '').toUpperCase();
}

/** Formats preserved: bc1/1/3… are case-sensitive, so only trimmed. */
export function normalizeWallet(value: string): string {
  return (value || '').trim();
}

export function normalizeText(value: string): string {
  return (value || '').replace(/\s+/g, ' ').trim();
}

export function normalizeActorRef(value: string): string {
  return (value || '').trim().replace(/^#/, '').toUpperCase();
}

/** Accepts ISO strings, "YYYY-MM-DD", and "Jan 2026" style free text. */
export function normalizeTimestamp(value: string | undefined | null, fallback?: string): string {
  const raw = (value ?? '').trim();
  if (!raw) return fallback ?? new Date().toISOString();
  const direct = new Date(raw);
  if (!Number.isNaN(direct.getTime())) return direct.toISOString();
  const monthYear = raw.match(/^([A-Za-z]{3,9})\s+(\d{4})$/);
  if (monthYear) {
    const parsed = new Date(`${monthYear[1]} 1, ${monthYear[2]}`);
    if (!Number.isNaN(parsed.getTime())) return parsed.toISOString();
  }
  return fallback ?? new Date().toISOString();
}

export function normalizeConfidence(value: unknown, fallback = 70): number {
  const numeric = typeof value === 'number' ? value : Number(String(value ?? '').replace(/[^0-9.]/g, ''));
  if (!Number.isFinite(numeric)) return fallback;
  return Math.max(0, Math.min(100, Math.round(numeric)));
}

export function normalizeSourceName(value: string): string {
  return (value || '').trim().replace(/\s+/g, ' ');
}

export function normalizeReliability(value: unknown, fallback = 75): number {
  return normalizeConfidence(value, fallback);
}

/** First 8 significant characters of a fingerprint — the analyst-visible short form. */
export function shortFingerprint(fingerprint: string): string {
  const flat = normalizePgp(fingerprint);
  return flat.slice(0, 8);
}

export interface DuplicateCandidate {
  kind: 'EXACT' | 'NORMALIZED' | 'SIMILAR';
  entityType: 'HANDLE' | 'PGP' | 'WALLET' | 'INFRASTRUCTURE' | 'ACTOR' | 'SOURCE' | 'MITRE_TTP' | 'CVE';
  existingId: string;
  existingLabel: string;
  existingActorId?: string | null;
  score: number;
  detail: string;
}

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (!m) return n;
  if (!n) return m;
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i++) {
    const curr = [i];
    for (let j = 1; j <= n; j++) {
      curr[j] = Math.min(
        prev[j] + 1,
        curr[j - 1] + 1,
        prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
    }
    prev = curr;
  }
  return prev[n];
}

export function similarity(a: string, b: string): number {
  const max = Math.max(a.length, b.length);
  if (!max) return 1;
  return 1 - levenshtein(a, b) / max;
}

/**
 * Find existing records that may be the same entity as the incoming one.
 * Ambiguous identities are reported, never auto-merged — the analyst
 * decides.
 */
export function findDuplicates(
  dataset: IntelligenceDataset,
  entityType: DuplicateCandidate['entityType'],
  value: string,
  platform?: string,
): DuplicateCandidate[] {
  const results: DuplicateCandidate[] = [];
  if (!value.trim()) return results;

  if (entityType === 'HANDLE') {
    const target = normalizeHandle(value);
    for (const handle of dataset.handles) {
      const sameNorm = normalizeHandle(handle.normalized || handle.value) === target;
      const sameValue = handle.value.toLowerCase() === value.trim().toLowerCase();
      const sim = similarity(normalizeHandle(handle.normalized || handle.value), target);
      if (!sameNorm && !sameValue && sim < 0.85) continue;
      results.push({
        kind: sameValue ? 'EXACT' : sameNorm ? 'NORMALIZED' : 'SIMILAR',
        entityType: 'HANDLE',
        existingId: handle.id,
        existingLabel: `${handle.value} (${handle.platform})`,
        existingActorId: handle.actorId ?? null,
        score: sameValue ? 100 : sameNorm ? 95 : Math.round(sim * 100),
        detail:
          sameValue
            ? `Handle "${handle.value}" already exists on ${handle.platform}`
            : sameNorm
              ? `Existing handle normalizes to the same value on ${handle.platform}`
              : `Similar spelling (${Math.round(sim * 100)}% Levenshtein) to ${handle.value} on ${handle.platform}`,
      });
    }
    if (platform) {
      for (const handle of dataset.handles) {
        if (handle.platform !== platform) continue;
        if (normalizeHandle(handle.normalized || handle.value) === normalizeHandle(value) && !results.some(r => r.existingId === handle.id)) {
          results.push({
            kind: 'EXACT',
            entityType: 'HANDLE',
            existingId: handle.id,
            existingLabel: `${handle.value} (${handle.platform})`,
            existingActorId: handle.actorId ?? null,
            score: 100,
            detail: `This platform already has a record for this handle`,
          });
        }
      }
    }
  }

  if (entityType === 'PGP') {
    const target = normalizePgp(value);
    for (const key of dataset.pgpKeys) {
      const existing = normalizePgp(key.fingerprint);
      if (existing === target || existing.startsWith(target) || target.startsWith(existing)) {
        results.push({
          kind: existing === target ? 'EXACT' : 'NORMALIZED',
          entityType: 'PGP',
          existingId: key.id,
          existingLabel: key.fingerprint,
          existingActorId: key.actorIds[0] ?? null,
          score: existing === target ? 100 : 80,
          detail:
            existing === target
              ? 'This PGP fingerprint is already recorded'
              : 'Matches an already-recorded PGP fingerprint prefix',
        });
      }
    }
  }

  if (entityType === 'WALLET') {
    const target = normalizeWallet(value);
    for (const wallet of dataset.wallets) {
      if (normalizeWallet(wallet.address) === target) {
        results.push({
          kind: 'EXACT',
          entityType: 'WALLET',
          existingId: wallet.id,
          existingLabel: wallet.address,
          existingActorId: wallet.actorIds[0] ?? null,
          score: 100,
          detail: 'This wallet address is already recorded',
        });
      }
    }
  }

  if (entityType === 'INFRASTRUCTURE') {
    const target = normalizeDomain(value);
    for (const infra of dataset.infrastructure) {
      const existing = normalizeDomain(infra.value);
      const same = existing === target;
      const sim = similarity(existing, target);
      if (!same && sim < 0.9) continue;
      results.push({
        kind: same ? 'EXACT' : 'SIMILAR',
        entityType: 'INFRASTRUCTURE',
        existingId: infra.id,
        existingLabel: `${infra.type} ${infra.value}`,
        existingActorId: infra.actorIds[0] ?? null,
        score: same ? 100 : Math.round(sim * 100),
        detail: same
          ? `${infra.type} ${infra.value} already exists in the dataset`
          : `Similar to existing ${infra.type} ${infra.value} (${Math.round(sim * 100)}%)`,
      });
    }
  }

  if (entityType === 'ACTOR') {
    const target = normalizeActorRef(value);
    for (const actor of dataset.actors) {
      if (actor.id.toUpperCase() === target || actor.aliases.some(alias => normalizeHandle(alias) === normalizeHandle(value))) {
        results.push({
          kind: 'EXACT',
          entityType: 'ACTOR',
          existingId: actor.id,
          existingLabel: `${actor.id} — ${actor.aliases[0] ?? actor.id}`,
          score: 100,
          detail: 'A threat actor with this identifier or alias already exists',
        });
      }
    }
  }

  if (entityType === 'SOURCE') {
    const target = normalizeSourceName(value).toLowerCase();
    for (const source of dataset.sources) {
      if (source.name.toLowerCase() === target) {
        results.push({
          kind: 'EXACT',
          entityType: 'SOURCE',
          existingId: source.id,
          existingLabel: source.name,
          score: 100,
          detail: 'A source with this name already exists',
        });
      }
    }
  }

  if (entityType === 'MITRE_TTP') {
    const target = value.trim().toUpperCase();
    for (const ttp of dataset.mitreTtps ?? []) {
      if (ttp.techniqueId.toUpperCase() === target) {
        results.push({
          kind: 'EXACT',
          entityType: 'MITRE_TTP',
          existingId: ttp.techniqueId,
          existingLabel: `${ttp.techniqueId} — ${ttp.name}`,
          score: 100,
          detail: 'This ATT&CK technique is already recorded',
        });
      }
    }
  }

  if (entityType === 'CVE') {
    const target = value.trim().toUpperCase();
    for (const cve of dataset.cves ?? []) {
      if (cve.cveId.toUpperCase() === target) {
        results.push({
          kind: 'EXACT',
          entityType: 'CVE',
          existingId: cve.cveId,
          existingLabel: cve.cveId,
          score: 100,
          detail: 'This CVE is already recorded',
        });
      }
    }
  }

  return results.sort((a, b) => b.score - a.score);
}

export function nextId(prefix: string, existing: Iterable<string>): string {
  let counter = 1;
  const taken = new Set(existing);
  let candidate = `${prefix}-${String(counter).padStart(3, '0')}`;
  while (taken.has(candidate)) {
    counter += 1;
    candidate = `${prefix}-${String(counter).padStart(3, '0')}`;
  }
  return candidate;
}

export function withDataState<T extends object>(record: T, state: DataState): T & { dataState: DataState } {
  return { ...record, dataState: state };
}
