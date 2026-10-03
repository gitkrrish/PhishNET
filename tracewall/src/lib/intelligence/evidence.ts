// ============================================================
// Evidence integrity and content inspection.
//
// Evidence is the part of a dataset that ends up in a court, so the
// rule here is narrow: report what can be established from the bytes
// and the recorded fields, and refuse to fill the rest in. Three
// distinctions are kept explicit throughout.
//
//   Observation vs. collection. `timestamp` is when the content was
//   observed; `collectionTimestamp` is when this model captured it.
//   A long gap between them is a collection-lag finding, not evidence
//   that anything was altered.
//
//   Presence vs. proof. A hash records an identity claim about a
//   file. Without the file, the hash cannot be recomputed, so nothing
//   here reports that evidence content is unaltered — only that its
//   recorded digest is well formed.
//
//   Structure vs. attribution. EXIF and provenance give strong
//   structural clues about capture. A camera model, a timezone or a
//   quoted listing title is a lead for a human, not a conclusion
//   about who was present.
// ============================================================

// ── Hash analysis ──────────────────────────────────────────────

/** Digest size in hex characters for the algorithms seen in practice. */
const HASH_LENGTHS: Record<string, number> = {
  md5: 32, sha1: 40, sha256: 64, sha384: 96, sha512: 128,
};

export type HashVerdict = 'VALID' | 'ALGORITHM_UNKNOWN' | 'LENGTH_INVALID' | 'CHARSET_INVALID' | 'MALFORMED' | 'MISSING';

export interface HashCheck {
  /** Digest exactly as recorded. */
  recorded: string;
  algorithm: string | null;
  normalized: string;
  verdict: HashVerdict;
  detail: string;
  /** True only when the digest is well formed, not when it verifies anything. */
  structurallyValid: boolean;
}

/**
 * Check that a recorded digest is well formed. This says nothing
 * about whether the evidence file still hashes to this value — that
 * requires the file, which this record does not hold.
 */
export function validateEvidenceHash(raw: string): HashCheck {
  const recorded = typeof raw === 'string' ? raw.trim() : '';
  const base = { recorded, normalized: '', algorithm: null as string | null, structurallyValid: false };
  if (!recorded) {
    return { ...base, verdict: 'MISSING', detail: 'No digest is recorded, so this evidence item has no integrity claim at all.' };
  }
  const separator = recorded.indexOf(':');
  const algorithm = separator > 0 ? recorded.slice(0, separator).toLowerCase() : null;
  const digest = separator > 0 ? recorded.slice(separator + 1) : recorded;
  const normalized = digest.toLowerCase();

  if (separator > 0 && !/^[a-z0-9-]+$/.test(algorithm!)) {
    return { ...base, algorithm, normalized, verdict: 'MALFORMED', detail: `The digest prefix "${recorded.slice(0, separator)}" is not an algorithm name in the form "name:value".` };
  }
  if (!/^[0-9a-f]*$/.test(normalized)) {
    return { ...base, algorithm, normalized, verdict: 'CHARSET_INVALID', detail: 'The digest contains characters outside 0-9 and a-f, so it is not a hex digest as recorded.' };
  }
  if (!algorithm) {
    return { ...base, normalized, verdict: 'ALGORITHM_UNKNOWN', detail: `A ${normalized.length}-character hex digest is recorded with no algorithm prefix, so the intended algorithm cannot be confirmed.` };
  }
  const expected = HASH_LENGTHS[algorithm];
  if (!expected) {
    return { ...base, algorithm, normalized, verdict: 'ALGORITHM_UNKNOWN', detail: `"${algorithm}" is not a digest algorithm this tool recognises. The recorded value was left unjudged.` };
  }
  if (normalized.length !== expected) {
    return { ...base, algorithm, normalized, verdict: 'LENGTH_INVALID', detail: `${algorithm.toUpperCase()} is ${expected} hex characters, but this record has ${normalized.length}. A digest of the wrong length cannot be a ${algorithm.toUpperCase()} value.` };
  }
  return {
    ...base, algorithm, normalized, verdict: 'VALID', structurallyValid: true,
    detail: `Well-formed ${algorithm.toUpperCase()} digest (${expected} hex characters). This confirms the recorded value is shaped like a digest; the file itself is not stored here, so it cannot be re-hashed to confirm the evidence is unaltered.`,
  };
}

/** Evidence records that carry the same digest. */
export function duplicateDigests(records: Array<{ id: string; hash: string }>): Map<string, string[]> {
  const seen = new Map<string, string[]>();
  for (const record of records) {
    const check = validateEvidenceHash(record.hash);
    if (!check.structurallyValid) continue;
    seen.set(check.normalized, [...(seen.get(check.normalized) ?? []), record.id]);
  }
  return new Map([...seen.entries()].filter(([, ids]) => ids.length > 1));
}

// ── Provenance parsing ─────────────────────────────────────────

export type ProvenanceKind = 'SOURCE' | 'CONTAINER' | 'REFERENCE';

export interface ProvenanceSegment {
  raw: string;
  kind: ProvenanceKind;
  /** A quoted human-readable title, when the segment carries one. */
  quotedTitle: string | null;
  /** Central-model identifiers mentioned in this segment. */
  entityRefs: string[];
  /** The trailing clause, e.g. "post by shadowfox". */
  clause: string | null;
}

const ENTITY_REF_PATTERNS: Array<{ kind: string; re: RegExp }> = [
  { kind: 'actor', re: /\bACTOR-\d+\b/g },
  { kind: 'pgp', re: /\bPGP-\d+\b/g },
  { kind: 'wallet', re: /\bWAL-\d+\b/g },
  { kind: 'transaction', re: /\bTX-\d+\b/g },
  { kind: 'handle', re: /\bHND-\d+\b/g },
  { kind: 'infrastructure', re: /\b(INF|DOM)-[\w-]+\b/g },
  { kind: 'cve', re: /\bCVE-\d{4}-\d+\b/g },
  { kind: 'technique', re: /\bT\d{4}(?:\.\d{3})?\b/g },
];

/** Central-model identifiers referenced anywhere in a string. */
export function extractEntityRefs(text: string): Array<{ kind: string; id: string }> {
  const out: Array<{ kind: string; id: string }> = [];
  for (const { kind, re } of ENTITY_REF_PATTERNS) {
    for (const match of text.matchAll(new RegExp(re.source, 'g'))) {
      if (!out.some(x => x.id === match[0])) out.push({ kind, id: match[0] });
    }
  }
  return out;
}

const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const URLISH = /\bhttps?:\/\/[^\s"'<>]+/g;
const EMAIL = /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g;
const DOMAIN = /\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:com|net|org|io|ru|onion|xyz|top|cc|su|biz|info|me|club)\b/gi;

/**
 * Split a provenance string into its breadcrumb path. The seed format
 * is "source › container "title" › clause", and the clause usually
 * carries the corroborating detail worth surfacing.
 */
export function parseProvenance(provenance: string): ProvenanceSegment[] {
  if (!provenance) return [];
  return provenance
    .split(/\s*›\s*/)
    .map((raw, index): ProvenanceSegment => {
      const quoted = /"([^"]+)"/.exec(raw);
      return {
        raw,
        // The first crumb is the source itself; later ones are containers
        // unless they name an actor or an action.
        kind: index === 0 ? 'SOURCE' : quoted || /by |signing|references|contains/i.test(raw) ? 'REFERENCE' : 'CONTAINER',
        quotedTitle: quoted ? quoted[1] : null,
        entityRefs: extractEntityRefs(raw).map(r => r.id),
        clause: index === 0 ? null : raw,
      };
    });
}

/** Observable strings in free text that are worth an analyst's attention. */
export function extractIndicators(text: string): { ipv4: string[]; urls: string[]; emails: string[]; domains: string[] } {
  const uniq = (m: Iterable<string>) => Array.from(new Set(Array.from(m)));
  return {
    ipv4: uniq((text ?? '').match(IPV4) ?? []),
    urls: uniq((text ?? '').match(URLISH) ?? []),
    emails: uniq((text ?? '').match(EMAIL) ?? []),
    domains: uniq((text ?? '').match(DOMAIN) ?? []),
  };
}

// ── Observation and collection timing ──────────────────────────

export interface CustodyAnalysis {
  observationLagDays: number | null;
  /** Records sharing this record's exact collection minute. */
  collectionBatch: string | null;
  collectionBatchSize: number;
  collectionBatchPeers: string[];
  /** Findings, each stating what the timing does and does not show. */
  findings: Array<{ label: string; detail: string; tone: 'ok' | 'warn' | 'info' }>;
}

export function analyseCustody(
  record: { id: string; timestamp: string; collectionTimestamp: string; evidenceType: string },
  peers: Array<{ id: string; collectionTimestamp: string }>,
): CustodyAnalysis {
  const observed = Date.parse(record.timestamp);
  const collected = Date.parse(record.collectionTimestamp);
  const findings: CustodyAnalysis['findings'] = [];

  if (!Number.isFinite(observed) || !Number.isFinite(collected)) {
    return {
      observationLagDays: null, collectionBatch: null, collectionBatchSize: 0, collectionBatchPeers: [],
      findings: [{
        label: 'Unreadable timestamps', tone: 'warn',
        detail: 'One or both timestamps on this record could not be parsed, so no collection interval can be computed. The raw values are shown unaltered above.',
      }],
    };
  }

  const lagDays = (collected - observed) / 86_400_000;
  const batch = Number.isFinite(collected) ? record.collectionTimestamp.slice(0, 16) : null;
  const batchPeers = batch
    ? peers.filter(p => p.id !== record.id && p.collectionTimestamp.slice(0, 16) === batch).map(p => p.id)
    : [];

  if (lagDays < 0) {
    findings.push({
      label: 'Observed after it was collected', tone: 'warn',
      detail: 'The observation timestamp is later than the collection timestamp, which is not a possible order of events. At least one of the two fields is wrong; neither should be relied on until reconciled.',
    });
  } else if (lagDays > 180) {
    findings.push({
      label: 'Long collection interval', tone: 'info',
      detail: `This content was observed ${Math.round(lagDays)} days before it was captured. A long interval means the earlier item was found retrospectively, so the surrounding context may since have changed. It is not a sign of tampering.`,
    });
  } else if (lagDays < 1) {
    findings.push({
      label: 'Captured close to observation', tone: 'ok',
      detail: `Captured within ${lagDays < 1/24 ? `${Math.round(lagDays * 1440)} minutes` : `${Math.round(lagDays * 24)} hours`} of observation, so little could have changed in between.`,
    });
  }

  if (batchPeers.length > 0) {
    findings.push({
      label: 'Captured in a batch', tone: 'info',
      detail: `${batchPeers.length} other record(s) share this exact collection minute (${batch}). Collection timestamps therefore record when a sweep happened, not when each item was individually captured. Do not read ordering into them.`,
    });
  }

  return {
    observationLagDays: lagDays,
    collectionBatch: batch,
    collectionBatchSize: batchPeers.length + 1,
    collectionBatchPeers: batchPeers,
    findings,
  };
}

// ── Content inspection ─────────────────────────────────────────

export type DetectedContent = 'JPEG' | 'PNG' | 'GIF' | 'WEBP' | 'PDF' | 'ZIP' | 'GZIP' | 'ELF' | 'TEXT' | 'HTML' | 'JSON' | 'SVG' | 'BMP' | 'TIFF' | 'UNKNOWN';

export interface ExifField {
  tag: string;
  label: string;
  value: string;
}

export interface ExifResult {
  present: boolean;
  /** Fields read, in file order. */
  fields: ExifField[];
  /** True when a GPS IFD is present, even if its values are absent. */
  hasGps: boolean;
  /** Fields that carry a time. */
  times: string[];
  warnings: string[];
}

export interface ContentInspection {
  detected: DetectedContent;
  magic: string;
  byteLength: number;
  /** A short hex preview of the leading bytes. */
  preview: string;
  exif: ExifResult | null;
  /** Printable runs found in a text-like file, capped. */
  text: string | null;
  /** Entity references and observables recovered from text. */
  indicators: ReturnType<typeof extractIndicators> | null;
  entityRefs: Array<{ kind: string; id: string }>;
  /** Strings that suggest the file was produced by a specific tool. */
  toolHints: string[];
  notes: string[];
}

function hexPreview(bytes: Uint8Array, count = 12): string {
  return Array.from(bytes.subarray(0, count), b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
}

/** Identify a file from its leading bytes. */
export function detectContentType(bytes: Uint8Array): { type: DetectedContent; magic: string } {
  if (bytes.length === 0) return { type: 'UNKNOWN', magic: 'empty' };
  const b = bytes;
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return { type: 'JPEG', magic: 'FF D8 FF' };
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return { type: 'PNG', magic: '89 50 4E 47' };
  if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46) return { type: 'GIF', magic: '47 49 46' };
  if (b[0] === 0x42 && b[1] === 0x4d) return { type: 'BMP', magic: '42 4D' };
  if (b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46) return { type: 'PDF', magic: '25 50 44 46' };
  if (b[0] === 0x1f && b[1] === 0x8b) return { type: 'GZIP', magic: '1F 8B' };
  if (b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return { type: 'ELF', magic: '7F 45 4C 46' };
  if (b[0] === 0x50 && b[1] === 0x4b && (b[2] === 0x03 || b[2] === 0x05)) return { type: 'ZIP', magic: '50 4B' };
  if (b[0] === 0x49 && b[1] === 0x49 && b[2] === 0x2a) return { type: 'TIFF', magic: '49 49 2A' };
  if (b[0] === 0x4d && b[1] === 0x4d) return { type: 'TIFF', magic: '4D 4D 2A' };
  if (
    b.length > 12 && b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 &&
    b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50
  ) return { type: 'WEBP', magic: 'RIFF....WEBP' };
  const head = new TextDecoder('utf-8', { fatal: false }).decode(b.subarray(0, 512));
  if (/^\s*<\?xml|^\s*<svg/i.test(head)) return { type: 'SVG', magic: '<svg or <?xml' };
  if (/^\s*<!doctype html|^\s*<html/i.test(head)) return { type: 'HTML', magic: '<!doctype html or <html' };
  try {
    JSON.parse(head.slice(head.lastIndexOf('}') + 1) || '{}');
    if (/^[\s]*[{[]/.test(head)) return { type: 'JSON', magic: '{ or [ start' };
  } catch { /* not JSON */ }
  if (head.includes('\0')) return { type: 'UNKNOWN', magic: 'contains NUL — binary' };
  return { type: 'TEXT', magic: 'printable' };
}

// EXIF / TIFF IFD field names, from the Exif 2.3 and TIFF 6.0 registries.
const EXIF_TAGS: Record<number, string> = {
  0x010e: 'ImageDescription', 0x010f: 'Make', 0x0110: 'Model',
  0x0112: 'Orientation', 0x011a: 'XResolution', 0x011b: 'YResolution',
  0x0128: 'ResolutionUnit', 0x0131: 'Software', 0x0132: 'DateTime',
  0x013b: 'Artist', 0x8298: 'Copyright', 0x8769: 'ExifIFDPointer',
  0x8825: 'GPSIFDPointer', 0x829a: 'ExposureTime', 0x829d: 'FNumber',
  0x8827: 'ISOSpeedRatings', 0x9003: 'DateTimeOriginal',
  0x9004: 'DateTimeDigitized', 0x920a: 'FocalLength',
  0xa002: 'PixelXDimension', 0xa003: 'PixelYDimension',
  0xa402: 'ExposureMode', 0xa403: 'WhiteBalance', 0xa406: 'SceneCaptureType',
};

const GPS_TAGS: Record<number, string> = {
  0x0001: 'GPSLatitudeRef', 0x0002: 'GPSLatitude', 0x0003: 'GPSLongitudeRef',
  0x0004: 'GPSLongitude', 0x0005: 'GPSAltitudeRef', 0x0006: 'GPSAltitude',
};

/** Decode a rational number as stored in EXIF. */
function readRational(view: DataView, offset: number): number {
  if (offset + 8 > view.byteLength) return NaN;
  const numerator = view.getUint32(offset, false);
  const denominator = view.getUint32(offset + 4, false);
  return denominator === 0 ? NaN : numerator / denominator;
}

/** Read one IFD, returning its entries and any sub-IFD pointers found. */
function readIfd(
  view: DataView,
  tiffStart: number,
  ifdOffset: number,
  tags: Record<number, string>,
  little: boolean,
  fields: ExifField[],
  warnings: string[],
  maxEntries = 64,
): { nextIfd: number; exifPointer: number | null; gpsPointer: number | null } {
  const base = tiffStart + ifdOffset;
  if (base + 2 > view.byteLength) {
    warnings.push('An image directory offset points past the end of the file.');
    return { nextIfd: 0, exifPointer: null, gpsPointer: null };
  }
  const count = view.getUint16(base, little);
  if (count > maxEntries) {
    warnings.push(`An image directory claims ${count} entries, which exceeds the ${maxEntries} this parser will read, so it was not walked.`);
    return { nextIfd: 0, exifPointer: null, gpsPointer: null };
  }
  let exifPointer: number | null = null;
  let gpsPointer: number | null = null;
  for (let i = 0; i < count; i++) {
    const entry = base + 2 + i * 12;
    if (entry + 12 > view.byteLength) {
      warnings.push('An image directory entry runs past the end of the file; parsing stopped early.');
      break;
    }
    const tag = view.getUint16(entry, little);
    const type = view.getUint16(entry + 2, little);
    const valueCount = view.getUint32(entry + 4, little);
    const valueOffset = entry + 8;
    const typeSize = [0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8][type] ?? 0;
    const totalBytes = typeSize * valueCount;
    // Values of four bytes or fewer are stored inline in the entry.
    const dataAt = totalBytes > 4 ? tiffStart + view.getUint32(valueOffset, little) : valueOffset;

    const label = tags[tag] ?? `Tag 0x${tag.toString(16)}`;
    if (tag === 0x8769) { exifPointer = view.getUint32(valueOffset, little); continue; }
    if (tag === 0x8825) { gpsPointer = view.getUint32(valueOffset, little); continue; }

    let value: string;
    if (type === 2) {
      // ASCII, NUL-terminated, and often padded.
      let text = '';
      for (let k = 0; k < valueCount && dataAt + k < view.byteLength; k++) {
        const ch = view.getUint8(dataAt + k);
        if (ch === 0) break;
        text += String.fromCharCode(ch);
      }
      value = text.trim();
    } else if (type === 3) {
      value = Array.from({ length: Math.min(valueCount, 8) }, (_, k) => view.getUint16(dataAt + k * 2, little)).join(', ');
    } else if (type === 4 && totalBytes === 8) {
      value = String(readRational(view, dataAt));
    } else if (type === 5 && totalBytes === 8) {
      value = `${readRational(view, dataAt)} / ${readRational(view, dataAt + 8)}`;
    } else if (type === 1) {
      value = Array.from({ length: Math.min(valueCount, 8) }, (_, k) => view.getUint8(dataAt + k)).join(', ');
    } else {
      value = `<${typeCountLabel(type)}, ${valueCount} value(s)>`;
    }
    if (value && !/^0(\.0+)?$/.test(value)) fields.push({ tag: `0x${tag.toString(16).padStart(4, '0')}`, label, value });
  }
  const nextAt = base + 2 + count * 12;
  const nextIfd = nextAt + 4 <= view.byteLength ? view.getUint32(nextAt, little) : 0;
  return { nextIfd, exifPointer, gpsPointer };
}

function typeCountLabel(type: number): string {
  return ['undefined', 'BYTE', 'ASCII', 'SHORT', 'LONG', 'RATIONAL', 'SBYTE', 'UNDEFINED', 'SSHORT', 'SLONG', 'SRATIONAL', 'FLOAT', 'DOUBLE'][type] ?? `type ${type}`;
}

/**
 * Extract EXIF from a JPEG. Only structural fields are read; no
 * pixel data is touched, so this is safe to run on a seized file.
 */
export function parseExif(bytes: Uint8Array): ExifResult | null {
  if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const fields: ExifField[] = [];
  const warnings: string[] = [];
  let offset = 2;
  let tiffStart = -1;
  let little = true;
  let exifPointer: number | null = null;
  let gpsPointer: number | null = null;
  let thumbnailBytes = 0;

  while (offset + 4 <= bytes.length) {
    if (bytes[offset] !== 0xff) { offset++; continue; }
    const marker = bytes[offset + 1];
    if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) { offset += 2; continue; }
    if (marker === 0xda) break; // start of scan — metadata ends here
    const segmentLength = view.getUint16(offset + 2, false);
    if (segmentLength < 2) { warnings.push('A JPEG segment declared a length below 2; the marker chain is malformed.'); break; }
    if (marker === 0xe1 && bytes[offset + 4] === 0x45 && bytes[offset + 5] === 0x78 && bytes[offset + 6] === 0x69 && bytes[offset + 7] === 0x66) {
      tiffStart = offset + 10;
      if (tiffStart + 8 <= bytes.length) {
        const byteOrder = view.getUint16(tiffStart, false);
        if (byteOrder === 0x4949) little = true;
        else if (byteOrder === 0x4d4d) little = false;
        else warnings.push('The TIFF byte-order marker is neither little- nor big-endian, so fields cannot be read.');
      }
      break;
    }
    offset += 2 + segmentLength;
  }

  if (tiffStart < 0) return { present: false, fields, hasGps: false, times: [], warnings: ['No EXIF APP1 segment is present in this JPEG. Cameras and editors often strip it, so its absence is not itself notable.'] };
  if (view.getUint16(tiffStart, false) !== 0x4949 && view.getUint16(tiffStart, false) !== 0x4d4d) {
    return { present: false, fields, hasGps: false, times: [], warnings: ['An EXIF segment is present but its TIFF header is unreadable.'] };
  }

  const ifd0 = view.getUint32(tiffStart + 4, little);
  const primary = readIfd(view, tiffStart, ifd0, EXIF_TAGS, little, fields, warnings);
  exifPointer = primary.exifPointer;
  gpsPointer = primary.gpsPointer;

  if (primary.nextIfd) {
    thumbnailBytes = primary.nextIfd;
  }
  if (exifPointer !== null) {
    readIfd(view, tiffStart, exifPointer, EXIF_TAGS, little, fields, warnings);
  }
  let hasGps = false;
  if (gpsPointer !== null) {
    const gpsFields: ExifField[] = [];
    readIfd(view, tiffStart, gpsPointer, GPS_TAGS, little, gpsFields, warnings);
    hasGps = gpsFields.length > 0;
    fields.push(...gpsFields);
  }

  return {
    present: true,
    fields,
    hasGps,
    times: fields.filter(f => /DateTime/i.test(f.label)).map(f => f.value),
    warnings: thumbnailBytes
      ? [...warnings, `An embedded thumbnail of ${thumbnailBytes} bytes is present and can be extracted separately.`]
      : warnings,
  };
}

const TOOL_PATTERNS: Array<{ label: string; re: RegExp }> = [
  { label: 'Photoshop', re: /photoshop|adobe\s*photoshop/i },
  { label: 'GIMP', re: /\bgimp\b/i },
  { label: 'Lightroom', re: /\blightroom\b/i },
  { label: 'Figma', re: /\bfigma\b/i },
  { label: 'Paint.NET', re: /paint\.?net/i },
  { label: 'XnView', re: /\bxnview\b/i },
  { label: 'OBS Studio', re: /\bobs\b.{0,12}(studio|screen|record)/i },
  { label: 'Snipping Tool', re: /snipping tool/i },
  { label: 'ScreenToGif', re: /screentogif/i },
  { label: 'Windows', re: /\bwindows\b/i },
  { label: 'macOS', re: /\bmacos\b|\bmac ?os\b/i },
  { label: 'Android', re: /\bandroid\b/i },
  { label: 'ExifTool', re: /exiftool/i },
];

/** Inspect raw bytes: type, structure, EXIF and any readable text. */
export function inspectContent(bytes: Uint8Array): ContentInspection {
  const { type, magic } = detectContentType(bytes);
  const notes: string[] = [];
  const exif = type === 'JPEG' ? parseExif(bytes) : null;
  if (exif) notes.push(...exif.warnings);

  const toolHints: string[] = [];
  let text: string | null = null;
  if (type === 'TEXT' || type === 'HTML' || type === 'JSON' || type === 'SVG') {
    text = new TextDecoder('utf-8', { fatal: false }).decode(bytes).slice(0, 20_000);
    for (const { label, re } of TOOL_PATTERNS) {
      if (re.test(text)) toolHints.push(label);
    }
    if (exif) for (const f of exif.fields) for (const { label, re } of TOOL_PATTERNS) if (re.test(f.value)) toolHints.push(label);
  } else {
    // Binary files still leak tool names through their metadata segments.
    const strings = printableRuns(bytes);
    for (const { label, re } of TOOL_PATTERNS) {
      if (strings.some(s => re.test(s))) toolHints.push(label);
    }
    text = strings.join('\n') || null;
  }
  if (toolHints.length) {
    notes.push('Tool hints come from metadata strings, not from a cryptographic signature, so they can be forged.');
  }

  return {
    detected: type,
    magic,
    byteLength: bytes.length,
    preview: hexPreview(bytes),
    exif,
    text,
    indicators: text ? extractIndicators(text) : null,
    entityRefs: text ? extractEntityRefs(text) : [],
    toolHints: Array.from(new Set(toolHints)),
    notes,
  };
}

/**
 * Extract printable runs from binary data, which is where tools leave their
 * names. The minimum run length is short on purpose: a software field such as
 * "Adobe Photoshop" is only a few characters, and a long threshold would
 * silently discard exactly the strings this is looking for.
 */
function printableRuns(bytes: Uint8Array, minLength = 4, cap = 200): string[] {
  const out: string[] = [];
  let current = '';
  for (const byte of bytes) {
    if (byte >= 0x20 && byte < 0x7f) {
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= minLength) out.push(current);
      current = '';
      if (out.length >= cap) break;
    }
  }
  if (current.length >= minLength) out.push(current);
  return out;
}

// ── Bundle ─────────────────────────────────────────────────────

export interface EvidenceAnalysis {
  id: string;
  hashCheck: HashCheck;
  provenance: ProvenanceSegment[];
  indicators: ReturnType<typeof extractIndicators>;
  entityRefs: Array<{ kind: string; id: string }>;
  custody: CustodyAnalysis;
  /** Other records carrying the same digest. */
  duplicateIds: string[];
  /** True when no raw content is attached, so nothing was inspected. */
  noContentStored: boolean;
  findings: Array<{ label: string; detail: string; tone: 'ok' | 'warn' | 'info' }>;
  caveats: string[];
}

export function evidenceAnalysis(
  record: {
    id: string; hash: string; provenance: string; timestamp: string;
    collectionTimestamp: string; evidenceType: string; source?: string;
  },
  all: Array<{ id: string; hash: string; collectionTimestamp: string }>,
): EvidenceAnalysis {
  const hashCheck = validateEvidenceHash(record.hash);
  const custody = analyseCustody(record, all);
  const provenance = parseProvenance(record.provenance);
  const indicators = extractIndicators(record.provenance);
  const entityRefs = extractEntityRefs(record.provenance);
  // duplicateDigests reports every record sharing a digest, including this
  // one. Only the *other* copies belong in this list.
  const duplicateIds = (duplicateDigests(all).get(hashCheck.normalized) ?? []).filter(id => id !== record.id);

  const findings: Array<{ label: string; detail: string; tone: 'ok' | 'warn' | 'info' }> = [
    ...custody.findings,
  ];

  if (hashCheck.verdict === 'VALID') {
    findings.push({ label: 'Digest well formed', tone: 'ok', detail: hashCheck.detail });
  } else {
    findings.push({ label: 'Digest problem', tone: 'warn', detail: hashCheck.detail });
  }

  if (duplicateIds.length > 0) {
    findings.push({
      label: 'Identical digest elsewhere', tone: 'info',
      detail: `${duplicateIds.join(', ')} record${duplicateIds.length === 1 ? 's' : ''} carry the same digest. That means one file was recorded from more than one source, which is a useful corroboration — it is not by itself evidence that either copy is authentic.`,
    });
  }

  const ipv4 = indicators.ipv4;
  if (ipv4.length) {
    findings.push({
      label: 'Addresses in provenance', tone: 'info',
      detail: `${ipv4.length} IP address(es) appear in the provenance string. These come from the recorded path description, not from the evidence file, so they should be corroborated against infrastructure records before being treated as actor infrastructure.`,
    });
  }

  const noContentStored = true;
  findings.push({
    label: 'No evidence content attached', tone: 'info',
    detail: 'This record carries a provenance description and a digest, but no file. No EXIF, OCR or raw-content inspection was possible, and the digest cannot be recomputed. Attach the original file to inspect it.',
  });

  return {
    id: record.id,
    hashCheck,
    provenance,
    indicators,
    entityRefs,
    custody,
    duplicateIds,
    noContentStored,
    findings,
    caveats: [
      'A recorded digest is an integrity claim, not a verified one. Without the file it cannot be re-hashed, so this analysis never reports that evidence is unaltered.',
      'A collection timestamp records when a sweep ran. Items captured together share a timestamp, so it does not order them relative to each other.',
      'EXIF and provenance text are attacker-controlled. A camera model, an edit timestamp or a quoted title is a lead for a human, never a conclusion about authorship.',
    ],
  };
}
