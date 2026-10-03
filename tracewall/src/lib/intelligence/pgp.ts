// ============================================================
// OpenPGP key analysis.
//
// A PGP fingerprint is the one identifier in this dataset that can
// be *checked* rather than merely recorded. Two rules govern this
// module:
//
//   1. Never assert more than was verified. If no armored key block
//      is stored, the fingerprint is checked for structure only and
//      the module says so. A well-formed fingerprint is not evidence
//      that a key exists, is not expired, and is not revoked — those
//      are claims about key material the model does not hold.
//
//   2. Identity is separated from key. A user ID inside a key is a
//      self-asserted label that anyone can set. UIDs are extracted
//      and shown, but they never become an actor attribution on
//      their own.
//
// Everything here is a pure function of bytes already in the record.
// No keyserver is contacted and no revocation status is fetched.
// ============================================================

/** Public-key algorithm names, from RFC 4880 §9.1 and the v5/v6 registries. */
const PUBLIC_KEY_ALGORITHMS: Record<number, { name: string; strength: string; note?: string }> = {
  1: { name: 'RSA (Encrypt or Sign)', strength: 'variable' },
  2: { name: 'RSA (Encrypt-Only)', strength: 'variable' },
  3: { name: 'RSA (Sign-Only)', strength: 'variable' },
  16: { name: 'ElGamal (Encrypt-Only)', strength: 'variable' },
  17: { name: 'DSA', strength: 'variable' },
  18: { name: 'ECDH', strength: 'curve-dependent' },
  19: { name: 'ECDSA', strength: 'curve-dependent' },
  20: { name: 'ElGamal (Encrypt or Sign)', strength: 'variable' },
  22: { name: 'EdDSA (Ed25519 legacy id)', strength: '255-bit' },
  23: { name: 'AEDH (X25519 legacy id)', strength: '255-bit' },
  25: { name: 'X25519', strength: '255-bit' },
  26: { name: 'X448', strength: '448-bit' },
  27: { name: 'Ed25519', strength: '255-bit' },
  28: { name: 'Ed448', strength: '448-bit' },
};

/** Curve names from the v5/v6 elliptic curve OID registry. */
const CURVES: Record<string, { name: string; bits: number; note?: string }> = {
  '2A8648CE3D030107': { name: 'NIST P-256', bits: 256, note: 'widely used; not post-quantum' },
  '2B81040022': { name: 'NIST P-384', bits: 384, note: 'not post-quantum' },
  '2B81040023': { name: 'NIST P-521', bits: 521, note: 'not post-quantum' },
  '2B06010401DA470F01': { name: 'Ed25519 (modern)', bits: 256, note: 'RFC 9580' },
  '2B060104019755010501': { name: 'Curve25519 (modern)', bits: 256, note: 'RFC 9580' },
  '2B06010401DA470F02': { name: 'Ed448', bits: 448, note: 'RFC 9580' },
  '2B060104019755010502': { name: 'Curve448', bits: 448, note: 'RFC 9580' },
  '2B06010401DA470F03': { name: 'Ed25519 (context-bound)', bits: 256, note: 'librePGP' },
  '2B060104019755010503': { name: 'X25519 (context-bound)', bits: 256, note: 'librePGP' },
};

export type PgpPacketTag =
  | 'PUBLIC_KEY'
  | 'PUBLIC_SUBKEY'
  | 'SIGNATURE'
  | 'USER_ID'
  | 'SECRET_KEY'
  | 'SECRET_SUBKEY'
  | 'TRUST'
  | 'USER_ATTR'
  | 'OTHER';

export interface PgpPacket {
  tag: PgpPacketTag;
  /** Byte offset of the packet body within the decoded transfer. */
  offset: number;
  length: number;
  /** Hex preview, capped, so a reviewer can eyeball raw structure. */
  preview: string;
}

export interface PgpUserId {
  /** The self-asserted label exactly as encoded. */
  uid: string;
  /** Comment field of a "Name (Comment) <email>" style UID. */
  comment: string | null;
  email: string | null;
  name: string | null;
}

export interface PgpSubPacket {
  type: number;
  typeName: string;
  /** Human reading, when the subpacket carries known structure. */
  value: string | null;
  /** Raw numeric payload for time and flag subpackets, for computation. */
  numeric: number | null;
  critical: boolean;
}

export interface PgpSignature {
  version: number;
  sigType: number;
  sigTypeName: string;
  pubkeyAlgorithm: number;
  hashAlgorithm: number;
  hashName: string;
  createdAt: string | null;
  issuerFingerprint: string | null;
  issuerKeyId: string | null;
  subPackets: PgpSubPacket[];
  /** Set when a reason-for-revocation subpacket was present. */
  revocationReason: string | null;
}

export interface PgpKeyPacket {
  version: number;
  createdAt: string | null;
  algorithm: number;
  algorithmName: string;
  algorithmStrength: string;
  curve: { name: string; bits: number; note?: string } | null;
  /** Modulus size for RSA-family algorithms, read from the MPI. */
  rsaBits: number | null;
  /** v4 keys carry a 20-byte SHA-1 fingerprint; v5/v6 use SHA-256. */
  fingerprint: string | null;
  /** Long key ID, i.e. the low 8 bytes of a v4 fingerprint. */
  keyId: string | null;
  expiresAt: string | null;
  expired: boolean | null;
  keyFlags: string[];
  usableForEncryption: boolean | null;
  usableForSigning: boolean | null;
}

export interface PgpParseResult {
  ok: boolean;
  /** Why parsing failed, phrased for an analyst. */
  error: string | null;
  /** Armor framing checks, reported whether or not the body parsed. */
  armor: {
    found: boolean;
    blockType: string | null;
    /** CRC-24 from the armor, matched against the decoded payload. */
    crcValid: boolean | null;
    lineCount: number;
  };
  packets: PgpPacket[];
  primaryKey: PgpKeyPacket | null;
  subkeys: PgpKeyPacket[];
  userIds: PgpUserId[];
  signatures: PgpSignature[];
  /** True when any signature is a certification over a user ID. */
  hasCertification: boolean;
  hasRevocationSignature: boolean;
  hasRevocationCertificate: boolean;
  /** A standalone revocation certificate is 0x01 0xXX ... "REVKEY". */
  revocationCertificateDetected: boolean;
  /** Set when the key declares an expiration subpacket. */
  declaredExpiry: string | null;
  /** Set when a revocation certificate was found alongside the key. */
  revoked: boolean | null;
  /** True when no expiration subpacket is present at all. */
  neverExpires: boolean | null;
  /** Names of algorithms considered unsafe for new use by this tool. */
  weakAlgorithms: string[];
}

// ── Base64 and CRC-24 ──────────────────────────────────────────

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function base64Decode(input: string): Uint8Array {
  const clean = input.replace(/=+$/, '').replace(/\s+/g, '');
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let bits = 0;
  let value = 0;
  let index = 0;
  for (const char of clean) {
    const digit = B64.indexOf(char);
    if (digit === -1) continue;
    value = (value << 6) | digit;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[index++] = (value >> bits) & 0xff;
    }
  }
  return out.subarray(0, index);
}

const CRC24_INIT = 0xb704ce;
const CRC24_POLY = 0x1864cfb;

function crc24(bytes: Uint8Array): number {
  let crc = CRC24_INIT;
  for (const byte of bytes) {
    crc ^= byte << 16;
    for (let bit = 0; bit < 8; bit++) {
      crc <<= 1;
      if (crc & 0x1000000) crc ^= CRC24_POLY;
    }
  }
  return crc & 0xffffff;
}

// ── SHA-1 (needed for RFC 4880 §12.2 v4 fingerprints) ──────────
// WebCrypto is async and unavailable for SHA-1 in some contexts, and
// fingerprinting a 20-byte digest is small enough to do inline.
function sha1(bytes: Uint8Array): Uint8Array {
  const h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
  const bitLength = bytes.length * 8;
  const padded = new Uint8Array((((bytes.length + 8) >> 6) + 1) << 6);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor(bitLength / 0x100000000), false);
  view.setUint32(padded.length - 4, bitLength >>> 0, false);

  const w = new Int32Array(80);
  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getInt32(offset + i * 4, false);
    for (let i = 16; i < 80; i++) {
      const n = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
      w[i] = (n << 1) | (n >>> 31);
    }
    let [a, b, c, d, e] = h;
    for (let i = 0; i < 80; i++) {
      let f: number;
      let k: number;
      if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
      else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
      else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
      else { f = b ^ c ^ d; k = 0xca62c1d6; }
      const temp = (((a << 5) | (a >>> 27)) + f + e + k + w[i]) | 0;
      e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = temp;
    }
    h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0;
    h[3] = (h[3] + d) | 0; h[4] = (h[4] + e) | 0;
  }
  const out = new Uint8Array(20);
  const outView = new DataView(out.buffer);
  h.forEach((word, i) => outView.setInt32(i * 4, word, false));
  return out;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0').toUpperCase()).join('');
}

function hexGroups(hex: string, size = 4): string {
  return hex.match(new RegExp(`.{1,${size}}`, 'g'))?.join(' ') ?? hex;
}

// ── Armor ──────────────────────────────────────────────────────

const ARMOR_RE = /-----BEGIN PGP ([A-Z ]+)-----([\s\S]*?)-----END PGP \1-----/;

/** Strip armor, decode the payload and verify the CRC-24 trailer. */
export function decodeArmoredKey(input: string): PgpParseResult['armor'] & { bytes?: Uint8Array } {
  const match = ARMOR_RE.exec(input);
  if (!match) {
    return { found: false, blockType: null, crcValid: null, lineCount: 0 };
  }
  const body = match[2];
  const lines = body.split(/\r?\n/);
  // The first line after the header is a blank line in the RFC 4880 form.
  const start = lines[0].trim() === '' ? 1 : 0;
  const dataLines: string[] = [];
  let crc: string | null = null;
  for (let i = start; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line === '') continue;
    if (line.startsWith('=')) { crc = line.slice(1); continue; }
    if (/^[A-Za-z0-9+/=]+$/.test(line)) dataLines.push(line);
  }
  const bytes = base64Decode(dataLines.join(''));
  let crcValid: boolean | null = null;
  if (crc) {
    const expected = parseInt(crc.padEnd(8, '0').slice(0, 6), 16);
    crcValid = crc24(bytes) === expected;
  }
  return {
    found: true,
    blockType: match[1].trim(),
    crcValid,
    lineCount: dataLines.length,
    bytes,
  };
}

// ── Packet framing (RFC 4880 §4.2) ─────────────────────────────

// RFC 4880 §4.3 packet tag numbers. The transferable public-key packets are
// tag 6 and 14; tag 1 is a public-key *encrypted session key* and tag 2 is a
// signature, so conflating them misreads every key.
const PACKET_TAGS: Record<number, PgpPacketTag> = {
  1: 'OTHER',        // public-key encrypted session key
  2: 'SIGNATURE',
  3: 'OTHER',        // symmetric-key encrypted session key
  4: 'OTHER',        // compressed data
  5: 'SECRET_KEY',
  6: 'PUBLIC_KEY',
  7: 'SECRET_SUBKEY',
  9: 'OTHER',        // symmetrically encrypted data
  11: 'OTHER',       // literal data
  12: 'TRUST',
  13: 'USER_ID',
  14: 'PUBLIC_SUBKEY',
  17: 'USER_ATTR',
  18: 'OTHER',       // symmetric-key encrypted session key (v5)
  19: 'OTHER',       // one-pass signature
  20: 'OTHER',       // AEAD encrypted data
};

function readPackets(bytes: Uint8Array): PgpPacket[] {
  const packets: PgpPacket[] = [];
  let offset = 0;
  while (offset < bytes.length) {
    const header = bytes[offset];
    // A bit 7 of 0 marks a stream of one-octet packet tags.
    if ((header & 0x80) === 0) break;
    const tagNumber = header & 0x3f;
    offset += 1;
    let length: number;
    if (header & 0x40) {
      // New format.
      const first = bytes[offset];
      if (first === undefined) break;
      if (first < 192) { length = first; offset += 1; }
      else if (first < 224) { length = ((first - 192) << 8) + bytes[offset + 1] + 192; offset += 2; }
      else if (first === 255) {
        length = (bytes[offset + 1] << 24 >>> 0) + (bytes[offset + 2] << 16) + (bytes[offset + 3] << 8) + bytes[offset + 4];
        offset += 5;
      } else { length = 1 << (first & 0x1f); offset += 1; }
    } else {
      // Old format: 1, 2 or 4 length octets by the top two bits.
      const octet = bytes[offset];
      if (octet === undefined) break;
      if (octet < 192) { length = octet; offset += 1; }
      else if (octet < 224) { length = ((octet - 192) << 8) + bytes[offset + 1] + 192; offset += 2; }
      else if (octet < 255) { length = 1 << (octet & 0x1f); offset += 1; }
      else { length = (bytes[offset + 1] << 24 >>> 0) + (bytes[offset + 2] << 16) + (bytes[offset + 3] << 8) + bytes[offset + 4]; offset += 5; }
    }
    if (length <= 0 || offset + length > bytes.length) break;
    packets.push({
      tag: PACKET_TAGS[tagNumber] ?? 'OTHER',
      offset,
      length,
      preview: toHex(bytes.subarray(offset, Math.min(offset + 8, offset + length))),
    });
    offset += length;
  }
  return packets;
}

// ── Key packet fields ──────────────────────────────────────────

const HASH_NAMES: Record<number, string> = {
  1: 'MD5', 2: 'SHA-1', 3: 'RIPEMD-160', 8: 'SHA-256', 9: 'SHA-384',
  10: 'SHA-512', 11: 'SHA-224', 12: 'SHA3-256', 14: 'SHA3-512',
};

const SIG_TYPE_NAMES: Record<number, string> = {
  0x10: 'Key certification (generic)', 0x11: 'Key certification (persona)',
  0x12: 'Key certification (casual)', 0x13: 'Key certification (positive)',
  0x18: 'Subkey binding', 0x1f: 'Direct-key signature',
  0x20: 'Key revocation', 0x28: 'Subkey revocation', 0x30: 'Certification revocation',
};

const KEY_FLAG_NAMES: Record<number, string> = {
  0x01: 'Certify other keys', 0x02: 'Sign data', 0x04: 'Encrypt communications',
  0x08: 'Encrypt storage', 0x10: 'Split key', 0x20: 'Authenticate',
  0x80: 'Shared key',
};

function parseKeyFlags(flags: number): string[] {
  return Object.entries(KEY_FLAG_NAMES)
    .filter(([bit]) => (flags & Number(bit)) !== 0)
    .map(([, label]) => label);
}

/** Read a multi-precision integer header, returning its bit length. */
function readMpi(bytes: Uint8Array, offset: number): { bits: number; value: Uint8Array; next: number } {
  if (offset + 2 > bytes.length) return { bits: 0, value: new Uint8Array(), next: bytes.length };
  const bits = (bytes[offset] << 8) + bytes[offset + 1];
  const length = Math.ceil(bits / 8);
  const end = Math.min(offset + 2 + length, bytes.length);
  return { bits, value: bytes.subarray(offset + 2, end), next: end };
}

function parseKeyPacket(body: Uint8Array): Omit<PgpKeyPacket, 'expiresAt' | 'expired' | 'keyFlags' | 'usableForEncryption' | 'usableForSigning'> {
  if (body.length < 6) {
    return {
      version: 0, createdAt: null, algorithm: 0,
      algorithmName: 'Unreadable', algorithmStrength: 'unknown',
      curve: null, rsaBits: null, fingerprint: null, keyId: null,
    };
  }
  const version = body[0];
  const createdAtSeconds = (body[1] << 24 >>> 0) + (body[2] << 16) + (body[3] << 8) + body[4];
  const algorithm = body[5];
  const meta = PUBLIC_KEY_ALGORITHMS[algorithm] ?? { name: `Unknown (${algorithm})`, strength: 'unknown' };
  const createdAt = version >= 4
    ? new Date(createdAtSeconds * 1000).toISOString()
    : null;

  // v4 fingerprint: SHA-1 over 0x99, the two-octet body length, then the body.
  let fingerprint: string | null = null;
  if (version === 4 && body.length > 0 && body.length < 0x10000) {
    const material = new Uint8Array(body.length + 3);
    material[0] = 0x99;
    material[1] = (body.length >> 8) & 0xff;
    material[2] = body.length & 0xff;
    material.set(body, 3);
    fingerprint = toHex(sha1(material));
  }

  // Curve OIDs appear in the public-key material for ECDH/ECDSA/EdDSA.
  let curve: PgpKeyPacket['curve'] = null;
  // RSA strength comes from the modulus MPI that follows the timestamp.
  let rsaBits: number | null = null;
  if ([1, 2, 3, 16, 20].includes(algorithm) && body.length > 7) {
    rsaBits = readMpi(body, 6).bits;
  }
  if ([18, 19, 22, 23, 25, 26, 27, 28].includes(algorithm)) {
    // The algorithm octet is followed by an OID length octet, then the OID.
    const oidLength = body[6];
    if (oidLength !== undefined && body.length > 7 + oidLength) {
      const oid = toHex(body.subarray(7, 7 + oidLength));
      curve = CURVES[oid] ?? { name: `Unknown curve (${oid})`, bits: 0, note: 'OID not in the known registry' };
    }
  }

  return {
    version,
    createdAt,
    algorithm,
    algorithmName: meta.name,
    algorithmStrength: rsaBits ? `${rsaBits}-bit modulus` : curve ? `${curve.bits}-bit ${curve.name}` : meta.strength,
    curve,
    rsaBits,
    fingerprint,
    keyId: fingerprint ? fingerprint.slice(-16) : null,
  };
}

function parseSubPackets(bytes: Uint8Array): PgpSubPacket[] {
  const out: PgpSubPacket[] = [];
  let offset = 0;
  while (offset < bytes.length) {
    let length: number;
    if (bytes[offset] < 192) { length = bytes[offset]; offset += 1; }
    else if (bytes[offset] < 255) { length = ((bytes[offset] - 192) << 8) + bytes[offset + 1] + 192; offset += 2; }
    else {
      length = (bytes[offset + 1] << 24 >>> 0) + (bytes[offset + 2] << 16) + (bytes[offset + 3] << 8) + bytes[offset + 4];
      offset += 5;
    }
    if (length <= 0 || offset + length > bytes.length) break;
    const typeByte = bytes[offset];
    const type = typeByte & 0x7f;
    const critical = (typeByte & 0x80) !== 0;
    const data = bytes.subarray(offset + 1, offset + length);
    offset += length;

    let typeName = `Subpacket ${type}`;
    let value: string | null = null;
    let numeric: number | null = null;
    switch (type) {
      case 2:
        typeName = 'Signature creation time';
        numeric = readUint32(data);
        value = numeric ? new Date(numeric * 1000).toISOString() : null;
        break;
      case 3: typeName = 'Signature expiration time'; numeric = readUint32(data); value = `${numeric} seconds after creation`; break;
      case 9: typeName = 'Key expiration time'; numeric = readUint32(data); value = `${numeric} seconds after key creation`; break;
      case 16: typeName = 'Issuer key ID'; value = toHex(data).padStart(16, '0'); break;
      case 27: typeName = 'Key flags'; {
        numeric = readUint32(data);
        value = parseKeyFlags(numeric).join(', ') || `0x${numeric.toString(16)}`;
        break;
      }
      case 29: typeName = 'Reason for revocation'; {
        const code = data[0];
        value = `${REVOCATION_REASONS[code] ?? `Code ${code}`}${data.length > 1 ? ` — ${new TextDecoder().decode(data.subarray(1)).replace(/\0+$/, '')}` : ''}`;
        break;
      }
      case 33: typeName = 'Issuer fingerprint';
        value = `v${data[0]} ${toHex(data.subarray(1))}`;
        break;
      default: break;
    }
    out.push({ type, typeName, value, numeric, critical });
  }
  return out;
}

const REVOCATION_REASONS: Record<number, string> = {
  0: 'No reason given', 1: 'Key is superseded', 2: 'Key material compromised',
  3: 'Key is retired and no longer used', 32: 'User ID is no longer valid',
};

function readUint32(bytes: Uint8Array): number {
  if (bytes.length < 4) return 0;
  return (bytes[0] << 24 >>> 0) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3];
}

function parseSignaturePacket(body: Uint8Array): PgpSignature {
  const version = body[0];
  const sigType = body[1];
  const pubkeyAlgorithm = body[2];
  const hashAlgorithm = body[3];
  const result: PgpSignature = {
    version, sigType, sigTypeName: SIG_TYPE_NAMES[sigType] ?? `Signature type 0x${sigType.toString(16)}`,
    pubkeyAlgorithm, hashAlgorithm, hashName: HASH_NAMES[hashAlgorithm] ?? `Hash ${hashAlgorithm}`,
    createdAt: null, issuerFingerprint: null, issuerKeyId: null, subPackets: [], revocationReason: null,
  };
  if (version < 4) {
    // v3 signature: hashed material is fixed-length and unhashed follows.
    if (body.length > 4) result.createdAt = new Date((body[4] << 24 >>> 0) * 1000).toISOString();
    if (body.length > 14) result.issuerKeyId = toHex(body.subarray(7, 14)).padStart(16, '0');
    return result;
  }
  // v4: 2-octet hashed subpacket length, then hashed subpackets.
  if (body.length < 6) return result;
  const hashedLength = (body[4] << 8) + body[5];
  const hashedEnd = Math.min(6 + hashedLength, body.length);
  result.subPackets = parseSubPackets(body.subarray(6, hashedEnd));
  if (body.length < hashedEnd + 2) return result;
  const unhashedLength = (body[hashedEnd] << 8) + body[hashedEnd + 1];
  const unhashedEnd = Math.min(hashedEnd + 2 + unhashedLength, body.length);
  // Issuer data is advisory and deliberately unhashed, so it is read last
  // and never used to authenticate the signature.
  result.subPackets.push(...parseSubPackets(body.subarray(hashedEnd + 2, unhashedEnd)));

  const creation = result.subPackets.find(s => s.type === 2);
  if (creation?.numeric) {
    result.createdAt = new Date(creation.numeric * 1000).toISOString();
  }
  const issuerFp = result.subPackets.find(s => s.type === 33);
  if (issuerFp?.value) result.issuerFingerprint = issuerFp.value.split(' ')[1] ?? null;
  const issuerId = result.subPackets.find(s => s.type === 16);
  if (issuerId?.value) result.issuerKeyId = issuerId.value;
  const revocation = result.subPackets.find(s => s.type === 29);
  if (revocation?.value) result.revocationReason = revocation.value;
  return result;
}

function parseUserId(body: Uint8Array): PgpUserId {
  const uid = new TextDecoder().decode(body).replace(/\0+$/, '').trim();
  const emailMatch = /<([^>]+)>/.exec(uid);
  let name: string | null = null;
  let comment: string | null = null;
  if (emailMatch) {
    const before = uid.slice(0, emailMatch.index).trim();
    const commentMatch = /\(([^)]*)\)/.exec(before);
    if (commentMatch) comment = commentMatch[1].trim();
    name = before.replace(/\([^)]*\)/, '').trim() || null;
  } else {
    name = uid || null;
  }
  return { uid, comment, email: emailMatch ? emailMatch[1] : null, name };
}

/** True when the decoded transfer is a bare revocation certificate. */
function isRevocationCertificate(bytes: Uint8Array): boolean {
  // RFC 4880 §5.2.3.6: 0x01, key-algo octet, the issuer's key material, and a
  // trailing "REVKEY" string in the signature trailer.
  if (bytes.length < 6 || bytes[0] !== 0x01) return false;
  const tail = new TextDecoder().decode(bytes.subarray(Math.max(0, bytes.length - 6)));
  return tail.includes('REVKEY');
}

// ── Public entry points ────────────────────────────────────────

export function emptyParseResult(error: string | null): PgpParseResult {
  return {
    ok: false, error,
    armor: { found: false, blockType: null, crcValid: null, lineCount: 0 },
    packets: [], primaryKey: null, subkeys: [], userIds: [], signatures: [],
    hasCertification: false, hasRevocationSignature: false, hasRevocationCertificate: false,
    revocationCertificateDetected: false, declaredExpiry: null, revoked: null,
    neverExpires: null, weakAlgorithms: [],
  };
}

/** Parse an armored (or raw binary) OpenPGP public key transfer. */
export function parseArmoredKey(input: string): PgpParseResult {
  if (!input || input.trim().length === 0) {
    return emptyParseResult('No key material is stored on this record, so nothing could be parsed.');
  }
  const armor = decodeArmoredKey(input);
  const bytes = armor.bytes ?? base64Decode(input);
  const result = emptyParseResult(null);
  result.armor = { found: armor.found, blockType: armor.blockType, crcValid: armor.crcValid, lineCount: armor.lineCount };

  if (bytes.length === 0) {
    return emptyParseResult('The stored key material decoded to zero bytes.');
  }
  if (isRevocationCertificate(bytes)) {
    // A revocation certificate carries no usable key, so it is not a
    // successful parse — but the revocation fact it encodes is still read.
    return {
      ...result,
      ok: false,
      revocationCertificateDetected: true,
      hasRevocationCertificate: true,
      revoked: true,
      error: 'This is a standalone revocation certificate, not a public key. It records that a key was revoked but contains no usable key material.',
    };
  }
  if (armor.found && armor.crcValid === false) {
    result.error = 'The armor CRC-24 does not match the decoded payload, so the block was modified in transit. Nothing below it is treated as verified.';
  }

  const packets = readPackets(bytes);
  result.packets = packets;
  if (packets.length === 0) {
    return { ...result, error: result.error ?? 'No OpenPGP packets could be framed from the stored bytes.' };
  }

  // A direct-key signature (0x1f) describes the primary key and a subkey
  // binding (0x18) the most recent subkey. Both can appear after intervening
  // user IDs and certifications, so they are routed by signature type rather
  // than by position.
  let mostRecentSubkey: PgpKeyPacket | null = null;
  for (let i = 0; i < packets.length; i++) {
    const packet = packets[i];
    const start = packet.offset;
    const end = start + packet.length;
    if (packet.tag === 'PUBLIC_KEY' || packet.tag === 'PUBLIC_SUBKEY') {
      const parsed = parseKeyPacket(bytes.subarray(start, end));
      const keyPacket: PgpKeyPacket = {
        ...parsed,
        expiresAt: null,
        expired: null,
        keyFlags: [],
        usableForEncryption: null,
        usableForSigning: null,
      };
      if (packet.tag === 'PUBLIC_KEY' && !result.primaryKey) result.primaryKey = keyPacket;
      else { result.subkeys.push(keyPacket); mostRecentSubkey = keyPacket; }
    } else if (packet.tag === 'SIGNATURE') {
      const sig = parseSignaturePacket(bytes.subarray(start, end));
      result.signatures.push(sig);
      if (sig.sigType === 0x20 || sig.sigType === 0x28) result.hasRevocationSignature = true;
      const target = sig.sigType === 0x18 ? (mostRecentSubkey ?? result.primaryKey) : result.primaryKey;
      if (target && (sig.sigType === 0x1f || sig.sigType === 0x18)) {
        const expirySub = sig.subPackets.find(s => s.type === 9);
        const flagsSub = sig.subPackets.find(s => s.type === 27);
        const flags = flagsSub?.numeric !== null && flagsSub?.numeric !== undefined
          ? parseKeyFlags(flagsSub.numeric)
          : [];
        target.keyFlags = flags;
        target.usableForEncryption = flags.length ? flags.some(f => f.includes('Encrypt')) : null;
        target.usableForSigning = flags.length ? flags.some(f => f.includes('Sign') || f.includes('Authenticate')) : null;
        if (expirySub?.numeric !== null && expirySub?.numeric !== undefined && target.createdAt) {
          const expiry = Date.parse(target.createdAt) + expirySub.numeric * 1000;
          target.expiresAt = new Date(expiry).toISOString();
          target.expired = Date.now() > expiry;
        }
      }
    } else if (packet.tag === 'USER_ID') {
      result.userIds.push(parseUserId(bytes.subarray(start, end)));
    }
  }

  // Certification must follow a user ID, so a UID with no signature after it
  // is an uncertified label rather than a verified identity.
  result.hasCertification = result.signatures.some(s => s.sigType >= 0x10 && s.sigType <= 0x13);

  // Prefer the primary key's own binding signature for the expiry it declares.
  const primarySig = result.signatures.find(s => s.sigType === 0x1f);
  const primaryExpiry = primarySig?.subPackets.find(s => s.type === 9);
  result.declaredExpiry = primaryKeyExpiry(result.primaryKey, primaryExpiry);
  result.neverExpires = result.primaryKey ? primarySig === undefined || primaryExpiry === undefined : null;

  if (result.hasRevocationSignature) {
    const reason = result.signatures.find(s => s.revocationReason)?.revocationReason;
    result.revoked = true;
    if (reason) result.error = `A revocation signature is present in this transfer: ${reason}. Revocation is carried by the transfer, not confirmed against a keyserver.`;
  } else if (result.ok || result.primaryKey) {
    // No revocation in this material. That is a statement about the bytes
    // stored here, not a live directory check.
    result.revoked = false;
  }

  const weak: string[] = [];
  const algorithms = [result.primaryKey, ...result.subkeys].filter(Boolean) as PgpKeyPacket[];
  for (const key of algorithms) {
      // Signing subpackets were used before a single unified algorithm id; the
      // encrypt-only and sign-only variants are legacy.
      if (key.algorithm === 2 || key.algorithm === 3) {
        weak.push(`${key.algorithmName} (algorithm ${key.algorithm}) — pre-unification algorithm id`);
      }
    // 1024-bit RSA has been factored since 2013 and offers no real protection.
    if (key.rsaBits !== null && key.rsaBits < 2048) {
      weak.push(`${key.rsaBits}-bit RSA modulus is below the 2048-bit floor`);
    }
    if (key.algorithm === 16) weak.push('ElGamal (algorithm 16) — encrypt-only, no signing');
    if (key.curve && /not post-quantum/.test(key.curve.note ?? '')) weak.push(`${key.curve.name} is not post-quantum`);
  }
  const weakHashes = result.signatures.filter(s => s.hashAlgorithm === 1 || s.hashAlgorithm === 2);
  if (weakHashes.length) weak.push(`Signature hashed with ${weakHashes[0].hashName} (weak for new signatures)`);
  result.weakAlgorithms = Array.from(new Set(weak));

  result.ok = result.primaryKey !== null;
  if (!result.ok && !result.error) {
    result.error = 'Packets were framed but no public-key packet was present.';
  }
  return result;
}

// ── Structural fingerprint checks ──────────────────────────────

export type FingerprintVerdict = 'VALID' | 'LENGTH_INVALID' | 'CHARSET_INVALID' | 'GROUPING_INVALID';

export interface FingerprintCheck {
  /** The fingerprint as stored, normalised to bare uppercase hex. */
  normalized: string;
  /** Grouped the way key servers print it, for display. */
  pretty: string;
  verdict: FingerprintVerdict;
  detail: string;
}

/**
 * Check a fingerprint's *structure* only. This cannot show that a key
 * exists, and a valid v4 fingerprint is still perfectly forgeable in
 * the sense that anyone may assert one for a key they do not hold.
 */
export function validateFingerprint(input: string): FingerprintCheck {
  const raw = (typeof input === 'string' ? input : '').trim().toUpperCase();
  const normalized = raw.replace(/[\s-]/g, '');
  const grouped = hexGroups(normalized);
  if (normalized.length === 0) {
    return { normalized, pretty: grouped, verdict: 'LENGTH_INVALID', detail: 'No fingerprint is recorded on this record.' };
  }
  if (!/^[0-9A-F]+$/.test(normalized)) {
    const bad = raw.split('').find(c => !/[0-9A-F\s-]/.test(c)) ?? '?';
    return { normalized, pretty: grouped, verdict: 'CHARSET_INVALID', detail: `The fingerprint contains "${bad}", which is not a hexadecimal digit. Fingerprints are printed as hex.` };
  }
  // A v4 fingerprint is SHA-1, so 20 bytes. v5/v6 use SHA-256, so 32.
  if (normalized.length === 40) {
    return { normalized, pretty: grouped, verdict: 'VALID', detail: 'Structurally a v4 fingerprint (20 bytes / 40 hex). Length and charset only — this does not show the key exists, is unexpired, or is unrevoked.' };
  }
  if (normalized.length === 64) {
    return { normalized, pretty: grouped, verdict: 'VALID', detail: 'Structurally a v5 or v6 fingerprint (32 bytes / 64 hex). Length and charset only.' };
  }
  if (normalized.length % 4 !== 0) {
    return { normalized, pretty: grouped, verdict: 'GROUPING_INVALID', detail: `A fingerprint is normally printed in 4-character groups, so 40 or 64 characters. This has ${normalized.length}.` };
  }
  return { normalized, pretty: grouped, verdict: 'LENGTH_INVALID', detail: `Expected 40 hex characters for a v4 fingerprint or 64 for v5/v6, but this has ${normalized.length}.` };
}

/** The long key ID: the low 8 bytes of a v4 fingerprint. */
export function longKeyId(fingerprint: string): string | null {
  if (typeof fingerprint !== 'string') return null;
  const normalized = fingerprint.replace(/[\s-]/g, '').toUpperCase();
  return normalized.length === 40 ? normalized.slice(-16) : null;
}

// ── Bundle ─────────────────────────────────────────────────────

export interface PgpAnalysisBundle {
  keyId: string;
  fingerprint: string;
  fingerprintCheck: FingerprintCheck;
  longKeyId: string | null;
  parse: PgpParseResult;
  /** True when key material is present, so parse results can be trusted. */
  hasKeyMaterial: boolean;
  /** True when a computed fingerprint disagrees with the stored one. */
  fingerprintMismatch: boolean;
  /** Plain statements of what this analysis can and cannot establish. */
  findings: Array<{ label: string; detail: string; tone: 'ok' | 'warn' | 'info' }>;
  /** Caveats always shown next to UID-derived identity claims. */
  caveats: string[];
}

const ARMOR_FIELDS = ['armoredKey', 'armor', 'publicKeyBlock', 'keyBlock', 'armored'] as const;

/** Absolute expiry of a key, or null when the key declares none. */
function primaryKeyExpiry(key: PgpKeyPacket | null, expirySub: PgpSubPacket | undefined): string | null {
  if (!key?.createdAt || expirySub?.numeric === null || expirySub?.numeric === undefined) return null;
  return new Date(Date.parse(key.createdAt) + expirySub.numeric * 1000).toISOString();
}

/**
 * Find key material without assuming a field name, so a record that
 * stores the block under a different key is still analysed.
 */
function findKeyMaterial(record: Record<string, unknown>): string | null {
  for (const field of ARMOR_FIELDS) {
    const value = record[field];
    if (typeof value === 'string' && value.includes('BEGIN PGP')) return value;
  }
  return null;
}

export function pgpAnalysis(key: Record<string, unknown> & { id: string; fingerprint: string }): PgpAnalysisBundle {
  const armor = findKeyMaterial(key as Record<string, unknown>);
  const parse = armor ? parseArmoredKey(armor) : emptyParseResult(null);
  const fingerprintCheck = validateFingerprint(key.fingerprint);
  const computed = parse.primaryKey?.fingerprint ?? null;
  const stored = fingerprintCheck.normalized;
  const fingerprintMismatch = computed !== null && stored.length > 0 && computed !== stored;

  const findings: PgpAnalysisBundle['findings'] = [];
  const caveats = [
    'A PGP fingerprint identifies a key, not a person. Anyone can publish a key bearing any name or address they choose.',
    'A user ID is a self-asserted label inside the key. It is not verified by a certificate authority and carries no proof of ownership.',
    'Revocation and expiry are properties of the key material as published. No keyserver was contacted here, so neither was confirmed against a live directory.',
  ];

  if (!armor) {
    findings.push({
      label: 'No key material stored',
      tone: 'info',
      detail: 'This record holds a fingerprint only. Algorithm, key size, user IDs, creation date, expiry and revocation cannot be determined without the key block, and nothing on this page should be read as saying the key is currently valid.',
    });
  } else {
    findings.push({
      label: fingerprintMismatch ? 'Fingerprint does not match the stored key' : 'Fingerprint computed from key material',
      tone: fingerprintMismatch ? 'warn' : 'ok',
      detail: fingerprintMismatch
        ? `The key block hashes to ${computed}, but the record stores ${stored}. One of the two is wrong, so this key must not be treated as the same identity until it is reconciled.`
        : `The key block hashes to ${stored}, matching the stored fingerprint. This confirms the bytes are the key the record means — nothing more.`,
    });
    if (parse.error) findings.push({ label: 'Parse note', tone: parse.revoked ? 'warn' : 'info', detail: parse.error });
    if (parse.armor.crcValid === false) {
      findings.push({ label: 'Armor checksum failed', tone: 'warn', detail: 'The CRC-24 on the armored block does not match its payload, so the block was altered after it was exported.' });
    }
    if (parse.weakAlgorithms.length) {
      findings.push({
        label: 'Weak cryptography present',
        tone: 'warn',
        detail: `${parse.weakAlgorithms.join('; ')}. A weak algorithm does not by itself compromise the key, but it lowers the assurance any signed statement carries.`,
      });
    }
    if (parse.revoked) {
      findings.push({ label: 'Revocation is present in the transfer', tone: 'warn', detail: 'The stored key material carries a revocation. Treat signatures made with this key as suspect unless signed before the revocation date.' });
    } else if (parse.primaryKey && parse.neverExpires === false && parse.primaryKey.expired) {
      findings.push({ label: 'Key has expired', tone: 'warn', detail: `The key declares an expiry of ${parse.primaryKey.expiresAt}, which has passed.` });
    }
    if (parse.userIds.length > 0 && !parse.hasCertification) {
      findings.push({
        label: 'User IDs are uncertified',
        tone: 'warn',
        detail: 'The key declares a user ID but carries no certification signature over it. The label is unsigned.',
      });
    }
  }

  if (fingerprintCheck.verdict !== 'VALID' && fingerprintCheck.verdict !== 'CHARSET_INVALID') {
    findings.push({ label: 'Fingerprint structure', tone: 'warn', detail: fingerprintCheck.detail });
  }

  return {
    keyId: key.id,
    fingerprint: key.fingerprint,
    fingerprintCheck,
    longKeyId: longKeyId(key.fingerprint),
    parse,
    hasKeyMaterial: !!armor,
    fingerprintMismatch,
    findings,
    caveats,
  };
}
