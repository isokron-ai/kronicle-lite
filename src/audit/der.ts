/**
 * Minimal DER (ASN.1 Distinguished Encoding Rules) reader and writer, enough
 * for RFC 3161 timestamp requests and tokens (src/audit/rfc3161.ts). No
 * recursion over untrusted input: `readTlv` decodes ONE element and
 * `children` one level, so callers walk only the structure they expect.
 * Definite lengths only (DER forbids indefinite ones); single-byte tags only
 * (no CMS / TSP structure needs high tag numbers).
 */

export class DerError extends Error {
  override readonly name = 'DerError';
}

export interface Tlv {
  /** The identifier octet (class, constructed bit and tag number). */
  tag: number;
  constructed: boolean;
  /** The whole element: identifier, length and value. */
  bytes: Buffer;
  /** The value octets. */
  value: Buffer;
}

export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  PRINTABLE_STRING: 0x13,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
  SEQUENCE: 0x30,
  SET: 0x31,
} as const;

/** Context-specific tag [n], constructed (EXPLICIT, or IMPLICIT over a constructed type). */
export const ctx = (n: number): number => 0xa0 | n;
/** Context-specific tag [n], primitive (IMPLICIT over a primitive type). */
export const ctxPrim = (n: number): number => 0x80 | n;

/** One element at `offset`; throws DerError on anything malformed or running past `buf`. */
export function readTlv(buf: Buffer, offset = 0): Tlv {
  if (offset + 2 > buf.length) throw new DerError('truncated element');
  const tag = buf[offset]!;
  if ((tag & 0x1f) === 0x1f) throw new DerError('high tag numbers are not supported');
  let len = buf[offset + 1]!;
  let p = offset + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0) throw new DerError('indefinite length is not DER');
    if (n > 4) throw new DerError('length field too long');
    if (p + n > buf.length) throw new DerError('truncated length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[p + i]!;
    if (buf[p] === 0 || len < 0x80) throw new DerError('non-minimal length');
    p += n;
  }
  if (p + len > buf.length) throw new DerError('element runs past its container');
  return { tag, constructed: (tag & 0x20) !== 0, bytes: buf.subarray(offset, p + len), value: buf.subarray(p, p + len) };
}

/** Parse `buf` as exactly one element (no trailing bytes). */
export function parseDer(buf: Buffer): Tlv {
  const t = readTlv(buf, 0);
  if (t.bytes.length !== buf.length) throw new DerError('trailing bytes after the element');
  return t;
}

/** The elements inside a constructed element, one level down. */
export function children(t: Tlv): Tlv[] {
  if (!t.constructed) throw new DerError(`element 0x${t.tag.toString(16)} is not constructed`);
  const out: Tlv[] = [];
  for (let p = 0; p < t.value.length; ) {
    const c = readTlv(t.value, p);
    out.push(c);
    p += c.bytes.length;
  }
  return out;
}

/** `t` with the given tag, else a DerError naming `what`. */
export function expect(t: Tlv | undefined, tag: number, what: string): Tlv {
  if (!t) throw new DerError(`${what} is missing`);
  if (t.tag !== tag) throw new DerError(`${what}: expected tag 0x${tag.toString(16)}, got 0x${t.tag.toString(16)}`);
  return t;
}

export function readOid(t: Tlv): string {
  if (t.tag !== TAG.OID || t.value.length === 0) throw new DerError('not an OBJECT IDENTIFIER');
  const v = t.value;
  const parts: number[] = [];
  let acc = 0;
  for (let i = 0; i < v.length; i++) {
    const b = v[i]!;
    if (acc === 0 && b === 0x80) throw new DerError('non-minimal OID component');
    acc = acc * 128 + (b & 0x7f);
    if (acc > Number.MAX_SAFE_INTEGER / 128) throw new DerError('OID component too large');
    if ((b & 0x80) === 0) {
      parts.push(acc);
      acc = 0;
    } else if (i === v.length - 1) throw new DerError('truncated OID');
  }
  const first = parts.shift()!;
  const head = first < 40 ? [0, first] : first < 80 ? [1, first - 40] : [2, first - 80];
  return [...head, ...parts].join('.');
}

/** The value octets of an INTEGER without a leading sign byte (for comparing serials). */
export function integerBytes(t: Tlv): Buffer {
  if (t.tag !== TAG.INTEGER || t.value.length === 0) throw new DerError('not an INTEGER');
  let v = t.value;
  while (v.length > 1 && v[0] === 0) v = v.subarray(1);
  return v;
}

export function readSmallInt(t: Tlv): number {
  const v = integerBytes(t);
  if (v.length > 6 || (t.value[0]! & 0x80) !== 0) throw new DerError('INTEGER out of range');
  return v.reduce((a, b) => a * 256 + b, 0);
}

/** GeneralizedTime (YYYYMMDDHHMMSS[.f+]Z) or UTCTime (YYMMDDHHMMSSZ) as a Date. */
export function readTime(t: Tlv): Date {
  const s = t.value.toString('latin1');
  let m: RegExpMatchArray | null;
  if (t.tag === TAG.GENERALIZED_TIME && (m = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d{1,9})?Z$/))) {
    const ms = m[7] ? Math.floor(Number(`0${m[7]}`) * 1000) : 0;
    return new Date(Date.UTC(+m[1]!, +m[2]! - 1, +m[3]!, +m[4]!, +m[5]!, +m[6]!, ms));
  }
  if (t.tag === TAG.UTC_TIME && (m = s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/))) {
    const yy = +m[1]!;
    return new Date(Date.UTC(yy < 50 ? 2000 + yy : 1900 + yy, +m[2]! - 1, +m[3]!, +m[4]!, +m[5]!, +m[6]!));
  }
  throw new DerError(`not a DER time: ${JSON.stringify(s.slice(0, 32))}`);
}

// ───────────────────────────── writer ─────────────────────────────

function lengthBytes(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const out: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) out.unshift(v & 0xff);
  return Buffer.from([0x80 | out.length, ...out]);
}

export function der(tag: number, ...content: Buffer[]): Buffer {
  const value = Buffer.concat(content);
  return Buffer.concat([Buffer.from([tag]), lengthBytes(value.length), value]);
}

export const derSeq = (...c: Buffer[]): Buffer => der(TAG.SEQUENCE, ...c);
export const derSet = (...c: Buffer[]): Buffer => der(TAG.SET, ...c);
export const derNull = (): Buffer => der(TAG.NULL);
export const derOctets = (b: Buffer | Uint8Array): Buffer => der(TAG.OCTET_STRING, Buffer.from(b));
export const derBool = (v: boolean): Buffer => der(TAG.BOOLEAN, Buffer.from([v ? 0xff : 0]));
export const derUtf8 = (s: string): Buffer => der(TAG.UTF8_STRING, Buffer.from(s, 'utf8'));
export const derBits = (b: Buffer): Buffer => der(TAG.BIT_STRING, Buffer.from([0]), b);

/** A non-negative INTEGER from big-endian magnitude bytes (or a small number). */
export function derInt(v: number | Buffer): Buffer {
  let b: Buffer;
  if (typeof v === 'number') {
    const out: number[] = [];
    for (let n = v; n > 0; n = Math.floor(n / 256)) out.unshift(n & 0xff);
    b = Buffer.from(out.length ? out : [0]);
  } else {
    b = v;
    while (b.length > 1 && b[0] === 0) b = b.subarray(1);
  }
  if (b[0]! & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return der(TAG.INTEGER, b);
}

export function derOid(oid: string): Buffer {
  const p = oid.split('.').map(Number);
  if (p.length < 2 || p.some((x) => !Number.isSafeInteger(x) || x < 0)) throw new DerError(`bad OID ${oid}`);
  const out: number[] = [];
  const enc = (n: number) => {
    const g: number[] = [n & 0x7f];
    for (let v = Math.floor(n / 128); v > 0; v = Math.floor(v / 128)) g.unshift((v & 0x7f) | 0x80);
    out.push(...g);
  };
  enc(p[0]! * 40 + p[1]!);
  for (const x of p.slice(2)) enc(x);
  return der(TAG.OID, Buffer.from(out));
}

const pad = (n: number, w = 2) => String(n).padStart(w, '0');

export function derGeneralizedTime(d: Date): Buffer {
  const s = `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}Z`;
  return der(TAG.GENERALIZED_TIME, Buffer.from(s, 'latin1'));
}

/** UTCTime for 1950..2049 (as X.509 requires), GeneralizedTime otherwise. */
export function derX509Time(d: Date): Buffer {
  const y = d.getUTCFullYear();
  if (y < 1950 || y > 2049) return derGeneralizedTime(d);
  const s = `${pad(y % 100)}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}Z`;
  return der(TAG.UTC_TIME, Buffer.from(s, 'latin1'));
}
