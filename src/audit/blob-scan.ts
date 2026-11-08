/**
 * Secret scan of an audit blob (0.9.0). Audit artifacts are HTTP bodies,
 * traces and transcripts, so a credential is often not in the raw bytes:
 * gzip/deflate bodies, UTF-16LE text, base64 / base64url fields (and gzip
 * inside base64). Each view is decoded within a size cap and scanned with the
 * write-time detectors. Anything that cannot be decoded within the cap is
 * scanned as raw bytes only and reported as `unscanned_encoding`.
 *
 * #15: text is scanned in overlapping windows (memory stays bounded whatever
 * the size: a 60 MB binary took 2.2 GB of heap), base64 runs are found by a
 * loop, not a regex (an 8 MB run overflowed the stack), and only the first
 * MAX_SCAN_BYTES of a blob are read: a larger blob is flagged `unscanned_size`.
 */

import { gunzipSync, inflateRawSync, inflateSync } from 'node:zlib';

import { secretSpans, type SecretFinding } from '../secrets/guard.js';

/** Most bytes any one decoded view may expand to. */
export const MAX_DECODED_BYTES = 16 * 1024 * 1024;
/** Most bytes all decoded views of one blob may add up to. */
const MAX_TOTAL_DECODED = 48 * 1024 * 1024;
/** Most bytes of a blob the scan reads (raw and its views); a larger blob is flagged `unscanned_size`. */
export const MAX_SCAN_BYTES = 32 * 1024 * 1024;
/**
 * Characters each scan window owns; a window also reads SCAN_CONTEXT before and
 * SCAN_OVERLAP after, so a match up to SCAN_OVERLAP long is found whole (a
 * longer one that crosses a window end is cut short or, for a private key
 * block, missed).
 */
export const SCAN_WINDOW = 2 * 1024 * 1024;
export const SCAN_OVERLAP = 512 * 1024;
const SCAN_CONTEXT = 1024;
/** Most base64 segments decoded per view. */
const MAX_SEGMENTS = 4096;
const MAX_NESTING = 3;

export type ScanFlag = 'unscanned_encoding' | 'unscanned_size';

export interface BlobScan {
  /** Findings in the raw bytes (latin1): these can be redacted in place. */
  raw: SecretFinding[];
  /** Byte ranges of the raw findings (same order), for redaction. */
  raw_spans: { detector: string; start: number; end: number }[];
  /** Findings only visible after decoding (gzip, deflate, UTF-16LE, base64): these cannot be redacted in place. */
  encoded: SecretFinding[];
  /** true when some view could not be decoded within the cap (scanned as raw bytes only). */
  unscanned_encoding: boolean;
  /** true when the blob is larger than MAX_SCAN_BYTES: bytes past it were not scanned. */
  unscanned_size: boolean;
}

/** The flags a scan sets, in a fixed order (stored comma-separated in blobs.flags). */
export function scanFlags(s: Pick<BlobScan, ScanFlag>): ScanFlag[] {
  return (['unscanned_encoding', 'unscanned_size'] as const).filter((f) => s[f]);
}

/**
 * Scan `n` characters of text, read through `slice`, window by window. Each
 * window keeps the matches that start in the part it owns, so a match across a
 * boundary is reported once; lines are counted across windows.
 */
function scanText(n: number, slice: (a: number, b: number) => string, field: string): { findings: SecretFinding[]; spans: BlobScan['raw_spans'] } {
  const findings: SecretFinding[] = [];
  const spans: BlobScan['raw_spans'] = [];
  let line = 1;
  let lastEnd = 0;
  for (let s = 0; s < n; s += SCAN_WINDOW) {
    const from = Math.max(0, s - SCAN_CONTEXT);
    const ctx = s - from;
    const text = slice(from, Math.min(n, s + SCAN_WINDOW + SCAN_OVERLAP));
    const own = ctx + Math.min(SCAN_WINDOW, n - s);
    let pos = ctx;
    for (const m of secretSpans(text)) {
      if (m.start < ctx || m.start >= own) continue;
      const start = from + m.start;
      if (start < lastEnd) continue; // inside a match an earlier window kept
      for (; pos < m.start; pos++) if (text.charCodeAt(pos) === 10) line++;
      findings.push({ field, detector: m.detector, line });
      spans.push({ detector: m.detector, start, end: from + m.end });
      lastEnd = from + m.end;
    }
    for (; pos < own; pos++) if (text.charCodeAt(pos) === 10) line++;
  }
  return { findings, spans };
}

const scanLatin1 = (b: Buffer, n: number, field: string) => scanText(n, (x, y) => b.toString('latin1', x, y), field);

// Byte classes for the base64 run finder.
const ALNUM = new Uint8Array(256);
for (let c = 0; c < 256; c++) ALNUM[c] = /[A-Za-z0-9]/.test(String.fromCharCode(c)) ? 1 : 0;
const inB64 = (c: number) => ALNUM[c] === 1 || c === 0x2b || c === 0x2f; // + /
const inB64url = (c: number) => ALNUM[c] === 1 || c === 0x2d || c === 0x5f; // - _

/** Maximal runs of ≥ 24 alphabet bytes in b[0, n) (base64: plus up to two `=`); a loop, so no run length overflows anything. */
function* runs(b: Buffer, n: number, inSet: (c: number) => boolean, pad: boolean): Generator<[start: number, end: number, alnumOnly: boolean]> {
  let i = 0;
  while (i < n) {
    if (!inSet(b[i]!)) {
      i++;
      continue;
    }
    let j = i;
    let alnum = true;
    while (j < n && inSet(b[j]!)) {
      if (ALNUM[b[j]!] !== 1) alnum = false;
      j++;
    }
    let e = j;
    if (pad) while (e < n && e - j < 2 && b[e] === 0x3d) e++;
    if (j - i >= 24) yield [i, e, alnum];
    i = j;
  }
}

export function scanBlob(bytes: Buffer): BlobScan {
  const limit = Math.min(bytes.byteLength, MAX_SCAN_BYTES);
  const raw = scanLatin1(bytes, limit, 'blob');
  const out: BlobScan = { raw: raw.findings, raw_spans: raw.spans, encoded: [], unscanned_encoding: false, unscanned_size: bytes.byteLength > MAX_SCAN_BYTES };
  let budget = MAX_TOTAL_DECODED;
  const take = (n: number): boolean => {
    if (n > budget) {
      out.unscanned_encoding = true;
      return false;
    }
    budget -= n;
    return true;
  };
  const visit = (b: Buffer, via: string, depth: number) => {
    if (depth > MAX_NESTING) return;
    const n = Math.min(b.byteLength, MAX_SCAN_BYTES);
    // gzip / zlib / raw deflate
    const z = decompress(b);
    if (z === 'too_large' || z === 'corrupt') out.unscanned_encoding = true;
    else if (z !== null && take(z.byteLength)) scanView(z, `${via}+${z.kind}`, depth);
    // UTF-16LE (BOM, or text with NUL high bytes)
    if (looksUtf16le(b) && take(n)) {
      out.encoded.push(...scanText(n >> 1, (x, y) => b.toString('utf16le', 2 * x, 2 * y), `${via}+utf16le`).findings);
    }
    // base64 / base64url segments
    let segments = 0;
    const seen = new Map<number, number>();
    for (const [inSet, enc] of [
      [inB64, 'base64'],
      [inB64url, 'base64url'],
    ] as const) {
      for (const [s, e, alnum] of runs(b, n, inSet, enc === 'base64')) {
        if (enc === 'base64') {
          if (alnum) seen.set(s, e);
        } else if (alnum && seen.get(s) === e) continue; // the same bytes decode the same way: done in the base64 pass
        if (++segments > MAX_SEGMENTS) {
          out.unscanned_encoding = true;
          return;
        }
        const size = Math.floor(((e - s) * 3) / 4);
        if (size < 8) continue;
        if (size > MAX_DECODED_BYTES || !take(size)) {
          out.unscanned_encoding = true;
          continue;
        }
        scanView(Buffer.from(b.toString('latin1', s, e), enc), `${via}+base64`, depth);
      }
    }
  };
  const scanView = (b: Buffer, via: string, depth: number) => {
    out.encoded.push(...scanLatin1(b, Math.min(b.byteLength, MAX_SCAN_BYTES), via).findings);
    visit(b, via, depth + 1);
  };
  visit(bytes, 'blob', 0);
  return out;
}

function decompress(b: Buffer): (Buffer & { kind?: string }) | 'too_large' | 'corrupt' | null {
  const gzip = b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b;
  const zlib = b.length >= 2 && b[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(b[1]!);
  if (!gzip && !zlib) return null;
  try {
    const r = (gzip ? gunzipSync : inflateSync)(b, { maxOutputLength: MAX_DECODED_BYTES }) as Buffer & { kind?: string };
    r.kind = gzip ? 'gzip' : 'deflate';
    return r;
  } catch (err) {
    if ((err as { code?: string }).code === 'ERR_BUFFER_TOO_LARGE' || err instanceof RangeError) return 'too_large';
    // A zlib header can be a coincidence in binary; try raw deflate before calling it undecodable.
    if (!gzip) {
      try {
        inflateRawSync(b, { maxOutputLength: MAX_DECODED_BYTES });
      } catch {
        return null;
      }
    }
    return 'corrupt';
  }
}

function looksUtf16le(b: Buffer): boolean {
  if (b.length >= 2 && b[0] === 0xff && b[1] === 0xfe) return true;
  const n = Math.min(b.length, 4096) & ~1;
  if (n < 16) return false;
  let zeros = 0;
  for (let i = 1; i < n; i += 2) if (b[i] === 0) zeros++;
  return zeros / (n / 2) > 0.3;
}
