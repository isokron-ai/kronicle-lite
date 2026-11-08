/**
 * Secret scan of an audit blob (0.9.0). Audit artifacts are HTTP bodies,
 * traces and transcripts, so a credential is often not in the raw bytes:
 * gzip / deflate / raw deflate / brotli bodies (also after HTTP headers),
 * UTF-16LE / UTF-16BE text anywhere, base64 / base64url fields, nested up to
 * 12 layers (deeper, if still encoded, is flagged). Each view is decoded within a size cap and scanned with the
 * write-time detectors. Anything that cannot be decoded within the cap is
 * scanned as raw bytes only and reported as `unscanned_encoding`.
 *
 * #15: text is scanned in overlapping windows (memory stays bounded whatever
 * the size: a 60 MB binary took 2.2 GB of heap), base64 runs are found by a
 * loop, not a regex (an 8 MB run overflowed the stack), and only the first
 * MAX_SCAN_BYTES of a blob are read: a larger blob is flagged `unscanned_size`.
 */

import { brotliDecompressSync, gunzipSync, inflateRawSync, inflateSync } from 'node:zlib';

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
/** Most decoding layers followed (#15: 5-deep nesting got through); a view still encoded past it is flagged. */
const MAX_NESTING = 12;
/** Most views decoded per blob, and most compressed-stream starts tried per view; past either the blob is flagged. */
const MAX_VIEWS = 8192;
const MAX_STREAMS = 64;
/** Longest HTTP header block examined for a Content-Encoding line. */
const MAX_HEADER_BLOCK = 16 * 1024;

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
  let views = 0;
  const visit = (b: Buffer, via: string, depth: number) => {
    if (depth > MAX_NESTING || ++views > MAX_VIEWS) {
      if (looksEncoded(b)) out.unscanned_encoding = true;
      return;
    }
    const n = Math.min(b.byteLength, MAX_SCAN_BYTES);
    // Compressed streams: at the start (gzip, zlib, or headerless raw deflate / brotli), after an
    // HTTP header block that declares a Content-Encoding, and at each gzip member header.
    const starts = streamStarts(b, n);
    if (starts === 'too_many') out.unscanned_encoding = true;
    else
      for (const st of starts) {
        const z = decompress(b.subarray(st.at), st.encoding);
        if (z === 'too_large' || (z === 'corrupt' && st.sure)) out.unscanned_encoding = true;
        else if (z !== null && z !== 'corrupt' && take(z.byteLength)) scanView(z, `${via}+${z.kind}`, depth);
      }
    // UTF-16 text anywhere in the view: LE at even offsets; at odd offsets (UTF-16BE, or LE after an odd-length prefix)
    for (const parity of utf16Parities(b, n)) {
      const chars = (n - parity) >> 1;
      if (!take(2 * chars)) continue;
      out.encoded.push(...scanText(chars, (x, y) => b.toString('utf16le', parity + 2 * x, parity + 2 * y), `${via}+${parity === 0 ? 'utf16le' : 'utf16be'}`).findings);
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

type Encoding = 'gzip' | 'deflate' | 'br' | 'unknown' | null;

/**
 * Where a compressed stream may start in b[0, n): offset 0 (the encoding is
 * sniffed) and the body after each HTTP header block with a Content-Encoding
 * line (that encoding), where a failure to decode is flagged (`sure`); and each
 * later gzip member header, where a failure may be a coincidence in binary.
 */
function streamStarts(b: Buffer, n: number): { at: number; encoding: Encoding; sure: boolean }[] | 'too_many' {
  const out: { at: number; encoding: Encoding; sure: boolean }[] = [{ at: 0, encoding: null, sure: true }];
  let from = 0;
  for (let i = b.indexOf('\r\n\r\n', 0, 'latin1'); i >= 0 && i < n; i = b.indexOf('\r\n\r\n', i + 1, 'latin1')) {
    if (i - from <= MAX_HEADER_BLOCK) {
      const m = /(?:^|\n)content-encoding:[ \t]*([^\r\n]*)/i.exec(b.toString('latin1', from, i));
      if (m) {
        const v = m[1]!.trim().toLowerCase();
        const encoding: Encoding = v === 'gzip' || v === 'x-gzip' ? 'gzip' : v === 'deflate' ? 'deflate' : v === 'br' ? 'br' : v === 'identity' || v === '' ? null : 'unknown';
        if (encoding !== null) out.push({ at: i + 4, encoding, sure: true });
      }
    }
    from = i + 4;
    if (out.length > MAX_STREAMS) return 'too_many';
  }
  // gzip member header: magic, CM = 8 (deflate), reserved FLG bits clear.
  for (let i = b.indexOf(GZIP_MAGIC, 1); i >= 0 && i < n; i = b.indexOf(GZIP_MAGIC, i + 1)) {
    if (i + 3 < b.length && (b[i + 3]! & 0xe0) === 0 && !out.some((s) => s.at === i)) out.push({ at: i, encoding: null, sure: false });
    if (out.length > MAX_STREAMS) return 'too_many';
  }
  return out;
}
const GZIP_MAGIC = Buffer.from([0x1f, 0x8b, 0x08]);

/**
 * Worth trying a headerless decoder (raw deflate, brotli) on? Each try costs a
 * zlib handle (~0.1 ms), so not on text: a compressed stream does not start
 * with 64 printable bytes.
 */
function headerless(b: Buffer): boolean {
  const n = Math.min(b.length, 64);
  let printable = true;
  for (let i = 0; i < n && printable; i++) printable = (b[i]! >= 0x20 && b[i]! < 0x7f) || b[i] === 0x09 || b[i] === 0x0a || b[i] === 0x0d;
  return !printable;
}

const DECODERS = {
  gzip: gunzipSync,
  deflate: inflateSync,
  'deflate-raw': inflateRawSync,
  br: brotliDecompressSync,
} as const;

/**
 * Decode one stream. `encoding` null: sniff (gzip and zlib by header, then
 * headerless raw deflate and brotli; a headerless decoder that fails means
 * "not this encoding"). `unknown`: declared but not decodable here (zstd…).
 */
function decompress(b: Buffer, encoding: Encoding): (Buffer & { kind?: string }) | 'too_large' | 'corrupt' | null {
  if (encoding === 'unknown') return 'corrupt';
  const gzip = b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b;
  const zlib = b.length >= 2 && b[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(b[1]!);
  const tries: (keyof typeof DECODERS)[] =
    encoding === 'gzip' ? ['gzip'] : encoding === 'deflate' ? ['deflate', 'deflate-raw'] : encoding === 'br' ? ['br'] : gzip ? ['gzip'] : zlib ? ['deflate', 'deflate-raw'] : headerless(b) ? ['deflate-raw', 'br'] : [];
  if (b.length < 8 || tries.length === 0) return null;
  for (const kind of tries) {
    try {
      const r = DECODERS[kind](b, { maxOutputLength: MAX_DECODED_BYTES }) as Buffer & { kind?: string };
      if (r.byteLength === 0) continue;
      r.kind = kind;
      return r;
    } catch (err) {
      if ((err as { code?: string }).code === 'ERR_BUFFER_TOO_LARGE' || err instanceof RangeError) return 'too_large';
    }
  }
  // A declared encoding, or a gzip / zlib header, that does not decode. A zlib header can be a
  // coincidence in binary (the raw-deflate retry above failed too): not flagged.
  return encoding !== null || gzip ? 'corrupt' : null;
}

/**
 * Offsets (0, 1) at which b[0, n) holds UTF-16 text: any 128-byte window
 * (stepped by 64) whose bytes at one parity are mostly NUL and at the other
 * mostly not (#15: only the first 4 KB was looked at, and
 * only for LE). Decoding as UTF-16LE from offset 1 reads UTF-16BE text at
 * offset 0 correctly for the ASCII the detectors match (and LE text after an
 * odd-length prefix).
 */
function utf16Parities(b: Buffer, n: number): (0 | 1)[] {
  const found = new Set<0 | 1>();
  const BLOCK = 64;
  let prevEven = 0;
  let prevOdd = 0;
  let prevLen = 0;
  for (let c = 0; c < n && found.size < 2; c += BLOCK) {
    const end = Math.min(n, c + BLOCK);
    let even = 0;
    let odd = 0;
    for (let i = c; i < end; i++) {
      if (b[i] !== 0) continue;
      if (i & 1) odd++;
      else even++;
    }
    const e = even + prevEven;
    const o = odd + prevOdd;
    const half = (end - c + prevLen) / 2;
    if (half >= 16) {
      if (o > 0.3 * half && e < o / 4) found.add(0);
      if (e > 0.3 * half && o < e / 4) found.add(1);
    }
    prevEven = even;
    prevOdd = odd;
    prevLen = end - c;
  }
  return [...found].sort();
}

/** Past the nesting limit: does this view still look like something the scan would decode? */
function looksEncoded(b: Buffer): boolean {
  const n = Math.min(b.byteLength, MAX_SCAN_BYTES);
  const gzip = b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b;
  const zlib = b.length >= 2 && b[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(b[1]!);
  return gzip || zlib || utf16Parities(b, n).length > 0 || !runs(b, n, inB64, true).next().done || !runs(b, n, inB64url, false).next().done;
}
