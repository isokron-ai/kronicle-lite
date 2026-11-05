/**
 * Secret scan of an audit blob (0.9.0). Audit artifacts are HTTP bodies,
 * traces and transcripts, so a credential is often not in the raw bytes:
 * gzip/deflate bodies, UTF-16LE text, base64 / base64url fields (and gzip
 * inside base64). Each view is decoded within a size cap and scanned with the
 * write-time detectors. Anything that cannot be decoded within the cap is
 * scanned as raw bytes only and reported as `unscanned_encoding`.
 */

import { gunzipSync, inflateRawSync, inflateSync } from 'node:zlib';

import { scanForSecrets, type SecretFinding } from '../secrets/guard.js';

/** Most bytes any one decoded view may expand to. */
export const MAX_DECODED_BYTES = 16 * 1024 * 1024;
/** Most bytes all decoded views of one blob may add up to. */
const MAX_TOTAL_DECODED = 48 * 1024 * 1024;
/** Most base64 segments decoded per view. */
const MAX_SEGMENTS = 4096;
const MAX_NESTING = 3;
const B64 = /[A-Za-z0-9+/]{24,}={0,2}/g;
const B64URL = /[A-Za-z0-9_-]{24,}/g;

export interface BlobScan {
  /** Findings in the raw bytes (latin1): these can be redacted in place. */
  raw: SecretFinding[];
  /** Findings only visible after decoding (gzip, deflate, UTF-16LE, base64): these cannot be redacted in place. */
  encoded: SecretFinding[];
  /** true when some view could not be decoded within the cap (scanned as raw bytes only). */
  unscanned_encoding: boolean;
}

export function scanBlob(bytes: Buffer): BlobScan {
  const out: BlobScan = { raw: scanForSecrets(bytes.toString('latin1'), 'blob'), encoded: [], unscanned_encoding: false };
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
    // gzip / zlib / raw deflate
    const z = decompress(b);
    if (z === 'too_large' || z === 'corrupt') out.unscanned_encoding = true;
    else if (z !== null && take(z.byteLength)) scanView(z, `${via}+${z.kind}`, depth);
    // UTF-16LE (BOM, or text with NUL high bytes)
    if (looksUtf16le(b) && take(b.byteLength)) {
      const t = b.toString('utf16le');
      out.encoded.push(...scanForSecrets(t, `${via}+utf16le`));
    }
    // base64 / base64url segments
    const text = b.toString('latin1');
    let segments = 0;
    for (const re of [B64, B64URL]) {
      for (const m of text.matchAll(re)) {
        if (++segments > MAX_SEGMENTS) {
          out.unscanned_encoding = true;
          return;
        }
        const dec = Buffer.from(m[0], re === B64 ? 'base64' : 'base64url');
        if (dec.byteLength < 8 || !take(dec.byteLength)) continue;
        scanView(dec, `${via}+base64`, depth);
      }
    }
  };
  const scanView = (b: Buffer, via: string, depth: number) => {
    out.encoded.push(...scanForSecrets(b.toString('latin1'), via));
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
