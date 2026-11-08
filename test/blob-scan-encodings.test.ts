/**
 * #15 (0.9.0 blockers): encodings the blob scan let through silently (no
 * finding and no `unscanned_encoding` flag): 5-deep nesting, an HTTP message
 * whose body is gzip, brotli, raw deflate, UTF-16LE after 4 KB of ASCII, and
 * UTF-16BE. Each is now decoded and refused; nesting past the limit is flagged.
 */
import { brotliCompressSync, deflateRawSync, deflateSync, gzipSync, inflateRawSync } from 'node:zlib';

import { describe, expect, it } from 'vitest';

import { MAX_DECODED_BYTES, MAX_SCAN_BYTES, MAX_SCAN_WORK, scanBlob } from '../src/audit/blob-scan.js';
import { KronicleLite } from '../src/index.js';
import { SecretDetectedError } from '../src/secrets/guard.js';

const GHP = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';
const SECRET = Buffer.from(`{"note": "deploy", "token": "${GHP}"}\n`);
const b64 = (b: Buffer) => Buffer.from(b.toString('base64'));
const http = (enc: string, body: Buffer) => Buffer.concat([Buffer.from(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: ${enc}\r\nContent-Length: ${body.length}\r\n\r\n`), body]);
const utf16be = (s: string) => Buffer.from(s, 'utf16le').swap16();
const ascii = (n: number) => Buffer.alloc(n, 'a');

function nest(depth: number, layer: (b: Buffer) => Buffer): Buffer {
  let b: Buffer = SECRET;
  for (let i = 0; i < depth; i++) b = layer(b);
  return b;
}

const cases: [string, Buffer][] = [
  ['base64 5 deep', nest(5, b64)],
  ['base64 8 deep', nest(8, b64)],
  ['gzip+base64 5 deep (10 layers)', nest(5, (b) => b64(gzipSync(b)))],
  ['HTTP response, gzip body', http('gzip', gzipSync(SECRET))],
  ['HTTP response, deflate (zlib) body', http('deflate', deflateSync(SECRET))],
  ['HTTP response, raw deflate body', http('deflate', deflateRawSync(SECRET))],
  ['HTTP response, brotli body', http('br', brotliCompressSync(SECRET))],
  ['gzip after a binary prefix', Buffer.concat([Buffer.from([0, 1, 2, 3, 0x1f, 0x8b, 9]), gzipSync(SECRET)])],
  ['brotli', brotliCompressSync(SECRET)],
  ['raw deflate', deflateRawSync(SECRET)],
  ['UTF-16LE after 4 KB of ASCII', Buffer.concat([ascii(4096), Buffer.from(SECRET.toString(), 'utf16le')])],
  ['UTF-16LE after 4 KB + 1 of ASCII (odd offset)', Buffer.concat([ascii(4097), Buffer.from(SECRET.toString(), 'utf16le')])],
  ['UTF-16LE after 100 KB of ASCII', Buffer.concat([ascii(100_000), Buffer.from(SECRET.toString(), 'utf16le')])],
  ['UTF-16BE', utf16be(SECRET.toString())],
  ['UTF-16BE with BOM', Buffer.concat([Buffer.from([0xfe, 0xff]), utf16be(SECRET.toString())])],
  ['UTF-16BE after 4 KB + 1 of ASCII', Buffer.concat([ascii(4097), utf16be(SECRET.toString())])],
  ['base64 of UTF-16BE', b64(utf16be(SECRET.toString()))],
];

describe('#15 encoded secrets that got through silently are now refused', () => {
  for (const [name, bytes] of cases) {
    it(name, () => {
      const s = scanBlob(bytes);
      expect(s.encoded.map((f) => f.detector), name).toContain('github_token');
      const kl = new KronicleLite({ memory: true });
      expect(() => kl.audit.putBlob(bytes, 'application/octet-stream')).toThrow(SecretDetectedError);
      expect((kl.db.prepare('SELECT COUNT(*) AS n FROM blobs').get() as { n: number }).n).toBe(0);
      kl.close();
    });
  }
});

describe('#15 what the scan cannot decode is flagged, not passed silently', () => {
  it('nesting past the limit is flagged unscanned_encoding', () => {
    const s = scanBlob(nest(14, b64));
    expect(s.unscanned_encoding).toBe(true);
  });
  it('an HTTP body in an encoding the scan cannot decode, or that does not decode, is flagged', () => {
    expect(scanBlob(http('zstd', Buffer.from('(\xb5/\xfd anything', 'latin1'))).unscanned_encoding).toBe(true);
    expect(scanBlob(http('zstd', Buffer.from('a body that happens to be printable'))).unscanned_encoding).toBe(true);
    expect(scanBlob(http('gzip', Buffer.from('not gzip at all, just text'))).unscanned_encoding).toBe(true);
    expect(scanBlob(http('identity', Buffer.from('plain body'))).unscanned_encoding).toBe(false);
  });
  it('a gzip header inside binary that does not decode is a coincidence: not flagged', () => {
    expect(scanBlob(Buffer.from([9, 9, 9, 0x1f, 0x8b, 0x08, 0x00, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])).unscanned_encoding).toBe(false);
  });
  it('more gzip headers than it will try, or more views than it will decode: flagged', () => {
    const many = Buffer.concat([Buffer.from('x'), ...Array.from({ length: 100 }, () => Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x20]))]);
    expect(scanBlob(many).unscanned_encoding).toBe(true);
    // 2 × 4000 fields, each base64 of a base64 run: about 16,000 views, the last ones still encoded.
    const field = Buffer.from('A'.repeat(30)).toString('base64');
    const inner = Buffer.from(Array.from({ length: 4000 }, () => field).join(' '));
    const wide = Buffer.from(Array.from({ length: 2 }, () => inner.toString('base64')).join(' '));
    expect(scanBlob(wide).unscanned_encoding).toBe(true);
  });
  it('plain text, zero padding and random-looking bytes are not flagged', () => {
    expect(scanBlob(Buffer.from('hello world\n'.repeat(1000))).unscanned_encoding).toBe(false);
    expect(scanBlob(Buffer.alloc(64 * 1024)).unscanned_encoding).toBe(false);
    const prng = Buffer.alloc(256 * 1024);
    let x = 12345;
    for (let i = 0; i < prng.length; i++) prng[i] = (x = (x * 1103515245 + 12345) >>> 0) >>> 24;
    expect(scanBlob(prng).unscanned_encoding).toBe(false);
  });
});

describe('#15 review: brotli that raw deflate "decodes" first, and bombs', () => {
  const hidden = brotliCompressSync(Buffer.concat([Buffer.alloc(1024 * 1024), Buffer.from(`token=${GHP}\n`)]));
  it('brotli of 1 MB of zeros + a token (raw deflate decodes it too, to junk) is refused, bare and in base64', () => {
    expect(hidden.length).toBeLessThan(200);
    expect(inflateRawSync(hidden).length).toBeGreaterThan(0); // the decoder that used to win
    for (const bytes of [hidden, b64(hidden)]) {
      expect(scanBlob(bytes).encoded.map((f) => f.detector)).toContain('github_token');
      const kl = new KronicleLite({ memory: true });
      expect(() => kl.audit.putBlob(bytes, 'application/octet-stream')).toThrow(SecretDetectedError);
      kl.close();
    }
  });
  it('a tiny brotli bomb (17 MB of output) is flagged unscanned_encoding, bare and in base64', () => {
    const bomb = brotliCompressSync(Buffer.alloc(17 * 1024 * 1024));
    expect(bomb.length).toBeLessThan(100);
    expect(scanBlob(bomb).unscanned_encoding).toBe(true);
    expect(scanBlob(b64(bomb)).unscanned_encoding).toBe(true);
  });
});

describe('#15 review: the work one blob can cost is bounded', () => {
  const bomb = brotliCompressSync(Buffer.alloc(17 * 1024 * 1024));
  it('63 brotli bombs in one view, and 4,000 base64-wrapped copies: a few decoder calls, flagged', () => {
    const declared = Buffer.concat(Array.from({ length: 63 }, () => http('br', bomb)));
    const wrapped = Buffer.from(Array.from({ length: 4000 }, () => bomb.toString('base64')).join(' '));
    for (const blob of [declared, wrapped]) {
      const s = scanBlob(blob);
      expect(s.unscanned_encoding).toBe(true);
      expect(s.cost.work).toBeLessThanOrEqual(MAX_SCAN_WORK);
      // Each capped stream is charged the whole 16 MB cap: the 48 MB decode budget allows 3, then nothing more is decoded.
      expect(s.cost.decoder_calls).toBeLessThan(20);
    }
  }, 60_000);
  it('a 32 MB view and a 16 MB gzip view, each with 62 gzip member headers, stop at MAX_SCAN_WORK, flagged', () => {
    const HDR = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 3]);
    const inner = Buffer.alloc(MAX_DECODED_BYTES, 0x20);
    for (let i = 0; i < 62; i++) HDR.copy(inner, 1 + i * 16);
    const z = gzipSync(inner);
    const big = Buffer.alloc(MAX_SCAN_BYTES, 0x20);
    z.copy(big, 0);
    for (let i = 0; i < 62; i++) HDR.copy(big, z.length + 1 + i * 16);
    const s = scanBlob(big);
    expect(s.unscanned_encoding).toBe(true);
    expect(s.cost.work).toBeLessThanOrEqual(MAX_SCAN_WORK);
  }, 60_000);
});
