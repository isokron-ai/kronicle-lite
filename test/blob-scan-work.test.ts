/**
 * #24: the blob scan's work cap did not count regex time (a 256 KB input took
 * 7.6 s at 1.4M work units). Every regex pass is now charged (REGEX_PASSES
 * units per character scanned), and a per-blob time budget (MAX_SCAN_MS) stops
 * the scan, flagged, instead of blocking. The clock is injected here: no
 * assertion depends on wall-clock time.
 */
import { gzipSync } from 'node:zlib';

import { describe, expect, it } from 'vitest';

import { MAX_SCAN_MS, MAX_SCAN_WORK, REGEX_PASSES, scanBlob } from '../src/audit/blob-scan.js';

const GHP = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';
const MB = 1024 * 1024;

describe('#24 blob scan: regex passes are charged, time is bounded', () => {
  it('each character scanned costs REGEX_PASSES work units, raw and decoded', () => {
    expect(REGEX_PASSES).toBeGreaterThan(10);
    const raw = scanBlob(Buffer.alloc(MB, 0x20));
    expect(raw.cost.work).toBeGreaterThanOrEqual(MB * REGEX_PASSES);
    const view = scanBlob(gzipSync(Buffer.alloc(MB, 0x20)));
    expect(view.cost.work).toBeGreaterThanOrEqual(MB * REGEX_PASSES);
  });
  it('out of time during the raw scan: it stops, flagged unscanned_size, and a secret past that point is not reached', () => {
    let t = 0;
    const clock = () => (t += MAX_SCAN_MS / 2); // every look at the clock costs half the budget
    const big = Buffer.alloc(16 * MB, 0x20);
    big.write(GHP, 12 * MB);
    const s = scanBlob(big, { clock });
    expect(s.unscanned_size).toBe(true);
    expect(s.unscanned_encoding).toBe(true);
    expect(s.raw).toEqual([]);
    // With time to spare the same bytes are scanned whole.
    const ok = scanBlob(big, { clock: () => 0 });
    expect(ok.unscanned_size).toBe(false);
    expect(ok.raw.map((f) => f.detector)).toEqual(['github_token']);
  });
  it('out of time before a decoded view: not decoded, flagged unscanned_encoding', () => {
    const z = gzipSync(Buffer.from(`token=${GHP}\n`));
    let calls = 0;
    const s = scanBlob(z, { clock: () => (++calls <= 2 ? 0 : MAX_SCAN_MS + 1) }); // the deadline, then the raw window: in time
    expect(s.unscanned_size).toBe(false);
    expect(s.unscanned_encoding).toBe(true);
    expect(s.encoded).toEqual([]);
    expect(scanBlob(z, { clock: () => 0 }).encoded.map((f) => f.detector)).toEqual(['github_token']);
  });
  it('the work cap stops decoding, flagged: work never passes it', () => {
    // 64 gzip views of 256 KB, base64-wrapped: about 64 × 256 KB × REGEX_PASSES units to scan them all. The OS byte is
    // Windows' (0x0a) on every platform: some base64url pieces of these then decode as brotli past the probe and fail,
    // which used to drain the decode budget and flag the real streams (Windows CI).
    const gz = (i: number) => {
      const g = gzipSync(Buffer.from(`#${i}` + ' '.repeat(256 * 1024)));
      g[9] = 0x0a;
      return g.toString('base64');
    };
    const blob = Buffer.from(Array.from({ length: 64 }, (_, i) => gz(i)).join(' '));
    const cap = 64 * 256 * 1024 * REGEX_PASSES * 0.5;
    const s = scanBlob(blob, { max_work: cap, clock: () => 0 });
    expect(s.unscanned_encoding).toBe(true);
    expect(s.cost.work).toBeLessThanOrEqual(cap);
    const whole = scanBlob(blob, { clock: () => 0 });
    expect(whole.unscanned_encoding).toBe(false);
    expect(whole.cost.work).toBeGreaterThan(cap);
  });
  it('max_work number tricks are ignored (the real cap applies)', () => {
    const blob = gzipSync(Buffer.alloc(MB, 0x20));
    for (const bad of [-1, 0, NaN, Infinity, Number('1e400'), MAX_SCAN_WORK * 2, '5' as unknown as number]) {
      expect(scanBlob(blob, { max_work: bad }).unscanned_encoding, String(bad)).toBe(false);
    }
  });
});
