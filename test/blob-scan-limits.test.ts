/**
 * #15 (0.9.0 blockers): the blob secret scan on hostile sizes. A single 8 MB
 * base64 run overflowed the stack (regex), a 60 MB random binary took 2.2 GB
 * of heap (whole-blob strings and a per-char map), and the private_key regex
 * backtracked quadratically (64 KB of BEGIN headers: 8 s). The scan now walks
 * runs iteratively, scans in windows, stops at MAX_SCAN_BYTES (the rest is
 * flagged `unscanned_size`), and private keys are matched in linear time.
 */
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { gzipSync } from 'node:zlib';

import { describe, expect, it } from 'vitest';

import { MAX_SCAN_BYTES, SCAN_OVERLAP, SCAN_WINDOW, scanBlob } from '../src/audit/blob-scan.js';
import { exportBundle } from '../src/audit/bundle.js';
import { KronicleLite } from '../src/index.js';
import { scanForSecrets, SecretDetectedError, WRITE_DETECTORS } from '../src/secrets/guard.js';
import { tempDir } from './helpers/fs.js';

const GHP = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';
const MB = 1024 * 1024;
const DIST = pathToFileURL(join(__dirname, '..', 'dist', 'index.js')).href;

describe('#15 blob scan: no stack overflow on long runs', () => {
  it('an 8 MB base64 / alnum run scans without throwing; a secret after it is still found', () => {
    const run = Buffer.alloc(8 * MB, 'A');
    expect(() => scanBlob(run)).not.toThrow();
    const b64 = Buffer.from(Buffer.alloc(6 * MB, 7).toString('base64'));
    expect(() => scanBlob(b64)).not.toThrow();
    const hidden = Buffer.concat([run, Buffer.from(' ' + Buffer.from(`token=${GHP}\n`).toString('base64') + '\n')]);
    const s = scanBlob(hidden);
    expect(s.encoded.map((f) => f.detector)).toContain('github_token');
  }, 60_000);
  it('a run that would decode past MAX_DECODED_BYTES is not decoded: flagged unscanned_encoding', () => {
    expect(scanBlob(Buffer.alloc(22 * MB, 'A')).unscanned_encoding).toBe(true);
    expect(scanBlob(Buffer.alloc(20 * MB, 'A')).unscanned_encoding).toBe(false);
  }, 60_000);
  it('a base64url run and a base64 run are both decoded (no regex)', () => {
    const enc = Buffer.from(`k ${GHP} k`).toString('base64url');
    expect(scanBlob(Buffer.from(`x=${enc}`)).encoded.map((f) => f.detector)).toContain('github_token');
  });
});

describe('#15 blob scan: windowed, capped', () => {
  it('a secret across every window boundary is found once, with its absolute line', () => {
    for (const off of [SCAN_WINDOW - 20, SCAN_WINDOW - 1, SCAN_WINDOW, 2 * SCAN_WINDOW - 5]) {
      const pad = Buffer.alloc(off, 0x20);
      pad[10] = 0x0a; // one newline before the secret
      const s = scanBlob(Buffer.concat([pad, Buffer.from(`${GHP}\n`), Buffer.alloc(3 * SCAN_WINDOW, 0x20)]));
      expect(s.raw, String(off)).toEqual([{ field: 'blob', detector: 'github_token', line: 2 }]);
    }
  });
  it('a window does not report what the whole text would not: a token cut by the window start or end, or inside an earlier match', () => {
    const sp = (n: number) => Buffer.alloc(n, 0x20);
    // `xghp_…`: no word boundary before ghp_, but a window whose context starts at the g would see one.
    expect(scanBlob(Buffer.concat([sp(SCAN_WINDOW - 1025), Buffer.from('x' + GHP + ' '), sp(SCAN_WINDOW)])).raw).toEqual([]);
    // `ghp_…_x`: no word boundary after the token, but a window whose text ends right after it would see one.
    expect(scanBlob(Buffer.concat([sp(SCAN_WINDOW + SCAN_OVERLAP - GHP.length), Buffer.from(GHP + '_x '), sp(SCAN_WINDOW)])).raw).toEqual([]);
    // An AWS key line inside a private key block that crosses a window start: one finding, the block.
    const pem = '-----BEGIN RSA PRIVATE KEY-----\n' + 'M'.repeat(64) + '\n' + 'Q'.repeat(64) + '\n'.repeat(3000) + 'AKIAIOSFODNN7EXAMPLQ\n' + 'Z'.repeat(64) + '\n-----END RSA PRIVATE KEY-----\n';
    const r = scanBlob(Buffer.concat([sp(SCAN_WINDOW - 2000), Buffer.from(pem), sp(10)])).raw;
    expect(r.map((f) => f.detector)).toEqual(['private_key']);
  });
  it('bytes past MAX_SCAN_BYTES are not read: a secret there is stored, flagged unscanned_size', () => {
    const kl = new KronicleLite({ memory: true });
    const big = Buffer.alloc(MAX_SCAN_BYTES + 100, 0x20);
    big.write(GHP, MAX_SCAN_BYTES + 10);
    expect(kl.audit.putBlob(big, 'application/octet-stream').unscanned).toEqual(['unscanned_size']);
    kl.close();
  }, 60_000);
  it('over MAX_SCAN_BYTES: flagged unscanned_size, stored, and the flag reaches the bundle', () => {
    expect(MAX_SCAN_BYTES).toBeLessThan(64 * MB);
    const kl = new KronicleLite({ memory: true });
    const big = Buffer.alloc(MAX_SCAN_BYTES + 1, 0x20);
    const r = kl.audit.putBlob(big, 'application/octet-stream');
    expect(r.unscanned).toEqual(['unscanned_size']);
    expect(kl.audit.getBlob(r.sha256)!.flags).toBe('unscanned_size');
    // A secret inside the scanned part is still refused.
    big.write(GHP, 100);
    expect(() => kl.audit.putBlob(big, 'application/octet-stream')).toThrow(SecretDetectedError);
    kl.audit.record('A', [{ kind: 'finding', event_key: 'f', payload: { finding_id: 'V', status: 'discovered', detail: { sha256: r.sha256, size: r.size } } }], 'x');
    const d = tempDir('scan-cap-');
    const m = exportBundle({ chain: kl.chain, audit: kl.audit, signer: kl.identity.signer, audit_id: 'A', dir: d }).manifest;
    expect(m.blobs).toEqual([{ sha256: r.sha256, size: r.size, media_type: 'application/octet-stream', unscanned_size: true }]);
    kl.close();
  }, 60_000);
  it('exactly MAX_SCAN_BYTES is fully scanned (no flag); both flags can be set', () => {
    expect(scanBlob(Buffer.alloc(MAX_SCAN_BYTES, 0x20)).unscanned_size).toBe(false);
    const kl = new KronicleLite({ memory: true });
    const cut = gzipSync(Buffer.from('a'.repeat(5000))).subarray(0, 30);
    const both = Buffer.concat([cut, Buffer.alloc(MAX_SCAN_BYTES, 0x20)]);
    const r = kl.audit.putBlob(both, 'application/gzip');
    expect(r.unscanned).toEqual(['unscanned_encoding', 'unscanned_size']);
    expect(kl.audit.getBlob(r.sha256)!.flags).toBe('unscanned_encoding,unscanned_size');
    kl.close();
  }, 60_000);
  it('redact mode redacts a secret that straddles a window boundary and keeps the rest byte-identical', () => {
    const kl = new KronicleLite({ memory: true });
    const body = Buffer.concat([Buffer.alloc(SCAN_WINDOW - 10, 0x2e), Buffer.from(` ${GHP} `), Buffer.alloc(SCAN_WINDOW, 0x2e)]);
    const r = kl.audit.putBlob(body, 'text/plain', { secrets: 'redact' });
    expect(r.redactions).toBe(1);
    const stored = kl.audit.getBlob(r.sha256)!.bytes;
    expect(stored.toString('latin1')).not.toContain(GHP);
    expect(stored.toString('latin1')).toBe(body.toString('latin1').replace(GHP, '[REDACTED:github_token]'));
    kl.close();
  });
  it('a 60 MB random binary scans under a 256 MB heap (was 2.2 GB)', () => {
    // Seeded (xorshift32), so every platform scans the same bytes; any secret-shaped run in them is refused, never an OOM.
    const code = `
      const { KronicleLite } = await import(${JSON.stringify(DIST)});
      const b = Buffer.alloc(60 * 1024 * 1024);
      let x = 0x9e3779b9;
      for (let i = 0; i < b.length; i += 4) {
        x ^= x << 13; x ^= x >>> 17; x ^= x << 5;
        b.writeUInt32LE(x >>> 0, i);
      }
      const kl = new KronicleLite({ memory: true });
      let r;
      try { r = kl.audit.putBlob(b, 'application/octet-stream').unscanned ?? []; } catch (e) { r = e.code ?? String(e); }
      process.stdout.write(JSON.stringify(r));`;
    const p = spawnSync(process.execPath, ['--max-old-space-size=256', '--input-type=module', '-e', code], { encoding: 'utf8', timeout: 120_000 });
    expect(p.stderr).toBe('');
    expect(p.status).toBe(0);
    expect(JSON.parse(p.stdout)).toEqual(['unscanned_size']);
  }, 130_000);
});

describe('#15 private_key detector: linear time, same matches as its regex', () => {
  const pk = WRITE_DETECTORS.find((d) => d.id === 'private_key')!;
  const B = '-----BEGIN RSA PRIVATE KEY-----\n';
  it('64 KB of BEGIN headers with no END, and a 4 MB body line, scan fast', () => {
    const flood = (B + 'A'.repeat(40) + '\n').repeat(900) + '-----END X\n'.repeat(1000);
    let t = Date.now();
    expect(scanForSecrets(flood)).toEqual([]);
    expect(Date.now() - t).toBeLessThan(1000);
    t = Date.now();
    expect(scanForSecrets(B + 'A'.repeat(4 * MB) + '\n')).toEqual([]);
    expect(Date.now() - t).toBeLessThan(2000);
  });
  it('agrees with the regex on random token soup', () => {
    const parts = [B, '-----BEGIN OPENSSH PRIVATE KEY-----  \r\n', '-----END RSA PRIVATE KEY-----', '-----END X-----', 'A'.repeat(40), 'A'.repeat(39), '+'.repeat(3), '  > ', '#', '\n', '\r\n', 'x', ':-', ' ', '"'];
    let seed = 7;
    const rnd = (n: number) => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) % n);
    for (let i = 0; i < 3000; i++) {
      let s = '';
      for (let j = rnd(24); j >= 0; j--) s += parts[rnd(parts.length)];
      const want = [...s.matchAll(new RegExp(pk.re.source, 'g'))].map((m) => [m.index, m[0]]);
      const got = [...pk.find!(s)].map((m) => [m.index, m[0]]);
      expect(got, JSON.stringify(s)).toEqual(want);
    }
  });
});
