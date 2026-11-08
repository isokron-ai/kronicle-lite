/**
 * #26: a zlib stream whose Adler-32 trailer is corrupted failed inflate (and the
 * raw-deflate retry, which started at the zlib header), so a token in it was
 * stored unscanned and unflagged. The body is now raw-inflated from byte 2,
 * what it recovers is scanned, and the stream is flagged corrupt.
 */
import { deflateSync, gzipSync } from 'node:zlib';

import { describe, expect, it } from 'vitest';

import { scanBlob } from '../src/audit/blob-scan.js';
import { KronicleLite } from '../src/index.js';
import { SecretDetectedError } from '../src/secrets/guard.js';

const GHP = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';
const badAdler = (text: string) => {
  const z = deflateSync(Buffer.from(text));
  z[z.length - 1] = z[z.length - 1]! ^ 0xff;
  return z;
};

describe('#26 zlib with a corrupted Adler-32 trailer', () => {
  it('a token in it is refused, bare and in base64', () => {
    for (const bytes of [badAdler(`token=${GHP}\n`), Buffer.from(badAdler(`token=${GHP}\n`).toString('base64'))]) {
      expect(scanBlob(bytes).encoded.map((f) => f.detector)).toContain('github_token');
      const kl = new KronicleLite({ memory: true });
      expect(() => kl.audit.putBlob(bytes, 'application/octet-stream')).toThrow(SecretDetectedError);
      kl.close();
    }
  });
  it('without a token it is stored flagged unscanned_encoding; an intact zlib stream is not flagged', () => {
    const kl = new KronicleLite({ memory: true });
    expect(kl.audit.putBlob(badAdler('nothing secret here\n'.repeat(40)), 'application/octet-stream').unscanned).toEqual(['unscanned_encoding']);
    expect(kl.audit.putBlob(deflateSync(Buffer.from('nothing secret here\n'.repeat(40))), 'application/octet-stream').unscanned).toBeUndefined();
    kl.close();
  });
  it('Windows-made gzip in base64 stays unflagged', () => {
    const g = gzipSync(Buffer.from('#0' + ' '.repeat(256 * 1024)));
    g[9] = 0x0a;
    expect(scanBlob(Buffer.from(g.toString('base64'))).unscanned_encoding).toBe(false);
  });
});
