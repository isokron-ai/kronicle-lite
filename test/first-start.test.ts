/**
 * Concurrent first start (agent-memory-bench S3d): several processes open a
 * FRESH data dir at the same instant. None may crash, and all must end up
 * with the same signing key and cursor secret (a split identity signs
 * receipts with a key that is later overwritten on disk).
 */

import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { describe, expect, it } from 'vitest';

import { loadOrCreateIdentity } from '../src/crypto/keys.js';
import { readOrCreateOnce } from '../src/util/once-file.js';
import { tempDir } from './helpers/fs.js';

const INDEX = pathToFileURL(join(__dirname, '..', 'dist', 'index.js')).href;

// Each child imports the built package, spins until a shared start time, then
// opens the store (data dir, key, secret, database) and prints its identity.
const WORKER = `
const [index, dataDir, goAt] = process.argv.slice(1);
const { KronicleLite } = await import(index);
while (Date.now() < Number(goAt)) {}
const s = new KronicleLite({ dataDir });
process.stdout.write(JSON.stringify({ key_id: s.identity.signer.key_id, secret: s.identity.cursor_secret }));
s.close();
`;

function child(dataDir: string, goAt: number): Promise<{ code: number | null; out: string; err: string }> {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, ['--input-type=module', '-e', WORKER, INDEX, dataDir, String(goAt)], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    c.stdout.on('data', (d: Buffer) => (out += d.toString()));
    c.stderr.on('data', (d: Buffer) => (err += d.toString()));
    c.on('close', (code) => resolve({ code, out, err }));
  });
}

describe('concurrent first start', () => {
  it('N processes on a fresh data dir: no crash, one identity', { timeout: 60_000 }, async () => {
    const N = 12;
    for (let trial = 0; trial < 2; trial++) {
      // Not created yet: the processes race on mkdir too.
      const dataDir = join(tempDir('kl-first-start-'), 'nested', 'data');
      const goAt = Date.now() + 1500 + N * 50;
      const rs = await Promise.all(Array.from({ length: N }, () => child(dataDir, goAt)));
      for (const r of rs) expect(r.code, r.err).toBe(0);
      const ids = rs.map((r) => JSON.parse(r.out) as { key_id: string; secret: string });
      expect(new Set(ids.map((i) => i.key_id)).size).toBe(1);
      expect(new Set(ids.map((i) => i.secret)).size).toBe(1);
      // What is on disk is what every process signed with.
      expect(loadOrCreateIdentity(dataDir).signer.key_id).toBe(ids[0]!.key_id);
    }
  });

  it('a create-if-absent file is created once and re-read after', () => {
    const p = join(tempDir('kl-once-'), 'f');
    let made = 0;
    const make = () => {
      made++;
      return `v${made}\n`;
    };
    const a = readOrCreateOnce(p, make, (t) => (t.startsWith('v') ? t.trim() : null));
    const b = readOrCreateOnce(p, make, (t) => (t.startsWith('v') ? t.trim() : null));
    expect(a).toEqual({ value: 'v1', created: true });
    expect(b).toEqual({ value: 'v1', created: false });
    expect(made).toBe(1);
  });

  it('a half-written file is waited for, then reported corrupt', () => {
    const dir = tempDir('kl-torn-');
    writeFileSync(join(dir, 'cursor-secret'), '');
    const t0 = Date.now();
    expect(() => loadOrCreateIdentity(dir)).toThrow(/cursor-secret is corrupt/);
    expect(Date.now() - t0).toBeGreaterThanOrEqual(1500);
    // The key was still created once and is reused.
    const key = readFileSync(join(dir, 'signing-key.pem'), 'utf8');
    writeFileSync(join(dir, 'cursor-secret'), 'a'.repeat(64) + '\n');
    expect(loadOrCreateIdentity(dir).cursor_secret).toBe('a'.repeat(64));
    expect(readFileSync(join(dir, 'signing-key.pem'), 'utf8')).toBe(key);
  });
});
