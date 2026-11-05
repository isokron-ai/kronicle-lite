/**
 * A store created by kronicle-lite 0.8.1 (test/fixtures/store-0.8.1.db.gz, made by
 * make-store-0.8.1.mjs with main 3df5fea) has none of the 0.9.0 tables. Verification opens it
 * read-only and never migrates: a missing audit table is "no audit events", never a divergence
 * (exit 1), and nothing is written.
 */
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';

import { afterEach, describe, expect, it } from 'vitest';

import { loadOrCreateIdentity } from '../src/crypto/keys.js';
import { KronicleLite } from '../src/index.js';
import { CLI, cleanEnv, tempDir } from './helpers/fs.js';

const POSIX = process.platform !== 'win32';
const ROOT = typeof process.getuid === 'function' && process.getuid() === 0;
const locked: string[] = [];
afterEach(() => {
  for (const d of locked.splice(0)) {
    try {
      chmodSync(d, 0o700);
      chmodSync(join(d, 'kronicle-lite.db'), 0o600);
    } catch {
      // ignore
    }
  }
});

/** A data dir holding the real 0.8.1 store (keys made beside it; the chain carries no signatures that need the original key). */
function store081(): string {
  const data = join(tempDir('kl-081-'), 'data');
  mkdirSync(data, { recursive: true });
  loadOrCreateIdentity(data);
  writeFileSync(join(data, 'kronicle-lite.db'), gunzipSync(readFileSync(join(__dirname, 'fixtures', 'store-0.8.1.db.gz'))));
  return data;
}
const tables = (data: string) => {
  const kl = new KronicleLite({ dataDir: data, readOnly: true });
  try {
    return (kl.db.prepare(`SELECT name FROM sqlite_master WHERE type = 'table'`).all() as { name: string }[]).map((r) => r.name);
  } finally {
    kl.close();
  }
};
const run = (args: string[], home: string) => spawnSync(process.execPath, [CLI, ...args], { env: cleanEnv({ HOME: home, USERPROFILE: home }), encoding: 'utf8' });

describe('a 0.8.1 store under 0.9.0 verification (read-only, no migration)', () => {
  it('the fixture really is a 0.8.1 store: no audit / blob / apply tables', () => {
    const t = tables(store081());
    expect(t).toContain('doc_lineage_gaps');
    for (const n of ['audit_events', 'audit_findings', 'blobs', 'apply_confirmations', 'apply_results']) expect(t).not.toContain(n);
  });

  it('verify-chain and verify (local) pass with exit 0, and write nothing', () => {
    const data = store081();
    const home = tempDir('kl-081h-');
    const before = readFileSync(join(data, 'kronicle-lite.db'));
    for (const args of [['verify-chain'], ['verify'], ['verify-chain', '--full']]) {
      const r = run([...args, '--data-dir', data], home);
      expect(r.status, `${args.join(' ')}: ${r.stdout}${r.stderr}`).toBe(0);
      expect(r.stdout + r.stderr).not.toMatch(/no such table/);
    }
    expect(readFileSync(join(data, 'kronicle-lite.db')).equals(before)).toBe(true);
    expect(tables(data)).not.toContain('audit_events');
  });

  it('read-only API: verifyAll ok, audit queries answer empty', () => {
    const kl = new KronicleLite({ dataDir: store081(), readOnly: true });
    expect(kl.verifyAll().ok).toBe(true);
    expect(kl.audit.query({ audit_id: 'A' })).toEqual([]);
    expect(kl.audit.findings('A')).toEqual([]);
    expect(kl.audit.checkProjection()).toBeNull();
    kl.close();
  });

  it.skipIf(!POSIX || ROOT)('on read-only media (chmod 0555 dir, 0444 file) verify-chain still passes', () => {
    const data = store081();
    const home = tempDir('kl-081h-');
    chmodSync(join(data, 'kronicle-lite.db'), 0o444);
    chmodSync(data, 0o555);
    locked.push(data);
    const r = run(['verify-chain', '--data-dir', data], home);
    expect(r.status, r.stdout + r.stderr).toBe(0);
  });

  it('a read-write open migrates it (the tables appear) and it still verifies', () => {
    const data = store081();
    const kl = new KronicleLite({ dataDir: data });
    expect(kl.verifyAll().ok).toBe(true);
    kl.close();
    expect(tables(data)).toEqual(expect.arrayContaining(['audit_events', 'blobs', 'apply_confirmations']));
  });
});
