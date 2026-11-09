/**
 * A store created by the published kronicle-lite 0.8.0 (test/fixtures/store-0.8.0.db.gz, made by
 * make-store-0.8.0.mjs) predates 0.8.1's doc_lineage_gaps table as well as the 0.9.0 tables.
 * Verification opens it read-only and never migrates; a missing derived table is "nothing stored
 * yet", never a divergence (exit 1) or "no such table".
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';

import { describe, expect, it } from 'vitest';

import { loadOrCreateIdentity } from '../src/crypto/keys.js';
import { KronicleLite } from '../src/index.js';
import { CLI, cleanEnv, tempDir } from './helpers/fs.js';

function store080(): string {
  const data = join(tempDir('kl-080-'), 'data');
  mkdirSync(data, { recursive: true });
  loadOrCreateIdentity(data);
  writeFileSync(join(data, 'kronicle-lite.db'), gunzipSync(readFileSync(join(__dirname, 'fixtures', 'store-0.8.0.db.gz'))));
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

describe('a 0.8.0 store under 0.9.0 verification (read-only, no migration)', () => {
  it('the fixture really is a 0.8.0 store: no doc_lineage_gaps', () => {
    expect(tables(store080())).not.toContain('doc_lineage_gaps');
  });

  it('verify-chain, verify and doctor pass, and write nothing', () => {
    const data = store080();
    const home = tempDir('kl-080h-');
    const before = readFileSync(join(data, 'kronicle-lite.db'));
    for (const args of [['verify-chain'], ['verify'], ['verify-chain', '--full'], ['doctor', '--no-network', '--full']]) {
      const r = run([...args, '--data-dir', data], home);
      expect(r.stdout + r.stderr).not.toMatch(/no such table/);
      expect(r.status, `${args.join(' ')}: ${r.stdout}${r.stderr}`).toBe(0);
    }
    expect(readFileSync(join(data, 'kronicle-lite.db')).equals(before)).toBe(true);
    expect(tables(data)).not.toContain('doc_lineage_gaps');
  });

  it('read-only API: verifyAll ok; lineage gap lookups answer from the chain', () => {
    const kl = new KronicleLite({ dataDir: store080(), readOnly: true });
    expect(kl.verifyAll().ok).toBe(true);
    expect(kl.lineage.checkProjection()).toBeNull();
    const doc = (kl.db.prepare(`SELECT doc_id FROM documents LIMIT 1`).get() as { doc_id: string }).doc_id;
    expect(kl.lineage.gapSeq(doc)).toBeNull();
    kl.close();
  });

  it('a migrated store that lost doc_lineage_gaps is a divergence, not "not derived yet"', () => {
    const data = store080();
    new KronicleLite({ dataDir: data }).close(); // read-write open: migrates
    const kl = new KronicleLite({ dataDir: data });
    kl.db.exec('DROP TABLE doc_lineage_gaps');
    expect(kl.verifyAll().ok).toBe(false);
    expect(kl.lineage.checkProjection()).toMatch(/doc_lineage_gaps/);
    kl.close();
  });
});
