/**
 * Stores created by the published 0.7.0 and 0.8.0 lack tables added since (0.7.0: doc_lineage,
 * doc_lineage_gaps, reads; 0.8.0: doc_lineage_gaps; both: the 0.9.0 audit / blob / apply tables).
 * Read-only opens (verify-chain, verify, doctor, orient, export, get, pending) never migrate the
 * file: the missing tables are served as empty TEMP tables, with the data migrations derived into
 * them, so every command answers as it would on a migrated store. A tampered store still fails
 * with the divergence exit code.
 */
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';

import Database from 'better-sqlite3';
import { describe, expect, it } from 'vitest';

import { loadOrCreateIdentity } from '../src/crypto/keys.js';
import { KronicleLite } from '../src/index.js';
import { CLI, cleanEnv, tempDir } from './helpers/fs.js';

const FIXTURES = { '0.7.0': 'store-0.7.0.db.gz', '0.8.0': 'store-0.8.0.db.gz' } as const;
const MISSING = { '0.7.0': ['doc_lineage', 'doc_lineage_gaps', 'reads', 'audit_events', 'blobs', 'apply_results'], '0.8.0': ['doc_lineage_gaps', 'audit_events', 'blobs', 'apply_results'] } as const;

function store(v: keyof typeof FIXTURES): string {
  const data = join(tempDir(`kl-${v}-`), 'data');
  mkdirSync(data, { recursive: true });
  chmodSync(data, 0o700);
  loadOrCreateIdentity(data);
  writeFileSync(join(data, 'kronicle-lite.db'), gunzipSync(readFileSync(join(__dirname, 'fixtures', FIXTURES[v]))), { mode: 0o600 });
  return data;
}
const tablesOnDisk = (data: string) => {
  const db = new Database(join(data, 'kronicle-lite.db'), { readonly: true });
  try {
    return (db.prepare(`SELECT name FROM sqlite_master WHERE type = 'table'`).all() as { name: string }[]).map((r) => r.name);
  } finally {
    db.close();
  }
};
const run = (args: string[], data: string) => {
  const home = tempDir('kl-oldh-');
  return spawnSync(process.execPath, [CLI, ...args, '--data-dir', data], { env: cleanEnv({ HOME: home, USERPROFILE: home }), encoding: 'utf8' });
};
/** Commands that always open read-only: they must not touch the file. */
const READ_ONLY_COMMANDS = [['verify-chain'], ['verify-chain', '--full'], ['verify'], ['doctor', '--no-network', '--full']];
/** Commands that open read-write when they can (and so migrate the store first). */
const MIGRATING_COMMANDS = [['orient', '--actor', 'agent'], ['export'], ['get', 'deploy'], ['pending', '--actor', 'agent']];

describe.each(['0.7.0', '0.8.0'] as const)('a store made by %s, opened read-only by 0.9.0', (v) => {
  it('the fixture really lacks the newer tables', () => {
    const t = tablesOnDisk(store(v));
    for (const n of MISSING[v]) expect(t).not.toContain(n);
  });

  it.each(READ_ONLY_COMMANDS.map((a) => [a.join(' '), a] as const))('%s succeeds and writes nothing', (_name, args) => {
    const data = store(v);
    const before = readFileSync(join(data, 'kronicle-lite.db'));
    const r = run([...args], data);
    expect(r.stdout + r.stderr).not.toMatch(/no such table|INTEGRITY FAILURE/);
    expect(r.status, `${args.join(' ')}: ${r.stdout}${r.stderr}`).toBe(0);
    expect(readFileSync(join(data, 'kronicle-lite.db')).equals(before)).toBe(true);
    for (const n of MISSING[v]) expect(tablesOnDisk(data)).not.toContain(n);
  });

  it.each(MIGRATING_COMMANDS.map((a) => [a.join(' '), a] as const))('%s succeeds on a writable store', (_name, args) => {
    const r = run([...args], store(v));
    expect(r.stdout + r.stderr).not.toMatch(/no such table|INTEGRITY FAILURE/);
    expect(r.status, `${args.join(' ')}: ${r.stdout}${r.stderr}`).toBe(0);
  });

  it('read-only API (a read-only medium): verify, orient, export, get, pending, recall, audit all answer; nothing written', () => {
    const data = store(v);
    const before = readFileSync(join(data, 'kronicle-lite.db'));
    const kl = new KronicleLite({ dataDir: data, readOnly: true });
    expect(kl.verifyAll().ok).toBe(true);
    expect(kl.lineage.checkProjection()).toBeNull();
    expect(kl.audit.query({ audit_id: 'A' })).toEqual([]);
    const st = kl.orient.getSystemState({ actor_id: 'agent' });
    expect(JSON.stringify(st)).not.toMatch(/no such table|could not be read/);
    expect(kl.docs.getDocument('deploy')).not.toBeNull();
    expect(kl.lineage.pending('agent', { limit: 50 })).toBeTruthy();
    expect(kl.recall.recall({ query: 'deploy port', actor_id: 'agent', include_receipts: false }).hits.length).toBeGreaterThan(0);
    const chunks: string[] = [];
    kl.exportEvents({ write: (c: string) => (chunks.push(c), true) } as never);
    expect(chunks.length).toBeGreaterThan(1);
    kl.close();
    expect(readFileSync(join(data, 'kronicle-lite.db')).equals(before)).toBe(true);
  });

  it('a tampered store still fails verify-chain and doctor with the divergence code', () => {
    const data = store(v);
    const db = new Database(join(data, 'kronicle-lite.db'));
    db.prepare(`UPDATE blocks SET content = replace(content, 'team-a', 'team-z') WHERE content LIKE '%team-a%'`).run();
    db.close();
    for (const args of [['verify-chain'], ['doctor', '--no-network', '--full']]) {
      const r = run(args, data);
      expect(r.stdout + r.stderr).not.toMatch(/no such table/);
      expect(r.status, `${args.join(' ')}: ${r.stdout}${r.stderr}`).toBe(1);
      expect(r.stdout + r.stderr).toMatch(/team-z|projection|mismatch/i);
    }
  });

  it('a read-write open migrates it and it still verifies', () => {
    const data = store(v);
    const kl = new KronicleLite({ dataDir: data });
    expect(kl.verifyAll().ok).toBe(true);
    kl.close();
    expect(tablesOnDisk(data)).toEqual(expect.arrayContaining([...MISSING[v]]));
  });
});
