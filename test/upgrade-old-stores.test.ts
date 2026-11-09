/**
 * Stores created by the published 0.7.0 and 0.8.0 lack tables added since (0.7.0: doc_lineage,
 * doc_lineage_gaps, reads; 0.8.0: doc_lineage_gaps; both: the 0.9.0 audit / blob / apply tables).
 * Opens that do not migrate (verify-chain, verify, doctor, a read-only medium) leave
 * kronicle-lite.db byte-identical (SQLite may create the -wal / -shm sidecars of a WAL database on
 * a writable directory): the tables the store's release never had are served as empty TEMP
 * tables, with the data migrations derived into them. Commands that open read-write (orient,
 * export, get, pending) migrate the store first, as intended. A table missing from a store whose
 * release had it is damage, and a tampered store fails, both with the divergence exit code.
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

  it.each(READ_ONLY_COMMANDS.map((a) => [a.join(' '), a] as const))('%s succeeds and leaves kronicle-lite.db byte-identical', (_name, args) => {
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

  const TAMPERS: [string, string, RegExp][] = [
    ['a block text', `UPDATE blocks SET content = replace(content, 'team-a', 'team-z') WHERE content LIKE '%team-a%'`, /projection|mismatch/i],
    ['an event payload', `UPDATE events SET payload_canonical = replace(payload_canonical, '8080', '8081') WHERE seq = (SELECT MIN(seq) FROM events WHERE payload_canonical LIKE '%8080%')`, /hash_mismatch/],
    ['an event this_hash', `UPDATE events SET this_hash = substr(this_hash, 1, 63) || CASE substr(this_hash, 64) WHEN '0' THEN '1' ELSE '0' END WHERE seq = 2`, /hash_mismatch|link_broken/],
    ['the head event (deleted)', `DELETE FROM events WHERE seq = (SELECT MAX(seq) FROM events)`, /seq_gap|hash|mismatch/],
  ];
  it.each(TAMPERS)('tampering with %s fails verify-chain and doctor with the divergence code', (_what, sql, why) => {
    const data = store(v);
    const db = new Database(join(data, 'kronicle-lite.db'));
    expect(db.prepare(sql).run().changes).toBeGreaterThan(0);
    db.close();
    for (const args of [['verify-chain'], ['doctor', '--no-network', '--full']]) {
      const r = run(args, data);
      expect(r.stdout + r.stderr).not.toMatch(/no such table/);
      expect(r.status, `${args.join(' ')}: ${r.stdout}${r.stderr}`).toBe(1);
      expect(r.stdout + r.stderr).toMatch(why);
    }
  });

  it.each(['doc_lineage_gaps', 'doc_lineage', 'reads', 'audit_events', 'blobs'])(
    'migrated, then %s dropped: damage, not "an older store" (exit 1, also with the migration keys gone)',
    (table) => {
      for (const forgetMigrations of [false, true]) {
        const data = store(v);
        new KronicleLite({ dataDir: data }).close(); // read-write open: migrates, marks the schema generation
        const db = new Database(join(data, 'kronicle-lite.db'));
        db.exec(`DROP TABLE ${table}`);
        if (forgetMigrations) db.exec(`DELETE FROM meta WHERE key LIKE 'migration.%'`);
        db.pragma('wal_checkpoint(TRUNCATE)');
        db.close();
        for (const args of [['verify-chain'], ['doctor', '--no-network', '--full']]) {
          const r = run(args, data);
          expect(r.status, `${table} ${args.join(' ')}: ${r.stdout}${r.stderr}`).toBe(1);
          expect(r.stdout + r.stderr).toMatch(new RegExp(`${table}.*missing|missing.*${table}|no such table: ${table}`));
        }
      }
    },
  );

  it.each(['reads', 'blobs', 'doc_lineage_gaps'])('a schema_generation key forged down to 0.7.0 cannot hide a dropped %s (exit 1)', (table) => {
    const data = store(v);
    new KronicleLite({ dataDir: data }).close(); // migrates and marks 0.9.0
    const db = new Database(join(data, 'kronicle-lite.db'));
    db.exec(`UPDATE meta SET value = '0.7.0' WHERE key = 'schema_generation'; DROP TABLE ${table};`);
    db.pragma('wal_checkpoint(TRUNCATE)');
    db.close();
    for (const args of [['verify-chain'], ['doctor', '--no-network', '--full']]) {
      const r = run(args, data);
      expect(r.status, `${table} ${args.join(' ')}: ${r.stdout}${r.stderr}`).toBe(1);
      expect(r.stdout + r.stderr).toMatch(new RegExp(`${table}.*missing|no such table: ${table}`));
    }
  });

  it('a long-lived read-only connection follows a migration made by another connection (no stale TEMP shadow)', () => {
    const data = store(v);
    const ro = new KronicleLite({ dataDir: data, readOnly: true });
    expect(ro.verifyAll().ok).toBe(true);
    const shadows = () => (ro.db.prepare(`SELECT name FROM sqlite_temp_master WHERE type = 'table'`).all() as { name: string }[]).map((r) => r.name);
    expect(shadows()).toContain('doc_lineage_gaps');
    const rw = new KronicleLite({ dataDir: data }); // migrates while the reader is open
    const doc = rw.docs.getDocument('deploy')!.doc_id;
    rw.db.prepare(`INSERT INTO doc_lineage_gaps (doc_id, chain_seq) VALUES (?, 1)`).run(doc);
    const blob = rw.audit.putBlob(Buffer.from('written after the reader opened'), 'text/plain');
    expect(ro.lineage.gapSeq(doc)).toBe(1);
    expect(ro.audit.getBlob(blob.sha256)?.size).toBe(blob.size);
    expect(shadows()).toEqual([]);
    rw.db.prepare(`DELETE FROM doc_lineage_gaps WHERE doc_id = ?`).run(doc);
    expect(ro.verifyAll().ok).toBe(true);
    rw.close();
    ro.close();
  });

  it('a read-write open migrates it and it still verifies', () => {
    const data = store(v);
    const kl = new KronicleLite({ dataDir: data });
    expect(kl.verifyAll().ok).toBe(true);
    kl.close();
    expect(tablesOnDisk(data)).toEqual(expect.arrayContaining([...MISSING[v]]));
  });
});
