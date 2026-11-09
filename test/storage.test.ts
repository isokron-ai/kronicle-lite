/**
 * 0.8.1 storage fixes: F12 (read-only / unreadable data dir: verify-chain,
 * doctor, pulse), F14 (`export | head`), C2-08 (readers never queue behind a
 * writer's lock), C2-01 (older writers: guard, marker, detection, repair).
 */

import Database from 'better-sqlite3';
import { spawn, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { generous } from './helpers/time.js';

import { openDatabase, openDbReadOnly } from '../src/db/open.js';
import { isStoreUnreadable, StoreUnreadableError } from '../src/db/storage.js';
import { checkWriters, describeWriters } from '../src/db/writers.js';
import { runDoctor } from '../src/doctor.js';
import { KronicleLite } from '../src/store.js';

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const POSIX = process.platform !== 'win32';
const ROOT = typeof process.getuid === 'function' && process.getuid() === 0;

const dirs: string[] = [];
function tmp(prefix = 'kl-storage-'): string {
  const d = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) {
    try {
      chmodSync(d, 0o700);
      for (const sub of ['data', 'data/kronicle-lite.db']) if (existsSync(join(d, sub))) chmodSync(join(d, sub), 0o700);
    } catch {
      // ignore
    }
    rmSync(d, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
});

function seeded(dir: string): string {
  const data = join(dir, 'data');
  const s = new KronicleLite({ dataDir: data });
  s.docs.putDocument({ slug: 'rb', title: 'RB', markdown: '# RB\n\nhost alpha', actor_id: 'a', project: { key: 'proj-a', root: dir } });
  s.docs.putDocument({ slug: 'note', title: 'N', markdown: 'plain note', actor_id: 'a' });
  s.close();
  return data;
}

const run = (args: string[], env: NodeJS.ProcessEnv = {}) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env: { ...process.env, ...env } });

describe('F12: a store that cannot be written is still read; one that cannot be read is an I/O error', () => {
  it('a store whose db path cannot be opened at all → StoreUnreadableError (the shim refuses it as "unreadable")', () => {
    const data = join(tmp(), 'data');
    mkdirSync(join(data, 'kronicle-lite.db'), { recursive: true }); // a directory where the database should be
    let err: unknown;
    try {
      new KronicleLite({ dataDir: data }).close();
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(StoreUnreadableError);
    expect(isStoreUnreadable(err)).toBe(true);
    expect((err as Error).message).toMatch(/cannot read the kronicle-lite store/);
  });

  it.skipIf(!existsSync(CLI))('verify-chain exits 2 (I/O) — not 1 (divergence) — when the store cannot be read; doctor exits 2 too', async () => {
    const data = join(tmp(), 'data');
    mkdirSync(join(data, 'kronicle-lite.db'), { recursive: true });
    const v = run(['verify-chain', '--data-dir', data]);
    expect(v.status).toBe(2);
    expect(v.stderr).toMatch(/I\/O, not a chain divergence/);
    const d = run(['doctor', '--no-network', '--data-dir', data]);
    expect(d.status).toBe(2);
    expect(d.stdout).toMatch(/db-open/);
  });

  it('verify-chain and doctor open read-only: they write nothing to a healthy store', async () => {
    const data = seeded(tmp());
    const before = new KronicleLite({ dataDir: data, readOnly: true });
    expect(before.readOnly).toBe(true);
    expect(before.verifyAll().ok).toBe(true);
    expect(() => before.docs.putDocument({ slug: 'x', title: 'x', markdown: 'x', actor_id: 'a' })).toThrow(/readonly/);
    before.close();
    const r = await runDoctor({ dataDir: data, network: false, env: {} });
    expect(r.io_error).toBeUndefined();
    expect(r.checks.find((c) => c.id === 'fts')).toMatchObject({ status: 'ok' });
  });

  it('openDbReadOnly reads a store in place', () => {
    const data = seeded(tmp());
    const r = openDbReadOnly(join(data, 'kronicle-lite.db'));
    expect(r.via).toBe('read-only');
    expect((r.db.prepare('SELECT seq FROM chain_head').get() as { seq: number }).seq).toBeGreaterThan(0);
    r.db.close();
  });

  // A read-only directory (no -shm can be created next to the WAL database). Root ignores modes.
  it.skipIf(!POSIX || ROOT)('a read-only data dir: reads (orient, pending, verify-chain, doctor) work from a snapshot; a put fails loudly', async () => {
    const data = seeded(tmp());
    chmodSync(join(data, 'kronicle-lite.db'), 0o444);
    chmodSync(data, 0o555);
    const s = new KronicleLite({ dataDir: data });
    try {
      expect(s.readOnly).toBe(true);
      expect(s.orient.getSystemState({ actor_id: 'x', focus: 'retractions' }).head.seq).toBeGreaterThan(0);
      expect(s.lineage.pending('x', { project_keys: null, limit: 5 }).count).toBe(0);
      expect(s.verifyAll().ok).toBe(true);
      expect(() => s.docs.putDocument({ slug: 'x', title: 'x', markdown: 'x', actor_id: 'a' })).toThrow();
    } finally {
      s.close();
    }
    const r = await runDoctor({ dataDir: data, network: false, env: {} });
    expect(r.io_error).toBeUndefined();
    if (existsSync(CLI)) expect(run(['verify-chain', '--data-dir', data]).status).toBe(0);
  });
});

describe.skipIf(!existsSync(CLI))('F14: export into a closed pipe', () => {
  it('stops quietly with exit 0 and no stack trace', async () => {
    const data = join(tmp(), 'data');
    const s = new KronicleLite({ dataDir: data });
    for (let i = 0; i < 300; i++) s.docs.putDocument({ slug: `d${i}`, title: 'd', markdown: `# D ${i}\n\n${'text '.repeat(200)}`, actor_id: 'a' });
    s.close();
    const child = spawn(process.execPath, [CLI, 'export', '--data-dir', data], { stdio: ['ignore', 'pipe', 'pipe'] });
    let err = '';
    child.stderr!.on('data', (d: Buffer) => (err += d.toString()));
    child.stdout!.once('data', () => child.stdout!.destroy()); // `| head -c 10`
    const code = await new Promise<number | null>((r) => child.once('exit', (c) => r(c)));
    expect(code).toBe(0);
    expect(err).not.toMatch(/EPIPE|at .*\(/);
  }, 60_000);
});

describe('C2-08: a reader never queues behind another process’s write lock', () => {
  it('open + orient + pending finish while a writer holds the lock (no BEGIN IMMEDIATE on a current schema)', () => {
    const data = seeded(tmp());
    const holder = new Database(join(data, 'kronicle-lite.db'));
    holder.exec('BEGIN IMMEDIATE');
    holder.prepare(`INSERT INTO meta (key, value) VALUES ('hold', '1')`).run();
    try {
      const t0 = Date.now();
      const s = new KronicleLite({ dataDir: data });
      s.orient.getSystemState({ actor_id: 'reader', focus: 'retractions' });
      s.lineage.pending('reader', { project_keys: null, limit: 5 });
      s.close();
      // The busy timeout is 10 s; the flight-recorder row waits at most 1 s, then is skipped.
      expect(Date.now() - t0).toBeLessThan(generous(5000));
    } finally {
      holder.exec('ROLLBACK');
      holder.close();
    }
  });

  it('a store missing a schema object still goes through setup (first start / upgrade)', () => {
    const data = seeded(tmp());
    const raw = new Database(join(data, 'kronicle-lite.db'));
    raw.exec('DROP TRIGGER kl_rebuild_guard');
    raw.close();
    new KronicleLite({ dataDir: data }).close();
    const again = new Database(join(data, 'kronicle-lite.db'));
    expect(again.prepare(`SELECT name FROM sqlite_master WHERE name = 'kl_rebuild_guard'`).get()).toBeTruthy();
    again.close();
  });
});

describe('C2-01: older writers', () => {
  it('kronicle-lite 0.7.0 and older cannot rebuild this store: their delete hits the guard and rolls back', () => {
    const data = seeded(tmp());
    const old = new Database(join(data, 'kronicle-lite.db')); // no kl_writer_guard(): like an old binary
    expect(() =>
      old.transaction(() => {
        old.exec(`DELETE FROM doc_sources; DELETE FROM document_revisions; DELETE FROM documents;`);
      })(),
    ).toThrow(/no such function: kl_writer_guard/);
    expect((old.prepare(`SELECT COUNT(*) AS n FROM documents`).get() as { n: number }).n).toBe(2);
    old.close();
    // 0.8.1's own rebuild still works and keeps project keys.
    const s = new KronicleLite({ dataDir: data });
    expect(s.rebuild().after.ok).toBe(true);
    expect(s.docs.getDocument('rb')?.project_key).toBe('proj-a');
    s.close();
  });

  it('every append records the writer; a project key the chain does not derive fails doctor and verify-chain; rebuild repairs it', async () => {
    const data = seeded(tmp());
    let s = new KronicleLite({ dataDir: data });
    const head = s.chain.head().seq;
    let w = checkWriters(s.db);
    expect(w.writer_head_seq).toBe(head);
    expect(describeWriters(w).status).toBe('ok');
    // What kronicle-lite 0.5.0/0.6.0 `rebuild` leaves behind: every project key NULL.
    s.db.prepare(`UPDATE documents SET project_key = NULL`).run();
    w = checkWriters(s.db);
    expect(w.project_key_mismatches).toEqual([{ slug: 'rb', live: null, derived: 'proj-a' }]);
    expect(describeWriters(w).status).toBe('fail');
    s.close();
    const r = await runDoctor({ dataDir: data, network: false, env: {} });
    expect(r.checks.find((c) => c.id === 'writers')).toMatchObject({ status: 'fail' });
    if (existsSync(CLI)) {
      const v = run(['verify-chain', '--data-dir', data]);
      expect(v.status).toBe(1);
      expect(v.stderr).toMatch(/project key the chain does not derive/);
    }
    s = new KronicleLite({ dataDir: data });
    s.rebuild();
    expect(describeWriters(checkWriters(s.db)).status).toBe('ok');
    s.close();
  });

  it('events appended by a version that does not record itself are reported', () => {
    const data = seeded(tmp());
    const s = new KronicleLite({ dataDir: data });
    s.db.prepare(`UPDATE meta SET value = '1' WHERE key = 'writer_head_seq'`).run();
    const d = describeWriters(checkWriters(s.db));
    expect(d.status).toBe('warn');
    expect(d.detail).toMatch(/events 2\.\.\d+ were appended by a kronicle-lite older than 0\.9\.0/);
    s.close();
  });

  it('a store marked by a newer writer generation is refused for writing, with a clear message', () => {
    const data = seeded(tmp());
    const raw = new Database(join(data, 'kronicle-lite.db'));
    raw.prepare(`UPDATE meta SET value = '99' WHERE key = 'min_writer_generation'`).run();
    raw.close();
    expect(() => new KronicleLite({ dataDir: data })).toThrow(/newer kronicle-lite/);
    // Reading it read-only is still possible.
    const ro = new KronicleLite({ dataDir: data, readOnly: true });
    expect(ro.chain.head().seq).toBeGreaterThan(0);
    ro.close();
  });

  it('in-memory stores get the guard too (functions are registered on every connection)', () => {
    const { db } = openDatabase({ memory: true });
    expect(db.prepare(`SELECT kl_writer_guard() AS g`).get()).toEqual({ g: 1 });
    db.close();
  });
});

