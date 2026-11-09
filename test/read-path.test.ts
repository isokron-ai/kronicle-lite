/**
 * The read path a short-lived process takes: opening a current store takes no
 * write lock (a hook never queues behind another process's writer), a store
 * that needs setup or migration still gets it, and `kronicle-lite/core` loads
 * the store without the MCP SDK.
 */

import Database from 'better-sqlite3';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

import type * as CoreApi from '../src/core.js';
import { BUSY_TIMEOUT_MS } from '../src/db/open.js';
import { DATA_MIGRATIONS } from '../src/db/schema.js';
import type * as MainApi from '../src/index.js';
import { KronicleLite } from '../src/store.js';

const DIST = join(__dirname, '..', 'dist');

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'kl-read-path-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function seeded(): string {
  const data = join(tmp(), 'data');
  const s = new KronicleLite({ dataDir: data });
  s.docs.putDocument({ slug: 'note', title: 'N', markdown: 'plain note', actor_id: 'a' });
  s.close();
  return data;
}

/** Another connection holding the write lock (BEGIN IMMEDIATE plus a pending write) for the duration of `fn`. */
function whileLocked<T>(data: string, fn: () => T): T {
  const holder = new Database(join(data, 'kronicle-lite.db'));
  holder.exec('BEGIN IMMEDIATE');
  holder.prepare(`INSERT OR REPLACE INTO meta (key, value) VALUES ('test-holder', '1')`).run();
  try {
    return fn();
  } finally {
    holder.exec('ROLLBACK');
    holder.close();
  }
}

const meta = (data: string, key: string): string | undefined => {
  const db = new Database(join(data, 'kronicle-lite.db'), { readonly: true });
  try {
    return (db.prepare(`SELECT value FROM meta WHERE key = ?`).get(key) as { value: string } | undefined)?.value;
  } finally {
    db.close();
  }
};

describe('open: a current store takes no write lock', () => {
  it('opens and reads the head while another connection holds BEGIN IMMEDIATE', () => {
    const data = seeded();
    const ms = whileLocked(data, () => {
      const t0 = Date.now();
      const s = new KronicleLite({ dataDir: data });
      try {
        expect(s.chain.head().seq).toBeGreaterThan(0);
        expect(s.db.inTransaction).toBe(false);
      } finally {
        s.close();
      }
      return Date.now() - t0;
    });
    // A write would wait the whole busy timeout (10 s) and then fail; a plain WAL read does not wait at all.
    expect(ms).toBeLessThan(Math.min(2000, BUSY_TIMEOUT_MS / 5));
  });

  it('a store missing a recorded data migration goes through setup and records it', () => {
    expect(DATA_MIGRATIONS.length).toBeGreaterThan(0);
    const data = seeded();
    const key = DATA_MIGRATIONS[0]!.key;
    const raw = new Database(join(data, 'kronicle-lite.db'));
    raw.prepare(`DELETE FROM meta WHERE key = ?`).run(key);
    raw.close();
    expect(meta(data, key)).toBeUndefined();
    new KronicleLite({ dataDir: data }).close();
    expect(meta(data, key)).toBeTruthy();
  });

  it('a store missing this identity’s signing-key row goes through setup and records it', () => {
    const data = seeded();
    const raw = new Database(join(data, 'kronicle-lite.db'));
    raw.exec(`DELETE FROM signing_keys`);
    raw.close();
    const s = new KronicleLite({ dataDir: data });
    try {
      expect(s.db.prepare(`SELECT 1 FROM signing_keys WHERE key_id = ?`).get(s.identity.signer.key_id)).toBeTruthy();
    } finally {
      s.close();
    }
  });

  it('a store needing setup still takes the write lock for it: it waits for another holder, then migrates', async () => {
    const data = seeded();
    const key = DATA_MIGRATIONS[0]!.key;
    const raw = new Database(join(data, 'kronicle-lite.db'));
    raw.prepare(`DELETE FROM meta WHERE key = ?`).run(key);
    raw.close();
    const HOLD_MS = 600;
    const holder = spawn(
      process.execPath,
      [
        '-e',
        `const D=require('better-sqlite3');const db=new D(process.argv[1]);db.exec('BEGIN IMMEDIATE');` +
          `process.stdout.write('locked\\n');Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,${HOLD_MS});db.exec('ROLLBACK');db.close();`,
        join(data, 'kronicle-lite.db'),
      ],
      { cwd: join(__dirname, '..'), stdio: ['ignore', 'pipe', 'inherit'] },
    );
    await new Promise<void>((ok, fail) => {
      holder.stdout.on('data', (b: Buffer) => b.toString().includes('locked') && ok());
      holder.on('exit', (c) => fail(new Error(`holder exited ${c} before locking`)));
    });
    const t0 = Date.now();
    new KronicleLite({ dataDir: data }).close();
    const waited = Date.now() - t0;
    await new Promise((ok) => holder.on('exit', ok));
    expect(meta(data, key)).toBeTruthy();
    expect(waited).toBeGreaterThan(HOLD_MS / 3); // it queued behind the holder instead of skipping setup
  });
});

/** Every module reachable from `entry` (static and dynamic imports): local files and bare package specifiers. */
function importGraph(entry: string): { files: Set<string>; packages: Set<string> } {
  const files = new Set<string>();
  const packages = new Set<string>();
  const re = /\b(?:import|export)\s*(?:[^'"`;]*?\s*from\s*)?["']([^"']+)["']|\bimport\s*\(\s*["']([^"']+)["']\s*\)/g;
  const visit = (file: string): void => {
    if (files.has(file)) return;
    files.add(file);
    const src = readFileSync(file, 'utf8');
    for (const m of src.matchAll(re)) {
      const spec = m[1] ?? m[2]!;
      if (spec.startsWith('.')) visit(resolve(dirname(file), spec));
      else packages.add(spec.startsWith('@') ? spec.split('/').slice(0, 2).join('/') : spec.split('/')[0]!);
    }
  };
  visit(entry);
  return { files, packages };
}

describe('kronicle-lite/core', () => {
  it('reaches no MCP SDK module (statically or dynamically); the main entry does', () => {
    const core = importGraph(join(DIST, 'core.js'));
    const main = importGraph(join(DIST, 'index.js'));
    expect([...main.packages].some((p) => p.startsWith('@modelcontextprotocol/'))).toBe(true); // the walk sees imports
    expect([...core.packages].filter((p) => p.startsWith('@modelcontextprotocol/'))).toEqual([]);
    expect(core.packages.has('better-sqlite3')).toBe(true);
    expect(core.files.size).toBeLessThan(main.files.size);
  });

  it('exports the same objects as the main entry, and opens a store', async () => {
    const core = (await import(join(DIST, 'core.js'))) as typeof CoreApi;
    const main = (await import(join(DIST, 'index.js'))) as typeof MainApi;
    for (const name of ['KronicleLite', 'Chain', 'ChainConflictError', 'canonicalize', 'sha256Hex', 'defaultDataDir', 'openDatabase', 'redactSecrets'] as const) {
      expect(core[name], name).toBe(main[name]);
    }
    const s = new core.KronicleLite({ dataDir: join(tmp(), 'data') });
    try {
      expect(s.chain.head().seq).toBe(0);
    } finally {
      s.close();
    }
  });

  it('is exported as a package subpath', () => {
    const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf8')) as { exports: Record<string, { import: string; types: string }> };
    expect(pkg.exports['./core']).toEqual({ types: './dist/core.d.ts', import: './dist/core.js' });
    expect(pkg.exports['.']).toEqual({ types: './dist/index.d.ts', import: './dist/index.js' });
  });
});
