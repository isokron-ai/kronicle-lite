/**
 * Optional: run the REAL isokron-anchor Worker locally for the anchor
 * acceptance tests. Set KRONICLE_ANCHOR_WORKER_DIR to a checkout of
 * isokron-anchor with its dependencies installed (esbuild, miniflare); the
 * Worker is bundled by esbuild and served by Miniflare (workerd) on a loopback
 * port with D1/KV/R2 in memory and dev license keys — the same setup as that
 * repo's client/test/harness.ts. Nothing from that repo is imported at build
 * time; its packages are resolved from its own node_modules at test time.
 */

import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import type { AnchorBackend } from './anchor-stub.js';

export const WORKER_DEV_LICENSE = 'KLA_dev-free-0001';
const TEST_SERVICE_SEED = '9f2a4c6e8b0d1f3a5c7e9b1d3f5a7c9e0b2d4f6a8c0e1b3d5f7a9c1e3b5d7f90';

interface EsbuildLike {
  build(opts: Record<string, unknown>): Promise<{ outputFiles: { text: string }[] }>;
}
interface D1Like {
  prepare(sql: string): unknown;
  batch(stmts: unknown[]): Promise<unknown>;
}
interface MiniflareLike {
  ready: Promise<URL>;
  getD1Database(name: string): Promise<D1Like>;
  dispose(): Promise<void>;
}
interface MiniflareModule {
  Miniflare: new (opts: unknown) => MiniflareLike;
  convertV4MiniflareOptions?: (opts: unknown) => unknown;
}

async function importFrom<T>(dir: string, name: string): Promise<T> {
  const req = createRequire(join(dir, 'package.json'));
  const mod = (await import(pathToFileURL(req.resolve(name)).href)) as T & { default?: T };
  return (mod.default && typeof mod.default === 'object' ? { ...mod.default, ...mod } : mod) as T;
}

export async function startAnchorWorker(dir: string): Promise<AnchorBackend> {
  const esbuild = await importFrom<EsbuildLike>(dir, 'esbuild');
  const mfMod = await importFrom<MiniflareModule>(dir, 'miniflare');
  const bundle = await esbuild.build({
    entryPoints: [join(dir, 'src', 'index.ts')],
    bundle: true,
    format: 'esm',
    platform: 'browser',
    conditions: ['workerd', 'worker', 'browser'],
    target: ['es2022'],
    write: false,
    logLevel: 'silent',
    absWorkingDir: dir,
  });
  const opts = {
    modules: [{ type: 'ESModule', path: 'worker.js', contents: bundle.outputFiles[0]!.text }],
    compatibilityDate: '2025-10-01',
    compatibilityFlags: ['nodejs_compat'],
    d1Databases: { DB: 'isokron-anchor' },
    kvNamespaces: ['LICENSE_CACHE'],
    r2Buckets: ['RECEIPTS'],
    bindings: {
      ANCHOR_SERVICE_KEY: TEST_SERVICE_SEED,
      ANCHOR_SERVICE_KEY_VALID_FROM: '2026-11-01T00:00:00.000Z',
      ANCHOR_DEV_KEYS: `${WORKER_DEV_LICENSE}:free,KLA_dev-pro-0001:pro`,
      POLAR_ORGANIZATION_ID: '11111111-2222-4333-8444-555555555555',
      POLAR_API_BASE: 'https://polar.invalid',
    },
    port: 0,
    host: '127.0.0.1',
  };
  const mf = new mfMod.Miniflare(mfMod.convertV4MiniflareOptions ? mfMod.convertV4MiniflareOptions(opts) : opts);
  const url = (await mf.ready).toString().replace(/\/$/, '');
  const db = await mf.getD1Database('DB');
  const sql = readFileSync(join(dir, 'migrations', '0001.sql'), 'utf8');
  const statements = sql
    .split('\n')
    .map((l) => l.replace(/--.*$/, ''))
    .join('\n')
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean);
  await db.batch(statements.map((s) => db.prepare(s)));
  return { url, license: WORKER_DEV_LICENSE, stop: () => mf.dispose() };
}
