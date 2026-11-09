/**
 * 0.9.0: reading a store made by an older release without migrating it.
 *
 * A store made by 0.7.0 lacks doc_lineage, doc_lineage_gaps and reads; one made by 0.8.0 lacks
 * doc_lineage_gaps; both lack the 0.9.0 audit / blob / apply tables. Opened without migrating
 * (read-only, a snapshot, an image, doctor's raw handle), each table its release did not have is
 * served as an empty TEMP table on that connection only (the file is never written), and each data
 * migration the store has not run is derived into its TEMP target.
 *
 * Only tables the store's release never had are shimmed. The release is the newest of the
 * `schema_generation` meta key (written by every migration since 0.9.0), `writer_version`, the
 * migration records and the objects the store holds: a forged key can only raise it. A
 * table missing from a store whose release had it is damage: it is not shimmed, and
 * `schemaDamage` reports it (verify-chain and doctor then fail, as before 0.9.0).
 *
 * A long-lived connection whose store is migrated by another process meanwhile drops a shim as
 * soon as the real table appears (checked against `PRAGMA main.schema_version` before every
 * statement), so it never keeps reading its TEMP copy.
 */

import Database from 'better-sqlite3';

import type { Db } from './open.js';
import { DATA_MIGRATIONS, SCHEMA_SQL } from './schema.js';

/** Releases whose schema differs, oldest first. */
export const SCHEMA_GENERATIONS = ['0.7.0', '0.8.0', '0.8.1', '0.9.0'] as const;
export const CURRENT_SCHEMA_GENERATION = '0.9.0';
export const SCHEMA_GENERATION_KEY = 'schema_generation';

/** The release that introduced each table (every other table is in 0.7.0). */
const TABLE_SINCE: Readonly<Record<string, string>> = {
  doc_lineage: '0.8.0',
  reads: '0.8.0',
  doc_lineage_gaps: '0.8.1',
  blobs: '0.9.0',
  audit_events: '0.9.0',
  audit_event_fingerprints: '0.9.0',
  audit_findings: '0.9.0',
  apply_confirmations: '0.9.0',
  apply_results: '0.9.0',
};
const genIndex = (g: string): number => (SCHEMA_GENERATIONS as readonly string[]).indexOf(g);

let tableDdl: { name: string; sql: string }[] | null = null;
/** Every ordinary table SCHEMA_SQL creates, with its CREATE TABLE statement (FTS5 and its shadow tables excluded). */
function schemaTables(): { name: string; sql: string }[] {
  if (tableDdl) return tableDdl;
  const mem = new Database(':memory:');
  try {
    mem.exec(SCHEMA_SQL.replace(/^\s*PRAGMA [^;]+;\s*$/gm, ''));
    tableDdl = (mem.prepare(`SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'blocks_fts%'`).all() as { name: string; sql: string }[]).filter(
      (t) => !/^CREATE VIRTUAL/i.test(t.sql),
    );
  } finally {
    mem.close();
  }
  return tableDdl;
}

type Prep = (sql: string) => Database.Statement;
const mainHas = (prep: Prep, type: 'table' | 'index', name: string) => prep(`SELECT 1 FROM main.sqlite_master WHERE type = ? AND name = ?`).get(type, name) !== undefined;

/**
 * The schema generation of the store: the newest release shown by its `schema_generation` meta key
 * (an unknown, newer key counts as current), `writer_version`, migration records or objects.
 */
export function storeGeneration(db: Db): number {
  const prep: Prep = (sql) => db.prepare(sql);
  const metaHas = mainHas(prep, 'table', 'meta');
  const meta = (key: string) => (metaHas ? ((prep(`SELECT value FROM main.meta WHERE key = ?`).get(key) as { value: string } | undefined)?.value ?? null) : null);
  // The marker, the migration records and the store's own objects are all evidence; the generation is the
  // newest any of them shows, so a marker (or a forged one) can only raise the expected tables, never lower them.
  let gen = genIndex('0.7.0');
  const raise = (g: number) => {
    if (g > gen) gen = g;
  };
  const marked = meta(SCHEMA_GENERATION_KEY);
  if (marked !== null) raise(genIndex(marked) === -1 ? SCHEMA_GENERATIONS.length - 1 : genIndex(marked));
  // writer_version (0.8.1+): the release that last appended; a generation at or below it is implied.
  const writer = meta('writer_version');
  if (writer !== null) for (const [i, g] of SCHEMA_GENERATIONS.entries()) if (compareVersions(writer, g) >= 0) raise(i);
  const tables = (since: string) => Object.entries(TABLE_SINCE).filter(([, s]) => s === since).map(([t]) => t);
  if (tables('0.9.0').some((t) => mainHas(prep, 'table', t))) raise(genIndex('0.9.0'));
  if (mainHas(prep, 'table', 'doc_lineage_gaps') || meta('migration.lineage_gaps') !== null) raise(genIndex('0.8.1'));
  // 0.8.0 added these tables and indexes (the indexes on events / blocks outlive a dropped table).
  if (['doc_lineage', 'reads'].some((t) => mainHas(prep, 'table', t)) || ['events_retired_block_idx', 'blocks_superseded_by_idx'].some((i) => mainHas(prep, 'index', i))) raise(genIndex('0.8.0'));
  return gen;
}

/** Numeric x.y.z comparison (a pre-release suffix is ignored); an unparseable version compares as 0.0.0. */
function compareVersions(a: string, b: string): number {
  const parse = (v: string) => (/^(\d+)\.(\d+)\.(\d+)/.exec(v) ?? ['', '0', '0', '0']).slice(1).map(Number);
  const [x, y] = [parse(a), parse(b)];
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i]! - y[i]!;
  return 0;
}

/** Missing schema tables, split into those the store's release never had (shim) and those it had (damage). */
function classify(db: Db): { shim: { name: string; sql: string }[]; damaged: string[]; generation: string } {
  const prep: Prep = (sql) => db.prepare(sql);
  const gen = storeGeneration(db);
  const shim: { name: string; sql: string }[] = [];
  const damaged: string[] = [];
  for (const t of schemaTables()) {
    if (mainHas(prep, 'table', t.name)) continue;
    if (genIndex(TABLE_SINCE[t.name] ?? '0.7.0') > gen) shim.push(t);
    else damaged.push(t.name);
  }
  return { shim, damaged, generation: SCHEMA_GENERATIONS[gen]! };
}

/** Tables missing from a store whose release had them: damage, reported by verify-chain and doctor. */
export function schemaDamage(db: Db): { tables: string[]; generation: string } {
  const c = classify(db);
  const temp = (name: string) => db.prepare(`SELECT 1 FROM sqlite_temp_master WHERE type = 'table' AND name = ?`).get(name) !== undefined;
  return { tables: c.damaged.filter((t) => !temp(t)), generation: c.generation };
}

/**
 * Shim the tables this store's release never had (see the module comment). Returns the tables
 * shimmed and the tables found damaged (missing although the release had them; not shimmed).
 */
export function shimMissingTables(db: Db): { shimmed: string[]; damaged: string[] } {
  const c = classify(db);
  const shimmed: string[] = [];
  for (const t of c.shim) {
    // Drop REFERENCES: a TEMP table cannot enforce a key into the main schema (and nothing writes it).
    db.exec(t.sql.replace(/^CREATE TABLE(?: IF NOT EXISTS)?/i, 'CREATE TEMP TABLE IF NOT EXISTS').replace(/\s+REFERENCES\s+\w+\s*\([^)]*\)/gi, ''));
    shimmed.push(t.name);
  }
  if (shimmed.length === 0) return { shimmed, damaged: c.damaged };
  const metaHas = mainHas((sql) => db.prepare(sql), 'table', 'meta');
  for (const m of DATA_MIGRATIONS) {
    if (!shimmed.includes(m.target)) continue;
    if (metaHas && db.prepare(`SELECT 1 FROM main.meta WHERE key = ?`).get(m.key) !== undefined) continue;
    db.exec(m.sql);
  }
  dropShimsWhenMigrated(db, shimmed);
  return { shimmed, damaged: c.damaged };
}

const EXEC_METHODS = new Set(['get', 'all', 'run', 'iterate']);

/**
 * Another process may migrate the store while this connection is open: then the real table exists
 * and the TEMP shim (resolved first by name) would hide it. Before every statement (one cheap
 * `PRAGMA main.schema_version` read), a changed main schema drops each shim whose real table now
 * exists; prepared statements re-resolve to it on their next step.
 */
function dropShimsWhenMigrated(db: Db, shimmed: string[]): void {
  const prepare = db.prepare.bind(db) as Prep;
  const exec = db.exec.bind(db);
  const cookie = prepare('PRAGMA main.schema_version').pluck();
  const realTable = prepare(`SELECT 1 FROM main.sqlite_master WHERE type = 'table' AND name = ?`);
  const live = new Set(shimmed);
  let seen = cookie.get() as number;
  const refresh = () => {
    if (live.size === 0 || db.inTransaction) return;
    const now = cookie.get() as number;
    if (now === seen) return;
    let all = true;
    for (const t of [...live]) {
      if (realTable.get(t) === undefined) continue;
      try {
        exec(`DROP TABLE temp."${t}"`);
        live.delete(t);
      } catch {
        all = false; // a statement still reading it: retry on the next call
      }
    }
    if (all) seen = now;
  };
  const wrap = (stmt: Database.Statement): Database.Statement => {
    const proxy: Database.Statement = new Proxy(stmt, {
      get(target, prop, _receiver) {
        const v = Reflect.get(target, prop, target) as unknown;
        if (typeof v !== 'function') return v;
        return (...args: unknown[]) => {
          if (EXEC_METHODS.has(String(prop))) refresh();
          const r = (v as (...a: unknown[]) => unknown).apply(target, args);
          return r === target ? proxy : r;
        };
      },
    });
    return proxy;
  };
  (db as { prepare: Prep }).prepare = (sql: string) => wrap(prepare(sql));
  (db as { exec: (sql: string) => Db }).exec = (sql: string) => {
    refresh();
    return exec(sql);
  };
}
