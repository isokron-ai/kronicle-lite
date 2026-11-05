import Database from 'better-sqlite3';
import { chmodSync, copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';

import { ensureDefaultConfig } from '../anchor/config.js';
import { GENESIS_HASH } from '../chain/genesis.js';
import {
  ephemeralIdentity,
  loadOrCreateIdentity,
  type ServerIdentity,
} from '../crypto/keys.js';
import { ensureDir } from '../util/once-file.js';
import { VERSION } from '../version.js';
import { ADDED_COLUMNS, DATA_MIGRATIONS, SCHEMA_SQL, SCHEMA_VERSION } from './schema.js';
import { isStorageWriteError, StoreUnreadableError, WRITER_GENERATION } from './storage.js';

export type Db = Database.Database;

export interface OpenOptions {
  /** Directory holding the database, signing key and cursor secret. */
  dataDir?: string;
  /** Use an in-memory database with an ephemeral identity (tests). */
  memory?: boolean;
  /**
   * 0.8.1: never write (verify-chain, doctor). The store must exist; it is
   * opened read-only, or from a private snapshot when the medium cannot hold
   * the WAL index (read-only or full data dir).
   */
  readOnly?: boolean;
}

export interface Opened {
  db: Db;
  identity: ServerIdentity;
  dataDir: string | null;
  /** 0.8.1: true when the store was opened read-only (requested, or the medium refused writes). */
  readOnly?: boolean;
  /** 0.8.1: how a read-only store was opened. */
  via?: 'read-only' | 'snapshot' | 'memory-image';
  /** 0.8.1: releases a snapshot (call after db.close()). */
  cleanup?: () => void;
}

export const DB_FILE = 'kronicle-lite.db';

export function defaultDataDir(): string {
  return process.env['KRONICLE_LITE_DATA_DIR'] ?? join(homedir(), '.kronicle-lite');
}

export function openDatabase(opts: OpenOptions = {}): Opened {
  if (opts.memory) {
    const db = new Database(':memory:');
    const identity = ephemeralIdentity();
    registerFunctions(db);
    db.pragma('foreign_keys = ON');
    setUp(db, identity);
    return { db, identity, dataDir: null };
  }
  const dataDir = opts.dataDir ?? defaultDataDir();
  const dbFile = join(dataDir, DB_FILE);
  const exists = existsSync(dbFile);
  if (opts.readOnly) {
    if (!exists) throw new Error(`no kronicle-lite store in ${dataDir}`);
    return openReadOnly(dataDir, dbFile, null);
  }
  try {
    return openReadWrite(dataDir, dbFile, !exists);
  } catch (err) {
    // 0.8.1 (F12): a store on a read-only or full medium is still readable.
    // Reads work; any real write then fails loudly (SQLITE_READONLY).
    if (!exists || !isStorageWriteError(err)) throw err;
    return openReadOnly(dataDir, dbFile, err);
  }
}

function openReadWrite(dataDir: string, dbFile: string, fresh: boolean): Opened {
  ensureDir(dataDir, 0o700);
  // Busy timeout before ANY statement: concurrent first starts (several
  // servers / hooks opening a fresh data dir at once) must wait for each
  // other's schema creation instead of failing with "database is locked".
  const db = new Database(dbFile, { timeout: BUSY_TIMEOUT_MS });
  try {
    db.pragma(`busy_timeout = ${BUSY_TIMEOUT_MS}`);
    // 0.4.0: a new database is private like the keys next to it (WAL/SHM inherit its mode). No-op on Windows.
    if (fresh) {
      try {
        chmodSync(dbFile, 0o600);
      } catch {
        // best effort
      }
    }
    let identity = loadOrCreateIdentity(dataDir);
    // First run: config.json with the default anchor_url only (no license key).
    ensureDefaultConfig(dataDir);

    // Connection settings first, outside any transaction (foreign_keys is a
    // no-op inside one; switching to WAL needs the file to itself for a moment).
    withBusyRetry(() => enableWal(db));
    db.pragma('foreign_keys = ON');
    registerFunctions(db);
    // 0.8.1 (C2-08): schema, migrations and seed rows run in ONE immediate
    // transaction only when something is missing (first start, upgrade). A
    // current store is opened with plain WAL reads, so read-only commands
    // (pulse, pending, orient, get) never queue behind a long writer.
    if (fresh || !schemaCurrent(db, identity)) setUp(db, identity);
    const min = Number(metaValue(db, 'min_writer_generation') ?? 0);
    if (min > WRITER_GENERATION) {
      throw new Error(
        `this kronicle-lite store was marked by a newer kronicle-lite (writer generation ${min}; this is ${VERSION}, generation ${WRITER_GENERATION}); upgrade before writing to it`,
      );
    }
    // 0.8.1 (C2-03): a cursor-secret created for a store that already had a chain
    // (restored without it, deleted) silently invalidated every cursor. Never silent:
    // say so on stderr, record it in meta, and let callers treat old cursors as unknown.
    if (identity.cursor_secret_created && (db.prepare(`SELECT seq FROM chain_head WHERE id = 1`).get() as { seq: number } | undefined)?.seq) {
      identity = { ...identity, cursor_secret_regenerated: true };
      process.stderr.write(`kronicle-lite: ${dataDir}/cursor-secret was missing and has been regenerated; every cursor issued before is now unreadable (positions recover from the flight recorder; shims re-check pending).\n`);
      try {
        db.prepare(`INSERT OR REPLACE INTO meta (key, value) VALUES ('cursor_secret_regenerated_at', ?)`).run(new Date().toISOString());
      } catch {
        // best effort: the warning above is the signal
      }
    }
    return { db, identity, dataDir };
  } catch (err) {
    db.close();
    throw err;
  }
}

/** Schema, migrations, seed rows and the writer guard, in ONE immediate transaction, retried on SQLITE_BUSY. */
function setUp(db: Db, identity: ServerIdentity): void {
  // The write lock is taken up front (waiting via the busy handler), so two
  // processes never deadlock upgrading a read to a write.
  withBusyRetry(() =>
    db
      .transaction(() => {
        db.exec(SCHEMA_DDL);
        addColumns(db);
        dataMigrations(db);
        initialize(db, identity);
        db.exec(GUARD_DDL);
      })
      .immediate(),
  );
}

/**
 * Open a store that must not (or cannot) be written: read-only in place, then
 * a private snapshot (db + WAL copied to a 0700 temp dir), then an in-memory
 * image of the main file when there is no WAL to lose. Throws
 * StoreUnreadableError when none of them reads the chain head.
 */
function openReadOnly(dataDir: string, dbFile: string, cause: unknown): Opened {
  let identity: ServerIdentity;
  try {
    identity = loadOrCreateIdentity(dataDir);
  } catch (err) {
    throw new StoreUnreadableError(`cannot read the kronicle-lite keys in ${dataDir}: ${errText(err)}`, { cause: err });
  }
  const r = openDbReadOnly(dbFile, cause);
  return { db: r.db, identity, dataDir, readOnly: true, via: r.via, ...(r.cleanup ? { cleanup: r.cleanup } : {}) };
}

/** The database file alone, read-only (doctor uses it without loading keys). See openReadOnly. */
export function openDbReadOnly(dbFile: string, cause: unknown = null): { db: Db; via: 'read-only' | 'snapshot' | 'memory-image'; cleanup?: () => void } {
  const problems: string[] = cause ? [`read-write: ${errText(cause)}`] : [];
  const probe = (db: Db): Db => {
    db.pragma(`busy_timeout = ${BUSY_TIMEOUT_MS}`);
    db.prepare('SELECT seq FROM chain_head WHERE id = 1').get();
    registerFunctions(db);
    return db;
  };
  const attempt = (label: string, fn: () => Db): Db | null => {
    let db: Db | null = null;
    try {
      db = fn();
      return probe(db);
    } catch (err) {
      try {
        db?.close();
      } catch {
        // ignore
      }
      problems.push(`${label}: ${errText(err)}`);
      return null;
    }
  };
  const inPlace = attempt('read-only', () => new Database(dbFile, { readonly: true, fileMustExist: true, timeout: BUSY_TIMEOUT_MS }));
  if (inPlace) return { db: inPlace, via: 'read-only' };

  // The WAL index (-shm) cannot be created next to the database: read a copy.
  let snap: string | null = null;
  const dropSnap = () => {
    if (snap) rmSync(snap, { recursive: true, force: true });
    snap = null;
  };
  const copied = attempt('snapshot', () => {
    snap = mkdtempSync(join(tmpdir(), 'kronicle-lite-ro-'));
    const target = join(snap, DB_FILE);
    copyFileSync(dbFile, target);
    if (existsSync(dbFile + '-wal')) copyFileSync(dbFile + '-wal', target + '-wal');
    return new Database(target, { readonly: true, fileMustExist: true });
  });
  if (copied) return { db: copied, via: 'snapshot', cleanup: dropSnap };
  dropSnap();

  // No room for a copy either: an in-memory image, only when no WAL frames would be lost.
  const walSize = (() => {
    try {
      return statSync(dbFile + '-wal').size;
    } catch {
      return 0;
    }
  })();
  if (walSize === 0) {
    const image = attempt('memory image', () => {
      const buf = readFileSync(dbFile);
      // Header bytes 18/19 = 2 mark WAL mode; an image has no WAL, so read it as a rollback-journal file.
      if (buf.length > 19 && buf[18] === 2) {
        buf[18] = 1;
        buf[19] = 1;
      }
      return new Database(buf, { readonly: true });
    });
    if (image) return { db: image, via: 'memory-image' };
  } else {
    problems.push(`memory image: skipped (${walSize} bytes of WAL would be ignored)`);
  }
  throw new StoreUnreadableError(`cannot read the kronicle-lite store ${dbFile} (${problems.join('; ')})`, { cause });
}

function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function metaValue(db: Db, key: string): string | null {
  const r = db.prepare(`SELECT value FROM meta WHERE key = ?`).get(key) as { value: string } | undefined;
  return r?.value ?? null;
}

/** Only rebuild ever deletes document revisions; older versions cannot run it on this store. */
const GUARD_DDL = `
CREATE TRIGGER IF NOT EXISTS kl_rebuild_guard BEFORE DELETE ON document_revisions
WHEN kl_writer_guard() IS NULL
BEGIN SELECT RAISE(ABORT, 'this store needs kronicle-lite >= 0.8.1 to rebuild'); END;
`;

/** Objects the setup creates; a store missing any of them goes through setUp. */
const SCHEMA_OBJECTS: readonly string[] = (() => {
  const names = new Set<string>();
  const re = /CREATE\s+(?:VIRTUAL\s+)?(?:TABLE|INDEX|TRIGGER)\s+IF\s+NOT\s+EXISTS\s+([A-Za-z0-9_]+)/gi;
  for (const sql of [SCHEMA_SQL, GUARD_DDL, ...ADDED_COLUMNS.map((c) => c.index ?? '')]) {
    for (const m of sql.matchAll(re)) names.add(m[1]!);
  }
  return [...names];
})();

/** Read-only check that the schema, migrations and seed rows are all in place (no write lock). */
function schemaCurrent(db: Db, identity: ServerIdentity): boolean {
  try {
    const have = new Set(db.prepare(`SELECT name FROM sqlite_master`).pluck().all() as string[]);
    if (SCHEMA_OBJECTS.some((n) => !have.has(n))) return false;
    for (const c of ADDED_COLUMNS) {
      const cols = db.prepare(`SELECT name FROM pragma_table_info(?)`).pluck().all(c.table) as string[];
      if (!cols.includes(c.column)) return false;
    }
    if (metaValue(db, 'schema_version') === null) return false;
    if (Number(metaValue(db, 'min_writer_generation') ?? 0) < WRITER_GENERATION) return false;
    if (!db.prepare(`SELECT 1 FROM chain_head WHERE id = 1`).get()) return false;
    if (!db.prepare(`SELECT 1 FROM signing_keys WHERE key_id = ?`).get(identity.signer.key_id)) return false;
    return true;
  } catch {
    return false;
  }
}

/**
 * 0.8.1 (C2-01): SQL functions every connection of this version registers.
 * `kl_writer_guard()` is referenced by GUARD_DDL; kronicle-lite 0.7.0 and
 * older do not define it, so their projection rebuild (which deletes every
 * document revision) fails with "no such function: kl_writer_guard" and rolls
 * back instead of silently dropping project keys.
 */
function registerFunctions(db: Db): void {
  db.function('kl_writer_guard', { deterministic: true }, () => 1);
}


/** How long a connection waits for another's lock (and how long open() retries a busy setup). */
export const BUSY_TIMEOUT_MS = 10_000;

/** SCHEMA_SQL without its connection pragmas (they run outside the setup transaction). */
const SCHEMA_DDL = SCHEMA_SQL.replace(/^\s*PRAGMA [^;]+;\s*$/gm, '');

function enableWal(db: Db): void {
  if (String(db.pragma('journal_mode', { simple: true })).toLowerCase() === 'wal') return;
  const mode = String(db.pragma('journal_mode = WAL', { simple: true })).toLowerCase();
  // Another connection holding the file can leave the mode unchanged: retry.
  if (mode !== 'wal') throw Object.assign(new Error(`journal_mode is ${mode}, wanted wal`), { code: 'SQLITE_BUSY' });
}

function isBusy(err: unknown): boolean {
  const code = (err as { code?: unknown })?.code;
  return typeof code === 'string' && (code.startsWith('SQLITE_BUSY') || code.startsWith('SQLITE_LOCKED'));
}

/** Run `fn`, retrying while SQLite reports BUSY/LOCKED, for up to BUSY_TIMEOUT_MS. */
export function withBusyRetry<T>(fn: () => T, deadlineMs = BUSY_TIMEOUT_MS): T {
  const deadline = Date.now() + deadlineMs;
  let wait = 5;
  for (;;) {
    try {
      return fn();
    } catch (err) {
      if (!isBusy(err) || Date.now() >= deadline) throw err;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, wait + Math.floor(Math.random() * wait));
      wait = Math.min(wait * 2, 200);
    }
  }
}

/** Additive migrations for databases created by an older version. */
function addColumns(db: Db): void {
  for (const c of ADDED_COLUMNS) {
    const cols = db.prepare(`SELECT name FROM pragma_table_info(?)`).all(c.table) as { name: string }[];
    if (!cols.some((x) => x.name === c.column)) {
      db.exec(c.ddl);
      if (c.backfill) db.exec(c.backfill);
    }
    if (c.index) db.exec(c.index);
  }
}

/** 0.8.1: one-time projection backfills (DATA_MIGRATIONS), each recorded in `meta`. */
function dataMigrations(db: Db): void {
  const done = db.prepare(`SELECT 1 FROM meta WHERE key = ?`);
  const mark = db.prepare(`INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)`);
  for (const m of DATA_MIGRATIONS) {
    if (done.get(m.key) !== undefined) continue;
    db.exec(m.sql);
    mark.run(m.key, new Date().toISOString());
  }
}

function initialize(db: Db, identity: ServerIdentity): void {
  const now = new Date().toISOString();
  // Runs inside open()'s immediate setup transaction.
  db.prepare(`INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)`).run(String(SCHEMA_VERSION));
  db.prepare(`INSERT OR IGNORE INTO chain_head (id, seq, hash) VALUES (1, 0, ?)`).run(GENESIS_HASH);
  db.prepare(
    `INSERT OR IGNORE INTO signing_keys (key_id, public_key_pem, algorithm, created_at)
     VALUES (?, ?, 'Ed25519', ?)`,
  ).run(identity.signer.key_id, identity.signer.public_key_pem, now);
  // 0.8.1 (C2-01): a later version that bumps WRITER_GENERATION makes this one refuse to write.
  if (Number(metaValue(db, 'min_writer_generation') ?? 0) < WRITER_GENERATION) {
    db.prepare(`INSERT OR REPLACE INTO meta (key, value) VALUES ('min_writer_generation', ?)`).run(String(WRITER_GENERATION));
  }
}
