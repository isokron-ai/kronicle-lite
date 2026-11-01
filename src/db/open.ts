import Database from 'better-sqlite3';
import { chmodSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import { ensureDefaultConfig } from '../anchor/config.js';
import { GENESIS_HASH } from '../chain/genesis.js';
import {
  ephemeralIdentity,
  loadOrCreateIdentity,
  type ServerIdentity,
} from '../crypto/keys.js';
import { ensureDir } from '../util/once-file.js';
import { ADDED_COLUMNS, SCHEMA_SQL, SCHEMA_VERSION } from './schema.js';

export type Db = Database.Database;

export interface OpenOptions {
  /** Directory holding the database, signing key and cursor secret. */
  dataDir?: string;
  /** Use an in-memory database with an ephemeral identity (tests). */
  memory?: boolean;
}

export interface Opened {
  db: Db;
  identity: ServerIdentity;
  dataDir: string | null;
}

export function defaultDataDir(): string {
  return process.env['KRONICLE_LITE_DATA_DIR'] ?? join(homedir(), '.kronicle-lite');
}

export function openDatabase(opts: OpenOptions = {}): Opened {
  let db: Db;
  let identity: ServerIdentity;
  let dataDir: string | null;

  if (opts.memory) {
    db = new Database(':memory:');
    identity = ephemeralIdentity();
    dataDir = null;
  } else {
    dataDir = opts.dataDir ?? defaultDataDir();
    ensureDir(dataDir, 0o700);
    const dbFile = join(dataDir, 'kronicle-lite.db');
    const fresh = !existsSync(dbFile);
    // Busy timeout before ANY statement: concurrent first starts (several
    // servers / hooks opening a fresh data dir at once) must wait for each
    // other's schema creation instead of failing with "database is locked".
    db = new Database(dbFile, { timeout: BUSY_TIMEOUT_MS });
    db.pragma(`busy_timeout = ${BUSY_TIMEOUT_MS}`);
    // 0.4.0: a new database is private like the keys next to it (WAL/SHM inherit its mode). No-op on Windows.
    if (fresh) {
      try {
        chmodSync(dbFile, 0o600);
      } catch {
        // best effort
      }
    }
    identity = loadOrCreateIdentity(dataDir);
    // First run: config.json with the default anchor_url only (no license key).
    ensureDefaultConfig(dataDir);
  }

  // Connection settings first, outside any transaction (foreign_keys is a
  // no-op inside one; switching to WAL needs the file to itself for a moment).
  if (!opts.memory) withBusyRetry(() => enableWal(db));
  db.pragma('foreign_keys = ON');
  // Schema, migrations and seed rows in ONE immediate transaction: the write
  // lock is taken up front (waiting via the busy handler), so two processes
  // never deadlock upgrading a read to a write. Retried on SQLITE_BUSY.
  withBusyRetry(() =>
    db
      .transaction(() => {
        db.exec(SCHEMA_DDL);
        addColumns(db);
        initialize(db, identity);
      })
      .immediate(),
  );
  return { db, identity, dataDir };
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

function initialize(db: Db, identity: ServerIdentity): void {
  const now = new Date().toISOString();
  // Runs inside open()'s immediate setup transaction.
  db.prepare(`INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)`).run(String(SCHEMA_VERSION));
  db.prepare(`INSERT OR IGNORE INTO chain_head (id, seq, hash) VALUES (1, 0, ?)`).run(GENESIS_HASH);
  db.prepare(
    `INSERT OR IGNORE INTO signing_keys (key_id, public_key_pem, algorithm, created_at)
     VALUES (?, ?, 'Ed25519', ?)`,
  ).run(identity.signer.key_id, identity.signer.public_key_pem, now);
}
