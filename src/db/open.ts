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
    db = new Database(dbFile);
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

  db.exec(SCHEMA_SQL);
  addColumns(db);
  initialize(db, identity);
  return { db, identity, dataDir };
}

/** Additive migrations for databases created by an older version. */
function addColumns(db: Db): void {
  for (const c of ADDED_COLUMNS) {
    const cols = db.prepare(`SELECT name FROM pragma_table_info(?)`).all(c.table) as { name: string }[];
    if (!cols.some((x) => x.name === c.column)) db.exec(c.ddl);
    if (c.index) db.exec(c.index);
  }
}

function initialize(db: Db, identity: ServerIdentity): void {
  const now = new Date().toISOString();
  const tx = db.transaction(() => {
    db.prepare(
      `INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)`,
    ).run(String(SCHEMA_VERSION));
    db.prepare(
      `INSERT OR IGNORE INTO chain_head (id, seq, hash) VALUES (1, 0, ?)`,
    ).run(GENESIS_HASH);
    db.prepare(
      `INSERT OR IGNORE INTO signing_keys (key_id, public_key_pem, algorithm, created_at)
       VALUES (?, ?, 'Ed25519', ?)`,
    ).run(identity.signer.key_id, identity.signer.public_key_pem, now);
  });
  tx();
}
