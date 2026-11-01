import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import { ensureDefaultConfig } from '../anchor/config.js';
import { GENESIS_HASH } from '../chain/genesis.js';
import {
  ephemeralIdentity,
  loadOrCreateIdentity,
  type ServerIdentity,
} from '../crypto/keys.js';
import { SCHEMA_SQL, SCHEMA_VERSION } from './schema.js';

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
    mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    db = new Database(join(dataDir, 'kronicle-lite.db'));
    identity = loadOrCreateIdentity(dataDir);
    // First run: config.json with the default anchor_url only (no license key).
    ensureDefaultConfig(dataDir);
  }

  db.exec(SCHEMA_SQL);
  initialize(db, identity);
  return { db, identity, dataDir };
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
