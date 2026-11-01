/**
 * SQLite schema. One file, one writer. See docs/FORMAT.md for which
 * columns participate in which hash.
 */

export const SCHEMA_VERSION = 1;

export const SCHEMA_SQL = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Single-row head pointer. Updated inside the same transaction as the append.
CREATE TABLE IF NOT EXISTS chain_head (
  id   INTEGER PRIMARY KEY CHECK (id = 1),
  seq  INTEGER NOT NULL,
  hash TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  seq               INTEGER PRIMARY KEY,
  event_id          TEXT NOT NULL UNIQUE,
  event_type        TEXT NOT NULL,
  payload_canonical TEXT NOT NULL,
  actor_id          TEXT NOT NULL,
  occurred_at       TEXT NOT NULL,
  nonce             TEXT NOT NULL,
  prev_hash         TEXT NOT NULL,
  this_hash         TEXT NOT NULL UNIQUE,
  idempotency_key   TEXT UNIQUE
);
CREATE INDEX IF NOT EXISTS events_type_idx ON events (event_type, seq);

CREATE TABLE IF NOT EXISTS checkpoints (
  checkpoint_id TEXT PRIMARY KEY,
  from_seq      INTEGER NOT NULL,
  to_seq        INTEGER NOT NULL,
  leaf_count    INTEGER NOT NULL,
  root          TEXT NOT NULL,
  key_id        TEXT NOT NULL,
  signature     TEXT NOT NULL,
  created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS signing_keys (
  key_id         TEXT PRIMARY KEY,
  public_key_pem TEXT NOT NULL,
  algorithm      TEXT NOT NULL DEFAULT 'Ed25519',
  created_at     TEXT NOT NULL,
  revoked_at     TEXT
);

CREATE TABLE IF NOT EXISTS documents (
  doc_id           TEXT PRIMARY KEY,
  slug             TEXT NOT NULL UNIQUE,
  title            TEXT NOT NULL,
  current_revision INTEGER NOT NULL,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL,
  tombstoned_at    TEXT
);

CREATE TABLE IF NOT EXISTS document_revisions (
  doc_id       TEXT NOT NULL REFERENCES documents(doc_id),
  revision     INTEGER NOT NULL,
  markdown     TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  chain_seq    INTEGER NOT NULL,
  created_at   TEXT NOT NULL,
  PRIMARY KEY (doc_id, revision)
);

CREATE TABLE IF NOT EXISTS blocks (
  block_id         TEXT PRIMARY KEY,
  doc_id           TEXT NOT NULL REFERENCES documents(doc_id),
  revision         INTEGER NOT NULL,
  ordinal          INTEGER NOT NULL,
  kind             TEXT NOT NULL,
  level            INTEGER NOT NULL DEFAULT 0,
  heading_path     TEXT NOT NULL,
  content          TEXT NOT NULL,
  content_hash     TEXT NOT NULL,
  chain_seq        INTEGER NOT NULL,
  valid_from       TEXT NOT NULL,
  valid_to         TEXT,
  superseded_by    TEXT REFERENCES blocks(block_id),
  tombstoned_at    TEXT,
  tombstone_reason TEXT
);
CREATE INDEX IF NOT EXISTS blocks_doc_idx ON blocks (doc_id, revision, ordinal);
CREATE INDEX IF NOT EXISTS blocks_live_idx ON blocks (doc_id) WHERE valid_to IS NULL AND tombstoned_at IS NULL;

CREATE VIRTUAL TABLE IF NOT EXISTS blocks_fts USING fts5(
  content,
  heading_path,
  content='blocks',
  content_rowid='rowid',
  tokenize='porter unicode61'
);
CREATE TRIGGER IF NOT EXISTS blocks_ai AFTER INSERT ON blocks BEGIN
  INSERT INTO blocks_fts(rowid, content, heading_path) VALUES (new.rowid, new.content, new.heading_path);
END;
CREATE TRIGGER IF NOT EXISTS blocks_ad AFTER DELETE ON blocks BEGIN
  INSERT INTO blocks_fts(blocks_fts, rowid, content, heading_path) VALUES ('delete', old.rowid, old.content, old.heading_path);
END;
CREATE TRIGGER IF NOT EXISTS blocks_au AFTER UPDATE OF content, heading_path ON blocks BEGIN
  INSERT INTO blocks_fts(blocks_fts, rowid, content, heading_path) VALUES ('delete', old.rowid, old.content, old.heading_path);
  INSERT INTO blocks_fts(rowid, content, heading_path) VALUES (new.rowid, new.content, new.heading_path);
END;

CREATE TABLE IF NOT EXISTS receipts (
  receipt_id      TEXT PRIMARY KEY,
  block_id        TEXT NOT NULL,
  chain_seq       INTEGER NOT NULL,
  query_hash      TEXT NOT NULL,
  issued_at       TEXT NOT NULL,
  receipt_json    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS receipts_block_idx ON receipts (block_id);

-- Every orient briefing issued, so a later call can recover the actor's
-- last position without a cursor, and the briefing can be replayed.
CREATE TABLE IF NOT EXISTS flight_recorder (
  briefing_id  TEXT PRIMARY KEY,
  actor_id     TEXT NOT NULL,
  issued_at    TEXT NOT NULL,
  from_seq     INTEGER NOT NULL,
  to_seq       INTEGER NOT NULL,
  head_hash    TEXT NOT NULL,
  focus        TEXT NOT NULL,
  delta_hash   TEXT NOT NULL,
  record_json  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS flight_actor_idx ON flight_recorder (actor_id, issued_at);

-- 0.4.0, additive. Countersigned anchor receipts fetched from the hosted
-- anchor service (checkpoint --push). Not part of any hash; re-fetchable
-- from the service by chain_id. receipt_json holds the JCS bytes, so
-- sha256(receipt_json) is the receipt's public-log leaf.
CREATE TABLE IF NOT EXISTS anchors (
  anchor_id     TEXT PRIMARY KEY,
  checkpoint_id TEXT,
  chain_id      TEXT NOT NULL,
  anchor_url    TEXT NOT NULL,
  from_seq      INTEGER NOT NULL,
  to_seq        INTEGER NOT NULL,
  root          TEXT NOT NULL,
  received_at   TEXT NOT NULL,
  receipt_json  TEXT NOT NULL,
  day           TEXT,
  leaf_index    INTEGER,
  path_json     TEXT,
  status        TEXT NOT NULL DEFAULT 'pending_public',
  fetched_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS anchors_range_idx ON anchors (chain_id, from_seq, to_seq);

-- 0.4.0, additive projection: provenance of each document from the optional
-- \`source\` field of its latest document.put (instruction import, git binding).
-- Rebuilt from the chain like every other projection table.
CREATE TABLE IF NOT EXISTS doc_sources (
  doc_id      TEXT PRIMARY KEY REFERENCES documents(doc_id),
  slug        TEXT NOT NULL,
  revision    INTEGER NOT NULL,
  chain_seq   INTEGER NOT NULL,
  kind        TEXT NOT NULL,
  path        TEXT NOT NULL,
  source_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS doc_sources_kind_idx ON doc_sources (kind, slug);
`;
