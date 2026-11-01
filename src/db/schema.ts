/**
 * SQLite schema. One file, one writer. See docs/FORMAT.md for which
 * columns participate in which hash.
 */

export const SCHEMA_VERSION = 1;

/**
 * Columns added to existing tables after 0.3.0; `openDatabase` adds them to
 * older databases (ALTER TABLE … ADD COLUMN), then creates their indexes.
 */
export const ADDED_COLUMNS: readonly { table: string; column: string; ddl: string; index?: string; backfill?: string }[] = [
  {
    table: 'receipts',
    column: 'actor_id',
    ddl: 'ALTER TABLE receipts ADD COLUMN actor_id TEXT',
    index: 'CREATE INDEX IF NOT EXISTS receipts_actor_idx ON receipts (actor_id, issued_at)',
  },
  {
    // Unreleased (next): the project a document belongs to (instruction files'
    // source.project.key, or the `project` of an MCP / CLI put). NULL = unscoped
    // (every 0.6.0-and-earlier note): visible from every project. A derived
    // index like the rest of the projection; recall and orient filter on it.
    table: 'documents',
    column: 'project_key',
    ddl: 'ALTER TABLE documents ADD COLUMN project_key TEXT',
    index: 'CREATE INDEX IF NOT EXISTS documents_project_idx ON documents (project_key)',
    backfill: `UPDATE documents SET project_key = (SELECT json_extract(s.source_json, '$.project.key') FROM doc_sources s WHERE s.doc_id = documents.doc_id) WHERE project_key IS NULL`,
  },
];

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
  tombstoned_at    TEXT,
  project_key      TEXT
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
-- Unreleased (next): rename detection looks documents up by their markdown hash.
CREATE INDEX IF NOT EXISTS revisions_hash_idx ON document_revisions (content_hash);

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
  receipt_json    TEXT NOT NULL,
  -- 0.6.0, additive, local only (not in the signed receipt or any hash): the
  -- actor recall served, so a later recall can lower what it already read.
  actor_id        TEXT
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

-- Unreleased, additive projection: derived-note lineage, from the optional
-- \`derived_from\` / \`derived_from_inferred\` fields of document.put and
-- block.created (supersede_block) payloads (docs/FORMAT.md §3.10). A put that
-- carries an explicit \`derived_from\` (even []) replaces the document's rows;
-- every other lineage field adds to them. Rebuilt from the chain like the rest.
CREATE TABLE IF NOT EXISTS doc_lineage (
  doc_id              TEXT NOT NULL,
  source_block_id     TEXT NOT NULL,
  source_content_hash TEXT NOT NULL,
  inferred            INTEGER NOT NULL,
  chain_seq           INTEGER NOT NULL,
  PRIMARY KEY (doc_id, source_block_id, inferred)
);
CREATE INDEX IF NOT EXISTS doc_lineage_source_idx ON doc_lineage (source_block_id);

-- Unreleased, additive, local only (never chained or hashed, like
-- receipts.actor_id): which version of what each actor read or wrote, for
-- version-bound reconciliation (docs/PUSH.md "pending"). block_id NULL = a
-- whole-document read (its live blocks get their own rows too).
-- via: recall | document | write.
CREATE TABLE IF NOT EXISTS reads (
  actor_id     TEXT NOT NULL,
  doc_id       TEXT NOT NULL,
  block_id     TEXT,
  content_hash TEXT NOT NULL,
  doc_revision INTEGER NOT NULL,
  head_seq     INTEGER NOT NULL,
  read_at      TEXT NOT NULL,
  via          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS reads_actor_idx ON reads (actor_id, read_at);
CREATE INDEX IF NOT EXISTS reads_actor_block_idx ON reads (actor_id, block_id);
-- Unreleased: walk a supersession lineage backwards (format-only predecessors).
CREATE INDEX IF NOT EXISTS blocks_superseded_by_idx ON blocks (superseded_by) WHERE superseded_by IS NOT NULL;
`;
