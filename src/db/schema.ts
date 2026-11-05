/**
 * SQLite schema. One file, one writer. See docs/FORMAT.md for which
 * columns participate in which hash.
 */

export const SCHEMA_VERSION = 1;

/**
 * 0.8.1: one-time data migrations, forward-only, each guarded by a `meta`
 * key and run inside open()'s setup transaction. They only derive projection
 * rows from the chain (never touch events), so re-running one is harmless.
 */
export const DATA_MIGRATIONS: readonly { key: string; sql: string }[] = [
  {
    // doc_lineage_gaps for notes written by 0.8.0 (lineageEffects in SQL): the
    // latest truncated inference per document, unless a later put declared
    // an explicit derived_from.
    key: 'migration.lineage_gaps',
    sql: `DELETE FROM doc_lineage_gaps;
      INSERT INTO doc_lineage_gaps (doc_id, chain_seq)
        SELECT json_extract(payload_canonical, '$.doc_id') AS d, MAX(seq) FROM events
         WHERE event_type IN ('document.put', 'block.created') AND instr(payload_canonical, '"derived_from') > 0
           AND json_valid(payload_canonical) AND json_extract(payload_canonical, '$.derived_from_inferred_truncated') = 1
           AND (CASE WHEN event_type = 'document.put' THEN json_type(payload_canonical, '$.derived_from') IS NOT 'array'
                     ELSE coalesce(json_array_length(payload_canonical, '$.derived_from'), 0) = 0 END)
           AND json_type(payload_canonical, '$.doc_id') = 'text'
         GROUP BY d;
      DELETE FROM doc_lineage_gaps WHERE EXISTS (
        SELECT 1 FROM events e WHERE e.event_type = 'document.put' AND instr(e.payload_canonical, '"derived_from') > 0 AND json_valid(e.payload_canonical)
           AND json_extract(e.payload_canonical, '$.doc_id') = doc_lineage_gaps.doc_id
           AND json_type(e.payload_canonical, '$.derived_from') = 'array' AND e.seq > doc_lineage_gaps.chain_seq);`,
  },
];

/**
 * Columns added to existing tables after 0.3.0; `openDatabase` adds them to
 * older databases (ALTER TABLE … ADD COLUMN), then creates their indexes.
 */
export const ADDED_COLUMNS: readonly { table: string; column: string; ddl: string; index?: string; backfill?: string }[] = [
  {
    table: 'receipts',
    column: 'actor_id',
    ddl: 'ALTER TABLE receipts ADD COLUMN actor_id TEXT',
    // 0.8.1: receipts_actor_rowid_idx serves an actor's receipts after a rowid
    // (the read log's receipts mark, src/lineage/read-log.ts): rowid is the
    // implicit last column, so (actor_id = ? AND rowid > ?) is one range.
    index:
      'CREATE INDEX IF NOT EXISTS receipts_actor_idx ON receipts (actor_id, issued_at); CREATE INDEX IF NOT EXISTS receipts_actor_rowid_idx ON receipts (actor_id)',
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
-- 0.8.1, additive projection: a note whose inferred lineage the bound cut
-- short (\`derived_from_inferred_truncated\` without an explicit statement):
-- its sources are undetermined, so recall never labels it can_act. Cleared by
-- an explicit \`derived_from\`. Rebuilt from the chain like the rest
-- (src/docs/documents.ts lineageEffects); backfilled once on upgrade.
CREATE TABLE IF NOT EXISTS doc_lineage_gaps (
  doc_id    TEXT PRIMARY KEY,
  chain_seq INTEGER NOT NULL
);

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
-- 0.8.1: the log keeps only the latest reads per (actor, block, document, via)
-- (src/lineage/read-log.ts); this index finds that key's rows and serves
-- pending's per-block MAX(head_seq) from the index alone. It replaces
-- reads_actor_block_idx (dropped by the one-time compaction).
CREATE INDEX IF NOT EXISTS reads_actor_key_idx ON reads (actor_id, block_id, doc_id, via, head_seq);
-- 0.8.1: readersOf (who read these blocks / this note) without a full scan.
CREATE INDEX IF NOT EXISTS reads_block_idx ON reads (block_id);
CREATE INDEX IF NOT EXISTS reads_doc_idx ON reads (doc_id);
-- Unreleased: walk a supersession lineage backwards (format-only predecessors).
CREATE INDEX IF NOT EXISTS blocks_superseded_by_idx ON blocks (superseded_by) WHERE superseded_by IS NOT NULL;
-- Unreleased: the event that retired a block (lineage change seqs; chainRetired). The
-- expression tolerates an unparseable payload (FORMAT §3.9), so opening a damaged store
-- never fails on it. An index, not chain data: no hash covers it.
CREATE INDEX IF NOT EXISTS events_retired_block_idx
  ON events ((CASE WHEN json_valid(payload_canonical) THEN json_extract(payload_canonical, '$.block_id') END))
  WHERE event_type IN ('block.superseded', 'block.tombstoned');
-- 0.8.1: the events that carry lineage fields (the integrity pass replays them
-- against doc_lineage). An index, not chain data.
CREATE INDEX IF NOT EXISTS events_lineage_idx
  ON events (seq)
  WHERE event_type IN ('document.put', 'block.created') AND instr(payload_canonical, '"derived_from') > 0;

-- 0.9.0: content-addressed artifact store for audit evidence (traces, responses,
-- transcripts, reports). OUTSIDE the chain: events carry {sha256, size} refs only.
-- Never projection: rebuild does not touch it.
CREATE TABLE IF NOT EXISTS blobs (
  sha256     TEXT PRIMARY KEY,
  size       INTEGER NOT NULL,
  media_type TEXT,
  bytes      BLOB NOT NULL,
  created_at TEXT NOT NULL,
  -- 'unscanned_encoding': a view (gzip, deflate…) could not be decoded within the scan cap.
  flags      TEXT
);

-- 0.9.0: audit event projection (re-derived from audit.* events by rebuild).
CREATE TABLE IF NOT EXISTS audit_events (
  seq        INTEGER PRIMARY KEY,
  event_id   TEXT NOT NULL UNIQUE,
  audit_id   TEXT NOT NULL,
  kind       TEXT NOT NULL,
  event_key  TEXT NOT NULL,
  finding_id TEXT,
  UNIQUE (audit_id, event_key)
);
CREATE INDEX IF NOT EXISTS audit_events_audit_idx ON audit_events (audit_id, kind, seq);
CREATE INDEX IF NOT EXISTS audit_events_finding_idx ON audit_events (audit_id, finding_id, seq);
CREATE TABLE IF NOT EXISTS audit_event_fingerprints (
  fingerprint TEXT NOT NULL,
  seq         INTEGER NOT NULL,
  PRIMARY KEY (fingerprint, seq)
);
-- Current state of each finding: a projection of its immutable events.
CREATE TABLE IF NOT EXISTS audit_findings (
  audit_id   TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  status     TEXT NOT NULL,
  title      TEXT,
  severity   TEXT,
  opened_seq INTEGER NOT NULL,
  last_seq   INTEGER NOT NULL,
  events     INTEGER NOT NULL,
  PRIMARY KEY (audit_id, finding_id)
);

-- 0.9.0: apply. Confirmations issued by a dry run (single use: used_at set by the
-- commit, or burned when the commit fails) and committed results by idempotency
-- key (replay). Side tables like receipts: not chain data, not projection.
CREATE TABLE IF NOT EXISTS apply_confirmations (
  nonce      TEXT PRIMARY KEY,
  plan_hash  TEXT NOT NULL,
  actor_id   TEXT NOT NULL,
  issued_at  TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at    TEXT,
  outcome    TEXT,
  -- What the token binds (plan hash, actor, tenant, sandbox, catalog, project, resources and
  -- versions, policy, expiry, idempotency key): server-side, so the token is only nonce + MAC.
  binding_json TEXT
);
CREATE INDEX IF NOT EXISTS apply_confirmations_expiry_idx ON apply_confirmations (expires_at);
CREATE INDEX IF NOT EXISTS apply_confirmations_actor_idx ON apply_confirmations (actor_id, plan_hash, expires_at);
CREATE TABLE IF NOT EXISTS apply_results (
  idempotency_key TEXT PRIMARY KEY,
  request_hash    TEXT NOT NULL,
  actor_id        TEXT NOT NULL,
  result_json     TEXT NOT NULL,
  seq             INTEGER NOT NULL
);
`;
