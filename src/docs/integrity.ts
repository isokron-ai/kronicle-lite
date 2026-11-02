/**
 * Projection integrity (0.5.0). The `documents`, `document_revisions`,
 * `blocks` and `doc_sources` tables are a projection of the chain; the
 * chain's own hashes say nothing about them. Before 0.5.0 an edit to
 * `blocks.content` passed `verify_chain`, `doctor` and receipt verification,
 * and `recall` served the edited text with a VERIFIED receipt.
 *
 * Two checks close that:
 *
 *   - per row (cheap, on every read path that serves text): BLAKE3 of the
 *     row's content must equal its `content_hash`, and the chained event that
 *     created the row (`events[chain_seq]`) must carry the same content and
 *     hash and still hash to its own `this_hash`;
 *   - whole projection (`verify-chain`, `doctor`, `rebuild`): replay every
 *     event into an in-memory copy of the schema and compare it with the
 *     stored tables column by column, re-hashing every block and revision.
 *
 * Neither check defends against someone who rewrites the events table
 * consistently from some seq onward and re-links the suffix; that is the
 * "box owner" case in docs/THREAT-MODEL.md, which only an off-box anchor of
 * an earlier root can expose.
 */

import Database from 'better-sqlite3';

import type { Chain, ChainEvent } from '../chain/index.js';
import { recomputeEventHash } from '../chain/event.js';
import { blake3Hex } from '../crypto/hash.js';
import type { Db } from '../db/open.js';
import { SCHEMA_SQL } from '../db/schema.js';
import { isPayloadUnparseable } from '../chain/index.js';
import { DocumentStore } from './documents.js';

/**
 *   content_hash_mismatch      BLAKE3(content) != stored content_hash
 *   chain_event_missing        no event at the row's chain_seq
 *   chain_event_mismatch       the event at chain_seq does not carry this row's id/content/hash
 *   chain_event_hash_mismatch  that event no longer hashes to its own this_hash
 */
export const ROW_PROBLEMS = ['content_hash_mismatch', 'chain_event_missing', 'chain_event_mismatch', 'chain_event_hash_mismatch'] as const;
export type RowProblem = (typeof ROW_PROBLEMS)[number];

/**
 * 0.8.1: why recall withheld a match. A row problem, or:
 *   projection_mismatch  the projection says the block is live but the chain retired it
 *   lineage_mismatch     the document's lineage rows do not match the chain
 *   store_damaged        the store file failed its check (db/health.ts)
 */
export const WITHHELD_PROBLEMS = [...ROW_PROBLEMS, 'projection_mismatch', 'lineage_mismatch', 'store_damaged'] as const;
export type WithheldProblem = (typeof WITHHELD_PROBLEMS)[number];

export interface BlockRowLike {
  block_id: string;
  doc_id: string;
  content: string;
  content_hash: string;
  chain_seq: number;
}

export interface RevisionRowLike {
  doc_id: string;
  revision: number;
  markdown: string;
  content_hash: string;
  chain_seq: number;
}

function eventOk(chain: Chain, seq: number): { ev: ChainEvent } | { problem: RowProblem } {
  let ev: ChainEvent | null;
  try {
    ev = chain.get(seq);
  } catch {
    return { problem: 'chain_event_mismatch' };
  }
  if (!ev) return { problem: 'chain_event_missing' };
  if (recomputeEventHash(ev) !== ev.this_hash) return { problem: 'chain_event_hash_mismatch' };
  return { ev };
}

/** null when the block row hashes and matches the block.created event that made it. */
export function checkBlockRow(chain: Chain, row: BlockRowLike): RowProblem | null {
  if (blake3Hex(row.content) !== row.content_hash) return 'content_hash_mismatch';
  const r = eventOk(chain, row.chain_seq);
  if ('problem' in r) return r.problem;
  const p = r.ev.payload;
  if (
    r.ev.event_type !== 'block.created' ||
    p['block_id'] !== row.block_id ||
    p['doc_id'] !== row.doc_id ||
    p['content'] !== row.content ||
    p['content_hash'] !== row.content_hash
  ) {
    return 'chain_event_mismatch';
  }
  return null;
}

/** null when the revision row hashes and matches the document.put / document.revised event that made it. */
export function checkRevisionRow(chain: Chain, row: RevisionRowLike): RowProblem | null {
  if (blake3Hex(row.markdown) !== row.content_hash) return 'content_hash_mismatch';
  const r = eventOk(chain, row.chain_seq);
  if ('problem' in r) return r.problem;
  const p = r.ev.payload;
  if (
    (r.ev.event_type !== 'document.put' && r.ev.event_type !== 'document.revised') ||
    p['doc_id'] !== row.doc_id ||
    p['revision'] !== row.revision ||
    p['markdown'] !== row.markdown ||
    p['markdown_hash'] !== row.content_hash
  ) {
    return 'chain_event_mismatch';
  }
  return null;
}

export interface ProjectionMismatch {
  table: 'documents' | 'document_revisions' | 'blocks' | 'doc_sources' | 'doc_lineage' | 'doc_lineage_gaps' | 'blocks_fts';
  /** Primary key of the row (doc_id, doc_id@revision or block_id). */
  key: string;
  /** missing (in the chain, not stored) | extra (stored, not in the chain) | a column name | content_hash. */
  field: string;
  detail: string;
}

export interface ProjectionResult {
  ok: boolean;
  events_replayed: number;
  documents_checked: number;
  revisions_checked: number;
  blocks_checked: number;
  mismatch_count: number;
  /** First 20 mismatches, in table order. */
  mismatches: ProjectionMismatch[];
}

const MAX_REPORTED = 20;

const TABLES: { table: ProjectionMismatch['table']; key: string; order: string; cols: string[] }[] = [
  {
    table: 'documents',
    key: 'doc_id',
    order: 'doc_id',
    cols: ['slug', 'title', 'current_revision', 'created_at', 'updated_at', 'tombstoned_at'],
  },
  {
    table: 'document_revisions',
    key: "doc_id || '@' || revision",
    order: 'doc_id, revision',
    cols: ['markdown', 'content_hash', 'chain_seq', 'created_at'],
  },
  {
    table: 'blocks',
    key: 'block_id',
    order: 'block_id',
    cols: [
      'doc_id',
      'revision',
      'ordinal',
      'kind',
      'level',
      'heading_path',
      'content',
      'content_hash',
      'chain_seq',
      'valid_from',
      'valid_to',
      'superseded_by',
      'tombstoned_at',
      'tombstone_reason',
    ],
  },
  { table: 'doc_sources', key: 'doc_id', order: 'doc_id', cols: ['slug', 'revision', 'chain_seq', 'kind', 'path', 'source_json'] },
  // Unreleased: derived-note lineage is safety state (it downgrades notes); a deleted row must not pass.
  {
    table: 'doc_lineage',
    key: "doc_id || '|' || source_block_id || '|' || inferred",
    order: 'doc_id, source_block_id, inferred',
    cols: ['source_content_hash', 'chain_seq'],
  },
  // 0.8.1: undetermined lineage (an inference the bound cut short) is safety state too.
  { table: 'doc_lineage_gaps', key: 'doc_id', order: 'doc_id', cols: ['chain_seq'] },
];

function short(v: unknown): string {
  const s = v === null || v === undefined ? 'null' : typeof v === 'string' ? JSON.stringify(v) : String(v);
  return s.length > 60 ? s.slice(0, 57) + '…' : s;
}

/**
 * Replay the whole chain into an in-memory projection and compare it with
 * the stored one. Read-only for `db`. Every stored block and revision is
 * also re-hashed (BLAKE3) on its own, so an import of an export whose
 * payloads disagree with their hashes is caught too.
 */
export function verifyProjection(db: Db, chain: Chain): ProjectionResult {
  const mismatches: ProjectionMismatch[] = [];
  let count = 0;
  const report = (m: ProjectionMismatch) => {
    count++;
    if (mismatches.length < MAX_REPORTED) mismatches.push(m);
  };

  const mem = new Database(':memory:');
  let events = 0;
  try {
    mem.exec(SCHEMA_SQL);
    const replay = new DocumentStore(mem, chain);
    const tx = mem.transaction(() => {
      for (const ev of chain.iterate()) {
        // An unparseable payload projects nothing (the rows it made are then
        // reported as extra/mismatched); an event that cannot be applied after
        // it is reported, not thrown.
        if (isPayloadUnparseable(ev)) {
          report({ table: 'documents', key: `seq ${ev.seq}`, field: 'payload', detail: `event ${ev.event_type} at seq ${ev.seq} has an unparseable payload` });
        } else {
          try {
            replay.applyEvent(ev);
          } catch (err) {
            report({ table: 'documents', key: `seq ${ev.seq}`, field: 'replay', detail: `event ${ev.event_type} at seq ${ev.seq} cannot be applied: ${err instanceof Error ? err.message : String(err)}` });
          }
        }
        events++;
      }
    });
    tx();

    const counts: Record<string, number> = {};
    for (const t of TABLES) {
      const sql = (d: Db) =>
        d.prepare(`SELECT ${t.key} AS k, ${t.cols.join(', ')} FROM ${t.table} ORDER BY ${t.order}`).all() as Record<string, unknown>[];
      const want = new Map(sql(mem).map((r) => [String(r['k']), r]));
      const have = sql(db);
      counts[t.table] = have.length;
      for (const row of have) {
        const k = String(row['k']);
        const exp = want.get(k);
        if (!exp) {
          report({ table: t.table, key: k, field: 'extra', detail: 'row is not produced by any chain event' });
          continue;
        }
        want.delete(k);
        for (const c of t.cols) {
          if (row[c] !== exp[c]) report({ table: t.table, key: k, field: c, detail: `stored ${short(row[c])}, chain says ${short(exp[c])}` });
        }
      }
      for (const k of want.keys()) report({ table: t.table, key: k, field: 'missing', detail: 'chain event produces this row; it is not stored' });
    }

    // Independent re-hash of what is stored (the replay compare above covers
    // content vs chain; this covers chain payloads whose own hash field lies).
    for (const r of db.prepare(`SELECT block_id, content, content_hash FROM blocks`).iterate() as Iterable<{
      block_id: string;
      content: string;
      content_hash: string;
    }>) {
      if (blake3Hex(r.content) !== r.content_hash) {
        report({ table: 'blocks', key: r.block_id, field: 'content_hash', detail: 'BLAKE3(content) does not equal content_hash' });
      }
    }
    for (const r of db.prepare(`SELECT doc_id, revision, markdown, content_hash FROM document_revisions`).iterate() as Iterable<{
      doc_id: string;
      revision: number;
      markdown: string;
      content_hash: string;
    }>) {
      if (blake3Hex(r.markdown) !== r.content_hash) {
        report({ table: 'document_revisions', key: `${r.doc_id}@${r.revision}`, field: 'content_hash', detail: 'BLAKE3(markdown) does not equal content_hash' });
      }
    }

    // 0.8.1 (R2-17): the full-text index must hold exactly the stored text
    // (absence is certified from it). FTS5's own check, against the content table.
    const fts = checkFtsContent(db);
    if (fts) report({ table: 'blocks_fts', key: 'index', field: 'content', detail: fts });

    return {
      ok: count === 0,
      events_replayed: events,
      documents_checked: counts['documents'] ?? 0,
      revisions_checked: counts['document_revisions'] ?? 0,
      blocks_checked: counts['blocks'] ?? 0,
      mismatch_count: count,
      mismatches,
    };
  } finally {
    mem.close();
  }
}

/** One line for CLIs and banners. */
export function describeProjection(r: ProjectionResult): string {
  if (r.ok) return `projection matches the chain (${r.blocks_checked} block(s), ${r.revisions_checked} revision(s) re-hashed against ${r.events_replayed} event(s))`;
  const m = r.mismatches[0];
  return `${r.mismatch_count} projection mismatch(es) vs the chain${m ? `; first: ${m.table} ${m.key} ${m.field} (${m.detail})` : ''}`;
}

/**
 * Rebuild the projection tables from the chain (after the chain itself
 * verified). Receipts, flight recorder, checkpoints and anchors are kept.
 */
export function rebuildProjection(db: Db, chain: Chain): { events: number } {
  let events = 0;
  const docs = new DocumentStore(db, chain);
  const tx = db.transaction(() => {
    // The delete trigger would feed possibly-corrupt old values back to FTS5;
    // drop it, clear everything, replay, then rebuild the index from scratch.
    db.exec(`INSERT INTO blocks_fts(blocks_fts) VALUES('delete-all'); DROP TRIGGER IF EXISTS blocks_ad;`);
    db.exec(`DELETE FROM doc_lineage_gaps; DELETE FROM doc_lineage; DELETE FROM doc_sources; UPDATE blocks SET superseded_by = NULL; DELETE FROM blocks; DELETE FROM document_revisions; DELETE FROM documents;`);
    db.exec(SCHEMA_SQL.replace(/PRAGMA journal_mode = WAL;/, ''));
    for (const ev of chain.iterate()) {
      docs.applyEvent(ev);
      events++;
    }
    db.exec(`INSERT INTO blocks_fts(blocks_fts) VALUES('rebuild')`);
  });
  tx.immediate();
  return { events };
}

// ───────────────────────────── 0.8.1: cheap cross-checks for every read ─────────────────────────────

const RETIRED_ID = `(CASE WHEN json_valid(e.payload_canonical) THEN json_extract(e.payload_canonical, '$.block_id') END)`;

/**
 * 0.8.1 (R2-09): block lifecycle in the projection against the chain, cheap
 * enough for every orient focus and pulse (index lookups and counts, no
 * replay). Catches what a partial restore or a hand edit of `blocks` does to
 * what agents are served: a superseded / tombstoned row made live again, a
 * live row retired, a row added or deleted, a supersession pointer
 * re-pointed. null when consistent, else the first problem in words.
 * Row content is checked separately (checkBlockRow); lineage rows by
 * Lineage.checkProjection; the whole projection by verifyProjection.
 */
export function checkBlockLifecycle(db: Db): string | null {
  const live = db
    .prepare(
      `SELECT b.block_id FROM blocks b WHERE b.valid_to IS NULL AND b.tombstoned_at IS NULL AND EXISTS (
         SELECT 1 FROM events e WHERE e.event_type IN ('block.superseded', 'block.tombstoned') AND ${RETIRED_ID} = b.block_id) LIMIT 1`,
    )
    .get() as { block_id: string } | undefined;
  if (live) return `block ${live.block_id} is live in the projection but the chain retired it`;
  const n = (sql: string) => (db.prepare(sql).get() as { n: number }).n;
  const created = n(`SELECT count(*) AS n FROM events WHERE event_type = 'block.created'`);
  const stored = n(`SELECT count(*) AS n FROM blocks`);
  if (created !== stored) return `${stored} block row(s) stored, the chain created ${created}`;
  const retiredChain = n(
    `SELECT count(*) AS n FROM (SELECT DISTINCT ${RETIRED_ID} AS id FROM events e WHERE e.event_type IN ('block.superseded', 'block.tombstoned')) WHERE id IS NOT NULL`,
  );
  const retiredStored = n(`SELECT count(*) AS n FROM blocks WHERE valid_to IS NOT NULL OR tombstoned_at IS NOT NULL`);
  if (retiredChain !== retiredStored) return `${retiredStored} block(s) retired in the projection, the chain retired ${retiredChain}`;
  const tombChain = n(
    `SELECT count(*) AS n FROM (SELECT DISTINCT ${RETIRED_ID} AS id FROM events e WHERE e.event_type = 'block.tombstoned') WHERE id IS NOT NULL`,
  );
  const tombStored = n(`SELECT count(*) AS n FROM blocks WHERE tombstoned_at IS NOT NULL`);
  if (tombChain !== tombStored) return `${tombStored} block(s) tombstoned in the projection, the chain tombstoned ${tombChain}`;
  const ptr = db
    .prepare(
      `SELECT b.block_id FROM events e JOIN blocks b ON b.block_id = ${RETIRED_ID}
        WHERE e.event_type = 'block.superseded' AND b.superseded_by IS NOT json_extract(e.payload_canonical, '$.successor_block_id') LIMIT 1`,
    )
    .get() as { block_id: string } | undefined;
  if (ptr) return `block ${ptr.block_id}: its successor in the projection is not the one the chain records`;
  return null;
}

/**
 * 0.8.1 (R2-17): the full-text index against the stored block text (FTS5
 * `integrity-check` with rank 1 compares the index with the content table).
 * null when they agree (or there is no index to check: indexFreshness
 * reports that), else the problem in words.
 */
export function checkFtsContent(db: Db): string | null {
  try {
    db.prepare(`INSERT INTO blocks_fts(blocks_fts, rank) VALUES('integrity-check', 1)`).run();
    return null;
  } catch (err) {
    const code = (err as { code?: unknown }).code;
    if (typeof code === 'string' && code.startsWith('SQLITE_CORRUPT')) return 'the full-text index does not match the stored block text (FTS5 integrity-check)';
    if (/no such table/i.test(String(err))) return null;
    return `full-text index check failed: ${err instanceof Error ? err.message : String(err)}`;
  }
}
