/**
 * The local read log (`reads`), bounded (0.8.1).
 *
 * Every question asked of the log is about the LATEST read of a version:
 * `pending` / `readCurrent` take MAX(head_seq) per (actor, block) and per
 * (actor, document); lineage inference takes the blocks whose latest
 * non-write read falls in its window (MAX(read_at) per block); `readersOf`
 * asks only whether a read exists. So per key (actor, block, document, via)
 * only the rows that are the latest by some measure are kept: the highest
 * head_seq, the latest read_at and the latest recorded (rowid). Older rows
 * of the key are pruned in the same transaction that records a new one, and
 * a 0.8.0 log is compacted the same way once (forward-only: nothing that any
 * of those questions can see is removed).
 *
 * Receipts: recall also signs a receipt per hit (with the actor since 0.6.0),
 * and receipts are never pruned (they are verifiable artifacts). Instead of
 * scanning an actor's every receipt on each `pending`, receipts are folded
 * into the log (one row per actor and block) and `meta.reads_receipts_mark`
 * records the last receipt rowid folded; readers union the log with only the
 * receipts after the mark (indexed: receipts_actor_rowid_idx). Receipts a
 * writer left unfolded (an older binary) are therefore still seen.
 */

import type BetterSqlite3 from 'better-sqlite3';

import type { Db } from '../db/open.js';

type Statement = BetterSqlite3.Statement<unknown[]>;

export interface ReadRow {
  actor_id: string;
  doc_id: string;
  /** null: a whole-document read. */
  block_id: string | null;
  content_hash: string;
  doc_revision: number;
  head_seq: number;
  read_at: string;
  via: 'recall' | 'document' | 'write';
}

/** meta key: rowid of the last receipt folded into the read log. */
export const RECEIPTS_MARK_KEY = 'reads_receipts_mark';
/** meta key: the one-time compaction of a log written before 0.8.1 is done. */
export const READS_COMPACTED_KEY = 'reads_compacted';

const KEY = `actor_id = @actor_id AND block_id IS @block_id AND doc_id = @doc_id AND via = @via`;

export class ReadLog {
  private readonly stmts = new Map<string, Statement>();
  private compacted = false;

  constructor(private readonly db: Db) {}

  private q(sql: string): Statement {
    let st = this.stmts.get(sql);
    if (!st) {
      st = this.db.prepare(sql);
      this.stmts.set(sql, st);
    }
    return st;
  }

  /** Rowid of the last receipt folded into the log (0: none yet). Receipts after it are read directly. */
  receiptsMark(): number {
    const r = this.q(`SELECT value FROM meta WHERE key = ?`).get(RECEIPTS_MARK_KEY) as { value: string } | undefined;
    const n = r ? Number(r.value) : 0;
    return Number.isSafeInteger(n) && n > 0 ? n : 0;
  }

  /**
   * Record reads and prune what they make redundant. Runs in its own
   * transaction (a savepoint inside the caller's). Also folds receipts
   * written since the mark into the log, except those `rows` already cover.
   */
  record(rows: readonly ReadRow[]): void {
    if (rows.length === 0) return;
    this.db.transaction(() => {
      this.compactOnce();
      this.foldReceipts(rows);
      const ins = this.q(
        `INSERT INTO reads (actor_id, doc_id, block_id, content_hash, doc_revision, head_seq, read_at, via)
         VALUES (@actor_id, @doc_id, @block_id, @content_hash, @doc_revision, @head_seq, @read_at, @via)`,
      );
      for (const r of rows) {
        ins.run(r);
        this.pruneKey(r);
      }
    })();
  }

  /** Delete the rows of one key that are not the latest by head_seq, by read_at or by insertion. */
  private pruneKey(k: Pick<ReadRow, 'actor_id' | 'doc_id' | 'block_id' | 'via'>): void {
    this.q(
      `DELETE FROM reads WHERE ${KEY} AND rowid NOT IN (
         SELECT rowid FROM (SELECT rowid FROM reads WHERE ${KEY} ORDER BY head_seq DESC, read_at DESC, rowid DESC LIMIT 1)
         UNION SELECT rowid FROM (SELECT rowid FROM reads WHERE ${KEY} ORDER BY read_at DESC, head_seq DESC, rowid DESC LIMIT 1)
         UNION SELECT rowid FROM (SELECT rowid FROM reads WHERE ${KEY} ORDER BY rowid DESC LIMIT 1)
       )`,
    ).run({ actor_id: k.actor_id, doc_id: k.doc_id, block_id: k.block_id, via: k.via });
  }

  /**
   * Fold receipts after the mark into the log (one row per actor and block:
   * the highest chain_seq and the latest issue time), then advance the mark.
   * Receipts of the reads being recorded now are skipped: those rows say it.
   */
  private foldReceipts(recording: readonly ReadRow[]): void {
    const max = (this.q(`SELECT MAX(rowid) AS m FROM receipts`).get() as { m: number | null }).m ?? 0;
    const mark = this.receiptsMark();
    if (max <= mark) return;
    const covered = new Set(recording.filter((r) => r.via === 'recall' && r.block_id !== null).map((r) => `${r.actor_id}\u0000${r.block_id}`));
    const folded = this.q(
      `SELECT r.actor_id, r.block_id, b.doc_id, b.content_hash, b.revision AS doc_revision, MAX(r.chain_seq) AS head_seq, MAX(r.issued_at) AS read_at
         FROM receipts r JOIN blocks b ON b.block_id = r.block_id
        WHERE r.rowid > ? AND r.rowid <= ? AND r.actor_id IS NOT NULL
        GROUP BY r.actor_id, r.block_id`,
    ).all(mark, max) as Omit<ReadRow, 'via'>[];
    const ins = this.q(
      `INSERT INTO reads (actor_id, doc_id, block_id, content_hash, doc_revision, head_seq, read_at, via)
       VALUES (@actor_id, @doc_id, @block_id, @content_hash, @doc_revision, @head_seq, @read_at, 'recall')`,
    );
    for (const f of folded) {
      if (covered.has(`${f.actor_id}\u0000${f.block_id}`)) continue;
      ins.run(f);
      this.pruneKey({ ...f, via: 'recall' });
    }
    this.q(`INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(RECEIPTS_MARK_KEY, String(max));
  }

  /**
   * Once per store: prune a log written before 0.8.1 to the rows `pruneKey`
   * would have kept, and drop the index this release replaced. Forward-only;
   * an older binary that recreates the old index changes nothing here.
   */
  compactOnce(): void {
    if (this.compacted) return;
    if (this.q(`SELECT 1 FROM meta WHERE key = ?`).get(READS_COMPACTED_KEY) === undefined) {
      this.db.exec(`DROP INDEX IF EXISTS reads_actor_block_idx`);
      this.db.exec(
        `DELETE FROM reads WHERE rowid NOT IN (
           SELECT rowid FROM (
             SELECT rowid,
                    ROW_NUMBER() OVER (PARTITION BY actor_id, block_id, doc_id, via ORDER BY head_seq DESC, read_at DESC, rowid DESC) AS by_seq,
                    ROW_NUMBER() OVER (PARTITION BY actor_id, block_id, doc_id, via ORDER BY read_at DESC, head_seq DESC, rowid DESC) AS by_time,
                    ROW_NUMBER() OVER (PARTITION BY actor_id, block_id, doc_id, via ORDER BY rowid DESC) AS by_insert
               FROM reads)
            WHERE by_seq = 1 OR by_time = 1 OR by_insert = 1)`,
      );
      this.q(`INSERT OR IGNORE INTO meta (key, value) VALUES (?, ?)`).run(READS_COMPACTED_KEY, new Date().toISOString());
    }
    this.compacted = true;
  }
}
