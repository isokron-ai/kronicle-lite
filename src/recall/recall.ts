/**
 * recall — FTS5 (bm25) search over blocks, each result carrying a signed
 * receipt bound to the current chain head. Receipts are stored so later
 * audits can see what was attested and when.
 */

import { randomUUID } from 'node:crypto';

import type { Chain } from '../chain/index.js';
import type { Signer } from '../crypto/keys.js';
import type { Db } from '../db/open.js';
import { splitHeadingPath, type BlockRow } from '../docs/documents.js';
import { checkBlockRow, type RowProblem } from '../docs/integrity.js';
import { queryHash, signReceipt, type Receipt } from './receipt.js';

export interface RecallInput {
  query: string;
  top_k?: number;
  include_tombstoned?: boolean;
  include_receipts?: boolean;
}

export interface RecallHit {
  block_id: string;
  doc_slug: string;
  doc_title: string;
  revision: number;
  ordinal: number;
  kind: string;
  heading_path: string[];
  content: string;
  content_hash: string;
  score: number;
  status: 'live' | 'superseded' | 'tombstoned';
  superseded_by: string | null;
  tombstone_reason: string | null;
  receipt: Receipt | null;
}

/** A matching block whose stored text no longer hashes to the chain (0.5.0). Never served, never receipted. */
export interface WithheldHit {
  block_id: string;
  doc_slug: string;
  problem: RowProblem;
}

export interface RecallResult {
  query: string;
  query_hash: string;
  head: { seq: number; hash: string };
  match_mode: 'all_terms' | 'any_term' | 'none';
  hits: RecallHit[];
  /** 0.5.0: hits withheld because their stored text fails the integrity check. Empty when all is well. */
  withheld: WithheldHit[];
}

interface HitRow extends BlockRow {
  slug: string;
  title: string;
  score: number;
}

/** Turn free text into an FTS5 MATCH expression that cannot inject syntax. */
export function toMatchExpression(query: string, mode: 'AND' | 'OR'): string | null {
  const tokens = query
    .toLowerCase()
    .split(/[^\p{L}\p{N}_]+/u)
    .filter((t) => t.length > 0)
    .slice(0, 32);
  if (tokens.length === 0) return null;
  const quoted = tokens.map((t) => `"${t.replace(/"/g, '""')}"`);
  return quoted.join(mode === 'AND' ? ' ' : ' OR ');
}

export class Recall {
  constructor(
    private readonly db: Db,
    private readonly chain: Chain,
    private readonly signer: Signer,
    private readonly workspace = 'local',
  ) {}

  recall(input: RecallInput): RecallResult {
    const top_k = input.top_k ?? 12;
    const includeTomb = input.include_tombstoned ?? false;
    const includeReceipts = input.include_receipts ?? true;
    const head = this.chain.head();
    const qh = queryHash(input.query);

    let rows: HitRow[] = [];
    let match_mode: RecallResult['match_mode'] = 'none';
    for (const mode of ['AND', 'OR'] as const) {
      const expr = toMatchExpression(input.query, mode);
      if (!expr) break;
      rows = this.search(expr, top_k, includeTomb);
      if (rows.length > 0) {
        match_mode = mode === 'AND' ? 'all_terms' : 'any_term';
        break;
      }
    }

    const issued_at = new Date().toISOString();
    const insert = this.db.prepare(
      `INSERT INTO receipts (receipt_id, block_id, chain_seq, query_hash, issued_at, receipt_json)
       VALUES (?, ?, ?, ?, ?, ?)`,
    );
    const hits: RecallHit[] = [];
    const withheld: WithheldHit[] = [];
    const tx = this.db.transaction(() => {
      for (const r of rows) {
        // 0.5.0: re-hash the text we are about to serve and check it against
        // the chained block.created event. A tampered or corrupted row is
        // withheld: no content, no receipt.
        const problem = checkBlockRow(this.chain, r);
        if (problem) {
          withheld.push({ block_id: r.block_id, doc_slug: r.slug, problem });
          continue;
        }
        let receipt: Receipt | null = null;
        if (includeReceipts) {
          receipt = signReceipt(
            {
              v: 2,
              receipt_id: randomUUID(),
              workspace: this.workspace,
              block_id: r.block_id,
              content_hash: r.content_hash,
              doc_slug: r.slug,
              revision: r.revision,
              chain_seq: head.seq,
              chain_head_hash: head.hash,
              query_hash: qh,
              issued_at,
              key_id: this.signer.key_id,
            },
            this.signer,
          );
          insert.run(receipt.receipt_id, r.block_id, head.seq, qh, issued_at, JSON.stringify(receipt));
        }
        hits.push({
          block_id: r.block_id,
          doc_slug: r.slug,
          doc_title: r.title,
          revision: r.revision,
          ordinal: r.ordinal,
          kind: r.kind,
          heading_path: splitHeadingPath(r.heading_path),
          content: r.content,
          content_hash: r.content_hash,
          score: r.score,
          status: r.tombstoned_at ? 'tombstoned' : r.valid_to ? 'superseded' : 'live',
          superseded_by: r.superseded_by,
          tombstone_reason: r.tombstone_reason,
          receipt,
        });
      }
    });
    tx();

    return { query: input.query, query_hash: qh, head, match_mode, hits, withheld };
  }

  private search(expr: string, top_k: number, includeTomb: boolean): HitRow[] {
    // Live blocks only (valid_to IS NULL) unless tombstoned are requested; superseded
    // blocks are never returned — the successor is the live head and will match instead.
    const liveFilter = includeTomb
      ? `(b.valid_to IS NULL OR b.tombstoned_at IS NOT NULL)`
      : `b.valid_to IS NULL AND b.tombstoned_at IS NULL`;
    return this.db
      .prepare(
        `SELECT b.*, d.slug, d.title, bm25(blocks_fts, 1.0, 0.5) AS score
           FROM blocks_fts f
           JOIN blocks b ON b.rowid = f.rowid
           JOIN documents d ON d.doc_id = b.doc_id
          WHERE blocks_fts MATCH ? AND ${liveFilter}
          ORDER BY score ASC, b.chain_seq DESC
          LIMIT ?`,
      )
      .all(expr, top_k) as HitRow[];
  }

  getReceipt(receipt_id: string): Receipt | null {
    const r = this.db.prepare(`SELECT receipt_json FROM receipts WHERE receipt_id = ?`).get(receipt_id) as
      | { receipt_json: string }
      | undefined;
    return r ? (JSON.parse(r.receipt_json) as Receipt) : null;
  }
}
