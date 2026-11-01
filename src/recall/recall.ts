/**
 * recall — FTS5 (bm25) search over blocks, each result carrying a signed
 * receipt bound to the current chain head. Receipts are stored so later
 * audits can see what was attested and when.
 *
 * 0.6.0 honest labels, all deterministic:
 *   - every hit carries `authority` (can_act | inspect_only | never_act), its
 *     reason and basis (honesty.ts, docs/HONESTY.md), and the result the floor;
 *   - `absence` says what was searched, what was not, and whether the index
 *     was fresh (absence.ts);
 *   - hits the same actor already read this session rank lower, never hidden
 *     (attention.ts);
 *   - served text goes through the read-time secret scrub, then the
 *     `max_chars` content budget (with a pointer to the whole document).
 */

import { randomUUID } from 'node:crypto';

import type { Chain } from '../chain/index.js';
import type { Signer } from '../crypto/keys.js';
import type { Db } from '../db/open.js';
import { splitHeadingPath, type BlockRow, type DocumentSource } from '../docs/documents.js';
import { checkBlockRow, type RowProblem } from '../docs/integrity.js';
import { scrubForRead } from '../secrets/guard.js';
import { certifyRecallAbsence, indexFreshness, type Absence, type RecallScope } from './absence.js';
import { attentionRerank } from './attention.js';
import { authorityFloor, resolveAuthority, type Authority, type AuthorityBasis, type AuthorityReason } from './honesty.js';
import { queryHash, signReceipt, type Receipt } from './receipt.js';
import { SourceChecker } from './source-check.js';

/** Default content budget per recall response (characters of hit content). */
export const DEFAULT_MAX_CHARS = 16_000;

export interface RecallInput {
  query: string;
  top_k?: number;
  include_tombstoned?: boolean;
  include_receipts?: boolean;
  /** 0.6.0: the actor reading (recorded on receipts; enables attention rerank). */
  actor_id?: string | undefined;
  /** 0.6.0: start of the actor's session (ISO time; see Orient.sessionStart). null/absent: no rerank. */
  session_since?: string | null | undefined;
  /** 0.6.0: total characters of hit content in the response (default 16000). */
  max_chars?: number | undefined;
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
  /** 0.6.0: may this text be acted on without further checks? See docs/HONESTY.md. */
  authority: Authority;
  authority_reason: AuthorityReason;
  authority_basis: AuthorityBasis;
  /** 0.6.0: this actor already read this block in this session (ranked lower, never hidden). */
  already_read: boolean;
  /** 0.6.0: read-time secret rules that masked part of the content (absent when none fired). */
  read_scrubbed?: string[];
  /** 0.6.0: content was cut to fit max_chars (absent when whole). The receipt still covers the whole block. */
  truncated?: { shown_chars: number; total_chars: number; read: string };
}

/** A matching block whose stored text no longer hashes to the chain (0.5.0). Never served, never receipted. */
export interface WithheldHit {
  block_id: string;
  doc_slug: string;
  problem: RowProblem;
  /** 0.6.0: always never_act / integrity_failed. */
  authority: 'never_act';
  authority_reason: 'integrity_failed';
}

export interface RecallResult {
  query: string;
  query_hash: string;
  head: { seq: number; hash: string };
  match_mode: 'all_terms' | 'any_term' | 'none';
  hits: RecallHit[];
  /** 0.5.0: hits withheld because their stored text fails the integrity check. Empty when all is well. */
  withheld: WithheldHit[];
  /** 0.6.0: meet of the hits' authority; null when there are no hits (an empty set is never a licence to act). */
  authority_floor: Authority | null;
  /** 0.6.0: what was searched, what was not, whether the index was fresh. */
  absence: Absence;
  /** 0.6.0: attention rerank applied (actor + session start), or null. */
  attention: { actor_id: string; session_since: string; already_read: number } | null;
  /** 0.6.0: content cut to fit max_chars, or null. */
  truncated: { hits: number; max_chars: number; hint: string } | null;
}

interface HitRow extends BlockRow {
  slug: string;
  title: string;
  score: number;
  source_kind: string | null;
  source_json: string | null;
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
    const maxChars = input.max_chars ?? DEFAULT_MAX_CHARS;
    const head = this.chain.head();
    const qh = queryHash(input.query);

    let rows: HitRow[] = [];
    let match_mode: RecallResult['match_mode'] = 'none';
    let searchedAny = false;
    for (const mode of ['AND', 'OR'] as const) {
      const expr = toMatchExpression(input.query, mode);
      if (!expr) break;
      searchedAny = true;
      rows = this.search(expr, top_k, includeTomb);
      if (rows.length > 0) {
        match_mode = mode === 'AND' ? 'all_terms' : 'any_term';
        break;
      }
    }

    // Attention: what this actor already read since its session started,
    // looked up before this call's own receipts are written.
    const actor = input.actor_id ?? null;
    const since = actor !== null ? (input.session_since ?? null) : null;
    const alreadyRead = new Set<string>();
    if (actor !== null && since !== null && rows.length > 0) {
      const read = this.db.prepare(`SELECT 1 FROM receipts WHERE actor_id = ? AND block_id = ? AND issued_at >= ? LIMIT 1`);
      for (const r of rows) if (read.get(actor, r.block_id, since) !== undefined) alreadyRead.add(r.block_id);
    }
    const ranked =
      actor !== null && since !== null
        ? attentionRerank(rows.map((r) => ({ id: r.block_id, relevance: -r.score, row: r })), alreadyRead).map((x) => ({ row: x.row, already_read: x.already_read }))
        : rows.map((row) => ({ row, already_read: false }));

    const issued_at = new Date().toISOString();
    const insert = this.db.prepare(
      `INSERT INTO receipts (receipt_id, block_id, chain_seq, query_hash, issued_at, receipt_json, actor_id)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    );
    const sources = new SourceChecker();
    const hits: RecallHit[] = [];
    const withheld: WithheldHit[] = [];
    const tx = this.db.transaction(() => {
      for (const { row: r, already_read } of ranked) {
        // 0.5.0: re-hash the text we are about to serve and check it against
        // the chained block.created event. A tampered or corrupted row is
        // withheld: no content, no receipt.
        const problem = checkBlockRow(this.chain, r);
        if (problem) {
          withheld.push({ block_id: r.block_id, doc_slug: r.slug, problem, authority: 'never_act', authority_reason: 'integrity_failed' });
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
          insert.run(receipt.receipt_id, r.block_id, head.seq, qh, issued_at, JSON.stringify(receipt), actor);
        }
        const status: RecallHit['status'] = r.tombstoned_at ? 'tombstoned' : r.valid_to ? 'superseded' : 'live';
        const scrub = scrubForRead(r.content);
        const source = r.source_json !== null ? (JSON.parse(r.source_json) as DocumentSource) : null;
        const honesty = resolveAuthority({
          status,
          source_kind: r.source_kind,
          source_check: source !== null && status === 'live' ? sources.check(source, r) : 'unchecked',
          read_scrubbed: scrub.detectors.length > 0,
        });
        hits.push({
          block_id: r.block_id,
          doc_slug: r.slug,
          doc_title: r.title,
          revision: r.revision,
          ordinal: r.ordinal,
          kind: r.kind,
          heading_path: splitHeadingPath(r.heading_path),
          content: scrub.text,
          content_hash: r.content_hash,
          score: r.score,
          status,
          superseded_by: r.superseded_by,
          tombstone_reason: r.tombstone_reason,
          receipt,
          authority: honesty.authority,
          authority_reason: honesty.reason,
          authority_basis: honesty.basis,
          already_read,
          ...(scrub.detectors.length > 0 ? { read_scrubbed: scrub.detectors } : {}),
        });
      }
    });
    tx();

    const truncated = applyContentBudget(hits, maxChars);
    const searched: RecallScope[] = searchedAny ? (includeTomb ? ['live_blocks', 'tombstoned_blocks'] : ['live_blocks']) : [];
    const all: RecallScope[] = ['live_blocks', 'tombstoned_blocks', 'superseded_blocks'];
    const fresh = indexFreshness(this.db);
    const absence = certifyRecallAbsence({
      hits: hits.length,
      withheld: withheld.length,
      searched,
      not_searched: all.filter((x) => !searched.includes(x)),
      index_fresh: fresh.fresh,
      index_detail: fresh.detail,
    });

    return {
      query: input.query,
      query_hash: qh,
      head,
      match_mode,
      hits,
      withheld,
      authority_floor: authorityFloor(hits.map((h) => h.authority)),
      absence,
      attention: actor !== null && since !== null ? { actor_id: actor, session_since: since, already_read: hits.filter((h) => h.already_read).length } : null,
      truncated,
    };
  }

  private search(expr: string, top_k: number, includeTomb: boolean): HitRow[] {
    // Live blocks only (valid_to IS NULL) unless tombstoned are requested; superseded
    // blocks are never returned — the successor is the live head and will match instead.
    const liveFilter = includeTomb
      ? `(b.valid_to IS NULL OR b.tombstoned_at IS NOT NULL)`
      : `b.valid_to IS NULL AND b.tombstoned_at IS NULL`;
    return this.db
      .prepare(
        `SELECT b.*, d.slug, d.title, bm25(blocks_fts, 1.0, 0.5) AS score, s.kind AS source_kind, s.source_json AS source_json
           FROM blocks_fts f
           JOIN blocks b ON b.rowid = f.rowid
           JOIN documents d ON d.doc_id = b.doc_id
           LEFT JOIN doc_sources s ON s.doc_id = b.doc_id
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

/** Cut at `n` UTF-16 units without splitting a surrogate pair. */
function cut(text: string, n: number): string {
  if (n >= text.length) return text;
  let end = Math.max(0, n);
  const c = text.charCodeAt(end - 1);
  if (end > 0 && c >= 0xd800 && c <= 0xdbff) end--;
  return text.slice(0, end);
}

/**
 * Fit hit content into `maxChars` total (water-filling: short hits stay
 * whole, long ones share what is left). Cut hits get `truncated` with a
 * pointer to the whole document; returns the result-level note or null.
 */
export function applyContentBudget(hits: RecallHit[], maxChars: number): RecallResult['truncated'] {
  const total = hits.reduce((n, h) => n + h.content.length, 0);
  if (total <= maxChars) return null;
  const order = hits.map((h, i) => ({ i, len: h.content.length })).sort((a, b) => a.len - b.len || a.i - b.i);
  let remaining = maxChars;
  let left = order.length;
  const cutHits: RecallHit[] = [];
  for (const { i, len } of order) {
    const share = Math.floor(remaining / left);
    left--;
    const h = hits[i]!;
    if (len <= share) {
      remaining -= len;
      continue;
    }
    const shown = cut(h.content, share);
    h.truncated = { shown_chars: shown.length, total_chars: len, read: `kronicle://docs/${encodeURIComponent(h.doc_slug)}` };
    h.content = shown;
    remaining -= shown.length;
    cutHits.push(h);
  }
  const first = cutHits[0]!;
  return {
    hits: cutHits.length,
    max_chars: maxChars,
    hint: `content cut to fit max_chars=${maxChars}: raise max_chars, lower top_k or narrow the query, or read the whole document (e.g. ${first.truncated!.read})`,
  };
}
