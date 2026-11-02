/**
 * Derived-note lineage and version-bound reconciliation (unreleased).
 *
 * Two questions, both answered at read time from the chain projection and
 * the local read log, deterministically (no LLM, no network):
 *
 *   1. Is this note stale because something it was derived from changed?
 *      A note (document) records `derived_from` (explicit) and
 *      `derived_from_inferred` (blocks its author read in the session before
 *      writing it) as `{block_id, content_hash}` pairs on the chain. An edge
 *      is FRESH when its source block's supersession lineage ends in a live
 *      block reached only through format-only edits (docs/FORMAT.md §3.8), or
 *      when the note also has an edge to a block in that current version
 *      (it was re-derived). Anything else (superseded, moved, tombstoned,
 *      missing) is STALE, and so is a note derived from a stale note.
 *
 *   2. Which changes has an actor not reconciled? An actor's reads (recall
 *      hits, document reads, its own writes) record the exact block version.
 *      A change to a block the actor read stays PENDING until the actor reads
 *      a block in the CURRENT version (the live lineage head, or a
 *      format-only-equivalent of it), or, for a removal, reads the document
 *      (or the tombstoned block) after the removal. Reading an older version
 *      never clears a newer change.
 *
 * "Version" = a block id (content hashes are immutable per block), up to
 * format-only edits, which are the one classifier result allowed to say two
 * versions are the same (AST-equivalent, identical text leaves).
 */

import type BetterSqlite3 from 'better-sqlite3';

import type { Chain } from '../chain/index.js';
import type { Db } from '../db/open.js';
type Statement = BetterSqlite3.Statement<unknown[]>;
import { isInstructionSlug, REORDERED_RE, splitHeadingPath, type BlockRow, type DocumentStore } from '../docs/documents.js';
import { classifyEdit } from '../orient/cosmetic.js';
import { changeSnippets, snippet, wordDiff } from '../orient/textdiff.js';

/** One lineage edge as written on the chain. */
export interface LineageRef {
  block_id: string;
  content_hash: string;
}

export type SourceChange = 'superseded' | 'moved' | 'tombstoned' | 'missing';

/** Why a derived note is stale: one source whose version it was derived from is no longer current. */
export interface StaleSource {
  /** The source block version the note was derived from. */
  source_block_id: string;
  source_content_hash: string;
  source_doc_slug: string | null;
  change: SourceChange;
  /** Chain seq of the first real (not format-only) change after that version; null when unknown. */
  seq: number | null;
  /** The current version (live lineage head), or null when removed. */
  current_block_id: string | null;
  current_content_hash: string | null;
  /** Bounded snippets (≤ 160 chars) of the version derived from and the current one. */
  old_text: string | null;
  new_text: string | null;
  /** Every edge to this source was inferred from reads (none declared). */
  inferred: boolean;
  /** Set when the source is itself a note that went stale (derived from a derived note): its slug. */
  via?: string;
}

export interface VersionRef {
  block_id: string;
  content_hash: string;
}

/** An unreconciled change for one actor (docs/PUSH.md "pending"). */
export interface PendingItem {
  /** supersession | tombstone | instruction (a block of an instructions/ or memory/ document) | derived */
  kind: 'supersession' | 'tombstone' | 'instruction' | 'derived';
  change: SourceChange;
  severity: 'safety' | 'behavioral';
  /** Seq of the first real change after the version read (null when unknown). */
  seq: number | null;
  /** Document of the changed block (for `derived`: the source's document). */
  doc_slug: string | null;
  heading_path: string[];
  /** The version the actor read (for `derived`: the version the note was derived from). */
  read: VersionRef & { head_seq: number | null };
  /** The current version, or null when the block was removed. */
  current: VersionRef | null;
  old_text: string | null;
  new_text: string | null;
  /** Word diff old → current (≤ 400 chars), null for a removal. */
  diff: string | null;
  /** Notes the actor read or wrote that were derived from this block (`derived` items name one). */
  derived_notes?: string[];
  /** How to resolve it: what to re-read. */
  resolve: string;
}

export interface PendingResult {
  actor_id: string;
  /** Unresolved items in scope (all of them; `items` may be cut to `limit`). */
  count: number;
  items: PendingItem[];
  /** Items about documents of other projects (not listed). */
  hidden: number;
}

interface Walk {
  /** The lineage from the start block to its head, in order. */
  blocks: BlockRow[];
  head: BlockRow;
  /** Index into `blocks` where the current version starts (head + its format-only predecessors); -1 when the head is not live. */
  currentFrom: number;
}

const MAX_DERIVED_DEPTH = 4;

/** Inference without a session (the actor never oriented): reads in this window… */
export const INFER_FALLBACK_WINDOW_MS = 24 * 60 * 60 * 1000;
/** …and at most this many of the most recently read blocks. */
export const INFER_FALLBACK_MAX = 200;

/** What `infer` returns: the edges, and whether the no-session bound left reads out. */
export interface InferredLineage {
  refs: LineageRef[];
  truncated: boolean;
}

export class Lineage {
  private readonly hopMemo = new Map<string, boolean>();
  private readonly stmts = new Map<string, Statement>();

  constructor(
    private readonly db: Db,
    private readonly chain: Chain,
    private readonly docs: DocumentStore,
  ) {}

  /** Prepared statements are reused: preparing dominated pending() on a 300-document store. */
  private q(sql: string): Statement {
    let st = this.stmts.get(sql);
    if (!st) {
      st = this.db.prepare(sql);
      this.stmts.set(sql, st);
    }
    return st;
  }

  // ───────────────────────────── versions ─────────────────────────────

  /**
   * True when `a → b` is a format-only edit in the same section (the same
   * version for every purpose here). Identical text in the same section
   * retired by a reorder (0.8.1, planRevision 1a) is never the same version:
   * order is meaning.
   */
  hopFormatOnly(a: BlockRow, b: BlockRow): boolean {
    const key = `${a.block_id}>${b.block_id}`;
    let v = this.hopMemo.get(key);
    if (v === undefined) {
      v = a.heading_path === b.heading_path && a.kind === b.kind && classifyEdit(a.content, b.content, a.kind).format_only && !(a.content === b.content && this.reordered(a.block_id));
      this.hopMemo.set(key, v);
    }
    return v;
  }

  walk(block_id: string): Walk | null {
    const blocks = this.q(
      `WITH RECURSIVE lineage(block_id, depth) AS (
         SELECT ?, 0
         UNION ALL
         SELECT b.superseded_by, l.depth + 1 FROM blocks b JOIN lineage l ON b.block_id = l.block_id
          WHERE b.superseded_by IS NOT NULL AND l.depth < 10000
       )
       SELECT b.* FROM lineage l JOIN blocks b ON b.block_id = l.block_id ORDER BY l.depth ASC`,
    ).all(block_id) as BlockRow[];
    if (blocks.length === 0) return null;
    const head = blocks[blocks.length - 1]!;
    const live = head.valid_to === null && head.tombstoned_at === null;
    let currentFrom = -1;
    if (live) {
      currentFrom = blocks.length - 1;
      while (currentFrom > 0 && this.hopFormatOnly(blocks[currentFrom - 1]!, blocks[currentFrom]!)) currentFrom--;
    }
    return { blocks, head, currentFrom };
  }

  /** True when the block was retired by a reorder within its section (planRevision 1a, reason "reordered in revision N"). */
  private reordered(block_id: string): boolean {
    const r = this.q(
      `SELECT CASE WHEN json_valid(payload_canonical) THEN json_extract(payload_canonical, '$.reason') END AS reason FROM events
        WHERE event_type = 'block.superseded' AND CASE WHEN json_valid(payload_canonical) THEN json_extract(payload_canonical, '$.block_id') END = ?
        ORDER BY seq LIMIT 1`,
    ).get(block_id) as { reason: unknown } | undefined;
    return typeof r?.reason === 'string' && REORDERED_RE.test(r.reason);
  }

  /** Seq of the event that retired a block (block.superseded / block.tombstoned), or null. */
  retireSeq(block_id: string): number | null {
    const r = this.q(
        `SELECT seq FROM events WHERE event_type IN ('block.superseded', 'block.tombstoned')
           AND CASE WHEN json_valid(payload_canonical) THEN json_extract(payload_canonical, '$.block_id') END = ?
         ORDER BY seq LIMIT 1`,
      )
      .get(block_id) as { seq: number } | undefined;
    return r?.seq ?? null;
  }

  /** The first real change after position `from` of a walk: what changed and at which seq. */
  private firstChange(w: Walk, from: number): { change: SourceChange; seq: number | null } {
    for (let j = from; j < w.blocks.length - 1; j++) {
      const a = w.blocks[j]!;
      const b = w.blocks[j + 1]!;
      if (this.hopFormatOnly(a, b)) continue;
      return { change: a.heading_path !== b.heading_path ? 'moved' : 'superseded', seq: this.retireSeq(a.block_id) };
    }
    return { change: 'tombstoned', seq: this.retireSeq(w.head.block_id) };
  }

  private slugOf(doc_id: string): string | null {
    return (this.q(`SELECT slug FROM documents WHERE doc_id = ?`).get(doc_id) as { slug: string } | undefined)?.slug ?? null;
  }

  // ───────────────────────────── derived notes ─────────────────────────────

  /** Lineage edges recorded for a document (explicit and inferred). */
  edges(doc_id: string): { source_block_id: string; source_content_hash: string; inferred: number; chain_seq: number }[] {
    return this.q(`SELECT source_block_id, source_content_hash, inferred, chain_seq FROM doc_lineage WHERE doc_id = ? ORDER BY chain_seq, source_block_id, inferred`)
      .all(doc_id) as { source_block_id: string; source_content_hash: string; inferred: number; chain_seq: number }[];
  }

  /** Any lineage recorded at all (cheap; lets orient skip the derived pass on stores without notes). */
  anyLineage(): boolean {
    return this.q(`SELECT 1 FROM doc_lineage LIMIT 1`).get() !== undefined;
  }

  hasLineage(doc_id: string): boolean {
    return this.q(`SELECT 1 FROM doc_lineage WHERE doc_id = ? LIMIT 1`).get(doc_id) !== undefined;
  }

  /**
   * Stale sources of a derived note; [] when it has no lineage or every
   * source is current. `memo` is shared across one read (recall / orient).
   */
  staleness(doc_id: string, memo: Map<string, StaleSource[]> = new Map(), depth = 0, seen: Set<string> = new Set()): StaleSource[] {
    return this.stalenessOf(doc_id, memo, depth, seen).out;
  }

  /**
   * `complete` is false when the result was cut short: by the depth bound
   * (a stale note more than MAX_DERIVED_DEPTH hops below was not looked at)
   * or by a cycle (a note already on the path was skipped). 0.8.1: such a
   * result is the right answer for the note the read started from, never for
   * this note on its own, so it is not memoized; before, a note evaluated
   * after its descendant or cycle partner in the same read could show fresh.
   */
  private stalenessOf(doc_id: string, memo: Map<string, StaleSource[]>, depth: number, seen: Set<string>): { out: StaleSource[]; complete: boolean } {
    const cached = memo.get(doc_id);
    if (cached) return { out: cached, complete: true };
    if (seen.has(doc_id)) return { out: [], complete: false };
    const edges = this.edges(doc_id);
    if (edges.length === 0) {
      memo.set(doc_id, []);
      return { out: [], complete: true };
    }
    let complete = true;
    seen.add(doc_id);
    const ids = new Set(edges.map((e) => e.source_block_id));
    const bySource = new Map<string, { hash: string; inferred: boolean }>();
    for (const e of edges) {
      const prev = bySource.get(e.source_block_id);
      bySource.set(e.source_block_id, { hash: e.source_content_hash, inferred: (prev?.inferred ?? true) && e.inferred === 1 });
    }
    const out: StaleSource[] = [];
    // One entry per source lineage: the latest version the note was derived from.
    const byHead = new Map<string, { at: number; len: number }>();
    const transitiveDocs = new Set<string>();
    for (const [sid, { hash, inferred }] of bySource) {
      const w = this.walk(sid);
      if (!w) {
        out.push({ source_block_id: sid, source_content_hash: hash, source_doc_slug: null, change: 'missing', seq: null, current_block_id: null, current_content_hash: null, old_text: null, new_text: null, inferred });
        continue;
      }
      const src = w.blocks[0]!;
      // Fresh: only format-only edits since, or the note has an edge to the current version too.
      if (w.currentFrom === 0 || (w.currentFrom > 0 && w.blocks.slice(w.currentFrom).some((b) => ids.has(b.block_id)))) {
        transitiveDocs.add(w.head.doc_id);
        continue;
      }
      const ch = this.firstChange(w, 0);
      const live = w.currentFrom >= 0;
      const prev = byHead.get(w.head.block_id);
      if (prev && prev.len <= w.blocks.length) {
        out[prev.at]!.inferred &&= inferred;
        continue;
      }
      const entry: StaleSource = {
        source_block_id: sid,
        source_content_hash: hash,
        source_doc_slug: this.slugOf(src.doc_id),
        change: live ? ch.change : 'tombstoned',
        seq: ch.seq,
        current_block_id: live ? w.head.block_id : null,
        current_content_hash: live ? w.head.content_hash : null,
        old_text: live ? changeSnippets(src.content, w.head.content)[0] : snippet(src.content),
        new_text: live ? changeSnippets(src.content, w.head.content)[1] : null,
        inferred: prev ? inferred && out[prev.at]!.inferred : inferred,
      };
      if (prev) out[prev.at] = entry;
      else {
        byHead.set(w.head.block_id, { at: out.length, len: w.blocks.length });
        out.push(entry);
      }
      if (prev) byHead.set(w.head.block_id, { at: prev.at, len: w.blocks.length });
    }
    // A note derived from a note that went stale is stale too (bounded depth).
    if (depth < MAX_DERIVED_DEPTH) {
      for (const d of transitiveDocs) {
        if (d === doc_id) continue;
        const r = this.stalenessOf(d, memo, depth + 1, seen);
        if (!r.complete) complete = false;
        const inner = r.out;
        if (inner.length > 0) {
          const slug = this.slugOf(d) ?? d;
          for (const s of inner) if (!out.some((o) => o.source_block_id === s.source_block_id)) out.push({ ...s, via: s.via ?? slug });
        }
      }
    } else if ([...transitiveDocs].some((d) => d !== doc_id && this.hasLineage(d))) {
      complete = false; // depth bound: notes below were not looked at
    }
    seen.delete(doc_id);
    out.sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0) || a.source_block_id.localeCompare(b.source_block_id));
    if (complete || depth === 0) memo.set(doc_id, out);
    return { out, complete };
  }

  /**
   * Derived notes whose lineage includes `block_id` or a format-only
   * predecessor of it (the same version), for orient's derived retractions.
   */
  derivedFrom(block_id: string): string[] {
    const ids = [block_id];
    let cur = block_id;
    for (let i = 0; i < 10_000; i++) {
      const prev = this.q(`SELECT * FROM blocks WHERE superseded_by = ?`).get(cur) as BlockRow | undefined;
      const curRow = this.docs.getBlock(cur);
      if (!prev || !curRow || !this.hopFormatOnly(prev, curRow)) break;
      ids.push(prev.block_id);
      cur = prev.block_id;
    }
    const rows = this.q(`SELECT DISTINCT doc_id FROM doc_lineage WHERE source_block_id IN (${ids.map(() => '?').join(', ')}) ORDER BY doc_id`)
      .all(...ids) as { doc_id: string }[];
    return rows.map((r) => r.doc_id);
  }

  /**
   * Lineage to infer for a note `actor_id` writes now: the blocks it read
   * (receipts and the read log; its own writes excluded), outside
   * `exclude_doc_id`, deduplicated by block and by lineage (when it read two
   * versions of one block, only the latest is kept: the same staleness
   * verdict with fewer edges). Sorted by block id.
   *
   * Bounded: `since` (ISO time) = its current session start (the briefing
   * behind its cursor, else its latest orient): every block read since then.
   * No session (the actor never oriented): never "everything ever read", but
   * the most recently read blocks within the last 24 h, at most 200
   * (`INFER_FALLBACK_WINDOW_MS`, `INFER_FALLBACK_MAX`); `truncated` is true
   * when that bound left out any block the actor ever read.
   */
  infer(actor_id: string, since: string | null, exclude_doc_id: string | null, opts: { now?: number } = {}): InferredLineage {
    const READS = `SELECT block_id, issued_at AS at FROM receipts WHERE actor_id = ?
           UNION ALL SELECT block_id, read_at AS at FROM reads WHERE actor_id = ? AND block_id IS NOT NULL AND via != 'write'`;
    let rows: { block_id: string; content_hash: string; retired: number }[];
    let truncated = false;
    if (since !== null) {
      rows = this.q(
        `SELECT b.block_id, b.content_hash, (b.valid_to IS NOT NULL OR b.tombstoned_at IS NOT NULL) AS retired
           FROM (SELECT DISTINCT block_id FROM (${READS}) WHERE at >= ?) r JOIN blocks b ON b.block_id = r.block_id
          WHERE b.doc_id IS NOT ?`,
      ).all(actor_id, actor_id, since, exclude_doc_id) as typeof rows;
    } else {
      const cutoff = new Date((opts.now ?? Date.now()) - INFER_FALLBACK_WINDOW_MS).toISOString();
      const recent = this.q(
        `SELECT b.block_id, b.content_hash, (b.valid_to IS NOT NULL OR b.tombstoned_at IS NOT NULL) AS retired, r.at
           FROM (SELECT block_id, MAX(at) AS at FROM (${READS}) GROUP BY block_id HAVING MAX(at) >= ?) r
           JOIN blocks b ON b.block_id = r.block_id
          WHERE b.doc_id IS NOT ?
          ORDER BY r.at DESC, b.block_id LIMIT ?`,
      ).all(actor_id, actor_id, cutoff, exclude_doc_id, INFER_FALLBACK_MAX + 1) as (typeof rows[number] & { at: string })[];
      if (recent.length > INFER_FALLBACK_MAX) truncated = true;
      rows = recent.slice(0, INFER_FALLBACK_MAX);
      if (!truncated) {
        truncated =
          this.q(
            `SELECT 1 FROM (SELECT block_id, MAX(at) AS at FROM (${READS}) GROUP BY block_id HAVING MAX(at) < ?) r
               JOIN blocks b ON b.block_id = r.block_id WHERE b.doc_id IS NOT ? LIMIT 1`,
          ).get(actor_id, actor_id, cutoff, exclude_doc_id) !== undefined;
      }
    }
    // Dedupe by lineage: drop a retired version when a later version of the same block was read too.
    const ids = new Set(rows.map((r) => r.block_id));
    const refs: LineageRef[] = [];
    for (const r of rows) {
      if (r.retired) {
        const w = this.walk(r.block_id);
        if (w && w.blocks.slice(1).some((b) => ids.has(b.block_id))) continue;
      }
      refs.push({ block_id: r.block_id, content_hash: r.content_hash });
    }
    refs.sort((a, b) => a.block_id.localeCompare(b.block_id));
    return { refs, truncated };
  }

  // ───────────────────────────── reconciliation (pulse) ─────────────────────────────

  /** Every block id of the supersession lineage through `block_id` (predecessors, itself, successors). */
  lineageIds(block_id: string): string[] {
    const back: string[] = [];
    let cur = block_id;
    for (let i = 0; i < 10_000; i++) {
      const prev = this.q(`SELECT block_id FROM blocks WHERE superseded_by = ?`).get(cur) as { block_id: string } | undefined;
      if (!prev) break;
      back.push(prev.block_id);
      cur = prev.block_id;
    }
    const fwd = this.walk(block_id)?.blocks.map((b) => b.block_id) ?? [block_id];
    return [...back.reverse(), ...fwd];
  }

  /**
   * Actors that read any version of these blocks (recall hits, document
   * reads; writes excluded: writing a version is not relying on it), plus,
   * for `note_doc_id`, the actors that read or wrote that note. Sorted.
   */
  readersOf(block_ids: readonly string[], note_doc_id: string | null = null): string[] {
    const out = new Set<string>();
    for (let i = 0; i < block_ids.length; i += 400) {
      const chunk = block_ids.slice(i, i + 400);
      const ph = chunk.map(() => '?').join(', ');
      for (const r of this.q(
        `SELECT DISTINCT actor_id FROM receipts WHERE actor_id IS NOT NULL AND block_id IN (${ph})
         UNION SELECT DISTINCT actor_id FROM reads WHERE via != 'write' AND block_id IN (${ph})`,
      ).all(...chunk, ...chunk) as { actor_id: string }[]) {
        out.add(r.actor_id);
      }
    }
    if (note_doc_id !== null) {
      for (const r of this.q(
        `SELECT DISTINCT actor_id FROM reads WHERE doc_id = ?
         UNION SELECT DISTINCT r.actor_id FROM receipts r JOIN blocks b ON b.block_id = r.block_id WHERE b.doc_id = ? AND r.actor_id IS NOT NULL`,
      ).all(note_doc_id, note_doc_id) as { actor_id: string }[]) {
        out.add(r.actor_id);
      }
    }
    return [...out].sort();
  }

  /**
   * True when `actor_id` has read the CURRENT version of the lineage through
   * `block_id` (the rule `pending` resolves by): a read of the live head or a
   * format-only twin of it; for a removed block, a read of the document (or of
   * the tombstoned block) after the removal. Its own writes count as reads.
   */
  readCurrent(actor_id: string, block_id: string): boolean {
    const w = this.walk(block_id);
    if (!w) return false;
    // 0.8.1: receipts up to the mark are folded into the read log (lineage/read-log.ts).
    const mark = this.docs.readLog.receiptsMark();
    const readAt = this.q(
      `SELECT MAX(hs) AS hs FROM (
         SELECT chain_seq AS hs FROM receipts WHERE actor_id = ? AND rowid > ? AND block_id = ?
         UNION ALL SELECT head_seq AS hs FROM reads WHERE actor_id = ? AND block_id = ?
       )`,
    );
    const seqOf = (id: string): number | null => (readAt.get(actor_id, mark, id, actor_id, id) as { hs: number | null }).hs;
    if (w.currentFrom >= 0) return w.blocks.slice(w.currentFrom).some((b) => seqOf(b.block_id) !== null);
    const tomb = this.retireSeq(w.head.block_id);
    if (tomb === null) return false;
    const hr = seqOf(w.head.block_id);
    const dr = (this.q(`SELECT MAX(head_seq) AS hs FROM reads WHERE actor_id = ? AND doc_id = ? AND block_id IS NULL`).get(actor_id, w.head.doc_id) as { hs: number | null }).hs;
    return (hr !== null && hr >= tomb) || (dr !== null && dr >= tomb);
  }

  // ───────────────────────────── read log ─────────────────────────────

  /** Record that `actor_id` read these blocks (recall hits). */
  recordBlockReads(actor_id: string, blocks: readonly { block_id: string; doc_id: string; content_hash: string }[], via: 'recall' | 'write'): void {
    if (blocks.length === 0) return;
    const head_seq = this.chain.head().seq;
    const read_at = new Date().toISOString();
    const rev = this.q(`SELECT current_revision FROM documents WHERE doc_id = ?`);
    this.docs.readLog.record(
      blocks.map((b) => ({
        actor_id,
        doc_id: b.doc_id,
        block_id: b.block_id,
        content_hash: b.content_hash,
        doc_revision: (rev.get(b.doc_id) as { current_revision: number } | undefined)?.current_revision ?? 0,
        head_seq,
        read_at,
        via,
      })),
    );
  }

  /** Record a whole-document read (and one row per live block) of the current revision. */
  recordDocumentRead(actor_id: string, doc_id: string, via: 'document' | 'write'): void {
    const doc = this.docs.getDocumentById(doc_id);
    if (!doc) return;
    const rev = this.docs.getRevision(doc_id, doc.current_revision);
    const base = { actor_id, doc_id, doc_revision: doc.current_revision, head_seq: this.chain.head().seq, read_at: new Date().toISOString(), via };
    this.docs.readLog.record([
      { ...base, block_id: null, content_hash: rev?.content_hash ?? '' },
      ...this.docs.liveBlocks(doc_id).map((b) => ({ ...base, block_id: b.block_id, content_hash: b.content_hash })),
    ]);
  }

  // ───────────────────────────── pending ─────────────────────────────

  /**
   * Changes `actor_id` read and has not reconciled against the CURRENT
   * version. `project_keys`: only documents of these projects (and unscoped
   * ones) are listed; others are counted in `hidden`.
   */
  pending(actor_id: string, opts: { project_keys?: readonly string[] | null; limit?: number } = {}): PendingResult {
    const limit = opts.limit ?? 20;
    const keys = opts.project_keys && opts.project_keys.length > 0 ? new Set(opts.project_keys) : null;
    const inScope = (doc_id: string) => {
      if (!keys) return true;
      const k = this.docs.projectKeyOf(doc_id);
      return k === null || keys.has(k);
    };

    // Every block version this actor read (receipts + read log), with the latest head seq it was read at.
    // 0.8.1: the log is bounded and receipts up to the mark are folded into it (lineage/read-log.ts).
    const mark = this.docs.readLog.receiptsMark();
    const reads = new Map<string, number>();
    for (const r of this.q(
        `SELECT block_id, MAX(head_seq) AS hs FROM (
           SELECT block_id, chain_seq AS head_seq FROM receipts WHERE actor_id = ? AND rowid > ?
           UNION ALL SELECT block_id, head_seq FROM reads WHERE actor_id = ? AND block_id IS NOT NULL
         ) GROUP BY block_id`,
      )
      .all(actor_id, mark, actor_id) as { block_id: string; hs: number }[]) {
      reads.set(r.block_id, r.hs);
    }
    const docReads = new Map<string, number>();
    for (const r of this.q(`SELECT doc_id, MAX(head_seq) AS hs FROM reads WHERE actor_id = ? AND block_id IS NULL GROUP BY doc_id`)
      .all(actor_id) as { doc_id: string; hs: number }[]) {
      docReads.set(r.doc_id, r.hs);
    }

    // Resolution of one lineage for this actor: read the current version (or, removed: the document / the tombstone after the removal).
    const resolved = (w: Walk): boolean => {
      if (w.currentFrom >= 0) return w.blocks.slice(w.currentFrom).some((b) => reads.has(b.block_id));
      const tomb = this.retireSeq(w.head.block_id);
      if (tomb === null) return false;
      const hr = reads.get(w.head.block_id);
      const dr = docReads.get(w.head.doc_id);
      return (hr !== undefined && hr >= tomb) || (dr !== undefined && dr >= tomb);
    };

    // Group retired read blocks by lineage head.
    const retired = this.q(
        `SELECT b.* FROM blocks b WHERE b.valid_to IS NOT NULL AND b.block_id IN (
           SELECT block_id FROM receipts WHERE actor_id = ? AND rowid > ? UNION SELECT block_id FROM reads WHERE actor_id = ? AND block_id IS NOT NULL
         ) ORDER BY b.chain_seq ASC`,
      )
      .all(actor_id, mark, actor_id) as BlockRow[];
    const groups = new Map<string, Walk>();
    const assigned = new Set<string>();
    for (const b of retired) {
      if (assigned.has(b.block_id)) continue;
      const w = this.walk(b.block_id);
      if (!w) continue;
      for (const x of w.blocks) assigned.add(x.block_id);
      const prev = groups.get(w.head.block_id);
      if (!prev || prev.blocks.length < w.blocks.length) groups.set(w.head.block_id, w);
    }

    const items: PendingItem[] = [];
    const byHead = new Map<string, PendingItem>();
    let hidden = 0;
    for (const [headId, w] of groups) {
      // The latest version this actor read in this lineage.
      let pos = -1;
      for (let i = w.blocks.length - 1; i >= 0; i--) if (reads.has(w.blocks[i]!.block_id)) { pos = i; break; }
      if (pos < 0) continue;
      if (w.currentFrom >= 0 && pos >= w.currentFrom) continue; // read the current version (or a format-only twin)
      if (resolved(w)) continue;
      if (!inScope(w.head.doc_id)) {
        hidden++;
        continue;
      }
      const item = this.item(w, pos, reads.get(w.blocks[pos]!.block_id) ?? null);
      items.push(item);
      byHead.set(headId, item);
    }

    // Derived notes this actor read or wrote whose sources changed and whose current version it has not read.
    const noteDocs = this.q(
        `SELECT DISTINCT d.doc_id FROM doc_lineage d WHERE d.doc_id IN (
           SELECT b.doc_id FROM receipts r JOIN blocks b ON b.block_id = r.block_id WHERE r.actor_id = ? AND r.rowid > ?
           UNION SELECT doc_id FROM reads WHERE actor_id = ?
         ) ORDER BY d.doc_id`,
      )
      .all(actor_id, mark, actor_id) as { doc_id: string }[];
    const memo = new Map<string, StaleSource[]>();
    for (const { doc_id } of noteDocs) {
      const note = this.docs.getDocumentById(doc_id);
      if (!note) continue;
      for (const s of this.staleness(doc_id, memo)) {
        const w = this.walk(s.source_block_id);
        if (w && resolved(w)) continue;
        const headId = w?.head.block_id ?? s.source_block_id;
        const direct = byHead.get(headId);
        if (direct) {
          direct.derived_notes = [...new Set([...(direct.derived_notes ?? []), note.slug])];
          continue;
        }
        if (!inScope(doc_id)) {
          hidden++;
          continue;
        }
        const item: PendingItem = w
          ? { ...this.item(w, 0, null), kind: 'derived', derived_notes: [note.slug] }
          : {
              kind: 'derived',
              change: 'missing',
              severity: 'safety',
              seq: null,
              doc_slug: null,
              heading_path: [],
              read: { block_id: s.source_block_id, content_hash: s.source_content_hash, head_seq: null },
              current: null,
              old_text: null,
              new_text: null,
              diff: null,
              derived_notes: [note.slug],
              resolve: `the source block ${s.source_block_id} is gone from the store; re-derive ${note.slug} from current sources`,
            };
        item.resolve = `${note.slug} was derived from a version that changed (${item.change}); re-read the source: ${item.resolve}`;
        items.push(item);
        byHead.set(headId, item);
      }
    }

    const rank = (x: PendingItem) => (x.severity === 'safety' ? 0 : 1);
    items.sort((a, b) => rank(a) - rank(b) || (a.seq ?? 0) - (b.seq ?? 0));
    return { actor_id, count: items.length, items: items.slice(0, Math.max(0, limit)), hidden };
  }

  private item(w: Walk, pos: number, head_seq: number | null): PendingItem {
    const read = w.blocks[pos]!;
    const live = w.currentFrom >= 0;
    const ch = this.firstChange(w, pos);
    const slug = this.slugOf(w.head.doc_id);
    const change: SourceChange = live ? ch.change : 'tombstoned';
    const kind: PendingItem['kind'] = isInstructionSlug(slug) ? 'instruction' : change === 'tombstoned' ? 'tombstone' : 'supersession';
    const uri = slug ? `kronicle://docs/${encodeURIComponent(slug)}` : 'the document';
    return {
      kind,
      change,
      severity: change === 'tombstoned' ? 'safety' : 'behavioral',
      seq: live ? ch.seq : (ch.seq ?? this.retireSeq(w.head.block_id)),
      doc_slug: slug,
      heading_path: splitHeadingPath(w.head.heading_path),
      read: { block_id: read.block_id, content_hash: read.content_hash, head_seq },
      current: live ? { block_id: w.head.block_id, content_hash: w.head.content_hash } : null,
      old_text: live ? changeSnippets(read.content, w.head.content)[0] : snippet(read.content),
      new_text: live ? changeSnippets(read.content, w.head.content)[1] : null,
      diff: live
        ? read.heading_path !== w.head.heading_path
          ? `section: ${wordDiff(read.heading_path.replaceAll(' > ', ' › '), w.head.heading_path.replaceAll(' > ', ' › '))}${read.content === w.head.content ? '' : `; ${wordDiff(read.content, w.head.content)}`}`
          : read.content === w.head.content
            ? `order: same text, new position within ${w.head.heading_path.replaceAll(' > ', ' › ') || '(top)'}`
            : wordDiff(read.content, w.head.content)
        : null,
      resolve: live ? `recall it again or read ${uri}` : `read ${uri} (or recall with include_tombstoned) to acknowledge the removal`,
    };
  }
}
