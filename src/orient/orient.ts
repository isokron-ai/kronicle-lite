/**
 * get_system_state — the orient call. Recovers the actor's position (cursor
 * → flight recorder → genesis), folds the delta since that position under
 * the token budget, classifies retractions, composes the drift banner and
 * stale-write advisory, issues a new cursor and records the briefing.
 *
 * Nothing here writes to the chain: orienting is observation.
 */

import { randomUUID } from 'node:crypto';

import type { Chain, ChainEvent, ChainHead } from '../chain/index.js';
import type { Db } from '../db/open.js';
import { GENESIS_HASH } from '../chain/genesis.js';
import { canonicalize } from '../crypto/canonical.js';
import { sha256Hex } from '../crypto/hash.js';
import { isInstructionSlug, splitHeadingPath, type DocumentStore, type SourceDrift } from '../docs/documents.js';
import { checkBlockRow } from '../docs/integrity.js';
import { CursorTokenError, parseAnyCursor, serializeCompactCursor, serializeCursor } from './cursor.js';
import { foldDelta, rollupDelta, type PolicyOptions, type TypeGroup, type TypedDelta } from './delta.js';
import {
  composeDriftBanner,
  composeStaleWriteAdvisory,
  DEFAULT_DRIFT_RULES,
  type DriftBanner,
  type DriftRules,
  type DriftSignals,
  type StaleWriteAdvisory,
} from './drift.js';
import { scrubDeep } from '../secrets/guard.js';
import { FlightRecorder, type FlightRecord } from './flight-recorder.js';
import { __mutants, type FormatRule } from './cosmetic.js';
import { computeRetractions, type Retraction } from './retraction.js';
import { snippet, wordDiff } from './textdiff.js';
import type { Lineage, PendingItem, StaleSource } from '../lineage/lineage.js';

export const FOCUSES = ['orientation', 'recent_changes', 'retractions', 'pulse'] as const;
export type Focus = (typeof FOCUSES)[number];

export const RECOVERY_METHODS = [
  'presented', // full cursor verified and still on the chain
  'presented_compact', // compact cursor verified
  'presented_stale', // cursor verified but its hash is no longer on the chain (chain reset/rewritten)
  'flight_recorder', // no usable cursor; position from the actor's last briefing
  'genesis', // first contact: no cursor, no prior briefing
] as const;
export type RecoveryMethod = (typeof RECOVERY_METHODS)[number];

export interface Recovery {
  method: RecoveryMethod;
  from_seq: number;
  reason: string;
  /** Set when a since_cursor was presented but rejected. The call still succeeds. */
  cursor_error: string | null;
  /** issued_at of a verified full cursor, when one was presented. */
  cursor_issued_at: string | null;
}

export interface OrientInput {
  actor_id: string;
  budget_tokens?: number;
  since_cursor?: string | undefined;
  focus?: Focus | undefined;
  /**
   * 0.5.0: the project the caller works in. Instruction retractions from
   * documents that recorded a different project (`source.project.key`) are
   * left out of `retractions` and counted in `scope.hidden_retractions`.
   * null/undefined: no scoping (every retraction is listed).
   */
  project?: ProjectScope | null | undefined;
  /**
   * Unreleased: also list format-only edits (identical raw text up to
   * whitespace and reflow, docs/FORMAT.md §3.8) in `retractions`. Default false: they are recorded and listed under
   * `format_only_edits` only. `include_cosmetic` is the earlier name.
   */
  include_format_only?: boolean | undefined;
  /** @deprecated earlier name of include_format_only. */
  include_cosmetic?: boolean | undefined;
  /**
   * Unreleased: whose reads `pending` is computed for (default: actor_id). A
   * hook that orients under its own actor (docs/PUSH.md) passes the agent's.
   */
  pending_actor?: string | undefined;
}

/** Unreleased: a supersession whose Markdown tree and text are unchanged (orient/cosmetic.ts). */
export interface FormatOnlyEdit {
  seq: number;
  doc_slug: string | null;
  block_id: string | null;
  successor_block_id: string | null;
  rules: FormatRule[];
  diff: string | null;
}
/** @deprecated earlier name. */
export type CosmeticEdit = FormatOnlyEdit;

/**
 * Unreleased (next): a note this actor wrote since its cursor, carried back
 * in the briefing (bounded) so a decision survives a context compaction as
 * text, not only as a slug. `stale_terms`: identifiers in the note that a
 * retraction in this briefing changed or removed.
 */
export interface CarriedNote {
  doc_slug: string;
  seq: number;
  revision: number;
  text: string;
  total_chars: number;
  truncated: boolean;
  stale_terms: { term: string; seq: number; now: string | null }[];
}

/** Bounds for carried notes: per note and per briefing (characters). */
export const CARRIED_NOTE_CHARS = 600;
export const CARRIED_NOTES_TOTAL_CHARS = 1500;
export const CARRIED_NOTES_MAX = 3;

/** The project keys (instructions + auto memory) of the working directory; see instructions/paths.ts. */
export interface ProjectScope {
  keys: string[];
  root?: string;
}

/** 0.5.0: a quick integrity pass over what this briefing is built from. */
export interface IntegritySummary {
  ok: boolean;
  /** Chain events re-hashed and re-linked (the delta window, at least the last 1000). */
  events_checked: number;
  /** Live blocks re-hashed against their block.created events (newest first, at most 2000). */
  blocks_checked: number;
  /** First problem found, in words; null when ok. */
  problem: string | null;
  /** Unreleased, additive: chain seq of the first bad event, when the problem is an event. */
  seq?: number | null;
}

export interface Digest {
  genesis_hash: string;
  documents: number;
  live_blocks: number;
  checkpoints: number;
  recent_documents: { slug: string; title: string; revision: number; updated_at: string }[];
}

/** Latest hosted anchor, from the local `anchors` table (no network). */
export interface AnchorSummary {
  anchor_id: string;
  from_seq: number;
  to_seq: number;
  received_at: string;
  status: string;
  /** head.seq - to_seq: events appended since the anchored range. */
  events_since: number;
}

export interface SystemState {
  format: 'kronicle-lite/1';
  briefing_id: string;
  issued_at: string;
  actor_id: string;
  focus: Focus;
  head: ChainHead;
  cursor: string;
  cursor_compact: string;
  recovery: Recovery;
  drift_banner: DriftBanner;
  stale_write_advisory: StaleWriteAdvisory;
  /** 0.4.0: latest anchor, or null when never anchored. */
  anchor: AnchorSummary | null;
  /** 0.4.0: git-bound documents whose source file changed or vanished; null for focus=pulse (and, unreleased/next, focus=retractions: not checked). */
  source_drift: SourceDrift[] | null;
  /** 0.5.0: chain + live-block integrity over what this briefing read; null for focus=pulse. */
  integrity: IntegritySummary | null;
  /**
   * 0.5.0: project scoping applied to instruction retractions; null when unscoped.
   * 0.6.0 `verdict`: `partial` when retractions were hidden, so "no retractions"
   * here is not a clean bill for the hidden projects.
   */
  scope: {
    project_keys: string[];
    hidden_retractions: number;
    verdict: 'complete' | 'partial';
    /** Unreleased (next): events about other projects' documents left out of the delta. */
    hidden_events?: number;
  } | null;
  delta: TypedDelta | null;
  retractions: Retraction[] | null;
  /** Unreleased: format-only supersessions since the cursor (not in `retractions` by default); null for focus=pulse. */
  format_only_edits?: FormatOnlyEdit[] | null;
  /** @deprecated alias of format_only_edits (same array). */
  cosmetic_edits?: FormatOnlyEdit[] | null;
  /** Unreleased (next): this actor's own notes written since the cursor, bounded; null unless focus is orientation / recent_changes. */
  carried_notes?: CarriedNote[] | null;
  /**
   * Unreleased: changes to blocks `pending_actor` (default: actor_id) read or
   * wrote, or to sources of notes it read or wrote, that it has not
   * reconciled by reading the CURRENT version (docs/PUSH.md). Every focus,
   * pulse included. Capped at 20 items; `pending_count` is the total.
   */
  pending?: PendingItem[] | null;
  pending_count?: number | null;
  /** Unreleased: whose reads `pending` was computed for (null when not computed). */
  pending_actor?: string | null;
  /** Unreleased: pending items about other projects' documents, not listed or counted in pending_count. */
  pending_hidden?: number | null;
  digest: Digest | null;
  next_steps: string[];
}

/** Unreleased: cap on pending items listed in a briefing (pending_count is the total). */
export const PENDING_LIMIT = 20;

export interface OrientOptions {
  rules?: DriftRules;
  policy?: PolicyOptions;
}

export class Orient {
  readonly recorder: FlightRecorder;
  private readonly rules: DriftRules;
  private readonly policy: PolicyOptions;

  constructor(
    private readonly db: Db,
    private readonly chain: Chain,
    private readonly docs: DocumentStore,
    private readonly secret: string,
    opts: OrientOptions = {},
    /** Unreleased: derived-note lineage and per-actor pending (null: neither is computed). */
    private readonly lineage: Lineage | null = null,
  ) {
    this.recorder = new FlightRecorder(db);
    this.rules = opts.rules ?? DEFAULT_DRIFT_RULES;
    this.policy = opts.policy ?? {};
  }

  /** Signals for drift banner / stale-write advisory, from the recorder (fallback: a valid cursor). */
  driftSignals(actor_id: string, now: Date, cursorPosition?: { chain_seq: number; issued_at: string | null }): DriftSignals {
    const head = this.chain.head();
    const latest = this.recorder.latestForActor(actor_id);
    if (latest) {
      return {
        events_since_last_orient: Math.max(0, head.seq - latest.to_seq),
        seconds_since_last_orient: Math.max(0, Math.floor((now.getTime() - Date.parse(latest.issued_at)) / 1000)),
      };
    }
    if (cursorPosition) {
      return {
        events_since_last_orient: Math.max(0, head.seq - cursorPosition.chain_seq),
        seconds_since_last_orient:
          cursorPosition.issued_at !== null
            ? Math.max(0, Math.floor((now.getTime() - Date.parse(cursorPosition.issued_at)) / 1000))
            : null,
      };
    }
    return { events_since_last_orient: null, seconds_since_last_orient: null };
  }

  /** For write tools: advisory only, never blocks. */
  staleWriteAdvisory(actor_id: string, cursor?: string | undefined, now = new Date()): StaleWriteAdvisory {
    let pos: { chain_seq: number; issued_at: string | null } | undefined;
    if (cursor) {
      try {
        const parsed = parseAnyCursor(cursor, actor_id, this.secret);
        pos =
          parsed.form === 'full'
            ? { chain_seq: parsed.body.chain_seq, issued_at: parsed.body.issued_at }
            : { chain_seq: parsed.chain_seq, issued_at: null };
      } catch {
        pos = undefined;
      }
    }
    return composeStaleWriteAdvisory(this.driftSignals(actor_id, now, pos), this.rules);
  }

  /**
   * 0.6.0: when the actor's current session started, for recall's attention
   * rerank: the issue time of the briefing behind the cursor it presents (a
   * full cursor carries it; a compact one is looked up in the flight
   * recorder), else the actor's latest briefing. null when the actor never
   * oriented. A cursor issued to another actor is ignored.
   */
  sessionStart(actor_id: string, cursor?: string | undefined): string | null {
    if (cursor) {
      try {
        const parsed = parseAnyCursor(cursor, actor_id, this.secret);
        if (parsed.form === 'full') {
          if (parsed.body.actor_id === actor_id) return parsed.body.issued_at;
        } else {
          const b = this.recorder.briefingAt(actor_id, parsed.chain_seq);
          if (b) return b.issued_at;
        }
      } catch {
        // fall through to the flight recorder
      }
    }
    return this.recorder.latestForActor(actor_id)?.issued_at ?? null;
  }

  /**
   * 0.8.1: where the actor's current SESSION began, for lineage inference:
   * the first briefing of the cursor chain that leads to the briefing behind
   * `cursor` (else to the actor's latest briefing). A briefing continues the
   * session when it was served from a cursor the actor presented (recovery
   * `presented` / `presented_compact`); one served without a usable cursor
   * (flight recorder, genesis, a stale cursor) starts a new session. Before,
   * inference started at the LATEST orient, so recall → orient → write (the
   * wake contract: re-orient before writing) inferred no lineage. null when
   * the actor never oriented.
   */
  sessionOrigin(actor_id: string, cursor?: string | undefined): string | null {
    let b: FlightRecord | null = null;
    if (cursor) {
      try {
        const parsed = parseAnyCursor(cursor, actor_id, this.secret);
        if (parsed.form === 'full') {
          if (parsed.body.actor_id === actor_id) {
            b = this.recorder.briefingIssuedAt(actor_id, parsed.body.issued_at);
            // A cursor whose briefing was not recorded (focus=pulse): its issue time is all we know.
            if (!b) return parsed.body.issued_at;
          }
        } else {
          b = this.recorder.briefingAt(actor_id, parsed.chain_seq);
        }
      } catch {
        // fall through to the flight recorder
      }
    }
    b ??= this.recorder.latestForActor(actor_id);
    if (!b) return null;
    let origin = b.issued_at;
    const seen = new Set<string>([b.briefing_id]);
    for (let hops = 0; hops < 10_000; hops++) {
      const rec = b.record['recovery'] as Partial<Recovery> | undefined;
      if (!rec || (rec.method !== 'presented' && rec.method !== 'presented_compact')) break;
      const prev: FlightRecord | null =
        typeof rec.cursor_issued_at === 'string'
          ? this.recorder.briefingIssuedAt(actor_id, rec.cursor_issued_at)
          : typeof rec.from_seq === 'number'
            ? this.recorder.briefingAtBefore(actor_id, rec.from_seq, b.issued_at, b.briefing_id)
            : null;
      if (!prev || seen.has(prev.briefing_id)) {
        if (typeof rec.cursor_issued_at === 'string' && rec.cursor_issued_at < origin) origin = rec.cursor_issued_at;
        break;
      }
      seen.add(prev.briefing_id);
      b = prev;
      if (b.issued_at < origin) origin = b.issued_at;
    }
    return origin;
  }

  recover(actor_id: string, since_cursor: string | undefined, head: ChainHead): Recovery {
    let cursor_error: string | null = null;
    if (since_cursor) {
      try {
        const parsed = parseAnyCursor(since_cursor, actor_id, this.secret);
        if (parsed.form === 'compact') {
          if (parsed.chain_seq <= head.seq) {
            return {
              method: 'presented_compact',
              from_seq: parsed.chain_seq,
              reason: `compact cursor verified at seq ${parsed.chain_seq}`,
              cursor_error: null,
              cursor_issued_at: null,
            };
          }
          cursor_error = `compact cursor seq ${parsed.chain_seq} is beyond head ${head.seq}`;
        } else {
          const b = parsed.body;
          if (b.actor_id !== actor_id) {
            cursor_error = `cursor was issued to actor "${b.actor_id}", not "${actor_id}"`;
          } else {
            const onChain =
              b.chain_seq === 0 ? b.chain_hash === GENESIS_HASH : this.chain.get(b.chain_seq)?.this_hash === b.chain_hash;
            if (onChain) {
              return {
                method: 'presented',
                from_seq: b.chain_seq,
                reason: `cursor verified; position seq ${b.chain_seq} is on the chain`,
                cursor_error: null,
                cursor_issued_at: b.issued_at,
              };
            }
            // Verified token but the chain no longer contains that hash at that seq.
            const fallback = this.recorder.latestForActor(actor_id);
            return {
              method: 'presented_stale',
              from_seq: fallback ? Math.min(fallback.to_seq, head.seq) : 0,
              reason: `cursor verified but seq ${b.chain_seq} hash is not on the chain (chain reset or rewritten); ${
                fallback ? `recovered from flight recorder briefing ${fallback.briefing_id}` : 'no prior briefing; serving from genesis'
              }`,
              cursor_error: null,
              cursor_issued_at: b.issued_at,
            };
          }
        }
      } catch (err) {
        cursor_error = err instanceof CursorTokenError ? err.message : String(err);
      }
    }
    const latest = this.recorder.latestForActor(actor_id);
    if (latest) {
      return {
        method: 'flight_recorder',
        from_seq: Math.min(latest.to_seq, head.seq),
        reason: `${cursor_error ? `presented cursor rejected (${cursor_error}); ` : 'no cursor presented; '}recovered position seq ${latest.to_seq} from briefing ${latest.briefing_id} issued ${latest.issued_at}`,
        cursor_error,
        cursor_issued_at: null,
      };
    }
    return {
      method: 'genesis',
      from_seq: 0,
      reason: `${cursor_error ? `presented cursor rejected (${cursor_error}); ` : 'no cursor presented; '}no prior briefing for actor "${actor_id}" — cold start from genesis`,
      cursor_error,
      cursor_issued_at: null,
    };
  }

  digest(projectKeys: string[] | null = null): Digest {
    return {
      genesis_hash: GENESIS_HASH,
      documents: this.docs.countDocuments(),
      live_blocks: this.docs.countLiveBlocks(),
      checkpoints: this.chain.listCheckpoints().length,
      recent_documents: this.docs.listDocuments(10, projectKeys).map((d) => ({
        slug: d.slug,
        title: d.title,
        revision: d.current_revision,
        updated_at: d.updated_at,
      })),
    };
  }

  /** Block text for retractions; withheld (null) when the row fails its integrity check. */
  private blockText(block_id: string): { content: string; heading_path: string[]; kind: string } | null {
    const b = this.docs.getBlock(block_id);
    if (!b || checkBlockRow(this.chain, b) !== null) return null;
    return { content: b.content, heading_path: splitHeadingPath(b.heading_path), kind: b.kind };
  }

  /** The actor's own non-instruction documents put in `events`, newest first, as bounded text. */
  carriedNotes(events: readonly ChainEvent[], actor_id: string, retractions: readonly Retraction[]): CarriedNote[] {
    const latest = new Map<string, ChainEvent>();
    for (const e of events) {
      if (e.event_type !== 'document.put' || e.actor_id !== actor_id) continue;
      const slug = e.payload['slug'];
      const doc_id = e.payload['doc_id'];
      if (typeof slug !== 'string' || typeof doc_id !== 'string' || isInstructionSlug(slug)) continue;
      latest.delete(doc_id);
      latest.set(doc_id, e);
    }
    const changed = retractions.filter((r) => !r.format_only && r.old_text);
    const out: CarriedNote[] = [];
    let budget = CARRIED_NOTES_TOTAL_CHARS;
    for (const [doc_id, e] of [...latest].reverse()) {
      if (out.length >= CARRIED_NOTES_MAX || budget <= 0) break;
      const doc = this.docs.getDocumentById(doc_id);
      if (!doc || doc.tombstoned_at) continue;
      const blocks = this.docs.liveBlocks(doc_id).filter((b) => b.kind !== 'heading' && checkBlockRow(this.chain, b) === null);
      const full = blocks.map((b) => b.content).join('\n\n');
      if (full.length === 0) continue;
      const limit = Math.min(CARRIED_NOTE_CHARS, budget);
      const text = full.length > limit ? full.slice(0, limit - 1).trimEnd() + '\u2026' : full;
      budget -= text.length;
      const stale_terms: CarriedNote['stale_terms'] = [];
      for (const r of changed) {
        const now = r.new_text ? new Set(identifiers(r.new_text)) : new Set<string>();
        for (const term of identifiers(r.old_text!)) {
          if (now.has(term) || !full.includes(term) || stale_terms.some((t) => t.term === term)) continue;
          if (stale_terms.length < 3) stale_terms.push({ term, seq: r.seq, now: r.new_text ? snippet(r.new_text, 80) : null });
        }
      }
      out.push({ doc_slug: doc.slug, seq: e.seq, revision: doc.current_revision, text, total_chars: full.length, truncated: text.length < full.length, stale_terms });
    }
    return out;
  }

  /**
   * Unreleased: one retraction per derived note whose source changed in
   * `events` and that is stale now (re-derived notes are not listed).
   * Format-only source edits never make a note stale.
   */
  derivedRetractions(events: readonly ChainEvent[]): { doc_id: string; retraction: Retraction }[] {
    const lineage = this.lineage;
    if (!lineage || !lineage.anyLineage()) return [];
    const memo = new Map<string, StaleSource[]>();
    const seen = new Set<string>();
    const out: { doc_id: string; retraction: Retraction }[] = [];
    for (const ev of events) {
      if (ev.event_type !== 'block.superseded' && ev.event_type !== 'block.tombstoned') continue;
      const block_id = ev.payload['block_id'];
      if (typeof block_id !== 'string') continue;
      const notes = lineage.derivedFrom(block_id);
      if (notes.length === 0) continue;
      if (ev.event_type === 'block.superseded') {
        const a = this.docs.getBlock(block_id);
        const succ = ev.payload['successor_block_id'];
        const b = typeof succ === 'string' ? this.docs.getBlock(succ) : null;
        if (a && b && lineage.hopFormatOnly(a, b)) continue;
      }
      for (const doc_id of notes) {
        const stale = lineage.staleness(doc_id, memo);
        const entry = stale.find((s) => !s.via && (lineage.walk(s.source_block_id)?.blocks.some((b) => b.block_id === block_id) ?? false));
        if (!entry) continue;
        const key = `${doc_id}|${entry.source_block_id}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const note = this.docs.getDocumentById(doc_id);
        if (!note) continue;
        const first = this.docs.liveBlocks(doc_id).find((b) => b.kind !== 'heading' && checkBlockRow(this.chain, b) === null) ?? null;
        const noteText = first ? snippet(first.content) : null;
        const src = this.docs.getBlock(entry.source_block_id);
        const cur = entry.current_block_id ? this.docs.getBlock(entry.current_block_id) : null;
        const removed = entry.current_block_id === null;
        const srcLoc = entry.source_doc_slug ? ` (${entry.source_doc_slug})` : '';
        const now = removed ? 'REMOVED' : entry.change === 'moved' ? `"${entry.new_text}" MOVED to another section` : `"${entry.new_text}"`;
        out.push({
          doc_id,
          retraction: {
            seq: ev.seq,
            event_type: ev.event_type,
            kind: 'derived',
            severity: removed ? 'safety' : 'behavioral',
            block_id: first?.block_id ?? null,
            doc_slug: note.slug,
            successor_block_id: null,
            reason: `derived from ${entry.source_doc_slug ?? entry.source_block_id}, which changed`,
            reason_line: `You previously relied on note ${noteText ? `"${noteText}" ` : ''}(${note.slug}), derived from "${entry.old_text ?? entry.source_block_id}"${srcLoc}; that source is now ${now} (seq ${ev.seq}). The note is STALE: re-derive it from the current source before acting.`,
            heading_path: first ? splitHeadingPath(first.heading_path) : null,
            old_text: noteText,
            new_text: null,
            diff: src && cur ? `source ${entry.source_doc_slug ?? ''}: ${wordDiff(src.content, cur.content)}`.replace(/^source : /, 'source: ') : null,
            format_only: false,
            derived_from_change: entry,
          },
        });
      }
    }
    return out;
  }

  /**
   * Re-hash the events this briefing covers (at least the last 1000) and the
   * newest live blocks against their chained block.created events. Cheap
   * enough for every orient; `verify-chain` / `doctor` do the full pass.
   */
  quickIntegrity(from_seq: number, head: ChainHead, opts: { windowOnly?: boolean; eventsOnly?: boolean } = {}): IntegritySummary {
    let problem: string | null = null;
    let seq: number | null = null;
    let events_checked = 0;
    // windowOnly (focus=retractions, the per-tool-call push path): re-hash just
    // the events since the cursor instead of the last 1000. Full briefings keep
    // the wider event pass.
    if (head.seq > 0 && (!opts.windowOnly || from_seq < head.seq)) {
      const from = opts.windowOnly ? Math.max(1, from_seq + 1) : Math.max(1, Math.min(from_seq + 1, head.seq - 999));
      const r = this.chain.verify(from);
      events_checked = r.events_checked;
      if (!r.ok && r.first_mismatch) {
        problem = `chain ${r.first_mismatch.kind} at seq ${r.first_mismatch.seq}`;
        seq = r.first_mismatch.seq;
      }
    }
    // Live blocks are always re-hashed (a tampered row must surface on every path, the push hook's too).
    const blocks = opts.eventsOnly ? [] : this.docs.liveBlockRows(2000);
    if (!problem) {
      for (const b of blocks) {
        const p = checkBlockRow(this.chain, b);
        if (p) {
          problem = `block ${b.block_id} (${p}): its stored text does not match the chain`;
          break;
        }
      }
    }
    return { ok: problem === null, events_checked, blocks_checked: blocks.length, problem, seq };
  }

  /** True when the actor has any read or receipt on record (it may have relied on something). */
  private hasReadAnything(actor_id: string): boolean {
    return (
      this.db.prepare(`SELECT 1 FROM reads WHERE actor_id = ? LIMIT 1`).get(actor_id) !== undefined ||
      this.db.prepare(`SELECT 1 FROM receipts WHERE actor_id = ? LIMIT 1`).get(actor_id) !== undefined
    );
  }

  /**
   * 0.8.1 (C2-09): focus=retractions for an actor that never oriented and
   * never read anything. A retraction tells an agent that something it relied
   * on changed; it relied on nothing, so there is nothing to retract (what it
   * reads from now on is current, and `pending` still covers pending_actor).
   * The delta is the counts a retractions briefing carries, from the
   * (event_type, seq) index instead of folding every event since genesis;
   * with a project scope, one SQL pass decides which events are about other
   * projects' documents (counted in hidden_events, as the full path does).
   */
  private firstContactRetractions(head: ChainHead, keys: readonly string[] | null): { delta: TypedDelta; hidden_events: number } {
    const counts = (keys
      ? this.db
          .prepare(
            `SELECT e.event_type, COUNT(*) AS count, MIN(e.seq) AS first_seq, MAX(e.seq) AS last_seq
               FROM events e LEFT JOIN documents d
                 ON d.doc_id = (CASE WHEN json_valid(e.payload_canonical) THEN json_extract(e.payload_canonical, '$.doc_id') END)
              WHERE e.seq <= ? AND (d.project_key IS NULL OR d.project_key IN (${keys.map(() => '?').join(', ')}))
              GROUP BY e.event_type`,
          )
          .all(head.seq, ...keys)
      : this.db
          .prepare(`SELECT event_type, COUNT(*) AS count, MIN(seq) AS first_seq, MAX(seq) AS last_seq FROM events WHERE seq <= ? GROUP BY event_type`)
          .all(head.seq)) as Omit<TypeGroup, 'last'>[];
    const groups: TypeGroup[] = [];
    for (const c of counts) {
      const last = this.chain.get(c.last_seq);
      if (last) groups.push({ ...c, last });
    }
    const delta = rollupDelta(groups, 0, head.seq, this.policy);
    const total = keys ? (this.db.prepare(`SELECT COUNT(*) AS n FROM events WHERE seq <= ?`).get(head.seq) as { n: number }).n : delta.events_since;
    return { delta: { ...delta, entries: [] }, hidden_events: total - delta.events_since };
  }

  getSystemState(input: OrientInput, now = new Date()): SystemState {
    const focus: Focus = input.focus ?? 'orientation';
    const budget = input.budget_tokens ?? 3000;
    const head = this.chain.head();
    const issued_at = now.toISOString();
    const briefing_id = randomUUID();

    const recovery = this.recover(input.actor_id, input.since_cursor, head);
    const cursorPos =
      recovery.method === 'presented' || recovery.method === 'presented_compact'
        ? { chain_seq: recovery.from_seq, issued_at: recovery.cursor_issued_at }
        : undefined;
    const signals = this.driftSignals(input.actor_id, now, cursorPos);
    const drift_banner = composeDriftBanner(signals, this.rules);
    const stale_write_advisory = composeStaleWriteAdvisory(signals, this.rules);

    const cursor = serializeCursor(
      { actor_id: input.actor_id, chain_seq: head.seq, chain_hash: head.hash, issued_at },
      this.secret,
    );
    const cursor_compact = serializeCompactCursor(input.actor_id, head.seq, this.secret);

    let delta: TypedDelta | null = null;
    let retractions: Retraction[] | null = null;
    let digest: Digest | null = null;
    let source_drift: SourceDrift[] | null = null;
    let integrity: IntegritySummary | null = null;
    let scope: SystemState['scope'] = null;

    let format_only_edits: FormatOnlyEdit[] | null = null;
    let carried_notes: CarriedNote[] | null = null;

    // 0.8.1 (C2-09): focus=retractions at first contact answers from indexes.
    const firstContact = focus === 'retractions' && recovery.method === 'genesis' && !this.hasReadAnything(input.actor_id);
    if (firstContact) {
      const keys = input.project && input.project.keys.length > 0 ? input.project.keys : null;
      const fc = this.firstContactRetractions(head, keys);
      delta = fc.delta;
      retractions = [];
      format_only_edits = [];
      if (keys && input.project) scope = { project_keys: input.project.keys, hidden_retractions: 0, verdict: 'complete', hidden_events: fc.hidden_events };
      digest = scrubDeep(this.digest(keys)).value;
      // Not windowOnly: there is no window. The briefing serves no event text, so the bounded
      // pass of a full briefing (the last 1000 events and the newest live blocks) is the check.
      integrity = this.quickIntegrity(Math.max(0, head.seq - 1000), head);
    } else if (focus !== 'pulse') {
      const allEvents = this.chain.since(recovery.from_seq);
      // Project scope (0.5.0 instruction retractions; unreleased/next: every
      // event about a document of another project). Unscoped documents and
      // events without a document stay visible.
      const keys = input.project && input.project.keys.length > 0 ? new Set(input.project.keys) : null;
      const projOf = new Map<string, string | null>();
      const inScopeDoc = (doc_id: string): boolean => {
        if (!keys) return true;
        let k = projOf.get(doc_id);
        if (k === undefined) {
          k = this.docs.projectKeyOf(doc_id);
          projOf.set(doc_id, k);
        }
        return k === null || keys.has(k);
      };
      const inScope = (e: ChainEvent): boolean => {
        const doc_id = e.payload['doc_id'];
        return typeof doc_id !== 'string' || inScopeDoc(doc_id);
      };
      const events = keys ? allEvents.filter(inScope) : allEvents;
      const lookup = (id: string) => this.blockText(id);
      if (focus === 'orientation' || focus === 'recent_changes') {
        // Reserve roughly a third of the budget for everything that is not delta entries.
        delta = foldDelta(events, recovery.from_seq, head.seq, {
          ...this.policy,
          budget_tokens: Math.max(100, Math.floor(budget * 0.66)),
        });
      } else {
        // retractions focus: counts only, no entries
        delta = { ...foldDelta(events, recovery.from_seq, head.seq, { ...this.policy, budget_tokens: 0 }), entries: [] };
      }
      const computed = computeRetractions(events, lookup);
      // Unreleased: derived notes (in scope) whose sources changed in the window (sources in any project).
      const derivedAll = this.derivedRetractions(allEvents);
      const derived = derivedAll.filter((d) => inScopeDoc(d.doc_id)).map((d) => d.retraction);
      if (keys && input.project) {
        const hiddenEvents = allEvents.length - events.length;
        const hidden = (hiddenEvents > 0 ? computeRetractions(allEvents.filter((e) => !inScope(e)), lookup).filter((r) => !r.format_only).length : 0) + (derivedAll.length - derived.length);
        scope = { project_keys: input.project.keys, hidden_retractions: hidden, verdict: hidden > 0 ? 'partial' : 'complete', hidden_events: hiddenEvents };
      }
      // The ONLY suppression: format-only edits move to their own list. A hint
      // (likely_typo) is a label and never moves anything.
      const suppressible = (r: Retraction) => r.format_only || (__mutants.has('gate_trusts_label') && r.hint === 'likely_typo');
      const includeFormat = input.include_format_only === true || input.include_cosmetic === true;
      retractions = [...(includeFormat ? computed : computed.filter((r) => !suppressible(r))), ...derived];
      format_only_edits = computed
        .filter(suppressible)
        .map((r) => ({ seq: r.seq, doc_slug: r.doc_slug, block_id: r.block_id, successor_block_id: r.successor_block_id, rules: r.format_rules ?? ['markup'], diff: r.diff }));
      // 0.6.0: read-time secret scrub on the text this briefing serves.
      retractions = scrubDeep(retractions).value;
      format_only_edits = scrubDeep(format_only_edits).value;
      if (delta.entries.length > 0) delta = { ...delta, entries: scrubDeep(delta.entries).value };
      if (focus === 'orientation' || focus === 'recent_changes') carried_notes = scrubDeep(this.carriedNotes(events, input.actor_id, computed)).value;
      if (focus === 'orientation' || recovery.method === 'genesis') digest = scrubDeep(this.digest(keys ? [...keys] : null)).value;
      // The retractions focus is the per-tool-call push contract (docs/PUSH.md): no git calls (null = not checked).
      source_drift = focus === 'retractions' ? null : this.docs.listSourceDrift();
      integrity = this.quickIntegrity(recovery.from_seq, head, { windowOnly: focus === 'retractions' });
    }

    // Unreleased: pulse re-hashes the events since the cursor too (cheap), so a
    // corrupt or edited event is never answered with "within threshold".
    if (focus === 'pulse' && recovery.from_seq < head.seq) {
      const pi = this.quickIntegrity(recovery.from_seq, head, { windowOnly: true, eventsOnly: true });
      if (!pi.ok) integrity = pi;
    }
    // Unreleased: version-bound reconciliation, every focus (pulse included).
    let pending: PendingItem[] | null = null;
    let pending_count: number | null = null;
    let pending_actor: string | null = null;
    let pending_hidden: number | null = null;
    if (this.lineage) {
      pending_actor = input.pending_actor ?? input.actor_id;
      const keys = input.project && input.project.keys.length > 0 ? input.project.keys : null;
      const p = this.lineage.pending(pending_actor, { project_keys: keys, limit: PENDING_LIMIT });
      pending = scrubDeep(p.items).value;
      pending_count = p.count;
      pending_hidden = p.hidden;
    }
    const next_steps = nextSteps({ focus, recovery, drift_banner, retractions, source_drift, integrity, scope, pending_count });
    const lastAnchor = this.chain.lastAnchor();
    const anchor: AnchorSummary | null = lastAnchor
      ? {
          anchor_id: lastAnchor.anchor_id,
          from_seq: lastAnchor.from_seq,
          to_seq: lastAnchor.to_seq,
          received_at: lastAnchor.received_at,
          status: lastAnchor.status,
          events_since: Math.max(0, head.seq - lastAnchor.to_seq),
        }
      : null;

    const state: SystemState = {
      format: 'kronicle-lite/1',
      briefing_id,
      issued_at,
      actor_id: input.actor_id,
      focus,
      head,
      cursor,
      cursor_compact,
      recovery,
      drift_banner,
      stale_write_advisory,
      anchor,
      source_drift,
      integrity,
      scope,
      delta,
      retractions,
      format_only_edits,
      cosmetic_edits: format_only_edits,
      carried_notes,
      pending,
      pending_count,
      pending_actor,
      pending_hidden,
      digest,
      next_steps,
    };

    if (focus !== 'pulse') {
      this.recorder.record({
        briefing_id,
        actor_id: input.actor_id,
        issued_at,
        from_seq: recovery.from_seq,
        to_seq: head.seq,
        head_hash: head.hash,
        focus,
        delta_hash: sha256Hex(canonicalize(delta ?? {})),
        record: {
          recovery,
          by_type: delta?.by_type ?? {},
          retraction_count: retractions?.length ?? 0,
          format_only_count: format_only_edits?.length ?? 0,
          drift_surfaced: drift_banner.surfaced,
          pending_count: pending_count ?? 0,
          budget_tokens: budget,
        },
      });
    }
    return state;
  }
}

function nextSteps(args: {
  focus: Focus;
  recovery: Recovery;
  drift_banner: DriftBanner;
  retractions: Retraction[] | null;
  source_drift: SourceDrift[] | null;
  integrity: IntegritySummary | null;
  scope?: SystemState['scope'];
  pending_count?: number | null;
}): string[] {
  const steps: string[] = [];
  const pendingStep =
    (args.pending_count ?? 0) > 0
      ? `${args.pending_count} pending: re-read the current version of each before acting (seeing a retraction or reading an older version never clears it).`
      : null;
  if (args.integrity && !args.integrity.ok) {
    steps.push(
      `INTEGRITY FAILURE (${args.integrity.problem}): the store was edited outside kronicle-lite. Do not rely on recalled text; tell the operator to run kronicle-lite verify-chain.`,
    );
  }
  if (args.recovery.cursor_error) {
    steps.push('Your since_cursor was rejected; position was recovered server-side. Replace it with the new cursor below.');
  }
  if (args.focus === 'pulse') {
    // A pulse never lists retractions, so it must never read as a clean bill
    // when something changed: "proceed" only when nothing changed and nothing
    // is pending (stress/bench finding: agents deployed on "within threshold").
    const integrityBad = !!args.integrity && !args.integrity.ok;
    const changed = (args.drift_banner.events_since_last_orient ?? 0) > 0;
    if (pendingStep) {
      steps.push(pendingStep);
      steps.push('Do NOT run deploy/migrate/publish/push until every pending item is re-read. Carry the new cursor.');
    } else if (integrityBad) {
      steps.push('Do NOT act on recalled text until the integrity failure is resolved.');
    } else if (args.drift_banner.surfaced) {
      steps.push('Drift threshold crossed: call get_system_state with focus=retractions (or recent_changes) to read what changed before acting.');
    } else if (changed) {
      steps.push(
        `${args.drift_banner.events_since_last_orient} change(s) since your last look; a pulse does not list retractions. Before a world-changing action (deploy, migrate, publish, push) call get_system_state with focus=retractions. Carry the new cursor.`,
      );
    } else {
      steps.push('No changes since your last look; proceed. Carry the new cursor.');
    }
    return steps;
  }
  const safety = args.retractions?.filter((r) => r.severity === 'safety').length ?? 0;
  if (args.retractions && args.retractions.length > 0) {
    steps.push(
      `Reconcile ${args.retractions.length} retraction(s)${safety ? ` (${safety} safety)` : ''} BEFORE acting: for each, affirm the current truth (cite seq), name the old claim once, and drop it as a decision premise.`,
    );
  }
  if (pendingStep) steps.push(pendingStep);
  if (args.scope && args.scope.verdict === 'partial') {
    steps.push(
      `${args.scope.hidden_retractions} retraction(s) from other projects were hidden and not reviewed: this briefing is not a clean bill for those projects (pass all_projects: true to see them).`,
    );
  }
  if (args.source_drift && args.source_drift.length > 0) {
    steps.push(
      `${args.source_drift.length} git-bound document(s) no longer match their source file (Source drift): re-read the file before relying on the stored copy, then re-put it with bind_git.`,
    );
  }
  if (args.recovery.method === 'genesis') {
    steps.push('Cold start: read the digest, then recall() what you need. Do not assume prior context.');
  } else if (args.drift_banner.surfaced) {
    steps.push('Drift banner surfaced: treat your memory of this store as stale; the delta above is the catch-up.');
  }
  steps.push('Carry the returned cursor (or cursor_compact) into your next get_system_state call and into write tools.');
  return steps;
}

/** Identifier-like words (a digit or one of - _ . : /), the kind a note copies verbatim. */
function identifiers(text: string): string[] {
  return [...new Set((text.match(/[\p{L}\p{N}][\p{L}\p{N}._:/-]*[\p{L}\p{N}]/gu) ?? []).filter((w) => w.length >= 4 && /[\d._:/-]/.test(w)))];
}
