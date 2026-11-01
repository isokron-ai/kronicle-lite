/**
 * get_system_state — the orient call. Recovers the actor's position (cursor
 * → flight recorder → genesis), folds the delta since that position under
 * the token budget, classifies retractions, composes the drift banner and
 * stale-write advisory, issues a new cursor and records the briefing.
 *
 * Nothing here writes to the chain: orienting is observation.
 */

import { randomUUID } from 'node:crypto';

import type { Chain, ChainHead } from '../chain/index.js';
import { GENESIS_HASH } from '../chain/genesis.js';
import { canonicalize } from '../crypto/canonical.js';
import { sha256Hex } from '../crypto/hash.js';
import { splitHeadingPath, type DocumentStore, type SourceDrift } from '../docs/documents.js';
import { checkBlockRow } from '../docs/integrity.js';
import { CursorTokenError, parseAnyCursor, serializeCompactCursor, serializeCursor } from './cursor.js';
import { foldDelta, type PolicyOptions, type TypedDelta } from './delta.js';
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
import { FlightRecorder } from './flight-recorder.js';
import { computeRetractions, type Retraction } from './retraction.js';

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
}

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
  /** 0.4.0: git-bound documents whose source file changed or vanished; null for focus=pulse. */
  source_drift: SourceDrift[] | null;
  /** 0.5.0: chain + live-block integrity over what this briefing read; null for focus=pulse. */
  integrity: IntegritySummary | null;
  /**
   * 0.5.0: project scoping applied to instruction retractions; null when unscoped.
   * 0.6.0 `verdict`: `partial` when retractions were hidden, so "no retractions"
   * here is not a clean bill for the hidden projects.
   */
  scope: { project_keys: string[]; hidden_retractions: number; verdict: 'complete' | 'partial' } | null;
  delta: TypedDelta | null;
  retractions: Retraction[] | null;
  digest: Digest | null;
  next_steps: string[];
}

export interface OrientOptions {
  rules?: DriftRules;
  policy?: PolicyOptions;
}

export class Orient {
  readonly recorder: FlightRecorder;
  private readonly rules: DriftRules;
  private readonly policy: PolicyOptions;

  constructor(
    db: ConstructorParameters<typeof FlightRecorder>[0],
    private readonly chain: Chain,
    private readonly docs: DocumentStore,
    private readonly secret: string,
    opts: OrientOptions = {},
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

  digest(): Digest {
    return {
      genesis_hash: GENESIS_HASH,
      documents: this.docs.countDocuments(),
      live_blocks: this.docs.countLiveBlocks(),
      checkpoints: this.chain.listCheckpoints().length,
      recent_documents: this.docs.listDocuments(10).map((d) => ({
        slug: d.slug,
        title: d.title,
        revision: d.current_revision,
        updated_at: d.updated_at,
      })),
    };
  }

  /** Block text for retractions; withheld (null) when the row fails its integrity check. */
  private blockText(block_id: string): { content: string; heading_path: string[] } | null {
    const b = this.docs.getBlock(block_id);
    if (!b || checkBlockRow(this.chain, b) !== null) return null;
    return { content: b.content, heading_path: splitHeadingPath(b.heading_path) };
  }

  /**
   * Re-hash the events this briefing covers (at least the last 1000) and the
   * newest live blocks against their chained block.created events. Cheap
   * enough for every orient; `verify-chain` / `doctor` do the full pass.
   */
  quickIntegrity(from_seq: number, head: ChainHead): IntegritySummary {
    let problem: string | null = null;
    let events_checked = 0;
    if (head.seq > 0) {
      const from = Math.max(1, Math.min(from_seq + 1, head.seq - 999));
      const r = this.chain.verify(from);
      events_checked = r.events_checked;
      if (!r.ok && r.first_mismatch) problem = `chain ${r.first_mismatch.kind} at seq ${r.first_mismatch.seq}`;
    }
    const blocks = this.docs.liveBlockRows(2000);
    if (!problem) {
      for (const b of blocks) {
        const p = checkBlockRow(this.chain, b);
        if (p) {
          problem = `block ${b.block_id} (${p}): its stored text does not match the chain`;
          break;
        }
      }
    }
    return { ok: problem === null, events_checked, blocks_checked: blocks.length, problem };
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

    if (focus !== 'pulse') {
      const events = this.chain.since(recovery.from_seq);
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
      const all = computeRetractions(events, (id) => this.blockText(id));
      if (input.project && input.project.keys.length > 0) {
        const docOf = new Map(events.map((e) => [e.seq, typeof e.payload['doc_id'] === 'string' ? (e.payload['doc_id'] as string) : null]));
        const keys = new Set(input.project.keys);
        retractions = all.filter((r) => {
          if (r.kind !== 'instruction') return true;
          const doc_id = docOf.get(r.seq);
          const key = doc_id ? this.docs.getSource(doc_id)?.source.project?.key : undefined;
          return key === undefined || keys.has(key);
        });
        const hidden = all.length - retractions.length;
        scope = { project_keys: input.project.keys, hidden_retractions: hidden, verdict: hidden > 0 ? 'partial' : 'complete' };
      } else {
        retractions = all;
      }
      // 0.6.0: read-time secret scrub on the text this briefing serves.
      retractions = scrubDeep(retractions).value;
      if (delta.entries.length > 0) delta = { ...delta, entries: scrubDeep(delta.entries).value };
      if (focus === 'orientation' || recovery.method === 'genesis') digest = scrubDeep(this.digest()).value;
      source_drift = this.docs.listSourceDrift();
      integrity = this.quickIntegrity(recovery.from_seq, head);
    }

    const next_steps = nextSteps({ focus, recovery, drift_banner, retractions, source_drift, integrity, scope });
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
          drift_surfaced: drift_banner.surfaced,
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
}): string[] {
  const steps: string[] = [];
  if (args.integrity && !args.integrity.ok) {
    steps.push(
      `INTEGRITY FAILURE (${args.integrity.problem}): the store was edited outside kronicle-lite. Do not rely on recalled text; tell the operator to run kronicle-lite verify-chain.`,
    );
  }
  if (args.recovery.cursor_error) {
    steps.push('Your since_cursor was rejected; position was recovered server-side. Replace it with the new cursor below.');
  }
  if (args.focus === 'pulse') {
    steps.push(
      args.drift_banner.surfaced
        ? 'Drift threshold crossed: call get_system_state with focus=recent_changes to read what changed.'
        : 'Within threshold; proceed. Carry the new cursor.',
    );
    return steps;
  }
  const safety = args.retractions?.filter((r) => r.severity === 'safety').length ?? 0;
  if (args.retractions && args.retractions.length > 0) {
    steps.push(
      `Reconcile ${args.retractions.length} retraction(s)${safety ? ` (${safety} safety)` : ''} BEFORE acting: for each, affirm the current truth (cite seq), name the old claim once, and drop it as a decision premise.`,
    );
  }
  if (args.scope && args.scope.verdict === 'partial') {
    steps.push(
      `${args.scope.hidden_retractions} instruction retraction(s) from other projects were hidden and not reviewed: this briefing is not a clean bill for those projects (pass all_projects: true to see them).`,
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
