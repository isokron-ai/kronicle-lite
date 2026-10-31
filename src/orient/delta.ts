/**
 * Typed delta: "what changed since your cursor", folded under a render
 * policy and a token budget.
 *
 * Render policy per event type is `enumerate` (every event listed) or
 * `volume-rollup` (collapsed to count + first/last seq + most recent sample).
 * There is no `suppress`: every input event lands somewhere, so the delta
 * never silently drops a fact. Output is chain order (oldest first).
 *
 * Budget: after the policy fold, if the estimated token size of the entries
 * exceeds the budget, enumerated event types are demoted to rollups one type
 * at a time (most numerous first) until it fits or everything is rolled up.
 * `coverage` reports exactly what happened so the consumer can tell a quiet
 * chain from a squeezed one.
 */

import { z } from 'zod';

import type { ChainEvent } from '../chain/index.js';

export const RenderPolicy = z.enum(['enumerate', 'volume-rollup']);
export type RenderPolicy = z.infer<typeof RenderPolicy>;

/** block.created is the firehose in a document store; everything else enumerates by default. */
export const DEFAULT_VOLUME_ROLLUP_PREFIXES: readonly string[] = Object.freeze(['block.created']);

export interface PolicyOptions {
  readonly volume_rollup_prefixes?: readonly string[];
  readonly never_rollup_event_types?: readonly string[];
  readonly overrides?: Readonly<Record<string, RenderPolicy>>;
}

function matchesPrefix(event_type: string, prefixes: readonly string[]): boolean {
  return prefixes.some((p) => (p.endsWith('.') ? event_type.startsWith(p) : event_type === p));
}

/**
 * Precedence: never-rollup set → explicit override → rollup prefix → enumerate.
 */
export function resolveRenderPolicy(event_type: string, opts: PolicyOptions = {}): RenderPolicy {
  if ((opts.never_rollup_event_types ?? []).includes(event_type)) return 'enumerate';
  const o = opts.overrides?.[event_type];
  if (o) return o;
  if (matchesPrefix(event_type, opts.volume_rollup_prefixes ?? DEFAULT_VOLUME_ROLLUP_PREFIXES)) {
    return 'volume-rollup';
  }
  return 'enumerate';
}

export interface DeltaEventEntry {
  kind: 'event';
  seq: number;
  hash: string;
  event_type: string;
  actor_id: string;
  occurred_at: string;
  payload: Record<string, unknown>;
  rendered_via: RenderPolicy;
}

export interface DeltaRollupEntry {
  kind: 'volume_rollup';
  event_type: string;
  count: number;
  first_seq: number;
  last_seq: number;
  sample: DeltaEventEntry;
  rendered_via: 'volume-rollup' | 'budget';
}

export type DeltaEntry = DeltaEventEntry | DeltaRollupEntry;

export interface DeltaCoverage {
  total_events_in: number;
  enumerated: number;
  rolled_up: number;
  rollup_groups: number;
  demoted_by_budget: string[];
  truncated: boolean;
  estimated_tokens: number;
}

export interface TypedDelta {
  from_seq: number; // exclusive
  to_seq: number; // inclusive
  events_since: number;
  by_type: Record<string, number>;
  entries: DeltaEntry[];
  coverage: DeltaCoverage;
}

export interface FoldOptions extends PolicyOptions {
  budget_tokens: number;
  /** Hard cap on entries regardless of budget (safety valve). */
  max_entries?: number;
  /** Truncate block content strings in payloads to this many chars. */
  payload_text_limit?: number;
}

export function estimateTokens(value: unknown): number {
  return Math.ceil(JSON.stringify(value).length / 4);
}

function toEntry(ev: ChainEvent, rendered_via: RenderPolicy, textLimit: number): DeltaEventEntry {
  return {
    kind: 'event',
    seq: ev.seq,
    hash: ev.this_hash,
    event_type: ev.event_type,
    actor_id: ev.actor_id,
    occurred_at: ev.occurred_at,
    payload: trimPayload(ev.payload, textLimit),
    rendered_via,
  };
}

function trimPayload(p: Record<string, unknown>, limit: number): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(p)) {
    if (typeof v === 'string' && v.length > limit) out[k] = v.slice(0, limit) + `…(+${v.length - limit} chars)`;
    else out[k] = v;
  }
  return out;
}

function rollupFrom(events: readonly ChainEvent[], rendered_via: 'volume-rollup' | 'budget', textLimit: number): DeltaRollupEntry {
  const first = events[0]!;
  const last = events[events.length - 1]!;
  return {
    kind: 'volume_rollup',
    event_type: first.event_type,
    count: events.length,
    first_seq: first.seq,
    last_seq: last.seq,
    sample: toEntry(last, 'volume-rollup', textLimit),
    rendered_via,
  };
}

export function foldDelta(events: readonly ChainEvent[], from_seq: number, to_seq: number, opts: FoldOptions): TypedDelta {
  const sorted = [...events].sort((a, b) => a.seq - b.seq);
  const textLimit = opts.payload_text_limit ?? 240;
  const by_type: Record<string, number> = {};
  for (const ev of sorted) by_type[ev.event_type] = (by_type[ev.event_type] ?? 0) + 1;

  const enumeratedTypes = new Set<string>();
  const rolledTypes = new Set<string>();
  for (const t of Object.keys(by_type)) {
    (resolveRenderPolicy(t, opts) === 'enumerate' ? enumeratedTypes : rolledTypes).add(t);
  }

  const demoted: string[] = [];
  const build = (): DeltaEntry[] => {
    const entries: DeltaEntry[] = [];
    const groups = new Map<string, ChainEvent[]>();
    for (const ev of sorted) {
      if (enumeratedTypes.has(ev.event_type)) {
        entries.push(toEntry(ev, 'enumerate', textLimit));
      } else {
        const g = groups.get(ev.event_type) ?? [];
        g.push(ev);
        groups.set(ev.event_type, g);
      }
    }
    for (const [t, evs] of groups) {
      entries.push(rollupFrom(evs, demoted.includes(t) ? 'budget' : 'volume-rollup', textLimit));
    }
    // Chain order: rollups sort by their first seq.
    entries.sort((a, b) => firstSeq(a) - firstSeq(b));
    return entries;
  };

  let entries = build();
  // Demote the most numerous enumerated type until the estimate fits.
  while (estimateTokens(entries) > opts.budget_tokens && enumeratedTypes.size > 0) {
    const victim = [...enumeratedTypes].sort((a, b) => (by_type[b] ?? 0) - (by_type[a] ?? 0))[0]!;
    enumeratedTypes.delete(victim);
    rolledTypes.add(victim);
    demoted.push(victim);
    entries = build();
  }
  let truncated = false;
  const cap = opts.max_entries ?? 500;
  if (entries.length > cap) {
    entries = entries.slice(entries.length - cap); // keep the most recent
    truncated = true;
  }

  const rolled = entries.filter((e): e is DeltaRollupEntry => e.kind === 'volume_rollup');
  return {
    from_seq,
    to_seq,
    events_since: sorted.length,
    by_type,
    entries,
    coverage: {
      total_events_in: sorted.length,
      enumerated: entries.filter((e) => e.kind === 'event').length,
      rolled_up: rolled.reduce((s, r) => s + r.count, 0),
      rollup_groups: rolled.length,
      demoted_by_budget: demoted,
      truncated,
      estimated_tokens: estimateTokens(entries),
    },
  };
}

function firstSeq(e: DeltaEntry): number {
  return e.kind === 'event' ? e.seq : e.first_seq;
}
