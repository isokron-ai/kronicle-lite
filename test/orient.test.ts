import { describe, expect, it } from 'vitest';

import { Chain, type ChainEvent } from '../src/chain/index.js';
import { openDatabase } from '../src/db/open.js';
import { DocumentStore } from '../src/docs/documents.js';
import {
  CursorTokenError,
  parseAnyCursor,
  parseCompactCursor,
  parseCursor,
  serializeCompactCursor,
  serializeCursor,
} from '../src/orient/cursor.js';
import { foldDelta, resolveRenderPolicy } from '../src/orient/delta.js';
import { composeDriftBanner, composeStaleWriteAdvisory } from '../src/orient/drift.js';
import { Orient } from '../src/orient/orient.js';
import { classifyRetraction, computeRetractions } from '../src/orient/retraction.js';

const SECRET = 'a'.repeat(64);

function fresh() {
  const { db, identity } = openDatabase({ memory: true });
  const chain = new Chain(db, identity.signer);
  const docs = new DocumentStore(db, chain);
  const orient = new Orient(db, chain, docs, identity.cursor_secret);
  return { db, identity, chain, docs, orient };
}

function ev(seq: number, event_type: string, payload: Record<string, unknown> = {}): ChainEvent {
  return {
    seq,
    event_id: `00000000-0000-4000-8000-${String(seq).padStart(12, '0')}`,
    event_type,
    payload,
    actor_id: 'a',
    occurred_at: '2026-01-01T00:00:00.000Z',
    nonce: '00'.repeat(16),
    prev_hash: '0'.repeat(64),
    this_hash: seq.toString(16).padStart(64, '0'),
    idempotency_key: null,
  };
}

describe('cursor tokens', () => {
  const body = { actor_id: 'alice', chain_seq: 42, chain_hash: 'b'.repeat(64), issued_at: '2026-01-01T00:00:00Z' };

  it('round-trips the full form', () => {
    const tok = serializeCursor(body, SECRET);
    expect(tok.startsWith('sxt1.')).toBe(true);
    expect(parseCursor(tok, SECRET)).toEqual(body);
  });

  it('rejects tampering, wrong secret and bad format', () => {
    const tok = serializeCursor(body, SECRET);
    const [v, b, s] = tok.split('.');
    const tamperedBody = Buffer.from(JSON.stringify({ ...body, chain_seq: 1 })).toString('base64url');
    expect(() => parseCursor(`${v}.${tamperedBody}.${s}`, SECRET)).toThrow(CursorTokenError);
    expect(() => parseCursor(`${v}.${b}.${s!.slice(0, -2)}xx`, SECRET)).toThrow(/signature/);
    expect(() => parseCursor(tok, 'b'.repeat(64))).toThrow(/signature/);
    expect(() => parseCursor('nope', SECRET)).toThrow(/three/);
    expect(() => parseCursor(`sxt9.${b}.${s}`, SECRET)).toThrow(/unknown format/);
    expect(() => parseCursor(tok, '')).toThrow(/empty secret/);
  });

  it('compact form binds to the actor', () => {
    const tok = serializeCompactCursor('alice', 7, SECRET);
    expect(tok).toMatch(/^sxt1c\.7\.[A-Za-z0-9_-]{8}$/);
    expect(parseCompactCursor(tok, 'alice', SECRET)).toEqual({ chain_seq: 7 });
    expect(() => parseCompactCursor(tok, 'bob', SECRET)).toThrow(/signature/);
    expect(() => parseCompactCursor('sxt1c.8.' + tok.split('.')[2], 'alice', SECRET)).toThrow(/signature/);
    expect(parseAnyCursor(tok, 'alice', SECRET)).toEqual({ form: 'compact', chain_seq: 7 });
    expect(parseAnyCursor(serializeCursor(body, SECRET), 'alice', SECRET)).toEqual({ form: 'full', body });
  });
});

describe('delta fold', () => {
  it('enumerates by default, rolls up block.created, keeps chain order', () => {
    expect(resolveRenderPolicy('block.created')).toBe('volume-rollup');
    expect(resolveRenderPolicy('block.tombstoned')).toBe('enumerate');
    // Companion work-queue claim churn rolls up by default; force-releases do not.
    expect(resolveRenderPolicy('sea_ticket.claimed')).toBe('volume-rollup');
    expect(resolveRenderPolicy('sea_ticket.claim_released')).toBe('volume-rollup');
    expect(resolveRenderPolicy('sea_ticket.claim_expired')).toBe('volume-rollup');
    expect(resolveRenderPolicy('sea_ticket.claim_force_released')).toBe('enumerate');
    expect(resolveRenderPolicy('sea_ticket.created')).toBe('enumerate');
    expect(resolveRenderPolicy('block.created', { never_rollup_event_types: ['block.created'] })).toBe('enumerate');
    expect(resolveRenderPolicy('x.y', { overrides: { 'x.y': 'volume-rollup' } })).toBe('volume-rollup');
    const events = [ev(1, 'document.put'), ev(2, 'block.created'), ev(3, 'block.created'), ev(4, 'block.tombstoned')];
    const d = foldDelta(events, 0, 4, { budget_tokens: 10_000 });
    expect(d.events_since).toBe(4);
    expect(d.by_type).toEqual({ 'document.put': 1, 'block.created': 2, 'block.tombstoned': 1 });
    expect(d.entries.map((e) => e.kind)).toEqual(['event', 'volume_rollup', 'event']);
    const roll = d.entries[1]!;
    expect(roll.kind === 'volume_rollup' && roll.count === 2 && roll.first_seq === 2 && roll.last_seq === 3).toBe(true);
    expect(d.coverage).toMatchObject({ enumerated: 2, rolled_up: 2, rollup_groups: 1, demoted_by_budget: [] });
  });

  it('demotes enumerated types to rollups when over budget, never drops facts', () => {
    const events: ChainEvent[] = [];
    for (let i = 1; i <= 60; i++) events.push(ev(i, i % 2 ? 'block.superseded' : 'document.revised', { reason: 'x'.repeat(50) }));
    const d = foldDelta(events, 0, 60, { budget_tokens: 300 });
    expect(d.coverage.demoted_by_budget.length).toBeGreaterThan(0);
    const total = d.coverage.enumerated + d.coverage.rolled_up;
    expect(total).toBe(60);
    expect(d.coverage.estimated_tokens).toBeLessThanOrEqual(300 + 50);
    const big = foldDelta(events, 0, 60, { budget_tokens: 100_000 });
    expect(big.coverage.demoted_by_budget).toEqual([]);
    expect(big.coverage.enumerated).toBe(60);
  });
});

describe('retraction classifier', () => {
  it('classifies explicit types and suffix rules with severities', () => {
    const t = classifyRetraction(ev(5, 'block.tombstoned', { block_id: 'b1', doc_slug: 'd', reason: 'wrong' }))!;
    expect(t).toMatchObject({ kind: 'tombstone', severity: 'safety', block_id: 'b1', doc_slug: 'd', seq: 5 });
    expect(t.reason_line).toMatch(/^You previously relied on .* current truth is .* Reconcile before proceeding\.$/);
    expect(t.reason_line).toContain('wrong');
    const s = classifyRetraction(ev(6, 'block.superseded', { block_id: 'b1', successor_block_id: 'b2' }))!;
    expect(s).toMatchObject({ kind: 'supersession', severity: 'behavioral', successor_block_id: 'b2' });
    expect(classifyRetraction(ev(7, 'custom.thing.retracted', { id: 'z' }))).toMatchObject({
      kind: 'retraction',
      block_id: 'z',
    });
    expect(classifyRetraction(ev(8, 'policy.tombstoned'))).toMatchObject({ kind: 'tombstone' });
    expect(classifyRetraction(ev(9, 'block.created'))).toBeNull();
    expect(classifyRetraction(ev(10, 'document.put'))).toBeNull();
  });

  it('orders safety first then by seq', () => {
    const list = computeRetractions([
      ev(1, 'block.superseded'),
      ev(2, 'block.tombstoned'),
      ev(3, 'block.created'),
      ev(4, 'block.superseded'),
    ]);
    expect(list.map((r) => r.seq)).toEqual([2, 1, 4]);
  });
});

describe('drift banner + stale write advisory', () => {
  it('first contact is not surfaced', () => {
    const b = composeDriftBanner({ events_since_last_orient: null, seconds_since_last_orient: null });
    expect(b.surfaced).toBe(false);
    expect(b.line).toMatch(/first contact/);
  });
  it('surfaces at >=100 events or >=4h', () => {
    expect(composeDriftBanner({ events_since_last_orient: 99, seconds_since_last_orient: 60 }).surfaced).toBe(false);
    expect(composeDriftBanner({ events_since_last_orient: 100, seconds_since_last_orient: 60 }).surfaced).toBe(true);
    expect(composeDriftBanner({ events_since_last_orient: 0, seconds_since_last_orient: 4 * 3600 - 1 }).surfaced).toBe(false);
    const b = composeDriftBanner({ events_since_last_orient: 3, seconds_since_last_orient: 4 * 3600 });
    expect(b.surfaced).toBe(true);
    expect(b.line).toContain('⚠️ 3 changes');
    expect(b.line).toContain('4h ago');
    expect(composeDriftBanner({ events_since_last_orient: 1, seconds_since_last_orient: 5 }).line).toContain('1 change ');
  });
  it('advisory for never-oriented and drifted actors only', () => {
    expect(composeStaleWriteAdvisory({ events_since_last_orient: null, seconds_since_last_orient: null }).advisory).toBe(true);
    expect(composeStaleWriteAdvisory({ events_since_last_orient: 5, seconds_since_last_orient: 10 })).toMatchObject({
      advisory: false,
      line: null,
    });
    const a = composeStaleWriteAdvisory({ events_since_last_orient: 150, seconds_since_last_orient: 10 });
    expect(a.advisory).toBe(true);
    expect(a.line).toMatch(/Write accepted, but 150 changes/);
  });
});

describe('Orient.getSystemState', () => {
  it('cold start: genesis recovery, digest, fresh cursor, flight record written', () => {
    const { orient, docs } = fresh();
    docs.putDocument({ slug: 'a', title: 'A', markdown: '# A\n\nalpha', actor_id: 'w' });
    const s = orient.getSystemState({ actor_id: 'agent-1' });
    expect(s.recovery.method).toBe('genesis');
    expect(s.recovery.from_seq).toBe(0);
    expect(s.digest).toMatchObject({ documents: 1, live_blocks: 2 });
    expect(s.delta?.events_since).toBe(3);
    expect(s.drift_banner.surfaced).toBe(false);
    expect(s.stale_write_advisory.advisory).toBe(true); // never oriented before this call
    expect(s.cursor.startsWith('sxt1.')).toBe(true);
    expect(s.cursor_compact.startsWith('sxt1c.')).toBe(true);
    expect(s.head.seq).toBe(3);
    const rec = orient.recorder.latestForActor('agent-1')!;
    expect(rec.briefing_id).toBe(s.briefing_id);
    expect(rec.to_seq).toBe(3);
    expect(s.next_steps.some((l) => /Cold start/.test(l))).toBe(true);
  });

  it('warm wake with a cursor returns only the delta since it', () => {
    const { orient, docs } = fresh();
    docs.putDocument({ slug: 'a', title: 'A', markdown: 'alpha', actor_id: 'w' });
    const s1 = orient.getSystemState({ actor_id: 'agent-1' });
    const put = docs.putDocument({ slug: 'b', title: 'B', markdown: 'beta\n\ngamma', actor_id: 'w' });
    docs.tombstoneBlock({ block_id: put.blocks[0]!.block_id, reason: 'oops', actor_id: 'w' });
    const s2 = orient.getSystemState({ actor_id: 'agent-1', since_cursor: s1.cursor, focus: 'recent_changes' });
    expect(s2.recovery.method).toBe('presented');
    expect(s2.recovery.from_seq).toBe(s1.head.seq);
    expect(s2.delta?.events_since).toBe(5); // put + 2 created + tombstoned + revised
    expect(s2.digest).toBeNull();
    expect(s2.retractions).toHaveLength(1);
    expect(s2.retractions![0]).toMatchObject({ kind: 'tombstone', block_id: put.blocks[0]!.block_id, doc_slug: 'b' });
    expect(s2.stale_write_advisory.advisory).toBe(false);
    // compact works too
    const s3 = orient.getSystemState({ actor_id: 'agent-1', since_cursor: s2.cursor_compact });
    expect(s3.recovery.method).toBe('presented_compact');
    expect(s3.delta?.events_since).toBe(0);
  });

  it('invalid cursor recovers from the flight recorder; another actor cold-starts', () => {
    const { orient, docs } = fresh();
    docs.putDocument({ slug: 'a', title: 'A', markdown: 'alpha', actor_id: 'w' });
    const s1 = orient.getSystemState({ actor_id: 'agent-1' });
    docs.putDocument({ slug: 'c', title: 'C', markdown: 'x', actor_id: 'w' });
    const s2 = orient.getSystemState({ actor_id: 'agent-1', since_cursor: 'sxt1.garbage.garbage' });
    expect(s2.recovery.method).toBe('flight_recorder');
    expect(s2.recovery.cursor_error).toMatch(/cursor token/);
    expect(s2.recovery.from_seq).toBe(s1.head.seq);
    expect(s2.delta?.events_since).toBe(2);
    expect(s2.next_steps[0]).toMatch(/rejected/);
    // Cursor issued to another actor is rejected and falls back.
    const other = orient.getSystemState({ actor_id: 'agent-2', since_cursor: s2.cursor });
    expect(other.recovery.method).toBe('genesis');
    expect(other.recovery.cursor_error).toMatch(/issued to actor/);
    // A cursor whose hash is no longer on the chain (chain rewritten) is presented_stale.
    const { orient: o2, docs: d2 } = fresh();
    d2.putDocument({ slug: 'a', title: 'A', markdown: 'alpha', actor_id: 'w' });
    const stale = o2.getSystemState({ actor_id: 'agent-1', since_cursor: s1.cursor });
    // Different secret in the fresh store → signature fails → genesis, not stale.
    expect(stale.recovery.method).toBe('genesis');
  });

  it('drift banner surfaces after many events; pulse is cheap and unrecorded', () => {
    const { orient, docs, chain } = fresh();
    const s1 = orient.getSystemState({ actor_id: 'agent-1' });
    for (let i = 0; i < 120; i++) chain.append({ event_type: 'note.added', payload: { i }, actor_id: 'w' });
    const pulse = orient.getSystemState({ actor_id: 'agent-1', since_cursor: s1.cursor, focus: 'pulse' });
    expect(pulse.drift_banner.surfaced).toBe(true);
    expect(pulse.drift_banner.events_since_last_orient).toBe(120);
    expect(pulse.delta).toBeNull();
    expect(orient.recorder.findByActor('agent-1')).toHaveLength(1);
    expect(orient.staleWriteAdvisory('agent-1', s1.cursor).advisory).toBe(true);
    const s2 = orient.getSystemState({ actor_id: 'agent-1', since_cursor: s1.cursor });
    expect(s2.drift_banner.surfaced).toBe(true);
    expect(s2.delta?.events_since).toBe(120);
    expect(orient.staleWriteAdvisory('agent-1', s2.cursor).advisory).toBe(false);
    docs.putDocument({ slug: 'z', title: 'z', markdown: 'z', actor_id: 'w' });
    expect(orient.staleWriteAdvisory('agent-1').advisory).toBe(false);
    expect(orient.staleWriteAdvisory('nobody').advisory).toBe(true);
  });

  it('time threshold surfaces the banner via injected clock', () => {
    const { orient } = fresh();
    const t0 = new Date('2026-01-01T00:00:00Z');
    orient.getSystemState({ actor_id: 'a' }, t0);
    const later = new Date(t0.getTime() + 5 * 3600 * 1000);
    const s = orient.getSystemState({ actor_id: 'a', focus: 'pulse' }, later);
    expect(s.drift_banner.surfaced).toBe(true);
    expect(s.drift_banner.seconds_since_last_orient).toBe(5 * 3600);
    expect(orient.staleWriteAdvisory('a', undefined, later).advisory).toBe(true);
  });

  it('retractions focus returns counts but no delta entries', () => {
    const { orient, docs } = fresh();
    const put = docs.putDocument({ slug: 'a', title: 'A', markdown: 'one\n\ntwo', actor_id: 'w' });
    const c0 = orient.getSystemState({ actor_id: 'a', focus: 'pulse' }).cursor;
    docs.supersedeBlock({ block_id: put.blocks[0]!.block_id, new_content: 'uno', reason: 'es', actor_id: 'w' });
    const s = orient.getSystemState({ actor_id: 'a', since_cursor: c0, focus: 'retractions' });
    expect(s.delta?.entries).toEqual([]);
    expect(s.delta?.by_type['block.superseded']).toBe(1);
    expect(s.retractions).toHaveLength(1);
    expect(s.retractions![0]!.successor_block_id).toBeTruthy();
  });

  it('0.8.1: retractions focus at first contact (never oriented, never read) lists none, counts from the index', () => {
    const { orient, docs } = fresh();
    const put = docs.putDocument({ slug: 'a', title: 'A', markdown: 'one\n\ntwo', actor_id: 'w' });
    docs.supersedeBlock({ block_id: put.blocks[0]!.block_id, new_content: 'uno', reason: 'es', actor_id: 'w' });
    const s = orient.getSystemState({ actor_id: 'a', focus: 'retractions' });
    expect(s.recovery.method).toBe('genesis');
    expect(s.retractions).toEqual([]);
    expect(s.delta?.entries).toEqual([]);
    expect(s.delta?.by_type).toEqual({ 'document.put': 1, 'block.created': 3, 'block.superseded': 1 });
    expect(s.digest).not.toBeNull(); // genesis recovery still gets the digest
    expect(s.integrity?.ok).toBe(true);
  });
});
