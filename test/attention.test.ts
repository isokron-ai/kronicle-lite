/**
 * 0.6.0 attention rerank and response caps on recall.
 *  - Hits the same actor already read this session (receipts issued to it
 *    since the orient that issued its cursor) are ranked lower, never hidden.
 *  - Content is capped (max_chars) with a "truncated, read X" pointer.
 */

import { describe, expect, it } from 'vitest';

import { attentionRerank } from '../src/recall/attention.js';
import { KronicleLite } from '../src/store.js';

const MD = `# Ops

Deploy checklist: run the deploy smoke test first.

Deploy rollback: deploy the previous tag.

Deploy window: deploy on weekdays.
`;

describe('attentionRerank (pure)', () => {
  const hits = [
    { id: 'a', relevance: 3 },
    { id: 'b', relevance: 2 },
    { id: 'c', relevance: 1 },
  ];
  it('lowers already-read hits and never drops one', () => {
    const r = attentionRerank(hits, new Set(['a']));
    expect(r.map((h) => h.id)).toEqual(['b', 'a', 'c']);
    expect(r).toHaveLength(3);
    expect(r.find((h) => h.id === 'a')).toMatchObject({ already_read: true });
    expect(r.find((h) => h.id === 'b')).toMatchObject({ already_read: false });
  });
  it('keeps the original order when nothing was read, and is stable on ties', () => {
    expect(attentionRerank(hits, new Set()).map((h) => h.id)).toEqual(['a', 'b', 'c']);
    const ties = [{ id: 'x', relevance: 1 }, { id: 'y', relevance: 1 }];
    expect(attentionRerank(ties, new Set()).map((h) => h.id)).toEqual(['x', 'y']);
  });
  it('even with every hit read the set is unchanged (lowered together, not hidden)', () => {
    expect(attentionRerank(hits, new Set(['a', 'b', 'c'])).map((h) => h.id)).toEqual(['a', 'b', 'c']);
  });
});

describe('recall attention', () => {
  it('a block this actor already read in this session drops below an unread one; other actors are unaffected', () => {
    const store = new KronicleLite({ memory: true });
    store.docs.putDocument({ slug: 'ops', title: 'Ops', markdown: MD, actor_id: 't' });
    const s = store.orient.getSystemState({ actor_id: 'agent' });
    const since = store.orient.sessionStart('agent', s.cursor);
    expect(since).toBe(s.issued_at);

    const first = store.recall.recall({ query: 'deploy', actor_id: 'agent', session_since: since });
    expect(first.attention).toMatchObject({ actor_id: 'agent', already_read: 0 });
    const order1 = first.hits.map((h) => h.block_id);
    expect(order1.length).toBe(3);
    expect(first.hits.every((h) => h.already_read === false)).toBe(true);

    // Read only the top hit, by itself.
    const top = first.hits[0]!;
    const again = store.recall.recall({ query: 'deploy', actor_id: 'agent', session_since: since });
    // Everything was read by the first call: the set and order are unchanged (all lowered together).
    expect(again.hits.map((h) => h.block_id)).toEqual(order1);
    expect(again.hits.every((h) => h.already_read)).toBe(true);

    // A fresh session (new orient) for a second actor that read only the top block.
    const s2 = store.orient.getSystemState({ actor_id: 'other' });
    const since2 = store.orient.sessionStart('other', s2.cursor_compact)!;
    store.recall.recall({ query: 'smoke test', actor_id: 'other', session_since: since2, top_k: 1 });
    const r = store.recall.recall({ query: 'deploy', actor_id: 'other', session_since: since2 });
    expect(r.hits).toHaveLength(3);
    const readHit = r.hits.find((h) => h.content.includes('smoke'))!;
    expect(readHit.already_read).toBe(true);
    expect(r.hits[r.hits.length - 1]!.block_id).toBe(readHit.block_id);
    expect(r.attention).toMatchObject({ actor_id: 'other', already_read: 1 });
    // Scores are reported raw; only the order changed.
    expect(typeof readHit.score).toBe('number');
    expect(top).toBeDefined();
    store.close();
  });

  it('no actor or no session → no rerank (attention null); reads before the session start do not count', async () => {
    const store = new KronicleLite({ memory: true });
    store.docs.putDocument({ slug: 'ops', title: 'Ops', markdown: MD, actor_id: 't' });
    store.recall.recall({ query: 'smoke', actor_id: 'agent', top_k: 1 });
    await new Promise((r) => setTimeout(r, 5)); // issued_at has millisecond resolution
    expect(store.recall.recall({ query: 'deploy' }).attention).toBeNull();
    expect(store.orient.sessionStart('agent')).toBeNull(); // never oriented
    const s = store.orient.getSystemState({ actor_id: 'agent' });
    const r = store.recall.recall({ query: 'deploy', actor_id: 'agent', session_since: store.orient.sessionStart('agent', s.cursor) });
    expect(r.hits.every((h) => !h.already_read)).toBe(true);
    // Without a cursor the actor's latest orient opens the session.
    expect(store.orient.sessionStart('agent')).toBe(s.issued_at);
    // A cursor issued to someone else is ignored (falls back to the actor's own latest orient).
    const o = store.orient.getSystemState({ actor_id: 'other' });
    expect(store.orient.sessionStart('agent', o.cursor)).toBe(s.issued_at);
    store.close();
  });
});

describe('recall response caps', () => {
  it('content over max_chars is cut with a pointer to the whole document; receipts still cover the whole block', () => {
    const store = new KronicleLite({ memory: true });
    const long = 'Overflow paragraph ' + 'word '.repeat(2000);
    store.docs.putDocument({ slug: 'big', title: 'Big', markdown: `# Big\n\n${long}\n\nShort overflow note.\n`, actor_id: 't' });
    const r = store.recall.recall({ query: 'overflow', max_chars: 1000 });
    expect(r.hits).toHaveLength(2);
    const total = r.hits.reduce((n, h) => n + h.content.length, 0);
    expect(total).toBeLessThanOrEqual(1000);
    const cut = r.hits.find((h) => h.truncated)!;
    expect(cut.truncated).toMatchObject({ total_chars: long.trim().length, read: 'kronicle://docs/big' });
    expect(cut.content.length).toBe(cut.truncated!.shown_chars);
    expect(long.trim().startsWith(cut.content)).toBe(true);
    const short = r.hits.find((h) => !h.truncated)!;
    expect(short.content).toBe('Short overflow note.');
    expect(r.truncated).toMatchObject({ hits: 1, max_chars: 1000 });
    expect(r.truncated!.hint).toMatch(/max_chars/);
    expect(r.truncated!.hint).toMatch(/kronicle:\/\/docs\//);
    expect(store.verifier.verify(cut.receipt).status).toBe('VERIFIED');
    // Default budget leaves small results alone.
    const small = store.recall.recall({ query: 'short note' });
    expect(small.truncated).toBeNull();
    expect(small.hits[0]!.truncated).toBeUndefined();
    store.close();
  });
});

describe('receipts.actor_id (additive local column)', () => {
  it('a database created before 0.6.0 gains the column on open; old receipts keep verifying', async () => {
    const { join } = await import('node:path');
    const { tempDir } = await import('./helpers/fs.js');
    const dataDir = join(tempDir('kl-actor-col-'), 'data');
    const a = new KronicleLite({ dataDir });
    a.docs.putDocument({ slug: 'ops', title: 'Ops', markdown: MD, actor_id: 't' });
    const old = a.recall.recall({ query: 'smoke' });
    expect(old.hits.length).toBeGreaterThan(0);
    // Back to the 0.5.0 table shape.
    a.db.exec('DROP INDEX receipts_actor_idx; ALTER TABLE receipts DROP COLUMN actor_id;');
    a.close();
    const b = new KronicleLite({ dataDir });
    const cols = (b.db.prepare(`SELECT name FROM pragma_table_info('receipts')`).all() as { name: string }[]).map((r) => r.name);
    expect(cols).toContain('actor_id');
    expect(b.verifier.verify(old.hits[0]!.receipt).status).toBe('VERIFIED');
    expect(b.recall.getReceipt(old.hits[0]!.receipt!.receipt_id)).toEqual(old.hits[0]!.receipt);
    expect(b.recall.recall({ query: 'smoke', actor_id: 'x', session_since: '1970-01-01T00:00:00.000Z' }).hits.length).toBeGreaterThan(0);
    expect(b.chain.verify().ok).toBe(true);
    b.close();
  });
});
