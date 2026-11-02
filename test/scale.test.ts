/**
 * 0.8.1 scale and robustness (hardening round 2, track 2):
 *
 *   C2-09  the local read log is bounded (latest reads per key, receipts
 *          folded behind a mark) and indexed, so `pending` costs what an
 *          actor read, not how often; a first-contact orient with
 *          focus=retractions answers from indexes.
 *   C2-10  a put identical to the document's current one appends nothing,
 *          decided under the write lock (concurrent imports of one edit).
 *
 * Perf guards count rows, statements and query plans, never wall time.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { ChainEvent } from '../src/chain/index.js';
import { foldDelta, rollupDelta, type TypeGroup } from '../src/orient/delta.js';
import { READS_COMPACTED_KEY, RECEIPTS_MARK_KEY } from '../src/lineage/read-log.js';
import { KronicleLite } from '../src/store.js';
import { cleanEnv, gitInit, runCli, tempDir, write } from './helpers/fs.js';

const open: KronicleLite[] = [];
afterEach(() => {
  for (const s of open.splice(0)) s.close();
});
function track(s: KronicleLite): KronicleLite {
  open.push(s);
  return s;
}

/** Rows per read-log key; the log keeps at most 3 (latest by head_seq, by read_at, by insertion). */
function maxRowsPerKey(kl: KronicleLite, actor?: string): number {
  const r = kl.db
    .prepare(`SELECT MAX(n) AS m FROM (SELECT COUNT(*) AS n FROM reads ${actor ? 'WHERE actor_id = ?' : ''} GROUP BY actor_id, block_id, doc_id, via)`)
    .get(...(actor ? [actor] : [])) as { m: number | null };
  return r.m ?? 0;
}

function indexes(kl: KronicleLite, table: string): string[] {
  return (kl.db.prepare(`SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = ? AND name NOT LIKE 'sqlite_%' ORDER BY name`).all(table) as { name: string }[]).map((r) => r.name);
}

function meta(kl: KronicleLite, key: string): string | null {
  return (kl.db.prepare(`SELECT value FROM meta WHERE key = ?`).get(key) as { value: string } | undefined)?.value ?? null;
}

/** Every SQL statement prepared while `fn` runs (Lineage caches statements, so use a fresh store). */
function preparedDuring(kl: KronicleLite, fn: () => void): string[] {
  const seen: string[] = [];
  const orig = kl.db.prepare.bind(kl.db);
  const spy = vi.spyOn(kl.db, 'prepare').mockImplementation(((sql: string) => {
    seen.push(sql);
    return orig(sql);
  }) as typeof kl.db.prepare);
  try {
    fn();
  } finally {
    spy.mockRestore();
  }
  return seen;
}

/**
 * Query-plan lines of `sql` that read a whole table or index of `tables`
 * (SCAN, by name or by alias) instead of a range (SEARCH).
 */
function fullScans(kl: KronicleLite, sql: string, tables: readonly string[]): string[] {
  const named = [...new Set(sql.match(/@\w+/g) ?? [])];
  const st = kl.db.prepare(`EXPLAIN QUERY PLAN ${sql}`);
  const plan = (named.length > 0 ? st.all(Object.fromEntries(named.map((n) => [n.slice(1), 'x']))) : st.all(...(sql.match(/\?/g) ?? []).map(() => 'x'))) as { detail: string }[];
  const names = new Set(tables);
  for (const t of tables) for (const m of sql.matchAll(new RegExp(`\\b${t}\\s+(?:AS\\s+)?(\\w+)`, 'gi'))) if (!/^(WHERE|ON|JOIN|GROUP|ORDER|UNION|LIMIT|USING|INNER|LEFT)$/i.test(m[1]!)) names.add(m[1]!);
  return plan.map((p) => p.detail).filter((d) => [...names].some((t) => new RegExp(`^SCAN ${t}\\b`).test(d)));
}

const MD = (port: number) => `# Deploy\n\nDeploy with port ${port}.\n\n## Owner\n\nOwner is team-a.\n`;

describe('C2-09: the read log is bounded and indexed', () => {
  it('repeat reads keep at most 3 rows per key; pending answers the same', () => {
    const kl = track(new KronicleLite({ memory: true }));
    kl.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: MD(8080), actor_id: 'w' });
    for (let i = 0; i < 200; i++) kl.recall.recall({ query: 'deploy port', top_k: 5, actor_id: 'agent' });
    const doc = kl.docs.getDocument('deploy')!;
    for (let i = 0; i < 50; i++) kl.lineage.recordDocumentRead('agent', doc.doc_id, 'document');
    for (let i = 0; i < 30; i++) kl.docs.putDocument({ slug: 'note', title: 'Note', markdown: `# Note\n\nPort 8080 (v${i}).\n`, actor_id: 'agent', infer_lineage: false });

    const keys = (kl.db.prepare(`SELECT COUNT(*) AS n FROM (SELECT DISTINCT actor_id, block_id, doc_id, via FROM reads)`).get() as { n: number }).n;
    const rows = (kl.db.prepare(`SELECT COUNT(*) AS n FROM reads`).get() as { n: number }).n;
    expect(maxRowsPerKey(kl)).toBeLessThanOrEqual(3);
    expect(rows).toBeLessThanOrEqual(3 * keys);
    // 200 recalls, 50 document reads, 30 writes: well over 300 reads recorded, a few dozen rows kept.
    expect(rows).toBeLessThan(60);
    // Receipts are kept (signed artifacts) and folded: the mark is the last receipt.
    const receipts = kl.db.prepare(`SELECT COUNT(*) AS n, MAX(rowid) AS m FROM receipts`).get() as { n: number; m: number };
    expect(receipts.n).toBeGreaterThanOrEqual(200);
    expect(Number(meta(kl, RECEIPTS_MARK_KEY))).toBe(receipts.m);

    expect(kl.lineage.pending('agent').count).toBe(0);
    kl.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: MD(9090), actor_id: 'w' });
    const p = kl.lineage.pending('agent');
    expect(p.count).toBe(1);
    expect(p.items[0]).toMatchObject({ kind: 'supersession', change: 'superseded', doc_slug: 'deploy' });
    kl.recall.recall({ query: 'deploy port', top_k: 5, actor_id: 'agent' });
    expect(kl.lineage.pending('agent').count).toBe(0);
  });

  it('pending, readCurrent and readersOf read the log and receipts by index range, never a full scan', () => {
    const kl = track(new KronicleLite({ memory: true }));
    const put = kl.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: MD(8080), actor_id: 'w' });
    for (let i = 0; i < 20; i++) kl.recall.recall({ query: 'deploy port', top_k: 5, actor_id: 'agent' });
    kl.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: MD(9090), actor_id: 'w' });
    const ids = put.blocks.map((b) => b.block_id);
    const sql = preparedDuring(kl, () => {
      kl.lineage.pending('agent');
      kl.lineage.readCurrent('agent', ids[1]!);
      kl.lineage.readersOf(ids, put.doc_id);
    });
    const touching = [...new Set(sql)].filter((s) => /\b(reads|receipts)\b/.test(s));
    expect(touching.length).toBeGreaterThanOrEqual(4);
    for (const s of touching) expect(fullScans(kl, s, ['reads', 'receipts']), s).toEqual([]);
  });

  it("recording a read prunes only that key's rows and folds only receipts after the mark (index ranges)", () => {
    const kl = track(new KronicleLite({ memory: true }));
    // First use of the log in this store, so its statements are prepared here.
    const sql = preparedDuring(kl, () => {
      kl.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: MD(8080), actor_id: 'w' });
      kl.recall.recall({ query: 'deploy port', top_k: 5, actor_id: 'agent' });
      kl.recall.recall({ query: 'deploy port', top_k: 5, actor_id: 'agent' });
    });
    const touching = [...new Set(sql)]
      .filter((x) => /\b(reads|receipts)\b/.test(x) && !/^\s*INSERT INTO \w+ \([^)]*\)\s*VALUES/i.test(x))
      .filter((x) => !/ROW_NUMBER/.test(x)); // the one-time compaction of a pre-0.8.1 log is a whole-log pass by design
    expect(touching.some((x) => /^\s*DELETE FROM reads/.test(x))).toBe(true);
    for (const s of touching) expect(fullScans(kl, s, ['reads', 'receipts']), s).toEqual([]);
  });
});

describe('C2-09: upgrade from a 0.8.0 store (forward-only)', () => {
  // test/fixtures/make-store-0.8.0.mjs, run with the published 0.8.0: an unpruned read log, an actor
  // with receipts only, and what 0.8.0 answered for it.
  const answers = JSON.parse(readFileSync(join(__dirname, 'fixtures', 'store-0.8.0.answers.json'), 'utf8')) as {
    pending: Record<string, unknown>;
    reads_rows: number;
    receipts_rows: number;
    infer_agent: unknown;
    readers: string[];
  };

  function upgraded(): KronicleLite {
    const dataDir = join(tempDir('kl-080-'), 'data');
    write(join(dataDir, 'kronicle-lite.db'), '');
    writeFileSync(join(dataDir, 'kronicle-lite.db'), gunzipSync(readFileSync(join(__dirname, 'fixtures', 'store-0.8.0.db.gz'))));
    return track(new KronicleLite({ dataDir }));
  }
  const allBlocks = (kl: KronicleLite) => (kl.db.prepare(`SELECT block_id FROM blocks ORDER BY block_id`).all() as { block_id: string }[]).map((r) => r.block_id);
  const sameAnswers = (kl: KronicleLite, ignore: readonly string[] = []) => {
    for (const [actor, want] of Object.entries(answers.pending)) expect(kl.lineage.pending(actor, { limit: 50 }), actor).toEqual(want);
    expect(kl.lineage.infer('agent', '1970-01-01T00:00:00.000Z', null)).toEqual(answers.infer_agent);
    expect(kl.lineage.readersOf(allBlocks(kl)).filter((a) => !ignore.includes(a))).toEqual(answers.readers);
  };

  it('opens with the new indexes and answers exactly as 0.8.0 did, before and after the one-time compaction', () => {
    const kl = upgraded();
    expect(indexes(kl, 'reads')).toEqual(expect.arrayContaining(['reads_actor_key_idx', 'reads_block_idx', 'reads_doc_idx']));
    expect(indexes(kl, 'receipts')).toContain('receipts_actor_rowid_idx');
    expect(answers.pending['agent']).toMatchObject({ count: 3 });
    expect(answers.pending['old']).toMatchObject({ count: 1 });

    // Opened, nothing written yet: the log is as 0.8.0 left it, receipts unfolded (mark 0).
    expect((kl.db.prepare(`SELECT COUNT(*) AS n FROM reads`).get() as { n: number }).n).toBe(answers.reads_rows);
    expect(meta(kl, RECEIPTS_MARK_KEY)).toBeNull();
    sameAnswers(kl);

    // The first read-log write compacts once and folds the receipts.
    const cache = kl.docs.getDocument('cache')!;
    kl.lineage.recordDocumentRead('probe', cache.doc_id, 'document');
    expect(meta(kl, READS_COMPACTED_KEY)).not.toBeNull();
    expect(Number(meta(kl, RECEIPTS_MARK_KEY))).toBe((kl.db.prepare(`SELECT MAX(rowid) AS m FROM receipts`).get() as { m: number }).m);
    expect(indexes(kl, 'reads')).not.toContain('reads_actor_block_idx');
    expect(maxRowsPerKey(kl)).toBeLessThanOrEqual(3);
    expect((kl.db.prepare(`SELECT COUNT(*) AS n FROM reads`).get() as { n: number }).n).toBeLessThan(answers.reads_rows / 2);
    // "old" read only through receipts (a 0.7.0 recall): folded into the log, one row per block.
    const oldRows = kl.db.prepare(`SELECT COUNT(*) AS n, COUNT(DISTINCT block_id) AS k FROM reads WHERE actor_id = 'old'`).get() as { n: number; k: number };
    expect(oldRows.n).toBeGreaterThan(0);
    expect(oldRows.n).toBe(oldRows.k);
    expect((kl.db.prepare(`SELECT COUNT(*) AS n FROM receipts`).get() as { n: number }).n).toBe(answers.receipts_rows);
    sameAnswers(kl, ['probe']);

    // Receipts a writer leaves unfolded after the mark (an older binary sharing the store) are still read.
    const before = kl.lineage.pending('late').count;
    kl.db
      .prepare(`INSERT INTO receipts (receipt_id, block_id, chain_seq, query_hash, issued_at, receipt_json, actor_id) SELECT 'late-1', block_id, chain_seq, query_hash, issued_at, receipt_json, 'late' FROM receipts WHERE actor_id = 'old' LIMIT 1`)
      .run();
    expect(before).toBe(0);
    expect(kl.lineage.pending('late').count).toBe(1);

    expect(kl.verifyAll().ok).toBe(true);
    // Reopening changes nothing (idempotent, forward-only).
    const dataDir = kl.dataDir!;
    kl.close();
    open.splice(open.indexOf(kl), 1);
    const again = track(new KronicleLite({ dataDir }));
    sameAnswers(again, ['probe', 'late']);
    expect(again.lineage.pending('late').count).toBe(1);
  });
});

describe('C2-09: first-contact orient with focus=retractions answers from indexes', () => {
  function bigStore(): KronicleLite {
    const kl = track(new KronicleLite({ memory: true }));
    // > 1000 events: one put of 1100 paragraphs, a second doc, then a supersession.
    kl.docs.putDocument({ slug: 'big', title: 'Big', markdown: Array.from({ length: 1100 }, (_, i) => `Paragraph ${i}.`).join('\n\n'), actor_id: 'w' });
    const put = kl.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: MD(8080), actor_id: 'w', project: { key: 'proj-a', root: '/a' } });
    kl.docs.supersedeBlock({ block_id: put.blocks[1]!.block_id, new_content: 'Deploy with port 9090.', reason: 'port', actor_id: 'w' });
    kl.docs.putDocument({ slug: 'other', title: 'Other', markdown: '# Other\n\nElsewhere.\n', actor_id: 'w', project: { key: 'proj-b', root: '/b' } });
    expect(kl.chain.head().seq).toBeGreaterThan(1100);
    return kl;
  }

  it('lists nothing to retract, never loads the chain, re-hashes a bounded window, and counts exactly like the full fold', () => {
    const kl = bigStore();
    const since = vi.spyOn(kl.chain, 'since');
    const s = kl.orient.getSystemState({ actor_id: 'newcomer', focus: 'retractions' });
    expect(since).not.toHaveBeenCalled();
    since.mockRestore();
    expect(s.recovery.method).toBe('genesis');
    expect(s.retractions).toEqual([]);
    expect(s.format_only_edits).toEqual([]);
    expect(s.integrity).toMatchObject({ ok: true, events_checked: 1000 });
    expect(s.integrity!.blocks_checked).toBeLessThanOrEqual(2000);
    expect(s.digest).not.toBeNull();
    const head = kl.chain.head();
    const full = foldDelta(kl.chain.since(0), 0, head.seq, { budget_tokens: 0 });
    expect(s.delta).toEqual({ ...full, entries: [] });
    // The second call is an ordinary flight-recorder briefing.
    expect(kl.orient.getSystemState({ actor_id: 'newcomer', focus: 'retractions' }).recovery.method).toBe('flight_recorder');
  });

  it('with a project scope, delta and hidden_events match the full path; an actor that read something keeps the full listing', () => {
    const kl = bigStore();
    // "reader" read before ever orienting: the full path (it may have relied on something).
    kl.recall.recall({ query: 'paragraph', top_k: 1, actor_id: 'reader' });
    const project = { keys: ['proj-a'] };
    const fast = kl.orient.getSystemState({ actor_id: 'newcomer', focus: 'retractions', project });
    const slow = kl.orient.getSystemState({ actor_id: 'reader', focus: 'retractions', project });
    expect(slow.recovery.method).toBe('genesis');
    expect(slow.retractions!.length).toBeGreaterThan(0);
    expect(fast.retractions).toEqual([]);
    expect(fast.delta).toEqual(slow.delta);
    expect(fast.scope).toEqual({ project_keys: ['proj-a'], hidden_retractions: 0, verdict: 'complete', hidden_events: slow.scope!.hidden_events });
    expect(slow.scope!.hidden_events).toBeGreaterThan(0);
  });

  it('the unscoped counts come from the (event_type, seq) index, not a table scan', () => {
    const kl = bigStore();
    const sql = preparedDuring(kl, () => kl.orient.getSystemState({ actor_id: 'newcomer', focus: 'retractions' }));
    const counts = sql.filter((s) => /GROUP BY event_type/.test(s));
    expect(counts).toHaveLength(1);
    const plan = (kl.db.prepare(`EXPLAIN QUERY PLAN ${counts[0]}`).all(1) as { detail: string }[]).map((p) => p.detail);
    expect(plan.join(' | ')).toMatch(/COVERING INDEX events_type_idx/);
  });

  it('rollupDelta reproduces foldDelta with no budget (ties, enumerate and rollup types, empty)', () => {
    const types = ['document.put', 'block.created', 'block.superseded', 'note.x', 'block.tombstoned', 'note.y'];
    const events: ChainEvent[] = [];
    let seq = 0;
    for (let i = 0; i < 300; i++) {
      const t = types[(i * 7 + (i % 5)) % types.length]!;
      seq++;
      events.push({ seq, event_id: `e${seq}`, event_type: t, payload: { n: i, content: 'x'.repeat(i % 300) }, actor_id: 'a', occurred_at: '2026-01-01T00:00:00.000Z', nonce: 'n', prev_hash: 'p', this_hash: `h${seq}` } as unknown as ChainEvent);
    }
    for (const evs of [events, events.slice(0, 7), events.filter((e) => e.event_type === 'note.x'), []]) {
      const groups = new Map<string, TypeGroup>();
      for (const e of evs) {
        const g = groups.get(e.event_type);
        if (g) groups.set(e.event_type, { ...g, count: g.count + 1, last_seq: e.seq, last: e });
        else groups.set(e.event_type, { event_type: e.event_type, count: 1, first_seq: e.seq, last_seq: e.seq, last: e });
      }
      expect(rollupDelta([...groups.values()].reverse(), 3, 400)).toEqual(foldDelta(evs, 3, 400, { budget_tokens: 0 }));
    }
  });
});

describe('C2-10: puts are idempotent by content', () => {
  it('an identical put appends nothing; any recorded difference still appends', () => {
    const kl = track(new KronicleLite({ memory: true }));
    const a = kl.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: MD(8080), actor_id: 'w' });
    const head = kl.chain.head();
    const same = kl.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: MD(8080), actor_id: 'other' });
    expect(same).toMatchObject({ doc_id: a.doc_id, revision: 1, chain_seq: a.chain_seq, events: 0, head });
    expect(kl.chain.head()).toEqual(head);
    // The writer still read what it wrote (its pending resolves against it).
    expect(kl.db.prepare(`SELECT COUNT(*) AS n FROM reads WHERE actor_id = 'other' AND via = 'write'`).get()).toEqual({ n: 1 + kl.docs.liveBlocks(a.doc_id).length });

    const revs = (args: Parameters<typeof kl.docs.putDocument>[0]) => kl.docs.putDocument(args).revision;
    expect(revs({ slug: 'deploy', title: 'Deploy v2', markdown: MD(8080), actor_id: 'w' })).toBe(2);
    expect(revs({ slug: 'deploy', title: 'Deploy v2', markdown: MD(8080), actor_id: 'w', project: { key: 'p', root: '/p' } })).toBe(3);
    expect(revs({ slug: 'deploy', title: 'Deploy v2', markdown: MD(8080), actor_id: 'w', project: { key: 'p', root: '/p' } })).toBe(3);
    expect(revs({ slug: 'deploy', title: 'Deploy v2', markdown: MD(8080), actor_id: 'w', source: { kind: 'file', path: 'd.md' } })).toBe(4);
    expect(revs({ slug: 'deploy', title: 'Deploy v2', markdown: MD(8080), actor_id: 'w', source: { kind: 'file', path: 'd.md' } })).toBe(4);
    expect(revs({ slug: 'deploy', title: 'Deploy v2', markdown: MD(8080), actor_id: 'w' })).toBe(5); // dropping the source is recorded
    expect(revs({ slug: 'deploy', title: 'Deploy v2', markdown: MD(8080), actor_id: 'w', derived_from: [] })).toBe(6); // explicit lineage
    expect(revs({ slug: 'deploy', title: 'Deploy v2', markdown: MD(8080), actor_id: 'w', idempotency_key: 'k1' })).toBe(7); // keyed puts keep their semantics
    expect(revs({ slug: 'deploy', title: 'Deploy v2', markdown: MD(8080), actor_id: 'w', idempotency_key: 'k1' })).toBe(7); // replay
    expect(kl.verifyAll().ok).toBe(true);
  });

  it('concurrent instruction imports of one edit append one revision per version (kl-import-race)', { timeout: 120_000 }, async () => {
    const root = tempDir('kl-race-');
    const home = tempDir('kl-race-home-');
    gitInit(root);
    const dataDir = join(tempDir('kl-race-data-'), 'd');
    const env = cleanEnv({ HOME: home, USERPROFILE: home });
    const claude = join(root, 'CLAUDE.md');
    write(claude, '# Rules\n\n## Deploy\n\nhost alpha\n');
    expect((await runCli(['put', '--from-instructions', '--cwd', root, '--data-dir', dataDir], { env })).status).toBe(0);
    const N = 8;
    for (const host of ['beta', 'gamma']) {
      write(claude, `# Rules\n\n## Deploy\n\nhost ${host}\n`);
      const runs = await Promise.all(
        Array.from({ length: N }, (_, i) =>
          i % 2 === 0
            ? runCli(['put', '--from-instructions', '--stdin-hook', '--data-dir', dataDir], { env, stdin: JSON.stringify({ session_id: `s${i}`, hook_event_name: 'FileChanged', cwd: root, file_path: claude }) })
            : runCli(['put', '--from-instructions', '--cwd', root, '--data-dir', dataDir], { env }),
        ),
      );
      for (const r of runs) expect(r.status, r.stderr).toBe(0);
    }
    const kl = track(new KronicleLite({ dataDir }));
    const puts = kl.chain.since(0).filter((e) => e.event_type === 'document.put' && String(e.payload['slug']).endsWith('/claude-md'));
    expect(puts.map((e) => /host (\w+)/.exec(String(e.payload['markdown']))?.[1])).toEqual(['alpha', 'beta', 'gamma']);
    expect(kl.verifyAll().ok).toBe(true);
  });
});
