/**
 * 0.8.1: hardening round 2, track 1 (lineage, pulse/pending, integrity,
 * secret guard) plus the live-agent (L2-01, L2-03) and chaos (C2-03..05)
 * findings that share their code. One regression test per finding; the
 * stress probes that found them live in agent-memory-bench
 * (stress/kl/r2-*.mjs, track-b/probes, stress/chaos).
 *
 * Every store lives in a temp dir; HOME and KRONICLE_LITE_DATA_DIR are
 * pinned to temp paths so nothing can reach a real ~/.kronicle-lite.
 */

import { closeSync, openSync, readdirSync, rmSync, writeFileSync, writeSync } from 'node:fs';
import { join } from 'node:path';

import Database from 'better-sqlite3';
import { beforeAll, describe, expect, it } from 'vitest';

import { scanForSecrets, scrubForRead } from '../src/secrets/guard.js';
import { pulse } from '../src/shim/pulse.js';
import { KronicleLite } from '../src/store.js';
import { tempDir } from './helpers/fs.js';

beforeAll(() => {
  const sb = tempDir('kl-081-li-');
  process.env['HOME'] = join(sb, 'home');
  process.env['KRONICLE_LITE_DATA_DIR'] = join(sb, 'no-default-store');
});

const RUNBOOK = (target: string) => `# Deploy runbook\n\n## Steps\n\nDeploy with ./bin/deploy --target ${target}.\n\nNotify #ops after the deploy.\n`;

function open(dir?: string): KronicleLite {
  return dir ? new KronicleLite({ dataDir: dir }) : new KronicleLite({ memory: true });
}

function withRunbook(dir?: string) {
  const store = open(dir);
  store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: RUNBOOK('staging-a'), actor_id: 'ops' });
  return store;
}

const hit = (store: KronicleLite, q: string, slug: string, actor = 'reader') => store.recall.recall({ query: q, actor_id: actor }).hits.find((h) => h.doc_slug === slug);
const docId = (store: KronicleLite, slug: string) => store.docs.getDocument(slug)!.doc_id;

describe('R2-04: inference keeps reads across a re-orient; undetermined lineage is never can_act', () => {
  it('a file-backed note written after recall → orient → put goes never_act when its source changes (was can_act)', () => {
    const dir = tempDir('kl-li-');
    const store = withRunbook(dir);
    const f = join(dir, 'NOTES.md');
    const md = '# Notes\n\nWe deploy to staging-a.\n';
    writeFileSync(f, md);
    store.orient.getSystemState({ actor_id: 'agent' });
    store.recall.recall({ query: 'deploy target', actor_id: 'agent' });
    store.orient.getSystemState({ actor_id: 'agent' }); // the wake contract: orient before writing
    store.docs.putDocument({ slug: 'note', title: 'note', markdown: md, actor_id: 'agent', source: { kind: 'file', path: f } });
    expect(hit(store, 'deploy staging note', 'note')).toMatchObject({ authority: 'can_act' });
    store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: RUNBOOK('staging-b'), actor_id: 'ops' });
    expect(hit(store, 'deploy staging note', 'note')).toMatchObject({ authority: 'never_act', authority_reason: 'stale_derived' });
    store.close();
  });

  it('a note whose inference the bound cut short (truncated) is inspect_only / lineage_unknown, even when its file matches', () => {
    const dir = tempDir('kl-li-');
    const store = withRunbook(dir);
    const f = join(dir, 'NOTES.md');
    const md = '# Notes\n\nWe deploy to staging-a.\n';
    writeFileSync(f, md);
    store.recall.recall({ query: 'deploy target', actor_id: 'agent' });
    const old = new Date(Date.now() - 30 * 3600_000).toISOString();
    store.db.prepare(`UPDATE reads SET read_at = ? WHERE actor_id = 'agent'`).run(old);
    store.db.prepare(`UPDATE receipts SET issued_at = ? WHERE actor_id = 'agent'`).run(old);
    const put = store.docs.putDocument({ slug: 'note', title: 'note', markdown: md, actor_id: 'agent', source: { kind: 'file', path: f } });
    expect(put.lineage).toMatchObject({ derived_from_inferred_truncated: true });
    expect(store.lineage.assess(put.doc_id).undetermined).toBe('inference_bound');
    expect(hit(store, 'deploy staging note', 'note')).toMatchObject({ authority: 'inspect_only', authority_reason: 'lineage_unknown' });
    expect(store.verifyAll().ok).toBe(true);
    // An explicit statement determines it again.
    store.docs.putDocument({ slug: 'note', title: 'note', markdown: md, actor_id: 'agent', source: { kind: 'file', path: f }, derived_from: [], infer_lineage: false });
    expect(hit(store, 'deploy staging note', 'note')).toMatchObject({ authority: 'can_act' });
    expect(store.verifyAll().ok).toBe(true);
    store.close();
  });
});

describe('R2-05: staleness memo is never poisoned by a cut-short walk', () => {
  it('cycle: B (derived from A, which is stale) is never_act whether or not A ranks first in the same recall', () => {
    const store = withRunbook();
    store.orient.getSystemState({ actor_id: 'agent', focus: 'pulse' });
    store.recall.recall({ query: 'deploy target', actor_id: 'agent' });
    store.docs.putDocument({ slug: 'nota', title: 'A', markdown: '# A\n\nkilo fact kilo fact kilo fact: deploy to staging-a.\n', actor_id: 'agent' });
    store.orient.getSystemState({ actor_id: 'b', focus: 'pulse' });
    store.recall.recall({ query: 'kilo fact', actor_id: 'b' });
    store.docs.putDocument({ slug: 'notb', title: 'B', markdown: '# B\n\nlima builds on the kilo fact.\n', actor_id: 'b' });
    store.orient.getSystemState({ actor_id: 'agent', focus: 'pulse' });
    store.recall.recall({ query: 'lima builds', actor_id: 'agent' });
    store.docs.putDocument({ slug: 'nota', title: 'A', markdown: '# A\n\nkilo fact kilo fact kilo fact: deploy to staging-a.\n\nSee also lima.\n', actor_id: 'agent' });
    store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: RUNBOOK('staging-b'), actor_id: 'ops' });
    const together = store.recall.recall({ query: 'kilo fact', actor_id: 'r' }).hits.map((h) => [h.doc_slug, h.authority]);
    expect(together.length).toBeGreaterThanOrEqual(2);
    for (const [, a] of together) expect(a).toBe('never_act');
    const memo = new Map();
    expect(store.lineage.staleness(docId(store, 'nota'), memo).length).toBeGreaterThan(0);
    expect(store.lineage.staleness(docId(store, 'notb'), memo).length).toBeGreaterThan(0);
    store.close();
  });

  it('depth: a chain of 6 notes; n5 is stale (the bound is 4 below), n6 is undetermined; serving n6 first never unmarks n2', () => {
    const store = withRunbook();
    store.orient.getSystemState({ actor_id: 'agent', focus: 'pulse' });
    store.recall.recall({ query: 'deploy target', actor_id: 'agent' });
    store.docs.putDocument({ slug: 'n1', title: 'N1', markdown: '# N1\n\nzulu1 deploy to staging-a.\n', actor_id: 'agent' });
    for (let i = 2; i <= 6; i++) {
      // A fresh actor per note, reading only the previous note (no other reads in its window).
      store.recall.recall({ query: `zulu${i - 1}`, actor_id: `a${i}` });
      store.docs.putDocument({ slug: `n${i}`, title: `N${i}`, markdown: `# N${i}\n\nzulu${i} relies on zulu${i - 1} and shared${i === 6 || i === 2 ? 'term' : ''}.\n`, actor_id: `a${i}` });
    }
    store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: RUNBOOK('staging-b'), actor_id: 'ops' });
    // Kills the "MAX_DERIVED_DEPTH 4 → 1" mutant: n3..n5 are 2..4 notes below n1.
    for (const n of ['n1', 'n2', 'n3', 'n4', 'n5']) expect(store.lineage.staleness(docId(store, n)).length, n).toBeGreaterThan(0);
    expect(store.lineage.staleness(docId(store, 'n6'))).toEqual([]);
    expect(store.lineage.assess(docId(store, 'n6')).undetermined).toBe('depth_bound');
    expect(store.lineage.assess(docId(store, 'n5')).undetermined).toBeNull();
    const both = store.recall.recall({ query: 'sharedterm', actor_id: 'r' }).hits.map((h) => [h.doc_slug, h.authority, h.authority_reason]);
    expect(both.find((h) => h[0] === 'n2')).toEqual(['n2', 'never_act', 'stale_derived']);
    expect(both.find((h) => h[0] === 'n6')?.[1]).not.toBe('can_act');
    store.close();
  });
});

describe('R2-14: re-deriving a note after its source was removed clears it', () => {
  function removed() {
    const store = withRunbook();
    store.orient.getSystemState({ actor_id: 'agent', focus: 'pulse' });
    store.recall.recall({ query: 'deploy target', actor_id: 'agent' });
    store.docs.putDocument({ slug: 'note', title: 'Note', markdown: '# Note\n\nWe deploy to staging-a.\n', actor_id: 'agent' });
    // The instruction moves to another document: removed here, added there.
    store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: '# Deploy runbook\n\n## Steps\n\nNotify #ops after the deploy.\n', actor_id: 'ops' });
    store.docs.putDocument({ slug: 'deploy-v2', title: 'Deploy v2', markdown: '# Deploy v2\n\nDeploy with ./bin/deploy2 --target staging-c.\n', actor_id: 'ops' });
    expect(store.lineage.staleness(docId(store, 'note'))[0]).toMatchObject({ change: 'tombstoned' });
    return store;
  }

  it('rewriting the note from material read after the removal releases the dead edge (on the chain; rebuild agrees)', () => {
    const store = removed();
    store.orient.getSystemState({ actor_id: 'agent', focus: 'pulse' });
    store.recall.recall({ query: 'deploy2 target', actor_id: 'agent' });
    const put = store.docs.putDocument({ slug: 'note', title: 'Note', markdown: '# Note\n\nWe deploy to staging-c with deploy2.\n', actor_id: 'agent' });
    expect(store.lineage.staleness(put.doc_id)).toEqual([]);
    expect(store.chain.get(put.chain_seq)!.payload['derived_from_released']).toHaveLength(1);
    expect(store.verifyAll().ok).toBe(true);
    store.rebuild();
    expect(store.lineage.staleness(put.doc_id)).toEqual([]);
    // Still derived from the new source: its change makes the note stale again.
    store.docs.putDocument({ slug: 'deploy-v2', title: 'Deploy v2', markdown: '# Deploy v2\n\nDeploy with ./bin/deploy2 --target prod-1.\n', actor_id: 'ops' });
    expect(store.lineage.staleness(put.doc_id).length).toBe(1);
    store.close();
  });

  it('a re-put without re-deriving (same text, or no read since the removal) keeps the note stale', () => {
    const store = removed();
    store.docs.putDocument({ slug: 'note', title: 'Note', markdown: '# Note\n\nWe deploy to staging-a, still.\n', actor_id: 'agent' });
    expect(store.lineage.staleness(docId(store, 'note')).length).toBe(1);
    store.recall.recall({ query: 'deploy2 target', actor_id: 'agent' });
    store.docs.putDocument({ slug: 'note', title: 'Note', markdown: '# Note\n\nWe deploy to staging-a, still.\n', actor_id: 'agent' }); // identical: not a rewrite
    expect(store.lineage.staleness(docId(store, 'note')).length).toBe(1);
    store.close();
  });

  it('acknowledging the removal (reading the document after it) releases it on the next put', () => {
    const store = removed();
    store.lineage.recordDocumentRead('agent', docId(store, 'runbook'), 'document');
    store.docs.putDocument({ slug: 'note', title: 'Note', markdown: '# Note\n\nWe deploy to staging-a.\n', actor_id: 'agent' });
    expect(store.lineage.staleness(docId(store, 'note'))).toEqual([]);
    store.close();
  });
});

describe('R2-15: derived retractions propagate to notes derived from a stale note', () => {
  it('n2 (from n1, from the runbook) gets its own derived retraction; a format-only source edit gives none', () => {
    const store = withRunbook();
    store.orient.getSystemState({ actor_id: 'agent', focus: 'pulse' });
    store.recall.recall({ query: 'deploy target', actor_id: 'agent' });
    store.docs.putDocument({ slug: 'n1', title: 'N1', markdown: '# N1\n\nmike1 deploy to staging-a.\n', actor_id: 'agent' });
    store.recall.recall({ query: 'mike1', actor_id: 'b' });
    store.docs.putDocument({ slug: 'n2', title: 'N2', markdown: '# N2\n\nmike2 relies on mike1.\n', actor_id: 'b' });
    const cur = store.orient.getSystemState({ actor_id: 'hook', focus: 'pulse' }).cursor;
    store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: RUNBOOK('staging-b'), actor_id: 'ops' });
    const o = store.orient.getSystemState({ actor_id: 'hook', since_cursor: cur, focus: 'retractions' });
    const derived = o.retractions!.filter((r) => r.kind === 'derived');
    expect(derived.map((r) => r.doc_slug).sort()).toEqual(['n1', 'n2']);
    expect(derived.find((r) => r.doc_slug === 'n2')!.derived_from_change).toMatchObject({ via: 'n1' });
    // Kills the "format-only source edits produce derived retractions" mutant: the notes stay
    // stale (n1's source changed), but a later window holding only a reflow lists nothing.
    const cur2 = store.orient.getSystemState({ actor_id: 'hook', since_cursor: cur, focus: 'pulse' }).cursor;
    store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: RUNBOOK('staging-b').replace('Deploy with ./bin/deploy', 'Deploy with\n./bin/deploy'), actor_id: 'ops' });
    const o2 = store.orient.getSystemState({ actor_id: 'hook', since_cursor: cur2, focus: 'retractions' });
    expect(o2.format_only_edits!.length).toBe(1);
    expect(o2.retractions!.filter((r) => r.kind === 'derived')).toEqual([]);
    store.close();
  });
});

describe('derived retractions come from real source changes only (mutation-run gap)', () => {
  it('a window with a format-only edit then a real one lists ONE derived retraction, at the real change', () => {
    const store = withRunbook();
    const v1 = store.docs.liveBlocks(docId(store, 'runbook')).find((b) => b.content.includes('staging-a'))!;
    store.docs.putDocument({ slug: 'note', title: 'Note', markdown: '# Note\n\nWe deploy to staging-a.\n', actor_id: 'agent', derived_from: [{ block_id: v1.block_id, content_hash: v1.content_hash }], infer_lineage: false });
    const cur = store.orient.getSystemState({ actor_id: 'hook', focus: 'pulse' }).cursor;
    const fo = store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: RUNBOOK('staging-a').replace('Deploy with ./bin/deploy', 'Deploy with\n./bin/deploy'), actor_id: 'ops' });
    const real = store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: RUNBOOK('staging-b').replace('Deploy with ./bin/deploy', 'Deploy with\n./bin/deploy'), actor_id: 'ops' });
    const o = store.orient.getSystemState({ actor_id: 'hook', since_cursor: cur, focus: 'retractions' });
    expect(o.format_only_edits!.length).toBe(1);
    const derived = o.retractions!.filter((r) => r.kind === 'derived');
    expect(derived).toHaveLength(1);
    // The supersession event of the real edit, never the format-only one.
    expect(derived[0]!.seq).toBeGreaterThan(fo.chain_seq);
    expect(derived[0]!.seq).toBeGreaterThanOrEqual(real.chain_seq);
    store.close();
  });
});

describe('R2-07 / C2-03 / C2-04: the pulse gate without a usable stored position', () => {
  function rig() {
    const dir = tempDir('kl-li-');
    const store = withRunbook(join(dir, 'data'));
    const state = join(dir, 'state');
    const cwd = tempDir('kl-li-proj-');
    store.lineage.recordDocumentRead('agent', docId(store, 'runbook'), 'document');
    store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: RUNBOOK('prod-eu'), actor_id: 'ops' });
    expect(store.lineage.pending('agent').count).toBe(1);
    const p = (s = store) => pulse(s, { dataDir: join(dir, 'data'), cwd, stateDir: state, pendingActors: ['agent'], command: ['git', 'push'] });
    return { dir, store, state, cwd, p };
  }

  it('R2-07: no stored position: refused while the pending actor has a change, not seeded, allowed after the re-read', () => {
    const { store, state, p } = rig();
    const r = p();
    expect(r).toMatchObject({ decision: 'deny', reason: 'pending', pending: [{ actor_id: 'agent', count: 1 }] });
    expect(r.message).toMatch(/prod-eu/);
    expect(p().decision).toBe('deny'); // not seeded: a plain retry is refused again
    store.lineage.recordDocumentRead('agent', docId(store, 'runbook'), 'document');
    expect(p()).toMatchObject({ decision: 'seed' });
    expect(p()).toMatchObject({ decision: 'allow' });
    void state;
    store.close();
  });

  it('C2-03: a junk cursor file refuses on pending; a denial never becomes the shim position (C2-04)', () => {
    const { store, state, cwd, p } = rig();
    store.lineage.recordDocumentRead('agent', docId(store, 'runbook'), 'document');
    expect(p().decision).toBe('seed');
    store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: RUNBOOK('prod-us'), actor_id: 'ops' });
    const files = readdirSync(join(state, 'cursors'));
    writeFileSync(join(state, 'cursors', files[0]!), 'sxt1.garbage\n');
    const shimBriefings = () => (store.db.prepare(`SELECT count(*) AS n FROM flight_recorder WHERE actor_id = 'shim'`).get() as { n: number }).n;
    const before = shimBriefings();
    expect(p()).toMatchObject({ decision: 'deny', reason: 'pending' });
    expect(p()).toMatchObject({ decision: 'deny', reason: 'pending' });
    expect(shimBriefings()).toBe(before);
    void cwd;
    store.close();
  });

  it('C2-04: a denial for retractions is not recorded as a briefing (the retry is refused again)', () => {
    const { store, p } = rig();
    store.lineage.recordDocumentRead('agent', docId(store, 'runbook'), 'document');
    expect(p().decision).toBe('seed');
    store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: RUNBOOK('prod-us'), actor_id: 'ops' });
    const n = () => (store.db.prepare(`SELECT count(*) AS n FROM flight_recorder WHERE actor_id = 'shim'`).get() as { n: number }).n;
    const before = n();
    expect(p().decision).toBe('deny');
    expect(n()).toBe(before);
    expect(p().decision).toBe('deny');
    store.close();
  });

  it('C2-03: a regenerated cursor-secret is flagged and its old cursors are unknown (pending refuses)', () => {
    const { dir, store, p } = rig();
    store.lineage.recordDocumentRead('agent', docId(store, 'runbook'), 'document');
    expect(p().decision).toBe('seed');
    store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: RUNBOOK('prod-us'), actor_id: 'ops' });
    store.close();
    rmSync(join(dir, 'data', 'cursor-secret'));
    const reopened = new KronicleLite({ dataDir: join(dir, 'data') });
    expect(reopened.identity.cursor_secret_regenerated).toBe(true);
    const r = p(reopened);
    expect(r).toMatchObject({ decision: 'deny', reason: 'pending' });
    expect(r.message).toMatch(/cursor secret was regenerated|unreadable|verifies/);
    reopened.close();
  });
});

describe('R2-08: a pulse counts changes since the cursor it is given', () => {
  it('another session with the same actor id taking a briefing never turns an old-cursor pulse into "proceed"', () => {
    const store = open();
    store.docs.putDocument({ slug: 'instructions/claude-md', title: 'CLAUDE.md', markdown: '# Rules\n\nDeploy target is staging-a.\n', actor_id: 'import' });
    const c0 = store.orient.getSystemState({ actor_id: 'agent', focus: 'pulse' }).cursor;
    store.docs.putDocument({ slug: 'instructions/claude-md', title: 'CLAUDE.md', markdown: '# Rules\n\nDeploy target is prod-eu.\n', actor_id: 'import' });
    store.orient.getSystemState({ actor_id: 'agent', focus: 'retractions' }); // a hook sharing the actor id
    const p = store.orient.getSystemState({ actor_id: 'agent', since_cursor: c0, focus: 'pulse' });
    expect(p.next_steps.join(' ')).not.toMatch(/proceed/i);
    expect(p.next_steps.join(' ')).toMatch(/since your cursor/);
    // No (or an invalid) cursor: never "proceed".
    for (const since_cursor of [undefined, 'sxt1.garbage.x']) {
      const q = store.orient.getSystemState({ actor_id: 'agent', focus: 'pulse', since_cursor });
      expect(q.next_steps.join(' ')).not.toMatch(/proceed/i);
    }
    // Control: nothing since a valid cursor → proceed.
    const c1 = store.orient.getSystemState({ actor_id: 'agent', focus: 'pulse' }).cursor;
    expect(store.orient.getSystemState({ actor_id: 'agent', since_cursor: c1, focus: 'pulse' }).next_steps.join(' ')).toMatch(/proceed/);
    store.close();
  });
});

describe('R2-09 / L2-01: the projection is cross-checked against the chain on every focus, pulse included', () => {
  function tampered(t: (db: KronicleLite['db'], ids: { old: string; neu: string }) => void) {
    const store = open();
    store.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: '# Deploy\n\n## Steps\n\nDeploy with --target staging-a.\n', actor_id: 'ops' });
    store.recall.recall({ query: 'deploy target', actor_id: 'agent' });
    store.docs.putDocument({ slug: 'note', title: 'Note', markdown: '# Note\n\nWe ship to staging-a.\n', actor_id: 'agent' });
    const cur = store.orient.getSystemState({ actor_id: 'hook', focus: 'pulse' }).cursor;
    store.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: '# Deploy\n\n## Steps\n\nDeploy with --target prod-eu.\n', actor_id: 'ops' });
    const rows = store.db.prepare(`SELECT block_id, content FROM blocks WHERE kind = 'paragraph' AND doc_id = ?`).all(docId(store, 'deploy')) as { block_id: string; content: string }[];
    t(store.db, { old: rows.find((r) => r.content.includes('staging-a'))!.block_id, neu: rows.find((r) => r.content.includes('prod-eu'))!.block_id });
    return { store, cur };
  }
  const TAMPERS: Record<string, (db: KronicleLite['db'], ids: { old: string; neu: string }) => void> = {
    resurrect_superseded: (db, ids) => db.prepare('UPDATE blocks SET valid_to = NULL, superseded_by = NULL WHERE block_id = ?').run(ids.old),
    resurrect_and_hide_new: (db, ids) => {
      db.prepare('UPDATE blocks SET valid_to = NULL, superseded_by = NULL WHERE block_id = ?').run(ids.old);
      db.prepare('UPDATE blocks SET valid_to = valid_from WHERE block_id = ?').run(ids.neu);
    },
    repoint_successor: (db, ids) => db.prepare('UPDATE blocks SET superseded_by = ? WHERE block_id = ?').run(ids.old, ids.old),
    drop_lineage_rows: (db) => db.prepare('DELETE FROM doc_lineage').run(),
    drop_lineage_gap: (db) => db.prepare(`INSERT INTO doc_lineage_gaps (doc_id, chain_seq) SELECT doc_id, 1 FROM documents WHERE slug = 'note'`).run(),
  };
  for (const [name, t] of Object.entries(TAMPERS)) {
    it(`${name}: integrity.ok is false on pulse, retractions and orientation, never "proceed"`, () => {
      const { store, cur } = tampered(t);
      for (const focus of ['pulse', 'retractions', 'orientation'] as const) {
        const s = store.orient.getSystemState({ actor_id: 'hook', since_cursor: cur, focus });
        expect(s.integrity, focus).toMatchObject({ ok: false });
        expect(s.next_steps[0]).toMatch(/^INTEGRITY FAILURE/);
        expect(s.next_steps.join(' ')).not.toMatch(/proceed/i);
      }
      expect(store.verifyAll().ok).toBe(false);
      store.close();
    });
  }

  it('recall withholds a resurrected superseded block and a note whose lineage rows were deleted', () => {
    const a = tampered(TAMPERS['resurrect_and_hide_new']!).store;
    const r = a.recall.recall({ query: 'deploy target', actor_id: 'x' });
    expect(r.hits.some((h) => h.content.includes('staging-a'))).toBe(false);
    expect(r.withheld).toContainEqual(expect.objectContaining({ problem: 'projection_mismatch' }));
    a.close();
    const b = tampered(TAMPERS['drop_lineage_rows']!).store;
    const r2 = b.recall.recall({ query: 'ship staging', actor_id: 'x' });
    expect(r2.hits.find((h) => h.doc_slug === 'note')).toBeUndefined();
    expect(r2.withheld).toContainEqual(expect.objectContaining({ doc_slug: 'note', problem: 'lineage_mismatch' }));
    b.close();
  });

  it('an untampered store with lineage, removals and supersessions passes every check', () => {
    const store = withRunbook();
    store.recall.recall({ query: 'deploy target', actor_id: 'agent' });
    store.docs.putDocument({ slug: 'note', title: 'Note', markdown: '# Note\n\nWe deploy to staging-a.\n', actor_id: 'agent' });
    store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: RUNBOOK('staging-b'), actor_id: 'ops' });
    store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: '# Deploy runbook\n\n## Steps\n\nNotify #ops.\n', actor_id: 'ops' });
    const blk = store.docs.liveBlocks(docId(store, 'note')).find((b) => b.kind === 'paragraph')!;
    store.docs.supersedeBlock({ block_id: blk.block_id, new_content: 'We deploy elsewhere now.', reason: 'x', actor_id: 'agent' });
    for (const focus of ['pulse', 'retractions', 'orientation'] as const) expect(store.orient.getSystemState({ actor_id: 'h', focus }).integrity, focus).toMatchObject({ ok: true });
    expect(store.verifyAll().ok).toBe(true);
    store.close();
  });
});

describe('R2-17: absence is never certified from an index that disagrees with the stored text', () => {
  it('a rewritten full-text row: cannot_certify; orient, verifyAll and the FTS check report it', () => {
    const store = open();
    store.docs.putDocument({ slug: 'r', title: 'R', markdown: '# R\n\nNever deploy to zebracluster on Fridays.\n', actor_id: 'o' });
    expect(store.recall.recall({ query: 'zebracluster', actor_id: 'a' }).hits.length).toBe(1);
    const absent = store.recall.recall({ query: 'nosuchtermanywhere', actor_id: 'a' });
    expect(absent.absence.verdict).toBe('absent_in_searched');
    const row = store.db.prepare(`SELECT rowid FROM blocks_fts WHERE blocks_fts MATCH 'zebracluster'`).get() as { rowid: number };
    store.db.prepare(`UPDATE blocks_fts SET content = 'Never deploy on Fridays.' WHERE rowid = ?`).run(row.rowid);
    const r = store.recall.recall({ query: 'zebracluster', actor_id: 'a' });
    expect(r.hits).toEqual([]);
    expect(r.absence).toMatchObject({ verdict: 'cannot_certify', index_fresh: false });
    expect(store.orient.getSystemState({ actor_id: 'a', focus: 'orientation' }).integrity).toMatchObject({ ok: false });
    const v = store.verifyAll();
    expect(v.ok).toBe(false);
    expect(v.projection!.mismatches.some((m) => m.table === 'blocks_fts')).toBe(true);
    store.close();
  });
});

describe('L2-03: a store file damaged under an open connection is never answered from the cache', () => {
  it('a zeroed page: every focus reports integrity ok:false, recall withholds, no "proceed"', () => {
    const dir = tempDir('kl-li-');
    const store = withRunbook(dir);
    for (let i = 0; i < 30; i++) store.docs.putDocument({ slug: `f${i}`, title: `F${i}`, markdown: `# F${i}\n\n${`filler ${i} `.repeat(200)}\n`, actor_id: 'o' });
    store.db.pragma('wal_checkpoint(TRUNCATE)');
    const cur = store.orient.getSystemState({ actor_id: 'agent' }).cursor;
    expect(store.orient.getSystemState({ actor_id: 'agent', since_cursor: cur, focus: 'pulse' }).integrity).toMatchObject({ ok: true });
    const fd = openSync(join(dir, 'kronicle-lite.db'), 'r+');
    writeSync(fd, Buffer.alloc(4096), 0, 4096, 2 * 4096);
    closeSync(fd);
    for (const focus of ['pulse', 'retractions', 'orientation'] as const) {
      const s = store.orient.getSystemState({ actor_id: 'agent', since_cursor: cur, focus });
      expect(s.integrity, focus).toMatchObject({ ok: false });
      expect(s.next_steps.join(' ')).not.toMatch(/proceed/i);
    }
    const r = store.recall.recall({ query: 'deploy target', actor_id: 'agent' });
    expect(r.hits).toEqual([]);
    store.close();
  });

  it('an SQLite error during orient is an integrity failure, not an exception or a clean briefing', () => {
    const store = withRunbook();
    const c = store.orient.getSystemState({ actor_id: 'agent', focus: 'pulse' }).cursor;
    const real = store.chain.head.bind(store.chain);
    store.chain.head = () => {
      throw Object.assign(new Error('database disk image is malformed'), { code: 'SQLITE_CORRUPT' });
    };
    const s = store.orient.getSystemState({ actor_id: 'agent', since_cursor: c, focus: 'pulse' });
    expect(s.integrity).toMatchObject({ ok: false });
    expect(s.integrity!.problem).toMatch(/SQLITE_CORRUPT/);
    expect(s.next_steps.join(' ')).not.toMatch(/proceed/i);
    expect(s.cursor).toBe(c); // the position does not move
    store.chain.head = real;
    store.close();
  });
});

describe('R2-10 / R2-11: secret guard shapes', () => {
  // Synthetic, obviously fake material (never a real credential).
  const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const body = Array.from({ length: 4 }, (_, i) => (B64 + B64).slice(i * 3, i * 3 + 64)).join('\n');
  const pem = `-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----`;
  const indent = (s: string, p: string) => s.split('\n').map((l) => p + l).join('\n');
  const FAKE = 'Zq7fakeTESTvalue9';

  it('an indented, quoted or listed PEM private key is refused (R2-10)', () => {
    for (const [name, md] of [
      ['column 0', `# K\n\n${pem}\n`],
      ['yaml block scalar', `# K\n\n\`\`\`yaml\ntls.key: |\n${indent(pem, '    ')}\n\`\`\`\n`],
      ['block quote', `# K\n\n${indent(pem, '> ')}\n`],
      ['list item', `# K\n\n- the key:\n${indent(pem, '  ')}\n`],
      ['comment', `# K\n\n\`\`\`\n${indent(pem, '# ')}\n\`\`\`\n`],
    ]) {
      expect(scanForSecrets(md!).map((f) => f.detector), name).toContain('private_key');
    }
  });

  it('password assignments under any key spelling are refused and scrubbed; placeholders pass (R2-11)', () => {
    for (const s of [`db_password: ${FAKE}`, `{"dbPassword": "${FAKE}"}`, `db-password=${FAKE}`, `export db_password=${FAKE}`, `apiToken: ${FAKE}`, `client_secret = "${FAKE}"`, `DB_PASSWORD=Kx9abcexampledef1`]) {
      expect(scanForSecrets(s).length, s).toBeGreaterThan(0);
      expect(scrubForRead(s).text, s).not.toContain(FAKE);
    }
    for (const s of [
      'db_password: ${DB_PASSWORD}',
      'db_password: <redacted>',
      'db_password: changeme',
      'db_password: example',
      'db_password: example-password-1',
      'password: your_password_here',
      'secretName: tls-cert-2024',
      'max_tokens: 4096',
      'token_url: https://auth.example.net/t1',
      'pwd=/srv/app2',
      'See THREAT-MODEL.md §"Secrets": write-time refusal',
    ]) {
      expect(scanForSecrets(s), s).toEqual([]);
    }
  });

  it('a soft hyphen or zero-width space inside a token does not hide it; nothing is normalised for storage', () => {
    const tok = `ghp_${'a1B2c3D4e5'.repeat(4)}`;
    for (const sep of ['­', '​']) {
      const split = `Token ${tok.slice(0, 20)}${sep}${tok.slice(20)}`;
      expect(scanForSecrets(split).map((f) => f.detector)).toContain('github_token');
      expect(scrubForRead(split).detectors).toContain('github_token');
      expect(scrubForRead(split).text).not.toContain(tok.slice(24));
      expect(scanForSecrets(`Use ${tok.slice(0, 20)}${sep}${tok.slice(20)} here`).map((f) => f.detector)).toContain('github_token');
    }
    const store = open();
    const md = '# K\n\nsoft­hyphen in plain prose.\n';
    store.docs.putDocument({ slug: 'k', title: 'K', markdown: md, actor_id: 'w' });
    expect(store.docs.getRevisionMarkdown(docId(store, 'k'), 1)).toContain('­');
    store.close();
  });
});

describe('migration: a 0.8.0 store upgrades forward-only', () => {
  it('doc_lineage_gaps is backfilled from the chain once; the projection then verifies', () => {
    const dir = tempDir('kl-li-');
    const store = withRunbook(dir);
    store.recall.recall({ query: 'deploy target', actor_id: 'agent' });
    const old = new Date(Date.now() - 30 * 3600_000).toISOString();
    store.db.prepare(`UPDATE receipts SET issued_at = ? WHERE actor_id = 'agent'`).run(old);
    store.db.prepare(`UPDATE reads SET read_at = ? WHERE actor_id = 'agent'`).run(old);
    const put = store.docs.putDocument({ slug: 'note', title: 'note', markdown: '# Note\n\nX 1.\n', actor_id: 'agent' });
    expect(put.lineage).toMatchObject({ derived_from_inferred_truncated: true });
    store.close();
    // Make it look like 0.8.0 wrote it: no gaps table, no lineage index, no migration mark.
    const db = new Database(join(dir, 'kronicle-lite.db'));
    db.exec(`DROP TABLE doc_lineage_gaps; DROP INDEX events_lineage_idx; DELETE FROM meta WHERE key LIKE 'migration.%';`);
    db.close();
    const up = new KronicleLite({ dataDir: dir });
    expect(up.lineage.gapSeq(put.doc_id)).toBe(put.chain_seq);
    expect(up.verifyAll().ok).toBe(true);
    expect(up.orient.getSystemState({ actor_id: 'x' }).integrity).toMatchObject({ ok: true });
    const mark = up.db.prepare(`SELECT value FROM meta WHERE key = 'migration.lineage_gaps'`).get();
    expect(mark).toBeDefined();
    up.close();
    // Re-opening does not run it again (and changes nothing).
    const again = new KronicleLite({ dataDir: dir });
    expect(again.db.prepare(`SELECT value FROM meta WHERE key = 'migration.lineage_gaps'`).get()).toEqual(mark);
    expect(again.verifyAll().ok).toBe(true);
    again.close();
  });
});
