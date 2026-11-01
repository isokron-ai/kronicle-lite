/**
 * Unreleased: derived-note lineage (docs/HONESTY.md §6, FORMAT §3.10) and
 * version-bound reconciliation (`pending`, docs/PUSH.md).
 *
 *   - a note derived from a block that changes is never_act / stale_derived
 *     in recall, a `derived` retraction in orient, and pending for its readers;
 *   - lineage is declared (`derived_from`) or inferred from the author's reads
 *     in its session;
 *   - a change is resolved for an actor only by reading the CURRENT version;
 *     receiving the push, or reading an older version, never clears it.
 */

import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { DocumentError } from '../src/docs/documents.js';
import { KronicleLite } from '../src/store.js';
import { tempDir, write } from './helpers/fs.js';

const RUNBOOK = (cluster: string) => `# Deploy\n\n## Target\n\nDeploys go to the cluster \`${cluster}\` first.\n\n## Notes\n\nPage the on-call before a deploy.\n`;

function setup() {
  const store = new KronicleLite({ memory: true });
  const src = store.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: RUNBOOK('blue-7'), actor_id: 'human' });
  const target = src.blocks.find((b) => b.kind === 'paragraph' && b.ordinal === 2)!;
  return { store, src, target };
}

const noteHit = (store: KronicleLite, q = 'deploy target note') => store.recall.recall({ query: q }).hits.find((h) => h.doc_slug === 'note')!;

describe('derived_from (explicit)', () => {
  it('a note derived from a block that is superseded is never_act / stale_derived with the source change', () => {
    const { store, target } = setup();
    const put = store.docs.putDocument({
      slug: 'note',
      title: 'Note',
      markdown: '# Note\n\nDeploy target note: blue-7.\n',
      actor_id: 'agent',
      derived_from: [{ block_id: target.block_id, content_hash: target.content_hash }],
      infer_lineage: false,
    });
    expect(put.lineage).toEqual({ derived_from: 1, derived_from_inferred: 0 });
    expect(noteHit(store)).toMatchObject({ authority: 'inspect_only', authority_reason: 'no_source' });
    expect(noteHit(store).stale_derived).toBeUndefined();

    const sup = store.docs.supersedeBlock({ block_id: target.block_id, new_content: 'Deploys go to the cluster `green-2` first.', reason: 'cutover', actor_id: 'human' });
    const hit = noteHit(store);
    expect(hit).toMatchObject({ authority: 'never_act', authority_reason: 'stale_derived', authority_basis: 'document' });
    expect(hit.stale_derived).toEqual([
      expect.objectContaining({
        source_block_id: target.block_id,
        source_content_hash: target.content_hash,
        source_doc_slug: 'deploy',
        change: 'superseded',
        current_block_id: sup.new_block_id,
        current_content_hash: sup.content_hash,
        inferred: false,
      }),
    ]);
    expect(hit.stale_derived![0]!.old_text).toContain('blue-7');
    expect(hit.stale_derived![0]!.new_text).toContain('green-2');
    // The marker sits next to the stale text in the serialized hit (what an agent reads first).
    const json = JSON.stringify(hit);
    expect(json.indexOf('stale_derived') - json.indexOf('blue-7')).toBeLessThan(120);
    expect(store.verifyAll().ok).toBe(true);
    store.close();
  });

  it('re-deriving from the current version (a put that declares it) makes the note fresh again', () => {
    const { store, target } = setup();
    store.docs.putDocument({ slug: 'note', title: 'Note', markdown: '# Note\n\nDeploy target note: blue-7.\n', actor_id: 'agent', derived_from: [target], infer_lineage: false });
    const sup = store.docs.supersedeBlock({ block_id: target.block_id, new_content: 'Deploys go to the cluster `green-2` first.', reason: 'cutover', actor_id: 'human' });
    expect(noteHit(store).authority_reason).toBe('stale_derived');
    // Adding an edge to the current version (supersede of the note block) reconciles the old edge.
    const nb = store.docs.liveBlocks(store.docs.getDocument('note')!.doc_id).find((b) => b.kind === 'paragraph')!;
    store.docs.supersedeBlock({ block_id: nb.block_id, new_content: 'Deploy target note: green-2.', reason: 're-derived', actor_id: 'agent', derived_from: [{ block_id: sup.new_block_id, content_hash: sup.content_hash }], infer_lineage: false });
    expect(noteHit(store)).toMatchObject({ authority: 'inspect_only', authority_reason: 'no_source' });
    // A third version: one entry for the lineage, naming the latest version the note was derived from.
    store.docs.supersedeBlock({ block_id: sup.new_block_id, new_content: 'Deploys go to the cluster `red-9` first.', reason: 'again', actor_id: 'human' });
    const hit = noteHit(store);
    expect(hit.authority_reason).toBe('stale_derived');
    expect(hit.stale_derived).toHaveLength(1);
    expect(hit.stale_derived![0]).toMatchObject({ source_block_id: sup.new_block_id, inferred: false });
    expect(hit.stale_derived![0]!.new_text).toContain('red-9');
    store.close();
  });

  it('a tombstoned source stays stale until a put declares new lineage (explicit [] resets it)', () => {
    const { store, target } = setup();
    store.docs.putDocument({ slug: 'note', title: 'Note', markdown: '# Note\n\nDeploy target note: blue-7.\n', actor_id: 'agent', derived_from: [target], infer_lineage: false });
    store.docs.tombstoneBlock({ block_id: target.block_id, reason: 'no fixed target any more', actor_id: 'human' });
    const hit = noteHit(store);
    expect(hit.authority_reason).toBe('stale_derived');
    expect(hit.stale_derived![0]).toMatchObject({ change: 'tombstoned', current_block_id: null, new_text: null });
    // A re-put without derived_from keeps the lineage (inference adds, never removes).
    store.docs.putDocument({ slug: 'note', title: 'Note', markdown: '# Note\n\nDeploy target note: blue-7 (checked).\n', actor_id: 'agent', infer_lineage: false });
    expect(noteHit(store).authority_reason).toBe('stale_derived');
    store.docs.putDocument({ slug: 'note', title: 'Note', markdown: '# Note\n\nDeploy target note: none fixed.\n', actor_id: 'agent', derived_from: [], infer_lineage: false });
    expect(noteHit(store).authority_reason).toBe('no_source');
    store.close();
  });

  it('format-only source edits keep the note fresh; a moved section makes it stale', () => {
    const { store, target } = setup();
    store.docs.putDocument({ slug: 'note', title: 'Note', markdown: '# Note\n\nDeploy target note: blue-7.\n', actor_id: 'agent', derived_from: [target], infer_lineage: false });
    store.docs.supersedeBlock({ block_id: target.block_id, new_content: 'Deploys go to the   cluster `blue-7`\nfirst.', reason: 'reflow', actor_id: 'human' });
    expect(noteHit(store).authority_reason).toBe('no_source');
    // Move the paragraph under another heading (same text): a change of meaning.
    store.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: '# Deploy\n\n## Target\n\n## Notes\n\nDeploys go to the   cluster `blue-7`\nfirst.\n\nPage the on-call before a deploy.\n', actor_id: 'human' });
    const hit = noteHit(store);
    expect(hit.authority_reason).toBe('stale_derived');
    expect(hit.stale_derived![0]!.change).toBe('moved');
    store.close();
  });

  it('a note derived from a note that went stale is stale too (via)', () => {
    const { store, target } = setup();
    const n1 = store.docs.putDocument({ slug: 'note', title: 'Note', markdown: '# Note\n\nDeploy target note: blue-7.\n', actor_id: 'agent', derived_from: [target], infer_lineage: false });
    const n1b = n1.blocks.find((b) => b.kind === 'paragraph')!;
    store.docs.putDocument({ slug: 'plan', title: 'Plan', markdown: '# Plan\n\nRelease plan uses blue-7.\n', actor_id: 'agent', derived_from: [n1b], infer_lineage: false });
    store.docs.supersedeBlock({ block_id: target.block_id, new_content: 'Deploys go to the cluster `green-2` first.', reason: 'cutover', actor_id: 'human' });
    const plan = store.recall.recall({ query: 'release plan' }).hits.find((h) => h.doc_slug === 'plan')!;
    expect(plan.authority_reason).toBe('stale_derived');
    expect(plan.stale_derived![0]).toMatchObject({ source_block_id: target.block_id, via: 'note' });
    store.close();
  });

  it('a file-backed note that matches its file (can_act) is downgraded when its source changes', () => {
    const dir = tempDir('kl-lineage-file-');
    const file = join(dir, 'note.md');
    const md = '# Note\n\nDeploy target note: blue-7.\n';
    write(file, md);
    const { store, target } = setup();
    store.docs.putDocument({ slug: 'note', title: 'Note', markdown: md, actor_id: 'agent', source: { kind: 'file', path: file }, derived_from: [target], infer_lineage: false });
    expect(noteHit(store).authority).toBe('can_act');
    store.docs.supersedeBlock({ block_id: target.block_id, new_content: 'Deploys go to the cluster `green-2` first.', reason: 'cutover', actor_id: 'human' });
    expect(noteHit(store)).toMatchObject({ authority: 'never_act', authority_reason: 'stale_derived' });
    store.close();
  });

  it('rejects an unknown block or a hash that is not that block\'s; accepts an already-retired version (born stale)', () => {
    const { store, target } = setup();
    const bad = (derived_from: { block_id: string; content_hash: string }[]) => () =>
      store.docs.putDocument({ slug: 'note', title: 'Note', markdown: '# Note\n\nx.\n', actor_id: 'agent', derived_from, infer_lineage: false });
    expect(bad([{ block_id: '00000000-0000-4000-8000-000000000000', content_hash: target.content_hash }])).toThrow(DocumentError);
    expect(bad([{ block_id: target.block_id, content_hash: 'f'.repeat(64) }])).toThrow(/content_hash/);
    expect(store.docs.getDocument('note')).toBeNull();
    store.docs.supersedeBlock({ block_id: target.block_id, new_content: 'Deploys go to the cluster `green-2` first.', reason: 'cutover', actor_id: 'human' });
    store.docs.putDocument({ slug: 'note', title: 'Note', markdown: '# Note\n\nDeploy target note: blue-7.\n', actor_id: 'agent', derived_from: [target], infer_lineage: false });
    expect(noteHit(store).authority_reason).toBe('stale_derived');
    store.close();
  });

  it('lineage is chained: export → import and rebuild restore it; a deleted lineage row fails the projection check', async () => {
    const { store, target } = setup();
    store.docs.putDocument({ slug: 'note', title: 'Note', markdown: '# Note\n\nDeploy target note: blue-7.\n', actor_id: 'agent', derived_from: [target], infer_lineage: false });
    store.docs.supersedeBlock({ block_id: target.block_id, new_content: 'Deploys go to the cluster `green-2` first.', reason: 'cutover', actor_id: 'human' });
    expect(store.verifyAll().ok).toBe(true);
    const chunks: string[] = [];
    store.exportEvents({ write: (c: string) => chunks.push(c) } as unknown as NodeJS.WritableStream as never);
    const copy = new KronicleLite({ memory: true });
    const { Readable } = await import('node:stream');
    await copy.importEvents(Readable.from(chunks.join('').split(/(?<=\n)/)));
    expect(noteHit(copy).authority_reason).toBe('stale_derived');
    copy.close();

    store.db.prepare('DELETE FROM doc_lineage').run();
    expect(noteHit(store).authority_reason).toBe('no_source');
    const v = store.verifyAll();
    expect(v.ok).toBe(false);
    expect(v.projection!.mismatches.some((m) => m.table === 'doc_lineage' && m.field === 'missing')).toBe(true);
    store.rebuild();
    expect(store.verifyAll().ok).toBe(true);
    expect(noteHit(store).authority_reason).toBe('stale_derived');
    store.close();
  });
});

describe('inferred lineage (derived_from_inferred)', () => {
  it('a note written after recalling a block in the same session is derived from it (S1 next-session copy)', async () => {
    const { store, target } = setup();
    // An earlier session read the Notes block: outside this session, not inferred.
    // (Session bounds are millisecond timestamps, inclusive: a read in the same
    // millisecond as the next orient counts as in-session, the conservative side.)
    store.orient.getSystemState({ actor_id: 'agent' });
    store.recall.recall({ query: 'page on-call', actor_id: 'agent' });
    await new Promise((r) => setTimeout(r, 5));
    const cursor = store.orient.getSystemState({ actor_id: 'agent' }).cursor;
    store.recall.recall({ query: 'deploys cluster', actor_id: 'agent' });
    store.recall.recall({ query: 'deploys cluster', actor_id: 'other-agent' });
    const put = store.docs.putDocument({ slug: 'note', title: 'Note', markdown: '# Note\n\nDeploy target note: blue-7.\n', actor_id: 'agent', cursor });
    expect(put.lineage).toEqual({ derived_from: 0, derived_from_inferred: 1 });
    expect(store.lineage.edges(put.doc_id)).toEqual([expect.objectContaining({ source_block_id: target.block_id, inferred: 1 })]);

    store.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: RUNBOOK('green-2'), actor_id: 'human' });
    const hit = store.recall.recall({ query: 'deploy target note' }).hits.find((h) => h.doc_slug === 'note')!;
    expect(hit).toMatchObject({ authority: 'never_act', authority_reason: 'stale_derived' });
    expect(hit.stale_derived![0]).toMatchObject({ inferred: true, change: 'superseded' });
    expect(hit.stale_derived![0]!.new_text).toContain('green-2');
    store.close();
  });

  it('without an orient the actor\'s reads so far count; its own writes and the note itself never do; opt-out exists for imports', () => {
    const { store } = setup();
    store.recall.recall({ query: 'deploys cluster', actor_id: 'agent' });
    const p1 = store.docs.putDocument({ slug: 'note', title: 'Note', markdown: '# Note\n\nA.\n', actor_id: 'agent' });
    expect(p1.lineage?.derived_from_inferred).toBe(1);
    store.recall.recall({ query: 'A', actor_id: 'agent' });
    const p2 = store.docs.putDocument({ slug: 'note', title: 'Note', markdown: '# Note\n\nB.\n', actor_id: 'agent' });
    // Re-put: its own blocks are excluded; the deploy read is still in the session.
    expect(store.lineage.edges(p2.doc_id).every((e) => store.docs.getBlock(e.source_block_id)!.doc_id !== p2.doc_id)).toBe(true);
    const p3 = store.docs.putDocument({ slug: 'other', title: 'Other', markdown: '# Other\n\nC.\n', actor_id: 'agent', infer_lineage: false });
    expect(p3.lineage).toBeUndefined();
    store.close();
  });
});

describe('derived retractions in orient', () => {
  it('a source change lists a `derived` retraction for the stale note (with the source diff); re-derived notes are not listed', () => {
    const { store, target } = setup();
    store.docs.putDocument({ slug: 'note', title: 'Note', markdown: '# Note\n\nDeploy target note: blue-7.\n', actor_id: 'agent', derived_from: [target], infer_lineage: false });
    const c = store.orient.getSystemState({ actor_id: 'agent' }).cursor;
    store.docs.supersedeBlock({ block_id: target.block_id, new_content: 'Deploys go to the cluster `green-2` first.', reason: 'cutover', actor_id: 'human' });
    const s = store.orient.getSystemState({ actor_id: 'agent', since_cursor: c, focus: 'retractions' });
    const d = s.retractions!.filter((r) => r.kind === 'derived');
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ doc_slug: 'note', severity: 'behavioral', format_only: false, derived_from_change: expect.objectContaining({ source_block_id: target.block_id }) });
    expect(d[0]!.old_text).toContain('blue-7');
    expect(d[0]!.diff).toMatch(/\[-`blue-7`-\]\{\+`green-2`\+\}/);
    expect(d[0]!.reason_line).toMatch(/STALE/);
    // The plain supersession is still there, unchanged.
    expect(s.retractions!.some((r) => r.kind === 'supersession' && r.block_id === target.block_id)).toBe(true);
    store.close();
  });
});

describe('pending: version-bound reconciliation', () => {
  it('receiving the push does not resolve a change; re-reading the current version does', () => {
    const { store, target } = setup();
    let c = store.orient.getSystemState({ actor_id: 'agent' }).cursor;
    store.recall.recall({ query: 'deploys cluster', actor_id: 'agent' });
    const sup = store.docs.supersedeBlock({ block_id: target.block_id, new_content: 'Deploys go to the cluster `green-2` first.', reason: 'cutover', actor_id: 'human' });
    const s1 = store.orient.getSystemState({ actor_id: 'agent', since_cursor: c, focus: 'retractions' });
    expect(s1.retractions!.length).toBeGreaterThan(0); // delivered
    expect(s1.pending_count).toBe(1);
    expect(s1.pending![0]).toMatchObject({
      kind: 'supersession',
      change: 'superseded',
      doc_slug: 'deploy',
      read: { block_id: target.block_id, content_hash: target.content_hash },
      current: { block_id: sup.new_block_id, content_hash: sup.content_hash },
    });
    c = s1.cursor;
    // Delivered twice, still pending: delivery is not reconciliation.
    expect(store.orient.getSystemState({ actor_id: 'agent', since_cursor: c, focus: 'pulse' }).pending_count).toBe(1);
    // Another actor's read does not count.
    store.recall.recall({ query: 'deploys cluster', actor_id: 'someone-else' });
    expect(store.lineage.pending('agent').count).toBe(1);
    store.recall.recall({ query: 'deploys cluster', actor_id: 'agent' });
    expect(store.lineage.pending('agent').count).toBe(0);
    store.close();
  });

  it('reading an older version never clears a newer change', () => {
    const { store, target } = setup();
    store.recall.recall({ query: 'deploys cluster', actor_id: 'agent' });
    const v2 = store.docs.supersedeBlock({ block_id: target.block_id, new_content: 'Deploys go to the cluster `green-2` first.', reason: 'r', actor_id: 'human' });
    const v3 = store.docs.supersedeBlock({ block_id: v2.new_block_id, new_content: 'Deploys go to the cluster `red-9` first.', reason: 'r', actor_id: 'human' });
    // The agent acknowledges v2 (e.g. `kronicle-lite get --block <v2>`): v3 is still pending, now "read v2".
    store.lineage.recordBlockReads('agent', [store.docs.getBlock(v2.new_block_id)!], 'recall');
    const p = store.lineage.pending('agent');
    expect(p.count).toBe(1);
    expect(p.items[0]).toMatchObject({ read: { block_id: v2.new_block_id }, current: { block_id: v3.new_block_id } });
    expect(p.items[0]!.diff).toContain('red-9');
    store.lineage.recordBlockReads('agent', [store.docs.getBlock(v3.new_block_id)!], 'recall');
    expect(store.lineage.pending('agent').count).toBe(0);
    store.close();
  });

  it('a removal is resolved by reading the document (or the tombstoned block) after it, not by recall of other text', () => {
    const { store, src, target } = setup();
    store.recall.recall({ query: 'deploys cluster', actor_id: 'agent' });
    store.docs.tombstoneBlock({ block_id: target.block_id, reason: 'gone', actor_id: 'human' });
    expect(store.lineage.pending('agent').items[0]).toMatchObject({ kind: 'tombstone', change: 'tombstoned', severity: 'safety', current: null });
    store.recall.recall({ query: 'page on-call', actor_id: 'agent' });
    expect(store.lineage.pending('agent').count).toBe(1);
    store.recall.recall({ query: 'deploys cluster', actor_id: 'agent', include_tombstoned: true });
    expect(store.lineage.pending('agent').count).toBe(0);
    // Same for a whole-document read.
    store.recall.recall({ query: 'page on-call', actor_id: 'b' });
    const notes = store.docs.liveBlocks(src.doc_id).find((x) => x.content.startsWith('Page'))!;
    store.docs.tombstoneBlock({ block_id: notes.block_id, reason: 'gone', actor_id: 'human' });
    expect(store.lineage.pending('b').count).toBe(1);
    store.lineage.recordDocumentRead('b', src.doc_id, 'document');
    expect(store.lineage.pending('b').count).toBe(0);
    store.close();
  });

  it('format-only edits are never pending; the author of a change has nothing pending for it', () => {
    const { store, target } = setup();
    store.recall.recall({ query: 'deploys cluster', actor_id: 'agent' });
    store.docs.supersedeBlock({ block_id: target.block_id, new_content: 'Deploys go to the  cluster `blue-7` first.', reason: 'ws', actor_id: 'human' });
    expect(store.lineage.pending('agent').count).toBe(0);
    store.recall.recall({ query: 'deploys cluster', actor_id: 'writer' });
    const live = store.docs.liveBlocks(store.docs.getDocument('deploy')!.doc_id).find((b) => b.content.includes('blue-7'))!;
    store.docs.supersedeBlock({ block_id: live.block_id, new_content: 'Deploys go to the cluster `green-2` first.', reason: 'r', actor_id: 'writer' });
    expect(store.lineage.pending('writer').count).toBe(0);
    expect(store.lineage.pending('agent').count).toBe(1);
    store.close();
  });

  it('a reader of a derived note has a `derived` item until it reads the source\'s current version', () => {
    const { store, target } = setup();
    store.docs.putDocument({ slug: 'note', title: 'Note', markdown: '# Note\n\nDeploy target note: blue-7.\n', actor_id: 'author', derived_from: [target], infer_lineage: false });
    store.recall.recall({ query: 'deploy target note', actor_id: 'reader' });
    const sup = store.docs.supersedeBlock({ block_id: target.block_id, new_content: 'Deploys go to the cluster `green-2` first.', reason: 'cutover', actor_id: 'human' });
    for (const who of ['reader', 'author']) {
      const p = store.lineage.pending(who);
      expect(p.count, who).toBe(1);
      expect(p.items[0]).toMatchObject({ kind: 'derived', derived_notes: ['note'], doc_slug: 'deploy', read: { block_id: target.block_id }, current: { block_id: sup.new_block_id } });
    }
    store.recall.recall({ query: 'deploys cluster', actor_id: 'reader' });
    expect(store.lineage.pending('reader').count).toBe(0);
    // The note itself is still stale for everyone: the reader knows the truth, the copy is still wrong.
    expect(noteHit(store).authority_reason).toBe('stale_derived');
    store.close();
  });

  it('a briefing with pending items is never the one-line quiet pulse', async () => {
    const { renderSystemStateMarkdown } = await import('../src/orient/render.js');
    const { store, target } = setup();
    store.recall.recall({ query: 'deploys cluster', actor_id: 'agent' });
    store.docs.supersedeBlock({ block_id: target.block_id, new_content: 'Deploys go to the cluster `green-2` first.', reason: 'cutover', actor_id: 'human' });
    const c = store.orient.getSystemState({ actor_id: 'agent' }).cursor;
    const s = store.orient.getSystemState({ actor_id: 'agent', since_cursor: c });
    expect(s.delta!.events_since).toBe(0);
    const md = renderSystemStateMarkdown(s);
    expect(md).toMatch(/## Pending \(1\)/);
    expect(md).toContain('green-2');
    expect(s.next_steps.join('\n')).toMatch(/1 pending: re-read the current version/);
    const pulse = renderSystemStateMarkdown(store.orient.getSystemState({ actor_id: 'agent', since_cursor: c, focus: 'pulse' }));
    expect(pulse).toMatch(/Pending \(1\)/);
    store.close();
  });
});
