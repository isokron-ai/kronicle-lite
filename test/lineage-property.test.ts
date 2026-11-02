/**
 * Properties (seeded, deterministic):
 *
 *   P1. Random supersede / format-only edit / tombstone / move / rename
 *       sequences on a source document never leave a note derived from it
 *       `can_act` once a source it was derived from really changed; and
 *       format-only edits and renames alone never mark it stale (it stays
 *       `can_act`, its file still matches). Checked against an independent
 *       model of which lineages changed.
 *
 *   P2. A change is resolved for an actor only by a read of the CURRENT
 *       version (or a format-only twin): random edit / read-a-random-version
 *       / remove sequences, pending checked after every step against a model.
 */

import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { KronicleLite } from '../src/store.js';
import { tempDir, write } from './helpers/fs.js';
import { rng } from './helpers/format-only.js';

type Rand = () => number;
const pick = <T>(r: Rand, xs: readonly T[]): T => xs[Math.floor(r() * xs.length)]!;

/** Same text, reflowed (the first space ↔ a line break): format-only (whitespace) under FORMAT §3.8 (0.8.1: only a line break is reflow). */
const formatOnly = (t: string) => (t.includes('\n') ? t.replace('\n', ' ') : t.replace(' ', '\n'));
let realN = 0;
const realChange = (t: string) => `${t.replace(/ rev\d+\.$/, '.').replace(/\.$/, '')} rev${++realN}.`;

describe('P1: a derived note is never can_act after a real source change', () => {
  it('60 seeded sequences × 10 operations', { timeout: 120_000 }, () => {
    const r = rng(20261102);
    const failures: string[] = [];
    const seen = { stale: 0, fresh: 0, ops: new Set<string>() };
    for (let seq = 0; seq < 60; seq++) {
      const store = new KronicleLite({ memory: true });
      const paras = [0, 1, 2, 3].map((i) => `Fact ${i} of seq ${seq} is value-${i}x${seq}.`);
      let slug = 'src';
      const put = store.docs.putDocument({ slug, title: 'Src', markdown: `# Src\n\n## Alpha\n\n${paras[0]}\n\n${paras[1]}\n\n## Beta\n\n${paras[2]}\n\n${paras[3]}\n`, actor_id: 'human' });
      const srcDoc = put.doc_id;
      const originals = put.blocks.filter((b) => b.kind === 'paragraph');
      const tracked = [pick(r, originals), pick(r, originals)];
      // model: origin of each live block, and whether that origin really changed
      const origin = new Map<string, string>(originals.map((b) => [b.block_id, b.block_id]));
      const changed = new Set<string>();
      const trackedIds = new Set(tracked.map((t) => t.block_id));

      const dir = tempDir('kl-lineage-prop-');
      const file = join(dir, 'note.md');
      const noteMd = `# Note\n\nDerived summary number ${seq} keeps zebra.\n`;
      write(file, noteMd);
      store.docs.putDocument({ slug: 'note', title: 'Note', markdown: noteMd, actor_id: 'agent', source: { kind: 'file', path: file }, derived_from: tracked.map((t) => ({ block_id: t.block_id, content_hash: t.content_hash })), infer_lineage: false });

      for (let step = 0; step < 10; step++) {
        const live = store.docs.liveBlocks(srcDoc).filter((b) => b.kind === 'paragraph');
        const op = live.length === 0 ? 'rename' : pick(r, ['format', 'real', 'tombstone', 'move', 'rename'] as const);
        if (op === 'format' || op === 'real') {
          const b = pick(r, live);
          const res = store.docs.supersedeBlock({ block_id: b.block_id, new_content: op === 'format' ? formatOnly(b.content) : realChange(b.content), reason: op, actor_id: 'human' });
          const o = origin.get(b.block_id)!;
          origin.set(res.new_block_id, o);
          if (op === 'real') changed.add(o);
        } else if (op === 'tombstone') {
          const b = pick(r, live);
          store.docs.tombstoneBlock({ block_id: b.block_id, reason: 'gone', actor_id: 'human' });
          changed.add(origin.get(b.block_id)!);
        } else if (op === 'rename') {
          const next = slug === 'src' ? 'src-renamed' : 'src';
          store.docs.renameDocument({ doc_id: srcDoc, slug: next, actor_id: 'human', reason: 'rename' });
          slug = next;
        } else {
          // Move one paragraph to the other section (re-put of the current text).
          const mv = pick(r, live);
          const sec = (b: { heading_path: string }) => (b.heading_path.endsWith('Alpha') ? 'Alpha' : 'Beta');
          const alpha = live.filter((b) => (b === mv ? sec(b) !== 'Alpha' : sec(b) === 'Alpha')).map((b) => b.content);
          const beta = live.filter((b) => (b === mv ? sec(b) !== 'Beta' : sec(b) === 'Beta')).map((b) => b.content);
          const res = store.docs.putDocument({ slug, title: 'Src', markdown: `# Src\n\n## Alpha\n\n${alpha.join('\n\n')}\n\n## Beta\n\n${beta.join('\n\n')}\n`, actor_id: 'human' });
          for (const s of res.blocks) {
            if (!s.supersedes) continue;
            const o = origin.get(s.supersedes);
            if (o === undefined) continue;
            origin.set(s.block_id, o);
            changed.add(o); // a move (or any re-pairing) is a real change
          }
          for (const s of res.blocks) if (s.status === 'tombstoned' && origin.has(s.block_id)) changed.add(origin.get(s.block_id)!);
        }
        const expectStale = [...changed].some((o) => trackedIds.has(o));
        seen[expectStale ? 'stale' : 'fresh']++;
        seen.ops.add(op);
        const hit = store.recall.recall({ query: `derived summary ${seq} zebra` }).hits.find((h) => h.doc_slug === 'note');
        const got = hit ? { authority: hit.authority, reason: hit.authority_reason, stale: hit.stale_derived?.length ?? 0 } : null;
        const ok =
          got !== null &&
          !(got.authority === 'can_act' && got.stale > 0) &&
          (expectStale ? got.authority === 'never_act' && got.reason === 'stale_derived' && got.stale > 0 : got.authority === 'can_act' && got.stale === 0);
        if (!ok) failures.push(JSON.stringify({ seq, step, op, expectStale, got }));
      }
      expect(store.verifyAll().ok).toBe(true);
      store.close();
    }
    expect(failures).toEqual([]);
    // The generator exercised both outcomes and every operation.
    expect(seen.stale).toBeGreaterThan(100);
    expect(seen.fresh).toBeGreaterThan(50);
    expect([...seen.ops].sort()).toEqual(['format', 'move', 'real', 'rename', 'tombstone']);
  });
});

describe('P2: resolution only by reading the current version', () => {
  it('60 seeded sequences × 14 steps', { timeout: 120_000 }, () => {
    const r = rng(20261103);
    const failures: string[] = [];
    const seen = { pending: 0, clear: 0, removedPending: 0, resolvedByCurrent: 0 };
    for (let seq = 0; seq < 60; seq++) {
      const store = new KronicleLite({ memory: true });
      const put = store.docs.putDocument({ slug: 'doc', title: 'Doc', markdown: `# Doc\n\nThe endpoint for run ${seq} is host-${seq}.example.\n\nUnrelated paragraph ${seq}.\n`, actor_id: 'human' });
      const docId = put.doc_id;
      const first = put.blocks.find((b) => b.kind === 'paragraph' && b.ordinal === 1)!;
      // model: versions in order with their equivalence class (bumped by a real change)
      const versions: { id: string; cls: number }[] = [{ id: first.block_id, cls: 0 }];
      let cls = 0;
      let readCls = -1; // highest class the actor read
      let readAny = false;
      let removedAtStep = -1;
      let readAfterRemoval = false;

      for (let step = 0; step < 14; step++) {
        const head = versions[versions.length - 1]!;
        const action = removedAtStep >= 0 ? pick(r, ['read_old', 'read_doc', 'read_other'] as const) : pick(r, ['real', 'format', 'read_old', 'read_current', 'read_other', 'remove'] as const);
        if (action === 'real' || action === 'format') {
          const b = store.docs.getBlock(head.id)!;
          const res = store.docs.supersedeBlock({ block_id: head.id, new_content: action === 'format' ? formatOnly(b.content) : realChange(b.content), reason: action, actor_id: 'human' });
          if (action === 'real') cls++;
          versions.push({ id: res.new_block_id, cls });
        } else if (action === 'read_old' || action === 'read_current') {
          const v = action === 'read_current' ? head : pick(r, versions);
          store.lineage.recordBlockReads('a', [store.docs.getBlock(v.id)!], 'recall');
          readAny = true;
          if (removedAtStep >= 0) {
            // Reading a superseded old version after the removal acknowledges nothing; the tombstoned head itself does.
            if (v.id === head.id) readAfterRemoval = true;
          } else readCls = Math.max(readCls, v.cls);
        } else if (action === 'read_other') {
          store.recall.recall({ query: `unrelated paragraph ${seq}`, actor_id: 'a' });
        } else if (action === 'read_doc') {
          store.lineage.recordDocumentRead('a', docId, 'document');
          readAfterRemoval = true;
        } else {
          store.docs.tombstoneBlock({ block_id: head.id, reason: 'removed', actor_id: 'human' });
          removedAtStep = step;
        }
        const expected = removedAtStep >= 0 ? readAny && !readAfterRemoval : readAny && readCls < cls;
        seen[expected ? 'pending' : 'clear']++;
        if (expected && removedAtStep >= 0) seen.removedPending++;
        if (!expected && readAny && cls > 0 && action === 'read_current') seen.resolvedByCurrent++;
        const p = store.lineage.pending('a');
        const mine = p.items.filter((i) => i.doc_slug === 'doc' && i.kind !== 'derived' && (i.read.block_id === first.block_id || versions.some((v) => v.id === i.read.block_id)));
        const gotPending = mine.length > 0;
        let ok = gotPending === expected && mine.length <= 1;
        if (ok && gotPending && removedAtStep < 0) ok = mine[0]!.current?.block_id === versions[versions.length - 1]!.id;
        if (ok && gotPending && removedAtStep >= 0) ok = mine[0]!.current === null;
        if (!ok) failures.push(JSON.stringify({ seq, step, action, expected, got: mine.map((m) => ({ read: m.read.block_id, cur: m.current?.block_id })), cls, readCls }));
      }
      store.close();
    }
    expect(failures).toEqual([]);
    expect(seen.pending).toBeGreaterThan(100);
    expect(seen.clear).toBeGreaterThan(100);
    expect(seen.removedPending).toBeGreaterThan(10);
    expect(seen.resolvedByCurrent).toBeGreaterThan(5);
  });
});
