/**
 * 0.6.0 retrieval honesty tags: every recall hit carries an action authority
 * (can_act | inspect_only | never_act) with a reason and the evidence it rests
 * on. Only block-level evidence (this block's exact text found, now, in the
 * document's recorded source file) reaches can_act; document-level provenance
 * caps at inspect_only; superseded, tombstoned and withheld are never_act.
 */

import { readFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import { bindGit } from '../src/git/binding.js';
import {
  AUTHORITY_REASONS,
  HONESTY_RULES,
  authorityFloor,
  resolveAuthority,
  type HonestyInput,
} from '../src/recall/honesty.js';
import { KronicleLite } from '../src/store.js';
import { gitInit, gitRun, tempDir, write } from './helpers/fs.js';

const DOC = '# Deploy\n\nUse blue/green for the API.\n\nRoll back with `deploy undo`.\n';

function boundRepo(store: KronicleLite) {
  const root = tempDir('kl-honesty-');
  gitInit(root);
  const file = join(root, 'docs', 'deploy.md');
  write(file, DOC);
  gitRun(root, ['add', '-A']);
  gitRun(root, ['commit', '-q', '-m', 'docs']);
  const b = bindGit(file);
  expect(b.binding).not.toBeNull();
  const put = store.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: DOC, actor_id: 't', source: { kind: 'file', path: b.binding!.path, git: b.binding! } });
  return { root, file, put };
}

const base: HonestyInput = { status: 'live', source_kind: null, source_check: 'unchecked', read_scrubbed: false };

describe('resolveAuthority (the rule table)', () => {
  it('only block-level evidence reaches can_act', () => {
    expect(resolveAuthority({ ...base, source_kind: 'file', source_check: 'match' })).toEqual({ authority: 'can_act', reason: 'block_matches_source', basis: 'block' });
    // Document-level provenance alone: capped at inspect_only, whatever the kind.
    for (const kind of ['file', 'instruction']) {
      expect(resolveAuthority({ ...base, source_kind: kind })).toEqual({ authority: 'inspect_only', reason: 'document_source_only', basis: 'document' });
    }
    expect(resolveAuthority(base)).toEqual({ authority: 'inspect_only', reason: 'no_source', basis: 'none' });
    expect(resolveAuthority({ ...base, source_kind: 'file', source_check: 'unavailable' })).toMatchObject({ authority: 'inspect_only', reason: 'source_unavailable' });
  });

  it('model-written memory never reaches can_act, even when it matches its file', () => {
    expect(resolveAuthority({ ...base, source_kind: 'memory', source_check: 'match' })).toMatchObject({ authority: 'inspect_only', reason: 'model_memory' });
  });

  it('superseded / tombstoned / drifted / missing are never_act, even when the text matches', () => {
    expect(resolveAuthority({ ...base, status: 'superseded', source_kind: 'file', source_check: 'match' })).toMatchObject({ authority: 'never_act', reason: 'superseded' });
    expect(resolveAuthority({ ...base, status: 'tombstoned', source_kind: 'file', source_check: 'match' })).toMatchObject({ authority: 'never_act', reason: 'tombstoned' });
    expect(resolveAuthority({ ...base, source_kind: 'file', source_check: 'not_in_source' })).toMatchObject({ authority: 'never_act', reason: 'not_in_source' });
    expect(resolveAuthority({ ...base, source_kind: 'file', source_check: 'missing' })).toMatchObject({ authority: 'never_act', reason: 'source_missing' });
  });

  it('a read-time scrub caps can_act at inspect_only (the text shown is not the chained text)', () => {
    expect(resolveAuthority({ ...base, source_kind: 'file', source_check: 'match', read_scrubbed: true })).toMatchObject({ authority: 'inspect_only', reason: 'read_scrubbed' });
    expect(resolveAuthority({ ...base, status: 'superseded', read_scrubbed: true })).toMatchObject({ authority: 'never_act', reason: 'superseded' });
  });

  it('exhaustively: can_act ⇒ basis block, live status, a matching source check and no scrub', () => {
    for (const status of ['live', 'superseded', 'tombstoned'] as const)
      for (const source_kind of [null, 'file', 'instruction', 'memory'])
        for (const source_check of ['match', 'not_in_source', 'missing', 'unavailable', 'unchecked'] as const)
          for (const read_scrubbed of [false, true]) {
            const r = resolveAuthority({ status, source_kind, source_check, read_scrubbed });
            expect(AUTHORITY_REASONS).toContain(r.reason);
            if (r.authority === 'can_act') {
              expect(r.basis).toBe('block');
              expect(status).toBe('live');
              expect(source_check).toBe('match');
              expect(read_scrubbed).toBe(false);
              expect(source_kind).not.toBe('memory');
            }
          }
  });

  it('the floor is the meet of the set; an empty set has no floor (never a licence to act)', () => {
    expect(authorityFloor([])).toBeNull();
    expect(authorityFloor(['can_act', 'can_act'])).toBe('can_act');
    expect(authorityFloor(['can_act', 'inspect_only'])).toBe('inspect_only');
    expect(authorityFloor(['inspect_only', 'never_act', 'can_act'])).toBe('never_act');
  });

  it('docs/HONESTY.md states every rule and reason code', () => {
    const doc = readFileSync(join(__dirname, '..', 'docs', 'HONESTY.md'), 'utf8');
    for (const reason of AUTHORITY_REASONS) expect(doc, reason).toContain(`\`${reason}\``);
    for (const rule of HONESTY_RULES) expect(doc, rule.reason).toMatch(new RegExp(`\\|\\s*${rule.n}\\s*\\|`));
  });
});

describe('recall hits carry honesty tags', () => {
  it('a plain put (no source) is inspect_only / no_source; the floor is reported', () => {
    const store = new KronicleLite({ memory: true });
    store.docs.putDocument({ slug: 'notes', title: 'Notes', markdown: '# Notes\n\nThe canary runs at noon.\n', actor_id: 't' });
    const r = store.recall.recall({ query: 'canary noon' });
    expect(r.hits[0]).toMatchObject({ authority: 'inspect_only', authority_reason: 'no_source', authority_basis: 'none' });
    expect(r.authority_floor).toBe('inspect_only');
    store.close();
  });

  it('git-bound: can_act per block while the file holds that text; doc-level "current" does not bless an edited block', () => {
    const store = new KronicleLite({ memory: true });
    const { put } = boundRepo(store);
    const r1 = store.recall.recall({ query: 'blue green API' });
    expect(r1.hits[0]).toMatchObject({ authority: 'can_act', authority_reason: 'block_matches_source', authority_basis: 'block' });
    expect(r1.authority_floor).toBe('can_act');

    // supersede_block after binding: the file is untouched, so the document-level
    // binding still says `current` — but this block's text is not in the file.
    const target = put.blocks.find((b) => store.docs.getBlock(b.block_id)!.content.includes('blue/green'))!;
    store.docs.supersedeBlock({ block_id: target.block_id, new_content: 'Use canary releases for the API.', reason: 'policy', actor_id: 'agent' });
    expect(store.docs.sourceDrift(put.doc_id)?.state).toBe('current');
    const r2 = store.recall.recall({ query: 'canary releases API' });
    expect(r2.hits[0]).toMatchObject({ authority: 'never_act', authority_reason: 'not_in_source', authority_basis: 'block' });
    const roll = store.recall.recall({ query: 'deploy undo' });
    expect(roll.hits[0]).toMatchObject({ authority: 'can_act' });
    store.close();
  });

  it('git-bound: a changed file demotes exactly the changed block; a deleted file demotes all', () => {
    const store = new KronicleLite({ memory: true });
    const { file } = boundRepo(store);
    write(file, DOC.replace('blue/green', 'rolling'));
    expect(store.recall.recall({ query: 'blue green API' }).hits[0]).toMatchObject({ authority: 'never_act', authority_reason: 'not_in_source' });
    expect(store.recall.recall({ query: 'deploy undo' }).hits[0]).toMatchObject({ authority: 'can_act' });
    unlinkSync(file);
    const gone = store.recall.recall({ query: 'deploy undo' });
    expect(gone.hits[0]).toMatchObject({ authority: 'never_act', authority_reason: 'source_missing' });
    expect(gone.authority_floor).toBe('never_act');
    store.close();
  });

  it('instruction files (project root recorded) are checked block by block; auto memory is capped', () => {
    const store = new KronicleLite({ memory: true });
    const root = tempDir('kl-honesty-instr-');
    write(join(root, 'CLAUDE.md'), '# Rules\n\nNever push to main directly.\n');
    write(join(root, 'mem', 'MEMORY.md'), '# Memory\n\nThe user prefers tabs.\n');
    const project = { key: 'proj-00000000', root };
    store.docs.putDocument({ slug: 'instructions/proj-00000000/claude-md', title: 'CLAUDE.md', markdown: '# Rules\n\nNever push to main directly.\n', actor_id: 'i', source: { kind: 'instruction', path: 'CLAUDE.md', project } });
    store.docs.putDocument({ slug: 'memory/proj-00000000/MEMORY', title: 'MEMORY.md', markdown: '# Memory\n\nThe user prefers tabs.\n', actor_id: 'i', source: { kind: 'memory', path: join(root, 'mem', 'MEMORY.md') } });
    store.docs.putDocument({ slug: 'loose', title: 'Loose', markdown: 'Loose relative file about bananas.\n', actor_id: 'i', source: { kind: 'file', path: 'somewhere/loose.md' } });
    expect(store.recall.recall({ query: 'push main' }).hits[0]).toMatchObject({ authority: 'can_act', authority_reason: 'block_matches_source' });
    expect(store.recall.recall({ query: 'prefers tabs' }).hits[0]).toMatchObject({ authority: 'inspect_only', authority_reason: 'model_memory' });
    expect(store.recall.recall({ query: 'bananas' }).hits[0]).toMatchObject({ authority: 'inspect_only', authority_reason: 'document_source_only', authority_basis: 'document' });
    // The rule changes on disk before watch re-chains it: the stored copy is no longer the rule.
    write(join(root, 'CLAUDE.md'), '# Rules\n\nPush to main only via PR.\n');
    expect(store.recall.recall({ query: 'push main directly' }).hits[0]).toMatchObject({ authority: 'never_act', authority_reason: 'not_in_source' });
    store.close();
  });

  it('tombstoned hits (include_tombstoned) are never_act; withheld entries say never_act / integrity_failed', () => {
    const store = new KronicleLite({ memory: true });
    const put = store.docs.putDocument({ slug: 'n', title: 'N', markdown: '# N\n\nAlpha bravo charlie.\n\nDelta echo foxtrot.\n', actor_id: 't' });
    const alpha = put.blocks.find((b) => store.docs.getBlock(b.block_id)!.content.startsWith('Alpha'))!;
    store.docs.tombstoneBlock({ block_id: alpha.block_id, reason: 'old', actor_id: 't' });
    const t = store.recall.recall({ query: 'alpha bravo', include_tombstoned: true });
    expect(t.hits[0]).toMatchObject({ status: 'tombstoned', authority: 'never_act', authority_reason: 'tombstoned' });
    const delta = put.blocks.find((b) => store.docs.getBlock(b.block_id)!.content.startsWith('Delta'))!;
    store.db.prepare(`UPDATE blocks SET content = 'Delta echo golf.' WHERE block_id = ?`).run(delta.block_id);
    const w = store.recall.recall({ query: 'delta echo' });
    expect(w.hits).toEqual([]);
    expect(w.withheld[0]).toMatchObject({ block_id: delta.block_id, authority: 'never_act', authority_reason: 'integrity_failed' });
    store.close();
  });
});
