/**
 * 0.6.0 honest absence: recall says which scopes it searched and which it did
 * not, and whether the index it searched is fresh. "Searched, found nothing"
 * is a different answer from "not searched", and a stale or cold index never
 * certifies "not found". Orient's verdict degrades when a scope is hidden.
 */

import { describe, expect, it } from 'vitest';

import { certifyRecallAbsence } from '../src/recall/absence.js';
import { renderSystemStateMarkdown } from '../src/server.js';
import { KronicleLite } from '../src/store.js';

const MD = '# Infra\n\nThe database password rotates every 90 days.\n\nDeploy on Tuesdays only.\n';

describe('certifyRecallAbsence (pure)', () => {
  const searched = ['live_blocks'] as const;
  const not_searched = ['tombstoned_blocks', 'superseded_blocks'] as const;
  it('found when there are hits, whatever else is true', () => {
    expect(certifyRecallAbsence({ hits: 2, withheld: 0, searched: [...searched], not_searched: [...not_searched], index_fresh: false }).verdict).toBe('found');
  });
  it('absent_in_searched only from a fresh index with nothing withheld, and it names what was not searched', () => {
    const a = certifyRecallAbsence({ hits: 0, withheld: 0, searched: [...searched], not_searched: [...not_searched], index_fresh: true });
    expect(a.verdict).toBe('absent_in_searched');
    expect(a.reason).toMatch(/live_blocks/);
    expect(a.reason).toMatch(/not searched: tombstoned_blocks, superseded_blocks/);
  });
  it('cannot_certify from a stale/cold index, from withheld matches, or when nothing was searched', () => {
    expect(certifyRecallAbsence({ hits: 0, withheld: 0, searched: [...searched], not_searched: [...not_searched], index_fresh: false }).verdict).toBe('cannot_certify');
    expect(certifyRecallAbsence({ hits: 0, withheld: 1, searched: [...searched], not_searched: [...not_searched], index_fresh: true }).verdict).toBe('cannot_certify');
    expect(certifyRecallAbsence({ hits: 0, withheld: 0, searched: [], not_searched: ['live_blocks'], index_fresh: true }).verdict).toBe('cannot_certify');
  });
});

describe('recall absence', () => {
  it('every result carries absence; a clean miss is absent_in_searched, not a global "not found"', () => {
    const store = new KronicleLite({ memory: true });
    store.docs.putDocument({ slug: 'infra', title: 'Infra', markdown: MD, actor_id: 't' });
    const hit = store.recall.recall({ query: 'password rotates' });
    expect(hit.absence).toMatchObject({ verdict: 'found', searched: ['live_blocks'], not_searched: ['tombstoned_blocks', 'superseded_blocks'], index_fresh: true });
    const miss = store.recall.recall({ query: 'kubernetes namespace' });
    expect(miss.hits).toEqual([]);
    expect(miss.absence).toMatchObject({ verdict: 'absent_in_searched', searched: ['live_blocks'], index_fresh: true });
    const withTomb = store.recall.recall({ query: 'kubernetes', include_tombstoned: true });
    expect(withTomb.absence).toMatchObject({ searched: ['live_blocks', 'tombstoned_blocks'], not_searched: ['superseded_blocks'] });
    store.close();
  });

  it('a query with no searchable terms searched nothing and says so', () => {
    const store = new KronicleLite({ memory: true });
    store.docs.putDocument({ slug: 'infra', title: 'Infra', markdown: MD, actor_id: 't' });
    const r = store.recall.recall({ query: '?!  …' });
    expect(r.absence).toMatchObject({ verdict: 'cannot_certify', searched: [] });
    expect(r.absence.not_searched).toContain('live_blocks');
    store.close();
  });

  it('a cold full-text index (blocks not indexed) never certifies absence', () => {
    const store = new KronicleLite({ memory: true });
    store.docs.putDocument({ slug: 'infra', title: 'Infra', markdown: MD, actor_id: 't' });
    store.db.exec(`INSERT INTO blocks_fts(blocks_fts) VALUES ('delete-all')`);
    const r = store.recall.recall({ query: 'password rotates' });
    expect(r.hits).toEqual([]);
    expect(r.absence).toMatchObject({ verdict: 'cannot_certify', index_fresh: false });
    expect(r.absence.reason).toMatch(/index/);
    store.close();
  });

  it('a projection behind the chain (stale index) never certifies absence', () => {
    const store = new KronicleLite({ memory: true });
    store.docs.putDocument({ slug: 'infra', title: 'Infra', markdown: MD, actor_id: 't' });
    store.docs.putDocument({ slug: 'infra', title: 'Infra', markdown: MD + '\nNew paragraph about zebras.\n', actor_id: 't' });
    // Lose the last revision's projection rows, as a crashed or hand-edited store would.
    const doc = store.docs.getDocument('infra')!;
    store.db.prepare(`DELETE FROM document_revisions WHERE doc_id = ? AND revision = 2`).run(doc.doc_id);
    store.db.exec(`DELETE FROM blocks WHERE content LIKE '%zebras%'`);
    const r = store.recall.recall({ query: 'zebras' });
    expect(r.hits).toEqual([]);
    expect(r.absence).toMatchObject({ verdict: 'cannot_certify', index_fresh: false });
    store.close();
  });

  it('matches withheld for integrity are not an absence', () => {
    const store = new KronicleLite({ memory: true });
    store.docs.putDocument({ slug: 'infra', title: 'Infra', markdown: MD, actor_id: 't' });
    store.db.exec(`UPDATE blocks SET content = 'Deploy on Tuesdays only!' WHERE content = 'Deploy on Tuesdays only.'`);
    const r = store.recall.recall({ query: 'tuesdays' });
    expect(r.hits).toEqual([]);
    expect(r.absence.verdict).toBe('cannot_certify');
    store.close();
  });
});

describe('orient: a hidden scope degrades the verdict', () => {
  it('scope.verdict is partial when other projects are hidden, and the briefing says so', () => {
    const store = new KronicleLite({ memory: true });
    const mk = (key: string, text: string) =>
      store.docs.putDocument({
        slug: `instructions/${key}/claude-md`,
        title: 'CLAUDE.md',
        markdown: `# Rules\n\n${text}\n`,
        actor_id: 'i',
        source: { kind: 'instruction', path: 'CLAUDE.md', project: { key, root: `/r/${key}` } },
      });
    mk('a-00000001', 'Rule A one.');
    mk('b-00000002', 'Rule B one.');
    const s0 = store.orient.getSystemState({ actor_id: 'x', project: { keys: ['a-00000001'] } });
    expect(s0.scope).toMatchObject({ hidden_retractions: 0, verdict: 'complete' });
    mk('b-00000002', 'Rule B two.');
    const s1 = store.orient.getSystemState({ actor_id: 'x', since_cursor: s0.cursor, project: { keys: ['a-00000001'] } });
    expect(s1.retractions).toEqual([]);
    expect(s1.scope).toMatchObject({ hidden_retractions: 1, verdict: 'partial' });
    const md = renderSystemStateMarkdown(s1);
    expect(md).not.toMatch(/## Retractions: none\n/);
    expect(md).toMatch(/none in this project/);
    expect(s1.next_steps.join('\n')).toMatch(/not reviewed/);
    // Unscoped orient has nothing hidden: no scope block at all.
    const all = store.orient.getSystemState({ actor_id: 'y', since_cursor: undefined, project: null });
    expect(all.scope).toBeNull();
    store.close();
  });
});
