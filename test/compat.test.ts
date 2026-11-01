/**
 * 0.3.0 → 0.4.0 compatibility. test/fixtures/export-0.3.0.jsonl was written
 * by the kronicle-lite 0.3.0 CLI (commit f365d5e): two puts of `deploy`
 * (one supersession, one tombstone), one put of `notes`. Everything 0.4.0
 * adds is additive: old chains must import, verify and re-export
 * byte-for-byte, and keep their 0.3.0 orient semantics.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { PassThrough, Readable } from 'node:stream';
import { describe, expect, it } from 'vitest';

import { KronicleLite } from '../src/store.js';
import { tempDir } from './helpers/fs.js';

const FIXTURE = readFileSync(join(__dirname, 'fixtures', 'export-0.3.0.jsonl'), 'utf8');

async function exportOf(store: KronicleLite): Promise<string> {
  const sink = new PassThrough();
  let buf = '';
  sink.on('data', (c: Buffer) => (buf += c.toString('utf8')));
  store.exportEvents(sink);
  sink.end();
  await new Promise((r) => sink.on('end', r));
  return buf;
}

describe('a 0.3.0 chain under 0.4.0', () => {
  it('imports (every hash and link re-verified), verifies, and re-exports its events byte-for-byte', async () => {
    const store = new KronicleLite({ memory: true });
    const imp = await store.importEvents(Readable.from([FIXTURE]));
    const header = JSON.parse(FIXTURE.split('\n')[0]!) as { head: { seq: number; hash: string } };
    expect(imp.head).toEqual(header.head);
    expect(store.chain.verify()).toMatchObject({ ok: true, events_checked: header.head.seq });
    const again = await exportOf(store);
    // Header differs (exported_at, this store's key); every event line is identical, and no anchors line is added.
    expect(again.split('\n').slice(1)).toEqual(FIXTURE.split('\n').slice(1));
    // 0.3.0 puts carry no `source`: nothing is bound, nothing drifts, no instruction retractions.
    expect(store.docs.listSources()).toEqual([]);
    const state = store.orient.getSystemState({ actor_id: 'compat' });
    expect(state.source_drift).toEqual([]);
    expect(state.anchor).toBeNull();
    expect(state.retractions!.map((r) => r.kind).sort()).toEqual(['supersession', 'tombstone']);
    const hit = store.recall.recall({ query: 'canary' }).hits[0]!;
    expect(store.verifier.verify(hit.receipt).status).toBe('VERIFIED');
    store.close();
  });

  it('a database created before the 0.4.0 tables existed gains them on open and still verifies', () => {
    const dataDir = join(tempDir('kl-compat-'), 'data');
    const a = new KronicleLite({ dataDir });
    a.docs.putDocument({ slug: 'x', title: 'X', markdown: '# X\n\nOne.\n', actor_id: 't' });
    a.chain.checkpoint();
    a.db.exec('DROP TABLE anchors; DROP TABLE doc_sources;');
    a.close();
    const b = new KronicleLite({ dataDir });
    const names = (b.db.prepare(`SELECT name FROM sqlite_master WHERE type = 'table'`).all() as { name: string }[]).map((r) => r.name);
    expect(names).toEqual(expect.arrayContaining(['anchors', 'doc_sources']));
    expect(b.chain.verify()).toMatchObject({ ok: true, checkpoints: [{ ok: true, reason: 'valid' }] });
    b.close();
  });
});
