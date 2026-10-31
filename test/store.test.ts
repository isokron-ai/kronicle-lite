import { PassThrough, Readable } from 'node:stream';
import { describe, expect, it } from 'vitest';

import { KronicleLite } from '../src/store.js';

describe('export / import', () => {
  it('round-trips events into an empty store and rebuilds the projection', async () => {
    const a = new KronicleLite({ memory: true });
    const put = a.docs.putDocument({ slug: 'd', title: 'D', markdown: '# D\n\none\n\ntwo', actor_id: 'w' });
    a.docs.supersedeBlock({ block_id: put.blocks[1]!.block_id, new_content: 'uno', reason: 'r', actor_id: 'w' });
    a.docs.tombstoneBlock({ block_id: put.blocks[2]!.block_id, reason: 'gone', actor_id: 'w' });
    const rc = a.recall.recall({ query: 'uno' });
    const receipt = rc.hits[0]!.receipt!;

    const sink = new PassThrough();
    let buf = '';
    sink.on('data', (c: Buffer) => (buf += c.toString('utf8')));
    const exp = a.exportEvents(sink);
    sink.end();
    await new Promise((r) => sink.on('end', r));
    expect(exp.events).toBe(a.chain.head().seq);
    const lines = buf.trim().split('\n');
    expect(lines).toHaveLength(exp.events + 1);
    expect(JSON.parse(lines[0]!)).toMatchObject({ kronicle_lite_export: 1, key_id: a.identity.signer.key_id });

    const b = new KronicleLite({ memory: true });
    const imp = await b.importEvents(Readable.from([buf]));
    expect(imp.head).toEqual(a.chain.head());
    expect(b.chain.verify().ok).toBe(true);
    expect(b.docs.liveBlocks(put.doc_id).map((x) => x.content)).toEqual(a.docs.liveBlocks(put.doc_id).map((x) => x.content));
    expect(b.docs.getBlock(put.blocks[2]!.block_id)!.tombstone_reason).toBe('gone');
    expect(b.docs.getRevisionMarkdown(put.doc_id, 3)).toBe(a.docs.getRevisionMarkdown(put.doc_id, 3));
    // Receipts issued by A verify in B because A's public key was imported.
    expect(b.verifier.verify(receipt).status).toBe('VERIFIED');

    // Refuses a non-empty target and a tampered line.
    await expect(b.importEvents(Readable.from([buf]))).rejects.toThrow(/empty store/);
    const c = new KronicleLite({ memory: true });
    const tampered = lines.map((l, i) => (i === 2 ? l.replace('"actor_id":"w"', '"actor_id":"mallory"') : l)).join('\n');
    await expect(c.importEvents(Readable.from([tampered]))).rejects.toThrow(/this_hash mismatch/);
    expect(c.chain.head().seq).toBe(0); // nothing committed
    a.close();
    b.close();
    c.close();
  });
});
