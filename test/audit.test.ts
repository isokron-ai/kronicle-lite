import { describe, expect, it } from 'vitest';

import { blake3Hex } from '../src/crypto/hash.js';
import { KronicleLite } from '../src/store.js';

describe('audit_assumptions', () => {
  it('grades block, document and head claims', () => {
    const kl = new KronicleLite({ memory: true });
    const put = kl.docs.putDocument({ slug: 'd', title: 'D', markdown: '# D\n\nalpha\n\nbeta\n\ngamma', actor_id: 'w' });
    const [h, a, b, g] = put.blocks.map((x) => x.block_id) as [string, string, string, string];
    const sup = kl.docs.supersedeBlock({ block_id: b, new_content: 'BETA', reason: 'caps', actor_id: 'w' });
    kl.docs.tombstoneBlock({ block_id: g, reason: 'gone', actor_id: 'w' });
    const head = kl.chain.head();

    const r = kl.auditor.audit([
      { symbol: a, value: 'alpha' },
      { symbol: a, value: blake3Hex('alpha') },
      { symbol: a, value: 'ALPHA' },
      { symbol: b, value: 'beta' },
      { symbol: g, value: 'gamma' },
      { symbol: h, value: 'D' },
      { symbol: '00000000-0000-4000-8000-000000000000', value: 'x' },
      { symbol: 'd', value: 1 },
      { symbol: 'd', value: 3 },
      { symbol: 'd', value: 9 },
      { symbol: 'nope', value: 1 },
      { symbol: 'head', value: head.seq },
      { symbol: 'head', value: head.hash },
      { symbol: 'head', value: 1 },
    ]);
    expect(r.results.map((x) => x.verdict)).toEqual([
      'current',
      'current',
      'contradicted',
      'stale',
      'retracted',
      'current',
      'unknown',
      'stale',
      'current',
      'contradicted',
      'unknown',
      'current',
      'current',
      'stale',
    ]);
    expect(r.results[3]!.current).toMatchObject({ block_id: sup.new_block_id, content: 'BETA' });
    expect(r.results[3]!.reconcile).toMatch(/SUPERSEDED by/);
    expect(r.results[4]!.reconcile).toMatch(/TOMBSTONED — gone/);
    expect(r.results[2]!.reconcile).toMatch(/Reconcile before proceeding/);
    expect(r.counts).toEqual({ current: 6, stale: 3, contradicted: 2, retracted: 1, unknown: 2 });
    kl.close();
  });
});
