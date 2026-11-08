/**
 * #15 (0.9.0 blocker): MAC check. A 32-byte MAC in 43 base64url characters
 * leaves 2 unused bits in the last one, so 4 spellings decoded to the same MAC
 * and all verified. The MAC is now compared as the canonical string.
 */
import { describe, expect, it } from 'vitest';

import { type ApplyOp } from '../src/apply/apply.js';
import { KronicleLite } from '../src/index.js';

function seeded() {
  const kl = new KronicleLite({ memory: true });
  const a = kl.docs.putDocument({ slug: 'alpha', title: 'Alpha', markdown: '# Alpha\n\nport 8080.\n', actor_id: 'h' });
  return { kl, port: a.blocks.filter((b) => b.kind === 'paragraph')[0]!.block_id };
}
const code = (fn: () => unknown): string => {
  try {
    const r = fn() as { status?: string } | undefined;
    return `ok:${r?.status ?? ''}`;
  } catch (err) {
    return (err as { code?: string }).code ?? (err as Error).message;
  }
};

describe('#15 confirm token MAC: canonical base64url only', () => {
  const B64U = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  it('the three non-canonical spellings of the last character are refused; the canonical one commits', () => {
    const { kl, port } = seeded();
    const ops: ApplyOp[] = [{ id: 'a', op: 'supersede', block_id: port, new_content: 'Port 9090.', reason: 'x' }];
    const t = kl.applier.apply({ actor_id: 'A', ops, dry_run: true }).confirm_token!;
    const v = B64U.indexOf(t.at(-1)!);
    expect(v % 4).toBe(0); // canonical: the 2 unused bits are 0
    for (const d of [1, 2, 3]) {
      const alt = t.slice(0, -1) + B64U[v + d];
      expect(Buffer.from(alt.split('.')[2]!, 'base64url').equals(Buffer.from(t.split('.')[2]!, 'base64url'))).toBe(true);
      expect(code(() => kl.applier.apply({ actor_id: 'A', ops, confirm_token: alt })), alt).toBe('confirm_invalid');
    }
    expect(kl.applier.apply({ actor_id: 'A', ops, confirm_token: t }).status).toBe('committed');
    kl.close();
  });
});
