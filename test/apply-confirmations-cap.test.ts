/**
 * #15 (0.9.0 blocker): confirmation table growth. Actor ids are self-asserted,
 * so distinct actors grew apply_confirmations without bound until TTL. A global
 * cap (MAX_CONFIRMATIONS) evicts the oldest rows first (DoS only: an evicted
 * token answers confirm_invalid, it never authorizes anything).
 */
import { describe, expect, it } from 'vitest';

import { MAX_CONFIRMATIONS, type ApplyOp } from '../src/apply/apply.js';
import { KronicleLite } from '../src/index.js';

function seeded() {
  const kl = new KronicleLite({ memory: true });
  const a = kl.docs.putDocument({ slug: 'alpha', title: 'Alpha', markdown: '# Alpha\n\nport 8080.\n', actor_id: 'h' });
  return { kl, port: a.blocks.filter((b) => b.kind === 'paragraph')[0]!.block_id };
}
const count = (kl: KronicleLite) => (kl.db.prepare(`SELECT COUNT(*) AS n FROM apply_confirmations`).get() as { n: number }).n;

describe('#15 apply_confirmations: a global cap, oldest first', () => {
  it('distinct (self-asserted) actors cannot grow the table past MAX_CONFIRMATIONS; the newest survive', () => {
    const { kl, port } = seeded();
    const later = new Date(Date.now() + 600_000).toISOString();
    const ins = kl.db.prepare(`INSERT INTO apply_confirmations (nonce, plan_hash, actor_id, issued_at, expires_at, binding_json) VALUES (?, 'p', ?, ?, ?, '{}')`);
    kl.db.transaction(() => {
      for (let i = 0; i < MAX_CONFIRMATIONS + 50; i++) ins.run(i.toString(16).padStart(32, '0'), `sybil-${i}`, new Date().toISOString(), later);
    })();
    const ops: ApplyOp[] = [{ id: 'a', op: 'supersede', block_id: port, new_content: 'Port 9090.', reason: 'x' }];
    const t = kl.applier.apply({ actor_id: 'A', ops, dry_run: true }).confirm_token!;
    expect(count(kl)).toBe(MAX_CONFIRMATIONS);
    const has = (nonce: string) => kl.db.prepare(`SELECT 1 FROM apply_confirmations WHERE nonce = ?`).get(nonce) !== undefined;
    expect(has((0).toString(16).padStart(32, '0'))).toBe(false); // oldest evicted
    expect(has((MAX_CONFIRMATIONS + 49).toString(16).padStart(32, '0'))).toBe(true); // newest kept
    expect(kl.applier.apply({ actor_id: 'A', ops, confirm_token: t }).status).toBe('committed');
    kl.close();
  });
});
