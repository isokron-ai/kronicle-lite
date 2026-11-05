import { describe, expect, it } from 'vitest';

import { ApplyEngine, type ApplyError, type ApplyOp } from '../src/apply/apply.js';
import { KronicleLite } from '../src/index.js';

function seeded() {
  const kl = new KronicleLite({ memory: true });
  const a = kl.docs.putDocument({ slug: 'alpha', title: 'Alpha', markdown: '# Alpha\n\nport 8080.\n\nhost blue.\n', actor_id: 'h' });
  const para = a.blocks.filter((b) => b.kind === 'paragraph');
  return { kl, port: para[0]!.block_id, host: para[1]!.block_id };
}

const counts = (kl: KronicleLite) => ({
  head: kl.chain.head().seq,
  docs: (kl.db.prepare('SELECT COUNT(*) AS n FROM documents').get() as { n: number }).n,
  live: (kl.db.prepare('SELECT COUNT(*) AS n FROM blocks WHERE valid_to IS NULL AND tombstoned_at IS NULL').get() as { n: number }).n,
});

const code = (fn: () => unknown): string => {
  try {
    fn();
  } catch (err) {
    return (err as ApplyError).code;
  }
  return 'no error';
};

describe('apply: all_or_nothing is one real SQLite transaction', () => {
  it('commits every op, one apply.committed event with plan hash, result hash and per-op receipts', () => {
    const { kl, port } = seeded();
    const before = kl.chain.head().seq;
    const r = kl.applier.apply({
      actor_id: 'agent',
      ops: [
        { id: 'a', op: 'supersede', block_id: port, new_content: 'port 9090.', reason: 'moved', expect_version: 1 },
        { id: 'b', op: 'put', slug: 'beta', title: 'Beta', markdown: '# Beta\n\nnew.\n', expect_version: 0 },
      ],
    });
    expect(r).toMatchObject({ status: 'committed', atomic: true, replayed: false });
    expect(r.ops.map((o) => [o.status, o.version_before, o.version_after])).toEqual([
      ['applied', 1, 2],
      ['applied', 0, 1],
    ]);
    expect(r.ops[0]!.diff).toContain('[-8080.-]{+9090.+}');
    const ev = kl.chain.get(r.receipt!.seq)!;
    expect(ev.event_type).toBe('apply.committed');
    expect(ev.payload).toMatchObject({ plan_hash: r.plan_hash, result_hash: r.result_hash, mode: 'all_or_nothing' });
    expect(kl.chain.range(before + 1, kl.chain.head().seq).filter((e) => e.event_type === 'apply.committed')).toHaveLength(1);
    expect(r.ops[0]!.receipt!.first_seq).toBe(before + 1);
    expect(kl.verifyAll().ok).toBe(true);
    kl.close();
  });

  it('rolls back everything when ANY op fails (first, middle or last), leaving no event and no rows', () => {
    for (const failAt of [0, 1, 2]) {
      const { kl, port, host } = seeded();
      const good: ApplyOp[] = [
        { id: 'a', op: 'supersede', block_id: port, new_content: 'port 1.', reason: 'x' },
        { id: 'b', op: 'put', slug: 'beta', title: 'B', markdown: '# B\n\nb.\n' },
        { id: 'c', op: 'tombstone', block_id: host, reason: 'gone' },
      ];
      const ops = good.map((o, i) => (i === failAt ? ({ id: o.id, op: 'tombstone', block_id: 'no-such-block', reason: 'x' } as ApplyOp) : o));
      const snap = counts(kl);
      const r = kl.applier.apply({ actor_id: 'agent', ops });
      expect(r.status, `fail at ${failAt}`).toBe('rolled_back');
      expect(r.receipt).toBeNull();
      expect(r.ops[failAt]).toMatchObject({ status: 'failed', error: { code: 'unknown_block' } });
      for (const [i, o] of r.ops.entries()) if (i < failAt) expect(o).toMatchObject({ status: 'rolled_back', receipt: null });
      for (const [i, o] of r.ops.entries()) if (i > failAt) expect(o.status).toBe('not_run');
      expect(counts(kl)).toEqual(snap);
      expect(kl.docs.getDocument('beta')).toBeNull();
      expect(kl.docs.getBlock(port)!.valid_to).toBeNull();
      expect(kl.verifyAll().ok).toBe(true);
      kl.close();
    }
  });

  it('a refused secret in a later op rolls back the earlier ones too', () => {
    const { kl, port } = seeded();
    const snap = counts(kl);
    const r = kl.applier.apply({
      actor_id: 'agent',
      ops: [
        { id: 'a', op: 'supersede', block_id: port, new_content: 'port 1.', reason: 'x' },
        { id: 'b', op: 'put', slug: 'creds', title: 'C', markdown: `# C\n\ntoken ghp_${'Ab3'.repeat(12)}\n` },
      ],
    });
    expect(r.status).toBe('rolled_back');
    expect(r.ops[1]!.error!.code).toBe('secret_detected');
    expect(counts(kl)).toEqual(snap);
    kl.close();
  });

  it('best_effort commits the ops that succeed, records the failures, still one event', () => {
    const { kl, port } = seeded();
    const r = kl.applier.apply({
      actor_id: 'agent',
      mode: 'best_effort',
      ops: [
        { id: 'a', op: 'tombstone', block_id: 'nope', reason: 'x' },
        { id: 'b', op: 'supersede', block_id: port, new_content: 'port 2.', reason: 'x' },
      ],
    });
    expect(r.status).toBe('partial');
    expect(r.ops.map((o) => o.status)).toEqual(['failed', 'applied']);
    expect(kl.chain.get(r.receipt!.seq)!.payload['ops']).toEqual([
      expect.objectContaining({ id: 'a', status: 'failed' }),
      expect.objectContaining({ id: 'b', status: 'applied' }),
    ]);
    kl.close();
  });
});

describe('apply: expect_version', () => {
  it('a stale expect_version rejects the op (and the whole all_or_nothing plan)', () => {
    const { kl, port } = seeded();
    kl.docs.putDocument({ slug: 'alpha', title: 'Alpha', markdown: '# Alpha\n\nport 8080.\n\nhost green.\n', actor_id: 'other' }); // rev 2
    const snap = counts(kl);
    const r = kl.applier.apply({ actor_id: 'agent', ops: [{ id: 'a', op: 'supersede', block_id: port, new_content: 'port 1.', reason: 'x', expect_version: 1 }] });
    expect(r.status).toBe('rolled_back');
    expect(r.ops[0]).toMatchObject({ status: 'failed', version_before: 2, error: { code: 'version_conflict' } });
    expect(counts(kl)).toEqual(snap);
    expect(kl.applier.apply({ actor_id: 'agent', ops: [{ id: 'b', op: 'put', slug: 'alpha', title: 'A', markdown: '# A\n\nx.\n', expect_version: 0 }] }).ops[0]!.error!.code).toBe(
      'version_conflict',
    );
    kl.close();
  });
});

describe('apply: idempotency', () => {
  it('replaying a committed idempotency_key returns the original result and writes nothing', () => {
    const { kl, port } = seeded();
    const ops: ApplyOp[] = [{ id: 'a', op: 'supersede', block_id: port, new_content: 'port 7.', reason: 'x' }];
    const first = kl.applier.apply({ actor_id: 'agent', idempotency_key: 'k-1', ops });
    const head = kl.chain.head().seq;
    const again = kl.applier.apply({ actor_id: 'agent', idempotency_key: 'k-1', ops });
    expect(again.replayed).toBe(true);
    expect({ ...again, replayed: false }).toEqual(first);
    expect(kl.chain.head().seq).toBe(head);
    // A different plan under the same key is refused, never replayed.
    expect(code(() => kl.applier.apply({ actor_id: 'agent', idempotency_key: 'k-1', ops: [{ id: 'a', op: 'tombstone', block_id: port, reason: 'y' }] }))).toBe('idempotency_key_reused');
    kl.close();
  });

  it('a rolled-back apply stores nothing under its key, so a fixed retry can commit', () => {
    const { kl, port } = seeded();
    const bad = kl.applier.apply({ actor_id: 'a', idempotency_key: 'k-2', ops: [{ id: 'a', op: 'tombstone', block_id: 'nope', reason: 'x' }] });
    expect(bad.status).toBe('rolled_back');
    const good = kl.applier.apply({ actor_id: 'a', idempotency_key: 'k-2', ops: [{ id: 'a', op: 'tombstone', block_id: port, reason: 'x' }] });
    expect(good.status).toBe('committed');
    kl.close();
  });
});

describe('apply: dry_run and the confirm token', () => {
  it('dry_run writes nothing, previews exact diffs, and returns a bound token that commits once', () => {
    const { kl, port } = seeded();
    const ops: ApplyOp[] = [
      { id: 'a', op: 'supersede', block_id: port, new_content: 'port 9.', reason: 'x' },
      { id: 'b', op: 'put', slug: 'beta', title: 'B', markdown: '# B\n\nb.\n' },
    ];
    const snap = counts(kl);
    const plan = kl.applier.apply({ actor_id: 'agent', dry_run: true, ops });
    expect(counts(kl)).toEqual(snap);
    expect(plan).toMatchObject({ status: 'planned', dry_run: true, receipt: null });
    expect(plan.ops.map((o) => o.status)).toEqual(['planned', 'planned']);
    expect(plan.ops[0]!.diff).toContain('{+9.+}');
    expect(plan.confirm_token).toMatch(/^klc1\./);
    const body = JSON.parse(Buffer.from(plan.confirm_token!.split('.')[1]!, 'base64url').toString()) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual(
      ['actor_id', 'catalog_fingerprint', 'exp', 'idempotency_key', 'nonce', 'plan_hash', 'policy_version', 'resources', 'sandbox', 'server', 'tenant', 'v', 'versions'].sort(),
    );
    expect(body['resources']).toEqual(['block:' + port, 'doc:alpha', 'doc:beta']);
    const done = kl.applier.apply({ actor_id: 'agent', ops, confirm_token: plan.confirm_token! });
    expect(done.status).toBe('committed');
    expect(kl.chain.get(done.receipt!.seq)!.payload['confirm_nonce']).toBe(body['nonce']);
    // Single use: the same token can never commit again (even the same plan).
    expect(code(() => kl.applier.apply({ actor_id: 'agent', ops, confirm_token: plan.confirm_token! }))).toBe('confirm_used');
    kl.close();
  });

  it('a token cannot be used for a different plan, actor, idempotency key, store, or after it expires', () => {
    const { kl, port, host } = seeded();
    const ops: ApplyOp[] = [{ id: 'a', op: 'supersede', block_id: port, new_content: 'port 9.', reason: 'x' }];
    const tok = () => kl.applier.apply({ actor_id: 'agent', dry_run: true, idempotency_key: 'k', ops }).confirm_token!;
    expect(code(() => kl.applier.apply({ actor_id: 'agent', idempotency_key: 'k', ops: [{ ...ops[0]!, new_content: 'port 10.' } as ApplyOp], confirm_token: tok() }))).toBe('confirm_mismatch');
    expect(code(() => kl.applier.apply({ actor_id: 'agent', idempotency_key: 'k', ops: [{ id: 'a', op: 'tombstone', block_id: host, reason: 'x' }], confirm_token: tok() }))).toBe('confirm_mismatch');
    expect(code(() => kl.applier.apply({ actor_id: 'mallory', idempotency_key: 'k', ops, confirm_token: tok() }))).toBe('confirm_mismatch');
    expect(code(() => kl.applier.apply({ actor_id: 'agent', idempotency_key: 'other', ops, confirm_token: tok() }))).toBe('confirm_mismatch');
    expect(code(() => kl.applier.apply({ actor_id: 'agent', idempotency_key: 'k', ops, confirm_token: tok().slice(0, -2) + 'AA' }))).toBe('confirm_invalid');
    // Another store (another key and secret) rejects it outright.
    const other = new KronicleLite({ memory: true });
    expect(code(() => other.applier.apply({ actor_id: 'agent', idempotency_key: 'k', ops, confirm_token: tok() }))).toBe('confirm_invalid');
    other.close();
    // Expiry: the clock moves past the ttl.
    const t = tok();
    const real = kl.applier.now;
    kl.applier.now = () => new Date(Date.now() + 301_000);
    expect(code(() => kl.applier.apply({ actor_id: 'agent', idempotency_key: 'k', ops, confirm_token: t }))).toBe('confirm_expired');
    kl.applier.now = real;
    // A token that failed a commit is burned: it cannot be retried either.
    expect(code(() => kl.applier.apply({ actor_id: 'agent', idempotency_key: 'k', ops, confirm_token: t }))).toBe('confirm_used');
    // Nothing above wrote anything.
    expect(kl.docs.getBlock(port)!.valid_to).toBeNull();
    kl.close();
  });

  it('TOCTOU: state changed between dry_run and confirm → stale_plan, nothing written', () => {
    const { kl, port } = seeded();
    const ops: ApplyOp[] = [{ id: 'a', op: 'put', slug: 'alpha', title: 'Alpha', markdown: '# Alpha\n\nport 9090.\n\nhost blue.\n' }];
    const plan = kl.applier.apply({ actor_id: 'agent', dry_run: true, ops });
    kl.docs.supersedeBlock({ block_id: port, new_content: 'port 7070.', reason: 'someone else', actor_id: 'other' });
    const snap = counts(kl);
    expect(code(() => kl.applier.apply({ actor_id: 'agent', ops, confirm_token: plan.confirm_token! }))).toBe('stale_plan');
    expect(counts(kl)).toEqual(snap);
    expect(kl.docs.getBlock(port)!.superseded_by).not.toBeNull();
    kl.close();
  });

  it('TOCTOU on a block: retired after the preview → stale_plan', () => {
    const { kl, host } = seeded();
    const ops: ApplyOp[] = [{ id: 'a', op: 'tombstone', block_id: host, reason: 'x' }];
    const plan = kl.applier.apply({ actor_id: 'agent', dry_run: true, ops });
    kl.docs.tombstoneBlock({ block_id: host, reason: 'raced', actor_id: 'other' });
    expect(code(() => kl.applier.apply({ actor_id: 'agent', ops, confirm_token: plan.confirm_token! }))).toBe('stale_plan');
    kl.close();
  });

  it('the token is not authorization: a policy that denies at commit wins over a valid token', () => {
    const { kl, port } = seeded();
    const ops: ApplyOp[] = [{ id: 'a', op: 'supersede', block_id: port, new_content: 'port 9.', reason: 'x' }];
    const plan = kl.applier.apply({ actor_id: 'agent', dry_run: true, ops });
    kl.applier.policy = (actor) => (actor === 'agent' ? 'agent lost write access' : null);
    const r = kl.applier.apply({ actor_id: 'agent', ops, confirm_token: plan.confirm_token! });
    expect(r.status).toBe('rolled_back');
    expect(r.ops[0]!.error).toEqual({ code: 'forbidden', message: 'agent lost write access' });
    kl.close();
  });

  it('a catalog or policy upgrade between preview and commit invalidates the token', () => {
    const { kl, port } = seeded();
    const ops: ApplyOp[] = [{ id: 'a', op: 'supersede', block_id: port, new_content: 'port 9.', reason: 'x' }];
    const p1 = kl.applier.apply({ actor_id: 'agent', dry_run: true, ops });
    kl.applier.catalog_fingerprint = 'f'.repeat(64);
    expect(code(() => kl.applier.apply({ actor_id: 'agent', ops, confirm_token: p1.confirm_token! }))).toBe('confirm_mismatch');
    const p2 = kl.applier.apply({ actor_id: 'agent', dry_run: true, ops });
    kl.applier.policy_version = 'kl-apply-policy/2';
    expect(code(() => kl.applier.apply({ actor_id: 'agent', ops, confirm_token: p2.confirm_token! }))).toBe('confirm_mismatch');
    kl.close();
  });

  it('a dry run that would fail returns no token; instruction-file documents are refused by the default policy', () => {
    const { kl } = seeded();
    const p = kl.applier.apply({ actor_id: 'agent', dry_run: true, ops: [{ id: 'a', op: 'tombstone', block_id: 'nope', reason: 'x' }] });
    expect(p).toMatchObject({ status: 'failed', confirm_token: null });
    const q = kl.applier.apply({ actor_id: 'agent', ops: [{ id: 'a', op: 'put', slug: 'instructions/claude-md', title: 'x', markdown: '# x\n' }] });
    expect(q.ops[0]!.error!.code).toBe('forbidden');
    expect(code(() => kl.applier.apply({ actor_id: 'a', ops: [] }))).toBe('invalid_plan');
    expect(code(() => kl.applier.apply({ actor_id: 'a', ops: [{ id: 'x', op: 'tombstone', block_id: 'b', reason: 'r' }, { id: 'x', op: 'tombstone', block_id: 'c', reason: 'r' }] }))).toBe('invalid_plan');
    expect(ApplyEngine).toBeDefined();
    kl.close();
  });
});
