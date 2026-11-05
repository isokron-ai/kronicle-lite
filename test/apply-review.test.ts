/**
 * Regression tests from the independent review of #14 (probes in
 * klrev/probes/zz-probe14*.test.ts).
 */
import { Client, InMemoryTransport } from '@modelcontextprotocol/client';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { describe, expect, it } from 'vitest';

import { ApplyEngine, type ApplyOp } from '../src/apply/apply.js';
import { sha256Hex } from '../src/crypto/hash.js';
import { KronicleLite } from '../src/index.js';
import { createServerFactory } from '../src/server.js';

function seeded() {
  const kl = new KronicleLite({ memory: true });
  const a = kl.docs.putDocument({ slug: 'alpha', title: 'Alpha', markdown: '# Alpha\n\nport 8080.\n\nhost blue.\n', actor_id: 'h' });
  const para = a.blocks.filter((b) => b.kind === 'paragraph');
  return { kl, port: para[0]!.block_id, host: para[1]!.block_id };
}
const code = (fn: () => unknown): string => {
  try {
    const r = fn() as { status?: string } | undefined;
    return `ok:${r?.status ?? ''}`;
  } catch (err) {
    return (err as { code?: string }).code ?? (err as Error).message;
  }
};
const bigDoc = (kl: KronicleLite, n: number) => {
  const md = '# D\n\n' + Array.from({ length: n }, (_, i) => `para ${i}.`).join('\n\n') + '\n';
  return kl.docs
    .putDocument({ slug: 'big', title: 'b', markdown: md, actor_id: 'h' })
    .blocks.filter((b) => b.kind === 'paragraph')
    .map((b, i): ApplyOp => ({ id: `o${i}`, op: 'supersede', block_id: b.block_id, new_content: `p${i}.`, reason: 'r' }));
};

describe('review #14 B3: a commit is reported only with its own apply.committed event', () => {
  it('a foreign event already holding the apply key fails the apply (nothing committed), never reports it as the receipt', () => {
    const { kl, port } = seeded();
    // Simulate a squatter that bypassed put_document's reserved-prefix check (an older version, a raw writer).
    kl.chain.append({ event_type: 'document.put', payload: { squat: true }, actor_id: 'evil', idempotency_key: `apply:${sha256Hex('K2')}` });
    const head = kl.chain.head().seq;
    expect(code(() => kl.applier.apply({ actor_id: 'A', idempotency_key: 'K2', ops: [{ id: 'a', op: 'supersede', block_id: port, new_content: 'p.', reason: 'x' }] }))).toBe('idempotency_conflict');
    expect(kl.chain.head().seq).toBe(head);
    expect(kl.docs.getBlock(port)!.valid_to).toBeNull();
    kl.close();
  });
  it('put_document cannot take an apply key', () => {
    const { kl } = seeded();
    expect(() => kl.docs.putDocument({ slug: 'sq', title: 's', markdown: '# s\n\ns.\n', actor_id: 'evil', idempotency_key: `apply:${sha256Hex('K2')}` })).toThrow(/reserved/);
    kl.close();
  });
});

describe('review #14 B4: confirm tokens are small and plans of any allowed size round-trip', () => {
  it('a 50-op token is a nonce + MAC (short), and commits', () => {
    const kl = new KronicleLite({ memory: true });
    const ops = bigDoc(kl, 50);
    const plan = kl.applier.apply({ actor_id: 'A', ops, dry_run: true });
    expect(plan.status).toBe('planned');
    expect(plan.confirm_token!.length).toBeLessThan(200);
    expect(kl.applier.apply({ actor_id: 'A', ops, confirm_token: plan.confirm_token! }).status).toBe('committed');
    kl.close();
  });
  it('over MCP: a 50-op dry_run → confirm round trip', async () => {
    const store = new KronicleLite({ memory: true });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const h = serveStdio(createServerFactory(store, { defaultActorId: 'a' }), { transport: st });
    const client = new Client({ name: 'p', version: '0' }, { versionNegotiation: { mode: { pin: '2026-07-28' } } });
    await client.connect(ct);
    const ops = bigDoc(store, 50);
    const txt = (r: unknown) => (r as { content: { text: string }[] }).content[0]!.text;
    const plan = JSON.parse(txt(await client.callTool({ name: 'apply', arguments: { ops, dry_run: true } }))) as { status: string; confirm_token: string };
    expect(plan.status).toBe('planned');
    const done = (await client.callTool({ name: 'apply', arguments: { ops, confirm_token: plan.confirm_token } })) as { isError?: boolean; content: { text: string }[] };
    expect(done.isError, done.content[0]!.text).toBeFalsy();
    expect(JSON.parse(done.content[0]!.text)).toMatchObject({ status: 'committed' });
    await client.close();
    await h.close();
    store.close();
  });
  it('the token body holds no plan data: only the server-side record knows it', () => {
    const { kl, port } = seeded();
    const t = kl.applier.apply({ actor_id: 'A', dry_run: true, ops: [{ id: 'a', op: 'supersede', block_id: port, new_content: 'p.', reason: 'x' }] }).confirm_token!;
    expect(t).not.toContain(port);
    expect(t.split('.')).toHaveLength(3);
    // a forged MAC on a real nonce is refused
    const [p, n] = t.split('.');
    expect(code(() => kl.applier.apply({ actor_id: 'A', ops: [{ id: 'a', op: 'supersede', block_id: port, new_content: 'p.', reason: 'x' }], confirm_token: `${p}.${n}.AAAA` }))).toBe('confirm_invalid');
    kl.close();
  });
});

describe('review #14: confirm-token discipline', () => {
  it('after a dry run, committing the same plan without the token is refused (confirm_required)', () => {
    const { kl, port } = seeded();
    const ops: ApplyOp[] = [{ id: 'a', op: 'supersede', block_id: port, new_content: 'p.', reason: 'x' }];
    kl.applier.apply({ actor_id: 'A', ops, dry_run: true });
    expect(code(() => kl.applier.apply({ actor_id: 'A', ops }))).toBe('confirm_required');
    expect(kl.docs.getBlock(port)!.valid_to).toBeNull();
    kl.close();
  });
  it('require_confirm (remote-capable servers) refuses any commit without a token', () => {
    const { kl, port } = seeded();
    expect(code(() => kl.applier.apply({ actor_id: 'A', require_confirm: true, ops: [{ id: 'a', op: 'supersede', block_id: port, new_content: 'p.', reason: 'x' }] }))).toBe('confirm_required');
    kl.close();
  });
  it('the HTTP server requires the token for apply', async () => {
    const store = new KronicleLite({ memory: true });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const h = serveStdio(createServerFactory(store, { defaultActorId: 'a', requireApplyConfirm: true }), { transport: st });
    const client = new Client({ name: 'p', version: '0' }, { versionNegotiation: { mode: { pin: '2026-07-28' } } });
    await client.connect(ct);
    const r = (await client.callTool({ name: 'apply', arguments: { ops: [{ id: 'a', op: 'put', slug: 'x', title: 'x', markdown: '# x\n\nx.\n' }] } })) as { isError?: boolean; content: { text: string }[] };
    expect(r.isError).toBe(true);
    expect(JSON.parse(r.content[0]!.text)).toMatchObject({ error: 'confirm_required' });
    await client.close();
    await h.close();
    store.close();
  });
  it("a wrong-actor attempt does not burn the owner's token", () => {
    const { kl, port } = seeded();
    const ops: ApplyOp[] = [{ id: 'a', op: 'supersede', block_id: port, new_content: 'p.', reason: 'x' }];
    const t = kl.applier.apply({ actor_id: 'A', ops, dry_run: true }).confirm_token!;
    expect(code(() => kl.applier.apply({ actor_id: 'B', ops, confirm_token: t }))).toBe('confirm_mismatch');
    expect(code(() => kl.applier.apply({ actor_id: 'A', ops, confirm_token: t }))).toBe('ok:committed');
    kl.close();
  });
  it('tenant binding: an engine for another tenant (same secret, same store) rejects the token', () => {
    const { kl, port } = seeded();
    const ops: ApplyOp[] = [{ id: 'a', op: 'supersede', block_id: port, new_content: 'p.', reason: 'x' }];
    const t = kl.applier.apply({ actor_id: 'A', ops, dry_run: true }).confirm_token!;
    const other = new ApplyEngine(kl.db, kl.chain, kl.docs, kl.identity.signer.public_key_pem, { tenant: 'other', secret: kl.identity.cursor_secret });
    expect(code(() => other.apply({ actor_id: 'A', ops, confirm_token: t }))).toBe('confirm_mismatch');
    kl.close();
  });
  it('ttl_seconds that is not a finite positive number gets the default; huge is capped', () => {
    const { kl, port } = seeded();
    const ops: ApplyOp[] = [{ id: 'a', op: 'supersede', block_id: port, new_content: 'p.', reason: 'x' }];
    const ttl = (v: number) => (Date.parse(kl.applier.apply({ actor_id: 'A', ops, dry_run: true, ttl_seconds: v }).confirm_expires_at!) - Date.now()) / 1000;
    expect(ttl(Number.NaN)).toBeGreaterThan(250);
    expect(ttl(Number.NaN)).toBeLessThanOrEqual(300);
    expect(ttl(-100)).toBeGreaterThan(0);
    expect(ttl(1e12)).toBeLessThanOrEqual(900);
    kl.close();
  });
});

describe('review #14: idempotent replay re-checks actor and authz', () => {
  it('another actor replaying a committed key is refused; a revoked actor is refused', () => {
    const { kl } = seeded();
    const ops: ApplyOp[] = [{ id: 'a', op: 'put', slug: 'i', title: 'i', markdown: '# i\n\ni.\n' }];
    expect(kl.applier.apply({ actor_id: 'A', ops, idempotency_key: 'K' }).status).toBe('committed');
    expect(kl.applier.apply({ actor_id: 'A', ops, idempotency_key: 'K' }).replayed).toBe(true);
    expect(code(() => kl.applier.apply({ actor_id: 'B', ops, idempotency_key: 'K' }))).toBe('idempotency_key_reused');
    kl.applier.policy = () => 'nobody may write';
    expect(code(() => kl.applier.apply({ actor_id: 'A', ops, idempotency_key: 'K' }))).toBe('forbidden');
    kl.close();
  });
});

describe('review #14: apply keeps project scoping', () => {
  it('a put through apply records the project like put_document does', () => {
    const { kl } = seeded();
    kl.applier.apply({ actor_id: 'A', project: { key: 'proj-1', root: '/w/p' }, ops: [{ id: 'a', op: 'put', slug: 'scoped', title: 's', markdown: '# s\n\ns.\n' }] });
    expect((kl.db.prepare(`SELECT project_key FROM documents WHERE slug = 'scoped'`).get() as { project_key: string | null }).project_key).toBe('proj-1');
    kl.close();
  });
  it('the MCP server passes its project to apply', async () => {
    const store = new KronicleLite({ memory: true });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const h = serveStdio(createServerFactory(store, { defaultActorId: 'a', project: { keys: ['proj-2'], root: '/w/q' } as never }), { transport: st });
    const client = new Client({ name: 'p', version: '0' }, { versionNegotiation: { mode: { pin: '2026-07-28' } } });
    await client.connect(ct);
    await client.callTool({ name: 'apply', arguments: { ops: [{ id: 'a', op: 'put', slug: 'mcp-scoped', title: 's', markdown: '# s\n\ns.\n' }] } });
    expect((store.db.prepare(`SELECT project_key FROM documents WHERE slug = 'mcp-scoped'`).get() as { project_key: string | null }).project_key).toBe('proj-2');
    await client.close();
    await h.close();
    store.close();
  });
});
