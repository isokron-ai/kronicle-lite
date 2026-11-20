/**
 * 0.12.0: the write surface states and enforces its guards.
 *
 *   - expect_version (optimistic concurrency) on put_document, supersede_block
 *     and tombstone_block, with apply's per-op semantics: the document
 *     revision the caller read, 0 = must not exist. A stale value is refused
 *     with `version_conflict` and structured `expected_version` /
 *     `current_version`; nothing is appended.
 *   - block_not_live carries `state` and `current_block_id`.
 *   - tombstone_block dry_run: a preview that writes nothing.
 *   - The catalog: every tool states all four hints as booleans, every input
 *     schema is strict (additionalProperties: false, unknown arguments
 *     refused), every top-level argument has a description, every
 *     description says when to use the tool, and every write tool says
 *     whether a retry repeats the effect.
 */

import { Client, InMemoryTransport } from '@modelcontextprotocol/client';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { Chain } from '../src/chain/index.js';
import { openDatabase } from '../src/db/open.js';
import { DocumentError, DocumentStore } from '../src/docs/documents.js';
import { createServerFactory } from '../src/server.js';
import { KronicleLite } from '../src/store.js';

interface ToolResult {
  content: { type: string; text?: string }[];
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
}

const body = <T = Record<string, unknown>>(r: unknown): T => JSON.parse((r as ToolResult).content[0]!.text!) as T;

function fresh() {
  const { db, identity } = openDatabase({ memory: true });
  const chain = new Chain(db, identity.signer);
  const docs = new DocumentStore(db, chain);
  return { db, chain, docs };
}

function refusal(fn: () => unknown): DocumentError {
  try {
    fn();
  } catch (err) {
    if (err instanceof DocumentError) return err;
    throw err;
  }
  throw new Error('expected a DocumentError');
}

const A = 'local-agent';

describe('expect_version on the store (put / supersede / tombstone)', () => {
  it('put: 0 creates; a stale or premature version is refused with current_version and appends nothing', () => {
    const { chain, docs } = fresh();
    const r1 = docs.putDocument({ slug: 'ev', title: 'T', markdown: 'one\n', actor_id: A, expect_version: 0 });
    expect(r1.revision).toBe(1);

    const head = chain.head();
    const again = refusal(() => docs.putDocument({ slug: 'ev', title: 'T', markdown: 'two\n', actor_id: A, expect_version: 0 }));
    expect(again.code).toBe('version_conflict');
    expect(again.details).toEqual({ slug: 'ev', expected_version: 0, current_version: 1 });
    expect(chain.head()).toEqual(head);

    const missing = refusal(() => docs.putDocument({ slug: 'nope', title: 'T', markdown: 'x\n', actor_id: A, expect_version: 3 }));
    expect(missing.details).toMatchObject({ expected_version: 3, current_version: 0 });
    expect(docs.getDocument('nope')).toBeNull();

    const r2 = docs.putDocument({ slug: 'ev', title: 'T', markdown: 'two\n', actor_id: A, expect_version: 1 });
    expect(r2.revision).toBe(2);
    expect(refusal(() => docs.putDocument({ slug: 'ev', title: 'T', markdown: 'three\n', actor_id: A, expect_version: 1 })).details).toMatchObject({
      current_version: 2,
    });
    expect(docs.getDocument('ev')!.current_revision).toBe(2);
  });

  it('put: a retry under the same idempotency_key replays even though the version moved on', () => {
    const { docs } = fresh();
    docs.putDocument({ slug: 'ev2', title: 'T', markdown: 'one\n', actor_id: A });
    const first = docs.putDocument({ slug: 'ev2', title: 'T', markdown: 'two\n', actor_id: A, expect_version: 1, idempotency_key: 'k-ev2' });
    expect(first).toMatchObject({ revision: 2, replayed: false });
    const retry = docs.putDocument({ slug: 'ev2', title: 'T', markdown: 'two\n', actor_id: A, expect_version: 1, idempotency_key: 'k-ev2' });
    expect(retry).toMatchObject({ revision: 2, replayed: true, events: 0 });
  });

  it('supersede and tombstone: a stale document version is refused; the right one writes', () => {
    const { chain, docs } = fresh();
    const put = docs.putDocument({ slug: 'sb', title: 'T', markdown: 'alpha\n\nbeta\n', actor_id: A });
    const [a, b] = put.blocks.map((x) => x.block_id);

    const s1 = docs.supersedeBlock({ block_id: a!, new_content: 'alpha 2', reason: 'r', actor_id: A, expect_version: 1 });
    expect(s1.revision).toBe(2);

    const head = chain.head();
    const stale = refusal(() => docs.tombstoneBlock({ block_id: b!, reason: 'r', actor_id: A, expect_version: 1 }));
    expect(stale.code).toBe('version_conflict');
    expect(stale.details).toEqual({ slug: 'sb', expected_version: 1, current_version: 2 });
    expect(refusal(() => docs.supersedeBlock({ block_id: b!, new_content: 'beta 2', reason: 'r', actor_id: A, expect_version: 1 })).code).toBe('version_conflict');
    expect(chain.head()).toEqual(head);
    expect(docs.getBlock(b!)!.tombstoned_at).toBeNull();

    expect(docs.tombstoneBlock({ block_id: b!, reason: 'r', actor_id: A, expect_version: 2 }).revision).toBe(3);
  });
});

describe('block_not_live is structured', () => {
  it('names the live end of the supersession walk, or tombstoned', () => {
    const { docs } = fresh();
    const put = docs.putDocument({ slug: 'bnl', title: 'T', markdown: 'one\n\ntwo\n', actor_id: A });
    const [a, b] = put.blocks.map((x) => x.block_id);
    const s1 = docs.supersedeBlock({ block_id: a!, new_content: 'one v2', reason: 'r', actor_id: A });
    const s2 = docs.supersedeBlock({ block_id: s1.new_block_id, new_content: 'one v3', reason: 'r', actor_id: A });

    const retry = refusal(() => docs.supersedeBlock({ block_id: a!, new_content: 'one v2', reason: 'r', actor_id: A }));
    expect(retry.code).toBe('block_not_live');
    expect(retry.details).toEqual({ block_id: a, state: 'superseded', superseded_by: s1.new_block_id, current_block_id: s2.new_block_id });

    docs.tombstoneBlock({ block_id: b!, reason: 'gone', actor_id: A });
    expect(refusal(() => docs.tombstoneBlock({ block_id: b!, reason: 'gone', actor_id: A })).details).toEqual({
      block_id: b,
      state: 'tombstoned',
      current_block_id: null,
    });
  });
});

describe('tombstone_block dry_run (store)', () => {
  it('returns the block that would be retired and writes nothing', () => {
    const { chain, docs } = fresh();
    const put = docs.putDocument({ slug: 'dr', title: 'T', markdown: '# H\n\nbody text\n', actor_id: A });
    const target = put.blocks.find((x) => x.kind === 'paragraph')!;
    const head = chain.head();
    const preview = docs.tombstoneBlock({ block_id: target.block_id, reason: 'r', actor_id: A, dry_run: true });
    expect(preview).toMatchObject({ block_id: target.block_id, doc_slug: 'dr', revision: 2, dry_run: true, head });
    expect(preview.preview).toEqual({ content: 'body text', content_hash: target.content_hash, kind: 'paragraph', heading_path: ['H'] });
    expect(chain.head()).toEqual(head);
    expect(docs.getBlock(target.block_id)!.tombstoned_at).toBeNull();
    expect(docs.getDocument('dr')!.current_revision).toBe(1);

    // A dry run checks expect_version too.
    expect(refusal(() => docs.tombstoneBlock({ block_id: target.block_id, reason: 'r', actor_id: A, dry_run: true, expect_version: 9 })).code).toBe('version_conflict');
  });
});

describe('MCP surface', () => {
  let store: KronicleLite;
  let client: Client;
  let close: () => Promise<void>;

  beforeAll(async () => {
    store = new KronicleLite({ memory: true });
    const [clientT, serverT] = InMemoryTransport.createLinkedPair();
    const handle = serveStdio(createServerFactory(store), { transport: serverT });
    close = () => handle.close();
    client = new Client({ name: 'write-surface-test', version: '0.0.0' }, { versionNegotiation: { mode: { pin: '2026-07-28' } } });
    await client.connect(clientT);
  });

  afterAll(async () => {
    await client.close();
    await close();
    store.close();
  });

  it('put_document: version_conflict is a tool error with structured fields', async () => {
    const ok = (await client.callTool({ name: 'put_document', arguments: { slug: 'mcp-ev', title: 'T', markdown: 'one\n', expect_version: 0 } })) as ToolResult;
    expect(ok.isError).toBeFalsy();
    const stale = (await client.callTool({ name: 'put_document', arguments: { slug: 'mcp-ev', title: 'T', markdown: 'two\n', expect_version: 0 } })) as ToolResult;
    expect(stale.isError).toBe(true);
    expect(body(stale)).toMatchObject({ error: 'version_conflict', slug: 'mcp-ev', expected_version: 0, current_version: 1 });
    expect(store.docs.getDocument('mcp-ev')!.current_revision).toBe(1);
  });

  it('supersede_block: a retry is refused with block_not_live and current_block_id', async () => {
    const put = body<{ blocks: { block_id: string }[] }>(await client.callTool({ name: 'put_document', arguments: { slug: 'mcp-sup', title: 'T', markdown: 'a\n' } }));
    const id = put.blocks[0]!.block_id;
    const args = { block_id: id, new_content: 'a2', reason: 'r', expect_version: 1 };
    const first = body<{ new_block_id: string }>(await client.callTool({ name: 'supersede_block', arguments: args }));
    const retry = (await client.callTool({ name: 'supersede_block', arguments: args })) as ToolResult;
    expect(retry.isError).toBe(true);
    expect(body(retry)).toMatchObject({ error: 'block_not_live', state: 'superseded', current_block_id: first.new_block_id });
  });

  it('tombstone_block: dry_run previews, then the real call retires', async () => {
    const put = body<{ blocks: { block_id: string }[] }>(await client.callTool({ name: 'put_document', arguments: { slug: 'mcp-tomb', title: 'T', markdown: 'keep\n\ndrop me\n' } }));
    const id = put.blocks[1]!.block_id;
    const preview = (await client.callTool({ name: 'tombstone_block', arguments: { block_id: id, reason: 'r', dry_run: true } })) as ToolResult;
    expect(preview.isError).toBeFalsy();
    expect(preview.structuredContent).toMatchObject({ dry_run: true, revision: 2, preview: { content: 'drop me' } });
    expect(store.docs.getBlock(id)!.tombstoned_at).toBeNull();

    const done = (await client.callTool({ name: 'tombstone_block', arguments: { block_id: id, reason: 'r', expect_version: 1 } })) as ToolResult;
    expect(done.isError).toBeFalsy();
    expect(done.structuredContent).toMatchObject({ dry_run: false, revision: 2 });
    expect(done.structuredContent).not.toHaveProperty('preview');
    expect(store.docs.getBlock(id)!.tombstoned_at).not.toBeNull();
  });

  it('refuses unknown arguments instead of ignoring them (a tool error, nothing written)', async () => {
    const r = (await client.callTool({ name: 'put_document', arguments: { slug: 'mcp-unknown', title: 'T', markdown: 'x\n', expected_revision: 0 } })) as ToolResult;
    expect(r.isError).toBe(true);
    expect(JSON.stringify(r.content)).toMatch(/expected_revision/);
    expect(store.docs.getDocument('mcp-unknown')).toBeNull();
  });

  it('tombstone_block dry_run over MCP changes no row in any table', async () => {
    const put = body<{ blocks: { block_id: string }[] }>(await client.callTool({ name: 'put_document', arguments: { slug: 'mcp-dry-all', title: 'T', markdown: 'keep\n\ndrop\n' } }));
    const snapshot = () => {
      const tables = (store.db.prepare(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`).all() as { name: string }[]).map((t) => t.name);
      return Object.fromEntries(tables.map((t) => [t, JSON.stringify(store.db.prepare(`SELECT * FROM "${t}"`).raw().all())]));
    };
    const before = snapshot();
    const r = (await client.callTool({ name: 'tombstone_block', arguments: { block_id: put.blocks[1]!.block_id, reason: 'r', dry_run: true } })) as ToolResult;
    expect(r.isError).toBeFalsy();
    expect(r.structuredContent).toMatchObject({ dry_run: true });
    const after = snapshot();
    expect(Object.keys(after)).toEqual(Object.keys(before));
    for (const t of Object.keys(before)) expect(after[t], t).toBe(before[t]);
  });

  it('verify: a malformed receipt object still answers UNVERIFIED / malformed_receipt', async () => {
    const r = (await client.callTool({ name: 'verify', arguments: { receipt: { v: 2, receipt_id: 'not-a-uuid', revision: 'x' } } })) as ToolResult;
    expect(r.isError).toBeFalsy();
    expect(r.structuredContent).toMatchObject({ status: 'UNVERIFIED', reason: 'malformed_receipt' });
  });

  it('catalog: explicit hints, strict schemas, described arguments, use-when and retry wording', async () => {
    const { tools } = await client.listTools();
    expect(tools.length).toBe(13);
    for (const t of tools) {
      const a = t.annotations as Record<string, unknown>;
      for (const k of ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint']) expect(typeof a[k], `${t.name}.${k}`).toBe('boolean');
      const s = t.inputSchema as { additionalProperties?: unknown; properties?: Record<string, { description?: string; type?: string; properties?: unknown }> };
      expect(s.additionalProperties, t.name).toBe(false);
      for (const [k, p] of Object.entries(s.properties ?? {})) {
        expect(p.description, `${t.name}.${k}`).toBeTruthy();
        if (p.type === 'object') expect(p.properties, `${t.name}.${k} declares its fields`).toBeTruthy();
      }
      expect(t.description, t.name).toMatch(/\b(use this|use it|use when|do not use)\b/i);
      if (a['readOnlyHint'] === false && a['idempotentHint'] !== true) expect(t.description, t.name).toMatch(/retr(y|ies)|idempot|repeat/i);
    }
    const byName = Object.fromEntries(tools.map((t) => [t.name, t]));
    for (const n of ['put_document', 'supersede_block', 'tombstone_block']) {
      expect((byName[n]!.inputSchema as { properties: Record<string, unknown> }).properties, n).toHaveProperty('expect_version');
    }
    expect((byName['tombstone_block']!.inputSchema as { properties: Record<string, unknown> }).properties).toHaveProperty('dry_run');
  });
});

describe('apply expected_head_hash (batch precondition)', () => {
  function seeded() {
    const kl = new KronicleLite({ memory: true });
    const a = kl.docs.putDocument({ slug: 'hh', title: 'T', markdown: 'one\n\ntwo\n', actor_id: 'h' });
    return { kl, block: a.blocks[0]!.block_id };
  }
  const op = (block_id: string) => ({ id: 'o', op: 'supersede' as const, block_id, new_content: 'one v2', reason: 'r' });

  it('commits when the head matches; refuses with head_conflict and current_head when anything was appended', () => {
    const { kl, block } = seeded();
    const read = kl.chain.head();
    kl.docs.putDocument({ slug: 'other', title: 'O', markdown: 'x\n', actor_id: 'someone-else' });
    const now = kl.chain.head();
    let err: { code?: string; details?: unknown } = {};
    try {
      kl.applier.apply({ actor_id: 'agent', ops: [op(block)], expected_head_hash: read.hash });
    } catch (e) {
      err = e as typeof err;
    }
    expect(err.code).toBe('head_conflict');
    expect(err.details).toEqual({ expected_head_hash: read.hash, current_head: { seq: now.seq, hash: now.hash } });
    expect(kl.chain.head()).toEqual(now);

    let dry: { code?: string } = {};
    try {
      kl.applier.apply({ actor_id: 'agent', ops: [op(block)], dry_run: true, expected_head_hash: read.hash });
    } catch (e) {
      dry = e as typeof dry;
    }
    expect(dry.code).toBe('head_conflict');

    const ok = kl.applier.apply({ actor_id: 'agent', ops: [op(block)], expected_head_hash: now.hash });
    expect(ok.status).toBe('committed');
    kl.close();
  });

  it('a retry under the same idempotency_key replays although the head moved (its own commit moved it)', () => {
    const { kl, block } = seeded();
    const read = kl.chain.head();
    const first = kl.applier.apply({ actor_id: 'agent', ops: [op(block)], expected_head_hash: read.hash, idempotency_key: 'hh-1' });
    const retry = kl.applier.apply({ actor_id: 'agent', ops: [op(block)], expected_head_hash: read.hash, idempotency_key: 'hh-1' });
    expect(first.status).toBe('committed');
    expect(retry).toMatchObject({ status: 'committed', replayed: true, plan_hash: first.plan_hash });
    kl.close();
  });

  it('over MCP: head_conflict is a tool error with structured fields', async () => {
    const { kl, block } = seeded();
    const read = kl.chain.head();
    kl.docs.putDocument({ slug: 'other', title: 'O', markdown: 'x\n', actor_id: 'someone-else' });
    const [clientT, serverT] = InMemoryTransport.createLinkedPair();
    const handle = serveStdio(createServerFactory(kl), { transport: serverT });
    const client = new Client({ name: 'hh-test', version: '0.0.0' }, { versionNegotiation: { mode: { pin: '2026-07-28' } } });
    try {
      await client.connect(clientT);
      const r = (await client.callTool({ name: 'apply', arguments: { ops: [op(block)], expected_head_hash: read.hash } })) as ToolResult;
      expect(r.isError).toBe(true);
      expect(body(r)).toMatchObject({ error: 'head_conflict', expected_head_hash: read.hash, current_head: kl.chain.head() });
    } finally {
      await client.close();
      await handle.close();
      kl.close();
    }
  });
});

describe('apply: confirm tokens bind expected_head_hash; op errors keep their structured fields', () => {
  function seeded() {
    const kl = new KronicleLite({ memory: true });
    const a = kl.docs.putDocument({ slug: 'tok', title: 'T', markdown: 'one\n\ntwo\n', actor_id: 'h' });
    return { kl, block: a.blocks[0]!.block_id };
  }
  const op = (block_id: string) => ({ id: 'o', op: 'supersede' as const, block_id, new_content: 'one v2', reason: 'r' });
  const codeOf = (fn: () => unknown): string => {
    try {
      fn();
    } catch (err) {
      return (err as { code: string }).code;
    }
    return 'no error';
  };

  it('a token previewed with expected_head_hash does not commit after another write (head_conflict, token burned)', () => {
    const { kl, block } = seeded();
    const h = kl.chain.head().hash;
    const plan = kl.applier.apply({ actor_id: 'agent', ops: [op(block)], dry_run: true, expected_head_hash: h });
    expect(plan.status).toBe('planned');
    kl.docs.putDocument({ slug: 'elsewhere', title: 'E', markdown: 'x\n', actor_id: 'someone-else' });
    const moved = kl.chain.head();
    expect(codeOf(() => kl.applier.apply({ actor_id: 'agent', ops: [op(block)], confirm_token: plan.confirm_token!, expected_head_hash: h }))).toBe('head_conflict');
    expect(kl.chain.head()).toEqual(moved);
    expect(codeOf(() => kl.applier.apply({ actor_id: 'agent', ops: [op(block)], confirm_token: plan.confirm_token!, expected_head_hash: h }))).toBe('confirm_used');
    kl.close();
  });

  it('a commit may not drop or change the bound expected_head_hash; with it unchanged and the head unmoved it commits', () => {
    const { kl, block } = seeded();
    const h = kl.chain.head().hash;
    const p1 = kl.applier.apply({ actor_id: 'agent', ops: [op(block)], dry_run: true, expected_head_hash: h });
    expect(codeOf(() => kl.applier.apply({ actor_id: 'agent', ops: [op(block)], confirm_token: p1.confirm_token! }))).toBe('confirm_mismatch');
    const p2 = kl.applier.apply({ actor_id: 'agent', ops: [op(block)], dry_run: true, expected_head_hash: h });
    expect(codeOf(() => kl.applier.apply({ actor_id: 'agent', ops: [op(block)], confirm_token: p2.confirm_token!, expected_head_hash: 'f'.repeat(64) }))).toBe('confirm_mismatch');
    const p3 = kl.applier.apply({ actor_id: 'agent', ops: [op(block)], dry_run: true });
    expect(codeOf(() => kl.applier.apply({ actor_id: 'agent', ops: [op(block)], confirm_token: p3.confirm_token!, expected_head_hash: h }))).toBe('confirm_mismatch');
    const p4 = kl.applier.apply({ actor_id: 'agent', ops: [op(block)], dry_run: true, expected_head_hash: h });
    const done = kl.applier.apply({ actor_id: 'agent', ops: [op(block)], confirm_token: p4.confirm_token!, expected_head_hash: h });
    expect(done.status).toBe('committed');
    kl.close();
  });

  it('per-op errors carry block_not_live and version_conflict fields', () => {
    const { kl, block } = seeded();
    const s = kl.docs.supersedeBlock({ block_id: block, new_content: 'one b', reason: 'r', actor_id: 'h' });
    const r = kl.applier.apply({ actor_id: 'agent', mode: 'best_effort', ops: [op(block), { id: 'v', op: 'put', slug: 'tok', title: 'T', markdown: 'z\n', expect_version: 1 }] });
    expect(r.ops[0]!.error).toMatchObject({ code: 'block_not_live', state: 'superseded', current_block_id: s.new_block_id });
    expect(r.ops[1]!.error).toMatchObject({ code: 'version_conflict', slug: 'tok', expected_version: 1, current_version: 2 });
    kl.close();
  });
});

describe('--core profile is strict too', () => {
  it('refuses derived_from, which the core put_document does not offer', async () => {
    const kl = new KronicleLite({ memory: true });
    const [clientT, serverT] = InMemoryTransport.createLinkedPair();
    const handle = serveStdio(createServerFactory(kl, { profile: 'core' }), { transport: serverT });
    const client = new Client({ name: 'core-strict', version: '0.0.0' }, { versionNegotiation: { mode: { pin: '2026-07-28' } } });
    try {
      await client.connect(clientT);
      const r = (await client.callTool({ name: 'put_document', arguments: { slug: 'core-df', title: 'T', markdown: 'x\n', derived_from: [] } })) as ToolResult;
      expect(r.isError).toBe(true);
      expect(JSON.stringify(r.content)).toMatch(/derived_from/);
      expect(kl.docs.getDocument('core-df')).toBeNull();
    } finally {
      await client.close();
      await handle.close();
      kl.close();
    }
  });
});
