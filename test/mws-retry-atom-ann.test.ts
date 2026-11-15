/**
 * Three MWS 0.9 findings from the write-check dogfood run (KL-1 to KL-3):
 *
 *   KL-1  MWS-RETRY-2 (MUST): put_document answered a reused idempotency_key
 *         with changed arguments with the first result, as a success. It now
 *         refuses (`idempotency_key_reused`); the same put replays with
 *         `replayed: true`. The chain refuses a changed request under a used
 *         key as well.
 *   KL-2  MWS-ATOM-1 (MUST): a failed all-or-nothing apply came back as a
 *         normal result. Any status but `committed` / `planned` is now
 *         `isError: true`, with the same structured body.
 *   KL-3  MWS-ANN-5 (SHOULD): supersede_block replaces a block's live content
 *         but declared `destructiveHint: false`.
 *
 * And the same reading for put_document (MWS-ANN-5; ANN-2 for an upsert with
 * no expected version): a re-put supersedes changed blocks and tombstones
 * dropped ones, so it declares `destructiveHint: true` in the full and core
 * catalogs.
 */

import { Client, InMemoryTransport } from '@modelcontextprotocol/client';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { Chain, IdempotencyKeyReusedError } from '../src/chain/index.js';
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

function codeOf(fn: () => unknown): string | null {
  try {
    fn();
    return null;
  } catch (err) {
    return (err as { code?: string }).code ?? String(err);
  }
}

// ─────────────────────────────── KL-1 ───────────────────────────────

describe('KL-1 (MWS-RETRY-2): a reused idempotency_key with changed arguments is refused', () => {
  it('chain.append replays only the same request', () => {
    const { chain } = fresh();
    const a = chain.append({ event_type: 't', payload: { x: 1 }, actor_id: 'a', idempotency_key: 'k1' });
    const same = chain.append({ event_type: 't', payload: { x: 1 }, actor_id: 'a', idempotency_key: 'k1' });
    expect(same.replayed).toBe(true);
    expect(same.event).toEqual(a.event);
    for (const [changed, differs] of [
      [{ event_type: 't', payload: { x: 999 }, actor_id: 'a' }, 'payload'],
      [{ event_type: 't', payload: { x: 1 }, actor_id: 'b' }, 'actor_id'],
      [{ event_type: 'u', payload: { x: 1 }, actor_id: 'a' }, 'event_type'],
    ] as const) {
      let err: unknown;
      try {
        chain.append({ ...changed, idempotency_key: 'k1' });
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(IdempotencyKeyReusedError);
      expect(err).toMatchObject({ code: 'idempotency_key_reused', seq: a.event.seq, differs });
    }
    expect(chain.head().seq).toBe(1);
  });

  it('putDocument: the same put replays (replayed: true, nothing appended)', () => {
    const { docs, chain } = fresh();
    const r1 = docs.putDocument({ slug: 'd', title: 't', markdown: '# d\n\nhello\n', actor_id: 'a', idempotency_key: 'k' });
    expect(r1.replayed).toBe(false);
    const head = chain.head();
    const r2 = docs.putDocument({ slug: 'd', title: 't', markdown: '# d\n\nhello\n', actor_id: 'a', idempotency_key: 'k' });
    expect(r2).toMatchObject({ replayed: true, events: 0, doc_id: r1.doc_id, revision: 1, chain_seq: r1.chain_seq });
    expect(chain.head()).toEqual(head);
    // A put without a key is never a replay, even when it changes nothing.
    expect(docs.putDocument({ slug: 'd', title: 't', markdown: '# d\n\nhello\n', actor_id: 'a' }).replayed).toBe(false);
  });

  it('putDocument: another slug, title, markdown, source, lineage or actor under the key is refused, nothing written', () => {
    const { docs, chain } = fresh();
    const base = { slug: 'd', title: 't', markdown: '# d\n\nhello\n', actor_id: 'a', idempotency_key: 'k' };
    const r1 = docs.putDocument(base);
    const head = chain.head();
    const lineage = [{ block_id: r1.blocks[0]!.block_id, content_hash: r1.blocks[0]!.content_hash }];
    for (const [change, field] of [
      [{ slug: 'other' }, 'slug'],
      [{ title: 'another title' }, 'title'],
      [{ markdown: '# d\n\nchanged\n' }, 'markdown'],
      [{ source: { kind: 'file', path: 'notes/d.md' } }, 'source'],
      [{ derived_from: lineage }, 'derived_from'],
      [{ actor_id: 'b' }, 'actor_id'],
    ] as const) {
      let err: unknown;
      try {
        docs.putDocument({ ...base, ...change });
      } catch (e) {
        err = e;
      }
      expect(err, field).toBeInstanceOf(DocumentError);
      expect((err as DocumentError).code, field).toBe('idempotency_key_reused');
      expect((err as DocumentError).message, field).toContain(field);
    }
    expect(chain.head()).toEqual(head);
    expect(docs.getDocument('other')).toBeNull();
    expect(docs.getDocument('d')!.title).toBe('t');
  });

  it('putDocument: a replay after later writes answers with the original put (revision, title and its blocks)', () => {
    const { docs } = fresh();
    const base = { slug: 'd', title: 't', markdown: '# d\n\nfirst\n', actor_id: 'a', idempotency_key: 'k' };
    const r1 = docs.putDocument(base);
    docs.putDocument({ slug: 'd', title: 't2', markdown: '# d\n\nsecond\n', actor_id: 'a' });
    const again = docs.putDocument(base);
    expect(again).toMatchObject({ replayed: true, revision: 1, title: 't', chain_seq: r1.chain_seq });
    expect(again.blocks.map((b) => [b.block_id, b.content_hash])).toEqual(r1.blocks.map((b) => [b.block_id, b.content_hash]));
  });

  it('putDocument: a git-bound source counts by path and binding, not by the blob it pins; the project counts', () => {
    const { docs, chain } = fresh();
    const git = (blob: string) => ({ repo_root: '/r', path: 'notes/d.md', blob_sha: blob, commit: null });
    const base = { slug: 'd', title: 't', markdown: 'x\n', actor_id: 'a', idempotency_key: 'k', project: { key: 'p1', root: '/r' } };
    docs.putDocument({ ...base, source: { kind: 'file', path: 'notes/d.md', git: git('1') } });
    const head = chain.head();
    // The file moved on (another blob): the same request, a replay.
    expect(docs.putDocument({ ...base, source: { kind: 'file', path: 'notes/d.md', git: git('2') } }).replayed).toBe(true);
    // Unbound now, or another project, or none: a different request.
    expect(codeOf(() => docs.putDocument({ ...base, source: { kind: 'file', path: 'notes/d.md' } }))).toBe('idempotency_key_reused');
    expect(codeOf(() => docs.putDocument({ ...base, project: { key: 'p2', root: '/r' }, source: { kind: 'file', path: 'notes/d.md', git: git('1') } }))).toBe('idempotency_key_reused');
    expect(codeOf(() => docs.putDocument({ ...base, project: null, source: { kind: 'file', path: 'notes/d.md', git: git('1') } }))).toBe('idempotency_key_reused');
    expect(chain.head()).toEqual(head);
  });

  it('putDocument: a key held by another kind of event is refused, not replayed as a put', () => {
    const { docs, chain } = fresh();
    chain.append({ event_type: 'note.added', payload: { n: 1 }, actor_id: 'a', idempotency_key: 'shared' });
    expect(codeOf(() => docs.putDocument({ slug: 'd', title: 't', markdown: 'x\n', actor_id: 'a', idempotency_key: 'shared' }))).toBe('idempotency_key_reused');
    expect(docs.getDocument('d')).toBeNull();
  });

  it('the refusal holds after a restart (the key lives in the chain)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'kl-kl1-'));
    try {
      const a = new KronicleLite({ dataDir: dir });
      a.docs.putDocument({ slug: 'd', title: 't', markdown: 'x\n', actor_id: 'a', idempotency_key: 'k' });
      a.close();
      const b = new KronicleLite({ dataDir: dir });
      try {
        expect(b.docs.putDocument({ slug: 'd', title: 't', markdown: 'x\n', actor_id: 'a', idempotency_key: 'k' }).replayed).toBe(true);
        expect(codeOf(() => b.docs.putDocument({ slug: 'e', title: 't', markdown: 'x\n', actor_id: 'a', idempotency_key: 'k' }))).toBe('idempotency_key_reused');
      } finally {
        b.close();
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ─────────────────────────── over MCP: KL-1 to KL-3 ───────────────────────────

describe('over MCP', () => {
  let store: KronicleLite;
  let client: Client;
  let close: () => Promise<void>;

  beforeAll(async () => {
    store = new KronicleLite({ memory: true });
    const [clientT, serverT] = InMemoryTransport.createLinkedPair();
    const handle = serveStdio(createServerFactory(store, { defaultActorId: 'mws-agent' }), { transport: serverT });
    close = () => handle.close();
    client = new Client({ name: 'mws-test', version: '0.0.0' }, { versionNegotiation: { mode: { pin: '2026-07-28' } } });
    await client.connect(clientT);
  });

  afterAll(async () => {
    await client.close();
    await close();
    store.close();
  });

  it('KL-1: put_document replays the same put with replayed: true and refuses changed arguments as a tool error', async () => {
    const args = { slug: 'kl1-doc', title: 'kl1-doc', markdown: '# kl1-doc\n\nkeyed\n', idempotency_key: 'kl1-key' };
    const first = (await client.callTool({ name: 'put_document', arguments: args })) as ToolResult;
    expect(first.isError).toBeFalsy();
    expect(first.structuredContent).toMatchObject({ replayed: false });
    expect(first.structuredContent!['events']).toBeGreaterThan(0);
    const again = (await client.callTool({ name: 'put_document', arguments: args })) as ToolResult;
    expect(again.isError).toBeFalsy();
    expect(again.structuredContent).toMatchObject({ replayed: true, events: 0, chain_seq: first.structuredContent!['chain_seq'] });
    const head = store.chain.head();
    for (const change of [{ slug: 'kl1-other' }, { title: 'another title' }, { markdown: '# kl1-doc\n\nchanged\n' }]) {
      const r = (await client.callTool({ name: 'put_document', arguments: { ...args, ...change } })) as ToolResult;
      expect(r.isError, JSON.stringify(change)).toBe(true);
      expect(body(r)).toMatchObject({ error: 'idempotency_key_reused' });
    }
    expect(store.chain.head()).toEqual(head);
    expect(store.docs.getDocument('kl1-other')).toBeNull();
  });

  it('KL-2: a failed all-or-nothing apply is isError: true and keeps the structured body', async () => {
    store.docs.putDocument({ slug: 'kl2-a', title: 'a', markdown: '# a\n\nA.\n', actor_id: 'h' });
    store.docs.putDocument({ slug: 'kl2-b', title: 'b', markdown: '# b\n\nB.\n', actor_id: 'h' });
    const head = store.chain.head();
    const op = (id: string, slug: string, expect_version: number) => ({ id, op: 'put', slug, title: 'batch title', markdown: 'batch\n', expect_version });
    // The invalid item first, in the middle and last: each rolls back the whole plan.
    for (const ops of [
      [op('x', 'kl2-a', 99), op('m0', 'kl2-a', 1), op('m1', 'kl2-b', 1)],
      [op('m0', 'kl2-a', 1), op('x', 'kl2-b', 99), op('m1', 'kl2-b', 1)],
      [op('m0', 'kl2-a', 1), op('m1', 'kl2-b', 1), op('x', 'kl2-a', 99)],
    ]) {
      const r = (await client.callTool({ name: 'apply', arguments: { ops } })) as ToolResult;
      expect(r.isError).toBe(true);
      const b = body<{ status: string; ops: { id: string; status: string; error?: { code: string } }[] }>(r);
      expect(b.status).toBe('rolled_back');
      expect(b.ops.find((o) => o.id === 'x')).toMatchObject({ status: 'failed', error: { code: 'version_conflict' } });
      expect(b.ops.some((o) => o.status === 'applied')).toBe(false);
      expect(r.structuredContent).toEqual(b);
    }
    expect(store.chain.head()).toEqual(head);
    expect(store.docs.getDocument('kl2-a')!.title).toBe('a');

    // A dry run that would roll back (status failed) is an error too; one that would commit is not.
    const blocked = (await client.callTool({ name: 'apply', arguments: { ops: [op('x', 'kl2-a', 99)], dry_run: true } })) as ToolResult;
    expect(blocked.isError).toBe(true);
    expect(body(blocked)).toMatchObject({ status: 'failed', confirm_token: null });
    const planned = (await client.callTool({ name: 'apply', arguments: { ops: [op('ok', 'kl2-a', 1)], dry_run: true } })) as ToolResult;
    expect(planned.isError).toBeFalsy();
    expect(body(planned)).toMatchObject({ status: 'planned' });

    // best_effort with a failed op (partial) is an error; the ops that succeeded are still reported (and committed).
    const partial = (await client.callTool({ name: 'apply', arguments: { mode: 'best_effort', ops: [op('ok', 'kl2-b', 1), op('x', 'kl2-a', 99)] } })) as ToolResult;
    expect(partial.isError).toBe(true);
    expect(body(partial)).toMatchObject({ status: 'partial', ops: [{ id: 'ok', status: 'applied' }, { id: 'x', status: 'failed' }] });
    expect(store.docs.getDocument('kl2-b')!.title).toBe('batch title');

    // A commit is a plain success (another op id: the plan previewed above would need its confirm_token).
    const committed = (await client.callTool({ name: 'apply', arguments: { ops: [op('commit', 'kl2-a', 1)] } })) as ToolResult;
    expect(committed.isError).toBeFalsy();
    expect(body(committed)).toMatchObject({ status: 'committed' });
  });

  it('KL-3: supersede_block declares destructiveHint: true and says the old text stays on the chain', async () => {
    const { tools } = await client.listTools();
    const sup = tools.find((t) => t.name === 'supersede_block')!;
    expect(sup.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: true, idempotentHint: false });
    expect(sup.description).toMatch(/old text stays on the chain/);
  });

  it('put_document declares destructiveHint: true (full and core catalogs) and says what a re-put replaces', async () => {
    type Listed = Awaited<ReturnType<Client['listTools']>>['tools'];
    const check = (tools: Listed) => {
      const put = tools.find((t) => t.name === 'put_document')!;
      expect(put.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false });
      expect(put.description).toMatch(/changed blocks are replaced \(superseded\) and dropped ones tombstoned/);
      expect(put.description).toMatch(/old text stays on the chain/);
    };
    check((await client.listTools()).tools);

    const coreStore = new KronicleLite({ memory: true });
    const [clientT, serverT] = InMemoryTransport.createLinkedPair();
    const handle = serveStdio(createServerFactory(coreStore, { profile: 'core' }), { transport: serverT });
    const coreClient = new Client({ name: 'mws-test-core', version: '0.0.0' }, { versionNegotiation: { mode: { pin: '2026-07-28' } } });
    try {
      await coreClient.connect(clientT);
      const { tools } = await coreClient.listTools();
      expect(tools.map((t) => t.name)).toContain('put_document');
      check(tools);
    } finally {
      await coreClient.close();
      await handle.close();
      coreStore.close();
    }
  });
});
