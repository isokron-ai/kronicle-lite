/**
 * 0.8.1, hardening round 2 track 4 (protocol and real clients):
 * P2-02 bounded results, P2-04 every result valid against both served
 * schemas, P2-05/F11 oversize input, P2-06 malformed input answered,
 * P2-08 one byte limit, P2-09 Host userinfo, P2-10 resource not found,
 * P2-11 lifecycle + ping, P2-13 bearer file mode, P2-14 schema-valid ids and
 * ranges.
 */

import { Client, InMemoryTransport } from '@modelcontextprotocol/client';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { Ajv2020 } from 'ajv/dist/2020.js';
import addFormatsModule from 'ajv-formats';
import { spawn } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createHttpListener, loadOrCreateBearer } from '../src/http.js';
import { BLOCKS_PAGE_SIZE, createServerFactory, PUT_BLOCKS_LISTED, RESULT_BUDGET_BYTES, withinBudget } from '../src/server.js';
import { GuardedStdioTransport, idFromPrefix, MAX_MESSAGE_BYTES } from '../src/stdio.js';
import { KronicleLite } from '../src/store.js';

const MODERN = '2026-07-28';
const META = { 'io.modelcontextprotocol/protocolVersion': MODERN, 'io.modelcontextprotocol/clientCapabilities': {} };
const CLI = join(__dirname, '..', 'dist', 'cli.js');
const POSIX = process.platform !== 'win32';
// ajv-formats is CommonJS: under ESM interop the function may sit on .default.
const addFormats = ((addFormatsModule as unknown as { default?: typeof addFormatsModule }).default ?? addFormatsModule) as unknown as (a: Ajv2020) => void;

type Res = { content: { type: string; text?: string }[]; structuredContent?: Record<string, unknown>; isError?: boolean };

function inProcess(store: KronicleLite, opts: { core?: boolean } = {}) {
  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  const handle = serveStdio(createServerFactory(store, { defaultActorId: 'proto', ...(opts.core ? { profile: 'core' as const } : {}) }), { transport: serverT });
  const client = new Client({ name: 'proto-test', version: '0' }, { versionNegotiation: { mode: { pin: MODERN } } });
  return {
    client,
    connect: () => client.connect(clientT),
    close: async () => {
      await client.close();
      await handle.close();
    },
  };
}

// ───────────────────────────── P2-02: bounded put_document ─────────────────────────────

describe('P2-02: put_document answers with a bounded summary; the full list is paged', () => {
  let store: KronicleLite;
  let c: ReturnType<typeof inProcess>;
  beforeAll(async () => {
    store = new KronicleLite({ memory: true });
    c = inProcess(store);
    await c.connect();
  });
  afterAll(async () => {
    await c.close();
    store.close();
  });

  const readJson = async (uri: string) => JSON.parse(((await c.client.readResource({ uri })).contents[0] as { text: string }).text) as Record<string, unknown>;
  const allPages = async (first: string) => {
    const out: { block_id: string; status: string; supersedes?: string }[] = [];
    let next: string | null = first;
    while (next) {
      const page = await readJson(next);
      out.push(...(page['blocks'] as typeof out));
      next = page['next'] as string | null;
    }
    return out;
  };

  it('a 2,500-paragraph document: ≤ 100 blocks listed, exact counts, compact text = structuredContent, rest via blocks_next', async () => {
    const md = Array.from({ length: 2500 }, (_, i) => `para ${i}`).join('\n\n');
    const r = (await c.client.callTool({ name: 'put_document', arguments: { slug: 'many', title: 'Many', markdown: md } })) as Res;
    expect(r.isError).toBeFalsy();
    const sc = r.structuredContent!;
    expect(r.content[0]!.text).toBe(JSON.stringify(sc)); // compact JSON, identical value
    expect(Buffer.byteLength(JSON.stringify(r))).toBeLessThan(64 * 1024);
    expect((sc['blocks'] as unknown[]).length).toBe(PUT_BLOCKS_LISTED);
    expect(sc['block_counts']).toEqual({ total: 2500, listed: PUT_BLOCKS_LISTED, added: 2500, kept: 0, retired: 0 });
    expect(sc['blocks_truncated']).toBe(true);
    expect(sc['blocks_next']).toBe(`kronicle://docs/many/blocks/1/${PUT_BLOCKS_LISTED}`);
    const firstPage = await readJson(sc['blocks_next'] as string);
    expect(firstPage['total']).toBe(2500);
    expect((firstPage['blocks'] as unknown[]).length).toBe(BLOCKS_PAGE_SIZE);
    const rest = await allPages(sc['blocks_next'] as string);
    const ids = [...(sc['blocks'] as { block_id: string }[]).map((b) => b.block_id), ...rest.map((b) => b.block_id)];
    expect(new Set(ids).size).toBe(2500);
    expect(new Set(ids)).toEqual(new Set(store.docs.liveBlocks(sc['doc_id'] as string).map((b) => b.block_id)));
  });

  it('a re-put: added / kept / retired counted over every block; the paged list matches the library result exactly', async () => {
    const md = Array.from({ length: 2500 }, (_, i) => (i % 10 === 0 ? `changed ${i}` : `para ${i}`)).filter((_, i) => i % 7 !== 3).join('\n\n');
    // The library result (unbounded) for the same put on an identical second store.
    const twin = new KronicleLite({ memory: true });
    const lib0 = twin.docs.putDocument({ slug: 'many', title: 'Many', markdown: Array.from({ length: 2500 }, (_, i) => `para ${i}`).join('\n\n'), actor_id: 'x' });
    expect(lib0.blocks.length).toBe(2500);
    const lib = twin.docs.putDocument({ slug: 'many', title: 'Many', markdown: md, actor_id: 'x' });
    twin.close();
    const r = (await c.client.callTool({ name: 'put_document', arguments: { slug: 'many', title: 'Many', markdown: md } })) as Res;
    const sc = r.structuredContent!;
    const counts = sc['block_counts'] as Record<string, number>;
    const by = (st: string) => lib.blocks.filter((b) => b.status === st).length;
    expect(counts).toEqual({
      total: lib.blocks.length,
      listed: PUT_BLOCKS_LISTED,
      added: by('created'),
      kept: by('unchanged'),
      retired: by('tombstoned') + lib.blocks.filter((b) => b.supersedes).length,
    });
    const full = [...(sc['blocks'] as { status: string; supersedes?: string }[]), ...(await allPages(sc['blocks_next'] as string))];
    expect(full.map((b) => [b.status, b.supersedes !== undefined])).toEqual(lib.blocks.map((b) => [b.status, b.supersedes !== undefined]));
  });

  it('a small put is unchanged apart from the added fields (blocks complete, blocks_next null)', async () => {
    const r = (await c.client.callTool({ name: 'put_document', arguments: { slug: 'small', title: 'S', markdown: '# S\n\none\n\ntwo' } })) as Res;
    const sc = r.structuredContent!;
    expect((sc['blocks'] as unknown[]).length).toBe(3);
    expect(sc['blocks_truncated']).toBe(false);
    expect(sc['blocks_next']).toBeNull();
    expect(sc['block_counts']).toMatchObject({ total: 3, listed: 3, added: 3 });
  });

  it('every tool result is held to the byte budget (result_too_large instead of a dead connection)', () => {
    const big = { content: [{ type: 'text' as const, text: 'x'.repeat(RESULT_BUDGET_BYTES) }] };
    const r = withinBudget(big, 'recall');
    expect(r.isError).toBe(true);
    expect(JSON.parse(r.content[0]!.text)).toMatchObject({ error: 'result_too_large', limit: RESULT_BUDGET_BYTES });
    const ok = { content: [{ type: 'text' as const, text: 'fine' }] };
    expect(withinBudget(ok, 'recall')).toBe(ok);
  });

  it('P2-05: markdown is bounded in wire bytes: 1.5M control characters (9 MB escaped) → document_too_large, nothing written', async () => {
    const head = store.chain.head().seq;
    const r = (await c.client.callTool({ name: 'put_document', arguments: { slug: 'ctl', title: 'c', markdown: '\u0001'.repeat(1_500_000) } })) as Res;
    expect(r.isError).toBe(true);
    expect(JSON.parse(r.content[0]!.text!)).toMatchObject({ error: 'document_too_large' });
    expect(store.chain.head().seq).toBe(head);
  });
});

// ───────────────────────────── P2-04: results vs served schemas ─────────────────────────────

describe('P2-04: every tool result validates against the advertised (compact) and the full served schema', () => {
  for (const core of [false, true]) {
    it(`random sample of calls${core ? ' (--core)' : ''}`, async () => {
      const store = new KronicleLite({ memory: true });
      const c = inProcess(store, { core });
      await c.connect();
      try {
        const { tools } = await c.client.listTools();
        const full = JSON.parse(((await c.client.readResource({ uri: 'kronicle://schemas/tools' })).contents[0] as { text: string }).text) as Record<string, object>;
        const mk = () => {
          const a = new Ajv2020({ strict: false, allErrors: true });
          addFormats(a);
          return a;
        };
        const v = Object.fromEntries(tools.map((t) => [t.name, { adv: mk().compile(t.outputSchema as object), full: mk().compile(full[t.name]!) }]));
        let seed = core ? 11 : 7;
        const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
        const pick = <T,>(a: readonly T[]) => a[Math.floor(rnd() * a.length)]!;
        const cursors: string[] = [];
        const blocks: string[] = [];
        const receipts: string[] = [];
        const gen: Record<string, () => Record<string, unknown>> = {
          put_document: () => ({ slug: pick(['a', 'b', 'c.d']), title: 'T', markdown: `# H${Math.floor(rnd() * 5)}\n\nport ${Math.floor(rnd() * 9)}\n\n- item ${Math.floor(rnd() * 3)}` }),
          get_system_state: () => ({ response_format: pick(['json', 'markdown']), focus: pick(['orientation', 'recent_changes', 'retractions', 'pulse']), ...(cursors.length && rnd() < 0.6 ? { since_cursor: pick(cursors) } : {}) }),
          recall: () => ({ query: pick(['port', 'item', 'H1 port', 'nothing here']), receipts: pick(['id', 'inline']), top_k: 1 + Math.floor(rnd() * 5) }),
          verify: () => (receipts.length ? (rnd() < 0.5 ? { receipt_id: pick(receipts) } : { receipt_ids: [pick(receipts), pick(receipts)] }) : { receipt: {} }),
          audit_record: () => ({
            audit_id: 'P',
            events: [{ kind: 'call_measured', event_key: `k${Math.floor(rnd() * 4)}`, payload: { fingerprint: 'a'.repeat(64), tool: 't', status: '200', is_error: false, latency_ms: 1, bytes_out: 1 } }],
          }),
          audit_query: () => (rnd() < 0.5 ? { audit_id: 'P' } : { fingerprint: 'a'.repeat(64) }),
          audit_assumptions: () => ({ claims: [{ symbol: pick(['head', 'a', ...(blocks.length ? [pick(blocks)] : [])]), value: pick([1, 'port 3', '0']) }] }),
          verify_chain: () => ({}),
          checkpoint_chain: () => ({}),
          anchor_status: () => ({}),
          supersede_block: () => ({ block_id: blocks.length ? pick(blocks) : '00000000-0000-0000-0000-000000000000', new_content: `new ${Math.floor(rnd() * 99)}`, reason: 'r' }),
          tombstone_block: () => ({ block_id: blocks.length ? pick(blocks) : '00000000-0000-0000-0000-000000000000', reason: 'r' }),
        };
        let checked = 0;
        const run = async (name: string) => {
          const r = (await c.client.callTool({ name, arguments: gen[name]!() })) as Res;
          if (r.isError) return;
          const sc = r.structuredContent!;
          expect(v[name]!.adv(sc), `${name} vs advertised: ${JSON.stringify(v[name]!.adv.errors)}`).toBe(true);
          expect(v[name]!.full(sc), `${name} vs full: ${JSON.stringify(v[name]!.full.errors)}`).toBe(true);
          checked++;
          const walk = (x: unknown, k?: string): void => {
            if (Array.isArray(x)) return x.forEach((y) => walk(y, k));
            if (x && typeof x === 'object') return Object.entries(x).forEach(([kk, y]) => walk(y, kk));
            if (typeof x !== 'string') return;
            if (k === 'cursor' || k === 'cursor_compact') cursors.push(x);
            else if (k === 'block_id' || k === 'new_block_id') blocks.push(x);
            else if (k === 'receipt_id') receipts.push(x);
          };
          walk(sc);
        };
        const names = tools.map((t) => t.name);
        for (const n of ['put_document', 'put_document', 'get_system_state', 'recall'].filter((n) => names.includes(n))) await run(n);
        for (let i = 0; i < 120; i++) await run(pick(names));
        for (const n of names) await run(n);
        expect(checked).toBeGreaterThan(60);
      } finally {
        await c.close();
        store.close();
      }
    }, 60_000);
  }
});

// ───────────────────────────── P2-10, P2-14 ─────────────────────────────

describe('P2-10 / P2-14: not found and out of range are the caller’s errors, never "internal"', () => {
  let store: KronicleLite;
  let c: ReturnType<typeof inProcess>;
  beforeAll(async () => {
    store = new KronicleLite({ memory: true });
    c = inProcess(store);
    await c.connect();
    await c.client.callTool({ name: 'put_document', arguments: { slug: 'a', title: 'A', markdown: 'x' } });
  });
  afterAll(async () => {
    await c.close();
    store.close();
  });

  it('resources/read of a missing document: resource not found (-32602 + data.uri, the 2026-07-28 code), not -32603', async () => {
    const err = await c.client.readResource({ uri: 'kronicle://docs/nope' }).then(
      () => null,
      (e: { code?: number; data?: { uri?: string } }) => e,
    );
    expect(err?.code).toBe(-32602);
    expect(err?.data?.uri).toBe('kronicle://docs/nope');
    const err2 = await c.client.readResource({ uri: 'kronicle://docs/a/blocks/9/0' }).then(
      () => null,
      (e: { code?: number }) => e,
    );
    expect(err2?.code).toBe(-32602);
  });

  it('a schema-valid non-v4 UUID is looked up (unknown_block), not refused as invalid input', async () => {
    for (const block_id of ['00000000-0000-0000-0000-000000000000', 'abcdef01-2345-6789-abcd-ef0123456789']) {
      const r = (await c.client.callTool({ name: 'tombstone_block', arguments: { block_id, reason: 'r' } })) as Res;
      expect(r.isError).toBe(true);
      expect(JSON.parse(r.content[0]!.text!)).toMatchObject({ error: 'unknown_block' });
    }
  });

  it('checkpoint_chain to_seq beyond head → invalid_params', async () => {
    const r = (await c.client.callTool({ name: 'checkpoint_chain', arguments: { to_seq: 99_999 } })) as Res;
    expect(r.isError).toBe(true);
    expect(JSON.parse(r.content[0]!.text!)).toMatchObject({ error: 'invalid_params' });
  });
});

// ───────────────────────────── stdio wire: P2-05/F11, P2-06, P2-11 ─────────────────────────────

function wire(opts: { maxMessageBytes?: number; maxOutboundBytes?: number } = {}) {
  const store = new KronicleLite({ memory: true });
  const input = new PassThrough();
  const output = new PassThrough();
  const t = new GuardedStdioTransport(input, output, opts);
  const handle = serveStdio(createServerFactory(store, { defaultActorId: 'wire' }), { transport: t });
  const msgs: unknown[] = [];
  let buf = '';
  output.on('data', (d: Buffer) => {
    buf += d.toString('utf8');
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 1);
      if (line.trim()) msgs.push(JSON.parse(line));
    }
  });
  const find = (pred: (m: Record<string, unknown> & { id?: unknown }) => boolean) => msgs.find((m) => !Array.isArray(m) && pred(m as Record<string, unknown>)) as Record<string, unknown> | undefined;
  const wait = async <T,>(fn: () => T | undefined, ms = 5000): Promise<T> => {
    const end = Date.now() + ms;
    for (;;) {
      const v = fn();
      if (v !== undefined) return v;
      if (Date.now() > end) throw new Error(`timeout; got ${JSON.stringify(msgs).slice(0, 400)}`);
      await new Promise((r) => setTimeout(r, 5));
    }
  };
  return {
    store,
    msgs,
    write: (s: string | Buffer) => input.write(s),
    send: (o: unknown) => input.write(JSON.stringify(o) + '\n'),
    reply: (id: unknown) => wait(() => find((m) => m['id'] === id && (m['result'] !== undefined || m['error'] !== undefined))),
    wait,
    close: async () => {
      input.end();
      await handle.close();
      store.close();
    },
  };
}

describe('stdio wire (src/stdio.ts)', () => {
  it('P2-06: parse errors, a BOM, invalid requests with an id and batches are answered; the connection stays up', async () => {
    const w = wire();
    try {
      w.write('not json\n');
      expect((await w.wait(() => w.msgs.find((m) => (m as { error?: { code: number } }).error?.code === -32700))) as object).toMatchObject({ id: null });
      w.write('﻿' + JSON.stringify({ jsonrpc: '2.0', id: 'bom', method: 'tools/list', params: { _meta: META } }) + '\n');
      expect(await w.reply('bom')).toHaveProperty('result');
      for (const [id, msg] of [
        ['pa', { jsonrpc: '2.0', id: 'pa', method: 'tools/list', params: [] }],
        ['ps', { jsonrpc: '2.0', id: 'ps', method: 'tools/call', params: 'x' }],
        ['mn', { jsonrpc: '2.0', id: 'mn', method: 5 }],
        ['v1', { jsonrpc: '1.0', id: 'v1', method: 'tools/list', params: { _meta: META } }],
        ['nj', { id: 'nj', method: 'tools/list', params: { _meta: META } }],
        [1.5, { jsonrpc: '2.0', id: 1.5, method: 'tools/list', params: { _meta: META } }],
      ] as const) {
        w.send(msg);
        expect(await w.reply(id)).toMatchObject({ error: { code: -32600 } });
      }
      w.send([
        { jsonrpc: '2.0', id: 'b1', method: 'tools/list', params: { _meta: META } },
        { jsonrpc: '2.0', id: 'b2', method: 'tools/list', params: { _meta: META } },
      ]);
      const batch = (await w.wait(() => w.msgs.find((m) => Array.isArray(m)))) as { id: string; error: { code: number } }[];
      expect(batch.map((x) => [x.id, x.error.code])).toEqual([
        ['b1', -32600],
        ['b2', -32600],
      ]);
      w.send([]);
      await w.wait(() => w.msgs.filter((m) => (m as { id?: unknown; error?: { message: string } }).id === null && /empty batch/.test((m as { error?: { message: string } }).error?.message ?? '')).at(0));
      w.send({ jsonrpc: '2.0', id: 'alive', method: 'tools/list', params: { _meta: META } });
      expect(await w.reply('alive')).toHaveProperty('result');
    } finally {
      await w.close();
    }
  });

  it('P2-05/F11: a line over the limit is discarded as it streams, answered -32600 with its id, and the server keeps serving', async () => {
    const w = wire({ maxMessageBytes: 64 * 1024 });
    try {
      const big = JSON.stringify({ jsonrpc: '2.0', id: 'huge', method: 'tools/call', params: { name: 'recall', arguments: { query: 'q'.repeat(200_000) }, _meta: META } }) + '\n';
      for (let i = 0; i < big.length; i += 10_000) w.write(big.slice(i, i + 10_000));
      expect(await w.reply('huge')).toMatchObject({ error: { code: -32600, data: { limit: 64 * 1024 } } });
      // id after a large params object: answered with id null
      w.write(JSON.stringify({ jsonrpc: '2.0', method: 'tools/call', params: { name: 'recall', arguments: { query: 'q'.repeat(200_000) } }, id: 'late' }) + '\n');
      await w.wait(() => w.msgs.find((m) => (m as { id?: unknown; error?: { code: number } }).id === null && (m as { error?: { code: number } }).error?.code === -32600));
      w.send({ jsonrpc: '2.0', id: 'after', method: 'tools/list', params: { _meta: META } });
      expect(await w.reply('after')).toHaveProperty('result');
    } finally {
      await w.close();
    }
  });

  it('the shared limit admits every schema-valid put_document (2,000,000 characters escaped as \\uXXXX)', () => {
    expect(MAX_MESSAGE_BYTES).toBeGreaterThan(2_000_000 * 6 + 64 * 1024);
  });

  it('an outbound message over the client buffer is replaced by an error for the same id', async () => {
    const w = wire({ maxOutboundBytes: 4096 });
    try {
      w.send({ jsonrpc: '2.0', id: 'tl', method: 'tools/list', params: { _meta: META } });
      expect(await w.reply('tl')).toMatchObject({ error: { code: -32603, data: { limit: 4096 } } });
    } finally {
      await w.close();
    }
  });

  it('P2-11: before the handshake a request is refused (no write lands), notifications are dropped, ping works in every era', async () => {
    const w = wire();
    try {
      w.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
      w.send({ jsonrpc: '2.0', id: 'p0', method: 'ping' });
      expect(await w.reply('p0')).toEqual({ jsonrpc: '2.0', id: 'p0', result: {} });
      w.send({ jsonrpc: '2.0', id: 'w', method: 'tools/call', params: { name: 'put_document', arguments: { slug: 'preinit', title: 'p', markdown: 'x' } } });
      expect(await w.reply('w')).toMatchObject({ error: { code: -32600 } });
      expect(w.store.chain.head().seq).toBe(0);
      // a 2026-07-28 opening pins the modern era; ping still answers
      w.send({ jsonrpc: '2.0', id: 'd', method: 'server/discover', params: { _meta: META } });
      expect(await w.reply('d')).toHaveProperty('result');
      w.send({ jsonrpc: '2.0', id: 'tl', method: 'tools/list', params: { _meta: META } });
      expect(await w.reply('tl')).toHaveProperty('result');
      w.send({ jsonrpc: '2.0', id: 'pm', method: 'ping', params: { _meta: META } });
      expect(await w.reply('pm')).toMatchObject({ result: {} });
      // every later request must carry a supported envelope
      w.send({ jsonrpc: '2.0', id: 'nm', method: 'tools/list' });
      expect(await w.reply('nm')).toMatchObject({ error: { code: -32602 } });
      w.send({ jsonrpc: '2.0', id: 'old', method: 'tools/list', params: { _meta: { ...META, 'io.modelcontextprotocol/protocolVersion': '1900-01-01' } } });
      expect(await w.reply('old')).toMatchObject({ error: { code: -32022, data: { requested: '1900-01-01' } } });
    } finally {
      await w.close();
    }
  });

  it('P2-11: a 2025-era initialize still opens a legacy connection (ping answered by the SDK)', async () => {
    const w = wire();
    try {
      w.send({ jsonrpc: '2.0', id: 'i', method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'old', version: '1' } } });
      expect(await w.reply('i')).toMatchObject({ result: { protocolVersion: '2025-06-18' } });
      w.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
      w.send({ jsonrpc: '2.0', id: 'c', method: 'tools/call', params: { name: 'verify_chain', arguments: {} } });
      expect(await w.reply('c')).toHaveProperty('result');
      w.send({ jsonrpc: '2.0', id: 'p', method: 'ping' });
      expect(await w.reply('p')).toMatchObject({ result: {} });
    } finally {
      await w.close();
    }
  });

  it('idFromPrefix reads the top-level id, not a nested one', () => {
    expect(idFromPrefix('{"jsonrpc":"2.0","params":{"id":"inner","x":[1,{"id":2}]},"id":"outer","method":"m"')).toEqual({ id: 'outer', method: 'm' });
    expect(idFromPrefix('{"id": 42, "method": "tools/call", "params": {"q": "aaaa')).toEqual({ id: 42, method: 'tools/call' });
    expect(idFromPrefix('{"method":"tools/call","params":{"q":"aaaa')).toEqual({ method: 'tools/call' });
    expect(idFromPrefix('[1,2')).toEqual({});
  });
});

describe.skipIf(!existsSync(CLI))('stdio wire through the built CLI', () => {
  it('F11: an oversize line does not end the process; the next request is served', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'kl-f11-'));
    const child = spawn(process.execPath, [CLI, 'serve', '--data-dir', join(dir, 'd')], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, KRONICLE_LITE_MAX_MESSAGE_BYTES: String(64 * 1024) },
    });
    let out = '';
    child.stdout!.on('data', (d: Buffer) => (out += d.toString()));
    const until = async (re: RegExp) => {
      const end = Date.now() + 15_000;
      while (!re.test(out)) {
        if (Date.now() > end) throw new Error(`timeout: ${out.slice(0, 300)}`);
        await new Promise((r) => setTimeout(r, 20));
      }
    };
    try {
      child.stdin!.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'recall', arguments: { query: 'z'.repeat(300_000) }, _meta: META } }) + '\n');
      await until(/"id":1,"error":\{"code":-32600/);
      child.stdin!.write(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: { _meta: META } }) + '\n');
      await until(/"result":\{"tools".*"id":2\}/);
      expect(child.exitCode).toBeNull();
    } finally {
      child.stdin!.end();
      await new Promise((r) => child.once('exit', r));
      rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
    }
  }, 30_000);
});

// ───────────────────────────── HTTP: P2-08, P2-09, P2-13 ─────────────────────────────

describe('HTTP transport limits and headers', () => {
  const TOKEN = 'b'.repeat(43);
  const call = (listener: ReturnType<typeof createHttpListener>['listener'], body: string, headers: Record<string, string> = {}) =>
    new Promise<{ status: number; body: string }>((resolve, reject) => {
      // A minimal in-process request through a real socket.
      import('node:http').then(({ createServer, request }) => {
        const srv = createServer(listener).listen(0, '127.0.0.1', () => {
          const port = (srv.address() as { port: number }).port;
          const req = request(
            {
              host: '127.0.0.1',
              port,
              path: '/mcp',
              method: 'POST',
              headers: {
                Host: `127.0.0.1:${port}`,
                Authorization: `Bearer ${TOKEN}`,
                'Content-Type': 'application/json',
                Accept: 'application/json, text/event-stream',
                'MCP-Protocol-Version': MODERN,
                'Mcp-Method': 'tools/call',
                'Mcp-Name': 'put_document',
                ...headers,
              },
            },
            (res) => {
              let b = '';
              res.on('data', (d: Buffer) => (b += d.toString()));
              res.on('end', () => srv.close(() => resolve({ status: res.statusCode ?? 0, body: b })));
            },
          );
          req.on('error', (e) => srv.close(() => reject(e)));
          req.end(body);
        });
      }, reject);
    });
  const putBody = (markdown: string) =>
    JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'put_document', arguments: { slug: 'big', title: 'b', markdown }, _meta: META } });

  it('P2-08: a schema-max CJK document (6 MB body, over the SDK 4 MiB default) is accepted, like on stdio', async () => {
    const store = new KronicleLite({ memory: true });
    const h = createHttpListener({ factory: createServerFactory(store), bearer: TOKEN });
    try {
      const r = await call(h.listener, putBody('中'.repeat(2_000_000)));
      expect(r.status).toBe(200);
      expect(r.body).not.toMatch(/"isError":true/);
      expect(store.docs.getDocument('big')).not.toBeNull();
    } finally {
      await h.close();
      store.close();
    }
  }, 60_000);

  it('P2-08: a body over the shared limit → 413', async () => {
    const store = new KronicleLite({ memory: true });
    const h = createHttpListener({ factory: createServerFactory(store), bearer: TOKEN, maxMessageBytes: 256 * 1024 });
    try {
      const r = await call(h.listener, putBody('a'.repeat(300_000))).catch((e: Error) => ({ status: -1, body: e.message }));
      expect([413, -1]).toContain(r.status);
    } finally {
      await h.close();
      store.close();
    }
  });

  it('P2-09: a Host header with userinfo → 400, not 500', async () => {
    const store = new KronicleLite({ memory: true });
    const h = createHttpListener({ factory: createServerFactory(store), bearer: TOKEN });
    try {
      const r = await call(h.listener, putBody('x'), { Host: 'evil.com:1@127.0.0.1' });
      expect(r.status).toBe(400);
    } finally {
      await h.close();
      store.close();
    }
  });

  it.skipIf(!POSIX)('P2-13: an existing bearer file readable by others is tightened to 0600 and reported', () => {
    const dir = mkdtempSync(join(tmpdir(), 'kl-bearer-'));
    try {
      writeFileSync(join(dir, 'http-bearer.token'), 'c'.repeat(43) + '\n');
      chmodSync(join(dir, 'http-bearer.token'), 0o644);
      const b = loadOrCreateBearer(dir);
      expect(b.created).toBe(false);
      expect(b.tightened).toBe(0o644);
      expect(statSync(b.file).mode & 0o777).toBe(0o600);
      expect(loadOrCreateBearer(dir).tightened).toBeUndefined();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
