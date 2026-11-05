/**
 * End-to-end over the MCP protocol with the v2 SDK:
 *   (a) in-memory 2026-07-28 client against the dual-era `serveStdio` entry,
 *   (b) the built CLI over real stdio (modern client, auto-negotiated),
 *   (c) one Streamable HTTP round trip with a bearer token,
 *   (d) a 2025-06-18-style `initialize` handshake client (raw JSON-RPC over
 *       stdio) proving legacy clients still get served,
 *   plus raw-wire checks of what the 2026-07-28 revision requires on
 *   results (resultType, ttlMs/cacheScope, _meta serverInfo).
 */

import { Client, InMemoryTransport, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { loadOrCreateBearer, serveHttp, type HttpServeHandle } from '../src/http.js';
import type { Receipt } from '../src/recall/receipt.js';
import { CACHE_HINTS, createServer, createServerFactory, INSTRUCTIONS } from '../src/server.js';
import { KronicleLite } from '../src/store.js';

const MODERN = '2026-07-28';
const META = { 'io.modelcontextprotocol/protocolVersion': MODERN, 'io.modelcontextprotocol/clientCapabilities': {} };

const TOOL_NAMES = [
  'anchor_status',
  'apply',
  'audit_assumptions',
  'audit_query',
  'audit_record',
  'checkpoint_chain',
  'get_system_state',
  'put_document',
  'recall',
  'supersede_block',
  'tombstone_block',
  'verify',
  'verify_chain',
].sort();

const OPEN_WORLD = new Set(['checkpoint_chain', 'anchor_status']);

interface ToolResult {
  content: { type: string; text?: string }[];
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
}

function parse<T = unknown>(r: unknown): T {
  const res = r as ToolResult;
  const t = res.content[0];
  if (!t || t.type !== 'text' || !t.text) throw new Error('no text content');
  const fromText = JSON.parse(t.text) as T;
  // Every successful result carries the same value as structuredContent.
  if (!res.isError) expect(res.structuredContent).toEqual(fromText);
  return fromText;
}

function textOf(r: unknown): string {
  return (r as ToolResult).content[0]?.text ?? '';
}

describe('server metadata', () => {
  it('instructions fit the 512-char window Codex reads', () => {
    expect(INSTRUCTIONS.length).toBeLessThanOrEqual(512);
    expect(INSTRUCTIONS).toMatch(/get_system_state/);
    expect(INSTRUCTIONS).toMatch(/since_cursor/);
  });

  it('cache hints: catalog is public and long-lived, document reads are private and stale', () => {
    expect(CACHE_HINTS['tools/list']).toEqual({ ttlMs: 3_600_000, cacheScope: 'public' });
    expect(CACHE_HINTS['resources/read']).toEqual({ ttlMs: 0, cacheScope: 'private' });
  });
});

describe('MCP server (in-process, 2026-07-28 client via serveStdio over InMemoryTransport)', () => {
  let store: KronicleLite;
  let client: Client;
  let close: () => Promise<void>;

  beforeAll(async () => {
    store = new KronicleLite({ memory: true });
    const [clientT, serverT] = InMemoryTransport.createLinkedPair();
    const handle = serveStdio(createServerFactory(store, { defaultActorId: 'test-agent' }), { transport: serverT });
    close = () => handle.close();
    client = new Client({ name: 'test-client', version: '0.0.0' }, { versionNegotiation: { mode: { pin: MODERN } } });
    await client.connect(clientT);
  });

  afterAll(async () => {
    await client.close();
    await close();
    store.close();
  });

  it('negotiates the modern era and answers server/discover with identity + instructions', async () => {
    expect(client.getProtocolEra()).toBe('modern');
    const d = await client.discover();
    expect(d.supportedVersions).toContain(MODERN);
    expect(d.capabilities).toMatchObject({ tools: expect.any(Object), resources: expect.any(Object) });
    expect(d.instructions).toBe(INSTRUCTIONS);
    expect(client.getServerVersion()).toMatchObject({ name: 'kronicle-lite' });
  });

  it('lists the expected tools with instructive descriptions, annotations and an outputSchema on every tool', async () => {
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(TOOL_NAMES);
    for (const t of tools) {
      expect(t.title, t.name).toBeTruthy();
      expect(t.inputSchema, t.name).toMatchObject({ type: 'object' });
      expect(t.outputSchema, t.name).toMatchObject({ type: 'object' });
      expect(t.annotations, t.name).toHaveProperty('readOnlyHint');
      // Only the anchoring surface can leave the box (push / remote check).
      expect(t.annotations?.openWorldHint, t.name).toBe(OPEN_WORLD.has(t.name));
    }
    const gss = tools.find((t) => t.name === 'get_system_state')!;
    expect(gss.description).toMatch(/since_cursor/);
    expect(gss.description).toMatch(/drift banner/);
    expect((gss.inputSchema as { properties: Record<string, unknown> }).properties).toHaveProperty('budget_tokens');
    expect((gss.outputSchema as { required: string[] }).required).toEqual(expect.arrayContaining(['cursor', 'head', 'drift_banner']));
    expect(tools.find((t) => t.name === 'tombstone_block')!.annotations).toMatchObject({ destructiveHint: true });
    expect(tools.find((t) => t.name === 'put_document')!.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: false });
  });

  it('tools/list order is deterministic across calls', async () => {
    const a = (await client.listTools({}, { cacheMode: 'bypass' })).tools.map((t) => t.name);
    const b = (await client.listTools({}, { cacheMode: 'bypass' })).tools.map((t) => t.name);
    expect(a).toEqual(b);
  });

  it('runs the full loop: orient → put → recall → verify → supersede → verify → orient', async () => {
    // Cold orient, markdown by default; structuredContent still carries the JSON state.
    const o1 = (await client.callTool({ name: 'get_system_state', arguments: {} })) as ToolResult;
    const md = textOf(o1);
    expect(md).toMatch(/^# kronicle-lite orient — head seq 0/);
    expect(md).toMatch(/cursor_compact:\*\* `sxt1c\.0\./);
    const cursorCompact = /cursor_compact:\*\* `([^`]+)`/.exec(md)![1]!;
    expect(o1.structuredContent).toMatchObject({ format: 'kronicle-lite/1', cursor_compact: cursorCompact, head: { seq: 0 } });

    // Write with the cursor: no advisory because we just oriented.
    const put = parse<{
      revision: number;
      head: { seq: number };
      blocks: { block_id: string; content_hash: string }[];
      stale_write_advisory: { advisory: boolean };
    }>(
      await client.callTool({
        name: 'put_document',
        arguments: {
          slug: 'runbook',
          title: 'Runbook',
          markdown: '# Runbook\n\nRestart the worker with systemctl.\n\nPage the on-call after two failures.',
          cursor: cursorCompact,
        },
      }),
    );
    expect(put.revision).toBe(1);
    expect(put.head.seq).toBe(4);
    expect(put.blocks).toHaveLength(3);
    expect(put.stale_write_advisory.advisory).toBe(false);

    // Recall: receipts by id (the default), verified by id.
    const rcId = parse<{ hits: { block_id: string; receipt: Receipt | null; receipt_id: string; content: string }[] }>(
      await client.callTool({ name: 'recall', arguments: { query: 'restart worker' } }),
    );
    expect(rcId.hits[0]!.receipt).toBeNull();
    expect(rcId.hits[0]!.receipt_id).toMatch(/^[0-9a-f-]{36}$/);
    const v0 = parse<{ status: string; receipt_id: string }>(
      await client.callTool({ name: 'verify', arguments: { receipt_id: rcId.hits[0]!.receipt_id } }),
    );
    expect(v0).toMatchObject({ status: 'VERIFIED', receipt_id: rcId.hits[0]!.receipt_id });
    const vUnknown = parse<{ status: string; reason: string }>(
      await client.callTool({ name: 'verify', arguments: { receipt_id: 'nope' } }),
    );
    expect(vUnknown.status).toBe('UNVERIFIED');

    // Recall with the receipt inline.
    const rc = parse<{ hits: { block_id: string; receipt: Receipt; content: string }[] }>(
      await client.callTool({ name: 'recall', arguments: { query: 'restart worker', receipts: 'inline' } }),
    );
    expect(rc.hits[0]!.content).toContain('systemctl');
    const receipt = rc.hits[0]!.receipt;
    expect(receipt.v).toBe(2);
    expect(receipt.chain_seq).toBe(4);

    const v1 = parse<{ status: string; reason: string }>(
      await client.callTool({ name: 'verify', arguments: { receipt } }),
    );
    expect(v1).toMatchObject({ status: 'VERIFIED', reason: 'verified' });

    // Supersede that block.
    const sup = parse<{ new_block_id: string; head: { seq: number }; stale_write_advisory: { advisory: boolean } }>(
      await client.callTool({
        name: 'supersede_block',
        arguments: { block_id: receipt.block_id, new_content: 'Restart the worker with the restart script.', reason: 'tooling changed' },
      }),
    );
    expect(sup.head.seq).toBe(7);

    const v2 = parse<{ status: string; current_block_id: string }>(
      await client.callTool({ name: 'verify', arguments: { receipt } }),
    );
    expect(v2.status).toBe('SUPERSEDED');
    expect(v2.current_block_id).toBe(sup.new_block_id);

    // Malformed receipt → structured UNVERIFIED, not an error.
    const v3 = parse<{ status: string; reason: string }>(
      await client.callTool({ name: 'verify', arguments: { receipt: { junk: 1 } } }),
    );
    expect(v3).toEqual(expect.objectContaining({ status: 'UNVERIFIED', reason: 'malformed_receipt' }));

    // Warm orient as JSON shows the retraction and the delta since the cursor.
    const o2 = parse<{
      recovery: { method: string; from_seq: number };
      delta: { events_since: number };
      retractions: { kind: string; block_id: string }[];
      cursor: string;
    }>(
      await client.callTool({
        name: 'get_system_state',
        arguments: { since_cursor: cursorCompact, focus: 'recent_changes', response_format: 'json' },
      }),
    );
    expect(o2.recovery.method).toBe('presented_compact');
    expect(o2.delta.events_since).toBe(7);
    expect(o2.retractions).toEqual([expect.objectContaining({ kind: 'supersession', block_id: receipt.block_id })]);

    // audit_assumptions grades the old block as stale.
    const audit = parse<{ results: { verdict: string }[]; counts: Record<string, number> }>(
      await client.callTool({
        name: 'audit_assumptions',
        arguments: { claims: [{ symbol: receipt.block_id, value: receipt.content_hash }, { symbol: 'head', value: 7 }] },
      }),
    );
    expect(audit.results.map((r) => r.verdict)).toEqual(['stale', 'current']);
    expect(audit.counts).toMatchObject({ stale: 1, current: 1 });

    // Tombstone with a different actor who never oriented → advisory true.
    const tomb = parse<{ stale_write_advisory: { advisory: boolean; line: string } }>(
      await client.callTool({
        name: 'tombstone_block',
        arguments: { block_id: put.blocks[2]!.block_id, reason: 'policy retired', actor_id: 'stranger' },
      }),
    );
    expect(tomb.stale_write_advisory.advisory).toBe(true);
    expect(tomb.stale_write_advisory.line).toMatch(/never oriented/);

    // Errors are structured tool errors (isError, text only — no structuredContent to validate).
    const bad = (await client.callTool({
      name: 'tombstone_block',
      arguments: { block_id: put.blocks[2]!.block_id, reason: 'again' },
    })) as ToolResult;
    expect(bad.isError).toBe(true);
    expect(parse<{ error: string }>(bad).error).toBe('block_not_live');

    // Chain + checkpoint.
    const cp = parse<{ to_seq: number }>(await client.callTool({ name: 'checkpoint_chain', arguments: {} }));
    expect(cp.to_seq).toBe(store.chain.head().seq);
    const vc = parse<{ ok: boolean; checkpoints: { ok: boolean }[] }>(
      await client.callTool({ name: 'verify_chain', arguments: {} }),
    );
    expect(vc.ok).toBe(true);
    expect(vc.checkpoints).toEqual([expect.objectContaining({ ok: true })]);

    // Resource read.
    const { resources } = await client.listResources();
    expect(resources.map((r) => r.uri)).toContain('kronicle://docs/runbook');
    const doc = await client.readResource({ uri: 'kronicle://docs/runbook' });
    expect((doc.contents[0] as { text: string }).text).toContain('restart script');
    expect((doc.contents[0] as { text: string }).text).not.toContain('Page the on-call');
  });

  it('0.9.0: audit_record / audit_query over MCP, idempotent retry, typed errors; verify takes a batch', async () => {
    const F = 'f'.repeat(64);
    const ev = { kind: 'call_measured', event_key: 'mcp-c1', payload: { fingerprint: F, tool: 'x', status: '200', is_error: false, latency_ms: 3, bytes_out: 10 } };
    const r1 = parse<{ recorded: { replayed: boolean; event_id: string }[] }>(await client.callTool({ name: 'audit_record', arguments: { audit_id: 'MCP', events: [ev] } }));
    const r2 = parse<{ recorded: { replayed: boolean; event_id: string }[] }>(await client.callTool({ name: 'audit_record', arguments: { audit_id: 'MCP', events: [ev] } }));
    expect(r1.recorded[0]!.replayed).toBe(false);
    expect(r2.recorded[0]).toMatchObject({ replayed: true, event_id: r1.recorded[0]!.event_id });
    const bad = (await client.callTool({ name: 'audit_record', arguments: { audit_id: 'MCP', events: [{ ...ev, payload: { ...ev.payload, latency_ms: 4 } }] } })) as ToolResult;
    expect(bad.isError).toBe(true);
    expect(JSON.parse(textOf(bad))).toMatchObject({ error: 'event_key_conflict', index: 0 });
    const q = parse<{ events: { event_key: string; actor_id: string }[]; findings: unknown[] | null }>(await client.callTool({ name: 'audit_query', arguments: { fingerprint: F } }));
    expect(q.events.map((e) => [e.event_key, e.actor_id])).toEqual([['mcp-c1', 'test-agent']]);
    expect(q.findings).toBeNull();
    const schemas = await client.readResource({ uri: 'kronicle://schemas/audit' });
    expect(Object.keys(JSON.parse((schemas.contents[0] as { text: string }).text) as object).sort()).toEqual(
      ['call_measured', 'catalog_snapshot', 'finding', 'fix_applied', 'gate_result', 'regression_result'],
    );

    store.docs.putDocument({ slug: 'batch-verify', title: 'b', markdown: '# B\n\nzebra crossing one.\n', actor_id: 'h' });
    const hits = parse<{ hits: { receipt_id: string }[] }>(await client.callTool({ name: 'recall', arguments: { query: 'zebra crossing' } })).hits;
    expect(hits.length).toBeGreaterThan(0);
    const vr = await client.callTool({ name: 'verify', arguments: { receipt_ids: [hits[0]!.receipt_id, 'no-such-receipt'] } });
    expect((vr as ToolResult).isError, textOf(vr)).toBeFalsy();
    const v = parse<{ status: string; results: { status: string }[]; counts: Record<string, number> }>(vr);
    expect(v.results.map((x) => x.status)).toEqual(['VERIFIED', 'UNVERIFIED']);
    expect(v.status).toBe('UNVERIFIED'); // fail closed at top level
    expect(v.counts['VERIFIED']).toBe(1);
  });

  it('0.9.0: apply over MCP: dry_run → confirm_token → commit once; a replayed token is a typed error', async () => {
    const ops = [{ id: 'n', op: 'put', slug: 'mcp-apply', title: 'M', markdown: '# M\n\nvia apply.\n', expect_version: 0 }];
    const plan = parse<{ status: string; confirm_token: string; ops: { status: string }[] }>(await client.callTool({ name: 'apply', arguments: { ops, dry_run: true } }));
    expect(plan.status).toBe('planned');
    expect(store.docs.getDocument('mcp-apply')).toBeNull();
    const done = parse<{ status: string; receipt: { seq: number } }>(await client.callTool({ name: 'apply', arguments: { ops, confirm_token: plan.confirm_token } }));
    expect(done.status).toBe('committed');
    expect(store.chain.get(done.receipt.seq)!.event_type).toBe('apply.committed');
    const again = (await client.callTool({ name: 'apply', arguments: { ops, confirm_token: plan.confirm_token } })) as ToolResult;
    expect(again.isError).toBe(true);
    expect(JSON.parse(textOf(again))).toMatchObject({ error: 'confirm_used' });
  });

  it('pulse is cheap and surfaces drift after many events', async () => {
    for (let i = 0; i < 110; i++) store.chain.append({ event_type: 'note.added', payload: { i }, actor_id: 'x' });
    const p = parse<{ drift_banner: { surfaced: boolean }; delta: null }>(
      await client.callTool({ name: 'get_system_state', arguments: { focus: 'pulse', response_format: 'json' } }),
    );
    expect(p.drift_banner.surfaced).toBe(true);
    expect(p.delta).toBeNull();
  });
});

describe('MCP server (in-process, legacy 2025-06-18 initialize client via serveStdio)', () => {
  let store: KronicleLite;
  let client: Client;
  let close: () => Promise<void>;

  beforeAll(async () => {
    store = new KronicleLite({ memory: true });
    const [clientT, serverT] = InMemoryTransport.createLinkedPair();
    const handle = serveStdio(createServerFactory(store, { defaultActorId: 'legacy-agent' }), { transport: serverT });
    close = () => handle.close();
    // Default negotiation mode is the plain 2025 `initialize` handshake; offer 2025-06-18 first.
    client = new Client({ name: 'legacy-client', version: '0.0.0' }, { supportedProtocolVersions: ['2025-06-18'] });
    await client.connect(clientT);
  });

  afterAll(async () => {
    await client.close();
    await close();
    store.close();
  });

  it('is served under the negotiated legacy revision with the same catalog', async () => {
    expect(client.getProtocolEra()).toBe('legacy');
    expect(client.getInstructions()).toBe(INSTRUCTIONS);
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(TOOL_NAMES);
    const put = parse<{ head: { seq: number } }>(
      await client.callTool({ name: 'put_document', arguments: { slug: 'a', title: 'A', markdown: 'hello legacy' } }),
    );
    expect(put.head.seq).toBe(2);
  });
});

describe('direct McpServer.connect (v1-style wiring still works for embedding)', () => {
  it('serves a legacy client over a plain transport', async () => {
    const store = new KronicleLite({ memory: true });
    const server = createServer(store, { defaultActorId: 'embed' });
    const [clientT, serverT] = InMemoryTransport.createLinkedPair();
    await server.connect(serverT);
    const client = new Client({ name: 'embed-client', version: '0.0.0' });
    await client.connect(clientT);
    const s = parse<{ actor_id: string }>(
      await client.callTool({ name: 'get_system_state', arguments: { response_format: 'json' } }),
    );
    expect(s.actor_id).toBe('embed');
    await client.close();
    await server.close();
    store.close();
  });
});

const CLI = join(process.cwd(), 'dist', 'cli.js');

describe.skipIf(!existsSync(CLI))('MCP server over stdio (built CLI, modern client with auto negotiation)', () => {
  let dir: string;
  let client: Client;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'kl-stdio-'));
    client = new Client({ name: 'stdio-test', version: '0.0.0' }, { versionNegotiation: { mode: 'auto' } });
    await client.connect(
      new StdioClientTransport({ command: process.execPath, args: [CLI, 'serve', '--data-dir', dir, '--actor', 'stdio-agent'] }),
    );
  });

  afterAll(async () => {
    await client.close();
    rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });

  it('probes with server/discover, lands on 2026-07-28, and answers tools/list and tools/call', async () => {
    expect(client.getProtocolEra()).toBe('modern');
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toContain('get_system_state');
    const put = parse<{ head: { seq: number } }>(
      await client.callTool({ name: 'put_document', arguments: { slug: 'a', title: 'A', markdown: 'hello stdio' } }),
    );
    expect(put.head.seq).toBe(2);
    const s = parse<{ actor_id: string; head: { seq: number } }>(
      await client.callTool({ name: 'get_system_state', arguments: { response_format: 'json' } }),
    );
    expect(s.actor_id).toBe('stdio-agent');
    expect(s.head.seq).toBe(2);
  });
});

// ───────────────────────────── raw wire (stdio) ─────────────────────────────

interface RawRpc {
  send(msg: Record<string, unknown>): void;
  /** Wait for the response with this id (responses may arrive out of order: handlers are async). */
  response(id: number): Promise<Record<string, unknown>>;
  close(): Promise<void>;
}

function rawStdio(dir: string): RawRpc {
  const child: ChildProcess = spawn(process.execPath, [CLI, 'serve', '--data-dir', dir], { stdio: ['pipe', 'pipe', 'ignore'] });
  const byId = new Map<number, Record<string, unknown>>();
  const waiters = new Map<number, (msg: Record<string, unknown>) => void>();
  createInterface({ input: child.stdout! }).on('line', (line) => {
    const msg = JSON.parse(line) as Record<string, unknown>;
    const id = msg['id'];
    if (typeof id !== 'number') return; // notifications
    const w = waiters.get(id);
    if (w) {
      waiters.delete(id);
      w(msg);
    } else byId.set(id, msg);
  });
  return {
    send: (msg) => child.stdin!.write(JSON.stringify(msg) + '\n'),
    response: (id) =>
      new Promise((resolve, reject) => {
        const got = byId.get(id);
        if (got) {
          byId.delete(id);
          return resolve(got);
        }
        const t = setTimeout(() => reject(new Error(`timeout waiting for response id ${id}`)), 10_000);
        waiters.set(id, (msg) => {
          clearTimeout(t);
          resolve(msg);
        });
      }),
    close: () =>
      new Promise((resolve) => {
        child.once('exit', () => resolve());
        child.stdin!.end();
      }),
  };
}

describe.skipIf(!existsSync(CLI))('raw JSON-RPC over stdio: era behavior of the built CLI', () => {
  it('(d) a 2025-06-18 initialize handshake client is served under 2025-06-18, without 2026 result fields', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'kl-legacy-'));
    const rpc = rawStdio(dir);
    try {
      rpc.send({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'old-client', version: '1' } },
      });
      const init = (await rpc.response(1)) as { id: number; result: Record<string, unknown> };
      expect(init.id).toBe(1);
      expect(init.result['protocolVersion']).toBe('2025-06-18');
      expect(init.result['serverInfo']).toMatchObject({ name: 'kronicle-lite' });
      expect(init.result['instructions']).toBe(INSTRUCTIONS);
      expect(init.result).not.toHaveProperty('resultType');

      rpc.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
      rpc.send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
      const list = (await rpc.response(2)) as { id: number; result: Record<string, unknown> };
      expect(list.id).toBe(2);
      expect((list.result['tools'] as { name: string }[]).map((t) => t.name).sort()).toEqual(TOOL_NAMES);
      expect(list.result).not.toHaveProperty('ttlMs');
      expect(list.result).not.toHaveProperty('resultType');

      rpc.send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'verify_chain', arguments: {} } });
      const call = (await rpc.response(3)) as { id: number; result: ToolResult };
      expect(call.id).toBe(3);
      expect(parse<{ ok: boolean }>(call.result).ok).toBe(true);
      expect(call.result).not.toHaveProperty('resultType');

      // A modern request on a connection pinned to the legacy era is refused.
      rpc.send({ jsonrpc: '2.0', id: 4, method: 'server/discover', params: { _meta: META } });
      const refused = (await rpc.response(4)) as { id: number; error?: { code: number } };
      expect(refused.id).toBe(4);
      expect(refused.error).toBeDefined();
    } finally {
      await rpc.close();
      rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
    }
  });

  it('a modern opening gets 2026-07-28 result fields; a later initialize on that connection gets -32022', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'kl-modern-'));
    const rpc = rawStdio(dir);
    try {
      rpc.send({ jsonrpc: '2.0', id: 1, method: 'server/discover', params: { _meta: META } });
      const d = (await rpc.response(1)) as { result: Record<string, unknown> };
      expect(d.result).toMatchObject({
        resultType: 'complete',
        supportedVersions: [MODERN],
        instructions: INSTRUCTIONS,
        ttlMs: CACHE_HINTS['server/discover'].ttlMs,
        cacheScope: 'public',
      });
      expect((d.result['_meta'] as Record<string, unknown>)['io.modelcontextprotocol/serverInfo']).toMatchObject({ name: 'kronicle-lite' });

      rpc.send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: { _meta: META } });
      const list = (await rpc.response(2)) as { result: Record<string, unknown> };
      expect(list.result).toMatchObject({ resultType: 'complete', ttlMs: CACHE_HINTS['tools/list'].ttlMs, cacheScope: 'public' });
      expect((list.result['tools'] as { outputSchema?: unknown }[]).every((t) => t.outputSchema !== undefined)).toBe(true);

      rpc.send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'verify_chain', arguments: {}, _meta: META } });
      const call = (await rpc.response(3)) as { result: ToolResult & { resultType: string } };
      expect(call.result.resultType).toBe('complete');
      expect(call.result.structuredContent).toMatchObject({ ok: true });

      // Note (SDK 2.4.0): once a stdio connection is pinned to an instance, that instance does not
      // re-validate the per-request protocol version; the opening request is where the version is
      // checked (see the next test). HTTP validates every request because each one is its own exchange.

      // Legacy handshake after a modern opening: the connection is pinned modern.
      rpc.send({
        jsonrpc: '2.0',
        id: 5,
        method: 'initialize',
        params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'old', version: '1' } },
      });
      const late = (await rpc.response(5)) as { error: { code: number } };
      expect(late.error.code).toBe(-32022);
    } finally {
      await rpc.close();
      rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
    }
  });
});

// ───────────────────────────── Streamable HTTP ─────────────────────────────

describe.skipIf(!existsSync(CLI))('raw JSON-RPC over stdio: unsupported version at opening', () => {
  it('answers UnsupportedProtocolVersionError (-32022) naming the supported list and stays open for a good opening', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'kl-badver-'));
    const rpc = rawStdio(dir);
    try {
      rpc.send({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/list',
        params: { _meta: { ...META, 'io.modelcontextprotocol/protocolVersion': '1900-01-01' } },
      });
      const bad = (await rpc.response(1)) as { error: { code: number; data: { supported: string[]; requested: string } } };
      expect(bad.error.code).toBe(-32022);
      expect(bad.error.data).toEqual({ supported: [MODERN], requested: '1900-01-01' });
      rpc.send({ jsonrpc: '2.0', id: 2, method: 'server/discover', params: { _meta: META } });
      const d = (await rpc.response(2)) as { result: { supportedVersions: string[] } };
      expect(d.result.supportedVersions).toEqual([MODERN]);
    } finally {
      await rpc.close();
      rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
    }
  });
});

describe('Streamable HTTP (2026-07-28 only, bearer, loopback)', () => {
  let store: KronicleLite;
  let dir: string;
  let http: HttpServeHandle;
  let bearer: string;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'kl-http-'));
    store = new KronicleLite({ memory: true });
    const b = loadOrCreateBearer(dir);
    bearer = b.token;
    http = await serveHttp({ factory: createServerFactory(store, { defaultActorId: 'http-agent' }), bearer, port: 0 });
  });

  afterAll(async () => {
    await http.close();
    store.close();
    rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });

  it('bearer file is created once with mode 0600 and reused', () => {
    const file = join(dir, 'http-bearer.token');
    // POSIX only: Windows does not enforce file modes (chmod 0600 is a no-op there).
    if (process.platform !== 'win32') expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(bearer.length).toBeGreaterThanOrEqual(32);
    const again = loadOrCreateBearer(dir);
    expect(again).toEqual({ token: bearer, created: false, file });
  });

  it('(c) a v2 client pinned to 2026-07-28 completes a round trip with the bearer', async () => {
    const client = new Client({ name: 'http-test', version: '0.0.0' }, { versionNegotiation: { mode: { pin: MODERN } } });
    await client.connect(
      new StreamableHTTPClientTransport(new URL(http.url), { requestInit: { headers: { Authorization: `Bearer ${bearer}` } } }),
    );
    expect(client.getProtocolEra()).toBe('modern');
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(TOOL_NAMES);
    const put = parse<{ head: { seq: number } }>(
      await client.callTool({ name: 'put_document', arguments: { slug: 'h', title: 'H', markdown: 'over http' } }),
    );
    expect(put.head.seq).toBe(2);
    const s = parse<{ actor_id: string; head: { seq: number } }>(
      await client.callTool({ name: 'get_system_state', arguments: { response_format: 'json' } }),
    );
    expect(s).toMatchObject({ actor_id: 'http-agent', head: { seq: 2 } });
    await client.close();
  });

  it('rejects: missing/wrong bearer → 401, bad Origin → 403, GET → 405, wrong path → 404', async () => {
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'server/discover', params: { _meta: META } });
    const headers = {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      'MCP-Protocol-Version': MODERN,
      'Mcp-Method': 'server/discover',
    };
    const noAuth = await fetch(http.url, { method: 'POST', headers, body });
    expect(noAuth.status).toBe(401);
    expect(noAuth.headers.get('www-authenticate')).toMatch(/Bearer/);
    const wrongAuth = await fetch(http.url, { method: 'POST', headers: { ...headers, Authorization: 'Bearer nope-nope-nope-nope' }, body });
    expect(wrongAuth.status).toBe(401);
    const badOrigin = await fetch(http.url, {
      method: 'POST',
      headers: { ...headers, Authorization: `Bearer ${bearer}`, Origin: 'https://evil.example' },
      body,
    });
    expect(badOrigin.status).toBe(403);
    const get = await fetch(http.url, { headers: { Authorization: `Bearer ${bearer}` } });
    expect(get.status).toBe(405);
    const notFound = await fetch(http.url.replace('/mcp', '/nope'), { method: 'POST', headers: { ...headers, Authorization: `Bearer ${bearer}` }, body });
    expect(notFound.status).toBe(404);
  });

  it('0.5.0: a 2025-era client (Cursor-style initialize) is served statelessly over HTTP, behind the same bearer', async () => {
    const client = new Client({ name: 'cursor-like', version: '0.0.0' }, { supportedProtocolVersions: ['2025-06-18'] });
    await client.connect(
      new StreamableHTTPClientTransport(new URL(http.url), { requestInit: { headers: { Authorization: `Bearer ${bearer}` } } }),
    );
    expect(client.getProtocolEra()).toBe('legacy');
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(TOOL_NAMES);
    const s = parse<{ actor_id: string }>(await client.callTool({ name: 'get_system_state', arguments: { response_format: 'json', focus: 'pulse' } }));
    expect(s.actor_id).toBe('http-agent');
    await client.close();
    // Raw: the initialize answer carries the 2025 revision and no session id; no bearer is still 401.
    const init = {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'old', version: '1' } },
    };
    const headers = { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' };
    const res = await fetch(http.url, { method: 'POST', headers: { ...headers, Authorization: `Bearer ${bearer}` }, body: JSON.stringify(init) });
    expect(res.status).toBe(200);
    expect(res.headers.get('mcp-session-id')).toBeNull();
    const text = await res.text();
    expect(text).toMatch(/"protocolVersion":"2025-06-18"/);
    expect((await fetch(http.url, { method: 'POST', headers, body: JSON.stringify(init) })).status).toBe(401);
  });

  it('--modern-only: a 2025-era initialize POST (no _meta, no version header) is refused with -32022 naming 2026-07-28', async () => {
    const strict = await serveHttp({ factory: createServerFactory(store), bearer, port: 0, modernOnly: true });
    const res = await fetch(strict.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        Authorization: `Bearer ${bearer}`,
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'old', version: '1' } },
      }),
    });
    expect(res.status).toBe(400);
    const json = (await res.json()) as { error: { code: number; data?: { supported?: string[] } } };
    expect(json.error.code).toBe(-32022);
    expect(json.error.data?.supported).toEqual([MODERN]);
    expect(res.headers.get('mcp-session-id')).toBeNull();
    await strict.close();
  });

  it('an unsupported protocol version on any request is refused with 400 / -32022', async () => {
    const res = await fetch(http.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        'MCP-Protocol-Version': '1900-01-01',
        'Mcp-Method': 'tools/list',
        Authorization: `Bearer ${bearer}`,
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 9,
        method: 'tools/list',
        params: { _meta: { ...META, 'io.modelcontextprotocol/protocolVersion': '1900-01-01' } },
      }),
    });
    expect(res.status).toBe(400);
    const json = (await res.json()) as { error: { code: number; data: { supported: string[] } } };
    expect(json.error.code).toBe(-32022);
    expect(json.error.data.supported).toEqual([MODERN]);
  });

  it('modern raw POST gets a plain JSON result with 2026 fields and no session id', async () => {
    const res = await fetch(http.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        'MCP-Protocol-Version': MODERN,
        'Mcp-Method': 'tools/list',
        Authorization: `Bearer ${bearer}`,
        Origin: 'http://localhost',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'tools/list', params: { _meta: META } }),
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('mcp-session-id')).toBeNull();
    const json = (await res.json()) as { id: number; result: Record<string, unknown> };
    expect(json.id).toBe(7);
    expect(json.result).toMatchObject({ resultType: 'complete', ttlMs: CACHE_HINTS['tools/list'].ttlMs, cacheScope: 'public' });
  });
});
