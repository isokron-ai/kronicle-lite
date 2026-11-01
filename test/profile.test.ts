/**
 * 0.6.0 over MCP: the `--core` tool profile (≤ 6 tools for small contexts),
 * honest labels on recall, the secret guard on put_document, and the pinned
 * core catalog.
 */

import { Client, InMemoryTransport } from '@modelcontextprotocol/client';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import { CORE_CATALOG_FINGERPRINT, liveCatalogFingerprint } from '../src/catalog.js';
import { CORE_TOOLS, createServerFactory, type ServerOptions } from '../src/server.js';
import { KronicleLite } from '../src/store.js';

const MODERN = '2026-07-28';

interface ToolResult {
  content: { type: string; text?: string }[];
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
}

async function connect(opts: ServerOptions = {}) {
  const store = new KronicleLite({ memory: true });
  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  const handle = serveStdio(createServerFactory(store, { defaultActorId: 'agent', ...opts }), { transport: serverT });
  const client = new Client({ name: 't', version: '0' }, { versionNegotiation: { mode: { pin: MODERN } } });
  await client.connect(clientT);
  return {
    store,
    client,
    close: async () => {
      await client.close();
      await handle.close();
      store.close();
    },
  };
}

describe('--core profile', () => {
  it('serves at most 6 tools: the orient → recall → verify → write loop', async () => {
    const { client, close } = await connect({ profile: 'core' });
    const { tools } = await client.listTools();
    expect(tools.length).toBeLessThanOrEqual(6);
    expect(tools.map((t) => t.name).sort()).toEqual([...CORE_TOOLS].sort());
    expect(CORE_TOOLS).toEqual(expect.arrayContaining(['get_system_state', 'recall', 'verify', 'put_document']));
    const bytes = JSON.stringify({ tools }).length;
    const full = await connect();
    const fullBytes = JSON.stringify({ tools: (await full.client.listTools()).tools }).length;
    expect(bytes).toBeLessThan(fullBytes * 0.75);
    await full.close();
    await close();
  });

  it('the core catalog is pinned: constant = .mcp-catalog snapshot = live', async () => {
    const snap = JSON.parse(readFileSync(join(__dirname, '..', '.mcp-catalog', 'kronicle-lite-core.json'), 'utf8')) as { sha256: string };
    const live = await liveCatalogFingerprint({ profile: 'core' });
    expect(live.tools).toBe(CORE_TOOLS.length);
    expect(live.fingerprint).toBe(CORE_CATALOG_FINGERPRINT);
    expect(snap.sha256).toBe(CORE_CATALOG_FINGERPRINT);
  });
});

describe('recall over MCP carries honest labels', () => {
  it('authority per hit, floor, absence, attention by actor+cursor, truncation pointer', async () => {
    const { client, close } = await connect();
    await client.callTool({ name: 'put_document', arguments: { slug: 'ops', title: 'Ops', markdown: '# Ops\n\nDeploy the API on weekdays.\n\nDeploy the worker after the API.\n' } });
    const o = (await client.callTool({ name: 'get_system_state', arguments: { response_format: 'json' } })) as ToolResult;
    const cursor = (o.structuredContent as { cursor: string }).cursor;
    const r1 = (await client.callTool({ name: 'recall', arguments: { query: 'deploy', cursor } })) as ToolResult;
    expect(r1.isError).toBeFalsy();
    const s1 = r1.structuredContent as { hits: { authority: string; authority_reason: string; already_read: boolean }[]; authority_floor: string; absence: { verdict: string }; attention: { actor_id: string } };
    expect(s1.hits[0]).toMatchObject({ authority: 'inspect_only', authority_reason: 'no_source', already_read: false });
    expect(s1.authority_floor).toBe('inspect_only');
    expect(s1.absence.verdict).toBe('found');
    expect(s1.attention.actor_id).toBe('agent');
    const r2 = (await client.callTool({ name: 'recall', arguments: { query: 'deploy', cursor } })) as ToolResult;
    expect((r2.structuredContent as typeof s1).hits.every((h) => h.already_read)).toBe(true);
    const miss = (await client.callTool({ name: 'recall', arguments: { query: 'kubernetes' } })) as ToolResult;
    expect((miss.structuredContent as typeof s1).absence).toMatchObject({ verdict: 'absent_in_searched', searched: ['live_blocks'], index_fresh: true });
    const cut = (await client.callTool({ name: 'recall', arguments: { query: 'deploy', max_chars: 200 } })) as ToolResult;
    const sc = cut.structuredContent as { truncated: { hint: string } | null; hits: { content: string }[] };
    expect(sc.hits.reduce((n, h) => n + h.content.length, 0)).toBeLessThanOrEqual(200);
    await close();
  });

  it('put_document refuses a secret with error secret_detected; redact_secrets:true stores a redacted copy', async () => {
    const { client, store, close } = await connect();
    const secret = ['ghp', '_', 'R8bX2kLq9Wm4Tz7Yc1Vn5Hd3Jf6Gs0Pa8Ue2'].join('');
    const md = `# Ci\n\nThe CI token is ${secret}.\n`;
    const r1 = (await client.callTool({ name: 'put_document', arguments: { slug: 'ci', title: 'CI', markdown: md } })) as ToolResult;
    expect(r1.isError).toBe(true);
    const err = JSON.parse(r1.content[0]!.text!) as { error: string; message: string; findings: unknown[] };
    expect(err.error).toBe('secret_detected');
    expect(err.findings).toEqual([{ field: 'markdown', detector: 'github_token', line: 3 }]);
    expect(r1.content[0]!.text).not.toContain(secret);
    expect(store.chain.head().seq).toBe(0);
    const r2 = (await client.callTool({ name: 'put_document', arguments: { slug: 'ci', title: 'CI', markdown: md, redact_secrets: true } })) as ToolResult;
    expect(r2.isError).toBeFalsy();
    expect((r2.structuredContent as { redactions: unknown[] }).redactions).toHaveLength(1);
    expect(store.recall.recall({ query: 'CI token' }).hits[0]!.content).toContain('[REDACTED:github_token]');
    await close();
  });
});
