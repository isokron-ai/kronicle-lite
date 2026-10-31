/**
 * End-to-end over the MCP protocol: an SDK Client talks to createServer()
 * through an in-process linked transport, and separately to the built CLI
 * over real stdio.
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import type { Receipt } from '../src/recall/receipt.js';
import { createServer } from '../src/server.js';
import { KronicleLite } from '../src/store.js';

interface ToolResult {
  content: { type: string; text?: string }[];
  isError?: boolean;
}

function parse<T = unknown>(r: unknown): T {
  const res = r as ToolResult;
  const t = res.content[0];
  if (!t || t.type !== 'text' || !t.text) throw new Error('no text content');
  return JSON.parse(t.text) as T;
}

function textOf(r: unknown): string {
  return (r as ToolResult).content[0]?.text ?? '';
}

describe('MCP server (in-process transport)', () => {
  let store: KronicleLite;
  let client: Client;

  beforeAll(async () => {
    store = new KronicleLite({ memory: true });
    const server = createServer(store, { defaultActorId: 'test-agent' });
    const [clientT, serverT] = InMemoryTransport.createLinkedPair();
    await server.connect(serverT);
    client = new Client({ name: 'test-client', version: '0.0.0' });
    await client.connect(clientT);
  });

  afterAll(async () => {
    await client.close();
    store.close();
  });

  it('lists the expected tools with instructive descriptions', async () => {
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name).sort();
    expect(names).toEqual(
      [
        'checkpoint_chain',
        'get_system_state',
        'put_document',
        'recall',
        'supersede_block',
        'tombstone_block',
        'verify',
        'verify_chain',
      ].sort(),
    );
    const gss = tools.find((t) => t.name === 'get_system_state')!;
    expect(gss.description).toMatch(/since_cursor/);
    expect(gss.description).toMatch(/drift banner/);
    expect(gss.inputSchema).toMatchObject({ type: 'object' });
    expect((gss.inputSchema as { properties: Record<string, unknown> }).properties).toHaveProperty('budget_tokens');
  });

  it('runs the full loop: orient → put → recall → verify → supersede → verify → orient', async () => {
    // Cold orient, markdown by default.
    const o1 = await client.callTool({ name: 'get_system_state', arguments: {} });
    const md = textOf(o1);
    expect(md).toMatch(/^# kronicle-lite orient — head seq 0/);
    expect(md).toMatch(/cursor_compact:\*\* `sxt1c\.0\./);
    const cursorCompact = /cursor_compact:\*\* `([^`]+)`/.exec(md)![1]!;

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

    // Recall with receipt.
    const rc = parse<{ hits: { block_id: string; receipt: Receipt; content: string }[] }>(
      await client.callTool({ name: 'recall', arguments: { query: 'restart worker' } }),
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

    // Tombstone with a different actor who never oriented → advisory true.
    const tomb = parse<{ stale_write_advisory: { advisory: boolean; line: string } }>(
      await client.callTool({
        name: 'tombstone_block',
        arguments: { block_id: put.blocks[2]!.block_id, reason: 'policy retired', actor_id: 'stranger' },
      }),
    );
    expect(tomb.stale_write_advisory.advisory).toBe(true);
    expect(tomb.stale_write_advisory.line).toMatch(/never oriented/);

    // Errors are structured tool errors.
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

  it('pulse is cheap and surfaces drift after many events', async () => {
    for (let i = 0; i < 110; i++) store.chain.append({ event_type: 'note.added', payload: { i }, actor_id: 'x' });
    const p = parse<{ drift_banner: { surfaced: boolean }; delta: null }>(
      await client.callTool({ name: 'get_system_state', arguments: { focus: 'pulse', response_format: 'json' } }),
    );
    expect(p.drift_banner.surfaced).toBe(true);
    expect(p.delta).toBeNull();
  });
});

const CLI = join(process.cwd(), 'dist', 'cli.js');

describe.skipIf(!existsSync(CLI))('MCP server over stdio (built CLI)', () => {
  let dir: string;
  let client: Client;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'kl-stdio-'));
    client = new Client({ name: 'stdio-test', version: '0.0.0' });
    await client.connect(
      new StdioClientTransport({ command: process.execPath, args: [CLI, 'serve', '--data-dir', dir, '--actor', 'stdio-agent'] }),
    );
  });

  afterAll(async () => {
    await client.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('answers tools/list and tools/call', async () => {
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
