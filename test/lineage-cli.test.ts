/**
 * Unreleased: lineage + pending, through the surfaces agents and hooks use.
 *
 *   CLI   put --derived-from / --cursor, supersede, get, pending --actor --json,
 *         orient --focus pulse|retractions --json [--pending-actor A]
 *   MCP   put_document / supersede_block derived_from (full profile only),
 *         recall stale_derived, get_system_state pending, document reads
 *
 * The hook contract (docs/PUSH.md) is additive: every pre-existing field is
 * still there with its old meaning.
 */

import { Client, InMemoryTransport } from '@modelcontextprotocol/client';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { createServerFactory } from '../src/server.js';
import { KronicleLite } from '../src/store.js';
import { cleanEnv, gitInit, runCli, tempDir, write } from './helpers/fs.js';

const MODERN = '2026-07-28';

interface Pending {
  kind: string;
  change: string;
  severity: string;
  seq: number | null;
  doc_slug: string | null;
  read: { block_id: string; content_hash: string; head_seq: number | null };
  current: { block_id: string; content_hash: string } | null;
  derived_notes?: string[];
  resolve: string;
}

describe('CLI contract', () => {
  it('put --derived-from, supersede, get and pending --actor --json; orient pulse/retractions carry pending', async () => {
    const root = tempDir('kl-lin-cli-');
    const data = tempDir('kl-lin-cli-data-');
    gitInit(root);
    const env = cleanEnv();
    const cli = async (args: string[], stdin?: string) => {
      const r = await runCli([...args, '--data-dir', data], { env, cwd: root, ...(stdin !== undefined ? { stdin } : {}) });
      expect(r.status, `${args.join(' ')}: ${r.stderr}`).toBe(0);
      return r.stdout;
    };
    const json = async <T>(args: string[], stdin?: string) => JSON.parse(await cli([...args, '--json'], stdin)) as T;

    write(join(root, 'deploy.md'), '# Deploy\n\nDeploys go to the cluster `blue-7` first.\n');
    const src = await json<{ blocks: { block_id: string; kind: string; content_hash: string }[] }>(['put', 'deploy', 'deploy.md', '--cwd', root]);
    const target = src.blocks.find((b) => b.kind === 'paragraph')!;

    // Nothing read yet: pending is empty, and the JSON already has the shape a gate keys on.
    const p0 = await json<{ format: string; actor_id: string; head: { seq: number }; pending_count: number; pending_hidden: number; pending: Pending[] }>(['pending', '--actor', 'agent', '--cwd', root]);
    expect(p0).toMatchObject({ format: 'kronicle-lite/1', actor_id: 'agent', pending_count: 0, pending_hidden: 0, pending: [] });

    // The agent reads the runbook (get records the read), then writes a note declaring its lineage.
    expect(await cli(['get', 'deploy', '--actor', 'agent'])).toContain('blue-7');
    write(join(root, 'note.md'), '# Note\n\nTarget is blue-7.\n');
    const bad = await runCli(['put', 'note', 'note.md', '--derived-from', `${target.block_id}:${'0'.repeat(64)}`, '--actor', 'agent', '--data-dir', data, '--cwd', root], { env, cwd: root });
    expect(bad.status).toBe(1);
    expect(bad.stderr).toMatch(/content_hash/);
    const note = await json<{ lineage: { derived_from: number; derived_from_inferred: number } }>(['put', 'note', 'note.md', '--derived-from', `${target.block_id}:${target.content_hash}`, '--actor', 'agent', '--cwd', root]);
    expect(note.lineage.derived_from).toBe(1);

    // The hook seeds its cursor (pulse), then the runbook changes via `supersede` from stdin.
    const o0 = await json<{ cursor: string; pending: Pending[]; pending_count: number; pending_actor: string }>(['orient', '--actor', 'push-hook', '--cwd', root, '--focus', 'pulse', '--pending-actor', 'agent']);
    expect(o0).toMatchObject({ pending: [], pending_count: 0, pending_actor: 'agent' });
    const sup = await json<{ new_block_id: string; content_hash: string }>(['supersede', target.block_id, '-', '--reason', 'cutover', '--actor', 'human'], 'Deploys go to the cluster `green-2` first.\n');

    // Push path: existing fields unchanged, plus the derived retraction and pending.
    const o1 = await json<{
      cursor: string;
      head: { seq: number };
      recovery: { method: string };
      retractions: { seq: number; kind: string; doc_slug: string; diff: string | null; old_text: string | null }[];
      format_only_edits: unknown[];
      source_drift: unknown;
      integrity: { ok: boolean };
      pending: Pending[];
      pending_count: number;
      pending_actor: string;
    }>(['orient', '--actor', 'push-hook', '--cwd', root, '--cursor', o0.cursor, '--focus', 'retractions', '--pending-actor', 'agent']);
    expect(o1.recovery.method).toBe('presented');
    expect(o1.integrity.ok).toBe(true);
    expect(o1.source_drift).toBeNull();
    expect(o1.format_only_edits).toEqual([]);
    expect(o1.retractions.map((r) => r.kind).sort()).toEqual(['derived', 'supersession']);
    expect(o1.retractions.find((r) => r.kind === 'derived')).toMatchObject({ doc_slug: 'note', old_text: expect.stringContaining('blue-7'), diff: expect.stringContaining('green-2') });
    expect(o1.pending_actor).toBe('agent');
    expect(o1.pending_count).toBe(1);
    expect(o1.pending[0]).toMatchObject({
      kind: 'supersession',
      doc_slug: 'deploy',
      read: { block_id: target.block_id, content_hash: target.content_hash },
      current: { block_id: sup.new_block_id, content_hash: sup.content_hash },
      derived_notes: ['note'],
    });
    // Without --pending-actor, pending is the calling actor's (the hook read nothing).
    expect((await json<{ pending_count: number }>(['orient', '--actor', 'push-hook', '--cwd', root, '--focus', 'pulse'])).pending_count).toBe(0);

    // Delivery is not reconciliation; reading the OLD block is not either.
    expect((await json<{ pending_count: number }>(['pending', '--actor', 'agent', '--cwd', root])).pending_count).toBe(1);
    await cli(['get', '--block', target.block_id, '--actor', 'agent']);
    expect((await json<{ pending_count: number }>(['pending', '--actor', 'agent', '--cwd', root])).pending_count).toBe(1);
    const text = await cli(['pending', '--actor', 'agent', '--cwd', root]);
    expect(text).toMatch(/1 pending for agent/);
    expect(text).toContain('green-2');
    // Reading the current version clears it.
    expect(await cli(['get', '--block', sup.new_block_id, '--actor', 'agent'])).toContain('green-2');
    expect((await json<{ pending_count: number }>(['pending', '--actor', 'agent', '--cwd', root])).pending_count).toBe(0);

    // The note itself stays stale (the copy is still wrong) until re-derived.
    write(join(root, 'note.md'), '# Note\n\nTarget is green-2.\n');
    await cli(['put', 'note', 'note.md', '--derived-from', `${sup.new_block_id}:${sup.content_hash}`, '--actor', 'agent', '--cwd', root]);
    const verify = await runCli(['verify-chain', '--data-dir', data], { env, cwd: root });
    expect(verify.status).toBe(0);
  });

  it('pending is project-scoped by --cwd: another project\'s items are counted, not listed', async () => {
    const a = tempDir('kl-lin-a-');
    const b = tempDir('kl-lin-b-');
    const data = tempDir('kl-lin-data-');
    gitInit(a);
    gitInit(b);
    const env = cleanEnv();
    const run = async (cwd: string, args: string[], stdin?: string) => {
      const r = await runCli([...args, '--data-dir', data, '--cwd', cwd], { env, cwd, ...(stdin !== undefined ? { stdin } : {}) });
      expect(r.status, r.stderr).toBe(0);
      return r.stdout;
    };
    write(join(b, 'd.md'), '# D\n\nUse uv for B.\n');
    const put = JSON.parse(await run(b, ['put', 'b-doc', 'd.md', '--json'])) as { blocks: { block_id: string; kind: string }[] };
    await run(b, ['get', 'b-doc', '--actor', 'agent']);
    await run(b, ['supersede', put.blocks.find((x) => x.kind === 'paragraph')!.block_id, '-', '--reason', 'r', '--actor', 'human'], 'Use uv, never pip, for B.\n');
    const inA = JSON.parse(await run(a, ['pending', '--actor', 'agent', '--json'])) as { pending_count: number; pending_hidden: number; pending: Pending[] };
    expect(inA).toMatchObject({ pending_count: 0, pending_hidden: 1, pending: [] });
    expect(JSON.stringify(inA)).not.toContain('uv');
    const inB = JSON.parse(await run(b, ['pending', '--actor', 'agent', '--json'])) as { pending_count: number };
    expect(inB.pending_count).toBe(1);
  });
});

describe('MCP', () => {
  async function connect(store: KronicleLite, profile?: 'core') {
    const [clientT, serverT] = InMemoryTransport.createLinkedPair();
    const handle = serveStdio(createServerFactory(store, { defaultActorId: 'agent-a', ...(profile ? { profile } : {}) }), { transport: serverT });
    const client = new Client({ name: 't', version: '0' }, { versionNegotiation: { mode: { pin: MODERN } } });
    await client.connect(clientT);
    return { client, close: async () => { await client.close(); await handle.close(); } };
  }
  const sc = (r: unknown) => (r as { structuredContent: Record<string, unknown> }).structuredContent;

  it('the S1 loop: orient → recall → put (cursor) infers lineage; after the change the next-session lookup marks the copy stale', async () => {
    const store = new KronicleLite({ memory: true });
    store.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: '# Deploy\n\nDeploys of api go to the cluster `blue-7` first.\n', actor_id: 'human' });
    const { client, close } = await connect(store);
    const o = sc(await client.callTool({ name: 'get_system_state', arguments: { response_format: 'json' } }));
    await client.callTool({ name: 'recall', arguments: { query: 'deploys cluster' } });
    const put = sc(await client.callTool({ name: 'put_document', arguments: { slug: 'notes-deploy-target', title: 't', markdown: '# t\n\nDeploy target for api is blue-7.\n', cursor: o['cursor'] } }));
    expect(put['lineage']).toEqual({ derived_from: 0, derived_from_inferred: 1 });
    const live = store.docs.liveBlocks(store.docs.getDocument('deploy')!.doc_id).find((b) => b.kind === 'paragraph')!;
    store.docs.supersedeBlock({ block_id: live.block_id, new_content: 'Deploys of api go to the cluster `green-2` first.', reason: 'cutover', actor_id: 'human' });
    await close();

    // Next session.
    const s2 = await connect(store);
    const gss = sc(await s2.client.callTool({ name: 'get_system_state', arguments: { since_cursor: o['cursor'], response_format: 'json' } }));
    expect((gss['retractions'] as { kind: string }[]).map((r) => r.kind).sort()).toEqual(['derived', 'supersession']);
    expect(gss['pending_count']).toBe(1);
    const r = await s2.client.callTool({ name: 'recall', arguments: { query: 'deploy target' } });
    const hit = (sc(r)['hits'] as { doc_slug: string; authority: string; authority_reason: string; stale_derived?: unknown[] }[]).find((h) => h.doc_slug === 'notes-deploy-target')!;
    expect(hit).toMatchObject({ authority: 'never_act', authority_reason: 'stale_derived' });
    expect(hit.stale_derived).toHaveLength(1);
    // Reading the current runbook through the document resource reconciles the change for this actor.
    await s2.client.readResource({ uri: 'kronicle://docs/deploy' });
    expect(sc(await s2.client.callTool({ name: 'get_system_state', arguments: { focus: 'pulse', response_format: 'json' } }))['pending_count']).toBe(0);
    await s2.close();
    store.close();
  });

  it('derived_from is in the full profile\'s put_document / supersede_block schema, not in --core; core still infers', async () => {
    const store = new KronicleLite({ memory: true });
    const full = await connect(store);
    const props = (name: string, tools: { name: string; inputSchema: unknown }[]) => Object.keys((tools.find((t) => t.name === name)!.inputSchema as { properties: object }).properties);
    const ft = (await full.client.listTools()).tools;
    expect(props('put_document', ft)).toContain('derived_from');
    expect(props('supersede_block', ft)).toContain('derived_from');
    await full.close();
    const core = await connect(store, 'core');
    const ct = (await core.client.listTools()).tools;
    expect(props('put_document', ct)).not.toContain('derived_from');
    expect(props('supersede_block', ct)).not.toContain('derived_from');
    store.docs.putDocument({ slug: 'src', title: 's', markdown: '# s\n\nThe quota is 40 rps.\n', actor_id: 'human' });
    await core.client.callTool({ name: 'recall', arguments: { query: 'quota rps' } });
    const put = sc(await core.client.callTool({ name: 'put_document', arguments: { slug: 'n', title: 'n', markdown: '# n\n\nquota 40.\n' } }));
    expect(put['lineage']).toEqual({ derived_from: 0, derived_from_inferred: 1 });
    // An explicit derived_from with a wrong hash is refused through MCP (full profile).
    const f2 = await connect(store);
    const blk = store.docs.liveBlocks(store.docs.getDocument('src')!.doc_id).find((b) => b.kind === 'paragraph')!;
    const bad = (await f2.client.callTool({ name: 'put_document', arguments: { slug: 'm', title: 'm', markdown: '# m\n\nx.\n', derived_from: [{ block_id: blk.block_id, content_hash: 'a'.repeat(64) }] } })) as { isError?: boolean; content: { text: string }[] };
    expect(bad.isError).toBe(true);
    expect(bad.content[0]!.text).toMatch(/invalid_lineage/);
    await f2.close();
    await core.close();
    store.close();
  });
});
