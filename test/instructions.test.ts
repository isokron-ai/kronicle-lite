/**
 * Chained instructions (0.4.0): slug rules, the Claude Code auto-memory path
 * rule, one-shot import, retractions of kind `instruction`, the watcher
 * (fs.watch and polling) and the CLI / Claude Code hook surface.
 */

import { Client, InMemoryTransport } from '@modelcontextprotocol/client';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { renameSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { PassThrough, Readable } from 'node:stream';
import { afterEach, describe, expect, it } from 'vitest';

import { isValidSlug } from '../src/docs/documents.js';
import { claudeProjectDirName, entryFor, instructionSlugFor, projectKey, resolveContext } from '../src/instructions/paths.js';
import { syncInstructionFile } from '../src/instructions/sync.js';
import { InstructionWatcher, resolveWatchSet, syncInstructionSet, type WatchEvent } from '../src/instructions/watch.js';
import { createServerFactory, renderSystemStateMarkdown } from '../src/server.js';
import { KronicleLite } from '../src/store.js';
import { cleanEnv, gitInit, gitRun, runCli, tempDir, waitFor, write } from './helpers/fs.js';

const NOENV = {} as NodeJS.ProcessEnv;

/** A project with every default instruction kind and a fake home holding its auto memory. */
function project(opts: { git?: boolean } = {}) {
  const root = tempDir('kl-proj-');
  const home = tempDir('kl-home-');
  if (opts.git !== false) gitInit(root);
  write(join(root, 'CLAUDE.md'), '# Project\n\nUse pnpm, not npm.\n\nRun tests with `pnpm test`.\n');
  write(join(root, 'AGENTS.md'), '# Agents\n\nNever push to main.\n');
  write(join(root, '.claude', 'rules', 'testing.md'), '# Testing\n\nVitest only.\n');
  write(join(root, '.claude', 'rules', 'frontend', 'react.md'), '# React\n\nFunction components.\n');
  write(join(root, '.claude', 'rules', 'notes.txt'), 'not a rule');
  write(join(root, '.cursor', 'rules', 'style.mdc'), '---\nalwaysApply: true\n---\n\nTwo-space indent.\n');
  const rc = resolveContext({ cwd: root, home, env: NOENV });
  write(join(rc.memoryDir, 'MEMORY.md'), '- [Testing](feedback_testing.md) — run the integration suite\n');
  /** 0.4.0 slug → its 0.5.0 project-keyed form for this project. */
  const ns = (slug: string) => slug.replace(/^instructions\//, `instructions/${rc.projectKey}/`).replace(/^memory\//, `memory/${rc.memoryKey}/`);
  return { root, home, rc, ns, ctx: { cwd: root, home, env: NOENV } };
}

describe('instruction slugs (deterministic, OS-independent)', () => {
  it('maps the default set and arbitrary paths to valid ≤128-char slugs', () => {
    const cases: [string, boolean, string][] = [
      ['CLAUDE.md', false, 'instructions/claude-md'],
      ['AGENTS.md', false, 'instructions/agents-md'],
      ['CLAUDE.local.md', false, 'instructions/claude-local-md'],
      ['.claude/CLAUDE.md', false, 'instructions/claude/claude-md'],
      ['.claude/rules/testing.md', false, 'instructions/claude-rules/testing'],
      ['.claude/rules/frontend/React.md', false, 'instructions/claude-rules/frontend/React'],
      ['.claude\\rules\\win\\x.md', false, 'instructions/claude-rules/win/x'],
      ['.cursor/rules/style.mdc', false, 'instructions/cursor-rules/style.mdc'],
      ['.cursor/rules/sub/a.md', false, 'instructions/cursor-rules/sub/a'],
      ['docs/My Notes (v2).md', false, 'instructions/docs/My-Notes-v2'],
      ['services/api/CLAUDE.md', false, 'instructions/services/api/claude-md'],
      ['MEMORY.md', true, 'memory/MEMORY'],
      ['feedback_testing.md', true, 'memory/feedback_testing'],
    ];
    for (const [rel, mem, slug] of cases) {
      expect(instructionSlugFor(rel, mem), rel).toBe(slug);
      expect(isValidSlug(slug), slug).toBe(true);
    }
    const long = instructionSlugFor(`${'deeply-nested-directory/'.repeat(12)}file.md`, false);
    expect(long.length).toBeLessThanOrEqual(128);
    expect(isValidSlug(long)).toBe(true);
    expect(instructionSlugFor(`${'deeply-nested-directory/'.repeat(12)}file.md`, false)).toBe(long);
    expect(isValidSlug('instructions/claude-md')).toBe(true);
    expect(isValidSlug('Instructions/x')).toBe(false);
    expect(isValidSlug('instructions/../x')).toBe(false);
    expect(isValidSlug('plain-slug')).toBe(true);
  });

  it('Claude Code project dir name: every non-alphanumeric character becomes "-"', () => {
    expect(claudeProjectDirName('/home/me/my.repo')).toBe('-home-me-my-repo');
    expect(claudeProjectDirName('/Users/jo/Code/kronicle_lite')).toBe('-Users-jo-Code-kronicle-lite');
    expect(claudeProjectDirName('C:\\Users\\me\\proj')).toBe('C--Users-me-proj');
  });
});

describe('Claude Code auto-memory location', () => {
  it('derived from the git repository root: subdirectories and worktrees share one memory dir', () => {
    const { root, home } = project();
    gitRun(root, ['add', '-A']);
    gitRun(root, ['commit', '-q', '-m', 'init']);
    const expected = join(home, '.claude', 'projects', claudeProjectDirName(root), 'memory');
    expect(resolveContext({ cwd: root, home, env: NOENV })).toMatchObject({ memoryDir: expected, memoryRule: 'derived', projectRoot: root });
    write(join(root, 'src', 'deep', 'x.ts'), '');
    expect(resolveContext({ cwd: join(root, 'src', 'deep'), home, env: NOENV }).memoryDir).toBe(expected);
    const wt = join(tempDir('kl-wt-'), 'wt');
    gitRun(root, ['worktree', 'add', '-q', '-b', 'side', wt]);
    const w = resolveContext({ cwd: wt, home, env: NOENV });
    expect(w.memoryDir).toBe(expected); // shared across worktrees
    expect(w.projectRoot).not.toBe(root); // but instruction files come from the worktree itself
  });

  it('outside git the project root (cwd) is used', () => {
    const { root, home } = project({ git: false });
    expect(resolveContext({ cwd: root, home, env: NOENV }).memoryDir).toBe(join(home, '.claude', 'projects', claudeProjectDirName(root), 'memory'));
  });

  it('CLAUDE_CODE_PROJECT_DIR_NAME applies only with CLAUDE_CONFIG_DIR; autoMemoryDirectory overrides both', () => {
    const { root, home } = project();
    const cfg = tempDir('kl-cfg-');
    expect(resolveContext({ cwd: root, home, env: { CLAUDE_CODE_PROJECT_DIR_NAME: 'work' } }).memoryRule).toBe('derived');
    expect(resolveContext({ cwd: root, home, env: { CLAUDE_CONFIG_DIR: cfg } }).memoryDir).toBe(join(cfg, 'projects', claudeProjectDirName(root), 'memory'));
    expect(resolveContext({ cwd: root, home, env: { CLAUDE_CONFIG_DIR: cfg, CLAUDE_CODE_PROJECT_DIR_NAME: 'work' } })).toMatchObject({
      memoryDir: join(cfg, 'projects', 'work', 'memory'),
      memoryRule: 'CLAUDE_CODE_PROJECT_DIR_NAME',
    });
    expect(resolveContext({ cwd: root, home, env: { CLAUDE_CONFIG_DIR: cfg, CLAUDE_CODE_PROJECT_DIR_NAME: 'bad name!' } }).memoryRule).toBe('derived');
    write(join(home, '.claude', 'settings.json'), JSON.stringify({ autoMemoryDirectory: '~/my-memory' }));
    expect(resolveContext({ cwd: root, home, env: NOENV })).toMatchObject({ memoryDir: join(home, 'my-memory'), memoryRule: 'autoMemoryDirectory' });
    write(join(root, '.claude', 'settings.local.json'), JSON.stringify({ autoMemoryDirectory: join(root, 'local-mem') }));
    expect(resolveContext({ cwd: root, home, env: NOENV }).memoryDir).toBe(join(root, 'local-mem'));
    write(join(root, '.claude', 'settings.local.json'), JSON.stringify({ autoMemoryDirectory: 'relative/is/ignored' }));
    expect(resolveContext({ cwd: root, home, env: NOENV }).memoryDir).toBe(join(home, 'my-memory'));
  });
});

describe('put --from-instructions (one shot)', () => {
  it('chains the default set; unchanged files append nothing; a change is a supersession retracted as kind=instruction', () => {
    const { root, rc, ctx, ns } = project();
    const set = resolveWatchSet(ctx);
    expect(set.entries.map((e) => e.slug).sort()).toEqual(
      [
        'instructions/agents-md',
        'instructions/claude-md',
        'instructions/claude-rules/frontend/react',
        'instructions/claude-rules/testing',
        'instructions/cursor-rules/style.mdc',
        'memory/MEMORY',
      ]
        .map(ns)
        .sort(),
    );
    expect(set.entries.map((e) => e.legacySlug).sort()).toContain('instructions/claude-md');
    const store = new KronicleLite({ memory: true });
    const first = syncInstructionSet(store, ctx);
    expect(first.every((r) => r.action === 'created')).toBe(true);
    const cold = store.orient.getSystemState({ actor_id: 'agent' });
    const mem = store.docs.getDocument(ns('memory/MEMORY'))!;
    expect(store.docs.getSource(mem.doc_id)!.source).toMatchObject({ kind: 'memory', path: expect.stringMatching(/^~\/\.claude\/projects\/.+\/memory\/MEMORY\.md$/) });
    expect(store.docs.getSource(store.docs.getDocument(ns('instructions/claude-md'))!.doc_id)!.source).toEqual({
      kind: 'instruction',
      path: 'CLAUDE.md',
      project: { key: rc.projectKey, root },
    });

    const head = store.chain.head().seq;
    expect(syncInstructionSet(store, ctx).every((r) => r.action === 'unchanged')).toBe(true);
    expect(store.chain.head().seq).toBe(head);

    write(join(root, 'CLAUDE.md'), '# Project\n\nUse bun, not npm.\n\nRun tests with `pnpm test`.\n');
    unlinkSync(join(root, 'AGENTS.md'));
    const second = syncInstructionSet(store, ctx);
    const claude = second.find((r) => r.slug === ns('instructions/claude-md'))!;
    expect(claude).toMatchObject({ action: 'updated', superseded: 1, created: 0, tombstoned: 0, revision: 2 });
    // AGENTS.md vanished from the set; sync it explicitly as the watcher does.
    const gone = syncInstructionFile(store, entryFor(join(root, 'AGENTS.md'), rc));
    expect(gone).toMatchObject({ action: 'removed', tombstoned: 2 });
    expect(syncInstructionFile(store, entryFor(join(root, 'AGENTS.md'), rc)).action).toBe('missing');

    const warm = store.orient.getSystemState({ actor_id: 'agent', since_cursor: cold.cursor });
    const kinds = warm.retractions!.map((r) => [r.kind, r.severity, r.doc_slug]);
    expect(kinds).toContainEqual(['instruction', 'behavioral', ns('instructions/claude-md')]);
    expect(kinds).toContainEqual(['instruction', 'safety', ns('instructions/agents-md')]);
    expect(warm.retractions!.every((r) => r.kind === 'instruction')).toBe(true);
    const md = renderSystemStateMarkdown(warm);
    // 0.5.0: the words, not block ids.
    expect(md).toMatch(/You previously relied on instruction "Use pnpm, not npm\." \(instructions\/[^ ]+\/claude-md › Project\); current truth is "Use bun, not npm\." \(seq \d+\); follow the new text/);
    expect(md).toContain('changed: Use [-pnpm,-]{+bun,+} not npm.');
    expect(md).toMatch(/instruction "Never push to main\." \(instructions\/[^ ]+\/agents-md › Agents\); current truth is REMOVED from instructions\/[^ ]+\/agents-md/);
    expect(md).toContain('removed: Never push to main.');
    store.close();
  });

  it('a put without source hashes exactly as 0.3.0 (no source key); export → import rebuilds doc_sources', async () => {
    const { ctx } = project();
    const store = new KronicleLite({ memory: true });
    const plain = store.docs.putDocument({ slug: 'plain', title: 'P', markdown: 'x', actor_id: 'a' });
    expect(Object.keys(store.chain.get(plain.chain_seq)!.payload)).not.toContain('source');
    syncInstructionSet(store, ctx);
    const sink = new PassThrough();
    let buf = '';
    sink.on('data', (c: Buffer) => (buf += c.toString('utf8')));
    store.exportEvents(sink);
    sink.end();
    await new Promise((r) => sink.on('end', r));
    const copy = new KronicleLite({ memory: true });
    await copy.importEvents(Readable.from([buf]));
    expect(copy.docs.listSources().map((s) => s.slug)).toEqual(store.docs.listSources().map((s) => s.slug));
    expect(copy.chain.verify().ok).toBe(true);
    copy.close();
    store.close();
  });

  it('MCP resources: namespaced slugs are listed percent-encoded and read back', async () => {
    const { ctx, ns } = project();
    const store = new KronicleLite({ memory: true });
    syncInstructionSet(store, ctx);
    const uri = `kronicle://docs/${encodeURIComponent(ns('instructions/claude-md'))}`;
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const handle = serveStdio(createServerFactory(store), { transport: st });
    const client = new Client({ name: 't', version: '0' }, { versionNegotiation: { mode: { pin: '2026-07-28' } } });
    await client.connect(ct);
    const { resources } = await client.listResources();
    expect(resources.map((r) => r.uri)).toContain(uri);
    const read = await client.readResource({ uri });
    expect((read.contents[0] as { text: string }).text).toMatch(/Use pnpm/);
    await client.close();
    await handle.close();
    store.close();
  });
});

describe('watch', () => {
  const open: { w: InstructionWatcher; s: KronicleLite }[] = [];
  afterEach(() => {
    for (const { w, s } of open.splice(0)) {
      w.close();
      s.close();
    }
  });

  function startWatcher(ctx: Record<string, unknown>, extra: { poll?: boolean; intervalMs?: number; paths?: string[] } = {}) {
    const events: WatchEvent[] = [];
    const s = new KronicleLite({ memory: true });
    const w = new InstructionWatcher(s, { ...ctx, debounceMs: 40, intervalMs: extra.intervalMs ?? 60_000, ...extra, onEvent: (e) => events.push(e) });
    open.push({ w, s });
    const initial = w.start();
    const synced = () => events.filter((e): e is Extract<WatchEvent, { type: 'synced' }> => e.type === 'synced' && e.trigger !== 'start');
    return { s, w, events, initial, synced };
  }

  it('fs.watch: an edit is re-put after the debounce; an editor-style atomic rename is seen too', async () => {
    const { root, ctx, ns } = project();
    const { s, initial, synced } = startWatcher(ctx);
    expect(initial).toHaveLength(6);
    write(join(root, 'CLAUDE.md'), '# Project\n\nUse yarn.\n\nRun tests with `pnpm test`.\n');
    await waitFor(() => synced().some((e) => e.result.slug === ns('instructions/claude-md') && e.result.action === 'updated'), 8_000, 'fs.watch sync');
    expect(s.docs.getDocument(ns('instructions/claude-md'))!.current_revision).toBe(2);
    const tmp = join(root, '.claude', 'rules', 'testing.md.tmp');
    writeFileSync(tmp, '# Testing\n\nVitest and Playwright.\n');
    renameSync(tmp, join(root, '.claude', 'rules', 'testing.md'));
    await waitFor(() => synced().some((e) => e.result.slug === ns('instructions/claude-rules/testing')), 8_000, 'rename sync');
    expect(s.docs.getDocument(ns('instructions/claude-rules/testing'))!.current_revision).toBe(2);
  });

  it('polling fallback: changes, new rule files in new directories, and deletions are picked up without fs.watch', async () => {
    const { root, ctx, ns } = project();
    const { s, w, synced } = startWatcher(ctx, { poll: true, intervalMs: 100 });
    expect(w.mode).toBe('poll');
    write(join(root, 'AGENTS.md'), '# Agents\n\nNever push to main. Open a PR.\n');
    write(join(root, '.claude', 'rules', 'backend', 'db.md'), '# DB\n\nMigrations are reviewed.\n');
    await waitFor(
      () => synced().some((e) => e.result.slug === ns('instructions/agents-md')) && synced().some((e) => e.result.slug === ns('instructions/claude-rules/backend/db')),
      8_000,
      'poll sync',
    );
    rmSync(join(root, '.cursor'), { recursive: true });
    await waitFor(() => synced().some((e) => e.result.slug === ns('instructions/cursor-rules/style.mdc') && e.result.action === 'removed'), 8_000, 'poll removal');
    expect(s.docs.liveBlocks(s.docs.getDocument(ns('instructions/cursor-rules/style.mdc'))!.doc_id)).toHaveLength(0);
  });

  it('explicit paths: a file and a directory (recursive *.md / *.mdc)', async () => {
    const { root, ctx, ns } = project();
    write(join(root, 'docs', 'guide.md'), '# Guide\n\nRead me.\n');
    write(join(root, 'docs', 'deep', 'more.mdc'), 'More.\n');
    write(join(root, 'docs', 'image.png'), 'png');
    const { initial } = startWatcher(ctx, { paths: [join(root, 'CLAUDE.md'), join(root, 'docs')] });
    expect(initial.map((r) => r.slug).sort()).toEqual(['instructions/claude-md', 'instructions/docs/deep/more.mdc', 'instructions/docs/guide'].map(ns));
  });
});

describe('CLI and the Claude Code hook surface', () => {
  it('watch --list --json, put --from-instructions, and --stdin-hook for SessionStart / FileChanged', async () => {
    const { root, home, rc, ns } = project();
    const dataDir = join(tempDir('kl-data-'), 'd');
    const env = cleanEnv({ HOME: home, USERPROFILE: home });
    const list = await runCli(['watch', '--list', '--json', '--cwd', root], { env });
    expect(list.status, list.stderr).toBe(0);
    const l = JSON.parse(list.stdout) as { memory_dir: string; files: { slug: string }[] };
    expect(l.memory_dir).toBe(rc.memoryDir);
    expect(l.files.map((f) => f.slug)).toContain(ns('memory/MEMORY'));

    const put = await runCli(['put', '--from-instructions', '--cwd', root, '--data-dir', dataDir, '--json'], { env });
    expect(put.status, put.stderr).toBe(0);
    expect((JSON.parse(put.stdout) as { results: { action: string }[] }).results.map((r) => r.action)).toEqual(Array(6).fill('created'));
    const one = await runCli(['put', '--from-instructions', 'CLAUDE.md', '--cwd', root, '--data-dir', dataDir], { env, cwd: root });
    expect(one.stdout.startsWith(`${ns('instructions/claude-md')} ← CLAUDE.md: unchanged (rev 1)`)).toBe(true);

    const ss = await runCli(['put', '--from-instructions', '--stdin-hook', '--data-dir', dataDir], {
      env,
      stdin: JSON.stringify({ hook_event_name: 'SessionStart', cwd: root, source: 'startup' }),
    });
    expect(ss.status).toBe(0);
    const out = JSON.parse(ss.stdout) as { hookSpecificOutput: { hookEventName: string; watchPaths: string[] }; systemMessage?: string };
    expect(out.hookSpecificOutput.hookEventName).toBe('SessionStart');
    expect(out.hookSpecificOutput.watchPaths).toEqual(expect.arrayContaining([join(root, 'CLAUDE.md'), join(rc.memoryDir, 'MEMORY.md')]));
    expect(out.systemMessage).toBeUndefined(); // nothing changed

    write(join(rc.memoryDir, 'MEMORY.md'), '- [Testing](feedback_testing.md) — run the integration suite before merging\n');
    const fc = await runCli(['put', '--from-instructions', '--stdin-hook', '--data-dir', dataDir], {
      env,
      stdin: JSON.stringify({ hook_event_name: 'FileChanged', cwd: root, file_path: join(rc.memoryDir, 'MEMORY.md'), event: 'change' }),
    });
    expect(fc.status).toBe(0);
    expect(JSON.parse(fc.stdout).systemMessage).toMatch(/memory\/[^/]+\/MEMORY ← ~\/.+: rev 2 \(1 superseded/);
    const quiet = await runCli(['put', '--from-instructions', '--stdin-hook', '--data-dir', dataDir], {
      env,
      stdin: JSON.stringify({ hook_event_name: 'FileChanged', cwd: root, file_path: join(rc.memoryDir, 'MEMORY.md'), event: 'change' }),
    });
    expect(quiet.stdout).toBe('');
    const bad = await runCli(['put', '--from-instructions', '--stdin-hook', '--data-dir', dataDir], { env, stdin: 'not json' });
    expect(bad.status).toBe(0); // a hook never fails the session

    const orient = await runCli(['orient', '--data-dir', dataDir, '--json', '--cwd', root], { env });
    const state = JSON.parse(orient.stdout) as { retractions: { kind: string }[]; scope: { hidden_retractions: number } };
    expect(state.retractions.some((r) => r.kind === 'instruction')).toBe(true);
    expect(state.scope.hidden_retractions).toBe(0);
    // From another project the same memory retraction is not this agent's business.
    const elsewhere = await runCli(['orient', '--actor', 'other', '--data-dir', dataDir, '--json', '--cwd', tempDir('kl-other-')], { env });
    const other = JSON.parse(elsewhere.stdout) as { retractions: { kind: string }[]; scope: { hidden_retractions: number } };
    expect(other.retractions.some((r) => r.kind === 'instruction')).toBe(false);
    expect(other.scope.hidden_retractions).toBeGreaterThan(0);
    const once = await runCli(['watch', '--once', '--cwd', root, '--data-dir', dataDir], { env });
    expect(once.status).toBe(0);
    expect(once.stderr).toMatch(/watching \d+ file\(s\)/);
  });
});

describe('0.5.0: instruction slugs are keyed by project (audit B3)', () => {
  it('project key: readable, stable, overridable; slugs insert it after the namespace', () => {
    const k = projectKey('/work/Acme API');
    expect(k).toMatch(/^acme-api-[0-9a-f]{8}$/);
    expect(projectKey('/work/Acme API')).toBe(k);
    expect(projectKey('/other/Acme API')).not.toBe(k);
    expect(instructionSlugFor('CLAUDE.md', false, k)).toBe(`instructions/${k}/claude-md`);
    expect(instructionSlugFor('.claude/rules/testing.md', false, k)).toBe(`instructions/${k}/claude-rules/testing`);
    expect(instructionSlugFor('MEMORY.md', true, k)).toBe(`memory/${k}/MEMORY`);
    expect(isValidSlug(instructionSlugFor(`${'deep/'.repeat(30)}x.md`, false, k))).toBe(true);
    const { root, home } = project();
    expect(resolveContext({ cwd: root, home, env: { KRONICLE_LITE_PROJECT: 'acme' } })).toMatchObject({ projectKey: 'acme', memoryKey: 'acme' });
    expect(resolveContext({ cwd: root, home, env: { KRONICLE_LITE_PROJECT: 'Bad Key!' } }).projectKey).toBe(projectKey(root));
  });

  it("two repos sharing one data dir: syncing B's CLAUDE.md never retracts A's rules (audit repro, via the CLI)", async () => {
    const home = tempDir('kl-home-');
    const env = cleanEnv({ HOME: home, USERPROFILE: home });
    const dataDir = join(tempDir('kl-data-'), 'shared');
    const a = tempDir('kl-repoA-');
    const b = tempDir('kl-repoB-');
    gitInit(a);
    gitInit(b);
    write(join(a, 'CLAUDE.md'), '# Rules\n- Never touch migrations/.\n');
    expect((await runCli(['put', '--from-instructions', '--cwd', a, '--data-dir', dataDir], { env })).status).toBe(0);
    const o1 = await runCli(['orient', '--actor', 'me', '--json', '--cwd', a, '--data-dir', dataDir], { env });
    const cursor = (JSON.parse(o1.stdout) as { cursor_compact: string }).cursor_compact;

    write(join(b, 'CLAUDE.md'), '# Other\n- Use uv.\n');
    const pb = await runCli(['put', '--from-instructions', '--cwd', b, '--data-dir', dataDir], { env });
    expect(pb.stdout).toMatch(/instructions\/kl-repob-[^/]+-[0-9a-f]{8}\/claude-md ← CLAUDE\.md: imported as rev 1/i);
    expect(pb.stdout).not.toMatch(/tombstoned/);

    type S = { retractions: { severity: string; kind: string; reason_line: string }[]; scope: { hidden_retractions: number } | null };
    const o2 = JSON.parse((await runCli(['orient', '--actor', 'me', '--cursor', cursor, '--focus', 'retractions', '--json', '--cwd', a, '--data-dir', dataDir], { env })).stdout) as S;
    expect(o2.retractions).toEqual([]);
    const all = JSON.parse((await runCli(['orient', '--actor', 'me', '--cursor', cursor, '--focus', 'retractions', '--json', '--all-projects', '--cwd', a, '--data-dir', dataDir], { env })).stdout) as S;
    expect(all.retractions.filter((r) => r.severity === 'safety')).toEqual([]);

    // B edits its rules: B's agent is told, A's agent is not (and is told that something was hidden).
    write(join(b, 'CLAUDE.md'), '# Other\n- Use uv, never pip.\n');
    await runCli(['put', '--from-instructions', '--cwd', b, '--data-dir', dataDir], { env });
    const o3 = JSON.parse((await runCli(['orient', '--actor', 'me', '--cursor', cursor, '--focus', 'retractions', '--json', '--cwd', a, '--data-dir', dataDir], { env })).stdout) as S;
    expect(o3.retractions).toEqual([]);
    expect(o3.scope!.hidden_retractions).toBe(1);
    const ob = JSON.parse((await runCli(['orient', '--actor', 'me', '--cursor', cursor, '--focus', 'retractions', '--json', '--cwd', b, '--data-dir', dataDir], { env })).stdout) as S;
    expect(ob.retractions.map((r) => r.kind)).toEqual(['instruction']);
    expect(ob.retractions[0]!.reason_line).toContain('"- Use uv, never pip."');

    const store = new KronicleLite({ dataDir });
    const keyA = resolveContext({ cwd: a, home, env: NOENV }).projectKey;
    const docA = store.docs.getDocument(`instructions/${keyA}/claude-md`)!;
    expect(store.docs.liveBlocks(docA.doc_id).map((x) => x.content)).toContain('- Never touch migrations/.');
    expect(store.verifyAll().ok).toBe(true);
    store.close();
  });

  it('a 0.4.0 un-keyed document is adopted in place when it holds this file: same doc_id, receipts still VERIFIED, no retraction', async () => {
    const { root, rc, ctx, ns } = project();
    const store = new KronicleLite({ memory: true });
    // What 0.4.0 wrote for CLAUDE.md.
    const text = '# Project\n\nUse pnpm, not npm.\n\nRun tests with `pnpm test`.\n';
    const legacy = store.docs.putDocument({ slug: 'instructions/claude-md', title: 'CLAUDE.md', markdown: text, actor_id: 'instructions', source: { kind: 'instruction', path: 'CLAUDE.md' } });
    // Another project's 0.4.0 AGENTS.md text, which does not match this project's file: left alone.
    store.docs.putDocument({ slug: 'instructions/agents-md', title: 'AGENTS.md', markdown: '# Elsewhere\n\nSomething else.\n', actor_id: 'instructions', source: { kind: 'instruction', path: 'AGENTS.md' } });
    const receipt = store.recall.recall({ query: 'pnpm' }).hits[0]!.receipt!;
    const cold = store.orient.getSystemState({ actor_id: 'agent' });

    const results = syncInstructionSet(store, ctx);
    const claude = results.find((r) => r.slug === ns('instructions/claude-md'))!;
    expect(claude).toMatchObject({ action: 'updated', migrated_from: 'instructions/claude-md', superseded: 0, created: 0, tombstoned: 0 });
    const moved = store.docs.getDocument(ns('instructions/claude-md'))!;
    expect(moved.doc_id).toBe(legacy.doc_id);
    expect(store.docs.getDocument('instructions/claude-md')).toBeNull();
    expect(store.docs.getSource(moved.doc_id)!.source.project).toEqual({ key: rc.projectKey, root });
    expect(store.docs.getDocument('instructions/agents-md')).not.toBeNull();
    expect(results.find((r) => r.slug === ns('instructions/agents-md'))!.action).toBe('created');
    expect(store.verifier.verify(receipt).status).toBe('VERIFIED');
    const warm = store.orient.getSystemState({ actor_id: 'agent', since_cursor: cold.cursor });
    expect(warm.retractions).toEqual([]);
    expect(warm.delta!.by_type['document.renamed']).toBe(1);
    expect(store.verifyAll().ok).toBe(true);

    // The rename is on the chain: an export rebuilds the same projection.
    const sink = new PassThrough();
    let buf = '';
    sink.on('data', (c: Buffer) => (buf += c.toString('utf8')));
    store.exportEvents(sink);
    sink.end();
    await new Promise((r) => sink.on('end', r));
    const copy = new KronicleLite({ memory: true });
    await copy.importEvents(Readable.from([buf]));
    expect(copy.docs.getDocument(ns('instructions/claude-md'))!.doc_id).toBe(legacy.doc_id);
    expect(copy.verifyAll().ok).toBe(true);
    copy.close();
    store.close();
  });
});
