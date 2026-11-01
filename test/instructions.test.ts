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
import { claudeProjectDirName, entryFor, instructionSlugFor, resolveContext } from '../src/instructions/paths.js';
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
  return { root, home, rc, ctx: { cwd: root, home, env: NOENV } };
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
    const { root, rc, ctx } = project();
    const set = resolveWatchSet(ctx);
    expect(set.entries.map((e) => e.slug).sort()).toEqual([
      'instructions/agents-md',
      'instructions/claude-md',
      'instructions/claude-rules/frontend/react',
      'instructions/claude-rules/testing',
      'instructions/cursor-rules/style.mdc',
      'memory/MEMORY',
    ]);
    const store = new KronicleLite({ memory: true });
    const first = syncInstructionSet(store, ctx);
    expect(first.every((r) => r.action === 'created')).toBe(true);
    const cold = store.orient.getSystemState({ actor_id: 'agent' });
    const mem = store.docs.getDocument('memory/MEMORY')!;
    expect(store.docs.getSource(mem.doc_id)!.source).toMatchObject({ kind: 'memory', path: expect.stringMatching(/^~\/\.claude\/projects\/.+\/memory\/MEMORY\.md$/) });
    expect(store.docs.getSource(store.docs.getDocument('instructions/claude-md')!.doc_id)!.source).toEqual({ kind: 'instruction', path: 'CLAUDE.md' });

    const head = store.chain.head().seq;
    expect(syncInstructionSet(store, ctx).every((r) => r.action === 'unchanged')).toBe(true);
    expect(store.chain.head().seq).toBe(head);

    write(join(root, 'CLAUDE.md'), '# Project\n\nUse bun, not npm.\n\nRun tests with `pnpm test`.\n');
    unlinkSync(join(root, 'AGENTS.md'));
    const second = syncInstructionSet(store, ctx);
    const claude = second.find((r) => r.slug === 'instructions/claude-md')!;
    expect(claude).toMatchObject({ action: 'updated', superseded: 1, created: 0, tombstoned: 0, revision: 2 });
    // AGENTS.md vanished from the set; sync it explicitly as the watcher does.
    const gone = syncInstructionFile(store, entryFor(join(root, 'AGENTS.md'), rc));
    expect(gone).toMatchObject({ action: 'removed', tombstoned: 2 });
    expect(syncInstructionFile(store, entryFor(join(root, 'AGENTS.md'), rc)).action).toBe('missing');

    const warm = store.orient.getSystemState({ actor_id: 'agent', since_cursor: cold.cursor });
    const kinds = warm.retractions!.map((r) => [r.kind, r.severity, r.doc_slug]);
    expect(kinds).toContainEqual(['instruction', 'behavioral', 'instructions/claude-md']);
    expect(kinds).toContainEqual(['instruction', 'safety', 'instructions/agents-md']);
    expect(warm.retractions!.every((r) => r.kind === 'instruction')).toBe(true);
    const md = renderSystemStateMarkdown(warm);
    expect(md).toMatch(/instruction block .* was CHANGED .* in instructions\/claude-md; re-read kronicle:\/\/docs\/instructions%2Fclaude-md/);
    expect(md).toMatch(/was REMOVED from instructions\/agents-md/);
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
    const { ctx } = project();
    const store = new KronicleLite({ memory: true });
    syncInstructionSet(store, ctx);
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const handle = serveStdio(createServerFactory(store), { transport: st });
    const client = new Client({ name: 't', version: '0' }, { versionNegotiation: { mode: { pin: '2026-07-28' } } });
    await client.connect(ct);
    const { resources } = await client.listResources();
    expect(resources.map((r) => r.uri)).toContain('kronicle://docs/instructions%2Fclaude-md');
    const read = await client.readResource({ uri: 'kronicle://docs/instructions%2Fclaude-md' });
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
    const { root, ctx } = project();
    const { s, initial, synced } = startWatcher(ctx);
    expect(initial).toHaveLength(6);
    write(join(root, 'CLAUDE.md'), '# Project\n\nUse yarn.\n\nRun tests with `pnpm test`.\n');
    await waitFor(() => synced().some((e) => e.result.slug === 'instructions/claude-md' && e.result.action === 'updated'), 8_000, 'fs.watch sync');
    expect(s.docs.getDocument('instructions/claude-md')!.current_revision).toBe(2);
    const tmp = join(root, '.claude', 'rules', 'testing.md.tmp');
    writeFileSync(tmp, '# Testing\n\nVitest and Playwright.\n');
    renameSync(tmp, join(root, '.claude', 'rules', 'testing.md'));
    await waitFor(() => synced().some((e) => e.result.slug === 'instructions/claude-rules/testing'), 8_000, 'rename sync');
    expect(s.docs.getDocument('instructions/claude-rules/testing')!.current_revision).toBe(2);
  });

  it('polling fallback: changes, new rule files in new directories, and deletions are picked up without fs.watch', async () => {
    const { root, ctx } = project();
    const { s, w, synced } = startWatcher(ctx, { poll: true, intervalMs: 100 });
    expect(w.mode).toBe('poll');
    write(join(root, 'AGENTS.md'), '# Agents\n\nNever push to main. Open a PR.\n');
    write(join(root, '.claude', 'rules', 'backend', 'db.md'), '# DB\n\nMigrations are reviewed.\n');
    await waitFor(
      () => synced().some((e) => e.result.slug === 'instructions/agents-md') && synced().some((e) => e.result.slug === 'instructions/claude-rules/backend/db'),
      8_000,
      'poll sync',
    );
    rmSync(join(root, '.cursor'), { recursive: true });
    await waitFor(() => synced().some((e) => e.result.slug === 'instructions/cursor-rules/style.mdc' && e.result.action === 'removed'), 8_000, 'poll removal');
    expect(s.docs.liveBlocks(s.docs.getDocument('instructions/cursor-rules/style.mdc')!.doc_id)).toHaveLength(0);
  });

  it('explicit paths: a file and a directory (recursive *.md / *.mdc)', async () => {
    const { root, ctx } = project();
    write(join(root, 'docs', 'guide.md'), '# Guide\n\nRead me.\n');
    write(join(root, 'docs', 'deep', 'more.mdc'), 'More.\n');
    write(join(root, 'docs', 'image.png'), 'png');
    const { initial } = startWatcher(ctx, { paths: [join(root, 'CLAUDE.md'), join(root, 'docs')] });
    expect(initial.map((r) => r.slug).sort()).toEqual(['instructions/claude-md', 'instructions/docs/deep/more.mdc', 'instructions/docs/guide']);
  });
});

describe('CLI and the Claude Code hook surface', () => {
  it('watch --list --json, put --from-instructions, and --stdin-hook for SessionStart / FileChanged', async () => {
    const { root, home, rc } = project();
    const dataDir = join(tempDir('kl-data-'), 'd');
    const env = cleanEnv({ HOME: home, USERPROFILE: home });
    const list = await runCli(['watch', '--list', '--json', '--cwd', root], { env });
    expect(list.status, list.stderr).toBe(0);
    const l = JSON.parse(list.stdout) as { memory_dir: string; files: { slug: string }[] };
    expect(l.memory_dir).toBe(rc.memoryDir);
    expect(l.files.map((f) => f.slug)).toContain('memory/MEMORY');

    const put = await runCli(['put', '--from-instructions', '--cwd', root, '--data-dir', dataDir, '--json'], { env });
    expect(put.status, put.stderr).toBe(0);
    expect((JSON.parse(put.stdout) as { results: { action: string }[] }).results.map((r) => r.action)).toEqual(Array(6).fill('created'));
    const one = await runCli(['put', '--from-instructions', 'CLAUDE.md', '--cwd', root, '--data-dir', dataDir], { env, cwd: root });
    expect(one.stdout).toMatch(/^instructions\/claude-md ← CLAUDE\.md: unchanged \(rev 1\)/);

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
    expect(JSON.parse(fc.stdout).systemMessage).toMatch(/memory\/MEMORY ← ~\/.+: rev 2 \(1 superseded/);
    const quiet = await runCli(['put', '--from-instructions', '--stdin-hook', '--data-dir', dataDir], {
      env,
      stdin: JSON.stringify({ hook_event_name: 'FileChanged', cwd: root, file_path: join(rc.memoryDir, 'MEMORY.md'), event: 'change' }),
    });
    expect(quiet.stdout).toBe('');
    const bad = await runCli(['put', '--from-instructions', '--stdin-hook', '--data-dir', dataDir], { env, stdin: 'not json' });
    expect(bad.status).toBe(0); // a hook never fails the session

    const orient = await runCli(['orient', '--data-dir', dataDir, '--json'], { env });
    const state = JSON.parse(orient.stdout) as { retractions: { kind: string }[] };
    expect(state.retractions.some((r) => r.kind === 'instruction')).toBe(true);
    const once = await runCli(['watch', '--once', '--cwd', root, '--data-dir', dataDir], { env });
    expect(once.status).toBe(0);
    expect(once.stderr).toMatch(/watching \d+ file\(s\)/);
  });
});
