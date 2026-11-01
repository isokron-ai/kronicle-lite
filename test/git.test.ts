/**
 * Git-aware blocks (0.4.0): bind_git records {repo_root, commit, path,
 * blob_sha}; verify / audit_assumptions answer stale_source with a diff stat
 * when the working-tree blob moves; orient lists it under "Source drift".
 * Graceful outside git.
 */

import { Client, InMemoryTransport } from '@modelcontextprotocol/client';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { renameSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import { bindGit, diffStat, editDistance } from '../src/git/binding.js';
import { createServerFactory, renderSystemStateMarkdown } from '../src/server.js';
import { KronicleLite } from '../src/store.js';
import { cleanEnv, gitInit, gitRun, runCli, tempDir, write } from './helpers/fs.js';

const DOC = '# Deploy\n\nUse blue/green for the API.\n\nRoll back with `deploy undo`.\n';

function repo(commit = true) {
  const root = tempDir('kl-git-');
  gitInit(root);
  write(join(root, 'docs', 'deploy.md'), DOC);
  if (commit) {
    gitRun(root, ['add', '-A']);
    gitRun(root, ['commit', '-q', '-m', 'docs']);
  }
  return { root, file: join(root, 'docs', 'deploy.md') };
}

function putBound(store: KronicleLite, file: string) {
  const b = bindGit(file);
  const source = b.binding ? { kind: 'file', path: b.binding.path, git: b.binding } : { kind: 'file', path: file };
  return { b, put: store.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: DOC, actor_id: 't', source }) };
}

describe('diff stat (Myers edit distance, no git needed)', () => {
  it('counts insertions and deletions like git diff --stat', () => {
    expect(editDistance([], [])).toBe(0);
    expect(editDistance(['a', 'b', 'c'], ['a', 'x', 'c'])).toBe(2);
    expect(diffStat('f.md', 'a\nb\nc\n', 'a\nx\nc\nd\n', 'git')).toMatchObject({ insertions: 2, deletions: 1, files_changed: 1, summary: ' f.md | 3 ++-' });
    expect(diffStat('f.md', 'a\r\nb\r\n', 'a\nb\n', 'git')).toMatchObject({ insertions: 0, deletions: 0, files_changed: 0 });
    expect(diffStat('f.md', 'a\nb\n', '', 'stored_revision')).toMatchObject({ insertions: 0, deletions: 2 });
  });
});

describe('bind_git', () => {
  it('records {repo_root, commit, path, blob_sha} from git rev-parse / hash-object', () => {
    const { root, file } = repo();
    const store = new KronicleLite({ memory: true });
    const { b, put } = putBound(store, file);
    expect(b.warning).toBeNull();
    expect(b.binding).toEqual({
      repo_root: root,
      commit: gitRun(root, ['rev-parse', 'HEAD']),
      path: 'docs/deploy.md',
      blob_sha: gitRun(root, ['hash-object', 'docs/deploy.md']),
    });
    // In the chain: the document.put payload carries it.
    expect(store.chain.get(put.chain_seq)!.payload['source']).toEqual({ kind: 'file', path: 'docs/deploy.md', git: b.binding });
    expect(store.docs.sourceDrift(put.doc_id)).toMatchObject({ state: 'current', diff_stat: null });
    store.close();
  });

  it('verify → STALE_SOURCE and audit → stale_source with a diff stat when the file changes; orient lists Source drift; re-binding clears it', () => {
    const { root, file } = repo();
    const store = new KronicleLite({ memory: true });
    const { put } = putBound(store, file);
    const cold = store.orient.getSystemState({ actor_id: 'a' });
    expect(cold.source_drift).toEqual([]);
    const hit = store.recall.recall({ query: 'blue green' }).hits[0]!;
    expect(store.verifier.verify(hit.receipt).status).toBe('VERIFIED');

    write(file, DOC.replace('blue/green', 'canary') + '\nNew line.\n');
    const v = store.verifier.verify(hit.receipt);
    expect(v).toMatchObject({ status: 'STALE_SOURCE', reason: 'stale_source' });
    expect(v.source_drift).toMatchObject({
      state: 'changed',
      path: 'docs/deploy.md',
      repo_root: root,
      bound_blob_sha: expect.stringMatching(/^[0-9a-f]{40}$/),
      working_blob_sha: gitRun(root, ['hash-object', 'docs/deploy.md']),
      diff_stat: { insertions: 3, deletions: 1, bound_from: 'git' },
    });
    const audit = store.auditor.audit([
      { symbol: hit.block_id, value: hit.content },
      { symbol: 'deploy', value: put.revision },
      { symbol: 'head', value: store.chain.head().seq },
    ]);
    expect(audit.results.map((r) => r.verdict)).toEqual(['stale_source', 'stale_source', 'current']);
    expect(audit.counts).toMatchObject({ stale_source: 2, current: 1 });
    expect(audit.results[0]!.reconcile).toMatch(/docs\/deploy\.md changed since it was bound .*\(\+3 −1\)/);

    const warm = store.orient.getSystemState({ actor_id: 'a', since_cursor: cold.cursor });
    expect(warm.source_drift).toHaveLength(1);
    const md = renderSystemStateMarkdown(warm);
    expect(md).toMatch(/## Source drift \(1\)/);
    expect(md).toMatch(/- `deploy` ← docs\/deploy\.md: blob [0-9a-f]{12} → [0-9a-f]{12} \(\+3 −1\)/);
    expect(warm.next_steps.join(' ')).toMatch(/Source drift/);
    expect(store.orient.getSystemState({ actor_id: 'a', focus: 'pulse' }).source_drift).toBeNull();

    // A non-bound document and a superseded receipt keep their 0.3.0 statuses.
    store.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: DOC.replace('blue/green', 'canary'), actor_id: 't' });
    expect(store.verifier.verify(hit.receipt).status).toBe('SUPERSEDED');
    expect(store.docs.getSource(put.doc_id)).toBeNull(); // a put without source clears the binding
    store.close();
  });

  it('an untracked file: diff stat from the stored revision; a deleted file is drift too', () => {
    const { root } = repo();
    const file = join(root, 'notes.md');
    write(file, 'one\ntwo\n');
    const store = new KronicleLite({ memory: true });
    const b = bindGit(file);
    expect(b.binding!.commit).toBe(gitRun(root, ['rev-parse', 'HEAD']));
    const put = store.docs.putDocument({ slug: 'notes', title: 'N', markdown: 'one\ntwo\n', actor_id: 't', source: { kind: 'file', path: 'notes.md', git: b.binding! } });
    write(file, 'one\ntwo\nthree\n');
    expect(store.docs.sourceDrift(put.doc_id)).toMatchObject({ state: 'changed', diff_stat: { insertions: 1, deletions: 0, bound_from: 'stored_revision' } });
    unlinkSync(file);
    expect(store.docs.sourceDrift(put.doc_id)).toMatchObject({ state: 'missing', working_blob_sha: null, diff_stat: { deletions: 2 } });
    expect(store.orient.getSystemState({ actor_id: 'x' }).source_drift!.map((d) => d.state)).toEqual(['missing']);
    store.close();
  });

  it('a repository without commits binds with commit null', () => {
    const { file } = repo(false);
    expect(bindGit(file).binding).toMatchObject({ commit: null, path: 'docs/deploy.md' });
  });

  it('graceful outside git: the put succeeds with a warning and no binding; verify stays VERIFIED', () => {
    const dir = tempDir('kl-nogit-');
    const file = join(dir, 'x.md');
    write(file, DOC);
    const b = bindGit(file);
    expect(b.binding).toBeNull();
    expect(b.warning).toMatch(/not a git repository/);
    expect(bindGit(join(dir, 'missing.md')).warning).toMatch(/source file not found/);
    const store = new KronicleLite({ memory: true });
    store.docs.putDocument({ slug: 'x', title: 'X', markdown: DOC, actor_id: 't', source: { kind: 'file', path: 'x.md' } });
    const hit = store.recall.recall({ query: 'blue green' }).hits[0]!;
    expect(store.verifier.verify(hit.receipt).status).toBe('VERIFIED');
    // A vanished repository is "unavailable", not drift.
    const { root, file: f2 } = repo();
    const { put } = putBound(store, f2);
    // Move the repository away rather than delete it (git object files are read-only on Windows).
    renameSync(root, `${root}-gone`);
    expect(store.docs.sourceDrift(put.doc_id)).toMatchObject({ state: 'unavailable' });
    expect(store.orient.getSystemState({ actor_id: 'y' }).source_drift).toEqual([]);
    store.close();
  });

  it('CLI put --bind-git and MCP put_document {bind_git, source_path}', async () => {
    const { root, file } = repo();
    const dataDir = join(tempDir('kl-data-'), 'd');
    const r = await runCli(['put', 'deploy', file, '--bind-git', '--json', '--data-dir', dataDir], { env: cleanEnv() });
    expect(r.status, r.stderr).toBe(0);
    const out = JSON.parse(r.stdout) as { source: { git: { path: string; blob_sha: string } } };
    expect(out.source.git).toMatchObject({ path: 'docs/deploy.md', blob_sha: gitRun(root, ['hash-object', 'docs/deploy.md']) });
    const nogit = tempDir('kl-nogit-');
    write(join(nogit, 'a.md'), 'a\n');
    const w = await runCli(['put', 'a', join(nogit, 'a.md'), '--bind-git', '--data-dir', dataDir], { env: cleanEnv() });
    expect(w.status).toBe(0);
    expect(w.stderr).toMatch(/warning: bind_git: not a git repository/);

    const store = new KronicleLite({ memory: true });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const handle = serveStdio(createServerFactory(store), { transport: st });
    const client = new Client({ name: 't', version: '0' }, { versionNegotiation: { mode: { pin: '2026-07-28' } } });
    await client.connect(ct);
    const res = (await client.callTool({ name: 'put_document', arguments: { slug: 'deploy', title: 'Deploy', markdown: DOC, source_path: file, bind_git: true } })) as {
      structuredContent: { source: { git: { path: string } } };
    };
    expect(res.structuredContent.source.git.path).toBe('docs/deploy.md');
    const bad = (await client.callTool({ name: 'put_document', arguments: { slug: 'z', title: 'Z', markdown: 'z', bind_git: true } })) as { isError?: boolean; content: { text: string }[] };
    expect(bad.isError).toBe(true);
    expect(bad.content[0]!.text).toMatch(/bind_git requires source_path/);
    write(file, DOC + '\nchanged\n');
    const hit = store.recall.recall({ query: 'blue green' }).hits[0]!;
    const v = (await client.callTool({ name: 'verify', arguments: { receipt: hit.receipt } })) as { structuredContent: { status: string; source_drift: { diff_stat: { insertions: number } } } };
    expect(v.structuredContent.status).toBe('STALE_SOURCE');
    expect(v.structuredContent.source_drift.diff_stat.insertions).toBe(2);
    await client.close();
    await handle.close();
    store.close();
  });
});
