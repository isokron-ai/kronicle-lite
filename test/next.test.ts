/**
 * Unreleased (next) fixes, each tied to an agent-memory-bench Track A cell:
 *   S7  cosmetic edits are recorded, not surfaced as retractions
 *   S8  a moved file is a rename (document.renamed), not a removal
 *   S4a orient carries the actor's own notes back as text
 *   S11 recall / orient are scoped to the current project
 *   S1/S12 response diet: the "nothing changed" pulse is one line
 *   push contract: `orient --cursor C --focus retractions --json`
 */

import { mkdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { entryFor, projectScopeFor, resolveContext } from '../src/instructions/paths.js';
import { syncInstructionFile } from '../src/instructions/sync.js';
import { renderSystemStateMarkdown } from '../src/server.js';
import { KronicleLite } from '../src/store.js';
import { cleanEnv, gitInit, runCli, tempDir, write } from './helpers/fs.js';

const NOENV = {} as NodeJS.ProcessEnv;
// The bench's alarm vocabulary (track-a/lib/grade.mjs ALARM_MARKER), minus the boilerplate it strips.
const ALARM = /(changed on disk|retraction|reconcile before|supersed|tombston|removed from|STALE_SOURCE|changed:|removed:|\[-.*?-\]|\{\+)/i;
const alarm = (t: string) => ALARM.test(t.replace(/Retractions: none/gi, ''));

const NOTES_PRE = [
  'Operators recieve alerts via the dispatcher.',
  'Status updates go to the  incident channel.',
  'Operators, responders and support engineers join the bridge.',
  'Use the “safe” profile for drills.',
  '1) Open the runbook.\n2) Follow the checklist.\n3) Acknowledge the page.',
  'Never *skip* the canary stage.',
  'Silence alerts only with a ticket',
  'Send an e-mail summary after each drill.',
  'Last reviewed: 2026-10-01',
];
const NOTES_POST = [
  'Operators receive alerts via the dispatcher.',
  'Status updates go to the incident channel.',
  'Operators, responders, and support engineers join the bridge.',
  'Use the "safe" profile for drills.',
  '1. Open the runbook.\n2. Follow the checklist.\n3. Acknowledge the page.',
  'Never _skip_ the canary stage.',
  'Silence alerts only with a ticket.',
  'Send an email summary after each drill.',
  'Last reviewed: 2026-11-01',
];
const runbook = (cluster: string, notes: string[]) => `# api deploy runbook\n\n## Deploy target\n\nDeploys go to the cluster \`${cluster}\` first.\n\n## Notes\n\n${notes.join('\n\n')}\n`;

function repo() {
  const root = tempDir('kl-next-');
  const home = tempDir('kl-next-home-');
  gitInit(root);
  const rc = resolveContext({ cwd: root, home, env: NOENV });
  return { root, home, rc, store: new KronicleLite({ memory: true }) };
}

describe('S7: cosmetic edits are recorded, not retractions', () => {
  it('each benign edit alone: quiet orient (a typo fix is delivered as likely_typo); a cluster change still alarms with its diff', () => {
    for (let i = 0; i < NOTES_PRE.length; i++) {
      const { root, rc, store } = repo();
      const file = join(root, 'docs', 'deploy.md');
      write(file, runbook('stg-west-3', NOTES_PRE));
      syncInstructionFile(store, entryFor(file, rc), { context: rc });
      const c0 = store.orient.getSystemState({ actor_id: 'a' }).cursor;
      write(file, runbook('stg-west-3', NOTES_PRE.map((n, j) => (j === i ? NOTES_POST[j]! : n))));
      expect(syncInstructionFile(store, entryFor(file, rc), { context: rc }).action).toBe('updated');
      const s = store.orient.getSystemState({ actor_id: 'a', since_cursor: c0 });
      if (i === 0) {
        // recieve → receive: typo-shaped, so delivered (informational), never hidden.
        expect(s.retractions).toEqual([expect.objectContaining({ likely_typo: true, severity: 'informational' })]);
        expect(s.cosmetic_edits).toEqual([]);
        expect(renderSystemStateMarkdown(s)).toMatch(/likely typo fixes: check the new wording/);
        continue;
      }
      expect(s.retractions).toEqual([]);
      expect(s.cosmetic_edits).toHaveLength(1);
      const md = renderSystemStateMarkdown(s);
      expect(alarm(md), md).toBe(false);
      expect(md).toMatch(/1 cosmetic edit\(s\) recorded/);
      // Still queryable: include_cosmetic lists it as an informational retraction.
      const all = store.orient.getSystemState({ actor_id: 'b', since_cursor: undefined, include_cosmetic: true });
      expect(all.retractions!.filter((r) => r.cosmetic)).toHaveLength(1);
      expect(all.retractions!.find((r) => r.cosmetic)!.severity).toBe('informational');
    }
    const { root, rc, store } = repo();
    const file = join(root, 'docs', 'deploy.md');
    write(file, runbook('stg-west-3', NOTES_PRE));
    syncInstructionFile(store, entryFor(file, rc), { context: rc });
    const c0 = store.orient.getSystemState({ actor_id: 'a' }).cursor;
    write(file, runbook('qa-east-7', NOTES_POST));
    syncInstructionFile(store, entryFor(file, rc), { context: rc });
    const s = store.orient.getSystemState({ actor_id: 'a', since_cursor: c0 });
    expect(s.retractions).toHaveLength(2);
    expect(s.retractions!.find((r) => !r.likely_typo)!.diff).toContain('[-`stg-west-3`-]{+`qa-east-7`+}');
    expect(s.cosmetic_edits).toHaveLength(NOTES_PRE.length - 1);
    expect(renderSystemStateMarkdown(s)).toMatch(/Retractions \(2\) — reconcile before acting/);
  });
});

describe('0.7.0 blocker: a one-letter value change is a retraction, not a typo', () => {
  it('runbook --target staging-a → staging-b: 1 retraction, 0 cosmetic edits', () => {
    const store = new KronicleLite({ memory: true });
    store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: '# Runbook\n\nDeploy with ./bin/deploy --target staging-a.\n', actor_id: 'ops' });
    const c0 = store.orient.getSystemState({ actor_id: 'hook', focus: 'pulse' }).cursor;
    store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: '# Runbook\n\nDeploy with ./bin/deploy --target staging-b.\n', actor_id: 'ops' });
    const s = store.orient.getSystemState({ actor_id: 'hook', since_cursor: c0, focus: 'retractions' });
    expect(s.retractions).toHaveLength(1);
    expect(s.retractions![0]!.diff).toContain('staging-b');
    expect(s.cosmetic_edits).toEqual([]);
  });
});

describe('S8: a moved file is a rename', () => {
  for (const order of ['old path first', 'new path first'] as const) {
    it(`same content at a new path → document.renamed, same block ids, no retraction (${order})`, () => {
      const { root, rc, store } = repo();
      const from = join(root, 'docs', 'deploy.md');
      const to = join(root, 'docs', 'ops', 'deploy-runbook.md');
      write(from, runbook('stg-west-3', NOTES_PRE));
      syncInstructionFile(store, entryFor(from, rc), { context: rc });
      const before = store.docs.getDocument(entryFor(from, rc).slug)!;
      const blocks = store.docs.liveBlocks(before.doc_id).map((b) => b.block_id);
      const c0 = store.orient.getSystemState({ actor_id: 'a' }).cursor;
      mkdirSync(join(root, 'docs', 'ops'), { recursive: true });
      renameSync(from, to);
      const paths = order === 'old path first' ? [from, to] : [to, from];
      const r1 = syncInstructionFile(store, entryFor(paths[0]!, rc), { context: rc });
      const r2 = syncInstructionFile(store, entryFor(paths[1]!, rc), { context: rc });
      expect(r1.action).toBe('renamed');
      expect(r1.renamed_from).toEqual({ slug: entryFor(from, rc).slug, path: 'docs/deploy.md' });
      expect(r2.action).toBe(order === 'old path first' ? 'unchanged' : 'missing');
      const after = store.docs.getDocument(entryFor(to, rc).slug)!;
      expect(after.doc_id).toBe(before.doc_id);
      expect(store.docs.liveBlocks(after.doc_id).map((b) => b.block_id).sort()).toEqual([...blocks].sort());
      expect(store.docs.getSource(after.doc_id)!.source.path).toBe('docs/ops/deploy-runbook.md');
      const s = store.orient.getSystemState({ actor_id: 'a', since_cursor: c0 });
      expect(s.retractions).toEqual([]);
      expect(s.delta!.by_type['document.renamed']).toBe(1);
      const md = renderSystemStateMarkdown(s);
      expect(alarm(md)).toBe(false);
      expect(md).not.toMatch(/removed|deleted|retired/i);
      expect(store.recall.recall({ query: 'deploys cluster' }).hits[0]!.content).toContain('stg-west-3');
    });
  }

  it('a real deletion still retracts (safety), and a copy is not a move', () => {
    const { root, rc, store } = repo();
    const a = join(root, 'docs', 'legacy.md');
    const b = join(root, 'docs', 'legacy-copy.md');
    write(a, '# Legacy\n\nDeploys used to go through `legacy-host-42.internal`.\n');
    write(b, '# Legacy\n\nDeploys used to go through `legacy-host-42.internal`.\n');
    syncInstructionFile(store, entryFor(a, rc), { context: rc });
    syncInstructionFile(store, entryFor(b, rc), { context: rc });
    const c0 = store.orient.getSystemState({ actor_id: 'a' }).cursor;
    rmSync(a);
    expect(syncInstructionFile(store, entryFor(a, rc), { context: rc }).action).toBe('removed');
    const s = store.orient.getSystemState({ actor_id: 'a', since_cursor: c0 });
    expect(s.retractions!.some((r) => r.severity === 'safety' && /REMOVED/.test(r.reason_line))).toBe(true);
  });
});

describe('S4a: orient carries your own notes back as text', () => {
  it('a decision written since the cursor comes back verbatim; other actors’ notes do not', () => {
    const store = new KronicleLite({ memory: true });
    store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: '# Runbook\n\nDeploy to `stg-west-3`.\n', actor_id: 'ops' });
    const c0 = store.orient.getSystemState({ actor_id: 'agent' }).cursor;
    const decision = 'Use feature flag ff_amber_1a2b3c instead of a schema migration; never edit billing/legacy_9f.py.';
    store.docs.putDocument({ slug: 'notes-session-decision', title: 'decision', markdown: `# session-decision\n\n${decision}\n`, actor_id: 'agent' });
    store.docs.putDocument({ slug: 'notes-planted', title: 'planted', markdown: '# p\n\nDeploy to `evil-1`.\n', actor_id: 'mallory' });
    const s = store.orient.getSystemState({ actor_id: 'agent', since_cursor: c0 });
    expect(s.carried_notes).toEqual([expect.objectContaining({ doc_slug: 'notes-session-decision', text: decision, truncated: false })]);
    const md = renderSystemStateMarkdown(s);
    expect(md).toContain(decision);
    expect(md).not.toContain('evil-1');
  });

  it('bounded, and a note repeating a value a retraction changed is marked', () => {
    const store = new KronicleLite({ memory: true });
    store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: '# Runbook\n\nDeploy to `stg-west-3` first.\n', actor_id: 'ops' });
    const c0 = store.orient.getSystemState({ actor_id: 'agent' }).cursor;
    store.docs.putDocument({ slug: 'notes-target', title: 't', markdown: '# t\n\nDeploy target is stg-west-3.\n', actor_id: 'agent' });
    store.docs.putDocument({ slug: 'notes-long', title: 'l', markdown: `# l\n\n${'word '.repeat(400)}\n`, actor_id: 'agent' });
    store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: '# Runbook\n\nDeploy to `qa-east-7` first.\n', actor_id: 'ops' });
    const s = store.orient.getSystemState({ actor_id: 'agent', since_cursor: c0 });
    const long = s.carried_notes!.find((n) => n.doc_slug === 'notes-long')!;
    expect(long.truncated).toBe(true);
    expect(long.text.length).toBeLessThanOrEqual(600);
    const target = s.carried_notes!.find((n) => n.doc_slug === 'notes-target')!;
    expect(target.stale_terms).toEqual([expect.objectContaining({ term: 'stg-west-3' })]);
    expect(renderSystemStateMarkdown(s)).toMatch(/this note repeats `stg-west-3`, changed at seq \d+/);
  });
});

describe('S11: recall and orient are scoped to the current project', () => {
  it('another project’s documents are counted, not served; unscoped (older) documents stay visible', () => {
    const store = new KronicleLite({ memory: true });
    const A = { key: 'repo-a-11111111', root: '/w/repo-a' };
    const B = { key: 'repo-b-22222222', root: '/w/repo-b' };
    store.docs.putDocument({ slug: 'notes-a', title: 'a', markdown: '# a\n\nDeploy target is `stg-west-3`.\n', actor_id: 'x', project: A });
    store.docs.putDocument({ slug: 'notes-b', title: 'b', markdown: '# b\n\nDeploy target is `qa-east-7`.\n', actor_id: 'y', project: B });
    store.docs.putDocument({ slug: 'notes-old', title: 'old', markdown: '# old\n\nDeploy target history lives in the wiki.\n', actor_id: 'z' });
    const r = store.recall.recall({ query: 'deploy target', project_keys: [A.key] });
    expect(r.hits.map((h) => h.doc_slug).sort()).toEqual(['notes-a', 'notes-old']);
    expect(r.scope).toEqual({ project_keys: [A.key], other_projects_hidden: 1 });
    expect(r.absence.not_searched).toContain('other_projects');
    expect(store.recall.recall({ query: 'deploy target' }).hits).toHaveLength(3);

    const s = store.orient.getSystemState({ actor_id: 'x', project: { keys: [A.key], root: A.root } });
    expect(JSON.stringify(s.delta)).not.toContain('notes-b');
    expect(s.scope!.hidden_events).toBeGreaterThan(0);
    expect(s.digest!.recent_documents.map((d) => d.slug)).not.toContain('notes-b');
  });

  it('a 0.6.0 database gains project_key on open, backfilled from instruction sources', () => {
    const dir = tempDir('kl-mig-');
    const s1 = new KronicleLite({ dataDir: dir });
    s1.docs.putDocument({ slug: 'instructions/p-1/claude-md', title: 'c', markdown: '# c\n\nx\n', actor_id: 'i', source: { kind: 'instruction', path: 'CLAUDE.md', project: { key: 'p-1', root: '/p' } } });
    s1.db.exec('UPDATE documents SET project_key = NULL');
    s1.db.exec('DROP INDEX documents_project_idx');
    s1.db.exec('ALTER TABLE documents DROP COLUMN project_key');
    s1.close();
    const s2 = new KronicleLite({ dataDir: dir });
    expect(s2.docs.getDocument('instructions/p-1/claude-md')!.project_key).toBe('p-1');
    expect(s2.verifyAll().ok).toBe(true);
    s2.close();
  });
});

describe('response diet', () => {
  it('nothing changed: a one-line pulse under 300 bytes that still carries a cursor', () => {
    const store = new KronicleLite({ memory: true });
    store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: '# Runbook\n\nDeploy to `stg-west-3`.\n', actor_id: 'ops' });
    const c0 = store.orient.getSystemState({ actor_id: 'agent' }).cursor;
    const s = store.orient.getSystemState({ actor_id: 'agent', since_cursor: c0 });
    const md = renderSystemStateMarkdown(s);
    expect(Buffer.byteLength(md)).toBeLessThanOrEqual(300);
    expect(md).toContain(s.cursor_compact);
    expect(md).toMatch(/no change since seq/);
    expect(Buffer.byteLength(renderSystemStateMarkdown(store.orient.getSystemState({ actor_id: 'agent', since_cursor: c0, focus: 'pulse' })))).toBeLessThanOrEqual(300);
  });
});

describe('CLI start-up', () => {
  it('help names the HTTP default port (the CLI inlines it so `orient` does not load the MCP SDK)', async () => {
    const { DEFAULT_HTTP_PORT } = await import('../src/http.js');
    const r = await runCli(['help']);
    expect(r.stdout).toContain(`127.0.0.1:${DEFAULT_HTTP_PORT}/mcp`);
  });
});

describe('push contract: orient --cursor C --focus retractions --json', () => {
  it('stable shape: cursor, head.seq, retractions[{seq,kind,diff,old_text,new_text}]; cosmetic edits not pushed', async () => {
    const root = tempDir('kl-push-');
    const data = tempDir('kl-push-data-');
    gitInit(root);
    const file = join(root, 'docs', 'deploy.md');
    write(file, runbook('stg-west-3', NOTES_PRE));
    const env = cleanEnv();
    const put = async () => {
      const r = await runCli(['put', '--from-instructions', 'docs/deploy.md', '--cwd', root, '--data-dir', data], { env, cwd: root });
      expect(r.status, r.stderr).toBe(0);
    };
    const orient = async (extra: string[]) => {
      const r = await runCli(['orient', '--data-dir', data, '--actor', 'push-hook', '--json', '--cwd', root, ...extra], { env, cwd: root });
      expect(r.status, r.stderr).toBe(0);
      return JSON.parse(r.stdout) as {
        cursor: string;
        head: { seq: number };
        retractions: { seq: number; kind: string; diff: string | null; old_text: string | null; new_text: string | null }[];
        cosmetic_edits: unknown[];
        source_drift: unknown;
      };
    };
    await put();
    const o0 = await orient(['--focus', 'pulse']);
    writeFileSync(file, runbook('stg-west-3', NOTES_POST));
    await put();
    const o1 = await orient(['--cursor', o0.cursor, '--focus', 'retractions']);
    expect(o1.retractions).toEqual([expect.objectContaining({ likely_typo: true })]); // recieve → receive is delivered
    expect(o1.cosmetic_edits.length).toBe(NOTES_PRE.length - 1);
    expect(o1.source_drift).toBeNull();
    writeFileSync(file, runbook('qa-east-7', NOTES_POST));
    await put();
    const o2 = await orient(['--cursor', o1.cursor, '--focus', 'retractions']);
    expect(o2.head.seq).toBeGreaterThan(o1.head.seq);
    expect(o2.retractions).toEqual([expect.objectContaining({ kind: 'instruction', diff: expect.stringContaining('qa-east-7'), old_text: expect.any(String), new_text: expect.any(String) })]);
    expect(typeof o2.retractions[0]!.seq).toBe('number');
    const o3 = await orient(['--cursor', o2.cursor, '--focus', 'retractions', '--include-cosmetic']);
    expect(o3.retractions).toEqual([]);
    // project scope comes from --cwd
    expect(projectScopeFor({ cwd: root }).keys.length).toBeGreaterThan(0);
  });
});
