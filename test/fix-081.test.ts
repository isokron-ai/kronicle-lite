/**
 * 0.8.1 safety fixes, as repros (each failed on 0.8.0):
 *   R2-01..03  format-only is raw-text equivalence: a renumbered port, a glob
 *              `*` → `_`, a backslash hard break → retraction, pending, and a
 *              pulse that refuses (exit 77), through the CLI an agent's hooks use;
 *   L1  `## Use C#` keeps its `#` (an ATX closing sequence needs a space before it);
 *   L2  reordering blocks inside a section is a retraction (order is meaning);
 *   L3  a staleness result cut short by the depth bound or a cycle is not
 *       memoized, so a note read later in the same pass is not shown fresh;
 *   L4  lineage inference starts at the session's FIRST orient (the cursor
 *       chain), so recall → orient → write still infers what was read;
 *   L5  (test/cosmetic.test.ts) the typo hint is bounded;
 *   L6  the word diff of a long block shows the changed words.
 * Round-2 ids for the same leads: L1 = R2-13, L2 = R2-06, L5 = R2-12, L6 = R2-16.
 * CLI runs pin HOME and the data dir to temp paths.
 */

import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { parseMarkdown } from '../src/docs/parser.js';
import { changeSnippets, wordDiff } from '../src/orient/textdiff.js';
import { KronicleLite } from '../src/store.js';
import { cleanEnv, runCli, tempDir, write } from './helpers/fs.js';

function edit(v1: string, v2: string) {
  const kl = new KronicleLite({ memory: true });
  kl.docs.putDocument({ slug: 'r', title: 'r', markdown: v1, actor_id: 'w' });
  const c0 = kl.orient.getSystemState({ actor_id: 'a', focus: 'pulse' }).cursor;
  const hit = kl.recall.recall({ query: 'kernel', actor_id: 'reader' }).hits[0];
  kl.docs.putDocument({ slug: 'r', title: 'r', markdown: v2, actor_id: 'w' });
  const s = kl.orient.getSystemState({ actor_id: 'a', since_cursor: c0, focus: 'retractions' });
  return { kl, s, hit };
}

describe('R2-01..03 through the CLI: retraction, pending, pulse refuses', () => {
  const cases: [string, string, string][] = [
    ['R2-01 numbered port after a paragraph line', 'Open these ports:\n8080. web\n9090. admin', 'Open these ports:\n8080. web\n9091. admin'],
    ['R2-02 glob * → _', 'Delete /tmp/*/cache/* nightly.', 'Delete /tmp/_/cache/_ nightly.'],
    ['R2-03 backslash hard break → literal backslash', 'Run deploy\\\n--force after review', 'Run deploy\\ --force after review'],
    ['L2 steps reordered', 'Drain the node.\n\nUpgrade the kernel.', 'Upgrade the kernel.\n\nDrain the node.'],
    ['R2-06 two code blocks swapped', '## Steps\n\n```sh\nkubectl drain node-1\n```\n\n```sh\nkubectl delete node node-1\n```', '## Steps\n\n```sh\nkubectl delete node node-1\n```\n\n```sh\nkubectl drain node-1\n```'],
  ];
  it.each(cases)('%s', { timeout: 60_000 }, async (_name, a, b) => {
    const root = tempDir('kl-081-gate-');
    const data = join(root, 'data');
    const proj = join(root, 'proj');
    write(join(root, 'v1.md'), `# Runbook\n\n${a}\n`);
    write(join(root, 'v2.md'), `# Runbook\n\n${b}\n`);
    write(join(proj, '.keep'), '');
    const env = cleanEnv({ HOME: join(root, 'home'), USERPROFILE: join(root, 'home'), KRONICLE_LITE_DATA_DIR: join(root, 'no-default-store') });
    const k = (cmd: string, ...rest: string[]) => runCli([cmd, '--data-dir', data, ...rest], { env, cwd: proj });
    const ok = async (cmd: string, ...rest: string[]) => {
      const r = await k(cmd, ...rest);
      expect(r.status, `${cmd}: ${r.stderr}`).toBe(0);
      return r.stdout;
    };
    await ok('put', 'runbook', join(root, 'v1.md'), '--title', 'Runbook', '--actor', 'writer', '--cwd', proj);
    await ok('get', 'runbook', '--actor', 'agent', '--cwd', proj);
    await k('pulse', '--cwd', proj, '--state', join(root, 'st'), '--', 'git', 'push');
    const c = (JSON.parse(await ok('orient', '--actor', 'push-hook', '--json', '--cwd', proj, '--focus', 'pulse')) as { cursor: string }).cursor;
    await ok('put', 'runbook', join(root, 'v2.md'), '--title', 'Runbook', '--actor', 'writer', '--cwd', proj);
    const o = JSON.parse(await ok('orient', '--actor', 'push-hook', '--json', '--cwd', proj, '--cursor', c, '--focus', 'retractions')) as { retractions: unknown[]; format_only_edits: unknown[] };
    expect(o.retractions.length).toBeGreaterThan(0);
    expect(o.format_only_edits).toEqual([]);
    const p = JSON.parse(await ok('pending', '--actor', 'agent', '--json', '--cwd', proj)) as { pending_count: number };
    expect(p.pending_count).toBeGreaterThan(0);
    const pulse = await k('pulse', '--cwd', proj, '--state', join(root, 'st'), '--pending-actor', 'agent', '--', 'git', 'push');
    expect(pulse.status, pulse.stderr).toBe(77);
  });
});

describe('L1: an ATX closing sequence needs a space before it', () => {
  it('parses `## Use C#` as "Use C#" and still strips a real closing sequence', () => {
    expect(parseMarkdown('## Use C#\n## Title ##\n## Title \\#\n## #hashtag\n### ###\n').map((b) => b.content)).toEqual(['Use C#', 'Title', 'Title \\#', '#hashtag', '']);
  });

  it('R2-13 probes: `C#` → `C` and `Never` → `Never#` are retractions; `Port #` → `Port` is not', () => {
    for (const [a, b, real] of [
      ['## Build with C#', '## Build with C', true],
      ['## Never', '## Never#', true],
      ['## Port #', '## Port', false],
      ['## Steps', '## Steps ##', false],
    ] as const) {
      const { kl, s } = edit(`# Ops\n\n${a}\n\nRun the build.\n`, `# Ops\n\n${b}\n\nRun the build.\n`);
      expect(s.retractions!.length > 0, `${a} → ${b}`).toBe(real);
      kl.close();
    }
  });

  it('`## Use C#` → `## Use C` is a retraction', () => {
    const { kl, s } = edit('# Doc\n\n## Use C#\n\nBuild the service.\n', '# Doc\n\n## Use C\n\nBuild the service.\n');
    expect(s.retractions!.map((r) => r.old_text)).toEqual(expect.arrayContaining(['Use C#']));
    expect(s.format_only_edits).toEqual([]);
    kl.close();
  });
});

describe('L2: order inside a section is meaning', () => {
  const v1 = '# Runbook\n\n## Steps\n\nDrain the node.\n\nUpgrade the kernel.\n\nUncordon the node.\n';
  const v2 = '# Runbook\n\n## Steps\n\nUpgrade the kernel.\n\nDrain the node.\n\nUncordon the node.\n';

  it('a reorder is a retraction naming the move; the old receipt verifies SUPERSEDED; pending until re-read', () => {
    const { kl, s, hit } = edit(v1, v2);
    expect(s.retractions).toHaveLength(1);
    expect(s.retractions![0]).toMatchObject({ kind: 'supersession', format_only: false, old_text: 'Upgrade the kernel.', new_text: 'Upgrade the kernel.', diff: 'order: same text, new position within Runbook › Steps' });
    expect(s.retractions![0]!.reason_line).toMatch(/MOVED within r › Runbook › Steps/);
    expect(s.format_only_edits).toEqual([]);
    expect(kl.verifier.verify(hit!.receipt).status).toBe('SUPERSEDED');
    expect(kl.lineage.pending('reader').items).toEqual([expect.objectContaining({ kind: 'supersession', diff: 'order: same text, new position within Runbook › Steps' })]);
    expect(kl.verifyAll().ok).toBe(true);
    kl.close();
  });

  it('only the fewest blocks that moved are superseded; inserts, deletes and section reorders are not reorders', () => {
    const kl = new KronicleLite({ memory: true });
    const put = (md: string) => kl.docs.putDocument({ slug: 'r', title: 'r', markdown: md, actor_id: 'w' });
    put('# R\n\n## A\n\none\n\ntwo\n\nthree\n\nfour\n\n## B\n\nfive\n');
    let c = kl.orient.getSystemState({ actor_id: 'x', focus: 'pulse' }).cursor;
    put('# R\n\n## A\n\none\n\nthree\n\nfour\n\ntwo\n\n## B\n\nfive\n'); // "two" moved to the end
    let s = kl.orient.getSystemState({ actor_id: 'x', since_cursor: c, focus: 'retractions' });
    expect(s.retractions!.map((r) => r.old_text)).toEqual(['two']);
    c = kl.orient.getSystemState({ actor_id: 'x', focus: 'pulse' }).cursor;
    put('# R\n\n## B\n\nfive\n\n## A\n\none\n\nthree\n\nfour\n'); // section reorder + delete
    s = kl.orient.getSystemState({ actor_id: 'x', since_cursor: c, focus: 'retractions' });
    expect(s.retractions!.map((r) => `${r.kind}:${r.old_text}`)).toEqual(['tombstone:two']);
    c = kl.orient.getSystemState({ actor_id: 'x', focus: 'pulse' }).cursor;
    put('# R\n\n## B\n\nfive\n\n## A\n\nzero\n\none\n\nthree\n\nfour\n'); // insert
    s = kl.orient.getSystemState({ actor_id: 'x', since_cursor: c, focus: 'retractions' });
    expect(s.retractions).toEqual([]);
    kl.close();
  });

  it('a derived note goes stale on a reorder of its source section (not a format-only hop)', () => {
    const kl = new KronicleLite({ memory: true });
    const src = kl.docs.putDocument({ slug: 'r', title: 'r', markdown: v1, actor_id: 'w' });
    const b = src.blocks.find((x) => x.kind === 'paragraph' && x.ordinal === 3)!; // "Upgrade the kernel."
    const note = kl.docs.putDocument({ slug: 'note', title: 'n', markdown: '# N\n\nUpgrade comes second.\n', actor_id: 'a', derived_from: [{ block_id: b.block_id, content_hash: b.content_hash }], infer_lineage: false });
    expect(kl.lineage.staleness(note.doc_id)).toEqual([]);
    kl.docs.putDocument({ slug: 'r', title: 'r', markdown: v2, actor_id: 'w' });
    expect(kl.lineage.staleness(note.doc_id)).toEqual([expect.objectContaining({ source_block_id: b.block_id, change: 'superseded' })]);
    kl.close();
  });

  it('an explicit same-text supersede is still not a reorder (format-only, as before)', () => {
    const kl = new KronicleLite({ memory: true });
    const p = kl.docs.putDocument({ slug: 'r', title: 'r', markdown: '# R\n\nKeep it.\n', actor_id: 'w' });
    const c = kl.orient.getSystemState({ actor_id: 'x', focus: 'pulse' }).cursor;
    kl.docs.supersedeBlock({ block_id: p.blocks[1]!.block_id, new_content: 'Keep it.', reason: 'touch', actor_id: 'w' });
    const s = kl.orient.getSystemState({ actor_id: 'x', since_cursor: c, focus: 'retractions' });
    expect(s.retractions).toEqual([]);
    expect(s.format_only_edits).toHaveLength(1);
    kl.close();
  });
});

describe('live L2-09: a section moved AND renamed, with a value changed, is a move with a diff, not a removal', () => {
  const v1 = '# Deploy runbook — orders-svc\n\nOwner: platform team. Last reviewed: 2026-10-01.\n\n## Steps\n1. Preflight: `./bin/preflight`\n2. Build: `./bin/build`\n3. Migrations: `./bin/migrate --mode online`\n4. Deploy target: deploys go to the staging cluster `stg-west-3`: `./bin/deploy --target stg-west-3`\n5. Announce: `./bin/notify --channel #deploys --message "<what you deployed and where>"`\n';
  const v2 = '# Deploy runbook — orders-svc\n\nOwner: platform team. Last reviewed: 2026-10-31.\n\n## Release procedure\n1. Preflight: `./bin/preflight`\n2. Build: `./bin/build`\n3. Migrations: `./bin/migrate --mode online`\n4. Deploy: `./bin/deploy --target <staging cluster>` — the staging cluster is listed under "Environments" below.\n5. Announce: `./bin/notify --channel #deploys --message "<what you deployed and where>"`\n\n## Environments\n- staging cluster: `qa-east-7`\n';

  it('the steps block is superseded with new_heading_path, new text and a diff; only the renamed heading is removed', () => {
    const kl = new KronicleLite({ memory: true });
    kl.docs.putDocument({ slug: 'runbook', title: 'R', markdown: v1, actor_id: 'w' });
    const c = kl.orient.getSystemState({ actor_id: 'a', focus: 'pulse' }).cursor;
    kl.docs.putDocument({ slug: 'runbook', title: 'R', markdown: v2, actor_id: 'w' });
    const s = kl.orient.getSystemState({ actor_id: 'a', since_cursor: c, focus: 'retractions' });
    const steps = s.retractions!.find((r) => r.old_text?.includes('Preflight'))!;
    expect(steps).toMatchObject({ kind: 'supersession', new_heading_path: ['Deploy runbook — orders-svc', 'Release procedure'] });
    expect(steps.new_text).toContain('--target <staging cluster>');
    expect(steps.diff).toContain('section: Deploy runbook — orders-svc › [-Steps-]{+Release procedure+}');
    expect(steps.diff).toContain('stg-west-3');
    expect(steps.reason_line).toMatch(/MOVED to runbook › Deploy runbook — orders-svc › Release procedure/);
    expect(s.retractions!.filter((r) => r.kind === 'tombstone').map((r) => r.old_text)).toEqual(['Steps']);
    kl.close();
  });

  it('an unrelated block under another section is not paired', () => {
    const kl = new KronicleLite({ memory: true });
    kl.docs.putDocument({ slug: 'r', title: 'R', markdown: '# R\n\n## A\n\nDrop the staging database nightly.\n', actor_id: 'w' });
    const c = kl.orient.getSystemState({ actor_id: 'a', focus: 'pulse' }).cursor;
    kl.docs.putDocument({ slug: 'r', title: 'R', markdown: '# R\n\n## B\n\nPage the on-call before a deploy.\n', actor_id: 'w' });
    const s = kl.orient.getSystemState({ actor_id: 'a', since_cursor: c, focus: 'retractions' });
    expect(s.retractions!.map((r) => `${r.kind}:${r.old_text}`).sort()).toEqual(['tombstone:A', 'tombstone:Drop the staging database nightly.']);
    kl.close();
  });
});

describe('L3: staleness cut short by the depth bound or a cycle is not memoized', () => {
  const para = (r: { blocks: { kind: string; block_id: string; content_hash: string }[] }) => r.blocks.find((b) => b.kind === 'paragraph')!;
  const ref = (b: { block_id: string; content_hash: string }) => ({ block_id: b.block_id, content_hash: b.content_hash });

  it('depth: n4 (one hop from a stale note) is stale even when n0 was evaluated first in the same read', () => {
    const kl = new KronicleLite({ memory: true });
    const src = kl.docs.putDocument({ slug: 'src', title: 's', markdown: '# S\n\nDeploy to blue-7.\n', actor_id: 'h' });
    let prev = para(src);
    const ids: string[] = [];
    for (let k = 5; k >= 0; k--) {
      const p = kl.docs.putDocument({ slug: `n${k}`, title: 'n', markdown: `# N${k}\n\nnote ${k}.\n`, actor_id: 'a', derived_from: [ref(prev)], infer_lineage: false });
      ids[k] = p.doc_id;
      prev = para(p);
    }
    kl.docs.supersedeBlock({ block_id: para(src).block_id, new_content: 'Deploy to green-2.', reason: 'x', actor_id: 'h' });
    const memo = new Map();
    expect(kl.lineage.staleness(ids[0]!, memo)).toEqual([]); // 6 hops: beyond the documented depth bound (4)
    for (let k = 1; k <= 5; k++) expect(kl.lineage.staleness(ids[k]!, memo).length, `n${k}`).toBe(1);
    // One recall pass over every note: n1..n5 are never_act.
    const reasons = Object.fromEntries(kl.recall.recall({ query: 'note', top_k: 20 }).hits.map((h) => [h.doc_slug, h.authority_reason]));
    for (let k = 1; k <= 5; k++) expect(reasons[`n${k}`], `n${k}`).toBe('stale_derived');
    kl.close();
  });

  it('cycle: B (derived from A, which is stale) is stale even when A was evaluated first', () => {
    const kl = new KronicleLite({ memory: true });
    const s2 = para(kl.docs.putDocument({ slug: 'src', title: 's', markdown: '# S\n\nPort 8080.\n', actor_id: 'h' }));
    const a = kl.docs.putDocument({ slug: 'a', title: 'a', markdown: '# A\n\nnote a.\n', actor_id: 'x', derived_from: [ref(s2)], infer_lineage: false });
    const b = kl.docs.putDocument({ slug: 'b', title: 'b', markdown: '# B\n\nnote b.\n', actor_id: 'x', derived_from: [ref(para(a))], infer_lineage: false });
    kl.docs.putDocument({ slug: 'a', title: 'a', markdown: '# A\n\nnote a.\n', actor_id: 'x', derived_from: [ref(s2), ref(para(b))], infer_lineage: false });
    kl.docs.supersedeBlock({ block_id: s2.block_id, new_content: 'Port 8081.', reason: 'x', actor_id: 'h' });
    const memo = new Map();
    expect(kl.lineage.staleness(a.doc_id, memo)).toHaveLength(1);
    expect(kl.lineage.staleness(b.doc_id, memo)).toEqual([expect.objectContaining({ via: 'a' })]);
    kl.close();
  });
});

describe('L4: lineage inference starts at the session\'s first orient', () => {
  const RUNBOOK = '# Deploy\n\nDeploys go to the cluster blue-7 first.\n';

  it('recall → orient (presenting the cursor) → write infers the read, with or without the cursor on the write', async () => {
    const kl = new KronicleLite({ memory: true });
    kl.docs.putDocument({ slug: 'deploy', title: 'D', markdown: RUNBOOK, actor_id: 'h' });
    const c1 = kl.orient.getSystemState({ actor_id: 'agent' }).cursor;
    kl.recall.recall({ query: 'deploys cluster', actor_id: 'agent' });
    await new Promise((r) => setTimeout(r, 5));
    const c2 = kl.orient.getSystemState({ actor_id: 'agent', since_cursor: c1 }).cursor;
    await new Promise((r) => setTimeout(r, 5));
    const c3 = kl.orient.getSystemState({ actor_id: 'agent', since_cursor: c2 }).cursor_compact; // compact cursors chain too
    expect(kl.docs.putDocument({ slug: 'n1', title: 'N', markdown: '# N\n\nTarget is blue-7.\n', actor_id: 'agent', cursor: c3 }).lineage).toEqual({ derived_from: 0, derived_from_inferred: 1 });
    expect(kl.docs.putDocument({ slug: 'n2', title: 'N', markdown: '# N\n\nTarget is blue-7.\n', actor_id: 'agent' }).lineage).toEqual({ derived_from: 0, derived_from_inferred: 1 });
    kl.close();
  });

  it('an orient without a cursor starts a new session (earlier reads are not inferred)', async () => {
    const kl = new KronicleLite({ memory: true });
    kl.docs.putDocument({ slug: 'deploy', title: 'D', markdown: RUNBOOK, actor_id: 'h' });
    kl.orient.getSystemState({ actor_id: 'agent' });
    kl.recall.recall({ query: 'deploys cluster', actor_id: 'agent' });
    await new Promise((r) => setTimeout(r, 5));
    const c = kl.orient.getSystemState({ actor_id: 'agent' }).cursor;
    expect(kl.orient.sessionOrigin('agent', c)).toBe(kl.orient.sessionStart('agent', c));
    expect(kl.docs.putDocument({ slug: 'n', title: 'N', markdown: '# N\n\nTarget.\n', actor_id: 'agent', cursor: c }).lineage).toBeUndefined();
    expect(kl.orient.sessionOrigin('nobody')).toBeNull();
    kl.close();
  });
});

describe('L6 / R2-16: a retraction of a long block shows what changed', () => {
  it('r2-diff probe: a 45-line script, change on the last line — diff, old/new text, reason line and pending all show it', () => {
    const kl = new KronicleLite({ memory: true });
    const lines = Array.from({ length: 45 }, (_, i) => `step_${i}: run check --id ${i} --verbose`);
    const v1 = '# Deploy\n\n```sh\n' + lines.join('\n') + '\n./bin/deploy --target staging-a\n```\n';
    kl.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: v1, actor_id: 'ops' });
    kl.recall.recall({ query: 'deploy target', actor_id: 'agent' });
    const c = kl.orient.getSystemState({ actor_id: 'hook', focus: 'pulse' }).cursor;
    kl.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: v1.replace('--target staging-a', '--target prod-eu'), actor_id: 'ops' });
    const r = kl.orient.getSystemState({ actor_id: 'hook', since_cursor: c, focus: 'retractions' }).retractions![0]!;
    expect(r.diff).toContain('[-staging-a-]{+prod-eu+}');
    expect(r.old_text).not.toBe(r.new_text);
    expect(r.old_text).toContain('staging-a');
    expect(r.new_text).toContain('prod-eu');
    expect(r.reason_line).toContain('prod-eu');
    const p = kl.lineage.pending('agent').items[0]!;
    expect(p.diff).toContain('prod-eu');
    expect(p.new_text).toContain('prod-eu');
    kl.close();
  });

  it('a whitespace-only change is never an empty diff', () => {
    expect(wordDiff('Use "a  b" here.', 'Use "a b" here.')).toBe('Use "a[-··-]{+·+}b" here.');
    expect(wordDiff('x\ty', 'x y')).toBe('x[-→-]{+·+}y');
    expect(changeSnippets('a b', 'a b')).toEqual(['a b', 'a b']);
  });

  it('a change at the end of a 600-word block', () => {
    const w = Array.from({ length: 600 }, (_, i) => `w${i}`).join(' ');
    const [o, n] = changeSnippets(`${w} target=a`, `${w} target=b`);
    expect(o.endsWith('target=a')).toBe(true);
    expect(n.endsWith('target=b')).toBe(true);
    expect(o.length).toBeLessThanOrEqual(160);
    const long = Array.from({ length: 600 }, (_, i) => `w${i}`).join(' ');
    expect(wordDiff(`${long} target=a`, `${long} target=b`)).toBe('…w596 w597 w598 w599 [-target=a-]{+target=b+}');
  });

  it('a changed region still longer than the LCS bound shows its start, with context', () => {
    const a = Array.from({ length: 900 }, (_, i) => `a${i}`);
    const b = [...a.slice(0, 100), ...Array.from({ length: 700 }, (_, i) => `b${i}`), ...a.slice(800)];
    const d = wordDiff(a.join(' '), b.join(' '));
    expect(d.startsWith('…a96 a97 a98 a99 [-a100 a101')).toBe(true);
    expect(d).toContain('{+b0 b1 b2');
    expect(d.length).toBeLessThanOrEqual(400);
  });

  it('short diffs are unchanged', () => {
    expect(wordDiff('Deploy to stg-west-2 first.', 'Deploy to stg-east-1 first.')).toBe('Deploy to [-stg-west-2-]{+stg-east-1+} first.');
  });
});
