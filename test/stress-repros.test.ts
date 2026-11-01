/**
 * agent-memory-bench `stress` findings, as tests:
 *   section-move.mjs — a paragraph moved byte-identical from "## Allowed" to
 *     "## Forbidden" must be a retraction, and the old receipt must stop
 *     verifying as current;
 *   tamper-json.sh — one non-JSON events.payload_canonical must not crash
 *     orient / get_system_state / verify-chain: integrity {ok:false, seq}.
 */

import { join } from 'node:path';

import Database from 'better-sqlite3';
import { describe, expect, it } from 'vitest';

import { renderSystemStateMarkdown } from '../src/server.js';
import { KronicleLite } from '../src/store.js';
import { cleanEnv, runCli, tempDir, write } from './helpers/fs.js';

describe('section move is a change of meaning', () => {
  const v1 = '# Ops policy\n\n## Allowed\n\nRestart the web tier.\n\nForce-push to the release branch.\n\n## Forbidden\n\nDrop production tables.\n';
  const v2 = '# Ops policy\n\n## Allowed\n\nRestart the web tier.\n\n## Forbidden\n\nDrop production tables.\n\nForce-push to the release branch.\n';

  it('retraction with old/new section; old receipt SUPERSEDED; recall shows the new section', () => {
    const kl = new KronicleLite({ memory: true });
    kl.docs.putDocument({ slug: 'policy', title: 'Ops policy', markdown: v1, actor_id: 'w' });
    const c0 = kl.orient.getSystemState({ actor_id: 'agent', focus: 'pulse' }).cursor;
    const hit = kl.recall.recall({ query: 'force push release branch', actor_id: 'agent' }).hits[0]!;
    expect(hit.heading_path).toEqual(['Ops policy', 'Allowed']);
    kl.docs.putDocument({ slug: 'policy', title: 'Ops policy', markdown: v2, actor_id: 'w' });
    const s = kl.orient.getSystemState({ actor_id: 'agent', since_cursor: c0, focus: 'retractions' });
    expect(s.retractions).toEqual([
      expect.objectContaining({ kind: 'supersession', heading_path: ['Ops policy', 'Allowed'], new_heading_path: ['Ops policy', 'Forbidden'], format_only: false }),
    ]);
    expect(s.retractions![0]!.diff).toContain('[-Allowed-]{+Forbidden+}');
    expect(s.retractions![0]!.reason_line).toMatch(/MOVED to policy › Ops policy › Forbidden/);
    expect(kl.verifier.verify(hit.receipt).status).toBe('SUPERSEDED');
    expect(kl.recall.recall({ query: 'force push release branch' }).hits[0]!.heading_path).toEqual(['Ops policy', 'Forbidden']);
  });

  it('a heading re-level or rename moves the blocks under it; a whole-section reorder does not', () => {
    const kl = new KronicleLite({ memory: true });
    const doc = (h1: string, order: [string, string]) => `# Runbook\n\n${order.map((k) => (k === 'a' ? `${h1}\n\nStep A.\n` : '## B\n\nStep B.\n')).join('\n')}`;
    kl.docs.putDocument({ slug: 'r', title: 'r', markdown: doc('## A', ['a', 'b']), actor_id: 'w' });
    let c = kl.orient.getSystemState({ actor_id: 'x', focus: 'pulse' }).cursor;
    kl.docs.putDocument({ slug: 'r', title: 'r', markdown: doc('## A', ['b', 'a']), actor_id: 'w' });
    expect(kl.orient.getSystemState({ actor_id: 'x', since_cursor: c, focus: 'retractions' }).retractions).toEqual([]);
    c = kl.orient.getSystemState({ actor_id: 'x', focus: 'pulse' }).cursor;
    kl.docs.putDocument({ slug: 'r', title: 'r', markdown: doc('# A', ['b', 'a']), actor_id: 'w' });
    const s = kl.orient.getSystemState({ actor_id: 'x', since_cursor: c, focus: 'retractions' });
    expect(s.retractions!.map((r) => r.old_text).sort()).toEqual(['A', 'Step A.']);
  });
});

describe('a corrupt event payload never crashes orient', () => {
  it('library: integrity {ok:false, seq} on every focus, real retractions still served; verify-chain reports the seq', () => {
    const dir = tempDir('kl-badjson-');
    const kl = new KronicleLite({ dataDir: dir });
    kl.docs.putDocument({ slug: 'runbook', title: 'R', markdown: '# Runbook\n\n## Deploy\n\nDeploy to stg-west-2.\n', actor_id: 'w' });
    const c0 = kl.orient.getSystemState({ actor_id: 'hook', focus: 'pulse' }).cursor;
    kl.docs.putDocument({ slug: 'runbook', title: 'R', markdown: '# Runbook\n\n## Deploy\n\nDeploy to stg-east-1.\n', actor_id: 'w' });
    const db = new Database(join(dir, 'kronicle-lite.db'));
    const row = db.prepare(`SELECT seq, payload_canonical p FROM events WHERE payload_canonical LIKE '%stg-east-1%' ORDER BY seq DESC LIMIT 1`).get() as { seq: number; p: string };
    db.prepare('UPDATE events SET payload_canonical = ? WHERE seq = ?').run(row.p.slice(0, -1), row.seq);
    db.close();
    for (const focus of ['retractions', 'pulse', 'orientation', 'recent_changes'] as const) {
      const s = kl.orient.getSystemState({ actor_id: 'hook', since_cursor: c0, focus });
      expect(s.integrity, focus).toMatchObject({ ok: false, seq: row.seq });
      expect(renderSystemStateMarkdown(s)).toMatch(/INTEGRITY FAILURE/);
      if (focus === 'retractions') expect(s.retractions!.length).toBe(1);
    }
    const v = kl.verifyAll();
    expect(v.ok).toBe(false);
    expect(v.first_mismatch).toMatchObject({ seq: row.seq, kind: 'payload_unparseable' });
    kl.close();
  });

  it('CLI: orient exits 0 with integrity.ok false; verify-chain exits 1 naming the seq', async () => {
    const dir = tempDir('kl-badjson-cli-');
    const data = join(dir, 'data');
    write(join(dir, 'r.md'), '# Runbook\n\nDeploy to stg-east-1.\n');
    const env = cleanEnv();
    expect((await runCli(['put', 'runbook', join(dir, 'r.md'), '--data-dir', data, '--cwd', dir], { env, cwd: dir })).status).toBe(0);
    const db = new Database(join(data, 'kronicle-lite.db'));
    db.prepare(`UPDATE events SET payload_canonical = substr(payload_canonical, 1, length(payload_canonical) - 1) WHERE seq = 2`).run();
    db.close();
    const o = await runCli(['orient', '--data-dir', data, '--actor', 'push-hook', '--json', '--cwd', dir, '--focus', 'retractions'], { env, cwd: dir });
    expect(o.status, o.stderr).toBe(0);
    expect(JSON.parse(o.stdout).integrity).toMatchObject({ ok: false, seq: 2 });
    const v = await runCli(['verify-chain', '--data-dir', data], { env, cwd: dir });
    expect(v.status).toBe(1);
    expect(JSON.parse(v.stdout).first_mismatch).toMatchObject({ seq: 2, kind: 'payload_unparseable' });
  });
});
