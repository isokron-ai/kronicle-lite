/**
 * KL-6 (dogfood): agent-a orients, agent-b re-puts the same document, agent-a then puts with its
 * stale cursor. The drift banner's volume thresholds were not crossed (4 events), so the write
 * got `advisory: false` and agent-b's change was overwritten silently. Another actor's change to
 * the very document being written, after the writer's cursor, now always raises the advisory.
 */
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { KronicleLite } from '../src/index.js';
import { CLI, cleanEnv, tempDir } from './helpers/fs.js';

describe('stale-write advisory: a lost update on the target document', () => {
  it('put by agent-a with a cursor taken before agent-b changed the same document: advisory with who and where', () => {
    const kl = new KronicleLite({ memory: true });
    kl.docs.putDocument({ slug: 'shared', title: 'S', markdown: '# S\n\nport 8080\n', actor_id: 'agent-b' });
    const a = kl.orient.getSystemState({ actor_id: 'agent-a' });
    kl.docs.putDocument({ slug: 'shared', title: 'S', markdown: '# S\n\nport 9090\n', actor_id: 'agent-b' });
    const doc = kl.docs.getDocument('shared')!;
    const adv = kl.orient.staleWriteAdvisory('agent-a', a.cursor, new Date(), { doc_id: doc.doc_id, slug: 'shared' });
    expect(adv.advisory).toBe(true);
    expect(adv.line).toMatch(/shared was changed by agent-b at seq \d+/);
    // the drift volume alone does not fire here (that was the bug)
    expect(kl.orient.staleWriteAdvisory('agent-a', a.cursor).advisory).toBe(false);
    // the writer's own later edits are not a lost update
    const b = kl.orient.getSystemState({ actor_id: 'agent-b' });
    kl.docs.putDocument({ slug: 'shared', title: 'S', markdown: '# S\n\nport 9091\n', actor_id: 'agent-b' });
    expect(kl.orient.staleWriteAdvisory('agent-b', b.cursor, new Date(), { doc_id: doc.doc_id, slug: 'shared' }).advisory).toBe(false);
    // an untouched document: no advisory
    kl.docs.putDocument({ slug: 'other', title: 'O', markdown: '# O\n\nx\n', actor_id: 'agent-b' });
    const fresh = kl.orient.getSystemState({ actor_id: 'agent-a' });
    expect(kl.orient.staleWriteAdvisory('agent-a', fresh.cursor, new Date(), { doc_id: doc.doc_id, slug: 'shared' }).advisory).toBe(false);
    kl.close();
  });

  it('CLI put --cursor prints the advisory on stderr', () => {
    const dir = tempDir('kl-kl6-');
    const env = cleanEnv({ HOME: dir, USERPROFILE: dir });
    const data = join(dir, 'd');
    const f = join(dir, 'f.md');
    const run = (args: string[]) => spawnSync(process.execPath, [CLI, ...args, '--data-dir', data], { env, encoding: 'utf8' });
    writeFileSync(f, '# S\n\nport 8080\n');
    expect(run(['put', 'shared', f, '--actor', 'agent-b']).status).toBe(0);
    const o = run(['orient', '--actor', 'agent-a', '--json']);
    const cursor = (JSON.parse(o.stdout) as { cursor: string }).cursor;
    writeFileSync(f, '# S\n\nport 9090\n');
    expect(run(['put', 'shared', f, '--actor', 'agent-b']).status).toBe(0);
    writeFileSync(f, '# S\n\nport 7070\n');
    const r = run(['put', 'shared', f, '--actor', 'agent-a', '--cursor', cursor]);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stderr).toMatch(/advisory: Write accepted, but shared was changed by agent-b/);
  });
});
