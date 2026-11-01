/**
 * `kronicle-lite demo`: the stale-runbook story end to end, in a temp dir,
 * with no LLM and no network. It drives the same store the MCP server uses
 * and prints what an agent (and a human watching) would see:
 *
 *   1. a runbook goes in;  2. an agent orients and recalls it (signed receipt);
 *   3. the runbook changes behind the agent's back;
 *   4. the agent orients again: a retraction with the old → new words, and
 *      its receipt now verifies SUPERSEDED;
 *   5. someone edits the database directly: recall withholds the text,
 *      verify says UNVERIFIED, verify-chain fails, orient raises an
 *      integrity banner;  6. rebuild from the chain repairs it;
 *   7. an edit to the chain itself is caught at its seq.
 *
 * Every step is also checked; the exit code is 1 if the story did not play
 * out as printed (so the demo doubles as a smoke test of a fresh install).
 */

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Writable } from 'node:stream';

import { describeProjection } from './docs/integrity.js';
import { KronicleLite } from './store.js';

export interface DemoOptions {
  out: Writable;
  /** Directory to work in (kept afterwards). Default: a fresh temp dir, removed at the end. */
  dir?: string;
  keep?: boolean;
}

const RUNBOOK_V1 = `# Deploy runbook

## Deploy target
Deploys go to the staging cluster \`stg-west-2\` first.

## Rollback
Roll back with \`deploy rollback --to previous\`.
`;

export function runDemo(opts: DemoOptions): number {
  const dir = opts.dir ?? mkdtempSync(join(tmpdir(), 'kronicle-lite-demo-'));
  const keep = opts.keep === true || opts.dir !== undefined;
  const dataDir = join(dir, 'data');
  const file = join(dir, 'runbook.md');
  const say = (s = '') => opts.out.write(s + '\n');
  const failures: string[] = [];
  const expect = (cond: boolean, what: string) => {
    if (!cond) failures.push(what);
  };

  say(`kronicle-lite demo: a runbook goes stale under an agent, then someone tampers with the store.`);
  say(`Working in ${dir} (data dir ${dataDir}). No LLM, no network.`);

  const store = new KronicleLite({ dataDir });
  try {
    // 1 ─────────────────────────────────────────────
    say();
    say('1. A runbook goes into the store.');
    writeFileSync(file, RUNBOOK_V1);
    const p1 = store.docs.putDocument({ slug: 'runbook', title: 'Deploy runbook', markdown: RUNBOOK_V1, actor_id: 'human' });
    say(`   $ kronicle-lite put runbook runbook.md`);
    say(`   runbook rev ${p1.revision}: ${p1.blocks.length} block(s); head seq ${p1.head.seq}`);

    // 2 ─────────────────────────────────────────────
    say();
    say('2. An agent orients (cold start) and reads the deploy target.');
    const s1 = store.orient.getSystemState({ actor_id: 'agent' });
    say(`   get_system_state → ${s1.recovery.method}: ${s1.digest?.documents ?? 0} document(s), ${s1.digest?.live_blocks ?? 0} live block(s); cursor ${s1.cursor_compact.slice(0, 24)}…`);
    const r1 = store.recall.recall({ query: 'staging cluster' });
    const hit1 = r1.hits[0];
    expect(hit1?.content.includes('stg-west-2') === true, 'recall finds stg-west-2');
    say(`   recall "staging cluster" → "${hit1?.content ?? '(nothing)'}"`);
    say(`   with a signed receipt (block ${hit1?.block_id.slice(0, 8)}…, chain seq ${hit1?.receipt?.chain_seq})`);

    // 3 ─────────────────────────────────────────────
    say();
    say("3. Someone changes the runbook behind the agent's back.");
    const v2 = RUNBOOK_V1.replace('stg-west-2', 'stg-east-1');
    writeFileSync(file, v2);
    const p2 = store.docs.putDocument({ slug: 'runbook', title: 'Deploy runbook', markdown: v2, actor_id: 'human' });
    say(`   $ sed -i 's/stg-west-2/stg-east-1/' runbook.md && kronicle-lite put runbook runbook.md`);
    say(`   runbook rev ${p2.revision}: ${p2.blocks.filter((b) => b.supersedes).length} block changed; head seq ${p2.head.seq}`);

    // 4 ─────────────────────────────────────────────
    say();
    say('4. The agent orients again with its cursor, before deploying.');
    const s2 = store.orient.getSystemState({ actor_id: 'agent', since_cursor: s1.cursor_compact, focus: 'retractions' });
    const rets = s2.retractions ?? [];
    expect(rets.length === 1 && rets[0]!.diff !== null, 'one retraction with a diff');
    say(`   Retractions (${rets.length}): reconcile before acting`);
    for (const r of rets) {
      say(`   - [${r.severity}] seq ${r.seq}: ${r.reason_line}`);
      if (r.diff) say(`     changed: ${r.diff}`);
    }
    const v = hit1?.receipt ? store.verifier.verify(hit1.receipt) : null;
    expect(v?.status === 'SUPERSEDED', 'old receipt verifies SUPERSEDED');
    say(`   verify(old receipt) → ${v?.status} (${v?.reason}); current block ${v?.current_block_id?.slice(0, 8)}…`);

    // 5 ─────────────────────────────────────────────
    say();
    say('5. Someone edits the database file directly, not through kronicle-lite.');
    const live = store.recall.recall({ query: 'staging cluster' }).hits[0];
    store.db.prepare(`UPDATE blocks SET content = replace(content, 'stg-east-1', 'prod-db-1') WHERE block_id = ?`).run(live?.block_id ?? '');
    say(`   sqlite> UPDATE blocks SET content = replace(content, 'stg-east-1', 'prod-db-1') …`);
    const r3 = store.recall.recall({ query: 'staging cluster' });
    expect(r3.hits.length === 0 && r3.withheld.length === 1, 'tampered block withheld from recall');
    say(`   recall "staging cluster" → ${r3.hits.length} hit(s); withheld ${r3.withheld.map((w) => `${w.block_id.slice(0, 8)}… (${w.problem})`).join(', ')}`);
    const v3 = live?.receipt ? store.verifier.verify(live.receipt) : null;
    expect(v3?.status === 'UNVERIFIED' && v3.reason === 'content_tampered', 'receipt UNVERIFIED/content_tampered');
    say(`   verify(receipt) → ${v3?.status} (${v3?.reason})`);
    const vc = store.verifyAll();
    expect(!vc.ok && vc.projection?.ok === false, 'verify-chain fails on the projection');
    say(`   $ kronicle-lite verify-chain → exit ${vc.ok ? 0 : 1}: chain ${vc.first_mismatch ? 'broken' : 'intact'}; ${vc.projection ? describeProjection(vc.projection) : ''}`);
    const s3 = store.orient.getSystemState({ actor_id: 'agent', focus: 'retractions' });
    expect(s3.integrity?.ok === false, 'orient raises the integrity banner');
    say(`   get_system_state → INTEGRITY FAILURE: ${s3.integrity?.problem}`);

    // 6 ─────────────────────────────────────────────
    say();
    say('6. The chain is intact, so the store can be rebuilt from it.');
    const rb = store.rebuild();
    expect(rb.after.ok, 'rebuild repairs the projection');
    const r4 = store.recall.recall({ query: 'staging cluster' }).hits[0];
    const v4 = r4?.receipt ? store.verifier.verify(r4.receipt) : null;
    expect(r4?.content.includes('stg-east-1') === true && v4?.status === 'VERIFIED', 'recall serves the chained text again');
    say(`   $ kronicle-lite rebuild → replayed ${rb.events} event(s); ${describeProjection(rb.after)}`);
    say(`   recall → "${r4?.content}" → verify ${v4?.status}`);

    // 7 ─────────────────────────────────────────────
    say();
    say('7. Editing the chain itself is caught at the exact event.');
    store.db.prepare(`UPDATE events SET payload_canonical = replace(payload_canonical, 'stg-west-2', 'stg-west-9') WHERE seq = 1`).run();
    const vc2 = store.chain.verify();
    expect(!vc2.ok && vc2.first_mismatch?.seq === 1, 'chain edit caught at seq 1');
    say(`   sqlite> UPDATE events SET payload_canonical = … WHERE seq = 1`);
    say(`   $ kronicle-lite verify-chain → exit 1: ${vc2.first_mismatch?.kind} at seq ${vc2.first_mismatch?.seq}`);
  } finally {
    store.close();
  }

  say();
  if (failures.length > 0) {
    say(`demo FAILED: ${failures.join('; ')}`);
  } else {
    say('Done. The agent was told what changed, in words, before it acted on the old cluster; and text that no longer');
    say('matches the chain was never served as verified.');
  }
  if (keep) say(`Kept ${dir}; try: kronicle-lite orient --data-dir ${dataDir} --actor agent`);
  else rmSync(dir, { recursive: true, force: true });
  return failures.length > 0 ? 1 : 0;
}
