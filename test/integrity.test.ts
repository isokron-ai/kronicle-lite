/**
 * 0.5.0 projection integrity (audit B4): an edit to the `blocks` /
 * `document_revisions` tables, made outside kronicle-lite, must never be
 * served as verified text. One tamper test per read path: recall, verify
 * (receipt), verify-chain / verify (CLI + MCP), doctor, the document
 * resource, orient; plus rebuild, the retraction text diff, first-run
 * hygiene and `kronicle-lite demo`.
 */

import { Client, InMemoryTransport } from '@modelcontextprotocol/client';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import { runDoctor } from '../src/doctor.js';
import { blake3Hex } from '../src/crypto/hash.js';
import { verifyProjection } from '../src/docs/integrity.js';
import { wordDiff } from '../src/orient/textdiff.js';
import { createServerFactory, renderSystemStateMarkdown } from '../src/server.js';
import { KronicleLite } from '../src/store.js';
import { cleanEnv, runCli, tempDir, write } from './helpers/fs.js';

const RUNBOOK = '# Deploy runbook\n\n## Deploy target\nDeploys go to the staging cluster `stg-west-2` first.\n\n## Canary\nThe canary cluster is `can-1`.\n';

/** The audit's B4 repro: put, recall (receipt), then UPDATE blocks.content and rebuild FTS so search still finds it. */
function tampered(opts: { dataDir?: string; alsoHash?: boolean } = {}) {
  const store = new KronicleLite(opts.dataDir ? { dataDir: opts.dataDir } : { memory: true });
  store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: RUNBOOK, actor_id: 'human' });
  const hit = store.recall.recall({ query: 'canary cluster' }).hits[0]!;
  expect(store.verifier.verify(hit.receipt).status).toBe('VERIFIED');
  const evil = hit.content.replace('can-1', 'prod-db-DROP');
  if (opts.alsoHash) {
    // A careful editor also fixes the row's own hash: only the chain disagrees now.
    store.db.prepare(`UPDATE blocks SET content = ?, content_hash = ? WHERE block_id = ?`).run(evil, blake3Hex(evil), hit.block_id);
  } else {
    store.db.prepare(`UPDATE blocks SET content = ? WHERE block_id = ?`).run(evil, hit.block_id);
  }
  store.db.prepare(`INSERT INTO blocks_fts(blocks_fts) VALUES('rebuild')`).run();
  return { store, hit };
}

describe('recall re-hashes what it serves', () => {
  it('withholds a block whose text was edited in the table (no content, no receipt)', () => {
    const { store, hit } = tampered();
    const r = store.recall.recall({ query: 'canary cluster' });
    expect(r.hits.map((h) => h.content).join('\n')).not.toContain('prod-db-DROP');
    expect(r.withheld).toEqual([{ block_id: hit.block_id, doc_slug: 'runbook', problem: 'content_hash_mismatch', authority: 'never_act', authority_reason: 'integrity_failed' }]);
    expect(store.db.prepare(`SELECT COUNT(*) n FROM receipts WHERE block_id = ?`).get(hit.block_id)).toEqual({ n: 1 }); // only the pre-tamper one
    store.close();
  });

  it('also when the row hash was fixed up to match: the chained block.created event disagrees', () => {
    const { store } = tampered({ alsoHash: true });
    const r = store.recall.recall({ query: 'prod db drop' });
    expect(r.hits).toEqual([]);
    expect(r.withheld.map((w) => w.problem)).toEqual(['chain_event_mismatch']);
    store.close();
  });
});

describe('verify(receipt) re-hashes', () => {
  it('UNVERIFIED / content_tampered for a receipt over a tampered block', () => {
    for (const alsoHash of [false, true]) {
      const { store, hit } = tampered({ alsoHash });
      const v = store.verifier.verify(hit.receipt);
      expect(v).toMatchObject({ status: 'UNVERIFIED', reason: 'content_tampered' });
      expect(v.integrity_problem).toBe(alsoHash ? 'chain_event_mismatch' : 'content_hash_mismatch');
      store.close();
    }
  });

  it('UNVERIFIED / projection_mismatch when a superseded block is made to look live again', () => {
    const store = new KronicleLite({ memory: true });
    store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: RUNBOOK, actor_id: 'h' });
    const old = store.recall.recall({ query: 'staging cluster' }).hits[0]!;
    store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: RUNBOOK.replace('stg-west-2', 'stg-east-1'), actor_id: 'h' });
    expect(store.verifier.verify(old.receipt).status).toBe('SUPERSEDED');
    store.db.prepare(`UPDATE blocks SET valid_to = NULL, superseded_by = NULL WHERE block_id = ?`).run(old.block_id);
    expect(store.verifier.verify(old.receipt)).toMatchObject({ status: 'UNVERIFIED', reason: 'projection_mismatch' });
    store.close();
  });
});

describe('verify-chain / verify / doctor re-derive the projection', () => {
  it('KronicleLite.verifyAll and verifyProjection: ok on a clean store, mismatch on content, lifecycle, extra and missing rows', () => {
    const { store, hit } = tampered();
    const r = store.verifyAll();
    expect(r.first_mismatch).toBeNull(); // the events are intact…
    expect(r.ok).toBe(false); // …but what the agent reads is not
    expect(r.projection!.mismatches).toContainEqual(expect.objectContaining({ table: 'blocks', key: hit.block_id, field: 'content' }));
    expect(r.projection!.mismatches).toContainEqual(expect.objectContaining({ table: 'blocks', key: hit.block_id, field: 'content_hash' }));
    // A range check is the chain only, unless asked.
    expect(store.verifyAll(1, 2).projection).toBeNull();
    expect(store.verifyAll(1, 2, { projection: true }).projection!.ok).toBe(false);

    const clean = new KronicleLite({ memory: true });
    clean.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: RUNBOOK, actor_id: 'h' });
    expect(clean.verifyAll()).toMatchObject({ ok: true, projection: { ok: true, mismatch_count: 0 } });
    const b = clean.docs.liveBlockRows(1)[0]!;
    clean.db.prepare(`UPDATE blocks SET tombstoned_at = '2026-01-01T00:00:00.000Z' WHERE block_id = ?`).run(b.block_id);
    expect(verifyProjection(clean.db, clean.chain).mismatches[0]).toMatchObject({ table: 'blocks', field: 'tombstoned_at' });
    clean.db.prepare(`DELETE FROM blocks_fts`).run();
    clean.db.exec(`DROP TRIGGER blocks_ad`);
    clean.db.prepare(`DELETE FROM blocks WHERE block_id = ?`).run(b.block_id);
    expect(verifyProjection(clean.db, clean.chain).mismatches).toContainEqual(expect.objectContaining({ key: b.block_id, field: 'missing' }));
    clean.close();
    store.close();
  });

  it('CLI verify-chain and verify exit 1 with a projection line; doctor fails the projection check', async () => {
    const dataDir = join(tempDir('kl-int-'), 'd');
    tampered({ dataDir }).store.close();
    for (const cmd of [['verify-chain'], ['verify'], ['verify-chain', '--full', '--from', '1', '--to', '2']]) {
      const r = await runCli([...cmd, '--data-dir', dataDir]);
      expect(r.status, cmd.join(' ')).toBe(1);
      expect(r.stderr).toMatch(/projection: \d+ projection mismatch\(es\) vs the chain; first: blocks .* content/);
      expect(JSON.parse(r.stdout)).toMatchObject({ ok: false, first_mismatch: null, projection: { ok: false } });
    }
    const d = await runDoctor({ dataDir, home: tempDir('kl-h-'), cwd: tempDir('kl-c-'), env: {}, network: false });
    expect(d.ok).toBe(false);
    expect(d.checks.find((c) => c.id === 'chain')!.status).toBe('ok');
    expect(d.checks.find((c) => c.id === 'projection')).toMatchObject({ status: 'fail', detail: expect.stringMatching(/projection mismatch/) });
  });

  it('rebuild re-derives the tables from a verified chain, and refuses a broken one', async () => {
    const dataDir = join(tempDir('kl-int-'), 'd');
    tampered({ dataDir }).store.close();
    const r = await runCli(['rebuild', '--data-dir', dataDir]);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toMatch(/before: \d+ projection mismatch.*after: projection matches the chain/);
    expect((await runCli(['verify-chain', '--data-dir', dataDir])).status).toBe(0);
    const store = new KronicleLite({ dataDir });
    const hit = store.recall.recall({ query: 'canary cluster' }).hits[0]!;
    expect(hit.content).toContain('can-1');
    expect(store.verifier.verify(hit.receipt).status).toBe('VERIFIED');
    store.db.prepare(`UPDATE events SET actor_id = 'mallory' WHERE seq = 2`).run();
    expect(() => store.rebuild()).toThrow(/hash_mismatch at seq 2/);
    store.close();
  });
});

describe('MCP surface', () => {
  it('verify_chain reports the projection; the document resource refuses tampered markdown; orient raises the integrity banner', async () => {
    const { store } = tampered();
    const doc = store.docs.getDocument('runbook')!;
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const handle = serveStdio(createServerFactory(store), { transport: st });
    const client = new Client({ name: 't', version: '0' }, { versionNegotiation: { mode: { pin: '2026-07-28' } } });
    await client.connect(ct);
    const vc = (await client.callTool({ name: 'verify_chain', arguments: {} })).structuredContent as { ok: boolean; projection: { ok: boolean } };
    expect(vc).toMatchObject({ ok: false, projection: { ok: false } });

    const before = await client.readResource({ uri: 'kronicle://docs/runbook' });
    expect((before.contents[0] as { text: string }).text).toContain('can-1');
    store.db.prepare(`UPDATE document_revisions SET markdown = replace(markdown, 'can-1', 'prod-db-DROP') WHERE doc_id = ?`).run(doc.doc_id);
    await expect(client.readResource({ uri: 'kronicle://docs/runbook' })).rejects.toThrow(/integrity failure \(content_hash_mismatch\)/);

    const s = (await client.callTool({ name: 'get_system_state', arguments: { actor_id: 'agent' } })) as { content: { text: string }[]; structuredContent: { integrity: { ok: boolean; problem: string } } };
    expect(s.structuredContent.integrity).toMatchObject({ ok: false, problem: expect.stringMatching(/content_hash_mismatch/) });
    expect(s.content[0]!.text).toMatch(/INTEGRITY FAILURE/);
    await client.close();
    await handle.close();
    store.close();
  });

  it('orient on an edited events table (inside the window) raises the banner too', () => {
    const store = new KronicleLite({ memory: true });
    store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: RUNBOOK, actor_id: 'h' });
    expect(store.orient.getSystemState({ actor_id: 'a' }).integrity).toMatchObject({ ok: true, problem: null });
    store.db.prepare(`UPDATE events SET actor_id = 'mallory' WHERE seq = 1`).run();
    const s = store.orient.getSystemState({ actor_id: 'b' });
    expect(s.integrity).toMatchObject({ ok: false, problem: 'chain hash_mismatch at seq 1' });
    expect(s.next_steps[0]).toMatch(/^INTEGRITY FAILURE/);
    expect(store.orient.getSystemState({ actor_id: 'b', focus: 'pulse' }).integrity).toBeNull();
    store.close();
  });
});

describe('retractions say what changed, in words (G3)', () => {
  it('word diff: changed words marked, long unchanged runs elided, bounded', () => {
    expect(wordDiff('Deploys go to the staging cluster `stg-west-2` first.', 'Deploys go to the staging cluster `stg-east-1` first.')).toBe(
      'Deploys go to the staging cluster [-`stg-west-2`-]{+`stg-east-1`+} first.',
    );
    const long = Array.from({ length: 40 }, (_, i) => `w${i}`).join(' ');
    const d = wordDiff(long, long.replace('w20', 'X'));
    expect(d).toBe('…w16 w17 w18 w19 [-w20-]{+X+} w21 w22 w23 w24…');
    expect(wordDiff('a '.repeat(2000), 'b '.repeat(2000)).length).toBeLessThanOrEqual(400);
  });

  it('get_system_state: supersession → old/new text + diff; tombstone → removed text; markdown shows both', () => {
    const store = new KronicleLite({ memory: true });
    store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: RUNBOOK, actor_id: 'h' });
    const cold = store.orient.getSystemState({ actor_id: 'a' });
    store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: RUNBOOK.replace('stg-west-2', 'stg-east-1').replace(/## Canary[\s\S]*$/, ''), actor_id: 'h' });
    const s = store.orient.getSystemState({ actor_id: 'a', since_cursor: cold.cursor, focus: 'retractions' });
    const sup = s.retractions!.find((r) => r.kind === 'supersession')!;
    expect(sup).toMatchObject({
      heading_path: ['Deploy runbook', 'Deploy target'],
      old_text: 'Deploys go to the staging cluster `stg-west-2` first.',
      new_text: 'Deploys go to the staging cluster `stg-east-1` first.',
      diff: 'Deploys go to the staging cluster [-`stg-west-2`-]{+`stg-east-1`+} first.',
    });
    expect(sup.reason_line).toBe(
      `You previously relied on "Deploys go to the staging cluster \`stg-west-2\` first." (runbook › Deploy runbook › Deploy target); current truth is "Deploys go to the staging cluster \`stg-east-1\` first." (seq ${sup.seq}). Reconcile before proceeding.`,
    );
    const tomb = s.retractions!.filter((r) => r.kind === 'tombstone');
    expect(tomb.map((t) => t.old_text)).toEqual(['Canary', 'The canary cluster is `can-1`.']);
    expect(tomb.every((t) => t.new_text === null && t.diff === null && t.severity === 'safety')).toBe(true);
    const md = renderSystemStateMarkdown(s);
    expect(md).toContain('changed: Deploys go to the staging cluster [-`stg-west-2`-]{+`stg-east-1`+} first.');
    expect(md).toContain('removed: The canary cluster is `can-1`.');
    expect(md).not.toMatch(/never anchored/);
    store.close();
  });
});

describe('first run', () => {
  it('a put of a missing file fails without creating the data dir or a signing key', async () => {
    const dataDir = join(tempDir('kl-first-'), 'fresh');
    const r = await runCli(['put', 'runbook', join(dataDir, '..', 'nope.md'), '--data-dir', dataDir]);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/cannot read .*nope\.md: ENOENT/);
    expect(existsSync(dataDir)).toBe(false);
    const bad = await runCli(['put', 'Bad Slug', join(dataDir, '..', 'nope.md'), '--data-dir', dataDir]);
    expect(bad.status).toBe(1);
    expect(existsSync(dataDir)).toBe(false);
  });

  it('the README tour runs verbatim in an empty directory with a fresh HOME', async () => {
    const cwd = tempDir('kl-tour-');
    const home = tempDir('kl-tour-home-');
    const env = cleanEnv({ HOME: home, USERPROFILE: home });
    const run = (args: string[]) => runCli(args, { env, cwd });
    // Lines of the README "Sixty-second tour" block, in order (shell-free equivalents).
    write(join(cwd, 'runbook.md'), '# Deploy runbook\n\n## Deploy target\nDeploys go to the staging cluster `stg-west-2` first.\n');
    const put = await run(['put', 'runbook', 'runbook.md', '--title', 'Runbook']);
    expect(put.status, put.stderr).toBe(0);
    expect(put.stdout).toMatch(/^runbook rev 1: 3 new, 0 changed, 0 removed, 0 unchanged block\(s\); head seq 4\n$/);
    const o1 = await run(['orient', '--actor', 'me', '--json']);
    const cursor = (JSON.parse(o1.stdout) as { cursor_compact: string }).cursor_compact;
    write(join(cwd, 'runbook.md'), '# Deploy runbook\n\n## Deploy target\nDeploys go to the staging cluster `stg-east-1` first.\n');
    expect((await run(['put', 'runbook', 'runbook.md', '--title', 'Runbook'])).stdout).toMatch(/rev 2: 0 new, 1 changed/);
    const o2 = await run(['orient', '--actor', 'me', '--cursor', cursor, '--focus', 'retractions']);
    expect(o2.stdout).toContain('changed: Deploys go to the staging cluster [-`stg-west-2`-]{+`stg-east-1`+} first.');
    expect(o2.stdout).not.toMatch(/anchor/);
    expect((await run(['verify-chain'])).status).toBe(0);
    expect((await run(['checkpoint'])).status).toBe(0);
    expect((await run(['export', '--out', 'events.jsonl'])).status).toBe(0);
    expect((await run(['import', '--data-dir', join(cwd, 'copy'), '--in', 'events.jsonl'])).status).toBe(0);
    expect(existsSync(join(home, '.kronicle-lite', 'kronicle-lite.db'))).toBe(true);
  });

  it('kronicle-lite demo plays the whole story and exits 0', async () => {
    const r = await runCli(['demo']);
    expect(r.status, r.stdout + r.stderr).toBe(0);
    for (const line of [
      /Retractions \(1\)/,
      /changed: Deploys go to the staging cluster \[-`stg-west-2`-\]\{\+`stg-east-1`\+\} first\./,
      /verify\(old receipt\) → SUPERSEDED/,
      /withheld .* \(content_hash_mismatch\)/,
      /verify\(receipt\) → UNVERIFIED \(content_tampered\)/,
      /INTEGRITY FAILURE/,
      /rebuild → replayed \d+ event\(s\); projection matches the chain/,
      // 0.6.0: honest labels
      /refused: secret_detected: aws_access_key \(markdown line \d+\)/,
      /nothing chained \(head seq still \d+\)/,
      /recall "kubernetes namespace" → 0 hit\(s\): absent_in_searched/,
      /not searched: tombstoned_blocks, superseded_blocks/,
      /authority inspect_only \(no_source\)/,
      /hash_mismatch at seq 1/,
    ]) {
      expect(r.stdout).toMatch(line);
    }
    expect(r.stdout).not.toMatch(/demo FAILED/);
  });
});
