/**
 * Hosted anchoring (0.4.0): acceptance suite ported from isokron-anchor
 * client/test/client.test.ts.
 *
 * Backends:
 *   - "stub": test/helpers/anchor-stub.ts, an in-test HTTP server implementing
 *     the same wire contract. Always runs (CI).
 *   - "worker": the real isokron-anchor Worker under Miniflare, when
 *     KRONICLE_ANCHOR_WORKER_DIR points at a checkout with its deps installed:
 *       KRONICLE_ANCHOR_WORKER_DIR=../isokron-anchor npx vitest run test/anchor.test.ts
 *
 * Every remote failure must surface as "anchor service unreachable" and never
 * break local operation; those cases run against closed ports and a non-anchor
 * HTTP server, never the real network.
 */

import { Client, InMemoryTransport } from '@modelcontextprotocol/client';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import Database from 'better-sqlite3';
import canonicalizeModule from 'canonicalize';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough, Readable } from 'node:stream';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { anchorStatus, pushCheckpoint, tryPushCheckpoint, verifyLastAnchor, verifyRemote } from '../src/anchor/anchor.js';
import { AnchorApiError, AnchorClient, AnchorUnreachableError } from '../src/anchor/client.js';
import { DEFAULT_ANCHOR_URL, KEYS_CACHE_FILE, loadConfig } from '../src/anchor/config.js';
import { LEGACY_PINS_FILE } from '../src/anchor/trust.js';
import { anchorReceiptSigningPayload, type AnchorReceipt } from '../src/anchor/receipt.js';
import { GENESIS_HASH } from '../src/chain/genesis.js';
import { verifyEd25519 } from '../src/crypto/keys.js';
import { anchorLine, createServerFactory, renderSystemStateMarkdown } from '../src/server.js';
import { KronicleLite } from '../src/store.js';
import { startAnchorStub, type AnchorBackend } from './helpers/anchor-stub.js';
import { startAnchorWorker } from './helpers/anchor-worker.js';

type CanonicalizeFn = (v: unknown) => string;
const jcs: CanonicalizeFn =
  typeof canonicalizeModule === 'function'
    ? (canonicalizeModule as unknown as CanonicalizeFn)
    : (canonicalizeModule as unknown as { default: CanonicalizeFn }).default;

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const WORKER_DIR = process.env['KRONICLE_ANCHOR_WORKER_DIR'];
const POSIX = process.platform !== 'win32';

/** FORMAT §1.2, written out independently of src/chain/event.ts. */
function eventHash(ev: { seq: number; event_id: string; event_type: string; actor_id: string; occurred_at: string; payload: unknown; nonce: string; prev_hash: string }): string {
  const envelope = jcs({ event_id: ev.event_id, event_type: ev.event_type, actor_id: ev.actor_id, occurred_at: ev.occurred_at, payload: ev.payload });
  return createHash('sha256').update(`${envelope}|${ev.seq}|${ev.prev_hash}|${ev.nonce}`, 'utf8').digest('hex');
}

interface EventRow {
  seq: number;
  event_id: string;
  event_type: string;
  actor_id: string;
  occurred_at: string;
  payload_canonical: string;
  nonce: string;
  prev_hash: string;
  this_hash: string;
}

/** Rewrite event `seq` and re-hash forward — what a box owner holding the key can do (THREAT-MODEL). */
function rewriteChain(db: Database.Database, seq: number, mutate: (p: Record<string, unknown>) => void): void {
  const rows = db.prepare(`SELECT * FROM events WHERE seq >= ? ORDER BY seq`).all(seq) as EventRow[];
  let prev = (db.prepare(`SELECT this_hash FROM events WHERE seq = ?`).get(seq - 1) as { this_hash: string } | undefined)?.this_hash ?? GENESIS_HASH;
  const upd = db.prepare(`UPDATE events SET payload_canonical = ?, prev_hash = ?, this_hash = ? WHERE seq = ?`);
  for (const r of rows) {
    const payload = JSON.parse(r.payload_canonical) as Record<string, unknown>;
    if (r.seq === seq) mutate(payload);
    const this_hash = eventHash({ ...r, payload, prev_hash: prev });
    upd.run(jcs(payload), prev, this_hash, r.seq);
    prev = this_hash;
  }
  db.prepare(`UPDATE chain_head SET seq = ?, hash = ? WHERE id = 1`).run(rows[rows.length - 1]!.seq, prev);
}

function makeStore(docs = 2): { dataDir: string; store: KronicleLite } {
  const dataDir = join(mkdtempSync(join(tmpdir(), 'kl-anchor-')), 'data');
  const store = new KronicleLite({ dataDir });
  for (let i = 1; i <= docs; i++) {
    store.docs.putDocument({
      slug: `doc-${i}`,
      title: `Doc ${i}`,
      markdown: `# Doc ${i}\n\nParagraph one of document ${i}.\n\nParagraph two of document ${i}.\n`,
      actor_id: 'tester',
    });
  }
  store.chain.checkpoint();
  return { dataDir, store };
}

/** Run the built CLI without blocking the event loop (the stub backend lives in this process). */
function cli(args: string[], env: Record<string, string | undefined> = {}): Promise<{ status: number | null; stdout: string; stderr: string }> {
  const e: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined && !k.startsWith('KRONICLE_ANCHOR_')) e[k] = v;
  for (const [k, v] of Object.entries(env)) if (v !== undefined) e[k] = v;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], { env: e });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8').on('data', (c: string) => (stdout += c));
    child.stderr.setEncoding('utf8').on('data', (c: string) => (stderr += c));
    child.on('error', reject);
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

async function closedPortUrl(): Promise<string> {
  const s = createServer();
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  const addr = s.address();
  const port = typeof addr === 'object' && addr ? addr.port : 9;
  await new Promise<void>((r) => s.close(() => r()));
  return `http://127.0.0.1:${port}`;
}

async function listen(handler: Parameters<typeof createServer>[1]): Promise<{ url: string; server: Server }> {
  const server = createServer(handler);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const addr = server.address();
  return { url: `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`, server };
}

const backends: { name: string; start: () => Promise<AnchorBackend> }[] = [
  { name: 'stub', start: startAnchorStub },
  ...(WORKER_DIR ? [{ name: 'worker', start: () => startAnchorWorker(WORKER_DIR) }] : []),
];

describe('FORMAT §1.2 / §2 reproduce on a 0.4.0 database (guards the anchor root recompute)', () => {
  it('every stored this_hash reproduces independently; rootOver equals the stored checkpoint root', () => {
    const { store } = makeStore(2);
    const rows = store.db.prepare(`SELECT * FROM events ORDER BY seq`).all() as EventRow[];
    expect(rows.length).toBeGreaterThanOrEqual(4);
    for (const r of rows) expect(eventHash({ ...r, payload: JSON.parse(r.payload_canonical) })).toBe(r.this_hash);
    const cp = store.chain.latestCheckpoint()!;
    expect(store.chain.rootOver(cp.from_seq, cp.to_seq)!.root).toBe(cp.root);
    expect(store.chain.rootOver(1, store.chain.head().seq + 1)).toBeNull();
    store.close();
  });
});

describe.each(backends)('anchoring against the $name backend', { timeout: 60_000 }, ({ start }) => {
  let b: AnchorBackend;
  beforeAll(async () => {
    b = await start();
  }, 120_000);
  afterAll(async () => {
    await b?.stop();
  });
  const opts = () => ({ anchorUrl: b.url, licenseKey: b.license, genesis: b.genesis });

  it('push stores the countersigned receipt in `anchors`; the countersignature verifies; chain tables untouched', async () => {
    const { dataDir, store } = makeStore(2);
    const headBefore = store.chain.head();
    const r = await pushCheckpoint(store, opts());
    expect(r).toMatchObject({ duplicate: false, conflict: false, public_status: 'pending_public' });
    expect(r.range[0]).toBe(1);
    expect(r.verify_url).toMatch(/\/v\/[0-9a-f]{64}$/);

    const anchors = store.chain.listAnchors();
    expect(anchors).toHaveLength(1);
    expect(anchors[0]).toMatchObject({ anchor_id: r.anchor_id, checkpoint_id: r.checkpoint_id, root: r.root, status: 'pending_public' });
    const receipt = JSON.parse(anchors[0]!.receipt_json) as AnchorReceipt;
    expect(jcs(receipt)).toBe(anchors[0]!.receipt_json);
    const keys = (await (await fetch(`${b.url}/.well-known/anchor-keys.json`)).json()) as { keys: { public_key_pem: string }[] };
    expect(verifyEd25519(keys.keys[0]!.public_key_pem, anchorReceiptSigningPayload(receipt), receipt.signature)).toBe(true);
    // Not a chain event: head, checkpoints and verify_chain unchanged.
    expect(store.chain.head()).toEqual(headBefore);
    expect(store.chain.listCheckpoints()).toHaveLength(1);
    expect(store.chain.verify().ok).toBe(true);
    // 0.10.0: the key list that chained to the genesis pin is kept (the rollback reference); no pin store
    expect(existsSync(join(dataDir, KEYS_CACHE_FILE))).toBe(true);
    expect(existsSync(join(dataDir, LEGACY_PINS_FILE))).toBe(false);
    store.close();
  });

  it('a second push of the same checkpoint is a duplicate with the same anchor_id', async () => {
    const { store } = makeStore(1);
    const a = await pushCheckpoint(store, opts());
    const c = await pushCheckpoint(store, opts());
    expect(c.duplicate).toBe(true);
    expect(c.anchor_id).toBe(a.anchor_id);
    expect(store.chain.listAnchors()).toHaveLength(1);
    store.close();
  });

  it('a bad license is refused in protocol (AnchorApiError 401); no key at all is refused before any request', async () => {
    const { store } = makeStore(1);
    await expect(pushCheckpoint(store, { anchorUrl: b.url, licenseKey: 'KLA_nope' })).rejects.toBeInstanceOf(AnchorApiError);
    await expect(pushCheckpoint(store, { anchorUrl: b.url })).rejects.toThrow(/no license key/);
    expect(store.chain.listAnchors()).toHaveLength(0);
    store.close();
  });

  it('refuses to push a checkpoint the local chain no longer matches', async () => {
    const { store } = makeStore(1);
    rewriteChain(store.db, 1, (p) => {
      p['title'] = 'rewritten';
    });
    await expect(pushCheckpoint(store, opts())).rejects.toThrow(/local chain no longer matches/);
    store.close();
  });

  it('verify --remote matches an intact chain, including after new events and a second anchor', async () => {
    const { store } = makeStore(2);
    await pushCheckpoint(store, opts());
    const r1 = await verifyRemote(store, opts());
    expect(r1.ok).toBe(true);
    expect(r1.checks).toHaveLength(1);
    expect(r1.checks[0]).toMatchObject({ result: 'match', countersignature: 'ok', source: 'remote' });

    store.docs.putDocument({ slug: 'later', title: 'Later', markdown: '# Later\n\nMore.\n', actor_id: 'tester' });
    store.chain.checkpoint();
    await pushCheckpoint(store, opts());
    const r2 = await verifyRemote(store, opts());
    expect(r2.ok).toBe(true);
    expect(r2.checks.map((c) => c.result)).toEqual(['match', 'match']);
    expect(r2.checks[1]!.to_seq).toBeGreaterThan(r2.checks[0]!.to_seq);
    store.close();
  });

  it('"local chain diverges from anchor at [a,b]" on a rewritten copy that still passes verify_chain; re-pushing is a CONFLICT', async () => {
    const { dataDir, store } = makeStore(2);
    const push = await pushCheckpoint(store, opts());
    const [a, z] = push.range;
    store.close();

    // Attacker with the key: copy the data dir, rewrite event 2, re-hash forward, sign a fresh checkpoint.
    const copyDir = join(dataDir, '..', 'tampered');
    cpSync(dataDir, copyDir, { recursive: true });
    const copy = new KronicleLite({ dataDir: copyDir });
    rewriteChain(copy.db, 2, (p) => {
      p['content'] = 'Use blue/green for the API. (rewritten after the fact)';
    });
    expect(copy.chain.verify(1).first_mismatch).toBeNull(); // every local hash still links
    copy.chain.checkpoint();
    const cps = copy.chain.listCheckpoints();
    expect(cps).toHaveLength(2);
    expect(cps[1]!.root).not.toBe(cps[0]!.root);

    const r = await verifyRemote(copy, opts());
    expect(r.ok).toBe(false);
    expect(r.checks[0]!.result).toBe('diverged');
    expect(r.checks[0]!.local_root).not.toBe(r.checks[0]!.anchored_root);
    expect(r.divergences[0]).toMatch(new RegExp(`^local chain diverges from anchor at \\[${a},${z}\\]`));

    const again = await pushCheckpoint(copy, opts());
    expect(again.conflict).toBe(true);
    expect(again.conflicting_anchor_ids).toEqual([push.anchor_id]);
    const chain = (await new AnchorClient(b.url).chain(r.chain_id))!;
    expect(chain.conflict).toBe(true);
    expect(chain.anchors.filter((x) => x.from_seq === a && x.to_seq === z)).toHaveLength(2);
    expect(copy.chain.lastAnchor()!.status).toBe('conflict');
    copy.close();

    // The honest original still matches its own anchor, sees the remote conflict flag, and fails overall.
    const orig = new KronicleLite({ dataDir });
    const o = await verifyRemote(orig, opts());
    const mine = o.checks.find((c) => c.anchor_id === push.anchor_id)!;
    expect(mine.result).toBe('match');
    expect(mine.conflict_remote).toBe(true);
    expect(o.ok).toBe(false);
    orig.close();
  });

  it('detects a truncated chain (beyond_head) and a silently edited hash (diverged)', async () => {
    const { store } = makeStore(2);
    const push = await pushCheckpoint(store, opts());
    store.db.prepare(`DELETE FROM events WHERE seq = ?`).run(push.range[1]);
    store.db.prepare(`UPDATE chain_head SET seq = seq - 1`).run();
    const r = await verifyRemote(store, opts());
    expect(r.checks[0]!.result).toBe('beyond_head');
    expect(r.ok).toBe(false);
    store.close();

    const two = makeStore(1);
    await pushCheckpoint(two.store, opts());
    two.store.db.prepare(`UPDATE events SET this_hash = ? WHERE seq = 1`).run(createHash('sha256').update('x').digest('hex'));
    const r2 = await verifyRemote(two.store, opts());
    expect(r2.checks[0]!.result).toBe('diverged');
    two.store.close();
  });

  it('--offline re-verifies stored receipts against the key list kept for the service they were pushed to; a tampered stored receipt fails its countersignature', async () => {
    const { store } = makeStore(1);
    await pushCheckpoint(store, opts());
    const dead = await closedPortUrl();
    const r = await verifyRemote(store, { anchorUrl: dead, offline: true });
    expect(r.ok).toBe(true);
    expect(r.checks[0]).toMatchObject({ source: 'local', countersignature: 'ok', result: 'match' });
    store.db.prepare(`UPDATE anchors SET receipt_json = replace(receipt_json, '"tier":"free"', '"tier":"pro"')`).run();
    const bad = await verifyRemote(store, { anchorUrl: dead, offline: true });
    expect(bad.checks[0]!.countersignature).toBe('failed');
    expect(bad.ok).toBe(false);
    store.close();
  });

  it('reports nothing anchored for a fresh chain', async () => {
    const { store } = makeStore(1);
    const r = await verifyRemote(store, opts());
    expect(r.ok).toBe(false);
    expect(r.summary).toMatch(/nothing anchored/);
    store.close();
  });

  it('anchor status: last anchor, events since, verify url; orient banner line', async () => {
    const { store } = makeStore(1);
    expect(anchorStatus(store, opts()).last).toBeNull();
    // 0.5.0: no anchor line at all until something was anchored.
    expect(anchorLine(store.orient.getSystemState({ actor_id: 'a' }))).toBeNull();
    await pushCheckpoint(store, opts());
    store.docs.putDocument({ slug: 'extra', title: 'Extra', markdown: '# Extra\n\nOne more paragraph.\n', actor_id: 'tester' });
    const s = anchorStatus(store, opts());
    expect(s.anchors).toBe(1);
    expect(s.last!.events_since).toBeGreaterThan(0);
    expect(s.head_seq).toBe(s.last!.range[1] + s.last!.events_since);
    expect(s.last!.verify_url).toBe(`${b.url}/v/${s.chain_id}`);
    const state = store.orient.getSystemState({ actor_id: 'a' });
    expect(state.anchor).toMatchObject({ events_since: s.last!.events_since, status: 'pending_public' });
    expect(renderSystemStateMarkdown(state)).toMatch(new RegExp(`> anchored ${s.last!.events_since} events ago \\(pending_public`));
    const v = await verifyLastAnchor(store, { ...opts(), remote: true });
    expect(v).toMatchObject({ result: 'match', countersignature: 'ok', remote: 'checked', remote_conflict: false });
    store.close();
  });

  it('CLI: checkpoint --push → verify --remote → anchor status, exit codes and --json', async () => {
    const { dataDir, store } = makeStore(1);
    store.close();
    const env = { KRONICLE_ANCHOR_URL: b.url, KRONICLE_ANCHOR_KEY: b.license, KRONICLE_ANCHOR_GENESIS: b.genesis };
    const push = await cli(['checkpoint', '--push', '--data-dir', dataDir], env);
    expect(push.status, push.stderr).toBe(0);
    expect(JSON.parse(push.stdout).anchor).toMatchObject({ ok: true, error: null });
    expect(push.stderr).toMatch(/^anchored \[1, \d+\]/);
    const v = await cli(['verify', '--remote', '--data-dir', dataDir, '--json'], env);
    expect(v.status, v.stderr).toBe(0);
    expect(JSON.parse(v.stdout).ok).toBe(true);
    const st = await cli(['anchor', 'status', '--data-dir', dataDir], env);
    expect(st.status).toBe(0);
    expect(st.stdout).toMatch(/last anchor \[1, \d+\] pending_public/);
    // Local-only verify still works without --remote.
    expect((await cli(['verify', '--data-dir', dataDir])).status).toBe(0);

    const db = new Database(join(dataDir, 'kronicle-lite.db'));
    rewriteChain(db, 1, (p) => {
      p['title'] = 'x';
    });
    db.close();
    const bad = await cli(['verify', '--remote', '--data-dir', dataDir, '--url', b.url, '--genesis', b.genesis]);
    expect(bad.status).toBe(1);
    expect(bad.stdout).toMatch(/local chain diverges from anchor at \[1,\d+\]/);
    // without the service's genesis pin the compiled production pin applies: the stub's list does not chain to it
    const prod = await cli(['verify', '--remote', '--data-dir', dataDir, '--url', b.url]);
    expect(prod.status).toBe(1);
    expect(prod.stdout + prod.stderr).toMatch(/does not chain to the genesis pin 3dca1ecf66c2993e/);
    expect((await cli(['anchor', '--data-dir', dataDir])).status).toBe(2);
  });

  it('MCP: checkpoint_chain {push} returns the anchor outcome; anchor_status verifies the last anchor', async () => {
    const { store } = makeStore(1);
    const prevUrl = process.env['KRONICLE_ANCHOR_URL'];
    const prevKey = process.env['KRONICLE_ANCHOR_KEY'];
    process.env['KRONICLE_ANCHOR_URL'] = b.url;
    process.env['KRONICLE_ANCHOR_KEY'] = b.license;
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const handle = serveStdio(createServerFactory(store, { defaultActorId: 'mcp' }), { transport: st });
    const client = new Client({ name: 't', version: '0' }, { versionNegotiation: { mode: { pin: '2026-07-28' } } });
    try {
      await client.connect(ct);
      const r = (await client.callTool({ name: 'checkpoint_chain', arguments: { push: true } })) as { structuredContent: Record<string, unknown>; isError?: boolean };
      expect(r.isError).toBeFalsy();
      expect(r.structuredContent['anchor']).toMatchObject({ ok: true, duplicate: false, conflict: false, error: null });
      const s = (await client.callTool({ name: 'anchor_status', arguments: { remote: true } })) as { structuredContent: Record<string, unknown> };
      expect(s.structuredContent).toMatchObject({ anchors: 1, license_key_configured: true, verification: { result: 'match', countersignature: 'ok', remote: 'checked' } });
      const local = (await client.callTool({ name: 'anchor_status', arguments: {} })) as { structuredContent: Record<string, unknown> };
      expect(local.structuredContent).toMatchObject({ verification: { result: 'match', countersignature: 'ok', remote: 'skipped' } });
    } finally {
      await client.close();
      await handle.close();
      if (prevUrl === undefined) delete process.env['KRONICLE_ANCHOR_URL'];
      else process.env['KRONICLE_ANCHOR_URL'] = prevUrl;
      if (prevKey === undefined) delete process.env['KRONICLE_ANCHOR_KEY'];
      else process.env['KRONICLE_ANCHOR_KEY'] = prevKey;
      store.close();
    }
  });

  it('export carries a trailing anchors line; import skips it and rebuilds the chain', async () => {
    const { store } = makeStore(1);
    await pushCheckpoint(store, opts());
    const sink = new PassThrough();
    let buf = '';
    sink.on('data', (c: Buffer) => (buf += c.toString('utf8')));
    store.exportEvents(sink);
    sink.end();
    await new Promise((r) => sink.on('end', r));
    const lines = buf.trim().split('\n');
    const last = JSON.parse(lines[lines.length - 1]!) as { kronicle_lite_anchors: number; anchors: { anchor_id: string; receipt: AnchorReceipt }[] };
    expect(last.kronicle_lite_anchors).toBe(1);
    expect(last.anchors[0]!.receipt.anchor_id).toBe(last.anchors[0]!.anchor_id);
    const copy = new KronicleLite({ memory: true });
    const imp = await copy.importEvents(Readable.from([buf]));
    expect(imp.head).toEqual(store.chain.head());
    expect(copy.chain.listAnchors()).toHaveLength(0);
    copy.close();
    store.close();
  });
});

// Refused loopback connects take ~2 s each on Windows (SYN retries); give these room.
describe('anchor service unreachable never breaks local operation', { timeout: 60_000 }, () => {
  let html: Server;
  let htmlUrl: string;
  let hang: Server;
  let hangUrl: string;
  beforeAll(async () => {
    ({ server: html, url: htmlUrl } = await listen((_req, res) => {
      res.writeHead(404, { 'content-type': 'text/html' });
      res.end('<html><body>Not Found</body></html>');
    }));
    ({ server: hang, url: hangUrl } = await listen(() => {
      /* never answers */
    }));
  });
  afterAll(async () => {
    html.closeAllConnections();
    hang.closeAllConnections();
    await new Promise<void>((r) => html.close(() => r()));
    await new Promise<void>((r) => hang.close(() => r()));
  });

  it('closed port, non-anchor HTML server and a timeout all raise AnchorUnreachableError("anchor service unreachable …")', async () => {
    const { store } = makeStore(1);
    const dead = await closedPortUrl();
    for (const anchorUrl of [dead, htmlUrl]) {
      const err = await pushCheckpoint(store, { anchorUrl, licenseKey: 'KLA_x' }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(AnchorUnreachableError);
      expect((err as Error).message).toMatch(/^anchor service unreachable at /);
      await expect(verifyRemote(store, { anchorUrl })).rejects.toThrow(/anchor service unreachable/);
    }
    await expect(pushCheckpoint(store, { anchorUrl: hangUrl, licenseKey: 'KLA_x', timeoutMs: 200 })).rejects.toThrow(/unreachable.*timed out/);
    // Local state untouched and usable.
    expect(store.chain.listAnchors()).toHaveLength(0);
    expect(store.chain.verify().ok).toBe(true);
    const out = await tryPushCheckpoint(store, { anchorUrl: dead, licenseKey: 'KLA_x' });
    expect(out).toMatchObject({ ok: false, error: 'anchor_unreachable' });
    expect(await verifyLastAnchor(store, { anchorUrl: dead, remote: true })).toMatchObject({ result: 'none' });
    store.close();
  });

  it('CLI checkpoint --push to an unreachable service: checkpoint stored, exit 2, clear message; orient still works', async () => {
    const { dataDir, store } = makeStore(1);
    store.close();
    const dead = await closedPortUrl();
    const r = await cli(['checkpoint', '--push', '--data-dir', dataDir, '--url', dead, '--key', 'KLA_x']);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/stored locally; push failed: anchor service unreachable at http:\/\/127\.0\.0\.1:\d+/);
    const out = JSON.parse(r.stdout) as { checkpoint: { checkpoint_id: string }; anchor: { error: string } };
    expect(out.anchor.error).toBe('anchor_unreachable');
    const v = await cli(['verify', '--remote', '--data-dir', dataDir, '--url', dead]);
    expect(v.status).toBe(2);
    expect(v.stderr).toMatch(/anchor service unreachable/);
    const o = await cli(['orient', '--data-dir', dataDir]);
    expect(o.status).toBe(0);
    expect(o.stdout).not.toMatch(/anchor/);
    const reopened = new KronicleLite({ dataDir });
    expect(reopened.chain.getCheckpoint(out.checkpoint.checkpoint_id)).not.toBeNull();
    reopened.close();
  });

  it('push without a license key reports anchor_config, not a crash', async () => {
    const { store } = makeStore(1);
    const prev = process.env['KRONICLE_ANCHOR_KEY'];
    delete process.env['KRONICLE_ANCHOR_KEY'];
    try {
      expect(await tryPushCheckpoint(store, { anchorUrl: htmlUrl })).toMatchObject({ ok: false, error: 'anchor_config' });
    } finally {
      if (prev !== undefined) process.env['KRONICLE_ANCHOR_KEY'] = prev;
      store.close();
    }
  });
});

describe('anchor config', () => {
  it('first open writes config.json with the default anchor_url only (0600); precedence flag > env > file > default', () => {
    const { dataDir, store } = makeStore(1);
    store.close();
    const file = join(dataDir, 'config.json');
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual({ anchor_url: DEFAULT_ANCHOR_URL });
    if (POSIX) expect(statSync(file).mode & 0o777).toBe(0o600);
    const saved = { url: process.env['KRONICLE_ANCHOR_URL'], key: process.env['KRONICLE_ANCHOR_KEY'] };
    delete process.env['KRONICLE_ANCHOR_URL'];
    delete process.env['KRONICLE_ANCHOR_KEY'];
    try {
      expect(loadConfig(dataDir)).toEqual({ anchor_url: 'https://anchor.isokron.ai', license_key: null });
      writeFileSync(file, JSON.stringify({ anchor_url: 'https://file.example', license_key: 'KLA_file' }));
      expect(loadConfig(dataDir)).toEqual({ anchor_url: 'https://file.example', license_key: 'KLA_file' });
      process.env['KRONICLE_ANCHOR_KEY'] = 'KLA_env';
      process.env['KRONICLE_ANCHOR_URL'] = 'https://env.example';
      expect(loadConfig(dataDir)).toEqual({ anchor_url: 'https://env.example', license_key: 'KLA_env' });
      expect(loadConfig(dataDir, { license_key: 'KLA_flag', anchor_url: 'https://flag.example' })).toEqual({
        anchor_url: 'https://flag.example',
        license_key: 'KLA_flag',
      });
      // An existing config.json is never overwritten by a later open.
      new KronicleLite({ dataDir }).close();
      expect(JSON.parse(readFileSync(file, 'utf8'))).toMatchObject({ license_key: 'KLA_file' });
      writeFileSync(file, '{nope');
      expect(() => loadConfig(dataDir)).toThrow(/not valid JSON/);
    } finally {
      if (saved.url === undefined) delete process.env['KRONICLE_ANCHOR_URL'];
      else process.env['KRONICLE_ANCHOR_URL'] = saved.url;
      if (saved.key === undefined) delete process.env['KRONICLE_ANCHOR_KEY'];
      else process.env['KRONICLE_ANCHOR_KEY'] = saved.key;
    }
  });
});
