/**
 * 0.8.1 hardening track 6 (kronicle-lite anchor client): regression tests for
 * A2-01, A2-04, A2-11, A2-12, A2-17 and A2-20. Every test runs against the
 * in-process anchor stub (test/helpers/anchor-stub.ts), optionally behind a
 * rewriting `fetch` or a loopback proxy standing in for a MITM / malicious
 * anchor_url. Nothing leaves 127.0.0.1.
 */

import { spawn } from 'node:child_process';
import { createHash, createPublicKey, generateKeyPairSync, sign, verify as nodeVerify, type KeyObject } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { pushCheckpoint, tryPushCheckpoint, verifyLastAnchor, verifyRemote } from '../src/anchor/anchor.js';
import { AnchorClient, AnchorListingError } from '../src/anchor/client.js';
import { isUsableEd25519Point, verifyEd25519Strict } from '../src/anchor/ed25519-strict.js';
import { AnchorConfigError, assertAnchorTransport } from '../src/anchor/config.js';
import { anchorReceiptJcs, anchorReceiptSigningPayload, type AnchorReceipt } from '../src/anchor/receipt.js';
import { formatGenesisPin, parseGenesisPin, retirementSigningPayload, successorSigningPayload, type GenesisPin } from '../src/anchor/keychain.js';
import { KEYS_CACHE_FILE, readKeysCache } from '../src/anchor/keys-cache.js';
import { acceptServiceKeys, anchorGenesis, LEGACY_PINS_FILE, serviceKeyIdFromPem, verifyReceiptWithKeys, type ServiceKeySet } from '../src/anchor/trust.js';
import { checkpointSigningPayload } from '../src/chain/chain.js';
import { KronicleLite } from '../src/store.js';
import { startAnchorStub, STUB_GENESIS, STUB_KEY_VALID_FROM, STUB_PRIVATE, type AnchorBackend } from './helpers/anchor-stub.js';

const CLI = join(__dirname, '..', 'dist', 'cli.js');

type Json = Record<string, unknown> & { anchors?: Record<string, unknown>[]; keys?: Record<string, unknown>[] };

function makeStore(docs = 3): { dataDir: string; store: KronicleLite } {
  const dataDir = join(mkdtempSync(join(tmpdir(), 'kl-anchor-h-')), 'data');
  const store = new KronicleLite({ dataDir });
  for (let i = 1; i <= docs; i++) {
    store.docs.putDocument({ slug: `d${i}`, title: `D${i}`, markdown: `# D${i}\n\nBody ${i}.\n`, actor_id: 't' });
  }
  store.chain.checkpoint();
  return { dataDir, store };
}

/** Overwrite one event hash: the local rewrite `verify --remote` exists to catch. Returns the new local root over [from,to]. */
function rewriteSeq(store: KronicleLite, seq: number, from: number, to: number): string {
  store.db.prepare(`UPDATE events SET this_hash = ? WHERE seq = ?`).run(createHash('sha256').update(`rewritten:${seq}`).digest('hex'), seq);
  return store.chain.rootOver(from, to)!.root;
}

/** A `fetch` that passes through to the stub and lets the test rewrite JSON bodies (MITM / malicious mirror). */
function rewriting(transform: (path: string, body: Json) => Json): typeof fetch {
  return async (input, init) => {
    const res = await globalThis.fetch(input, init);
    const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const path = new URL(href).pathname;
    const text = await res.text();
    let out = text;
    try {
      out = JSON.stringify(transform(path, JSON.parse(text) as Json));
    } catch {
      /* non-JSON: pass */
    }
    return new Response(out, { status: res.status, headers: { 'content-type': 'application/json' } });
  };
}

/**
 * Serve the stub's full chain listing the way the paginated service does
 * (isokron-anchor A2-13: `page`, `next_cursor`, null on the last page), with
 * hooks to break the protocol.
 */
function paginated(
  size: number,
  hook: (pageNo: number, body: Json) => Json = (_n, j) => j,
): typeof fetch & { calls: string[] } {
  const calls: string[] = [];
  const f = (async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
    const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const u = new URL(href);
    calls.push(u.pathname + u.search);
    if (!u.pathname.startsWith('/v1/chains/')) return globalThis.fetch(input, init);
    const res = await globalThis.fetch(`${u.origin}${u.pathname}`, init);
    if (res.status !== 200) return res;
    const full = (await res.json()) as Json;
    const all = full.anchors ?? [];
    const start = u.searchParams.has('cursor') ? Number(u.searchParams.get('cursor')!.slice(1)) : 0;
    const pageNo = start / size;
    const next = start + size < all.length ? `c${start + size}` : null;
    const body = hook(pageNo, { ...full, anchors: all.slice(start, start + size), page: { limit: size, returned: Math.min(size, all.length - start) }, next_cursor: next });
    return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch & { calls: string[] };
  f.calls = calls;
  return f;
}

function ed25519(): { priv: KeyObject; pem: string; id: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
  return { priv: privateKey, pem, id: serviceKeyIdFromPem(pem) };
}

function resign(r: AnchorReceipt, priv: KeyObject, patch: Partial<AnchorReceipt> = {}): AnchorReceipt {
  const { signature: _s, ...body } = { ...r, ...patch };
  void _s;
  return { ...body, signature: sign(null, Buffer.from(anchorReceiptSigningPayload(body as AnchorReceipt), 'utf8'), priv).toString('base64') } as AnchorReceipt;
}

/** A genesis pin for a test key. */
const pinOf = (k: { pem: string }, validFrom = '2026-01-01T00:00:00.000Z'): GenesisPin => parseGenesisPin(`${createHash('sha256').update(createPublicKey(k.pem).export({ type: 'spki', format: 'der' })).digest('hex')}@${validFrom}`)!;

function cli(args: string[], env: Record<string, string | undefined> = {}): Promise<{ status: number | null; stdout: string; stderr: string }> {
  const e: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined && !k.startsWith('KRONICLE_ANCHOR_')) e[k] = v;
  e['KRONICLE_ANCHOR_GENESIS'] = STUB_GENESIS; // the stub's pin; a test may override or drop it
  for (const [k, v] of Object.entries(env)) if (v !== undefined) e[k] = v;
  for (const [k, v] of Object.entries(env)) if (v === undefined) delete e[k];
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

/** Loopback proxy in front of the stub for CLI tests (the CLI cannot take an injected fetch). */
async function proxy(upstream: string, transform: (path: string, body: Json) => Json): Promise<{ url: string; server: Server }> {
  const f = rewriting(transform);
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      void (async () => {
        const headers: Record<string, string> = {};
        for (const [k, v] of Object.entries(req.headers)) if (typeof v === 'string' && k !== 'host' && k !== 'content-length') headers[k] = v;
        const r = await f(upstream + (req.url ?? '/'), { method: req.method ?? 'GET', headers, ...(chunks.length ? { body: Buffer.concat(chunks) } : {}) });
        res.writeHead(r.status, { 'content-type': 'application/json' });
        res.end(await r.text());
      })().catch((e: unknown) => {
        res.writeHead(502);
        res.end(String(e));
      });
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const addr = server.address();
  return { url: `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`, server };
}

describe('anchor client hardening (0.8.1, track 6)', { timeout: 60_000 }, () => {
  let b: AnchorBackend;
  beforeAll(async () => {
    b = await startAnchorStub();
  });
  afterAll(async () => {
    await b?.stop();
  });
  const opts = () => ({ anchorUrl: b.url, licenseKey: b.license });

  // ───────────────────────────── A2-01 ─────────────────────────────

  it('A2-01 online: a listing whose unsigned top-level root was rewritten cannot hide a local rewrite', async () => {
    const { store } = makeStore();
    const p = await pushCheckpoint(store, opts());
    const [a, z] = p.range;
    const forged = rewriteSeq(store, 2, a, z);
    const honest = await verifyRemote(store, opts());
    expect(honest.ok).toBe(false);
    const mitm = rewriting((path, j) => {
      if (path.startsWith('/v1/chains/')) for (const x of j.anchors ?? []) x['root'] = forged;
      return j;
    });
    const r = await verifyRemote(store, { ...opts(), fetch: mitm });
    expect(r.ok).toBe(false);
    expect(r.checks[0]).toMatchObject({ result: 'diverged', countersignature: 'ok', anchored_root: p.root });
    expect(r.divergences[0]).toMatch(/^local chain diverges from anchor at \[/);
    expect(r.problems.join('\n')).toMatch(/disagrees with its countersigned receipt \(root\)/);
    store.close();
  });

  it('A2-01 offline + MCP anchor_status: rewriting the unsigned anchors.root column does not make a rewrite pass', async () => {
    const { store } = makeStore();
    const p = await pushCheckpoint(store, opts());
    const forged = rewriteSeq(store, 2, p.range[0], p.range[1]);
    store.db.prepare(`UPDATE anchors SET root = ?`).run(forged);
    const off = await verifyRemote(store, { anchorUrl: 'http://127.0.0.1:9', offline: true });
    expect(off.ok).toBe(false);
    expect(off.checks[0]).toMatchObject({ result: 'diverged', countersignature: 'ok', source: 'local', anchored_root: p.root });
    expect(off.problems.join('\n')).toMatch(/local anchors row disagrees/);
    const mcpRemote = await verifyLastAnchor(store, { ...opts(), remote: true });
    expect(mcpRemote).toMatchObject({ result: 'diverged', remote: 'checked' });
    const mcpLocal = await verifyLastAnchor(store, { anchorUrl: b.url });
    expect(mcpLocal).toMatchObject({ result: 'diverged', remote: 'skipped' });
    store.close();
  });

  it('A2-01 offline: the stored receipt is re-verified; a tampered receipt_json is unverified, not compared', async () => {
    const { store } = makeStore();
    await pushCheckpoint(store, opts());
    const fake = rewriteSeq(store, 1, 1, store.chain.head().seq);
    store.db.prepare(`UPDATE anchors SET receipt_json = replace(receipt_json, root, ?), root = ?`).run(fake, fake);
    const r = await verifyRemote(store, { anchorUrl: b.url, offline: true });
    expect(r.ok).toBe(false);
    expect(r.checks[0]).toMatchObject({ result: 'unverified', countersignature: 'failed' });
    expect((await verifyLastAnchor(store, { anchorUrl: b.url })).result).toBe('unverified');
    store.close();
  });

  it('A2-01: a valid receipt for ANOTHER chain listed under this chain is refused, not compared', async () => {
    const mine = makeStore();
    const other = makeStore(5);
    await pushCheckpoint(mine.store, opts());
    await pushCheckpoint(other.store, opts());
    const otherReceipt = other.store.chain.lastAnchor()!;
    const inject = rewriting((path, j) => {
      if (path.startsWith('/v1/chains/')) {
        const r = JSON.parse(otherReceipt.receipt_json) as AnchorReceipt;
        j.anchors = [{ ...j.anchors![0]!, anchor_id: r.anchor_id, receipt: r }];
      }
      return j;
    });
    const r = await verifyRemote(mine.store, { ...opts(), fetch: inject });
    expect(r.ok).toBe(false);
    const foreign = r.checks.find((c) => c.anchor_id === otherReceipt.anchor_id)!;
    expect(foreign).toMatchObject({ result: 'unverified', countersignature: 'failed' });
    expect(r.problems.join('\n')).toMatch(/not this chain/);
    mine.store.close();
    other.store.close();
  });

  // ───────────────────────────── A2-11 ─────────────────────────────

  it('A2-11: an anchor the service withholds is still checked from the local receipt (and the omission reported)', async () => {
    const { store } = makeStore();
    await pushCheckpoint(store, opts());
    store.docs.putDocument({ slug: 'x', title: 'X', markdown: '# X\n\nx.\n', actor_id: 't' });
    store.chain.checkpoint();
    const second = await pushCheckpoint(store, opts());
    // A careful MITM also lowers anchor_count, so the listing looks complete.
    const drop = rewriting((path, j) => {
      if (path.startsWith('/v1/chains/')) {
        j.anchors = (j.anchors ?? []).filter((x) => x['anchor_id'] !== second.anchor_id);
        j['anchor_count'] = j.anchors.length;
      }
      return j;
    });
    // A careless one leaves anchor_count: the listing itself is rejected.
    const sloppy = rewriting((path, j) => {
      if (path.startsWith('/v1/chains/')) j.anchors = (j.anchors ?? []).filter((x) => x['anchor_id'] !== second.anchor_id);
      return j;
    });
    const s1 = await verifyRemote(store, { ...opts(), fetch: sloppy });
    expect(s1.ok).toBe(false);
    expect(s1.problems.join('\n')).toMatch(/ended after 1 of 2 anchors/);
    expect(s1.checks.every((c) => c.source === 'local' && c.result === 'match')).toBe(true);
    // Intact chain: still ok, but the omission is reported.
    const intact = await verifyRemote(store, { ...opts(), fetch: drop });
    expect(intact.ok).toBe(true);
    expect(intact.checks).toHaveLength(2);
    expect(intact.checks.find((c) => c.anchor_id === second.anchor_id)).toMatchObject({ source: 'local', result: 'match' });
    expect(intact.notes.join('\n')).toMatch(new RegExp(`${second.anchor_id} .* held locally but not listed`));
    // Rewritten inside the withheld range: diverged, exit-1 territory.
    rewriteSeq(store, store.chain.head().seq, 1, 1);
    const r = await verifyRemote(store, { ...opts(), fetch: drop });
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.anchor_id === second.anchor_id)).toMatchObject({ source: 'local', result: 'diverged' });
    store.close();
  });

  // ───────────────────────────── A2-12 (0.10.0: the service's key model) ─────────────────────────────

  it('A2-12: the key list must chain to the genesis pin; a MITM key under the real key_id or its own is refused; the kept list is untouched', async () => {
    const { dataDir, store } = makeStore();
    const p = await pushCheckpoint(store, opts());
    expect(existsSync(join(dataDir, KEYS_CACHE_FILE))).toBe(true);
    if (process.platform !== 'win32') expect((await import('node:fs')).statSync(join(dataDir, KEYS_CACHE_FILE)).mode & 0o777).toBe(0o600);
    const keptBefore = readFileSync(join(dataDir, KEYS_CACHE_FILE), 'utf8');

    const forged = rewriteSeq(store, 2, p.range[0], p.range[1]);
    const atk = ed25519();
    const mitm = rewriting((path, j) => {
      if (path === '/.well-known/anchor-keys.json') j.keys = [{ ...j.keys![0]!, public_key_pem: atk.pem }];
      if (path.startsWith('/v1/chains/')) {
        for (const x of j.anchors ?? []) {
          const r = x['receipt'] as AnchorReceipt;
          x['root'] = forged;
          x['receipt'] = resign(r, atk.priv, { checkpoint: { ...r.checkpoint, root: forged } });
        }
      }
      return j;
    });
    const r = await verifyRemote(store, { ...opts(), fetch: mitm });
    expect(r.ok).toBe(false);
    expect(r.problems.join('\n')).toMatch(/service key list refused: anchor-ed25519-[0-9a-f]{16} has a different public key than in the list seen earlier/);
    expect(r.checks[0]).toMatchObject({ result: 'unverified', countersignature: 'failed' });
    expect(readFileSync(join(dataDir, KEYS_CACHE_FILE), 'utf8')).toBe(keptBefore);

    // Attacker key under its OWN key_id, as the only key: the real key is missing (rollback) and it does not chain to the pin.
    const own = rewriting((path, j) => {
      if (path === '/.well-known/anchor-keys.json') j.keys = [{ ...j.keys![0]!, key_id: atk.id, public_key_pem: atk.pem }];
      if (path.startsWith('/v1/chains/')) {
        for (const x of j.anchors ?? []) {
          const r = x['receipt'] as AnchorReceipt;
          x['receipt'] = resign(r, atk.priv, { service_key_id: atk.id, checkpoint: { ...r.checkpoint, root: forged } });
        }
      }
      return j;
    });
    const r2 = await verifyRemote(store, { ...opts(), fetch: own });
    expect(r2.ok).toBe(false);
    expect(r2.problems.join('\n')).toMatch(/is in the key list seen earlier but missing now/);
    expect(readFileSync(join(dataDir, KEYS_CACHE_FILE), 'utf8')).toBe(keptBefore);
    // A fresh data dir has no kept list to compare with: the chain check alone refuses the attacker's key.
    const fresh = makeStore(1);
    const r3 = await verifyRemote(fresh.store, { ...opts(), fetch: own });
    expect(r3.problems.join('\n')).toMatch(/does not chain to the genesis pin .*genesis fingerprint [0-9a-f]{64} does not match the pinned/);
    fresh.store.close();
    store.close();
  });

  it('A2-12: receipt.checkpoint.signature is re-checked against the local chain key', async () => {
    const { store } = makeStore();
    const svc = ed25519();
    const svcPin = pinOf(svc);
    expect(acceptServiceKeys(store, b.url, svcPin, { v: 1, keys: [{ key_id: svc.id, public_key_pem: svc.pem, valid_from: svcPin.valid_from, status: 'active' }] }).violations).toEqual([]);
    const cp = store.chain.latestCheckpoint()!;
    const { chain_id } = (await import('../src/anchor/anchor.js')).localChainIdentity(store);
    const base: AnchorReceipt = resign(
      {
        v: 1,
        anchor_id: '01900000-0000-7000-8000-000000000001',
        chain_id,
        key_id: cp.key_id,
        checkpoint: { v: 1, from_seq: cp.from_seq, to_seq: cp.to_seq, leaf_count: cp.leaf_count, root: cp.root, key_id: cp.key_id, signature: cp.signature },
        received_at: new Date().toISOString(),
        tier: 'free',
        service_key_id: svc.id,
        verified: ['chain_id', 'key_id', 'signature', 'range'],
        signature: '',
      },
      svc.priv,
    );
    const record = (r: AnchorReceipt) => {
      store.db.prepare(`DELETE FROM anchors`).run();
      store.chain.recordAnchor({
        anchor_id: r.anchor_id,
        checkpoint_id: cp.checkpoint_id,
        chain_id,
        anchor_url: b.url,
        from_seq: cp.from_seq,
        to_seq: cp.to_seq,
        root: r.checkpoint.root,
        received_at: r.received_at,
        receipt_json: anchorReceiptJcs(r),
        day: null,
        leaf_index: null,
        path_json: null,
        status: 'pending_public',
      });
    };
    const offline = { anchorUrl: b.url, offline: true, genesis: formatGenesisPin(svcPin) };
    record(base);
    expect((await verifyRemote(store, offline)).ok).toBe(true);
    // A service-signed receipt whose checkpoint root the chain key never signed.
    const forgedRoot = createHash('sha256').update('other').digest('hex');
    record(resign(base, svc.priv, { checkpoint: { ...base.checkpoint, root: forgedRoot } }));
    const r = await verifyRemote(store, offline);
    expect(r.ok).toBe(false);
    expect(r.problems.join('\n')).toMatch(/checkpoint signature does not verify against the local chain key/);
    expect(checkpointSigningPayload(base.checkpoint)).toContain(cp.root);
    store.close();
  });

  it('item 2: only the head key vouches; a retired or revoked key\u2019s receipt is refused (no TSA time here); a forged successor breaks the list', () => {
    const { store } = makeStore(1);
    const G = ed25519();
    const S = ed25519();
    const X = ed25519();
    const gFrom = '2026-01-01T00:00:00.000Z';
    const sFrom = '2026-06-01T00:00:00.000Z';
    const sig = (k: KeyObject, msg: string) => sign(null, Buffer.from(msg, 'utf8'), k).toString('base64');
    const rotated = [
      { key_id: S.id, public_key_pem: S.pem, valid_from: sFrom, status: 'active', successor_signature: sig(G.priv, successorSigningPayload({ key_id: S.id, public_key_pem: S.pem, valid_from: sFrom })), signed_by: G.id },
      { key_id: G.id, public_key_pem: G.pem, valid_from: gFrom, valid_to: sFrom, status: 'retired', retirement_signature: sig(S.priv, retirementSigningPayload({ key_id: G.id, status: 'retired', valid_to: sFrom })), retirement_signed_by: S.id },
    ];
    const pin = pinOf(G, gFrom);
    const set = acceptServiceKeys(store, 'https://anchor.test', pin, { v: 1, keys: rotated }).set!;
    expect(set).not.toBeNull();
    const receiptBy = (k: { id: string; priv: KeyObject }, at: string) =>
      resign(
        {
          v: 1,
          anchor_id: '01900000-0000-7000-8000-000000000002',
          chain_id: 'ab'.repeat(32),
          key_id: 'ed25519-0000000000000000',
          checkpoint: { v: 1, from_seq: 1, to_seq: 1, leaf_count: 1, root: 'cd'.repeat(32), key_id: 'ed25519-0000000000000000', signature: 'A'.repeat(86) + '==' },
          received_at: at,
          tier: 'free',
          service_key_id: k.id,
          verified: ['chain_id', 'key_id', 'signature', 'range'],
          signature: '',
        },
        k.priv,
      );
    expect(verifyReceiptWithKeys(receiptBy(S, '2026-07-01T00:00:00.000Z'), set).ok).toBe(true);
    // G is retired: its receipt is dated inside its window, but received_at is its own claim.
    expect(verifyReceiptWithKeys(receiptBy(G, '2026-03-01T00:00:00.000Z'), set)).toMatchObject({
      ok: false,
      reason: expect.stringMatching(new RegExp(`^${G.id} is retired \\(valid to ${sFrom}\\); its receipts count only with an RFC 3161 time inside its window: verify independent timestamps at https://anchor.test/v/[0-9a-f]{64} or with \`kronicle-lite verify-audit\``)),
    });
    // S revoked by itself: refused, whatever received_at says.
    const cs = '2026-08-01T00:00:00.000Z';
    const vt = '2026-09-01T00:00:00.000Z';
    const revoked = rotated.map((k) =>
      k.key_id === S.id ? { ...k, status: 'revoked', valid_to: vt, compromised_since: cs, retirement_signature: sig(S.priv, retirementSigningPayload({ key_id: S.id, status: 'revoked', valid_to: vt, compromised_since: cs })), retirement_signed_by: S.id } : k,
    );
    const rset = acceptServiceKeys(store, 'https://anchor.test', pin, { v: 1, keys: revoked }).set!;
    expect(verifyReceiptWithKeys(receiptBy(S, '2026-07-01T00:00:00.000Z'), rset)).toMatchObject({ ok: false, reason: expect.stringMatching(/^revoked key: .* is revoked \(compromised since 2026-08-01T00:00:00.000Z\)/) });
    // ...and that revocation is now the kept reference: the older, unrevoked list is a rollback.
    expect(acceptServiceKeys(store, 'https://anchor.test', pin, { v: 1, keys: rotated }).violations.join('\n')).toMatch(/was revoked in the list seen earlier and is active now/);
    // A successor signed by a key that is not its predecessor: the list does not chain.
    const fresh = makeStore(1);
    const forgedSucc = rotated.map((k) => (k.key_id === S.id ? { ...k, successor_signature: sig(X.priv, successorSigningPayload({ key_id: S.id, public_key_pem: S.pem, valid_from: sFrom })) } : k));
    const bad = acceptServiceKeys(fresh.store, 'https://anchor.test', pin, { v: 1, keys: forgedSucc });
    expect(bad.set).toBeNull();
    expect(bad.violations.join('\n')).toMatch(/does not chain to the genesis pin/);
    fresh.store.close();
    store.close();
  });

  it('item 2: a signed revocation served by the service is kept; the old active list is then a rollback (push, verify)', async () => {
    const { store } = makeStore(1);
    await pushCheckpoint(store, opts());
    expect((await verifyRemote(store, opts())).ok).toBe(true);
    const cs = '2026-11-01T06:00:00.000Z';
    const vt = new Date(Date.now() + 3600e3).toISOString();
    const revoke = rewriting((path, j) => {
      if (path === '/.well-known/anchor-keys.json') {
        const k = j.keys![0]! as Record<string, unknown>;
        j.keys = [{ ...k, status: 'revoked', valid_to: vt, compromised_since: cs, retirement_signature: sign(null, Buffer.from(retirementSigningPayload({ key_id: k['key_id'] as string, status: 'revoked', valid_to: vt, compromised_since: cs }), 'utf8'), STUB_PRIVATE).toString('base64'), retirement_signed_by: k['key_id'] }];
      }
      return j;
    });
    const r = await verifyRemote(store, { ...opts(), fetch: revoke });
    expect(r.ok).toBe(false);
    expect(r.problems.join('\n')).toMatch(/revoked key: anchor-ed25519-[0-9a-f]{16} is revoked \(compromised since 2026-11-01T06:00:00.000Z\)/);
    const back = await verifyRemote(store, opts());
    expect(back.ok).toBe(false);
    expect(back.problems.join('\n')).toMatch(/service key list refused: .* was revoked in the list seen earlier and is active now/);
    await expect(pushCheckpoint(store, opts())).rejects.toThrow(/was revoked in the list seen earlier and is active now.*nothing sent/);
    store.close();
  });

  it('item 2: the genesis pin comes from --genesis, KRONICLE_ANCHOR_GENESIS, config.json anchor_genesis, else the compiled pin; old settings are refused', () => {
    const { dataDir, store } = makeStore(1);
    const prev = process.env['KRONICLE_ANCHOR_GENESIS'];
    try {
      delete process.env['KRONICLE_ANCHOR_GENESIS'];
      expect(anchorGenesis(dataDir)).toMatchObject({ source: 'compiled', pin: { sha256: '3dca1ecf66c2993e534ff08fe350dc9368ca52042e38b20a9d58cd7c2b7b3367' } });
      writeFileSync(join(dataDir, 'config.json'), JSON.stringify({ anchor_genesis: `${'ab'.repeat(32)}@2026-01-01T00:00:00Z` }));
      expect(anchorGenesis(dataDir)).toEqual({ source: 'config', pin: { sha256: 'ab'.repeat(32), valid_from: '2026-01-01T00:00:00.000Z' } });
      process.env['KRONICLE_ANCHOR_GENESIS'] = STUB_GENESIS;
      expect(anchorGenesis(dataDir).source).toBe('env');
      expect(anchorGenesis(dataDir, `${'cd'.repeat(32)}@${STUB_KEY_VALID_FROM}`).source).toBe('option');
      expect(() => anchorGenesis(dataDir, 'cd'.repeat(32))).toThrow(/--genesis must be <sha256>@<valid_from>/);
      writeFileSync(join(dataDir, 'config.json'), JSON.stringify({ service_key_pins: ['x'] }));
      expect(() => anchorGenesis(dataDir)).toThrow(/service_key_pins is no longer read/);
      writeFileSync(join(dataDir, 'config.json'), '{}');
      process.env['KRONICLE_ANCHOR_GENESIS_SHA256'] = 'ab'.repeat(32);
      expect(() => anchorGenesis(dataDir)).toThrow(/KRONICLE_ANCHOR_GENESIS_SHA256 is no longer read/);
    } finally {
      delete process.env['KRONICLE_ANCHOR_GENESIS_SHA256'];
      if (prev === undefined) delete process.env['KRONICLE_ANCHOR_GENESIS'];
      else process.env['KRONICLE_ANCHOR_GENESIS'] = prev;
      store.close();
    }
  });

  it('item 2: the kept-list file is the service client\u2019s format: records found under any spelling of the URL and pin; a damaged file is a violation', () => {
    const { dataDir, store } = makeStore(1);
    const G = ed25519();
    const pin = pinOf(G, '2026-01-01T00:00:00.000Z');
    const keys = [{ key_id: G.id, public_key_pem: G.pem, valid_from: '2026-01-01T00:00:00.000Z', status: 'active' }];
    // as isokron-anchor's client writes it, with a URL and a pin spelled differently
    const record = { anchor_url: 'https://Anchor.Test:443/', genesis: `${pin.sha256.toUpperCase()}@2026-01-01T00:00:00Z`, keys: { v: 1, keys } };
    writeFileSync(join(dataDir, KEYS_CACHE_FILE), JSON.stringify({ v: 2, records: { [`${record.anchor_url}|${record.genesis}`]: record } }));
    expect(readKeysCache(store, 'https://anchor.test', pin)!.keys).toEqual(keys);
    // a fresh list that drops the kept key is a rollback
    expect(acceptServiceKeys(store, 'https://anchor.test/', pin, { v: 1, keys: [] }).violations.join('\n')).toMatch(/is in the key list seen earlier but missing now/);
    writeFileSync(join(dataDir, KEYS_CACHE_FILE), '{"v":2,"records":[]}');
    expect(acceptServiceKeys(store, 'https://anchor.test', pin, { v: 1, keys }).violations.join('\n')).toMatch(/anchor-keys\.cache\.json has the wrong shape \(records\)/);
    store.close();
  });

  it('A2-12: anchor keys shows the genesis pin and the kept list; add/remove/reset are gone (exit 2)', async () => {
    const { dataDir, store } = makeStore(1);
    store.close();
    expect((await cli(['anchor', 'keys', '--data-dir', dataDir, '--url', b.url])).stdout).toMatch(/genesis pin {4}[0-9a-f]{64}@2026-11-01T00:00:00.000Z \(KRONICLE_ANCHOR_GENESIS\)\nkey list {7}none kept yet/);
    const push = await cli(['checkpoint', '--push', '--data-dir', dataDir], { KRONICLE_ANCHOR_URL: b.url, KRONICLE_ANCHOR_KEY: b.license });
    expect(push.status, push.stderr).toBe(0);
    const list = await cli(['anchor', 'keys', 'list', '--data-dir', dataDir, '--url', b.url, '--json']);
    expect(JSON.parse(list.stdout)).toMatchObject({ anchor_url: b.url, genesis: STUB_GENESIS, genesis_source: 'env', kept: true, chain: { ok: true, entries: [{ state: 'genesis' }] } });
    writeFileSync(join(dataDir, LEGACY_PINS_FILE), '{"v":1,"keys":[]}');
    expect((await cli(['anchor', 'keys', '--data-dir', dataDir, '--url', b.url])).stdout).toMatch(/anchor-keys.pinned.json \(the 0.9.x pin store\) is no longer read/);
    for (const op of [['add', 'x.pem'], ['remove', 'k'], ['reset']]) {
      const r = await cli(['anchor', 'keys', ...op, '--data-dir', dataDir]);
      expect(r.status, op[0]).toBe(2);
      expect(r.stderr).toMatch(/was removed in 0.10.0: trust comes from the anchor service's signed key chain/);
    }
    expect((await cli(['anchor', 'keys', 'bogus', '--data-dir', dataDir])).status).toBe(2);
    // the compiled pin, for a service whose list does not chain to it: push refused before anything is sent
    const prod = await cli(['checkpoint', '--push', '--data-dir', dataDir], { KRONICLE_ANCHOR_URL: b.url, KRONICLE_ANCHOR_KEY: b.license, KRONICLE_ANCHOR_GENESIS: undefined });
    expect(prod.status).not.toBe(0);
    expect(prod.stdout + prod.stderr).toMatch(/does not chain to the genesis pin 3dca1ecf/);
  });

  // ───────────────────────────── A2-04 ─────────────────────────────

  it('A2-04: key validity window against the receipt\u2019s signed time; the client helpers apply the same head-only rule', async () => {
    const { store } = makeStore(1);
    await pushCheckpoint(store, opts());
    const receipt = JSON.parse(store.chain.lastAnchor()!.receipt_json) as AnchorReceipt;
    const set: ServiceKeySet = { anchor_url: b.url, genesis: parseGenesisPin(STUB_GENESIS)!, keys: readKeysCache(store, b.url, parseGenesisPin(STUB_GENESIS)!)!.keys, source: 'kept' };
    expect(verifyReceiptWithKeys(receipt, set).ok).toBe(true);
    expect(verifyReceiptWithKeys({ ...receipt, received_at: '2020-01-01T00:00:00.000Z' }, set)).toMatchObject({ ok: false, reason: expect.stringMatching(/precedes .* valid_from/) });
    expect(verifyReceiptWithKeys(receipt, null)).toMatchObject({ ok: false, reason: expect.stringMatching(/no trusted anchor service key list/) });
    // The unpinned client check: the list must chain to the pin, and only the head key vouches.
    const pin = parseGenesisPin(STUB_GENESIS)!;
    const doc = (await (await fetch(`${b.url}/.well-known/anchor-keys.json`)).json()) as { v: 1; issuer: string; keys: { key_id: string; public_key_pem: string; status: string; valid_from: string; valid_to: string | null }[] };
    expect((await new AnchorClient(b.url, { preloadedKeys: doc }).verifyReceipt(receipt, pin)).anchor_id).toBe(receipt.anchor_id);
    await expect(new AnchorClient(b.url, { preloadedKeys: doc }).verifyReceipt(receipt)).rejects.toThrow(/does not chain to the pinned genesis key/);
    await expect(new AnchorClient(b.url, { preloadedKeys: { ...doc, keys: [{ ...doc.keys[0]!, status: 'compromised' }] } }).verifyReceipt(receipt, pin)).rejects.toThrow(/service key/);
    await expect(new AnchorClient(b.url, { preloadedKeys: { ...doc, keys: [doc.keys[0]!, doc.keys[0]!] } }).verifyReceipt(receipt, pin)).rejects.toThrow(/listed more than once/);
    // An unsigned status change served by the service breaks the list (it is not a revocation) and is not kept.
    const unsigned = rewriting((path, j) => {
      if (path === '/.well-known/anchor-keys.json') j.keys = [{ ...j.keys![0]!, status: 'revoked' }];
      return j;
    });
    expect((await verifyRemote(store, { ...opts(), fetch: unsigned })).ok).toBe(false);
    expect((await verifyRemote(store, opts())).ok).toBe(true);
    store.close();
  });

  // ───────────────────────────── A2-17 ─────────────────────────────

  it('A2-17: push verifies receipt_jcs before storing; a bad one is refused and nothing is stored (CLI exits non-zero)', async () => {
    const { dataDir, store } = makeStore(1);
    for (const bad of ['{"v":1,"note":"not the receipt"}', 'not json']) {
      const mitm = rewriting((path, j) => {
        if (path === '/v1/anchor') j['receipt_jcs'] = bad;
        return j;
      });
      await expect(pushCheckpoint(store, { ...opts(), fetch: mitm })).rejects.toThrow(/receipt_jcs .*nothing stored/);
      expect(store.chain.listAnchors()).toHaveLength(0);
    }
    // Same receipt but not its JCS bytes.
    const spaced = rewriting((path, j) => {
      if (path === '/v1/anchor') j['receipt_jcs'] = JSON.stringify(j['receipt'], null, 1);
      return j;
    });
    await expect(pushCheckpoint(store, { ...opts(), fetch: spaced })).rejects.toThrow(/not the JCS/);
    expect(store.chain.listAnchors()).toHaveLength(0);
    store.close();

    const p = await proxy(b.url, (path, j) => {
      if (path === '/v1/anchor') j['receipt_jcs'] = '{"v":1,"note":"not the receipt"}';
      return j;
    });
    try {
      const r = await cli(['checkpoint', '--push', '--data-dir', dataDir, '--url', p.url], { KRONICLE_ANCHOR_KEY: b.license });
      expect(r.status).not.toBe(0);
      expect(r.stderr).toMatch(/push failed: anchor response receipt_jcs rejected/);
      const s = new KronicleLite({ dataDir });
      expect(s.chain.listAnchors()).toHaveLength(0);
      s.close();
    } finally {
      await new Promise<void>((r) => p.server.close(() => r()));
    }
  });

  // ───────────────────────────── A2-20 ─────────────────────────────

  it('A2-20: http:// is refused unless loopback or --insecure-http; --key on argv warns', async () => {
    expect(() => assertAnchorTransport('https://anchor.isokron.ai')).not.toThrow();
    for (const ok of ['http://localhost:8787', 'http://127.0.0.1:8787', 'http://[::1]:8787']) expect(() => assertAnchorTransport(ok)).not.toThrow();
    expect(() => assertAnchorTransport('http://anchor.example')).toThrow(AnchorConfigError);
    expect(() => assertAnchorTransport('http://127.0.0.2:8787')).toThrow(/refusing http:\/\//);
    expect(() => assertAnchorTransport('http://anchor.example', true)).not.toThrow();
    expect(() => assertAnchorTransport('ftp://anchor.example', true)).toThrow(/must be https/);

    const { dataDir, store } = makeStore(1);
    let calls = 0;
    const counting: typeof fetch = (...a) => {
      calls++;
      return globalThis.fetch(...a);
    };
    await expect(pushCheckpoint(store, { anchorUrl: 'http://anchor.example', licenseKey: 'KLA_x', fetch: counting })).rejects.toThrow(/refusing http:\/\/ anchor_url/);
    await expect(verifyRemote(store, { anchorUrl: 'http://anchor.example', fetch: counting })).rejects.toThrow(/refusing http/);
    expect(calls).toBe(0);
    store.close();

    const refused = await cli(['checkpoint', '--push', '--data-dir', dataDir, '--url', 'http://anchor.example', '--key', 'KLA_x']);
    expect(refused.status).toBe(2);
    expect(refused.stderr).toMatch(/warning: --key puts the license key on the command line/);
    expect(refused.stderr).toMatch(/refusing http:\/\/ anchor_url http:\/\/anchor\.example/);
    expect(refused.stderr).not.toContain('KLA_x');
    const v = await cli(['verify', '--remote', '--data-dir', dataDir, '--url', 'http://anchor.example']);
    expect(v.status).toBe(2);
    expect(v.stderr).toMatch(/refusing http/);
    // From the environment: no argv warning; loopback http allowed.
    const envPush = await cli(['checkpoint', '--push', '--data-dir', dataDir], { KRONICLE_ANCHOR_URL: b.url, KRONICLE_ANCHOR_KEY: b.license });
    expect(envPush.status, envPush.stderr).toBe(0);
    expect(envPush.stderr).not.toMatch(/warning: --key/);
  });
  // ─────────────── isokron-anchor hardening A2 compatibility ───────────────

  it('pagination: verify --remote and anchor_status follow next_cursor to the end; held receipts on later pages are not "withheld"', async () => {
    const { store } = makeStore(1);
    const ids: string[] = [];
    for (let i = 0; i < 3; i++) {
      store.docs.putDocument({ slug: `p${i}`, title: `P${i}`, markdown: `# P${i}\n\np.\n`, actor_id: 't' });
      store.chain.checkpoint();
      ids.push((await pushCheckpoint(store, opts())).anchor_id);
    }
    const f = paginated(1);
    const r = await verifyRemote(store, { ...opts(), fetch: f });
    expect(r.ok, r.problems.join('; ')).toBe(true);
    expect(r.checks.map((c) => c.source)).toEqual(['remote', 'remote', 'remote']);
    expect(r.notes.join('\n')).not.toMatch(/not listed/);
    expect(f.calls.filter((c) => c.startsWith('/v1/chains/'))).toHaveLength(3);
    expect((await verifyLastAnchor(store, { ...opts(), fetch: paginated(1), remote: true })).detail).toBeNull();
    store.close();
  });

  it('pagination: a missing, looping or truncating cursor is an error, never "verified"; held receipts are still checked', async () => {
    const { store } = makeStore(1);
    for (let i = 0; i < 3; i++) {
      store.docs.putDocument({ slug: `q${i}`, title: `Q${i}`, markdown: `# Q${i}\n\nq.\n`, actor_id: 't' });
      store.chain.checkpoint();
      await pushCheckpoint(store, opts());
    }
    const broken: [string, typeof fetch, RegExp][] = [
      ['missing cursor', paginated(1, (n, j) => (n === 1 ? (({ next_cursor: _c, ...rest }) => rest)(j) as Json : j)), /paginated but has no next_cursor/],
      ['looping cursor', paginated(1, (_n, j) => ({ ...j, next_cursor: j['next_cursor'] === null ? null : 'c1' })), /repeats next_cursor|a second time/],
      ['truncated', paginated(1, (n, j) => (n === 1 ? { ...j, next_cursor: null } : j)), /ended after 2 of 3 anchors/],
      ['stripped legacy', paginated(10, (_n, j) => (({ next_cursor: _c, page: _p, ...rest }) => ({ ...rest, anchors: (rest.anchors as unknown[]).slice(0, 2) }))(j) as Json), /ended after 2 of 3 anchors/],
    ];
    for (const [label, f, re] of broken) {
      await expect(new AnchorClient(b.url, { fetch: f }).chain((await import('../src/anchor/anchor.js')).localChainIdentity(store).chain_id), label).rejects.toBeInstanceOf(AnchorListingError);
      const r = await verifyRemote(store, { ...opts(), fetch: f });
      expect(r.ok, label).toBe(false);
      expect(r.problems.join('\n'), label).toMatch(re);
      expect(r.checks.map((c) => `${c.source}:${c.result}`), label).toEqual(['local:match', 'local:match', 'local:match']);
      const v = await verifyLastAnchor(store, { ...opts(), fetch: f, remote: true });
      expect(v.remote, label).toBe('invalid');
      expect(v.detail, label).toMatch(re);
    }
    // A divergence inside a range the broken listing never delivered is still found from the local receipt.
    rewriteSeq(store, store.chain.head().seq, 1, 1);
    const r = await verifyRemote(store, { ...opts(), fetch: broken[2]![1] });
    expect(r.checks.some((c) => c.result === 'diverged')).toBe(true);
    store.close();
  });

  it('410 chain_erased: reported clearly, exit non-zero, not retried, nothing stored', async () => {
    const { dataDir, store } = makeStore(1);
    let posts = 0;
    const erased: typeof fetch = async (input, init) => {
      if ((init?.method ?? 'GET') === 'POST') {
        posts++;
        return new Response(JSON.stringify({ error: 'chain_erased', detail: 'this chain was erased on request; it accepts no further anchors (existing receipts stay public)' }), { status: 410, headers: { 'content-type': 'application/json' } });
      }
      return globalThis.fetch(input, init);
    };
    const out = await tryPushCheckpoint(store, { ...opts(), fetch: erased });
    expect(out).toMatchObject({ ok: false, error: 'anchor_refused' });
    expect(out.message).toMatch(/410 chain_erased.*erased on the anchor service.*Not retried/);
    expect(posts).toBe(1);
    expect(store.chain.listAnchors()).toHaveLength(0);
    store.close();
    const gone = createServer((req, res) => {
      res.writeHead(410, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'chain_erased', detail: 'erased' }));
      req.resume();
    });
    await new Promise<void>((r) => gone.listen(0, '127.0.0.1', r));
    const addr = gone.address();
    try {
      const r = await cli(['checkpoint', '--push', '--data-dir', dataDir, '--url', `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`], { KRONICLE_ANCHOR_KEY: b.license });
      expect(r.status).toBe(2);
      expect(r.stderr).toMatch(/push failed: anchor service refused \(410 chain_erased\)/);
    } finally {
      await new Promise<void>((r) => gone.close(() => r()));
    }
  });

  it('A2-09 parity: small-order keys and small-order R are refused (node:crypto alone accepts them)', () => {
    const identity = Buffer.alloc(32);
    identity[0] = 1;
    const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), identity]);
    const pem = createPublicKey({ key: spki, format: 'der', type: 'spki' }).export({ type: 'spki', format: 'pem' }) as string;
    const forgery = Buffer.concat([identity, Buffer.alloc(32)]).toString('base64');
    expect(nodeVerify(null, Buffer.from('any root'), createPublicKey(pem), Buffer.from(forgery, 'base64'))).toBe(true); // the gap
    expect(verifyEd25519Strict(pem, 'any root', forgery)).toBe(false);
    for (const hex of [
      '0000000000000000000000000000000000000000000000000000000000000000',
      '0000000000000000000000000000000000000000000000000000000000000080',
      '0100000000000000000000000000000000000000000000000000000000000000',
      '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
      '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
      'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
      'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
      'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', // p (non-canonical 0)
      'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', // p+1 (non-canonical 1)
    ]) {
      expect(isUsableEd25519Point(Buffer.from(hex, 'hex')), hex).toBe(false);
    }
    const k = ed25519();
    const sig = sign(null, Buffer.from('m'), k.priv);
    expect(verifyEd25519Strict(k.pem, 'm', sig.toString('base64'))).toBe(true);
    // S ≥ L (S + L) is refused even where a lenient verifier would reduce it.
    const L = 2n ** 252n + 27742317777372353535851937790883648493n;
    let S = 0n;
    for (let i = 63; i >= 32; i--) S = (S << 8n) | BigInt(sig[i]!);
    const big = S + L;
    const hi = Buffer.alloc(32);
    for (let i = 0, v = big; i < 32; i++, v >>= 8n) hi[i] = Number(v & 0xffn);
    if (big < 2n ** 256n) expect(verifyEd25519Strict(k.pem, 'm', Buffer.concat([sig.subarray(0, 32), hi]).toString('base64'))).toBe(false);
    // A small-order service key in a key list breaks it and is never kept.
    const { store } = makeStore(1);
    const small = { v: 1, keys: [{ key_id: serviceKeyIdFromPem(pem), public_key_pem: pem, status: 'active', valid_from: '2026-01-01T00:00:00.000Z' }] };
    const rec = acceptServiceKeys(store, b.url, pinOf({ pem }), small);
    expect(rec.set).toBeNull();
    expect(rec.violations.join('\n')).toMatch(/public key is unusable or does not derive to its key_id/);
    store.close();
  });
});
