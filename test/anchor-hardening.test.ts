/**
 * 0.8.1 hardening track 6 (kronicle-lite anchor client): regression tests for
 * A2-01, A2-04, A2-11, A2-12, A2-17 and A2-20. Every test runs against the
 * in-process anchor stub (test/helpers/anchor-stub.ts), optionally behind a
 * rewriting `fetch` or a loopback proxy standing in for a MITM / malicious
 * anchor_url. Nothing leaves 127.0.0.1.
 */

import { spawn } from 'node:child_process';
import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { pushCheckpoint, verifyLastAnchor, verifyRemote } from '../src/anchor/anchor.js';
import { AnchorClient } from '../src/anchor/client.js';
import { AnchorConfigError, assertAnchorTransport } from '../src/anchor/config.js';
import { anchorReceiptJcs, anchorReceiptSigningPayload, type AnchorReceipt } from '../src/anchor/receipt.js';
import {
  PINS_FILE,
  readPinFile,
  reconcileServiceKeys,
  serviceKeyIdFromPem,
  serviceKeyRefusal,
  verifyReceiptWithPins,
  writePinFile,
  type PinnedServiceKey,
} from '../src/anchor/trust.js';
import { checkpointSigningPayload } from '../src/chain/chain.js';
import { canonicalize } from '../src/crypto/canonical.js';
import { KronicleLite } from '../src/store.js';
import { startAnchorStub, type AnchorBackend } from './helpers/anchor-stub.js';

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

function pin(pem: string, extra: Partial<PinnedServiceKey> = {}): PinnedServiceKey {
  return {
    key_id: serviceKeyIdFromPem(pem),
    public_key_pem: pem,
    status: 'active',
    valid_from: null,
    valid_to: null,
    source: 'operator',
    pinned_at: new Date().toISOString(),
    signed_by: null,
    issuer: null,
    ...extra,
  };
}

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
    const drop = rewriting((path, j) => {
      if (path.startsWith('/v1/chains/')) j.anchors = (j.anchors ?? []).filter((x) => x['anchor_id'] !== second.anchor_id);
      return j;
    });
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

  // ───────────────────────────── A2-12 ─────────────────────────────

  it('A2-12: first use pins the service key (TOFU, 0600); a MITM key under the real key_id is refused and never overwrites the pin', async () => {
    const { dataDir, store } = makeStore();
    const p = await pushCheckpoint(store, opts());
    expect(p.key_notes.join('\n')).toMatch(/pinned 1 anchor service key\(s\) .* on first use/);
    const pinsBefore = readFileSync(join(dataDir, PINS_FILE), 'utf8');
    const pins = readPinFile(store);
    expect(pins).toHaveLength(1);
    expect(pins[0]).toMatchObject({ source: 'tofu', status: 'active' });
    if (process.platform !== 'win32') expect((await import('node:fs')).statSync(join(dataDir, PINS_FILE)).mode & 0o777).toBe(0o600);

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
    expect(r.problems.join('\n')).toMatch(/derives to anchor-ed25519-[0-9a-f]{16}; refusing it/);
    expect(r.checks[0]).toMatchObject({ result: 'unverified', countersignature: 'failed' });
    expect(readFileSync(join(dataDir, PINS_FILE), 'utf8')).toBe(pinsBefore);

    // Attacker key under its OWN key_id: not pinned, no successor signature → receipts untrusted.
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
    expect(r2.notes.join('\n')).toMatch(/not pinned and carries no valid successor signature/);
    expect(r2.problems.join('\n')).toMatch(new RegExp(`service key ${atk.id} is not pinned`));
    expect(readFileSync(join(dataDir, PINS_FILE), 'utf8')).toBe(pinsBefore);
    store.close();
  });

  it('A2-12: receipt.checkpoint.signature is re-checked against the local chain key', async () => {
    const { store } = makeStore();
    const svc = ed25519();
    writePinFile(store, [pin(svc.pem)]);
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
    record(base);
    expect((await verifyRemote(store, { anchorUrl: b.url, offline: true })).ok).toBe(true);
    // A service-signed receipt whose checkpoint root the chain key never signed.
    const forgedRoot = createHash('sha256').update('other').digest('hex');
    record(resign(base, svc.priv, { checkpoint: { ...base.checkpoint, root: forgedRoot } }));
    const r = await verifyRemote(store, { anchorUrl: b.url, offline: true });
    expect(r.ok).toBe(false);
    expect(r.problems.join('\n')).toMatch(/checkpoint signature does not verify against the local chain key/);
    expect(checkpointSigningPayload(base.checkpoint)).toContain(cp.root);
    store.close();
  });

  it('A2-12: rotation needs a successor signature from a pinned key; config pins switch first-use pinning off', () => {
    const { dataDir, store } = makeStore(1);
    const k1 = ed25519();
    const k2 = ed25519();
    const k3 = ed25519();
    writePinFile(store, [pin(k1.pem, { source: 'tofu' })]);
    const entry = (k: { pem: string; id: string }, extra: Record<string, unknown> = {}) => ({
      key_id: k.id,
      public_key_pem: k.pem,
      status: 'active',
      valid_from: '2026-11-01T00:00:00.000Z',
      valid_to: null,
      ...extra,
    });
    const succSig = (signer: KeyObject, k: { pem: string; id: string }) =>
      sign(null, Buffer.from(canonicalize({ key_id: k.id, public_key_pem: k.pem, valid_from: '2026-11-01T00:00:00.000Z' }), 'utf8'), signer).toString('base64');
    // k2 with a valid successor signature by k1; k3 signed by k2 (chained); a bogus one for k3 first.
    const doc = {
      v: 1,
      keys: [
        entry(k1, { status: 'retired', valid_to: '2026-11-02T00:00:00.000Z' }),
        entry(k3, { signed_by: k2.id, successor_signature: succSig(k2.priv, k3) }),
        entry(k2, { signed_by: k1.id, successor_signature: succSig(k1.priv, k2) }),
      ],
    };
    const rec = reconcileServiceKeys(store, b.url, doc);
    expect(rec.violations).toEqual([]);
    const ids = Object.fromEntries(rec.keys.map((k) => [k.key_id, k]));
    expect(ids[k2.id]).toMatchObject({ source: 'successor', signed_by: k1.id });
    expect(ids[k3.id]).toMatchObject({ source: 'successor', signed_by: k2.id });
    expect(ids[k1.id]).toMatchObject({ status: 'retired', valid_to: '2026-11-02T00:00:00.000Z' });

    // A forged successor signature (by a non-pinned key) is not enough.
    const fresh = makeStore(1);
    writePinFile(fresh.store, [pin(k1.pem, { source: 'tofu' })]);
    const k4 = ed25519();
    const bad = reconcileServiceKeys(fresh.store, b.url, { v: 1, keys: [entry(k1), entry(k2, { signed_by: k1.id, successor_signature: succSig(k4.priv, k2) })] });
    expect(bad.keys.map((k) => k.key_id)).toEqual([k1.id]);
    expect(bad.notes.join('\n')).toMatch(new RegExp(`${k2.id} .* not pinned`));

    // Tighten-only: a later document cannot un-revoke or extend a pin.
    reconcileServiceKeys(fresh.store, b.url, { v: 1, keys: [entry(k1, { status: 'revoked' })] });
    const again = reconcileServiceKeys(fresh.store, b.url, { v: 1, keys: [entry(k1, { status: 'active' })] });
    expect(again.keys.find((k) => k.key_id === k1.id)!.status).toBe('revoked');
    fresh.store.close();

    // Config pins: authoritative, so an empty pin file does not TOFU an unknown key.
    const cfgd = makeStore(1);
    const cfgFile = join(cfgd.dataDir, 'config.json');
    writeFileSync(cfgFile, JSON.stringify({ anchor_url: b.url, service_key_pins: [k1.pem] }));
    const c = reconcileServiceKeys(cfgd.store, b.url, { v: 1, keys: [entry(k3)] });
    expect(c.keys.map((k) => k.key_id)).toEqual([k1.id]);
    expect(c.keys[0]!.source).toBe('config');
    expect(existsSync(join(cfgd.dataDir, PINS_FILE))).toBe(false);
    cfgd.store.close();
    store.close();
    expect(dataDir).toBeTruthy();
  });

  it('A2-12: anchor keys CLI lists, adds, removes and resets pins', async () => {
    const { dataDir, store } = makeStore(1);
    store.close();
    expect((await cli(['anchor', 'keys', '--data-dir', dataDir, '--url', b.url])).stdout).toMatch(/no anchor service key pinned/);
    const k = ed25519();
    const pemFile = join(dataDir, '..', 'svc.pem');
    writeFileSync(pemFile, k.pem);
    const add = await cli(['anchor', 'keys', 'add', pemFile, '--data-dir', dataDir]);
    expect(add.status, add.stderr).toBe(0);
    const list = await cli(['anchor', 'keys', 'list', '--data-dir', dataDir, '--url', b.url, '--json']);
    expect(JSON.parse(list.stdout).keys).toMatchObject([{ key_id: k.id, source: 'operator' }]);
    // With an operator pin in place the stub's key is not trusted: push is refused, nothing stored.
    const push = await cli(['checkpoint', '--push', '--data-dir', dataDir], { KRONICLE_ANCHOR_URL: b.url, KRONICLE_ANCHOR_KEY: b.license });
    expect(push.status).toBe(2);
    expect(push.stderr).toMatch(/anchor receipt rejected: service key anchor-ed25519-[0-9a-f]{16} is not pinned/);
    expect((await cli(['anchor', 'keys', 'remove', k.id, '--data-dir', dataDir])).status).toBe(0);
    expect((await cli(['anchor', 'keys', 'reset', '--data-dir', dataDir])).status).toBe(0);
    expect((await cli(['anchor', 'keys', 'bogus', '--data-dir', dataDir])).status).toBe(2);
  });

  // ───────────────────────────── A2-04 ─────────────────────────────

  it('A2-04: key status and validity window are enforced against the receipt’s signed time', async () => {
    const t = '2026-11-01T12:00:00.000Z';
    expect(serviceKeyRefusal({ key_id: 'k', status: 'active', valid_from: '2026-11-01T00:00:00.000Z', valid_to: null }, t)).toBeNull();
    expect(serviceKeyRefusal({ key_id: 'k', status: 'retired', valid_from: '2026-10-01T00:00:00.000Z', valid_to: '2026-11-02T00:00:00.000Z' }, t)).toBeNull();
    expect(serviceKeyRefusal({ key_id: 'k', status: 'retired', valid_from: null, valid_to: '2026-11-01T06:00:00.000Z' }, t)).toMatch(/after .* valid_to/);
    expect(serviceKeyRefusal({ key_id: 'k', status: 'active', valid_from: '2026-11-02T00:00:00.000Z', valid_to: null }, t)).toMatch(/before .* valid_from/);
    expect(serviceKeyRefusal({ key_id: 'k', status: 'compromised' }, t)).toMatch(/status compromised/);
    expect(serviceKeyRefusal({ key_id: 'k', status: 'revoked' }, t)).toMatch(/status revoked/);
    expect(serviceKeyRefusal({ key_id: 'k' }, t)).toMatch(/status unknown/);

    const { store } = makeStore(1);
    await pushCheckpoint(store, opts());
    const receipt = JSON.parse(store.chain.lastAnchor()!.receipt_json) as AnchorReceipt;
    const [p] = readPinFile(store);
    expect(verifyReceiptWithPins(receipt, [p!]).ok).toBe(true);
    expect(verifyReceiptWithPins(receipt, [{ ...p!, status: 'compromised' }])).toMatchObject({ ok: false, reason: expect.stringMatching(/compromised/) });
    expect(verifyReceiptWithPins(receipt, [{ ...p!, valid_to: '2020-01-01T00:00:00.000Z' }]).ok).toBe(false);
    // The unpinned client check applies the same rules.
    const doc = (await (await fetch(`${b.url}/.well-known/anchor-keys.json`)).json()) as { v: 1; issuer: string; keys: { key_id: string; public_key_pem: string; status: string; valid_from: string; valid_to: string | null }[] };
    await expect(new AnchorClient(b.url, { preloadedKeys: { ...doc, keys: [{ ...doc.keys[0]!, status: 'compromised' }] } }).verifyReceipt(receipt)).rejects.toThrow(/not published \(or not usable\)/);
    await expect(new AnchorClient(b.url, { preloadedKeys: { ...doc, keys: [{ ...doc.keys[0]!, status: 'retired', valid_to: '2020-01-01T00:00:00.000Z' }] } }).verifyReceipt(receipt)).rejects.toThrow(/valid_to/);
    // A served status change is pinned (tighten-only) and fails the next verify.
    const revoke = rewriting((path, j) => {
      if (path === '/.well-known/anchor-keys.json') j.keys = [{ ...j.keys![0]!, status: 'revoked' }];
      return j;
    });
    expect((await verifyRemote(store, { ...opts(), fetch: revoke })).ok).toBe(false);
    expect((await verifyRemote(store, opts())).ok).toBe(false); // still revoked locally
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
});
