/**
 * Minimal in-test HTTP stub of the hosted anchor service (isokron-anchor),
 * implementing the same wire contract the client uses:
 *
 *   POST /v1/anchor                 bearer → shape → sha256(SPKI)==chain_id →
 *                                   key_id derivation → Ed25519 over FORMAT §2 →
 *                                   idempotency (200 duplicate) → conflict scan
 *                                   (409, chain flagged) → countersign (201)
 *   GET  /v1/chains/:chain_id       chain view with every anchor + receipt (404 JSON when unknown)
 *   GET  /.well-known/anchor-keys.json
 *
 * Used when the real Worker (KRONICLE_ANCHOR_WORKER_DIR) is not available,
 * which includes CI. No quotas, no rate limits, no R2/D1.
 */

import { createPublicKey, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';

import { checkpointPayloadHash, parseWireCheckpoint, type WireCheckpoint } from '../../src/anchor/wire.js';
import { anchorReceiptSigningPayload, type AnchorReceipt, type AnchorReceiptBody } from '../../src/anchor/receipt.js';
import { checkpointSigningPayload } from '../../src/chain/chain.js';
import { canonicalize } from '../../src/crypto/canonical.js';
import { sha256Hex } from '../../src/crypto/hash.js';
import { chainIdFromPublicKeyPem, keyIdFromPublicKey, verifyEd25519 } from '../../src/crypto/keys.js';

export const STUB_LICENSE = 'KLA_stub-free-0001';

export interface AnchorBackend {
  url: string;
  license: string;
  stop(): Promise<void>;
}

interface Row {
  anchor_id: string;
  chain_id: string;
  payload_hash: string;
  checkpoint: WireCheckpoint;
  received_at: string;
  receipt: AnchorReceipt;
  receipt_json: string;
  conflict: boolean;
}

export async function startAnchorStub(): Promise<AnchorBackend> {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const servicePem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
  const service_key_id = `anchor-ed25519-${chainIdFromPublicKeyPem(servicePem).slice(0, 16)}`;
  const rows: Row[] = [];
  const chains = new Map<string, { key_id: string; pubkey: string; conflict: boolean }>();
  let base = '';

  const send = (res: ServerResponse, status: number, body: unknown) => {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  };
  const publicView = () => ({
    status: 'pending_public',
    day: null,
    leaf_index: null,
    path: null,
    ots: null,
    rekor_uuid: null,
    note: 'service-signed only; not yet in public logs',
  });
  const anchorResponse = (row: Row, duplicate: boolean, conflicting: string[]) => {
    const conflict = conflicting.length > 0 || row.conflict;
    return {
      ok: true,
      anchor_id: row.anchor_id,
      duplicate,
      conflict,
      ...(conflict ? { error: 'conflict', detail: 'same chain and range were anchored with a different root', conflicting_anchor_ids: conflicting } : {}),
      receipt: row.receipt,
      receipt_jcs: row.receipt_json,
      receipt_hash: sha256Hex(row.receipt_json),
      public: publicView(),
      verify_url: `${base}/v/${row.chain_id}`,
      receipt_url: `${base}/v1/receipts/${row.anchor_id}`,
    };
  };
  const conflictsFor = (chain_id: string, cp: WireCheckpoint) =>
    rows.filter((r) => r.chain_id === chain_id && r.checkpoint.from_seq === cp.from_seq && r.checkpoint.to_seq === cp.to_seq && r.checkpoint.root !== cp.root);

  const handle = async (req: IncomingMessage, res: ServerResponse, body: string) => {
    const url = new URL(req.url ?? '/', 'http://stub');
    if (req.method === 'GET' && url.pathname === '/.well-known/anchor-keys.json') {
      return send(res, 200, {
        v: 1,
        issuer: base,
        keys: [{ key_id: service_key_id, alg: 'Ed25519', public_key_pem: servicePem, valid_from: '2026-11-01T00:00:00.000Z', valid_to: null, status: 'active' }],
      });
    }
    const chainMatch = /^\/v1\/chains\/([^/]+)$/.exec(url.pathname);
    if (req.method === 'GET' && chainMatch) {
      const chain_id = chainMatch[1]!;
      const c = chains.get(chain_id);
      if (!c) return send(res, 404, { error: 'unknown_chain', detail: 'nothing anchored for this chain_id' });
      const mine = rows.filter((r) => r.chain_id === chain_id).sort((a, b) => a.received_at.localeCompare(b.received_at));
      return send(res, 200, {
        chain_id,
        key_id: c.key_id,
        pubkey: c.pubkey,
        erased: false,
        conflict: c.conflict,
        anchor_count: mine.length,
        anchors: mine.map((r) => ({
          anchor_id: r.anchor_id,
          from_seq: r.checkpoint.from_seq,
          to_seq: r.checkpoint.to_seq,
          leaf_count: r.checkpoint.leaf_count,
          root: r.checkpoint.root,
          key_id: r.checkpoint.key_id,
          client_sig: r.checkpoint.signature,
          received_at: r.received_at,
          tier: 'free',
          service_key_id,
          service_sig: r.receipt.signature,
          receipt_hash: sha256Hex(r.receipt_json),
          conflict: r.conflict,
          public: publicView(),
          receipt: r.receipt,
        })),
        verify_url: `${base}/v/${chain_id}`,
      });
    }
    if (req.method === 'POST' && url.pathname === '/v1/anchor') {
      const auth = req.headers['authorization'] ?? '';
      if (auth !== `Bearer ${STUB_LICENSE}`) return send(res, 401, { error: 'invalid_license', detail: 'license key not recognized' });
      let j: Record<string, unknown>;
      try {
        j = JSON.parse(body) as Record<string, unknown>;
      } catch {
        return send(res, 400, { error: 'bad_json', detail: 'body is not valid JSON' });
      }
      const chain_id = j['chain_id'];
      const pem = j['pubkey'];
      if (typeof chain_id !== 'string' || !/^[0-9a-f]{64}$/.test(chain_id)) return send(res, 400, { error: 'bad_chain_id', detail: 'chain_id' });
      if (typeof pem !== 'string') return send(res, 400, { error: 'bad_pubkey', detail: 'pubkey' });
      let derivedChain: string;
      let derivedKey: string;
      try {
        derivedChain = chainIdFromPublicKeyPem(pem);
        derivedKey = keyIdFromPublicKey(createPublicKey(pem));
      } catch (e) {
        return send(res, 400, { error: 'bad_pubkey', detail: (e as Error).message });
      }
      if (derivedChain !== chain_id) return send(res, 422, { error: 'chain_id_mismatch', detail: 'sha256(SPKI DER) ≠ chain_id' });
      const cp = parseWireCheckpoint(j['checkpoint']);
      if (!cp.ok) return send(res, 400, { error: `checkpoint_${cp.error}`, detail: cp.detail });
      if (cp.value.key_id !== derivedKey) return send(res, 422, { error: 'key_id_mismatch', detail: 'key_id' });
      if (!verifyEd25519(pem, checkpointSigningPayload(cp.value), cp.value.signature)) {
        return send(res, 422, { error: 'signature_invalid', detail: 'Ed25519 signature does not verify' });
      }
      const payload_hash = checkpointPayloadHash(cp.value);
      const existing = rows.find((r) => r.chain_id === chain_id && r.payload_hash === payload_hash);
      if (existing) {
        const ids = existing.conflict ? conflictsFor(chain_id, cp.value).map((r) => r.anchor_id) : [];
        return send(res, 200, anchorResponse(existing, true, ids));
      }
      const conflicts = conflictsFor(chain_id, cp.value);
      const received_at = new Date().toISOString();
      const anchor_id = randomUUID();
      const bodyR: AnchorReceiptBody = {
        v: 1,
        anchor_id,
        chain_id,
        key_id: derivedKey,
        checkpoint: cp.value,
        received_at,
        tier: 'free',
        service_key_id,
        verified: ['chain_id', 'key_id', 'signature', 'range'],
      };
      const signature = sign(null, Buffer.from(anchorReceiptSigningPayload(bodyR), 'utf8'), privateKey).toString('base64');
      const receipt: AnchorReceipt = { ...bodyR, signature };
      const row: Row = {
        anchor_id,
        chain_id,
        payload_hash,
        checkpoint: cp.value,
        received_at,
        receipt,
        receipt_json: canonicalize(receipt),
        conflict: conflicts.length > 0,
      };
      rows.push(row);
      for (const other of conflicts) other.conflict = true; // both sides of a conflict are flagged, as the Worker does
      const c = chains.get(chain_id) ?? { key_id: derivedKey, pubkey: pem, conflict: false };
      if (conflicts.length > 0) c.conflict = true;
      chains.set(chain_id, c);
      return send(res, conflicts.length > 0 ? 409 : 201, anchorResponse(row, false, conflicts.map((r) => r.anchor_id)));
    }
    return send(res, 404, { error: 'not_found', detail: url.pathname });
  };

  const server = createServer((req, res) => {
    let body = '';
    req.setEncoding('utf8');
    req.on('data', (c: string) => (body += c));
    req.on('end', () => {
      void handle(req, res, body).catch((e: unknown) => send(res, 500, { error: 'stub_error', detail: String(e) }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`;
  return {
    url: base,
    license: STUB_LICENSE,
    stop: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
