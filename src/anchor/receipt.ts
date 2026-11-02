/**
 * Anchor receipt v1 — what the hosted anchor service countersigns and the
 * client stores in `anchors.receipt_json`. Ported from isokron-anchor
 * `src/core/receipt.ts` with kronicle-lite's own canonicalize and Ed25519
 * verify (node:crypto) in place of the isomorphic ones.
 *
 * {
 *   "v": 1,
 *   "anchor_id": "<uuidv7>",
 *   "chain_id": "<sha256 hex of SPKI DER>",
 *   "key_id": "ed25519-…",
 *   "checkpoint": { FORMAT §2 wire object, incl. the client signature },
 *   "received_at": "2026-11-02T03:14:07.120Z",
 *   "tier": "free" | "pro",
 *   "service_key_id": "anchor-ed25519-<16hex>",
 *   "verified": ["chain_id","key_id","signature","range"],
 *   "signature": "<b64 Ed25519 over canonicalize(receipt minus signature)>"
 * }
 *
 * Not to be confused with the retrieval receipt v2 in src/recall/receipt.ts.
 */

import { canonicalize } from '../crypto/canonical.js';
import { sha256Hex } from '../crypto/hash.js';
import { verifyEd25519Strict } from './ed25519-strict.js';
import { checkpointForReceipt, isJsonObject, parseWireCheckpoint, type WireCheckpoint } from './wire.js';

export const ANCHOR_RECEIPT_VERSION = 1 as const;
export type AnchorTier = 'free' | 'pro';

/** Exactly what the service verifies before countersigning. */
export const VERIFIED_CLAIMS = ['chain_id', 'key_id', 'signature', 'range'] as const;
/** What a countersignature cannot vouch for. */
export const UNVERIFIED_CLAIMS = [
  'that root covers real events (the server never sees leaves)',
  'that [1..N+k] extends an earlier [1..N] (no consistency proof in v1)',
  'who holds the signing key (signature = possession; the license key only pays)',
] as const;

export interface AnchorReceiptBody {
  v: 1;
  anchor_id: string;
  chain_id: string;
  key_id: string;
  checkpoint: WireCheckpoint;
  received_at: string;
  tier: AnchorTier;
  service_key_id: string;
  verified: string[];
}

export interface AnchorReceipt extends AnchorReceiptBody {
  signature: string;
}

export function anchorReceiptSigningPayload(body: AnchorReceiptBody | AnchorReceipt): string {
  const { signature: _drop, ...rest } = body as AnchorReceipt;
  void _drop;
  return canonicalize(rest);
}

/** JCS bytes of the full receipt (what `anchors.receipt_json` stores). */
export function anchorReceiptJcs(receipt: AnchorReceipt): string {
  return canonicalize(receipt);
}

/** The public-log leaf value for this receipt: sha256(JCS(receipt)). */
export function anchorReceiptHash(receipt: AnchorReceipt): string {
  return sha256Hex(anchorReceiptJcs(receipt));
}

/** Strict Ed25519 (no small-order key or R, S < L), as the service verifies since hardening A2-09. */
export function verifyAnchorReceiptSignature(receipt: AnchorReceipt, service_public_key_pem: string): boolean {
  return verifyEd25519Strict(service_public_key_pem, anchorReceiptSigningPayload(receipt), receipt.signature);
}

export type AnchorReceiptParseError = 'not_an_object' | 'bad_version' | 'bad_field' | 'bad_checkpoint';

export function parseAnchorReceipt(
  input: unknown,
): { ok: true; value: AnchorReceipt } | { ok: false; error: AnchorReceiptParseError; detail: string } {
  if (!isJsonObject(input)) return { ok: false, error: 'not_an_object', detail: 'receipt must be a JSON object' };
  if (input['v'] !== ANCHOR_RECEIPT_VERSION) return { ok: false, error: 'bad_version', detail: 'receipt.v must be 1' };
  const str = (k: string, re?: RegExp): string | null => {
    const v = input[k];
    if (typeof v !== 'string' || v.length === 0) return null;
    if (re && !re.test(v)) return null;
    return v;
  };
  const anchor_id = str('anchor_id', /^[0-9a-f-]{36}$/);
  const chain_id = str('chain_id', /^[0-9a-f]{64}$/);
  const key_id = str('key_id', /^ed25519-[0-9a-f]{16}$/);
  const received_at = str('received_at', /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  const tier = str('tier', /^(free|pro)$/) as AnchorTier | null;
  const service_key_id = str('service_key_id', /^anchor-ed25519-[0-9a-f]{16}$/);
  const signature = str('signature', /^[A-Za-z0-9+/]{86}==$/);
  const verified = input['verified'];
  for (const [k, v] of Object.entries({ anchor_id, chain_id, key_id, received_at, tier, service_key_id, signature })) {
    if (v === null) return { ok: false, error: 'bad_field', detail: `receipt.${k} missing or malformed` };
  }
  if (!Array.isArray(verified) || !verified.every((x) => typeof x === 'string')) {
    return { ok: false, error: 'bad_field', detail: 'receipt.verified must be a string array' };
  }
  const cp = parseWireCheckpoint(input['checkpoint']);
  if (!cp.ok) return { ok: false, error: 'bad_checkpoint', detail: `receipt.checkpoint: ${cp.detail}` };
  if (cp.value.key_id !== key_id) return { ok: false, error: 'bad_field', detail: 'receipt.key_id ≠ checkpoint.key_id' };
  const allowed = new Set(['v', 'anchor_id', 'chain_id', 'key_id', 'checkpoint', 'received_at', 'tier', 'service_key_id', 'verified', 'signature']);
  for (const k of Object.keys(input)) {
    if (!allowed.has(k)) return { ok: false, error: 'bad_field', detail: `unexpected receipt field ${k}` };
  }
  return {
    ok: true,
    value: {
      v: 1,
      anchor_id: anchor_id!,
      chain_id: chain_id!,
      key_id: key_id!,
      checkpoint: checkpointForReceipt(cp.value),
      received_at: received_at!,
      tier: tier!,
      service_key_id: service_key_id!,
      verified: verified as string[],
      signature: signature!,
    },
  };
}
