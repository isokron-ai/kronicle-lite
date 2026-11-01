/**
 * Wire shape of a FORMAT §2 checkpoint as the hosted anchor service takes it
 * and as it comes back inside an anchor receipt. Ported from isokron-anchor
 * `src/core/checkpoint.ts`; the signing payload itself is NOT duplicated —
 * `checkpointSigningPayload` is kronicle-lite's own (src/chain/chain.ts).
 *
 *   { v: 1, from_seq, to_seq, leaf_count, root, key_id, signature }
 *
 * Shape and arithmetic only: the service never sees leaves.
 */

import { checkpointSigningPayload, CHECKPOINT_VERSION } from '../chain/chain.js';
import { sha256Hex } from '../crypto/hash.js';

/** 1 ≤ from ≤ to ≤ 2^40 (service limit). */
export const MAX_SEQ = 2 ** 40;

export interface WireCheckpoint {
  v: 1;
  from_seq: number;
  to_seq: number;
  leaf_count: number;
  root: string;
  key_id: string;
  signature: string;
}

export type WireCheckpointError =
  | 'not_an_object'
  | 'bad_version'
  | 'bad_from_seq'
  | 'bad_to_seq'
  | 'range_inverted'
  | 'range_too_large'
  | 'bad_leaf_count'
  | 'leaf_count_mismatch'
  | 'bad_root'
  | 'bad_key_id'
  | 'bad_signature';

export type WireParseResult<T, E extends string> = { ok: true; value: T } | { ok: false; error: E; detail: string };

const HEX64 = /^[0-9a-f]{64}$/;
const KEY_ID = /^ed25519-[0-9a-f]{16}$/;
const B64_SIG = /^[A-Za-z0-9+/]{86}==$/; // 64 bytes

export function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isUint(n: unknown): n is number {
  return typeof n === 'number' && Number.isInteger(n) && n >= 0;
}

/** Shape + arithmetic only. Extra keys are ignored on input and never emitted. */
export function parseWireCheckpoint(input: unknown): WireParseResult<WireCheckpoint, WireCheckpointError> {
  if (!isJsonObject(input)) return { ok: false, error: 'not_an_object', detail: 'checkpoint must be a JSON object' };
  const cp = input;
  if (cp['v'] !== CHECKPOINT_VERSION) return { ok: false, error: 'bad_version', detail: 'checkpoint.v must be 1' };
  const from_seq = cp['from_seq'];
  const to_seq = cp['to_seq'];
  const leaf_count = cp['leaf_count'];
  if (!isUint(from_seq) || from_seq < 1) return { ok: false, error: 'bad_from_seq', detail: 'from_seq must be an integer ≥ 1' };
  if (!isUint(to_seq) || to_seq < 1) return { ok: false, error: 'bad_to_seq', detail: 'to_seq must be an integer ≥ 1' };
  if (to_seq < from_seq) return { ok: false, error: 'range_inverted', detail: 'to_seq must be ≥ from_seq' };
  if (to_seq > MAX_SEQ) return { ok: false, error: 'range_too_large', detail: 'to_seq must be ≤ 2^40' };
  if (!isUint(leaf_count) || leaf_count < 1) return { ok: false, error: 'bad_leaf_count', detail: 'leaf_count must be an integer ≥ 1' };
  if (leaf_count !== to_seq - from_seq + 1) {
    return { ok: false, error: 'leaf_count_mismatch', detail: `leaf_count must equal to_seq - from_seq + 1 (${to_seq - from_seq + 1})` };
  }
  const root = cp['root'];
  if (typeof root !== 'string' || !HEX64.test(root)) return { ok: false, error: 'bad_root', detail: 'root must be 64 lowercase hex chars' };
  const key_id = cp['key_id'];
  if (typeof key_id !== 'string' || !KEY_ID.test(key_id)) {
    return { ok: false, error: 'bad_key_id', detail: 'key_id must look like ed25519-<16 hex>' };
  }
  const signature = cp['signature'];
  if (typeof signature !== 'string' || !B64_SIG.test(signature)) {
    return { ok: false, error: 'bad_signature', detail: 'signature must be base64 of 64 bytes' };
  }
  return { ok: true, value: { v: 1, from_seq, to_seq, leaf_count, root, key_id, signature } };
}

/** sha256 hex of the §2 signing payload — the service's idempotency key component. */
export function checkpointPayloadHash(cp: Pick<WireCheckpoint, 'from_seq' | 'to_seq' | 'leaf_count' | 'root'>): string {
  return sha256Hex(checkpointSigningPayload(cp));
}

/** Strip to exactly the §2 object a receipt carries. */
export function checkpointForReceipt(cp: WireCheckpoint): WireCheckpoint {
  return {
    v: 1,
    from_seq: cp.from_seq,
    to_seq: cp.to_seq,
    leaf_count: cp.leaf_count,
    root: cp.root,
    key_id: cp.key_id,
    signature: cp.signature,
  };
}
