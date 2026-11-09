/**
 * The anchor service key-list model, as the service enforces it: isokron-anchor
 * PR #3 (fix/rollback-cache e28daa3) `src/core/genesis.ts` and
 * `src/core/servicekeys.ts`, vendored byte for byte in ./service-core/ (the
 * service's ed25519.ts and jcs.ts are small adapters there). A key list valid
 * for the service, its verification page and its client is valid here, and
 * one that is BROKEN there is BROKEN here. test/keychain.test.ts checks the
 * vendored files' SHA-256 against the service commit and holds lists the
 * service's scripts/rotate-key.mjs built and its own checkKeyChain judged.
 *
 * Signed statements (RFC 8785 canonical JSON, pure Ed25519, standard base64):
 *   successor   {key_id, public_key_pem, valid_from}               by the predecessor (signed_by)
 *   retired     {key_id, status, valid_to}                         by the successor (retirement_signed_by)
 *   revoked     {compromised_since, key_id, status, valid_to}      by the key itself or an earlier key
 */

import { isJsonObject } from './wire.js';
import type { ServiceKeyEntry } from './service-core/servicekeys.js';

export { publicKeyFromPem, verifySignature, type PublicKey } from './service-core/ed25519.js';
export { canonicalValidFrom, formatGenesisPin, parseGenesisPin, PRODUCTION_GENESIS, type GenesisPin } from './service-core/genesis.js';
export * from './service-core/servicekeys.js';

/** Entries of a key document ({keys: [...]}), string-typed fields kept, others dropped; null when it is not one. */
export function keyListOf(doc: unknown): ServiceKeyEntry[] | null {
  if (!isJsonObject(doc) || !Array.isArray(doc['keys'])) return null;
  const out: ServiceKeyEntry[] = [];
  const s = (x: unknown) => (typeof x === 'string' ? x : null);
  for (const e of doc['keys'] as unknown[]) {
    if (!isJsonObject(e) || typeof e['key_id'] !== 'string' || typeof e['public_key_pem'] !== 'string') return null;
    const entry: ServiceKeyEntry = { key_id: e['key_id'], public_key_pem: e['public_key_pem'] };
    for (const k of ['valid_from', 'valid_to', 'successor_signature', 'signed_by', 'retirement_signature', 'retirement_signed_by', 'compromised_since'] as const) {
      if (s(e[k]) !== null) entry[k] = s(e[k]);
    }
    if (s(e['status']) !== null) entry.status = s(e['status'])!;
    out.push(entry);
  }
  return out;
}
