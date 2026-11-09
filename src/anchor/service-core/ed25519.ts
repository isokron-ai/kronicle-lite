/**
 * Adapter: the surface of isokron-anchor `src/core/ed25519.ts` that the
 * vendored `servicekeys.ts` uses (PublicKey, publicKeyFromPem,
 * verifySignature), on kronicle-lite's node:crypto primitives. genesis.ts and
 * servicekeys.ts in this directory are the service's files byte for byte
 * (test/keychain.test.ts checks their SHA-256); this file and jcs.ts are the
 * only kronicle-lite code under them.
 */

import { chainIdFromPublicKeyPem } from '../../crypto/keys.js';
import { isUsableEd25519PublicKeyPem, verifyEd25519Strict } from '../ed25519-strict.js';

export interface PublicKey {
  pem: string;
  /** SHA-256 of the SPKI DER, hex. */
  chain_id: string;
}

export function publicKeyFromPem(pem: string): PublicKey {
  if (typeof pem !== 'string' || !isUsableEd25519PublicKeyPem(pem)) throw new Error('not a usable Ed25519 SPKI PEM');
  return { pem, chain_id: chainIdFromPublicKeyPem(pem) };
}

/** Strict Ed25519 (RFC 8032) over the UTF-8 message, base64 signature. */
export function verifySignature(pub: PublicKey, message: string, signatureB64: string): boolean {
  return typeof signatureB64 === 'string' && verifyEd25519Strict(pub.pem, message, signatureB64);
}
