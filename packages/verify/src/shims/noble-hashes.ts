/**
 * The @noble/hashes functions kronicle-lite's src/crypto/hash.ts imports (sha2.js, blake3.js,
 * utils.js), on node:crypto. SHA-256 is all verification needs. BLAKE3 addresses blocks in the
 * document store, which a pack does not contain; node:crypto has no BLAKE3, so it throws.
 */
import { createHash } from 'node:crypto';

export function sha256(msg: Uint8Array): Uint8Array {
  if (!(msg instanceof Uint8Array)) throw new Error('Uint8Array expected');
  return new Uint8Array(createHash('sha256').update(msg).digest());
}

export function blake3(_msg: Uint8Array): Uint8Array {
  throw new Error('BLAKE3 is not part of the standalone verifier (evidence packs do not use it)');
}

export function utf8ToBytes(str: string): Uint8Array {
  if (typeof str !== 'string') throw new Error('string expected');
  return new Uint8Array(new TextEncoder().encode(str));
}

export function bytesToHex(bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array)) throw new Error('Uint8Array expected');
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('hex');
}
