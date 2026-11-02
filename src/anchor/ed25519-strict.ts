/**
 * Strict Ed25519 verification for the anchor paths (matches isokron-anchor
 * src/core/ed25519.ts after hardening A2-09).
 *
 * node:crypto (OpenSSL) accepts small-order public keys and a small-order R:
 * with the identity key, the signature R = identity, S = 0 verifies over
 * every message. The anchor service now refuses such keys and signatures;
 * the client refuses them too, for service keys, receipt countersignatures,
 * successor signatures and the checkpoint signatures it re-checks:
 *   - public key and R must be canonical encodings (y < p) and not of small
 *     order (the eight torsion points, any sign bit);
 *   - S must be < L.
 * Then the ordinary node:crypto verify runs.
 */

import { createPublicKey, verify as nodeVerify } from 'node:crypto';

const P = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

/** y-coordinates (sign bit cleared) of the canonical encodings of the 8 small-order points of edwards25519. */
const SMALL_ORDER_Y = new Set([
  '0000000000000000000000000000000000000000000000000000000000000000', // order 4 (two points, sign bit)
  '0100000000000000000000000000000000000000000000000000000000000000', // identity
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05', // order 8 (two points)
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a', // order 8 (two points)
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', // order 2 (y = p - 1)
]);

function leToBigInt(b: Uint8Array): bigint {
  let n = 0n;
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]!);
  return n;
}

/** A 32-byte point encoding that is canonical (y < p) and not of small order. */
export function isUsableEd25519Point(enc: Uint8Array): boolean {
  if (enc.length !== 32) return false;
  const y = Uint8Array.from(enc);
  y[31] = y[31]! & 0x7f;
  if (leToBigInt(y) >= P) return false; // non-canonical (covers p and p+1, i.e. 0 and 1 again)
  return !SMALL_ORDER_Y.has(Buffer.from(y).toString('hex'));
}

/** Raw 32-byte public key from an Ed25519 SPKI PEM, or null when it is not one. */
export function rawEd25519PublicKey(pem: string): Uint8Array | null {
  try {
    const k = createPublicKey(pem);
    if (k.asymmetricKeyType !== 'ed25519') return null;
    const der = k.export({ type: 'spki', format: 'der' }) as Buffer;
    return der.length === 44 ? new Uint8Array(der.subarray(12)) : null;
  } catch {
    return null;
  }
}

/** An Ed25519 public key PEM whose point is canonical and not of small order. */
export function isUsableEd25519PublicKeyPem(pem: string): boolean {
  const raw = rawEd25519PublicKey(pem);
  return raw !== null && isUsableEd25519Point(raw);
}

/** Strict verify: usable key, usable R, S < L, then Ed25519. Never throws. */
export function verifyEd25519Strict(public_key_pem: string, message: string | Uint8Array, signature_base64: string): boolean {
  try {
    if (!isUsableEd25519PublicKeyPem(public_key_pem)) return false;
    const sig = Buffer.from(signature_base64, 'base64');
    if (sig.length !== 64) return false;
    if (!isUsableEd25519Point(sig.subarray(0, 32))) return false;
    if (leToBigInt(sig.subarray(32)) >= L) return false;
    const msg = typeof message === 'string' ? Buffer.from(message, 'utf8') : message;
    return nodeVerify(null, msg, createPublicKey(public_key_pem), sig);
  } catch {
    return false;
  }
}
