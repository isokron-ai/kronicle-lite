/**
 * Local server identity: one Ed25519 signing key and one HMAC secret for
 * cursor tokens. Both live in the data directory, created on first run.
 *
 *   <data-dir>/signing-key.pem   PKCS#8 PEM, Ed25519 private key (mode 0600)
 *   <data-dir>/cursor-secret     32 random bytes, hex (mode 0600)
 *
 * The public key is also written into the `signing_keys` table so a copy of
 * the database alone can verify receipts and checkpoints. Lite proves
 * integrity against the local key — it is not third-party notarization. See
 * docs/THREAT-MODEL.md.
 */

import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from 'node:crypto';
import { join } from 'node:path';

import { CorruptFileError, ensureDir, readOrCreateOnce } from '../util/once-file.js';
import { sha256Hex } from './hash.js';

export interface Signer {
  readonly key_id: string;
  readonly public_key_pem: string;
  sign(message: Uint8Array | string): string; // base64
}

export interface ServerIdentity {
  readonly signer: Signer;
  readonly cursor_secret: string;
  readonly data_dir: string | null;
  /** 0.8.1 (C2-03): this open created a new cursor-secret for an existing store: every earlier cursor is now unreadable. */
  readonly cursor_secret_regenerated?: boolean;
  /** 0.8.1: set when this open had to create the cursor-secret file. */
  readonly cursor_secret_created?: boolean;
}

/** key_id = first 16 hex chars of sha256(SPKI DER of the public key). */
export function keyIdFromPublicKey(pub: KeyObject): string {
  const der = pub.export({ type: 'spki', format: 'der' }) as Buffer;
  return `ed25519-${sha256Hex(new Uint8Array(der)).slice(0, 16)}`;
}

/**
 * chain_id = sha256 hex of the SPKI DER of the public key — the same DER
 * `keyIdFromPublicKey` hashes, kept whole. The hosted anchor service keys a
 * chain by it (key_id is its first 16 hex chars with an `ed25519-` prefix).
 */
export function chainIdFromPublicKeyPem(public_key_pem: string): string {
  const der = createPublicKey(public_key_pem).export({ type: 'spki', format: 'der' }) as Buffer;
  return sha256Hex(new Uint8Array(der));
}

export function signerFromPrivateKey(priv: KeyObject): Signer {
  const pub = createPublicKey(priv);
  const public_key_pem = pub.export({ type: 'spki', format: 'pem' }) as string;
  const key_id = keyIdFromPublicKey(pub);
  return {
    key_id,
    public_key_pem,
    sign(message) {
      const bytes = typeof message === 'string' ? Buffer.from(message, 'utf8') : message;
      return edSign(null, bytes, priv).toString('base64');
    },
  };
}

export function verifyEd25519(
  public_key_pem: string,
  message: Uint8Array | string,
  signature_base64: string,
): boolean {
  try {
    const bytes = typeof message === 'string' ? Buffer.from(message, 'utf8') : message;
    return edVerify(
      null,
      bytes,
      createPublicKey(public_key_pem),
      Buffer.from(signature_base64, 'base64'),
    );
  } catch {
    return false;
  }
}

/** Ephemeral identity (tests, `:memory:` databases). Nothing touches disk. */
export function ephemeralIdentity(): ServerIdentity {
  const { privateKey } = generateKeyPairSync('ed25519');
  return {
    signer: signerFromPrivateKey(privateKey),
    cursor_secret: randomBytes(32).toString('hex'),
    data_dir: null,
  };
}

/**
 * Load or create the identity files under `dataDir`. Safe when several
 * processes start at once on a fresh data dir: each file is published
 * atomically and exclusively (first creator wins, the rest read its bytes),
 * so every process ends up with the same key and secret.
 */
export function loadOrCreateIdentity(dataDir: string): ServerIdentity {
  ensureDir(dataDir, 0o700);
  const keyPath = join(dataDir, 'signing-key.pem');
  const secretPath = join(dataDir, 'cursor-secret');

  const priv = readOrCreateOnce(
    keyPath,
    () => generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
    (text) => {
      if (!text.includes('-----END')) return null;
      try {
        return createPrivateKey(text);
      } catch {
        return null;
      }
    },
  ).value;

  let secret: string;
  let secretCreated = false;
  try {
    const r = readOrCreateOnce(
      secretPath,
      () => randomBytes(32).toString('hex') + '\n',
      (text) => (/^[0-9a-f]{64}$/.test(text.trim()) ? text.trim() : null),
    );
    secret = r.value;
    secretCreated = r.created;
  } catch (err) {
    if (err instanceof CorruptFileError) throw new Error(`${secretPath} is corrupt; expected 64 hex chars`);
    throw err;
  }

  return { signer: signerFromPrivateKey(priv), cursor_secret: secret, data_dir: dataDir, ...(secretCreated ? { cursor_secret_created: true } : {}) };
}
