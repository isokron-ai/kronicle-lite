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
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

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
}

/** key_id = first 16 hex chars of sha256(SPKI DER of the public key). */
export function keyIdFromPublicKey(pub: KeyObject): string {
  const der = pub.export({ type: 'spki', format: 'der' }) as Buffer;
  return `ed25519-${sha256Hex(new Uint8Array(der)).slice(0, 16)}`;
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

/** Load or create the identity files under `dataDir`. */
export function loadOrCreateIdentity(dataDir: string): ServerIdentity {
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const keyPath = join(dataDir, 'signing-key.pem');
  const secretPath = join(dataDir, 'cursor-secret');

  let priv: KeyObject;
  if (existsSync(keyPath)) {
    priv = createPrivateKey(readFileSync(keyPath, 'utf8'));
  } else {
    const pair = generateKeyPairSync('ed25519');
    priv = pair.privateKey;
    writeFileSync(
      keyPath,
      priv.export({ type: 'pkcs8', format: 'pem' }) as string,
      { mode: 0o600 },
    );
  }

  let secret: string;
  if (existsSync(secretPath)) {
    secret = readFileSync(secretPath, 'utf8').trim();
    if (!/^[0-9a-f]{64}$/.test(secret)) {
      throw new Error(`${secretPath} is corrupt; expected 64 hex chars`);
    }
  } else {
    secret = randomBytes(32).toString('hex');
    writeFileSync(secretPath, secret + '\n', { mode: 0o600 });
  }

  return { signer: signerFromPrivateKey(priv), cursor_secret: secret, data_dir: dataDir };
}
