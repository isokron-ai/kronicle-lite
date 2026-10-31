/**
 * Hash primitives. SHA-256 for the chain, receipts and checkpoints;
 * BLAKE3 for block content addresses. Both from @noble/hashes so the
 * recipes in docs/FORMAT.md are reproducible outside Node.
 */

import { blake3 } from '@noble/hashes/blake3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

export function sha256Hex(input: string | Uint8Array): string {
  const bytes = typeof input === 'string' ? utf8ToBytes(input) : input;
  return bytesToHex(sha256(bytes));
}

export function sha256Bytes(input: string | Uint8Array): Uint8Array {
  const bytes = typeof input === 'string' ? utf8ToBytes(input) : input;
  return sha256(bytes);
}

export function blake3Hex(input: string | Uint8Array): string {
  const bytes = typeof input === 'string' ? utf8ToBytes(input) : input;
  return bytesToHex(blake3(bytes));
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) {
    throw new Error('invalid lowercase hex');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export { bytesToHex };
