/**
 * Retrieval receipt v2 — the signed attestation a recall result carries:
 * "block_id had content_hash in doc_slug@revision when the chain head was
 * (chain_seq, chain_head_hash), answering query_hash, signed by key_id".
 *
 * Signing payload = RFC 8785 canonical JSON of the receipt minus `signature`.
 * Signature = Ed25519 over the UTF-8 bytes of that payload, base64.
 *
 * v2 differs from a plain content receipt by binding the chain position, so
 * a verifier can check the receipt was issued against a head that is still
 * on the chain (not just that the block exists).
 */

import { z } from 'zod';

import { HEX64 } from '../chain/event.js';
import { canonicalize } from '../crypto/canonical.js';
import type { Signer } from '../crypto/keys.js';
import { verifyEd25519 } from '../crypto/keys.js';
import { sha256Hex } from '../crypto/hash.js';

export const RECEIPT_VERSION = 2 as const;

export const ReceiptSchema = z
  .object({
    v: z.literal(RECEIPT_VERSION),
    receipt_id: z.string().uuid(),
    workspace: z.string().min(1).max(100),
    block_id: z.string().uuid(),
    content_hash: z.string().regex(HEX64),
    doc_slug: z.string().min(1).max(128),
    revision: z.number().int().positive(),
    chain_seq: z.number().int().nonnegative(),
    chain_head_hash: z.string().regex(HEX64),
    query_hash: z.string().regex(HEX64),
    issued_at: z.string().datetime(),
    key_id: z.string().min(1).max(100),
    signature: z.string().min(1).optional(),
  })
  .strict();
export type Receipt = z.infer<typeof Receipt>;
const Receipt = ReceiptSchema;
export type UnsignedReceipt = Omit<Receipt, 'signature'>;

export function receiptSigningPayload(receipt: Receipt | UnsignedReceipt): string {
  const { signature: _omit, ...signed } = receipt as Receipt;
  return canonicalize(signed);
}

export function signReceipt(unsigned: UnsignedReceipt, signer: Signer): Receipt {
  if (unsigned.key_id !== signer.key_id) throw new Error('receipt key_id does not match signer');
  const signature = signer.sign(receiptSigningPayload(unsigned));
  return { ...unsigned, signature };
}

export function verifyReceiptSignature(receipt: Receipt, public_key_pem: string): boolean {
  if (!receipt.signature) return false;
  return verifyEd25519(public_key_pem, receiptSigningPayload(receipt), receipt.signature);
}

export function queryHash(query: string): string {
  return sha256Hex(query);
}
