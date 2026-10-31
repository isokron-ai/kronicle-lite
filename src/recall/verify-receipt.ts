/**
 * verify — re-derive a receipt's claim against the live store. Fail-closed:
 * UNVERIFIED is the default; VERIFIED only when every gate passes.
 *
 *   1. SHAPE       zod parse; malformed ⇒ UNVERIFIED/malformed_receipt
 *   2. SIGNATURE   key known + not revoked, Ed25519 over the signing payload
 *   3. EXISTENCE   block row present
 *   4. CONTENT     stored content_hash == receipt.content_hash
 *   5. CHAIN       events[chain_seq].this_hash == chain_head_hash (seq 0 ⇒ genesis)
 *   6. CURRENCY    recursive superseded_by walk: head is this block and live ⇒
 *                  VERIFIED; head tombstoned ⇒ TOMBSTONED; other head ⇒ SUPERSEDED
 */

import type { Chain } from '../chain/index.js';
import { GENESIS_HASH } from '../chain/genesis.js';
import type { Db } from '../db/open.js';
import type { DocumentStore } from '../docs/documents.js';
import { ReceiptSchema, verifyReceiptSignature, type Receipt } from './receipt.js';

export type VerifyStatus = 'VERIFIED' | 'SUPERSEDED' | 'TOMBSTONED' | 'UNVERIFIED';

export const VERIFY_REASONS = [
  'verified',
  'malformed_receipt',
  'unsigned_receipt',
  'unknown_key',
  'key_revoked',
  'signature_invalid',
  'unknown_block',
  'content_hash_mismatch',
  'chain_seq_unknown',
  'chain_head_mismatch',
  'superseded_by_newer_head',
  'tombstoned',
] as const;
export type VerifyReason = (typeof VERIFY_REASONS)[number];

export interface VerifyResult {
  status: VerifyStatus;
  reason: VerifyReason;
  receipt_id: string | null;
  block_id: string | null;
  /** Head of the supersession lineage when it differs from the receipt's block. */
  current_block_id?: string;
  current_content_hash?: string;
  tombstone_reason?: string | null;
  /** Length of the supersession walk (0 = block is its own head). */
  supersession_depth?: number;
  checked_at: string;
  chain_head: { seq: number; hash: string };
}

export class ReceiptVerifier {
  constructor(
    private readonly db: Db,
    private readonly chain: Chain,
    private readonly docs: DocumentStore,
  ) {}

  verify(input: unknown): VerifyResult {
    const checked_at = new Date().toISOString();
    const chain_head = this.chain.head();
    const fail = (
      reason: VerifyReason,
      status: VerifyStatus,
      extra: Partial<VerifyResult> = {},
      ids: { receipt_id: string | null; block_id: string | null } = { receipt_id: null, block_id: null },
    ): VerifyResult => ({ status, reason, ...ids, ...extra, checked_at, chain_head });

    // 1. SHAPE
    const parsed = ReceiptSchema.safeParse(input);
    if (!parsed.success) return fail('malformed_receipt', 'UNVERIFIED');
    const receipt: Receipt = parsed.data;
    const ids = { receipt_id: receipt.receipt_id, block_id: receipt.block_id };
    if (!receipt.signature) return fail('unsigned_receipt', 'UNVERIFIED', {}, ids);

    // 2. SIGNATURE
    const key = this.db
      .prepare(`SELECT public_key_pem, revoked_at FROM signing_keys WHERE key_id = ?`)
      .get(receipt.key_id) as { public_key_pem: string; revoked_at: string | null } | undefined;
    if (!key) return fail('unknown_key', 'UNVERIFIED', {}, ids);
    if (key.revoked_at !== null) return fail('key_revoked', 'UNVERIFIED', {}, ids);
    if (!verifyReceiptSignature(receipt, key.public_key_pem)) {
      return fail('signature_invalid', 'UNVERIFIED', {}, ids);
    }

    // 3. EXISTENCE
    const block = this.docs.getBlock(receipt.block_id);
    if (!block) return fail('unknown_block', 'UNVERIFIED', {}, ids);

    // 4. CONTENT
    if (block.content_hash !== receipt.content_hash) {
      return fail('content_hash_mismatch', 'UNVERIFIED', { current_content_hash: block.content_hash }, ids);
    }

    // 5. CHAIN BINDING
    if (receipt.chain_seq === 0) {
      if (receipt.chain_head_hash !== GENESIS_HASH) return fail('chain_head_mismatch', 'UNVERIFIED', {}, ids);
    } else {
      const ev = this.chain.get(receipt.chain_seq);
      if (!ev) return fail('chain_seq_unknown', 'UNVERIFIED', {}, ids);
      if (ev.this_hash !== receipt.chain_head_hash) return fail('chain_head_mismatch', 'UNVERIFIED', {}, ids);
    }

    // 6. CURRENCY
    const walk = this.docs.supersessionWalk(receipt.block_id);
    const head = walk[walk.length - 1] ?? block;
    const depth = walk.length - 1;
    if (head.tombstoned_at !== null) {
      return fail(
        'tombstoned',
        'TOMBSTONED',
        {
          supersession_depth: depth,
          tombstone_reason: head.tombstone_reason,
          ...(head.block_id !== block.block_id
            ? { current_block_id: head.block_id, current_content_hash: head.content_hash }
            : {}),
        },
        ids,
      );
    }
    if (head.block_id !== block.block_id) {
      return fail(
        'superseded_by_newer_head',
        'SUPERSEDED',
        { current_block_id: head.block_id, current_content_hash: head.content_hash, supersession_depth: depth },
        ids,
      );
    }
    return fail('verified', 'VERIFIED', { supersession_depth: 0 }, ids);
  }
}
