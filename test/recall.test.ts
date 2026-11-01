import { describe, expect, it } from 'vitest';

import { Chain } from '../src/chain/index.js';
import { openDatabase } from '../src/db/open.js';
import { DocumentStore } from '../src/docs/documents.js';
import { receiptSigningPayload, signReceipt, verifyReceiptSignature, type Receipt } from '../src/recall/receipt.js';
import { Recall, toMatchExpression } from '../src/recall/recall.js';
import { ReceiptVerifier } from '../src/recall/verify-receipt.js';

function fresh() {
  const { db, identity } = openDatabase({ memory: true });
  const chain = new Chain(db, identity.signer);
  const docs = new DocumentStore(db, chain);
  const recall = new Recall(db, chain, identity.signer);
  const verifier = new ReceiptVerifier(db, chain, docs);
  return { db, identity, chain, docs, recall, verifier };
}

const MD = `# Infra

The database password rotates every 90 days.

## Deploys

Deploy on Tuesdays only; never on Friday.

Rollback uses the previous image tag.
`;

describe('toMatchExpression', () => {
  it('quotes tokens and strips FTS syntax', () => {
    expect(toMatchExpression('deploy OR "x" NEAR(y) col:z', 'AND')).toBe('"deploy" "or" "x" "near" "y" "col" "z"');
    expect(toMatchExpression('   ', 'AND')).toBeNull();
    expect(toMatchExpression('a b', 'OR')).toBe('"a" OR "b"');
  });
});

describe('recall', () => {
  it('finds live blocks by bm25 and attaches chain-bound signed receipts', () => {
    const { docs, recall, chain, identity } = fresh();
    docs.putDocument({ slug: 'infra', title: 'Infra', markdown: MD, actor_id: 'a' });
    const r = recall.recall({ query: 'deploy friday' });
    expect(r.match_mode).toBe('all_terms');
    expect(r.hits.length).toBeGreaterThanOrEqual(1);
    const top = r.hits[0]!;
    expect(top.content).toContain('Tuesdays');
    expect(top.status).toBe('live');
    expect(top.receipt).not.toBeNull();
    const rc = top.receipt!;
    expect(rc.v).toBe(2);
    expect(rc.chain_seq).toBe(chain.head().seq);
    expect(rc.chain_head_hash).toBe(chain.head().hash);
    expect(rc.key_id).toBe(identity.signer.key_id);
    expect(rc.query_hash).toBe(r.query_hash);
    expect(verifyReceiptSignature(rc, identity.signer.public_key_pem)).toBe(true);
    expect(recall.getReceipt(rc.receipt_id)).toEqual(rc);
  });

  it('falls back to any-term matching and honors include_receipts=false', () => {
    const { docs, recall } = fresh();
    docs.putDocument({ slug: 'infra', title: 'Infra', markdown: MD, actor_id: 'a' });
    const r = recall.recall({ query: 'rollback unicorns', include_receipts: false });
    expect(r.match_mode).toBe('any_term');
    expect(r.hits[0]!.content).toContain('Rollback');
    expect(r.hits[0]!.receipt).toBeNull();
    expect(recall.recall({ query: 'zzzz' }).hits).toEqual([]);
  });

  it('hides superseded blocks and tombstoned unless asked', () => {
    const { docs, recall } = fresh();
    const put = docs.putDocument({ slug: 'infra', title: 'Infra', markdown: MD, actor_id: 'a' });
    const target = put.blocks.find((b) => b.content_hash && docs.getBlock(b.block_id)!.content.includes('Tuesdays'))!;
    docs.supersedeBlock({ block_id: target.block_id, new_content: 'Deploy any weekday.', reason: 'r', actor_id: 'a' });
    const r1 = recall.recall({ query: 'tuesdays' });
    expect(r1.hits).toEqual([]);
    const r2 = recall.recall({ query: 'weekday' });
    expect(r2.hits[0]!.status).toBe('live');
    const roll = put.blocks.find((b) => docs.getBlock(b.block_id)!.content.includes('Rollback'))!;
    docs.tombstoneBlock({ block_id: roll.block_id, reason: 'obsolete', actor_id: 'a' });
    expect(recall.recall({ query: 'rollback' }).hits).toEqual([]);
    const r3 = recall.recall({ query: 'rollback', include_tombstoned: true });
    expect(r3.hits[0]!.status).toBe('tombstoned');
    expect(r3.hits[0]!.tombstone_reason).toBe('obsolete');
  });
});

describe('verify receipt', () => {
  function issued() {
    const ctx = fresh();
    ctx.docs.putDocument({ slug: 'infra', title: 'Infra', markdown: MD, actor_id: 'a' });
    const r = ctx.recall.recall({ query: 'tuesdays' });
    const receipt = r.hits[0]!.receipt!;
    return { ...ctx, receipt };
  }

  it('VERIFIED on a fresh receipt, even after the chain advances', () => {
    const { verifier, receipt, docs } = issued();
    expect(verifier.verify(receipt)).toMatchObject({ status: 'VERIFIED', reason: 'verified' });
    docs.putDocument({ slug: 'other', title: 'o', markdown: 'unrelated', actor_id: 'a' });
    expect(verifier.verify(receipt).status).toBe('VERIFIED');
  });

  it('SUPERSEDED after supersede_block, with the current head', () => {
    const { verifier, receipt, docs } = issued();
    const s = docs.supersedeBlock({ block_id: receipt.block_id, new_content: 'Deploy daily.', reason: 'r', actor_id: 'a' });
    const v = verifier.verify(receipt);
    expect(v.status).toBe('SUPERSEDED');
    expect(v.reason).toBe('superseded_by_newer_head');
    expect(v.current_block_id).toBe(s.new_block_id);
    expect(v.current_content_hash).toBe(s.content_hash);
    expect(v.supersession_depth).toBe(1);
    // Two hops
    const s2 = docs.supersedeBlock({ block_id: s.new_block_id, new_content: 'Deploy hourly.', reason: 'r', actor_id: 'a' });
    const v2 = verifier.verify(receipt);
    expect(v2.current_block_id).toBe(s2.new_block_id);
    expect(v2.supersession_depth).toBe(2);
  });

  it('TOMBSTONED when the block or its lineage head is tombstoned', () => {
    const { verifier, receipt, docs } = issued();
    docs.tombstoneBlock({ block_id: receipt.block_id, reason: 'wrong', actor_id: 'a' });
    const v = verifier.verify(receipt);
    expect(v).toMatchObject({ status: 'TOMBSTONED', reason: 'tombstoned', tombstone_reason: 'wrong' });
  });

  it('UNVERIFIED: malformed, unsigned, bad signature, unknown key', () => {
    const { verifier, receipt, identity } = issued();
    expect(verifier.verify({ nope: true }).reason).toBe('malformed_receipt');
    expect(verifier.verify('string').reason).toBe('malformed_receipt');
    const { signature: _s, ...unsigned } = receipt;
    expect(verifier.verify(unsigned).reason).toBe('unsigned_receipt');
    const tampered: Receipt = { ...receipt, content_hash: 'f'.repeat(64) };
    expect(verifier.verify(tampered).reason).toBe('signature_invalid');
    const badSig: Receipt = { ...receipt, signature: Buffer.from('x'.repeat(64)).toString('base64') };
    expect(verifier.verify(badSig).reason).toBe('signature_invalid');
    const otherKey: Receipt = { ...receipt, key_id: 'ed25519-0000000000000000' };
    expect(verifier.verify(otherKey).reason).toBe('unknown_key');
    expect(receiptSigningPayload(receipt)).not.toContain('signature');
    expect(signReceipt(unsigned, identity.signer)).toEqual(receipt);
  });

  it('UNVERIFIED when the chain binding no longer holds', () => {
    const { verifier, receipt, db } = issued();
    db.prepare(`UPDATE events SET this_hash = ? WHERE seq = ?`).run('0'.repeat(64), receipt.chain_seq);
    expect(verifier.verify(receipt).reason).toBe('chain_head_mismatch');
    db.prepare(`DELETE FROM events WHERE seq = ?`).run(receipt.chain_seq);
    expect(verifier.verify(receipt).reason).toBe('chain_seq_unknown');
  });

  it('UNVERIFIED when the stored block content was altered under a valid receipt', () => {
    const { verifier, receipt, db } = issued();
    db.prepare(`UPDATE blocks SET content_hash = ? WHERE block_id = ?`).run('a'.repeat(64), receipt.block_id);
    const v = verifier.verify(receipt);
    // 0.5.0: the row no longer hashes; that is tampering, reported before the receipt comparison.
    expect(v).toMatchObject({ status: 'UNVERIFIED', reason: 'content_tampered', integrity_problem: 'content_hash_mismatch' });
    db.prepare(`DELETE FROM blocks WHERE block_id = ?`).run(receipt.block_id);
    expect(verifier.verify(receipt).reason).toBe('unknown_block');
  });

  it('UNVERIFIED when the signing key is revoked', () => {
    const { verifier, receipt, db } = issued();
    db.prepare(`UPDATE signing_keys SET revoked_at = ? WHERE key_id = ?`).run(new Date().toISOString(), receipt.key_id);
    expect(verifier.verify(receipt).reason).toBe('key_revoked');
  });
});
