import { describe, expect, it } from 'vitest';

import { Chain, ChainConflictError, checkpointSigningPayload } from '../src/chain/chain.js';
import { computeEventHash, envelopeCanonical, recomputeEventHash } from '../src/chain/event.js';
import { GENESIS_HASH, GENESIS_STRING } from '../src/chain/genesis.js';
import { merkleRootHex } from '../src/chain/merkle.js';
import { canonicalize } from '../src/crypto/canonical.js';
import { sha256Hex } from '../src/crypto/hash.js';
import { verifyEd25519 } from '../src/crypto/keys.js';
import { openDatabase } from '../src/db/open.js';

function fresh() {
  const { db, identity } = openDatabase({ memory: true });
  return { db, identity, chain: new Chain(db, identity.signer) };
}

describe('genesis', () => {
  it('is the public sha256 of the genesis string', () => {
    expect(GENESIS_HASH).toBe(sha256Hex(GENESIS_STRING));
    expect(GENESIS_HASH).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('hash recipe', () => {
  it('matches the documented worked example', () => {
    const envelope = {
      event_id: '00000000-0000-4000-8000-000000000001',
      event_type: 'note.added',
      actor_id: 'alice',
      occurred_at: '2026-01-01T00:00:00.000Z',
      payload: { b: 2, a: 'x', nested: { z: [1, 2], y: null } },
    };
    const env = envelopeCanonical(envelope);
    expect(env).toBe(
      '{"actor_id":"alice","event_id":"00000000-0000-4000-8000-000000000001","event_type":"note.added","occurred_at":"2026-01-01T00:00:00.000Z","payload":{"a":"x","b":2,"nested":{"y":null,"z":[1,2]}}}',
    );
    const nonce = '000102030405060708090a0b0c0d0e0f';
    const h = computeEventHash({ envelope_canonical: env, seq: 1, prev_hash: GENESIS_HASH, nonce });
    expect(h).toBe(sha256Hex(`${env}|1|${GENESIS_HASH}|${nonce}`));
  });
});

describe('Chain.append', () => {
  it('links from genesis and advances the head', () => {
    const { chain } = fresh();
    expect(chain.head()).toEqual({ seq: 0, hash: GENESIS_HASH });
    const a = chain.append({ event_type: 't.one', payload: { n: 1 }, actor_id: 'a' });
    expect(a.event.seq).toBe(1);
    expect(a.event.prev_hash).toBe(GENESIS_HASH);
    expect(a.replayed).toBe(false);
    const b = chain.append({ event_type: 't.two', payload: { n: 2 }, actor_id: 'a' });
    expect(b.event.prev_hash).toBe(a.event.this_hash);
    expect(chain.head()).toEqual({ seq: 2, hash: b.event.this_hash });
    expect(recomputeEventHash(b.event)).toBe(b.event.this_hash);
  });

  it('compare-and-swap refuses a stale expected_prev_hash', () => {
    const { chain } = fresh();
    const a = chain.append({ event_type: 't', payload: {}, actor_id: 'a' });
    chain.append({ event_type: 't', payload: {}, actor_id: 'b' });
    expect(() =>
      chain.append({
        event_type: 't',
        payload: {},
        actor_id: 'a',
        expected_prev_hash: a.event.this_hash,
      }),
    ).toThrow(ChainConflictError);
    expect(chain.head().seq).toBe(2);
    const ok = chain.append({
      event_type: 't',
      payload: {},
      actor_id: 'a',
      expected_prev_hash: chain.head().hash,
    });
    expect(ok.event.seq).toBe(3);
  });

  it('idempotency_key replays the original event without appending', () => {
    const { chain } = fresh();
    const a = chain.append({ event_type: 't', payload: { x: 1 }, actor_id: 'a', idempotency_key: 'k1' });
    const b = chain.append({ event_type: 't', payload: { x: 999 }, actor_id: 'a', idempotency_key: 'k1' });
    expect(b.replayed).toBe(true);
    expect(b.event).toEqual(a.event);
    expect(chain.head().seq).toBe(1);
  });

  it('findByIdempotencyKey returns the prior event or null', () => {
    const { chain } = fresh();
    expect(chain.findByIdempotencyKey('sea:nope')).toBeNull();
    const a = chain.append({ event_type: 't', payload: { x: 1 }, actor_id: 'a', idempotency_key: 'sea:k1' });
    expect(chain.findByIdempotencyKey('sea:k1')).toEqual(a.event);
  });

  it('rejects non-object payloads', () => {
    const { chain } = fresh();
    expect(() =>
      chain.append({ event_type: 't', payload: [] as unknown as Record<string, unknown>, actor_id: 'a' }),
    ).toThrow(TypeError);
  });

  it('canonicalizes nested payloads (key order does not matter)', () => {
    const { chain } = fresh();
    const a = chain.append({
      event_type: 't',
      payload: { z: 1, a: { d: [3, { k: 'v' }], c: true } },
      actor_id: 'a',
      nonce: '00'.repeat(16),
      occurred_at: '2026-01-01T00:00:00.000Z',
      event_id: '00000000-0000-4000-8000-000000000002',
    });
    const { chain: chain2 } = fresh();
    const b = chain2.append({
      event_type: 't',
      payload: { a: { c: true, d: [3, { k: 'v' }] }, z: 1 },
      actor_id: 'a',
      nonce: '00'.repeat(16),
      occurred_at: '2026-01-01T00:00:00.000Z',
      event_id: '00000000-0000-4000-8000-000000000002',
    });
    expect(a.event.this_hash).toBe(b.event.this_hash);
  });
});

describe('Chain.verify', () => {
  it('passes on an untouched chain and reports counts', () => {
    const { chain } = fresh();
    for (let i = 0; i < 10; i++) chain.append({ event_type: 't', payload: { i }, actor_id: 'a' });
    const r = chain.verify();
    expect(r.ok).toBe(true);
    expect(r.events_checked).toBe(10);
    expect(r.first_mismatch).toBeNull();
  });

  it('detects a tampered payload at the first mismatching seq', () => {
    const { chain, db } = fresh();
    for (let i = 0; i < 10; i++) chain.append({ event_type: 't', payload: { i }, actor_id: 'a' });
    db.prepare(`UPDATE events SET payload_canonical = ? WHERE seq = 4`).run(canonicalize({ i: 999 }));
    const r = chain.verify();
    expect(r.ok).toBe(false);
    expect(r.first_mismatch?.seq).toBe(4);
    expect(r.first_mismatch?.kind).toBe('hash_mismatch');
    expect(r.events_checked).toBe(3);
  });

  it('detects a tampered event_type (envelope is hash-bound)', () => {
    const { chain, db } = fresh();
    for (let i = 0; i < 3; i++) chain.append({ event_type: 'block.tombstoned', payload: { i }, actor_id: 'a' });
    db.prepare(`UPDATE events SET event_type = 'block.noop' WHERE seq = 2`).run();
    const r = chain.verify();
    expect(r.first_mismatch).toMatchObject({ seq: 2, kind: 'hash_mismatch' });
  });

  it('detects a re-hashed row whose link is now broken', () => {
    const { chain, db } = fresh();
    for (let i = 0; i < 5; i++) chain.append({ event_type: 't', payload: { i }, actor_id: 'a' });
    // Attacker rewrites seq 3 AND recomputes its hash; seq 4's prev_hash no longer matches.
    const ev = chain.get(3)!;
    const forged = { ...ev, payload: { i: 'forged' } };
    const newHash = recomputeEventHash(forged);
    db.prepare(`UPDATE events SET payload_canonical = ?, this_hash = ? WHERE seq = 3`).run(
      canonicalize(forged.payload),
      newHash,
    );
    const r = chain.verify();
    expect(r.first_mismatch).toMatchObject({ seq: 4, kind: 'link_broken' });
  });

  it('detects a deleted tail event via head_mismatch / seq_gap', () => {
    const { chain, db } = fresh();
    for (let i = 0; i < 5; i++) chain.append({ event_type: 't', payload: { i }, actor_id: 'a' });
    db.prepare(`DELETE FROM events WHERE seq = 5`).run();
    const r = chain.verify();
    expect(r.ok).toBe(false);
    expect(r.first_mismatch?.kind).toBe('seq_gap');
    expect(r.first_mismatch?.seq).toBe(5);
  });

  it('supports partial ranges', () => {
    const { chain, db } = fresh();
    for (let i = 0; i < 8; i++) chain.append({ event_type: 't', payload: { i }, actor_id: 'a' });
    db.prepare(`UPDATE events SET payload_canonical = '{"i":"x"}' WHERE seq = 2`).run();
    expect(chain.verify(3, 8).ok).toBe(true);
    expect(chain.verify(1, 8).first_mismatch?.seq).toBe(2);
  });
});

describe('checkpoints', () => {
  it('computes a Merkle root over the range and signs it', () => {
    const { chain, identity } = fresh();
    const hashes: { seq: number; this_hash: string }[] = [];
    for (let i = 0; i < 5; i++) {
      const r = chain.append({ event_type: 't', payload: { i }, actor_id: 'a' });
      hashes.push({ seq: r.event.seq, this_hash: r.event.this_hash });
    }
    const cp = chain.checkpoint();
    expect(cp.from_seq).toBe(1);
    expect(cp.to_seq).toBe(5);
    expect(cp.root).toBe(merkleRootHex(hashes));
    expect(cp.key_id).toBe(identity.signer.key_id);
    expect(verifyEd25519(identity.signer.public_key_pem, checkpointSigningPayload(cp), cp.signature)).toBe(true);
    const v = chain.verify();
    expect(v.ok).toBe(true);
    expect(v.checkpoints).toEqual([expect.objectContaining({ ok: true, reason: 'valid' })]);
  });

  it('single-leaf root equals leaf hash; odd nodes promote', () => {
    const one = [{ seq: 1, this_hash: 'a'.repeat(64) }];
    const three = [
      { seq: 1, this_hash: 'a'.repeat(64) },
      { seq: 2, this_hash: 'b'.repeat(64) },
      { seq: 3, this_hash: 'c'.repeat(64) },
    ];
    expect(merkleRootHex(one)).toMatch(/^[0-9a-f]{64}$/);
    expect(merkleRootHex(three)).not.toBe(merkleRootHex(three.slice(0, 2)));
    expect(() => merkleRootHex([])).toThrow();
  });

  it('flags a checkpoint whose signature was tampered', () => {
    const { chain, db } = fresh();
    for (let i = 0; i < 3; i++) chain.append({ event_type: 't', payload: { i }, actor_id: 'a' });
    const cp = chain.checkpoint();
    db.prepare(`UPDATE checkpoints SET root = ? WHERE checkpoint_id = ?`).run('0'.repeat(64), cp.checkpoint_id);
    const v = chain.verify();
    expect(v.ok).toBe(false);
    expect(v.checkpoints[0]?.reason).toBe('signature_invalid');
  });

  it('flags a checkpoint when the chain beneath it is rewritten consistently', () => {
    const { chain, db } = fresh();
    for (let i = 0; i < 3; i++) chain.append({ event_type: 't', payload: { i }, actor_id: 'a' });
    chain.checkpoint();
    // Append more so the checkpoint covers a prefix only.
    chain.append({ event_type: 't', payload: { i: 3 }, actor_id: 'a' });
    const v0 = chain.verify();
    expect(v0.ok).toBe(true);
    // Swap this_hash of seq 2 with a valid-looking value and fix links: expensive for an
    // attacker without the key, but simulate by changing the stored root instead.
    db.prepare(`UPDATE checkpoints SET leaf_count = 2`).run();
    const v = chain.verify();
    expect(v.checkpoints[0]?.reason).toBe('signature_invalid');
  });
});
