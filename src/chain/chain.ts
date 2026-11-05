/**
 * The hash chain: append-only event log in SQLite with a single-writer
 * discipline (BEGIN IMMEDIATE), compare-and-swap on the head hash, and
 * idempotency keys. Checkpoints are Ed25519-signed Merkle roots over a seq
 * range. `verify()` recomputes every hash.
 */

import { randomBytes, randomUUID } from 'node:crypto';

import { assertJsonObject } from '../crypto/canonical.js';
import { canonicalize } from '../crypto/canonical.js';
import type { Signer } from '../crypto/keys.js';
import { verifyEd25519 } from '../crypto/keys.js';
import type { Db } from '../db/open.js';
import { markWriter } from '../db/storage.js';
import { VERSION } from '../version.js';
import {
  computeEventHash,
  envelopeCanonical,
  recomputeEventHash,
  type ChainEvent,
} from './event.js';
import { GENESIS_HASH } from './genesis.js';
import { merkleRootHex } from './merkle.js';

export interface ChainHead {
  seq: number;
  hash: string;
}

export interface AppendInput {
  event_type: string;
  payload: Record<string, unknown>;
  actor_id: string;
  /** Replay-safe key; a second append with the same key returns the first event. */
  idempotency_key?: string;
  /** Compare-and-swap: refuse unless the current head hash equals this. */
  expected_prev_hash?: string;
  /** Override the timestamp (import / tests). */
  occurred_at?: string;
  /** Override the nonce (import / tests). */
  nonce?: string;
  /** Override the event id (import). */
  event_id?: string;
}

export interface AppendResult {
  event: ChainEvent;
  head: ChainHead;
  /** True when an existing event was returned because the idempotency key matched. */
  replayed: boolean;
}

export class ChainConflictError extends Error {
  override readonly name = 'ChainConflictError';
  constructor(
    readonly expected_prev_hash: string,
    readonly actual_head_hash: string,
  ) {
    super(
      `chain head moved: expected prev_hash ${expected_prev_hash.slice(0, 12)}…, head is ${actual_head_hash.slice(0, 12)}…`,
    );
  }
}

export interface Checkpoint {
  checkpoint_id: string;
  from_seq: number;
  to_seq: number;
  leaf_count: number;
  root: string;
  key_id: string;
  signature: string;
  created_at: string;
}

/** One row of the additive `anchors` table (0.4.0): a service-countersigned receipt for a pushed checkpoint. */
export interface AnchorRecord {
  anchor_id: string;
  checkpoint_id: string | null;
  /** sha256 hex of the SPKI DER of the signing key (key_id is its 16-char prefix). */
  chain_id: string;
  anchor_url: string;
  from_seq: number;
  to_seq: number;
  root: string;
  received_at: string;
  /** The receipt as JCS bytes; sha256 of this string is its public-log leaf. */
  receipt_json: string;
  day: string | null;
  leaf_index: number | null;
  path_json: string | null;
  /** pending_public | published | conflict */
  status: string;
  fetched_at: string;
}

export const CHECKPOINT_VERSION = 1 as const;

/** The bytes a checkpoint signature covers. */
export function checkpointSigningPayload(cp: {
  from_seq: number;
  to_seq: number;
  leaf_count: number;
  root: string;
}): string {
  return canonicalize({
    v: CHECKPOINT_VERSION,
    from_seq: cp.from_seq,
    to_seq: cp.to_seq,
    leaf_count: cp.leaf_count,
    root: cp.root,
  });
}

export type ChainMismatchKind =
  | 'hash_mismatch' // recomputed this_hash != stored this_hash
  | 'link_broken' // prev_hash != previous event's this_hash
  | 'seq_gap' // missing seq
  | 'head_mismatch' // chain_head row disagrees with last event
  | 'payload_unparseable'; // unreleased: the stored payload is not a JSON object

export interface CheckpointResult {
  checkpoint_id: string;
  from_seq: number;
  to_seq: number;
  ok: boolean;
  reason: 'valid' | 'root_mismatch' | 'signature_invalid' | 'unknown_key' | 'range_outside_verified';
}

export interface VerifyChainResult {
  ok: boolean;
  from_seq: number;
  to_seq: number;
  events_checked: number;
  first_mismatch: {
    seq: number;
    kind: ChainMismatchKind;
    expected: string;
    actual: string;
  } | null;
  head: ChainHead;
  checkpoints: CheckpointResult[];
}

interface EventRow {
  seq: number;
  event_id: string;
  event_type: string;
  payload_canonical: string;
  actor_id: string;
  occurred_at: string;
  nonce: string;
  prev_hash: string;
  this_hash: string;
  idempotency_key: string | null;
}

/**
 * Unreleased: events whose stored payload is not JSON (a hand edit, a torn
 * page). They are returned with an empty payload, so readers never crash on
 * one bad row; `verify()` reports them as `payload_unparseable`, and the
 * empty payload can never hash to the stored this_hash.
 */
const UNPARSEABLE = new WeakSet<ChainEvent>();
export function isPayloadUnparseable(ev: ChainEvent): boolean {
  return UNPARSEABLE.has(ev);
}

function rowToEvent(r: EventRow): ChainEvent {
  let payload: Record<string, unknown>;
  let bad = false;
  try {
    const v: unknown = JSON.parse(r.payload_canonical);
    bad = typeof v !== 'object' || v === null || Array.isArray(v);
    payload = bad ? {} : (v as Record<string, unknown>);
  } catch {
    payload = {};
    bad = true;
  }
  const ev: ChainEvent = {
    seq: r.seq,
    event_id: r.event_id,
    event_type: r.event_type,
    payload,
    actor_id: r.actor_id,
    occurred_at: r.occurred_at,
    nonce: r.nonce,
    prev_hash: r.prev_hash,
    this_hash: r.this_hash,
    idempotency_key: r.idempotency_key,
  };
  if (bad) UNPARSEABLE.add(ev);
  return ev;
}

export class Chain {
  constructor(
    private readonly db: Db,
    private readonly signer: Signer,
  ) {}

  head(): ChainHead {
    const row = this.db
      .prepare(`SELECT seq, hash FROM chain_head WHERE id = 1`)
      .get() as ChainHead;
    return row;
  }

  /**
   * Append one event. Runs in an IMMEDIATE transaction so the head read and
   * the insert are atomic against other writers in other processes. Safe to
   * call inside an outer transaction (better-sqlite3 nests as a savepoint).
   */
  append(input: AppendInput): AppendResult {
    assertJsonObject(input.payload);
    const run = this.db.transaction((): AppendResult => {
      if (input.idempotency_key !== undefined) {
        const existing = this.db
          .prepare(`SELECT * FROM events WHERE idempotency_key = ?`)
          .get(input.idempotency_key) as EventRow | undefined;
        if (existing) {
          return { event: rowToEvent(existing), head: this.head(), replayed: true };
        }
      }
      const head = this.head();
      if (input.expected_prev_hash !== undefined && input.expected_prev_hash !== head.hash) {
        throw new ChainConflictError(input.expected_prev_hash, head.hash);
      }
      const seq = head.seq + 1;
      const event_id = input.event_id ?? randomUUID();
      const occurred_at = input.occurred_at ?? new Date().toISOString();
      const nonce = input.nonce ?? randomBytes(16).toString('hex');
      const envelope = {
        event_id,
        event_type: input.event_type,
        actor_id: input.actor_id,
        occurred_at,
        payload: input.payload,
      };
      const envelope_canonical = envelopeCanonical(envelope);
      const payload_canonical = canonicalize(input.payload);
      const this_hash = computeEventHash({
        envelope_canonical,
        seq,
        prev_hash: head.hash,
        nonce,
      });
      this.db
        .prepare(
          `INSERT INTO events (seq, event_id, event_type, payload_canonical, actor_id,
             occurred_at, nonce, prev_hash, this_hash, idempotency_key)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          seq,
          event_id,
          input.event_type,
          payload_canonical,
          input.actor_id,
          occurred_at,
          nonce,
          head.hash,
          this_hash,
          input.idempotency_key ?? null,
        );
      this.db.prepare(`UPDATE chain_head SET seq = ?, hash = ? WHERE id = 1`).run(seq, this_hash);
      markWriter(this.db, seq, VERSION);
      const event: ChainEvent = {
        seq,
        event_id,
        event_type: input.event_type,
        payload: JSON.parse(payload_canonical) as Record<string, unknown>,
        actor_id: input.actor_id,
        occurred_at,
        nonce,
        prev_hash: head.hash,
        this_hash,
        idempotency_key: input.idempotency_key ?? null,
      };
      return { event, head: { seq, hash: this_hash }, replayed: false };
    });
    return run.immediate();
  }

  /**
   * Import path: insert an event with ALL fields supplied, verifying that it
   * hashes and links correctly before it lands. Throws on any mismatch.
   */
  appendVerbatim(ev: ChainEvent): void {
    const run = this.db.transaction(() => {
      const head = this.head();
      if (ev.seq !== head.seq + 1) {
        throw new Error(`import: expected seq ${head.seq + 1}, got ${ev.seq}`);
      }
      if (ev.prev_hash !== head.hash) {
        throw new Error(`import: seq ${ev.seq} prev_hash does not link to current head`);
      }
      const recomputed = recomputeEventHash(ev);
      if (recomputed !== ev.this_hash) {
        throw new Error(`import: seq ${ev.seq} this_hash mismatch`);
      }
      this.db
        .prepare(
          `INSERT INTO events (seq, event_id, event_type, payload_canonical, actor_id,
             occurred_at, nonce, prev_hash, this_hash, idempotency_key)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          ev.seq,
          ev.event_id,
          ev.event_type,
          canonicalize(ev.payload),
          ev.actor_id,
          ev.occurred_at,
          ev.nonce,
          ev.prev_hash,
          ev.this_hash,
          ev.idempotency_key,
        );
      this.db.prepare(`UPDATE chain_head SET seq = ?, hash = ? WHERE id = 1`).run(ev.seq, ev.this_hash);
      markWriter(this.db, ev.seq, VERSION);
    });
    run.immediate();
  }

  get(seq: number): ChainEvent | null {
    const row = this.db.prepare(`SELECT * FROM events WHERE seq = ?`).get(seq) as EventRow | undefined;
    return row ? rowToEvent(row) : null;
  }

  /**
   * The event previously appended under this idempotency key, or null. Lets a
   * caller that does row work BEFORE its append (a projection sharing the
   * file) detect a replay up front instead of discovering it from
   * `append().replayed` after it has already mutated rows.
   */
  findByIdempotencyKey(idempotency_key: string): ChainEvent | null {
    const row = this.db.prepare(`SELECT * FROM events WHERE idempotency_key = ?`).get(idempotency_key) as
      | EventRow
      | undefined;
    return row ? rowToEvent(row) : null;
  }

  /** Events with from_seq <= seq <= to_seq, ascending. */
  range(from_seq: number, to_seq: number, limit?: number): ChainEvent[] {
    const sql = `SELECT * FROM events WHERE seq >= ? AND seq <= ? ORDER BY seq ASC${limit !== undefined ? ' LIMIT ?' : ''}`;
    const rows = (
      limit !== undefined
        ? this.db.prepare(sql).all(from_seq, to_seq, limit)
        : this.db.prepare(sql).all(from_seq, to_seq)
    ) as EventRow[];
    return rows.map(rowToEvent);
  }

  /** Events strictly after `after_seq`. */
  since(after_seq: number, limit?: number): ChainEvent[] {
    return this.range(after_seq + 1, Number.MAX_SAFE_INTEGER, limit);
  }

  countSince(after_seq: number): number {
    const r = this.db.prepare(`SELECT COUNT(*) AS n FROM events WHERE seq > ?`).get(after_seq) as {
      n: number;
    };
    return r.n;
  }

  *iterate(from_seq = 1, batch = 500): Generator<ChainEvent> {
    let cursor = from_seq;
    for (;;) {
      const rows = this.range(cursor, Number.MAX_SAFE_INTEGER, batch);
      if (rows.length === 0) return;
      for (const r of rows) yield r;
      cursor = rows[rows.length - 1]!.seq + 1;
    }
  }

  /** Create and store a signed checkpoint over [from_seq, to_seq] (default: 1..head). */
  checkpoint(from_seq = 1, to_seq?: number): Checkpoint {
    const head = this.head();
    const to = to_seq ?? head.seq;
    if (to < from_seq || from_seq < 1) throw new Error('checkpoint: invalid range');
    if (to > head.seq) throw new Error(`checkpoint: to_seq ${to} beyond head ${head.seq}`);
    const over = this.rootOver(from_seq, to);
    if (!over) throw new Error('checkpoint: seq gap in range');
    const cp: Checkpoint = {
      checkpoint_id: randomUUID(),
      from_seq,
      to_seq: to,
      leaf_count: over.leaf_count,
      root: over.root,
      key_id: this.signer.key_id,
      signature: '',
      created_at: new Date().toISOString(),
    };
    cp.signature = this.signer.sign(checkpointSigningPayload(cp));
    this.db
      .prepare(
        `INSERT INTO checkpoints (checkpoint_id, from_seq, to_seq, leaf_count, root, key_id, signature, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(cp.checkpoint_id, cp.from_seq, cp.to_seq, cp.leaf_count, cp.root, cp.key_id, cp.signature, cp.created_at);
    return cp;
  }

  listCheckpoints(): Checkpoint[] {
    return this.db.prepare(`SELECT * FROM checkpoints ORDER BY to_seq, from_seq`).all() as Checkpoint[];
  }

  /** The checkpoint reaching furthest up the chain (newest on ties), or null. */
  latestCheckpoint(): Checkpoint | null {
    return (
      (this.db.prepare(`SELECT * FROM checkpoints ORDER BY to_seq DESC, created_at DESC LIMIT 1`).get() as
        | Checkpoint
        | undefined) ?? null
    );
  }

  getCheckpoint(checkpoint_id: string): Checkpoint | null {
    return (
      (this.db.prepare(`SELECT * FROM checkpoints WHERE checkpoint_id = ?`).get(checkpoint_id) as Checkpoint | undefined) ??
      null
    );
  }

  /**
   * FORMAT §2 Merkle root over the stored event hashes in [from_seq, to_seq],
   * or null when the range is empty, inverted, has a gap or runs past head.
   * Shared by checkpoint(), verifyCheckpoint() and the anchor client.
   */
  rootOver(from_seq: number, to_seq: number): { root: string; leaf_count: number } | null {
    if (from_seq < 1 || to_seq < from_seq) return null;
    const leaves = this.db
      .prepare(`SELECT seq, this_hash FROM events WHERE seq >= ? AND seq <= ? ORDER BY seq`)
      .all(from_seq, to_seq) as { seq: number; this_hash: string }[];
    if (leaves.length !== to_seq - from_seq + 1) return null;
    return { root: merkleRootHex(leaves), leaf_count: leaves.length };
  }

  // ───────────────────────────── anchors (0.4.0, additive) ─────────────────────────────

  /**
   * Insert a countersigned anchor receipt, or refresh the mutable public
   * fields (day, leaf_index, path_json, status) of one already stored.
   * Anchors are not chain events: they live beside the chain and never
   * change a hash.
   */
  recordAnchor(a: Omit<AnchorRecord, 'fetched_at'> & { fetched_at?: string }): void {
    this.db
      .prepare(
        `INSERT INTO anchors (anchor_id, checkpoint_id, chain_id, anchor_url, from_seq, to_seq, root, received_at,
           receipt_json, day, leaf_index, path_json, status, fetched_at)
         VALUES (@anchor_id, @checkpoint_id, @chain_id, @anchor_url, @from_seq, @to_seq, @root, @received_at,
           @receipt_json, @day, @leaf_index, @path_json, @status, @fetched_at)
         ON CONFLICT(anchor_id) DO UPDATE SET day = excluded.day, leaf_index = excluded.leaf_index,
           path_json = excluded.path_json, status = excluded.status, fetched_at = excluded.fetched_at`,
      )
      .run({
        ...a,
        checkpoint_id: a.checkpoint_id ?? null,
        day: a.day ?? null,
        leaf_index: a.leaf_index ?? null,
        path_json: a.path_json ?? null,
        fetched_at: a.fetched_at ?? new Date().toISOString(),
      });
  }

  listAnchors(): AnchorRecord[] {
    return this.db.prepare(`SELECT * FROM anchors ORDER BY from_seq, to_seq, received_at`).all() as AnchorRecord[];
  }

  lastAnchor(): AnchorRecord | null {
    return (
      (this.db.prepare(`SELECT * FROM anchors ORDER BY to_seq DESC, received_at DESC LIMIT 1`).get() as
        | AnchorRecord
        | undefined) ?? null
    );
  }

  private publicKeyFor(key_id: string): string | null {
    const r = this.db
      .prepare(`SELECT public_key_pem FROM signing_keys WHERE key_id = ? AND revoked_at IS NULL`)
      .get(key_id) as { public_key_pem: string } | undefined;
    return r?.public_key_pem ?? null;
  }

  /**
   * Walk [from_seq, to_seq] recomputing every hash and checking every link.
   * Stops at the first mismatch. Then verifies every stored checkpoint whose
   * range lies within the verified range.
   */
  verify(from_seq = 1, to_seq?: number): VerifyChainResult {
    const head = this.head();
    const to = Math.min(to_seq ?? head.seq, head.seq);
    const result: VerifyChainResult = {
      ok: true,
      from_seq,
      to_seq: to,
      events_checked: 0,
      first_mismatch: null,
      head,
      checkpoints: [],
    };

    let expectedPrev: string;
    if (from_seq === 1) {
      expectedPrev = GENESIS_HASH;
    } else {
      const prev = this.get(from_seq - 1);
      if (!prev) {
        result.ok = false;
        result.first_mismatch = {
          seq: from_seq - 1,
          kind: 'seq_gap',
          expected: 'event present',
          actual: 'missing',
        };
        return result;
      }
      expectedPrev = prev.this_hash;
    }

    let expectedSeq = from_seq;
    let lastHash = expectedPrev;
    for (const ev of this.iterate(from_seq)) {
      if (ev.seq > to) break;
      if (ev.seq !== expectedSeq) {
        result.ok = false;
        result.first_mismatch = {
          seq: expectedSeq,
          kind: 'seq_gap',
          expected: String(expectedSeq),
          actual: String(ev.seq),
        };
        break;
      }
      if (ev.prev_hash !== expectedPrev) {
        result.ok = false;
        result.first_mismatch = {
          seq: ev.seq,
          kind: 'link_broken',
          expected: expectedPrev,
          actual: ev.prev_hash,
        };
        break;
      }
      if (UNPARSEABLE.has(ev)) {
        result.ok = false;
        result.first_mismatch = { seq: ev.seq, kind: 'payload_unparseable', expected: 'a JSON object', actual: 'unparseable payload' };
        break;
      }
      const recomputed = recomputeEventHash(ev);
      if (recomputed !== ev.this_hash) {
        result.ok = false;
        result.first_mismatch = {
          seq: ev.seq,
          kind: 'hash_mismatch',
          expected: recomputed,
          actual: ev.this_hash,
        };
        break;
      }
      result.events_checked += 1;
      expectedPrev = ev.this_hash;
      lastHash = ev.this_hash;
      expectedSeq += 1;
    }

    if (result.ok && expectedSeq !== to + 1) {
      result.ok = false;
      result.first_mismatch = {
        seq: expectedSeq,
        kind: 'seq_gap',
        expected: 'event present',
        actual: 'missing',
      };
    }

    if (result.ok && to === head.seq && lastHash !== head.hash) {
      result.ok = false;
      result.first_mismatch = {
        seq: head.seq,
        kind: 'head_mismatch',
        expected: lastHash,
        actual: head.hash,
      };
    }

    const verifiedTo = result.first_mismatch ? result.first_mismatch.seq - 1 : to;
    for (const cp of this.listCheckpoints()) {
      if (cp.from_seq < from_seq || cp.to_seq > verifiedTo) {
        result.checkpoints.push({
          checkpoint_id: cp.checkpoint_id,
          from_seq: cp.from_seq,
          to_seq: cp.to_seq,
          ok: false,
          reason: 'range_outside_verified',
        });
        continue;
      }
      result.checkpoints.push(this.verifyCheckpoint(cp));
    }
    if (result.checkpoints.some((c) => !c.ok && c.reason !== 'range_outside_verified')) {
      result.ok = false;
    }
    return result;
  }

  verifyCheckpoint(cp: Checkpoint): CheckpointResult {
    const base = { checkpoint_id: cp.checkpoint_id, from_seq: cp.from_seq, to_seq: cp.to_seq };
    const pem = this.publicKeyFor(cp.key_id);
    if (!pem) return { ...base, ok: false, reason: 'unknown_key' };
    if (!verifyEd25519(pem, checkpointSigningPayload(cp), cp.signature)) {
      return { ...base, ok: false, reason: 'signature_invalid' };
    }
    const over = this.rootOver(cp.from_seq, cp.to_seq);
    if (!over || over.leaf_count !== cp.leaf_count || over.root !== cp.root) {
      return { ...base, ok: false, reason: 'root_mismatch' };
    }
    return { ...base, ok: true, reason: 'valid' };
  }
}
