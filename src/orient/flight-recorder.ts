/**
 * Flight recorder: every orient briefing issued, keyed by actor, so a later
 * call can recover the actor's last position without a cursor and an
 * operator can see exactly what an agent was told and when.
 */

import { boundedBookkeepingWrite } from '../db/storage.js';
import type { Db } from '../db/open.js';

export interface FlightRecord {
  briefing_id: string;
  actor_id: string;
  issued_at: string;
  /** Exclusive lower bound the delta was folded from. */
  from_seq: number;
  /** Inclusive upper bound = chain head at issue time. */
  to_seq: number;
  head_hash: string;
  focus: string;
  delta_hash: string;
  record: Record<string, unknown>;
}

interface Row {
  briefing_id: string;
  actor_id: string;
  issued_at: string;
  from_seq: number;
  to_seq: number;
  head_hash: string;
  focus: string;
  delta_hash: string;
  record_json: string;
}

function fromRow(r: Row): FlightRecord {
  return { ...r, record: JSON.parse(r.record_json) as Record<string, unknown> };
}

/** C2-08: how long a briefing's flight-recorder row waits for another process's write lock before it is skipped. */
export const BOOKKEEPING_WAIT_MS = 1000;

export class FlightRecorder {
  constructor(private readonly db: Db) {}

  record(rec: FlightRecord): void {
    // 0.8.1: a read-only or full store still briefs; the briefing is just not kept. Behind
    // another process's long write it waits at most 1 s (C2-08), then skips the row.
    boundedBookkeepingWrite(this.db, BOOKKEEPING_WAIT_MS, () => this.insert(rec));
  }

  private insert(rec: FlightRecord): void {
    this.db
      .prepare(
        `INSERT INTO flight_recorder (briefing_id, actor_id, issued_at, from_seq, to_seq, head_hash, focus, delta_hash, record_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        rec.briefing_id,
        rec.actor_id,
        rec.issued_at,
        rec.from_seq,
        rec.to_seq,
        rec.head_hash,
        rec.focus,
        rec.delta_hash,
        JSON.stringify(rec.record),
      );
  }

  latestForActor(actor_id: string): FlightRecord | null {
    const r = this.db
      .prepare(`SELECT * FROM flight_recorder WHERE actor_id = ? ORDER BY issued_at DESC, rowid DESC LIMIT 1`)
      .get(actor_id) as Row | undefined;
    return r ? fromRow(r) : null;
  }

  /** 0.6.0: the actor's latest briefing issued at head `to_seq` (what a compact cursor points at). */
  briefingAt(actor_id: string, to_seq: number): FlightRecord | null {
    const r = this.db
      .prepare(`SELECT * FROM flight_recorder WHERE actor_id = ? AND to_seq = ? ORDER BY issued_at DESC, rowid DESC LIMIT 1`)
      .get(actor_id, to_seq) as Row | undefined;
    return r ? fromRow(r) : null;
  }

  findById(briefing_id: string): FlightRecord | null {
    const r = this.db.prepare(`SELECT * FROM flight_recorder WHERE briefing_id = ?`).get(briefing_id) as Row | undefined;
    return r ? fromRow(r) : null;
  }

  findByActor(actor_id: string, limit = 20): FlightRecord[] {
    return (
      this.db
        .prepare(`SELECT * FROM flight_recorder WHERE actor_id = ? ORDER BY issued_at DESC, rowid DESC LIMIT ?`)
        .all(actor_id, limit) as Row[]
    ).map(fromRow);
  }
}
