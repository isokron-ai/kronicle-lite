/**
 * AuditLog (0.9.0): records audit events on the chain, keeps their
 * projection (by audit, by catalog fingerprint, per-finding state) and the
 * content-addressed blob store beside it.
 *
 * Ingest is idempotent by a stable logical id, not by content: the same
 * (audit_id, event_key) always maps to one chain idempotency key and one
 * event_id (auditIdentity). A retry with the same payload returns the
 * original event (`replayed: true`); a retry with a DIFFERENT payload is
 * refused (`event_key_conflict`), never silently treated as a new event.
 */

import { createHash } from 'node:crypto';

import type { Chain, ChainEvent } from '../chain/index.js';
import { canonicalize } from '../crypto/canonical.js';
import { sha256Hex } from '../crypto/hash.js';
import type { Db } from '../db/open.js';
import { scanValue, SecretDetectedError } from '../secrets/guard.js';
import {
  auditEventType,
  auditIdentity,
  AuditEventInputSchema,
  blobRefsOf,
  evidenceOf,
  fingerprintsOf,
  kindOfEventType,
  parseAuditPayload,
  statusEffect,
  transitionAllowed,
  type AuditEventInput,
  type AuditKind,
  type FindingStatus,
} from './schemas.js';

export class AuditError extends Error {
  override readonly name = 'AuditError';
  constructor(
    readonly code: 'invalid_audit_event' | 'event_key_conflict' | 'unknown_blob' | 'unknown_evidence' | 'illegal_transition' | 'blob_too_large' | 'too_many_events',
    message: string,
    readonly index?: number,
  ) {
    super(message);
  }
}

/** Largest single blob accepted (bytes). Bigger artifacts belong in an external store referenced by hash. */
export const MAX_BLOB_BYTES = 64 * 1024 * 1024;
/** Most events in one record() call (one transaction). */
export const MAX_EVENTS_PER_CALL = 500;

export interface RecordedAuditEvent {
  index: number;
  event_id: string;
  seq: number;
  this_hash: string;
  kind: AuditKind;
  event_key: string;
  replayed: boolean;
}

export interface AuditEventView {
  seq: number;
  event_id: string;
  this_hash: string;
  kind: AuditKind;
  audit_id: string;
  event_key: string;
  actor_id: string;
  occurred_at: string;
  payload: Record<string, unknown>;
}

export interface FindingState {
  audit_id: string;
  finding_id: string;
  status: FindingStatus;
  title: string | null;
  severity: string | null;
  opened_seq: number;
  last_seq: number;
  events: number;
}

export interface AuditQuery {
  audit_id?: string | undefined;
  fingerprint?: string | undefined;
  kind?: AuditKind | undefined;
  finding_id?: string | undefined;
  after_seq?: number | undefined;
  limit?: number | undefined;
}

export interface BlobRow {
  sha256: string;
  size: number;
  media_type: string | null;
  bytes: Buffer;
}

/** sha256 hex of raw bytes (blob ids). */
export function blobHash(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

export class AuditLog {
  constructor(
    private readonly db: Db,
    private readonly chain: Chain,
  ) {}

  // ───────────────────────────── blobs ─────────────────────────────

  /** Store an artifact by content; returns its ref. Re-putting the same bytes is a no-op. */
  putBlob(bytes: Uint8Array, media_type?: string): { sha256: string; size: number; media_type?: string } {
    if (bytes.byteLength > MAX_BLOB_BYTES) throw new AuditError('blob_too_large', `blob is ${bytes.byteLength} bytes; the limit is ${MAX_BLOB_BYTES}`);
    const sha256 = blobHash(bytes);
    this.db
      .prepare(`INSERT OR IGNORE INTO blobs (sha256, size, media_type, bytes, created_at) VALUES (?, ?, ?, ?, ?)`)
      .run(sha256, bytes.byteLength, media_type ?? null, Buffer.from(bytes), new Date().toISOString());
    return { sha256, size: bytes.byteLength, ...(media_type !== undefined ? { media_type } : {}) };
  }

  getBlob(sha256: string): BlobRow | null {
    return (this.db.prepare(`SELECT sha256, size, media_type, bytes FROM blobs WHERE sha256 = ?`).get(sha256) as BlobRow | undefined) ?? null;
  }

  hasBlob(sha256: string): boolean {
    return this.db.prepare(`SELECT 1 FROM blobs WHERE sha256 = ?`).get(sha256) !== undefined;
  }

  // ───────────────────────────── ingest ─────────────────────────────

  /**
   * Record events in ONE transaction: all land or none (a bad event at index
   * i refuses the whole call with `AuditError.index = i`). Each event is
   * validated against its kind's schema, scanned by the write-time secret
   * guard (a key must never be burned into the chain), its blob refs must
   * exist in the blob store (or be declared `redacted`), its evidence ids
   * must be audit events of the same audit, and a finding's status
   * transition must be legal.
   */
  record(audit_id: string, events: readonly AuditEventInput[], actor_id: string): RecordedAuditEvent[] {
    if (events.length === 0) return [];
    if (events.length > MAX_EVENTS_PER_CALL) throw new AuditError('too_many_events', `${events.length} events; at most ${MAX_EVENTS_PER_CALL} per call`);
    const run = this.db.transaction((): RecordedAuditEvent[] => events.map((e, i) => this.recordOne(audit_id, e, actor_id, i)));
    return run.immediate();
  }

  private recordOne(audit_id: string, raw: AuditEventInput, actor_id: string, index: number): RecordedAuditEvent {
    const input = AuditEventInputSchema.safeParse(raw);
    if (!input.success) throw new AuditError('invalid_audit_event', `event ${index}: ${input.error.issues[0]!.message}`, index);
    const { kind, event_key } = input.data;
    const payloadIn = { ...input.data.payload, audit_id, event_key };
    for (const [k, v] of [['audit_id', audit_id], ['event_key', event_key]] as const) {
      if (input.data.payload[k] !== undefined && input.data.payload[k] !== v) {
        throw new AuditError('invalid_audit_event', `event ${index}: payload.${k} differs from the event's ${k}`, index);
      }
    }
    const parsed = parseAuditPayload(kind, payloadIn);
    if (!parsed.ok) throw new AuditError('invalid_audit_event', `event ${index} (${kind}): ${parsed.problem}`, index);
    const payload = parsed.value as Record<string, unknown>;
    const secrets = scanValue(payload, `audit event ${index}`);
    if (secrets.length > 0) throw new SecretDetectedError(secrets, `audit event ${index}`, 'redact the value before recording (store the artifact as a blob ref with redacted: true)');

    const id = auditIdentity(audit_id, event_key);
    const prior = this.chain.findByIdempotencyKey(id.idempotency_key);
    if (prior) {
      if (prior.event_type !== auditEventType(kind) || canonicalize(prior.payload) !== canonicalize(payload)) {
        throw new AuditError('event_key_conflict', `event ${index}: event_key "${event_key}" was already recorded in audit "${audit_id}" with a different ${prior.event_type !== auditEventType(kind) ? 'kind' : 'payload'} (seq ${prior.seq})`, index);
      }
      return { index, event_id: prior.event_id, seq: prior.seq, this_hash: prior.this_hash, kind, event_key, replayed: true };
    }

    for (const { field, ref } of blobRefsOf(payload)) {
      if (ref.redacted) continue;
      const b = this.getBlobMeta(ref.sha256);
      if (!b) throw new AuditError('unknown_blob', `event ${index}: ${field} references blob ${ref.sha256.slice(0, 12)}… that is not in the blob store (put it first, or mark the ref redacted)`, index);
      if (b.size !== ref.size) throw new AuditError('unknown_blob', `event ${index}: ${field} size ${ref.size} differs from the stored blob's ${b.size}`, index);
    }
    for (const ev of evidenceOf(payload)) {
      const row = this.db.prepare(`SELECT audit_id FROM audit_events WHERE event_id = ?`).get(ev) as { audit_id: string } | undefined;
      if (!row || row.audit_id !== audit_id) throw new AuditError('unknown_evidence', `event ${index}: evidence ${ev} is not an audit event of "${audit_id}"`, index);
    }
    const effect = statusEffect(kind, payload);
    const findingId = typeof payload['finding_id'] === 'string' ? payload['finding_id'] : null;
    if (findingId !== null && (effect !== null || kind !== 'finding')) {
      const cur = this.finding(audit_id, findingId);
      if (effect !== null && !transitionAllowed(cur?.status ?? null, effect)) {
        throw new AuditError('illegal_transition', `event ${index}: finding ${findingId} cannot go ${cur?.status ?? '(new)'} → ${effect}`, index);
      }
      if (effect === null && cur === null) throw new AuditError('illegal_transition', `event ${index}: finding ${findingId} has no "discovered" event in "${audit_id}"`, index);
    }

    const r = this.chain.append({ event_type: auditEventType(kind), payload, actor_id, idempotency_key: id.idempotency_key, event_id: id.event_id });
    this.applyEvent(r.event);
    return { index, event_id: r.event.event_id, seq: r.event.seq, this_hash: r.event.this_hash, kind, event_key, replayed: false };
  }

  private getBlobMeta(sha256: string): { size: number } | null {
    return (this.db.prepare(`SELECT size FROM blobs WHERE sha256 = ?`).get(sha256) as { size: number } | undefined) ?? null;
  }

  // ───────────────────────────── projection ─────────────────────────────

  /** Project one chain event (no-op for non-audit events). Used by record, import and rebuild. */
  applyEvent(ev: ChainEvent): void {
    const kind = kindOfEventType(ev.event_type);
    if (!kind) return;
    const p = ev.payload;
    const audit_id = typeof p['audit_id'] === 'string' ? p['audit_id'] : null;
    if (audit_id === null) return; // malformed (hand-built chain): verify-bundle and verifyProjection report it
    const event_key = typeof p['event_key'] === 'string' ? p['event_key'] : ev.event_id;
    const finding_id = typeof p['finding_id'] === 'string' ? p['finding_id'] : null;
    this.db
      .prepare(`INSERT OR IGNORE INTO audit_events (seq, event_id, audit_id, kind, event_key, finding_id) VALUES (?, ?, ?, ?, ?, ?)`)
      .run(ev.seq, ev.event_id, audit_id, kind, event_key, finding_id);
    for (const f of fingerprintsOf(p)) this.db.prepare(`INSERT OR IGNORE INTO audit_event_fingerprints (fingerprint, seq) VALUES (?, ?)`).run(f, ev.seq);
    if (finding_id === null) return;
    const effect = statusEffect(kind, p);
    const cur = this.finding(audit_id, finding_id);
    if (!cur) {
      if (effect !== 'discovered') return;
      this.db
        .prepare(
          `INSERT INTO audit_findings (audit_id, finding_id, status, title, severity, opened_seq, last_seq, events) VALUES (?, ?, 'discovered', ?, ?, ?, ?, 1)`,
        )
        .run(audit_id, finding_id, strOrNull(p['title']), strOrNull(p['severity']), ev.seq, ev.seq);
      return;
    }
    this.db
      .prepare(
        `UPDATE audit_findings SET status = ?, title = COALESCE(?, title), severity = COALESCE(?, severity), last_seq = ?, events = events + 1 WHERE audit_id = ? AND finding_id = ?`,
      )
      .run(effect ?? cur.status, strOrNull(p['title']), strOrNull(p['severity']), ev.seq, audit_id, finding_id);
  }

  /** Clear and re-derive the audit projection from the chain (inside rebuild's transaction). */
  rebuildProjection(events: Iterable<ChainEvent>): number {
    this.db.exec(`DELETE FROM audit_events; DELETE FROM audit_event_fingerprints; DELETE FROM audit_findings;`);
    let n = 0;
    for (const ev of events) {
      if (kindOfEventType(ev.event_type)) {
        this.applyEvent(ev);
        n++;
      }
    }
    return n;
  }

  /** null when the projection matches the chain's audit events (count and ids), else the problem. */
  checkProjection(): string | null {
    const chainN = (this.db.prepare(`SELECT COUNT(*) AS n FROM events WHERE event_type LIKE 'audit.%'`).get() as { n: number }).n;
    const projN = (this.db.prepare(`SELECT COUNT(*) AS n FROM audit_events`).get() as { n: number }).n;
    if (chainN !== projN) return `audit_events has ${projN} rows; the chain has ${chainN} audit events`;
    const stray = this.db
      .prepare(`SELECT a.seq FROM audit_events a LEFT JOIN events e ON e.seq = a.seq AND e.event_id = a.event_id WHERE e.seq IS NULL LIMIT 1`)
      .get() as { seq: number } | undefined;
    return stray ? `audit_events row seq ${stray.seq} has no matching chain event` : null;
  }

  // ───────────────────────────── queries ─────────────────────────────

  finding(audit_id: string, finding_id: string): FindingState | null {
    return (
      (this.db.prepare(`SELECT * FROM audit_findings WHERE audit_id = ? AND finding_id = ?`).get(audit_id, finding_id) as FindingState | undefined) ?? null
    );
  }

  findings(audit_id: string, status?: FindingStatus): FindingState[] {
    return (
      status
        ? this.db.prepare(`SELECT * FROM audit_findings WHERE audit_id = ? AND status = ? ORDER BY opened_seq`).all(audit_id, status)
        : this.db.prepare(`SELECT * FROM audit_findings WHERE audit_id = ? ORDER BY opened_seq`).all(audit_id)
    ) as FindingState[];
  }

  /** Audit events matching every given filter, ascending seq. At least audit_id or fingerprint is required. */
  query(q: AuditQuery): AuditEventView[] {
    if (q.audit_id === undefined && q.fingerprint === undefined) throw new AuditError('invalid_audit_event', 'query needs audit_id or fingerprint');
    const where: string[] = ['a.seq > ?'];
    const args: (string | number)[] = [q.after_seq ?? 0];
    let from = 'audit_events a';
    if (q.fingerprint !== undefined) {
      from = 'audit_event_fingerprints f JOIN audit_events a ON a.seq = f.seq';
      where.push('f.fingerprint = ?');
      args.push(q.fingerprint);
    }
    for (const [col, v] of [['audit_id', q.audit_id], ['kind', q.kind], ['finding_id', q.finding_id]] as const) {
      if (v === undefined) continue;
      where.push(`a.${col} = ?`);
      args.push(v);
    }
    const limit = Math.min(Math.max(q.limit ?? 200, 1), 5000);
    const rows = this.db
      .prepare(
        `SELECT a.seq, a.audit_id, a.kind, a.event_key, e.event_id, e.this_hash, e.actor_id, e.occurred_at, e.payload_canonical
           FROM ${from} JOIN events e ON e.seq = a.seq WHERE ${where.join(' AND ')} ORDER BY a.seq LIMIT ?`,
      )
      .all(...args, limit) as (Omit<AuditEventView, 'payload'> & { payload_canonical: string })[];
    return rows.map(({ payload_canonical, ...r }) => ({ ...r, payload: JSON.parse(payload_canonical) as Record<string, unknown> }));
  }

  /** Every seq of an audit's events, ascending (bundle export). */
  seqsOf(audit_id: string): number[] {
    return (this.db.prepare(`SELECT seq FROM audit_events WHERE audit_id = ? ORDER BY seq`).all(audit_id) as { seq: number }[]).map((r) => r.seq);
  }

  /** sha256 of the canonical payload (handy for callers comparing a retry). */
  static payloadHash(payload: Record<string, unknown>): string {
    return sha256Hex(canonicalize(payload));
  }
}

function strOrNull(v: unknown): string | null {
  return typeof v === 'string' ? v : null;
}
