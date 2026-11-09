/**
 * Audit event types (0.9.0): first-class, schema-validated records on the
 * chain for MCP audits. Payloads carry hashes, blob refs, ids and small
 * scalars only: traces, responses, transcripts and reports go to the
 * content-addressed blob store (src/audit/blobs.ts) and are referenced by
 * sha256. docs/AUDIT.md is the reference; docs/EVIDENCE-BUNDLE.md the
 * offline verification procedure.
 *
 * This module has no store dependency so `verify-bundle` can use it alone.
 */

import { createHash } from 'node:crypto';

import { z } from 'zod';

/** The 0.9.0 kinds: a bundle that holds only these is written as format /1, which 0.9.0 readers verify. */
export const AUDIT_KINDS_V1 = ['catalog_snapshot', 'call_measured', 'finding', 'gate_result', 'fix_applied', 'regression_result'] as const;
/** Audit milestones (0.10.0): a bundle holding any of these is written as format /2 (0.9.0 readers refuse it by format). */
export const MILESTONE_KINDS = ['harness_frozen', 'run_completed', 'report_issued'] as const;
export const AUDIT_KINDS = [...AUDIT_KINDS_V1, ...MILESTONE_KINDS] as const;
export type AuditKind = (typeof AUDIT_KINDS)[number];
export const AUDIT_EVENT_PREFIX = 'audit.';
/** Evidence bundle format tags (src/audit/bundle.ts, docs/EVIDENCE-BUNDLE.md). */
export const BUNDLE_FORMAT_V1 = 'kronicle-lite-evidence-bundle/1';
export const BUNDLE_FORMAT_V2 = 'kronicle-lite-evidence-bundle/2';
export const BUNDLE_FORMATS = [BUNDLE_FORMAT_V1, BUNDLE_FORMAT_V2] as const;
export type BundleFormat = (typeof BUNDLE_FORMATS)[number];
/** @deprecated the /1 tag; kept for 0.9.0 callers. */
export const BUNDLE_FORMAT = BUNDLE_FORMAT_V1;
/** The kinds a bundle of `format` may hold. */
export function kindsOfFormat(format: BundleFormat): readonly AuditKind[] {
  return format === BUNDLE_FORMAT_V1 ? AUDIT_KINDS_V1 : AUDIT_KINDS;
}
/** The oldest format that can carry every kind in `kinds` (older readers keep working when they can). */
export function formatForKinds(kinds: Iterable<AuditKind>): BundleFormat {
  for (const k of kinds) if (!(AUDIT_KINDS_V1 as readonly string[]).includes(k)) return BUNDLE_FORMAT_V2;
  return BUNDLE_FORMAT_V1;
}
export const auditEventType = (kind: AuditKind): string => `${AUDIT_EVENT_PREFIX}${kind}`;
export function kindOfEventType(event_type: string): AuditKind | null {
  if (!event_type.startsWith(AUDIT_EVENT_PREFIX)) return null;
  const k = event_type.slice(AUDIT_EVENT_PREFIX.length);
  return (AUDIT_KINDS as readonly string[]).includes(k) ? (k as AuditKind) : null;
}

export const FINDING_STATUSES = ['discovered', 'refuted', 'reopened', 'accepted'] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

const SHA256 = z.string().regex(/^[0-9a-f]{64}$/, 'lowercase hex sha256');
const ID = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/, 'id: 1-128 of [A-Za-z0-9._:/-], starting alphanumeric');
const SHORT = z.string().min(1).max(200);
const COUNT = z.number().int().nonnegative();
/** Token counts by tokenizer name (bytes, cl100k, o200k, a model id …). */
const TOKENS = z.record(z.string().min(1).max(64), COUNT).refine((r) => Object.keys(r).length <= 16, 'at most 16 tokenizers');

/**
 * A reference to an artifact in the blob store. `redacted: true` declares
 * an artifact that was deliberately NOT stored (redacted before
 * persistence); its sha256 is the hash of the original, so a holder of the
 * original can still prove it matches.
 */
export const BlobRefSchema = z.strictObject({
  sha256: SHA256,
  size: COUNT,
  media_type: z.string().min(1).max(100).optional(),
  redacted: z.literal(true).optional(),
});
export type BlobRef = z.infer<typeof BlobRefSchema>;

/** Event ids (chain event_id, a UUID) of earlier audit events this one rests on. */
const EVIDENCE = z.array(z.uuid()).max(100);

const Common = {
  audit_id: ID,
  /** Stable id of this logical event within the audit (the idempotency handle; see auditIdentity). */
  event_key: ID,
  /** Wall-clock time of the measurement itself, when it differs from the append time. */
  measured_at: z.iso.datetime().optional(),
};

export const PAYLOAD_SCHEMAS = {
  catalog_snapshot: z.strictObject({
    ...Common,
    fingerprint: SHA256.describe('catalog fingerprint (mcp-catalog-snap/1)'),
    server: z.strictObject({ name: SHORT, version: z.string().min(1).max(64).optional() }),
    tool_count: COUNT,
    bytes: COUNT,
    tokens: TOKENS.optional(),
    snapshot: BlobRefSchema,
  }),
  call_measured: z.strictObject({
    ...Common,
    fingerprint: SHA256,
    tool: SHORT,
    status: z.string().min(1).max(32),
    is_error: z.boolean(),
    latency_ms: z.number().nonnegative(),
    bytes_in: COUNT.optional(),
    bytes_out: COUNT,
    tokens: TOKENS.optional(),
    request: BlobRefSchema.optional(),
    response: BlobRefSchema.optional(),
  }),
  finding: z.strictObject({
    ...Common,
    finding_id: ID,
    status: z.enum(FINDING_STATUSES),
    title: SHORT.optional(),
    severity: z.enum(['S1', 'S2', 'S3', 'S4', 'info']).optional(),
    class: z.string().min(1).max(64).optional(),
    fingerprint: SHA256.optional(),
    detail: BlobRefSchema.optional(),
    evidence: EVIDENCE.optional(),
  }),
  gate_result: z.strictObject({
    ...Common,
    finding_id: ID,
    gate: z.string().min(1).max(64),
    verdict: z.enum(['upheld', 'refuted', 'inconclusive']),
    report: BlobRefSchema.optional(),
    evidence: EVIDENCE.optional(),
  }),
  fix_applied: z.strictObject({
    ...Common,
    finding_id: ID,
    ref: z.string().min(1).max(500).describe('PR URL, commit or proxy rule id'),
    fingerprint_before: SHA256.optional(),
    fingerprint_after: SHA256.optional(),
    diff: BlobRefSchema.optional(),
    evidence: EVIDENCE.optional(),
  }),
  harness_frozen: z.strictObject({
    ...Common,
    harness_id: ID.describe('name of the frozen harness / protocol version'),
    fingerprint: SHA256.describe('sha256 of the harness manifest (e.g. HARNESS_SHA256.txt)'),
    manifest: BlobRefSchema.describe('the frozen harness (a tar or its manifest)'),
    hypotheses: BlobRefSchema.optional().describe('pre-registered hypotheses / expected outcomes'),
    planned_runs: COUNT.optional().describe('number of runs declared at freeze time (completeness signal)'),
    title: SHORT.optional(),
  }),
  run_completed: z.strictObject({
    ...Common,
    run_id: ID,
    run_seq: z.number().int().positive().describe('1-based run sequence number: the runs of an audit are numbered 1..N with no gaps'),
    fingerprint: SHA256.describe('harness fingerprint the run executed under'),
    status: z.string().min(1).max(32),
    capture: z.enum(['complete', 'interrupted']).optional().describe('whether evidence capture ran uninterrupted (default complete)'),
    interruption: SHORT.optional().describe('what interrupted capture, when capture is interrupted'),
    nonce: SHA256.optional().describe('freeze nonce: sha256 of the harness-freeze anchor receipt, known only after the freeze'),
    result: BlobRefSchema.optional(),
    evidence: EVIDENCE.optional(),
  }),
  report_issued: z.strictObject({
    ...Common,
    report_id: ID,
    report: BlobRefSchema,
    run_count: COUNT.optional().describe('number of runs the report covers (completeness signal)'),
    title: SHORT.optional(),
    evidence: EVIDENCE.optional(),
  }),
  regression_result: z.strictObject({
    ...Common,
    finding_id: ID.optional(),
    fingerprint_before: SHA256,
    fingerprint_after: SHA256,
    verdict: z.enum(['improved', 'regressed', 'unchanged']),
    deltas: z.record(z.string().min(1).max(64), z.number()).refine((r) => Object.keys(r).length <= 64, 'at most 64 deltas'),
    report: BlobRefSchema.optional(),
    evidence: EVIDENCE.optional(),
  }),
} as const satisfies Record<AuditKind, z.ZodType>;

export type AuditPayload<K extends AuditKind = AuditKind> = z.infer<(typeof PAYLOAD_SCHEMAS)[K]>;

/** One event to record. `event_key` names the LOGICAL event within the audit: a retry with the same key is the same event. */
export const AuditEventInputSchema = z.strictObject({
  kind: z.enum(AUDIT_KINDS),
  event_key: ID.describe('stable id of this logical event within the audit; a retry with the same key is a no-op'),
  payload: z.record(z.string(), z.unknown()),
});
export type AuditEventInput = z.infer<typeof AuditEventInputSchema>;

/** Validate a payload for `kind`; returns the parsed payload or the first problem. */
export function parseAuditPayload(kind: AuditKind, payload: unknown): { ok: true; value: AuditPayload } | { ok: false; problem: string } {
  const r = PAYLOAD_SCHEMAS[kind].safeParse(payload);
  if (r.success) return { ok: true, value: r.data as AuditPayload };
  const i = r.error.issues[0]!;
  return { ok: false, problem: `${i.path.length > 0 ? i.path.join('.') : '(payload)'}: ${i.message}` };
}

/** Every blob ref in a payload, with the field it sits in. */
export function blobRefsOf(payload: Record<string, unknown>): { field: string; ref: BlobRef }[] {
  const out: { field: string; ref: BlobRef }[] = [];
  for (const field of ['snapshot', 'request', 'response', 'detail', 'report', 'diff', 'manifest', 'hypotheses', 'result'] as const) {
    const r = BlobRefSchema.safeParse(payload[field]);
    if (r.success) out.push({ field, ref: r.data });
  }
  return out;
}

/** Every catalog fingerprint a payload names (queryable index). */
export function fingerprintsOf(payload: Record<string, unknown>): string[] {
  const out = new Set<string>();
  for (const k of ['fingerprint', 'fingerprint_before', 'fingerprint_after']) {
    const v = payload[k];
    if (typeof v === 'string') out.add(v);
  }
  return [...out].sort();
}

/** Evidence event ids a payload references. */
export function evidenceOf(payload: Record<string, unknown>): string[] {
  const v = payload['evidence'];
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

/**
 * The status a finding moves to on this event, or null when the event does
 * not move it. A `gate_result` with verdict `refuted` refutes; acceptance and
 * reopening are explicit `finding` events (a human or reviewer decision).
 */
export function statusEffect(kind: AuditKind, payload: Record<string, unknown>): FindingStatus | null {
  if (kind === 'finding') return payload['status'] as FindingStatus;
  if (kind === 'gate_result' && payload['verdict'] === 'refuted') return 'refuted';
  return null;
}

/**
 * Allowed finding transitions (from → to); docs/AUDIT.md has the table.
 * The first event must be `discovered`.
 */
export function transitionAllowed(from: FindingStatus | null, to: FindingStatus): boolean {
  if (from === null) return to === 'discovered';
  switch (to) {
    case 'discovered':
      return false;
    case 'refuted':
      // Several refuters may refute the same finding: refuted → refuted is a no-op transition.
      return from === 'discovered' || from === 'reopened' || from === 'refuted';
    case 'accepted':
      return from === 'discovered' || from === 'reopened';
    case 'reopened':
      return from === 'refuted' || from === 'accepted';
  }
}

/**
 * Stable identity of a logical audit event: the same (audit_id, event_key)
 * always yields the same chain idempotency key and the same event_id (a
 * UUID-shaped slice of sha256), in any store. Not a content hash: a retry
 * with a different payload is a conflict, not a new event.
 */
export function auditIdentity(audit_id: string, event_key: string): { idempotency_key: string; event_id: string } {
  const h = createHash('sha256').update(`kronicle-lite/audit-event/1\n${audit_id}\n${event_key}`, 'utf8').digest('hex');
  // RFC 4122 layout with version 8 (custom) and the variant bits set, so z.uuid() accepts it.
  const v = `8${h.slice(13, 16)}`;
  const variant = ((parseInt(h.slice(16, 17), 16) & 0x3) | 0x8).toString(16) + h.slice(17, 20);
  return { idempotency_key: `audit:${h}`, event_id: `${h.slice(0, 8)}-${h.slice(8, 12)}-${v}-${variant}-${h.slice(20, 32)}` };
}
