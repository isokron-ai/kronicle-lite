/**
 * Tool output schemas (MCP `outputSchema`, spec 2026-07-28 "Structured
 * Content"). Each schema mirrors the TypeScript result type the tool handler
 * returns from the store; the server validates `structuredContent` against
 * these before answering, so a drift between a result type and its schema
 * fails the tool call loudly instead of shipping a wrong contract.
 *
 * Keep these in lock-step with:
 *   - src/orient/orient.ts        SystemState, Recovery, Digest
 *   - src/orient/delta.ts         TypedDelta, DeltaEntry, DeltaCoverage
 *   - src/orient/drift.ts         DriftBanner, StaleWriteAdvisory
 *   - src/orient/retraction.ts    Retraction
 *   - src/orient/audit.ts         AuditSummary, AuditResult
 *   - src/recall/recall.ts        RecallResult, RecallHit (0.6.0: honesty.ts, absence.ts)
 *   - src/recall/receipt.ts       Receipt
 *   - src/recall/verify-receipt.ts VerifyResult
 *   - src/chain/chain.ts          ChainHead, Checkpoint, VerifyChainResult
 *   - src/docs/documents.ts       PutDocumentResult, SupersedeBlockResult, TombstoneBlockResult
 *
 * The catalog snapshot in .mcp-catalog/ pins the emitted JSON Schema bytes.
 */

import { z } from 'zod';

import { VERIFY_REASONS, VERIFY_STATUSES } from './recall/verify-receipt.js';
import { AUDIT_VERDICTS } from './orient/audit.js';
import { ReceiptSchema } from './recall/receipt.js';
import { FOCUSES, RECOVERY_METHODS } from './orient/orient.js';
import { RETRACTION_KINDS } from './orient/retraction.js';
import { ROW_PROBLEMS } from './docs/integrity.js';
import { ABSENCE_VERDICTS, RECALL_SCOPES } from './recall/absence.js';
import { AUTHORITIES, AUTHORITY_BASES, AUTHORITY_REASONS } from './recall/honesty.js';

// ───────────────────────────── lean JSON Schema (0.5.0) ─────────────────────────────

type Json = { [k: string]: unknown };
const SAFE = Number.MAX_SAFE_INTEGER;
const OUTPUT_DEPTH = 0;

function isPlain(v: unknown): v is Json {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Type-only summary of a nested node: what `tools/list` shows below OUTPUT_DEPTH. */
function shallow(s: Json): Json {
  if (Array.isArray(s['anyOf'])) {
    const types = [...new Set((s['anyOf'] as Json[]).flatMap((x) => (x['type'] === undefined ? [] : ([] as unknown[]).concat(x['type']))))];
    return types.length === 0 ? {} : { type: types.length === 1 ? types[0] : types };
  }
  const r: Json = {};
  for (const k of ['type', 'enum', 'const']) if (s[k] !== undefined) r[k] = s[k];
  return r;
}

/**
 * Shrink an emitted JSON Schema without loosening anything a caller relies
 * on. Both directions: no `$schema`, no ±2^53 integer bounds, no
 * `propertyNames: string`, nullable `anyOf` folded into `type: [T, "null"]`.
 * Outputs additionally lose descriptions, patterns, numeric bounds and
 * `additionalProperties: false`, and below the top-level properties keep
 * only their types (the full contract is the `kronicle://schemas/tools`
 * resource and docs/FORMAT.md). A `pattern` next to a `format` is dropped. The server still validates every result against the full
 * zod schema; the advertised one is a strict relaxation of it.
 */
export function compactJsonSchema(node: unknown, io: 'input' | 'output', depth = 0): unknown {
  if (Array.isArray(node)) return node.map((x) => compactJsonSchema(x, io, depth));
  if (!isPlain(node)) return node;
  if (io === 'output' && depth > OUTPUT_DEPTH && (node['properties'] || node['items'] || node['anyOf'])) return shallow(node);
  const any = node['anyOf'];
  if (Array.isArray(any) && any.length === 2) {
    const isNull = (x: unknown) => isPlain(x) && x['type'] === 'null' && Object.keys(x).length === 1;
    const other = (any as unknown[]).find((x) => !isNull(x));
    if ((any as unknown[]).some(isNull) && isPlain(other) && typeof other['type'] === 'string') {
      const { anyOf: _drop, ...rest } = node;
      return compactJsonSchema({ ...other, ...rest, type: [other['type'], 'null'] }, io, depth);
    }
  }
  const out: Json = {};
  for (const [k, v] of Object.entries(node)) {
    if (k === '$schema') continue;
    if ((k === 'maximum' && v === SAFE) || (k === 'minimum' && v === -SAFE)) continue;
    if (k === 'propertyNames' && isPlain(v) && v['type'] === 'string' && Object.keys(v).length === 1) continue;
    if (k === 'additionalProperties' && isPlain(v) && Object.keys(v).length === 0) continue;
    // `format` (uuid, date-time, …) already says what the regex zod emits beside it says.
    if (k === 'pattern' && typeof node['format'] === 'string') continue;
    if (io === 'output') {
      if (k === 'description' || k === 'pattern' || k === 'minimum' || k === 'maximum' || k === 'exclusiveMinimum' || k === 'exclusiveMaximum') continue;
      if (k === 'additionalProperties' && v === false) continue;
      if (k === 'required' && depth > 0) continue;
    }
    if (k === 'properties' && isPlain(v)) {
      out[k] = Object.fromEntries(Object.entries(v).map(([pk, pv]) => [pk, compactJsonSchema(pv, io, depth + 1)]));
      continue;
    }
    out[k] = compactJsonSchema(v, io, depth);
  }
  return out;
}

/** The full emitted JSON Schema of a zod schema (the kronicle://schemas/tools resource). */
export function fullJsonSchema(schema: z.ZodType, io: 'input' | 'output'): Json {
  return z.toJSONSchema(schema, { target: 'draft-2020-12', io }) as Json;
}

/**
 * Wrap a zod schema as a Standard Schema whose advertised JSON Schema is the
 * compact one and whose validation is the full zod schema, unchanged.
 */
export function lean<T extends z.ZodType>(schema: T, io: 'input' | 'output'): T {
  const std = schema['~standard'];
  const json = () => compactJsonSchema(fullJsonSchema(schema, io), io) as Json;
  return {
    '~standard': {
      version: 1,
      vendor: 'kronicle-lite',
      validate: (v: unknown) => std.validate(v),
      jsonSchema: { input: json, output: json },
    },
  } as unknown as T;
}

const HEX64 = z.string().regex(/^[0-9a-f]{64}$/).describe('lowercase hex sha256');

export const ChainHeadSchema = z
  .object({
    seq: z.number().int().nonnegative().describe('Chain head sequence number (0 = genesis).'),
    hash: HEX64.describe('Hash of the head event (genesis hash at seq 0).'),
  })
  .describe('Chain head at the time of the call.');

export const StaleWriteAdvisorySchema = z.object({
  advisory: z.boolean().describe('true when the actor wrote without a fresh orient; nothing is blocked.'),
  events_since_last_orient: z.number().int().nullable(),
  seconds_since_last_orient: z.number().nullable(),
  line: z.string().nullable().describe('Human-readable advisory, or null when none.'),
});

export const DriftBannerSchema = z.object({
  surfaced: z.boolean().describe('true when the drift rules fired: your memory of this store is stale.'),
  events_since_last_orient: z.number().int().nullable(),
  seconds_since_last_orient: z.number().nullable(),
  line: z.string(),
});

export const RecoverySchema = z.object({
  method: z.enum(RECOVERY_METHODS).describe('How the server recovered your position.'),
  from_seq: z.number().int().nonnegative(),
  reason: z.string(),
  cursor_error: z.string().nullable().describe('Set when a since_cursor was presented but rejected. The call still succeeds.'),
  cursor_issued_at: z.string().nullable(),
});

export const DigestSchema = z.object({
  genesis_hash: HEX64,
  documents: z.number().int().nonnegative(),
  live_blocks: z.number().int().nonnegative(),
  checkpoints: z.number().int().nonnegative(),
  recent_documents: z.array(
    z.object({ slug: z.string(), title: z.string(), revision: z.number().int().positive(), updated_at: z.string() }),
  ),
});

export const RetractionSchema = z.object({
  seq: z.number().int().positive(),
  event_type: z.string(),
  kind: z.enum(RETRACTION_KINDS).describe('instruction = a CLAUDE.md / AGENTS.md / rule / memory block changed on disk.'),
  severity: z.enum(['safety', 'behavioral', 'informational']),
  block_id: z.string().nullable(),
  doc_slug: z.string().nullable(),
  successor_block_id: z.string().nullable(),
  reason: z.string().nullable(),
  reason_line: z.string().describe('"You previously relied on X; current truth is Y. Reconcile before proceeding."'),
  heading_path: z.array(z.string()).nullable(),
  old_text: z.string().nullable(),
  new_text: z.string().nullable(),
  diff: z.string().nullable().describe('Word diff: [-removed-]{+added+}.'),
});

export const DeltaEventEntrySchema = z.object({
  kind: z.literal('event'),
  seq: z.number().int().positive(),
  hash: HEX64,
  event_type: z.string(),
  actor_id: z.string(),
  occurred_at: z.string(),
  payload: z.record(z.string(), z.unknown()),
  rendered_via: z.enum(['enumerate', 'volume-rollup']),
});

export const DeltaRollupEntrySchema = z.object({
  kind: z.literal('volume_rollup'),
  event_type: z.string(),
  count: z.number().int().positive(),
  first_seq: z.number().int().positive(),
  last_seq: z.number().int().positive(),
  sample: DeltaEventEntrySchema.describe('Most recent event in the group.'),
  rendered_via: z.enum(['volume-rollup', 'budget']),
});

export const TypedDeltaSchema = z.object({
  from_seq: z.number().int().nonnegative().describe('Exclusive.'),
  to_seq: z.number().int().nonnegative().describe('Inclusive.'),
  events_since: z.number().int().nonnegative(),
  by_type: z.record(z.string(), z.number().int().nonnegative()),
  entries: z.array(z.union([DeltaEventEntrySchema, DeltaRollupEntrySchema])).describe('Chain order, oldest first.'),
  coverage: z.object({
    total_events_in: z.number().int().nonnegative(),
    enumerated: z.number().int().nonnegative(),
    rolled_up: z.number().int().nonnegative(),
    rollup_groups: z.number().int().nonnegative(),
    demoted_by_budget: z.array(z.string()),
    truncated: z.boolean(),
    estimated_tokens: z.number().int().nonnegative(),
  }),
});

export const DiffStatSchema = z.object({
  files_changed: z.number().int().nonnegative(),
  insertions: z.number().int().nonnegative(),
  deletions: z.number().int().nonnegative(),
  summary: z.string().describe('git diff --stat style line.'),
  bound_from: z.enum(['git', 'stored_revision', 'none']).describe('Where the bound side of the diff came from.'),
});

export const SourceDriftSchema = z
  .object({
    slug: z.string(),
    doc_id: z.string(),
    revision: z.number().int().positive().describe('Revision whose put recorded the binding.'),
    repo_root: z.string(),
    path: z.string().describe('Path inside repo_root, /-separated.'),
    bound_commit: z.string().nullable(),
    bound_blob_sha: z.string(),
    state: z.enum(['current', 'changed', 'missing', 'unavailable']),
    working_blob_sha: z.string().nullable(),
    head_commit: z.string().nullable(),
    diff_stat: DiffStatSchema.nullable(),
    detail: z.string().nullable(),
  })
  .describe('A git-bound document compared with its working-tree source file.');

export const AnchorSummarySchema = z
  .object({
    anchor_id: z.string(),
    from_seq: z.number().int().positive(),
    to_seq: z.number().int().positive(),
    received_at: z.string(),
    status: z.string().describe('pending_public | published | conflict'),
    events_since: z.number().int().nonnegative().describe('Events appended after the anchored range.'),
  })
  .describe('Latest hosted anchor of this chain (local record, no network).');

export const SystemStateSchema = z.object({
  format: z.literal('kronicle-lite/1'),
  briefing_id: z.string(),
  issued_at: z.string(),
  actor_id: z.string(),
  focus: z.enum(FOCUSES),
  head: ChainHeadSchema,
  cursor: z.string().describe('Full cursor (sxt1.). Carry it forward to the next get_system_state call.'),
  cursor_compact: z.string().describe('Compact cursor (sxt1c.), interchangeable with cursor.'),
  recovery: RecoverySchema,
  drift_banner: DriftBannerSchema,
  stale_write_advisory: StaleWriteAdvisorySchema,
  anchor: AnchorSummarySchema.nullable().describe('null when the chain was never anchored.'),
  source_drift: z
    .array(SourceDriftSchema)
    .nullable()
    .describe('Git-bound documents whose source file changed or was deleted since binding; null for focus=pulse.'),
  integrity: z
    .object({ ok: z.boolean(), events_checked: z.number().int().nonnegative(), blocks_checked: z.number().int().nonnegative(), problem: z.string().nullable() })
    .nullable(),
  scope: z
    .object({
      project_keys: z.array(z.string()),
      hidden_retractions: z.number().int().nonnegative(),
      verdict: z.enum(['complete', 'partial']).describe('partial: retractions were hidden, so "none" is not a clean bill for them.'),
    })
    .nullable(),
  delta: TypedDeltaSchema.nullable().describe('null for focus=retractions and focus=pulse.'),
  retractions: z.array(RetractionSchema).nullable().describe('null for focus=pulse.'),
  digest: DigestSchema.nullable().describe('Present on cold start and focus=orientation.'),
  next_steps: z.array(z.string()),
});

export const AuditSummarySchema = z.object({
  checked_at: z.string(),
  head: ChainHeadSchema,
  results: z.array(
    z.object({
      symbol: z.string(),
      asserted: z.string(),
      verdict: z.enum(AUDIT_VERDICTS),
      kind: z.enum(['block', 'document', 'chain', 'unknown']),
      current: z.record(z.string(), z.unknown()).nullable().describe('The current truth for the symbol, when known.'),
      reconcile: z.string().nullable(),
      source_drift: SourceDriftSchema.optional().describe('With stale_source: the bound file changed.'),
    }),
  ),
  counts: z.object({
    current: z.number().int().nonnegative(),
    stale: z.number().int().nonnegative(),
    contradicted: z.number().int().nonnegative(),
    retracted: z.number().int().nonnegative(),
    unknown: z.number().int().nonnegative(),
    stale_source: z.number().int().nonnegative().optional().describe('Present when any claim is stale_source.'),
  }),
});

export const RecallHitSchema = z.object({
  block_id: z.string(),
  doc_slug: z.string(),
  doc_title: z.string(),
  revision: z.number().int().positive(),
  ordinal: z.number().int().nonnegative(),
  kind: z.string(),
  heading_path: z.array(z.string()),
  content: z.string(),
  content_hash: HEX64.describe('BLAKE3 of the block content.'),
  score: z.number(),
  status: z.enum(['live', 'superseded', 'tombstoned']),
  superseded_by: z.string().nullable(),
  tombstone_reason: z.string().nullable(),
  receipt: ReceiptSchema.nullable().describe('Signed receipt v2; null when include_receipts=false.'),
  authority: z.enum(AUTHORITIES).describe('0.6.0: can_act only from block-level evidence (docs/HONESTY.md).'),
  authority_reason: z.enum(AUTHORITY_REASONS),
  authority_basis: z.enum(AUTHORITY_BASES),
  already_read: z.boolean().describe('Read by this actor this session; ranked lower, never hidden.'),
  read_scrubbed: z.array(z.string()).optional().describe('Read-time secret rules that masked part of the content.'),
  truncated: z
    .object({ shown_chars: z.number().int().nonnegative(), total_chars: z.number().int().nonnegative(), read: z.string() })
    .optional()
    .describe('Content cut to fit max_chars; `read` is the whole document. The receipt covers the whole block.'),
});

export const AbsenceSchema = z.object({
  searched: z.array(z.enum(RECALL_SCOPES)),
  not_searched: z.array(z.enum(RECALL_SCOPES)),
  index_fresh: z.boolean(),
  verdict: z.enum(ABSENCE_VERDICTS).describe('found | absent_in_searched (fresh index, nothing withheld) | cannot_certify'),
  reason: z.string(),
});

export const RecallResultSchema = z.object({
  query: z.string(),
  query_hash: HEX64,
  head: ChainHeadSchema,
  match_mode: z.enum(['all_terms', 'any_term', 'none']),
  hits: z.array(RecallHitSchema),
  withheld: z.array(
    z.object({
      block_id: z.string(),
      doc_slug: z.string(),
      problem: z.enum(ROW_PROBLEMS),
      authority: z.literal('never_act'),
      authority_reason: z.literal('integrity_failed'),
    }),
  ),
  authority_floor: z.enum(AUTHORITIES).nullable().describe('Meet of the hits\' authority; null when there are no hits.'),
  absence: AbsenceSchema,
  attention: z.object({ actor_id: z.string(), session_since: z.string(), already_read: z.number().int().nonnegative() }).nullable(),
  truncated: z.object({ hits: z.number().int().positive(), max_chars: z.number().int().positive(), hint: z.string() }).nullable(),
});

export const VerifyResultSchema = z.object({
  status: z.enum(VERIFY_STATUSES),
  reason: z.enum(VERIFY_REASONS),
  receipt_id: z.string().nullable(),
  block_id: z.string().nullable(),
  current_block_id: z.string().optional().describe('Head of the supersession lineage when it differs from the receipt block.'),
  current_content_hash: z.string().optional(),
  tombstone_reason: z.string().nullable().optional(),
  supersession_depth: z.number().int().nonnegative().optional(),
  source_drift: SourceDriftSchema.optional().describe('With STALE_SOURCE: the git-bound source file changed since binding.'),
  integrity_problem: z.enum(ROW_PROBLEMS).optional(),
  checked_at: z.string(),
  chain_head: ChainHeadSchema,
});

export const CheckpointResultSchema = z.object({
  checkpoint_id: z.string(),
  from_seq: z.number().int().positive(),
  to_seq: z.number().int().positive(),
  ok: z.boolean(),
  reason: z.enum(['valid', 'root_mismatch', 'signature_invalid', 'unknown_key', 'range_outside_verified']),
});

export const ProjectionResultSchema = z.object({
  ok: z.boolean(),
  events_replayed: z.number().int().nonnegative(),
  documents_checked: z.number().int().nonnegative(),
  revisions_checked: z.number().int().nonnegative(),
  blocks_checked: z.number().int().nonnegative(),
  mismatch_count: z.number().int().nonnegative(),
  mismatches: z.array(z.object({ table: z.string(), key: z.string(), field: z.string(), detail: z.string() })),
});

export const VerifyChainResultSchema = z.object({
  ok: z.boolean(),
  from_seq: z.number().int().nonnegative(),
  to_seq: z.number().int().nonnegative(),
  events_checked: z.number().int().nonnegative(),
  first_mismatch: z
    .object({
      seq: z.number().int(),
      kind: z.enum(['hash_mismatch', 'link_broken', 'seq_gap', 'head_mismatch']),
      expected: z.string(),
      actual: z.string(),
    })
    .nullable(),
  head: ChainHeadSchema,
  checkpoints: z.array(CheckpointResultSchema),
  projection: ProjectionResultSchema.nullable(),
});

export const CheckpointSchema = z.object({
  checkpoint_id: z.string(),
  from_seq: z.number().int().positive(),
  to_seq: z.number().int().nonnegative(),
  leaf_count: z.number().int().nonnegative(),
  root: HEX64.describe('Merkle root over event hashes in range.'),
  key_id: z.string(),
  signature: z.string().describe('Ed25519 signature, base64.'),
  created_at: z.string(),
  anchor: z
    .object({
      ok: z.boolean().describe('true when the service countersigned and the receipt verified.'),
      anchor_id: z.string().nullable(),
      duplicate: z.boolean().nullable().describe('Same checkpoint was anchored before; the original receipt is returned.'),
      conflict: z.boolean().nullable().describe('This range was anchored earlier with a different root: the chain was rewritten.'),
      conflicting_anchor_ids: z.array(z.string()),
      received_at: z.string().nullable(),
      verify_url: z.string().nullable(),
      public_status: z.string().nullable(),
      error: z
        .enum(['anchor_unreachable', 'anchor_refused', 'anchor_config', 'anchor_failed'])
        .nullable()
        .describe('Why the push did not complete. The local checkpoint is stored either way.'),
      message: z.string().nullable(),
    })
    .optional()
    .describe('Present when push=true: the hosted anchor outcome.'),
});

const RANGE_RESULTS = ['match', 'diverged', 'beyond_head', 'gap'] as const;

export const AnchorStatusResultSchema = z.object({
  chain_id: HEX64.describe('sha256 of the signing key SPKI DER; the service keys the chain by it.'),
  key_id: z.string(),
  head_seq: z.number().int().nonnegative(),
  anchor_url: z.string(),
  license_key_configured: z.boolean(),
  anchors: z.number().int().nonnegative().describe('Anchor receipts stored locally.'),
  last: z
    .object({
      anchor_id: z.string(),
      range: z.tuple([z.number().int(), z.number().int()]),
      root: HEX64,
      received_at: z.string(),
      status: z.string(),
      verify_url: z.string(),
      events_since: z.number().int().nonnegative(),
    })
    .nullable(),
  verification: z.object({
    result: z.enum([...RANGE_RESULTS, 'none']).describe('Local root over the last anchored range vs the anchored root.'),
    countersignature: z.enum(['ok', 'failed', 'unchecked']),
    remote: z.enum(['checked', 'skipped', 'unreachable']),
    remote_conflict: z.boolean().nullable(),
    detail: z.string().nullable(),
  }),
});

export const SecretFindingSchema = z.object({ field: z.string(), detector: z.string(), line: z.number().int().positive() });

export const BlockSummarySchema = z.object({
  block_id: z.string(),
  ordinal: z.number().int().nonnegative(),
  kind: z.enum(['heading', 'paragraph', 'code']),
  heading_path: z.array(z.string()),
  content_hash: HEX64,
  status: z.enum(['created', 'unchanged', 'superseded', 'tombstoned']),
  supersedes: z.string().optional().describe('The block this one replaced, when status=superseded.'),
});

export const DocumentSourceSchema = z
  .object({
    kind: z.string().describe('instruction | memory | file'),
    path: z.string(),
    git: z
      .object({
        repo_root: z.string(),
        commit: z.string().nullable().describe('HEAD at put time; null in a repository without commits.'),
        path: z.string().describe('Path inside repo_root, /-separated.'),
        blob_sha: z.string().describe('git hash-object of the file at put time.'),
      })
      .optional(),
  })
  .describe('Provenance recorded in the document.put event.');

export const PutDocumentResultSchema = z.object({
  doc_id: z.string(),
  slug: z.string(),
  title: z.string(),
  revision: z.number().int().positive(),
  chain_seq: z.number().int().positive().describe('seq of the document.put event.'),
  head: ChainHeadSchema,
  blocks: z.array(BlockSummarySchema),
  events: z.number().int().nonnegative().describe('Events appended by this call (0 on idempotent replay).'),
  source: DocumentSourceSchema.optional(),
  warnings: z.array(z.string()).optional().describe('Non-fatal notes, e.g. bind_git outside a git repository.'),
  redactions: z.array(SecretFindingSchema).optional().describe('0.6.0: secrets replaced before chaining (redact_secrets).'),
  stale_write_advisory: StaleWriteAdvisorySchema,
});

export const SupersedeBlockResultSchema = z.object({
  old_block_id: z.string(),
  new_block_id: z.string(),
  content_hash: HEX64,
  doc_slug: z.string(),
  revision: z.number().int().positive(),
  head: ChainHeadSchema,
  redactions: z.array(SecretFindingSchema).optional().describe('0.6.0: secrets replaced before chaining (redact_secrets).'),
  stale_write_advisory: StaleWriteAdvisorySchema,
});

export const TombstoneBlockResultSchema = z.object({
  block_id: z.string(),
  doc_slug: z.string(),
  revision: z.number().int().positive(),
  head: ChainHeadSchema,
  stale_write_advisory: StaleWriteAdvisorySchema,
});
