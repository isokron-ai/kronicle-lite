/**
 * MCP server surface (spec 2026-07-28, TypeScript SDK v2).
 *
 * Tools are registered with zod input AND output schemas; every result
 * carries `structuredContent` (validated against `outputSchema` by the SDK)
 * plus the same JSON as a text block for clients that only read text. Every
 * write tool accepts an optional `cursor` and returns the new chain head plus
 * a stale-write advisory. Nothing here blocks a write: the advisory is text.
 *
 * `createServer` builds one McpServer instance. `createServerFactory` wraps it
 * as the per-connection / per-request factory the SDK's serving entries
 * (`serveStdio`, `createMcpHandler`) call; the store is shared, the MCP
 * instance is cheap and stateless (spec: "Statelessness").
 */

import { McpServer, ResourceTemplate, type McpServerFactory } from '@modelcontextprotocol/server';
import { z } from 'zod';

import { anchorStatus, tryPushCheckpoint, verifyLastAnchor } from './anchor/anchor.js';
import { ChainConflictError } from './chain/index.js';
import { bindGit } from './git/binding.js';
import type { DocumentSource } from './docs/documents.js';
import { DocumentError } from './docs/documents.js';
import { checkRevisionRow } from './docs/integrity.js';
import { FOCUSES, type ProjectScope } from './orient/orient.js';
import { renderSystemStateMarkdown } from './orient/render.js';
import {
  lean,
  fullJsonSchema,
  AnchorStatusResultSchema,
  AuditSummarySchema,
  CheckpointSchema,
  PutDocumentResultSchema,
  RecallResultSchema,
  SupersedeBlockResultSchema,
  SystemStateSchema,
  TombstoneBlockResultSchema,
  VerifyChainResultSchema,
  VerifyResultSchema,
} from './schemas.js';
import { scrubDeep, SecretDetectedError } from './secrets/guard.js';
import type { KronicleLite } from './store.js';
import { VERSION } from './version.js';

export interface ServerOptions {
  /** Actor id used when a tool call does not pass one. */
  defaultActorId?: string;
  version?: string;
  /**
   * 0.5.0: project scope for get_system_state (instruction retractions from
   * other projects are hidden). The CLI passes the scope of its working
   * directory; embedders pass their own or leave it unscoped.
   */
  project?: ProjectScope | null;
  /**
   * 0.6.0: `core` serves only CORE_TOOLS (≤ 6) for small context windows;
   * `full` (default) serves every tool.
   */
  profile?: 'full' | 'core';
}

/** 0.6.0: the `--core` profile: orient, grade, search, check a receipt, write, fix one block. */
export const CORE_TOOLS = ['get_system_state', 'audit_assumptions', 'recall', 'verify', 'put_document', 'supersede_block'] as const;

/**
 * Server instructions. Codex reads only the first 512 characters, so the
 * whole orient loop has to fit there; keep this under 512 (guarded by test).
 */
export const INSTRUCTIONS =
  'kronicle-lite: hash-chained document store with signed receipts and an orient protocol. ' +
  'Call get_system_state at session start, before writes and before world-changing commands (deploy, migrate, publish, git push), ' +
  'passing your previous cursor as since_cursor; honor the drift banner and reconcile retractions before acting. ' +
  'recall() returns blocks with receipts; verify() re-checks one against the live chain. Carry the returned cursor forward. ' +
  'The chain is authority over your own memory.';

/** Cache hints for the 2026-07-28 cacheable results. */
export const CACHE_HINTS = {
  // The catalog is identical for every caller and only changes with a release.
  'tools/list': { ttlMs: 3_600_000, cacheScope: 'public' },
  'server/discover': { ttlMs: 3_600_000, cacheScope: 'public' },
  // Document lists and bodies change with every write and are private to the data dir.
  'resources/list': { ttlMs: 0, cacheScope: 'private' },
  'resources/templates/list': { ttlMs: 3_600_000, cacheScope: 'public' },
  'resources/read': { ttlMs: 0, cacheScope: 'private' },
} as const;

const ACTOR = z.string().min(1).max(200).optional().describe('Your agent id (default: server --actor). Cursors are bound to it.');

const CURSOR = z.string().optional().describe('Your latest cursor (for the stale-write advisory).');

const REDACT = z.boolean().default(false).describe('Store a redacted copy instead of refusing a detected secret.');

/**
 * Unreleased: explicit lineage (full profile only; `--core` stays lean and
 * relies on inference from what you read this session).
 */
const DERIVED_FROM = z
  .array(z.strictObject({ block_id: z.uuid(), content_hash: z.string().regex(/^[0-9a-f]{64}$/) }))
  .max(200)
  .optional()
  .describe('Blocks (from recall) this text was derived from; when one changes, this note is marked stale. Inferred from your reads when omitted.');

type ToolResult = {
  content: { type: 'text'; text: string }[];
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
};

/**
 * Unreleased (next): MCP recall's default content budget (characters). The
 * library default stays DEFAULT_MAX_CHARS (16000); agents ask for more.
 */
export const DEFAULT_MCP_MAX_CHARS = 4000;

/** Structured result: the value as structuredContent and, for text-only clients, as JSON (pretty unless compact). */
function json(value: object, opts: { compact?: boolean } = {}): ToolResult {
  return {
    content: [{ type: 'text', text: opts.compact ? JSON.stringify(value) : JSON.stringify(value, null, 2) }],
    structuredContent: value as Record<string, unknown>,
  };
}

function errorResult(err: unknown): ToolResult {
  if (err instanceof SecretDetectedError) {
    // Findings name the detector and line only; the secret is never echoed.
    return { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: err.code, message: err.message, findings: err.findings }) }] };
  }
  if (err instanceof DocumentError) {
    return { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: err.code, message: err.message }) }] };
  }
  if (err instanceof ChainConflictError) {
    return {
      isError: true,
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            error: 'chain_conflict',
            message: err.message,
            expected_prev_hash: err.expected_prev_hash,
            actual_head_hash: err.actual_head_hash,
          }),
        },
      ],
    };
  }
  const message = err instanceof Error ? err.message : String(err);
  return { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: 'internal', message }) }] };
}

/** The optional `derived_from` argument (absent from the core profile's schema). */
function derivedFrom(args: object): { block_id: string; content_hash: string }[] | undefined {
  const v = (args as { derived_from?: unknown }).derived_from;
  return Array.isArray(v) ? (v as { block_id: string; content_hash: string }[]) : undefined;
}

/** Factory form for the SDK serving entries: one fresh McpServer per connection (stdio) or request (HTTP). */
export function createServerFactory(store: KronicleLite, opts: ServerOptions = {}): McpServerFactory {
  return () => createServer(store, opts);
}

export function createServer(store: KronicleLite, opts: ServerOptions = {}): McpServer {
  const defaultActor = opts.defaultActorId ?? process.env['KRONICLE_LITE_ACTOR'] ?? 'local-agent';
  const server = new McpServer(
    { name: 'kronicle-lite', title: 'kronicle-lite', version: opts.version ?? VERSION, websiteUrl: 'https://github.com/rafe-walker/kronicle-lite' },
    {
      instructions: INSTRUCTIONS,
      cacheHints: CACHE_HINTS,
      capabilities: { tools: {}, resources: {} },
    },
  );

  const actorOf = (a: string | undefined) => a ?? defaultActor;
  // 0.6.0: the core profile registers only CORE_TOOLS.
  const core = opts.profile === 'core';
  const register = server.registerTool.bind(server);
  const registerTool = ((name: string, ...rest: unknown[]) =>
    core && !(CORE_TOOLS as readonly string[]).includes(name)
      ? undefined
      : (register as (...a: unknown[]) => unknown)(name, ...rest)) as typeof server.registerTool;

  // ───────────────────────────── orient ─────────────────────────────

  registerTool(
    'get_system_state',
    {
      title: 'Orient against the chain',
      description:
        'Orient. Call at session start and before writes with your last cursor as since_cursor. Returns what changed since ' +
        '(delta), a drift banner, and retractions: things you relied on that changed, with old → new text. Reconcile ' +
        'retractions before acting. A bad or missing cursor never fails. focus: orientation (default) | recent_changes | ' +
        'retractions | pulse (head + banner only). Carry the returned cursor forward.',
      inputSchema: lean(
        z.object({
          budget_tokens: z.number().int().min(200).max(64_000).default(3000),
          since_cursor: z.string().optional().describe('cursor or cursor_compact from your last call'),
          focus: z.enum(FOCUSES).default('orientation'),
          response_format: z.enum(['markdown', 'json']).default('markdown'),
          all_projects: z.boolean().default(false).describe('Include other projects\' documents and retractions.'),
          include_format_only: z.boolean().default(false).describe('Also list format-only edits (identical raw text up to whitespace and reflow) as retractions.'),
          include_cosmetic: z.boolean().default(false).describe('Deprecated alias of include_format_only.'),
          actor_id: ACTOR,
        }),
        'input',
      ),
      outputSchema: lean(SystemStateSchema, 'output'),
      annotations: { readOnlyHint: true, idempotentHint: false, openWorldHint: false },
    },
    (args) => {
      try {
        const state = store.orient.getSystemState({
          actor_id: actorOf(args.actor_id),
          budget_tokens: args.budget_tokens,
          since_cursor: args.since_cursor,
          focus: args.focus,
          project: args.all_projects ? null : (opts.project ?? null),
          include_format_only: args.include_format_only || args.include_cosmetic,
        });
        if (args.response_format === 'json') return json(state);
        return {
          content: [{ type: 'text', text: renderSystemStateMarkdown(state) }],
          structuredContent: state as unknown as Record<string, unknown>,
        };
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  registerTool(
    'audit_assumptions',
    {
      title: 'Grade beliefs against the chain',
      description:
        'Grade facts before acting on them. claims: [{symbol, value}]; symbol is a block id (value: content or ' +
        'content_hash), a document slug (value: revision, markdown hash or markdown) or "head" (value: seq or hash). ' +
        'Verdict per claim: current | stale | contradicted | retracted | unknown | stale_source, with the current truth.',
      inputSchema: lean(
        z.object({
          claims: z
            .array(z.strictObject({ symbol: z.string().min(1).max(300), value: z.union([z.string().max(200_000), z.number()]) }))
            .min(1)
            .max(100),
        }),
        'input',
      ),
      outputSchema: lean(AuditSummarySchema, 'output'),
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    },
    (args) => json(scrubDeep(store.auditor.audit(args.claims)).value),
  );

  // ───────────────────────────── recall / verify ─────────────────────────────

  registerTool(
    'recall',
    {
      title: 'Search blocks with signed receipts',
      description:
        'Full-text search over live blocks. Each hit carries a signed receipt (pass it to verify() before relying on it later) ' +
        'and authority: can_act | inspect_only | never_act with a reason; only can_act is safe to act on unchecked. absence says what was and was not ' +
        'searched: an empty result is not proof of absence unless verdict is absent_in_searched. Pass cursor: hits you already ' +
        'read this session rank lower.',
      inputSchema: lean(
        z.object({
          query: z.string().min(1).max(2000),
          top_k: z.number().int().min(1).max(50).default(12),
          include_tombstoned: z.boolean().default(false),
          include_receipts: z.boolean().default(true),
          receipts: z.enum(['id', 'inline']).default('id').describe('id: receipt_id per hit (verify takes it); inline: the signed receipt.'),
          max_chars: z.number().int().min(200).max(400_000).default(DEFAULT_MCP_MAX_CHARS).describe('Content budget; longer hits are cut with a pointer.'),
          all_projects: z.boolean().default(false).describe('Search other projects\' documents too.'),
          cursor: CURSOR,
          actor_id: ACTOR,
        }),
        'input',
      ),
      outputSchema: lean(RecallResultSchema, 'output'),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    (args) => {
      try {
        const actor_id = actorOf(args.actor_id);
        return json(
          store.recall.recall({
            query: args.query,
            top_k: args.top_k,
            include_tombstoned: args.include_tombstoned,
            include_receipts: args.include_receipts,
            receipt_format: args.receipts,
            max_chars: args.max_chars,
            actor_id,
            session_since: store.orient.sessionStart(actor_id, args.cursor),
            project_keys: args.all_projects ? null : (opts.project?.keys ?? null),
          }),
          { compact: true },
        );
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  registerTool(
    'verify',
    {
      title: 'Verify a retrieval receipt',
      description:
        'Re-check a recall() receipt (object or receipt_id) against the store (signature, re-hashed block text, chain position, supersession): ' +
        'VERIFIED | SUPERSEDED (see current_block_id) | TOMBSTONED | STALE_SOURCE | UNVERIFIED, with a reason. Fail-closed.',
      inputSchema: lean(
        z.object({
          receipt: z.record(z.string(), z.unknown()).optional().describe('The receipt object from recall().'),
          receipt_id: z.string().min(1).max(100).optional().describe('Or the receipt_id from recall().'),
        }),
        'input',
      ),
      outputSchema: lean(VerifyResultSchema, 'output'),
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    },
    (args) => json(store.verifier.verify(args.receipt ?? (args.receipt_id !== undefined ? store.recall.getReceipt(args.receipt_id) : null))),
  );

  registerTool(
    'verify_chain',
    {
      title: 'Verify chain integrity',
      description:
        'Recompute every event hash and link in [from_seq, to_seq] and check stored checkpoints. Over the whole chain ' +
        '(the default) it also re-derives and re-hashes every stored document and block (projection). ok:false means the ' +
        'database was edited outside kronicle-lite or is corrupt.',
      inputSchema: lean(z.object({ from_seq: z.number().int().min(1).default(1), to_seq: z.number().int().min(1).optional() }), 'input'),
      outputSchema: lean(VerifyChainResultSchema, 'output'),
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    },
    (args) => json(store.verifyAll(args.from_seq, args.to_seq)),
  );

  registerTool(
    'checkpoint_chain',
    {
      title: 'Sign a Merkle checkpoint',
      description:
        'Sign and store a Merkle root over event hashes in [from_seq, to_seq] (default: all). push:true also anchors it ' +
        'off-box (root, range, signature and public key leave the machine; the local checkpoint is kept either way).',
      inputSchema: lean(
        z.object({
          from_seq: z.number().int().min(1).default(1),
          to_seq: z.number().int().min(1).optional(),
          push: z.boolean().default(false),
        }),
        'input',
      ),
      outputSchema: lean(CheckpointSchema, 'output'),
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    },
    async (args) => {
      try {
        const cp = store.chain.checkpoint(args.from_seq, args.to_seq);
        if (!args.push) return json(cp);
        const anchor = await tryPushCheckpoint(store, { checkpointId: cp.checkpoint_id });
        return json({ ...cp, anchor });
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  registerTool(
    'anchor_status',
    {
      title: 'Hosted anchor status',
      description:
        'Last off-box anchor and whether the local chain still matches it: match | diverged (rewritten after anchoring) | ' +
        'beyond_head | gap | unverified (receipt not trusted). remote:true also asks the anchor service.',
      inputSchema: lean(z.object({ remote: z.boolean().default(false) }), 'input'),
      outputSchema: lean(AnchorStatusResultSchema, 'output'),
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    },
    async (args) => {
      try {
        const status = anchorStatus(store);
        const verification = await verifyLastAnchor(store, { remote: args.remote });
        return json({ ...status, verification });
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  // ───────────────────────────── writes ─────────────────────────────

  registerTool(
    'put_document',
    {
      title: 'Create or replace a document',
      description:
        'Create or re-put a Markdown document by slug. Unchanged blocks keep their ids; changed blocks are superseded and ' +
        'removed ones tombstoned, which other agents see as retractions. bind_git with source_path ties the document to ' +
        'that file\'s git blob (verify reports STALE_SOURCE when the file changes). Refuses text holding a secret (API key, ' +
        'token, private key, connection string): the chain cannot forget it.',
      inputSchema: lean(
        z.object({
          slug: z.string().regex(/^[a-z0-9][a-z0-9._-]{0,127}$/),
          title: z.string().min(1).max(300),
          markdown: z.string().max(2_000_000),
          idempotency_key: z.string().min(1).max(200).optional(),
          source_path: z.string().min(1).max(4096).optional().describe('File the markdown came from.'),
          bind_git: z.boolean().default(false),
          redact_secrets: REDACT,
          ...(core ? {} : { derived_from: DERIVED_FROM }),
          cursor: CURSOR,
          actor_id: ACTOR,
        }),
        'input',
      ),
      outputSchema: lean(PutDocumentResultSchema, 'output'),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    (args) => {
      try {
        const actor_id = actorOf(args.actor_id);
        const stale_write_advisory = store.orient.staleWriteAdvisory(actor_id, args.cursor);
        if (args.bind_git && !args.source_path) {
          return errorResult(new DocumentError('invalid_source', 'bind_git requires source_path'));
        }
        const warnings: string[] = [];
        let source: DocumentSource | undefined;
        if (args.source_path !== undefined) {
          source = { kind: 'file', path: args.source_path.split(/[\\/]+/).join('/') };
          if (args.bind_git) {
            const b = bindGit(args.source_path);
            if (b.binding) source = { kind: 'file', path: b.binding.path, git: b.binding };
            if (b.warning) warnings.push(b.warning);
          }
        }
        const result = store.docs.putDocument({
          slug: args.slug,
          title: args.title,
          markdown: args.markdown,
          actor_id,
          ...(args.idempotency_key !== undefined ? { idempotency_key: args.idempotency_key } : {}),
          ...(source !== undefined ? { source } : {}),
          ...(args.redact_secrets ? { secrets: 'redact' as const } : {}),
          ...(opts.project && opts.project.keys.length > 0 ? { project: { key: opts.project.keys[0]!, root: opts.project.root ?? '' } } : {}),
          ...(derivedFrom(args) !== undefined ? { derived_from: derivedFrom(args)! } : {}),
          ...(args.cursor !== undefined ? { cursor: args.cursor } : {}),
        });
        return json({
          ...result,
          ...(source !== undefined ? { source } : {}),
          ...(warnings.length > 0 ? { warnings } : {}),
          stale_write_advisory,
        });
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  registerTool(
    'supersede_block',
    {
      title: 'Replace one block',
      description: 'Replace one live block\'s content, with a reason. Receipts for the old block then verify as SUPERSEDED.',
      inputSchema: lean(
        z.object({
          block_id: z.uuid(),
          new_content: z.string().min(1).max(200_000),
          reason: z.string().min(1).max(1000),
          redact_secrets: REDACT,
          ...(core ? {} : { derived_from: DERIVED_FROM }),
          cursor: CURSOR,
          actor_id: ACTOR,
        }),
        'input',
      ),
      outputSchema: lean(SupersedeBlockResultSchema, 'output'),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    (args) => {
      try {
        const actor_id = actorOf(args.actor_id);
        const stale_write_advisory = store.orient.staleWriteAdvisory(actor_id, args.cursor);
        const result = store.docs.supersedeBlock({
          block_id: args.block_id,
          new_content: args.new_content,
          reason: args.reason,
          actor_id,
          ...(args.redact_secrets ? { secrets: 'redact' as const } : {}),
          ...(derivedFrom(args) !== undefined ? { derived_from: derivedFrom(args)! } : {}),
          ...(args.cursor !== undefined ? { cursor: args.cursor } : {}),
        });
        return json({ ...result, stale_write_advisory });
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  registerTool(
    'tombstone_block',
    {
      title: 'Retire one block',
      description: 'Retire one live block with a reason (no successor). Receipts for it then verify as TOMBSTONED.',
      inputSchema: lean(z.object({ block_id: z.uuid(), reason: z.string().min(1).max(1000), cursor: CURSOR, actor_id: ACTOR }), 'input'),
      outputSchema: lean(TombstoneBlockResultSchema, 'output'),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
    },
    (args) => {
      try {
        const actor_id = actorOf(args.actor_id);
        const stale_write_advisory = store.orient.staleWriteAdvisory(actor_id, args.cursor);
        const result = store.docs.tombstoneBlock({ block_id: args.block_id, reason: args.reason, actor_id });
        return json({ ...result, stale_write_advisory });
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  // ───────────────────────────── resources ─────────────────────────────

  server.registerResource(
    'document',
    new ResourceTemplate('kronicle://docs/{slug}', {
      list: () => ({
        resources: store.docs.listDocuments(200).map((d) => ({
          // Namespaced slugs (instructions/claude-md) are percent-encoded so
          // they match the single-segment {slug} template; flat slugs are unchanged.
          uri: `kronicle://docs/${encodeURIComponent(d.slug)}`,
          name: d.slug,
          title: d.title,
          description: `revision ${d.current_revision}, updated ${d.updated_at}`,
          mimeType: 'text/markdown',
        })),
      }),
    }),
    {
      title: 'Documents',
      description: 'Current revision of a stored document as Markdown.',
      mimeType: 'text/markdown',
      cacheHint: CACHE_HINTS['resources/read'],
    },
    (uri, vars) => {
      const raw = String(vars['slug']);
      let slug: string;
      try {
        slug = decodeURIComponent(raw);
      } catch {
        slug = raw;
      }
      const doc = store.docs.getDocument(slug);
      if (!doc) throw new Error(`no document ${slug}`);
      const rev = store.docs.getRevision(doc.doc_id, doc.current_revision);
      if (!rev) throw new Error(`no revision ${doc.current_revision} of ${slug}`);
      // 0.5.0: never serve text that does not hash to the chain.
      const problem = checkRevisionRow(store.chain, rev);
      if (problem) throw new Error(`integrity failure (${problem}) in ${slug}@${rev.revision}: the stored text does not match the chain; run kronicle-lite verify-chain`);
      // 0.6.0: read-time secret scrub (independent of the write-time guard).
      const markdown = scrubDeep(rev.markdown).value;
      // Unreleased: a document read is a read of its current version (pending reconciliation).
      store.lineage.recordDocumentRead(defaultActor, doc.doc_id, 'document');
      return { contents: [{ uri: uri.href, mimeType: 'text/markdown', text: markdown }] };
    },
  );

  // 0.5.0: tools/list advertises compact output schemas; the full ones live here.
  server.registerResource(
    'tool-schemas',
    'kronicle://schemas/tools',
    {
      title: 'Tool output schemas',
      description: 'Full JSON Schema of every tool result (tools/list carries a compact form).',
      mimeType: 'application/json',
      cacheHint: CACHE_HINTS['resources/templates/list'],
    },
    (uri) => ({ contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(fullOutputSchemas(), null, 2) }] }),
  );

  return server;
}

const OUTPUT_SCHEMAS = {
  get_system_state: SystemStateSchema,
  audit_assumptions: AuditSummarySchema,
  recall: RecallResultSchema,
  verify: VerifyResultSchema,
  verify_chain: VerifyChainResultSchema,
  checkpoint_chain: CheckpointSchema,
  anchor_status: AnchorStatusResultSchema,
  put_document: PutDocumentResultSchema,
  supersede_block: SupersedeBlockResultSchema,
  tombstone_block: TombstoneBlockResultSchema,
} as const;

/** Every tool's full output JSON Schema, by tool name. */
export function fullOutputSchemas(): Record<string, unknown> {
  return Object.fromEntries(Object.entries(OUTPUT_SCHEMAS).map(([k, v]) => [k, fullJsonSchema(v, 'output')]));
}

// Markdown rendering lives in orient/render.ts (no MCP SDK import, so the CLI's
// `orient` path stays cheap); re-exported here for compatibility.
export { anchorLine, isQuietBriefing, renderSystemStateMarkdown } from './orient/render.js';
