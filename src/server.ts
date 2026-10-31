/**
 * MCP server surface. Tools are registered with zod shapes; every write
 * tool accepts an optional `cursor` and returns the new chain head plus a
 * stale-write advisory. Nothing here blocks a write: the advisory is text.
 */

import { McpServer, ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { ChainConflictError } from './chain/index.js';
import { DocumentError } from './docs/documents.js';
import { FOCUSES, type SystemState } from './orient/orient.js';
import type { KronicleLite } from './store.js';

export interface ServerOptions {
  /** Actor id used when a tool call does not pass one. */
  defaultActorId?: string;
  version?: string;
}

const ACTOR = z
  .string()
  .min(1)
  .max(200)
  .optional()
  .describe('Stable identity of the calling agent. Defaults to the server --actor setting. Cursors are bound to it.');

const CURSOR = z
  .string()
  .optional()
  .describe('Your most recent cursor from get_system_state (full or compact). Used only to compute the stale-write advisory.');

type ToolText = { content: { type: 'text'; text: string }[]; isError?: boolean };

function json(value: unknown): ToolText {
  return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] };
}

function text(s: string): ToolText {
  return { content: [{ type: 'text', text: s }] };
}

function errorResult(err: unknown): ToolText {
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

export function createServer(store: KronicleLite, opts: ServerOptions = {}): McpServer {
  const defaultActor = opts.defaultActorId ?? process.env['KRONICLE_LITE_ACTOR'] ?? 'local-agent';
  const server = new McpServer(
    { name: 'kronicle-lite', version: opts.version ?? '0.1.0' },
    {
      instructions:
        'kronicle-lite is a hash-chained document store with signed retrieval receipts and an orient protocol. ' +
        'Call get_system_state at session start and before writes, passing your previous cursor as since_cursor. ' +
        'Honor the drift banner and reconcile retractions before acting. recall() returns blocks with receipts; ' +
        'verify() re-checks a receipt against the live chain. Treat the chain as authority over your own memory.',
    },
  );

  const actorOf = (a: string | undefined) => a ?? defaultActor;

  // ───────────────────────────── orient ─────────────────────────────

  server.registerTool(
    'get_system_state',
    {
      title: 'Orient against the chain',
      description:
        'Orient call — INSTRUCTS the agent. Call at session start AND before any write-class work. Present your previous ' +
        '`cursor` (or `cursor_compact`) as `since_cursor` to get a true delta: cold start receives the digest plus everything; ' +
        'warm wake receives only what changed since your cursor. Honor the drift banner: when it is surfaced, your memory of ' +
        'this store is stale and the delta is the catch-up. When retractions are reported, reconcile BEFORE acting — affirm ' +
        'the current truth (cite seq), name the old claim once, stop using it as a premise. An invalid or missing cursor never ' +
        'fails: position is recovered from the flight recorder or genesis, and the response says which. Focuses: ' +
        'orientation (default: digest + delta + retractions) | recent_changes (delta + retractions) | retractions (only ' +
        'retractions) | pulse (head + drift banner, ~50 tokens; call this before every write and only pay for a full delta ' +
        'when the banner surfaces). response_format markdown (default) or json. Always carry the returned cursor forward.',
      inputSchema: {
        budget_tokens: z.number().int().min(200).max(64_000).default(3000).describe('Approximate token budget for the delta.'),
        since_cursor: z.string().optional().describe('Cursor from your previous call (sxt1. or sxt1c. form).'),
        focus: z.enum(FOCUSES).default('orientation'),
        response_format: z.enum(['markdown', 'json']).default('markdown'),
        actor_id: ACTOR,
      },
      annotations: { readOnlyHint: true, idempotentHint: false, openWorldHint: false },
    },
    (args) => {
      try {
        const state = store.orient.getSystemState({
          actor_id: actorOf(args.actor_id),
          budget_tokens: args.budget_tokens,
          since_cursor: args.since_cursor,
          focus: args.focus,
        });
        return args.response_format === 'json' ? json(state) : text(renderSystemStateMarkdown(state));
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    'audit_assumptions',
    {
      title: 'Grade beliefs against the chain',
      description:
        'The reconciliation surface. Pass the facts you are about to act on as claims {symbol, value}: symbol is a block ' +
        'id (value = its content or content_hash), a document slug (value = revision number, markdown hash, or markdown), ' +
        'or "head" (value = chain seq or hash). Each claim is graded current | stale (a newer version exists) | ' +
        'contradicted (the live value differs) | retracted (tombstoned) | unknown, with the current truth and a reconcile ' +
        'line. Use it after a drift banner or retraction list, before writing.',
      inputSchema: {
        claims: z
          .array(z.object({ symbol: z.string().min(1).max(300), value: z.union([z.string().max(200_000), z.number()]) }).strict())
          .min(1)
          .max(100),
      },
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    },
    (args) => json(store.auditor.audit(args.claims)),
  );

  // ───────────────────────────── recall / verify ─────────────────────────────

  server.registerTool(
    'recall',
    {
      title: 'Search blocks with signed receipts',
      description:
        'Full-text search (bm25) over live document blocks. Each hit carries a signed receipt v2 binding (block_id, ' +
        'content_hash, doc_slug, revision) to the chain head at issue time. Keep the receipt with any claim you derive from ' +
        'the block; pass it to verify() later to learn whether the block is still current (VERIFIED), was replaced ' +
        '(SUPERSEDED, with the current head), was retired (TOMBSTONED), or cannot be trusted (UNVERIFIED). Superseded ' +
        'blocks are never returned; tombstoned only with include_tombstoned. Set include_receipts:false for a lean result.',
      inputSchema: {
        query: z.string().min(1).max(2000),
        top_k: z.number().int().min(1).max(50).default(12),
        include_tombstoned: z.boolean().default(false),
        include_receipts: z.boolean().default(true),
      },
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    (args) => {
      try {
        return json(store.recall.recall(args));
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    'verify',
    {
      title: 'Verify a retrieval receipt',
      description:
        'Re-derive a receipt against the live store. Fail-closed. Checks the Ed25519 signature (local key registry), block ' +
        'existence, content hash, that the receipt\'s chain position is still on the chain, and walks supersession to the ' +
        'current head. Returns VERIFIED | SUPERSEDED (with current_block_id/current_content_hash) | TOMBSTONED | UNVERIFIED ' +
        'with a closed-enum reason. Malformed input yields UNVERIFIED/malformed_receipt, never a tool error.',
      inputSchema: {
        receipt: z.record(z.string(), z.unknown()).describe('The full receipt object from recall(), including signature.'),
      },
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    },
    (args) => json(store.verifier.verify(args.receipt)),
  );

  server.registerTool(
    'verify_chain',
    {
      title: 'Verify chain integrity',
      description:
        'Recompute every event hash and link in [from_seq, to_seq] (default: whole chain), report the first mismatch if ' +
        'any, and validate every stored signed checkpoint in range. ok:false means the database was altered outside the ' +
        'append path or is corrupt; the first_mismatch seq tells you where.',
      inputSchema: {
        from_seq: z.number().int().min(1).default(1),
        to_seq: z.number().int().min(1).optional(),
      },
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    },
    (args) => json(store.chain.verify(args.from_seq, args.to_seq)),
  );

  server.registerTool(
    'checkpoint_chain',
    {
      title: 'Sign a Merkle checkpoint',
      description:
        'Compute a Merkle root over event hashes in [from_seq, to_seq] (default: 1..head), sign it with the server key, and ' +
        'store it. verify_chain checks checkpoints; export them off-box if you want a record that survives local tampering.',
      inputSchema: {
        from_seq: z.number().int().min(1).default(1),
        to_seq: z.number().int().min(1).optional(),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    (args) => {
      try {
        return json(store.chain.checkpoint(args.from_seq, args.to_seq));
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  // ───────────────────────────── writes ─────────────────────────────

  server.registerTool(
    'put_document',
    {
      title: 'Create or replace a document',
      description:
        'Store a Markdown document under a slug. A new slug creates revision 1; an existing slug creates the next revision: ' +
        'unchanged blocks keep their ids, changed blocks are superseded (old → new), removed blocks are tombstoned. Emits ' +
        'document.put + block.* events and returns every block id with its BLAKE3 content hash and the new chain head. ' +
        'Pass your cursor so the response can tell you if you are writing on stale assumptions (advisory only).',
      inputSchema: {
        slug: z.string().regex(/^[a-z0-9][a-z0-9._-]{0,127}$/).describe('lowercase letters, digits, . _ -'),
        title: z.string().min(1).max(300),
        markdown: z.string().max(2_000_000),
        idempotency_key: z.string().min(1).max(200).optional().describe('Replay-safe key; repeating it returns the first result.'),
        cursor: CURSOR,
        actor_id: ACTOR,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    (args) => {
      try {
        const actor_id = actorOf(args.actor_id);
        const stale_write_advisory = store.orient.staleWriteAdvisory(actor_id, args.cursor);
        const result = store.docs.putDocument({
          slug: args.slug,
          title: args.title,
          markdown: args.markdown,
          actor_id,
          ...(args.idempotency_key !== undefined ? { idempotency_key: args.idempotency_key } : {}),
        });
        return json({ ...result, stale_write_advisory });
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    'supersede_block',
    {
      title: 'Replace one block',
      description:
        'Replace a live block\'s content with a new block (old → new supersession, with a reason). Receipts issued for the old ' +
        'block will verify as SUPERSEDED pointing at the new one. The document gets a new revision. Refused if the block is ' +
        'already superseded or tombstoned (operate on the current head instead).',
      inputSchema: {
        block_id: z.string().uuid(),
        new_content: z.string().min(1).max(200_000),
        reason: z.string().min(1).max(1000),
        cursor: CURSOR,
        actor_id: ACTOR,
      },
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
        });
        return json({ ...result, stale_write_advisory });
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    'tombstone_block',
    {
      title: 'Retire one block',
      description:
        'Mark a live block as no longer valid, with a reason, and no successor. It leaves recall() results (unless ' +
        'include_tombstoned) and receipts for it verify as TOMBSTONED. The document gets a new revision.',
      inputSchema: {
        block_id: z.string().uuid(),
        reason: z.string().min(1).max(1000),
        cursor: CURSOR,
        actor_id: ACTOR,
      },
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
          uri: `kronicle://docs/${d.slug}`,
          name: d.slug,
          title: d.title,
          description: `revision ${d.current_revision}, updated ${d.updated_at}`,
          mimeType: 'text/markdown',
        })),
      }),
    }),
    { title: 'Documents', description: 'Current revision of a stored document as Markdown.', mimeType: 'text/markdown' },
    (uri, vars) => {
      const slug = String(vars['slug']);
      const doc = store.docs.getDocument(slug);
      if (!doc) throw new Error(`no document ${slug}`);
      const markdown = store.docs.getRevisionMarkdown(doc.doc_id, doc.current_revision) ?? '';
      return { contents: [{ uri: uri.href, mimeType: 'text/markdown', text: markdown }] };
    },
  );

  return server;
}

// ───────────────────────────── markdown rendering ─────────────────────────────

export function renderSystemStateMarkdown(s: SystemState): string {
  const lines: string[] = [];
  const shortHash = s.head.hash.slice(0, 12);
  lines.push(`# kronicle-lite orient — head seq ${s.head.seq} (${shortHash}…)`);
  lines.push('');
  if (s.drift_banner.surfaced) lines.push(`> **${s.drift_banner.line}**`);
  else lines.push(`> ${s.drift_banner.line}`);
  lines.push('');
  lines.push(`**cursor_compact:** \`${s.cursor_compact}\`  `);
  lines.push(`**recovery:** ${s.recovery.method} — ${s.recovery.reason}`);
  if (s.focus === 'pulse') {
    lines.push('');
    for (const n of s.next_steps) lines.push(`- ${n}`);
    lines.push('');
    lines.push(`<details><summary>full cursor</summary>\n\n\`${s.cursor}\`\n\n</details>`);
    return lines.join('\n');
  }

  if (s.retractions && s.retractions.length > 0) {
    lines.push('');
    lines.push(`## Retractions (${s.retractions.length}) — reconcile before acting`);
    for (const r of s.retractions) {
      lines.push(`- **[${r.severity}]** seq ${r.seq} \`${r.event_type}\` ${r.doc_slug ? `(${r.doc_slug}) ` : ''}${r.reason_line}`);
    }
  } else if (s.retractions) {
    lines.push('');
    lines.push('## Retractions: none');
  }

  if (s.digest) {
    lines.push('');
    lines.push('## Digest');
    lines.push(
      `${s.digest.documents} document(s), ${s.digest.live_blocks} live block(s), ${s.digest.checkpoints} checkpoint(s). Genesis \`${s.digest.genesis_hash.slice(0, 12)}…\`.`,
    );
    for (const d of s.digest.recent_documents) {
      lines.push(`- \`${d.slug}\` — ${d.title} (rev ${d.revision}, ${d.updated_at}) → kronicle://docs/${d.slug}`);
    }
  }

  if (s.delta) {
    lines.push('');
    lines.push(`## Delta: ${s.delta.events_since} event(s) since seq ${s.delta.from_seq}`);
    const types = Object.entries(s.delta.by_type)
      .sort((a, b) => b[1] - a[1])
      .map(([t, n]) => `${t}×${n}`)
      .join(', ');
    if (types) lines.push(`by type: ${types}`);
    const c = s.delta.coverage;
    if (c.demoted_by_budget.length > 0) lines.push(`_budget: ${c.demoted_by_budget.join(', ')} rolled up to fit ${c.estimated_tokens} tokens_`);
    if (c.truncated) lines.push('_truncated to the most recent entries_');
    for (const e of s.delta.entries) {
      if (e.kind === 'event') {
        lines.push(`- seq ${e.seq} \`${e.event_type}\` by ${e.actor_id} @ ${e.occurred_at} — ${summarizePayload(e.payload)}`);
      } else {
        lines.push(`- seq ${e.first_seq}–${e.last_seq} \`${e.event_type}\` ×${e.count} (rolled up${e.rendered_via === 'budget' ? ' by budget' : ''}); last: ${summarizePayload(e.sample.payload)}`);
      }
    }
  }

  lines.push('');
  lines.push('## Next');
  for (const n of s.next_steps) lines.push(`- ${n}`);
  lines.push('');
  lines.push(`<details><summary>full cursor</summary>\n\n\`${s.cursor}\`\n\n</details>`);
  return lines.join('\n');
}

function summarizePayload(p: Record<string, unknown>): string {
  const keys = ['slug', 'doc_slug', 'title', 'revision', 'block_id', 'successor_block_id', 'reason', 'kind', 'cause'];
  const parts: string[] = [];
  for (const k of keys) {
    const v = p[k];
    if (v === undefined || v === null) continue;
    parts.push(`${k}=${typeof v === 'string' ? JSON.stringify(v.length > 80 ? v.slice(0, 80) + '…' : v) : String(v)}`);
  }
  if (parts.length === 0) {
    const s = JSON.stringify(p);
    return s.length > 120 ? s.slice(0, 120) + '…' : s;
  }
  return parts.join(' ');
}
