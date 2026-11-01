/**
 * audit_assumptions — grade an agent's beliefs against the store.
 *
 * A claim is `{symbol, value}`. The symbol names something in the store:
 *   - a block id (UUID)            → value is the block's content or content_hash
 *   - a document slug              → value is a revision number or markdown BLAKE3 hash
 *   - "chain" / "head"             → value is the head seq or head hash
 *
 * Verdicts: current | stale | contradicted | retracted | unknown. Every
 * verdict comes with the current truth and a reconcile line, so the agent
 * can replace the belief in one step.
 */

import type { Chain } from '../chain/index.js';
import { blake3Hex } from '../crypto/hash.js';
import type { DocumentStore, SourceDrift } from '../docs/documents.js';
import { normalizeMarkdown } from '../docs/parser.js';
import { buildReasonLine } from './retraction.js';

/** stale_source (0.4.0): current in the store, but its git-bound source file changed. */
export type AuditVerdict = 'current' | 'stale' | 'contradicted' | 'retracted' | 'unknown' | 'stale_source';
export const AUDIT_VERDICTS = ['current', 'stale', 'contradicted', 'retracted', 'unknown', 'stale_source'] as const;

export interface AuditClaim {
  symbol: string;
  value: string | number;
}

export interface AuditResult {
  symbol: string;
  asserted: string;
  verdict: AuditVerdict;
  kind: 'block' | 'document' | 'chain' | 'unknown';
  current: Record<string, unknown> | null;
  reconcile: string | null;
  /** Present with stale_source. */
  source_drift?: SourceDrift;
}

export interface AuditSummary {
  checked_at: string;
  head: { seq: number; hash: string };
  results: AuditResult[];
  counts: Record<Exclude<AuditVerdict, 'stale_source'>, number> & { stale_source?: number };
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX64 = /^[0-9a-f]{64}$/;

export class AssumptionAuditor {
  constructor(
    private readonly chain: Chain,
    private readonly docs: DocumentStore,
  ) {}

  audit(claims: readonly AuditClaim[]): AuditSummary {
    const head = this.chain.head();
    const results = claims.map((c) => this.one(c, head));
    const counts: AuditSummary['counts'] = { current: 0, stale: 0, contradicted: 0, retracted: 0, unknown: 0 };
    for (const r of results) counts[r.verdict] = (counts[r.verdict] ?? 0) + 1;
    // stale_source (0.4.0) is counted only when it occurs, so the 0.3.0 counts shape is unchanged otherwise.
    return { checked_at: new Date().toISOString(), head, results, counts };
  }

  /** Downgrade a `current` verdict to `stale_source` when the document's git-bound source drifted. */
  private withSource(r: AuditResult, doc_id: string): AuditResult {
    if (r.verdict !== 'current') return r;
    const d = this.docs.sourceDrift(doc_id);
    if (!d || (d.state !== 'changed' && d.state !== 'missing')) return r;
    const stat = d.diff_stat ? ` (+${d.diff_stat.insertions} −${d.diff_stat.deletions})` : '';
    return {
      ...r,
      verdict: 'stale_source',
      source_drift: d,
      reconcile: buildReasonLine(
        `${r.symbol} matches its source ${d.path}`,
        `${d.path} ${d.state === 'missing' ? 'was deleted' : 'changed'} since it was bound at ${d.bound_blob_sha.slice(0, 12)}${stat}; re-read the file and re-put with bind_git before relying on ${r.symbol}`,
      ),
    };
  }

  private one(claim: AuditClaim, head: { seq: number; hash: string }): AuditResult {
    const asserted = String(claim.value);
    const symbol = claim.symbol.trim();

    if (symbol === 'chain' || symbol === 'head') {
      const ok = asserted === String(head.seq) || asserted.toLowerCase() === head.hash;
      return {
        symbol,
        asserted,
        verdict: ok ? 'current' : 'stale',
        kind: 'chain',
        current: { seq: head.seq, hash: head.hash },
        reconcile: ok ? null : buildReasonLine(`chain head ${asserted}`, `chain head is seq ${head.seq} (${head.hash.slice(0, 12)}…)`),
      };
    }

    if (UUID_RE.test(symbol)) {
      const block = this.docs.getBlock(symbol.toLowerCase());
      if (!block) return { symbol, asserted, verdict: 'unknown', kind: 'block', current: null, reconcile: null };
      const walk = this.docs.supersessionWalk(block.block_id);
      const lineageHead = walk[walk.length - 1] ?? block;
      const doc = this.docs.getDocumentById(block.doc_id);
      const current = {
        block_id: lineageHead.block_id,
        content_hash: lineageHead.content_hash,
        content: lineageHead.content,
        doc_slug: doc?.slug ?? null,
        tombstoned_at: lineageHead.tombstoned_at,
        tombstone_reason: lineageHead.tombstone_reason,
        chain_seq: lineageHead.chain_seq,
      };
      if (lineageHead.tombstoned_at !== null) {
        return {
          symbol,
          asserted,
          verdict: 'retracted',
          kind: 'block',
          current,
          reconcile: buildReasonLine(
            `block ${symbol} (assumed live)`,
            `block ${lineageHead.block_id} is TOMBSTONED${lineageHead.tombstone_reason ? ` — ${lineageHead.tombstone_reason}` : ''}; drop the claim`,
          ),
        };
      }
      if (lineageHead.block_id !== block.block_id) {
        return {
          symbol,
          asserted,
          verdict: 'stale',
          kind: 'block',
          current,
          reconcile: buildReasonLine(
            `block ${symbol} (assumed current)`,
            `block ${symbol} is SUPERSEDED by ${lineageHead.block_id} (seq ${lineageHead.chain_seq}); use its content`,
          ),
        };
      }
      const matches =
        asserted.toLowerCase() === block.content_hash ||
        normalizeMarkdown(asserted).trim() === block.content ||
        blake3Hex(normalizeMarkdown(asserted).trim()) === block.content_hash;
      return this.withSource(
        {
          symbol,
          asserted,
          verdict: matches ? 'current' : 'contradicted',
          kind: 'block',
          current,
          reconcile: matches
            ? null
            : buildReasonLine(`block ${symbol} = ${truncate(asserted)}`, `block ${symbol} = ${truncate(block.content)} (hash ${block.content_hash.slice(0, 12)}…)`),
        },
        block.doc_id,
      );
    }

    const doc = this.docs.getDocument(symbol);
    if (doc) {
      const markdown = this.docs.getRevisionMarkdown(doc.doc_id, doc.current_revision) ?? '';
      const mdHash = blake3Hex(markdown);
      const current = {
        slug: doc.slug,
        title: doc.title,
        revision: doc.current_revision,
        markdown_hash: mdHash,
        updated_at: doc.updated_at,
      };
      const isRevision = /^\d+$/.test(asserted);
      let verdict: AuditVerdict;
      if (isRevision) {
        const n = Number(asserted);
        verdict = n === doc.current_revision ? 'current' : n < doc.current_revision ? 'stale' : 'contradicted';
      } else if (HEX64.test(asserted.toLowerCase())) {
        verdict = asserted.toLowerCase() === mdHash ? 'current' : 'stale';
      } else {
        verdict = normalizeMarkdown(asserted).trim() === markdown.trim() ? 'current' : 'stale';
      }
      return this.withSource(
        {
          symbol,
          asserted,
          verdict,
          kind: 'document',
          current,
          reconcile:
            verdict === 'current'
              ? null
              : buildReasonLine(`document ${symbol} @ ${truncate(asserted)}`, `document ${symbol} is at revision ${doc.current_revision} (hash ${mdHash.slice(0, 12)}…)`),
        },
        doc.doc_id,
      );
    }

    return { symbol, asserted, verdict: 'unknown', kind: 'unknown', current: null, reconcile: null };
  }
}

function truncate(s: string, n = 80): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}
