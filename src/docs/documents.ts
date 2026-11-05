/**
 * Documents → revisions → blocks, as a projection of chain events.
 *
 * Every write builds its events, appends them to the chain and applies the
 * same `applyEvent` projection that `import` uses to rebuild the tables from
 * a JSONL export. The chain is the source of truth; these tables are a
 * derived index.
 *
 * Event vocabulary (payloads are documented in docs/FORMAT.md):
 *   document.put       new document or new full revision (carries markdown)
 *   document.revised   revision bump caused by supersede_block / tombstone_block
 *   block.created      one new block (carries content)
 *   block.superseded   old block → successor block
 *   block.tombstoned   block retired with a reason, no successor
 *   document.renamed   (0.5.0) same doc_id, new slug
 */

import { randomUUID } from 'node:crypto';

import type { Chain, ChainEvent, ChainHead } from '../chain/index.js';
import { canonicalize } from '../crypto/canonical.js';
import { blake3Hex } from '../crypto/hash.js';
import { checkGitBinding, type DiffStat, type SourceState } from '../git/binding.js';
import type { Db } from '../db/open.js';
import { ReadLog, type ReadRow } from '../lineage/read-log.js';
import { guardFields, type SecretFinding, type SecretPolicy } from '../secrets/guard.js';
import { normalizeMarkdown, parseMarkdown, renderBlocks, type BlockKind, type ParsedBlock } from './parser.js';

export interface BlockRow {
  block_id: string;
  doc_id: string;
  revision: number;
  ordinal: number;
  kind: BlockKind;
  level: number;
  heading_path: string; // " > " joined
  content: string;
  content_hash: string;
  chain_seq: number;
  valid_from: string;
  valid_to: string | null;
  superseded_by: string | null;
  tombstoned_at: string | null;
  tombstone_reason: string | null;
}

export interface DocumentRow {
  doc_id: string;
  slug: string;
  title: string;
  current_revision: number;
  created_at: string;
  updated_at: string;
  tombstoned_at: string | null;
  /** Unreleased (next): owning project key, or null (unscoped, visible from every project). */
  project_key?: string | null;
}

export interface BlockSummary {
  block_id: string;
  ordinal: number;
  kind: BlockKind;
  heading_path: string[];
  content_hash: string;
  status: 'created' | 'unchanged' | 'superseded' | 'tombstoned';
  supersedes?: string;
}

export interface PutDocumentResult {
  doc_id: string;
  slug: string;
  title: string;
  revision: number;
  chain_seq: number;
  head: ChainHead;
  blocks: BlockSummary[];
  events: number;
  /** 0.6.0: present when secrets: 'redact' replaced something before chaining. */
  redactions?: SecretFinding[];
  /** Unreleased: lineage recorded on this write (counts), when any. */
  lineage?: LineageCounts;
}

/** Unreleased: a derived-note lineage edge (docs/FORMAT.md §3.10). */
export interface LineageRef {
  block_id: string;
  content_hash: string;
}

export interface LineageCounts {
  /** Explicit `derived_from` edges recorded. */
  derived_from: number;
  /** Edges inferred from what the author read in its session. */
  derived_from_inferred: number;
  /** The author had no session (never oriented) and the 24 h / 200-block bound left reads out. */
  derived_from_inferred_truncated?: true;
}

/**
 * Unreleased: computes `derived_from_inferred` for a write (KronicleLite
 * wires it to the read log; see src/lineage/lineage.ts `infer`).
 */
export type LineageInference = (
  actor_id: string,
  cursor: string | undefined,
  exclude_doc_id: string | null,
  opts?: { rewrite?: boolean },
) => { refs: LineageRef[]; truncated: boolean; released?: LineageRef[] };

export interface SupersedeBlockResult {
  old_block_id: string;
  new_block_id: string;
  content_hash: string;
  doc_slug: string;
  revision: number;
  head: ChainHead;
  /** 0.6.0: present when secrets: 'redact' replaced something before chaining. */
  redactions?: SecretFinding[];
  /** Unreleased: lineage recorded on this write (counts), when any. */
  lineage?: LineageCounts;
}

export interface TombstoneBlockResult {
  block_id: string;
  doc_slug: string;
  revision: number;
  head: ChainHead;
}

export class DocumentError extends Error {
  override readonly name = 'DocumentError';
  constructor(
    readonly code: 'unknown_block' | 'block_not_live' | 'unknown_document' | 'invalid_slug' | 'empty_content' | 'invalid_source' | 'invalid_lineage',
    message: string,
  ) {
    super(message);
  }
}

export const SLUG_RE = /^[a-z0-9][a-z0-9._-]{0,127}$/;
/**
 * 0.4.0: namespaced slugs for documents imported from files — a lowercase
 * namespace, then `/`-separated segments that keep the file's case
 * (`instructions/claude-md`, `instructions/claude-rules/frontend/react`,
 * `memory/MEMORY`). At most 128 characters, so they fit receipts. The
 * `instructions/` and `memory/` namespaces are reserved for instruction
 * import (their supersessions are retractions of kind `instruction`).
 */
export const PATH_SLUG_RE = /^[a-z0-9][a-z0-9._-]{0,63}(?:\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}){1,16}$/;
export const INSTRUCTION_NAMESPACES = ['instructions/', 'memory/'] as const;

export function isValidSlug(slug: string): boolean {
  return slug.length <= 128 && (SLUG_RE.test(slug) || PATH_SLUG_RE.test(slug));
}

export function isInstructionSlug(slug: string | null | undefined): boolean {
  return typeof slug === 'string' && INSTRUCTION_NAMESPACES.some((n) => slug.startsWith(n));
}

/**
 * Where a document's markdown came from (0.4.0, optional `source` field of
 * the `document.put` payload). Chained into the event hash like every other
 * payload field; absent on every 0.3.0 event.
 */
export interface DocumentSource {
  /** instruction | memory | file */
  kind: string;
  /** Path as recorded: project-relative, `~/`-relative or absolute, `/`-separated. */
  path: string;
  /** Present when bound with bind_git (FORMAT §3.4). */
  git?: GitBinding;
  /**
   * 0.5.0: the project an instruction / memory file belongs to (key derived
   * from the git worktree root, see instructions/paths.ts). Orient uses it to
   * keep one project's instruction retractions out of another's briefing.
   */
  project?: { key: string; root: string };
}

export interface GitBinding {
  /** Absolute repository root (`git rev-parse --show-toplevel`). */
  repo_root: string;
  /** HEAD commit at put time, or null in a repository without commits. */
  commit: string | null;
  /** Path relative to repo_root, `/`-separated. */
  path: string;
  /** `git hash-object <file>` at put time. */
  blob_sha: string;
}

/** Result of comparing a git-bound document with its working-tree file (0.4.0). */
export interface SourceDrift {
  slug: string;
  doc_id: string;
  /** Revision whose put recorded the binding. */
  revision: number;
  repo_root: string;
  path: string;
  bound_commit: string | null;
  bound_blob_sha: string;
  state: SourceState;
  working_blob_sha: string | null;
  head_commit: string | null;
  diff_stat: DiffStat | null;
  detail: string | null;
}

export interface DocSourceRow {
  doc_id: string;
  slug: string;
  revision: number;
  chain_seq: number;
  kind: string;
  path: string;
  source_json: string;
}
export const HP_SEP = ' > ';

export function joinHeadingPath(p: readonly string[]): string {
  return p.join(HP_SEP);
}
export function splitHeadingPath(s: string): string[] {
  return s.length === 0 ? [] : s.split(HP_SEP);
}

type Pending = { event_type: string; payload: Record<string, unknown> };

export class DocumentStore {
  /** Unreleased: set by KronicleLite; null = no automatic lineage inference. */
  lineageInference: LineageInference | null = null;
  /** 0.8.1: the bounded local read log (shared with Lineage). */
  readonly readLog: ReadLog;

  constructor(
    private readonly db: Db,
    private readonly chain: Chain,
  ) {
    this.readLog = new ReadLog(db);
  }

  /**
   * Unreleased: check explicit `derived_from` edges (the block exists and the
   * hash is its content hash; a block that is no longer live is accepted: the
   * note is then stale from the start). Deduplicated by block id.
   */
  private checkLineage(refs: readonly LineageRef[] | undefined): LineageRef[] | undefined {
    if (refs === undefined) return undefined;
    const out = new Map<string, LineageRef>();
    for (const r of refs) {
      if (!r || typeof r.block_id !== 'string' || typeof r.content_hash !== 'string') throw new DocumentError('invalid_lineage', 'derived_from entries need block_id and content_hash');
      const b = this.getBlock(r.block_id);
      if (!b) throw new DocumentError('invalid_lineage', `derived_from: no block ${r.block_id}`);
      if (b.content_hash !== r.content_hash) {
        throw new DocumentError('invalid_lineage', `derived_from: block ${r.block_id} has content_hash ${b.content_hash}, not ${r.content_hash} (a block id names one version; pass the hash recall returned)`);
      }
      out.set(r.block_id, { block_id: r.block_id, content_hash: r.content_hash });
    }
    return [...out.values()].sort((a, b) => a.block_id.localeCompare(b.block_id));
  }

  private inferLineage(
    actor_id: string,
    cursor: string | undefined,
    infer: boolean | undefined,
    exclude_doc_id: string | null,
    explicit: readonly LineageRef[] | undefined,
    opts: { rewrite?: boolean } = {},
  ): { refs: LineageRef[]; truncated: boolean; released: LineageRef[] } {
    if (infer === false || !this.lineageInference) return { refs: [], truncated: false, released: [] };
    const skip = new Set((explicit ?? []).map((r) => r.block_id));
    const r = this.lineageInference(actor_id, cursor, exclude_doc_id, opts);
    // An explicit derived_from replaces the whole lineage: nothing to release then.
    return { refs: r.refs.filter((x) => !skip.has(x.block_id)), truncated: r.truncated, released: explicit !== undefined ? [] : (r.released ?? []) };
  }

  /** Unreleased: a write is a read of what was written (local read log, never chained; pruned, see lineage/read-log.ts). */
  private logWrite(actor_id: string, doc_id: string, block_ids: readonly string[] | 'document'): void {
    const doc = this.getDocumentById(doc_id);
    if (!doc) return;
    const base = { actor_id, doc_id, doc_revision: doc.current_revision, head_seq: this.chain.head().seq, read_at: new Date().toISOString(), via: 'write' as const };
    const rows: ReadRow[] = [];
    if (block_ids === 'document') {
      const rev = this.getRevision(doc_id, doc.current_revision);
      rows.push({ ...base, block_id: null, content_hash: rev?.content_hash ?? '' });
      for (const b of this.liveBlocks(doc_id)) rows.push({ ...base, block_id: b.block_id, content_hash: b.content_hash });
    } else {
      for (const id of block_ids) {
        const b = this.getBlock(id);
        if (b) rows.push({ ...base, block_id: b.block_id, content_hash: b.content_hash });
      }
    }
    this.readLog.record(rows);
  }

  // ───────────────────────────── reads ─────────────────────────────

  getDocument(slug: string): DocumentRow | null {
    return (this.db.prepare(`SELECT * FROM documents WHERE slug = ?`).get(slug) as DocumentRow | undefined) ?? null;
  }

  /** Unreleased (next): the document's project key, or null when unscoped / unknown. */
  projectKeyOf(doc_id: string): string | null {
    const r = this.db.prepare(`SELECT project_key FROM documents WHERE doc_id = ?`).get(doc_id) as { project_key: string | null } | undefined;
    return r?.project_key ?? null;
  }

  getDocumentById(doc_id: string): DocumentRow | null {
    return (
      (this.db.prepare(`SELECT * FROM documents WHERE doc_id = ?`).get(doc_id) as DocumentRow | undefined) ?? null
    );
  }

  /** Live documents, newest first; with `projectKeys`, only those projects' and unscoped ones. */
  listDocuments(limit = 50, projectKeys: readonly string[] | null = null): DocumentRow[] {
    if (projectKeys && projectKeys.length > 0) {
      return this.db
        .prepare(
          `SELECT * FROM documents WHERE tombstoned_at IS NULL AND (project_key IS NULL OR project_key IN (${projectKeys.map(() => '?').join(', ')}))
            ORDER BY updated_at DESC LIMIT ?`,
        )
        .all(...projectKeys, limit) as DocumentRow[];
    }
    return this.db
      .prepare(`SELECT * FROM documents WHERE tombstoned_at IS NULL ORDER BY updated_at DESC LIMIT ?`)
      .all(limit) as DocumentRow[];
  }

  countDocuments(): number {
    return (this.db.prepare(`SELECT COUNT(*) n FROM documents WHERE tombstoned_at IS NULL`).get() as { n: number }).n;
  }

  countLiveBlocks(): number {
    return (
      this.db.prepare(`SELECT COUNT(*) n FROM blocks WHERE valid_to IS NULL AND tombstoned_at IS NULL`).get() as {
        n: number;
      }
    ).n;
  }

  getBlock(block_id: string): BlockRow | null {
    return (this.db.prepare(`SELECT * FROM blocks WHERE block_id = ?`).get(block_id) as BlockRow | undefined) ?? null;
  }

  /** Live blocks across all documents, newest first (orient's integrity pass). */
  liveBlockRows(limit: number): BlockRow[] {
    return this.db
      .prepare(`SELECT * FROM blocks WHERE valid_to IS NULL AND tombstoned_at IS NULL ORDER BY chain_seq DESC LIMIT ?`)
      .all(limit) as BlockRow[];
  }

  liveBlocks(doc_id: string): BlockRow[] {
    return this.db
      .prepare(
        `SELECT * FROM blocks WHERE doc_id = ? AND valid_to IS NULL AND tombstoned_at IS NULL ORDER BY ordinal ASC`,
      )
      .all(doc_id) as BlockRow[];
  }

  /** Current provenance of a document (from its latest document.put), or null. */
  getSource(doc_id: string): (DocSourceRow & { source: DocumentSource }) | null {
    const r = this.db.prepare(`SELECT * FROM doc_sources WHERE doc_id = ?`).get(doc_id) as DocSourceRow | undefined;
    return r ? { ...r, source: JSON.parse(r.source_json) as DocumentSource } : null;
  }

  /**
   * Unreleased (next): live documents whose CURRENT revision has this markdown
   * hash and whose latest put recorded a source of this kind in this project
   * (indexed; used to recognise a moved file).
   */
  sourcesWithCurrentHash(hash: string, kind: string, project_key: string): (DocSourceRow & { source: DocumentSource })[] {
    const rows = this.db
      .prepare(
        `SELECT s.* FROM document_revisions r
           JOIN documents d ON d.doc_id = r.doc_id AND d.current_revision = r.revision
           JOIN doc_sources s ON s.doc_id = d.doc_id
          WHERE r.content_hash = ? AND s.kind = ? AND d.project_key = ? AND d.tombstoned_at IS NULL`,
      )
      .all(hash, kind, project_key) as DocSourceRow[];
    return rows.map((r) => ({ ...r, source: JSON.parse(r.source_json) as DocumentSource }));
  }

  /** Every document whose latest put recorded a source, optionally filtered by kind. */
  listSources(kind?: string): (DocSourceRow & { source: DocumentSource })[] {
    const rows = (
      kind === undefined
        ? this.db.prepare(`SELECT * FROM doc_sources ORDER BY slug`).all()
        : this.db.prepare(`SELECT * FROM doc_sources WHERE kind = ? ORDER BY slug`).all(kind)
    ) as DocSourceRow[];
    return rows.map((r) => ({ ...r, source: JSON.parse(r.source_json) as DocumentSource }));
  }

  /**
   * Compare a git-bound document with its working-tree file. null when the
   * document has no git binding. Runs `git hash-object` (and `git cat-file`
   * for the diff stat when the file changed).
   */
  sourceDrift(doc_id: string): SourceDrift | null {
    const src = this.getSource(doc_id);
    const g = src?.source.git;
    if (!src || !g || typeof g.repo_root !== 'string' || typeof g.path !== 'string' || typeof g.blob_sha !== 'string') return null;
    const check = checkGitBinding(g, this.getRevisionMarkdown(doc_id, src.revision));
    return {
      slug: src.slug,
      doc_id,
      revision: src.revision,
      repo_root: g.repo_root,
      path: g.path,
      bound_commit: g.commit ?? null,
      bound_blob_sha: g.blob_sha,
      ...check,
    };
  }

  /** Every git-bound document whose source drifted (changed or missing), up to `limit` checked. */
  listSourceDrift(limit = 50): SourceDrift[] {
    const out: SourceDrift[] = [];
    let checked = 0;
    for (const s of this.listSources()) {
      if (!s.source.git) continue;
      if (checked++ >= limit) break;
      const d = this.sourceDrift(s.doc_id);
      if (d && (d.state === 'changed' || d.state === 'missing')) out.push(d);
    }
    return out;
  }

  /** BLAKE3 of the current revision's markdown, or null for an unknown slug. */
  currentMarkdownHash(slug: string): string | null {
    const r = this.db
      .prepare(
        `SELECT r.content_hash FROM documents d JOIN document_revisions r ON r.doc_id = d.doc_id AND r.revision = d.current_revision WHERE d.slug = ?`,
      )
      .get(slug) as { content_hash: string } | undefined;
    return r?.content_hash ?? null;
  }

  getRevision(doc_id: string, revision: number): { doc_id: string; revision: number; markdown: string; content_hash: string; chain_seq: number } | null {
    return (
      (this.db
        .prepare(`SELECT doc_id, revision, markdown, content_hash, chain_seq FROM document_revisions WHERE doc_id = ? AND revision = ?`)
        .get(doc_id, revision) as { doc_id: string; revision: number; markdown: string; content_hash: string; chain_seq: number } | undefined) ?? null
    );
  }

  getRevisionMarkdown(doc_id: string, revision: number): string | null {
    const r = this.db
      .prepare(`SELECT markdown FROM document_revisions WHERE doc_id = ? AND revision = ?`)
      .get(doc_id, revision) as { markdown: string } | undefined;
    return r?.markdown ?? null;
  }

  /**
   * 0.5.0: does the chain (not the projection) record a block.superseded or
   * block.tombstoned event for this block? Used to confirm a "live" answer
   * from the projection before signing off on it.
   */
  chainRetired(block_id: string): boolean {
    return (
      this.db
        .prepare(
          `SELECT 1 FROM events WHERE event_type IN ('block.superseded', 'block.tombstoned')
             AND CASE WHEN json_valid(payload_canonical) THEN json_extract(payload_canonical, '$.block_id') END = ? LIMIT 1`,
        )
        .get(block_id) !== undefined
    );
  }

  /**
   * Follow superseded_by from `block_id` to the chain's end. Returns the
   * walk (first = the block itself, last = the current head of the lineage).
   */
  supersessionWalk(block_id: string): BlockRow[] {
    return this.db
      .prepare(
        `WITH RECURSIVE lineage(block_id, depth) AS (
           SELECT ?, 0
           UNION ALL
           SELECT b.superseded_by, l.depth + 1
             FROM blocks b JOIN lineage l ON b.block_id = l.block_id
            WHERE b.superseded_by IS NOT NULL AND l.depth < 10000
         )
         SELECT b.* FROM lineage l JOIN blocks b ON b.block_id = l.block_id ORDER BY l.depth ASC`,
      )
      .all(block_id) as BlockRow[];
  }

  // ───────────────────────────── writes ─────────────────────────────

  putDocument(args: {
    slug: string;
    title: string;
    markdown: string;
    actor_id: string;
    idempotency_key?: string;
    /** 0.4.0: provenance recorded in the document.put payload (`source`). */
    source?: DocumentSource;
    /** 0.6.0: what to do with a detected secret (default refuse; nothing is chained). */
    secrets?: SecretPolicy;
    /**
     * Unreleased (next): the project this document belongs to, recorded as the
     * document.put payload's `project` (additive; absent = unscoped). Ignored
     * when `source.project` is set (instruction files carry their own).
     */
    project?: { key: string; root: string } | null;
    /**
     * Unreleased: explicit lineage (docs/FORMAT.md §3.10). Present (even [])
     * = the author's statement of what the note now rests on: it replaces the
     * document's earlier lineage. Absent = earlier lineage is kept.
     */
    derived_from?: LineageRef[];
    /** Unreleased: the author's cursor (its session start bounds lineage inference). */
    cursor?: string;
    /** Unreleased: infer lineage from the author's reads (default true when an inference is wired). */
    infer_lineage?: boolean;
  }): PutDocumentResult {
    const guarded = guardFields({ title: args.title, markdown: args.markdown }, args.secrets ?? 'refuse', `document ${args.slug}`);
    args = { ...args, ...guarded.fields };
    if (!isValidSlug(args.slug)) {
      throw new DocumentError('invalid_slug', `slug must match ${SLUG_RE} or the namespaced form ${PATH_SLUG_RE}`);
    }
    if (args.source !== undefined && (typeof args.source.kind !== 'string' || typeof args.source.path !== 'string')) {
      throw new DocumentError('invalid_source', 'source needs string kind and path');
    }
    const parsed = parseMarkdown(args.markdown);
    const markdown = normalizeMarkdown(args.markdown);
    const markdown_hash = blake3Hex(markdown);
    const explicit = this.checkLineage(args.derived_from);
    const prior = this.getDocument(args.slug);
    const { refs: inferred, truncated, released } = this.inferLineage(args.actor_id, args.cursor, args.infer_lineage, prior?.doc_id ?? null, explicit, {
      rewrite: prior !== null && this.currentMarkdownHash(args.slug) !== markdown_hash,
    });

    const run = this.db.transaction((): PutDocumentResult => {
      const existing = this.getDocument(args.slug);
      // 0.8.1: idempotent by content. Decided here, under the write lock, so
      // concurrent identical puts (several instruction-import hooks firing on
      // one edit) append one revision, not one each. Only a put that would
      // record nothing new is a no-op: no lineage, no idempotency key, and the
      // same markdown, title, source and project as the current revision's put.
      if (existing && args.idempotency_key === undefined && explicit === undefined && inferred.length === 0 && !truncated) {
        const same = this.unchangedPut(existing, { title: args.title, markdown_hash, source: args.source, project: args.project ?? null });
        if (same) {
          this.logWrite(args.actor_id, existing.doc_id, 'document');
          return this.describePut(same); // events: 0, like an idempotent replay
        }
      }
      const doc_id = existing?.doc_id ?? randomUUID();
      const revision = (existing?.current_revision ?? 0) + 1;
      const oldLive = existing ? this.liveBlocks(doc_id) : [];

      const plan = planRevision(oldLive, parsed);
      const summaries: BlockSummary[] = [];
      const pending: Pending[] = [];

      const carried = plan.carried.map((c) => ({
        block_id: c.old.block_id,
        ordinal: c.next.ordinal,
        heading_path: c.next.heading_path,
      }));
      const created = plan.created.map((p) => ({ block_id: randomUUID(), parsed: p }));
      const replaced = plan.replaced.map((r) => ({
        old_block_id: r.old.block_id,
        new_block_id: randomUUID(),
        parsed: r.next,
        reordered: r.reordered === true,
      }));

      const liveBlockIds: string[] = [];
      const byOrdinal = new Map<number, string>();
      for (const c of carried) byOrdinal.set(c.ordinal, c.block_id);
      for (const c of created) byOrdinal.set(c.parsed.ordinal, c.block_id);
      for (const r of replaced) byOrdinal.set(r.parsed.ordinal, r.new_block_id);
      for (const p of parsed) liveBlockIds.push(byOrdinal.get(p.ordinal)!);

      pending.push({
        event_type: 'document.put',
        payload: {
          doc_id,
          slug: args.slug,
          title: args.title,
          revision,
          markdown,
          markdown_hash,
          block_ids: liveBlockIds,
          carried,
          // Additive (0.4.0): only present when the caller supplied it, so a
          // put without a source hashes exactly as in 0.3.0.
          ...(args.source !== undefined ? { source: args.source as unknown as Record<string, unknown> } : {}),
          ...(args.project && !args.source?.project ? { project: { key: args.project.key, root: args.project.root } } : {}),
          // Unreleased, additive: lineage, only when there is any (a put without it hashes as before).
          ...(explicit !== undefined ? { derived_from: explicit as unknown as Record<string, unknown>[] } : {}),
          ...(inferred.length > 0 ? { derived_from_inferred: inferred as unknown as Record<string, unknown>[] } : {}),
          ...(truncated ? { derived_from_inferred_truncated: true } : {}),
          // 0.8.1, additive: earlier inferred edges to removed sources this put re-derives past.
          ...(released.length > 0 ? { derived_from_released: released as unknown as Record<string, unknown>[] } : {}),
        },
      });
      for (const c of [...created, ...replaced]) {
        const p = c.parsed;
        const block_id = 'new_block_id' in c ? c.new_block_id : c.block_id;
        pending.push({
          event_type: 'block.created',
          payload: {
            block_id,
            doc_id,
            doc_slug: args.slug,
            revision,
            ordinal: p.ordinal,
            kind: p.kind,
            level: p.level,
            heading_path: p.heading_path,
            content: p.content,
            content_hash: p.content_hash,
          },
        });
      }
      for (const r of replaced) {
        pending.push({
          event_type: 'block.superseded',
          payload: {
            block_id: r.old_block_id,
            successor_block_id: r.new_block_id,
            doc_id,
            doc_slug: args.slug,
            revision,
            reason: `${r.reordered ? 'reordered' : 'replaced'} in revision ${revision}`,
          },
        });
      }
      for (const t of plan.tombstoned) {
        pending.push({
          event_type: 'block.tombstoned',
          payload: {
            block_id: t.block_id,
            doc_id,
            doc_slug: args.slug,
            revision,
            reason: `removed in revision ${revision}`,
          },
        });
      }

      // Idempotency: key only the first event; if it replays, the whole put
      // already happened and we return the current state.
      const first = this.chain.append({
        event_type: pending[0]!.event_type,
        payload: pending[0]!.payload,
        actor_id: args.actor_id,
        ...(args.idempotency_key !== undefined ? { idempotency_key: args.idempotency_key } : {}),
      });
      if (first.replayed) {
        return this.describePut(first.event);
      }
      this.applyEvent(first.event);
      let head = first.head;
      for (const ev of pending.slice(1)) {
        const r = this.chain.append({ event_type: ev.event_type, payload: ev.payload, actor_id: args.actor_id });
        this.applyEvent(r.event);
        head = r.head;
      }

      for (const c of carried) {
        const next = parsed[c.ordinal]!;
        summaries.push({
          block_id: c.block_id,
          ordinal: c.ordinal,
          kind: next.kind,
          heading_path: next.heading_path,
          content_hash: next.content_hash,
          status: 'unchanged',
        });
      }
      for (const c of created) {
        summaries.push({
          block_id: c.block_id,
          ordinal: c.parsed.ordinal,
          kind: c.parsed.kind,
          heading_path: c.parsed.heading_path,
          content_hash: c.parsed.content_hash,
          status: 'created',
        });
      }
      for (const r of replaced) {
        summaries.push({
          block_id: r.new_block_id,
          ordinal: r.parsed.ordinal,
          kind: r.parsed.kind,
          heading_path: r.parsed.heading_path,
          content_hash: r.parsed.content_hash,
          status: 'created',
          supersedes: r.old_block_id,
        });
      }
      for (const t of plan.tombstoned) {
        summaries.push({
          block_id: t.block_id,
          ordinal: t.ordinal,
          kind: t.kind,
          heading_path: splitHeadingPath(t.heading_path),
          content_hash: t.content_hash,
          status: 'tombstoned',
        });
      }
      summaries.sort((a, b) => a.ordinal - b.ordinal || a.status.localeCompare(b.status));
      this.logWrite(args.actor_id, doc_id, 'document');

      return {
        doc_id,
        slug: args.slug,
        title: args.title,
        revision,
        chain_seq: first.event.seq,
        head,
        blocks: summaries,
        events: pending.length,
        ...(explicit !== undefined || inferred.length > 0 || truncated
          ? { lineage: { derived_from: explicit?.length ?? 0, derived_from_inferred: inferred.length, ...(truncated ? { derived_from_inferred_truncated: true as const } : {}) } }
          : {}),
      };
    });
    const result = run.immediate();
    return guarded.redactions.length > 0 ? { ...result, redactions: guarded.redactions } : result;
  }

  /**
   * 0.8.1: the document.put behind `doc`'s current revision when a new put
   * with these fields would record exactly what it already records (same
   * markdown hash, title, source and project); null otherwise.
   */
  private unchangedPut(
    doc: DocumentRow,
    next: { title: string; markdown_hash: string; source: DocumentSource | undefined; project: { key: string; root: string } | null },
  ): ChainEvent | null {
    const rev = this.getRevision(doc.doc_id, doc.current_revision);
    if (!rev || rev.content_hash !== next.markdown_hash) return null;
    let ev: ChainEvent | null;
    try {
      ev = this.chain.get(rev.chain_seq);
    } catch {
      return null;
    }
    if (!ev || ev.event_type !== 'document.put') return null;
    const p = ev.payload;
    if (p['doc_id'] !== doc.doc_id || p['revision'] !== doc.current_revision || p['markdown_hash'] !== next.markdown_hash || p['title'] !== next.title) return null;
    const canon = (v: unknown) => (v === undefined || v === null ? null : canonicalize(v as Record<string, unknown>));
    if (canon(p['source']) !== canon(next.source)) return null;
    const project = next.project && !next.source?.project ? { key: next.project.key, root: next.project.root } : undefined;
    if (canon(p['project']) !== canon(project)) return null;
    return ev;
  }

  private describePut(putEvent: ChainEvent): PutDocumentResult {
    const p = putEvent.payload as { doc_id: string; slug: string; title: string; revision: number };
    const live = this.liveBlocks(p.doc_id);
    return {
      doc_id: p.doc_id,
      slug: p.slug,
      title: p.title,
      revision: p.revision,
      chain_seq: putEvent.seq,
      head: this.chain.head(),
      blocks: live.map((b) => ({
        block_id: b.block_id,
        ordinal: b.ordinal,
        kind: b.kind,
        heading_path: splitHeadingPath(b.heading_path),
        content_hash: b.content_hash,
        status: 'unchanged' as const,
      })),
      events: 0,
    };
  }

  supersedeBlock(args: {
    block_id: string;
    new_content: string;
    reason: string;
    actor_id: string;
    /** 0.6.0: see putDocument. */
    secrets?: SecretPolicy;
    /** Unreleased: lineage of the new text; added to the document's lineage (never replaces it). */
    derived_from?: LineageRef[];
    cursor?: string;
    infer_lineage?: boolean;
  }): SupersedeBlockResult {
    const guarded = guardFields({ new_content: args.new_content, reason: args.reason }, args.secrets ?? 'refuse', `block content`);
    args = { ...args, ...guarded.fields };
    const content = normalizeMarkdown(args.new_content).trim();
    if (content.length === 0) throw new DocumentError('empty_content', 'new_content is empty');
    const explicit = this.checkLineage(args.derived_from);
    const { refs: inferred, truncated } = this.inferLineage(args.actor_id, args.cursor, args.infer_lineage, this.getBlock(args.block_id)?.doc_id ?? null, explicit);
    const run = this.db.transaction((): SupersedeBlockResult => {
      const old = this.requireLive(args.block_id);
      const doc = this.getDocumentById(old.doc_id)!;
      const revision = doc.current_revision + 1;
      const new_block_id = randomUUID();
      const content_hash = blake3Hex(content);
      const level = old.kind === 'heading' ? headingLevelOf(old) : 0;

      const r1 = this.chain.append({
        event_type: 'block.created',
        actor_id: args.actor_id,
        payload: {
          block_id: new_block_id,
          doc_id: old.doc_id,
          doc_slug: doc.slug,
          revision,
          ordinal: old.ordinal,
          kind: old.kind,
          level,
          heading_path: splitHeadingPath(old.heading_path),
          content,
          content_hash,
          // Unreleased, additive: lineage of the new text (absent = none recorded).
          ...(explicit !== undefined && explicit.length > 0 ? { derived_from: explicit as unknown as Record<string, unknown>[] } : {}),
          ...(inferred.length > 0 ? { derived_from_inferred: inferred as unknown as Record<string, unknown>[] } : {}),
          ...(truncated ? { derived_from_inferred_truncated: true } : {}),
        },
      });
      this.applyEvent(r1.event);
      const r2 = this.chain.append({
        event_type: 'block.superseded',
        actor_id: args.actor_id,
        payload: {
          block_id: old.block_id,
          successor_block_id: new_block_id,
          doc_id: old.doc_id,
          doc_slug: doc.slug,
          revision,
          reason: args.reason,
        },
      });
      this.applyEvent(r2.event);
      const head = this.emitRevised(doc, revision, args.actor_id, 'supersede_block');
      this.logWrite(args.actor_id, old.doc_id, [new_block_id]);
      const n: LineageCounts = { derived_from: explicit?.length ?? 0, derived_from_inferred: inferred.length, ...(truncated ? { derived_from_inferred_truncated: true as const } : {}) };
      return { old_block_id: old.block_id, new_block_id, content_hash, doc_slug: doc.slug, revision, head, ...(n.derived_from + n.derived_from_inferred > 0 || truncated ? { lineage: n } : {}) };
    });
    const result = run.immediate();
    return guarded.redactions.length > 0 ? { ...result, redactions: guarded.redactions } : result;
  }

  /**
   * 0.5.0: give a document a new slug, keeping its doc_id, revisions and
   * blocks (`document.renamed`). Used to move 0.4.0 instruction documents
   * under their project key. Refused when the new slug is taken.
   */
  renameDocument(args: { doc_id: string; slug: string; actor_id: string; reason: string }): ChainHead {
    if (!isValidSlug(args.slug)) throw new DocumentError('invalid_slug', `invalid slug ${args.slug}`);
    const run = this.db.transaction((): ChainHead => {
      const doc = this.getDocumentById(args.doc_id);
      if (!doc) throw new DocumentError('unknown_document', `no document ${args.doc_id}`);
      if (this.getDocument(args.slug)) throw new DocumentError('invalid_slug', `slug ${args.slug} is taken`);
      const r = this.chain.append({
        event_type: 'document.renamed',
        actor_id: args.actor_id,
        payload: { doc_id: doc.doc_id, from_slug: doc.slug, slug: args.slug, revision: doc.current_revision, reason: args.reason },
      });
      this.applyEvent(r.event);
      return r.head;
    });
    return run.immediate();
  }

  tombstoneBlock(args: { block_id: string; reason: string; actor_id: string; secrets?: SecretPolicy }): TombstoneBlockResult {
    args = { ...args, ...guardFields({ reason: args.reason }, args.secrets ?? 'refuse', 'tombstone reason', 'reword the reason').fields };
    const run = this.db.transaction((): TombstoneBlockResult => {
      const old = this.requireLive(args.block_id);
      const doc = this.getDocumentById(old.doc_id)!;
      const revision = doc.current_revision + 1;
      const r = this.chain.append({
        event_type: 'block.tombstoned',
        actor_id: args.actor_id,
        payload: {
          block_id: old.block_id,
          doc_id: old.doc_id,
          doc_slug: doc.slug,
          revision,
          reason: args.reason,
        },
      });
      this.applyEvent(r.event);
      const head = this.emitRevised(doc, revision, args.actor_id, 'tombstone_block');
      this.logWrite(args.actor_id, old.doc_id, [old.block_id]);
      return { block_id: old.block_id, doc_slug: doc.slug, revision, head };
    });
    return run.immediate();
  }

  private emitRevised(doc: DocumentRow, revision: number, actor_id: string, cause: string): ChainHead {
    const live = this.liveBlocks(doc.doc_id).map((b) => ({
      kind: b.kind,
      level: b.kind === 'heading' ? headingLevelOf(b) : 0,
      content: b.content,
    }));
    const markdown = renderBlocks(live);
    const r = this.chain.append({
      event_type: 'document.revised',
      actor_id,
      payload: {
        doc_id: doc.doc_id,
        slug: doc.slug,
        title: doc.title,
        revision,
        markdown,
        markdown_hash: blake3Hex(markdown),
        cause,
      },
    });
    this.applyEvent(r.event);
    return r.head;
  }

  private requireLive(block_id: string): BlockRow {
    const b = this.getBlock(block_id);
    if (!b) throw new DocumentError('unknown_block', `no block ${block_id}`);
    if (b.tombstoned_at !== null) {
      throw new DocumentError('block_not_live', `block ${block_id} is tombstoned (${b.tombstone_reason ?? 'no reason'})`);
    }
    if (b.valid_to !== null) {
      throw new DocumentError(
        'block_not_live',
        `block ${block_id} is superseded by ${b.superseded_by ?? 'unknown'}; operate on the current head`,
      );
    }
    return b;
  }

  // ───────────────────────────── projection ─────────────────────────────

  /** Apply the lineage fields of one event (lineageEffects; malformed entries are skipped, never thrown). */
  private applyLineage(event_type: string, p: Record<string, unknown>, seq: number): void {
    const fx = lineageEffects(event_type, p);
    if (!fx) return;
    if (fx.replace) this.db.prepare(`DELETE FROM doc_lineage WHERE doc_id = ?`).run(fx.doc_id);
    const del = this.db.prepare(`DELETE FROM doc_lineage WHERE doc_id = ? AND source_block_id = ? AND inferred = 1`);
    for (const id of fx.release) del.run(fx.doc_id, id);
    const ins = this.db.prepare(`INSERT OR IGNORE INTO doc_lineage (doc_id, source_block_id, source_content_hash, inferred, chain_seq) VALUES (?, ?, ?, ?, ?)`);
    for (const a of fx.add) ins.run(fx.doc_id, a.block_id, a.content_hash, a.inferred, seq);
    if (fx.gap === 'clear') this.db.prepare(`DELETE FROM doc_lineage_gaps WHERE doc_id = ?`).run(fx.doc_id);
    else if (fx.gap === 'set') this.db.prepare(`INSERT INTO doc_lineage_gaps (doc_id, chain_seq) VALUES (?, ?) ON CONFLICT(doc_id) DO UPDATE SET chain_seq = excluded.chain_seq`).run(fx.doc_id, seq);
  }

  /** Apply one chain event to the derived tables. Idempotent per event. */
  applyEvent(ev: ChainEvent): void {
    const p = ev.payload as Record<string, unknown>;
    switch (ev.event_type) {
      case 'document.put':
      case 'document.revised': {
        const doc_id = p['doc_id'] as string;
        const slug = p['slug'] as string;
        const title = p['title'] as string;
        const revision = p['revision'] as number;
        const markdown = p['markdown'] as string;
        const markdown_hash = p['markdown_hash'] as string;
        this.db
          .prepare(
            `INSERT INTO documents (doc_id, slug, title, current_revision, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(doc_id) DO UPDATE SET title = excluded.title,
               current_revision = excluded.current_revision, updated_at = excluded.updated_at`,
          )
          .run(doc_id, slug, title, revision, ev.occurred_at, ev.occurred_at);
        this.db
          .prepare(
            `INSERT OR IGNORE INTO document_revisions (doc_id, revision, markdown, content_hash, chain_seq, created_at)
             VALUES (?, ?, ?, ?, ?, ?)`,
          )
          .run(doc_id, revision, markdown, markdown_hash, ev.seq, ev.occurred_at);
        const carried = (p['carried'] as { block_id: string; ordinal: number; heading_path: string[] }[] | undefined) ?? [];
        const upd = this.db.prepare(`UPDATE blocks SET ordinal = ?, heading_path = ? WHERE block_id = ?`);
        for (const c of carried) upd.run(c.ordinal, joinHeadingPath(c.heading_path), c.block_id);
        if (ev.event_type === 'document.put') {
          // Unreleased (next): the latest full put decides the project too.
          const src = p['source'] as DocumentSource | undefined;
          const proj = (src && typeof src === 'object' ? src.project?.key : undefined) ?? (p['project'] as { key?: unknown } | undefined)?.key;
          this.db.prepare(`UPDATE documents SET project_key = ? WHERE doc_id = ?`).run(typeof proj === 'string' ? proj : null, doc_id);
          // The latest full put decides provenance: a put without `source`
          // (every 0.3.0 put) clears any earlier binding.
          const source = p['source'] as DocumentSource | undefined;
          if (source && typeof source === 'object' && typeof source.kind === 'string' && typeof source.path === 'string') {
            this.db
              .prepare(
                `INSERT INTO doc_sources (doc_id, slug, revision, chain_seq, kind, path, source_json) VALUES (?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(doc_id) DO UPDATE SET slug = excluded.slug, revision = excluded.revision, chain_seq = excluded.chain_seq,
                   kind = excluded.kind, path = excluded.path, source_json = excluded.source_json`,
              )
              .run(doc_id, slug, revision, ev.seq, source.kind, source.path, JSON.stringify(source));
          } else {
            this.db.prepare(`DELETE FROM doc_sources WHERE doc_id = ?`).run(doc_id);
          }
          // Unreleased: an explicit derived_from (even []) replaces the lineage; inferred edges add.
          this.applyLineage(ev.event_type, p, ev.seq);
        }
        return;
      }
      case 'block.created': {
        this.db
          .prepare(
            `INSERT OR IGNORE INTO blocks (block_id, doc_id, revision, ordinal, kind, level, heading_path, content,
               content_hash, chain_seq, valid_from)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          )
          .run(
            p['block_id'],
            p['doc_id'],
            p['revision'],
            p['ordinal'],
            p['kind'],
            (p['level'] as number | undefined) ?? 0,
            joinHeadingPath(p['heading_path'] as string[]),
            p['content'],
            p['content_hash'],
            ev.seq,
            ev.occurred_at,
          );
        // Unreleased: supersede_block lineage adds to the document's.
        this.applyLineage(ev.event_type, p, ev.seq);
        return;
      }
      case 'block.superseded': {
        this.db
          .prepare(`UPDATE blocks SET valid_to = ?, superseded_by = ? WHERE block_id = ? AND valid_to IS NULL`)
          .run(ev.occurred_at, p['successor_block_id'], p['block_id']);
        return;
      }
      case 'block.tombstoned': {
        this.db
          .prepare(
            `UPDATE blocks SET tombstoned_at = ?, tombstone_reason = ?, valid_to = COALESCE(valid_to, ?)
              WHERE block_id = ? AND tombstoned_at IS NULL`,
          )
          .run(ev.occurred_at, p['reason'] ?? null, ev.occurred_at, p['block_id']);
        return;
      }
      case 'document.renamed': {
        // 0.5.0: same doc_id, new slug. Revisions and blocks are keyed by doc_id.
        this.db.prepare(`UPDATE documents SET slug = ?, updated_at = ? WHERE doc_id = ?`).run(p['slug'], ev.occurred_at, p['doc_id']);
        this.db.prepare(`UPDATE doc_sources SET slug = ? WHERE doc_id = ?`).run(p['slug'], p['doc_id']);
        return;
      }
      default:
        return; // unknown types (checkpoints, future vocab) have no projection
    }
  }
}

/**
 * 0.8.1: what one event does to a document's lineage projection
 * (doc_lineage + doc_lineage_gaps), shared by the projection and the
 * integrity replay so the two can never disagree. null: nothing.
 *   document.put: an explicit `derived_from` (even []) replaces the rows and
 *     clears a gap; `derived_from_released` drops earlier inferred edges;
 *     inferred edges add; `derived_from_inferred_truncated` (without an
 *     explicit statement) records a gap: the note's sources are undetermined.
 *   block.created (supersede_block): edges add; truncated inference without
 *     a non-empty explicit derived_from records a gap.
 */
export function lineageEffects(
  event_type: string,
  p: Record<string, unknown>,
): { doc_id: string; replace: boolean; release: string[]; add: (LineageRef & { inferred: 0 | 1 })[]; gap: 'set' | 'clear' | null } | null {
  if (event_type !== 'document.put' && event_type !== 'block.created') return null;
  const doc_id = p['doc_id'];
  if (typeof doc_id !== 'string') return null;
  const replace = event_type === 'document.put' && Array.isArray(p['derived_from']);
  const explicit = lineageRefs(p['derived_from']);
  const inferred = lineageRefs(p['derived_from_inferred']);
  const release = event_type === 'document.put' ? lineageRefs(p['derived_from_released']).map((r) => r.block_id) : [];
  const truncated = p['derived_from_inferred_truncated'] === true;
  const gap: 'set' | 'clear' | null = replace ? 'clear' : truncated && explicit.length === 0 ? 'set' : null;
  if (!replace && explicit.length + inferred.length + release.length === 0 && gap === null) return null;
  return {
    doc_id,
    replace,
    release,
    add: [...explicit.map((r) => ({ ...r, inferred: 0 as const })), ...inferred.map((r) => ({ ...r, inferred: 1 as const }))],
    gap,
  };
}

function lineageRefs(v: unknown): LineageRef[] {
  if (!Array.isArray(v)) return [];
  return v.filter((r): r is LineageRef => typeof r === 'object' && r !== null && typeof (r as LineageRef).block_id === 'string' && typeof (r as LineageRef).content_hash === 'string');
}

function headingLevelOf(b: BlockRow): number {
  return Math.max(1, Math.min(6, b.level || 1));
}

/** The supersession reason planRevision writes for a reorder within a section (0.8.1, step 1a). */
export const REORDERED_RE = /^reordered in revision \d+$/;

interface RevisionPlan {
  carried: { old: BlockRow; next: ParsedBlock }[];
  /** `reordered` (0.8.1): same text, same section, new position relative to its neighbours. */
  replaced: { old: BlockRow; next: ParsedBlock; reordered?: true }[];
  created: ParsedBlock[];
  tombstoned: BlockRow[];
}

/**
 * Deterministic diff between the live blocks and a freshly parsed revision.
 *   1. Same content_hash, kind AND heading_path → carried (block id
 *      preserved, position updated). A reorder of whole sections keeps
 *      every heading path, so it carries.
 *   1a. 0.8.1: inside one section (same heading_path) carried blocks must
 *      keep their relative order: order is meaning (runbook steps). The
 *      fewest blocks that changed order (those outside a longest increasing
 *      run of old positions) are superseded by an identical-text block
 *      (`reordered`), so receipts for them verify SUPERSEDED and orient
 *      lists "MOVED within …".
 *   1b. Unreleased: same content_hash and kind under a DIFFERENT heading
 *      path (the paragraph moved to another section, or an ancestor heading
 *      was renamed or re-levelled) → superseded by a block with the same
 *      text: "Allowed › X" → "Forbidden › X" is a change of meaning, so
 *      receipts for the old block verify as SUPERSEDED and orient lists it.
 *   2. Remaining old/new paired in order within the same (kind, heading_path).
 *   3. Leftover old → tombstoned; leftover new → created, except:
 *   3b. 0.8.1: a leftover non-heading old block closely matching a leftover
 *      new block of the same kind under another heading path (word-multiset
 *      Dice ≥ 0.6) is superseded by it: moved and edited, reported with
 *      `new_heading_path` and a diff instead of "REMOVED".
 */
export function planRevision(oldLive: readonly BlockRow[], next: readonly ParsedBlock[]): RevisionPlan {
  const plan: RevisionPlan = { carried: [], replaced: [], created: [], tombstoned: [] };
  const oldUnmatched = [...oldLive];
  const pending: ParsedBlock[] = [];

  for (const n of next) {
    const path = joinHeadingPath(n.heading_path);
    const i = oldUnmatched.findIndex((o) => o.content_hash === n.content_hash && o.kind === n.kind && o.heading_path === path);
    if (i >= 0) {
      plan.carried.push({ old: oldUnmatched[i]!, next: n });
      oldUnmatched.splice(i, 1);
    } else {
      pending.push(n);
    }
  }
  // 1a. Order within a section.
  const bySection = new Map<string, number[]>();
  plan.carried.forEach((c, k) => {
    const key = `${c.next.kind === 'heading' ? 'h' : 'b'}\u0000${c.old.heading_path}`;
    const list = bySection.get(key);
    if (list) list.push(k);
    else bySection.set(key, [k]);
  });
  const moved = new Set<number>();
  for (const ks of bySection.values()) {
    if (ks.length < 2) continue;
    const keep = longestIncreasing(ks.map((k) => plan.carried[k]!.old.ordinal));
    ks.forEach((k, idx) => {
      if (!keep.has(idx)) moved.add(k);
    });
  }
  if (moved.size > 0) {
    const stay: RevisionPlan['carried'] = [];
    plan.carried.forEach((c, k) => {
      if (moved.has(k)) plan.replaced.push({ old: c.old, next: c.next, reordered: true });
      else stay.push(c);
    });
    plan.carried = stay;
  }

  const newUnmatched: ParsedBlock[] = [];
  for (const n of pending) {
    const i = oldUnmatched.findIndex((o) => o.content_hash === n.content_hash && o.kind === n.kind);
    if (i >= 0) {
      plan.replaced.push({ old: oldUnmatched[i]!, next: n });
      oldUnmatched.splice(i, 1);
    } else {
      newUnmatched.push(n);
    }
  }

  for (const n of newUnmatched) {
    const key = joinHeadingPath(n.heading_path);
    const i = oldUnmatched.findIndex((o) => o.kind === n.kind && o.heading_path === key);
    if (i >= 0) {
      plan.replaced.push({ old: oldUnmatched[i]!, next: n });
      oldUnmatched.splice(i, 1);
    } else {
      plan.created.push(n);
    }
  }
  // 3b. (0.8.1) Moved AND edited: a leftover old block whose text reappears, closely, as a leftover
  //     new block of the same kind under another heading path is superseded by it (a move with a
  //     diff), not tombstoned with no successor. Headings are not paired (a renamed heading is a
  //     removal plus an addition). Close = word-multiset Dice ≥ MOVE_MIN_SIMILARITY, best match first.
  if (plan.created.length > 0 && oldUnmatched.length > 0 && plan.created.length * oldUnmatched.length <= 10_000) {
    const bags = new Map<string, Map<string, number>>();
    const bag = (key: string, text: string) => {
      let b = bags.get(key);
      if (!b) {
        b = new Map();
        for (const w of text.split(/\s+/)) if (w) b.set(w, (b.get(w) ?? 0) + 1);
        bags.set(key, b);
      }
      return b;
    };
    const dice = (a: Map<string, number>, b: Map<string, number>) => {
      let na = 0;
      let nb = 0;
      let both = 0;
      for (const v of a.values()) na += v;
      for (const v of b.values()) nb += v;
      for (const [w, v] of a) both += Math.min(v, b.get(w) ?? 0);
      return na + nb === 0 ? 0 : (2 * both) / (na + nb);
    };
    const stillCreated: ParsedBlock[] = [];
    for (const n of plan.created) {
      if (n.kind === 'heading') {
        stillCreated.push(n);
        continue;
      }
      const nb = bag(`n${n.ordinal}`, n.content);
      let best = -1;
      let bestScore = MOVE_MIN_SIMILARITY;
      oldUnmatched.forEach((o, i) => {
        if (o.kind !== n.kind || o.heading_path === joinHeadingPath(n.heading_path)) return;
        const sc = dice(bag(`o${o.block_id}`, o.content), nb);
        if (sc >= bestScore && (best < 0 || sc > bestScore)) {
          best = i;
          bestScore = sc;
        }
      });
      if (best >= 0) {
        plan.replaced.push({ old: oldUnmatched[best]!, next: n });
        oldUnmatched.splice(best, 1);
      } else {
        stillCreated.push(n);
      }
    }
    plan.created = stillCreated;
  }
  plan.tombstoned = oldUnmatched;
  return plan;
}

/** 0.8.1: how close (word-multiset Dice) a block under a new heading path must be to count as the same block moved and edited. */
export const MOVE_MIN_SIMILARITY = 0.6;

/** Indices (into `xs`) of one longest strictly increasing subsequence; ties keep the earliest. O(n log n). */
function longestIncreasing(xs: readonly number[]): Set<number> {
  const tails: number[] = []; // index into xs of the smallest tail of a run of each length
  const prev: number[] = new Array<number>(xs.length).fill(-1);
  for (let i = 0; i < xs.length; i++) {
    let lo = 0;
    let hi = tails.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (xs[tails[mid]!]! < xs[i]!) lo = mid + 1;
      else hi = mid;
    }
    if (lo > 0) prev[i] = tails[lo - 1]!;
    tails[lo] = i;
  }
  const out = new Set<number>();
  for (let k = tails.length > 0 ? tails[tails.length - 1]! : -1; k >= 0; k = prev[k]!) out.add(k);
  return out;
}
