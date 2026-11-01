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
import { blake3Hex } from '../crypto/hash.js';
import { checkGitBinding, type DiffStat, type SourceState } from '../git/binding.js';
import type { Db } from '../db/open.js';
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
}

export interface SupersedeBlockResult {
  old_block_id: string;
  new_block_id: string;
  content_hash: string;
  doc_slug: string;
  revision: number;
  head: ChainHead;
  /** 0.6.0: present when secrets: 'redact' replaced something before chaining. */
  redactions?: SecretFinding[];
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
    readonly code: 'unknown_block' | 'block_not_live' | 'unknown_document' | 'invalid_slug' | 'empty_content' | 'invalid_source',
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
  constructor(
    private readonly db: Db,
    private readonly chain: Chain,
  ) {}

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
             AND json_extract(payload_canonical, '$.block_id') = ? LIMIT 1`,
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

    const run = this.db.transaction((): PutDocumentResult => {
      const existing = this.getDocument(args.slug);
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
            reason: `replaced in revision ${revision}`,
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

      return {
        doc_id,
        slug: args.slug,
        title: args.title,
        revision,
        chain_seq: first.event.seq,
        head,
        blocks: summaries,
        events: pending.length,
      };
    });
    const result = run.immediate();
    return guarded.redactions.length > 0 ? { ...result, redactions: guarded.redactions } : result;
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
  }): SupersedeBlockResult {
    const guarded = guardFields({ new_content: args.new_content, reason: args.reason }, args.secrets ?? 'refuse', `block content`);
    args = { ...args, ...guarded.fields };
    const content = normalizeMarkdown(args.new_content).trim();
    if (content.length === 0) throw new DocumentError('empty_content', 'new_content is empty');
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
      return { old_block_id: old.block_id, new_block_id, content_hash, doc_slug: doc.slug, revision, head };
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

function headingLevelOf(b: BlockRow): number {
  return Math.max(1, Math.min(6, b.level || 1));
}

interface RevisionPlan {
  carried: { old: BlockRow; next: ParsedBlock }[];
  replaced: { old: BlockRow; next: ParsedBlock }[];
  created: ParsedBlock[];
  tombstoned: BlockRow[];
}

/**
 * Deterministic diff between the live blocks and a freshly parsed revision.
 *   1. Same content_hash → carried (block id preserved, position updated).
 *   2. Remaining old/new paired in order within the same (kind, heading_path).
 *   3. Leftover old → tombstoned; leftover new → created.
 */
export function planRevision(oldLive: readonly BlockRow[], next: readonly ParsedBlock[]): RevisionPlan {
  const plan: RevisionPlan = { carried: [], replaced: [], created: [], tombstoned: [] };
  const oldUnmatched = [...oldLive];
  const newUnmatched: ParsedBlock[] = [];

  for (const n of next) {
    const i = oldUnmatched.findIndex((o) => o.content_hash === n.content_hash && o.kind === n.kind);
    if (i >= 0) {
      plan.carried.push({ old: oldUnmatched[i]!, next: n });
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
  plan.tombstoned = oldUnmatched;
  return plan;
}
