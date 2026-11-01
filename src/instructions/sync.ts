/**
 * Chain an instruction file: re-put it when its content differs from the
 * stored current revision. A changed file becomes a new revision whose
 * changed blocks are superseded (and removed blocks tombstoned), so the next
 * orient lists them as retractions of kind `instruction`. A deleted file is
 * re-put empty (every block tombstoned). An unchanged file appends nothing.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { extname, join, resolve } from 'node:path';

import { blake3Hex } from '../crypto/hash.js';
import { normalizeMarkdown } from '../docs/parser.js';
import type { ChainHead } from '../chain/chain.js';
import { redactSecrets, type SecretPolicy } from '../secrets/guard.js';
import type { KronicleLite } from '../store.js';
import { git } from '../git/git.js';
import { entryFor, type InstructionEntry, type ResolvedContext } from './paths.js';

/** Claude Code skips CLAUDE.md files over 4 MiB; so do we. */
export const MAX_INSTRUCTION_BYTES = 4 * 1024 * 1024;

/** `renamed` (unreleased, next): the file moved with its content intact; the document followed it (`document.renamed`). */
export type SyncAction = 'created' | 'updated' | 'unchanged' | 'removed' | 'renamed' | 'missing' | 'too_large' | 'error';

/**
 * 0.5.0 migration: adopt the 0.4.0 un-keyed document (`instructions/claude-md`)
 * for this project when it still holds exactly this file's text and was
 * recorded from the same relative path. The document is renamed in place
 * (`document.renamed`), so its blocks, receipts and supersession history
 * carry over. Anything else leaves the legacy document alone: with one
 * shared data dir it may hold another project's file.
 */
function adoptLegacy(store: KronicleLite, entry: InstructionEntry, normalizedHash: string | null, actor_id: string): string | null {
  if (!entry.legacySlug || entry.legacySlug === entry.slug || normalizedHash === null) return null;
  if (store.docs.getDocument(entry.slug)) return null;
  const legacy = store.docs.getDocument(entry.legacySlug);
  if (!legacy) return null;
  const src = store.docs.getSource(legacy.doc_id);
  if (src?.source.path !== entry.recordPath || src.source.project !== undefined) return null;
  if (store.docs.currentMarkdownHash(entry.legacySlug) !== normalizedHash) return null;
  store.docs.renameDocument({
    doc_id: legacy.doc_id,
    slug: entry.slug,
    actor_id,
    reason: `0.5.0 project key: ${entry.project?.root ?? 'unknown project'}`,
  });
  return entry.legacySlug;
}

export interface SyncResult {
  slug: string;
  path: string;
  kind: InstructionEntry['kind'];
  action: SyncAction;
  revision: number | null;
  created: number;
  superseded: number;
  tombstoned: number;
  head: ChainHead;
  error?: string;
  /** 0.5.0: the legacy slug this document was renamed from in this sync. */
  migrated_from?: string;
  /** Unreleased (next): with action `renamed`, the document's previous slug and path. */
  renamed_from?: { slug: string; path: string };
}

function readText(path: string): { text: string } | { missing: true } | { tooLarge: number } {
  let size: number;
  try {
    const st = statSync(path);
    if (!st.isFile()) return { missing: true };
    size = st.size;
  } catch {
    return { missing: true };
  }
  if (size > MAX_INSTRUCTION_BYTES) return { tooLarge: size };
  try {
    return { text: readFileSync(path, 'utf8').replace(/^\uFEFF/, '') };
  } catch {
    return { missing: true };
  }
}

/**
 * 0.6.0: `secrets` (default `refuse`) applies the write-time secret guard. A
 * refused file syncs as `action: 'error'` (`secret_detected: …`) and nothing is
 * chained; `redact` chains a redacted copy and compares the redacted text on
 * later syncs, so an unchanged file stays `unchanged`.
 */
export interface SyncOptions {
  actor_id?: string;
  secrets?: SecretPolicy;
  /**
   * Unreleased (next): the resolved project context. With it, a file that
   * moved inside the project with its content intact is a rename
   * (`document.renamed`, block ids kept, no retraction) instead of a removal
   * plus a new document — whichever of the two paths is synced first.
   */
  context?: ResolvedContext;
}

export function syncInstructionFile(store: KronicleLite, entry: InstructionEntry, opts: SyncOptions = {}): SyncResult {
  const actor_id = opts.actor_id ?? 'instructions';
  const base: Pick<SyncResult, 'slug' | 'path' | 'kind' | 'created' | 'superseded' | 'tombstoned' | 'migrated_from'> = {
    slug: entry.slug,
    path: entry.recordPath,
    kind: entry.kind,
    created: 0,
    superseded: 0,
    tombstoned: 0,
  };
  try {
    const read = readText(entry.path);
    const migrated = adoptLegacy(store, entry, 'text' in read ? blake3Hex(normalizeMarkdown(read.text)) : null, actor_id);
    if (migrated) base.migrated_from = migrated;
    const existing = store.docs.getDocument(entry.slug);
    if ('tooLarge' in read) {
      return { ...base, action: 'too_large', revision: existing?.current_revision ?? null, head: store.chain.head(), error: `${read.tooLarge} bytes > 4 MiB` };
    }
    let markdown: string;
    let removing = false;
    if ('missing' in read) {
      // Never stored, or already emptied: nothing to retract.
      if (!existing || store.docs.liveBlocks(existing.doc_id).length === 0) {
        return { ...base, action: 'missing', revision: existing?.current_revision ?? null, head: store.chain.head() };
      }
      // Moved, not deleted? Follow the content to its new path.
      if (opts.context) {
        const to = findMovedCopy(store, entry, opts.context, opts.secrets);
        if (to) {
          const moved = followRename(store, existing.doc_id, entry, to.entry, to.text, actor_id, opts.secrets);
          if (moved) return moved;
        }
      }
      markdown = '';
      removing = true;
    } else {
      markdown = read.text;
      const stored = opts.secrets === 'redact' ? redactSecrets(markdown).text : markdown;
      const hash = blake3Hex(normalizeMarkdown(stored));
      const src = existing ? store.docs.getSource(existing.doc_id) : null;
      if (
        existing &&
        store.docs.currentMarkdownHash(entry.slug) === hash &&
        src?.source.path === entry.recordPath &&
        src.source.project?.key === entry.project?.key
      ) {
        return { ...base, action: 'unchanged', revision: existing.current_revision, head: store.chain.head() };
      }
      // A new path whose exact content belongs to a document whose file is gone: a move.
      if (!existing && opts.context) {
        const from = findMovedOrigin(store, entry, hash, opts.context);
        if (from) {
          const moved = followRename(store, from.doc_id, from.entry, entry, markdown, actor_id, opts.secrets);
          if (moved) return moved;
        }
      }
    }
    const r = store.docs.putDocument({
      slug: entry.slug,
      title: entry.title,
      markdown,
      actor_id,
      source: { kind: entry.kind, path: entry.recordPath, ...(entry.project ? { project: entry.project } : {}) },
      ...(opts.secrets !== undefined ? { secrets: opts.secrets } : {}),
      // A file import is the file's text, not something the importing actor derived from its reads.
      infer_lineage: false,
    });
    let created = 0;
    let superseded = 0;
    let tombstoned = 0;
    for (const b of r.blocks) {
      if (b.status === 'tombstoned') tombstoned++;
      else if (b.status === 'created' && b.supersedes) superseded++;
      else if (b.status === 'created') created++;
    }
    return {
      ...base,
      action: removing ? 'removed' : existing ? 'updated' : 'created',
      revision: r.revision,
      created,
      superseded,
      tombstoned,
      head: r.head,
    };
  } catch (err) {
    return { ...base, action: 'error', revision: null, head: store.chain.head(), error: err instanceof Error ? err.message : String(err) };
  }
}

/** One line per result for CLI logs and hook system messages. */
export function describeSync(r: SyncResult): string {
  const counts = `${r.superseded} superseded, ${r.created} created, ${r.tombstoned} tombstoned`;
  switch (r.action) {
    case 'created':
      return `${r.slug} ← ${r.path}: imported as rev ${r.revision} (${r.created} block(s))`;
    case 'updated':
      return `${r.slug} ← ${r.path}: rev ${r.revision} (${counts})${r.migrated_from ? `; renamed from ${r.migrated_from}` : ''}`;
    case 'removed':
      return `${r.slug} ← ${r.path}: file removed; rev ${r.revision} retires ${r.tombstoned} block(s)`;
    case 'renamed':
      return `${r.slug} ← ${r.path}: moved from ${r.renamed_from?.path ?? '?'} with its content intact; same document, block ids kept (rev ${r.revision})`;
    case 'unchanged':
      return `${r.slug} ← ${r.path}: unchanged (rev ${r.revision})`;
    case 'missing':
      return `${r.slug} ← ${r.path}: not present`;
    case 'too_large':
      return `${r.slug} ← ${r.path}: skipped (${r.error})`;
    case 'error':
      return `${r.slug} ← ${r.path}: error: ${r.error}`;
  }
}

// ───────────────────────────── renames (unreleased, next) ─────────────────────────────

const MAX_CANDIDATES_HASHED = 200;
const MAX_WALK_FILES = 5000;

/** Files under the project root a moved instruction file could now be at (git-aware, else a bounded walk). */
function projectFiles(root: string): string[] {
  const listed = git(['ls-files', '-z', '--cached', '--others', '--exclude-standard'], root, { trim: false });
  if (listed !== null) return listed.split('\0').filter((f) => f.length > 0).map((f) => resolve(root, f));
  const out: string[] = [];
  const walk = (dir: string, depth: number) => {
    if (depth > 8 || out.length >= MAX_WALK_FILES) return;
    let names: string[];
    try {
      names = readdirSync(dir);
    } catch {
      return;
    }
    for (const n of names) {
      if (n === '.git' || n === 'node_modules') continue;
      const full = join(dir, n);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) walk(full, depth + 1);
      else if (st.isFile()) out.push(full);
    }
  };
  walk(root, 0);
  return out;
}

function storedHash(text: string, secrets: SecretPolicy | undefined): string {
  return blake3Hex(normalizeMarkdown(secrets === 'redact' ? redactSecrets(text).text : text));
}

/**
 * The deleted file's content, intact, at another path in the same project
 * that is not already its own live document. null when there is none, or
 * more than one (ambiguous: treat as a removal).
 */
function findMovedCopy(
  store: KronicleLite,
  gone: InstructionEntry,
  rc: ResolvedContext,
  secrets: SecretPolicy | undefined,
): { entry: InstructionEntry; text: string } | null {
  if (gone.kind !== 'instruction' || !gone.project) return null;
  const want = store.docs.currentMarkdownHash(gone.slug);
  const doc = store.docs.getDocument(gone.slug);
  if (!want || !doc) return null;
  const rev = store.docs.getRevision(doc.doc_id, doc.current_revision);
  if (!rev) return null;
  const size = Buffer.byteLength(rev.markdown);
  const ext = extname(gone.path).toLowerCase();
  const hits: { entry: InstructionEntry; text: string }[] = [];
  let hashed = 0;
  for (const f of projectFiles(gone.project.root)) {
    if (f === gone.path || extname(f).toLowerCase() !== ext) continue;
    let st;
    try {
      st = statSync(f);
    } catch {
      continue;
    }
    // Normalization only trims trailing whitespace and line endings.
    if (st.size < size || st.size > size * 1.25 + 256) continue;
    if (++hashed > MAX_CANDIDATES_HASHED) break;
    const read = readText(f);
    if (!('text' in read) || storedHash(read.text, secrets) !== want) continue;
    const entry = entryFor(f, rc);
    if (entry.project?.key !== gone.project.key || entry.kind !== gone.kind) continue;
    const there = store.docs.getDocument(entry.slug);
    if (there && store.docs.liveBlocks(there.doc_id).length > 0) continue; // a copy that already existed, not a move
    hits.push({ entry, text: read.text });
  }
  return hits.length === 1 ? hits[0]! : null;
}

/** A live instruction document of this project whose file is gone and whose text hashes to `hash`. */
function findMovedOrigin(store: KronicleLite, arrived: InstructionEntry, hash: string, rc: ResolvedContext): { doc_id: string; entry: InstructionEntry } | null {
  if (arrived.kind !== 'instruction' || !arrived.project) return null;
  const hits: { doc_id: string; entry: InstructionEntry }[] = [];
  for (const src of store.docs.sourcesWithCurrentHash(hash, arrived.kind, arrived.project.key)) {
    if (src.source.project?.key !== arrived.project.key || src.slug === arrived.slug) continue;
    const oldPath = resolve(arrived.project.root, src.source.path);
    if (!('missing' in readText(oldPath))) continue; // still there: a copy, not a move
    if (store.docs.liveBlocks(src.doc_id).length === 0) continue;
    hits.push({ doc_id: src.doc_id, entry: entryFor(oldPath, rc) });
  }
  return hits.length === 1 ? hits[0]! : null;
}

/** document.renamed to the new slug, then a put recording the new path (every block carried). */
function followRename(
  store: KronicleLite,
  doc_id: string,
  from: InstructionEntry,
  to: InstructionEntry,
  text: string,
  actor_id: string,
  secrets: SecretPolicy | undefined,
): SyncResult | null {
  if (store.docs.getDocument(to.slug)) return null; // slug taken (e.g. an emptied document): plain removal + import
  try {
    store.docs.renameDocument({ doc_id, slug: to.slug, actor_id, reason: `moved: ${from.recordPath} → ${to.recordPath} (same content)` });
  } catch {
    return null;
  }
  const r = store.docs.putDocument({
    slug: to.slug,
    title: to.title,
    markdown: text,
    actor_id,
    source: { kind: to.kind, path: to.recordPath, ...(to.project ? { project: to.project } : {}) },
    ...(secrets !== undefined ? { secrets } : {}),
    infer_lineage: false,
  });
  let created = 0;
  let superseded = 0;
  let tombstoned = 0;
  for (const b of r.blocks) {
    if (b.status === 'tombstoned') tombstoned++;
    else if (b.status === 'created' && b.supersedes) superseded++;
    else if (b.status === 'created') created++;
  }
  return {
    slug: to.slug,
    path: to.recordPath,
    kind: to.kind,
    action: 'renamed',
    revision: r.revision,
    created,
    superseded,
    tombstoned,
    head: r.head,
    renamed_from: { slug: from.slug, path: from.recordPath },
  };
}
