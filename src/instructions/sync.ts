/**
 * Chain an instruction file: re-put it when its content differs from the
 * stored current revision. A changed file becomes a new revision whose
 * changed blocks are superseded (and removed blocks tombstoned), so the next
 * orient lists them as retractions of kind `instruction`. A deleted file is
 * re-put empty (every block tombstoned). An unchanged file appends nothing.
 */

import { readFileSync, statSync } from 'node:fs';

import { blake3Hex } from '../crypto/hash.js';
import { normalizeMarkdown } from '../docs/parser.js';
import type { ChainHead } from '../chain/chain.js';
import { redactSecrets, type SecretPolicy } from '../secrets/guard.js';
import type { KronicleLite } from '../store.js';
import type { InstructionEntry } from './paths.js';

/** Claude Code skips CLAUDE.md files over 4 MiB; so do we. */
export const MAX_INSTRUCTION_BYTES = 4 * 1024 * 1024;

export type SyncAction = 'created' | 'updated' | 'unchanged' | 'removed' | 'missing' | 'too_large' | 'error';

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
export function syncInstructionFile(store: KronicleLite, entry: InstructionEntry, opts: { actor_id?: string; secrets?: SecretPolicy } = {}): SyncResult {
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
    }
    const r = store.docs.putDocument({
      slug: entry.slug,
      title: entry.title,
      markdown,
      actor_id,
      source: { kind: entry.kind, path: entry.recordPath, ...(entry.project ? { project: entry.project } : {}) },
      ...(opts.secrets !== undefined ? { secrets: opts.secrets } : {}),
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
