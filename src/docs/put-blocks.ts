/**
 * 0.8.1 (P2-02): the full block list of one document revision, as
 * put_document reports it (created / unchanged / tombstoned, `supersedes` on
 * a replacement), re-derived from the store so a large put can answer with a
 * summary and point here for the rest.
 *
 * Live blocks at revision R come from the R `document.put` event
 * (`block_ids`, `carried`); blocks created in R carry revision R; the blocks
 * R tombstoned carry the reason put_document writes ("removed in revision R").
 * Order: ordinal, then status, the same as put_document's `blocks`.
 */

import type { BlockSummary } from './documents.js';
import { splitHeadingPath } from './documents.js';
import type { Db } from '../db/open.js';

interface Row {
  block_id: string;
  revision: number;
  ordinal: number;
  kind: BlockSummary['kind'];
  heading_path: string;
  content_hash: string;
  superseded_by: string | null;
  tombstone_reason: string | null;
}

export interface RevisionBlocks {
  doc_id: string;
  slug: string;
  revision: number;
  blocks: BlockSummary[];
}

/** null when the document or revision does not exist. */
export function revisionBlocks(db: Db, slug: string, revision: number): RevisionBlocks | null {
  const doc = db.prepare(`SELECT doc_id FROM documents WHERE slug = ?`).get(slug) as { doc_id: string } | undefined;
  if (!doc) return null;
  const rev = db.prepare(`SELECT chain_seq FROM document_revisions WHERE doc_id = ? AND revision = ?`).get(doc.doc_id, revision) as { chain_seq: number } | undefined;
  if (!rev) return null;
  const ev = db.prepare(`SELECT event_type, payload_canonical FROM events WHERE seq = ?`).get(rev.chain_seq) as { event_type: string; payload_canonical: string } | undefined;
  let liveIds: string[] = [];
  const carried = new Map<string, { ordinal: number; heading_path: string[] }>();
  if (ev) {
    try {
      const p = JSON.parse(ev.payload_canonical) as { block_ids?: unknown; carried?: unknown };
      if (Array.isArray(p.block_ids)) liveIds = p.block_ids.filter((x): x is string => typeof x === 'string');
      if (Array.isArray(p.carried)) {
        for (const c of p.carried as { block_id?: unknown; ordinal?: unknown; heading_path?: unknown }[]) {
          if (typeof c.block_id === 'string' && typeof c.ordinal === 'number' && Array.isArray(c.heading_path)) {
            carried.set(c.block_id, { ordinal: c.ordinal, heading_path: c.heading_path.map(String) });
          }
        }
      }
    } catch {
      // an unparseable put payload: fall back to the rows of this revision
    }
  }
  const rows = db
    .prepare(`SELECT block_id, revision, ordinal, kind, heading_path, content_hash, superseded_by, tombstone_reason FROM blocks WHERE doc_id = ?`)
    .all(doc.doc_id) as Row[];
  const byId = new Map(rows.map((r) => [r.block_id, r]));
  const supersedes = new Map<string, string>();
  for (const r of rows) if (r.superseded_by) supersedes.set(r.superseded_by, r.block_id);

  const out: BlockSummary[] = [];
  const live = liveIds.length > 0 ? liveIds : rows.filter((r) => r.revision === revision && !r.tombstone_reason).map((r) => r.block_id);
  live.forEach((id, i) => {
    const r = byId.get(id);
    if (!r) return;
    const c = carried.get(id);
    const created = r.revision === revision && !c;
    out.push({
      block_id: id,
      ordinal: c?.ordinal ?? (liveIds.length > 0 ? i : r.ordinal),
      kind: r.kind,
      heading_path: c?.heading_path ?? splitHeadingPath(r.heading_path),
      content_hash: r.content_hash,
      status: created ? 'created' : 'unchanged',
      ...(created && supersedes.has(id) ? { supersedes: supersedes.get(id)! } : {}),
    });
  });
  const reason = `removed in revision ${revision}`;
  for (const r of rows) {
    if (r.tombstone_reason !== reason) continue;
    out.push({ block_id: r.block_id, ordinal: r.ordinal, kind: r.kind, heading_path: splitHeadingPath(r.heading_path), content_hash: r.content_hash, status: 'tombstoned' });
  }
  out.sort((a, b) => a.ordinal - b.ordinal || a.status.localeCompare(b.status));
  return { doc_id: doc.doc_id, slug, revision, blocks: out };
}
