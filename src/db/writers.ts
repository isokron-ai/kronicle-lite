/**
 * 0.8.1 (C2-01): did an older kronicle-lite write this store?
 *
 * Versions up to 0.8.0 record nothing about themselves, and every one of
 * them opens and writes a newer store without complaint. Two traces remain:
 *
 * - events appended after the last append made by 0.8.1 or later
 *   (`meta.writer_head_seq`, updated in every append's transaction);
 * - `documents.project_key` that differs from what the chain derives (the
 *   latest document.put's `source.project.key` or `project.key`). 0.5.0 /
 *   0.6.0 `rebuild` null every key, and 0.6.0 / 0.7.0 puts next to newer
 *   ones leave keys that a rebuild would not produce. Recall and orient scope
 *   by this column, so a wrong key leaks one project's notes into another.
 *
 * `kronicle-lite rebuild` (0.8.1) re-derives the projection from the chain
 * and repairs both kinds of damage it can see.
 */

import type { Db } from './open.js';

export interface WriterReport {
  /** Version of the last 0.8.1+ append (null: never written by 0.8.1 or later). */
  writer_version: string | null;
  writer_head_seq: number | null;
  head_seq: number;
  /** Events appended by a version that does not record itself (0.8.0 or older), when known. */
  unrecorded_events: { from_seq: number; to_seq: number } | null;
  project_key_mismatches: { slug: string; live: string | null; derived: string | null }[];
  project_key_mismatch_count: number;
}

const MAX_LISTED = 20;

function meta(db: Db, key: string): string | null {
  const r = db.prepare(`SELECT value FROM meta WHERE key = ?`).get(key) as { value: string } | undefined;
  return r?.value ?? null;
}

export function checkWriters(db: Db): WriterReport {
  const head = (db.prepare(`SELECT seq FROM chain_head WHERE id = 1`).get() as { seq: number } | undefined)?.seq ?? 0;
  const writer_version = meta(db, 'writer_version');
  const whs = meta(db, 'writer_head_seq');
  const writer_head_seq = whs === null ? null : Number(whs);
  const unrecorded_events = writer_head_seq !== null && head > writer_head_seq ? { from_seq: writer_head_seq + 1, to_seq: head } : null;

  // The latest full put per document decides its project (docs/documents.ts applyEvent).
  const derived = new Map<string, string | null>();
  const rows = db
    .prepare(
      `SELECT json_extract(payload_canonical, '$.doc_id') AS doc_id,
              json_extract(payload_canonical, '$.source.project.key') AS sk,
              json_extract(payload_canonical, '$.project.key') AS pk
         FROM events WHERE event_type = 'document.put' ORDER BY seq`,
    )
    .iterate() as Iterable<{ doc_id: unknown; sk: unknown; pk: unknown }>;
  for (const r of rows) {
    if (typeof r.doc_id !== 'string') continue;
    const k = r.sk ?? r.pk;
    derived.set(r.doc_id, typeof k === 'string' ? k : null);
  }
  const mismatches: WriterReport['project_key_mismatches'] = [];
  let count = 0;
  for (const d of db.prepare(`SELECT doc_id, slug, project_key FROM documents ORDER BY slug`).iterate() as Iterable<{ doc_id: string; slug: string; project_key: string | null }>) {
    if (!derived.has(d.doc_id)) continue;
    const want = derived.get(d.doc_id) ?? null;
    if ((d.project_key ?? null) === want) continue;
    count++;
    if (mismatches.length < MAX_LISTED) mismatches.push({ slug: d.slug, live: d.project_key ?? null, derived: want });
  }
  return { writer_version, writer_head_seq, head_seq: head, unrecorded_events, project_key_mismatches: mismatches, project_key_mismatch_count: count };
}

/** One line for doctor / verify-chain; null when nothing older was seen. */
export function describeWriters(r: WriterReport): { status: 'ok' | 'warn' | 'fail'; detail: string } {
  if (r.project_key_mismatch_count > 0) {
    const ex = r.project_key_mismatches.slice(0, 3).map((m) => `${m.slug} (${m.live ?? 'null'}, chain says ${m.derived ?? 'null'})`).join(', ');
    return {
      status: 'fail',
      detail:
        `${r.project_key_mismatch_count} document(s) carry a project key the chain does not derive — an older kronicle-lite rebuilt or wrote this store, ` +
        `so project scoping (recall, orient) is wrong: ${ex}; run kronicle-lite rebuild (0.9.0 or later)`,
    };
  }
  if (r.unrecorded_events) {
    return {
      status: 'warn',
      detail: `events ${r.unrecorded_events.from_seq}..${r.unrecorded_events.to_seq} were appended by a kronicle-lite older than 0.9.0 (last 0.9.0+ write: ${r.writer_version} at seq ${r.writer_head_seq}); keep every client on 0.9.0 or later`,
    };
  }
  return { status: 'ok', detail: r.writer_version ? `last written by ${r.writer_version} (seq ${r.writer_head_seq}); project keys match the chain` : 'project keys match the chain' };
}
