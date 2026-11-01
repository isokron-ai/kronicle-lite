/**
 * Honest absence (0.6.0). Ported from IsoKron
 * packages/sb1-substrate-shapes/src/certify-absence.ts: "searched, found
 * nothing" is a different answer from "not searched", and an index that is
 * stale or cold never certifies "not found" (coverage ≠ freshness).
 *
 * Every recall result carries `absence`. Its verdict:
 *   found               at least one hit
 *   absent_in_searched  no hit, every searched scope was indexed and fresh,
 *                       nothing was withheld; names the scopes NOT searched
 *   cannot_certify      no hit, but the index is stale/cold, matches were
 *                       withheld for integrity, or nothing was searched
 * There is no global "absent": recall never searches superseded blocks, and
 * tombstoned ones only on request.
 */

import type { Db } from '../db/open.js';

/** `other_projects` (unreleased, next): documents of other projects, skipped by a project-scoped recall. */
export const RECALL_SCOPES = ['live_blocks', 'tombstoned_blocks', 'superseded_blocks', 'other_projects'] as const;
export type RecallScope = (typeof RECALL_SCOPES)[number];

export const ABSENCE_VERDICTS = ['found', 'absent_in_searched', 'cannot_certify'] as const;
export type AbsenceVerdict = (typeof ABSENCE_VERDICTS)[number];

export interface Absence {
  searched: RecallScope[];
  not_searched: RecallScope[];
  /** The full-text index covers every block and the projection is at the chain's last document event. */
  index_fresh: boolean;
  verdict: AbsenceVerdict;
  reason: string;
}

export function certifyRecallAbsence(i: {
  hits: number;
  withheld: number;
  searched: RecallScope[];
  not_searched: RecallScope[];
  index_fresh: boolean;
  index_detail?: string | null;
}): Absence {
  const base = { searched: i.searched, not_searched: i.not_searched, index_fresh: i.index_fresh };
  const ns = i.not_searched.length > 0 ? `; not searched: ${i.not_searched.join(', ')}` : '';
  if (i.hits > 0) return { ...base, verdict: 'found', reason: `${i.hits} hit(s) in ${i.searched.join(', ')}${ns}` };
  if (i.searched.length === 0) return { ...base, verdict: 'cannot_certify', reason: 'the query has no searchable terms: nothing was searched' };
  if (!i.index_fresh) {
    return { ...base, verdict: 'cannot_certify', reason: `the search index is stale or cold (${i.index_detail ?? 'not fresh'}): no hit is not evidence of absence; run kronicle-lite verify-chain / rebuild` };
  }
  if (i.withheld > 0) return { ...base, verdict: 'cannot_certify', reason: `${i.withheld} match(es) withheld for failing their integrity check: the text exists but cannot be served` };
  return { ...base, verdict: 'absent_in_searched', reason: `searched ${i.searched.join(', ')} with a fresh index: nothing matched${ns}` };
}

/**
 * Is the index the search ran on current? Two cheap checks:
 *  - the projection has the revision of the chain's latest document.put /
 *    document.revised event (a lost or unapplied revision means stale);
 *  - the FTS index holds one row per block (a dropped or emptied index is cold).
 */
export function indexFreshness(db: Db): { fresh: boolean; detail: string | null } {
  const lastDoc = (
    db.prepare(`SELECT MAX(seq) AS s FROM events WHERE event_type IN ('document.put', 'document.revised')`).get() as { s: number | null }
  ).s;
  const projected = (db.prepare(`SELECT MAX(chain_seq) AS s FROM document_revisions`).get() as { s: number | null }).s;
  if ((lastDoc ?? 0) > (projected ?? 0)) return { fresh: false, detail: `projection at seq ${projected ?? 0}, chain has a document event at seq ${lastDoc}` };
  const blocks = (db.prepare(`SELECT count(*) AS n FROM blocks`).get() as { n: number }).n;
  let indexed: number;
  try {
    indexed = (db.prepare(`SELECT count(*) AS n FROM blocks_fts_docsize`).get() as { n: number }).n;
  } catch {
    return { fresh: false, detail: 'full-text index missing' };
  }
  if (indexed !== blocks) return { fresh: false, detail: `full-text index holds ${indexed} of ${blocks} block(s)` };
  return { fresh: true, detail: null };
}
