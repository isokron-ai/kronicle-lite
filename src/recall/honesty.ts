/**
 * Retrieval honesty tags (0.6.0). Ported from IsoKron
 * packages/reality/src/retrieval-honesty-tags.ts (tier → action authority,
 * meet-floor of the set) and packages/library-retrieval/src/c1-inherit-ladder.ts
 * (the C-1 cliff: trust inherited from a document never reaches can_act).
 * Pure; no I/O. docs/HONESTY.md states the same table (a test keeps the two
 * in step).
 *
 * The labels answer "may I act on this text without checking further?":
 *   can_act       this exact block text is, right now, the text of its
 *                 recorded source file (checked per block, at recall time)
 *   inspect_only  read it and reason with it; verify before acting
 *   never_act     do not act on it: retired, drifted, missing or failed integrity
 *
 * can_act says the text is current and sourced, not that the prose is true.
 */

export const AUTHORITIES = ['can_act', 'inspect_only', 'never_act'] as const;
export type Authority = (typeof AUTHORITIES)[number];

/** What a label rests on: one block's own evidence, its document's provenance, or nothing. */
export const AUTHORITY_BASES = ['block', 'document', 'none'] as const;
export type AuthorityBasis = (typeof AUTHORITY_BASES)[number];

export const AUTHORITY_REASONS = [
  'block_matches_source',
  'superseded',
  'tombstoned',
  'stale_derived',
  'integrity_failed',
  'source_missing',
  'not_in_source',
  'model_memory',
  'source_unavailable',
  'document_source_only',
  'no_source',
  'read_scrubbed',
  'lineage_unknown',
] as const;
export type AuthorityReason = (typeof AUTHORITY_REASONS)[number];

/** Result of comparing one block with its document's recorded source file, live. */
export const SOURCE_CHECKS = ['match', 'not_in_source', 'missing', 'unavailable', 'unchecked'] as const;
export type SourceCheck = (typeof SOURCE_CHECKS)[number];

export interface HonestyInput {
  status: 'live' | 'superseded' | 'tombstoned';
  /** `source.kind` of the document's latest put (instruction | memory | file), or null. */
  source_kind: string | null;
  source_check: SourceCheck;
  /** The read-time scrub changed the text being served. */
  read_scrubbed: boolean;
  /**
   * Unreleased: the hit's document is a derived note and a block it was
   * derived from changed (superseded, moved, tombstoned) without the note
   * being re-derived from the current version (src/lineage/lineage.ts).
   */
  stale_derived?: boolean;
  /**
   * 0.8.1: the hit's document is a derived note whose sources could not all
   * be determined (inference cut short by its bound, or a chain of derived
   * notes deeper than the bound). Caps can_act at inspect_only.
   */
  lineage_undetermined?: boolean;
}

export interface Honesty {
  authority: Authority;
  reason: AuthorityReason;
  basis: AuthorityBasis;
}

interface Rule {
  n: number;
  when: string;
  authority: Authority;
  reason: AuthorityReason;
  basis: AuthorityBasis;
  test: (i: HonestyInput) => boolean;
}

/** First match wins. Row 0 (integrity) applies to withheld matches, which never reach this table. */
export const HONESTY_RULES: readonly Rule[] = [
  { n: 1, when: 'block was tombstoned', authority: 'never_act', reason: 'tombstoned', basis: 'block', test: (i) => i.status === 'tombstoned' },
  { n: 2, when: 'block was superseded', authority: 'never_act', reason: 'superseded', basis: 'block', test: (i) => i.status === 'superseded' },
  { n: 3, when: 'derived note: a block it was derived from changed or was removed (not re-derived)', authority: 'never_act', reason: 'stale_derived', basis: 'document', test: (i) => i.stale_derived === true },
  { n: 4, when: 'recorded source file is gone', authority: 'never_act', reason: 'source_missing', basis: 'document', test: (i) => i.source_check === 'missing' },
  { n: 5, when: "source file exists but no longer holds this block's text", authority: 'never_act', reason: 'not_in_source', basis: 'block', test: (i) => i.source_check === 'not_in_source' },
  { n: 6, when: 'document is model-written memory (source kind memory)', authority: 'inspect_only', reason: 'model_memory', basis: 'document', test: (i) => i.source_kind === 'memory' },
  { n: 7, when: "source file holds this block's exact text now", authority: 'can_act', reason: 'block_matches_source', basis: 'block', test: (i) => i.source_check === 'match' },
  { n: 8, when: 'source recorded but could not be checked (repo/file unreadable, too large)', authority: 'inspect_only', reason: 'source_unavailable', basis: 'document', test: (i) => i.source_check === 'unavailable' },
  { n: 9, when: 'source recorded, no block-level check possible (e.g. relative path, no root)', authority: 'inspect_only', reason: 'document_source_only', basis: 'document', test: (i) => i.source_kind !== null },
  { n: 10, when: 'no source recorded (put by an agent or a human)', authority: 'inspect_only', reason: 'no_source', basis: 'none', test: () => true },
];

const RANK: Readonly<Record<Authority, number>> = { never_act: 0, inspect_only: 1, can_act: 2 };

export function meet(a: Authority, b: Authority): Authority {
  return RANK[a] <= RANK[b] ? a : b;
}

/**
 * Resolve one hit's authority. After the table, a read-time scrub caps
 * can_act at inspect_only (`read_scrubbed`): the text served is not the
 * chained text the evidence was about. 0.8.1: so does an undetermined
 * lineage (`lineage_unknown`): a note whose sources are not known is never
 * can_act on the strength of its own file.
 */
export function resolveAuthority(i: HonestyInput): Honesty {
  const rule = HONESTY_RULES.find((r) => r.test(i))!;
  if (rule.authority === 'can_act' && i.lineage_undetermined === true) return { authority: 'inspect_only', reason: 'lineage_unknown', basis: 'document' };
  if (rule.authority === 'can_act' && i.read_scrubbed) return { authority: 'inspect_only', reason: 'read_scrubbed', basis: 'block' };
  return { authority: rule.authority, reason: rule.reason, basis: rule.basis };
}

/**
 * Floor of a retrieved set: the meet of its labels. IsoKron returns can_act
 * (the meet identity) for an empty set; here an empty set has no floor
 * (null), so "nothing found" never reads as permission.
 */
export function authorityFloor(labels: readonly Authority[]): Authority | null {
  if (labels.length === 0) return null;
  return labels.reduce<Authority>((acc, a) => meet(acc, a), 'can_act');
}
