/**
 * Attention rerank (0.6.0). Ported from IsoKron
 * packages/library-retrieval/src/attention-decay-recall.ts: hits the same
 * actor already read this session are LOWERED, never hidden (an important
 * stable fact must still surface). Pure; the caller supplies relevance
 * (higher = better) and the set of block ids already read.
 *
 * Only the down-weighting is ported; IsoKron's ×1.5 changed-since-cursor
 * boost is not (orient's delta already leads with what changed).
 */

export const READ_WEIGHT = 0.5;

export function attentionRerank<T extends { id: string; relevance: number }>(
  hits: readonly T[],
  alreadyRead: ReadonlySet<string>,
  weight = READ_WEIGHT,
): (T & { already_read: boolean })[] {
  const w = Math.max(0.01, weight); // > 0: lowers, never hides
  return hits
    .map((h, i) => {
      const already_read = alreadyRead.has(h.id);
      return { h: { ...h, already_read }, i, adjusted: already_read ? h.relevance * w : h.relevance };
    })
    .sort((a, b) => b.adjusted - a.adjusted || a.i - b.i)
    .map((x) => x.h);
}
