/**
 * Property: a single-character mutation (insert / delete / replace with a
 * hyphen, a digit, a case flip or a Unicode compatibility / combining
 * character) anywhere in the non-whitespace text of a real runbook — prose,
 * identifiers, URLs, numbers, dates, inline code, code fences, list markers —
 * is NEVER reported as format-only, and is always visible (a retraction or
 * a new block). Seeded, deterministic.
 */

import { describe, expect, it } from 'vitest';

import { RUNBOOKS } from './fixtures/format-only-cases.js';
import { mutate, reported, rng } from './helpers/format-only.js';

describe('property: single-character mutations are never format-only', () => {
  it('400 seeded mutations over real runbooks', { timeout: 120_000 }, () => {
    const r = rng(20261101);
    const failures: string[] = [];
    for (let n = 0; n < 400; n++) {
      const doc = RUNBOOKS[n % RUNBOOKS.length]!;
      const m = mutate(doc, r);
      const got = reported(doc, m);
      // Visible: a retraction, or (an edit the block splitter sees as a new block) a block.created.
      const visible = got.retractions > 0 || got.created > 0;
      // A mutation the block splitter itself erases (none expected) would show as zero events.
      if (got.formatOnly > 0 || !visible) failures.push(JSON.stringify({ n, got, at: [...doc].findIndex((c, k) => c !== [...m][k]), was: doc.slice(Math.max(0, [...doc].findIndex((c, k) => c !== [...m][k]) - 15), [...doc].findIndex((c, k) => c !== [...m][k]) + 15), now: m.slice(Math.max(0, [...doc].findIndex((c, k) => c !== [...m][k]) - 15), [...doc].findIndex((c, k) => c !== [...m][k]) + 15) }));
    }
    expect(failures).toEqual([]);
  });
});
