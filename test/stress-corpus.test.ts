/**
 * Adversarial classifier corpora, end to end (put v1 → orient → put v2 →
 * orient --focus retractions).
 *
 * Round 1: adopted verbatim from agent-memory-bench
 * `stress/kl/classifier-corpus.mjs` (branch stress @ b42ae46).
 *   S cases: a real change. Must be a retraction, never a format-only edit:
 *            false format_only 0/38.
 *   C cases: under raw-text equivalence only trailing whitespace / reflow
 *            stays quiet (C01, C02); every other "cosmetic" case changes a
 *            text byte and is delivered as a retraction (the accepted cost).
 *
 * Round 2: agent-memory-bench hardening round 2 (`hardening-retractions`
 * @ c0bdadc, findings R2-01..03), 69 cases in test/fixtures/r2-classifier-cases.ts.
 *   S cases: retraction, with exactly two exceptions that docs/FORMAT.md §3.8
 *            rule 3 (0.8.1 decision) defines as format-only: W01 (a run of two
 *            spaces in prose → one) and W06 (a tab in prose → a space). Raw
 *            text cannot tell them from the bench's benign whitespace_double
 *            edit; whitespace that matters belongs in code or quotes, which
 *            keep every byte.
 *   C cases: whitespace-only edits quiet; list-delimiter, bullet and emphasis
 *            style edits (L11, L12, E08) are retractions since 0.8.1.
 */

import { describe, expect, it } from 'vitest';

import { KronicleLite } from '../src/store.js';
import { CORPUS } from './fixtures/format-only-cases.js';
import { R2_CORPUS } from './fixtures/r2-classifier-cases.js';

/** C cases that stay quiet (format-only or no change at all). Every other C case is delivered. */
const QUIET = new Set(['C01', 'C02']);

function run(oldT: string, newT: string) {
  const kl = new KronicleLite({ memory: true });
  const md = (t: string) => `# Runbook\n\n## Section\n\n${t}\n`;
  kl.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: md(oldT), actor_id: 'writer' });
  const c0 = kl.orient.getSystemState({ actor_id: 'agent', focus: 'pulse' }).cursor;
  kl.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: md(newT), actor_id: 'writer' });
  const s = kl.orient.getSystemState({ actor_id: 'agent', since_cursor: c0, focus: 'retractions' });
  kl.close();
  return s;
}

describe('stress corpus round 1: false format_only 0/38', () => {
  it.each(CORPUS.filter((c) => c[1] === 'S'))('%s is delivered as a retraction (%s)', (_id, _l, a, b) => {
    const s = run(a, b);
    expect(s.retractions!.length, JSON.stringify(s.format_only_edits)).toBeGreaterThan(0);
    expect(s.format_only_edits).toEqual([]);
  });

  it.each(CORPUS.filter((c) => c[1] === 'C'))('%s formatting case (%s)', (id, _l, a, b) => {
    const s = run(a, b);
    if (QUIET.has(id)) {
      expect(s.retractions, JSON.stringify(s.retractions)).toEqual([]);
      expect(s.format_only_edits!.length).toBeLessThanOrEqual(1); // 0 when the block parser already normalized it (C01)
    } else {
      expect(s.retractions!.length).toBe(1);
      expect(s.format_only_edits).toEqual([]);
    }
  });
});

/** Every case in one store, as the bench harness does (stress/kl/r2-lib.mjs classifyE2E). */
function runAll(cases: readonly (readonly [string, string, string, string, string])[]) {
  const kl = new KronicleLite({ memory: true });
  try {
    const H = '# Runbook\n\n';
    cases.forEach(([, , o], i) => kl.docs.putDocument({ slug: `c${i}`, title: 't', markdown: `${H}${o}\n`, actor_id: 'w' }));
    const cur = kl.orient.getSystemState({ actor_id: 'agent', focus: 'pulse' }).cursor;
    cases.forEach(([, , , n], i) => kl.docs.putDocument({ slug: `c${i}`, title: 't', markdown: `${H}${n}\n`, actor_id: 'w' }));
    const def = kl.orient.getSystemState({ actor_id: 'agent', since_cursor: cur, focus: 'retractions' });
    const all = kl.orient.getSystemState({ actor_id: 'agent2', since_cursor: cur, focus: 'retractions', include_format_only: true });
    return new Map(
      cases.map(([id], i) => {
        const slug = `c${i}`;
        const real = def.retractions!.filter((r) => r.doc_slug === slug).length;
        const any = all.retractions!.filter((r) => r.doc_slug === slug).length;
        return [id, any === 0 ? 'no_event' : real === 0 ? 'format_only' : 'retraction'] as const;
      }),
    );
  } finally {
    kl.close();
  }
}

/** Format-only by decision (FORMAT §3.8 rule 3: runs of spaces / tabs in prose collapse). */
const R2_RULE3 = new Set(['W01', 'W06']);
/** Benign cases that stay quiet under raw-text equivalence. */
const R2_QUIET = new Set(['W02', 'W04', 'W05', 'N02', 'V02']);

describe('stress corpus round 2 (R2-01..03): raw-text equivalence', () => {
  const verdicts = runAll(R2_CORPUS);

  it('every real change is a retraction (except the two whitespace runs rule 3 collapses)', () => {
    const hidden = R2_CORPUS.filter(([id, l]) => l === 'S' && !R2_RULE3.has(id) && verdicts.get(id) !== 'retraction').map(([id]) => `${id}:${verdicts.get(id)}`);
    expect(hidden).toEqual([]);
    expect(R2_CORPUS.filter(([, l]) => l === 'S').length).toBe(61);
  });

  it('W01 / W06 are format-only by rule 3, and nothing else is', () => {
    expect([...verdicts].filter(([, v]) => v === 'format_only').map(([id]) => id).sort()).toEqual(['V02', 'W01', 'W04', 'W05', 'W06']);
    for (const id of R2_RULE3) expect(verdicts.get(id)).toBe('format_only');
  });

  it('benign cases: whitespace-only quiet; delimiter, bullet and emphasis style are delivered', () => {
    for (const [id, l] of R2_CORPUS) {
      if (l !== 'C') continue;
      if (R2_QUIET.has(id)) expect(verdicts.get(id), id).not.toBe('retraction');
      else expect(verdicts.get(id), id).toBe('retraction');
    }
    expect(R2_CORPUS.filter(([, l]) => l === 'C').map(([id]) => id).filter((id) => !R2_QUIET.has(id))).toEqual(['L11', 'L12', 'E08']);
  });
});
