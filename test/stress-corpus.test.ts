/**
 * Adversarial classifier corpus, end to end (put v1 → orient → put v2 →
 * orient --focus retractions), adopted verbatim from agent-memory-bench
 * `stress/kl/classifier-corpus.mjs` (branch stress @ b42ae46).
 *
 *   S cases: a real change. Must be a retraction, never a format-only edit:
 *            false format_only 0/38.
 *   C cases: under Markdown-AST equivalence only reflow / whitespace stays
 *            quiet (C01, C02); every other "cosmetic" case changes a text
 *            byte and is delivered as a retraction (the accepted cost).
 */

import { describe, expect, it } from 'vitest';

import { KronicleLite } from '../src/store.js';
import { CORPUS } from './fixtures/format-only-cases.js';

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

describe('stress corpus: false format_only 0/38', () => {
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
