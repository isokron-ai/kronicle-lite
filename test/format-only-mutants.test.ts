/**
 * Mutation tests for the format-only classifier: each heuristic that was
 * REMOVED (hyphen stripping, lowercasing, the typo rule, date masking,
 * NFKC) and "the gate trusts the likely_typo label" is re-introduced behind
 * the test-only `__mutants` switch, and the classifier suite (must-alarm
 * cases, the stress corpus, the single-character property) must catch it.
 * A mutant that survives means the tests no longer guard that regression.
 */

import { afterEach, describe, expect, it } from 'vitest';

import { __mutants, classifyEdit } from '../src/orient/cosmetic.js';
import { KronicleLite } from '../src/store.js';
import { CORPUS, MUST_ALARM, RUNBOOKS } from './fixtures/format-only-cases.js';
import { mutate, reported } from './helpers/format-only.js';

type Mutant = Parameters<typeof __mutants.add>[0];
const MUTANTS: Mutant[] = ['hyphen_strip', 'lowercase', 'typo', 'date_mask', 'nfkc', 'gate_trusts_label'];

/** Run the suite's checks in-process; return the failures it would report. */
function suiteFailures(): string[] {
  const failures: string[] = [];
  for (const [name, a, b] of MUST_ALARM) if (classifyEdit(a, b).format_only) failures.push(`must-alarm: ${name}`);
  for (const [id, label, a, b] of CORPUS) {
    if (label !== 'S') continue;
    const kl = new KronicleLite({ memory: true });
    const md = (t: string) => `# Runbook\n\n## Section\n\n${t}\n`;
    kl.docs.putDocument({ slug: 'r', title: 'R', markdown: md(a), actor_id: 'w' });
    const c0 = kl.orient.getSystemState({ actor_id: 'a', focus: 'pulse' }).cursor;
    kl.docs.putDocument({ slug: 'r', title: 'R', markdown: md(b), actor_id: 'w' });
    const s = kl.orient.getSystemState({ actor_id: 'a', since_cursor: c0, focus: 'retractions' });
    if (s.retractions!.length === 0) failures.push(`corpus: ${id}`);
    kl.close();
  }
  let seed = 7;
  const r = () => ((seed = (seed * 1103515245 + 12345) >>> 0) / 4294967296);
  for (let n = 0; n < 120; n++) {
    const doc = RUNBOOKS[n % RUNBOOKS.length]!;
    const got = reported(doc, mutate(doc, r));
    if (got.formatOnly > 0) failures.push(`property: #${n}`);
  }
  return failures;
}

describe('classifier mutation tests: every removed heuristic is caught', () => {
  afterEach(() => __mutants.clear());

  it('the unmutated classifier passes its own suite', { timeout: 60_000 }, () => {
    expect(suiteFailures()).toEqual([]);
  });

  it.each(MUTANTS)('mutant %s is killed', { timeout: 60_000 }, (m) => {
    __mutants.add(m);
    const failures = suiteFailures();
    expect(failures.length, `mutant ${m} survived the suite`).toBeGreaterThan(0);
  });
});
