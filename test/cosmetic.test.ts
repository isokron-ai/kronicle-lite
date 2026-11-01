/**
 * Format-only classifier (orient/cosmetic.ts): Markdown AST equivalence with
 * exact text leaves. Format-only = reflow / whitespace runs, `*`↔`_`
 * emphasis markers, bullet and ordered-list delimiter style, renumbering
 * after the first item. Everything else — any changed character in text,
 * code, links or unknown syntax — is a retraction. Typo-shaped edits carry
 * `hint: likely_typo` as a label only.
 *
 * End-to-end corpus: test/stress-corpus.test.ts. Property test:
 * test/format-only-property.test.ts. Mutation tests:
 * test/format-only-mutants.test.ts.
 */

import { describe, expect, it } from 'vitest';

import { classifyEdit, editDistance, formatCanon } from '../src/orient/cosmetic.js';
import { FORMAT_ONLY, MUST_ALARM } from './fixtures/format-only-cases.js';

describe('classifyEdit: Markdown AST equivalence with exact text leaves', () => {
  it.each(FORMAT_ONLY)('%s is format-only', (_t, a, b) => {
    const c = classifyEdit(a, b);
    expect(c.format_only, JSON.stringify(c)).toBe(true);
    expect(c.hint).toBeNull();
  });

  it.each(MUST_ALARM)('must alarm: %s', (_t, a, b) => {
    expect(classifyEdit(a, b).format_only).toBe(false);
  });

  it('typo-shaped edits get a hint label (and are still not format-only)', () => {
    expect(classifyEdit('Operators recieve alerts.', 'Operators receive alerts.')).toEqual({ format_only: false, rules: [], hint: 'likely_typo' });
    expect(classifyEdit('Page Karen now.', 'Page Karin now.').hint).toBe('likely_typo');
    expect(classifyEdit('Use http here.', 'Use https here.').hint).toBeNull(); // too short for the label; delivered either way
  });

  it('names what differed', () => {
    expect(classifyEdit('a  b', 'a b').rules).toEqual(['whitespace']);
    expect(classifyEdit('*a* b', '_a_ b').rules).toEqual(['markup']);
  });

  it('code blocks and unknown syntax are opaque', () => {
    expect(classifyEdit('```sh\nmake deploy\n```', '```sh\nmake  deploy\n```', 'code').format_only).toBe(false);
    expect(formatCanon('```sh\nx\n```', 'code')).toBeNull();
    expect(formatCanon('---\ntitle: x\n---')).toBeNull();
    expect(formatCanon('See [x][ref].')).toBeNull();
    expect(formatCanon('Unclosed `code')).toBeNull();
  });

  it('editDistance counts a transposition as one edit', () => {
    expect(editDistance('recieve', 'receive')).toBe(1);
    expect(editDistance('kitten', 'sitting')).toBe(3);
  });
});
