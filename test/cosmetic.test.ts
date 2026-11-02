/**
 * Format-only classifier (orient/cosmetic.ts), 0.8.1: RAW-TEXT equivalence.
 * Format-only = line endings, trailing whitespace, reflow inside a paragraph
 * (not in code, quotes, link destinations or HTML; never across a hard break
 * or a block-construct line) and blank-line runs. Everything else — emphasis
 * markers, list markers, renumbering, any changed character — is a
 * retraction. Typo-shaped edits carry `hint: likely_typo` as a label only.
 *
 * End-to-end corpora: test/stress-corpus.test.ts. Property test:
 * test/format-only-property.test.ts. Mutation tests:
 * test/format-only-mutants.test.ts.
 */

import { describe, expect, it } from 'vitest';

import { classifyEdit, editDistance, formatCanon } from '../src/orient/cosmetic.js';
import { FORMAT_ONLY, MUST_ALARM } from './fixtures/format-only-cases.js';

describe('classifyEdit: raw-text equivalence', () => {
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

  it('names what differed (only whitespace since 0.8.1)', () => {
    expect(classifyEdit('a  b', 'a b').rules).toEqual(['whitespace']);
    expect(classifyEdit('*a* b', '_a_ b')).toEqual({ format_only: false, rules: [], hint: null });
  });

  it('code blocks, front matter, HTML blocks and unclosed constructs are opaque', () => {
    expect(classifyEdit('```sh\nmake deploy\n```', '```sh\nmake  deploy\n```', 'code').format_only).toBe(false);
    expect(formatCanon('```sh\nx\n```', 'code')).toBeNull();
    expect(formatCanon('---\ntitle: x\n---')).toBeNull();
    expect(formatCanon('<div>\n  x\n</div>')).toBeNull();
    expect(formatCanon('Unclosed `code')).toBeNull();
    expect(formatCanon('Unclosed "quote and  more')).toBeNull();
    expect(formatCanon('A <tag that  never closes')).toBeNull();
    expect(formatCanon('See [x](https://x.example/a  b')).toBeNull();
    // A reference link is plain raw text now: compared byte for byte, reflow allowed around it.
    expect(formatCanon('See  [x][ref].')).toBe('See [x][ref].');
  });

  it('the canonical form keeps raw bytes and only collapses prose whitespace', () => {
    expect(formatCanon('Delete /tmp/*/cache/*  nightly.')).toBe('Delete /tmp/*/cache/* nightly.');
    expect(formatCanon('Run deploy\\\n--force')).toBe('Run deploy\\\n--force'); // hard break kept
    expect(formatCanon('Open ports:\n8080. web')).toBe('Open ports:\n8080. web'); // a numbered line keeps its break
    expect(formatCanon("it's  a 'quoted  run' here")).toBe("it's a 'quoted  run' here"); // apostrophe is not a quote
    expect(formatCanon('Line one\r\nline two   \n\n\n\nnext')).toBe('Line one line two\n\nnext');
  });

  it('editDistance counts a transposition as one edit', () => {
    expect(editDistance('recieve', 'receive')).toBe(1);
    expect(editDistance('kitten', 'sitting')).toBe(3);
  });

  it('the raw-text scan stays linear on adversarial blocks', () => {
    const n = 40_000;
    for (const unit of ['`a ', "'a ", 'x <b> ', '[x](y) ', '"q" ', '``a` ', ' \n', '1. a\n']) {
      const t = unit.repeat(n);
      const t0 = Date.now();
      classifyEdit(t, `${t}z`);
      expect(Date.now() - t0, JSON.stringify(unit)).toBeLessThan(3_000);
    }
  });

  it('L5: one huge letters-only word cannot stall the typo hint (bounded at 64 letters)', () => {
    const w = 'a'.repeat(200_000);
    const t0 = Date.now();
    expect(classifyEdit(`Use ${w} now.`, `Use ${w.slice(0, -1)}b now.`)).toEqual({ format_only: false, rules: [], hint: null });
    expect(editDistance(w, `${w.slice(0, -1)}b`)).toBe(3);
    expect(Date.now() - t0).toBeLessThan(2_000);
    expect(classifyEdit(`Use ${'a'.repeat(63)}x now.`, `Use ${'a'.repeat(63)}y now.`).hint).toBe('likely_typo'); // 64 letters: still a word
  });
});
