/**
 * Format-only classifier (orient/cosmetic.ts), 0.8.1: RAW-TEXT equivalence.
 * Format-only = line endings, trailing whitespace, reflow (a line break)
 * inside a paragraph (not in code, quotes, link destinations or HTML; a
 * whitespace run inside one line is text; never across a hard break
 * or a block-construct line) and blank-line runs. Everything else — emphasis
 * markers, list markers, renumbering, any changed character — is a
 * retraction. Typo-shaped edits carry `hint: likely_typo` as a label only.
 *
 * End-to-end corpora: test/stress-corpus.test.ts. Property test:
 * test/format-only-property.test.ts. Mutation tests:
 * test/format-only-mutants.test.ts.
 */

import { describe, expect, it } from 'vitest';
import { generous } from './helpers/time.js';

import { classifyEdit, editDistance, formatCanon } from '../src/orient/cosmetic.js';
import { KronicleLite } from '../src/store.js';
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
    expect(classifyEdit('a\nb', 'a b').rules).toEqual(['whitespace']);
    expect(classifyEdit('a  b', 'a b').format_only).toBe(false); // strict: a run inside a line is text
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
    expect(formatCanon('See [x][ref]\nfirst.')).toBe('See [x][ref] first.');
    expect(formatCanon('See\n[x][ref].')).toBe('See\n[x][ref].'); // a line starting with `[` keeps its break
  });

  it('the canonical form keeps raw bytes and only collapses prose whitespace', () => {
    expect(formatCanon('Delete /tmp/*/cache/*\n  nightly.')).toBe('Delete /tmp/*/cache/* nightly.');
    expect(formatCanon('Delete  /tmp/*/cache/*\tnightly.')).toBe('Delete  /tmp/*/cache/*\tnightly.'); // runs inside a line keep every byte
    expect(formatCanon('Run deploy\\\n--force')).toBe('Run deploy\\\n--force'); // hard break kept
    expect(formatCanon('Open ports:\n8080. web')).toBe('Open ports:\n8080. web'); // a numbered line keeps its break
    expect(formatCanon("it's\na 'quoted\nrun' here")).toBe("it's a 'quoted\nrun' here"); // apostrophe is not a quote; the quote keeps its break
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
      expect(Date.now() - t0, JSON.stringify(unit)).toBeLessThan(generous(3_000));
    }
  });

  it('R2-12 probe: orient and pending stay fast with an 8,000-letter word changed by one letter', () => {
    let w = '';
    let x = 1;
    for (let i = 0; i < 8000; i++) {
      x = (x * 1103515245 + 12345) >>> 0;
      w += String.fromCharCode(97 + (x % 26));
    }
    const w2 = w.slice(0, -1) + (w.at(-1) === 'a' ? 'b' : 'a');
    const kl = new KronicleLite({ memory: true });
    kl.docs.putDocument({ slug: 'k', title: 'K', markdown: `# K\n\nFingerprint ${w} is trusted.\n`, actor_id: 'w' });
    kl.recall.recall({ query: 'fingerprint trusted', actor_id: 'agent' });
    const c = kl.orient.getSystemState({ actor_id: 'hook', focus: 'pulse' }).cursor;
    kl.docs.putDocument({ slug: 'k', title: 'K', markdown: `# K\n\nFingerprint ${w2} is trusted.\n`, actor_id: 'w' });
    const t0 = Date.now();
    expect(kl.orient.getSystemState({ actor_id: 'hook', since_cursor: c, focus: 'retractions' }).retractions).toHaveLength(1);
    expect(kl.lineage.pending('agent').count).toBe(1);
    expect(Date.now() - t0).toBeLessThan(generous(5_000));
    kl.close();
  });

  it('L5: one huge letters-only word cannot stall the typo hint (bounded at 64 letters)', () => {
    const w = 'a'.repeat(200_000);
    const t0 = Date.now();
    expect(classifyEdit(`Use ${w} now.`, `Use ${w.slice(0, -1)}b now.`)).toEqual({ format_only: false, rules: [], hint: null });
    expect(editDistance(w, `${w.slice(0, -1)}b`)).toBe(3);
    expect(Date.now() - t0).toBeLessThan(generous(2_000));
    expect(classifyEdit(`Use ${'a'.repeat(63)}x now.`, `Use ${'a'.repeat(63)}y now.`).hint).toBe('likely_typo'); // 64 letters: still a word
  });
});
