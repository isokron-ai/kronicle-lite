/**
 * Format-only edits: RAW-TEXT equivalence (0.8.1).
 *
 * Agents copy raw Markdown into commands, so "renders the same" is not
 * "says the same": `/tmp/*\/cache/*` and `/tmp/_/cache/_` are the same
 * CommonMark tree but different globs, and `9090. admin` after a paragraph
 * line is text, not a list item. A supersession is `format_only` only when
 * old and new block text are byte-identical after exactly these steps:
 *
 *   1. line endings: CRLF / CR → LF;
 *   2. trailing spaces and tabs removed from every line;
 *   3. reflow inside a paragraph: a whitespace run that CONTAINS exactly one
 *      newline (a line break plus the spaces / tabs around it) between two
 *      non-space characters becomes one space — but
 *      NOT inside inline code, link destinations, inline HTML or autolinks,
 *      quoted strings ('…', "…", “…”, ‘…’), and never across a line break
 *      that ends a backslash hard break, starts a list item / quote / heading
 *      / table row / fence / HTML / reference definition / thematic break or
 *      setext underline, or touches an indented (4+ spaces or tab) line;
 *      such lines and table, quote, HTML and reference-definition lines keep
 *      every byte;
 *   4. runs of blank lines collapse to one.
 *
 * Nothing else is normalized: no whitespace runs inside a line (two spaces
 * → one, a tab → a space), no emphasis markers (`*` ↔ `_`), bullet or
 * ordered-list markers, renumbering, heading style, escapes, entities,
 * letter case, punctuation, Unicode (NFC / NFKC, no-break or thin spaces,
 * U+2028) — and no typo tolerance. Code blocks, front matter (a block that
 * opens with `---` / `+++`) and HTML blocks are opaque; a construct the
 * scanner cannot close (an unclosed code span, quote, `<tag` or link
 * destination) makes the block opaque. Opaque ⇒ only identical text is
 * format-only. Doubt ⇒ not format-only.
 *
 * This label is presentation only: it decides how an edit is SHOWN (one
 * line under `format_only_edits` instead of a retraction). It never decides
 * safety; a `likely_typo` hint on a retraction is a label and never moves
 * it out of `retractions`.
 *
 * Tests: test/cosmetic.test.ts (must-alarm cases), test/stress-corpus.test.ts
 * (agent-memory-bench round-1 and round-2 adversarial corpora),
 * test/format-only-property.test.ts (single-character mutations never
 * format-only) and test/format-only-mutants.test.ts (each removed heuristic,
 * re-introduced via __mutants, makes the suite fail).
 */

/**
 * What differed in a format-only edit. Since 0.8.1 only `whitespace` is
 * produced (line endings, trailing whitespace, reflow, blank-line runs);
 * `markup` is kept in the type for readers of older results.
 */
export const FORMAT_RULES = ['whitespace', 'markup'] as const;
export type FormatRule = (typeof FORMAT_RULES)[number];
/** @deprecated alias of FORMAT_RULES (unreleased name). */
export const COSMETIC_RULES = FORMAT_RULES;
export type CosmeticRule = FormatRule;

export interface EditClass {
  format_only: boolean;
  /** What differed when format-only, else empty. */
  rules: FormatRule[];
  /** Presentation hint for a retraction; never affects delivery. */
  hint: 'likely_typo' | null;
}

/**
 * TEST-ONLY. Re-introduces a removed heuristic so the mutation tests can
 * prove the suite kills it. Production code never adds to this set.
 */
export const __mutants = new Set<'hyphen_strip' | 'lowercase' | 'typo' | 'date_mask' | 'nfkc' | 'gate_trusts_label' | 'emphasis_fold' | 'list_renumber'>();

// ───────────────────────────── raw-text canonical form ─────────────────────────────

/** Steps 1, 2 and 4: line endings, trailing whitespace per line, blank-line runs, outer blank lines. */
export function normalizeRaw(s: string): string {
  return s
    .replace(/\r\n?/g, '\n')
    .split('\n')
    .map((l) => l.replace(/[ \t]+$/, ''))
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .replace(/^\n+|\n+$/g, '');
}

/** A line that keeps every byte (and the line breaks around it): not paragraph text. */
function verbatimLine(line: string): boolean {
  return (
    line.includes('|') || // table row (or prose with pipes: kept, the conservative side)
    /^(?: {4,}|\t)/.test(line) || // indented code / deep continuation
    /^[ \t]*(?:#|<|>|```|~~~|\[[^\]]*\]:)/.test(line) || // heading, HTML, quote, fence, reference definition
    /^[ \t]*[-=*_+][-=*_+ \t]*$/.test(line) // thematic break, setext underline, front-matter delimiter
  );
}

/** A line whose first character could open a block construct: the line break before it is kept. */
function startsConstruct(line: string): boolean {
  return /^[ \t]*(?:[-*+=_#>|<`~[]|\d{1,9}[.)](?:[ \t]|$))/.test(line);
}

/** Whole block opaque: front matter or an HTML block. */
function opaqueBlock(text: string): boolean {
  const first = text.split('\n', 1)[0]!;
  return /^(?:---|\+\+\+)[ \t]*$/.test(first) || /^[ \t]{0,3}</.test(first);
}

/**
 * Mark the characters whose surrounding whitespace must stay verbatim.
 * Returns null when a protected construct does not close (⇒ opaque).
 */
function protectedMask(text: string, lines: string[]): Uint8Array | null {
  const mask = new Uint8Array(text.length);
  // Verbatim lines, newline included.
  let at = 0;
  for (const line of lines) {
    if (verbatimLine(line)) mask.fill(1, at, Math.min(text.length, at + line.length + 1));
    at += line.length + 1;
  }
  const isWord = (c: string | undefined) => c !== undefined && /[\p{L}\p{N}]/u.test(c);
  const noCloser = { "'": false, '‘': false }; // once one opener has no closer, no later one can (keeps the scan linear)
  let i = 0;
  while (i < text.length) {
    const ch = text[i]!;
    if (ch === '\\') {
      i += 2; // an escaped character opens nothing
      continue;
    }
    let end = -1;
    if (ch === '`') {
      let r = i;
      while (text[r] === '`') r++;
      const run = text.slice(i, r); // scanned in place: slicing the rest per run would be O(n²) on backtick-heavy text
      let j = r;
      for (;;) {
        const k = text.indexOf(run, j);
        if (k < 0) return null; // unclosed code span
        if (text[k + run.length] !== '`' && text[k - 1] !== '`') {
          end = k + run.length;
          break;
        }
        j = k + 1;
        while (text[j] === '`') j++;
      }
    } else if (ch === '<' && /[A-Za-z/!?]/.test(text[i + 1] ?? '')) {
      const k = text.indexOf('>', i);
      if (k < 0) return null;
      end = k + 1;
    } else if (ch === ']' && text[i + 1] === '(') {
      let depth = 0;
      let k = i + 1;
      for (; k < text.length; k++) {
        if (text[k] === '\\') {
          k++;
          continue;
        }
        if (text[k] === '(') depth++;
        else if (text[k] === ')' && --depth === 0) break;
      }
      if (k >= text.length) return null;
      end = k + 1;
    } else if (ch === '"' || ch === '“') {
      const close = ch === '"' ? '"' : '”';
      const k = text.indexOf(close, i + 1);
      if (k < 0) return null; // unclosed quote
      end = k + 1;
    } else if ((ch === "'" || ch === '‘') && !noCloser[ch] && !isWord(text[i - 1]) && /\S/.test(text[i + 1] ?? ' ')) {
      // A quote, not an apostrophe: closes at a quote not followed by a letter or digit.
      const close = ch === "'" ? "'" : '’';
      let k = text.indexOf(close, i + 1);
      while (k >= 0 && isWord(text[k + 1])) k = text.indexOf(close, k + 1);
      if (k >= 0) end = k + 1;
      else noCloser[ch] = true;
    }
    if (end > i) {
      mask.fill(1, i, end);
      i = end;
    } else {
      i++;
    }
  }
  return mask;
}

/** Steps 1–4 for one block; null when the block is opaque (only identical text is format-only). */
function rawCanon(content: string): string | null {
  const text = normalizeRaw(content);
  if (opaqueBlock(text)) return null;
  const lines = text.split('\n');
  const mask = protectedMask(text, lines);
  if (!mask) return null;
  // Line index of each newline position, to judge the break.
  const lineStarts: number[] = [0];
  for (let k = 0; k < text.length; k++) if (text[k] === '\n') lineStarts.push(k + 1);
  const lineAt = (pos: number) => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid]! <= pos) lo = mid;
      else hi = mid - 1;
    }
    return lo;
  };
  let out = '';
  let i = 0;
  while (i < text.length) {
    const ch = text[i]!;
    if (ch !== ' ' && ch !== '\t' && ch !== '\n') {
      out += ch;
      i++;
      continue;
    }
    let j = i;
    while (j < text.length && (text[j] === ' ' || text[j] === '\t' || text[j] === '\n')) j++;
    const run = text.slice(i, j);
    const newlines = run.split('\n').length - 1;
    // Strict (0.8.1 decision): only a line break is reflow. A run inside one line (two spaces → one,
    // a tab → a space) keeps every byte: agents copy commands out of unfenced prose.
    let collapsible = i > 0 && j < text.length && newlines === 1;
    for (let k = i; collapsible && k < j; k++) if (mask[k]) collapsible = false;
    if (collapsible && newlines === 1) {
      const nl = i + run.indexOf('\n');
      const prev = lines[lineAt(nl)]!;
      const next = lines[lineAt(nl + 1)]!;
      if (prev.endsWith('\\') || verbatimLine(prev) || verbatimLine(next) || startsConstruct(next)) collapsible = false;
    }
    out += collapsible ? ' ' : run;
    i = j;
  }
  return out;
}

/** Canonical form of a block's content, or null when it is opaque (code, front matter, HTML, unclosed constructs). */
export function formatCanon(content: string, kind?: string): string | null {
  if (kind === 'code') return null; // opaque: any byte change counts
  let v = rawCanon(content);
  if (v === null) return null;
  if (__mutants.has('emphasis_fold')) v = v.replace(/_/g, '*');
  if (__mutants.has('list_renumber')) v = v.replace(/^([ \t]*)\d{1,9}[.)]/gm, '$11.');
  if (__mutants.has('nfkc')) v = v.normalize('NFKC');
  if (__mutants.has('lowercase')) v = v.toLowerCase();
  if (__mutants.has('hyphen_strip')) v = v.replace(/(?<=\p{L})-(?=\p{L})/gu, '');
  if (__mutants.has('date_mask')) v = v.replace(/\d{4}-\d{2}-\d{2}|\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.? \d{1,2},? \d{4}/gi, '⟨date⟩');
  return v;
}

// ───────────────────────────── hint (label only) ─────────────────────────────

/** Longest word the typo hint considers; longer tokens are not "ordinary words" (bounds the O(m·n) distance). */
export const TYPO_MAX_WORD = 64;

/** Damerau–Levenshtein (optimal string alignment) distance, capped: anything over 2 (or too long to compare) is 3. */
export function editDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (Math.abs(m - n) > 2) return 3;
  if (m > TYPO_MAX_WORD || n > TYPO_MAX_WORD) return a === b ? 0 : 3;
  const d: number[][] = Array.from({ length: m + 1 }, (_, i) => Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)));
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) v = Math.min(v, d[i - 2]![j - 2]! + 1);
      d[i]![j] = v;
    }
  }
  return d[m]![n]!;
}

/** Exactly one alphabetic word of 5–64 letters differs, by one edit, same first letter. A label, nothing more. */
export function looksLikeTypo(a: string, b: string): boolean {
  const ta = a.split(/\s+/).filter(Boolean);
  const tb = b.split(/\s+/).filter(Boolean);
  if (ta.length !== tb.length) return false;
  const diffs: [string, string][] = [];
  for (let i = 0; i < ta.length; i++) if (ta[i] !== tb[i]) diffs.push([ta[i]!, tb[i]!]);
  if (diffs.length !== 1) return false;
  const strip = (w: string) => w.replace(/^[^\p{L}]+|[^\p{L}]+$/gu, '');
  const x = strip(diffs[0]![0]);
  const y = strip(diffs[0]![1]);
  if (x.length > TYPO_MAX_WORD || y.length > TYPO_MAX_WORD) return false;
  if (!/^\p{L}{5,}$/u.test(x) || !/^\p{L}{5,}$/u.test(y) || x[0] !== y[0]) return false;
  if (diffs[0]![0].replace(x, '') !== diffs[0]![1].replace(y, '')) return false;
  return editDistance(x, y) === 1;
}

// ───────────────────────────── classify ─────────────────────────────

/**
 * Classify the edit from `oldText` to `newText` (one block's content and kind).
 * Identical text is format-only here (nothing changed); a caller that sees an
 * identical-text supersession in the same section (a reorder) must treat it
 * as a change itself (order is meaning).
 */
export function classifyEdit(oldText: string, newText: string, kind?: string): EditClass {
  const typo = looksLikeTypo(oldText, newText);
  const hint = typo ? ('likely_typo' as const) : null;
  if (oldText === newText) return { format_only: true, rules: [], hint: null };
  if (__mutants.has('typo') && typo) return { format_only: true, rules: ['markup'], hint: null };
  const a = formatCanon(oldText, kind);
  const b = formatCanon(newText, kind);
  if (a === null || b === null || a !== b) return { format_only: false, rules: [], hint };
  return { format_only: true, rules: ['whitespace'], hint: null };
}
