/**
 * Format-only edits: Markdown AST equivalence with exact text leaves.
 *
 * A supersession is `format_only` when old and new block parse to the same
 * tree under the narrow parser below and every text leaf is byte-identical,
 * except that runs of spaces, tabs and newlines inside prose text are
 * collapsed (reflow). That covers: reflow and whitespace runs, `*` ↔ `_`
 * emphasis markers, `-`/`*`/`+` bullets, `1.` ↔ `1)` list delimiters and
 * item renumbering after the first (CommonMark keeps only the start).
 *
 * Nothing else is normalized: no typo tolerance, case folding, hyphen
 * stripping, quote or punctuation folding, date masking, Unicode
 * normalization (NFC/NFKC). Code blocks, inline code, link targets, raw
 * HTML and anything the parser does not know (tables, block quotes, front
 * matter, indented code, setext headings, reference links …) are opaque:
 * any byte change there is not format-only. Parser doubt ⇒ not format-only.
 *
 * This label is presentation only: it decides how an edit is SHOWN (one
 * line under `format_only_edits` instead of a retraction). It never decides
 * safety; a `likely_typo` hint on a retraction is a label and never moves
 * it out of `retractions`.
 *
 * Tests: test/cosmetic.test.ts (must-alarm cases), test/stress-corpus.test.ts
 * (agent-memory-bench adversarial corpus), test/format-only-property.test.ts
 * (single-character mutations never format-only) and
 * test/format-only-mutants.test.ts (each removed heuristic, re-introduced
 * via __mutants, makes the suite fail).
 */

/** What differed in a format-only edit: whitespace/reflow, or Markdown markup style. */
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
export const __mutants = new Set<'hyphen_strip' | 'lowercase' | 'typo' | 'date_mask' | 'nfkc' | 'gate_trusts_label'>();

// ───────────────────────────── narrow Markdown parser ─────────────────────────────

type Inline = string | { t: 'em' | 'strong'; c: Inline[] } | { t: 'code'; v: string } | { t: 'link'; href: string; c: Inline[] } | { t: 'html'; v: string };
type Block = { t: 'p'; c: Inline[] } | { t: 'li'; indent: number; ordered: boolean; start: number | null; c: Inline[] };

const OPAQUE_LINE = /^(?: {4}|\t|>|\||<|\[[^\]]+\]:|---|\*\*\*|___|===|~~~|```|#{1,6}\s|\+\+\+)/;
const LIST_ITEM = /^( *)([-*+]|(\d{1,9})[.)])( +)(.*)$/;

function textLeaf(s: string): string {
  let v = s.replace(/[ \t\n]+/g, ' ');
  if (__mutants.has('nfkc')) v = v.normalize('NFKC');
  if (__mutants.has('lowercase')) v = v.toLowerCase();
  if (__mutants.has('hyphen_strip')) v = v.replace(/(?<=\p{L})-(?=\p{L})/gu, '');
  if (__mutants.has('date_mask')) v = v.replace(/\d{4}-\d{2}-\d{2}|\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.? \d{1,2},? \d{4}/gi, '⟨date⟩');
  return v;
}

/** Inline parse; null when a construct is ambiguous (⇒ not format-only). */
function inline(src: string): Inline[] | null {
  const out: Inline[] = [];
  let buf = '';
  const flush = () => {
    if (buf) out.push(textLeaf(buf));
    buf = '';
  };
  let i = 0;
  while (i < src.length) {
    const ch = src[i]!;
    if (ch === '\\' && i + 1 < src.length) {
      buf += src.slice(i, i + 2); // escapes stay literal bytes
      i += 2;
      continue;
    }
    if (ch === '`') {
      const run = /^`+/.exec(src.slice(i))![0];
      const close = src.indexOf(run, i + run.length);
      if (close < 0) return null;
      flush();
      out.push({ t: 'code', v: src.slice(i, close + run.length) }); // opaque, exact bytes incl. fences
      i = close + run.length;
      continue;
    }
    if (ch === '<') {
      const close = src.indexOf('>', i);
      if (close < 0) return null;
      flush();
      out.push({ t: 'html', v: src.slice(i, close + 1) }); // autolink or raw HTML: opaque
      i = close + 1;
      continue;
    }
    if (ch === '[') {
      const m = /^\[([^\]]*)\]\(([^)\s]*)(?:\s+"[^"]*")?\)/.exec(src.slice(i));
      if (!m) {
        if (/^\[[^\]]*\]/.test(src.slice(i))) return null; // reference links etc.: unknown
        buf += ch;
        i++;
        continue;
      }
      const c = inline(m[1]!);
      if (!c) return null;
      flush();
      out.push({ t: 'link', href: m[0].slice(m[1]!.length + 2), c }); // target + title: opaque bytes
      i += m[0].length;
      continue;
    }
    if (ch === '*' || ch === '_') {
      const run = /^(\*+|_+)/.exec(src.slice(i))![0];
      const prev = i > 0 ? src[i - 1]! : ' ';
      if (ch === '_' && /[\p{L}\p{N}]/u.test(prev)) {
        buf += run; // intraword underscore: literal
        i += run.length;
        continue;
      }
      if (run.length > 2 || !/\S/.test(src[i + run.length] ?? ' ')) {
        buf += run;
        i += run.length;
        continue;
      }
      // Find the matching closer: same run, preceded by non-space, not intraword for _.
      let j = i + run.length;
      let found = -1;
      while ((j = src.indexOf(run, j)) >= 0) {
        const before = src[j - 1] ?? ' ';
        const after = src[j + run.length] ?? ' ';
        const sameRunContinues = after === ch || before === ch;
        if (!sameRunContinues && /\S/.test(before) && !(ch === '_' && /[\p{L}\p{N}]/u.test(after))) {
          found = j;
          break;
        }
        j += 1;
      }
      if (found < 0) {
        buf += run;
        i += run.length;
        continue;
      }
      const c = inline(src.slice(i + run.length, found));
      if (!c) return null;
      flush();
      out.push({ t: run.length === 2 ? 'strong' : 'em', c });
      i = found + run.length;
      continue;
    }
    buf += ch;
    i++;
  }
  flush();
  return out;
}

/** Parse one kronicle paragraph-kind block; null when it holds syntax outside the subset. */
function parseBlock(content: string): Block[] | null {
  const lines = content.split('\n');
  const blocks: { t: 'p' | 'li'; indent: number; ordered: boolean; start: number | null; text: string[] }[] = [];
  let prevOrdered: boolean | null = null;
  for (const line of lines) {
    if (OPAQUE_LINE.test(line)) return null;
    const m = LIST_ITEM.exec(line);
    if (m) {
      const ordered = m[3] !== undefined;
      const continuesList = blocks.length > 0 && blocks[blocks.length - 1]!.t === 'li' && prevOrdered === ordered;
      blocks.push({ t: 'li', indent: m[1]!.length, ordered, start: ordered && !continuesList ? Number(m[3]) : null, text: [m[5]!] });
      prevOrdered = ordered;
      continue;
    }
    const last = blocks[blocks.length - 1];
    if (last) last.text.push(line); // paragraph line or lazy continuation of a list item
    else blocks.push({ t: 'p', indent: 0, ordered: false, start: null, text: [line] });
  }
  const out: Block[] = [];
  for (const b of blocks) {
    const c = inline(b.text.join('\n').trim());
    if (!c) return null;
    out.push(b.t === 'p' ? { t: 'p', c } : { t: 'li', indent: b.indent, ordered: b.ordered, start: b.start, c });
  }
  return out;
}

/** Canonical form of a block's content, or null when it cannot be parsed under the subset. */
export function formatCanon(content: string, kind?: string): string | null {
  if (kind === 'code') return null; // opaque: any byte change counts
  if (kind === 'heading') {
    const c = inline(content.trim());
    return c ? JSON.stringify(['h', c]) : null;
  }
  const b = parseBlock(content);
  return b ? JSON.stringify(b) : null;
}

// ───────────────────────────── hint (label only) ─────────────────────────────

/** Damerau–Levenshtein (optimal string alignment) distance, capped early. */
export function editDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (Math.abs(m - n) > 2) return 3;
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

/** Exactly one alphabetic word of 5+ letters differs, by one edit, same first letter. A label, nothing more. */
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
  if (!/^\p{L}{5,}$/u.test(x) || !/^\p{L}{5,}$/u.test(y) || x[0] !== y[0]) return false;
  if (diffs[0]![0].replace(x, '') !== diffs[0]![1].replace(y, '')) return false;
  return editDistance(x, y) === 1;
}

// ───────────────────────────── classify ─────────────────────────────

/** Classify the edit from `oldText` to `newText` (one block's content and kind). */
export function classifyEdit(oldText: string, newText: string, kind?: string): EditClass {
  const typo = looksLikeTypo(oldText, newText);
  const hint = typo ? ('likely_typo' as const) : null;
  if (oldText === newText) return { format_only: true, rules: [], hint: null };
  if (__mutants.has('typo') && typo) return { format_only: true, rules: ['markup'], hint: null };
  const a = formatCanon(oldText, kind);
  const b = formatCanon(newText, kind);
  if (a === null || b === null || a !== b) return { format_only: false, rules: [], hint };
  const ws = (s: string) => s.replace(/[ \t\n]+/g, ' ').trim();
  return { format_only: true, rules: [ws(oldText) === ws(newText) ? 'whitespace' : 'markup'], hint: null };
}
