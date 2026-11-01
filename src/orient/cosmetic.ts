/**
 * Cosmetic vs semantic edits.
 *
 * Rule: NOTHING that changes a word, number, date or identifier is
 * cosmetic. An edit is cosmetic only when the sequence of word and number
 * tokens is byte-identical after formatting is set aside:
 *
 *   always set aside   line endings, whitespace and reflow, a space before
 *                      sentence punctuation, list markers (`1)`/`1.`/`-`/`*`),
 *                      paired emphasis markers (`*x*`, `**x**`, `_x_`),
 *                      curly vs straight quotes, a standalone dash's style
 *                      (` - ` / ` — `);
 *   one at a time      sentence punctuation at a token's end (`.`, `,`, `;`,
 *                      `:`, `!`, `?`), letter case, or a soft hyphen
 *                      (`e-mail` → `email`: a hyphen between letters with 3+
 *                      letters after it) — each only when, with that one
 *                      difference set aside, the texts are otherwise equal;
 *   review stamp       a line that is exactly a stamp phrase and one date
 *                      ("Last reviewed: 2026-10-01", "Reviewed on …") and
 *                      nothing else; any other date is content.
 *
 * Code spans and code blocks must be byte-identical (code blocks tolerate
 * line endings and trailing whitespace). There is no Unicode compatibility
 * folding (`2³` is not `23`).
 *
 * A probable typo fix (one ordinary word one letter off) is NOT cosmetic:
 * it is delivered as a retraction labelled `likely_typo` with informational
 * severity, because "typo-shaped" edits include http→https, Mark→Mary,
 * payments→payment and stable→stale.
 *
 * Checked against the agent-memory-bench benign-edit templates, the stress
 * corpus (track `stress/kl/classifier-corpus.mjs`) and must-alarm cases in
 * test/cosmetic.test.ts.
 */

export const COSMETIC_RULES = [
  'whitespace',
  'line_endings',
  'quotes',
  'punctuation',
  'emphasis',
  'list_markers',
  'hyphenation',
  'case',
  'review_stamp',
] as const;
export type CosmeticRule = (typeof COSMETIC_RULES)[number];

export interface EditClass {
  cosmetic: boolean;
  /** Rules that explain the difference (cosmetic), or empty. */
  rules: CosmeticRule[];
  /** Why it is semantic (null when cosmetic). */
  semantic_reason: string | null;
  /** Semantic, but shaped like a one-letter typo fix of an ordinary word (still a retraction). */
  likely_typo: boolean;
}

const SEMANTIC = (why: string, likely_typo = false): EditClass => ({ cosmetic: false, rules: [], semantic_reason: why, likely_typo });

/** Meaning-bearing words: an edit touching one is never labelled a likely typo. */
const MEANING_WORDS = new Set(
  (
    'not no nor never now always must should shall may might can cannot cant wont dont doesnt isnt arent wasnt ' +
    'do does did will would only all any none every each some before after above below over under up down on off in out ' +
    'into onto enable enabled enables disable disabled disables unable allow allowed allows deny denied denies block blocked ' +
    'open opened close closed start started stop stopped true false yes min max minimum maximum more less most least first ' +
    'last next previous prev old new prod production staging stage stale stable dev test primary secondary replica read write ' +
    'add remove include exclude increase decrease higher lower high low east west north south left right inbound outbound ' +
    'accept reject pass fail required optional public private internal external sync async lock unlock with without'
  ).split(' '),
);

// ── review stamps: the whole line is a stamp phrase plus one date ──
const MONTH = '(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)';
const DATE = [
  '\\d{4}-\\d{2}-\\d{2}',
  '\\d{1,2}/\\d{1,2}/\\d{4}',
  `${MONTH}\\.? \\d{1,2},? \\d{4}`,
  `\\d{1,2} ${MONTH}\\.? \\d{4}`,
].join('|');
const STAMP_PHRASE = '(?:last (?:reviewed|updated|modified|edited|checked|verified|revised)(?: on)?|reviewed on|updated on|reviewed|updated)';
const STAMP_LINE = new RegExp(`^(\\s*(?:[-*+>]\\s+)?[*_]{0,2}${STAMP_PHRASE}:?\\s+)(${DATE})(\\.?[*_]{0,2}\\.?\\s*)$`, 'i');

function maskStamps(text: string): { text: string; dates: string[] } {
  const dates: string[] = [];
  const lines = text.split('\n').map((line) =>
    line.replace(STAMP_LINE, (_m, pre: string, d: string, post: string) => {
      dates.push(d);
      return `${pre}⟨date⟩${post}`;
    }),
  );
  return { text: lines.join('\n'), dates };
}

const CODE_SPAN = /(`+)([\s\S]*?)\1/g;

type Step = { rule: CosmeticRule; apply: (s: string) => string };

/** Formatting that can never change a token. */
const BASE: Step[] = [
  { rule: 'line_endings', apply: (s) => s.replace(/\r\n?/g, '\n') },
  {
    rule: 'quotes',
    apply: (s) =>
      s
        .replace(/[“”„‟]/g, '"')
        .replace(/[‘’‚‛]/g, "'")
        .replace(/(?<=\s)[‐-―](?=\s)/g, '-'),
  },
  { rule: 'list_markers', apply: (s) => s.replace(/^[ \t]*(?:\d{1,4}[.)]|[-*+])[ \t]+/gm, '') },
  {
    rule: 'emphasis',
    // Paired markers only: *x*, **x**, ***x***, _x_, __x__ (underscores not inside a word).
    apply: (s) =>
      s
        .replace(/(\*{1,3})(?=\S)([^*\n]*?\S)\1(?!\*)/g, '$2')
        .replace(/(?<![\p{L}\p{N}_])(_{1,2})(?=\S)([^_\n]*?\S)\1(?![\p{L}\p{N}_])/gu, '$2'),
  },
  { rule: 'whitespace', apply: (s) => s.replace(/\s+/g, ' ').replace(/ (?=[.,;:!?](?:\s|$))/g, '').trim() },
];

/** Applied one at a time on top of BASE. */
const SINGLE: Step[] = [
  { rule: 'punctuation', apply: (s) => s.replace(/[.,;:!?]+(?=\s|$)/g, '') },
  { rule: 'case', apply: (s) => s.toLowerCase() },
  // Soft hyphens only inside plain words (`e-mail`, `non-blocking`); never in `--dry-run`, `us-east-1`, `a/b-c`.
  { rule: 'hyphenation', apply: (s) => s.split(' ').map((t) => (/^[("']*\p{L}+(?:-\p{L}+)+[)"'.,;:!?]*$/u.test(t) ? t.replace(/(?<=\p{L})-(?=\p{L}{3})/gu, '') : t)).join(' ') },
];

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

/** One ordinary alphabetic word (5+ letters, same first letter) one edit off, everything else equal. */
function looksLikeTypo(a: string, b: string): boolean {
  const strip = (s: string) => SINGLE[0]!.apply(s).split(' ');
  const ta = strip(a);
  const tb = strip(b);
  if (ta.length !== tb.length) return false;
  const diffs: [string, string][] = [];
  for (let i = 0; i < ta.length; i++) if (ta[i] !== tb[i]) diffs.push([ta[i]!, tb[i]!]);
  if (diffs.length !== 1) return false;
  const [x, y] = diffs[0]!;
  if (!/^\p{L}{5,}$/u.test(x) || !/^\p{L}{5,}$/u.test(y)) return false;
  const lx = x.toLowerCase();
  const ly = y.toLowerCase();
  if (MEANING_WORDS.has(lx) || MEANING_WORDS.has(ly) || lx[0] !== ly[0]) return false;
  return editDistance(lx, ly) === 1;
}

/**
 * Classify the edit from `oldText` to `newText` (one block's content).
 * `kind` is the block kind; code blocks only tolerate line endings and
 * trailing whitespace.
 */
export function classifyEdit(oldText: string, newText: string, kind?: string): EditClass {
  if (oldText === newText) return { cosmetic: true, rules: [], semantic_reason: null, likely_typo: false };
  if (kind === 'code') {
    const norm = (s: string) => s.replace(/\r\n?/g, '\n').replace(/[ \t]+$/gm, '').trimEnd();
    return norm(oldText) === norm(newText) ? { cosmetic: true, rules: ['whitespace'], semantic_reason: null, likely_typo: false } : SEMANTIC('code block changed');
  }
  const rules = new Set<CosmeticRule>();
  const sa = maskStamps(oldText.replace(/\r\n?/g, '\n'));
  const sb = maskStamps(newText.replace(/\r\n?/g, '\n'));
  if (sa.dates.join('\n') !== sb.dates.join('\n')) rules.add('review_stamp');
  let a = sa.text;
  let b = sb.text;

  // Code spans: byte-identical and in the same order, then out of the comparison.
  const spans = (t: string) => [...t.matchAll(CODE_SPAN)].map((m) => m[0]);
  const spA = spans(a);
  const spB = spans(b);
  if (spA.length !== spB.length || spA.some((s, i) => s !== spB[i])) return SEMANTIC('code span changed');
  a = a.replace(CODE_SPAN, '⟨code⟩');
  b = b.replace(CODE_SPAN, '⟨code⟩');

  for (const step of BASE) {
    const na = step.apply(a);
    const nb = step.apply(b);
    if (a !== b && (na !== a || nb !== b) && stepMatters(a, b, na, nb)) rules.add(step.rule);
    a = na;
    b = nb;
  }
  if (oldText.includes('\r') !== newText.includes('\r')) rules.add('line_endings');
  if (a === b) return { cosmetic: true, rules: [...rules], semantic_reason: null, likely_typo: false };

  for (const step of SINGLE) {
    if (step.apply(a) === step.apply(b)) return { cosmetic: true, rules: [...rules, step.rule], semantic_reason: null, likely_typo: false };
  }
  const typo = looksLikeTypo(a, b);
  return SEMANTIC(typo ? 'one word changed by one letter (likely a typo fix, but it may be a different name or value)' : 'words, numbers, dates or identifiers changed', typo);
}

/** Did this normalization step remove a difference (rather than touch both sides identically)? */
function stepMatters(a: string, b: string, na: string, nb: string): boolean {
  if (a !== na !== (b !== nb)) return true;
  return (a === b) !== (na === nb) || closeness(na, nb) < closeness(a, b);
}

/** Length of the differing middle after the common prefix and suffix. */
function closeness(a: string, b: string): number {
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  let j = 0;
  while (j < a.length - i && j < b.length - i && a[a.length - 1 - j] === b[b.length - 1 - j]) j++;
  return Math.max(a.length, b.length) - i - j;
}
