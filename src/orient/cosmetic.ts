/**
 * Cosmetic vs semantic edits. A supersession whose old and new text differ
 * only in ways that cannot change what an agent would do — whitespace, line
 * endings, reflow, quote style, punctuation, emphasis markers, list
 * numbering, hyphenation, letter case, a typo-level fix of an ordinary word,
 * or the date on a "Last reviewed" line — is recorded on the chain like any
 * other edit but is not surfaced as a retraction by default.
 *
 * Deterministic and conservative: anything the rules cannot prove harmless
 * is semantic. In particular these always stay semantic:
 *   - any change inside a `code span` or a code block (beyond line endings
 *     and trailing whitespace);
 *   - any change to a "protected" token: one holding a digit, a path or URL
 *     separator, `@`, `=`, an internal `.`/`:`/`_`, or a leading `-`/`--`
 *     (numbers, hosts, paths, flags, versions, identifiers) — including a
 *     reorder of such tokens;
 *   - a word swap that is not a one-letter typo (two letters for words of 8+),
 *     a word whose first letter changes, a word shorter than 4 letters, and
 *     any change to a meaning-bearing word (not/never/must/enable/east/...).
 *
 * Ported in spirit from IsoKron's trivial-edit rules and checked against the
 * agent-memory-bench benign-edit templates plus semantic counter-cases
 * (test/cosmetic.test.ts).
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
  'typo',
  'review_stamp',
] as const;
export type CosmeticRule = (typeof COSMETIC_RULES)[number];

export interface EditClass {
  cosmetic: boolean;
  /** Rules that explain the difference (cosmetic), or empty. */
  rules: CosmeticRule[];
  /** Why it is semantic (null when cosmetic). */
  semantic_reason: string | null;
}

const SEMANTIC = (why: string): EditClass => ({ cosmetic: false, rules: [], semantic_reason: why });

/** Meaning-bearing words: a "typo fix" that touches one of these is never cosmetic. */
const MEANING_WORDS = new Set(
  (
    'not no nor never now always must should shall may might can cannot cant wont dont doesnt isnt arent wasnt ' +
    'do does did will would only all any none every each some before after above below over under up down on off in out ' +
    'into onto enable enabled enables disable disabled disables unable allow allowed allows deny denied denies block blocked ' +
    'open opened close closed start started stop stopped true false yes min max minimum maximum more less most least first ' +
    'last next previous prev old new prod production staging stage dev test primary secondary replica read write add ' +
    'remove include exclude increase decrease higher lower high low east west north south left right inbound outbound ' +
    'accept reject pass fail required optional public private internal external sync async lock unlock'
  ).split(' '),
);

const MONTH = '(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)';
const DATE_TOKEN = new RegExp(
  [
    '\\d{4}-\\d{2}-\\d{2}(?:[T ][0-9:.]+(?:Z|[+-]\\d{2}:?\\d{2})?)?',
    '\\d{1,2}[/.]\\d{1,2}[/.]\\d{2,4}',
    `${MONTH}\\.?\\s+\\d{1,2}(?:st|nd|rd|th)?,?\\s+\\d{4}`,
    `\\d{1,2}(?:st|nd|rd|th)?\\s+${MONTH}\\.?,?\\s+\\d{4}`,
    `${MONTH}\\.?\\s+\\d{4}`,
  ].join('|'),
  'gi',
);
/** A "Last reviewed: <date>" style line (the whole line is a stamp). */
const STAMP_LINE =
  /^\s*(?:[>*_-]+\s*)*(?:last\s+(?:reviewed|updated|modified|edited|checked|verified|revised|changed)|(?:reviewed|updated|modified|revised|verified|edited)(?:\s+(?:on|at))?|review(?:ed)?\s+date|as\s+of)\b.{0,100}$/i;

function stampDates(text: string): { text: string; dates: string[] } {
  const dates: string[] = [];
  const lines = text.split('\n').map((line) => {
    if (!STAMP_LINE.test(line)) return line;
    return line.replace(DATE_TOKEN, (d) => {
      dates.push(d);
      return '\u27e8date\u27e9';
    });
  });
  return { text: lines.join('\n'), dates };
}

const CODE_SPAN = /(`+)([\s\S]*?)\1/g;

function codeSpans(text: string): string[] {
  return [...text.matchAll(CODE_SPAN)].map((m) => m[2]!.trim());
}

const EDGE = /^["'()[\]{}<>*_,;:!?.…]+|["'()[\]{}<>*_,;:!?.…]+$/g;

/** Tokens whose exact spelling carries meaning: numbers, hosts, paths, flags, identifiers. */
function protectedTokens(text: string): string[] {
  const out: string[] = [];
  for (const raw of text.split(/\s+/)) {
    const t = raw.replace(EDGE, '');
    if (t.length === 0) continue;
    if (/\d/.test(t) || /[/\\@=#$%&~^|]/.test(t) || /\w[._:]\w/.test(t) || /^-{1,2}\w/.test(raw.replace(/^["'(]+/, ''))) out.push(t);
  }
  return out;
}

type Step = { rule: CosmeticRule; apply: (s: string) => string };

const STEPS: Step[] = [
  { rule: 'line_endings', apply: (s) => s.replace(/\r\n?/g, '\n') },
  { rule: 'quotes', apply: (s) => s.normalize('NFKC').replace(/[\u201c\u201d\u201e\u201f\u2033\u00ab\u00bb]/g, '"').replace(/[\u2018\u2019\u201a\u201b\u2032]/g, "'").replace(/[\u2010-\u2015]/g, '-') },
  { rule: 'list_markers', apply: (s) => s.replace(/^[ \t]*(?:\d{1,4}[.)]|[-*+])[ \t]+/gm, '\u2022 ') },
  {
    rule: 'emphasis',
    // *x* / _x_ / **x** / __x__ markers at word edges; `a_b_c` identifiers are left alone.
    apply: (s) => s.replace(/(?<![\p{L}\p{N}*_])[*_]{1,3}(?=[\p{L}\p{N}])/gu, '').replace(/(?<=[\p{L}\p{N}.!?])[*_]{1,3}(?![\p{L}\p{N}*_])/gu, ''),
  },
  { rule: 'hyphenation', apply: (s) => s.replace(/(?<=\p{L})-(?=\p{L})/gu, '') },
  { rule: 'punctuation', apply: (s) => s.replace(/[.,;:!?\u2026]+(?=\s|$)/g, '').replace(/^[.,;:!?\u2026]+/gm, '') },
  { rule: 'whitespace', apply: (s) => s.replace(/\s+/g, ' ').trim() },
  { rule: 'case', apply: (s) => s.toLowerCase() },
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

function typoLevel(a: string, b: string): boolean {
  if (!/^\p{L}+$/u.test(a) || !/^\p{L}+$/u.test(b)) return false;
  if (MEANING_WORDS.has(a) || MEANING_WORDS.has(b)) return false;
  const len = Math.min(a.length, b.length);
  if (len < 4 || a[0] !== b[0]) return false;
  return editDistance(a, b) <= (len >= 8 ? 2 : 1);
}

/**
 * Classify the edit from `oldText` to `newText` (one block's content).
 * `kind` is the block kind; code blocks only tolerate line endings and
 * trailing whitespace.
 */
export function classifyEdit(oldText: string, newText: string, kind?: string): EditClass {
  if (oldText === newText) return { cosmetic: true, rules: [], semantic_reason: null };
  if (kind === 'code') {
    const norm = (s: string) => s.replace(/\r\n?/g, '\n').replace(/[ \t]+$/gm, '').trimEnd();
    return norm(oldText) === norm(newText) ? { cosmetic: true, rules: ['whitespace'], semantic_reason: null } : SEMANTIC('code block changed');
  }
  const rules = new Set<CosmeticRule>();
  let a = oldText;
  let b = newText;
  // A "Last reviewed: <date>" line: the date is bookkeeping, not an instruction.
  const sa = stampDates(a);
  const sb = stampDates(b);
  if (sa.dates.join('\n') !== sb.dates.join('\n')) rules.add('review_stamp');
  a = sa.text;
  b = sb.text;

  const spansA = codeSpans(a);
  const spansB = codeSpans(b);
  if (spansA.length !== spansB.length || spansA.some((s, i) => s !== spansB[i])) return SEMANTIC('code span changed');
  // Code spans are equal and in the same order: take them out of the comparison.
  a = a.replace(CODE_SPAN, ' \u27e8code\u27e9 ');
  b = b.replace(CODE_SPAN, ' \u27e8code\u27e9 ');

  const quote = STEPS[1]!.apply;
  const pa = protectedTokens(quote(a));
  const pb = protectedTokens(quote(b));
  if (pa.length !== pb.length || pa.some((t, i) => t !== pb[i])) {
    const changed = pa.filter((t, i) => t !== pb[i]).concat(pb.filter((t, i) => t !== pa[i]));
    return SEMANTIC(`number, path, host, flag or identifier changed (${changed.slice(0, 2).join(' / ') || 'order'})`);
  }

  for (const step of STEPS) {
    if (a === b) break;
    const na = step.apply(a);
    const nb = step.apply(b);
    if ((na !== a || nb !== b) && stepMatters(a, b, na, nb)) rules.add(step.rule);
    a = na;
    b = nb;
  }
  if (a === b) return { cosmetic: true, rules: [...rules], semantic_reason: null };

  // Typo-level: same token count, at most two ordinary words each one letter off.
  const ta = a.split(' ');
  const tb = b.split(' ');
  if (ta.length !== tb.length) return SEMANTIC('words added or removed');
  const diffs: [string, string][] = [];
  for (let i = 0; i < ta.length; i++) if (ta[i] !== tb[i]) diffs.push([ta[i]!, tb[i]!]);
  if (diffs.length > 2) return SEMANTIC(`${diffs.length} words changed`);
  for (const [x, y] of diffs) {
    if (!typoLevel(x, y)) return SEMANTIC(`word changed: "${x}" → "${y}"`);
  }
  rules.add('typo');
  return { cosmetic: true, rules: [...rules], semantic_reason: null };
}

/** Did this normalization step remove a difference (rather than touch both sides identically)? */
function stepMatters(a: string, b: string, na: string, nb: string): boolean {
  const da = a !== na;
  const db = b !== nb;
  if (da !== db) return true;
  // Both sides changed: it matters when the step brought them closer.
  return (a === b) !== (na === nb) || levenshteinish(na, nb) < levenshteinish(a, b);
}

/** Cheap closeness proxy: length of the differing middle after the common prefix and suffix. */
function levenshteinish(a: string, b: string): number {
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  let j = 0;
  while (j < a.length - i && j < b.length - i && a[a.length - 1 - j] === b[b.length - 1 - j]) j++;
  return Math.max(a.length, b.length) - i - j;
}
