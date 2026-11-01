/**
 * Cosmetic vs semantic edits. A supersession whose old and new text differ
 * only in ways that cannot change what an agent would do — whitespace, line
 * endings, reflow, quote style, punctuation, emphasis markers, list
 * numbering, hyphenation, letter case, a typo-level fix of an ordinary word,
 * or the date on a "Last reviewed" line — is recorded on the chain like any
 * other edit but is not surfaced as a retraction by default.
 *
 * Deterministic and conservative — a false "cosmetic" hides a real change,
 * which is far worse than a false alarm, so anything the rules cannot prove
 * harmless is semantic. In particular these always stay semantic:
 *   - any change inside a `code span` or a code block (beyond line endings
 *     and trailing whitespace);
 *   - any change to a "protected" token: one holding a digit, a path or URL
 *     separator, `@`, `=`, `~`, an internal `.`/`:`/`_`, or a leading
 *     `-`/`--` (numbers, hosts, paths, flags, versions, identifiers),
 *     including a reorder of such tokens;
 *   - any change on a command-like line (one with a flag, a path, `./x`, an
 *     `a=b`, a `$ ` prompt or a code span): every token there is protected;
 *   - a hyphenated token that changes other than by dropping a hyphen
 *     followed by 3+ letters (`e-mail` → `email`; never `staging-a` →
 *     `staging-b`);
 *   - a word swap that is not a one-letter typo of a purely alphabetic word
 *     of 5+ letters with the same first letter (so `now`/`not`, `prod1`,
 *     `staging-a` never qualify), any change to a meaning-bearing word
 *     (not/never/must/enable/east/...), and added or removed words
 *     (`must` → `must not`, `do` → `don't`).
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

const EDGE = /^["'()[\]{}<>*_,;:!?.\u2026]+|["'()[\]{}<>*_,;:!?.\u2026]+$/g;

/** A line that reads like a command or config: every token on it carries meaning. */
function commandLike(line: string): boolean {
  if (/^\s*[$>#]\s/.test(line) || /`/.test(line)) return true;
  return line.split(/\s+/).some((raw) => {
    const t = raw.replace(/^["'([]+/, '');
    return /^(?:\.{1,2}\/|~\/|\/\w)/.test(t) || /^-{1,2}[\p{L}\p{N}]/u.test(t) || /\w\/\w/.test(t) || /\w=/.test(t);
  });
}

/** Tokens whose exact spelling carries meaning: numbers, hosts, paths, flags, identifiers, anything on a command line. */
function protectedTokens(text: string): string[] {
  const out: string[] = [];
  for (const line of text.split('\n')) {
    const cmd = commandLike(line);
    for (const raw of line.split(/\s+/)) {
      const t = raw.replace(EDGE, '');
      if (t.length === 0) continue;
      if (cmd || /\d/.test(t) || /[/\\@=#$%&~^|]/.test(t) || /\w[._:]\w/.test(t) || /^-{1,2}\w/.test(raw.replace(/^["'(]+/, ''))) out.push(t);
    }
  }
  return out;
}

type Step = { rule: CosmeticRule; apply: (s: string) => string };

// Normalizations that cannot change a word. Hyphens and letter case are NOT
// normalized globally: they are judged per aligned token pair below.
const STEPS: Step[] = [
  { rule: 'line_endings', apply: (s) => s.replace(/\r\n?/g, '\n') },
  { rule: 'quotes', apply: (s) => s.normalize('NFKC').replace(/[\u201c\u201d\u201e\u201f\u2033\u00ab\u00bb]/g, '"').replace(/[\u2018\u2019\u201a\u201b\u2032]/g, "'") },
  { rule: 'list_markers', apply: (s) => s.replace(/^[ \t]*(?:\d{1,4}[.)]|[-*+])[ \t]+/gm, '\u2022 ') },
  {
    rule: 'emphasis',
    // *x* / _x_ / **x** / __x__ markers at word edges; `a_b_c` identifiers are left alone.
    apply: (s) => s.replace(/(?<![\p{L}\p{N}*_])[*_]{1,3}(?=[\p{L}\p{N}])/gu, '').replace(/(?<=[\p{L}\p{N}.!?])[*_]{1,3}(?![\p{L}\p{N}*_])/gu, ''),
  },
  { rule: 'punctuation', apply: (s) => s.replace(/[.,;:!?\u2026]+(?=\s|$)/g, '').replace(/^[.,;:!?\u2026]+/gm, '') },
  { rule: 'whitespace', apply: (s) => s.replace(/\s+/g, ' ').trim() },
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

const ALPHA = /^\p{L}+$/u;
/** Letters joined by hyphens, every hyphen followed by 3+ letters (`e-mail`, `follow-up`; not `staging-a`). */
const SOFT_HYPHENATED = /^\p{L}+(?:-\p{L}{3,})+$/u;

/** Why one aligned token pair is cosmetic, or null when it is not. */
function pairRule(x: string, y: string): CosmeticRule | null {
  const lx = x.toLowerCase();
  const ly = y.toLowerCase();
  // Same word, different case (NEVER → Never): harmless even for meaning words.
  if (ALPHA.test(x) && ALPHA.test(y) && lx === ly) return 'case';
  if (MEANING_WORDS.has(lx) || MEANING_WORDS.has(ly)) return null;
  // Hyphenation: only dropping/adding a hyphen, same letters, same case.
  if ((SOFT_HYPHENATED.test(x) && ALPHA.test(y)) || (ALPHA.test(x) && SOFT_HYPHENATED.test(y))) {
    return x.replace(/-/g, '') === y.replace(/-/g, '') ? 'hyphenation' : null;
  }
  // One-letter typo: purely alphabetic words of 5+ letters, same first letter.
  if (!ALPHA.test(x) || !ALPHA.test(y)) return null;
  if (Math.min(x.length, y.length) < 5 || lx[0] !== ly[0]) return null;
  return editDistance(lx, ly) <= 1 ? 'typo' : null;
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
  // A "Last reviewed: <date>" line: the date is bookkeeping, not an instruction.
  const sa = stampDates(oldText);
  const sb = stampDates(newText);
  if (sa.dates.join('\n') !== sb.dates.join('\n')) rules.add('review_stamp');
  let a = sa.text;
  let b = sb.text;

  const spansA = codeSpans(a);
  const spansB = codeSpans(b);
  if (spansA.length !== spansB.length || spansA.some((s, i) => s !== spansB[i])) return SEMANTIC('code span changed');

  // Protected tokens are compared exactly (quote style aside), in order.
  const quote = STEPS[1]!.apply;
  const pa = protectedTokens(quote(a.replace(/\r\n?/g, '\n')));
  const pb = protectedTokens(quote(b.replace(/\r\n?/g, '\n')));
  if (pa.length !== pb.length || pa.some((t, i) => t !== pb[i])) {
    const changed = pa.filter((t, i) => t !== pb[i]).concat(pb.filter((t, i) => t !== pa[i]));
    return SEMANTIC(`number, path, host, flag, identifier or command changed (${changed.slice(0, 2).join(' / ') || 'order'})`);
  }
  // Code spans are equal and in the same order: take them out of the comparison.
  a = a.replace(CODE_SPAN, ' \u27e8code\u27e9 ');
  b = b.replace(CODE_SPAN, ' \u27e8code\u27e9 ');

  for (const step of STEPS) {
    if (a === b) break;
    const na = step.apply(a);
    const nb = step.apply(b);
    if ((na !== a || nb !== b) && stepMatters(a, b, na, nb)) rules.add(step.rule);
    a = na;
    b = nb;
  }
  if (a === b) return { cosmetic: true, rules: [...rules], semantic_reason: null };

  // Token by token: at most two pairs, each a case change, a soft hyphen or a one-letter typo.
  const ta = a.split(' ');
  const tb = b.split(' ');
  if (ta.length !== tb.length) return SEMANTIC('words added or removed');
  const diffs: [string, string][] = [];
  for (let i = 0; i < ta.length; i++) if (ta[i] !== tb[i]) diffs.push([ta[i]!, tb[i]!]);
  if (diffs.length > 2) return SEMANTIC(`${diffs.length} words changed`);
  for (const [x, y] of diffs) {
    const r = pairRule(x, y);
    if (!r) return SEMANTIC(`word changed: "${x}" → "${y}"`);
    rules.add(r);
  }
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
