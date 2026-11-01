/**
 * Compact, bounded word diff for retractions (0.5.0): show what changed in
 * words, git `--word-diff=plain` style (`[-old-]{+new+}`), with unchanged
 * runs longer than a few words elided to `…`. Deterministic, no
 * dependencies; falls back to `[-old-]{+new+}` of the whole snippet when the
 * inputs are too long for the O(n·m) LCS.
 */

const MAX_TOKENS = 400;
const CONTEXT = 4;

function tokens(s: string): string[] {
  // Words and the whitespace between them, so the output re-joins exactly.
  return s.match(/\s+|[^\s]+/g) ?? [];
}

/** Collapse whitespace and cut to `max` characters with an ellipsis. */
export function snippet(s: string, max = 160): string {
  const one = s.replace(/\s+/g, ' ').trim();
  return one.length <= max ? one : one.slice(0, max - 1).trimEnd() + '…';
}

type Op = { op: '=' | '-' | '+'; text: string };

function lcsOps(a: string[], b: string[]): Op[] {
  const n = a.length;
  const m = b.length;
  // dp[i][j] = LCS length of a[i..], b[j..]
  const dp: Uint16Array[] = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i]![j] = a[i] === b[j] ? dp[i + 1]![j + 1]! + 1 : Math.max(dp[i + 1]![j]!, dp[i]![j + 1]!);
    }
  }
  const out: Op[] = [];
  let i = 0;
  let j = 0;
  const push = (op: Op['op'], text: string) => {
    const last = out[out.length - 1];
    if (last && last.op === op) last.text += text;
    else out.push({ op, text });
  };
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      push('=', a[i]!);
      i++;
      j++;
    } else if (dp[i + 1]![j]! >= dp[i]![j + 1]!) {
      push('-', a[i]!);
      i++;
    } else {
      push('+', b[j]!);
      j++;
    }
  }
  while (i < n) push('-', a[i++]!);
  while (j < m) push('+', b[j++]!);
  return out;
}

function elide(text: string, where: 'start' | 'middle' | 'end'): string {
  const t = tokens(text);
  const words = t.filter((x) => !/^\s+$/.test(x)).length;
  if (words <= CONTEXT * 2) return text.replace(/\s+/g, ' ');
  const keepTail = (n: number) => {
    let seen = 0;
    let k = t.length;
    while (k > 0 && seen < n) if (!/^\s+$/.test(t[--k]!)) seen++;
    return t.slice(k).join('').replace(/\s+/g, ' ');
  };
  const keepHead = (n: number) => {
    let seen = 0;
    let k = 0;
    while (k < t.length && seen < n) if (!/^\s+$/.test(t[k++]!)) seen++;
    return t.slice(0, k).join('').replace(/\s+/g, ' ');
  };
  if (where === 'start') return '…' + keepTail(CONTEXT);
  if (where === 'end') return keepHead(CONTEXT) + '…';
  return keepHead(CONTEXT) + ' … ' + keepTail(CONTEXT);
}

/**
 * `old → new` as one line: unchanged words kept around each change, removed
 * words in `[-…-]`, added in `{+…+}`, at most `max` characters.
 */
export function wordDiff(oldText: string, newText: string, max = 400): string {
  const a = tokens(oldText);
  const b = tokens(newText);
  let s: string;
  if (a.length > MAX_TOKENS || b.length > MAX_TOKENS) {
    s = `[-${snippet(oldText, Math.floor(max / 2) - 6)}-]{+${snippet(newText, Math.floor(max / 2) - 6)}+}`;
  } else {
    const ops = lcsOps(a, b);
    s = ops
      .map((o, k) => {
        const flat = o.text.replace(/\s+/g, ' ');
        if (o.op === '-') return `[-${flat.trim()}-]`;
        if (o.op === '+') return `{+${flat.trim()}+}`;
        return elide(o.text, k === 0 ? 'start' : k === ops.length - 1 ? 'end' : 'middle');
      })
      .join('')
      // keep a space between adjacent markers and words the trim removed
      .replace(/-\]\{\+/g, '-]{+')
      .replace(/\s+/g, ' ')
      .trim();
  }
  return s.length <= max ? s : s.slice(0, max - 1) + '…';
}
