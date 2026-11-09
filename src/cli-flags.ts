/**
 * 0.9.0: which options each CLI command takes (pulse / shim parse their own argv). An option a
 * command does not know is an error, not a no-op: `orient --bogus` used to exit 0, and a typo such
 * as `verify-bundle --max-byte 1000` ran with the default. Ported from mcp-catalog-snap 0.2.0.
 */

const GLOBAL = ['data-dir'];
const ANCHOR = ['url', 'key', 'insecure-http'];
const RANGE = ['from', 'to', 'full'];

export const COMMAND_OPTIONS: Readonly<Record<string, readonly string[]>> = {
  serve: ['actor', 'all-projects', 'allow-host', 'allow-origin', 'bearer', 'bearer-file', 'core', 'host', 'http', 'modern-only', 'port', 'cwd'],
  'verify-chain': [...RANGE],
  'verify-bundle': ['allow-hardlinks', 'allow-missing', 'json', 'key', 'max-bytes', 'strict'],
  audit: ['media-type', 'redact-secrets', 'audit-id', 'in', 'json', 'actor', 'kind', 'findings', 'fingerprint', 'finding', 'out'],
  rebuild: [],
  demo: ['dir', 'keep'],
  checkpoint: ['from', 'to', 'push', ...ANCHOR],
  verify: ['json', 'offline', 'remote', ...ANCHOR, ...RANGE],
  anchor: ['json', ...ANCHOR],
  export: ['out'],
  import: ['allow-secrets', 'in'],
  keys: [],
  put: ['actor', 'all-projects', 'bind-git', 'cursor', 'from-instructions', 'json', 'redact-secrets', 'title', 'derived-from', 'cwd', 'stdin-hook'],
  orient: ['actor', 'all-projects', 'budget', 'cursor', 'focus', 'include-cosmetic', 'include-format-only', 'json', 'pending-actor', 'cwd'],
  // --cwd is accepted (no effect) on get / supersede: hooks pass it to every document command.
  supersede: ['actor', 'cursor', 'json', 'reason', 'redact-secrets', 'derived-from', 'cwd'],
  get: ['actor', 'block', 'json', 'cwd'],
  pending: ['actor', 'all-projects', 'json', 'limit', 'cwd'],
  watch: ['actor', 'debounce', 'interval', 'json', 'list', 'once', 'poll', 'redact-secrets', 'cwd'],
  doctor: ['cwd', 'no-network', 'full', 'json'],
};

/** Options that may be given more than once (their values are joined with commas). */
export const REPEATABLE: ReadonlySet<string> = new Set(['allow-host', 'allow-origin']);

/** Most positional arguments a command takes (absent: not checked, e.g. audit / anchor subcommands). */
const MAX_POSITIONALS: Readonly<Record<string, number>> = {
  serve: 0,
  'verify-chain': 0,
  'verify-bundle': 1,
  rebuild: 0,
  demo: 0,
  checkpoint: 0,
  verify: 0,
  export: 0,
  import: 0,
  keys: 0,
  put: 2,
  orient: 0,
  supersede: 2,
  get: 1,
  pending: 0,
  doctor: 0,
};

function distance(a: string, b: string): number {
  const prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0]!;
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const up = prev[j]!;
      prev[j] = Math.min(up + 1, prev[j - 1]! + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = up;
    }
  }
  return prev[b.length]!;
}

function closest(name: string, known: readonly string[]): string | null {
  let best: string | null = null;
  let bestD = 3;
  for (const k of known) {
    const d = distance(name, k);
    if (d < bestD) [best, bestD] = [k, d];
  }
  return best;
}

/**
 * Throw on an option the command does not take (with a did-you-mean), a single-value option given
 * twice, a boolean given a value other than true/false, or a stray positional. Unknown commands
 * are left to the caller.
 */
export function validateFlags(
  cmd: string,
  flags: Record<string, string | true>,
  positional: readonly string[],
  repeated: readonly string[],
  booleans: ReadonlySet<string>,
): void {
  if (!Object.hasOwn(COMMAND_OPTIONS, cmd)) return;
  const known = [...COMMAND_OPTIONS[cmd]!, ...GLOBAL];
  for (const name of Object.keys(flags)) {
    if (known.includes(name)) continue;
    const hint = closest(name, known);
    throw new Error(`unknown option --${name} for ${cmd}${hint ? ` (did you mean --${hint}?)` : ''}; see kronicle-lite help`);
  }
  for (const name of repeated) if (!REPEATABLE.has(name)) throw new Error(`--${name} given more than once`);
  for (const name of Object.keys(flags)) {
    const v = flags[name];
    if (booleans.has(name) && typeof v === 'string' && !['true', 'false', '1', '0'].includes(v)) {
      throw new Error(`--${name} takes no value (or true / false), got ${JSON.stringify(v)}`);
    }
    if (booleans.has(name) && (v === 'false' || v === '0')) delete flags[name];
    else if (booleans.has(name)) flags[name] = true;
  }
  const max = MAX_POSITIONALS[cmd];
  if (max !== undefined && positional.length > max) throw new Error(`unexpected argument ${JSON.stringify(positional[max])} for ${cmd}`);
}
