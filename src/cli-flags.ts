/**
 * 0.9.0: which options each CLI command takes (pulse / shim parse their own argv). An option a
 * command does not know is an error, not a no-op: `orient --bogus` used to exit 0, and a typo such
 * as `verify-bundle --max-byte 1000` ran with the default. Ported from mcp-catalog-snap 0.2.0.
 */

const GLOBAL = ['data-dir'];
const ANCHOR = ['url', 'key', 'anchor-key-file', 'insecure-http', 'genesis'];
const RANGE = ['from', 'to', 'full'];

export const COMMAND_OPTIONS: Readonly<Record<string, readonly string[]>> = {
  serve: ['actor', 'all-projects', 'allow-host', 'allow-origin', 'bearer', 'bearer-file', 'core', 'host', 'http', 'modern-only', 'port', 'cwd'],
  'verify-chain': [...RANGE],
  'verify-bundle': ['allow-hardlinks', 'allow-missing', 'json', 'key', 'max-bytes', 'strict'],
  'audit put-blob': ['media-type', 'redact-secrets'],
  'audit record': ['audit-id', 'in', 'json', 'actor'],
  'audit query': ['audit-id', 'fingerprint', 'kind', 'finding', 'findings', 'json'],
  'audit export': ['audit-id', 'out'],
  'audit stamp': ['anchor-id', 'out', 'tsa', 'json', 'allow-pending', ...ANCHOR],
  'audit package': ['audit-id', 'out', 'timestamps', 'tsa-roots', 'anchor-keys', 'genesis', 'allowed-signers', 'freeze-pending', 'tsa', 'no-stamp-sums', 'json'],
  'verify-audit': ['allow-hardlinks', 'allowed-signers', 'anchor-keys', 'genesis', 'json', 'key', 'key-fingerprint', 'max-bytes', 'no-tsa', 'profile', 'require', 'skip-claim', 'strict-freeze', 'tsa-at-gentime', 'tsa-roots'],
  rebuild: [],
  demo: ['dir', 'keep'],
  checkpoint: ['from', 'to', 'push', ...ANCHOR],
  verify: ['json', 'offline', 'remote', ...ANCHOR, ...RANGE],
  'anchor status': ['json', ...ANCHOR],
  'anchor keys': ['json', 'url', 'genesis'],
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

/** Commands whose options depend on a subcommand (the first positional). */
const WITH_SUBCOMMANDS: ReadonlySet<string> = new Set(['audit', 'anchor']);

/** Options that take a value but may be given bare on purpose (`--derived-from` alone: an explicit empty list). */
const OPTIONAL_VALUE: ReadonlySet<string> = new Set(['derived-from']);

/** Most positional arguments a command takes, the subcommand included (absent: not checked). */
const MAX_POSITIONALS: Readonly<Record<string, number>> = {
  'audit put-blob': 2,
  'audit record': 1,
  'audit query': 1,
  'audit export': 1,
  'audit stamp': 1,
  'audit package': 1,
  'verify-audit': 1,
  'anchor status': 1,
  'anchor keys': 3,
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
 * Throw on an option `label` does not take (with a did-you-mean), a value-taking option given no
 * value, a single-value option given twice, a boolean given a value other than true/false, or a
 * stray positional. Shared by the main CLI and `pulse` / `shim`.
 */
export function checkOptions(
  label: string,
  known: readonly string[],
  flags: Record<string, string | true>,
  positional: readonly string[],
  maxPositionals: number | undefined,
  repeated: readonly string[],
  booleans: ReadonlySet<string>,
  repeatable: ReadonlySet<string> = REPEATABLE,
): void {
  for (const name of Object.keys(flags)) {
    if (known.includes(name)) continue;
    const hint = closest(name, known);
    throw new Error(`unknown option --${name} for ${label}${hint ? ` (did you mean --${hint}?)` : ''}; see kronicle-lite help`);
  }
  for (const name of repeated) if (!repeatable.has(name)) throw new Error(`--${name} given more than once`);
  for (const name of Object.keys(flags)) {
    const v = flags[name];
    if (booleans.has(name)) {
      if (typeof v === 'string' && !['true', 'false', '1', '0'].includes(v)) throw new Error(`--${name} takes no value (or true / false), got ${JSON.stringify(v)}`);
      if (v === 'false' || v === '0') delete flags[name];
      else flags[name] = true;
    } else if (v === true && !OPTIONAL_VALUE.has(name)) {
      throw new Error(`--${name} needs a value`);
    }
  }
  if (maxPositionals !== undefined && positional.length > maxPositionals) throw new Error(`unexpected argument ${JSON.stringify(positional[maxPositionals])} for ${label}`);
}

/** checkOptions for the main CLI: the command's table (or its subcommand's). Unknown commands are left to the caller. */
export function validateFlags(
  cmd: string,
  flags: Record<string, string | true>,
  positional: readonly string[],
  repeated: readonly string[],
  booleans: ReadonlySet<string>,
): void {
  let key = cmd;
  if (WITH_SUBCOMMANDS.has(cmd)) {
    const sub = positional[0];
    if (sub === undefined || !Object.hasOwn(COMMAND_OPTIONS, `${cmd} ${sub}`)) {
      const subs = Object.keys(COMMAND_OPTIONS).filter((k) => k.startsWith(`${cmd} `)).map((k) => k.slice(cmd.length + 1));
      if (Object.keys(flags).some((f) => f !== 'data-dir')) throw new Error(`${cmd} needs a subcommand first (${subs.join(' | ')})`);
      return;
    }
    key = `${cmd} ${sub}`;
  }
  if (!Object.hasOwn(COMMAND_OPTIONS, key)) return;
  checkOptions(key, [...COMMAND_OPTIONS[key]!, ...GLOBAL], flags, positional, MAX_POSITIONALS[key], repeated, booleans);
}

/** `pulse` and the shim subcommands (src/shim/cli.ts): their own tables, same rules. */
const SHIM_GLOBAL = ['data-dir', 'cwd', 'json'];
export const SHIM_OPTIONS: Readonly<Record<string, readonly string[]>> = {
  pulse: ['state', 'default-data-dir', 'mode', 'actor', 'cursor', 'pending-actor', 'all-projects', 'invoking-actor', 'all-readers'],
  'shim install': ['dir', 'commands', 'world', 'mode', 'pending-actor', 'on-timeout', 'all-readers', 'git-hook', 'repo', 'windows', 'no-windows', 'posix', 'no-posix'],
  'shim uninstall': ['dir', 'git-hook', 'repo'],
  'shim status': ['dir'],
  'shim ack': ['actor', 'dir', 'operator', 'through'],
  'shim exec': ['dir', 'tool', 'project'],
  'shim help': [],
};

export function validateShimFlags(cmd: 'pulse' | 'shim', flags: Record<string, string | true>, positional: readonly string[], repeated: readonly string[], booleans: ReadonlySet<string>): void {
  const key = cmd === 'pulse' ? 'pulse' : `shim ${positional[0] ?? 'help'}`;
  if (!Object.hasOwn(SHIM_OPTIONS, key)) return; // unknown subcommand: the caller prints usage
  checkOptions(key, [...SHIM_OPTIONS[key]!, ...SHIM_GLOBAL], flags, positional, cmd === 'pulse' ? 0 : 1, repeated, booleans, new Set());
}
