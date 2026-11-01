/**
 * Exec-time pulse shims: which invocations of a tool are world-changing.
 *
 * One rule table, two implementations of the same decision:
 *   - `classify()` below (TypeScript): `kronicle-lite shim exec` (the Windows
 *     wrappers) and `shim status`;
 *   - the POSIX sh wrapper generated from the same table (script.ts), which
 *     decides without starting node, so a read-only `git status` costs a few
 *     shell builtins.
 * test/shim-*.test.ts runs one decision table through both and requires them
 * to agree.
 *
 * Matcher semantics follow cc-anchor's PreToolUse pulse (scripts/pulse.jq):
 * the tool's own global options are skipped before the verb
 * (`git -C x --no-pager push` → `git push`, `kubectl -n prod apply`,
 * `terraform -chdir=infra apply`, `npm --prefix x publish`); later quoted
 * arguments never count (`git commit -m "git push"` is a commit). A shim sees
 * argv after the shell removed the quotes, so `"git" "push"` is `git push`.
 *
 * Conservative where it is cheap: when the word just before the verb is an
 * option the table does not know, that option may have taken the word as its
 * value (`npm --registry https://r publish`), so the next word is tried as the
 * verb too. A false "world-changing" costs one pulse (~0.3 s, and a denial only
 * when something is unreconciled); a miss costs a stale deploy.
 */

/** Script / make-target words that mean "this changes the world" (= cc-anchor's default pulse_match words). */
export const WORLD_WORDS = ['deploy', 'migrate', 'publish', 'release'] as const;

export interface ToolSpec {
  /** Options before the verb that take the NEXT argument as their value (`-C dir`). `--opt=value` never needs listing. */
  globalValueOpts: string[];
  /** Options after the verb that take a value (`git subtree -P prefix push`). */
  subValueOpts: string[];
  /** Verb sequences (space-separated words, `*` = any one word) that are world-changing; matched as a prefix. */
  world: string[];
  /** Sequences that are read-only although a `world` prefix matches (`kubectl rollout status`). Checked first. */
  except: string[];
  /** `run` / `run-script` SCRIPT where SCRIPT contains a WORLD_WORDS word (npm, pnpm, yarn). */
  scriptRun?: boolean;
  /** The first word may itself be a script name (`yarn deploy`, `pnpm release`). */
  directScript?: boolean;
  /** Any non-option, non-assignment argument with a WORLD_WORDS word (`make release`). */
  anyTarget?: boolean;
  /** `--help` anywhere makes the invocation read-only (built-in tools only). */
  help?: boolean;
  /** Every invocation is world-changing (a command with no rules: a deploy script). */
  all?: boolean;
}

const GIT_GLOBAL = ['-C', '-c', '--git-dir', '--work-tree', '--namespace', '--exec-path', '--super-prefix', '--config-env'];
const KUBE_GLOBAL = [
  '-n',
  '--namespace',
  '--context',
  '--kubeconfig',
  '--cluster',
  '--user',
  '-s',
  '--server',
  '--as',
  '--as-group',
  '--as-uid',
  '--token',
  '--request-timeout',
  '-v',
  '--certificate-authority',
  '--client-certificate',
  '--client-key',
  '--cache-dir',
  '--tls-server-name',
  '--profile',
  '--profile-output',
  '--log-file',
  '--password',
  '--username',
];
const KUBE_WORLD = ['apply', 'delete', 'patch', 'replace', 'rollout', 'create', 'scale', 'set', 'edit', 'label', 'annotate', 'drain', 'cordon', 'uncordon', 'taint', 'autoscale', 'expose'];
const KUBE_EXCEPT = ['rollout status', 'rollout history'];

const npmFamily = (globalValueOpts: string[], extra: Partial<ToolSpec> = {}): ToolSpec => ({
  globalValueOpts,
  subValueOpts: globalValueOpts,
  world: ['publish'],
  except: [],
  scriptRun: true,
  help: true,
  ...extra,
});

/** Built-in rules. `git,terraform,tofu,kubectl,helm,npm,pnpm,yarn` are installed by default; `oc` and `make` on request. */
export const BUILTIN_TOOLS: Record<string, ToolSpec> = {
  git: { globalValueOpts: GIT_GLOBAL, subValueOpts: ['-P', '--prefix'], world: ['push', 'subtree push', 'lfs push'], except: [], help: true },
  terraform: { globalValueOpts: [], subValueOpts: [], world: ['apply', 'destroy'], except: [], help: true },
  tofu: { globalValueOpts: [], subValueOpts: [], world: ['apply', 'destroy'], except: [], help: true },
  kubectl: { globalValueOpts: KUBE_GLOBAL, subValueOpts: KUBE_GLOBAL, world: KUBE_WORLD, except: KUBE_EXCEPT, help: true },
  oc: { globalValueOpts: KUBE_GLOBAL, subValueOpts: KUBE_GLOBAL, world: KUBE_WORLD, except: KUBE_EXCEPT, help: true },
  helm: {
    globalValueOpts: ['-n', '--namespace', '--kube-context', '--kubeconfig', '--kube-apiserver', '--kube-as-user', '--kube-token', '--registry-config', '--repository-config', '--repository-cache'],
    subValueOpts: ['-n', '--namespace', '--kube-context', '--kubeconfig'],
    world: ['install', 'upgrade', 'uninstall', 'delete', 'del', 'un', 'rollback'],
    except: [],
    help: true,
  },
  npm: npmFamily(['--prefix', '-w', '--workspace', '--userconfig', '--globalconfig', '--registry', '--cache', '--otp', '--tag', '--access']),
  pnpm: npmFamily(['-C', '--dir', '--filter', '-F', '--registry', '--config-dir', '--otp', '--tag', '--access'], { directScript: true }),
  yarn: npmFamily(['--cwd', '--registry', '--otp', '--tag', '--access'], { world: ['publish', 'npm publish'], directScript: true }),
  make: { globalValueOpts: ['-C', '-f', '--directory', '--file', '--makefile', '-I', '--include-dir', '-o', '-W'], subValueOpts: [], world: [], except: [], anyTarget: true, help: true },
};

export const DEFAULT_COMMANDS = ['git', 'terraform', 'tofu', 'kubectl', 'helm', 'npm', 'pnpm', 'yarn'] as const;

export const TOOL_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;
/** Words allowed in a user pattern: no shell glob or quoting characters. `*` alone = any one word. */
export const PATTERN_WORD_RE = /^(\*|[A-Za-z0-9._:/@+=%,-]{1,128})$/;

/**
 * Parse user patterns (`--world "make release,docker push,deploy-prod"`):
 * "TOOL [WORD…]" each; TOOL alone means every invocation of TOOL.
 */
export function parsePatterns(patterns: string[]): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const raw of patterns) {
    const words = raw.trim().split(/\s+/).filter((w) => w.length > 0);
    if (words.length === 0) continue;
    const [tool, ...rest] = words as [string, ...string[]];
    if (!TOOL_NAME_RE.test(tool)) throw new Error(`world pattern "${raw}": "${tool}" is not a command name`);
    for (const w of rest) {
      if (!PATTERN_WORD_RE.test(w)) throw new Error(`world pattern "${raw}": word "${w}" may use only letters, digits and . _ : / @ + = % , - (or be *)`);
    }
    const list = out.get(tool) ?? [];
    list.push(rest.length === 0 ? '*ALL*' : rest.join(' '));
    out.set(tool, list);
  }
  return out;
}

/** The rule set for one shimmed tool: built-in rules plus the user's patterns for it. */
export function specFor(tool: string, userPatterns: string[] = []): ToolSpec {
  const base = BUILTIN_TOOLS[tool];
  const all = userPatterns.includes('*ALL*');
  const extra = userPatterns.filter((p) => p !== '*ALL*');
  if (!base) {
    // Unknown command: every invocation unless the user said which ones.
    return { globalValueOpts: [], subValueOpts: [], world: extra, except: [], all: all || extra.length === 0 };
  }
  return { ...base, world: [...base.world, ...extra], ...(all ? { all: true } : {}) };
}

/** Longest verb sequence any rule needs (positional words to collect, before the shifted retry). */
export function seqDepth(spec: ToolSpec): number {
  let n = 1;
  for (const s of [...spec.world, ...spec.except]) n = Math.max(n, s.split(' ').length);
  if (spec.scriptRun) n = Math.max(n, 2);
  return n;
}

const WORD_RE = new RegExp(`(?<![A-Za-z0-9_])(?:${WORLD_WORDS.join('|')})(?![A-Za-z0-9_])`);

/** A script / target name that names a world-changing step (`deploy`, `release:prod`, `db-migrate`; not `predeploy`). */
export function hasWorldWord(s: string): boolean {
  return WORD_RE.test(s);
}

function seqMatches(pattern: string, words: string[]): boolean {
  const p = pattern.split(' ');
  for (let i = 0; i < p.length; i++) {
    const w = words[i];
    if (w === undefined || w === '') return false;
    if (p[i] !== '*' && p[i] !== w) return false;
  }
  return true;
}

export interface Classification {
  world: boolean;
  /** Why (for status / tests): the rule that matched, or why it is read-only. */
  rule: string;
}

/**
 * Collect the positional words after the tool's global options. Returns the
 * words and whether the word before the first one was an option the table
 * does not know (so the first word may be that option's value).
 */
function positionals(spec: ToolSpec, args: readonly string[], want: number): { words: string[]; shift: boolean } {
  const words: string[] = [];
  let skip = false;
  let prevOpt = false;
  let shift = false;
  let dashdash = false;
  for (const a of args) {
    if (skip) {
      skip = false;
      prevOpt = false;
      continue;
    }
    if (!dashdash && a === '--') {
      dashdash = true;
      prevOpt = false;
      continue;
    }
    if (!dashdash && a.length > 1 && a.startsWith('-')) {
      const opts = words.length === 0 ? spec.globalValueOpts : spec.subValueOpts;
      if (opts.includes(a)) {
        skip = true;
        prevOpt = false;
      } else {
        prevOpt = !a.includes('=');
      }
      continue;
    }
    if (words.length === 0) shift = prevOpt;
    prevOpt = false;
    words.push(a);
    if (words.length >= want) break;
  }
  return { words, shift };
}

export function classify(spec: ToolSpec, args: readonly string[]): Classification {
  if (spec.all) return { world: true, rule: 'every invocation' };
  let hit: string | null = null;
  if (spec.anyTarget) {
    for (const a of args) {
      if (a.startsWith('-') || /^[A-Za-z_][A-Za-z0-9_]*=/.test(a)) continue;
      if (hasWorldWord(a)) {
        hit = `target ${a}`;
        break;
      }
    }
  }
  if (hit === null) {
    const depth = seqDepth(spec);
    const { words, shift } = positionals(spec, args, depth + 1);
    const candidates = shift ? [words, words.slice(1)] : [words];
    for (const c of candidates) {
      if (spec.except.some((p) => seqMatches(p, c))) continue;
      const w = spec.world.find((p) => seqMatches(p, c));
      if (w !== undefined) {
        hit = w;
        break;
      }
      if (spec.scriptRun && (c[0] === 'run' || c[0] === 'run-script') && c[1] !== undefined && hasWorldWord(c[1])) {
        hit = `${c[0]} ${c[1]}`;
        break;
      }
      if (spec.directScript && c[0] !== undefined && hasWorldWord(c[0])) {
        hit = `script ${c[0]}`;
        break;
      }
    }
  }
  if (hit === null) return { world: false, rule: 'read-only' };
  if (spec.help && args.includes('--help')) return { world: false, rule: '--help' };
  return { world: true, rule: hit };
}
