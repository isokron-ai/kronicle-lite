/**
 * Which project a command acts on (H2-14). The shim used to judge the project
 * of the working directory, so `cd /tmp && git -C ~/work/api push` was checked
 * against /tmp. The pulse now takes the directory from the command itself:
 *
 *   git        `-C DIR` (cumulative, each relative to the previous; `-C ""` is
 *              a no-op), `--git-dir[=]G`, `--work-tree[=]W`, and the GIT_DIR /
 *              GIT_WORK_TREE environment (relative values resolve against the
 *              final `-C` directory, as git does). A work tree wins; a git dir
 *              maps to its repository (`/r/.git` → `/r`, `/r/.git/modules/x` →
 *              `/r`); a bare repository is its own project. Global options
 *              before the verb only.
 *   terraform, tofu   `-chdir=DIR` before the verb
 *   make       `-C DIR`, `-CDIR`, `--directory[=]DIR` anywhere (cumulative)
 *   npm        `--prefix[=]DIR` anywhere
 *   pnpm       `-C DIR`, `--dir[=]DIR` anywhere
 *   yarn       `--cwd[=]DIR` anywhere
 *
 * A directory option that names something that does not exist, or has no
 * value, is an error: the pulse refuses the command (fail closed). It would
 * fail anyway; checking the wrong project would not.
 */

import { statSync } from 'node:fs';
import { basename, dirname, resolve, sep } from 'node:path';

import { GIT_GLOBAL, toolBasename } from './rules.js';

export interface CommandTarget {
  /** Absolute directory whose project the command acts on. */
  dir: string;
  /** The directory came from the command (an option or GIT_DIR / GIT_WORK_TREE), not the working directory. */
  explicit: boolean;
  /** What set it (`-C`, `--git-dir`, `GIT_WORK_TREE`, …), or null. */
  via: string | null;
  /** Set when the target cannot be determined: the pulse refuses (fail closed). */
  error: string | null;
  /** git: GIT_DIR / GIT_WORK_TREE were folded into `dir` (resolve the project with them unset). */
  git_env: boolean;
}

/** `git`, `/usr/bin/git`, `git.exe`, `C:\…\git.cmd` → `git`. */
export const toolName = toolBasename;

function isDir(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

function exists(p: string): boolean {
  try {
    statSync(p);
    return true;
  } catch {
    return false;
  }
}

/** The repository a git dir belongs to: `/r/.git` → `/r`, `/r/.git/worktrees/w` → `/r`; else the dir itself (bare). */
export function repoOfGitDir(g: string): string {
  if (basename(g) === '.git') return dirname(g);
  const i = g.indexOf(`${sep}.git${sep}`);
  if (i > 0) return g.slice(0, i);
  return g;
}

/** Value of `--opt=v` / `--opt v` at args[i]; `undefined` when args[i] is not that option. */
function optValue(args: readonly string[], i: number, long: string): { value: string | null; used: number } | undefined {
  const a = args[i]!;
  if (a === long) return { value: args[i + 1] ?? null, used: 2 };
  if (a.startsWith(long + '=')) return { value: a.slice(long.length + 1), used: 1 };
  return undefined;
}

function gitTarget(args: readonly string[], cwd: string, env: NodeJS.ProcessEnv): CommandTarget {
  let cur = cwd;
  let via: string | null = null;
  let gitDir: string | undefined;
  let workTree: string | undefined;
  for (let i = 0; i < args.length; ) {
    const a = args[i]!;
    if (a === '--' || !a.startsWith('-') || a.length < 2) break; // the verb (or end of options)
    if (a === '-C') {
      const v = args[i + 1];
      if (v === undefined) return { dir: cur, explicit: true, via: '-C', error: 'git -C has no directory', git_env: false };
      if (v !== '') {
        cur = resolve(cur, v);
        via = '-C';
      }
      i += 2;
      continue;
    }
    const gd = optValue(args, i, '--git-dir');
    if (gd) {
      if (gd.value === null) return { dir: cur, explicit: true, via: '--git-dir', error: 'git --git-dir has no value', git_env: false };
      gitDir = gd.value;
      i += gd.used;
      continue;
    }
    const wt = optValue(args, i, '--work-tree');
    if (wt) {
      if (wt.value === null) return { dir: cur, explicit: true, via: '--work-tree', error: 'git --work-tree has no value', git_env: false };
      workTree = wt.value;
      i += wt.used;
      continue;
    }
    i += GIT_GLOBAL.includes(a) ? 2 : 1;
  }
  let gitEnv = false;
  let wtVia = '--work-tree';
  let gdVia = '--git-dir';
  if (workTree === undefined && env['GIT_WORK_TREE']) {
    workTree = env['GIT_WORK_TREE'];
    wtVia = 'GIT_WORK_TREE';
  }
  if (gitDir === undefined && env['GIT_DIR']) {
    gitDir = env['GIT_DIR'];
    gdVia = 'GIT_DIR';
  }
  if (env['GIT_DIR'] || env['GIT_WORK_TREE']) gitEnv = true;
  if (workTree !== undefined && workTree !== '') {
    const w = resolve(cur, workTree);
    if (!isDir(w)) return { dir: w, explicit: true, via: wtVia, error: `the git work tree ${w} is not a directory`, git_env: gitEnv };
    return { dir: w, explicit: true, via: wtVia, error: null, git_env: gitEnv };
  }
  if (gitDir !== undefined && gitDir !== '') {
    const g = resolve(cur, gitDir);
    if (!exists(g)) return { dir: g, explicit: true, via: gdVia, error: `the git dir ${g} does not exist`, git_env: gitEnv };
    return { dir: repoOfGitDir(g), explicit: true, via: gdVia, error: null, git_env: gitEnv };
  }
  if (via !== null && !isDir(cur)) return { dir: cur, explicit: true, via, error: `${cur} is not a directory`, git_env: gitEnv };
  return { dir: cur, explicit: via !== null, via, error: null, git_env: gitEnv };
}

/**
 * Generic chdir-style options. `before`: only options before the first
 * positional word count (terraform); else anywhere before `--`.
 */
function chdirTarget(
  tool: string,
  args: readonly string[],
  cwd: string,
  o: { short?: string[]; long?: string[]; eqOnly?: string[]; attached?: boolean; cumulative?: boolean; before?: boolean },
): CommandTarget {
  let cur = cwd;
  let via: string | null = null;
  const set = (v: string, name: string) => {
    if (v === '') return;
    cur = o.cumulative ? resolve(cur, v) : resolve(cwd, v);
    via = name;
  };
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === '--') break;
    if (!a.startsWith('-')) {
      if (o.before) break;
      continue;
    }
    let matched = false;
    for (const s of o.short ?? []) {
      if (a === s) {
        const v = args[i + 1];
        if (v === undefined) return { dir: cur, explicit: true, via: s, error: `${tool} ${s} has no directory`, git_env: false };
        set(v, s);
        i++;
        matched = true;
        break;
      }
      if (o.attached && a.startsWith(s) && a.length > s.length && s.length === 2) {
        set(a.slice(2), s);
        matched = true;
        break;
      }
    }
    if (matched) continue;
    for (const l of o.long ?? []) {
      const v = optValue(args, i, l);
      if (v) {
        if (v.value === null) return { dir: cur, explicit: true, via: l, error: `${tool} ${l} has no directory`, git_env: false };
        set(v.value, l);
        i += v.used - 1;
        matched = true;
        break;
      }
    }
    if (matched) continue;
    for (const l of o.eqOnly ?? []) {
      if (a.startsWith(l + '=')) {
        set(a.slice(l.length + 1), l);
        break;
      }
    }
  }
  if (via !== null && !isDir(cur)) return { dir: cur, explicit: true, via, error: `${cur} is not a directory`, git_env: false };
  return { dir: cur, explicit: via !== null, via, error: null, git_env: false };
}

/** The directory whose project `command` (argv, tool first) acts on, run from `cwd`. */
export function commandTarget(command: readonly string[] | undefined, cwd: string, env: NodeJS.ProcessEnv = process.env): CommandTarget {
  const base = resolve(cwd);
  if (!command || command.length === 0) return { dir: base, explicit: false, via: null, error: null, git_env: false };
  const tool = toolName(command[0]!);
  const args = command.slice(1);
  switch (tool) {
    case 'git':
      return gitTarget(args, base, env);
    case 'terraform':
    case 'tofu':
      return chdirTarget(tool, args, base, { eqOnly: ['-chdir'], before: true });
    case 'make':
      return chdirTarget(tool, args, base, { short: ['-C'], long: ['--directory'], attached: true, cumulative: true });
    case 'npm':
      return chdirTarget(tool, args, base, { long: ['--prefix'] });
    case 'pnpm':
      return chdirTarget(tool, args, base, { short: ['-C'], long: ['--dir'] });
    case 'yarn':
      return chdirTarget(tool, args, base, { long: ['--cwd'] });
    default:
      return { dir: base, explicit: false, via: null, error: null, git_env: false };
  }
}

const GIT_LOCATE_ENV = ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR', 'GIT_INDEX_FILE', 'GIT_NAMESPACE'] as const;

/** Run `fn` with git's repository-locating variables unset (the target already accounts for them). */
export function withoutGitEnv<T>(fn: () => T): T {
  const saved: [string, string][] = [];
  for (const k of GIT_LOCATE_ENV) {
    const v = process.env[k];
    if (v !== undefined) {
      saved.push([k, v]);
      delete process.env[k];
    }
  }
  try {
    return fn();
  } finally {
    for (const [k, v] of saved) process.env[k] = v;
  }
}
