/**
 * Thin, dependency-free git access through the `git` executable
 * (`git rev-parse`, `git hash-object`, `git cat-file`). No libgit2. Every call
 * is synchronous with a short timeout and returns null instead of throwing
 * when git is missing, the path is not in a repository, or the object does
 * not exist — callers degrade gracefully.
 */

import { execFileSync } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { basename, dirname, isAbsolute, relative, resolve } from 'node:path';

const GIT_TIMEOUT_MS = 5_000;

/** Run git in `cwd`; stdout trimmed of one trailing newline, or null on any failure. */
export function git(args: string[], cwd: string, opts: { trim?: boolean; maxBuffer?: number } = {}): string | null {
  try {
    const out = execFileSync('git', args, {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: GIT_TIMEOUT_MS,
      windowsHide: true,
      maxBuffer: opts.maxBuffer ?? 16 * 1024 * 1024,
      env: { ...process.env, GIT_OPTIONAL_LOCKS: '0', LC_ALL: 'C' },
    });
    return opts.trim === false ? out : out.replace(/\r?\n$/, '');
  } catch {
    return null;
  }
}

/** Is a usable `git` on PATH? */
export function gitAvailable(): boolean {
  return git(['--version'], process.cwd()) !== null;
}

function realOr(p: string): string {
  try {
    return realpathSync.native(p);
  } catch {
    return resolve(p);
  }
}

/** Worktree root containing `dir` (`git rev-parse --show-toplevel`), or null. */
export function gitToplevel(dir: string): string | null {
  const out = git(['rev-parse', '--show-toplevel'], dir);
  return out ? realOr(out) : null;
}

/**
 * Root of the MAIN worktree of the repository containing `dir`: the parent
 * of the common `.git` directory, shared by every linked worktree. This is
 * the root Claude Code keys auto memory by ("all worktrees and
 * subdirectories within the same repo share one auto memory directory").
 * Falls back to the worktree toplevel for bare or unusual layouts.
 */
export function gitMainRoot(dir: string): string | null {
  const top = gitToplevel(dir);
  if (!top) return null;
  let common = git(['rev-parse', '--path-format=absolute', '--git-common-dir'], dir);
  if (!common) {
    const rel = git(['rev-parse', '--git-common-dir'], dir);
    common = rel ? (isAbsolute(rel) ? rel : resolve(dir, rel)) : null;
  }
  if (common && basename(common) === '.git') return realOr(dirname(common));
  return top;
}

/** `/`-separated path of `file` relative to `root`, or null when outside it. */
export function relativeInside(root: string, file: string): string | null {
  const rel = relative(realOr(root), realOr(file));
  if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) return null;
  return rel.split(/[\\/]+/).join('/');
}
