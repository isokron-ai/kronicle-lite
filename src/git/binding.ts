/**
 * Git-bound documents (0.4.0): record `{repo_root, commit, path, blob_sha}`
 * for a source file at put time, and later tell whether the working-tree file
 * still has that blob. Uses only `git rev-parse` and `git hash-object` (plus
 * `git cat-file` to fetch the bound content for a diff stat, when the blob is
 * in the object store). Never throws: not a repository, no git, a missing
 * file all degrade to a warning or an `unavailable` state.
 */

import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import type { GitBinding } from '../docs/documents.js';
import { git, gitToplevel, relativeInside } from './git.js';

export interface BindResult {
  binding: GitBinding | null;
  warning: string | null;
}

/** Bind `file` to its repository state. Graceful outside git. */
export function bindGit(file: string): BindResult {
  const abs = resolve(file);
  let isFile = false;
  try {
    isFile = statSync(abs).isFile();
  } catch {
    isFile = false;
  }
  if (!isFile) return { binding: null, warning: `bind_git: source file not found: ${abs}` };
  const repo_root = gitToplevel(dirname(abs));
  if (!repo_root) return { binding: null, warning: `bind_git: not a git repository (or git is not installed): ${dirname(abs)}; stored without a binding` };
  const path = relativeInside(repo_root, abs);
  if (!path) return { binding: null, warning: `bind_git: ${abs} is outside ${repo_root}; stored without a binding` };
  const blob_sha = git(['hash-object', '--', path], repo_root);
  if (!blob_sha || !/^[0-9a-f]{40,64}$/.test(blob_sha)) return { binding: null, warning: `bind_git: git hash-object failed for ${path}; stored without a binding` };
  const commit = git(['rev-parse', '--verify', '--quiet', 'HEAD'], repo_root);
  return { binding: { repo_root, commit: commit && /^[0-9a-f]{40,64}$/.test(commit) ? commit : null, path, blob_sha }, warning: null };
}

export interface DiffStat {
  files_changed: number;
  insertions: number;
  deletions: number;
  /** `git diff --stat`-style line: ` path | 4 ++--` */
  summary: string;
  /** Where the bound side came from: the git object store, or the stored revision markdown (normalized). */
  bound_from: 'git' | 'stored_revision' | 'none';
}

export type SourceState = 'current' | 'changed' | 'missing' | 'unavailable';

export interface SourceCheck {
  state: SourceState;
  working_blob_sha: string | null;
  head_commit: string | null;
  diff_stat: DiffStat | null;
  detail: string | null;
}

function lines(text: string): string[] {
  const l = text.split(/\r?\n/);
  if (l.length > 0 && l[l.length - 1] === '') l.pop();
  return l;
}

/**
 * Length of the shortest edit script (insertions + deletions) between two
 * line arrays — Myers' O((N+M)·D) greedy algorithm, O(N+M) memory. Returns
 * null when D exceeds `maxD` (huge rewrites), and the caller falls back to
 * "everything changed".
 */
export function editDistance(a: readonly string[], b: readonly string[], maxD = 20_000): number | null {
  const n = a.length;
  const m = b.length;
  const max = Math.min(n + m, maxD);
  const off = max + 1;
  const v = new Int32Array(2 * max + 3);
  v[off + 1] = 0;
  for (let d = 0; d <= max; d++) {
    for (let k = -d; k <= d; k += 2) {
      let x = k === -d || (k !== d && v[off + k - 1]! < v[off + k + 1]!) ? v[off + k + 1]! : v[off + k - 1]! + 1;
      let y = x - k;
      while (x < n && y < m && a[x] === b[y]) {
        x++;
        y++;
      }
      v[off + k] = x;
      if (x >= n && y >= m) return d;
    }
  }
  return null;
}

export function diffStat(path: string, bound: string, working: string, bound_from: DiffStat['bound_from']): DiffStat {
  const a = lines(bound);
  const b = lines(working);
  const d = editDistance(a, b);
  let insertions: number;
  let deletions: number;
  if (d === null) {
    insertions = b.length;
    deletions = a.length;
  } else {
    insertions = (d + (b.length - a.length)) / 2;
    deletions = (d - (b.length - a.length)) / 2;
  }
  const total = insertions + deletions;
  const scale = total > 40 ? 40 / total : 1;
  const plus = '+'.repeat(Math.round(insertions * scale));
  const minus = '-'.repeat(Math.round(deletions * scale));
  return { files_changed: total > 0 ? 1 : 0, insertions, deletions, summary: ` ${path} | ${total} ${plus}${minus}`, bound_from };
}

/**
 * Compare a binding with the working tree. `boundFallback` is the text the
 * document was put with (used for the diff stat when the bound blob is not
 * in the object store, e.g. the file was never committed).
 */
export function checkGitBinding(binding: GitBinding, boundFallback: string | null): SourceCheck {
  if (!existsSync(binding.repo_root)) {
    return { state: 'unavailable', working_blob_sha: null, head_commit: null, diff_stat: null, detail: `repository ${binding.repo_root} not found` };
  }
  const file = join(binding.repo_root, ...binding.path.split('/'));
  const head_commit = git(['rev-parse', '--verify', '--quiet', 'HEAD'], binding.repo_root);
  const boundText = (): { text: string; from: DiffStat['bound_from'] } => {
    const fromGit = git(['cat-file', 'blob', binding.blob_sha], binding.repo_root, { trim: false });
    if (fromGit !== null) return { text: fromGit, from: 'git' };
    return boundFallback !== null ? { text: boundFallback, from: 'stored_revision' } : { text: '', from: 'none' };
  };
  if (!existsSync(file)) {
    const b = boundText();
    return {
      state: 'missing',
      working_blob_sha: null,
      head_commit,
      diff_stat: diffStat(binding.path, b.text, '', b.from),
      detail: `${binding.path} no longer exists in ${binding.repo_root}`,
    };
  }
  const working = git(['hash-object', '--', binding.path], binding.repo_root);
  if (!working) return { state: 'unavailable', working_blob_sha: null, head_commit, diff_stat: null, detail: 'git hash-object failed (is git installed?)' };
  if (working === binding.blob_sha) return { state: 'current', working_blob_sha: working, head_commit, diff_stat: null, detail: null };
  let workingText = '';
  try {
    workingText = readFileSync(file, 'utf8');
  } catch {
    workingText = '';
  }
  const b = boundText();
  return {
    state: 'changed',
    working_blob_sha: working,
    head_commit,
    diff_stat: diffStat(binding.path, b.text, workingText, b.from),
    detail: `${binding.path} changed since it was bound (blob ${binding.blob_sha.slice(0, 12)} → ${working.slice(0, 12)})`,
  };
}
