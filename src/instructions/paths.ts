/**
 * Which instruction files to chain, and the slug each one gets.
 *
 * Default watch set (relative to the project root = git worktree toplevel,
 * or the working directory outside git):
 *
 *   CLAUDE.md                → instructions/claude-md
 *   AGENTS.md                → instructions/agents-md
 *   .claude/rules/**\/*.md    → instructions/claude-rules/<path without .md>
 *   .cursor/rules/**         → instructions/cursor-rules/<path without .md>
 *   Claude Code auto memory  → memory/MEMORY
 *     <config>/projects/<project>/memory/MEMORY.md
 *
 * Auto-memory location, per https://code.claude.com/docs/en/memory.md
 * ("Storage location") and /sessions.md ("Where transcripts are stored",
 * "Name the project directory yourself"), checked 2026-10-31:
 *   - <config> is $CLAUDE_CONFIG_DIR, else ~/.claude;
 *   - <project> is derived from the git repository (all worktrees and
 *     subdirectories share it; outside git, the project root): the path with
 *     every non-alphanumeric character replaced by `-`; a name longer than
 *     200 characters is truncated to 200 and suffixed with a hash of the full
 *     path (the hash is not specified, so we find that directory by prefix);
 *   - $CLAUDE_CODE_PROJECT_DIR_NAME (1-64 of [A-Za-z0-9_-], honoured only
 *     with $CLAUDE_CONFIG_DIR) replaces <project>;
 *   - `autoMemoryDirectory` in settings (absolute or `~/`) replaces the whole
 *     memory directory; local > project > user settings.
 *
 * Slugs are deterministic: the same file under the same project root always
 * maps to the same slug, on every OS (paths are `/`-normalized first).
 *
 * 0.5.0: slugs carry a project key right after the namespace, so two
 * repositories sharing one data dir no longer overwrite (and falsely
 * retract) each other's instructions:
 *
 *   CLAUDE.md in /work/acme-api   → instructions/acme-api-1a2b3c4d/claude-md
 *   its auto memory MEMORY.md     → memory/acme-api-1a2b3c4d/MEMORY
 *
 * key = <basename of the root, sanitized, ≤ 40 chars>-<first 8 hex of
 * sha256(absolute root, `/`-separated)>; the instruction key uses the git
 * worktree toplevel, the memory key the main worktree root (the directory
 * Claude Code keys auto memory by). $KRONICLE_LITE_PROJECT (1-64 of
 * [a-z0-9._-]) replaces both, e.g. to keep slugs stable when a repository
 * moves. The 0.4.0 un-keyed slug of each file is kept as `legacySlug`; the
 * first sync that finds it holding this file's current text renames it in
 * place (sync.ts), so blocks, receipts and retractions carry over.
 */

import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';

import { gitMainRoot, gitToplevel, relativeInside } from '../git/git.js';

export type InstructionKind = 'instruction' | 'memory';

export interface InstructionEntry {
  /** Absolute path on this machine. */
  path: string;
  slug: string;
  /** 0.4.0 slug of the same file (no project key), or null for external files. */
  legacySlug: string | null;
  /** Project the file belongs to (null for files outside the project and its memory dir). */
  project: { key: string; root: string } | null;
  kind: InstructionKind;
  /** What is recorded in the document.put `source.path`: project-relative, `~/`-relative or absolute; `/`-separated. */
  recordPath: string;
  title: string;
}

export interface InstructionContext {
  /** Working directory (default process.cwd()). */
  cwd?: string;
  /** Home directory (default os.homedir()). */
  home?: string;
  env?: NodeJS.ProcessEnv;
}

export interface ResolvedContext {
  cwd: string;
  home: string;
  env: NodeJS.ProcessEnv;
  /** Instruction files are looked up here: git worktree toplevel, else cwd. */
  projectRoot: string;
  /** Root Claude Code keys auto memory by: main worktree root, else cwd. */
  memoryRoot: string;
  /** Claude Code config dir: $CLAUDE_CONFIG_DIR or ~/.claude. */
  claudeDir: string;
  memoryDir: string;
  /** How memoryDir was decided (for `watch --list` / doctor). */
  memoryRule: 'autoMemoryDirectory' | 'CLAUDE_CODE_PROJECT_DIR_NAME' | 'derived' | 'derived-long-name';
  /** 0.5.0: slug key for instruction files (from projectRoot). */
  projectKey: string;
  /** 0.5.0: slug key for auto-memory files (from memoryRoot). */
  memoryKey: string;
}

const PROJECT_OVERRIDE_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

/**
 * 0.8.0: the canonical spelling of a path: symlinks resolved
 * (`realpathSync.native`), so `/var/x` and `/private/var/x` (macOS), or a
 * project reached through a symlink, name ONE project. A path that does not
 * exist (a deleted file) is canonicalised through its nearest existing
 * ancestor. On Windows a result that differs only in letter case keeps the
 * given spelling (keys stay what they were; junctions still resolve).
 */
export function canonicalPath(p: string): string {
  const abs = resolve(p);
  let real: string;
  try {
    real = realpathSync.native(abs);
  } catch {
    const parent = dirname(abs);
    return parent === abs ? abs : join(canonicalPath(parent), basename(abs));
  }
  if (process.platform === 'win32' && real.toLowerCase() === abs.toLowerCase()) return abs;
  return real;
}

/** Readable, stable key for a project root: `<basename>-<sha256(root)[:8]>`. */
export function projectKey(root: string): string {
  const norm = root.split(/[\\/]+/).join('/');
  const name = (sanitizeSegment(basename(root) || 'root').toLowerCase().slice(0, 40).replace(/[._-]+$/, '') || 'root');
  return `${name}-${hash8(norm)}`;
}

/** The keys orient scopes instruction retractions to, for a working directory. */
export function projectScopeFor(ctx: InstructionContext = {}): { keys: string[]; root: string } {
  const rc = resolveContext(ctx);
  return { keys: [...new Set([rc.projectKey, rc.memoryKey])], root: rc.projectRoot };
}

export function resolveContext(ctx: InstructionContext = {}): ResolvedContext {
  // 0.8.0: canonical (symlinks resolved), so the project key is the same whichever spelling of the
  // project path a caller passes (`put` from process.cwd() vs a hook's literal --cwd through a symlink).
  const cwd = canonicalPath(ctx.cwd ?? process.cwd());
  const home = ctx.home ?? homedir();
  const env = ctx.env ?? process.env;
  const projectRoot = gitToplevel(cwd) ?? cwd;
  const memoryRoot = gitMainRoot(cwd) ?? cwd;
  const claudeDir = env['CLAUDE_CONFIG_DIR'] ? resolve(expandHome(env['CLAUDE_CONFIG_DIR'], home)) : join(home, '.claude');
  const mem = autoMemoryDir({ claudeDir, projectRoot, memoryRoot, home, env });
  const override = env['KRONICLE_LITE_PROJECT'];
  const fixed = override && PROJECT_OVERRIDE_RE.test(override) ? override : null;
  return {
    cwd,
    home,
    env,
    projectRoot,
    memoryRoot,
    claudeDir,
    memoryDir: mem.dir,
    memoryRule: mem.rule,
    projectKey: fixed ?? projectKey(projectRoot),
    memoryKey: fixed ?? projectKey(memoryRoot),
  };
}

function expandHome(p: string, home: string): string {
  return p === '~' ? home : p.startsWith('~/') || p.startsWith('~\\') ? join(home, p.slice(2)) : p;
}

/** Claude Code's project directory name: every non-alphanumeric character becomes `-`. */
export function claudeProjectDirName(projectPath: string): string {
  return projectPath.replace(/[^A-Za-z0-9]/g, '-');
}

function readJson(file: string): Record<string, unknown> | null {
  try {
    const j: unknown = JSON.parse(readFileSync(file, 'utf8'));
    return j && typeof j === 'object' && !Array.isArray(j) ? (j as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

export function autoMemoryDir(args: {
  claudeDir: string;
  projectRoot: string;
  memoryRoot: string;
  home: string;
  env: NodeJS.ProcessEnv;
}): { dir: string; rule: ResolvedContext['memoryRule'] } {
  // 1. autoMemoryDirectory: local > project > user settings. Absolute or ~/ only.
  for (const f of [
    join(args.projectRoot, '.claude', 'settings.local.json'),
    join(args.projectRoot, '.claude', 'settings.json'),
    join(args.claudeDir, 'settings.json'),
  ]) {
    const v = readJson(f)?.['autoMemoryDirectory'];
    if (typeof v === 'string' && (isAbsolute(v) || v.startsWith('~/'))) {
      return { dir: resolve(expandHome(v, args.home)), rule: 'autoMemoryDirectory' };
    }
  }
  // 2. CLAUDE_CODE_PROJECT_DIR_NAME, only together with CLAUDE_CONFIG_DIR.
  const named = args.env['CLAUDE_CODE_PROJECT_DIR_NAME'];
  if (args.env['CLAUDE_CONFIG_DIR'] && named && /^[A-Za-z0-9_-]{1,64}$/.test(named)) {
    return { dir: join(args.claudeDir, 'projects', named, 'memory'), rule: 'CLAUDE_CODE_PROJECT_DIR_NAME' };
  }
  // 3. Derived from the repository (or project) root.
  const name = claudeProjectDirName(args.memoryRoot);
  if (name.length <= 200) return { dir: join(args.claudeDir, 'projects', name, 'memory'), rule: 'derived' };
  const prefix = name.slice(0, 200);
  let found: string | null = null;
  try {
    const hits = readdirSync(join(args.claudeDir, 'projects')).filter((d) => d.startsWith(prefix));
    if (hits.length === 1) found = hits[0]!;
  } catch {
    // no projects dir yet
  }
  return { dir: join(args.claudeDir, 'projects', found ?? prefix, 'memory'), rule: 'derived-long-name' };
}

// ───────────────────────────── slugs ─────────────────────────────

const WELL_KNOWN: Readonly<Record<string, string>> = Object.freeze({
  'CLAUDE.md': 'claude-md',
  'AGENTS.md': 'agents-md',
  'CLAUDE.local.md': 'claude-local-md',
});

function sanitizeSegment(seg: string): string {
  const s = seg.replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^[._-]+/, '').replace(/-+$/, '');
  return s.length > 0 ? s.slice(0, 127) : 'x';
}

function stripMd(name: string): string {
  return name.toLowerCase().endsWith('.md') && name.length > 3 ? name.slice(0, -3) : name;
}

function hash8(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex').slice(0, 8);
}

/**
 * Keep slugs ≤ 128 chars (receipt limit) and ≤ 17 `/`-segments (PATH_SLUG_RE):
 * truncate and append a short hash of the full slug.
 */
function boundSlug(slug: string): string {
  const parts = slug.split('/');
  if (slug.length <= 128 && parts.length <= 17) return slug;
  return parts.slice(0, 16).join('/').slice(0, 119).replace(/[/._-]+$/, '') + '-' + hash8(slug);
}

/**
 * Deterministic slug for an instruction file. `rel` is the path relative to
 * the project root (any separator); `inMemoryDir` marks a file in the auto
 * memory directory. Pure: no filesystem access.
 */
export function instructionSlugFor(rel: string, inMemoryDir: boolean, key?: string): string {
  const parts = rel.split(/[\\/]+/).filter((p) => p.length > 0 && p !== '.');
  const k = key !== undefined ? [key] : [];
  if (inMemoryDir) {
    return boundSlug(['memory', ...k, ...parts.slice(0, -1).map(sanitizeSegment), sanitizeSegment(stripMd(parts[parts.length - 1] ?? 'MEMORY.md'))].join('/'));
  }
  const tail = (segs: string[]) => [...segs.slice(0, -1).map(sanitizeSegment), sanitizeSegment(stripMd(segs[segs.length - 1] ?? 'x'))];
  if (parts[0] === '.claude' && parts[1] === 'rules' && parts.length > 2) {
    return boundSlug(['instructions', ...k, 'claude-rules', ...tail(parts.slice(2))].join('/'));
  }
  if (parts[0] === '.cursor' && parts[1] === 'rules' && parts.length > 2) {
    return boundSlug(['instructions', ...k, 'cursor-rules', ...tail(parts.slice(2))].join('/'));
  }
  const file = parts[parts.length - 1] ?? 'x';
  const dirs = parts.slice(0, -1).map(sanitizeSegment);
  const leaf = WELL_KNOWN[file] ?? sanitizeSegment(stripMd(file));
  return boundSlug(['instructions', ...k, ...dirs, leaf].join('/'));
}

function isInside(root: string, file: string): string | null {
  return relativeInside(root, file);
}

/** Build the entry (slug, recorded path, title) for one absolute file path. */
export function entryFor(absPath: string, rc: ResolvedContext): InstructionEntry {
  // 0.8.0: classify by the canonical path (the project root is canonical), so a hook's
  // /var/… spelling of a /private/var/… project file is still that project's file.
  const path = canonicalPath(absPath);
  const inMem = isInside(rc.memoryDir, path) ?? isInside(canonicalPath(rc.memoryDir), path);
  if (inMem !== null) {
    const homeRel = isInside(rc.home, path) ?? isInside(canonicalPath(rc.home), path);
    const recordPath = homeRel !== null ? `~/${homeRel}` : path.split(/[\\/]+/).join('/');
    return {
      path,
      slug: instructionSlugFor(inMem, true, rc.memoryKey),
      legacySlug: instructionSlugFor(inMem, true),
      project: { key: rc.memoryKey, root: rc.memoryRoot },
      kind: 'memory',
      recordPath,
      title: `Claude Code auto memory: ${inMem}`,
    };
  }
  const rel = isInside(rc.projectRoot, path);
  if (rel !== null) {
    return {
      path,
      slug: instructionSlugFor(rel, false, rc.projectKey),
      legacySlug: instructionSlugFor(rel, false),
      project: { key: rc.projectKey, root: rc.projectRoot },
      kind: 'instruction',
      recordPath: rel,
      title: `${basename(rc.projectRoot)}/${rel}`,
    };
  }
  const homeRel = isInside(rc.home, path) ?? isInside(canonicalPath(rc.home), path);
  const recordPath = homeRel !== null ? `~/${homeRel}` : path.split(/[\\/]+/).join('/');
  const slug = boundSlug(`instructions/external/${hash8(recordPath)}-${sanitizeSegment(stripMd(basename(path)))}`);
  return { path, slug, legacySlug: null, project: null, kind: 'instruction', recordPath, title: recordPath };
}

// ───────────────────────────── watch set ─────────────────────────────

export type WatchPattern =
  | { type: 'file'; path: string }
  | { type: 'dir'; path: string; match: 'md' | 'any' | 'md-or-mdc' };

/** The default watch set as patterns (re-expanded on every rescan, so new rule files are picked up). */
export function defaultPatterns(rc: ResolvedContext): WatchPattern[] {
  return [
    { type: 'file', path: join(rc.projectRoot, 'CLAUDE.md') },
    { type: 'file', path: join(rc.projectRoot, 'AGENTS.md') },
    { type: 'dir', path: join(rc.projectRoot, '.claude', 'rules'), match: 'md' },
    { type: 'dir', path: join(rc.projectRoot, '.cursor', 'rules'), match: 'any' },
    { type: 'file', path: join(rc.memoryDir, 'MEMORY.md') },
  ];
}

/** Patterns for explicit CLI paths: a file is watched as-is, a directory for *.md / *.mdc recursively. */
export function explicitPatterns(paths: readonly string[], rc: ResolvedContext): WatchPattern[] {
  return paths.map((p) => {
    const abs = resolve(rc.cwd, expandHome(p, rc.home));
    let isDir = false;
    try {
      isDir = statSync(abs).isDirectory();
    } catch {
      isDir = false;
    }
    return isDir ? { type: 'dir', path: abs, match: 'md-or-mdc' } : { type: 'file', path: abs };
  });
}

export function patternMatches(p: WatchPattern, file: string): boolean {
  if (p.type === 'file') return resolve(p.path) === resolve(file);
  if (isInside(p.path, file) === null) return false;
  const lower = file.toLowerCase();
  if (p.match === 'any') return true;
  if (p.match === 'md') return lower.endsWith('.md');
  return lower.endsWith('.md') || lower.endsWith('.mdc');
}

const MAX_DEPTH = 16;
const MAX_FILES = 2_000;

/** Every existing file the patterns cover, plus every directory to watch. Follows symlinks, detects cycles. */
export function expandPatterns(patterns: readonly WatchPattern[]): { files: string[]; dirs: string[] } {
  const files = new Set<string>();
  const dirs = new Set<string>();
  for (const p of patterns) {
    if (p.type === 'file') {
      dirs.add(dirname(p.path));
      if (isFile(p.path)) files.add(resolve(p.path));
      continue;
    }
    const seen = new Set<string>();
    const walk = (dir: string, depth: number) => {
      if (depth > MAX_DEPTH || files.size >= MAX_FILES) return;
      let real: string;
      try {
        real = realpathSync.native(dir);
      } catch {
        return;
      }
      if (seen.has(real)) return;
      seen.add(real);
      dirs.add(dir);
      let names: string[];
      try {
        names = readdirSync(dir).sort();
      } catch {
        return;
      }
      for (const n of names) {
        const full = join(dir, n);
        let st;
        try {
          st = statSync(full);
        } catch {
          continue;
        }
        if (st.isDirectory()) walk(full, depth + 1);
        else if (st.isFile() && patternMatches(p, full)) files.add(resolve(full));
      }
    };
    if (existsSync(p.path)) walk(p.path, 0);
    else dirs.add(dirname(p.path));
  }
  return { files: [...files].sort(), dirs: [...dirs].sort() };
}

function isFile(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}
