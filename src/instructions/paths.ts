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
}

export function resolveContext(ctx: InstructionContext = {}): ResolvedContext {
  const cwd = resolve(ctx.cwd ?? process.cwd());
  const home = ctx.home ?? homedir();
  const env = ctx.env ?? process.env;
  const projectRoot = gitToplevel(cwd) ?? cwd;
  const memoryRoot = gitMainRoot(cwd) ?? cwd;
  const claudeDir = env['CLAUDE_CONFIG_DIR'] ? resolve(expandHome(env['CLAUDE_CONFIG_DIR'], home)) : join(home, '.claude');
  const mem = autoMemoryDir({ claudeDir, projectRoot, memoryRoot, home, env });
  return { cwd, home, env, projectRoot, memoryRoot, claudeDir, memoryDir: mem.dir, memoryRule: mem.rule };
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

/** Keep slugs ≤ 128 chars (receipt limit): truncate and append a short hash of the full slug. */
function boundSlug(slug: string): string {
  if (slug.length <= 128) return slug;
  return slug.slice(0, 119).replace(/[/._-]+$/, '') + '-' + hash8(slug);
}

/**
 * Deterministic slug for an instruction file. `rel` is the path relative to
 * the project root (any separator); `inMemoryDir` marks a file in the auto
 * memory directory. Pure: no filesystem access.
 */
export function instructionSlugFor(rel: string, inMemoryDir: boolean): string {
  const parts = rel.split(/[\\/]+/).filter((p) => p.length > 0 && p !== '.');
  if (inMemoryDir) {
    return boundSlug(['memory', ...parts.slice(0, -1).map(sanitizeSegment), sanitizeSegment(stripMd(parts[parts.length - 1] ?? 'MEMORY.md'))].join('/'));
  }
  const tail = (segs: string[]) => [...segs.slice(0, -1).map(sanitizeSegment), sanitizeSegment(stripMd(segs[segs.length - 1] ?? 'x'))];
  if (parts[0] === '.claude' && parts[1] === 'rules' && parts.length > 2) {
    return boundSlug(['instructions', 'claude-rules', ...tail(parts.slice(2))].join('/'));
  }
  if (parts[0] === '.cursor' && parts[1] === 'rules' && parts.length > 2) {
    return boundSlug(['instructions', 'cursor-rules', ...tail(parts.slice(2))].join('/'));
  }
  const file = parts[parts.length - 1] ?? 'x';
  const dirs = parts.slice(0, -1).map(sanitizeSegment);
  const leaf = WELL_KNOWN[file] ?? sanitizeSegment(stripMd(file));
  return boundSlug(['instructions', ...dirs, leaf].join('/'));
}

function isInside(root: string, file: string): string | null {
  return relativeInside(root, file);
}

/** Build the entry (slug, recorded path, title) for one absolute file path. */
export function entryFor(absPath: string, rc: ResolvedContext): InstructionEntry {
  const path = resolve(absPath);
  const inMem = isInside(rc.memoryDir, path);
  if (inMem !== null) {
    const homeRel = isInside(rc.home, path);
    const recordPath = homeRel !== null ? `~/${homeRel}` : path.split(/[\\/]+/).join('/');
    return { path, slug: instructionSlugFor(inMem, true), kind: 'memory', recordPath, title: `Claude Code auto memory: ${inMem}` };
  }
  const rel = isInside(rc.projectRoot, path);
  if (rel !== null) return { path, slug: instructionSlugFor(rel, false), kind: 'instruction', recordPath: rel, title: rel };
  const homeRel = isInside(rc.home, path);
  const recordPath = homeRel !== null ? `~/${homeRel}` : path.split(/[\\/]+/).join('/');
  const slug = boundSlug(`instructions/external/${hash8(recordPath)}-${sanitizeSegment(stripMd(basename(path)))}`);
  return { path, slug, kind: 'instruction', recordPath, title: recordPath };
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
