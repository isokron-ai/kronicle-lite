/**
 * `kronicle-lite shim install | uninstall | status | ack | exec`.
 *
 * Safety rules (the shim dir sits on PATH, so a mistake here shadows or
 * breaks real binaries):
 *   - never write into a system directory (/, /bin, /usr/…, /etc, /dev, …);
 *   - never overwrite a file that is not one of our shims, and never write
 *     through a symlink (files are written to a temp name and renamed);
 *   - uninstall removes only files that carry the shim marker, plus our own
 *     `.kronicle-shim` state dir;
 *   - the git pre-push hook (`--git-hook`, H2-13) goes into the hooks dir git
 *     itself reports (core.hooksPath respected), chains a pre-push hook that
 *     was there (moved aside to pre-push.kronicle-chained, put back on
 *     uninstall), and never writes any git config.
 */

import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  rmdirSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { userInfo } from 'node:os';
import { delimiter, isAbsolute, join, resolve, sep, win32 } from 'node:path';

import { DEFAULT_COMMANDS, TOOL_NAME_RE, classify, parsePatterns, specFor, toolBasename, type Classification } from './rules.js';
import { SHIM_MARKER, cmdShim, gitHookScript, posixShim, ps1Shim, type ShimParams } from './script.js';
import {
  PULSE_DENY_EXIT,
  PulseUnavailableError,
  ack,
  corruptOutcome,
  resolveStore,
  storeOutcome,
  targetFor,
  isCorruptError,
  baselineFile,
  openForPulse,
  pulse,
  readProjectCursor,
  storeExists,
  ensureStoreBaseline,
  writeBaseline,
  type AckResult,
  type StoreResolution,
  type PulseMode,
  type PulseResult,
} from './pulse.js';
import { git } from '../git/git.js';
import { projectScopeFor } from '../instructions/paths.js';

export const STATE_DIR_NAME = '.kronicle-shim';
export const CONFIG_NAME = 'config.json';

export interface ShimConfig {
  format: 'kronicle-lite-shim/1';
  version: string;
  dir: string;
  tools: string[];
  /** User patterns, "TOOL [WORD…]". */
  world: string[];
  mode: PulseMode;
  /** Whose current-version reads reconcile a change (absent: the invoking actor, else each change's readers). */
  pending_actors?: string[];
  /** (0.8.1) Every reader of a changed block must re-read, even when the invoking actor is known (the 0.8.0 default). */
  all_readers?: boolean;
  /** (0.8.1) Git pre-push hooks installed with `--git-hook`. */
  git_hooks?: GitHookRecord[];
  /** A check that times out: run the command (allow, the default when absent) or refuse it (deny). */
  on_timeout?: 'allow' | 'deny';
  /** '' = kronicle-lite's default data dir at run time. */
  data_dir: string;
  node: string;
  cli: string;
  windows: boolean;
  installed_at: string;
  baseline_seq: number | null;
}

/** A git pre-push hook this shim dir installed. */
export interface GitHookRecord {
  /** The repository it was installed for (absolute). */
  repo: string;
  /** The hooks dir git reported (core.hooksPath respected). */
  hooks_dir: string;
  /** <hooks_dir>/pre-push */
  file: string;
  /** Where the pre-push hook that was there before now lives (run after the check), or null. */
  chained: string | null;
  installed_at: string;
}

/** The variable naming the actor that runs a command (also `serve`'s default actor). */
export const ACTOR_ENV = 'KRONICLE_LITE_ACTOR';

/** The invoking actor from the environment, or undefined. */
export function invokingActorFromEnv(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const v = env[ACTOR_ENV]?.trim();
  return v ? v : undefined;
}

const FORBIDDEN_POSIX = ['/bin', '/sbin', '/usr', '/etc', '/dev', '/proc', '/sys', '/boot', '/lib', '/lib32', '/lib64', '/libx32', '/run', '/System', '/Library', '/private/etc', '/private/var/db'];

/** Refuse system directories. Returns the reason, or null when the dir is acceptable. */
export function forbiddenDir(dir: string, platform: NodeJS.Platform = process.platform): string | null {
  if (platform === 'win32') {
    const low = win32.resolve(dir).toLowerCase().replace(/\//g, '\\');
    const win = (process.env['SystemRoot'] ?? 'C:\\Windows').toLowerCase();
    if (/^[a-z]:\\?$/.test(low)) return 'a drive root';
    if (low === win || low.startsWith(win + '\\')) return 'the Windows directory';
    if (/^[a-z]:\\program files( \(x86\))?(\\|$)/.test(low)) return 'Program Files';
    return null;
  }
  const d = resolve(dir);
  const candidates = [d];
  try {
    candidates.push(realpathSync.native(d));
  } catch {
    // does not exist yet: the resolved path is what will be created
  }
  for (const c of candidates) {
    if (c === '/') return 'the root directory';
    for (const f of FORBIDDEN_POSIX) if (c === f || c.startsWith(f + '/')) return `a system directory (${f})`;
  }
  return null;
}

function hasMarker(file: string): boolean {
  let fd: number | null = null;
  try {
    fd = openSync(file, 'r');
    const buf = Buffer.alloc(512);
    const n = readSync(fd, buf, 0, 512, 0);
    return buf.subarray(0, n).toString('latin1').includes(SHIM_MARKER);
  } catch {
    return false;
  } finally {
    if (fd !== null) closeSync(fd);
  }
}

function isExecutableFile(file: string, win: boolean): boolean {
  try {
    const st = statSync(file);
    if (!st.isFile()) return false;
    return win || (st.mode & 0o111) !== 0;
  } catch {
    return false;
  }
}

function normDir(d: string): string {
  let x = d;
  while (x.length > 1 && (x.endsWith('/') || x.endsWith('\\'))) x = x.slice(0, -1);
  return x;
}

function sameDir(a: string, b: string, win: boolean): boolean {
  const n = (s: string) => {
    let r = normDir(resolve(s));
    try {
      r = realpathSync.native(r);
    } catch {
      // keep the resolved path
    }
    return win ? r.toLowerCase() : r;
  };
  return n(a) === n(b);
}

/**
 * The real binary for `tool`: the first executable on PATH that is outside
 * the skipped dirs and is not a kronicle-lite shim (whatever dir it is in).
 */
export function resolveReal(
  tool: string,
  opts: {
    path?: string | undefined;
    skipDirs?: string[];
    platform?: NodeJS.Platform;
    pathext?: string | undefined;
  } = {},
): string | null {
  const win = (opts.platform ?? process.platform) === 'win32';
  const exts = win ? ['', ...(opts.pathext ?? process.env['PATHEXT'] ?? '.COM;.EXE;.BAT;.CMD').split(';').filter((e) => e.length > 0)] : [''];
  for (const raw of (opts.path ?? process.env['PATH'] ?? '').split(win ? ';' : delimiter)) {
    if (raw === '') continue;
    const d = normDir(raw);
    if ((opts.skipDirs ?? []).some((s) => sameDir(s, d, win))) continue;
    for (const e of exts) {
      const f = join(d, tool + e);
      if (win && e === '' && !/\.[A-Za-z0-9]+$/.test(tool)) continue;
      if (isExecutableFile(f, win) && !hasMarker(f)) return f;
    }
  }
  return null;
}

/** The first `tool` a shell would run (the shim, when its dir is ahead on PATH). */
export function firstOnPath(tool: string, path = process.env['PATH'] ?? ''): string | null {
  for (const raw of path.split(delimiter)) {
    if (raw === '') continue;
    const f = join(normDir(raw), tool);
    if (isExecutableFile(f, process.platform === 'win32')) return f;
  }
  return null;
}

export function stateDirOf(dir: string): string {
  return join(dir, STATE_DIR_NAME);
}

export function readConfig(dir: string): ShimConfig | null {
  try {
    return JSON.parse(readFileSync(join(stateDirOf(dir), CONFIG_NAME), 'utf8')) as ShimConfig;
  } catch {
    return null;
  }
}

/** The shim dir to act on: --dir, else the first PATH dir holding a shim config, else the default. */
export function locateShimDir(explicit: string | undefined, fallback: string, path = process.env['PATH'] ?? ''): string {
  if (explicit !== undefined) return resolve(explicit);
  for (const raw of path.split(delimiter)) {
    if (raw === '' || !isAbsolute(raw)) continue;
    if (existsSync(join(raw, STATE_DIR_NAME, CONFIG_NAME))) return normDir(raw);
  }
  return resolve(fallback);
}

function writeFileAtomic(file: string, text: string, mode: number): void {
  const tmp = `${file}.kl-${process.pid}.tmp`;
  writeFileSync(tmp, text, { mode });
  chmodSync(tmp, mode);
  renameSync(tmp, file); // replaces a symlink itself, never writes through it
}

export interface InstallOptions {
  dir: string;
  commands?: string[] | undefined;
  world?: string[] | undefined;
  mode?: PulseMode | undefined;
  /** Whose reads reconcile a change (stored in the config; pulse reads it). */
  pendingActors?: string[] | undefined;
  /** A check that times out: allow (default) or deny. Baked into the wrappers and stored in the config. */
  onTimeout?: 'allow' | 'deny' | undefined;
  /** Every reader must re-read, even when the invoking actor is known (the 0.8.0 default). */
  allReaders?: boolean | undefined;
  /** Also install the git pre-push hook into this repository (and its submodules). */
  gitHookRepo?: string | undefined;
  /** Explicit data dir to embed (undefined: kronicle-lite's default at run time). */
  dataDir?: string | undefined;
  /** Data dir to seed the baseline from (the explicit one, or the default). */
  effectiveDataDir: string;
  node: string;
  cli: string;
  version: string;
  /** Also write .cmd/.ps1 (default: on Windows only). */
  windows?: boolean | undefined;
  /** Write the POSIX sh wrappers (default: not on Windows). */
  posix?: boolean | undefined;
  path?: string | undefined;
}

export interface InstallReport {
  dir: string;
  state_dir: string;
  tools: string[];
  files: string[];
  mode: PulseMode;
  on_timeout: 'allow' | 'deny';
  data_dir: string;
  baseline_seq: number | null;
  first_on_path: boolean;
  warnings: string[];
  path_hint: string;
  /** (0.8.1) Pre-push hooks written by this install (`--git-hook`). */
  git_hooks: (GitHookRecord & { chained_now: boolean })[];
}

export function install(o: InstallOptions): InstallReport {
  const dir = normDir(resolve(o.dir));
  const bad = forbiddenDir(dir);
  if (bad) throw new Error(`refusing to install shims into ${dir}: ${bad}. Pick a directory of your own (default: ~/.kronicle-lite/shims).`);
  const tools = [...new Set((o.commands && o.commands.length > 0 ? o.commands : [...DEFAULT_COMMANDS]).map((t) => t.trim()).filter((t) => t.length > 0))];
  for (const t of tools) if (!TOOL_NAME_RE.test(t)) throw new Error(`"${t}" is not a command name`);
  const patterns = parsePatterns(o.world ?? []);
  for (const t of patterns.keys()) if (!tools.includes(t)) tools.push(t);
  const mode: PulseMode = o.mode ?? 'deny';
  const win = o.windows ?? process.platform === 'win32';
  const posix = o.posix ?? process.platform !== 'win32';

  if (existsSync(dir)) {
    const st = lstatSync(dir);
    if (!st.isDirectory()) throw new Error(`${dir} exists and is not a directory`);
  }
  const state = stateDirOf(dir);
  if (existsSync(state) && !lstatSync(state).isDirectory()) throw new Error(`${state} exists and is not a directory`);

  // Plan every file and refuse before writing anything.
  const planned: { file: string; text: string; mode: number }[] = [];
  const phys = (() => {
    try {
      return realpathSync.native(dir);
    } catch {
      return dir;
    }
  })();
  for (const tool of tools) {
    const spec = specFor(tool, patterns.get(tool) ?? []);
    const params: ShimParams = {
      tool,
      spec,
      dir: phys,
      aliases: phys === dir ? [] : [dir],
      stateDir: join(phys, STATE_DIR_NAME),
      node: o.node,
      cli: o.cli,
      dataDir: o.dataDir ?? '',
      mode,
      onTimeout: o.onTimeout ?? 'allow',
      version: o.version,
    };
    if (posix)
      planned.push({
        file: join(dir, tool),
        text: posixShim(params),
        mode: 0o755,
      });
    if (win) {
      planned.push({
        file: join(dir, `${tool}.cmd`),
        text: cmdShim(params),
        mode: 0o755,
      });
      planned.push({
        file: join(dir, `${tool}.ps1`),
        text: ps1Shim(params),
        mode: 0o644,
      });
    }
  }
  for (const p of planned) {
    if (!existsSync(p.file) && !isSymlink(p.file)) continue;
    if (isSymlink(p.file)) throw new Error(`refusing to replace ${p.file}: it is a symlink, not a kronicle-lite shim`);
    if (!hasMarker(p.file)) throw new Error(`refusing to overwrite ${p.file}: it is not a kronicle-lite shim (remove it yourself if it should go)`);
  }

  const hookPlan = o.gitHookRepo !== undefined ? planGitHooks(o.gitHookRepo) : [];

  mkdirSync(dir, { recursive: true, mode: 0o755 });
  mkdirSync(state, { recursive: true, mode: 0o700 });
  for (const p of planned) writeFileAtomic(p.file, p.text, p.mode);

  const warnings: string[] = [];
  const previous = readConfig(dir);
  let baseline: number | null = null;
  const found = resolveStore({
    pinned: o.dataDir,
    targetDir: o.gitHookRepo ?? process.cwd(),
    defaultDir: o.effectiveDataDir,
  });
  const baseDir = found.dataDir ?? o.effectiveDataDir;
  if (found.source === 'ambiguous')
    warnings.push(`more than one kronicle-lite store (${found.candidates.join(', ')}): world-changing commands are refused until one is pinned (shim install --data-dir DIR)`);
  if (storeExists(baseDir)) {
    const store = openForPulse(baseDir);
    try {
      // A re-install keeps the existing starting point: moving it to the head
      // would acknowledge every pending change of every project without a
      // cursor of its own, an operator action (H2-12) by the back door.
      const kept = existsSync(baselineFile(state)) && previous !== null && previous.baseline_seq !== null ? previous.baseline_seq : null;
      baseline = kept ?? writeBaseline(state, store);
    } finally {
      store.close();
    }
  } else if (found.source !== 'ambiguous') {
    warnings.push(
      `no kronicle-lite store in ${o.effectiveDataDir} yet: world-changing commands are refused (deny mode) until the store the MCP server uses exists; the first check then starts at its head`,
    );
  }
  // Every other store the shims may check gets its own starting point (P2-01),
  // unless the generic one is already that store's (never moved on re-install).
  for (const c of found.candidates) {
    if (c === baseDir) continue;
    try {
      const store = openForPulse(c);
      try {
        if (readProjectCursor(state, '\u0000none', store).source === 'none') ensureStoreBaseline(state, store);
      } finally {
        store.close();
      }
    } catch {
      // a store that cannot be opened now gets its starting point at its first check
    }
  }
  const hooks = writeGitHooks(hookPlan, {
    dir: phys,
    stateDir: join(phys, STATE_DIR_NAME),
    node: o.node,
    cli: o.cli,
    dataDir: o.dataDir ? resolve(o.dataDir) : '',
    defaultDataDir: resolve(o.effectiveDataDir),
    mode,
    onTimeout: o.onTimeout ?? 'allow',
    version: o.version,
  });
  const keptHooks = (previous?.git_hooks ?? []).filter((h) => !hooks.some((n) => n.file === h.file));
  const config: ShimConfig = {
    format: 'kronicle-lite-shim/1',
    version: o.version,
    dir: phys,
    tools,
    world: o.world ?? [],
    mode,
    ...(o.pendingActors && o.pendingActors.length > 0 ? { pending_actors: o.pendingActors } : {}),
    ...(o.allReaders ? { all_readers: true } : {}),
    ...(keptHooks.length + hooks.length > 0
      ? {
          git_hooks: [...keptHooks, ...hooks.map(({ chained_now: _c, ...h }) => h)],
        }
      : {}),
    on_timeout: o.onTimeout ?? 'allow',
    data_dir: o.dataDir ?? '',
    node: o.node,
    cli: o.cli,
    windows: win,
    installed_at: new Date().toISOString(),
    baseline_seq: baseline,
  };
  writeFileAtomic(join(state, CONFIG_NAME), JSON.stringify(config, null, 2) + '\n', 0o600);

  const path = o.path ?? process.env['PATH'] ?? '';
  for (const t of tools) {
    if (!resolveReal(t, { path, skipDirs: [dir, phys] })) warnings.push(`${t} is not on PATH outside ${dir}: its shim exits 127 until ${t} is installed`);
  }
  const entries = path.split(delimiter).filter((x) => x !== '');
  const first = entries.length > 0 && sameDir(entries[0]!, phys, win);
  return {
    dir: phys,
    state_dir: join(phys, STATE_DIR_NAME),
    tools,
    files: planned.map((p) => p.file),
    mode,
    on_timeout: o.onTimeout ?? 'allow',
    data_dir: o.dataDir ?? '',
    baseline_seq: baseline,
    first_on_path: first,
    warnings,
    git_hooks: hooks,
    path_hint: win ? `$env:Path = "${phys};$env:Path"   # PowerShell (or System Properties → Environment Variables)` : `export PATH="${phys}:$PATH"`,
  };
}

function isSymlink(f: string): boolean {
  try {
    return lstatSync(f).isSymbolicLink();
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------- git pre-push hook (H2-13)

export const HOOK_NAME = 'pre-push';
export const CHAINED_SUFFIX = '.kronicle-chained';

interface HookPlanItem {
  repo: string;
  hooksDir: string;
  file: string;
  chained: string;
  /** The existing pre-push is someone else's: move it to `chained` and run it after the check. */
  chainNow: boolean;
}

/** The hooks dir git uses for the repository at `repo` (core.hooksPath respected), absolute. */
export function gitHooksDir(repo: string): string | null {
  const out = git(['rev-parse', '--git-path', 'hooks'], repo);
  if (!out) return null;
  return resolve(repo, out);
}

/** The repository at `repo` and its initialized submodules (recursively), as work-tree roots. */
function reposToHook(repo: string): string[] {
  const top = git(['rev-parse', '--show-toplevel'], repo);
  const root = top ? resolve(top) : resolve(repo);
  const subs = git(['submodule', '--quiet', 'foreach', '--recursive', 'pwd'], root);
  return [root, ...(subs ? subs.split(/\r?\n/).filter((l) => l.trim() !== '') : [])];
}

/** Decide every hook file before writing anything (refusals throw). */
export function planGitHooks(repoIn: string): HookPlanItem[] {
  const repo = resolve(repoIn);
  if (git(['rev-parse', '--git-dir'], repo) === null) throw new Error(`--git-hook: ${repo} is not a git repository (pass --repo PATH)`);
  const plan: HookPlanItem[] = [];
  for (const r of reposToHook(repo)) {
    const hooksDir = gitHooksDir(r);
    if (hooksDir === null) throw new Error(`--git-hook: cannot ask git for the hooks dir of ${r}`);
    if (plan.some((p) => sameDir(p.hooksDir, hooksDir, process.platform === 'win32'))) continue; // a shared core.hooksPath
    const bad = forbiddenDir(hooksDir);
    if (bad) throw new Error(`--git-hook: refusing to write into ${hooksDir}: ${bad}`);
    if (existsSync(hooksDir) && !lstatSync(hooksDir).isDirectory()) throw new Error(`--git-hook: ${hooksDir} is not a directory`);
    const file = join(hooksDir, HOOK_NAME);
    const chained = file + CHAINED_SUFFIX;
    const present = existsSync(file) || isSymlink(file);
    const ours = present && !isSymlink(file) && hasMarker(file);
    let chainNow = false;
    if (present && !ours) {
      if (existsSync(chained) || isSymlink(chained)) {
        throw new Error(`--git-hook: ${file} is not ours and ${chained} already exists: refusing to overwrite either (merge them by hand)`);
      }
      chainNow = true;
    }
    plan.push({ repo: r, hooksDir, file, chained, chainNow });
  }
  return plan;
}

function writeGitHooks(
  plan: HookPlanItem[],
  p: {
    dir: string;
    stateDir: string;
    node: string;
    cli: string;
    dataDir: string;
    defaultDataDir: string;
    mode: PulseMode;
    onTimeout: 'allow' | 'deny';
    version: string;
  },
): (GitHookRecord & { chained_now: boolean })[] {
  const out: (GitHookRecord & { chained_now: boolean })[] = [];
  for (const h of plan) {
    mkdirSync(h.hooksDir, { recursive: true });
    if (h.chainNow) renameSync(h.file, h.chained); // moves a symlink itself, never its target
    writeFileAtomic(h.file, gitHookScript({ ...p, chained: h.chained }), 0o755);
    out.push({
      repo: h.repo,
      hooks_dir: h.hooksDir,
      file: h.file,
      chained: existsSync(h.chained) || isSymlink(h.chained) ? h.chained : null,
      installed_at: new Date().toISOString(),
      chained_now: h.chainNow,
    });
  }
  return out;
}

export interface HookRemoval {
  file: string;
  removed: boolean;
  /** The chained hook moved back to pre-push. */
  restored: string | null;
  /** Why it was left alone. */
  kept: string | null;
}

/** Remove one recorded hook: ours (marker-checked) goes, the chained one comes back. */
function removeGitHook(h: GitHookRecord): HookRemoval {
  const r: HookRemoval = {
    file: h.file,
    removed: false,
    restored: null,
    kept: null,
  };
  const present = existsSync(h.file) || isSymlink(h.file);
  if (present) {
    if (isSymlink(h.file) || !hasMarker(h.file)) {
      r.kept = 'not ours any more (replaced since install)';
      return r;
    }
    unlinkSync(h.file);
    r.removed = true;
  }
  const chained = h.file + CHAINED_SUFFIX;
  if ((existsSync(chained) || isSymlink(chained)) && !existsSync(h.file) && !isSymlink(h.file)) {
    renameSync(chained, h.file);
    r.restored = h.file;
  }
  return r;
}

/** `shim uninstall --git-hook [--repo P]`: remove the hooks (all, or those of one repository) and keep the shims. */
export function uninstallGitHooks(dirIn: string, repo?: string): { dir: string; hooks: HookRemoval[] } {
  const dir = normDir(resolve(dirIn));
  const config = readConfig(dir);
  if (!config) throw new Error(`no kronicle-lite shims installed in ${dir} (pass --dir)`);
  const win = process.platform === 'win32';
  const match = (h: GitHookRecord) => {
    if (repo === undefined) return true;
    const want = resolve(repo);
    const hd = gitHooksDir(want);
    return sameDir(h.repo, want, win) || (hd !== null && sameDir(h.hooks_dir, hd, win));
  };
  const all = config.git_hooks ?? [];
  const hooks = all.filter(match).map(removeGitHook);
  const left = all.filter((h) => !match(h));
  const next: ShimConfig = { ...config };
  if (left.length > 0) next.git_hooks = left;
  else delete next.git_hooks;
  writeFileAtomic(join(stateDirOf(dir), CONFIG_NAME), JSON.stringify(next, null, 2) + '\n', 0o600);
  return { dir, hooks };
}

export interface HookStatus {
  repo: string;
  file: string;
  /** Our hook is at `file`. */
  present: boolean;
  /** git still uses the hooks dir it is in (core.hooksPath unchanged). */
  active: boolean;
  /** The hooks dir git uses for `repo` now. */
  hooks_dir_now: string | null;
  chained: string | null;
}

function hookStatus(h: GitHookRecord): HookStatus {
  const now = gitHooksDir(h.repo);
  const present = existsSync(h.file) && !isSymlink(h.file) && hasMarker(h.file);
  const chained = h.file + CHAINED_SUFFIX;
  return {
    repo: h.repo,
    file: h.file,
    present,
    active: present && now !== null && sameDir(now, h.hooks_dir, process.platform === 'win32'),
    hooks_dir_now: now,
    chained: existsSync(chained) ? chained : null,
  };
}

/** Does the repository at `cwd` have our pre-push hook? null outside git. */
export function repoHookState(cwd: string): { hooks_dir: string; present: boolean } | null {
  if (git(['rev-parse', '--git-dir'], cwd) === null) return null;
  const hd = gitHooksDir(cwd);
  if (hd === null) return null;
  const f = join(hd, HOOK_NAME);
  return {
    hooks_dir: hd,
    present: existsSync(f) && !isSymlink(f) && hasMarker(f),
  };
}

export interface UninstallReport {
  dir: string;
  removed: string[];
  kept: string[];
  dir_removed: boolean;
  /** (0.8.1) The git pre-push hooks this dir installed. */
  git_hooks: HookRemoval[];
}

export function uninstall(dirIn: string): UninstallReport {
  const dir = normDir(resolve(dirIn));
  const bad = forbiddenDir(dir);
  if (bad) throw new Error(`refusing to touch ${dir}: ${bad}`);
  const removed: string[] = [];
  const kept: string[] = [];
  if (!existsSync(dir)) return { dir, removed, kept, dir_removed: false, git_hooks: [] };
  const hooks = (readConfig(dir)?.git_hooks ?? []).map(removeGitHook);
  for (const name of readdirSync(dir)) {
    if (name === STATE_DIR_NAME) continue;
    const f = join(dir, name);
    if (isSymlink(f) || !statSync(f).isFile()) {
      kept.push(f);
      continue;
    }
    if (hasMarker(f)) {
      unlinkSync(f);
      removed.push(f);
    } else {
      kept.push(f);
    }
  }
  const state = stateDirOf(dir);
  if (existsSync(state) && !isSymlink(state) && lstatSync(state).isDirectory()) {
    rmSync(state, { recursive: true, force: true });
    removed.push(state + sep);
  } else if (isSymlink(state)) {
    unlinkSync(state); // our name, but never follow it
    removed.push(state);
  }
  let dirRemoved = false;
  try {
    if (readdirSync(dir).length === 0) {
      rmdirSync(dir);
      dirRemoved = true;
    }
  } catch {
    // not empty or not ours to remove
  }
  return { dir, removed, kept, dir_removed: dirRemoved, git_hooks: hooks };
}

export interface ToolStatus {
  tool: string;
  shim: string | null;
  real: string | null;
  /** The shim is what the current PATH runs for this name. */
  active: boolean;
  first_on_path: string | null;
}

export interface StatusReport {
  dir: string;
  installed: boolean;
  config: ShimConfig | null;
  tools: ToolStatus[];
  /** (0.8.1) `source`: pinned | found | none | ambiguous (P2-01); `candidates`: the stores found. */
  store: { data_dir: string; exists: boolean; head_seq: number | null; error: string | null; source: StoreResolution['source']; candidates: string[] };
  project: {
    key: string;
    cursor_source: 'project' | 'baseline' | 'none';
    pending: PulseResult | null;
  } | null;
  unavailable_noted: boolean;
  /** The last reason a check could not run (fail open), from <state>/last-error. */
  last_error: string | null;
  /** (0.8.1) The invoking actor in this environment ($KRONICLE_LITE_ACTOR), or null. */
  invoking_actor: string | null;
  /** (0.8.1) Recorded git pre-push hooks. */
  git_hooks: HookStatus[];
  /** (0.8.1) The repository at --cwd: its hooks dir and whether our pre-push hook is there (null outside git). */
  repo_hook: { hooks_dir: string; present: boolean } | null;
}

export function status(
  dirIn: string,
  opts: {
    defaultDataDir: string;
    cwd?: string | undefined;
    path?: string | undefined;
  },
): StatusReport {
  const dir = normDir(resolve(dirIn));
  const config = readConfig(dir);
  const path = opts.path ?? process.env['PATH'] ?? '';
  const tools: ToolStatus[] = (config?.tools ?? []).map((tool) => {
    const shimFile = join(dir, tool);
    const shim = existsSync(shimFile) && hasMarker(shimFile) ? shimFile : null;
    const first = firstOnPath(tool, path);
    return {
      tool,
      shim,
      real: resolveReal(tool, { path, skipDirs: [dir] }),
      active: first !== null && hasMarker(first),
      first_on_path: first,
    };
  });
  const found = resolveStore({ pinned: config?.data_dir, targetDir: opts.cwd ?? process.cwd(), defaultDir: opts.defaultDataDir });
  const dataDir = found.dataDir ?? (config?.data_dir || opts.defaultDataDir);
  const store: StatusReport['store'] = {
    data_dir: dataDir,
    exists: found.dataDir !== null && storeExists(found.dataDir),
    head_seq: null,
    error: found.source === 'ambiguous' ? `more than one kronicle-lite store (${found.candidates.join(', ')}): world-changing commands are refused until one is pinned (shim install --data-dir DIR)` : null,
    source: found.source,
    candidates: found.candidates,
  };
  let project: StatusReport['project'] = null;
  if (config && store.exists) {
    try {
      const s = openForPulse(dataDir);
      try {
        store.head_seq = s.chain.head().seq;
        const key = projectScopeFor(opts.cwd !== undefined ? { cwd: opts.cwd } : {}).keys[0]!;
        const { source } = readProjectCursor(stateDirOf(dir), key, s);
        // A read-only look: no state file is written.
        const r =
          source === 'none'
            ? null
            : pulse(s, {
                dataDir,
                cwd: opts.cwd,
                stateDir: stateDirOf(dir),
                mode: config.mode,
                persist: false,
                invokingActor: invokingActorFromEnv(),
              });
        project = { key, cursor_source: source, pending: r };
      } finally {
        s.close();
      }
    } catch (err) {
      store.error = err instanceof Error ? err.message : String(err);
    }
  }
  return {
    dir,
    installed: config !== null,
    config,
    tools,
    store,
    project,
    unavailable_noted: existsSync(join(stateDirOf(dir), 'unavailable')),
    last_error: readLastError(dir),
    invoking_actor: invokingActorFromEnv() ?? null,
    git_hooks: (config?.git_hooks ?? []).map(hookStatus),
    repo_hook: repoHookState(opts.cwd ?? process.cwd()),
  };
}

function readLastError(dir: string): string | null {
  try {
    return readFileSync(join(stateDirOf(dir), 'last-error'), 'utf8').trim() || null;
  } catch {
    return null;
  }
}

/** Who is acknowledging: --actor, else $KRONICLE_LITE_ACTOR, else the OS user; plus the OS user. */
export function ackIdentity(explicit: string | undefined): {
  actor: string;
  user: string;
} {
  let user = 'unknown';
  try {
    user = userInfo().username || user;
  } catch {
    // no passwd entry
  }
  const a = explicit?.trim() || invokingActorFromEnv() || user;
  return { actor: a, user };
}

const logField = (v: string) => v.replace(/[^A-Za-z0-9._@:/+-]/g, '_').slice(0, 120);

/**
 * `shim ack`: an OPERATOR action (H2-12). `confirmed` says how the caller
 * established that (an interactive TTY, or `--operator`); null = neither, and
 * the ack is refused. Every attempt, refused or not, is logged in shim.log
 * with the actor and the through-seq.
 */
export function ackShim(
  dirIn: string,
  opts: {
    defaultDataDir: string;
    cwd?: string | undefined;
    through?: number | undefined;
    confirmed: 'tty' | '--operator' | null;
    actor?: string | undefined;
  },
): AckResult & {
  actor: string;
  user: string;
  confirmed: 'tty' | '--operator';
} {
  const dir = normDir(resolve(dirIn));
  const config = readConfig(dir);
  if (!config) throw new Error(`no kronicle-lite shims installed in ${dir} (pass --dir)`);
  const state = stateDirOf(dir);
  const who = ackIdentity(opts.actor);
  const id = `actor=${logField(who.actor)} user=${logField(who.user)}`;
  const want = opts.through === undefined ? 'head' : String(opts.through);
  if (opts.confirmed === null) {
    shimLog(state, 'ack', `refused through=${want} ${id} reason=not-an-operator (no tty, no --operator)`);
    throw new AckRefusedError();
  }
  const found = resolveStore({ pinned: config.data_dir, targetDir: opts.cwd ?? process.cwd(), defaultDir: opts.defaultDataDir });
  if (found.dataDir === null) throw new Error(storeOutcome(found, 'deny', ['shim', 'ack']).error);
  const store = openForPulse(found.dataDir);
  try {
    const r = ack(store, {
      stateDir: state,
      cwd: opts.cwd,
      through: opts.through,
    });
    shimLog(state, 'ack', `operator-ack through=${r.through} from=${r.from_seq} acknowledged=${r.acknowledged.length} project=${logField(r.project_key)} ${id} confirmed=${opts.confirmed}`);
    return {
      ...r,
      actor: who.actor,
      user: who.user,
      confirmed: opts.confirmed,
    };
  } finally {
    store.close();
  }
}

export class AckRefusedError extends Error {
  override readonly name = 'AckRefusedError';
  constructor() {
    super(
      'kronicle-lite shim ack is an operator action: it clears the gate without anyone re-reading. ' +
        'Run it from an interactive terminal, or pass --operator to confirm you are the operator. ' +
        'An agent should re-read the pending items instead (kronicle-lite pending --actor <its actor>), or ask the operator.',
    );
  }
}

/** The decision a shim in `dir` makes for `tool args…` (status / tests / exec). */
export function decide(dir: string, toolIn: string, args: readonly string[]): Classification {
  const config = readConfig(dir);
  const patterns = parsePatterns(config?.world ?? []);
  const tool = toolBasename(toolIn); // `/usr/bin/make release` is `make release` (L2-08)
  return classify(specFor(tool, patterns.get(tool) ?? []), args);
}

/** One line in <state>/shim.log (never throws). */
export function shimLog(stateDir: string, tool: string, text: string): void {
  try {
    mkdirSync(stateDir, { recursive: true, mode: 0o700 });
    writeFileSync(join(stateDir, 'shim.log'), `${new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')} ${tool} ${text}\n`, { flag: 'a' });
  } catch {
    // logging must never block the command
  }
}

function logOnce(stateDir: string, tool: string, reason: string): void {
  try {
    mkdirSync(stateDir, { recursive: true, mode: 0o700 });
    writeFileSync(join(stateDir, 'shim.log'), `${new Date().toISOString()} ${tool} fail-open: ${reason}\n`, { flag: 'a' });
    const marker = join(stateDir, 'unavailable');
    if (!existsSync(marker)) {
      process.stderr.write(`kronicle-lite shim: ${reason}; running ${tool} unchecked (fail open; noted once, see ${join(stateDir, 'shim.log')})\n`);
      writeFileSync(marker, '');
    }
  } catch {
    // logging must never block the command
  }
}

/**
 * `kronicle-lite shim exec --dir D --tool T -- ARGS…`: the Windows wrappers'
 * entry point (and a portable reference implementation): decide, pulse when
 * world-changing, then run the real binary and return its exit code.
 */
export function execShim(
  dirIn: string,
  tool: string,
  args: string[],
  opts: {
    defaultDataDir: string;
    cwd?: string | undefined;
    project?: string | undefined;
  },
): number {
  const dir = normDir(resolve(dirIn));
  const config = readConfig(dir);
  const state = stateDirOf(dir);
  const win = process.platform === 'win32';
  const depthRaw = process.env['KRONICLE_SHIM_DEPTH'] ?? '0';
  const depth = /^\d+$/.test(depthRaw) ? Number(depthRaw) : 0;
  if (depth >= 8) {
    process.stderr.write(`kronicle-lite shim: ${tool} reached the shims 8 times in nested calls; stopping (does a wrapper named ${tool} call ${tool} again?)\n`);
    return 126;
  }
  const c = decide(dir, tool, args);
  if (c.world && config) {
    const t0 = Date.now();
    const found = resolveStore({
      pinned: config.data_dir,
      targetDir: targetFor({
        cwd: opts.cwd,
        project: opts.project,
        command: [tool, ...args],
      }).dir,
    });
    if (found.dataDir === null || !storeExists(found.dataDir)) {
      const so = storeOutcome(found, config.mode, [toolBasename(tool), ...args]);
      shimLog(state, tool, `check ${Date.now() - t0}ms outcome=${so.reason}-${so.decision} (in-process)`);
      process.stderr.write(so.message + '\n');
      if (so.decision === 'deny') return PULSE_DENY_EXIT;
    }
    if (found.dataDir !== null && storeExists(found.dataDir)) {
      const dataDir = found.dataDir;
      try {
        const store = openForPulse(dataDir);
        let r: PulseResult;
        try {
          r = pulse(store, {
            dataDir,
            cwd: opts.cwd,
            project: opts.project,
            stateDir: state,
            mode: config.mode,
            command: [tool, ...args],
            invokingActor: invokingActorFromEnv(),
          });
        } finally {
          store.close();
        }
        shimLog(state, tool, `check ${Date.now() - t0}ms outcome=${r.decision === 'deny' ? 'deny' : 'allow'} rc=${r.decision === 'deny' ? PULSE_DENY_EXIT : 0} (in-process)`);
        if (r.message) process.stderr.write(r.message + '\n');
        try {
          rmSync(join(state, 'unavailable'), { force: true });
        } catch {
          // ignore
        }
        if (r.decision === 'deny') return PULSE_DENY_EXIT;
      } catch (err) {
        if (isCorruptError(err)) {
          // L2-03: a damaged store fails closed (deny mode) or warns loudly (warn mode), every time.
          const co = corruptOutcome(err, config.mode, [tool, ...args]);
          shimLog(state, tool, `check ${Date.now() - t0}ms outcome=${co.reason}-${co.decision} (in-process)`);
          process.stderr.write(co.message + '\n');
          if (co.decision === 'deny') return PULSE_DENY_EXIT;
        } else if (err instanceof PulseUnavailableError && config.on_timeout === 'deny') {
          // Missing or locked store under --on-timeout deny: not checked, so not run.
          shimLog(state, tool, `check ${Date.now() - t0}ms outcome=unavailable-deny (in-process)`);
          process.stderr.write(`kronicle-lite store UNAVAILABLE (${err.message}) — \`${[tool, ...args].join(' ')}\` was NOT checked and NOT run (--on-timeout deny)\n`);
          return PULSE_DENY_EXIT;
        } else {
          shimLog(state, tool, `check ${Date.now() - t0}ms outcome=failed (in-process)`);
          logOnce(state, tool, err instanceof Error ? err.message : String(err));
        }
      }
    }
  }
  // An explicit path (`shim exec --tool /usr/bin/make`) is the binary itself.
  const real = isAbsolute(tool) ? (isExecutableFile(tool, win) ? tool : null) : resolveReal(tool, { skipDirs: [dir, ...(config ? [config.dir] : [])] });
  if (!real) {
    process.stderr.write(`kronicle-lite shim: ${tool}: command not found on PATH (outside the shim dir)\n`);
    return 127;
  }
  const env = { ...process.env, KRONICLE_SHIM_DEPTH: String(depth + 1) };
  const r =
    win && /\.(cmd|bat)$/i.test(real)
      ? spawnSync(process.env['ComSpec'] ?? 'cmd.exe', ['/d', '/s', '/c', `"${[real, ...args].map(winQuote).join(' ')}"`], { stdio: 'inherit', env, windowsVerbatimArguments: true })
      : spawnSync(real, args, { stdio: 'inherit', env });
  if (r.error) {
    process.stderr.write(`kronicle-lite shim: cannot run ${real}: ${r.error.message}\n`);
    return 126;
  }
  if (r.signal) {
    process.kill(process.pid, r.signal);
    return 128;
  }
  return r.status ?? 1;
}

function winQuote(a: string): string {
  if (a !== '' && !/[\s"^&|<>()%!]/.test(a)) return a;
  return `"${a.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, '$1$1')}"`;
}
