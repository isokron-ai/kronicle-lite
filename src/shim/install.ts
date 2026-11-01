/**
 * `kronicle-lite shim install | uninstall | status | ack | exec`.
 *
 * Safety rules (the shim dir sits on PATH, so a mistake here shadows or
 * breaks real binaries):
 *   - never write into a system directory (/, /bin, /usr/…, /etc, /dev, …);
 *   - never overwrite a file that is not one of our shims, and never write
 *     through a symlink (files are written to a temp name and renamed);
 *   - uninstall removes only files that carry the shim marker, plus our own
 *     `.kronicle-shim` state dir.
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
import { delimiter, isAbsolute, join, resolve, sep, win32 } from 'node:path';

import { DEFAULT_COMMANDS, TOOL_NAME_RE, classify, parsePatterns, specFor, type Classification } from './rules.js';
import { SHIM_MARKER, cmdShim, posixShim, ps1Shim, type ShimParams } from './script.js';
import {
  PULSE_DENY_EXIT,
  ack,
  openForPulse,
  pulse,
  readProjectCursor,
  storeExists,
  writeBaseline,
  type AckResult,
  type PulseMode,
  type PulseResult,
} from './pulse.js';
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
  /** Whose current-version reads reconcile a change (absent: each change's readers). */
  pending_actors?: string[];
  /** '' = kronicle-lite's default data dir at run time. */
  data_dir: string;
  node: string;
  cli: string;
  windows: boolean;
  installed_at: string;
  baseline_seq: number | null;
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
  opts: { path?: string | undefined; skipDirs?: string[]; platform?: NodeJS.Platform; pathext?: string | undefined } = {},
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
  data_dir: string;
  baseline_seq: number | null;
  first_on_path: boolean;
  warnings: string[];
  path_hint: string;
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
      version: o.version,
    };
    if (posix) planned.push({ file: join(dir, tool), text: posixShim(params), mode: 0o755 });
    if (win) {
      planned.push({ file: join(dir, `${tool}.cmd`), text: cmdShim(params), mode: 0o755 });
      planned.push({ file: join(dir, `${tool}.ps1`), text: ps1Shim(params), mode: 0o644 });
    }
  }
  for (const p of planned) {
    if (!existsSync(p.file) && !isSymlink(p.file)) continue;
    if (isSymlink(p.file)) throw new Error(`refusing to replace ${p.file}: it is a symlink, not a kronicle-lite shim`);
    if (!hasMarker(p.file)) throw new Error(`refusing to overwrite ${p.file}: it is not a kronicle-lite shim (remove it yourself if it should go)`);
  }

  mkdirSync(dir, { recursive: true, mode: 0o755 });
  mkdirSync(state, { recursive: true, mode: 0o700 });
  for (const p of planned) writeFileAtomic(p.file, p.text, p.mode);

  const warnings: string[] = [];
  let baseline: number | null = null;
  if (storeExists(o.effectiveDataDir)) {
    const store = openForPulse(o.effectiveDataDir);
    try {
      baseline = writeBaseline(state, store);
    } finally {
      store.close();
    }
  } else {
    warnings.push(`no kronicle-lite store in ${o.effectiveDataDir} yet: shims fail open until one exists; the first check then starts at its head`);
  }
  const config: ShimConfig = {
    format: 'kronicle-lite-shim/1',
    version: o.version,
    dir: phys,
    tools,
    world: o.world ?? [],
    mode,
    ...(o.pendingActors && o.pendingActors.length > 0 ? { pending_actors: o.pendingActors } : {}),
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
    data_dir: o.dataDir ?? '',
    baseline_seq: baseline,
    first_on_path: first,
    warnings,
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

export interface UninstallReport {
  dir: string;
  removed: string[];
  kept: string[];
  dir_removed: boolean;
}

export function uninstall(dirIn: string): UninstallReport {
  const dir = normDir(resolve(dirIn));
  const bad = forbiddenDir(dir);
  if (bad) throw new Error(`refusing to touch ${dir}: ${bad}`);
  const removed: string[] = [];
  const kept: string[] = [];
  if (!existsSync(dir)) return { dir, removed, kept, dir_removed: false };
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
  return { dir, removed, kept, dir_removed: dirRemoved };
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
  store: { data_dir: string; exists: boolean; head_seq: number | null; error: string | null };
  project: { key: string; cursor_source: 'project' | 'baseline' | 'none'; pending: PulseResult | null } | null;
  unavailable_noted: boolean;
  /** The last reason a check could not run (fail open), from <state>/last-error. */
  last_error: string | null;
}

export function status(dirIn: string, opts: { defaultDataDir: string; cwd?: string | undefined; path?: string | undefined }): StatusReport {
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
  const dataDir = config?.data_dir ? config.data_dir : opts.defaultDataDir;
  const store: StatusReport['store'] = { data_dir: dataDir, exists: storeExists(dataDir), head_seq: null, error: null };
  let project: StatusReport['project'] = null;
  if (config && store.exists) {
    try {
      const s = openForPulse(dataDir);
      try {
        store.head_seq = s.chain.head().seq;
        const key = projectScopeFor(opts.cwd !== undefined ? { cwd: opts.cwd } : {}).keys[0]!;
        const { source } = readProjectCursor(stateDirOf(dir), key);
        // A read-only look: no state file is written.
        const r = source === 'none' ? null : pulse(s, { dataDir, cwd: opts.cwd, stateDir: stateDirOf(dir), mode: config.mode, persist: false });
        project = { key, cursor_source: source, pending: r };
      } finally {
        s.close();
      }
    } catch (err) {
      store.error = err instanceof Error ? err.message : String(err);
    }
  }
  return { dir, installed: config !== null, config, tools, store, project, unavailable_noted: existsSync(join(stateDirOf(dir), 'unavailable')), last_error: readLastError(dir) };
}

function readLastError(dir: string): string | null {
  try {
    return readFileSync(join(stateDirOf(dir), 'last-error'), 'utf8').trim() || null;
  } catch {
    return null;
  }
}

export function ackShim(dirIn: string, opts: { defaultDataDir: string; cwd?: string | undefined; through?: number | undefined }): AckResult {
  const dir = normDir(resolve(dirIn));
  const config = readConfig(dir);
  if (!config) throw new Error(`no kronicle-lite shims installed in ${dir} (pass --dir)`);
  const dataDir = config.data_dir || opts.defaultDataDir;
  const store = openForPulse(dataDir);
  try {
    return ack(store, { stateDir: stateDirOf(dir), cwd: opts.cwd, through: opts.through });
  } finally {
    store.close();
  }
}

/** The decision a shim in `dir` makes for `tool args…` (status / tests / exec). */
export function decide(dir: string, tool: string, args: readonly string[]): Classification {
  const config = readConfig(dir);
  const patterns = parsePatterns(config?.world ?? []);
  return classify(specFor(tool, patterns.get(tool) ?? []), args);
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
export function execShim(dirIn: string, tool: string, args: string[], opts: { defaultDataDir: string; cwd?: string | undefined }): number {
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
    const dataDir = config.data_dir || opts.defaultDataDir;
    try {
      const store = openForPulse(dataDir);
      let r: PulseResult;
      try {
        r = pulse(store, { dataDir, cwd: opts.cwd, stateDir: state, mode: config.mode, command: [tool, ...args] });
      } finally {
        store.close();
      }
      if (r.message) process.stderr.write(r.message + '\n');
      try {
        rmSync(join(state, 'unavailable'), { force: true });
      } catch {
        // ignore
      }
      if (r.decision === 'deny') return PULSE_DENY_EXIT;
    } catch (err) {
      logOnce(state, tool, err instanceof Error ? err.message : String(err));
    }
  }
  const real = resolveReal(tool, { skipDirs: [dir, ...(config ? [config.dir] : [])] });
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

