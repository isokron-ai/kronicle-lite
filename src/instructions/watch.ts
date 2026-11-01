/**
 * `kronicle-lite watch`: keep instruction files chained while they change.
 *
 * Two detectors feed one debounced sync per path:
 *   - fs.watch on every directory that holds (or will hold) a watched file —
 *     parent directories, not the files, so editors that save by rename are
 *     seen; non-recursive, so it behaves the same on Linux, macOS and Windows;
 *   - a polling pass every `intervalMs` that re-expands the patterns (new
 *     rule files, new subdirectories, the memory dir appearing), compares
 *     mtime+size and catches anything fs.watch missed or never reported.
 * `poll: true` (or an fs.watch error) leaves polling alone. A sync re-reads
 * the file and is a no-op when the content hash matches the stored revision,
 * so double triggers cost nothing.
 */

import { watch as fsWatch, statSync, type FSWatcher } from 'node:fs';
import { join, resolve } from 'node:path';

import type { KronicleLite } from '../store.js';
import {
  defaultPatterns,
  entryFor,
  expandPatterns,
  explicitPatterns,
  patternMatches,
  resolveContext,
  type InstructionContext,
  type InstructionEntry,
  type ResolvedContext,
  type WatchPattern,
} from './paths.js';
import { syncInstructionFile, type SyncResult } from './sync.js';

export interface WatchOptions extends InstructionContext {
  /** Explicit files or directories; empty = the default instruction set. */
  paths?: readonly string[];
  /** Polling / rescan interval (default 2000 ms). */
  intervalMs?: number;
  /** Quiet period after the last change before syncing (default 150 ms). */
  debounceMs?: number;
  /** Polling only; no fs.watch. */
  poll?: boolean;
  actor_id?: string;
  onEvent?: (e: WatchEvent) => void;
}

export type WatchEvent =
  | { type: 'synced'; result: SyncResult; trigger: 'start' | 'fs' | 'poll' }
  | { type: 'warning'; message: string }
  | { type: 'watching'; files: string[]; dirs: number; mode: 'fs.watch+poll' | 'poll' };

/** Resolve the watch set without starting anything (watch --list, hooks, doctor). */
export function resolveWatchSet(opts: WatchOptions = {}): { rc: ResolvedContext; patterns: WatchPattern[]; entries: InstructionEntry[]; dirs: string[] } {
  const rc = resolveContext(opts);
  const patterns = opts.paths && opts.paths.length > 0 ? explicitPatterns(opts.paths, rc) : defaultPatterns(rc);
  const { files, dirs } = expandPatterns(patterns);
  return { rc, patterns, entries: files.map((f) => entryFor(f, rc)), dirs };
}

/** One-shot: sync every file of the watch set (put --from-instructions). */
export function syncInstructionSet(store: KronicleLite, opts: WatchOptions = {}): SyncResult[] {
  const { entries } = resolveWatchSet(opts);
  return entries.map((e) => syncInstructionFile(store, e, opts.actor_id !== undefined ? { actor_id: opts.actor_id } : {}));
}

export class InstructionWatcher {
  private readonly rc: ResolvedContext;
  private readonly patterns: WatchPattern[];
  private readonly interval: number;
  private readonly debounce: number;
  private readonly watchers = new Map<string, FSWatcher>();
  private readonly timers = new Map<string, NodeJS.Timeout>();
  private readonly stamps = new Map<string, string>();
  private readonly known = new Map<string, InstructionEntry>();
  private poller: NodeJS.Timeout | null = null;
  private fsEnabled: boolean;
  private closed = false;

  constructor(
    private readonly store: KronicleLite,
    private readonly opts: WatchOptions = {},
  ) {
    const set = resolveWatchSet(opts);
    this.rc = set.rc;
    this.patterns = set.patterns;
    this.interval = Math.max(50, opts.intervalMs ?? 2_000);
    this.debounce = Math.max(0, opts.debounceMs ?? 150);
    this.fsEnabled = !opts.poll;
  }

  get context(): ResolvedContext {
    return this.rc;
  }

  get mode(): 'fs.watch+poll' | 'poll' {
    return this.fsEnabled ? 'fs.watch+poll' : 'poll';
  }

  /** Initial sync of every present file, then start fs.watch + polling. */
  start(): SyncResult[] {
    const { files, dirs } = expandPatterns(this.patterns);
    const results: SyncResult[] = [];
    for (const f of files) {
      const r = this.syncPath(f, 'start');
      if (r) results.push(r);
    }
    this.watchDirs(dirs);
    this.poller = setInterval(() => this.pollOnce(), this.interval);
    this.emit({ type: 'watching', files, dirs: dirs.length, mode: this.mode });
    return results;
  }

  close(): void {
    this.closed = true;
    if (this.poller) clearInterval(this.poller);
    this.poller = null;
    for (const t of this.timers.values()) clearTimeout(t);
    this.timers.clear();
    for (const w of this.watchers.values()) w.close();
    this.watchers.clear();
  }

  private emit(e: WatchEvent): void {
    this.opts.onEvent?.(e);
  }

  private stamp(path: string): string {
    try {
      const st = statSync(path);
      return st.isFile() ? `${st.mtimeMs}:${st.size}:${st.ino}` : 'absent';
    } catch {
      return 'absent';
    }
  }

  private matches(path: string): boolean {
    return this.patterns.some((p) => patternMatches(p, path));
  }

  private syncPath(path: string, trigger: 'start' | 'fs' | 'poll'): SyncResult | null {
    if (this.closed) return null;
    const abs = resolve(path);
    const entry = this.known.get(abs) ?? entryFor(abs, this.rc);
    this.known.set(abs, entry);
    this.stamps.set(abs, this.stamp(abs));
    const result = syncInstructionFile(this.store, entry, this.opts.actor_id !== undefined ? { actor_id: this.opts.actor_id } : {});
    if (trigger === 'start' || (result.action !== 'unchanged' && result.action !== 'missing')) {
      this.emit({ type: 'synced', result, trigger });
    }
    return result;
  }

  private schedule(path: string, trigger: 'fs' | 'poll'): void {
    if (this.closed) return;
    const abs = resolve(path);
    const prev = this.timers.get(abs);
    if (prev) clearTimeout(prev);
    this.timers.set(
      abs,
      setTimeout(() => {
        this.timers.delete(abs);
        this.syncPath(abs, trigger);
      }, this.debounce),
    );
  }

  private watchDirs(dirs: readonly string[]): void {
    if (!this.fsEnabled) return;
    for (const dir of dirs) {
      if (this.watchers.has(dir)) continue;
      let w: FSWatcher;
      try {
        w = fsWatch(dir, { persistent: true }, (_event, filename) => {
          if (filename === null || filename === undefined) {
            this.pollOnce();
            return;
          }
          const full = join(dir, filename.toString());
          if (this.known.has(resolve(full)) || this.matches(full)) this.schedule(full, 'fs');
        });
      } catch {
        continue; // the directory does not exist (yet); polling will add it when it appears
      }
      w.on('error', (err: Error) => {
        w.close();
        this.watchers.delete(dir);
        this.emit({ type: 'warning', message: `fs.watch on ${dir} failed (${err.message}); polling continues` });
      });
      this.watchers.set(dir, w);
    }
  }

  /** Rescan the patterns, compare stamps, schedule what changed or disappeared. */
  pollOnce(): void {
    if (this.closed) return;
    const { files, dirs } = expandPatterns(this.patterns);
    this.watchDirs(dirs);
    const present = new Set(files);
    for (const f of files) {
      if (this.stamps.get(f) !== this.stamp(f)) this.schedule(f, 'poll');
    }
    for (const f of this.known.keys()) {
      if (!present.has(f) && this.stamps.get(f) !== 'absent') this.schedule(f, 'poll');
    }
  }
}
