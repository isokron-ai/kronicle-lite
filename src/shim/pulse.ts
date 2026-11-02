/**
 * `kronicle-lite pulse`: the exec-time check a shim (or any hook) runs right
 * before a world-changing command. It is orient `--focus retractions` plus the
 * integrity pass, turned into one decision:
 *
 *   allow  nothing blocking since the cursor (informational news is noted and
 *          the cursor advances);
 *   deny   blocking retractions (severity safety | behavioral; format-only
 *          edits are never in `retractions`) since the cursor that are not
 *          yet reconciled: the command must not run; the cursor does NOT
 *          move, so a retry without reconciling is refused again;
 *   warn   same as deny under `--mode warn`: printed, the cursor advances,
 *          the command runs;
 *   seed   first check (no cursor yet): records the head, allows.
 *
 * Reconciled = version-bound, the rule `pending` uses (src/lineage): a
 * blocking change is resolved once every pending actor has read the CURRENT
 * version of the changed block (a recall hit, a document read, its own
 * write; for a removal, the document after the removal). Pending actors: the
 * configured ones (`--pending-actor`, `shim install --pending-actor`), else
 * the invoking actor (0.8.1: `KRONICLE_LITE_ACTOR` in the command's
 * environment, `--invoking-actor`), else (no invoking actor known, or
 * `--all-readers`) the actors that read any version of the affected block
 * (for a `derived` change: also those that read or wrote the note). Nobody to
 * check (no reader recorded, or a document-level event) = not resolved. So an
 * agent that re-reads the runbook through recall clears the gate itself.
 * `kronicle-lite shim ack --through SEQ` is an OPERATOR override (0.8.1: a
 * TTY or `--operator`, logged); the refusal never tells the agent about it.
 *
 * With an invoking actor, a change blocks that actor when it relied on it
 * (read an earlier version; an instruction file; or a change nobody read),
 * and the actor keeps its own cursor per project (cursors/<key>@<actor>), so
 * one agent clearing the gate never moves another agent's position.
 *
 * The project is the one the command acts on (0.8.1, src/shim/target.ts:
 * `git -C`, `--git-dir`, `--work-tree`, GIT_DIR, `terraform -chdir=`, …),
 * plus the superproject of a submodule; a target that cannot be determined
 * refuses (reason `target`).
 *
 * An integrity failure (the store was edited outside kronicle-lite) denies in
 * every mode: fail closed. A store that cannot be opened at all is
 * "unavailable" (exit 3): the shim fails open and logs once (docs/PUSH.md).
 *
 * State (`--state DIR`, the shim's `.kronicle-shim` dir) holds one cursor per
 * project (cursors/<project key>), seeded from the install-time baseline, so
 * acknowledging in one project never clears another project's gate.
 */

import { createHash } from 'node:crypto';
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, readSync, realpathSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';

import { parseCursor, serializeCursor } from '../orient/cursor.js';
import type { Retraction } from '../orient/retraction.js';
import type { IntegritySummary, SystemState } from '../orient/orient.js';
import { git } from '../git/git.js';
import { projectScopeFor } from '../instructions/paths.js';
import { KronicleLite } from '../store.js';
import { commandTarget, withoutGitEnv, type CommandTarget } from './target.js';

export const PULSE_DENY_EXIT = 77;
export const PULSE_UNAVAILABLE_EXIT = 3;
export const SHIM_ACTOR = 'shim';

export type PulseMode = 'deny' | 'warn';
export type PulseDecision = 'allow' | 'deny' | 'warn' | 'seed';

export interface PulseOptions {
  dataDir: string;
  cwd?: string | undefined;
  actor?: string | undefined;
  /** Explicit cursor (hook use). Ignored when `stateDir` is given. */
  cursor?: string | undefined;
  /** Shim state dir: per-project cursors, baseline, log. */
  stateDir?: string | undefined;
  mode?: PulseMode | undefined;
  /** The command about to run (for the message only). */
  command?: string[] | undefined;
  /** No project scoping. */
  allProjects?: boolean | undefined;
  /** false: compute the decision without writing the state dir (status). Default true. */
  persist?: boolean | undefined;
  /**
   * Whose reads reconcile a change. Undefined: `pending_actors` of the shim
   * config in `stateDir` when set, else the actors that read the affected
   * blocks. [] = no read reconciles anything (acknowledgement only).
   */
  pendingActors?: string[] | undefined;
  /**
   * The actor running the command (0.8.1; the shim passes $KRONICLE_LITE_ACTOR).
   * Used when no pending actors are configured and `allReaders` is off.
   */
  invokingActor?: string | undefined;
  /** Every reader of a changed block must re-read (the 0.8.0 default). Undefined: the shim config's `all_readers`. */
  allReaders?: boolean | undefined;
  /** Explicit project directory (`shim exec --project`): skips reading the target from the command. */
  project?: string | undefined;
}

/** Whose reads reconcile: the configured actors, the invoking actor, or every reader of the changed block. */
export type PendingMode = 'configured' | 'actor' | 'readers';

/** A blocking retraction, with who still has to read the current version. */
export type BlockingRetraction = Retraction & {
  /** Actors checked for this change (configured, or its readers). */
  pending_actors: string[];
  /** Of those, the ones that have not read the current version ([] with no actors: only an ack clears it). */
  unread_by: string[];
};

/** A target the pulse resolved the project from. */
export type PulseTarget = Pick<CommandTarget, 'dir' | 'explicit' | 'via'>;

export interface PulseResult {
  format: 'kronicle-lite/1';
  decision: PulseDecision;
  reason: 'clear' | 'retractions' | 'integrity' | 'seeded' | 'genesis' | 'target';
  mode: PulseMode;
  head: { seq: number; hash: string };
  /** The cursor to carry: the head when allowed / warned / seeded; the unchanged cursor when denied. */
  cursor: string;
  from_seq: number;
  recovery: string;
  project_keys: string[] | null;
  /** Unreconciled blocking retractions. */
  blocking: BlockingRetraction[];
  /** Blocking retractions since the cursor that every pending actor has re-read at the current version. */
  resolved: BlockingRetraction[];
  informational: Retraction[];
  hidden_retractions: number;
  /** The configured pending actors, or null (each change's readers). */
  pending_actors: string[] | null;
  /** (0.8.1) `configured` (pending_actors), `actor` (invoking_actor only), `readers` (every reader). */
  pending_mode: PendingMode;
  /** (0.8.1) The actor running the command, when known. */
  invoking_actor: string | null;
  /** (0.8.1) Actor mode: blocking changes since the cursor to blocks the invoking actor never read (others did): not blocking for it. */
  not_relied_on: BlockingRetraction[];
  /** (0.8.1) The directory whose project was checked, and what named it (`-C`, `--git-dir`, `GIT_DIR`, `--project`, …; null = the working directory). */
  target: PulseTarget | null;
  integrity: IntegritySummary | null;
  /** What the shim prints on stderr (null: nothing to say). */
  message: string | null;
  /** Denied for retractions: the head seq an operator acknowledges through (`shim ack --through`). Not shown to the agent. */
  ack_through: number | null;
}

export class PulseUnavailableError extends Error {
  override readonly name = 'PulseUnavailableError';
}

/**
 * The store file is there but is not a sound SQLite database (0.8.1, live
 * finding L2-03): a zeroed page, a bad header, SQLITE_CORRUPT / NOTADB. Unlike
 * "unavailable" (missing, locked, slow), this is an integrity failure: the
 * shim refuses (deny mode) or warns loudly (warn mode); it never fails open.
 */
export class PulseCorruptError extends Error {
  override readonly name: string = 'PulseCorruptError';
}

/**
 * The store file is there but cannot be read or opened for a reason that is
 * not transient (permissions, an I/O error, a format this version cannot
 * open). Misconfiguration or damage, like a corrupt store: refused in deny
 * mode. Only a lock or a slow check is transient (`--on-timeout`).
 */
export class PulseUnreadableError extends PulseCorruptError {
  override readonly name: string = 'PulseUnreadableError';
}

const TRANSIENT_CODE_RE = /^(SQLITE_BUSY|SQLITE_LOCKED|EBUSY|EAGAIN|EINTR)/;
const TRANSIENT_TEXT_RE = /database is locked|database table is locked|SQLITE_BUSY/i;

/** A lock or a busy wait that ran out: retrying later can succeed (`--on-timeout` decides). */
export function isTransientError(err: unknown): boolean {
  for (let e: unknown = err, i = 0; e && i < 5; i++) {
    const code = (e as { code?: unknown }).code;
    if (typeof code === 'string' && TRANSIENT_CODE_RE.test(code)) return true;
    if (e instanceof Error && TRANSIENT_TEXT_RE.test(e.message)) return true;
    e = (e as { cause?: unknown }).cause;
  }
  return false;
}

export function storeExists(dataDir: string): boolean {
  return existsSync(join(dataDir, 'kronicle-lite.db'));
}

const CORRUPT_CODE_RE = /^SQLITE_(CORRUPT|NOTADB)/;
const CORRUPT_TEXT_RE = /database disk image is malformed|file is not a database|file is encrypted or is not a database|malformed database schema|bad header/i;

/** Does this error (or its cause) say the database file itself is damaged? */
export function isCorruptError(err: unknown): boolean {
  for (let e: unknown = err, i = 0; e && i < 5; i++) {
    if (e instanceof PulseCorruptError) return true;
    const code = (e as { code?: unknown }).code;
    if (typeof code === 'string' && CORRUPT_CODE_RE.test(code)) return true;
    if (e instanceof Error && CORRUPT_TEXT_RE.test(e.message)) return true;
    e = (e as { cause?: unknown }).cause;
  }
  return false;
}

const SQLITE_HEADER = 'SQLite format 3\0';

/**
 * Open the store for a pulse; never created. Missing or locked = "unavailable"
 * (PulseUnavailableError); damaged = "corrupt" (PulseCorruptError); there but
 * unreadable for any other reason = "unreadable" (PulseUnreadableError).
 */
export function openForPulse(dataDir: string): KronicleLite {
  const file = join(dataDir, 'kronicle-lite.db');
  if (!storeExists(dataDir)) throw new PulseUnavailableError(`no kronicle-lite store in ${dataDir}`);
  try {
    const buf = Buffer.alloc(16);
    const fd = openSync(file, 'r');
    let n = 0;
    try {
      n = readSync(fd, buf, 0, 16, 0);
    } finally {
      closeSync(fd);
    }
    const head = buf.subarray(0, n).toString('latin1');
    if (head !== SQLITE_HEADER) throw new PulseCorruptError(`${file}: bad header (not an SQLite database)`);
  } catch (err) {
    if (err instanceof PulseCorruptError) throw err;
    const msg = `cannot read the kronicle-lite store in ${dataDir}: ${err instanceof Error ? err.message : String(err)}`;
    if (isTransientError(err)) throw new PulseUnavailableError(msg, { cause: err });
    throw new PulseUnreadableError(msg, { cause: err });
  }
  try {
    return new KronicleLite({ dataDir });
  } catch (err) {
    const msg = `cannot open the kronicle-lite store in ${dataDir}: ${err instanceof Error ? err.message : String(err)}`;
    if (isCorruptError(err)) throw new PulseCorruptError(msg, { cause: err });
    if (isTransientError(err)) throw new PulseUnavailableError(msg, { cause: err });
    throw new PulseUnreadableError(msg, { cause: err });
  }
}

// ---------------------------------------------------------------- which store (P2-01)

export interface StoreResolution {
  /** The store to check, or null (none found, or more than one). */
  dataDir: string | null;
  /** `pinned`: shim install --data-dir; `found`: the one store discovered; `none` / `ambiguous`: refuse. */
  source: 'pinned' | 'found' | 'none' | 'ambiguous';
  /** Existing stores considered (realpaths). */
  candidates: string[];
  /** Where it looked. */
  looked: string[];
}

function real(p: string): string {
  try {
    return realpathSync.native(p);
  } catch {
    return resolve(p);
  }
}

/**
 * The store a shim checks, resolved the way the MCP server finds it (0.8.1,
 * protocol finding P2-01: a Cursor / Copilot server on a project-local
 * `.kronicle-lite/` while the shim checked ~/.kronicle-lite, so a push after a
 * change landed silently):
 *   - `shim install --data-dir DIR` pins it: that store only;
 *   - else `$KRONICLE_LITE_DATA_DIR`, else the default (`defaultDir`, or
 *     ~/.kronicle-lite), PLUS the nearest `.kronicle-lite/` holding a store
 *     found walking up from the directory the command acts on.
 * Exactly one existing store = use it. None, or two different ones = the
 * caller refuses in deny mode (it cannot tell which store the agent uses).
 */
export function resolveStore(o: { pinned?: string | undefined; targetDir: string; env?: NodeJS.ProcessEnv; defaultDir?: string | undefined }): StoreResolution {
  if (o.pinned !== undefined && o.pinned !== '') {
    const d = resolve(o.pinned);
    return { dataDir: d, source: storeExists(d) ? 'pinned' : 'none', candidates: storeExists(d) ? [real(d)] : [], looked: [d] };
  }
  const env = o.env ?? process.env;
  const configured = resolve(env['KRONICLE_LITE_DATA_DIR'] || o.defaultDir || join(homedir(), '.kronicle-lite'));
  const looked = [configured];
  const found: string[] = [];
  if (storeExists(configured)) found.push(real(configured));
  let d = resolve(o.targetDir);
  for (let i = 0; i < 64; i++) {
    const c = join(d, '.kronicle-lite');
    if (storeExists(c)) {
      const r = real(c);
      if (!found.includes(r)) found.push(r);
      break;
    }
    const up = dirname(d);
    if (up === d) break;
    d = up;
  }
  looked.push(`.kronicle-lite/ in ${resolve(o.targetDir)} and its parents`);
  if (found.length === 1) return { dataDir: found[0]!, source: 'found', candidates: found, looked };
  return { dataDir: null, source: found.length === 0 ? 'none' : 'ambiguous', candidates: found, looked };
}

/** A shim with no single store to check: refuse (deny mode) or run with a loud warning (warn mode). */
export function storeOutcome(r: StoreResolution, mode: PulseMode, command: readonly string[] | undefined): { decision: 'deny' | 'warn'; reason: 'no-store' | 'ambiguous-store'; message: string; exit: number; error: string } {
  const cmd = displayCommand(command);
  const why =
    r.source === 'ambiguous'
      ? `found more than one kronicle-lite store (${r.candidates.join(', ')}) and cannot tell which one your MCP server uses`
      : `found no kronicle-lite store (looked in ${r.looked.join('; ')})`;
  const fix =
    r.source === 'ambiguous'
      ? `Operator fix: pin the store the MCP server uses (its --data-dir): kronicle-lite shim install --data-dir ${r.candidates[0] ?? 'DIR'} (or ${r.candidates.slice(1).join(', ') || 'the other one'}).`
      : "Operator fix: point the shims at the store the MCP server uses (its --data-dir, or KRONICLE_LITE_DATA_DIR): kronicle-lite shim install --data-dir DIR, or set KRONICLE_LITE_DATA_DIR=DIR in this command's environment.";
  const error = why;
  return mode === 'warn'
    ? { decision: 'warn', reason: r.source === 'ambiguous' ? 'ambiguous-store' : 'no-store', exit: 0, error, message: `kronicle-lite shim (warn): \`${cmd}\` is running UNCHECKED — the shim ${why}. ${fix}` }
    : {
        decision: 'deny',
        reason: r.source === 'ambiguous' ? 'ambiguous-store' : 'no-store',
        exit: PULSE_DENY_EXIT,
        error,
        message: `kronicle-lite shim: did NOT run \`${cmd}\` — the shim ${why}, so it could not be checked. ${fix}`,
      };
}

/** What a shim says and does for a corrupt store: refuse (deny mode, exit 77) or run with a loud warning (warn mode). */
export function corruptOutcome(
  err: unknown,
  mode: PulseMode,
  command: readonly string[] | undefined,
): { decision: 'deny' | 'warn'; reason: 'corrupt' | 'unreadable'; message: string; exit: number; error: string } {
  const detail = err instanceof Error ? err.message : String(err);
  const cmd = displayCommand(command);
  const unreadable = err instanceof PulseUnreadableError;
  const reason = unreadable ? ('unreadable' as const) : ('corrupt' as const);
  const why = unreadable
    ? `the kronicle-lite store is UNREADABLE (${detail}). Tell the operator: fix its permissions or the data dir the shims use (kronicle-lite shim status, doctor).`
    : `the kronicle-lite store is CORRUPT (${detail}). Do not act on runbooks, notes or anything else recalled from it until it is repaired (kronicle-lite doctor / verify-chain, or restore a backup; tell the operator).`;
  return mode === 'warn'
    ? { decision: 'warn', reason, exit: 0, error: detail, message: `kronicle-lite shim (warn): \`${cmd}\` is running UNCHECKED — ${why}` }
    : { decision: 'deny', reason, exit: PULSE_DENY_EXIT, error: detail, message: `kronicle-lite shim: did NOT run \`${cmd}\` — ${why} World-changing commands are refused until then.` };
}

// ---------------------------------------------------------------- state files

export function safeKey(key: string): string {
  return key.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 120) || '_';
}

function readText(file: string): string | null {
  try {
    const t = readFileSync(file, 'utf8').trim();
    return t.length > 0 ? t : null;
  } catch {
    return null;
  }
}

function writeAtomic(file: string, text: string): void {
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, text + '\n', { mode: 0o600 });
  renameSync(tmp, file);
}

export function cursorFile(stateDir: string, projectKey: string): string {
  return join(stateDir, 'cursors', safeKey(projectKey));
}

/** `pending_actors` from the shim config next to the state (`shim install --pending-actor`), or null. */
export function configuredPendingActors(stateDir: string): string[] | null {
  try {
    const c = JSON.parse(readFileSync(join(stateDir, 'config.json'), 'utf8')) as { pending_actors?: unknown };
    if (Array.isArray(c.pending_actors) && c.pending_actors.every((a) => typeof a === 'string')) return c.pending_actors as string[];
  } catch {
    // no config (a bare --state dir): readers decide
  }
  return null;
}

export function baselineFile(stateDir: string): string {
  return join(stateDir, 'baseline.cursor');
}

/** One store's own starting point (0.8.1: the shims may check more than one store, P2-01). */
export function storeBaselineFile(stateDir: string, store: KronicleLite): string {
  return join(stateDir, 'baselines', createHash('sha256').update(store.identity.cursor_secret).digest('hex').slice(0, 16));
}

/**
 * The project's cursor, else the starting point. With `store`, a cursor that
 * store did not sign (written while another store was checked) is passed
 * over, and the store's own baseline comes first: a foreign cursor would
 * re-seed at the head and skip what changed (P2-01).
 */
export function readProjectCursor(stateDir: string, projectKey: string, store?: KronicleLite): { cursor: string | null; source: 'project' | 'baseline' | 'none' } {
  const ok = (c: string | null): c is string => c !== null && (store === undefined || cursorSeq(store, c) !== null);
  const own = readText(cursorFile(stateDir, projectKey));
  if (ok(own)) return { cursor: own, source: 'project' };
  if (store !== undefined) {
    const sb = readText(storeBaselineFile(stateDir, store));
    if (ok(sb)) return { cursor: sb, source: 'baseline' };
  }
  const base = readText(baselineFile(stateDir));
  if (ok(base)) return { cursor: base, source: 'baseline' };
  return { cursor: null, source: 'none' };
}

export function writeProjectCursor(stateDir: string, projectKey: string, cursor: string): void {
  mkdirSync(join(stateDir, 'cursors'), { recursive: true, mode: 0o700 });
  writeAtomic(cursorFile(stateDir, projectKey), cursor);
}

/** `all_readers` from the shim config (`shim install --all-readers`). */
export function configuredAllReaders(stateDir: string): boolean {
  try {
    const c = JSON.parse(readFileSync(join(stateDir, 'config.json'), 'utf8')) as { all_readers?: unknown };
    return c.all_readers === true;
  } catch {
    return false;
  }
}

/** One actor's own position in one project (actor mode): cursors/<key>@<actor>-<hash8>. */
export function actorCursorFile(stateDir: string, projectKey: string, actor: string): string {
  const h = createHash('sha256').update(actor).digest('hex').slice(0, 8);
  return join(stateDir, 'cursors', `${safeKey(projectKey)}@${safeKey(actor).slice(0, 40)}-${h}`);
}

function cursorSeq(store: KronicleLite, token: string): number | null {
  try {
    return parseCursor(token, store.identity.cursor_secret).chain_seq;
  } catch {
    return null;
  }
}

/**
 * Actor mode: the later of the actor's own cursor and the project cursor (an
 * operator `ack` moves the project cursor and so clears every actor up to it).
 */
export function readActorCursor(store: KronicleLite, stateDir: string, projectKey: string, actor: string): { cursor: string | null; source: 'actor' | 'project' | 'baseline' | 'none' } {
  const proj = readProjectCursor(stateDir, projectKey, store);
  const own = readText(actorCursorFile(stateDir, projectKey, actor));
  if (own === null) return proj;
  if (proj.cursor === null) return { cursor: own, source: 'actor' };
  const a = cursorSeq(store, own);
  const p = cursorSeq(store, proj.cursor);
  if (a === null) return proj;
  if (p !== null && p > a) return proj;
  return { cursor: own, source: 'actor' };
}

/** A blocked directory is the only thing this checks: does it exist? */
function isDirectory(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

/**
 * The project scope for a target directory: its own keys, plus the keys of the
 * superproject(s) when it is a submodule (a submodule push during work on the
 * superproject is checked against the superproject's documents too).
 */
export function shimScope(t: CommandTarget): { keys: string[]; root: string } {
  const run = () => {
    const own = projectScopeFor({ cwd: t.dir });
    const keys = [...own.keys];
    let dir = own.root;
    for (let i = 0; i < 4; i++) {
      const sup = git(['rev-parse', '--show-superproject-working-tree'], dir);
      if (!sup) break;
      const s = projectScopeFor({ cwd: sup });
      for (const k of s.keys) if (!keys.includes(k)) keys.push(k);
      if (s.root === dir) break;
      dir = s.root;
    }
    return { keys, root: own.root };
  };
  return t.git_env ? withoutGitEnv(run) : run();
}

/** The target of the command (or the explicit project). */
export function targetFor(opts: Pick<PulseOptions, 'cwd' | 'command' | 'project'>): CommandTarget {
  if (opts.project !== undefined) {
    const dir = resolve(opts.cwd ?? process.cwd(), opts.project);
    return { dir, explicit: true, via: '--project', error: isDirectory(dir) ? null : `--project ${dir} is not a directory`, git_env: false };
  }
  return commandTarget(opts.command, opts.cwd ?? process.cwd());
}

/** Whose reads count, from the options and the shim config. */
export function pendingModeFor(opts: Pick<PulseOptions, 'pendingActors' | 'stateDir' | 'invokingActor' | 'allReaders'>): {
  mode: PendingMode;
  configured: string[] | null;
  invoker: string | null;
  allReaders: boolean;
} {
  const configured = opts.pendingActors ?? (opts.stateDir !== undefined ? configuredPendingActors(opts.stateDir) : null);
  const allReaders = opts.allReaders ?? (opts.stateDir !== undefined ? configuredAllReaders(opts.stateDir) : false);
  const inv = opts.invokingActor?.trim();
  const invoker = inv !== undefined && inv !== '' ? inv : null;
  if (configured !== null) return { mode: 'configured', configured, invoker, allReaders };
  if (invoker !== null && !allReaders) return { mode: 'actor', configured: null, invoker, allReaders };
  return { mode: 'readers', configured: null, invoker, allReaders };
}

/** A full cursor for the shim actor at `seq` (must be on the chain). */
export function cursorAt(store: KronicleLite, seq: number, actor = SHIM_ACTOR): string {
  const head = store.chain.head();
  if (!Number.isInteger(seq) || seq < 0 || seq > head.seq) throw new Error(`seq ${seq} is not on the chain (head ${head.seq})`);
  const hash = seq === head.seq ? head.hash : store.chain.get(seq)?.this_hash;
  if (!hash) throw new Error(`seq ${seq} is not on the chain`);
  return serializeCursor({ actor_id: actor, chain_seq: seq, chain_hash: hash, issued_at: new Date().toISOString() }, store.identity.cursor_secret);
}

/** Record the current head as the starting point for projects with no cursor of their own (shim install). */
export function writeBaseline(stateDir: string, store: KronicleLite, opts: { generic?: boolean } = {}): number {
  mkdirSync(join(stateDir, 'baselines'), { recursive: true, mode: 0o700 });
  const head = store.chain.head();
  const c = cursorAt(store, head.seq);
  if (opts.generic !== false) writeAtomic(baselineFile(stateDir), c);
  writeAtomic(storeBaselineFile(stateDir, store), c);
  return head.seq;
}

/** Write a store's own baseline unless it has one (re-install never moves a starting point). */
export function ensureStoreBaseline(stateDir: string, store: KronicleLite): void {
  if (readText(storeBaselineFile(stateDir, store)) === null) writeBaseline(stateDir, store, { generic: false });
}

// ---------------------------------------------------------------- rendering

function clip(s: string | null | undefined, n: number): string {
  const t = (s ?? '').replace(/\s+/g, ' ');
  return t.length > n ? t.slice(0, n - 1) + '…' : t;
}

/** One line per retraction, the same shape cc-anchor's push and pulse print (scripts/retractions.jq). */
export function retractionLine(r: Retraction): string {
  const where = [r.doc_slug ?? '', (r.heading_path ?? []).join(' › ')].filter((x) => x !== '').join(' › ');
  const body =
    r.old_text !== null
      ? `relied on "${clip(r.old_text, 140)}" → ${r.new_text === null ? 'now REMOVED' : `now "${clip(r.new_text, 140)}"`}${r.diff !== null ? `; diff: ${clip(r.diff, 240)}` : ''}`
      : clip(r.reason_line || r.event_type, 300);
  return `- ${where ? where + ' ' : ''}(seq ${r.seq}, ${r.kind}/${r.severity}): ${body}`;
}

function retractionLines(rs: (Retraction | BlockingRetraction)[]): string {
  const lines = rs.slice(0, 6).map((r) => {
    const line = retractionLine(r);
    if (!('unread_by' in r)) return line;
    return r.unread_by.length > 0 ? `${line} [not yet re-read at the current version by: ${r.unread_by.join(', ')}]` : `${line} [no reader recorded: re-read it, or acknowledge]`;
  });
  if (rs.length > 6) lines.push(`- … and ${rs.length - 6} more (kronicle-lite orient --focus retractions lists them all)`);
  return lines.join('\n');
}

/** argv → one display line (quoted where needed, ≤ 120 chars). */
export function displayCommand(argv: readonly string[] | undefined): string {
  if (!argv || argv.length === 0) return 'this command';
  const q = argv.map((a) => (/^[A-Za-z0-9_@%+=:,./-]+$/.test(a) ? a : `'${a.replace(/'/g, `'\\''`)}'`)).join(' ');
  return q.length > 120 ? q.slice(0, 119) + '…' : q;
}

export function integrityText(i: IntegritySummary): string {
  return `kronicle-lite STORE INTEGRITY FAILURE${i.seq != null ? ` at seq ${i.seq}` : ''}: ${i.problem ?? 'integrity check failed'}. The store was edited outside kronicle-lite: do not act on runbooks, notes or anything else recalled from it until it is resolved (kronicle-lite verify-chain / doctor; tell the operator). World-changing commands are refused until the store verifies again.`;
}

// ---------------------------------------------------------------- the check

const isBlocking = (r: Retraction) => !r.format_only && (r.severity === 'safety' || r.severity === 'behavioral');

/**
 * Version-bound reconciliation of one blocking retraction: resolved when
 * every pending actor has read the current version of the changed block
 * (for `derived`: of the note's source). See the header.
 */
export function reconcile(store: KronicleLite, r: Retraction, configured: readonly string[] | null, self: string): BlockingRetraction {
  const lineageBlock = r.kind === 'derived' ? (r.derived_from_change?.source_block_id ?? null) : r.block_id;
  let actors: string[];
  if (configured !== null) actors = [...configured];
  else if (lineageBlock === null) actors = [];
  else {
    const note = r.kind === 'derived' && r.doc_slug ? (store.docs.getDocument(r.doc_slug)?.doc_id ?? null) : null;
    actors = store.lineage.readersOf(store.lineage.lineageIds(lineageBlock), note).filter((a) => a !== SHIM_ACTOR && a !== self);
  }
  const unread = lineageBlock === null ? actors : actors.filter((a) => !store.lineage.readCurrent(a, lineageBlock));
  return { ...r, pending_actors: actors, unread_by: unread };
}

/**
 * Actor mode (0.8.1): does this change block `invoker`? It does when the
 * invoker read some version of the block (or, for `derived`, read or wrote the
 * note), when it is an instruction-file change (instructions reach the agent
 * without a kronicle read), or when nobody's read is recorded. Then only the
 * invoker's read of the current version resolves it. A change only OTHER
 * actors read does not block the invoker (`relied: false`).
 */
export function reconcileActor(store: KronicleLite, r: Retraction, invoker: string): BlockingRetraction & { relied: boolean } {
  const lineageBlock = r.kind === 'derived' ? (r.derived_from_change?.source_block_id ?? null) : r.block_id;
  if (lineageBlock === null) return { ...r, pending_actors: [invoker], unread_by: [invoker], relied: true };
  const note = r.kind === 'derived' && r.doc_slug ? (store.docs.getDocument(r.doc_slug)?.doc_id ?? null) : null;
  const readers = store.lineage.readersOf(store.lineage.lineageIds(lineageBlock), note).filter((a) => a !== SHIM_ACTOR);
  const relied = r.kind === 'instruction' || readers.length === 0 || readers.includes(invoker);
  if (!relied) return { ...r, pending_actors: [], unread_by: [], relied: false };
  return { ...r, pending_actors: [invoker], unread_by: store.lineage.readCurrent(invoker, lineageBlock) ? [] : [invoker], relied: true };
}

const isResolved = (b: BlockingRetraction) => b.pending_actors.length > 0 && b.unread_by.length === 0;

/** The last lines of a refusal: exactly who still has to re-read, and what to do otherwise (never `ack`). */
function whoMustReRead(blocking: BlockingRetraction[], mode: PendingMode, invoker: string | null): string {
  const unread = [...new Set(blocking.flatMap((b) => b.unread_by))];
  const noReader = blocking.filter((b) => b.unread_by.length === 0).length;
  const lines: string[] = [];
  if (unread.length > 0) {
    const why =
      mode === 'actor'
        ? ` (the invoking actor, ${invoker})`
        : mode === 'configured'
          ? ' (the configured pending actor(s))'
          : invoker === null
            ? ' (every reader of the changed text is checked: no invoking actor is set for this command)'
            : ' (every reader of the changed text is checked: --all-readers)';
    lines.push(`Still to re-read the current version: ${unread.join(', ')}${why}.`);
  }
  if (noReader > 0) lines.push(`${noReader} change(s) have no recorded reader: reading the current version clears them (a document-level change with no block to read needs the operator).`);
  lines.push('If you cannot re-read them yourself, stop and ask the operator.');
  return lines.join('\n');
}

/**
 * Run the pulse against an open store. Pure apart from the state files (when
 * `stateDir` is set) and orient's flight-recorder row.
 */
export function pulse(store: KronicleLite, opts: PulseOptions): PulseResult {
  const mode: PulseMode = opts.mode ?? 'deny';
  const actor = opts.actor ?? SHIM_ACTOR;
  const cmd = displayCommand(opts.command);
  const pm = pendingModeFor(opts);
  const configured = pm.configured;
  const invoker = pm.mode === 'actor' ? pm.invoker : null;
  const tgt = targetFor(opts);
  const target: PulseTarget = { dir: tgt.dir, explicit: tgt.explicit, via: tgt.via };
  const extra = { pending_mode: pm.mode, invoking_actor: pm.invoker, target };

  if (tgt.error !== null && !opts.allProjects) {
    // H2-14: the command names a directory we cannot resolve. Checking the
    // working directory's project instead could miss the real one: refuse.
    const head = store.chain.head();
    return {
      format: 'kronicle-lite/1',
      mode,
      head: { seq: head.seq, hash: head.hash },
      from_seq: head.seq,
      recovery: 'none',
      project_keys: null,
      hidden_retractions: 0,
      pending_actors: configured,
      ...extra,
      decision: 'deny',
      reason: 'target',
      cursor: opts.cursor ?? '',
      blocking: [],
      resolved: [],
      not_relied_on: [],
      informational: [],
      integrity: null,
      message: `kronicle-lite shim: did NOT run \`${cmd}\` — cannot tell which project it acts on (${tgt.error}), so it could not be checked. Fix the ${tgt.via ?? 'directory'} argument and run it again.`,
      ack_through: null,
    };
  }
  const scope = opts.allProjects ? null : shimScope(tgt);
  const projectKey = scope?.keys[0] ?? '_all';

  let cursor: string | null = opts.cursor ?? null;
  if (opts.stateDir !== undefined) cursor = invoker !== null ? readActorCursor(store, opts.stateDir, projectKey, invoker).cursor : readProjectCursor(opts.stateDir, projectKey, store).cursor;
  const save = (c: string) => {
    if (opts.stateDir === undefined || opts.persist === false) return;
    if (invoker !== null) {
      mkdirSync(join(opts.stateDir, 'cursors'), { recursive: true, mode: 0o700 });
      writeAtomic(actorCursorFile(opts.stateDir, projectKey, invoker), c);
    } else writeProjectCursor(opts.stateDir, projectKey, c);
  };

  const base = (st: SystemState) => ({
    format: 'kronicle-lite/1' as const,
    mode,
    head: { seq: st.head.seq, hash: st.head.hash },
    from_seq: st.recovery.from_seq,
    recovery: st.recovery.method,
    project_keys: scope?.keys ?? null,
    hidden_retractions: st.scope?.hidden_retractions ?? 0,
    pending_actors: configured,
    ...extra,
  });

  if (cursor === null) {
    // First check: the head is the starting point (that is history, not news).
    const st = store.orient.getSystemState({ actor_id: actor, focus: 'pulse', project: scope });
    if (st.integrity && !st.integrity.ok) return integrityDeny(st, base(st), cursorAt(store, st.head.seq, actor), cmd);
    save(st.cursor);
    return {
      ...base(st),
      decision: 'seed',
      reason: 'seeded',
      cursor: st.cursor,
      blocking: [],
      resolved: [],
      not_relied_on: [],
      informational: [],
      integrity: st.integrity,
      message: null,
      ack_through: null,
    };
  }

  const st = store.orient.getSystemState({ actor_id: actor, since_cursor: cursor, focus: 'retractions', project: scope });
  if (st.integrity && !st.integrity.ok) return integrityDeny(st, base(st), cursor, cmd);
  if (st.recovery.method === 'genesis') {
    // The cursor was unreadable and this actor has no briefing: re-seed rather
    // than replay the whole chain as news (docs/PUSH.md).
    save(st.cursor);
    return {
      ...base(st),
      decision: 'seed',
      reason: 'genesis',
      cursor: st.cursor,
      blocking: [],
      resolved: [],
      not_relied_on: [],
      informational: [],
      integrity: st.integrity,
      message: `kronicle-lite shim: the stored position was unreadable (${st.recovery.cursor_error ?? 'no cursor'}); re-seeded at seq ${st.head.seq}.`,
      ack_through: null,
    };
  }
  const all = st.retractions ?? [];
  let checked: BlockingRetraction[];
  let notRelied: BlockingRetraction[] = [];
  if (invoker !== null) {
    const rs = all.filter(isBlocking).map((r) => reconcileActor(store, r, invoker));
    checked = rs.filter((r) => r.relied).map(({ relied: _r, ...b }) => b);
    notRelied = rs.filter((r) => !r.relied).map(({ relied: _r, ...b }) => b);
  } else checked = all.filter(isBlocking).map((r) => reconcile(store, r, configured, actor));
  const blocking = checked.filter((b) => !isResolved(b));
  const resolved = checked.filter(isResolved);
  const informational = all.filter((r) => !isBlocking(r));

  if (blocking.length === 0) {
    save(st.cursor);
    const notes: string[] = [];
    if (resolved.length > 0) {
      const who = [...new Set(resolved.flatMap((r) => r.pending_actors))].join(', ');
      notes.push(`kronicle-lite: ${resolved.length} change(s) since the last check already re-read at the current version (by ${who}); not blocking \`${cmd}\`.`);
    }
    if (notRelied.length > 0) {
      notes.push(`kronicle-lite: ${notRelied.length} change(s) since the last check to text ${invoker} never read (read by others only); not blocking \`${cmd}\` for ${invoker}:\n${retractionLines(notRelied.map(({ pending_actors: _p, unread_by: _u, ...r }) => r))}`);
    }
    if (informational.length > 0) notes.push(`kronicle-lite: ${informational.length} informational change(s) since the last check (none blocks \`${cmd}\`):\n${retractionLines(informational)}`);
    return {
      ...base(st),
      decision: 'allow',
      reason: 'clear',
      cursor: st.cursor,
      blocking,
      resolved,
      not_relied_on: notRelied,
      informational,
      integrity: st.integrity,
      message: notes.length > 0 ? notes.join('\n') : null,
      ack_through: null,
    };
  }

  const n = blocking.length;
  if (mode === 'warn') {
    save(st.cursor);
    return {
      ...base(st),
      decision: 'warn',
      reason: 'retractions',
      cursor: st.cursor,
      blocking,
      resolved,
      not_relied_on: notRelied,
      informational,
      integrity: st.integrity,
      message: `kronicle-lite shim (warn): \`${cmd}\` is running, but kronicle-lite has ${n} change(s) you have not reconciled (head seq ${st.head.seq}):\n${retractionLines(blocking)}\nCheck that this command used the current values.`,
      ack_through: null,
    };
  }
  const through = st.head.seq;
  // H2-12: no override hint here. The agent clears the gate by re-reading;
  // acknowledging without a read is an operator action (shim ack, docs/PUSH.md).
  const next = opts.stateDir !== undefined ? 'Then run the command again.' : 'Then check again (the same cursor is fine).';
  return {
    ...base(st),
    decision: 'deny',
    reason: 'retractions',
    cursor,
    blocking,
    resolved,
    not_relied_on: notRelied,
    informational,
    integrity: st.integrity,
    message:
      `kronicle-lite shim: did NOT run \`${cmd}\` — kronicle-lite has ${n} change(s) you have not reconciled (head seq ${through}):\n` +
      `${retractionLines(blocking)}\n` +
      `Re-read the pending item(s) above (recall them again, or read kronicle://docs/<slug>; the briefing alone does not count) and check the values this command uses: ` +
      `reading the current version clears the gate by itself. ${next}\n` +
      whoMustReRead(blocking, pm.mode, pm.invoker),
    ack_through: through,
  };
}

function integrityDeny(st: SystemState, b: Omit<PulseResult, 'decision' | 'reason' | 'cursor' | 'blocking' | 'resolved' | 'not_relied_on' | 'informational' | 'integrity' | 'message' | 'ack_through'>, cursor: string, cmd: string): PulseResult {
  return {
    ...b,
    decision: 'deny',
    reason: 'integrity',
    cursor,
    blocking: [],
    resolved: [],
    not_relied_on: [],
    informational: [],
    integrity: st.integrity,
    message: `kronicle-lite shim: did NOT run \`${cmd}\` — ${integrityText(st.integrity!)}`,
    ack_through: null,
  };
}

export function exitCodeFor(r: PulseResult): number {
  return r.decision === 'deny' ? PULSE_DENY_EXIT : 0;
}

export interface AckResult {
  project_key: string;
  from_seq: number;
  through: number;
  acknowledged: Retraction[];
  cursor: string;
}

/**
 * `kronicle-lite shim ack [--through SEQ]`: move this project's shim cursor to
 * SEQ (default: the head), clearing the gate for the retractions up to it. A
 * retraction after SEQ still blocks: acknowledging seq 42 never clears 43.
 * An operator action (0.8.1): the CLI requires a TTY or `--operator` and logs
 * every ack (install.ts ackShim); this function does neither.
 */
export function ack(store: KronicleLite, opts: { stateDir: string; cwd?: string | undefined; through?: number | undefined; allProjects?: boolean | undefined }): AckResult {
  // The project cursor: every actor's effective position is at least this (readActorCursor).
  const scope = opts.allProjects ? null : shimScope(commandTarget(undefined, opts.cwd ?? process.cwd()));
  const projectKey = scope?.keys[0] ?? '_all';
  const head = store.chain.head();
  const through = opts.through ?? head.seq;
  if (through > head.seq) throw new Error(`--through ${through} is beyond the chain head (seq ${head.seq})`);
  const { cursor } = readProjectCursor(opts.stateDir, projectKey, store);
  let from = 0;
  let acknowledged: Retraction[] = [];
  if (cursor !== null) {
    const st = store.orient.getSystemState({ actor_id: SHIM_ACTOR, since_cursor: cursor, focus: 'retractions', project: scope });
    from = st.recovery.from_seq;
    if (through < from) throw new Error(`--through ${through} is before this project's shim position (seq ${from}): nothing to acknowledge`);
    acknowledged = (st.retractions ?? []).filter((r) => isBlocking(r) && r.seq <= through);
  }
  const c = cursorAt(store, through);
  writeProjectCursor(opts.stateDir, projectKey, c);
  return { project_key: projectKey, from_seq: from, through, acknowledged, cursor: c };
}
