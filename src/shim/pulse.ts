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
 * the actors that read any version of the affected block (for a `derived`
 * change: also those that read or wrote the note). Nobody to check (no
 * reader recorded, or a document-level event) = not resolved. So an agent
 * that re-reads the runbook through recall clears the gate itself;
 * `kronicle-lite shim ack --through SEQ` stays as the manual override.
 *
 * An integrity failure (the store was edited outside kronicle-lite) denies in
 * every mode: fail closed. A store that cannot be opened at all is
 * "unavailable" (exit 3): the shim fails open and logs once (docs/PUSH.md).
 *
 * State (`--state DIR`, the shim's `.kronicle-shim` dir) holds one cursor per
 * project (cursors/<project key>), seeded from the install-time baseline, so
 * acknowledging in one project never clears another project's gate.
 */

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { serializeCursor } from '../orient/cursor.js';
import type { Retraction } from '../orient/retraction.js';
import type { IntegritySummary, SystemState } from '../orient/orient.js';
import { projectScopeFor } from '../instructions/paths.js';
import { KronicleLite } from '../store.js';

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
}

/** A blocking retraction, with who still has to read the current version. */
export type BlockingRetraction = Retraction & {
  /** Actors checked for this change (configured, or its readers). */
  pending_actors: string[];
  /** Of those, the ones that have not read the current version ([] with no actors: only an ack clears it). */
  unread_by: string[];
};

export interface PulseResult {
  format: 'kronicle-lite/1';
  decision: PulseDecision;
  reason: 'clear' | 'retractions' | 'integrity' | 'seeded' | 'genesis';
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
  integrity: IntegritySummary | null;
  /** What the shim prints on stderr (null: nothing to say). */
  message: string | null;
  /** Denied for retractions: acknowledge through this seq once reconciled. */
  ack_through: number | null;
}

export class PulseUnavailableError extends Error {
  override readonly name = 'PulseUnavailableError';
}

export function storeExists(dataDir: string): boolean {
  return existsSync(join(dataDir, 'kronicle-lite.db'));
}

/** Open the store for a pulse; a missing store is "unavailable", never created. */
export function openForPulse(dataDir: string): KronicleLite {
  if (!storeExists(dataDir)) throw new PulseUnavailableError(`no kronicle-lite store in ${dataDir}`);
  try {
    return new KronicleLite({ dataDir });
  } catch (err) {
    throw new PulseUnavailableError(`cannot open the kronicle-lite store in ${dataDir}: ${err instanceof Error ? err.message : String(err)}`);
  }
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

export function readProjectCursor(stateDir: string, projectKey: string): { cursor: string | null; source: 'project' | 'baseline' | 'none' } {
  const own = readText(cursorFile(stateDir, projectKey));
  if (own) return { cursor: own, source: 'project' };
  const base = readText(baselineFile(stateDir));
  if (base) return { cursor: base, source: 'baseline' };
  return { cursor: null, source: 'none' };
}

export function writeProjectCursor(stateDir: string, projectKey: string, cursor: string): void {
  mkdirSync(join(stateDir, 'cursors'), { recursive: true, mode: 0o700 });
  writeAtomic(cursorFile(stateDir, projectKey), cursor);
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
export function writeBaseline(stateDir: string, store: KronicleLite): number {
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const head = store.chain.head();
  writeAtomic(baselineFile(stateDir), cursorAt(store, head.seq));
  return head.seq;
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

const isResolved = (b: BlockingRetraction) => b.pending_actors.length > 0 && b.unread_by.length === 0;

/**
 * Run the pulse against an open store. Pure apart from the state files (when
 * `stateDir` is set) and orient's flight-recorder row.
 */
export function pulse(store: KronicleLite, opts: PulseOptions): PulseResult {
  const mode: PulseMode = opts.mode ?? 'deny';
  const actor = opts.actor ?? SHIM_ACTOR;
  const scope = opts.allProjects ? null : projectScopeFor(opts.cwd !== undefined ? { cwd: opts.cwd } : {});
  const projectKey = scope?.keys[0] ?? '_all';
  const cmd = displayCommand(opts.command);
  const configured = opts.pendingActors ?? (opts.stateDir !== undefined ? configuredPendingActors(opts.stateDir) : null);

  let cursor: string | null = opts.cursor ?? null;
  if (opts.stateDir !== undefined) cursor = readProjectCursor(opts.stateDir, projectKey).cursor;
  const save = (c: string) => {
    if (opts.stateDir !== undefined && opts.persist !== false) writeProjectCursor(opts.stateDir, projectKey, c);
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
      informational: [],
      integrity: st.integrity,
      message: `kronicle-lite shim: the stored position was unreadable (${st.recovery.cursor_error ?? 'no cursor'}); re-seeded at seq ${st.head.seq}.`,
      ack_through: null,
    };
  }
  const all = st.retractions ?? [];
  const checked = all.filter(isBlocking).map((r) => reconcile(store, r, configured, actor));
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
    if (informational.length > 0) notes.push(`kronicle-lite: ${informational.length} informational change(s) since the last check (none blocks \`${cmd}\`):\n${retractionLines(informational)}`);
    return {
      ...base(st),
      decision: 'allow',
      reason: 'clear',
      cursor: st.cursor,
      blocking,
      resolved,
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
      informational,
      integrity: st.integrity,
      message: `kronicle-lite shim (warn): \`${cmd}\` is running, but kronicle-lite has ${n} change(s) you have not reconciled (head seq ${st.head.seq}):\n${retractionLines(blocking)}\nCheck that this command used the current values.`,
      ack_through: null,
    };
  }
  const through = st.head.seq;
  const ack =
    opts.stateDir !== undefined
      ? `Then run the command again. To override without re-reading: \`kronicle-lite shim ack --through ${through}\` (in this directory).`
      : `Then check again (the same cursor is fine), or carry a cursor at seq ${through} or later to override.`;
  return {
    ...base(st),
    decision: 'deny',
    reason: 'retractions',
    cursor,
    blocking,
    resolved,
    informational,
    integrity: st.integrity,
    message:
      `kronicle-lite shim: did NOT run \`${cmd}\` — kronicle-lite has ${n} change(s) you have not reconciled (head seq ${through}):\n` +
      `${retractionLines(blocking)}\n` +
      `Re-read the affected document(s) (recall them again, or read kronicle://docs/<slug>; the briefing alone does not count) and check the values this command uses: ` +
      `reading the current version clears the gate by itself. ` +
      ack,
    ack_through: through,
  };
}

function integrityDeny(st: SystemState, b: Omit<PulseResult, 'decision' | 'reason' | 'cursor' | 'blocking' | 'resolved' | 'informational' | 'integrity' | 'message' | 'ack_through'>, cursor: string, cmd: string): PulseResult {
  return {
    ...b,
    decision: 'deny',
    reason: 'integrity',
    cursor,
    blocking: [],
    resolved: [],
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
 */
export function ack(store: KronicleLite, opts: { stateDir: string; cwd?: string | undefined; through?: number | undefined; allProjects?: boolean | undefined }): AckResult {
  const scope = opts.allProjects ? null : projectScopeFor(opts.cwd !== undefined ? { cwd: opts.cwd } : {});
  const projectKey = scope?.keys[0] ?? '_all';
  const head = store.chain.head();
  const through = opts.through ?? head.seq;
  if (through > head.seq) throw new Error(`--through ${through} is beyond the chain head (seq ${head.seq})`);
  const { cursor } = readProjectCursor(opts.stateDir, projectKey);
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
