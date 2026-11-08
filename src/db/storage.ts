/**
 * 0.8.1: storage-level failures and the writer marker.
 *
 * - `StoreUnreadableError`: the store file is there but cannot be read by any
 *   means (normal open, read-only open, a private snapshot). The pulse treats
 *   it like a corrupt store: an integrity-class failure (refuse in deny mode),
 *   never "unavailable" (fail open).
 * - `isStorageWriteError`: the database refused a write because the medium is
 *   read-only or full. Bookkeeping writes on read paths (flight recorder, read
 *   log) are best-effort and skip on these; real writes still fail loudly.
 * - The writer marker (`meta.writer_version`, `meta.writer_head_seq`) is
 *   updated by every append of this version, so a later reader can tell that
 *   an older kronicle-lite (which records nothing) appended events since.
 */

export const STORE_UNREADABLE_CODE = 'KL_STORE_UNREADABLE';

export class StoreUnreadableError extends Error {
  override readonly name = 'StoreUnreadableError';
  readonly code = STORE_UNREADABLE_CODE;
}

/** Does this error (or its cause) say the store exists but could not be read at all? */
export function isStoreUnreadable(err: unknown): boolean {
  for (let e: unknown = err, i = 0; e && i < 5; i++) {
    if (e instanceof StoreUnreadableError) return true;
    if ((e as { code?: unknown }).code === STORE_UNREADABLE_CODE) return true;
    e = (e as { cause?: unknown }).cause;
  }
  return false;
}

const WRITE_CODES = /^(SQLITE_(READONLY|FULL|CANTOPEN|IOERR|PERM)|EROFS|ENOSPC|EACCES|EPERM|EDQUOT)/;

/** The medium refused a write (read-only, full, permission). */
export function isStorageWriteError(err: unknown): boolean {
  const code = (err as { code?: unknown })?.code;
  if (typeof code === 'string' && WRITE_CODES.test(code)) return true;
  return err instanceof Error && /readonly database|read-only file system|database or disk is full|disk I\/O error|no space left/i.test(err.message);
}

/** Run a best-effort bookkeeping write; skipped when the medium refuses writes. */
export function bestEffortWrite(fn: () => void): void {
  try {
    fn();
  } catch (err) {
    if (!isStorageWriteError(err)) throw err;
  }
}

/**
 * 0.8.1 (C2-08): a bookkeeping write on a read path (the orient flight
 * recorder) waits at most `busyMs` for another process's write lock, then is
 * skipped, so a long writer never stalls a read-only check.
 */
export function boundedBookkeepingWrite(db: { pragma(sql: string, o?: { simple: boolean }): unknown; inTransaction: boolean }, busyMs: number, fn: () => void): void {
  const prev = Number(db.pragma('busy_timeout', { simple: true }));
  const lower = !db.inTransaction && prev > busyMs;
  if (lower) db.pragma(`busy_timeout = ${busyMs}`);
  try {
    fn();
  } catch (err) {
    const code = (err as { code?: unknown })?.code;
    if (!isStorageWriteError(err) && !(typeof code === 'string' && /^SQLITE_(BUSY|LOCKED)/.test(code))) throw err;
  } finally {
    if (lower) db.pragma(`busy_timeout = ${prev}`);
  }
}

/**
 * Writer generation (C2-01). The store records the highest generation that
 * opened it for writing (`meta.min_writer_generation`); a version whose own
 * generation is lower refuses to write. 0.8.0 and older know nothing of it,
 * so this only protects against versions from 0.8.1 on; bump it when a store
 * change must not be written by an older writer.
 */
export const WRITER_GENERATION = 1;

/** Record that this version appended up to `seq` (inside the append's transaction). */
export function markWriter(db: { prepare(sql: string): { run(...a: unknown[]): unknown } }, seq: number, version: string): void {
  db.prepare(`INSERT INTO meta (key, value) VALUES ('writer_head_seq', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(String(seq));
  db.prepare(`INSERT INTO meta (key, value) VALUES ('writer_version', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(version);
}

/**
 * 0.9.0: the state of 0.8.1's `doc_lineage_gaps` table. A store made by 0.8.0
 * and opened read-only (verify-chain, doctor, a read-only medium) is never
 * migrated: the table does not exist yet and nothing has been derived into it
 * (`not_derived`), which is not a divergence. A store that ran the migration
 * (`meta` key `migration.lineage_gaps`) but has lost the table is (`missing`).
 */
export function lineageGapsState(db: { prepare(sql: string): { get(...a: unknown[]): unknown } }): 'present' | 'not_derived' | 'missing' {
  // A TEMP table (shimMissingTables: an older store opened without migrating) holds the derived rows too.
  if (db.prepare(`SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'doc_lineage_gaps' UNION ALL SELECT 1 FROM sqlite_temp_master WHERE type = 'table' AND name = 'doc_lineage_gaps'`).get() !== undefined) return 'present';
  return db.prepare(`SELECT 1 FROM meta WHERE key = 'migration.lineage_gaps'`).get() !== undefined ? 'missing' : 'not_derived';
}
