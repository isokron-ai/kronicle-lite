/**
 * 0.8.1 (L2-03): is the store FILE still sane under a long-lived connection?
 *
 * SQLite keeps pages in a per-connection cache and, in WAL mode, trusts it
 * until the WAL index says another connection committed. A page changed on
 * disk by anything else (a zeroed page, a partial restore, a bad copy) is
 * then never read again by an MCP server that has the store open: every
 * orient focus and recall kept answering from the cache, "proceed" included.
 *
 * So each check stats the database file. Unchanged since the last check: the
 * previous verdict stands (cheap). Changed (another process checkpointed,
 * or something wrote the file outside SQLite): drop this connection's page
 * cache and run `PRAGMA quick_check`, which reads every page from disk. The
 * first check of a process only records the file's state: a fresh connection
 * has no cache to mask anything, and a damaged page surfaces as an SQLite
 * error, which orient turns into an integrity failure (never a briefing).
 */

import { statSync } from 'node:fs';

import type { Db } from './open.js';

export class StoreFileHealth {
  private sig: string | null = null;
  private verdict: string | null = null;

  constructor(
    private readonly db: Db,
    /** The database file; null (in-memory store) = never checked. */
    private readonly file: string | null,
  ) {}

  private signature(): string {
    const st = statSync(this.file!);
    return `${st.ino}:${st.size}:${st.mtimeMs}`;
  }

  /** null when the file is sane (or unchanged since a sane check), else the problem in words. */
  check(): string | null {
    if (this.file === null) return null;
    let sig: string;
    try {
      sig = this.signature();
    } catch (err) {
      return `the store file cannot be read (${err instanceof Error ? err.message : String(err)})`;
    }
    if (this.sig === null) {
      this.sig = sig;
      return null;
    }
    if (sig === this.sig) return this.verdict;
    try {
      this.db.pragma('shrink_memory');
      const rows = this.db.pragma('quick_check(3)') as { quick_check: string }[];
      const msgs = rows.map((r) => r.quick_check).filter((m) => m !== 'ok');
      this.verdict = msgs.length === 0 ? null : `the store file is damaged (SQLite quick_check: ${msgs.join('; ')})`;
    } catch (err) {
      const code = (err as { code?: unknown })?.code;
      this.verdict = `the store file is damaged (${typeof code === 'string' ? code + ': ' : ''}${err instanceof Error ? err.message : String(err)})`;
    }
    // A damaged verdict is kept until the file changes again (re-checked then).
    this.sig = sig;
    return this.verdict;
  }
}
