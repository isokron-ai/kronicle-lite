/**
 * The service key lists last trusted, one record per (normalized service URL,
 * genesis pin), and the rollback check against them. A port of isokron-anchor
 * main 8521a16 `client/src/anchor.ts` (normalizeAnchorUrl, keysCacheRecordKey,
 * loadKeysCacheFile, writeKeysCacheFile, readKeysCache, keysCacheGuard): the
 * same file name and format, so kronicle-lite and the service's own client
 * keep one record per service and pin in a shared data dir.
 *
 *   <data-dir>/anchor-keys.cache.json   mode 0600
 *   { "v": 2, "records": { "<url>|<sha256>@<valid_from>": { "anchor_url", "genesis", "keys": ServiceKeys } } }
 *
 * A list that drops or changes a kept key other than by the allowed status
 * progression (keyListRegression) is refused before anything is verified with
 * it (KeyListRollbackError). A damaged file refuses too; it is reset only by
 * deleting it. An in-memory store (no data dir) keeps its records in memory.
 */

import { randomBytes } from 'node:crypto';
import { closeSync, existsSync, openSync, readFileSync, renameSync, rmSync, statSync, unlinkSync, writeFileSync, writeSync } from 'node:fs';
import { join } from 'node:path';

import { KEYS_CACHE_FILE } from './config.js';
import { checkKeyChain, formatGenesisPin, keyListRegression, parseGenesisPin, type GenesisPin, type ServiceKeyEntry } from './keychain.js';

export { KEYS_CACHE_FILE };

export interface ServiceKeys {
  v?: number;
  issuer?: string;
  keys: ServiceKeyEntry[];
}

/** A fetched key list is shorter or weaker than the kept one, or the kept file is unusable. */
export class KeyListRollbackError extends Error {
  override name = 'KeyListRollbackError';
}

/**
 * The form a service URL is recorded under: scheme and host lowercased and
 * the default port dropped (both by WHATWG URL), one trailing dot of the host
 * dropped, percent-encoded unreserved characters in the path decoded (other
 * escapes upper-cased), trailing slashes dropped, no query or fragment.
 * A URL with user info or that does not parse is refused.
 */
export function normalizeAnchorUrl(u: string): string {
  let x: URL;
  try {
    x = new URL(u.trim());
  } catch {
    throw new Error(`anchor URL ${JSON.stringify(u)} is not a valid URL`);
  }
  if (x.username || x.password) throw new Error('anchor URL must not contain user info (user:password@)');
  const host = x.hostname.replace(/\.$/, '') + (x.port ? `:${x.port}` : '');
  const path = x.pathname
    .replace(/%([0-9A-Fa-f]{2})/g, (_m, h: string) => {
      const c = String.fromCharCode(parseInt(h, 16));
      return /[A-Za-z0-9\-._~]/.test(c) ? c : `%${h.toUpperCase()}`;
    })
    .replace(/\/+$/, '');
  return `${x.protocol}//${host}${path}`;
}

export interface KeysCacheRecord {
  anchor_url: string;
  genesis: string;
  keys: ServiceKeys;
}

export interface KeysCacheFile {
  v: 2;
  records: Record<string, KeysCacheRecord>;
}

/** `<normalized url>|<canonical sha256>@<canonical valid_from>`: every spelling of one service and pin gives one key. */
export function keysCacheRecordKey(anchorUrl: string, genesis: GenesisPin): string {
  return `${normalizeAnchorUrl(anchorUrl)}|${formatGenesisPin(genesis)}`;
}

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const optStr = (v: unknown) => v === undefined || v === null || typeof v === 'string';

/** Shape of one kept key list: an object with a `keys` array of entries with string key_id/public_key_pem and string-or-null optional fields. */
export function validKeysDoc(d: unknown): d is ServiceKeys {
  if (!isObj(d) || !Array.isArray(d['keys'])) return false;
  return d['keys'].every(
    (k) =>
      isObj(k) &&
      typeof k['key_id'] === 'string' &&
      typeof k['public_key_pem'] === 'string' &&
      ['status', 'valid_from', 'valid_to', 'successor_signature', 'signed_by', 'retirement_signature', 'retirement_signed_by', 'compromised_since', 'alg'].every((f) => optStr(k[f])),
  );
}

/** Where a scope keeps its records: the data dir, or memory for an in-memory store. */
export interface KeysCacheScope {
  readonly dataDir: string | null;
}
const memory = new WeakMap<KeysCacheScope, KeysCacheFile>();

/**
 * A pre-v2 single-document file: kronicle-lite 0.4–0.8 wrote the last key document it fetched
 * (unchecked), and the service's round-4 client wrote its kept list, optionally with kept_for. It is
 * never trusted as it stands (C2a): the fetch path adopts it only when it chains to the current pin
 * and its recorded anchor_url (if any) is the service's; offline checks and doctor never use it (C2b).
 */
export interface LegacyKeysDoc {
  keys: ServiceKeys;
  kept_for: { anchor_url: string; genesis: string } | null;
}

export interface LoadedKeysCache {
  file: KeysCacheFile;
  legacy: LegacyKeysDoc | null;
}

/**
 * The stronger of two kept lists for one record, or a refusal: `b` when it keeps every key of `a`
 * with an allowed status progression (a longer list wins; revoked beats retired; an earlier
 * valid_to or compromised_since wins), `a` when `a` is at least as strong as `b`; two lists that
 * each drop or weaken something of the other contradict each other (null).
 */
export function strongerKeyList(a: ServiceKeys, b: ServiceKeys): ServiceKeys | null {
  if (keyListRegression(a.keys, b.keys) === null) return b;
  if (keyListRegression(b.keys, a.keys) === null) return a;
  return null;
}

/**
 * Read and validate the whole cache file. Absent → an empty file. Present but unparseable or of the
 * wrong shape → KeyListRollbackError (fail closed). A pre-v2 single document comes back as `legacy`,
 * never as a record.
 */
export function loadKeysCache(scope: KeysCacheScope): LoadedKeysCache {
  if (!scope.dataDir) return { file: memory.get(scope) ?? { v: 2, records: {} }, legacy: null };
  const p = join(scope.dataDir, KEYS_CACHE_FILE);
  if (!existsSync(p)) return { file: { v: 2, records: {} }, legacy: null };
  const bad = (why: string) => new KeyListRollbackError(`${p} ${why}, so the service key list cannot be checked for rollback; delete it only if you trust the list the service serves now`);
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(p, 'utf8'));
  } catch {
    throw bad('is unreadable');
  }
  // Records are re-keyed by the canonical URL and pin, whatever spelling wrote them.
  const canon = (anchorUrl: string, genesis: string): { key: string; anchor_url: string; genesis: string } | null => {
    const g = parseGenesisPin(genesis);
    if (!g) return null;
    let url: string;
    try {
      url = normalizeAnchorUrl(anchorUrl);
    } catch {
      return null;
    }
    const label = formatGenesisPin(g);
    return { key: `${url}|${label}`, anchor_url: url, genesis: label };
  };
  const records: Record<string, KeysCacheRecord> = {};
  const add = (c: { key: string; anchor_url: string; genesis: string }, keys: ServiceKeys) => {
    const prev = records[c.key];
    const merged = prev ? strongerKeyList(prev.keys, keys) : keys;
    if (!merged) throw bad(`holds two records for ${c.key.slice(0, 120)} that contradict each other`);
    records[c.key] = { anchor_url: c.anchor_url, genesis: c.genesis, keys: merged };
  };
  if (isObj(raw) && raw['v'] === 2) {
    if (!isObj(raw['records'])) throw bad('has the wrong shape (records)');
    for (const [k, r] of Object.entries(raw['records'])) {
      if (!isObj(r) || typeof r['anchor_url'] !== 'string' || typeof r['genesis'] !== 'string' || !validKeysDoc(r['keys'])) throw bad(`has the wrong shape (record ${k.slice(0, 80)})`);
      const c = canon(r['anchor_url'], r['genesis']);
      if (!c) throw bad(`has the wrong shape (record ${k.slice(0, 80)}: URL or genesis pin)`);
      if (k !== `${r['anchor_url']}|${r['genesis']}` && k !== c.key) throw bad(`has the wrong shape (record key ${k.slice(0, 80)})`);
      add(c, r['keys']);
    }
    return { file: { v: 2, records }, legacy: null };
  }
  // A pre-v2 single document: returned as legacy, never adopted here.
  if (!validKeysDoc(raw)) throw bad('has the wrong shape');
  const kf = (raw as unknown as Record<string, unknown>)['kept_for'];
  const keptFor = isObj(kf) && typeof kf['anchor_url'] === 'string' && typeof kf['genesis'] === 'string' ? { anchor_url: kf['anchor_url'], genesis: kf['genesis'] } : null;
  const { kept_for: _k, ...doc } = raw as ServiceKeys & { kept_for?: unknown };
  void _k;
  return { file: { v: 2, records: {} }, legacy: { keys: doc as ServiceKeys, kept_for: keptFor } };
}

/** loadKeysCache's v2 records (a legacy single document reads as no records). */
export function loadKeysCacheFile(scope: KeysCacheScope): KeysCacheFile {
  return loadKeysCache(scope).file;
}

// ── the lock around the read-modify-write (C3c) ──

/**
 * Exclusive lock for writing anchor-keys.cache.json, shared with isokron-anchor's client (both
 * write the file, so both follow exactly one protocol: isokron-anchor fix/cache-lock e894d67,
 * README "Safe writes", whose text is authoritative):
 *   - lock file `anchor-keys.cache.json.lock` in the data directory, created with O_CREAT|O_EXCL
 *     (flag 'wx'), mode 0600, holding {"pid": <holder pid>, "created_at": "<ISO 8601>"};
 *   - a lock is stale only when its pid is not a running process on this host, or when it is older
 *     than KEYS_CACHE_LOCK_STALE_MS (10 min; by created_at, or by mtime when the content does not
 *     parse or created_at lies more than 1 min ahead). A waiter deletes a stale lock (only the
 *     content it judged);
 *   - every path (taken, stale, held) retries every 25 ms and gives up at the deadline (10 s) with
 *     KeyListRollbackError;
 *   - a lock that cannot be created, or a stale one that cannot be deleted, with EACCES, EROFS or
 *     EPERM means a read-only data dir: the list is checked but the cache is not written;
 *   - the holder writes a 0600 temporary file; just before the rename it re-reads the lock (still
 *     its own body, else "cache lock lost" and nothing is written), re-reads the cache and merges
 *     every record (strongest wins, contradiction refuses) and re-checks its own record; then it
 *     renames and deletes the lock only if it still holds its body (guardUnlocked).
 */
export const KEYS_CACHE_LOCK = `${KEYS_CACHE_FILE}.lock`;
export const KEYS_CACHE_LOCK_STALE_MS = 10 * 60_000;
export const KEYS_CACHE_LOCK_TIMEOUT_MS = 10_000;
export const KEYS_CACHE_LOCK_RETRY_MS = 25;
/** How far ahead a lock's created_at may lie (clock skew); a later one is ignored and the mtime counts. */
export const KEYS_CACHE_LOCK_FUTURE_MS = 60_000;

const sleepSync = (ms: number) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
const READ_ONLY = new Set(['EACCES', 'EROFS', 'EPERM']);

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code !== 'ESRCH';
  }
}

/** The lock's content when it is stale, else null (also when it vanished meanwhile). */
function staleLockContent(p: string, staleMs: number, now: number): string | null {
  let text: string;
  let mtime: number;
  try {
    text = readFileSync(p, 'utf8');
    mtime = statSync(p).mtimeMs;
  } catch {
    return null;
  }
  let info: { pid?: unknown; created_at?: unknown } | null = null;
  try {
    info = JSON.parse(text) as { pid?: unknown; created_at?: unknown };
  } catch {
    info = null;
  }
  const pid = info?.pid;
  if (typeof pid === 'number' && Number.isInteger(pid) && pid > 0 && !pidAlive(pid)) return text;
  const created = info && typeof info.created_at === 'string' ? Date.parse(info.created_at) : Number.NaN;
  // A created_at more than KEYS_CACHE_LOCK_FUTURE_MS ahead is not believed: the mtime counts.
  const basis = Number.isFinite(created) && created <= now + KEYS_CACHE_LOCK_FUTURE_MS ? created : mtime;
  return now - basis > staleMs ? text : null;
}

export interface KeysCacheLock {
  /** false: the data dir is read-only (the lock could not be created, or a stale one deleted); do not write. */
  locked: boolean;
  /** The lock file still holds this holder's content. */
  held(): boolean;
  release(): void;
}

/** Take the cache lock (see above). */
export function acquireKeysCacheLock(dataDir: string, opts: { timeoutMs?: number; staleMs?: number } = {}): KeysCacheLock {
  const p = join(dataDir, KEYS_CACHE_LOCK);
  const timeoutMs = opts.timeoutMs ?? KEYS_CACHE_LOCK_TIMEOUT_MS;
  const staleMs = opts.staleMs ?? KEYS_CACHE_LOCK_STALE_MS;
  const deadline = Date.now() + timeoutMs;
  const readOnly: KeysCacheLock = { locked: false, held: () => false, release: () => undefined };
  for (;;) {
    const body = JSON.stringify({ pid: process.pid, created_at: new Date().toISOString() });
    try {
      const fd = openSync(p, 'wx', 0o600);
      try {
        writeSync(fd, body);
      } finally {
        closeSync(fd);
      }
      const held = () => {
        try {
          return readFileSync(p, 'utf8') === body;
        } catch {
          return false;
        }
      };
      return {
        locked: true,
        held,
        release: () => {
          try {
            if (held()) unlinkSync(p);
          } catch {
            // already gone
          }
        },
      };
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code ?? '';
      if (code !== 'EEXIST') {
        if (READ_ONLY.has(code)) return readOnly;
        throw e;
      }
    }
    const stale = staleLockContent(p, staleMs, Date.now());
    if (stale !== null) {
      try {
        // delete only the stale lock we judged, not one a peer created meanwhile
        if (readFileSync(p, 'utf8') === stale) unlinkSync(p);
      } catch (e) {
        if (READ_ONLY.has((e as NodeJS.ErrnoException).code ?? '')) return readOnly;
        // gone already
      }
    }
    if (Date.now() >= deadline) {
      let holder = '';
      try {
        holder = readFileSync(p, 'utf8').slice(0, 200);
      } catch {
        holder = '(gone)';
      }
      throw new KeyListRollbackError(`could not lock ${p} within ${timeoutMs} ms (held: ${holder}); another kronicle-lite or anchor client is writing the key list cache. If no such process is running, delete the lock file`);
    }
    sleepSync(KEYS_CACHE_LOCK_RETRY_MS);
  }
}

/** Merge two record sets with the duplicate-merge rule: per record the stronger list wins; a contradiction refuses. */
function mergeRecords(where: string, a: Record<string, KeysCacheRecord>, b: Record<string, KeysCacheRecord>): Record<string, KeysCacheRecord> {
  const out: Record<string, KeysCacheRecord> = { ...a };
  for (const [k, r] of Object.entries(b)) {
    const prev = out[k];
    if (!prev || keyListRegression(prev.keys.keys, r.keys.keys) === null) out[k] = r;
    else if (keyListRegression(r.keys.keys, prev.keys.keys) !== null) {
      throw new KeyListRollbackError(`${where} holds two versions of the record ${k.slice(0, 120)} that contradict each other; refusing to write it`);
    }
  }
  return out;
}

/** Write the cache atomically: a 0600 temporary file in the same directory, then (after `beforeRename`, which may abort) rename over the old one. */
export function writeKeysCacheFile(scope: KeysCacheScope, file: KeysCacheFile, beforeRename?: () => void): void {
  if (!scope.dataDir) {
    beforeRename?.();
    memory.set(scope, JSON.parse(JSON.stringify(file)) as KeysCacheFile);
    return;
  }
  const p = join(scope.dataDir, KEYS_CACHE_FILE);
  const tmp = join(scope.dataDir, `.${KEYS_CACHE_FILE}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`);
  try {
    writeFileSync(tmp, JSON.stringify(file, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    beforeRename?.();
    renameSync(tmp, p);
  } catch (e) {
    try {
      rmSync(tmp, { force: true });
    } catch {
      // ignore
    }
    throw e;
  }
}

/**
 * The kept list for this service and pin, for offline checks and doctor; null when there is none.
 * Only a record a fetch has confirmed (v2): a legacy single document is never used here (C2b).
 * Throws KeyListRollbackError on a damaged file.
 */
export function readKeysCache(scope: KeysCacheScope, anchorUrl: string, genesis: GenesisPin): ServiceKeys | null {
  return loadKeysCache(scope).file.records[keysCacheRecordKey(anchorUrl, genesis)]?.keys ?? null;
}

/**
 * Rollback protection: `fresh` (a list just fetched from `anchorUrl`) is compared with the record
 * kept for (normalized `anchorUrl`, genesis pin). Throws KeyListRollbackError when it drops or
 * changes a kept key other than by an allowed status progression, before anything is verified with
 * it. The read, the comparison and the write happen under the cache lock, on the file as it is then
 * (C3c): a revocation another writer recorded in the meantime is the reference, never overwritten.
 * A list that passes and chains to the pin replaces that record only. Returns notes (a legacy file
 * ignored or adopted).
 */
export function guardKeyList(
  scope: KeysCacheScope,
  anchorUrl: string,
  fresh: unknown,
  genesis: GenesisPin,
  opts: { lockWaitMs?: number; /** Tests: runs between the read and the write (widens the race window C3c is about). */ afterRead?: () => void } = {},
): string[] {
  const memoryLock: KeysCacheLock = { locked: true, held: () => true, release: () => undefined };
  if (!scope.dataDir) return guardUnlocked(scope, anchorUrl, fresh, genesis, memoryLock, opts.afterRead);
  const lock = acquireKeysCacheLock(scope.dataDir, opts.lockWaitMs !== undefined ? { timeoutMs: opts.lockWaitMs } : {});
  try {
    return guardUnlocked(scope, anchorUrl, fresh, genesis, lock, opts.afterRead);
  } finally {
    lock.release();
  }
}

function guardUnlocked(scope: KeysCacheScope, anchorUrl: string, fresh: unknown, genesis: GenesisPin, lock: KeysCacheLock, afterRead?: () => void): string[] {
  const notes: string[] = [];
  const where = scope.dataDir ? join(scope.dataDir, KEYS_CACHE_FILE) : 'memory';
  const key = keysCacheRecordKey(anchorUrl, genesis);
  const owner = { anchor_url: normalizeAnchorUrl(anchorUrl), genesis: formatGenesisPin(genesis) };
  const check = (kept: ServiceKeys | null | undefined) => {
    if (!kept) return;
    if (!validKeysDoc(fresh)) throw new KeyListRollbackError(`service key list refused: ${anchorUrl} served a key list of the wrong shape`);
    const why = keyListRegression(kept.keys, fresh.keys);
    if (why) {
      throw new KeyListRollbackError(
        `service key list refused: ${why}. The list kept in ${where} for ${owner.anchor_url} is longer or stronger than the one it serves now, which can mean the service rolled its key list back. Nothing was verified with it; delete that file only if you have confirmed the change with the operator`,
      );
    }
  };
  const first = loadKeysCache(scope);
  let kept: ServiceKeys | null = first.file.records[key]?.keys ?? null;
  if (first.legacy) {
    // C2a: adopt an old single document only when it is this service's and chains to this pin.
    const legacy = first.legacy;
    let url: string | null = null;
    try {
      url = legacy.kept_for ? normalizeAnchorUrl(legacy.kept_for.anchor_url) : null;
    } catch {
      url = '(unparseable)';
    }
    const chains = checkKeyChain(legacy.keys.keys, genesis).usable;
    if (url !== null && url !== owner.anchor_url) notes.push(`${where}: an old single-document key list kept for ${url} was ignored (not this service); it is replaced by the v2 format`);
    else if (!chains) notes.push(`${where}: an old single-document key list that does not chain to the genesis pin ${owner.genesis} was ignored; it is replaced by the v2 format`);
    else if (!kept) {
      kept = legacy.keys;
      notes.push(`${where}: an old single-document key list for this service and pin is the rollback reference until this fetch confirms it`);
    }
  }
  check(kept);
  if (!lock.locked) {
    notes.push(`${where}: the data dir is not writable (cache lock); the list was checked but not kept`);
    return notes;
  }
  if (!validKeysDoc(fresh) || !checkKeyChain(fresh.keys, genesis).usable) return notes; // keep the last good list; verification reports the break
  afterRead?.();
  // Just before the write: the lock must still be ours, and the file is merged with what is on disk now.
  const lost = () => new KeyListRollbackError(`cache lock lost: ${scope.dataDir ? join(scope.dataDir, KEYS_CACHE_LOCK) : 'memory'} no longer holds this process's lock; the key list cache was not written`);
  if (!lock.held()) throw lost();
  const now = loadKeysCache(scope).file;
  const merged = mergeRecords(where, first.file.records, now.records);
  check(merged[key]?.keys);
  const out: KeysCacheFile = { v: 2, records: { ...merged, [key]: { ...owner, keys: fresh } } };
  try {
    writeKeysCacheFile(scope, out, () => {
      if (!lock.held()) throw lost();
    });
  } catch (e) {
    if (e instanceof KeyListRollbackError) throw e;
    // best effort: an unwritable data dir must not block verification
  }
  return notes;
}
