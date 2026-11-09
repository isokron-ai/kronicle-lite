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
import { existsSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
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
 * Read and validate the whole cache file. Absent → an empty file. Present
 * but unparseable or of the wrong shape → KeyListRollbackError (fail closed).
 * `legacyOwner` is the record key a round-4 file without kept_for is attributed to.
 */
export function loadKeysCacheFile(scope: KeysCacheScope, legacyOwner: { anchor_url: string; genesis: string } | null = null): KeysCacheFile {
  if (!scope.dataDir) return memory.get(scope) ?? { v: 2, records: {} };
  const p = join(scope.dataDir, KEYS_CACHE_FILE);
  if (!existsSync(p)) return { v: 2, records: {} };
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
    if (!prev || keyListRegression(prev.keys.keys, keys.keys) === null) records[c.key] = { anchor_url: c.anchor_url, genesis: c.genesis, keys };
    else if (keyListRegression(keys.keys, prev.keys.keys) !== null) throw bad(`holds two records for ${c.key.slice(0, 120)} that contradict each other`);
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
    return { v: 2, records };
  }
  // round-4 single document (the service client's older format)
  if (!validKeysDoc(raw)) throw bad('has the wrong shape');
  const kf = (raw as unknown as Record<string, unknown>)['kept_for'];
  if (kf !== undefined && !(isObj(kf) && typeof kf['anchor_url'] === 'string' && typeof kf['genesis'] === 'string')) throw bad('has the wrong shape (kept_for)');
  const { kept_for: _k, ...doc } = raw as ServiceKeys & { kept_for?: unknown };
  void _k;
  const owner = kf ? { anchor_url: kf['anchor_url'] as string, genesis: kf['genesis'] as string } : legacyOwner;
  if (!owner) return { v: 2, records: {} };
  const c = canon(owner.anchor_url, owner.genesis);
  if (!c) throw bad('has the wrong shape (kept_for: URL or genesis pin)');
  add(c, doc as ServiceKeys);
  return { v: 2, records };
}

/** Write the cache atomically: a 0600 temporary file in the same directory, then rename over the old one. */
export function writeKeysCacheFile(scope: KeysCacheScope, file: KeysCacheFile): void {
  if (!scope.dataDir) {
    memory.set(scope, JSON.parse(JSON.stringify(file)) as KeysCacheFile);
    return;
  }
  const p = join(scope.dataDir, KEYS_CACHE_FILE);
  const tmp = join(scope.dataDir, `.${KEYS_CACHE_FILE}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`);
  try {
    writeFileSync(tmp, JSON.stringify(file, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
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

/** The kept list for this service and pin, for offline checks; null when there is none. Throws KeyListRollbackError on a damaged file. */
export function readKeysCache(scope: KeysCacheScope, anchorUrl: string, genesis: GenesisPin): ServiceKeys | null {
  const key = keysCacheRecordKey(anchorUrl, genesis);
  const legacy = { anchor_url: anchorUrl, genesis: formatGenesisPin(genesis) };
  return loadKeysCacheFile(scope, legacy).records[key]?.keys ?? null;
}

/**
 * Rollback protection: `fresh` (a list just fetched from `anchorUrl`) is
 * compared with the record kept for (normalized `anchorUrl`, genesis pin).
 * Throws KeyListRollbackError when it drops or changes a kept key other than
 * by an allowed status progression, before anything is verified with it. A
 * list that passes and chains to the pin replaces that record only.
 */
export function guardKeyList(scope: KeysCacheScope, anchorUrl: string, fresh: unknown, genesis: GenesisPin): void {
  const where = scope.dataDir ? join(scope.dataDir, KEYS_CACHE_FILE) : 'memory';
  const key = keysCacheRecordKey(anchorUrl, genesis);
  const owner = { anchor_url: normalizeAnchorUrl(anchorUrl), genesis: formatGenesisPin(genesis) };
  const file = loadKeysCacheFile(scope, owner);
  const kept = file.records[key];
  if (kept) {
    if (!validKeysDoc(fresh)) throw new KeyListRollbackError(`service key list refused: ${anchorUrl} served a key list of the wrong shape`);
    const why = keyListRegression(kept.keys.keys, fresh.keys);
    if (why) {
      throw new KeyListRollbackError(
        `service key list refused: ${why}. The list kept in ${where} for ${owner.anchor_url} is longer or stronger than the one it serves now, which can mean the service rolled its key list back. Nothing was verified with it; delete that file only if you have confirmed the change with the operator`,
      );
    }
  }
  if (!validKeysDoc(fresh) || !checkKeyChain(fresh.keys, genesis).usable) return; // keep the last good list; verification reports the break
  try {
    writeKeysCacheFile(scope, { v: 2, records: { ...file.records, [key]: { ...owner, keys: fresh } } });
  } catch {
    // best effort: an unwritable data dir must not block verification
  }
}
