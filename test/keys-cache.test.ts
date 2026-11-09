/**
 * The anchor client's kept key lists (src/anchor/keys-cache.ts): the cache lock and the merge under
 * it (C3c), and old single-document files (C2a, C2b).
 */

import { spawn, spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { chmodSync, existsSync, readdirSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { parseGenesisPin, retirementSigningPayload, type GenesisPin } from '../src/anchor/keychain.js';
import { acquireKeysCacheLock, guardKeyList, KEYS_CACHE_FILE, KEYS_CACHE_LOCK, KeyListRollbackError, readKeysCache, strongerKeyList, type ServiceKeys } from '../src/anchor/keys-cache.js';
import { acceptServiceKeys, serviceKeyIdFromPem } from '../src/anchor/trust.js';
import { tempDir } from './helpers/fs.js';

const URL_ = 'https://anchor.test';
const GF = '2026-01-01T00:00:00.000Z';

function key(): { priv: KeyObject; pem: string; id: string; pin: GenesisPin } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
  const sha = createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
  return { priv: privateKey, pem, id: serviceKeyIdFromPem(pem), pin: parseGenesisPin(`${sha}@${GF}`)! };
}
const active = (k: ReturnType<typeof key>): ServiceKeys => ({ v: 1, keys: [{ key_id: k.id, public_key_pem: k.pem, valid_from: GF, status: 'active' }] });
const revoked = (k: ReturnType<typeof key>, cs = '2026-11-01T00:00:00.000Z', vt = '2026-11-02T00:00:00.000Z'): ServiceKeys => ({
  v: 1,
  keys: [
    {
      key_id: k.id,
      public_key_pem: k.pem,
      valid_from: GF,
      status: 'revoked',
      valid_to: vt,
      compromised_since: cs,
      retirement_signature: sign(null, Buffer.from(retirementSigningPayload({ key_id: k.id, status: 'revoked', valid_to: vt, compromised_since: cs }), 'utf8'), k.priv).toString('base64'),
      retirement_signed_by: k.id,
    },
  ],
});
const keptStatus = (dataDir: string, k: ReturnType<typeof key>) => readKeysCache({ dataDir }, URL_, k.pin)?.keys[0]?.status ?? null;
const VITE_NODE = join(__dirname, '..', 'node_modules', 'vite-node', 'vite-node.mjs');
const WRITER = join(__dirname, 'helpers', 'keys-cache-writer.ts');

interface WriterResult {
  pid: number;
  ok: number;
  refused: number;
  last: string;
}
function writer(dataDir: string, k: ReturnType<typeof key>, list: ServiceKeys, rounds: number, stallMs = 0, signal?: { file: string; role: 'hold' | 'wait' }, url = URL_): Promise<WriterResult> {
  const f = join(tempDir('kl-kc-list-'), 'list.json');
  writeFileSync(f, JSON.stringify(list));
  return new Promise((resolve, reject) => {
    const args = [VITE_NODE, WRITER, dataDir, url, `${k.pin.sha256}@${k.pin.valid_from}`, f, String(rounds), String(stallMs), ...(signal ? [signal.file, signal.role] : [])];
    const c = spawn(process.execPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    c.stdout.setEncoding('utf8').on('data', (d: string) => (out += d));
    c.stderr.setEncoding('utf8').on('data', (d: string) => (err += d));
    c.on('error', reject);
    c.on('close', (code) => (code === 0 ? resolve(JSON.parse(out.trim().split('\n').pop()!) as WriterResult) : reject(new Error(`writer exited ${code}: ${err}`))));
  });
}
const waitFor = async (cond: () => boolean, what: string) => {
  for (let i = 0; i < 500; i++) {
    if (cond()) return;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error(`timed out waiting for ${what}`);
};
const lockPid = (dataDir: string): number | null => {
  try {
    return (JSON.parse(readFileSync(join(dataDir, KEYS_CACHE_LOCK), 'utf8')) as { pid: number }).pid;
  } catch {
    return null;
  }
};
const cacheFile = (dataDir: string) => JSON.parse(readFileSync(join(dataDir, KEYS_CACHE_FILE), 'utf8')) as { v: 2; records: Record<string, { anchor_url: string; genesis: string; keys: ServiceKeys }> };
const recordKey = (url: string, k: ReturnType<typeof key>) => `${url}|${k.pin.sha256}@${k.pin.valid_from}`;

/**
 * The lock protocol shared with isokron-anchor's client (fix/cache-lock e894d67, README "Safe writes"):
 * these cases are ports of its client/test/cache-lock.test.ts, with kronicle-lite writers.
 */
describe('C3c: the cache write takes the shared lock, and re-reads and merges just before the rename', () => {
  it('interleaved writers: a writer that started before a revocation was stored cannot erase it', async () => {
    const dataDir = tempDir('kl-kc-race-');
    const k = key();
    guardKeyList({ dataDir }, URL_, active(k), k.pin); // both start from the active list
    // writer A (this test) holds the lock …
    const a = acquireKeysCacheLock(dataDir);
    expect(a.locked).toBe(true);
    expect(JSON.parse(readFileSync(join(dataDir, KEYS_CACHE_LOCK), 'utf8'))).toEqual({ pid: process.pid, created_at: expect.any(String) });
    // … writer B (another process) starts with the old list and has to wait for the lock
    const b = writer(dataDir, k, active(k), 1);
    await new Promise((r) => setTimeout(r, 600));
    const f = cacheFile(dataDir);
    f.records[recordKey(URL_, k)]!.keys = revoked(k);
    writeFileSync(join(dataDir, KEYS_CACHE_FILE), JSON.stringify(f));
    a.release();
    // B reads under the lock, sees the revocation, refuses its weaker list instead of overwriting it
    const rb = await b;
    expect(rb).toMatchObject({ ok: 0, refused: 1, last: expect.stringMatching(/was revoked in the list seen earlier and is active now/) });
    expect(keptStatus(dataDir, k)).toBe('revoked');
    expect(existsSync(join(dataDir, KEYS_CACHE_LOCK))).toBe(false);
  }, 60_000);

  it('a stalled writer holding the lock: the revocation writer waits instead of breaking it, then the revocation stays', async () => {
    const dataDir = tempDir('kl-kc-stall-');
    const signal = join(tempDir('kl-kc-sig-'), 'a-holds');
    const k = key();
    guardKeyList({ dataDir }, URL_, active(k), k.pin);
    const aRun = writer(dataDir, k, active(k), 1, 2500, { file: signal, role: 'hold' });
    await waitFor(() => existsSync(signal), 'A to hold the lock');
    const tB = Date.now();
    const [a, b] = await Promise.all([aRun, writer(dataDir, k, revoked(k), 1)]);
    expect(lockPid(dataDir)).toBeNull();
    expect([a.ok, b.ok]).toEqual([1, 1]);
    expect(Date.now() - tB).toBeGreaterThan(1500); // B waited for A
    expect(keptStatus(dataDir, k)).toBe('revoked');
    expect(() => guardKeyList({ dataDir }, URL_, active(k), k.pin)).toThrow(/was revoked in the list seen earlier and is active now/);
  }, 60_000);

  it('B holds a read-then-write open while A revokes (the old read-modify-write window): the revocation survives', async () => {
    for (let trial = 0; trial < 2; trial++) {
      const dataDir = tempDir('kl-kc-race2-');
      const signal = join(tempDir('kl-kc-sig-'), 'b-has-read');
      const k = key();
      guardKeyList({ dataDir }, URL_, active(k), k.pin);
      const [b, a] = await Promise.all([writer(dataDir, k, active(k), 5, 800, { file: signal, role: 'hold' }), writer(dataDir, k, revoked(k), 1, 0, { file: signal, role: 'wait' })]);
      expect(a.ok).toBe(1);
      expect(b.ok + b.refused).toBe(5);
      expect(keptStatus(dataDir, k)).toBe('revoked');
      expect(existsSync(join(dataDir, KEYS_CACHE_LOCK))).toBe(false);
    }
  }, 60_000);

  it('two concurrent writers for different services, many rounds: neither record is lost', async () => {
    const dataDir = tempDir('kl-kc-two-');
    const k = key();
    const [r1, r2] = await Promise.all([writer(dataDir, k, active(k), 40, 0, undefined, 'https://one.test'), writer(dataDir, k, revoked(k), 40, 0, undefined, 'https://two.test')]);
    expect([r1.ok, r2.ok]).toEqual([40, 40]);
    const f = cacheFile(dataDir);
    expect(Object.keys(f.records).sort()).toEqual([recordKey('https://one.test', k), recordKey('https://two.test', k)].sort());
    expect(f.records[recordKey('https://two.test', k)]!.keys.keys[0]!.status).toBe('revoked');
    expect(existsSync(join(dataDir, KEYS_CACHE_LOCK))).toBe(false);
  }, 60_000);

  it('a lock lost mid-write aborts with "cache lock lost" and writes nothing', async () => {
    const dataDir = tempDir('kl-kc-lost-');
    const signal = join(tempDir('kl-kc-sig-'), 'a-holds');
    const k = key();
    guardKeyList({ dataDir }, URL_, active(k), k.pin);
    const aRun = writer(dataDir, k, active(k), 1, 1500, { file: signal, role: 'hold' });
    await waitFor(() => existsSync(signal), 'A to hold the lock');
    // someone breaks A's lock (not following the rules), takes it and stores a revocation
    rmSync(join(dataDir, KEYS_CACHE_LOCK));
    const thief = acquireKeysCacheLock(dataDir);
    const f = cacheFile(dataDir);
    f.records[recordKey(URL_, k)]!.keys = revoked(k);
    writeFileSync(join(dataDir, KEYS_CACHE_FILE), JSON.stringify(f));
    const a = await aRun;
    thief.release();
    expect(a).toMatchObject({ ok: 0, refused: 1, last: expect.stringMatching(/^cache lock lost/) });
    expect(keptStatus(dataDir, k)).toBe('revoked');
    expect(readdirSync(dataDir).filter((n) => n.endsWith('.tmp'))).toEqual([]);
  }, 60_000);

  it('just before the write the file is re-read and merged: another record changed meanwhile is kept, and a stronger own record refuses', async () => {
    const dataDir = tempDir('kl-kc-merge-');
    const k = key();
    guardKeyList({ dataDir }, URL_, active(k), k.pin);
    // (1) a record for another service appears during A's stall (written without the lock): A keeps it
    const s1 = join(tempDir('kl-kc-sig-'), 'a1');
    const a1 = writer(dataDir, k, active(k), 1, 1200, { file: s1, role: 'hold' });
    await waitFor(() => existsSync(s1), 'A to stall');
    const f = cacheFile(dataDir);
    f.records[recordKey('https://other.test', k)] = { ...f.records[recordKey(URL_, k)]!, anchor_url: 'https://other.test', keys: revoked(k) };
    writeFileSync(join(dataDir, KEYS_CACHE_FILE), JSON.stringify(f));
    expect((await a1).ok).toBe(1);
    expect(Object.keys(cacheFile(dataDir).records).sort()).toEqual([recordKey(URL_, k), recordKey('https://other.test', k)].sort());
    expect(cacheFile(dataDir).records[recordKey('https://other.test', k)]!.keys.keys[0]!.status).toBe('revoked');
    // (2) A's own record becomes a revocation during the stall: A re-checks and refuses instead of overwriting it
    const s2 = join(tempDir('kl-kc-sig-'), 'a2');
    const a2 = writer(dataDir, k, active(k), 1, 1200, { file: s2, role: 'hold' });
    await waitFor(() => existsSync(s2), 'A to stall');
    const g = cacheFile(dataDir);
    g.records[recordKey(URL_, k)]!.keys = revoked(k);
    writeFileSync(join(dataDir, KEYS_CACHE_FILE), JSON.stringify(g));
    const r2 = await a2;
    expect(r2).toMatchObject({ ok: 0, refused: 1, last: expect.stringMatching(/was revoked in the list seen earlier and is active now/) });
    expect(keptStatus(dataDir, k)).toBe('revoked');
  }, 60_000);

  // Cross-client: isokron-anchor's own client (a checkout in KRONICLE_ANCHOR_CLIENT_DIR, e.g. its fix/cache-lock e894d67)
  // writes the same file under the same lock. Skipped without a checkout (CI has none).
  const CLIENT_DIR = process.env['KRONICLE_ANCHOR_CLIENT_DIR'];
  const clientWriter = (dataDir: string, k: ReturnType<typeof key>, list: ServiceKeys, signal: string, stallMs = 0) => {
    const f = join(tempDir('kl-kc-list-'), 'list.json');
    writeFileSync(f, JSON.stringify(list));
    return new Promise<{ ok: number; refused: number }>((resolve, reject) => {
      const env = { ...process.env, ...(stallMs ? { ISOKRON_ANCHOR_TEST_CACHE_STALL_MS: String(stallMs) } : {}) };
      const c = spawn(process.execPath, [VITE_NODE, join(__dirname, 'helpers', 'anchor-client-writer.ts'), CLIENT_DIR!, dataDir, URL_, `${k.pin.sha256}@${k.pin.valid_from}`, f, signal], { stdio: ['ignore', 'pipe', 'pipe'], env });
      let out = '';
      let err = '';
      c.stdout.setEncoding('utf8').on('data', (d: string) => (out += d));
      c.stderr.setEncoding('utf8').on('data', (d: string) => (err += d));
      c.on('error', reject);
      c.on('close', (code) => (code === 0 ? resolve(JSON.parse(out.trim().split('\n').pop()!) as { ok: number; refused: number }) : reject(new Error(`client exited ${code}: ${err}`))));
    });
  };
  it.skipIf(!CLIENT_DIR)('cross-client, both ways: each client waits for the other’s lock and never erases its revocation (skipped without KRONICLE_ANCHOR_CLIENT_DIR)', async () => {
    // kronicle-lite holds a read-then-write open; the anchor client revokes
    const d1 = tempDir('kl-kc-xclient-');
    const s1 = join(tempDir('kl-kc-sig-'), 'kl-holds');
    const k = key();
    guardKeyList({ dataDir: d1 }, URL_, active(k), k.pin);
    const [b, a] = await Promise.all([writer(d1, k, active(k), 5, 800, { file: s1, role: 'hold' }), clientWriter(d1, k, revoked(k), s1)]);
    expect(a).toEqual({ ok: 1, refused: 0 });
    expect(b.ok + b.refused).toBe(5);
    expect(keptStatus(d1, k)).toBe('revoked');
    // the anchor client stalls holding the lock with the older list; kronicle-lite revokes and waits for it
    const d2 = tempDir('kl-kc-xclient-');
    const s2 = join(tempDir('kl-kc-sig-'), 'go');
    writeFileSync(s2, 'go');
    guardKeyList({ dataDir: d2 }, URL_, active(k), k.pin);
    const cRun = clientWriter(d2, k, active(k), s2, 2000);
    await waitFor(() => lockPid(d2) !== null, 'the anchor client to hold the lock');
    const t0 = Date.now();
    const kl = await writer(d2, k, revoked(k), 1);
    expect(kl.ok).toBe(1);
    expect(Date.now() - t0).toBeGreaterThan(800);
    expect((await cRun).ok).toBe(1);
    expect(keptStatus(d2, k)).toBe('revoked');
    expect(existsSync(join(d2, KEYS_CACHE_LOCK))).toBe(false);
  }, 60_000);

  it('the merge rule: a longer or stronger list wins, the earlier compromised_since wins, a contradiction is refused', () => {
    const k = key();
    const j = key();
    expect(strongerKeyList(active(k), revoked(k))).toEqual(revoked(k));
    expect(strongerKeyList(revoked(k), active(k))).toEqual(revoked(k));
    const early = revoked(k, '2026-10-01T00:00:00.000Z');
    expect(strongerKeyList(revoked(k), early)).toEqual(early);
    expect(strongerKeyList(early, revoked(k))).toEqual(early);
    expect(strongerKeyList(active(k), active(j))).toBeNull(); // each drops the other's key
  });

  it('stale locks: broken when the pid is dead or after 10 minutes; a live holder is never broken earlier; created_at at most 1 min ahead', () => {
    const dataDir = tempDir('kl-kc-lock-');
    const k = key();
    const lock = join(dataDir, KEYS_CACHE_LOCK);
    expect(KEYS_CACHE_LOCK).toBe('anchor-keys.cache.json.lock');
    const deadPid = spawnSync(process.execPath, ['-e', '']).pid!;
    // dead pid, recent: broken
    writeFileSync(lock, JSON.stringify({ pid: deadPid, created_at: new Date().toISOString() }));
    guardKeyList({ dataDir }, URL_, active(k), k.pin);
    expect(existsSync(lock)).toBe(false);
    expect(keptStatus(dataDir, k)).toBe('active');
    // live pid, 33 s old (a stalled writer): not broken; only after 10 minutes
    writeFileSync(lock, JSON.stringify({ pid: process.pid, created_at: new Date(Date.now() - 33_000).toISOString() }));
    expect(() => acquireKeysCacheLock(dataDir, { timeoutMs: 150 })).toThrow(/could not lock/);
    expect(existsSync(lock)).toBe(true);
    writeFileSync(lock, JSON.stringify({ pid: process.pid, created_at: new Date(Date.now() - 11 * 60_000).toISOString() }));
    const got = acquireKeysCacheLock(dataDir, { timeoutMs: 1000 });
    expect(got.locked).toBe(true);
    got.release();
    // created_at more than 1 minute ahead is not believed: the age comes from mtime (recent → wait; old → broken)
    const ancient = (Date.now() - 11 * 60_000) / 1000;
    writeFileSync(lock, JSON.stringify({ pid: process.pid, created_at: new Date(Date.now() + 24 * 3600_000).toISOString() }));
    expect(() => acquireKeysCacheLock(dataDir, { timeoutMs: 150 })).toThrow(/could not lock/);
    utimesSync(lock, ancient, ancient);
    acquireKeysCacheLock(dataDir, { timeoutMs: 1000 }).release();
    // within the 1-minute cap the future created_at counts (recent → wait, even with an old mtime)
    writeFileSync(lock, JSON.stringify({ pid: process.pid, created_at: new Date(Date.now() + 30_000).toISOString() }));
    utimesSync(lock, ancient, ancient);
    expect(() => acquireKeysCacheLock(dataDir, { timeoutMs: 150 })).toThrow(/could not lock/);
    rmSync(lock);
    // unparseable content: judged by mtime (recent → wait; 1 minute is not stale; older than 10 minutes → broken)
    writeFileSync(lock, 'garbage');
    expect(() => acquireKeysCacheLock(dataDir, { timeoutMs: 150 })).toThrow(KeyListRollbackError);
    const old = (Date.now() - 60_000) / 1000;
    utimesSync(lock, old, old);
    expect(() => acquireKeysCacheLock(dataDir, { timeoutMs: 150 })).toThrow(KeyListRollbackError);
    utimesSync(lock, ancient, ancient);
    acquireKeysCacheLock(dataDir, { timeoutMs: 1000 }).release();
    // live pid, recent: the writer waits and then refuses (fail closed); the lock is left alone
    writeFileSync(lock, JSON.stringify({ pid: process.pid, created_at: new Date().toISOString() }));
    const t0 = Date.now();
    expect(() => guardKeyList({ dataDir }, URL_, revoked(k), k.pin, { lockWaitMs: 200 })).toThrow(/could not lock .* within 200 ms \(held: \{"pid":.* another kronicle-lite or anchor client is writing/);
    expect(Date.now() - t0).toBeGreaterThanOrEqual(150);
    expect(existsSync(lock)).toBe(true);
    // the holder's lock: 0600, exactly {pid, created_at}; release() removes only its own lock
    rmSync(lock);
    const mine = acquireKeysCacheLock(dataDir);
    expect(JSON.parse(readFileSync(lock, 'utf8'))).toEqual({ pid: process.pid, created_at: expect.any(String) });
    expect(Object.keys(JSON.parse(readFileSync(lock, 'utf8')) as object)).toEqual(['pid', 'created_at']);
    if (process.platform !== 'win32') expect(statSync(lock).mode & 0o777).toBe(0o600);
    writeFileSync(lock, JSON.stringify({ pid: 1, created_at: new Date().toISOString() })); // replaced by someone else
    mine.release();
    expect(existsSync(lock)).toBe(true);
  });

  it.skipIf(process.platform === 'win32' || process.getuid?.() === 0)('a read-only data dir (and a leftover stale lock in it): the list is checked, the cache is not written, and it returns promptly (skipped on Windows and as root)', () => {
    const dataDir = tempDir('kl-kc-ro-');
    const k = key();
    guardKeyList({ dataDir }, URL_, revoked(k), k.pin);
    const lock = join(dataDir, KEYS_CACHE_LOCK);
    const before = readFileSync(join(dataDir, KEYS_CACHE_FILE), 'utf8');
    chmodSync(dataDir, 0o500);
    try {
      const t0 = Date.now();
      expect(() => guardKeyList({ dataDir }, URL_, active(k), k.pin)).toThrow(/was revoked in the list seen earlier/);
      const j = key();
      expect(guardKeyList({ dataDir }, 'https://other.test', active(j), j.pin).join('\n')).toMatch(/checked but not kept/);
      expect(Date.now() - t0).toBeLessThan(5000);
      expect(readFileSync(join(dataDir, KEYS_CACHE_FILE), 'utf8')).toBe(before);
    } finally {
      chmodSync(dataDir, 0o700);
    }
    // a stale lock that cannot be removed: checked without writing, no spinning
    const deadPid = spawnSync(process.execPath, ['-e', '']).pid!;
    writeFileSync(lock, JSON.stringify({ pid: deadPid, created_at: new Date().toISOString() }));
    chmodSync(dataDir, 0o500);
    try {
      const t0 = Date.now();
      expect(() => guardKeyList({ dataDir }, URL_, active(k), k.pin)).toThrow(/was revoked in the list seen earlier/);
      expect(guardKeyList({ dataDir }, URL_, revoked(k), k.pin).join('\n')).toMatch(/checked but not kept/);
      expect(Date.now() - t0).toBeLessThan(5000);
      expect(existsSync(lock)).toBe(true);
    } finally {
      chmodSync(dataDir, 0o700);
    }
  });
});

describe('C2a / C2b: an old single-document cache file', () => {
  const legacy = (dataDir: string, doc: unknown) => writeFileSync(join(dataDir, KEYS_CACHE_FILE), JSON.stringify(doc));

  it('of another service, or that does not chain to the pin: ignored with one line, never blocks a valid list', () => {
    const k = key();
    const other = key();
    for (const doc of [
      { ...active(other) }, // a 0.4–0.8 kronicle-lite file: some other service's last document
      { ...active(k), kept_for: { anchor_url: 'https://elsewhere.test', genesis: `${k.pin.sha256}@${GF}` } }, // the service client's round-4 file for another URL
    ]) {
      const dataDir = tempDir('kl-kc-legacy-');
      legacy(dataDir, doc);
      const r = acceptServiceKeys({ dataDir }, URL_, k.pin, active(k));
      expect(r.violations).toEqual([]);
      expect(r.set).not.toBeNull();
      expect(r.notes.filter((n) => /old single-document key list .* was ignored/.test(n))).toHaveLength(1);
      expect(keptStatus(dataDir, k)).toBe('active'); // the file is now v2, holding the confirmed list
      expect((JSON.parse(readFileSync(join(dataDir, KEYS_CACHE_FILE), 'utf8')) as { v: number }).v).toBe(2);
    }
  });

  it('of this service and pin: the rollback reference for the next fetch (a weaker list is refused), but never the kept list offline until a fetch confirms it', () => {
    const k = key();
    const dataDir = tempDir('kl-kc-legacy-');
    legacy(dataDir, { ...revoked(k), kept_for: { anchor_url: 'https://Anchor.Test:443/', genesis: `${k.pin.sha256.toUpperCase()}@2026-01-01T00:00:00Z` } });
    // C2b: offline and doctor read only confirmed (v2) records
    expect(readKeysCache({ dataDir }, URL_, k.pin)).toBeNull();
    // the fetch path compares with it: the active list would undo the revocation
    expect(acceptServiceKeys({ dataDir }, URL_, k.pin, active(k)).violations.join('\n')).toMatch(/was revoked in the list seen earlier and is active now/);
    expect(readKeysCache({ dataDir }, URL_, k.pin)).toBeNull();
    // a fetch that confirms it (as strong or stronger) makes it the kept list
    const ok = acceptServiceKeys({ dataDir }, URL_, k.pin, revoked(k));
    expect(ok.notes.join('\n')).toMatch(/rollback reference until this fetch confirms it/);
    expect(keptStatus(dataDir, k)).toBe('revoked');
  });
});
