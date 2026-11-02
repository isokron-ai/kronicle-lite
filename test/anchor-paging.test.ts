/**
 * 0.8.1 anchor re-review: the chain listing always asks for a page
 * (`?limit=500`, then `&cursor=`), retries a 400 paginate_required once, and
 * honours 429 `retry-after` (≤ 60 s, ≤ 3 retries per request, then fails
 * closed). Runs against the in-process stub (a pre-pagination service that
 * ignores query parameters) and fake hardened-service behaviour layered on it
 * with an injected fetch. Nothing leaves 127.0.0.1; no real sleeping.
 */

import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { localChainIdentity, pushCheckpoint, tryPushCheckpoint, verifyLastAnchor, verifyRemote } from '../src/anchor/anchor.js';
import {
  AnchorClient,
  AnchorListingError,
  AnchorRateLimitedError,
  CHAIN_PAGE_LIMIT,
  DEFAULT_RETRY_AFTER_MS,
  MAX_RATE_LIMIT_RETRIES,
  parseRetryAfter,
} from '../src/anchor/client.js';
import { KronicleLite } from '../src/store.js';
import { startAnchorStub, type AnchorBackend } from './helpers/anchor-stub.js';

type Json = Record<string, unknown> & { anchors?: Record<string, unknown>[] };

function hrefOf(input: Parameters<typeof fetch>[0]): string {
  return typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
}

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

/**
 * The hardened service's listing semantics over the stub's data: no limit and
 * no cursor → 400 paginate_required when more than `unpagedMax` anchors;
 * otherwise pages of min(limit, 500) with `next_cursor`.
 */
function hardened(opts: { unpagedMax?: number; pageMax?: number } = {}): typeof fetch & { calls: string[] } {
  const calls: string[] = [];
  const f = (async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
    const u = new URL(hrefOf(input));
    if (!u.pathname.startsWith('/v1/chains/')) return globalThis.fetch(input, init);
    calls.push(u.search);
    const res = await globalThis.fetch(`${u.origin}${u.pathname}`, init);
    if (res.status !== 200) return res;
    const full = (await res.json()) as Json;
    const all = full.anchors ?? [];
    const limitRaw = u.searchParams.get('limit');
    const cursorRaw = u.searchParams.get('cursor');
    if (limitRaw === null && cursorRaw === null) {
      if (all.length > (opts.unpagedMax ?? 5000)) return json(400, { error: 'paginate_required', detail: 'request ?limit=500', anchor_count: all.length });
      return json(200, { ...full, page: { limit: null, returned: all.length }, next_cursor: null });
    }
    const size = Math.min(Number(limitRaw ?? 500), opts.pageMax ?? 500);
    const start = cursorRaw ? Number(cursorRaw.slice(1)) : 0;
    const next = start + size < all.length ? `c${start + size}` : null;
    return json(200, { ...full, anchors: all.slice(start, start + size), page: { limit: size, returned: Math.min(size, all.length - start) }, next_cursor: next });
  }) as typeof fetch & { calls: string[] };
  f.calls = calls;
  return f;
}

/** Wrap a fetch: answer 429 for the first `n` matching requests (per distinct URL when perUrl). */
function throttled(inner: typeof fetch, n: number, retryAfter: string | null, match: (path: string) => boolean, perUrl = true): typeof fetch & { hits: number } {
  const count = new Map<string, number>();
  const f = (async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
    const u = new URL(hrefOf(input));
    if (match(u.pathname)) {
      const key = perUrl ? u.pathname + u.search : 'all';
      const c = count.get(key) ?? 0;
      if (c < n) {
        count.set(key, c + 1);
        f.hits++;
        return json(429, { error: 'rate_limited', detail: 'slow down' }, retryAfter === null ? {} : { 'retry-after': retryAfter });
      }
    }
    return inner(input, init);
  }) as typeof fetch & { hits: number };
  f.hits = 0;
  return f;
}

function fakeSleep(): ((ms: number) => Promise<void>) & { waits: number[] } {
  const waits: number[] = [];
  const s = (async (ms: number) => {
    waits.push(ms);
  }) as ((ms: number) => Promise<void>) & { waits: number[] };
  s.waits = waits;
  return s;
}

function makeStore(): { dataDir: string; store: KronicleLite } {
  const dataDir = join(mkdtempSync(join(tmpdir(), 'kl-anchor-pg-')), 'data');
  const store = new KronicleLite({ dataDir });
  store.docs.putDocument({ slug: 'd', title: 'D', markdown: '# D\n\nBody.\n', actor_id: 't' });
  store.chain.checkpoint();
  return { dataDir, store };
}

describe('anchor chain listing: always paged, 429 honoured (0.8.1 re-review)', { timeout: 60_000 }, () => {
  let b: AnchorBackend;
  let store: KronicleLite;
  let chain_id: string;
  let anchorIds: string[];
  beforeAll(async () => {
    b = await startAnchorStub();
    ({ store } = makeStore());
    anchorIds = [(await pushCheckpoint(store, { anchorUrl: b.url, licenseKey: b.license })).anchor_id];
    for (let i = 0; i < 4; i++) {
      store.docs.putDocument({ slug: `n${i}`, title: `N${i}`, markdown: `# N${i}\n\nn.\n`, actor_id: 't' });
      store.chain.checkpoint();
      anchorIds.push((await pushCheckpoint(store, { anchorUrl: b.url, licenseKey: b.license })).anchor_id);
    }
    chain_id = localChainIdentity(store).chain_id;
  });
  afterAll(async () => {
    store?.close();
    await b?.stop();
  });
  const opts = () => ({ anchorUrl: b.url, licenseKey: b.license });

  it('the first request already carries ?limit=500 and continuations add the cursor; a pre-pagination service ignores both', async () => {
    const calls: string[] = [];
    const recording: typeof fetch = (input, init) => {
      const u = new URL(hrefOf(input));
      if (u.pathname.startsWith('/v1/chains/')) calls.push(u.search);
      return globalThis.fetch(input, init);
    };
    // The stub is a pre-pagination service: one page, no next_cursor, query ignored.
    const legacy = await new AnchorClient(b.url, { fetch: recording }).chain(chain_id);
    expect(legacy!.anchors.map((a) => a.anchor_id).sort()).toEqual([...anchorIds].sort());
    expect(calls).toEqual([`?limit=${CHAIN_PAGE_LIMIT}`]);
    const r = await verifyRemote(store, { ...opts(), fetch: recording });
    expect(r.ok, r.problems.join('; ')).toBe(true);
    expect(r.checks).toHaveLength(5);

    // Hardened service with 2-per-page: limit on every request, cursor from page 2 on.
    const h = hardened({ pageMax: 2 });
    const paged = await new AnchorClient(b.url, { fetch: h }).chain(chain_id);
    expect(paged!.anchors).toHaveLength(5);
    expect(h.calls).toEqual(['?limit=500', '?limit=500&cursor=c2', '?limit=500&cursor=c4']);
  });

  it('a chain above the unpaged cap verifies (the hardened service would answer 400 paginate_required to a bare request)', async () => {
    const h = hardened({ unpagedMax: 3, pageMax: 2 });
    // A bare request is refused by such a service…
    const bare = await h(`${b.url}/v1/chains/${chain_id}`);
    expect(bare.status).toBe(400);
    // …and the client never sends one.
    const r = await verifyRemote(store, { ...opts(), fetch: h });
    expect(r.ok, r.problems.join('; ')).toBe(true);
    expect(r.checks.map((c) => c.source)).toEqual(['remote', 'remote', 'remote', 'remote', 'remote']);
    expect(h.calls.slice(1).every((q) => q.includes('limit=500'))).toBe(true); // [0] is the bare probe above
    expect((await verifyLastAnchor(store, { ...opts(), fetch: hardened({ unpagedMax: 3, pageMax: 2 }), remote: true })).remote).toBe('checked');
  });

  it('400 paginate_required is retried once with ?limit=500; twice fails closed (listing rejected, held receipts still checked)', async () => {
    let refusals = 0;
    const once: typeof fetch = (input, init) => {
      const u = new URL(hrefOf(input));
      if (u.pathname.startsWith('/v1/chains/') && refusals === 0) {
        refusals++;
        return Promise.resolve(json(400, { error: 'paginate_required', detail: 'x', anchor_count: 5 }));
      }
      return hardened({ pageMax: 2 })(input, init);
    };
    const ok = await new AnchorClient(b.url, { fetch: once }).chain(chain_id);
    expect(ok!.anchors).toHaveLength(5);

    const always: typeof fetch = (input, init) =>
      new URL(hrefOf(input)).pathname.startsWith('/v1/chains/') ? Promise.resolve(json(400, { error: 'paginate_required', detail: 'x' })) : globalThis.fetch(input, init);
    await expect(new AnchorClient(b.url, { fetch: always }).chain(chain_id)).rejects.toThrow(/paginate_required although \?limit=500 was sent/);
    const r = await verifyRemote(store, { ...opts(), fetch: always });
    expect(r.ok).toBe(false);
    expect(r.problems.join('\n')).toMatch(/paginate_required/);
    expect(r.checks.every((c) => c.source === 'local' && c.result === 'match')).toBe(true);
  });

  it('429 on a page: waits retry-after and retries (≤ 3 per page), then the listing completes', async () => {
    const sleep = fakeSleep();
    const f = throttled(hardened({ pageMax: 2 }), 2, '7', (p) => p.startsWith('/v1/chains/'));
    const c = await new AnchorClient(b.url, { fetch: f, sleep }).chain(chain_id);
    expect(c!.anchors).toHaveLength(5);
    expect(f.hits).toBe(6); // 2 per page × 3 pages
    expect(sleep.waits).toEqual([7000, 7000, 7000, 7000, 7000, 7000]);
    // Through verifyRemote as well, with exactly MAX_RATE_LIMIT_RETRIES 429s per page.
    const s2 = fakeSleep();
    const r = await verifyRemote(store, { ...opts(), fetch: throttled(hardened({ pageMax: 2 }), MAX_RATE_LIMIT_RETRIES, '1', (p) => p.startsWith('/v1/chains/')), sleep: s2 });
    expect(r.ok, r.problems.join('; ')).toBe(true);
    expect(s2.waits).toHaveLength(MAX_RATE_LIMIT_RETRIES * 3);
  });

  it('429 that persists, or asks for more than 60 s, fails closed: never "verified"; held receipts still checked', async () => {
    const sleep = fakeSleep();
    const persistent = throttled(hardened({ pageMax: 2 }), 99, '2', (p) => p.startsWith('/v1/chains/'));
    await expect(new AnchorClient(b.url, { fetch: persistent, sleep }).chain(chain_id)).rejects.toBeInstanceOf(AnchorListingError);
    expect(sleep.waits).toEqual([2000, 2000, 2000]);
    const r = await verifyRemote(store, { ...opts(), fetch: throttled(hardened({ pageMax: 2 }), 99, '2', (p) => p.startsWith('/v1/chains/')), sleep: fakeSleep() });
    expect(r.ok).toBe(false);
    expect(r.problems.join('\n')).toMatch(/still 429 after 3 retries/);
    expect(r.checks.every((c) => c.source === 'local' && c.result === 'match')).toBe(true);
    const mcp = await verifyLastAnchor(store, { ...opts(), fetch: throttled(hardened(), 99, '2', (p) => p.startsWith('/v1/chains/')), sleep: fakeSleep(), remote: true });
    expect(mcp.remote).toBe('invalid');

    // A page 2 that stays rate-limited: the first page alone is never accepted.
    let page2 = 0;
    const midway: typeof fetch = (input, init) => {
      const u = new URL(hrefOf(input));
      if (u.searchParams.has('cursor')) {
        page2++;
        return Promise.resolve(json(429, { error: 'rate_limited' }, { 'retry-after': '1' }));
      }
      return hardened({ pageMax: 2 })(input, init);
    };
    await expect(new AnchorClient(b.url, { fetch: midway, sleep: fakeSleep() }).chain(chain_id)).rejects.toThrow(/page 2.*still 429/);
    expect(page2).toBe(MAX_RATE_LIMIT_RETRIES + 1);

    // retry-after above 60 s: no waiting at all, fail closed.
    const s3 = fakeSleep();
    await expect(new AnchorClient(b.url, { fetch: throttled(hardened(), 1, '120', (p) => p.startsWith('/v1/chains/')), sleep: s3 }).chain(chain_id)).rejects.toThrow(/retry-after 120 s exceeds 60 s/);
    expect(s3.waits).toEqual([]);
  });

  it('429 on the key document: retried the same way; exhausted, verify and push fail closed (no pins written from nothing)', async () => {
    const sleep = fakeSleep();
    const keys429 = throttled(globalThis.fetch, 1, null, (p) => p === '/.well-known/anchor-keys.json');
    const r = await verifyRemote(store, { ...opts(), fetch: keys429, sleep });
    expect(r.ok, r.problems.join('; ')).toBe(true);
    expect(sleep.waits).toEqual([DEFAULT_RETRY_AFTER_MS]); // no retry-after header → 1 s
    const always = throttled(globalThis.fetch, 99, '1', (p) => p === '/.well-known/anchor-keys.json');
    await expect(verifyRemote(store, { ...opts(), fetch: always, sleep: fakeSleep() })).rejects.toBeInstanceOf(AnchorRateLimitedError);
    const fresh = makeStore();
    const out = await tryPushCheckpoint(fresh.store, { ...opts(), fetch: throttled(globalThis.fetch, 99, '1', (p) => p === '/.well-known/anchor-keys.json'), sleep: fakeSleep() });
    expect(out).toMatchObject({ ok: false, error: 'anchor_refused' });
    expect(out.message).toMatch(/rate-limited GET \/\.well-known\/anchor-keys\.json: still 429 after 3 retries/);
    expect(fresh.store.chain.listAnchors()).toHaveLength(0);
    fresh.store.close();
  });

  it('parseRetryAfter: delta-seconds, HTTP date, absent or garbage', () => {
    const now = Date.parse('2026-11-02T00:00:00.000Z');
    expect(parseRetryAfter('5', now)).toBe(5000);
    expect(parseRetryAfter('0', now)).toBe(0);
    expect(parseRetryAfter('Mon, 02 Nov 2026 00:00:30 GMT', now)).toBe(30_000);
    expect(parseRetryAfter('Sun, 01 Nov 2026 00:00:00 GMT', now)).toBe(0);
    expect(parseRetryAfter(null, now)).toBeNull();
    expect(parseRetryAfter('soon', now)).toBeNull();
    expect(parseRetryAfter('-3', now)).toBeNull();
  });
});
