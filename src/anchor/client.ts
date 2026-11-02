/**
 * HTTP client for the hosted anchor service (default https://anchor.isokron.ai).
 * Ported from isokron-anchor `client/src/api.ts`; Node ≥ 20 global fetch, no
 * dependencies.
 *
 * Two error classes, so callers can keep local work going:
 *   - AnchorUnreachableError: no answer, a timeout, or an answer that is not
 *     the anchor protocol (an HTML 404 from a parked domain, a proxy 502).
 *     Message always starts with "anchor service unreachable".
 *   - AnchorApiError: the service answered in protocol and said no
 *     (401 bad license, 402 quota, 422 bad signature, 429 rate limited…).
 */

import { parseAnchorReceipt, verifyAnchorReceiptSignature, type AnchorReceipt } from './receipt.js';
import { checkPublishedServiceKey } from './trust.js';
import type { WireCheckpoint } from './wire.js';

export const DEFAULT_ANCHOR_TIMEOUT_MS = 10_000;

export interface AnchorPublicView {
  status: string;
  day: string | null;
  leaf_index: number | null;
  path: unknown;
  ots: string | null;
  rekor_uuid: string | null;
  note: string;
}

export interface AnchorPushResponse {
  ok: boolean;
  anchor_id: string;
  duplicate: boolean;
  conflict: boolean;
  conflicting_anchor_ids?: string[];
  receipt: AnchorReceipt;
  receipt_jcs: string;
  receipt_hash: string;
  public: AnchorPublicView;
  verify_url: string;
  receipt_url: string;
  usage?: { used_this_month: number; limit: number | null; tier: string };
}

export interface RemoteAnchor {
  anchor_id: string;
  from_seq: number;
  to_seq: number;
  leaf_count: number;
  root: string;
  received_at: string;
  service_key_id: string;
  service_sig: string;
  conflict: boolean;
  public: AnchorPublicView;
  receipt: AnchorReceipt;
}

export interface RemoteChain {
  /** Paginated listing (isokron-anchor A2-13): null on the last page; chain() follows it and returns every page. */
  next_cursor?: string | null;
  chain_id: string;
  key_id: string;
  pubkey: string | null;
  erased: boolean;
  conflict: boolean;
  anchor_count: number;
  anchors: RemoteAnchor[];
  verify_url: string;
}

export interface ServiceKeys {
  v: 1;
  issuer: string;
  keys: { key_id: string; public_key_pem: string; status: string; valid_from: string; valid_to: string | null }[];
}

export class AnchorApiError extends Error {
  override readonly name = 'AnchorApiError';
  constructor(
    readonly status: number,
    readonly code: string,
    readonly detail: string,
    readonly body: unknown,
  ) {
    super(`anchor service refused (${status} ${code}): ${detail}`);
  }
}

/** Upper bound on pages AnchorClient.chain() follows (500 anchors per page → 5,000,000 anchors). */
export const MAX_CHAIN_PAGES = 10_000;

/**
 * The service answered, but its chain listing broke the pagination protocol
 * (missing or looping cursor, truncated, duplicated or foreign pages). Never
 * treated as a complete list.
 */
export class AnchorListingError extends Error {
  override readonly name = 'AnchorListingError';
  constructor(
    readonly url: string,
    readonly detail: string,
  ) {
    super(`anchor listing from ${url} rejected: ${detail}`);
  }
}

export class AnchorUnreachableError extends Error {
  override readonly name = 'AnchorUnreachableError';
  readonly code = 'anchor_unreachable';
  constructor(
    readonly url: string,
    readonly cause_detail: string,
  ) {
    super(`anchor service unreachable at ${url}: ${cause_detail}. Local data is unaffected; retry later or set anchor_url.`);
  }
}

export interface AnchorClientOptions {
  fetch?: typeof fetch;
  preloadedKeys?: ServiceKeys | null;
  timeoutMs?: number;
}

function describeFetchError(err: unknown): string {
  if (err instanceof Error) {
    if (err.name === 'TimeoutError' || err.name === 'AbortError') return 'request timed out';
    const cause = (err as Error & { cause?: unknown }).cause;
    if (cause instanceof Error) {
      const code = (cause as Error & { code?: string }).code;
      return code ? `${code} (${cause.message})` : cause.message;
    }
    return err.message;
  }
  return String(err);
}

export class AnchorClient {
  readonly baseUrl: string;
  private keysCache: ServiceKeys | null;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(baseUrl: string, opts: AnchorClientOptions = {}) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.fetchImpl = opts.fetch ?? ((...a) => globalThis.fetch(...a));
    this.keysCache = opts.preloadedKeys ?? null;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_ANCHOR_TIMEOUT_MS;
  }

  /** fetch + JSON parse; anything that is not a JSON answer is "unreachable". */
  private async request(path: string, init: RequestInit = {}): Promise<{ status: number; json: unknown; isJson: boolean }> {
    const url = `${this.baseUrl}${path}`;
    let res: Response;
    try {
      res = await this.fetchImpl(url, { ...init, signal: AbortSignal.timeout(this.timeoutMs) });
    } catch (err) {
      throw new AnchorUnreachableError(this.baseUrl, describeFetchError(err));
    }
    const text = await res.text().catch(() => '');
    let json: unknown = null;
    let isJson = false;
    try {
      json = JSON.parse(text);
      isJson = json !== null && typeof json === 'object';
    } catch {
      isJson = false;
    }
    return { status: res.status, json, isJson };
  }

  private refusal(status: number, json: unknown, isJson: boolean, what: string): Error {
    if (!isJson) return new AnchorUnreachableError(this.baseUrl, `HTTP ${status} with a non-JSON body for ${what} (not an anchor service)`);
    const e = json as { error?: unknown; detail?: unknown };
    if (typeof e.error !== 'string') {
      return new AnchorUnreachableError(this.baseUrl, `HTTP ${status} for ${what} without an anchor-protocol error body`);
    }
    return new AnchorApiError(status, e.error, typeof e.detail === 'string' ? e.detail : '', json);
  }

  async push(licenseKey: string, body: { chain_id: string; pubkey: string; checkpoint: WireCheckpoint }): Promise<AnchorPushResponse> {
    const r = await this.request('/v1/anchor', {
      method: 'POST',
      headers: { authorization: `Bearer ${licenseKey}`, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify(body),
    });
    if ((r.status === 201 || r.status === 200 || r.status === 409) && r.isJson && 'receipt' in (r.json as object)) {
      return r.json as AnchorPushResponse;
    }
    throw this.refusal(r.status, r.json, r.isJson, 'POST /v1/anchor');
  }

  /**
   * The service's view of a chain with EVERY anchor, or null when nothing was
   * anchored for it. Since isokron-anchor hardening A2-13 the listing is
   * paginated (≤ 500 per page, `next_cursor`, null on the last page); a
   * service from before that returns one page without `next_cursor`. Throws
   * AnchorListingError — never a short list — when a page breaks the
   * protocol: a later page without `next_cursor`, a cursor seen before, an
   * anchor listed twice, another chain's page, more than MAX_CHAIN_PAGES
   * pages, or fewer anchors in total than the service's own anchor_count.
   */
  async chain(chain_id: string): Promise<RemoteChain | null> {
    let first: RemoteChain | null = null;
    const anchors: RemoteAnchor[] = [];
    const ids = new Set<string>();
    const seen = new Set<string>();
    let cursor: string | null = null;
    for (let page = 0; page < MAX_CHAIN_PAGES; page++) {
      const qs = cursor === null ? '' : `?cursor=${encodeURIComponent(cursor)}`;
      const what = `GET /v1/chains/${chain_id.slice(0, 12)}…${page > 0 ? ` (page ${page + 1})` : ''}`;
      const r = await this.request(`/v1/chains/${chain_id}${qs}`, { headers: { accept: 'application/json' } });
      if (page === 0 && r.status === 404 && r.isJson && typeof (r.json as { error?: unknown }).error === 'string') return null;
      if (!(r.status === 200 && r.isJson && Array.isArray((r.json as { anchors?: unknown }).anchors))) throw this.refusal(r.status, r.json, r.isJson, what);
      const body = r.json as RemoteChain & { next_cursor?: unknown; page?: unknown };
      if (body.chain_id !== chain_id) throw new AnchorListingError(this.baseUrl, `${what} answered for chain ${String(body.chain_id).slice(0, 12)}…`);
      first ??= body;
      for (const a of body.anchors) {
        const id = (a as { anchor_id?: unknown }).anchor_id;
        if (typeof id !== 'string') throw new AnchorListingError(this.baseUrl, `${what} lists an anchor without anchor_id`);
        if (ids.has(id)) throw new AnchorListingError(this.baseUrl, `${what} lists anchor ${id} a second time (looping cursor?)`);
        ids.add(id);
        anchors.push(a);
      }
      const hasCursorField = Object.prototype.hasOwnProperty.call(body, 'next_cursor');
      if (!hasCursorField) {
        // Pre-pagination service: one page, no cursor, no page object.
        if (page > 0 || body.page !== undefined) throw new AnchorListingError(this.baseUrl, `${what} is paginated but has no next_cursor`);
        cursor = null;
      } else if (body.next_cursor === null) {
        cursor = null;
      } else if (typeof body.next_cursor === 'string' && body.next_cursor.length > 0) {
        if (seen.has(body.next_cursor)) throw new AnchorListingError(this.baseUrl, `${what} repeats next_cursor (looping)`);
        seen.add(body.next_cursor);
        cursor = body.next_cursor;
      } else {
        throw new AnchorListingError(this.baseUrl, `${what} has a malformed next_cursor`);
      }
      if (cursor === null) {
        const expected = typeof first.anchor_count === 'number' ? first.anchor_count : null;
        if (expected !== null && anchors.length < expected) {
          throw new AnchorListingError(this.baseUrl, `the listing ended after ${anchors.length} of ${expected} anchors (anchor_count); pages missing or truncated`);
        }
        return { ...first, anchors, next_cursor: null };
      }
    }
    throw new AnchorListingError(this.baseUrl, `chain listing exceeds ${MAX_CHAIN_PAGES} pages`);
  }

  async serviceKeys(): Promise<ServiceKeys> {
    if (this.keysCache) return this.keysCache;
    const r = await this.request('/.well-known/anchor-keys.json', { headers: { accept: 'application/json' } });
    if (r.status === 200 && r.isJson && Array.isArray((r.json as { keys?: unknown }).keys)) {
      this.keysCache = r.json as ServiceKeys;
      return this.keysCache;
    }
    throw this.refusal(r.status, r.json, r.isJson, 'GET /.well-known/anchor-keys.json');
  }

  /**
   * The published key for `service_key_id` when it may vouch for something
   * issued at `at` — the service's own rule (isokron-anchor
   * src/core/servicekeys.ts): listed once, derives to its key_id, usable
   * Ed25519 point, status active (or retired with valid_to), inside its
   * validity window, successor signature verified when present. Unpinned:
   * the anchor commands verify against the local pins (trust.ts), not this.
   */
  async servicePublicKeyPem(service_key_id: string, at: string): Promise<string | null> {
    const keys = await this.serviceKeys();
    const c = checkPublishedServiceKey(Array.isArray(keys?.keys) ? keys.keys : [], service_key_id, at);
    return c.ok ? c.pem : null;
  }

  /**
   * Parse + countersignature check against the keys this client was given
   * (preloaded) or fetched, with the service's key rules at the receipt's
   * signed time. Throws on failure. NOT pinned: a key document from the
   * same channel as the receipt proves little on its own — the CLI and MCP
   * paths use verifyReceiptWithPins.
   */
  async verifyReceipt(input: unknown): Promise<AnchorReceipt> {
    const parsed = parseAnchorReceipt(input);
    if (!parsed.ok) throw new Error(`anchor receipt malformed: ${parsed.detail}`);
    const id = parsed.value.service_key_id;
    const keys = await this.serviceKeys();
    const c = checkPublishedServiceKey(Array.isArray(keys?.keys) ? keys.keys : [], id, parsed.value.received_at);
    if (!c.ok) throw new Error(`service key ${id} (${this.baseUrl}/.well-known/anchor-keys.json): ${c.detail}`);
    if (!verifyAnchorReceiptSignature(parsed.value, c.pem)) throw new Error('anchor receipt countersignature does not verify');
    return parsed.value;
  }
}
