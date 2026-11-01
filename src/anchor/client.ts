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

  /** The service's view of a chain, or null when nothing was anchored for it. */
  async chain(chain_id: string): Promise<RemoteChain | null> {
    const r = await this.request(`/v1/chains/${chain_id}`, { headers: { accept: 'application/json' } });
    if (r.status === 200 && r.isJson && Array.isArray((r.json as { anchors?: unknown }).anchors)) return r.json as RemoteChain;
    if (r.status === 404 && r.isJson && typeof (r.json as { error?: unknown }).error === 'string') return null;
    throw this.refusal(r.status, r.json, r.isJson, `GET /v1/chains/${chain_id.slice(0, 12)}…`);
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

  async servicePublicKeyPem(service_key_id: string): Promise<string | null> {
    const keys = await this.serviceKeys();
    const k = keys.keys.find((x) => x.key_id === service_key_id && x.status !== 'revoked');
    return k ? k.public_key_pem : null;
  }

  /** Parse + countersignature check against the published service keys. Throws on failure. */
  async verifyReceipt(input: unknown): Promise<AnchorReceipt> {
    const parsed = parseAnchorReceipt(input);
    if (!parsed.ok) throw new Error(`anchor receipt malformed: ${parsed.detail}`);
    const pem = await this.servicePublicKeyPem(parsed.value.service_key_id);
    if (!pem) throw new Error(`service key ${parsed.value.service_key_id} not published at ${this.baseUrl}/.well-known/anchor-keys.json`);
    if (!verifyAnchorReceiptSignature(parsed.value, pem)) throw new Error('anchor receipt countersignature does not verify');
    return parsed.value;
  }
}
