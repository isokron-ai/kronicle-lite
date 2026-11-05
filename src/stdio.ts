/**
 * 0.8.1: the stdio wire under `serveStdio` (findings P2-05/F11, P2-06, P2-11).
 *
 * The SDK's `StdioServerTransport` (2.4.0) drops malformed input without an
 * answer, closes the connection (and the process exits 0) on any line over
 * 10 MiB, and serves a `tools/call` sent before `initialize`. This transport
 * replaces it (serveStdio's `transport` option) and keeps the SDK's era
 * logic untouched; it only decides what reaches it:
 *
 * - framing: newline-delimited, CR stripped, a UTF-8 BOM (stream start or
 *   line start) stripped, blank lines ignored;
 * - a line over `maxMessageBytes` is discarded as it streams in and answered
 *   with -32600 "message too large" (the id is recovered from the line's
 *   start when it is there); the connection stays up;
 * - unparsable JSON → -32700 (id null); a JSON-RPC batch → -32600 per request
 *   ("batches are not supported", removed in 2025-06-18), or one error for an
 *   empty batch; an object that is not a valid JSON-RPC message → -32600 with
 *   its id when it has a usable one;
 * - lifecycle: before the era is known, a request that is neither
 *   `initialize` (2025) nor carries a 2026-07-28 envelope is refused
 *   (-32600 "not initialized"), and claim-less notifications are dropped, so a
 *   stray message cannot pin a 2025-era connection without its handshake;
 *   `ping` is answered here, before and after the handshake, in both eras;
 * - on a 2026-07-28 connection every request must carry the envelope: none
 *   → -32602, an unsupported version → -32022 (the SDK checks only the opening
 *   request on stdio);
 * - outbound: a message over `maxOutboundBytes` is replaced by a JSON-RPC
 *   error for the same id, so a client's own 10 MiB read buffer never closes
 *   the connection after a write committed.
 */

import {
  classifyInboundRequest,
  parseJSONRPCMessage,
  PROTOCOL_VERSION_META_KEY,
  UnsupportedProtocolVersionError,
  type JSONRPCMessage,
  type Transport,
} from '@modelcontextprotocol/server';

/**
 * One inbound message size limit for both transports (stdio line, HTTP body).
 * Every schema-valid put_document fits: 2,000,000 characters escaped as
 * `\uXXXX` are 12 MB on the wire. Override with KRONICLE_LITE_MAX_MESSAGE_BYTES.
 */
export const MAX_MESSAGE_BYTES = 16 * 1024 * 1024;

/** Outbound line limit: under the 10 MiB read buffer of the TS SDK clients (v1 and v2), with headroom. */
export const MAX_OUTBOUND_BYTES = 9 * 1024 * 1024;

export function maxMessageBytes(env: NodeJS.ProcessEnv = process.env): number {
  const v = Number(env['KRONICLE_LITE_MAX_MESSAGE_BYTES']);
  return Number.isInteger(v) && v >= 64 * 1024 ? v : MAX_MESSAGE_BYTES;
}

/**
 * The stateless revisions this server speaks (SDK 2.4 serves exactly these on
 * its modern leg; its SUPPORTED_PROTOCOL_VERSIONS export lists the 2025 era only).
 */
export const MODERN_VERSIONS: readonly string[] = ['2026-07-28'];
const BOM = '﻿';
/** How much of an oversize line is kept to recover its id. */
const HEAD_KEEP = 64 * 1024;

type Id = string | number | null;
type Era = 'opening' | 'probe' | 'legacy' | 'modern';

export interface GuardedStdioOptions {
  maxMessageBytes?: number;
  maxOutboundBytes?: number;
  /** Diagnostics (stderr in the CLI). */
  log?: (line: string) => void;
}

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function usableId(v: unknown): v is string | number {
  return typeof v === 'string' || (typeof v === 'number' && Number.isFinite(v));
}

/**
 * The top-level `id` of a JSON object from the first bytes of its text, or
 * undefined when it is not there (or the text is not an object). A small
 * scanner: tracks string/escape state and nesting, reads depth-1 keys.
 */
export function idFromPrefix(text: string): { id?: Id; method?: string } {
  const out: { id?: Id; method?: string } = {};
  let depth = 0;
  let i = 0;
  const n = text.length;
  const readString = (): string | null => {
    // at an opening quote
    let s = '';
    i++;
    while (i < n) {
      const c = text[i]!;
      if (c === '\\') {
        const e = text[i + 1];
        if (e === undefined) return null;
        if (e === 'u') {
          const hex = text.slice(i + 2, i + 6);
          if (hex.length < 4) return null;
          s += String.fromCharCode(parseInt(hex, 16));
          i += 6;
          continue;
        }
        s += ({ n: '\n', t: '\t', r: '\r', b: '\b', f: '\f' } as Record<string, string>)[e] ?? e;
        i += 2;
        continue;
      }
      if (c === '"') {
        i++;
        return s;
      }
      s += c;
      i++;
    }
    return null;
  };
  const skipWs = () => {
    while (i < n && /\s/.test(text[i]!)) i++;
  };
  skipWs();
  if (text[i] !== '{') return out;
  while (i < n) {
    const c = text[i]!;
    if (c === '"') {
      const atKey = depth === 1;
      const s = readString();
      if (s === null) return out;
      if (atKey) {
        skipWs();
        if (text[i] !== ':') continue;
        i++;
        skipWs();
        if (s === 'id' || s === 'method') {
          if (text[i] === '"') {
            const v = readString();
            if (v === null) return out;
            if (s === 'id') out.id = v;
            else out.method = v;
          } else {
            const m = /^(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|null)/.exec(text.slice(i, i + 40));
            if (m && s === 'id') out.id = m[1] === 'null' ? null : Number(m[1]);
          }
          if (out.id !== undefined && out.method !== undefined) return out;
        }
      }
      continue;
    }
    if (c === '{' || c === '[') depth++;
    else if (c === '}' || c === ']') {
      depth--;
      if (depth === 0) return out;
    }
    i++;
  }
  return out;
}

function errorResponse(id: Id, code: number, message: string, data?: unknown): JSONRPCMessage {
  return { jsonrpc: '2.0', id, error: { code, message, ...(data !== undefined ? { data } : {}) } } as unknown as JSONRPCMessage;
}

export class GuardedStdioTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  private readonly max: number;
  private readonly maxOut: number;
  private readonly log: (line: string) => void;
  private chunks: Buffer[] = [];
  private pending = 0;
  /** Discarding an oversize line: the bytes seen so far and its kept head. */
  private oversize: { bytes: number; head: string } | null = null;
  private started = false;
  private closed = false;
  private era: Era = 'opening';

  constructor(
    private readonly stdin: NodeJS.ReadableStream = process.stdin,
    private readonly stdout: NodeJS.WritableStream = process.stdout,
    opts: GuardedStdioOptions = {},
  ) {
    this.max = opts.maxMessageBytes ?? maxMessageBytes();
    this.maxOut = opts.maxOutboundBytes ?? MAX_OUTBOUND_BYTES;
    this.log = opts.log ?? (() => {});
  }

  private readonly onData = (chunk: Buffer | string) => {
    try {
      this.ingest(typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk);
    } catch (err) {
      this.onerror?.(err instanceof Error ? err : new Error(String(err)));
    }
  };
  private readonly onEnd = () => {
    void this.close();
  };
  private readonly onErr = (err: Error) => this.onerror?.(err);
  private readonly onOutErr = (err: Error) => {
    if (this.closed) return;
    this.onerror?.(err);
    void this.close();
  };

  async start(): Promise<void> {
    if (this.started) throw new Error('GuardedStdioTransport already started');
    this.started = true;
    this.stdin.on('data', this.onData);
    this.stdin.on('error', this.onErr);
    this.stdin.on('end', this.onEnd);
    this.stdin.on('close', this.onEnd);
    this.stdout.on('error', this.onOutErr);
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.stdin.off('data', this.onData);
    this.stdin.off('error', this.onErr);
    this.stdin.off('end', this.onEnd);
    this.stdin.off('close', this.onEnd);
    // Late write failures after close are not errors (the client went away).
    this.stdout.off('error', this.onOutErr);
    this.stdout.on('error', () => {});
    (this.stdin as NodeJS.ReadableStream & { pause?: () => void }).pause?.();
    this.chunks = [];
    this.onclose?.();
  }

  send(message: JSONRPCMessage): Promise<void> {
    if (this.closed) return Promise.reject(new Error('stdio transport is closed'));
    let line = JSON.stringify(message) + '\n';
    const bytes = Buffer.byteLength(line);
    if (bytes > this.maxOut) {
      const m = message as { id?: unknown; result?: unknown; error?: unknown };
      if (m.id === undefined || (m.result === undefined && m.error === undefined)) {
        this.log(`stdio: dropped a ${bytes}-byte outbound notification (limit ${this.maxOut})`);
        return Promise.resolve();
      }
      this.log(`stdio: a ${bytes}-byte response to id ${JSON.stringify(m.id)} exceeds ${this.maxOut} bytes; answered with an error instead`);
      line =
        JSON.stringify(
          errorResponse(
            m.id as Id,
            -32603,
            `Response too large for stdio clients: ${bytes} bytes (limit ${this.maxOut}). Narrow the request (smaller budget, fewer results) or read the resource in parts.`,
            { bytes, limit: this.maxOut },
          ),
        ) + '\n';
    }
    return this.write(line);
  }

  private write(line: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const ok = this.stdout.write(line, (err) => {
        if (err) reject(err);
      });
      if (ok) resolve();
      else this.stdout.once('drain', () => resolve());
    });
  }

  private reply(message: JSONRPCMessage): void {
    if (this.closed) return;
    this.write(JSON.stringify(message) + '\n').catch((err: unknown) => this.onerror?.(err instanceof Error ? err : new Error(String(err))));
  }

  // ───────────────────────────── framing ─────────────────────────────

  private ingest(buf: Buffer): void {
    let start = 0;
    while (start < buf.length) {
      const nl = buf.indexOf(0x0a, start);
      const end = nl === -1 ? buf.length : nl;
      const piece = buf.subarray(start, end);
      if (this.oversize) {
        this.oversize.bytes += piece.length;
      } else if (this.pending + piece.length > this.max) {
        const head = Buffer.concat([...this.chunks, piece]).subarray(0, HEAD_KEEP).toString('utf8');
        this.oversize = { bytes: this.pending + piece.length, head };
        this.chunks = [];
        this.pending = 0;
      } else if (piece.length > 0) {
        this.chunks.push(Buffer.from(piece));
        this.pending += piece.length;
      }
      if (nl === -1) break;
      // end of line
      if (this.oversize) {
        const o = this.oversize;
        this.oversize = null;
        this.tooLarge(o.bytes, o.head);
      } else {
        const line = Buffer.concat(this.chunks).toString('utf8');
        this.chunks = [];
        this.pending = 0;
        this.line(line);
      }
      start = nl + 1;
    }
  }

  private tooLarge(bytes: number, head: string): void {
    const { id, method } = idFromPrefix(head.startsWith(BOM) ? head.slice(1) : head);
    this.log(`stdio: discarded a ${bytes}-byte message (limit ${this.max})${method ? ` (${method})` : ''}`);
    // Answered with the id when it is among the first bytes, else null (the id may come after the
    // params, so "no id seen" cannot tell a notification from a request).
    this.reply(
      errorResponse(
        id === undefined ? null : id,
        -32600,
        `Message too large: ${bytes} bytes exceeds the ${this.max}-byte limit (KRONICLE_LITE_MAX_MESSAGE_BYTES); the request was not processed`,
        { bytes, limit: this.max },
      ),
    );
  }

  private line(raw: string): void {
    let text = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    if (text.startsWith(BOM)) text = text.slice(1);
    if (text.trim().length === 0) return;
    let value: unknown;
    try {
      value = JSON.parse(text);
    } catch (err) {
      this.reply(errorResponse(null, -32700, `Parse error: ${err instanceof Error ? err.message : String(err)}`));
      return;
    }
    if (Array.isArray(value)) {
      this.batch(value);
      return;
    }
    let message: JSONRPCMessage;
    try {
      message = parseJSONRPCMessage(value);
    } catch {
      const id = isObj(value) && usableId(value['id']) ? value['id'] : null;
      // A malformed notification (method, no id) is dropped; anything else is answered.
      if (isObj(value) && value['id'] === undefined && typeof value['method'] === 'string') return;
      this.reply(errorResponse(id, -32600, 'Invalid Request: not a valid JSON-RPC 2.0 message (jsonrpc "2.0", a string method, params an object, an integer or string id)'));
      return;
    }
    this.dispatch(message);
  }

  private batch(items: unknown[]): void {
    if (items.length === 0) {
      this.reply(errorResponse(null, -32600, 'Invalid Request: empty batch'));
      return;
    }
    const replies = items
      .filter((x) => isObj(x) && usableId(x['id']) && x['method'] !== undefined)
      .map((x) =>
        errorResponse((x as { id: string | number }).id, -32600, 'Invalid Request: JSON-RPC batches are not supported (removed in MCP 2025-06-18); send each message on its own line'),
      );
    if (replies.length === 0) return;
    if (this.closed) return;
    this.write(JSON.stringify(replies) + '\n').catch(() => {});
  }

  // ───────────────────────────── lifecycle ─────────────────────────────

  private dispatch(message: JSONRPCMessage): void {
    const m = message as { id?: string | number; method?: string; params?: unknown };
    const isRequest = m.method !== undefined && m.id !== undefined;
    const isNotification = m.method !== undefined && m.id === undefined;

    // ping: answered here in every state and era (the SDK's 2026-07-28 instance has no handler).
    if (isRequest && m.method === 'ping' && this.era !== 'legacy') {
      this.reply({ jsonrpc: '2.0', id: m.id!, result: {} } as unknown as JSONRPCMessage);
      return;
    }

    if (this.era === 'opening' || this.era === 'probe') {
      if (!isRequest && !isNotification) {
        // A response before any handshake: the SDK discards it; pass it on.
        this.onmessage?.(message);
        return;
      }
      const c = classifyInboundRequest({ httpMethod: 'POST', body: message } as Parameters<typeof classifyInboundRequest>[0]) as { kind: string; reason?: string };
      if (c.kind === 'legacy') {
        if (isRequest && m.method === 'initialize') {
          this.era = 'legacy';
          this.onmessage?.(message);
          return;
        }
        if (isNotification) return; // no handshake yet: nothing to notify
        this.reply(
          errorResponse(
            m.id!,
            -32600,
            'Server not initialized: send initialize first (2025-era clients), or carry the 2026-07-28 envelope in params._meta ' +
              `("${PROTOCOL_VERSION_META_KEY}") on every request`,
          ),
        );
        return;
      }
      if (c.kind === 'modern' && isRequest && this.claimVersionOk(m.params)) {
        this.era = m.method === 'server/discover' && this.era === 'opening' ? 'probe' : 'modern';
      }
      // Rejections (bad envelope, unsupported version) and modern traffic: the SDK answers.
      this.onmessage?.(message);
      return;
    }

    if (this.era === 'modern' && isRequest && m.method !== 'initialize') {
      const meta = isObj(m.params) && isObj(m.params['_meta']) ? m.params['_meta'] : undefined;
      if (!meta || !(PROTOCOL_VERSION_META_KEY in meta)) {
        this.reply(
          errorResponse(m.id!, -32602, `Invalid _meta envelope: _meta: the per-request envelope ("${PROTOCOL_VERSION_META_KEY}") is required on protocol revision 2026-07-28`),
        );
        return;
      }
      const v = meta[PROTOCOL_VERSION_META_KEY];
      if (typeof v !== 'string' || !MODERN_VERSIONS.includes(v)) {
        const e = new UnsupportedProtocolVersionError({ supported: [...MODERN_VERSIONS], requested: typeof v === 'string' ? v : 'unknown' });
        this.reply(errorResponse(m.id!, e.code, e.message, e.data));
        return;
      }
    }
    this.onmessage?.(message);
  }

  private claimVersionOk(params: unknown): boolean {
    const meta = isObj(params) && isObj(params['_meta']) ? params['_meta'] : undefined;
    const v = meta?.[PROTOCOL_VERSION_META_KEY];
    return typeof v === 'string' && MODERN_VERSIONS.includes(v);
  }
}
