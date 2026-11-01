/**
 * Streamable HTTP serving (2026-07-28, plus 2025-era clients since 0.5.0).
 *
 * One endpoint, POST only, stateless: no session id is minted or honored, GET
 * and DELETE answer 405, per-request `_meta` carries the protocol version and
 * client capabilities. 2025-era (`initialize`) clients — Cursor's among them —
 * are served by the SDK's stateless legacy leg (`legacy: 'stateless'`): each
 * request gets a fresh server instance from the same factory, behind the same
 * Host/Origin/bearer checks. `modernOnly` restores the 0.3.0/0.4.0 behavior
 * (reject them with `UnsupportedProtocolVersionError`, -32022).
 *
 * Trust model: single tenant, one bearer token, loopback by default. Origin
 * and Host are validated against an allowlist (DNS-rebinding defence). See
 * docs/THREAT-MODEL.md "HTTP transport".
 */

import { createMcpHandler, type McpServerFactory } from '@modelcontextprotocol/server';
import { hostHeaderValidation, originValidation, toNodeHandler } from '@modelcontextprotocol/node';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer as createHttpServer, type IncomingMessage, type Server as NodeHttpServer, type ServerResponse } from 'node:http';
import { join } from 'node:path';

export const DEFAULT_HTTP_PORT = 7417;
export const DEFAULT_HTTP_PATH = '/mcp';
export const BEARER_FILE_NAME = 'http-bearer.token';

export interface HttpServeOptions {
  factory: McpServerFactory;
  /** Bearer token every request must present. Required; `loadOrCreateBearer` makes one. */
  bearer: string;
  host?: string;
  port?: number;
  path?: string;
  /** Extra Origin hostnames to accept besides loopback. */
  allowedOrigins?: string[];
  /** Extra Host header hostnames to accept besides loopback. */
  allowedHosts?: string[];
  /** 0.5.0: refuse 2025-era clients (-32022) instead of serving them statelessly. Default false. */
  modernOnly?: boolean;
  onerror?: (err: Error) => void;
}

export interface HttpServeHandle {
  server: NodeHttpServer;
  url: string;
  host: string;
  port: number;
  close(): Promise<void>;
}

const LOOPBACK = ['localhost', '127.0.0.1', '[::1]'];

/**
 * Read the bearer token from `<dataDir>/http-bearer.token`, creating a random
 * 256-bit one with mode 0600 when absent. Returns the token and whether it was
 * just created.
 */
export function loadOrCreateBearer(dataDir: string): { token: string; created: boolean; file: string } {
  const file = join(dataDir, BEARER_FILE_NAME);
  if (existsSync(file)) {
    const token = readFileSync(file, 'utf8').trim();
    if (token.length === 0) throw new Error(`${file} is empty; delete it to regenerate or pass --bearer`);
    return { token, created: false, file };
  }
  const token = randomBytes(32).toString('base64url');
  writeFileSync(file, token + '\n', { mode: 0o600, flag: 'wx' });
  chmodSync(file, 0o600);
  return { token, created: true, file };
}

export function readBearerFile(file: string): string {
  const token = readFileSync(file, 'utf8').trim();
  if (token.length === 0) throw new Error(`${file} is empty`);
  return token;
}

function bearerOf(req: IncomingMessage): string | null {
  const h = req.headers['authorization'];
  if (typeof h !== 'string') return null;
  const m = /^Bearer\s+(\S+)$/i.exec(h.trim());
  return m ? m[1]! : null;
}

function tokensEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

function reject(res: ServerResponse, status: number, message: string, headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
  res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32600, message }, id: null }));
}

/** Build the Node request listener without binding a socket (used by tests and `serveHttp`). */
export function createHttpListener(opts: HttpServeOptions): {
  listener: (req: IncomingMessage, res: ServerResponse) => void;
  close: () => Promise<void>;
} {
  if (!opts.bearer || opts.bearer.length < 16) throw new Error('bearer token must be at least 16 characters');
  const path = opts.path ?? DEFAULT_HTTP_PATH;
  const host = opts.host ?? '127.0.0.1';
  const allowedHosts = [...new Set([...LOOPBACK, host, ...(opts.allowedHosts ?? [])])];
  const allowedOrigins = [...new Set([...LOOPBACK, ...(opts.allowedOrigins ?? [])])];
  const validateHost = hostHeaderValidation(allowedHosts);
  const validateOrigin = originValidation(allowedOrigins);

  const handler = createMcpHandler(opts.factory, {
    legacy: opts.modernOnly === true ? 'reject' : 'stateless',
    ...(opts.onerror ? { onerror: opts.onerror } : {}),
  });
  const node = toNodeHandler(handler, opts.onerror ? { onerror: opts.onerror } : {});

  const listener = (req: IncomingMessage, res: ServerResponse): void => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (url.pathname !== path) {
      reject(res, 404, `not found; the MCP endpoint is ${path}`);
      return;
    }
    // Order: Host (rebinding) → Origin (browser cross-site) → bearer → MCP.
    if (!validateHost(req, res)) return;
    if (!validateOrigin(req, res)) return;
    const presented = bearerOf(req);
    if (presented === null || !tokensEqual(presented, opts.bearer)) {
      reject(res, 401, 'missing or invalid bearer token', { 'WWW-Authenticate': 'Bearer realm="kronicle-lite"' });
      return;
    }
    if (req.method !== 'POST') {
      // 2026-07-28: GET/DELETE session operations are not part of this revision.
      reject(res, 405, 'method not allowed; the MCP endpoint accepts POST only', { Allow: 'POST' });
      return;
    }
    // `exactOptionalPropertyTypes` disagrees with the SDK's duck type for `method?`; the shape is the same.
    void node(req as unknown as Parameters<typeof node>[0], res);
  };

  return { listener, close: () => handler.close() };
}

export async function serveHttp(opts: HttpServeOptions): Promise<HttpServeHandle> {
  const host = opts.host ?? '127.0.0.1';
  const port = opts.port ?? DEFAULT_HTTP_PORT;
  const path = opts.path ?? DEFAULT_HTTP_PATH;
  const { listener, close } = createHttpListener({ ...opts, host, port, path });
  const server = createHttpServer(listener);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      resolve();
    });
  });
  const addr = server.address();
  const boundPort = typeof addr === 'object' && addr ? addr.port : port;
  const displayHost = host.includes(':') ? `[${host}]` : host;
  return {
    server,
    host,
    port: boundPort,
    url: `http://${displayHost}:${boundPort}${path}`,
    close: async () => {
      await close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
