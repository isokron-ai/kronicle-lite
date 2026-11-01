/**
 * The MCP catalog this build is supposed to serve, and a way to measure the
 * one it actually serves. `doctor` compares the two, so a stale global
 * install, a half-upgraded dist or a patched copy shows up as drift.
 *
 * CATALOG_FINGERPRINT is the `sha256` that `npm run catalog:snapshot` pins in
 * .mcp-catalog/kronicle-lite.json; test/catalog.test.ts fails when either the
 * constant, the snapshot or the package version disagree, so re-snapshotting
 * means updating this file in the same commit.
 *
 * Fingerprint recipe (mcp-catalog-snap/1): sha256 of the RFC 8785 JSON of
 * { tools (by name), prompts (by name), resourceTemplates (by uriTemplate) }.
 */

import { createMcpHandler } from '@modelcontextprotocol/server';

import { canonicalize } from './crypto/canonical.js';
import { sha256Hex } from './crypto/hash.js';
import { createServerFactory } from './server.js';
import { KronicleLite } from './store.js';

export const CATALOG_FINGERPRINT = 'fa8d1d6f50b1c461af859c6520515c621c7aee09be19f516a03e366b42a48dee';
/** Package version the fingerprint above was pinned for. */
export const CATALOG_VERSION = '0.3.0';

const MODERN = '2026-07-28';

function byKey<T extends Record<string, unknown>>(key: string) {
  return (a: T, b: T) => {
    const ka = String(a[key]);
    const kb = String(b[key]);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  };
}

/**
 * Serve tools/list and resources/templates/list in-process (no socket, an
 * in-memory store) through the same SDK entry `serve --http` uses, and
 * fingerprint the result.
 */
export async function liveCatalogFingerprint(): Promise<{ fingerprint: string; tools: number; resourceTemplates: number }> {
  const store = new KronicleLite({ memory: true });
  const handler = createMcpHandler(createServerFactory(store), {});
  try {
    const call = async (method: string): Promise<Record<string, unknown>> => {
      const res = await handler.fetch(
        new Request('http://localhost/mcp', {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            accept: 'application/json, text/event-stream',
            'mcp-protocol-version': MODERN,
            'mcp-method': method,
          },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method,
            params: { _meta: { 'io.modelcontextprotocol/protocolVersion': MODERN, 'io.modelcontextprotocol/clientCapabilities': {} } },
          }),
        }),
      );
      let text = await res.text();
      if (text.startsWith('event:') || text.startsWith('data:')) {
        const data = text.split('\n').find((l) => l.startsWith('data:'));
        text = data ? data.slice(5).trim() : '{}';
      }
      const j = JSON.parse(text) as { result?: Record<string, unknown>; error?: { message: string } };
      if (!j.result) throw new Error(`${method}: ${j.error?.message ?? 'no result'}`);
      return j.result;
    };
    const tools = ((await call('tools/list'))['tools'] as Record<string, unknown>[]).sort(byKey('name'));
    const resourceTemplates = ((await call('resources/templates/list'))['resourceTemplates'] as Record<string, unknown>[]).sort(byKey('uriTemplate'));
    const fingerprint = sha256Hex(canonicalize({ tools, prompts: [], resourceTemplates }));
    return { fingerprint, tools: tools.length, resourceTemplates: resourceTemplates.length };
  } finally {
    await handler.close();
    store.close();
  }
}
