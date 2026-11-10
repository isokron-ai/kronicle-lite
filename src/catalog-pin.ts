/**
 * The pinned MCP catalog fingerprints (see src/catalog.ts). No imports, so
 * any module (apply's confirm tokens bind the fingerprint) can read them
 * without pulling in the server.
 */

export const CATALOG_FINGERPRINT = 'ebd2f0092cb3a7a9e94dae9825384bf6110d464273bd5811e84a1e20c70ed4d6';
/** Package version the fingerprint above was pinned for. */
export const CATALOG_VERSION = '0.10.2';
/** 0.6.0: the `serve --core` catalog (.mcp-catalog/kronicle-lite-core.json). */
export const CORE_CATALOG_FINGERPRINT = '4fa11b1848b3c8fa19d1eeeef47d91e60b81e9a8bdcf8430bbc5b095c3002c6a';
