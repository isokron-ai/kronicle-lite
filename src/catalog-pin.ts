/**
 * The pinned MCP catalog fingerprints (see src/catalog.ts). No imports, so
 * any module (apply's confirm tokens bind the fingerprint) can read them
 * without pulling in the server.
 */

export const CATALOG_FINGERPRINT = 'e637c91cb88459555de409fdd3b52b1055faef81f116d91c0ecb20e627a276fd';
/** Package version the fingerprint above was pinned for. */
export const CATALOG_VERSION = '0.10.0';
/** 0.6.0: the `serve --core` catalog (.mcp-catalog/kronicle-lite-core.json). */
export const CORE_CATALOG_FINGERPRINT = '4fa11b1848b3c8fa19d1eeeef47d91e60b81e9a8bdcf8430bbc5b095c3002c6a';
