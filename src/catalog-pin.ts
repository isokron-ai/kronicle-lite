/**
 * The pinned MCP catalog fingerprints (see src/catalog.ts). No imports, so
 * any module (apply's confirm tokens bind the fingerprint) can read them
 * without pulling in the server.
 */

export const CATALOG_FINGERPRINT = 'b6d64f0dfe9624374e3c964a665bc8a25698753a3f3f46f929bad527e3cbb47c';
/** Package version the fingerprint above was pinned for. */
export const CATALOG_VERSION = '0.11.2';
/** 0.6.0: the `serve --core` catalog (.mcp-catalog/kronicle-lite-core.json). */
export const CORE_CATALOG_FINGERPRINT = 'b4f0c16456e32c3b23a7c8dd77c6b583485085bfb0452a291bbecb6c7e7c6af3';
