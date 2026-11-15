/**
 * The pinned MCP catalog fingerprints (see src/catalog.ts). No imports, so
 * any module (apply's confirm tokens bind the fingerprint) can read them
 * without pulling in the server.
 */

export const CATALOG_FINGERPRINT = 'd31f975b0c67426ee2586849b4195b08ead73b7f70ffca5762f5d81b88f8e439';
/** Package version the fingerprint above was pinned for. */
export const CATALOG_VERSION = '0.11.2';
/** 0.6.0: the `serve --core` catalog (.mcp-catalog/kronicle-lite-core.json). */
export const CORE_CATALOG_FINGERPRINT = 'f8d2b0aea9972c539297d3261f83125fa74d066b49ddd995279a2cd182c4daeb';
