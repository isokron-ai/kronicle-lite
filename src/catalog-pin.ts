/**
 * The pinned MCP catalog fingerprints (see src/catalog.ts). No imports, so
 * any module (apply's confirm tokens bind the fingerprint) can read them
 * without pulling in the server.
 */

export const CATALOG_FINGERPRINT = '0bee094f8e840a4f02fdf4cb75356c9e8978a139572f70790dd52224a35cf7f4';
/** Package version the fingerprint above was pinned for. */
export const CATALOG_VERSION = '0.9.0';
/** 0.6.0: the `serve --core` catalog (.mcp-catalog/kronicle-lite-core.json). */
export const CORE_CATALOG_FINGERPRINT = 'e6dcc147cc205958704c5bf075c7d8940dcb2a1759e35b4fd220fbc700f92a00';
