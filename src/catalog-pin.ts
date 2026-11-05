/**
 * The pinned MCP catalog fingerprints (see src/catalog.ts). No imports, so
 * any module (apply's confirm tokens bind the fingerprint) can read them
 * without pulling in the server.
 */

export const CATALOG_FINGERPRINT = '22d85066120b2840b7dd9a987853bf4d188157e4c29195945702bcb469c3e3f9';
/** Package version the fingerprint above was pinned for. */
export const CATALOG_VERSION = '0.9.0';
/** 0.6.0: the `serve --core` catalog (.mcp-catalog/kronicle-lite-core.json). */
export const CORE_CATALOG_FINGERPRINT = '18a336bb3830da7d04420c2d3344b952603e51fd08941ab54bc0b79bda7a2da4';
