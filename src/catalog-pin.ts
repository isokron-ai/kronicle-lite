/**
 * The pinned MCP catalog fingerprints (see src/catalog.ts). No imports, so
 * any module (apply's confirm tokens bind the fingerprint) can read them
 * without pulling in the server.
 */

export const CATALOG_FINGERPRINT = '0b5ef071a0d63b2371a54cefe8d1f3ee3845e2d41069de17adf1b804be7bea88';
/** Package version the fingerprint above was pinned for. */
export const CATALOG_VERSION = '0.12.1';
/** 0.6.0: the `serve --core` catalog (.mcp-catalog/kronicle-lite-core.json). */
export const CORE_CATALOG_FINGERPRINT = '4dc777b01f0a5a8215fb29d651d4353f0fb23af67dc0252010797c04fbfbd328';
