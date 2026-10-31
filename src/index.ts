/**
 * kronicle-lite public API. Most users want the CLI (`kronicle-lite serve`);
 * this module is for embedding the store or building another transport.
 */

export { KronicleLite, type KronicleLiteOptions } from './store.js';
export { createServer, renderSystemStateMarkdown, type ServerOptions } from './server.js';
export * from './chain/index.js';
export { canonicalize, type JsonValue } from './crypto/canonical.js';
export { sha256Hex, blake3Hex } from './crypto/hash.js';
export { verifyEd25519, type Signer, type ServerIdentity } from './crypto/keys.js';
export { openDatabase, defaultDataDir, type Db, type OpenOptions, type Opened } from './db/open.js';
export { SCHEMA_SQL, SCHEMA_VERSION } from './db/schema.js';
export {
  DocumentStore,
  DocumentError,
  planRevision,
  type BlockRow,
  type DocumentRow,
  type PutDocumentResult,
  type SupersedeBlockResult,
  type TombstoneBlockResult,
} from './docs/documents.js';
export { parseMarkdown, renderBlocks, normalizeMarkdown, type ParsedBlock, type BlockKind } from './docs/parser.js';
export * from './recall/receipt.js';
export { Recall, toMatchExpression, type RecallInput, type RecallResult, type RecallHit } from './recall/recall.js';
export { ReceiptVerifier, VERIFY_REASONS, type VerifyResult, type VerifyStatus, type VerifyReason } from './recall/verify-receipt.js';
export * from './orient/index.js';
