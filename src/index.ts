/**
 * kronicle-lite public API. Most users want the CLI (`kronicle-lite serve`);
 * this module is for embedding the store or building another transport.
 */

export { KronicleLite, type KronicleLiteOptions } from './store.js';
export { createServer, createServerFactory, renderSystemStateMarkdown, anchorLine, INSTRUCTIONS, CACHE_HINTS, type ServerOptions } from './server.js';
export { serveHttp, createHttpListener, loadOrCreateBearer, DEFAULT_HTTP_PORT, DEFAULT_HTTP_PATH, type HttpServeOptions, type HttpServeHandle } from './http.js';
export * as toolSchemas from './schemas.js';
export * from './chain/index.js';
export { canonicalize, type JsonValue } from './crypto/canonical.js';
export { sha256Hex, blake3Hex } from './crypto/hash.js';
export { verifyEd25519, chainIdFromPublicKeyPem, keyIdFromPublicKey, type Signer, type ServerIdentity } from './crypto/keys.js';
export { openDatabase, defaultDataDir, type Db, type OpenOptions, type Opened } from './db/open.js';
export { SCHEMA_SQL, SCHEMA_VERSION } from './db/schema.js';
export {
  DocumentStore,
  DocumentError,
  planRevision,
  isValidSlug,
  isInstructionSlug,
  SLUG_RE,
  PATH_SLUG_RE,
  type DocumentSource,
  type GitBinding,
  type SourceDrift,
  type BlockRow,
  type DocumentRow,
  type PutDocumentResult,
  type SupersedeBlockResult,
  type TombstoneBlockResult,
} from './docs/documents.js';
export { parseMarkdown, renderBlocks, normalizeMarkdown, type ParsedBlock, type BlockKind } from './docs/parser.js';
export * from './recall/receipt.js';
export { Recall, toMatchExpression, type RecallInput, type RecallResult, type RecallHit } from './recall/recall.js';
export { ReceiptVerifier, VERIFY_REASONS, VERIFY_STATUSES, type VerifyResult, type VerifyStatus, type VerifyReason } from './recall/verify-receipt.js';
export * from './orient/index.js';
export * as anchor from './anchor/index.js';
export * as instructions from './instructions/index.js';
export { InstructionWatcher, syncInstructionSet, resolveWatchSet, type WatchOptions, type WatchEvent } from './instructions/watch.js';
export { syncInstructionFile, type SyncResult } from './instructions/sync.js';
export { bindGit, checkGitBinding, diffStat, type BindResult, type SourceCheck, type DiffStat } from './git/binding.js';
export {
  pushCheckpoint,
  tryPushCheckpoint,
  verifyRemote,
  anchorStatus,
  verifyLastAnchor,
  type PushResult,
  type PushOutcome,
  type VerifyRemoteResult,
  type AnchorStatus,
} from './anchor/anchor.js';
export { AnchorClient, AnchorApiError, AnchorUnreachableError } from './anchor/client.js';
export { DEFAULT_ANCHOR_URL, loadConfig as loadAnchorConfig, type AnchorConfig } from './anchor/config.js';
