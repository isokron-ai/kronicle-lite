/**
 * kronicle-lite/core: the store, the chain and the crypto helpers, without the
 * MCP server, its tool schemas, the HTTP transport, doctor, anchor or the shim.
 *
 * For embedders that open the store from a short-lived process (a hook, a CLI
 * that answers one question and exits): this entry does not load the MCP SDK
 * or the server code the main entry (`kronicle-lite`) pulls in. Everything
 * here is also exported, unchanged, from the main entry.
 */

export { KronicleLite, type KronicleLiteOptions } from './store.js';
export * from './chain/index.js';
export { canonicalize, type JsonValue } from './crypto/canonical.js';
export { sha256Hex, blake3Hex } from './crypto/hash.js';
export { verifyEd25519, chainIdFromPublicKeyPem, keyIdFromPublicKey, type Signer, type ServerIdentity } from './crypto/keys.js';
export { openDatabase, defaultDataDir, type Db, type OpenOptions, type Opened } from './db/open.js';
export { SCHEMA_SQL, SCHEMA_VERSION } from './db/schema.js';
export {
  scanForSecrets,
  redactSecrets,
  scrubForRead,
  scrubDeep,
  scanValue,
  guardFields,
  SecretDetectedError,
  WRITE_DETECTORS,
  type SecretFinding,
  type SecretPolicy,
} from './secrets/guard.js';
