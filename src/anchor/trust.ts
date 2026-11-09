/**
 * Anchor service key trust for the anchor client (`checkpoint --push`,
 * `verify --remote [--offline]`, `anchor status`, the MCP tools and doctor),
 * on the service's own key model (0.10.0): isokron-anchor src/core
 * genesis.ts / servicekeys.ts, vendored in ./service-core/.
 *
 *   - The published key list must be one signed chain from the genesis pin:
 *     the compiled production pin, or a self-hosted service's own
 *     (`--genesis`, KRONICLE_ANCHOR_GENESIS, or `anchor_genesis` in
 *     <data-dir>/config.json, as `<sha256>@<valid_from>`).
 *   - Every list fetched is first checked for rollback against the one kept
 *     for that service and pin in <data-dir>/anchor-keys.cache.json
 *     (keys-cache.ts, the service client's format).
 *   - A receipt counts only when its key is the current head:
 *     checkServiceKey with revoked 'reject' and nonHead 'reject'. This client
 *     checks no RFC 3161 tokens, and a receipt's received_at is signed by the
 *     same key, so a retired or revoked key's receipt is refused with a pointer
 *     to the verification page and `kronicle-lite verify-audit`, which weigh
 *     independent timestamps.
 *
 * Replaces 0.8.1's pin store (anchor-keys.pinned.json, first-use pinning,
 * operator pins and successor pins), which is no longer read.
 */

import { join } from 'node:path';

import type Database from 'better-sqlite3';

import { checkpointSigningPayload } from '../chain/chain.js';
import { chainIdFromPublicKeyPem } from '../crypto/keys.js';
import { AnchorConfigError, CONFIG_FILE, readConfigFile } from './config.js';
import { verifyEd25519Strict } from './ed25519-strict.js';
import { guardKeyList, KeyListRollbackError, readKeysCache, type KeysCacheScope, type ServiceKeys } from './keys-cache.js';
import { checkKeyChain, checkServiceKey, formatGenesisPin, keyListOf, parseGenesisPin, PRODUCTION_GENESIS, type GenesisPin, type ServiceKeyEntry } from './keychain.js';
import { parseAnchorReceipt, verifyAnchorReceiptSignature, type AnchorReceipt } from './receipt.js';

export const SERVICE_KEY_PREFIX = 'anchor-ed25519-';
/** 0.8.1–0.9.x pin store; no longer read (trust comes from the genesis pin). `anchor keys` and doctor mention it when present. */
export const LEGACY_PINS_FILE = 'anchor-keys.pinned.json';

/**
 * The production genesis service key, for reference and out-of-band checks:
 * IsoKron's audit-verification service (https://anchor.isokron.ai) signs with
 * anchor-ed25519-3dca1ecf66c2993e from 2026-11-01T02:29:25.705Z. The pin in
 * force is keychain.ts PRODUCTION_GENESIS; a test keeps the two equal.
 */
export const SHIPPED_SERVICE_KEYS: Readonly<Record<string, readonly { key_id: string; spki_sha256: string; public_key_pem: string; valid_from: string }[]>> = {
  'https://anchor.isokron.ai': [
    {
      key_id: 'anchor-ed25519-3dca1ecf66c2993e',
      spki_sha256: '3dca1ecf66c2993e534ff08fe350dc9368ca52042e38b20a9d58cd7c2b7b3367',
      public_key_pem: '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAvJAsc6UvXIKrZXFNO6jjSKKnkUKZvh2crVOyvrQqJm4=\n-----END PUBLIC KEY-----\n',
      valid_from: '2026-11-01T02:29:25.705Z',
    },
  ],
};

export class ServiceKeyTrustError extends Error {
  override readonly name = 'ServiceKeyTrustError';
}

/** "anchor-ed25519-" + first 16 hex of sha256(SPKI DER). Throws on a PEM that is not a public key. */
export function serviceKeyIdFromPem(pem: string): string {
  return `${SERVICE_KEY_PREFIX}${chainIdFromPublicKeyPem(pem).slice(0, 16)}`;
}

/** Where a genesis pin came from (reported by `anchor keys` and in errors). */
export type GenesisSource = 'option' | 'env' | 'config' | 'compiled';

/**
 * The genesis pin the service's key list must chain to: `override` (--genesis),
 * else KRONICLE_ANCHOR_GENESIS, else `anchor_genesis` in config.json, else the
 * compiled production pin. KRONICLE_ANCHOR_GENESIS_SHA256 and config.json
 * `service_key_pins` (the 0.8.1 pin store) are refused, not ignored.
 */
export function anchorGenesis(dataDir: string | null, override?: string): { pin: GenesisPin; source: GenesisSource } {
  if (process.env['KRONICLE_ANCHOR_GENESIS_SHA256'] !== undefined) {
    throw new AnchorConfigError("KRONICLE_ANCHOR_GENESIS_SHA256 is no longer read: set KRONICLE_ANCHOR_GENESIS=<sha256>@<valid_from> (the genesis key's valid_from is part of the pin)");
  }
  const j = dataDir ? readConfigFile(dataDir) : null;
  if (j && j['service_key_pins'] !== undefined) {
    throw new AnchorConfigError(
      `${join(dataDir!, CONFIG_FILE)}: service_key_pins is no longer read (0.10.0): trust comes from the anchor service's signed key chain back to its genesis key; for a self-hosted service set "anchor_genesis": "<sha256>@<valid_from>" instead, and remove service_key_pins`,
    );
  }
  const env = process.env['KRONICLE_ANCHOR_GENESIS'];
  const cfg = j?.['anchor_genesis'];
  const [raw, source]: [unknown, GenesisSource] =
    override !== undefined ? [override, 'option'] : env !== undefined && env !== '' ? [env, 'env'] : cfg !== undefined ? [cfg, 'config'] : [null, 'compiled'];
  if (source === 'compiled') return { pin: PRODUCTION_GENESIS, source };
  const pin = typeof raw === 'string' ? parseGenesisPin(raw) : null;
  if (!pin) {
    const what = source === 'option' ? '--genesis' : source === 'env' ? 'KRONICLE_ANCHOR_GENESIS' : `${join(dataDir!, CONFIG_FILE)} anchor_genesis`;
    throw new AnchorConfigError(`${what} must be <sha256>@<valid_from>: SHA-256 of the genesis service key's SPKI DER (64 hex) and its valid_from (ISO 8601 in UTC, ending in Z)`);
  }
  return { pin, source };
}

/** A key list this client may verify receipts with: it chains to `genesis` (usable) and passed the rollback check. */
export interface ServiceKeySet {
  anchor_url: string;
  genesis: GenesisPin;
  keys: ServiceKeyEntry[];
  /** fetched: from the service just now; kept: from the data dir's cache (offline). */
  source: 'fetched' | 'kept';
}

export interface KeyListCheck {
  /** null when the list is refused (rollback, not a key list, or it does not chain to the pin). */
  set: ServiceKeySet | null;
  notes: string[];
  /** The list is refused or broken; verification must fail. */
  violations: string[];
}

function judge(anchorUrl: string, genesis: GenesisPin, doc: unknown, source: ServiceKeySet['source']): KeyListCheck {
  const what = source === 'kept' ? `the key list kept for ${anchorUrl}` : `the service key list from ${anchorUrl}`;
  const keys = keyListOf(doc);
  if (!keys || keys.length === 0) return { set: null, notes: [], violations: [`${what} lists no keys`] };
  const kc = checkKeyChain(keys, genesis);
  if (!kc.usable) {
    const first = kc.entries.find((e) => e.state === 'broken' && !e.revoked_ancestor);
    return {
      set: null,
      notes: [],
      violations: [`${what} does not chain to the genesis pin ${formatGenesisPin(genesis)}: ${first ? `${first.key_id}: ${first.detail}` : kc.detail}`],
    };
  }
  const notes: string[] = [];
  const untrusted = kc.entries.filter((e) => e.revoked_ancestor);
  if (untrusted.length) notes.push(`${what}: ${untrusted.map((e) => e.key_id).join(', ')} not trusted (after revoked ${untrusted[0]!.revoked_ancestor}); their receipts fail until a release pins a new genesis key`);
  return { set: { anchor_url: anchorUrl, genesis, keys, source }, notes, violations: [] };
}

/**
 * A key list fetched from `anchorUrl`: the rollback check against the kept
 * record first (a refusal is a violation, and nothing is verified with it),
 * then the chain check against `genesis`. A usable list becomes the kept one.
 */
export function acceptServiceKeys(scope: KeysCacheScope, anchorUrl: string, genesis: GenesisPin, doc: unknown): KeyListCheck {
  let cacheNotes: string[];
  try {
    cacheNotes = guardKeyList(scope, anchorUrl, doc, genesis);
  } catch (e) {
    if (e instanceof KeyListRollbackError) return { set: null, notes: [], violations: [e.message] };
    throw e;
  }
  const r = judge(anchorUrl, genesis, doc, 'fetched');
  r.notes.unshift(...cacheNotes);
  if (!scope.dataDir) r.notes.push('key list rollback check: in-memory store, nothing kept between runs');
  return r;
}

/** The key list kept for `anchorUrl` and `genesis` (offline). */
export function keptServiceKeys(scope: KeysCacheScope, anchorUrl: string, genesis: GenesisPin): KeyListCheck {
  let kept: ServiceKeys | null;
  try {
    kept = readKeysCache(scope, anchorUrl, genesis);
  } catch (e) {
    if (e instanceof KeyListRollbackError) return { set: null, notes: [], violations: [e.message] };
    throw e;
  }
  if (!kept) return { set: null, notes: [], violations: [`no anchor service key list kept for ${anchorUrl} and genesis ${formatGenesisPin(genesis)}; run verify --remote online once`] };
  return judge(anchorUrl, genesis, kept, 'kept');
}

export type TrustedReceiptResult = { ok: true; receipt: AnchorReceipt } | { ok: false; reason: string; claimed: AnchorReceipt | null };

/**
 * Parse + countersignature against the key list, with the service's
 * checkServiceKey (revoked 'reject', nonHead 'reject'): only the current head
 * key vouches here. A retired or revoked key's receipt needs an independent
 * RFC 3161 time inside the key's window, which this client does not check.
 */
export function verifyReceiptWithKeys(input: unknown, set: ServiceKeySet | null): TrustedReceiptResult {
  const parsed = parseAnchorReceipt(input);
  if (!parsed.ok) return { ok: false, reason: `anchor receipt malformed: ${parsed.detail}`, claimed: null };
  const r = parsed.value;
  if (!set) return { ok: false, reason: 'no trusted anchor service key list (see the key list problem above)', claimed: r };
  const c = checkServiceKey(set.keys, r.service_key_id, r.received_at, set.genesis, { revoked: 'reject', nonHead: 'reject' });
  if (!c.ok) {
    const where = `verify independent timestamps at ${set.anchor_url.replace(/\/+$/, '')}/v/${r.chain_id} or with \`kronicle-lite verify-audit\` on an Evidence Pack`;
    if (c.revoked) return { ok: false, reason: `revoked key: ${r.service_key_id} is revoked (compromised since ${c.revoked.compromised_since}); its receipts count only with an RFC 3161 time before that: ${where}`, claimed: r };
    if (c.retired) return { ok: false, reason: `${r.service_key_id} is retired (valid to ${c.retired.valid_to}); its receipts count only with an RFC 3161 time inside its window: ${where}`, claimed: r };
    return { ok: false, reason: `service key ${r.service_key_id}: ${c.detail}`, claimed: r };
  }
  if (!verifyAnchorReceiptSignature(r, c.entry.public_key_pem)) return { ok: false, reason: 'anchor receipt countersignature does not verify against the service key', claimed: r };
  return { ok: true, receipt: r };
}

/**
 * Tie a countersigned receipt to this chain: its checkpoint key is a local
 * signing key, receipt.chain_id derives from that key (and equals
 * `expectedChainId` when given), and the checkpoint signature verifies
 * against it. null when all hold, else why not.
 */
export function receiptChainRefusal(db: Database.Database, receipt: AnchorReceipt, expectedChainId: string | null): string | null {
  if (expectedChainId !== null && receipt.chain_id !== expectedChainId) {
    return `receipt is for chain ${receipt.chain_id.slice(0, 16)}…, not this chain ${expectedChainId.slice(0, 16)}…`;
  }
  const row = db.prepare(`SELECT public_key_pem FROM signing_keys WHERE key_id = ?`).get(receipt.checkpoint.key_id) as { public_key_pem: string } | undefined;
  if (!row) return `receipt checkpoint key ${receipt.checkpoint.key_id} is not a local signing key`;
  let localChain: string;
  try {
    localChain = chainIdFromPublicKeyPem(row.public_key_pem);
  } catch {
    return `local signing key ${receipt.checkpoint.key_id} is unreadable`;
  }
  if (localChain !== receipt.chain_id) return `receipt chain_id ${receipt.chain_id.slice(0, 16)}… does not derive from local key ${receipt.checkpoint.key_id}`;
  if (!verifyEd25519Strict(row.public_key_pem, checkpointSigningPayload(receipt.checkpoint), receipt.checkpoint.signature)) {
    return 'receipt checkpoint signature does not verify against the local chain key';
  }
  return null;
}
