/**
 * Service-key pinning and receipt trust (0.8.1, hardening track 6: A2-01,
 * A2-04, A2-11, A2-12).
 *
 * The anchor service publishes its keys at /.well-known/anchor-keys.json,
 * which is the same channel the receipts come over. Trusting whatever that
 * document says on every run lets anyone between the box and the service
 * (or anyone who controls `anchor_url`) publish their own key and re-sign
 * receipts. So the client keeps a local trust store:
 *
 *   <data-dir>/anchor-keys.pinned.json   mode 0600
 *
 * Sources of trust, strongest first:
 *   - shipped: SHIPPED_SERVICE_KEY_PINS for the configured origin (part of the
 *     package; disables first-use pinning for that origin)
 *   - config:  `service_key_pins: [<PEM>, …]` in <data-dir>/config.json
 *     (also disables first-use pinning)
 *   - tofu:    the first key document fetched when nothing at all is pinned
 *   - operator: `kronicle-lite anchor keys add <pem-file>`
 *   - successor: a new key in the document whose `successor_signature` is a
 *     valid Ed25519 signature by an already-pinned key (`signed_by`) over
 *     canonicalize({key_id, public_key_pem, valid_from}) — the rotation shape
 *     isokron-anchor publishes (src/servicekey.ts).
 *
 * A pinned public key is never replaced from the network. A key document
 * entry whose key_id does not derive from its public key, or that names a
 * pinned key_id with a different public key, is a violation (verify fails).
 * Status and validity metadata from the network can only tighten a pin
 * (active → retired → revoked; valid_to only moves earlier).
 */

import { chmodSync, existsSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import type Database from 'better-sqlite3';

import { checkpointSigningPayload } from '../chain/chain.js';
import { canonicalize } from '../crypto/canonical.js';
import { chainIdFromPublicKeyPem } from '../crypto/keys.js';
import { AnchorConfigError, CONFIG_FILE, readConfigFile } from './config.js';
import { parseAnchorReceipt, verifyAnchorReceiptSignature, type AnchorReceipt } from './receipt.js';
import { isUsableEd25519PublicKeyPem, verifyEd25519Strict } from './ed25519-strict.js';
import { isJsonObject } from './wire.js';

export const SERVICE_KEY_PREFIX = 'anchor-ed25519-';
export const PINS_FILE = 'anchor-keys.pinned.json';

/**
 * Service keys shipped with the package, by anchor origin. A non-empty list
 * for an origin is authoritative: first-use pinning is off for it and only
 * these keys (and successors they sign) are trusted. Empty until the
 * production key is published through a channel other than the service
 * itself; until then the production origin uses first-use pinning.
 */
export const SHIPPED_SERVICE_KEY_PINS: Readonly<Record<string, readonly string[]>> = {
  'https://anchor.isokron.ai': [],
};

/** Statuses a service key may have and still vouch for a receipt (inside its validity window). */
export const ACCEPTED_SERVICE_KEY_STATUSES = ['active', 'retired'] as const;

export type PinSource = 'shipped' | 'config' | 'tofu' | 'operator' | 'successor';

export interface PinnedServiceKey {
  key_id: string;
  public_key_pem: string;
  status: string;
  valid_from: string | null;
  valid_to: string | null;
  source: PinSource;
  pinned_at: string;
  /** For a successor pin: the pinned key whose signature admitted it. */
  signed_by: string | null;
  /** Anchor URL the pin was learned from (informational). */
  issuer: string | null;
}

export class ServiceKeyTrustError extends Error {
  override readonly name = 'ServiceKeyTrustError';
}

export interface PinScope {
  readonly dataDir: string | null;
}

/** "anchor-ed25519-" + first 16 hex of sha256(SPKI DER). Throws on a PEM that is not a public key. */
export function serviceKeyIdFromPem(pem: string): string {
  return `${SERVICE_KEY_PREFIX}${chainIdFromPublicKeyPem(pem).slice(0, 16)}`;
}

function spkiHash(pem: string): string | null {
  try {
    return chainIdFromPublicKeyPem(pem);
  } catch {
    return null;
  }
}

/** Ed25519 SPKI PEM with a canonical, non-small-order point (A2-09). */
function isEd25519Pem(pem: string): boolean {
  return isUsableEd25519PublicKeyPem(pem);
}

function originOf(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return url.replace(/\/+$/, '');
  }
}

// ───────────────────────────── pin file ─────────────────────────────

const memoryPins = new WeakMap<PinScope, PinnedServiceKey[]>();

function pinsPath(dataDir: string): string {
  return join(dataDir, PINS_FILE);
}

/** File-backed pins (tofu/operator/successor, plus metadata for config/shipped keys). Fails closed on a corrupt file. */
export function readPinFile(scope: PinScope): PinnedServiceKey[] {
  if (!scope.dataDir) return [...(memoryPins.get(scope) ?? [])];
  const p = pinsPath(scope.dataDir);
  if (!existsSync(p)) return [];
  let j: unknown;
  try {
    j = JSON.parse(readFileSync(p, 'utf8'));
  } catch {
    throw new ServiceKeyTrustError(`${p} is not valid JSON; fix it or run \`kronicle-lite anchor keys reset\` to pin again on next use`);
  }
  if (!isJsonObject(j) || !Array.isArray(j['keys'])) {
    throw new ServiceKeyTrustError(`${p} has no keys array; fix it or run \`kronicle-lite anchor keys reset\``);
  }
  const out: PinnedServiceKey[] = [];
  for (const k of j['keys'] as unknown[]) {
    if (!isJsonObject(k) || typeof k['key_id'] !== 'string' || typeof k['public_key_pem'] !== 'string') {
      throw new ServiceKeyTrustError(`${p} holds a malformed key entry; fix it or run \`kronicle-lite anchor keys reset\``);
    }
    const str = (x: unknown) => (typeof x === 'string' ? x : null);
    out.push({
      key_id: k['key_id'],
      public_key_pem: k['public_key_pem'],
      status: str(k['status']) ?? 'active',
      valid_from: str(k['valid_from']),
      valid_to: str(k['valid_to']),
      source: (str(k['source']) ?? 'tofu') as PinSource,
      pinned_at: str(k['pinned_at']) ?? '',
      signed_by: str(k['signed_by']),
      issuer: str(k['issuer']),
    });
  }
  return out;
}

export function writePinFile(scope: PinScope, keys: PinnedServiceKey[]): void {
  if (!scope.dataDir) {
    memoryPins.set(scope, keys.map((k) => ({ ...k })));
    return;
  }
  const p = pinsPath(scope.dataDir);
  const tmp = `${p}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify({ v: 1, keys }, null, 2) + '\n', { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, p);
}

/** `anchor keys reset`: forget every file-backed pin. Returns true when something was removed. */
export function resetPins(scope: PinScope): boolean {
  if (!scope.dataDir) return memoryPins.delete(scope);
  const p = pinsPath(scope.dataDir);
  if (!existsSync(p)) return false;
  unlinkSync(p);
  return true;
}

/** `service_key_pins` from config.json: an array of PEM strings. Fails closed on anything else. */
export function readConfigPins(dataDir: string | null): string[] {
  if (!dataDir) return [];
  const j = readConfigFile(dataDir);
  const v = j?.['service_key_pins'];
  if (v === undefined) return [];
  if (!Array.isArray(v) || !v.every((x) => typeof x === 'string')) {
    throw new AnchorConfigError(`${join(dataDir, CONFIG_FILE)}: service_key_pins must be an array of PEM strings`);
  }
  for (const pem of v as string[]) {
    if (!isEd25519Pem(pem)) throw new AnchorConfigError(`${join(dataDir, CONFIG_FILE)}: service_key_pins holds something that is not an Ed25519 public key PEM`);
  }
  return v as string[];
}

function anchorPin(pem: string, source: PinSource, issuer: string | null): PinnedServiceKey {
  return {
    key_id: serviceKeyIdFromPem(pem),
    public_key_pem: pem,
    status: 'active',
    valid_from: null,
    valid_to: null,
    source,
    pinned_at: new Date().toISOString(),
    signed_by: null,
    issuer,
  };
}

/**
 * The keys this data dir trusts for `anchor_url`: shipped + config pins
 * (authoritative) and file pins. File entries for config/shipped keys only
 * carry metadata; they are trusted while the key is still configured.
 */
export function trustedServiceKeys(scope: PinScope, anchorUrl: string): { keys: PinnedServiceKey[]; authoritative: boolean } {
  const file = readPinFile(scope);
  const fixed: PinnedServiceKey[] = [
    ...(SHIPPED_SERVICE_KEY_PINS[originOf(anchorUrl)] ?? []).map((pem) => anchorPin(pem, 'shipped', originOf(anchorUrl))),
    ...readConfigPins(scope.dataDir).map((pem) => anchorPin(pem, 'config', null)),
  ];
  const byId = new Map<string, PinnedServiceKey>();
  for (const f of fixed) {
    const meta = file.find((k) => k.key_id === f.key_id && spkiHash(k.public_key_pem) === spkiHash(f.public_key_pem));
    byId.set(f.key_id, meta ? { ...meta, public_key_pem: f.public_key_pem, source: f.source } : f);
  }
  for (const k of file) {
    if (k.source === 'shipped' || k.source === 'config') continue; // metadata only
    const have = byId.get(k.key_id);
    if (have) {
      if (spkiHash(have.public_key_pem) !== spkiHash(k.public_key_pem)) {
        throw new ServiceKeyTrustError(`${PINS_FILE} pins ${k.key_id} with a different public key than the configured pin; fix one of them`);
      }
      continue;
    }
    byId.set(k.key_id, k);
  }
  return { keys: [...byId.values()], authoritative: fixed.length > 0 };
}

// ───────────────────────────── key document ─────────────────────────────

const STATUS_RANK: Record<string, number> = { active: 0, retired: 1 };
const rank = (s: string) => STATUS_RANK[s] ?? 2;

function laterIso(a: string | null, b: string | null): string | null {
  if (a === null) return b;
  if (b === null) return a;
  return Date.parse(b) > Date.parse(a) ? b : a;
}
function earlierIso(a: string | null, b: string | null): string | null {
  if (a === null) return b;
  if (b === null) return a;
  return Date.parse(b) < Date.parse(a) ? b : a;
}

/** Tighten-only merge of network metadata into a pin. */
function tighten(pin: PinnedServiceKey, fresh: { status: string; valid_from: string | null; valid_to: string | null }): PinnedServiceKey {
  const status = rank(fresh.status) > rank(pin.status) ? fresh.status : pin.status;
  return { ...pin, status, valid_from: laterIso(pin.valid_from, fresh.valid_from), valid_to: earlierIso(pin.valid_to, fresh.valid_to) };
}

interface DocEntry {
  key_id: string;
  public_key_pem: string;
  status: string;
  valid_from: string | null;
  valid_to: string | null;
  successor_signature: string | null;
  signed_by: string | null;
}

export interface KeyReconciliation {
  /** The trust set after this document (what receipts are checked against). */
  keys: PinnedServiceKey[];
  /** Informational: what was pinned or ignored. */
  notes: string[];
  /** The document contradicts the pins or itself; verification must fail. */
  violations: string[];
}

/**
 * Merge a fetched key document into the trust store under the pinning rules
 * and return the trust set. Persists new pins and tightened metadata; never
 * replaces a pinned public key.
 */
export function reconcileServiceKeys(scope: PinScope, anchorUrl: string, doc: unknown): KeyReconciliation {
  const notes: string[] = [];
  const violations: string[] = [];
  const { keys: trusted0, authoritative } = trustedServiceKeys(scope, anchorUrl);
  const filePins = readPinFile(scope);
  const origin = originOf(anchorUrl);

  const entries: DocEntry[] = [];
  const raw = isJsonObject(doc) && Array.isArray(doc['keys']) ? (doc['keys'] as unknown[]) : [];
  if (raw.length === 0) violations.push(`service key document from ${origin} lists no keys`);
  for (const e of raw) {
    if (!isJsonObject(e) || typeof e['key_id'] !== 'string' || typeof e['public_key_pem'] !== 'string') {
      violations.push(`service key document from ${origin} holds a malformed entry`);
      continue;
    }
    const key_id = e['key_id'];
    const pem = e['public_key_pem'];
    if (!isEd25519Pem(pem)) {
      violations.push(`service key ${key_id} from ${origin}: public_key_pem is not a usable Ed25519 public key (malformed, non-canonical or small order)`);
      continue;
    }
    const derived = serviceKeyIdFromPem(pem);
    if (derived !== key_id) {
      violations.push(`service key document from ${origin} lists ${key_id} with a public key that derives to ${derived}; refusing it (possible man-in-the-middle)`);
      continue;
    }
    const s = (x: unknown) => (typeof x === 'string' ? x : null);
    entries.push({
      key_id,
      public_key_pem: pem,
      status: s(e['status']) ?? 'active',
      valid_from: s(e['valid_from']),
      valid_to: s(e['valid_to']),
      successor_signature: s(e['successor_signature']),
      signed_by: s(e['signed_by']),
    });
  }

  // Same rules the service applies (isokron-anchor src/core/servicekeys.ts):
  // a key_id listed twice, or a successor_signature that does not verify
  // against a listed, trusted predecessor, disqualifies the entry.
  const counts = new Map<string, number>();
  for (const e of entries) counts.set(e.key_id, (counts.get(e.key_id) ?? 0) + 1);
  for (let i = entries.length - 1; i >= 0; i--) {
    const e = entries[i]!;
    const why = (counts.get(e.key_id) ?? 0) > 1 ? `${e.key_id} is listed more than once` : successionRefusal(e, entries);
    if (why) {
      violations.push(`service key document from ${origin}: ${why}; refusing it`);
      entries.splice(i, 1);
    }
  }

  const trust = new Map(trusted0.map((k) => [k.key_id, k]));
  const file = new Map(filePins.map((k) => [k.key_id, k]));
  let dirty = false;
  const now = new Date().toISOString();

  // Pinned keys: the public key must match; metadata may only tighten.
  for (const e of entries) {
    const pin = trust.get(e.key_id);
    if (!pin) continue;
    if (spkiHash(pin.public_key_pem) !== spkiHash(e.public_key_pem)) {
      violations.push(`service key document from ${origin} serves ${e.key_id} with a public key other than the pinned one; the pin is kept`);
      continue;
    }
    const next = tighten(pin, e);
    if (next.status !== pin.status || next.valid_from !== pin.valid_from || next.valid_to !== pin.valid_to) {
      trust.set(e.key_id, next);
      file.set(e.key_id, next);
      dirty = true;
    }
  }

  const fresh = entries.filter((e) => !trust.has(e.key_id));
  if (trust.size === 0 && !authoritative && fresh.length > 0) {
    // First use: nothing pinned at all for this data dir.
    for (const e of fresh) {
      const pin: PinnedServiceKey = { ...anchorPin(e.public_key_pem, 'tofu', origin), status: e.status, valid_from: e.valid_from, valid_to: e.valid_to, pinned_at: now };
      trust.set(e.key_id, pin);
      file.set(e.key_id, pin);
    }
    dirty = true;
    notes.push(`pinned ${fresh.length} anchor service key(s) from ${origin} on first use (${fresh.map((e) => e.key_id).join(', ')}); later key changes need a successor signature or \`kronicle-lite anchor keys add\``);
  } else {
    // Rotation: admit a new key only on a valid successor signature from a pinned, non-revoked key.
    let pending = fresh;
    for (let progress = true; progress && pending.length > 0; ) {
      progress = false;
      const still: DocEntry[] = [];
      for (const e of pending) {
        const signer = e.signed_by ? trust.get(e.signed_by) : undefined;
        const ok =
          signer !== undefined &&
          rank(signer.status) < 2 &&
          e.successor_signature !== null &&
          e.valid_from !== null &&
          verifyEd25519Strict(signer.public_key_pem, successorSigningPayload({ key_id: e.key_id, public_key_pem: e.public_key_pem, valid_from: e.valid_from }), e.successor_signature);
        if (ok) {
          const pin: PinnedServiceKey = {
            ...anchorPin(e.public_key_pem, 'successor', origin),
            status: e.status,
            valid_from: e.valid_from,
            valid_to: e.valid_to,
            pinned_at: now,
            signed_by: signer.key_id,
          };
          trust.set(e.key_id, pin);
          file.set(e.key_id, pin);
          dirty = true;
          progress = true;
          notes.push(`pinned rotated anchor service key ${e.key_id} (successor signature by ${signer.key_id})`);
        } else {
          still.push(e);
        }
      }
      pending = still;
    }
    for (const e of pending) {
      notes.push(
        `anchor service key ${e.key_id} from ${origin} is not pinned and carries no valid successor signature from a pinned key; receipts it signs are not trusted (pin it with \`kronicle-lite anchor keys add\` after checking it out of band)`,
      );
    }
  }

  if (dirty) {
    try {
      writePinFile(scope, [...file.values()]);
    } catch (e) {
      notes.push(`could not save ${PINS_FILE}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  return { keys: [...trust.values()], notes, violations };
}

// ───────────────────────────── receipts ─────────────────────────────

export function successorSigningPayload(k: { key_id: string; public_key_pem: string; valid_from: string }): string {
  return canonicalize({ key_id: k.key_id, public_key_pem: k.public_key_pem, valid_from: k.valid_from });
}

const UNTRUSTED_STATUSES = new Set(['revoked', 'compromised']);

/**
 * A successor_signature, when present, must verify against a listed,
 * not-revoked/compromised predecessor named by signed_by (not itself) over
 * canonicalize({key_id, public_key_pem, valid_from}). null when fine.
 */
function successionRefusal(
  entry: { key_id: string; public_key_pem: string; valid_from?: string | null; successor_signature?: string | null; signed_by?: string | null },
  listed: readonly { key_id: string; public_key_pem: string; status?: string | null }[],
): string | null {
  if (entry.successor_signature === null || entry.successor_signature === undefined) return null;
  if (!entry.signed_by) return `${entry.key_id}: successor_signature present but signed_by is missing`;
  if (entry.signed_by === entry.key_id) return `${entry.key_id}: successor_signature is self-signed`;
  const pred = listed.find((k) => k.key_id === entry.signed_by);
  if (!pred) return `${entry.key_id}: successor_signature signed_by ${entry.signed_by}, which is not listed`;
  if (UNTRUSTED_STATUSES.has(pred.status ?? '')) return `${entry.key_id}: predecessor ${pred.key_id} is ${pred.status}`;
  if (!isEd25519Pem(pred.public_key_pem) || serviceKeyIdFromPem(pred.public_key_pem) !== pred.key_id) {
    return `${entry.key_id}: predecessor ${pred.key_id} does not derive from its public key`;
  }
  if (typeof entry.valid_from !== 'string') return `${entry.key_id}: successor_signature present but valid_from is missing`;
  const payload = successorSigningPayload({ key_id: entry.key_id, public_key_pem: entry.public_key_pem, valid_from: entry.valid_from });
  return verifyEd25519Strict(pred.public_key_pem, payload, entry.successor_signature) ? null : `${entry.key_id}: successor_signature by ${pred.key_id} does not verify`;
}

function parseTime(s: string | null | undefined): number | null {
  if (s === null || s === undefined) return null;
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : Number.NaN;
}

/**
 * null when `key` may vouch for something issued at `received_at` (the
 * receipt's signed time), else why not (A2-04). Same rules as the service
 * (isokron-anchor src/core/servicekeys.ts checkServiceKey):
 *   - status "active" (the default when absent), or "retired" with a
 *     valid_to; every other status fails;
 *   - valid_from ≤ received_at, and received_at < valid_to when set;
 *   - an unparseable time fails.
 */
export function serviceKeyRefusal(
  key: { key_id: string; status?: string | null; valid_from?: string | null; valid_to?: string | null },
  received_at: string,
): string | null {
  const status = key.status ?? 'active';
  if (!(ACCEPTED_SERVICE_KEY_STATUSES as readonly string[]).includes(status)) return `service key ${key.key_id} is ${status}; it vouches for nothing`;
  const t = parseTime(received_at);
  if (t === null || Number.isNaN(t)) return `receipt time ${received_at} is not a timestamp`;
  const from = parseTime(key.valid_from);
  const to = parseTime(key.valid_to);
  if (Number.isNaN(from) || Number.isNaN(to)) return `service key ${key.key_id} has an unparseable validity window`;
  if (status === 'retired' && to === null) return `service key ${key.key_id} is retired without valid_to`;
  if (from !== null && t < from) return `receipt dated ${received_at} precedes service key ${key.key_id} valid_from ${key.valid_from}`;
  if (to !== null && t >= to) return `receipt dated ${received_at} is after service key ${key.key_id} valid_to ${key.valid_to}`;
  return null;
}

/**
 * The service's full check for an UNPINNED key list (AnchorClient.verifyReceipt):
 * listed exactly once, derives to its key_id, usable point, status and window
 * at `at`, successor signature when present. Returns the PEM or the reason.
 */
export function checkPublishedServiceKey(
  keys: readonly { key_id: string; public_key_pem: string; status?: string | null; valid_from?: string | null; valid_to?: string | null; successor_signature?: string | null; signed_by?: string | null }[],
  service_key_id: string,
  at: string,
): { ok: true; pem: string } | { ok: false; detail: string } {
  const matches = keys.filter((k) => k.key_id === service_key_id);
  if (matches.length === 0) return { ok: false, detail: `${service_key_id} is not listed in /.well-known/anchor-keys.json` };
  if (matches.length > 1) return { ok: false, detail: `${service_key_id} is listed more than once` };
  const entry = matches[0]!;
  if (typeof entry.public_key_pem !== 'string' || !isEd25519Pem(entry.public_key_pem)) return { ok: false, detail: `${service_key_id}: listed key is not a usable Ed25519 public key` };
  const derived = serviceKeyIdFromPem(entry.public_key_pem);
  if (derived !== service_key_id) return { ok: false, detail: `listed key derives to ${derived}, not ${service_key_id}` };
  const refusal = serviceKeyRefusal(entry, at);
  if (refusal) return { ok: false, detail: refusal };
  const succ = successionRefusal(entry, keys);
  if (succ) return { ok: false, detail: succ };
  return { ok: true, pem: entry.public_key_pem };
}

export type TrustedReceiptResult = { ok: true; receipt: AnchorReceipt } | { ok: false; reason: string; claimed: AnchorReceipt | null };

/** Parse + countersignature against a pinned key, with key status and validity window. */
export function verifyReceiptWithPins(input: unknown, keys: readonly PinnedServiceKey[]): TrustedReceiptResult {
  const parsed = parseAnchorReceipt(input);
  if (!parsed.ok) return { ok: false, reason: `anchor receipt malformed: ${parsed.detail}`, claimed: null };
  const r = parsed.value;
  if (keys.length === 0) {
    return { ok: false, reason: 'no anchor service key is pinned for this data dir (run `verify --remote` online once, or `anchor keys add`)', claimed: r };
  }
  const key = keys.find((k) => k.key_id === r.service_key_id);
  if (!key) return { ok: false, reason: `service key ${r.service_key_id} is not pinned`, claimed: r };
  if (spkiHash(key.public_key_pem) === null || serviceKeyIdFromPem(key.public_key_pem) !== key.key_id) {
    return { ok: false, reason: `pinned service key ${key.key_id} does not derive from its public key`, claimed: r };
  }
  const refusal = serviceKeyRefusal(key, r.received_at);
  if (refusal) return { ok: false, reason: refusal, claimed: r };
  if (!verifyAnchorReceiptSignature(r, key.public_key_pem)) return { ok: false, reason: 'anchor receipt countersignature does not verify against the pinned key', claimed: r };
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
