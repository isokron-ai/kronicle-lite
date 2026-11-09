/**
 * The anchor service key-list model: a port of isokron-anchor
 * `src/core/servicekeys.ts` and the GenesisPin of `src/core/genesis.ts`
 * (feat/audit-anchoring f289c6b). The code below the adapter is the service's,
 * statement for statement, with its error texts, so that a key list valid for
 * the service, its verification page and its client is valid here, and one
 * that is BROKEN there is BROKEN here. test/keychain.test.ts holds lists the
 * service's scripts/rotate-key.mjs built and its own checkKeyChain judged, and
 * requires the same verdicts.
 *
 * Signed statements (RFC 8785 canonical JSON, Ed25519, base64 signatures):
 *   successor   {key_id, public_key_pem, valid_from}               by the predecessor (signed_by)
 *   retired     {key_id, status, valid_to}                         by the successor (retirement_signed_by)
 *   revoked     {key_id, status, valid_to, compromised_since}      by the key itself or an earlier key
 *
 * The service module's own doc comment follows.
 *

 * Which published service key may vouch for a receipt (A2-04). Pure and
 * isomorphic: used by the verify page (src/verify-page/verifier.ts) and the
 * Node client (client/src/api.ts).
 *
 * A receipt's countersignature is accepted only when the key named by
 * `service_key_id`
 *   - is listed, and its PEM derives to that key_id;
 *   - chains back to the compiled genesis pin (checkKeyChain below);
 *   - has status "active", or "retired" with a closed validity window, or
 *     "revoked" under the caller's revocation rule (see checkServiceKey);
 *     every other status fails;
 *   - was valid when the receipt says it was issued:
 *       valid_from ≤ received_at, and received_at < valid_to when valid_to is set
 *     (a retired or revoked key must have valid_to). The genesis key's
 *     valid_from is the compiled one (src/core/genesis.ts), never the listed one.
 *
 * `received_at` is chosen by the service and covered by its signature, so the
 * window check stops a key from vouching outside the period the operator
 * published for it. A key that leaked is revoked with a signed
 * `compromised_since`: its receipts count only when something the key holder
 * cannot forge (an RFC 3161 time from a third-party TSA) shows they existed
 * before that time.
 */

import { canonicalize } from '../crypto/canonical.js';
import { chainIdFromPublicKeyPem } from '../crypto/keys.js';
import { isUsableEd25519PublicKeyPem, verifyEd25519Strict } from './ed25519-strict.js';
import { isJsonObject } from './wire.js';

// ── adapter: the service's ed25519.ts / genesis.ts surface, on kronicle-lite's node:crypto primitives ──

export interface PublicKey {
  pem: string;
  /** SHA-256 of the SPKI DER, hex. */
  chain_id: string;
}
export function publicKeyFromPem(pem: string): PublicKey {
  if (typeof pem !== 'string' || !isUsableEd25519PublicKeyPem(pem)) throw new Error('not a usable Ed25519 SPKI PEM');
  return { pem, chain_id: chainIdFromPublicKeyPem(pem) };
}
export function verifySignature(pub: PublicKey, message: string, signatureB64: string): boolean {
  return typeof signatureB64 === 'string' && verifyEd25519Strict(pub.pem, message, signatureB64);
}

/** A genesis pin: SHA-256 of the genesis key's SPKI DER and the start of its validity window. */
export interface GenesisPin {
  sha256: string;
  valid_from: string;
}
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
/** `<sha256>@<valid_from>` (sha256 may carry colons) or {sha256, valid_from}; null when malformed (the service's parseGenesisPin). */
export function parseGenesisPin(v: unknown): GenesisPin | null {
  let sha: unknown;
  let vf: unknown;
  if (typeof v === 'string') {
    const at = v.indexOf('@');
    if (at < 0) return null;
    sha = v.slice(0, at);
    vf = v.slice(at + 1);
  } else if (v !== null && typeof v === 'object') {
    sha = (v as Record<string, unknown>)['sha256'];
    vf = (v as Record<string, unknown>)['valid_from'];
  } else return null;
  if (typeof sha !== 'string' || typeof vf !== 'string') return null;
  const s = sha.replace(/:/g, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(s)) return null;
  if (!ISO_UTC.test(vf) || !Number.isFinite(Date.parse(vf))) return null;
  return { sha256: s, valid_from: vf };
}
export const formatGenesisPin = (p: GenesisPin): string => `${p.sha256}@${p.valid_from}`;
/** The compiled production pin (isokron-anchor src/core/genesis.ts PRODUCTION_GENESIS). */
export const PRODUCTION_GENESIS: GenesisPin = Object.freeze({ sha256: '3dca1ecf66c2993e534ff08fe350dc9368ca52042e38b20a9d58cd7c2b7b3367', valid_from: '2026-11-01T02:29:25.705Z' });
const GENESIS = PRODUCTION_GENESIS;

// ── the service's servicekeys.ts from here on ──

export const SERVICE_KEY_PREFIX = 'anchor-ed25519-';

export interface ServiceKeyEntry {
  key_id: string;
  public_key_pem: string;
  status?: string;
  valid_from?: string | null;
  valid_to?: string | null;
  successor_signature?: string | null;
  signed_by?: string | null;
  /** Signature over canonicalize({key_id, status, valid_to}) of a key that is no longer active. */
  retirement_signature?: string | null;
  /**
   * The key that signed the status statement: for "retired", its successor;
   * for "revoked", the revoked key itself or an earlier key on its chain.
   */
  retirement_signed_by?: string | null;
  /** "revoked" only, covered by the revocation statement: from when the key must be treated as in other hands. */
  compromised_since?: string | null;
}

export type ServiceKeyCheck =
  | {
      ok: true;
      pub: PublicKey;
      entry: ServiceKeyEntry;
      detail: string;
      /**
       * Set when the key is revoked and the caller asked for revoked: 'tsa'. The
       * caller must then accept the receipt only with an independent (RFC 3161)
       * time earlier than compromised_since − KEY_TIME_SKEW_MS.
       */
      revoked?: { compromised_since: string };
    }
  | {
      ok: false;
      detail: string;
      /** Set when the only reason is that the key is revoked (policy 'reject'). */
      revoked?: { compromised_since: string };
    };

/**
 * How a caller treats a receipt signed by a revoked key:
 *   'reject' — never accept (default; the client CLI);
 *   'tsa'    — accept the key, flagged `revoked`; the caller then requires a
 *              verified RFC 3161 time before compromised_since − KEY_TIME_SKEW_MS
 *              (verify page).
 * There is deliberately no policy that trusts the receipt's own received_at:
 * the revoked key signs it, so whoever holds the leaked key can backdate it.
 */
export type RevokedPolicy = 'reject' | 'tsa';

/** Accepted clock difference between the service's times and a TSA's genTime (TSAs report whole seconds). */
export const KEY_TIME_SKEW_MS = 5 * 60 * 1000;

export function serviceKeyIdOf(pub: PublicKey): string {
  return `${SERVICE_KEY_PREFIX}${pub.chain_id.slice(0, 16)}`;
}

export function successorSigningPayload(k: Pick<ServiceKeyEntry, 'key_id' | 'public_key_pem'> & { valid_from: string }): string {
  return canonicalize({ key_id: k.key_id, public_key_pem: k.public_key_pem, valid_from: k.valid_from });
}

const UNTRUSTED_STATUSES = new Set(['revoked', 'compromised']);

function parseTime(s: string | null | undefined): number | null {
  if (s === null || s === undefined) return null;
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : Number.NaN;
}

function derive(entry: ServiceKeyEntry): { ok: true; pub: PublicKey } | { ok: false; detail: string } {
  let pub: PublicKey;
  try {
    pub = publicKeyFromPem(entry.public_key_pem);
  } catch (e) {
    return { ok: false, detail: `listed key is not an Ed25519 SPKI PEM: ${(e as Error).message}` };
  }
  const derived = serviceKeyIdOf(pub);
  if (derived !== entry.key_id) return { ok: false, detail: `listed key derives to ${derived}, not ${entry.key_id}` };
  return { ok: true, pub };
}


const normFp = (s: string) => s.replace(/:/g, '').toLowerCase();

/**
 * The list as the checks read it: the genesis entry (no successor_signature,
 * fingerprint equal to the pin) takes its valid_from from the compiled pin,
 * whatever the list says.
 */
export function effectiveKeys(keys: readonly ServiceKeyEntry[], genesis: GenesisPin = GENESIS): ServiceKeyEntry[] {
  const pinned = normFp(genesis.sha256);
  return keys.map((k) => {
    if (k.successor_signature) return k;
    const d = derive(k);
    return d.ok && d.pub.chain_id === pinned ? { ...k, valid_from: genesis.valid_from } : k;
  });
}

/**
 * Decide whether `service_key_id` may vouch for something issued at `at`
 * (ISO timestamp from the signed receipt). The published list must pass the
 * key-chain check against the compiled genesis pin (`genesis`, default
 * GENESIS; only tests pass another value): every key verified, except keys
 * that are untrusted only because an earlier key was revoked. The key itself
 * must chain cleanly, be active / retired / revoked, and have `at` inside its
 * validity window. A revoked key is handled by `opts.revoked` (RevokedPolicy).
 */
export function checkServiceKey(
  keys: readonly ServiceKeyEntry[],
  service_key_id: string,
  at: string,
  genesis: GenesisPin = GENESIS,
  opts: { revoked?: RevokedPolicy } = {},
): ServiceKeyCheck {
  const matches = keys.filter((k) => k.key_id === service_key_id);
  if (matches.length === 0) return { ok: false, detail: `${service_key_id} is not listed in /.well-known/anchor-keys.json` };
  if (matches.length > 1) return { ok: false, detail: `${service_key_id} is listed more than once` };
  const d = derive(matches[0]!);
  if (!d.ok) return { ok: false, detail: d.detail };

  const chain = checkKeyChain(keys, genesis);
  const mine = chain.entries.find((e) => e.key_id === service_key_id);
  if (!chain.usable) {
    const first = chain.entries.find((e) => e.state === 'broken' && !e.revoked_ancestor);
    return { ok: false, detail: `service key list does not chain to the pinned genesis key: ${mine?.state === 'broken' ? mine.detail : `${first?.key_id ?? '?'}: ${first?.detail ?? chain.detail}`}` };
  }
  if (!mine || mine.state === 'broken') return { ok: false, detail: `${service_key_id} is not trusted: ${mine?.detail ?? 'not in the chain'}` };
  const entry = effectiveKeys(keys, genesis).find((k) => k.key_id === service_key_id)!;

  const status = entry.status ?? 'active';
  if (status !== 'active' && status !== 'retired' && status !== 'revoked') return { ok: false, detail: `${service_key_id} is ${status}; it vouches for nothing` };

  const t = parseTime(at);
  if (t === null || Number.isNaN(t)) return { ok: false, detail: `receipt time ${at} is not a timestamp` };
  const from = parseTime(entry.valid_from);
  const to = parseTime(entry.valid_to);
  if (Number.isNaN(from) || Number.isNaN(to)) return { ok: false, detail: `${service_key_id} has an unparseable validity window` };
  if (status !== 'active' && to === null) return { ok: false, detail: `${service_key_id} is ${status} without valid_to` };
  if (from !== null && t < from) return { ok: false, detail: `receipt dated ${at} precedes ${service_key_id} valid_from ${entry.valid_from}` };
  if (to !== null && t >= to) return { ok: false, detail: `receipt dated ${at} is after ${service_key_id} valid_to ${entry.valid_to}` };

  const window = `${entry.valid_from ?? '…'} → ${entry.valid_to ?? 'now'}`;
  const lineage = entry.successor_signature ? `successor of ${entry.signed_by}` : 'genesis';
  if (status === 'revoked') {
    const since = entry.compromised_since!; // present and parseable: the chain check requires it
    const policy = opts.revoked ?? 'reject';
    // Anything but an explicit 'tsa' rejects (fail closed, also for untyped callers).
    if (policy !== 'tsa') {
      return { ok: false, detail: `${service_key_id} is revoked (compromised since ${since}); only an independent RFC 3161 timestamp before that time can keep its receipts valid`, revoked: { compromised_since: since } };
    }
    return {
      ok: true,
      pub: d.pub,
      entry,
      detail: `${service_key_id} (revoked, compromised since ${since}; valid ${window}, ${lineage}; key chain verified; the receipt counts only with an independent timestamp before ${since})`,
      revoked: { compromised_since: since },
    };
  }
  return { ok: true, pub: d.pub, entry, detail: `${service_key_id} (${status}, valid ${window}, ${lineage}; key chain verified)` };
}

/**
 * The statement a status signature covers: {key_id, status, valid_to} for
 * "retired"; {key_id, status, valid_to, compromised_since} for "revoked".
 */
export function retirementSigningPayload(k: { key_id: string; status: string; valid_to: string | null; compromised_since?: string | null }): string {
  if (k.status === 'revoked') return canonicalize({ key_id: k.key_id, status: k.status, valid_to: k.valid_to, compromised_since: k.compromised_since ?? null });
  return canonicalize({ key_id: k.key_id, status: k.status, valid_to: k.valid_to });
}

export interface KeyChainEntry {
  key_id: string;
  state: 'genesis' | 'verified' | 'revoked' | 'broken';
  detail: string;
  /** SHA-256 of the SPKI DER, hex (null when the PEM is unusable). */
  spki_sha256: string | null;
  /** Broken only because this earlier key was revoked (the revoked key signed this key's transition). */
  revoked_ancestor?: string;
}

export interface KeyChainResult {
  /** Every key verified (genesis, verified or revoked); nothing broken. */
  ok: boolean;
  /**
   * The list can be used for the keys that are not broken: every broken key
   * is broken only because an earlier key was revoked. Any other break makes
   * the whole list unusable.
   */
  usable: boolean;
  detail: string;
  entries: KeyChainEntry[];
}

/**
 * The key-list model (one linear, signed chain from a compiled genesis pin):
 *   - exactly one key has no successor_signature (the genesis), and its
 *     SHA-256(SPKI DER) equals the pinned fingerprint; its valid_from is the
 *     pinned one;
 *   - every other key K has signed_by = P and successor_signature = P's
 *     Ed25519 signature over {key_id, public_key_pem, valid_from} of K, where
 *     P is listed, chains to the genesis itself, has exactly one successor
 *     (no forks), and P.valid_from < P.valid_to <= K.valid_from (a
 *     predecessor stops vouching before its successor starts);
 *   - a "retired" key has a successor S, valid_to, and a retirement_signature
 *     over {key_id, status, valid_to} by S (retirement_signed_by = S);
 *   - a "revoked" key has valid_to, compromised_since and a revocation
 *     statement over {key_id, status, valid_to, compromised_since} signed by
 *     the key itself or an earlier key on its chain (never by a later key,
 *     which the revoked key may have signed);
 *   - the key without a successor (the head) is "active" with no valid_to,
 *     or "revoked".
 * Keys after a revoked key are BROKEN: the revoked key signed their
 * transitions and nothing shows those signatures were made before
 * compromised_since. Keys before it stay verified, so their receipts stay
 * valid (`usable`). Recovery after a revocation is a release with a new
 * genesis pin. Anything else marks the key, and the list, BROKEN.
 *
 * One copy of the list cannot show that its operator rolled it back (served
 * an older or weaker list). The client keeps the longest list it has seen in
 * its data directory and refuses a shorter or weaker one (keyListRegression);
 * Evidence Packs carry the list current when they were made.
 */
export function checkKeyChain(input: readonly ServiceKeyEntry[], genesis: GenesisPin = GENESIS): KeyChainResult {
  const keys = effectiveKeys(input, genesis);
  const pubs = new Map<string, PublicKey | null>();
  const derived = new Map<string, string | null>();
  for (const k of keys) {
    const d = derive(k);
    pubs.set(k.key_id, d.ok ? d.pub : null);
    derived.set(k.key_id, d.ok ? d.pub.chain_id : null);
  }
  const ids = keys.map((k) => k.key_id);
  const dup = ids.find((id, i) => ids.indexOf(id) !== i);
  const byId = new Map(keys.map((k) => [k.key_id, k]));
  const successors = new Map<string, ServiceKeyEntry[]>();
  for (const k of keys) if (k.signed_by && k.successor_signature) (successors.get(k.signed_by) ?? successors.set(k.signed_by, []).get(k.signed_by)!).push(k);
  const genesisCandidates = keys.filter((k) => !k.successor_signature);
  const pinned = normFp(genesis.sha256);
  type Up = { ok: boolean; detail: string; revokedAncestor?: string };
  const memo = new Map<string, Up>();
  const t = (s: string | null | undefined) => (s ? Date.parse(s) : Number.NaN);

  function chainOk(id: string, seen: Set<string>): Up {
    const hit = memo.get(id);
    if (hit) return hit;
    const k = byId.get(id)!;
    let r: Up;
    if (!pubs.get(id)) r = { ok: false, detail: 'public key is unusable or does not derive to its key_id' };
    else if (!k.successor_signature) {
      if (genesisCandidates.length !== 1) r = { ok: false, detail: `${genesisCandidates.length} keys have no successor_signature; exactly one genesis key is allowed` };
      else if (derived.get(id) !== pinned) r = { ok: false, detail: `genesis fingerprint ${derived.get(id)} does not match the pinned ${pinned}` };
      else r = { ok: true, detail: `genesis key; SHA-256(SPKI) matches the pinned fingerprint; valid_from ${genesis.valid_from} (pinned)` };
    } else if (seen.has(id)) r = { ok: false, detail: 'successor signatures form a cycle' };
    else {
      const pred = k.signed_by ? byId.get(k.signed_by) : undefined;
      const predPub = pred ? pubs.get(pred.key_id) : null;
      const vf = typeof k.valid_from === 'string' ? k.valid_from : null;
      if (!pred || !predPub) r = { ok: false, detail: `signed_by ${k.signed_by ?? '(missing)'} is not a listed, usable key` };
      else if (!vf || !Number.isFinite(t(vf))) r = { ok: false, detail: 'valid_from missing or unparseable' };
      else if (!verifySignature(predPub, successorSigningPayload({ key_id: k.key_id, public_key_pem: k.public_key_pem, valid_from: vf }), k.successor_signature)) r = { ok: false, detail: `successor_signature by ${pred.key_id} does not verify` };
      else if ((successors.get(pred.key_id) ?? []).length !== 1) r = { ok: false, detail: `${pred.key_id} has ${(successors.get(pred.key_id) ?? []).length} successors; the chain must not fork` };
      else if (pred.valid_to == null || !(t(pred.valid_from) < t(pred.valid_to) && t(pred.valid_to) <= t(vf))) r = { ok: false, detail: `${pred.key_id} must end (valid_to) after it starts and no later than this key's valid_from ${vf}` };
      else {
        const up = chainOk(pred.key_id, new Set([...seen, id]));
        if (!up.ok) r = { ok: false, detail: `predecessor ${pred.key_id} is broken: ${up.detail}`, ...(up.revokedAncestor ? { revokedAncestor: up.revokedAncestor } : {}) };
        else if (UNTRUSTED_STATUSES.has(pred.status ?? '')) r = { ok: false, detail: `signed by ${pred.key_id}, which is ${pred.status}; a key after a revoked key is not trusted`, revokedAncestor: pred.key_id };
        else r = { ok: true, detail: `transition signed by ${pred.key_id}, which ended at ${pred.valid_to}; chain verified to the genesis` };
      }
    }
    memo.set(id, r);
    return r;
  }

  /** The key and every key before it on its chain (it has verified, so signed_by links are sound). */
  function lineage(k: ServiceKeyEntry): Set<string> {
    const out = new Set<string>([k.key_id]);
    let cur: ServiceKeyEntry | undefined = k;
    while (cur?.successor_signature && cur.signed_by && !out.has(cur.signed_by)) {
      out.add(cur.signed_by);
      cur = byId.get(cur.signed_by);
    }
    return out;
  }

  const entries: KeyChainEntry[] = keys.map((k) => {
    const fp = derived.get(k.key_id) ?? null;
    const broken = (detail: string, revoked_ancestor?: string): KeyChainEntry => ({ key_id: k.key_id, state: 'broken', detail, spki_sha256: fp, ...(revoked_ancestor ? { revoked_ancestor } : {}) });
    if (dup) return broken(`${dup} is listed more than once`);
    const c = chainOk(k.key_id, new Set());
    if (!c.ok) return broken(c.detail, c.revokedAncestor);
    const status = k.status ?? 'active';
    const next = successors.get(k.key_id) ?? [];
    if (next.length > 1) return broken(`${next.length} successors; the chain must not fork`);
    const state: KeyChainEntry['state'] = k.successor_signature ? 'verified' : 'genesis';
    if (status === 'revoked') {
      if (!Number.isFinite(t(k.valid_to))) return broken('revoked without a parseable valid_to');
      if (!Number.isFinite(t(k.compromised_since))) return broken('revoked without a parseable compromised_since');
      const signer = k.retirement_signed_by ?? '';
      const signerPub = pubs.get(signer);
      if (!k.retirement_signature || !lineage(k).has(signer) || !signerPub) return broken(`revocation must be signed by the key itself or an earlier key on its chain (signed by ${signer || 'nobody'})`);
      if (!verifySignature(signerPub, retirementSigningPayload({ key_id: k.key_id, status, valid_to: k.valid_to ?? null, compromised_since: k.compromised_since ?? null }), k.retirement_signature)) return broken(`revocation statement signed by ${signer} does not verify`);
      return { key_id: k.key_id, state: 'revoked', detail: `${c.detail}; REVOKED: compromised since ${k.compromised_since}, valid_to ${k.valid_to}, statement signed by ${signer === k.key_id ? 'the key itself' : signer}`, spki_sha256: fp };
    }
    if (next.length === 0) {
      if (status !== 'active' || k.valid_to != null) return broken(`the newest key must be active with no valid_to, or revoked (it is ${status}${k.valid_to ? ` until ${k.valid_to}` : ''}); a retirement needs a signed successor`);
      return { key_id: k.key_id, state, detail: `${c.detail}; current key`, spki_sha256: fp };
    }
    const s = next[0]!;
    if (status !== 'retired') return broken(`has successor ${s.key_id} but is ${status}; it must be retired or revoked`);
    const sPub = pubs.get(s.key_id);
    if (!k.retirement_signature || k.retirement_signed_by !== s.key_id || !sPub) return broken(`status "${status}" is not signed by its successor ${s.key_id}`);
    if (!verifySignature(sPub, retirementSigningPayload({ key_id: k.key_id, status, valid_to: k.valid_to ?? null }), k.retirement_signature)) return broken(`${status} statement signed by ${s.key_id} does not verify`);
    return { key_id: k.key_id, state, detail: `${c.detail}; ${status} from ${k.valid_to}, statement signed by successor ${s.key_id}`, spki_sha256: fp };
  });
  const brokenN = entries.filter((e) => e.state === 'broken').length;
  const afterRevoked = entries.filter((e) => e.state === 'broken' && e.revoked_ancestor).length;
  const revokedN = entries.filter((e) => e.state === 'revoked').length;
  const usable = keys.length > 0 && brokenN === afterRevoked;
  const detail =
    keys.length === 0
      ? 'no keys published'
      : !usable
        ? `BROKEN: ${brokenN} of ${keys.length} key(s) do not verify`
        : brokenN
          ? `${keys.length - brokenN} key(s) verified back to the pinned genesis key, ${revokedN} revoked; ${brokenN} later key(s) not trusted because an earlier key was revoked`
          : `intact: ${keys.length} key(s), each verified back to the pinned genesis key${revokedN ? `; ${revokedN} revoked` : ''}`;
  return { ok: keys.length > 0 && brokenN === 0, usable, detail, entries };
}

const STATUS_RANK: Record<string, number> = { active: 0, retired: 1, revoked: 2 };

/**
 * Rollback check for a client that keeps the key list it last trusted:
 * null when `fresh` keeps every key of `cached` with the same public key and
 * a status, valid_to and compromised_since at least as strong; otherwise why
 * not. A list that drops a key (a prefix of the cached chain), turns revoked
 * into retired/active or retired into active, removes or extends valid_to,
 * or removes or moves compromised_since later, is a regression.
 */
export function keyListRegression(cached: readonly ServiceKeyEntry[], fresh: readonly ServiceKeyEntry[]): string | null {
  for (const c of cached) {
    const f = fresh.find((k) => k.key_id === c.key_id);
    if (!f) return `${c.key_id} is in the key list seen earlier but missing now (an older or truncated list)`;
    if (f.public_key_pem.trim() !== c.public_key_pem.trim()) return `${c.key_id} has a different public key than in the list seen earlier`;
    const cs = c.status ?? 'active';
    const fs = f.status ?? 'active';
    // An unknown status is not a rollback: such a list does not verify anyway.
    if ((STATUS_RANK[fs] ?? Number.POSITIVE_INFINITY) < (STATUS_RANK[cs] ?? 0)) return `${c.key_id} was ${cs} in the list seen earlier and is ${fs} now`;
    if (c.valid_to != null && (f.valid_to == null || !(Date.parse(f.valid_to) <= Date.parse(c.valid_to)))) return `${c.key_id} valid_to was ${c.valid_to} in the list seen earlier and is ${f.valid_to ?? 'unset'} now`;
    if (c.compromised_since != null && (f.compromised_since == null || !(Date.parse(f.compromised_since) <= Date.parse(c.compromised_since)))) {
      return `${c.key_id} compromised_since was ${c.compromised_since} in the list seen earlier and is ${f.compromised_since ?? 'unset'} now`;
    }
  }
  return null;
}


/** Entries of a key document ({keys: [...]}), string-typed fields kept, others dropped; null when it is not one. */
export function keyListOf(doc: unknown): ServiceKeyEntry[] | null {
  if (!isJsonObject(doc) || !Array.isArray(doc['keys'])) return null;
  const out: ServiceKeyEntry[] = [];
  const s = (x: unknown) => (typeof x === 'string' ? x : null);
  for (const e of doc['keys'] as unknown[]) {
    if (!isJsonObject(e) || typeof e['key_id'] !== 'string' || typeof e['public_key_pem'] !== 'string') return null;
    const entry: ServiceKeyEntry = { key_id: e['key_id'], public_key_pem: e['public_key_pem'] };
    for (const k of ['valid_from', 'valid_to', 'successor_signature', 'signed_by', 'retirement_signature', 'retirement_signed_by', 'compromised_since'] as const) {
      if (s(e[k]) !== null) entry[k] = s(e[k]);
    }
    if (s(e['status']) !== null) entry.status = s(e['status'])!;
    out.push(entry);
  }
  return out;
}
