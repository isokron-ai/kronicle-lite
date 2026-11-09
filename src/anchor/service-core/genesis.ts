/**
 * The pinned genesis service key: SHA-256 of the SPKI DER of
 * anchor-ed25519-3dca1ecf66c2993e, the first production anchor service key,
 * and the start of its validity window. Compiled into the Worker, the verify
 * page bundle and the client; never read from the server. Every other service
 * key is trusted only through a signed chain back to this key
 * (src/core/servicekeys.ts checkKeyChain).
 *
 * The genesis key's `valid_from` is part of the pin: whatever valid_from the
 * published list shows for the genesis key is ignored, so the list cannot
 * move the start of the genesis window (the genesis entry has no successor
 * signature that would cover it).
 *
 * Changing the pin is a release, not a configuration change. Tests may
 * override it at bundle time (`__ANCHOR_GENESIS_OVERRIDE__`, set by
 * scripts/build-verify-page.mjs buildVerifyPage({ genesis })); every
 * production build defines the identifier as `undefined` (build scripts and
 * wrangler.toml [define]), so no override can reach a shipped bundle.
 */

export interface GenesisPin {
  /** SHA-256 of the genesis key's SPKI DER, 64 lowercase hex. */
  sha256: string;
  /** Start of the genesis key's validity window (ISO 8601, UTC). */
  valid_from: string;
}

export const PRODUCTION_GENESIS: GenesisPin = Object.freeze({
  sha256: '3dca1ecf66c2993e534ff08fe350dc9368ca52042e38b20a9d58cd7c2b7b3367',
  valid_from: '2026-11-01T02:29:25.705Z',
});

export const PRODUCTION_GENESIS_KEY_SHA256 = PRODUCTION_GENESIS.sha256;

const ISO_UTC = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/;

/**
 * The canonical form of a pin's valid_from: `new Date(v).toISOString()`
 * (`YYYY-MM-DDTHH:MM:SS.sssZ`). Accepted input is ISO 8601 in UTC with a
 * literal `Z` and 0-3 fraction digits; anything else (another offset, a
 * lowercase `z`, a date or time that does not round-trip such as Feb 30 or
 * 24:00) is null.
 */
export function canonicalValidFrom(v: string): string | null {
  const m = ISO_UTC.exec(v);
  if (!m) return null;
  const t = Date.parse(v);
  if (!Number.isFinite(t)) return null;
  const iso = new Date(t).toISOString();
  return iso === `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}.${(m[7] ?? '').padEnd(3, '0')}Z` ? iso : null;
}

/**
 * Parse a genesis pin into its canonical form: a {sha256, valid_from} object,
 * or the string form `<sha256>@<valid_from>`. sha256 may carry colons and
 * upper case and comes back as 64 lowercase hex; valid_from comes back as
 * `new Date(v).toISOString()` (canonicalValidFrom). Every spelling of one pin
 * parses to the same value, so the result can be compared and used as a key
 * (formatGenesisPin). Null when malformed.
 */
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
  const valid_from = canonicalValidFrom(vf);
  if (valid_from === null) return null;
  return { sha256: s, valid_from };
}

/** `<sha256>@<valid_from>` of the canonical pin; the label and the key under which a pin is recorded. */
export function formatGenesisPin(p: GenesisPin): string {
  const c = parseGenesisPin(p);
  if (!c) throw new Error('not a valid genesis pin');
  return `${c.sha256}@${c.valid_from}`;
}

declare const __ANCHOR_GENESIS_OVERRIDE__: string | undefined;

/** The pin in force: the production pin, unless a test bundle defined an override. */
export const GENESIS: GenesisPin =
  (typeof __ANCHOR_GENESIS_OVERRIDE__ === 'string' ? parseGenesisPin(__ANCHOR_GENESIS_OVERRIDE__) : null) ?? PRODUCTION_GENESIS;

export const GENESIS_KEY_SHA256: string = GENESIS.sha256;
