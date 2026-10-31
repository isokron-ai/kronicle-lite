/**
 * RFC 8785 (JSON Canonicalization Scheme) helpers.
 *
 * Every hash and signature in kronicle-lite is computed over the JCS form
 * of a JSON value, produced by the `canonicalize` package. Nested objects
 * and arrays are allowed; keys are sorted, whitespace is removed, numbers
 * are serialized per ECMAScript rules. `undefined` members are dropped
 * (same as JSON.stringify), so callers should not rely on them.
 */

import canonicalizeModule from 'canonicalize';

// `canonicalize` is CommonJS (`module.exports = fn`); its typings declare a
// default export. Resolve whichever shape the runtime hands us.
type CanonicalizeFn = (input: unknown) => string | undefined;
const canonicalizeJson: CanonicalizeFn =
  typeof canonicalizeModule === 'function'
    ? (canonicalizeModule as unknown as CanonicalizeFn)
    : ((canonicalizeModule as unknown as { default: CanonicalizeFn }).default);

export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

/** Canonical JSON string (RFC 8785) of `value`. Throws on non-JSON input. */
export function canonicalize(value: unknown): string {
  const out = canonicalizeJson(value);
  if (out === undefined) {
    throw new Error('value cannot be canonicalized (not JSON)');
  }
  return out;
}

/** Assert `value` is a plain JSON object (not array, not null). */
export function assertJsonObject(
  value: unknown,
  what = 'payload',
): asserts value is Record<string, JsonValue> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${what} must be a JSON object`);
  }
  // Round-trip through canonicalize to reject functions, bigint, cycles.
  canonicalize(value);
}
