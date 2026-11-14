/*!
 * Adapted from canonicalize 2.1.0 (https://github.com/erdtman/canonicalize), Copyright Samuel
 * Erdtman. @license Apache-2.0
 */

/**
 * RFC 8785 (JSON Canonicalization Scheme) on Node built-ins: the same function, with the same
 * results and errors, as the `canonicalize` package 2.1.0 (Apache-2.0, Samuel Erdtman) that
 * kronicle-lite's src/crypto/canonical.ts uses. Keys are sorted by UTF-16 code units, numbers and
 * strings are serialized by ECMAScript JSON.stringify (which RFC 8785 adopts), undefined and
 * symbol members are dropped from objects and become null in arrays.
 *
 * Every hash and signature the verifier checks is over this form; packages/verify/test checks it
 * against the package byte for byte.
 */
export default function canonicalize(object: unknown): string | undefined {
  if (typeof object === 'number' && isNaN(object)) throw new Error('NaN is not allowed');
  if (typeof object === 'number' && !isFinite(object)) throw new Error('Infinity is not allowed');
  if (object === null || typeof object !== 'object') return JSON.stringify(object) as string | undefined;
  const withToJson = object as { toJSON?: unknown };
  if (withToJson.toJSON instanceof Function) return canonicalize((withToJson.toJSON as () => unknown)());
  if (Array.isArray(object)) {
    const values = object.reduce((t: string, cv: unknown, ci: number) => {
      const comma = ci === 0 ? '' : ',';
      const value = cv === undefined || typeof cv === 'symbol' ? null : cv;
      return `${t}${comma}${canonicalize(value)}`;
    }, '');
    return `[${values}]`;
  }
  const rec = object as Record<string, unknown>;
  const values = Object.keys(rec)
    .sort()
    .reduce((t, cv) => {
      if (rec[cv] === undefined || typeof rec[cv] === 'symbol') return t;
      const comma = t.length === 0 ? '' : ',';
      return `${t}${comma}${canonicalize(cv)}:${canonicalize(rec[cv])}`;
    }, '');
  return `{${values}}`;
}
