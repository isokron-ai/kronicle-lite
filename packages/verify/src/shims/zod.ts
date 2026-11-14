/*!
 * Portions adapted from zod 4.6 (https://github.com/colinhacks/zod): check order and abort rules,
 * object / record / array traversal, the uuid and ISO datetime patterns and the en locale messages.
 * @license MIT. Copyright (c) 2025 Colin McDonnell. Permission is hereby granted, free of charge, to
 * any person obtaining a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the following conditions: The above
 * copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/**
 * The part of zod 4 (classic API) that kronicle-lite's verification code uses, on Node built-ins only.
 *
 * The standalone verifier is built from the same source as `kronicle-lite verify-audit`
 * (src/audit/verify-audit.ts and what it imports). That code validates event payloads and
 * claims.json with zod schemas and prints the first issue (`path: message`). This module stands in
 * for `zod` in the standalone build so the verifier has no third-party code, and it reproduces
 * zod 4.6's results for the schemas used: the same pass / fail, the same parsed value, and the same
 * issues in the same order with the same English messages.
 *
 * packages/verify/test/zod-shim.test.ts parses a corpus of valid and mutated payloads with both
 * zod and this module and requires identical results. Anything outside this subset throws at
 * build or load time rather than silently differing.
 *
 * Reproduced from zod 4.6 (MIT, Colin McDonnell): the check order and abort rules
 * ($ZodType runChecks: a check without `when` is skipped once an issue without continue: true
 * exists; length checks run whenever the value has a length unless an issue has continue: false),
 * the object / record / array traversal, and the en locale messages.
 */

export type Path = (string | number)[];

export interface Issue {
  code: string;
  path: Path;
  message: string;
  /** zod's `continue`: true lets later checks run; undefined or false stops checks without a `when`. */
  continue?: boolean;
}

interface Payload {
  value: unknown;
  issues: Issue[];
}

interface Check {
  /** Length checks: run whenever the value has a length (unless an issue has continue: false). */
  when?: (p: Payload) => boolean;
  run: (p: Payload) => void;
  /** A length check (min, max, exact); `cap` is the most items it allows (max, exact). */
  size?: { cap?: number };
}

type SafeParse = { success: true; data: unknown; error?: undefined } | { success: false; error: { issues: Issue[] }; data?: undefined };

// ── issue helpers (zod core/util.js and locales/en.js) ──

const aborted = (p: Payload, start = 0): boolean => {
  for (let i = start; i < p.issues.length; i++) if (p.issues[i]!.continue !== true) return true;
  return false;
};
const explicitlyAborted = (p: Payload): boolean => p.issues.some((i) => i.continue === false);
const prefix = (key: string | number, issues: Issue[]): Issue[] => issues.map((i) => ((i.path = [key, ...i.path]), i));

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
function isPlainObject(o: unknown): o is Record<string, unknown> {
  if (!isObject(o)) return false;
  const ctor = (o as { constructor?: unknown }).constructor;
  if (ctor === undefined || typeof ctor !== 'function') return true;
  const prot = (ctor as { prototype?: unknown }).prototype;
  if (!isObject(prot)) return false;
  return Object.prototype.hasOwnProperty.call(prot, 'isPrototypeOf');
}

function parsedType(v: unknown): string {
  if (typeof v === 'number') return Number.isNaN(v) ? 'nan' : 'number';
  if (typeof v === 'object') {
    if (v === null) return 'null';
    if (Array.isArray(v)) return 'array';
    if (Object.getPrototypeOf(v) !== Object.prototype && 'constructor' in v && (v as { constructor?: { name?: string } }).constructor) {
      return (v as { constructor: { name: string } }).constructor.name;
    }
  }
  return typeof v;
}
const typeName = (t: string, input?: unknown): string => (t === 'number' && typeof input === 'number' && !Number.isFinite(input) ? String(input) : t === 'nan' ? 'NaN' : t);
const primitive = (v: unknown): string => (typeof v === 'bigint' ? `${v}n` : typeof v === 'string' ? `"${v}"` : `${String(v)}`);
const SIZING: Record<string, string> = { string: 'characters', array: 'items' };

const invalidType = (expected: string, input: unknown, cont?: boolean): Issue => ({
  code: 'invalid_type',
  path: [],
  message: `Invalid input: expected ${typeName(expected)}, received ${typeName(parsedType(input), input)}`,
  ...(cont !== undefined ? { continue: cont } : {}),
});
const bound = (big: boolean, origin: string, limit: number, inclusive: boolean, exact: boolean, message?: string): Issue => {
  const adj = exact ? 'exactly ' : big ? (inclusive ? '<=' : '<') : inclusive ? '>=' : '>';
  const head = big ? 'Too big' : 'Too small';
  return {
    code: big ? 'too_big' : 'too_small',
    path: [],
    continue: true,
    message: message ?? (SIZING[origin] ? `${head}: expected ${origin} to have ${adj}${limit} ${SIZING[origin]}` : `${head}: expected ${origin} to be ${adj}${limit}`),
  };
};
const tooBig = (origin: string, maximum: number, inclusive: boolean, message?: string): Issue => bound(true, origin, maximum, inclusive, false, message);
const tooSmall = (origin: string, minimum: number, inclusive: boolean, message?: string): Issue => bound(false, origin, minimum, inclusive, false, message);

function codePointLength(s: string): number {
  if (!/[\uD800-\uDBFF]/.test(s)) return s.length;
  let count = s.length;
  for (let i = 0; i < s.length - 1; i++) {
    if ((s.charCodeAt(i) & 0xfc00) === 0xd800 && (s.charCodeAt(i + 1) & 0xfc00) === 0xdc00) {
      count--;
      i++;
    }
  }
  return count;
}
const lengthOrigin = (v: unknown): string => (Array.isArray(v) ? 'array' : typeof v === 'string' ? 'string' : 'unknown');
const hasLength = (p: Payload): boolean => p.value !== null && p.value !== undefined && (p.value as { length?: unknown }).length !== undefined;

function maxLength(maximum: number, message?: string): Check {
  return {
    size: { cap: maximum },
    when: hasLength,
    run: (p) => {
      const v = p.value as string | unknown[];
      const units = v.length;
      const length = typeof v === 'string' && units > maximum ? codePointLength(v) : units;
      if (length > maximum) p.issues.push(tooBig(lengthOrigin(v), maximum, true, message));
    },
  };
}
function minLength(minimum: number, message?: string): Check {
  return {
    size: {},
    when: hasLength,
    run: (p) => {
      const v = p.value as string | unknown[];
      const units = v.length;
      const length = typeof v === 'string' && units >= minimum && units < minimum * 2 ? codePointLength(v) : units;
      if (length < minimum) p.issues.push(tooSmall(lengthOrigin(v), minimum, true, message));
    },
  };
}
function exactLength(n: number, message?: string): Check {
  return {
    size: { cap: n },
    when: hasLength,
    run: (p) => {
      const v = p.value as string | unknown[];
      const units = v.length;
      const length = typeof v === 'string' && units >= n && units <= n * 2 ? codePointLength(v) : units;
      if (length !== n) p.issues.push(bound(length > n, lengthOrigin(v), n, true, true, message));
    },
  };
}
const FORMAT_NAMES: Record<string, string> = { uuid: 'UUID', datetime: 'ISO datetime' };
function stringFormat(format: 'regex' | 'uuid' | 'datetime', pattern: RegExp, message?: string): Check {
  return {
    run: (p) => {
      pattern.lastIndex = 0;
      if (pattern.test(p.value as string)) return;
      p.issues.push({
        code: 'invalid_format',
        path: [],
        continue: true,
        message: message ?? (format === 'regex' ? `Invalid string: must match pattern ${pattern.toString()}` : `Invalid ${FORMAT_NAMES[format]}`),
      });
    },
  };
}

// ── schemas ──

export abstract class ZodType {
  checks: Check[] = [];
  /** zod's optin / optout: how an object treats this property when it is absent. */
  optin: 'optional' | undefined = undefined;
  optout: 'optional' | undefined = undefined;

  /** The type step (zod's `_zod.parse`); mutates the payload. */
  protected abstract parseType(p: Payload): void;

  run(p: Payload): Payload {
    this.parseType(p);
    let isAborted = aborted(p);
    for (const ch of this.checks) {
      if (ch.when) {
        if (explicitlyAborted(p) || !ch.when(p)) continue;
      } else if (isAborted) continue;
      const before = p.issues.length;
      ch.run(p);
      if (p.issues.length !== before && !isAborted) isAborted = aborted(p, before);
    }
    return p;
  }

  safeParse(value: unknown): SafeParse {
    const p = this.run({ value, issues: [] });
    return p.issues.length ? { success: false, error: { issues: p.issues } } : { success: true, data: p.value };
  }

  parse(value: unknown): unknown {
    const r = this.safeParse(value);
    if (!r.success) throw new Error(r.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`).join('; '));
    return r.data;
  }

  protected withCheck(ch: Check): this {
    const copy = Object.assign(Object.create(Object.getPrototypeOf(this) as object) as this, this);
    copy.checks = [...this.checks, ch];
    return copy;
  }

  optional(): ZodOptional {
    return new ZodOptional(this);
  }
  nullable(): ZodNullable {
    return new ZodNullable(this);
  }
  /** Metadata only; parsing is unchanged. */
  describe(_description: string): this {
    return this;
  }
  refine(fn: (value: never) => unknown, message?: string): this {
    return this.withCheck({
      run: (p) => {
        if (!fn(p.value as never)) p.issues.push({ code: 'custom', path: [], continue: true, message: message ?? 'Invalid input' });
      },
    });
  }
}

export class ZodString extends ZodType {
  protected parseType(p: Payload): void {
    if (typeof p.value !== 'string') p.issues.push(invalidType('string', p.value));
  }
  min(n: number, message?: string): this {
    return this.withCheck(minLength(n, message));
  }
  max(n: number, message?: string): this {
    return this.withCheck(maxLength(n, message));
  }
  regex(pattern: RegExp, message?: string): this {
    return this.withCheck(stringFormat('regex', pattern, message));
  }
  /** z.uuid() / z.iso.datetime(): a string whose format check runs first. */
  static format(format: 'uuid' | 'datetime', pattern: RegExp): ZodString {
    const s = new ZodString();
    s.checks = [stringFormat(format, pattern)];
    return s;
  }
}

export class ZodNumber extends ZodType {
  protected parseType(p: Payload): void {
    const v = p.value;
    if (typeof v === 'number' && Number.isFinite(v)) return;
    p.issues.push(invalidType('number', v));
  }
  /** zod's safeint format: a non-integer stops the checks after it (continue: false). */
  int(): this {
    return this.withCheck({
      run: (p) => {
        const v = p.value as number;
        if (!Number.isInteger(v)) {
          p.issues.push(invalidType('int', v, false));
          return;
        }
        if (!Number.isSafeInteger(v)) {
          p.issues.push(v > 0 ? tooBig('int', Number.MAX_SAFE_INTEGER, true) : tooSmall('int', Number.MIN_SAFE_INTEGER, true));
        }
      },
    });
  }
  nonnegative(): this {
    return this.withCheck({ run: (p) => void ((p.value as number) >= 0 || p.issues.push(tooSmall('number', 0, true))) });
  }
  positive(): this {
    return this.withCheck({ run: (p) => void ((p.value as number) > 0 || p.issues.push(tooSmall('number', 0, false))) });
  }
}

export class ZodBoolean extends ZodType {
  protected parseType(p: Payload): void {
    if (typeof p.value !== 'boolean') p.issues.push(invalidType('boolean', p.value));
  }
}

export class ZodUnknown extends ZodType {
  protected parseType(): void {}
}

/** z.literal(v) and z.enum([...]): a value from a fixed set. */
export class ZodValues extends ZodType {
  constructor(readonly values: readonly unknown[]) {
    super();
  }
  protected parseType(p: Payload): void {
    if (this.values.includes(p.value)) return; // SameValueZero, as zod's Set.has
    p.issues.push({
      code: 'invalid_value',
      path: [],
      message: this.values.length === 1 ? `Invalid input: expected ${primitive(this.values[0])}` : `Invalid option: expected one of ${this.values.map(primitive).join('|')}`,
    });
  }
}

export class ZodArray extends ZodType {
  constructor(readonly element: ZodType) {
    super();
  }
  protected parseType(p: Payload): void {
    const input = p.value;
    if (!Array.isArray(input)) {
      p.issues.push(invalidType('array', input));
      return;
    }
    // zod's capSize: an array longer than a leading max / exact length check fails that check
    // (continue: false) before any element is parsed.
    const caps: [number, Check][] = [];
    for (const ch of this.checks) {
      if (!ch.size) break;
      if (ch.size.cap !== undefined) caps.push([ch.size.cap, ch]);
    }
    if (caps.length && input.length > Math.min(...caps.map(([c]) => c))) {
      for (const [max, ch] of caps) {
        if (input.length > max && ch.when!(p)) {
          const start = p.issues.length;
          ch.run(p);
          p.issues[start]!.continue = false;
          return;
        }
      }
    }
    const out: unknown[] = new Array<unknown>(input.length);
    p.value = out;
    for (let i = 0; i < input.length; i++) {
      const r = this.element.run({ value: input[i], issues: [] });
      if (r.issues.length) p.issues.push(...prefix(i, r.issues));
      out[i] = r.value;
    }
  }
  min(n: number, message?: string): this {
    return this.withCheck(minLength(n, message));
  }
  max(n: number, message?: string): this {
    return this.withCheck(maxLength(n, message));
  }
  length(n: number, message?: string): this {
    return this.withCheck(exactLength(n, message));
  }
}

export class ZodObject extends ZodType {
  constructor(
    readonly shape: Record<string, ZodType>,
    readonly unknownKeys: 'strip' | 'strict',
  ) {
    super();
    for (const [k, v] of Object.entries(shape)) if (!(v instanceof ZodType)) throw new Error(`Invalid element at key "${k}": expected a Zod schema`);
  }
  strict(): ZodObject {
    const o = new ZodObject(this.shape, 'strict');
    o.checks = this.checks;
    return o;
  }
  protected parseType(p: Payload): void {
    const input = p.value;
    if (!isObject(input)) {
      p.issues.push(invalidType('object', input));
      return;
    }
    const out: Record<string, unknown> = {};
    p.value = out;
    for (const key of Object.keys(this.shape)) {
      if (key === '__proto__') continue;
      const el = this.shape[key]!;
      const r = el.run({ value: input[key], issues: [] });
      // zod's handlePropertyResult
      const present = key in input;
      if (!present && el.optout === 'optional' && el.optin === 'optional') continue;
      if (r.issues.length) {
        if (el.optin !== undefined && el.optout === 'optional' && !present) continue;
        p.issues.push(...prefix(key, r.issues));
      }
      if (!present && el.optin === undefined) {
        if (!r.issues.length) p.issues.push({ code: 'invalid_type', path: [key], message: 'Invalid input: expected nonoptional, received undefined' });
        continue;
      }
      if (r.value === undefined) {
        if (present) out[key] = undefined;
      } else out[key] = r.value;
    }
    if (this.unknownKeys === 'strict') {
      const unrecognized: string[] = [];
      for (const key in input) if (key === '__proto__' || !Object.prototype.hasOwnProperty.call(this.shape, key)) unrecognized.push(key);
      if (unrecognized.length) {
        p.issues.push({ code: 'unrecognized_keys', path: [], continue: true, message: `Unrecognized key${unrecognized.length > 1 ? 's' : ''}: ${unrecognized.map(primitive).join(', ')}` });
      }
    }
  }
}

const NUMERIC_KEY = /^-?\d+(?:\.\d+)?$/;

/** z.record(keySchema, valueSchema) with a key schema that lists no fixed values (z.string()…). */
export class ZodRecord extends ZodType {
  constructor(
    readonly keyType: ZodType,
    readonly valueType: ZodType,
  ) {
    super();
    if (keyType instanceof ZodValues) throw new Error('zod shim: records with enumerated keys are not supported');
  }
  protected parseType(p: Payload): void {
    const input = p.value;
    if (!isPlainObject(input)) {
      p.issues.push(invalidType('record', input));
      return;
    }
    const out: Record<string, unknown> = {};
    p.value = out;
    for (const key of Reflect.ownKeys(input)) {
      if (key === '__proto__' || !Object.prototype.propertyIsEnumerable.call(input, key)) continue;
      let kr = this.keyType.run({ value: key, issues: [] });
      if (typeof key === 'string' && NUMERIC_KEY.test(key) && kr.issues.length) {
        const retry = this.keyType.run({ value: Number(key), issues: [] });
        if (retry.issues.length === 0) kr = retry;
      }
      if (kr.issues.length) {
        p.issues.push({ code: 'invalid_key', path: [key as string], message: 'Invalid key in record' });
        continue;
      }
      const outKey = kr.value as string;
      if (outKey === '__proto__') continue;
      const r = this.valueType.run({ value: (input as Record<string | symbol, unknown>)[key], issues: [] });
      if (r.issues.length) p.issues.push(...prefix(key as string, r.issues));
      out[outKey] = r.value;
    }
  }
}

export class ZodOptional extends ZodType {
  constructor(readonly inner: ZodType) {
    super();
    this.optin = 'optional';
    this.optout = 'optional';
  }
  protected parseType(p: Payload): void {
    if (p.value === undefined) return;
    this.inner.run(p);
  }
}

export class ZodNullable extends ZodType {
  constructor(readonly inner: ZodType) {
    super();
    this.optin = inner.optin;
    this.optout = inner.optout;
  }
  protected parseType(p: Payload): void {
    if (p.value === null) return;
    this.inner.run(p);
  }
}

// zod core/regexes.js: uuid() without a version, and datetime({offset: false, local: false, precision: null}).
const UUID = /^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$/;
const DATE_SOURCE = `(?:(?:\\d\\d[2468][048]|\\d\\d[13579][26]|\\d\\d0[48]|[02468][048]00|[13579][26]00)-02-29|\\d{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12]\\d|3[01])|(?:0[469]|11)-(?:0[1-9]|[12]\\d|30)|(?:02)-(?:0[1-9]|1\\d|2[0-8])))`;
const DATETIME = new RegExp(`^${DATE_SOURCE}T(?:(?:[01]\\d|2[0-3]):[0-5]\\d:[0-5]\\d(?:\\.\\d+)?(?:Z))$`);

export const z = {
  string: () => new ZodString(),
  number: () => new ZodNumber(),
  boolean: () => new ZodBoolean(),
  unknown: () => new ZodUnknown(),
  literal: (value: unknown) => new ZodValues([value]),
  enum: (values: readonly unknown[]) => {
    if (!Array.isArray(values)) throw new Error('zod shim: z.enum takes an array');
    return new ZodValues(values);
  },
  array: (element: ZodType) => new ZodArray(element),
  object: (shape: Record<string, ZodType>) => new ZodObject(shape, 'strip'),
  strictObject: (shape: Record<string, ZodType>) => new ZodObject(shape, 'strict'),
  record: (key: ZodType, value: ZodType) => new ZodRecord(key, value),
  uuid: () => ZodString.format('uuid', UUID),
  iso: { datetime: () => ZodString.format('datetime', DATETIME) },
};
