/**
 * The shims the standalone verifier is built with give the same results as the packages
 * kronicle-lite uses (zod 4, canonicalize, @noble/hashes), on a corpus of valid and mutated inputs:
 * every payload schema the verifier parses with, claims.json, RFC 8785 canonical JSON and SHA-256.
 *
 * The real side is the source imported normally (with the packages); the shim side is the same
 * source bundled exactly as verify.mjs is.
 */

import { beforeAll, describe, expect, it } from 'vitest';

import * as real from './entries/schemas.js';
import { importBundled } from './helpers.js';
import { join } from 'node:path';

type Mod = typeof real;
let shim: Mod;
beforeAll(async () => {
  shim = await importBundled<Mod>(join(__dirname, 'entries', 'schemas.ts'));
});

const SHA = 'ab'.repeat(32);
const BLOB = { sha256: SHA, size: 10, media_type: 'text/plain' };
const UUID = '01a1c0a2-8192-7f52-b0ac-e43c4d3a6e58';
const COMMON = { audit_id: 'acme-2026', event_key: 'k1', measured_at: '2026-11-09T14:07:20.000Z' };

/** A valid payload of every kind, with every optional field present. */
const BASES: Record<string, Record<string, unknown>> = {
  catalog_snapshot: { ...COMMON, fingerprint: SHA, server: { name: 'acme', version: '1.0' }, tool_count: 3, bytes: 10, tokens: { cl100k: 5 }, snapshot: BLOB },
  call_measured: { ...COMMON, fingerprint: SHA, tool: 'bench', status: 'ok', is_error: false, latency_ms: 1.5, bytes_in: 1, bytes_out: 2, tokens: { bytes: 3 }, request: BLOB, response: { ...BLOB, redacted: true } },
  finding: { ...COMMON, finding_id: 'F1', status: 'discovered', title: 't', severity: 'S2', class: 'c', fingerprint: SHA, detail: BLOB, evidence: [UUID] },
  gate_result: { ...COMMON, finding_id: 'F1', gate: 'refuter', verdict: 'upheld', report: BLOB, evidence: [UUID] },
  fix_applied: { ...COMMON, finding_id: 'F1', ref: 'https://example.test/pr/1', fingerprint_before: SHA, fingerprint_after: SHA, diff: BLOB, evidence: [UUID] },
  harness_frozen: { ...COMMON, harness_id: 'h1', fingerprint: SHA, manifest: BLOB, hypotheses: BLOB, planned_runs: 2, plan: ['run-1', 'run-2'], plan_detail: BLOB, title: 't' },
  run_completed: { ...COMMON, run_id: 'run-1', run_seq: 1, fingerprint: SHA, status: 'pass', capture: 'complete', interruption: 'x', nonce: SHA, result: BLOB, evidence: [UUID] },
  report_issued: { ...COMMON, report_id: 'R1', report: BLOB, run_count: 2, title: 't', evidence: [UUID] },
  run_abandoned: { ...COMMON, run_id: 'run-2', reason: 'r', fingerprint: SHA, detail: BLOB, evidence: [UUID] },
  reproduction_signed: { ...COMMON, finding_id: 'F1', signer: 'a@b.test', reproduced_at: '2026-12-01T10:00:00Z', commands: BLOB, output: BLOB, signature: BLOB, evidence: [UUID] },
  audit_closed: { ...COMMON, report_id: 'R1', run_count: 2, findings_digest: SHA },
  regression_result: { ...COMMON, finding_id: 'F1', fingerprint_before: SHA, fingerprint_after: SHA, verdict: 'improved', deltas: { a: 1.5 }, report: BLOB, evidence: [UUID] },
};

/** JSON values that hit every check: types, bounds, formats, safe-integer edges, surrogate pairs. */
const VALUES: unknown[] = [
  null, true, false, 0, -0, 1, -1, 1.5, 2 ** 53, -(2 ** 53), 2 ** 53 - 1, JSON.parse('1e400'), 1e21,
  '', 'x', 'A', 'run-1', 'a'.repeat(32), 'a'.repeat(33), 'a'.repeat(64), 'a'.repeat(65), 'a'.repeat(100), 'a'.repeat(101), 'a'.repeat(128), 'a'.repeat(129), 'a'.repeat(200), 'a'.repeat(201), 'a'.repeat(500), 'a'.repeat(501),
  '😀'.repeat(100), '😀'.repeat(101), '😀'.repeat(200), '😀'.repeat(201), 'a\uD800b',
  SHA, 'AB'.repeat(32), `${'a'.repeat(63)}g`, '-bad-id', 'id with space', 'a@b.test', 'a,b',
  UUID, UUID.toUpperCase(), '00000000-0000-0000-0000-000000000000', '01a1c0a2-8192-9f52-b0ac-e43c4d3a6e58', 'not-a-uuid',
  '2026-11-09T14:07:20Z', '2026-11-09T14:07:20.123456Z', '2026-11-09T14:07Z', '2026-11-09T14:07:20+01:00', '2026-02-29T00:00:00Z', '2028-02-29T00:00:00Z', '2026-13-01T00:00:00Z', '2026-11-09',
  'discovered', 'accepted', 'S2', 'info', 'upheld', 'refuted', 'improved', 'complete', 'interrupted',
  'isokron-evidence-pack-claims/1', 'integrity', 'chain',
  [], [1], ['x'], [UUID, UUID], ['run-1', 'run-1'], [null],
  {}, { a: 1 }, { sha256: SHA, size: 1 }, { sha256: SHA, size: 1, redacted: false }, { sha256: SHA, size: -1, extra: 1 }, { name: 'x' }, { '': 1 }, { ['k'.repeat(65)]: 1 }, { ['1'.repeat(65)]: 1 }, { a: 'x' },
  Object.fromEntries(Array.from({ length: 17 }, (_, i) => [`t${i}`, i])), Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`d${i}`, i])),
  JSON.parse('{"__proto__": 1}'), JSON.parse('{"constructor": 1}'),
];

/** Every input to try for one schema: the base, each key removed, each key set to each value, unknown keys, and one level down. */
function mutations(base: Record<string, unknown>): unknown[] {
  const out: unknown[] = [base, ...VALUES, { ...base, zz: 1 }, { ...base, zz: 1, yy: 2 }, JSON.parse(`{"__proto__": 1, ${JSON.stringify(base).slice(1)}`)];
  for (const k of Object.keys(base)) {
    const { [k]: _gone, ...rest } = base;
    void _gone;
    out.push(rest);
    for (const v of VALUES) out.push({ ...base, [k]: v });
    const inner = base[k];
    if (inner && typeof inner === 'object' && !Array.isArray(inner)) {
      for (const ik of Object.keys(inner)) {
        const { [ik]: _g, ...irest } = inner as Record<string, unknown>;
        void _g;
        out.push({ ...base, [k]: irest });
        for (const v of VALUES) out.push({ ...base, [k]: { ...(inner as object), [ik]: v } });
      }
      out.push({ ...base, [k]: { ...(inner as object), zz: 1 } });
    }
    if (Array.isArray(inner)) {
      for (const v of VALUES) out.push({ ...base, [k]: [v] }, { ...base, [k]: [...inner, v] });
      out.push({ ...base, [k]: [...inner, ...inner] }, { ...base, [k]: Array(101).fill(inner[0]) }, { ...base, [k]: Array.from({ length: 2001 }, (_, i) => `run-${i}`) });
    }
  }
  return out;
}

const issues = (r: { success: boolean; data?: unknown; error?: { issues: { code: string; path: PropertyKey[]; message: string }[] } }) =>
  r.success ? { ok: true, data: r.data } : { ok: false, issues: r.error!.issues.map((i) => ({ code: i.code, path: i.path.map(String), message: i.message })) };

describe('the zod shim gives zod 4 results for every schema the verifier parses with', () => {
  for (const kind of Object.keys(BASES)) {
    it(`${kind}: the same pass / fail, parsed value and issues (code, path, message, order)`, () => {
      const realSchema = real.PAYLOAD_SCHEMAS[kind as keyof typeof real.PAYLOAD_SCHEMAS];
      const shimSchema = shim.PAYLOAD_SCHEMAS[kind as keyof typeof shim.PAYLOAD_SCHEMAS];
      const inputs = mutations(BASES[kind]!);
      expect(realSchema.safeParse(BASES[kind]).success, 'the base payload is valid').toBe(true);
      let failures = 0;
      for (const input of inputs) {
        const a = issues(realSchema.safeParse(input));
        const b = issues(shimSchema.safeParse(input) as never);
        expect(b, JSON.stringify(input)?.slice(0, 300)).toStrictEqual(a);
        if (!a.ok) failures++;
        for (const format of ['kronicle-lite-evidence-bundle/1', 'kronicle-lite-evidence-bundle/2', 'kronicle-lite-evidence-bundle/3'] as const) {
          expect(shim.parseAuditPayloadIn(format, kind as never, input)).toStrictEqual(real.parseAuditPayloadIn(format, kind as never, input));
        }
      }
      expect(failures).toBeGreaterThan(inputs.length / 2);
    });
  }

  it('blob refs and claims.json', () => {
    for (const input of mutations(BLOB)) expect(issues(shim.BlobRefSchema.safeParse(input) as never)).toStrictEqual(issues(real.BlobRefSchema.safeParse(input)));
    const claims = { format: 'isokron-evidence-pack-claims/1', audit_id: 'a', claims: ['integrity', 'chain'], runs: { count: 1, seqs: [1], interruptions: [{ run_seq: 1, event_key: 'run:1', note: null }] } };
    expect(real.ClaimsFileSchema.safeParse(claims).success).toBe(true);
    for (const input of mutations(claims)) expect(issues(shim.ClaimsFileSchema.safeParse(input) as never), JSON.stringify(input)?.slice(0, 300)).toStrictEqual(issues(real.ClaimsFileSchema.safeParse(input)));
    const runs = claims.runs;
    for (const input of mutations(runs)) {
      const c = { ...claims, runs: input };
      expect(issues(shim.ClaimsFileSchema.safeParse(c) as never)).toStrictEqual(issues(real.ClaimsFileSchema.safeParse(c)));
    }
  });

  it('chain events', () => {
    const ev = { seq: 1, event_id: UUID, event_type: 'audit.finding', payload: { a: 1 }, actor_id: 'auditor', occurred_at: '2026-11-09T14:07:20.000Z', nonce: 'a'.repeat(32), prev_hash: SHA, this_hash: SHA, idempotency_key: null };
    for (const input of mutations(ev)) expect(issues(shim.ChainEventSchema.safeParse(input) as never)).toStrictEqual(issues(real.ChainEventSchema.safeParse(input)));
  });
});

describe('canonical JSON and SHA-256 on node built-ins', () => {
  const values: unknown[] = [
    ...VALUES.filter((v) => !(typeof v === 'number' && !Number.isFinite(v))),
    { b: 1, a: [1, 'x', null, { d: 1e21, c: 5e-7 }], é: 'ü', '€': '😀', '10': 1, '9': 2 },
    { n: [0.1 + 0.2, -0, 1e-7, 123456789012345680000, 4.5, -1e-300] },
    { u: undefined, s: 'line\n"quote"\\ \u0001' },
    [undefined, () => 1],
    { toJSON: () => ({ z: 1 }) },
  ];
  it('canonicalize: the same string as the canonicalize package, and the same errors', () => {
    for (const v of values) expect(shim.canonicalize(v)).toBe(real.canonicalize(v));
    for (const bad of [NaN, Infinity, { a: -Infinity }, [NaN]]) expect(() => shim.canonicalize(bad)).toThrow(/NaN is not allowed|Infinity is not allowed/);
    for (const bad of [NaN, Infinity]) expect(() => shim.canonicalize(bad)).toThrow(String((() => { try { real.canonicalize(bad); } catch (e) { return (e as Error).message; } })()));
    expect(() => shim.canonicalize(undefined)).toThrow('value cannot be canonicalized (not JSON)');
  });
  it('sha256Hex: the same digest as @noble/hashes, for strings and bytes', () => {
    for (const s of ['', 'abc', '😀', 'a\uD800b', 'x'.repeat(100_000)]) expect(shim.sha256Hex(s)).toBe(real.sha256Hex(s));
    const bytes = new Uint8Array(Array.from({ length: 1000 }, (_, i) => (i * 7) % 256));
    expect(shim.sha256Hex(bytes)).toBe(real.sha256Hex(bytes));
    expect(shim.sha256Hex(bytes.subarray(3, 900))).toBe(real.sha256Hex(bytes.subarray(3, 900)));
    expect(shim.bytesToHex(bytes.subarray(10, 20))).toBe(real.bytesToHex(bytes.subarray(10, 20)));
  });
});
