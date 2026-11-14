/**
 * Differential: `node verify.mjs` and `kronicle-lite verify-audit` (dist/cli.js) on the same packs
 * with the same arguments and the same data dir give the same stdout (text and --json), the same
 * exit code, the same stderr (up to the program name) and leave the same rollback cache.
 *
 * Packs: one of each bundle format (/1, /2, /3, /3 with a late-anchored freeze) made by kronicle-lite
 * itself, the published sample pack (packages/verify/test/fixtures, real Sectigo and DigiCert tokens),
 * a tampered copy of each, the usage errors, the rollback cache, and the key-rotation case.
 *
 * KL_VERIFY_EXTRA_PACKS=<file.json> adds packs from disk ([{ "name", "dir", "args": [...] }]), for
 * real-world packs that cannot be committed.
 */

import { spawn } from 'node:child_process';
import { appendFileSync, cpSync, existsSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { retirementSigningPayload, successorSigningPayload } from '../../../src/anchor/keychain.js';
import { SEEN_KEYS_FILE } from '../../../src/audit/verify-audit.js';
import { startAnchorStub, type AnchorBackend } from '../../../test/helpers/anchor-stub.js';
import { cleanEnv, tempDir } from '../../../test/helpers/fs.js';
import { makeTsa, serveTsa, type TestTsa } from '../../../test/helpers/tsa.js';
import { sign as edSign } from 'node:crypto';
import { KRONICLE_CLI, PKG_DIR, VERIFY } from './helpers.js';
import { buildPack, newServiceKey, resignPack, type Format, type Pack, type ServiceKey } from './packs.js';

const SAMPLE = join(PKG_DIR, 'test', 'fixtures', 'isokron-sample-evidence-pack');
const SAMPLE_FP = 'd70b311bf6e25c0c20ec3b4645f806f28b8712e212142720eeb51d2c6fa5072b';

interface Run {
  code: number | null;
  out: string;
  err: string;
  cache: unknown;
}

function exec(file: string, args: string[], env: Record<string, string>): Promise<{ code: number | null; out: string; err: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [file, ...args], { env });
    let out = '';
    let err = '';
    child.stdout.setEncoding('utf8').on('data', (c: string) => (out += c));
    child.stderr.setEncoding('utf8').on('data', (c: string) => (err += c));
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, out, err }));
    child.stdin.end();
  });
}

/** The program name is the only allowed difference (usage line, unknown-option hint). */
const normalize = (s: string) =>
  s
    .replace(/; see (kronicle-lite help|node verify\.mjs --help)/g, '; see HELP')
    .replace(/ for (verify-audit|verify\.mjs)\b/g, ' for PROGRAM')
    .replace(/kronicle-lite verify-audit|node verify\.mjs/g, 'PROGRAM');

/** seen_at is the time of the run; everything else in the cache must match. */
const readCache = (dd: string): unknown => {
  const p = join(dd, SEEN_KEYS_FILE);
  if (!existsSync(p)) return null;
  const c = JSON.parse(readFileSync(p, 'utf8')) as { lists?: Record<string, { seen_at?: string }> };
  for (const slot of Object.values(c.lists ?? {})) if (slot && typeof slot === 'object') slot.seen_at = '(time)';
  return c;
};

/**
 * Run both with the same arguments, each in the same data dir path, starting from the same cache
 * (`seed`, when given). Returns [kronicle-lite, verify.mjs].
 */
async function both(args: string[], o: { seed?: string; env?: Record<string, string>; noDataDir?: boolean } = {}): Promise<[Run, Run]> {
  const dd = join(tempDir('kl-vd-dd-'), 'data');
  const out: Run[] = [];
  for (const [file, pre] of [[KRONICLE_CLI, ['verify-audit']], [VERIFY, []]] as const) {
    rmSync(dd, { recursive: true, force: true });
    if (o.seed !== undefined) {
      cpSync(o.seed, dd, { recursive: true });
    }
    const env = cleanEnv({ ...(o.noDataDir ? { KRONICLE_LITE_DATA_DIR: dd } : {}), ...(o.env ?? {}) });
    const r = await exec(file, [...pre, ...args, ...(o.noDataDir ? [] : ['--data-dir', dd])], env);
    out.push({ code: r.code, out: r.out, err: normalize(r.err), cache: readCache(dd) });
  }
  rmSync(dd, { recursive: true, force: true });
  return [out[0]!, out[1]!];
}

/** Results by case, printed at the end (and appended to $KL_VERIFY_DIFF_REPORT when set). */
const results: { group: string; name: string; code: number | null; verdict: string; same: boolean }[] = [];
const verdictOf = (r: Run) => (/^RESULT: (.*?)( {2}|$)/m.exec(r.out)?.[1] ?? (/"verdict": "([a-z_]+)"/.exec(r.out)?.[1] ?? (r.err ? 'usage/error' : '?')));

async function expectSame(group: string, name: string, args: string[], o: Parameters<typeof both>[1] = {}): Promise<Run> {
  const [a, b] = await both(args, o);
  const same = a.code === b.code && a.out === b.out && a.err === b.err && JSON.stringify(a.cache) === JSON.stringify(b.cache);
  results.push({ group, name, code: a.code, verdict: verdictOf(a), same });
  expect(b.out, `${group} / ${name}: stdout`).toBe(a.out);
  expect(b.err, `${group} / ${name}: stderr`).toBe(a.err);
  expect(b.code, `${group} / ${name}: exit code`).toBe(a.code);
  expect(b.cache, `${group} / ${name}: rollback cache`).toEqual(a.cache);
  return a;
}

/** Tampers, each on a fresh copy of the pack. */
const TAMPERS: [string, (d: string) => void][] = [
  ['one byte of a blob flipped', (d) => flip(join(d, 'bundle', 'blobs', readdirSync(join(d, 'bundle', 'blobs')).sort()[0]!))],
  ['one byte of a receipt flipped', (d) => flip(join(d, 'anchors', readdirSync(join(d, 'anchors')).filter((f) => f.endsWith('.receipt.json')).sort()[0]!), 40)],
  ['a timestamp token deleted', (d) => rmSync(join(d, 'anchors', readdirSync(join(d, 'anchors')).filter((f) => f.endsWith('.tsr')).sort()[0]!))],
  ['SHA256SUMS.sig deleted', (d) => rmSync(join(d, 'SHA256SUMS.sig'))],
  ['claims.json edited', (d) => writeFileSync(join(d, 'claims.json'), readFileSync(join(d, 'claims.json'), 'utf8').replace('"integrity"', '"chain", "integrity"'))],
  ['an event payload edited', (d) => writeFileSync(join(d, 'bundle', 'events.jsonl'), readFileSync(join(d, 'bundle', 'events.jsonl'), 'utf8').replace(/"run_seq":\s*1/, '"run_seq":"1"').replace(/"status":\s*"discovered"/, '"status":"found"'))],
  ['an extra file', (d) => writeFileSync(join(d, 'NOTES.txt'), 'added after the freeze\n')],
  ['events.jsonl truncated', (d) => appendFileSync(join(d, 'bundle', 'events.jsonl'), '{"seq":')],
];
function flip(p: string, at = 0): void {
  const b = readFileSync(p);
  const i = Math.min(at, b.length - 1);
  b[i] = b[i]! ^ 0x01;
  rmSync(p);
  writeFileSync(p, b);
}
const copyOf = (dir: string) => {
  const d = join(tempDir('kl-vd-copy-'), 'pack');
  cpSync(dir, d, { recursive: true });
  return d;
};

let backend: AnchorBackend;
let tsas: TestTsa[];
let servers: { url: string; stop(): Promise<void> }[];
const packs = new Map<Format, Pack>();

beforeAll(async () => {
  if (!existsSync(KRONICLE_CLI)) throw new Error(`${KRONICLE_CLI} is missing: run npm run build first`);
  // verify.mjs from this tree (the build is deterministic for a given tree)
  const build = await exec(join(PKG_DIR, 'build.mjs'), [], cleanEnv());
  if (build.code !== 0) throw new Error(`build.mjs failed: ${build.err}`);
  backend = await startAnchorStub();
  tsas = [makeTsa({ name: 'Alpha' }), makeTsa({ name: 'Beta' })];
  servers = await Promise.all(tsas.map((t) => serveTsa(t)));
  const env = { backend, tsas, servers };
  const built = await Promise.all((['v1', 'v2', 'v3', 'v3-late'] as const).map((f) => buildPack(f, env)));
  for (const p of built) packs.set(p.format, p);
});

afterAll(async () => {
  await backend?.stop();
  await Promise.all((servers ?? []).map((s) => s.stop()));
  const lines = results.map((r) => `${r.same ? 'same' : 'DIFF'}  exit ${r.code}  ${r.verdict.padEnd(44)} ${r.group} / ${r.name}`);
  process.stdout.write(`\nverify.mjs vs kronicle-lite verify-audit: ${results.filter((r) => r.same).length}/${results.length} identical\n${lines.join('\n')}\n`);
  if (process.env['KL_VERIFY_DIFF_REPORT']) appendFileSync(process.env['KL_VERIFY_DIFF_REPORT'], lines.join('\n') + '\n');
});

const trust = (p: Pack) => ['--key-fingerprint', p.fp, '--genesis', p.genesis, '--tsa-roots', p.rootsDir];
const ARGSETS: [string, string[]][] = [
  ['default (audit profile)', []],
  ['--profile legacy', ['--profile', 'legacy']],
  ['--json', ['--json']],
  ['--profile legacy --json', ['--profile', 'legacy', '--json']],
  ['--strict-freeze', ['--strict-freeze']],
  ['--require closed,plan_complete', ['--require', 'closed,plan_complete']],
  ['--skip-claim reproductions_signed', ['--skip-claim', 'reproductions_signed']],
  ['--tsa-at-gentime', ['--tsa-at-gentime']],
];

describe.each(['v1', 'v2', 'v3', 'v3-late'] as const)('format %s: the same report and exit code', (format) => {
  it('every option set', async () => {
    const p = packs.get(format)!;
    const first = await expectSame(format, ARGSETS[0]![0], [p.dir, ...trust(p)]);
    // what each format is expected to give (the reference, not the comparison)
    expect(first.code).toBe(format === 'v3' || format === 'v3-late' ? 0 : 1);
    const legacy = await expectSame(format, ARGSETS[1]![0], [p.dir, ...trust(p), '--profile', 'legacy']);
    // PARTIAL is the best the legacy profile gives; a late-anchored freeze is an audit-profile reading (FAILED under legacy)
    expect(legacy.code).toBe(format === 'v3-late' ? 1 : 2);
    for (const [name, extra] of ARGSETS.slice(2)) await expectSame(format, name, [p.dir, ...trust(p), ...extra]);
    await expectSame(format, '--no-tsa (no TSA roots)', [p.dir, '--key-fingerprint', p.fp, '--genesis', p.genesis, '--no-tsa']);
    await expectSame(format, '--no-tsa --profile legacy', [p.dir, '--key-fingerprint', p.fp, '--genesis', p.genesis, '--no-tsa', '--profile', 'legacy']);
    await expectSame(format, 'wrong --key-fingerprint', [p.dir, '--key-fingerprint', 'ab'.repeat(32), '--genesis', p.genesis, '--tsa-roots', p.rootsDir]);
    await expectSame(format, 'no key pinned', [p.dir, '--genesis', p.genesis, '--tsa-roots', p.rootsDir]);
    await expectSame(format, 'compiled genesis pin (the stub list is foreign)', [p.dir, '--key-fingerprint', p.fp, '--tsa-roots', p.rootsDir]);
    await expectSame(format, 'KRONICLE_LITE_DATA_DIR instead of --data-dir', [p.dir, ...trust(p)], { noDataDir: true });
  });

  it('every tamper', async () => {
    const p = packs.get(format)!;
    for (const [name, tamper] of TAMPERS) {
      const d = copyOf(p.dir);
      tamper(d);
      const r = await expectSame(format, `tamper: ${name}`, [d, ...trust(p), ...(format === 'v1' || format === 'v2' ? ['--profile', 'legacy'] : [])]);
      expect(r.code, name).toBe(1);
    }
  });
});

describe('the published sample pack (format /2, real Sectigo and DigiCert tokens, the production genesis pin)', () => {
  it('as published, and tampered', async () => {
    const audit = await expectSame('sample', 'default (audit profile)', [SAMPLE, '--key-fingerprint', SAMPLE_FP]);
    expect(audit.code).toBe(1); // a /2 pack does not meet the 0.11 audit profile
    const legacy = await expectSame('sample', '--profile legacy', [SAMPLE, '--key-fingerprint', SAMPLE_FP, '--profile', 'legacy']);
    expect(legacy.code).toBe(2);
    expect(legacy.out).toMatch(/^RESULT: PARTIAL {2}integrity, chain, receipts, independent_timestamps, harness_frozen_before_runs, run_sequence$/m);
    await expectSame('sample', '--json', [SAMPLE, '--key-fingerprint', SAMPLE_FP, '--json']);
    await expectSame('sample', '--profile legacy --json', [SAMPLE, '--key-fingerprint', SAMPLE_FP, '--profile', 'legacy', '--json']);
    await expectSame('sample', '--profile legacy --tsa-at-gentime', [SAMPLE, '--key-fingerprint', SAMPLE_FP, '--profile', 'legacy', '--tsa-at-gentime']);
    await expectSame('sample', 'wrong --key-fingerprint', [SAMPLE, '--key-fingerprint', 'ab'.repeat(32), '--profile', 'legacy']);
    for (const [name, tamper] of TAMPERS) {
      const d = copyOf(SAMPLE);
      tamper(d);
      const r = await expectSame('sample', `tamper: ${name}`, [d, '--key-fingerprint', SAMPLE_FP, '--profile', 'legacy']);
      expect(r.code, name).toBe(1);
    }
  });
});

describe('usage errors: the same message and exit 2', () => {
  it('each', async () => {
    const p = packs.get('v3')!;
    const cases: [string, string[]][] = [
      ['no pack', []],
      ['unknown option', [p.dir, '--key-fingerprnt', p.fp]],
      ['--key-fingerprint without a value', [p.dir, '--key-fingerprint']],
      ['two packs', [p.dir, p.dir, '--key-fingerprint', p.fp]],
      ['--profile strict', [p.dir, '--key-fingerprint', p.fp, '--profile', 'strict']],
      ['--no-tsa with --tsa-roots', [p.dir, ...trust(p), '--no-tsa']],
      ['--require unknown claim', [p.dir, ...trust(p), '--require', 'everything']],
      ['--skip-claim integrity', [p.dir, ...trust(p), '--skip-claim', 'integrity']],
      ['--key inside the pack', [p.dir, '--key', join(p.dir, 'auditor-key.pem'), '--genesis', p.genesis, '--tsa-roots', p.rootsDir]],
      ['--genesis without valid_from', [p.dir, '--key-fingerprint', p.fp, '--genesis', 'ab'.repeat(32)]],
      ['--max-bytes 0', [p.dir, ...trust(p), '--max-bytes', '0']],
      ['--json given twice', [p.dir, ...trust(p), '--json', '--json=false', '--profile', 'legacy', '--profile', 'audit']],
      ['a pack that is not a directory', [join(p.dir, 'SHA256SUMS'), ...trust(p)]],
      ['a pack that does not exist', [join(p.dir, 'nope'), ...trust(p)]],
    ];
    for (const [name, args] of cases) await expectSame('usage', name, args);
    const [, v] = await both([]);
    expect(v.err).toMatch(/^usage: PROGRAM PACK --key-fingerprint SHA256/);
  });
});

describe('the rollback cache: the same check against the same kept list', () => {
  it('a second run reads what the first recorded', async () => {
    const p = packs.get('v3')!;
    const dd = join(tempDir('kl-vd-seed-'), 'data');
    const first = await exec(KRONICLE_CLI, ['verify-audit', p.dir, ...trust(p), '--data-dir', dd], cleanEnv());
    expect(first.out).toMatch(/^key list {7}first seen for this genesis; recorded in /m);
    const second = await expectSame('rollback', 'list seen before', [p.dir, ...trust(p)], { seed: dd });
    expect(second.out).toMatch(/PASS {2}key list rollback {10}at least as new as the list seen /);
    // a damaged cache: the same failure, and neither tool overwrites it
    writeFileSync(join(dd, SEEN_KEYS_FILE), '{"v":1,"lists":[]}');
    const damaged = await expectSame('rollback', 'damaged cache', [p.dir, ...trust(p)], { seed: dd });
    expect(damaged.code).toBe(1);
  });
});

describe('keyListRegression after a planned anchor-key rotation (fixed in 0.11.3)', () => {
  // The data dir has seen R → S (R retired a day ago). An honest pack made two days ago carries the
  // list current then (R alone, active). Before the fix it failed "key list rollback": S is missing.
  const GF = '2026-01-01T00:00:00.000Z';
  const now = Date.now();
  const iso = (t: number) => new Date(t).toISOString();
  const b64 = (k: ServiceKey, m: string) => edSign(null, Buffer.from(m), k.priv).toString('base64');
  const rotated = (r: ServiceKey, s: ServiceKey, sFrom: string) => [
    { key_id: s.id, public_key_pem: s.pem, valid_from: sFrom, status: 'active', successor_signature: b64(r, successorSigningPayload({ key_id: s.id, public_key_pem: s.pem, valid_from: sFrom })), signed_by: r.id },
    { key_id: r.id, public_key_pem: r.pem, valid_from: GF, valid_to: sFrom, status: 'retired', retirement_signature: b64(s, retirementSigningPayload({ key_id: r.id, status: 'retired', valid_to: sFrom })), retirement_signed_by: s.id },
  ];

  it('the honest older pack verifies against the newer list kept (both tools), and a pack stamped after the rotation still fails', async () => {
    const base = packs.get('v2')!;
    const R = newServiceKey();
    const S = newServiceKey();
    const env = { backend, tsas, servers };
    const vf = iso(now - 86400e3);
    const pin = `${R.fp}@${GF}`;
    const args = (d: string) => [d, '--profile', 'legacy', '--key-fingerprint', base.fp, '--genesis', pin, '--tsa-roots', base.rootsDir];
    const newer: Pack = { ...base, dir: copyOf(base.dir) };
    resignPack(newer, env, S, rotated(R, S, vf), (i) => iso(now - 60e3 + i * 1e3), (i) => new Date(now - 50e3 + i * 1e3));
    const older: Pack = { ...base, dir: copyOf(base.dir) };
    resignPack(older, env, R, [{ key_id: R.id, public_key_pem: R.pem, valid_from: GF, status: 'active' }], (i) => iso(now - 2 * 86400e3 + i * 1e3), (i) => new Date(now - 2 * 86400e3 + 60e3 + i * 1e3));
    const forged: Pack = { ...base, dir: copyOf(base.dir) };
    resignPack(forged, env, R, [{ key_id: R.id, public_key_pem: R.pem, valid_from: GF, status: 'active' }], (i) => iso(now - 2 * 86400e3 + i * 1e3), (i) => new Date(now - 50e3 + i * 1e3));

    // a buyer verified the newer pack first
    const dd = join(tempDir('kl-vd-rot-'), 'data');
    const seenNewer = await exec(VERIFY, [...args(newer.dir), '--data-dir', dd], cleanEnv());
    expect(seenNewer.code, seenNewer.out).toBe(2); // PARTIAL: a legacy pack that passes every check
    expect(statSync(join(dd, SEEN_KEYS_FILE)).isFile()).toBe(true);

    const honest = await expectSame('rotation', 'honest pack made before the rotation', args(older.dir), { seed: dd });
    expect(honest.code, honest.out).toBe(2);
    expect(honest.out).toMatch(/^key list {7}an earlier state of the list seen .*; receipts checked against that newer list$/m);
    expect(honest.out).toMatch(/PASS {2}key list rollback {10}an earlier state of the list seen /);
    expect(honest.out).not.toMatch(/FAIL/);

    const late = await expectSame('rotation', 'old list, stamped after the rotation', args(forged.dir), { seed: dd });
    expect(late.code).toBe(1);
    expect(late.out).toMatch(/FAIL {2}stamped within key validity/);
  });
});

describe('extra packs from disk (KL_VERIFY_EXTRA_PACKS)', () => {
  const file = process.env['KL_VERIFY_EXTRA_PACKS'];
  it.skipIf(!file)('each', async () => {
    const list = JSON.parse(readFileSync(file!, 'utf8')) as { name: string; dir: string; args: string[] }[];
    for (const e of list) await expectSame('extra', e.name, [e.dir, ...e.args]);
  });
});
