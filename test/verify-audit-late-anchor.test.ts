/**
 * A8: verify-audit on a pack whose freeze was made with the anchor pending and anchored later.
 *
 * The audit is recorded as mcp-audit's `freeze --anchor-pending` records one: harness_frozen with
 * the plan; a pending-freeze record (an auditor-signed checkpoint over seq 1..F, the manifest and
 * plan detail, SHA256SUMS of the three, two RFC 3161 tokens over SHA256SUMS, the nonce derived from
 * them); runs carrying that nonce; then one late anchor over the freeze and every run; report, close,
 * final anchor; the pack. The freeze tokens are dated 20 hours before the late anchor.
 *
 * Default: VERIFIED (FREEZE ANCHORED LATE), exit 0, the two freeze-anchor checks replaced and the
 * unwitnessed window printed. --strict-freeze: FAILED on exactly those checks. The record is read from
 * the pack's freeze-pending/ (audit package --freeze-pending) or from the report archive, as
 * mcp-audit's close writes it. Every tamper of the record (rewritten chain, one TSA CA, a token added,
 * a run without the nonce, a call_measured before the freeze or inside the window without the nonce)
 * is FAILED.
 *
 * No network: the anchor service is the in-test stub, the TSAs are throwaway CAs on 127.0.0.1.
 */

import { createHash } from 'node:crypto';
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { pushCheckpoint } from '../src/anchor/anchor.js';
import { checkpointSigningPayload } from '../src/chain/chain.js';
import { freezePendingFromArchive, readUstar } from '../src/audit/freeze-pending.js';
import { buildAuditPackage, renderPackage, type PackageResult } from '../src/audit/package.js';
import { findingsDigest, freezeNonce } from '../src/audit/profile.js';
import type { AuditEventInput } from '../src/audit/schemas.js';
import { LATE_ANCHOR_RESULT, renderVerifyAudit, verifyAudit, VerifyAuditJsonSchema, type VerifyAuditOptions, type VerifyAuditResult } from '../src/audit/verify-audit.js';
import { chainIdFromPublicKeyPem } from '../src/crypto/keys.js';
import { KronicleLite } from '../src/index.js';
import { startAnchorStub, STUB_LICENSE, type AnchorBackend } from './helpers/anchor-stub.js';
import { CLI, cleanEnv, tempDir } from './helpers/fs.js';
import { makeTsa, serveTsa, type TestTsa } from './helpers/tsa.js';

const AUDIT = 'isokron-late-2026-11';
const H = 'ab'.repeat(32);
const sha = (b: string | Buffer) => createHash('sha256').update(b).digest('hex');
const TSA_NAMES = ['alpha', 'beta'] as const;
const HOURS_20 = 20 * 3600 * 1000;

let backend: AnchorBackend;
let tsas: TestTsa[];
let servers: { url: string; stop(): Promise<void> }[];
beforeAll(async () => {
  backend = await startAnchorStub();
  tsas = [makeTsa({ name: 'Alpha' }), makeTsa({ name: 'Beta' })];
  servers = await Promise.all(tsas.map((t) => serveTsa(t)));
});
afterAll(async () => {
  await backend.stop();
  await Promise.all(servers.map((s) => s.stop()));
});

/** A deterministic ustar archive, as mcp-audit's run and report archives are written. */
function tar(entries: { name: string; data: Buffer }[]): Buffer {
  const parts: Buffer[] = [];
  for (const e of entries) {
    const h = Buffer.alloc(512);
    h.write(e.name, 0, 'ascii');
    h.write('0000644\0', 100, 'ascii');
    h.write('0000000\0', 108, 'ascii');
    h.write('0000000\0', 116, 'ascii');
    h.write(e.data.length.toString(8).padStart(11, '0') + '\0', 124, 'ascii');
    h.write('00000000000\0', 136, 'ascii');
    h.write('        ', 148, 'ascii');
    h.write('0', 156, 'ascii');
    h.write('ustar\0', 257, 'ascii');
    h.write('00', 263, 'ascii');
    let sum = 0;
    for (const b of h) sum += b;
    h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 'ascii');
    parts.push(h, e.data, Buffer.alloc((512 - (e.data.length % 512)) % 512));
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}

/** cm_before_freeze, cm_in_window: a call_measured (a run kind with no nonce) before the freeze or inside the window. */
type Variant = 'cm_before_freeze' | 'cm_in_window' | 'pack_dir' | 'report_archive' | 'anchored_before_runs' | 'rewritten_chain' | 'one_ca' | 'token_added' | 'run_without_nonce';

interface Built {
  dataDir: string;
  pkg: string;
  fp: string;
  genesis: string;
  rootsDir: string;
  pendingDir: string;
  nonce: string;
  packaged: PackageResult;
}

async function build(variant: Variant): Promise<Built> {
  const dataDir = tempDir('kl-late-store-');
  const work = tempDir('kl-late-work-');
  const tsDir = join(work, 'timestamps');
  mkdirSync(tsDir);
  const store = new KronicleLite({ dataDir });
  const measured = (event_key: string, extra: Record<string, unknown> = {}) =>
    rec([{ kind: 'call_measured', event_key, payload: { fingerprint: H, tool: 'probe', status: 'ok', is_error: false, latency_ms: 1, bytes_out: 1, ...extra } }], 'harness');
  const blob = (s: string | Buffer, t = 'text/plain') => store.audit.putBlob(typeof s === 'string' ? Buffer.from(s) : s, t);
  const rec = (events: AuditEventInput[], actor = 'auditor') => store.audit.record(AUDIT, events, actor);
  const anchor = async () => {
    store.chain.checkpoint(1, store.chain.head().seq);
    const r = await pushCheckpoint(store, { anchorUrl: backend.url, licenseKey: STUB_LICENSE });
    const row = store.chain.listAnchors().find((a) => a.anchor_id === r.anchor_id)!;
    const tokens = tsas.map((t, k) => ({ tsa: TSA_NAMES[k]!, bytes: t.stamp(row.receipt_json) }));
    for (const t of tokens) writeFileSync(join(tsDir, `${r.anchor_id}.${t.tsa}.tsr`), t.bytes);
  };

  if (variant === 'cm_before_freeze') measured('cm-early', { measured_at: '2026-01-01T00:00:00Z' });
  // ── freeze with the anchor pending ──
  const plan = ['run-1', 'run-2', 'run-3'];
  const manifestBytes = Buffer.from(JSON.stringify({ format: 'mcp-audit/harness-manifest@2', harness: H }) + '\n');
  const planBytes = Buffer.from(JSON.stringify({ runs: plan.map((run_id) => ({ run_id, command: 'probe', criterion: 'pass', write_cap: 5 })) }) + '\n');
  rec([{ kind: 'harness_frozen', event_key: 'freeze', payload: { harness_id: 'harness-v1', fingerprint: H, manifest: blob(manifestBytes, 'application/json'), plan, plan_detail: blob(planBytes, 'application/json') } }]);
  const F = store.chain.head().seq;
  let cp: Record<string, unknown> = { ...store.chain.checkpoint(1, F) };
  if (variant === 'rewritten_chain') {
    // The auditor key holder signs a checkpoint over another root: the chain at the freeze is not this one.
    const fake = { ...cp, root: 'ee'.repeat(32) } as { from_seq: number; to_seq: number; leaf_count: number; root: string };
    cp = { ...fake, signature: store.identity.signer.sign(checkpointSigningPayload(fake)) };
  }
  const pendingDir = join(work, 'freeze-pending');
  mkdirSync(pendingDir);
  const cpBytes = Buffer.from(JSON.stringify(cp, null, 1) + '\n');
  writeFileSync(join(pendingDir, 'checkpoint.json'), cpBytes);
  writeFileSync(join(pendingDir, 'manifest.json'), manifestBytes);
  writeFileSync(join(pendingDir, 'plan-detail.json'), planBytes);
  const sums = Buffer.from(['checkpoint.json', 'manifest.json', 'plan-detail.json'].map((f) => `${sha(readFileSync(join(pendingDir, f)))}  ${f}\n`).join(''));
  writeFileSync(join(pendingDir, 'SHA256SUMS'), sums);
  const frozenAt = new Date(Date.now() - HOURS_20);
  const stampers = variant === 'one_ca' ? [tsas[0]!, tsas[0]!] : tsas;
  const tokens = stampers.map((t, k) => ({ tsa: TSA_NAMES[k]!, file: `SHA256SUMS.${TSA_NAMES[k]}.tsr`, bytes: t.stamp(sums, { genTime: new Date(frozenAt.getTime() + k * 1000) }) }));
  for (const t of tokens) writeFileSync(join(pendingDir, t.file), t.bytes);
  const nonce = freezeNonce(sha(sums), tokens);
  writeFileSync(
    join(pendingDir, 'freeze-pending.json'),
    JSON.stringify({ format: 'isokron/freeze-pending@1', audit_id: AUDIT, fingerprint: H, commit: 'c0ffee', chain_head_seq: F, checkpoint_sha256: sha(cpBytes), sha256sums_sha256: sha(sums), tokens: tokens.map((t) => ({ tsa: t.tsa, gen_time: null, file: t.file, sha256: sha(t.bytes) })), nonce, anchor: 'pending', nonce_recipe: 'freezeNonce(sha256(SHA256SUMS), tokens)', recorded_at: frozenAt.toISOString(), events: [{ seq: F, kind: 'harness_frozen' }] }, null, 1) + '\n',
  );
  if (variant === 'token_added') writeFileSync(join(pendingDir, 'SHA256SUMS.gamma.tsr'), tsas[1]!.stamp(sums));

  if (variant === 'cm_in_window') measured('cm-window');
  // A normal freeze anchor before the runs: the record is then not needed.
  if (variant === 'anchored_before_runs') await anchor();
  // ── runs carrying the pending nonce, then the late anchor over the freeze and every run ──
  rec([
    ...plan.slice(0, 2).map((run_id, i) => ({ kind: 'run_completed' as const, event_key: `run:${run_id}`, payload: { run_id, run_seq: i + 1, fingerprint: H, status: 'pass', nonce: variant === 'run_without_nonce' && i === 1 ? 'ef'.repeat(32) : nonce, result: blob(`run ${i + 1}`) } })),
    { kind: 'run_abandoned' as const, event_key: 'run:run-3', payload: { run_id: 'run-3', reason: 'server crashed at start', fingerprint: H } },
  ], 'harness');
  await anchor(); // the late anchor (or the last-run anchor when the freeze was anchored before the runs)

  // ── report (the record in the report archive, as mcp-audit's close writes it), close, final anchor ──
  const recFiles = ['freeze-pending.json', 'SHA256SUMS', 'checkpoint.json', 'manifest.json', 'plan-detail.json', ...tokens.map((t) => t.file)];
  const report = variant === 'report_archive'
    ? blob(tar([{ name: 'report-archive.json', data: Buffer.from('{}') }, { name: 'report/REPORT.md', data: Buffer.from('# Report\n') }, ...recFiles.map((f) => ({ name: `attachments/freeze-pending.${f}`, data: readFileSync(join(pendingDir, f)) }))]), 'application/x-tar')
    : blob('# Report\n', 'text/markdown');
  rec([{ kind: 'report_issued', event_key: 'report', payload: { report_id: 'R1', report, run_count: 2 } }]);
  rec([{ kind: 'audit_closed', event_key: 'close', payload: { report_id: 'R1', run_count: 2, findings_digest: findingsDigest([]) } }]);
  await anchor();

  const rootsDir = join(work, 'roots');
  mkdirSync(rootsDir);
  tsas.forEach((t, k) => writeFileSync(join(rootsDir, `tsa-${k}.pem`), t.root.pem));
  const doc = (await (await fetch(`${backend.url}/.well-known/anchor-keys.json`)).json()) as { keys: { public_key_pem: string; valid_from: string }[] };
  const genesis = `${chainIdFromPublicKeyPem(doc.keys[0]!.public_key_pem)}@${doc.keys[0]!.valid_from}`;
  const pkg = join(work, 'package');
  const inPackDir = variant !== 'report_archive';
  const packaged = await buildAuditPackage(store, {
    audit_id: AUDIT,
    out: pkg,
    timestamps_dir: tsDir,
    tsa_roots: tsas.map((t) => t.root.pem),
    genesis,
    anchor_keys: doc,
    allowed_signers: 'nobody@isokron.test namespaces="kronicle-lite-reproduction" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n',
    ...(inPackDir && variant !== 'token_added' && variant !== 'rewritten_chain' && variant !== 'one_ca' ? { freeze_pending_dir: pendingDir } : {}),
    stamp_sums: { tsas: TSA_NAMES.map((name, k) => ({ name, url: servers[k]!.url })) },
  });
  const fp = chainIdFromPublicKeyPem(store.identity.signer.public_key_pem);
  store.close();
  return { dataDir, pkg, fp, genesis, rootsDir, pendingDir, nonce, packaged };
}

const trust = (b: Built, extra: Partial<VerifyAuditOptions> = {}): VerifyAuditOptions => ({ seen_dir: tempDir('kl-late-seen-'), key_fingerprint: b.fp, genesis: b.genesis, tsa_roots: tsas.map((t, k) => ({ name: `tsa-${k}`, pem: t.root.pem })), ...extra });
function cli(b: Built, extra: string[] = []) {
  const r = spawnSync(process.execPath, [CLI, 'verify-audit', b.pkg, '--key-fingerprint', b.fp, '--genesis', b.genesis, '--tsa-roots', b.rootsDir, ...extra], { encoding: 'utf8', env: cleanEnv({ KRONICLE_LITE_DATA_DIR: tempDir('kl-late-cli-') }) });
  return { code: r.status, out: r.stdout, err: r.stderr };
}
/** openssl 3+, jq and xxd: VERIFY.md's raw route can run here. */
const rawTools = (() => {
  if (process.platform === 'win32') return false;
  const o = spawnSync('openssl', ['version'], { encoding: 'utf8' });
  return o.status === 0 && /^OpenSSL [3-9]\./.test(o.stdout) && spawnSync('jq', ['--version']).status === 0 && spawnSync('xxd', ['-v']).status === 0 && spawnSync('shasum', ['--version']).status === 0;
})();

/**
 * VERIFY.md of a pack whose runs carry the pending-freeze nonce: it derives that nonce from the
 * record's SHA256SUMS and tokens, never from an anchor receipt, and its raw commands (run on a copy
 * of the pack) print the same nonce the runs carry.
 */
function expectPendingVerifyMd(b: Built): void {
  const md = readFileSync(join(b.pkg, 'VERIFY.md'), 'utf8');
  expect(md).toMatch(/^### \d+\. The freeze nonce every run carries \(freeze made with the anchor pending\)$/m);
  expect(md).not.toContain('The freeze nonce every run carries\n');
  expect(md).not.toMatch(/D=\$\(shasum -a 256 anchors\/[^)]*harness-frozen/);
  expect(md).toContain(`\`${LATE_ANCHOR_RESULT}\` (exit 0), never the plain \`VERIFIED\``);
  if (!rawTools) return;
  const sec = md.slice(md.indexOf('(freeze made with the anchor pending)'));
  const block = /```sh\n([\s\S]*?)```/.exec(sec)![1]!;
  const d = tempDir('kl-late-raw-');
  cpSync(b.pkg, d, { recursive: true });
  const r = spawnSync('bash', ['-euo', 'pipefail', '-c', block], { cwd: d, encoding: 'utf8' });
  const all = r.stdout + r.stderr;
  expect(r.status, all).toBe(0);
  expect(all).not.toMatch(/FAILED|Failure/);
  for (const f of ['checkpoint.json', 'manifest.json', 'plan-detail.json']) expect(r.stdout).toContain(`${f}: OK`);
  expect(r.stdout.match(/^Verification: OK$/gm)).toHaveLength(2);
  expect(r.stdout).toContain('Signature Verified Successfully');
  const lines = r.stdout.trim().split('\n');
  expect(lines).toContain(`${b.nonce}  -`); // the nonce derived by hand
  expect(lines[lines.length - 1]).toBe(b.nonce); // the one nonce every run carries
}

const failedChecks = (r: VerifyAuditResult) => r.checks.filter((c) => c.status === 'fail').map((c) => `${c.claim ?? '-'} | ${c.subject ? `${c.subject} ` : ''}${c.check}: ${c.evidence}`);

/**
 * The tampered record goes into the pack's freeze-pending/ by hand, after packaging (audit package
 * refuses a record that does not hold together), and the pack is resealed as the auditor key holder
 * could: SHA256SUMS re-made, re-signed with the auditor key and re-stamped. Only the record's own
 * proof can then catch it.
 */
async function sealTampered(b: Built): Promise<void> {
  const { isSumsFile, listPackFiles, sha256sums } = await import('../src/audit/verify-audit.js');
  const { cpSync, readdirSync } = await import('node:fs');
  rmSync(join(b.pkg, 'freeze-pending'), { recursive: true, force: true });
  cpSync(b.pendingDir, join(b.pkg, 'freeze-pending'), { recursive: true });
  for (const f of readdirSync(b.pkg).filter(isSumsFile)) rmSync(join(b.pkg, f));
  const sums = sha256sums(b.pkg, listPackFiles(b.pkg).files.filter((f) => !isSumsFile(f)));
  writeFileSync(join(b.pkg, 'SHA256SUMS'), sums);
  const store = new KronicleLite({ dataDir: b.dataDir });
  try {
    writeFileSync(join(b.pkg, 'SHA256SUMS.sig'), Buffer.from(store.identity.signer.sign(Buffer.from(sums)), 'base64'));
  } finally {
    store.close();
  }
  tsas.forEach((t, k) => writeFileSync(join(b.pkg, `SHA256SUMS.${TSA_NAMES[k]}.tsr`), t.stamp(sums)));
}

describe('verify-audit: a freeze made with the anchor pending and anchored later (A8)', () => {
  let b: Built;
  let r: VerifyAuditResult;
  beforeAll(async () => {
    b = await build('pack_dir');
    r = verifyAudit(b.pkg, trust(b));
  });

  it('is VERIFIED WITH UNWITNESSED WINDOW (FREEZE ANCHORED LATE), exit 0, with the unwitnessed window printed', () => {
    const c = cli(b);
    expect(c.err).toBe('');
    expect(c.code, c.out).toBe(0);
    expect(c.out).toMatch(/^RESULT: VERIFIED WITH UNWITNESSED WINDOW \(FREEZE ANCHORED LATE\) {2}integrity, chain, receipts, independent_timestamps, harness_frozen_before_runs, run_sequence, plan_complete, reproductions_signed, closed; unwitnessed window 20h0\dm$/m);
    expect(c.out).toMatch(/^Late anchor \(freeze made with the anchor pending\)$/m);
    expect(c.out).toMatch(/UNWITNESSED WINDOW {2}\S+ → \S+ \(20h0\dm\): seq 2\.\.4 \(3 event\(s\), 3 run\(s\)\) were held only by the auditor's key until the late anchor\./);
    expect(c.out).toMatch(/replaced {9}receipts \/ milestone anchors: "missing an anchor after the freeze \(seq 1\) that commits no run/);
    expect(c.out).toMatch(/replaced {9}harness_frozen_before_runs \/ harness frozen before runs: "the freeze event \(seq 1\) is first committed by 01-\S+ together with 2 run\(s\) \(seq 2\.\.3\)"/);
    expect(c.out).toMatch(/PASS {2}checkpoint +signed by the pinned auditor key; root \S+ is the bundle's root over seq 1\.\.1/);
    expect(c.out).not.toMatch(/^ *FAIL /m);
  });

  it('JSON: verdict verified_late_anchor, ordering by the pending freeze, the late anchor and the window', () => {
    expect(VerifyAuditJsonSchema.safeParse(JSON.parse(JSON.stringify(r))).success).toBe(true);
    expect(r.ok).toBe(true);
    expect(r.verdict).toBe('verified_late_anchor');
    expect(failedChecks(r)).toEqual([]);
    expect(r.ordering).toMatchObject({ status: 'pass', basis: 'pending_freeze', nonce: b.nonce });
    expect(r.late_anchor).toMatchObject({ status: 'accepted', source: 'pack_dir', nonce: b.nonce, checkpoint_to_seq: 1, anchor: { from_seq: 1, to_seq: 4 }, window: { seqs: { from: 2, to: 4 }, events: 3, runs: 3 } });
    expect(r.late_anchor.window!.ms).toBeGreaterThan(HOURS_20 - 60_000);
    expect(r.late_anchor.window!.ms).toBeLessThan(HOURS_20 + 10 * 60_000);
    expect(r.late_anchor.replaced.map((x) => `${x.claim}/${x.check}`)).toEqual(['receipts/milestone anchors', 'harness_frozen_before_runs/harness frozen before runs']);
    expect(r.late_anchor.freeze_stamped.map((x) => x.ca)).toEqual(['tsa-0', 'tsa-1']);
    for (const c of r.claims) expect(c.status, c.claim).toBe('pass');
  });

  it('--strict-freeze: FAILED on exactly the two freeze-anchor checks (exit 1)', () => {
    const c = cli(b, ['--strict-freeze']);
    expect(c.code, c.out).toBe(1);
    expect(c.out).toMatch(/^RESULT: FAILED {2}receipts, harness_frozen_before_runs \(2 failed check\(s\)\)/m);
    const s = verifyAudit(b.pkg, trust(b, { late_anchor: 'strict' }));
    expect(s.verdict).toBe('failed');
    expect(s.late_anchor.status).toBe('strict');
    expect(failedChecks(s)).toEqual([expect.stringMatching(/^receipts \| milestone anchors: missing an anchor after the freeze \(seq 1\) that commits no run/), expect.stringMatching(/^harness_frozen_before_runs \| harness frozen before runs: the freeze event \(seq 1\) is first committed by /)]);
  });

  it('the RESULT line is never the plain VERIFIED: a script keyed on the verdict cannot take it for a pass', () => {
    const out = cli(b).out;
    const result = out.split('\n').find((l) => l.startsWith('RESULT: '))!;
    expect(result.startsWith(`RESULT: ${LATE_ANCHOR_RESULT}  `)).toBe(true);
    expect(result).not.toMatch(/^RESULT: VERIFIED {2}/);
    expect(result).not.toMatch(/^RESULT: VERIFIED$/);
    expect(renderVerifyAudit(r)).toContain(result);
    expect(out).toMatch(/^ {2}VERIFIED WITH UNWITNESSED WINDOW \(FREEZE ANCHORED LATE\): every claim passed, .* for 20h0\dm after the freeze only the auditor's key held the chain\. Exit 0 and JSON ok: true, as for VERIFIED; a plain pass is verdict "verified"/m);
  });

  it('audit package prints the late verdict and the window, not FAIL (renderPackage)', () => {
    expect(b.packaged.check.verdict).toBe('verified_late_anchor');
    const t = renderPackage(b.packaged);
    expect(t).toMatch(/^verify-audit {3}VERIFIED WITH UNWITNESSED WINDOW \(FREEZE ANCHORED LATE\) \(audit profile\) {2}integrity, chain, receipts, independent_timestamps, harness_frozen_before_runs, run_sequence, plan_complete, reproductions_signed, closed$/m);
    expect(t).toMatch(/^ {2}unwitnessed window {2}\S+ → \S+ \(20h0\dm\): seq 2\.\.4 \(3 event\(s\), 3 run\(s\)\) held only by the auditor's key until 01-/m);
    expect(t).not.toMatch(/FAIL/);
  });

  it("VERIFY.md derives the pending-freeze nonce from the record's tokens, and its raw commands give the runs' nonce", () => {
    expectPendingVerifyMd(b);
  });

  it('COMPLETION.txt says the freeze was anchored late, with the window', () => {
    const t = readFileSync(join(b.pkg, 'COMPLETION.txt'), 'utf8');
    expect(t).toMatch(/^Freeze anchor {9}LATE: frozen with the anchor pending \(stamped .* alpha, .* beta\), anchored later by 01-/m);
    expect(t).toMatch(/^ {2}unwitnessed window {2}\S+ → \S+ \(20h0\dm\): 3 run\(s\) recorded before any third party held the chain/m);
  });
});

describe('the record in mcp-audit\'s report archive (attachments/freeze-pending.*)', () => {
  it('is found on the chain and accepted the same way', async () => {
    const b = await build('report_archive');
    const r = verifyAudit(b.pkg, trust(b));
    expect(failedChecks(r)).toEqual([]);
    expect(r.verdict).toBe('verified_late_anchor');
    expect(r.late_anchor).toMatchObject({ status: 'accepted', source: 'report_archive' });
    expect(cli(b).code).toBe(0);
    // VERIFY.md copies the record out of the archive before deriving the nonce.
    expect(readFileSync(join(b.pkg, 'VERIFY.md'), 'utf8')).toMatch(/^mkdir -p freeze-pending-record\.x freeze-pending-record && tar -xf bundle\/blobs\/[0-9a-f]{64} -C freeze-pending-record\.x$/m);
    expectPendingVerifyMd(b);
  }, 60_000);

  it('readUstar and freezePendingFromArchive read only attachments/freeze-pending.* and refuse a non-ustar blob', () => {
    expect(readUstar(Buffer.from('# plain report'))).toBeNull();
    const a = tar([{ name: 'report/REPORT.md', data: Buffer.from('x') }, { name: 'attachments/freeze-pending.freeze-pending.json', data: Buffer.from('{}') }, { name: 'attachments/freeze-pending.evil.sh', data: Buffer.from('rm') }]);
    expect([...freezePendingFromArchive(a)!.keys()]).toEqual(['freeze-pending.json']);
    expect(freezePendingFromArchive(tar([{ name: 'report/REPORT.md', data: Buffer.from('x') }]))).toBeNull();
  });
});

describe('frozen with the anchor pending, anchored before the first run', () => {
  it('the runs carry the pending nonce: accepted, the nonce check replaced, a window with no run in it', async () => {
    const b = await build('anchored_before_runs');
    const strict = verifyAudit(b.pkg, trust(b, { late_anchor: 'strict' }));
    expect(failedChecks(strict)).toEqual([expect.stringMatching(/^harness_frozen_before_runs \| harness frozen before runs: run seq 2, 3 carries a nonce that is not the derived freeze nonce/)]);
    const r = verifyAudit(b.pkg, trust(b));
    expect(failedChecks(r)).toEqual([]);
    expect(r.verdict).toBe('verified_late_anchor');
    expect(r.late_anchor.replaced.map((x) => x.check)).toEqual(['harness frozen before runs']);
    expect(r.late_anchor).toMatchObject({ status: 'accepted', anchor: { from_seq: 1, to_seq: 1 }, window: { seqs: null, events: 0, runs: 0 } });
    expect(r.ordering).toMatchObject({ status: 'pass', basis: 'pending_freeze', nonce: b.nonce });
  });
});

describe('a call_measured without the nonce is FAILED (every run kind the ordering check counts)', () => {
  // Before the fix only run_completed was held to the nonce, so these packs were VERIFIED (FREEZE ANCHORED LATE).
  const cases: [Variant, RegExp][] = [
    ['cm_before_freeze', /^harness_frozen_before_runs \| pending freeze runs carry the nonce: run seq 1 \(call_measured\) is inside the stamped checkpoint \(seq 1\.\.2\), recorded before the freeze stamp; run seq 1 do not carry the pending-freeze nonce and harness \(call_measured\)$/],
    ['cm_in_window', /^harness_frozen_before_runs \| pending freeze runs carry the nonce: run seq 2 do not carry the pending-freeze nonce and harness \(call_measured\)$/],
  ];
  for (const [variant, why] of cases) {
    it(`${variant}: FAILED, the record rejected, the freeze-anchor checks stand (exit 1)`, async () => {
      const b = await build(variant);
      const r = verifyAudit(b.pkg, trust(b));
      expect(r.verdict, failedChecks(r).join('\n')).toBe('failed');
      expect(r.ok).toBe(false);
      expect(r.late_anchor.status).toBe('rejected');
      expect(r.late_anchor.replaced).toEqual([]);
      expect(failedChecks(r)).toContainEqual(expect.stringMatching(why));
      expect(failedChecks(r).some((x) => x.startsWith('harness_frozen_before_runs | harness frozen before runs: '))).toBe(true);
      expect(verifyAudit(b.pkg, trust(b, { late_anchor: 'strict' })).verdict).toBe('failed');
      const c = cli(b);
      expect(c.code, c.out).toBe(1);
      expect(c.out).toMatch(/^RESULT: FAILED /m);
      expect(c.out).not.toContain(LATE_ANCHOR_RESULT);
    }, 60_000);
  }
});

describe('tampered pending-freeze records are FAILED', () => {
  const cases: [Variant, RegExp][] = [
    ['rewritten_chain', /checkpoint: the checkpoint root \S+ is not the bundle's root over seq 1\.\.1 .*the chain was rewritten after the freeze stamp/],
    ['one_ca', /freeze stamped: .*valid tokens under 1 pinned TSA CA\(s\), two different CAs are required/],
    ['token_added', /record: .*a token is not in the record \(a token added later changes the nonce\)/],
    ['run_without_nonce', /runs carry the nonce: run seq 3 do not carry the pending-freeze nonce and harness/],
  ];
  for (const [variant, why] of cases) {
    it(`${variant}: FAILED, the record rejected, the freeze-anchor checks stand`, async () => {
      const b = await build(variant);
      if (variant !== 'run_without_nonce') await sealTampered(b);
      const r = verifyAudit(b.pkg, trust(b));
      expect(r.verdict, failedChecks(r).join('\n')).toBe('failed');
      expect(r.late_anchor.status).toBe('rejected');
      expect(failedChecks(r).join('\n')).toMatch(why);
      expect(failedChecks(r).some((x) => x.startsWith('harness_frozen_before_runs | harness frozen before runs: the freeze event (seq 1) is first committed by'))).toBe(true);
      expect(cli(b).code).toBe(1);
    }, 60_000);
  }
});
