/**
 * The audit profile (0.11.0): the tests that define done for the verifier fixes W1–W3.
 *
 * A golden pack is recorded the way an IsoKron MCP audit records one (freeze with a plan of run IDs,
 * freeze anchor and two TSA tokens, runs carrying the derived nonce, an abandoned run, a finding
 * reproduced and signed off by a human with an SSH key, the report, the close, a final anchor), then
 * packaged with SHA256SUMS stamped by two TSAs. It verifies with nothing pending. Then each tamper
 * exits 1, one test each, and names the check that caught it. A 0.10.0 pack exits 2 with PARTIAL.
 *
 * No network: the anchor service is the in-test stub, the TSAs are throwaway CAs
 * (test/helpers/tsa.ts) served on 127.0.0.1, the reproducer key lives in memory.
 */

import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign as edSign, type KeyObject } from 'node:crypto';
import { cpSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { pushCheckpoint } from '../src/anchor/anchor.js';
import { buildAuditPackage, stampAnchor } from '../src/audit/package.js';
import { findingsDigest, freezeNonce, REPRODUCTION_NAMESPACE, reproductionStatement } from '../src/audit/profile.js';
import { BUNDLE_FORMAT_V2, BUNDLE_FORMAT_V3, type AuditEventInput } from '../src/audit/schemas.js';
import { allowedSignerLine, parseAllowedSigners, sshSign, verifySshSignature } from '../src/audit/sshsig.js';
import { isSumsFile, listPackFiles, renderVerifyAudit, sha256sums, verifyAudit, VerifyAuditJsonSchema, type VerifyAuditOptions, type VerifyAuditResult } from '../src/audit/verify-audit.js';
import { verifyBundle } from '../src/audit/verify-bundle.js';
import { chainIdFromPublicKeyPem } from '../src/crypto/keys.js';
import { KronicleLite } from '../src/index.js';
import { startAnchorStub, STUB_LICENSE, type AnchorBackend } from './helpers/anchor-stub.js';
import { CLI, cleanEnv, tempDir } from './helpers/fs.js';
import { makeTsa, serveTsa, type TestTsa } from './helpers/tsa.js';

const AUDIT = 'isokron-mcp-2026-12';
const H = 'cd'.repeat(32);
const SIGNER = 'reproducer@isokron.test';
const sha = (b: string | Buffer) => createHash('sha256').update(b).digest('hex');
const TSA_NAMES = ['alpha', 'beta'] as const;

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

/** The reproducer: an Ed25519 key that is not the auditor's (ssh-keygen -Y sign, done in-process). */
interface Reproducer {
  priv: KeyObject;
  raw: Buffer;
  allowed: string;
}
function reproducer(): Reproducer {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const raw = (publicKey.export({ type: 'spki', format: 'der' }) as Buffer).subarray(12);
  return { priv: privateKey, raw, allowed: allowedSignerLine(SIGNER, raw, REPRODUCTION_NAMESPACE) };
}
const sshSignWith = (k: Reproducer, message: string) => sshSign(message, { namespace: REPRODUCTION_NAMESPACE, public_key: k.raw, sign: (d) => edSign(null, d, k.priv) });

type Tamper =
  | 'unplanned_run'
  | 'missing_planned_run'
  | 'duplicate_run'
  | 'run_before_freeze_anchor'
  | 'nonce_mismatch'
  | 'foreign_stub'
  | 'unsigned_accepted_finding'
  | 'wrong_run_count'
  | 'tampered_signoff'
  | 'allow_pending'
  | 'legacy';

interface Golden {
  dataDir: string;
  pkg: string;
  rootsDir: string;
  fp: string;
  genesis: string;
  reproducer: Reproducer;
  pack: Awaited<ReturnType<typeof buildAuditPackage>>;
  freezeNonce: string;
  freezeDigest: string;
}

/**
 * Record an audit as mcp-audit's evidence module will: harness_frozen with the plan → anchor + two
 * TSA tokens → runs with the derived nonce (and one abandoned) → anchor → finding, refuter, human
 * sign-off, acceptance → report → close → anchor; then package and stamp SHA256SUMS.
 */
async function build(tamper?: Tamper): Promise<Golden> {
  const dataDir = tempDir('kl-vp-store-');
  const work = tempDir('kl-vp-work-');
  const tsDir = join(work, 'timestamps');
  mkdirSync(tsDir);
  const store = new KronicleLite({ dataDir });
  const rep = reproducer();
  const blob = (s: string, t = 'text/plain') => store.audit.putBlob(Buffer.from(s), t);
  const rec = (events: AuditEventInput[], actor = 'auditor') => store.audit.record(AUDIT, events, actor);
  const anchor = async (): Promise<{ digest: string; nonce: string }> => {
    store.chain.checkpoint(1, store.chain.head().seq);
    const r = await pushCheckpoint(store, { anchorUrl: backend.url, licenseKey: STUB_LICENSE });
    const row = store.chain.listAnchors().find((a) => a.anchor_id === r.anchor_id)!;
    const tokens = tsas.map((t, k) => ({ tsa: TSA_NAMES[k]!, bytes: t.stamp(row.receipt_json) }));
    for (const t of tokens) writeFileSync(join(tsDir, `${r.anchor_id}.${t.tsa}.tsr`), t.bytes);
    return { digest: sha(row.receipt_json), nonce: freezeNonce(sha(row.receipt_json), tokens) };
  };

  let freeze: { digest: string; nonce: string } | null = null;
  if (tamper === 'legacy') {
    // A 0.10.0 audit: no plan, the receipt digest as the nonce, no sign-off and no close (format /2).
    rec([{ kind: 'harness_frozen', event_key: 'freeze', payload: { harness_id: 'harness-v1', fingerprint: H, manifest: blob('harness files'), planned_runs: 2 } }]);
    const f = await anchor();
    rec([1, 2].map((n) => ({ kind: 'run_completed', event_key: `run:${n}`, payload: { run_id: `run-${n}`, run_seq: n, fingerprint: H, status: 'pass', nonce: f.digest, result: blob(`run ${n}`) } })), 'proxy');
    await anchor();
    rec([{ kind: 'report_issued', event_key: 'report', payload: { report_id: 'R1', report: blob('# Report'), run_count: 2 } }]);
    await anchor();
  } else {
    const plan = tamper === 'missing_planned_run' ? ['run-1', 'run-2', 'run-3', 'run-4', 'run-5'] : ['run-1', 'run-2', 'run-3', 'run-4'];
    rec([{ kind: 'harness_frozen', event_key: 'freeze', payload: { harness_id: 'harness-v1', fingerprint: H, manifest: blob('harness files'), hypotheses: blob('H1'), plan, plan_detail: blob(JSON.stringify(plan.map((run_id) => ({ run_id, command: 'bench', criterion: 'pass', write_cap: 5 }))), 'application/json') } }]);
    const early = tamper === 'run_before_freeze_anchor';
    const runEvents = (nonce: string): AuditEventInput[] => {
      const ids = tamper === 'unplanned_run' ? ['run-1', 'run-2', 'run-9'] : tamper === 'duplicate_run' ? ['run-1', 'run-2', 'run-2'] : ['run-1', 'run-2', 'run-3'];
      return [
        ...ids.map((run_id, i) => ({ kind: 'run_completed' as const, event_key: `run:${i + 1}`, payload: { run_id, run_seq: i + 1, fingerprint: H, status: 'pass', nonce, result: blob(`run ${i + 1} wire log`) } })),
        { kind: 'run_abandoned' as const, event_key: 'run:4', payload: { run_id: 'run-4', reason: 'harness refused: API key not exported', fingerprint: H } },
      ];
    };
    if (early) rec(runEvents('ef'.repeat(32)), 'proxy');
    const f = await anchor();
    freeze = f;
    if (!early) {
      if (tamper === 'foreign_stub') store.docs.putDocument({ slug: 'notes', title: 'notes', markdown: '# another project\n', actor_id: 'a' });
      rec(runEvents(tamper === 'nonce_mismatch' ? f.digest : f.nonce), 'proxy');
    }
    await anchor();
    // F1: found, upheld by the refuter, reproduced and signed off by a human, accepted. F2: refuted.
    rec([
      { kind: 'finding', event_key: 'f1', payload: { finding_id: 'F1', status: 'discovered', title: 'lost update', severity: 'S2' } },
      { kind: 'gate_result', event_key: 'f1-gate', payload: { finding_id: 'F1', gate: 'refuter', verdict: 'upheld' } },
      { kind: 'finding', event_key: 'f2', payload: { finding_id: 'F2', status: 'discovered', title: 'hedged claim' } },
      { kind: 'gate_result', event_key: 'f2-gate', payload: { finding_id: 'F2', gate: 'refuter', verdict: 'refuted' } },
    ]);
    if (tamper !== 'unsigned_accepted_finding') {
      const commands = blob('./repro.sh F1\n');
      const output = blob('second write lost\n');
      const reproduced_at = '2026-12-01T10:00:00Z';
      const fields = { audit_id: AUDIT, finding_id: 'F1', signer: SIGNER, reproduced_at, commands: commands.sha256, output: output.sha256 };
      // tampered: the human signed a statement about other output than the one recorded
      const signed = tamper === 'tampered_signoff' ? reproductionStatement({ ...fields, output: sha('no lost write\n') }) : reproductionStatement(fields);
      const signature = blob(sshSignWith(rep, signed));
      rec([{ kind: 'reproduction_signed', event_key: 'f1-signoff', payload: { finding_id: 'F1', signer: SIGNER, reproduced_at, commands, output, signature } }], 'human');
    }
    rec([{ kind: 'finding', event_key: 'f1-accept', payload: { finding_id: 'F1', status: 'accepted' } }]);
    rec([{ kind: 'report_issued', event_key: 'report', payload: { report_id: 'R1', report: blob('# Report'), run_count: tamper === 'wrong_run_count' ? 2 : 3 } }]);
    rec([{ kind: 'audit_closed', event_key: 'close', payload: { report_id: 'R1', run_count: 3, findings_digest: findingsDigest([{ finding_id: 'F1', status: 'accepted' }, { finding_id: 'F2', status: 'refuted' }]) } }]);
    await anchor();
    // 0.11.1: `audit stamp --allow-pending` with a third TSA that does not answer records it as pending
    if (tamper === 'allow_pending') {
      const r = await stampAnchor(store, { out_dir: tsDir, tsas: [{ name: 'gamma', url: 'http://127.0.0.1:9/' }], timeoutMs: 2000, allow_pending: true });
      expect(r.pending).toHaveLength(1);
    }
  }

  const rootsDir = join(work, 'roots');
  mkdirSync(rootsDir);
  tsas.forEach((t, k) => writeFileSync(join(rootsDir, `tsa-${k}.pem`), t.root.pem));
  const doc = (await (await fetch(`${backend.url}/.well-known/anchor-keys.json`)).json()) as { keys: { public_key_pem: string; valid_from: string }[] };
  const genesis = `${chainIdFromPublicKeyPem(doc.keys[0]!.public_key_pem)}@${doc.keys[0]!.valid_from}`;
  const pkg = join(work, 'package');
  const pack = await buildAuditPackage(store, {
    audit_id: AUDIT,
    out: pkg,
    timestamps_dir: tsDir,
    tsa_roots: tsas.map((t) => t.root.pem),
    genesis,
    anchor_keys: doc,
    ...(tamper === 'legacy' ? {} : { allowed_signers: rep.allowed }),
    stamp_sums: { tsas: TSA_NAMES.map((name, k) => ({ name, url: servers[k]!.url })) },
  });
  const fp = chainIdFromPublicKeyPem(store.identity.signer.public_key_pem);
  store.close();
  return { dataDir, pkg, rootsDir, fp, genesis, reproducer: rep, pack, freezeNonce: freeze?.nonce ?? '', freezeDigest: freeze?.digest ?? '' };
}

const trust = (g: Golden, extra: Partial<VerifyAuditOptions> = {}): VerifyAuditOptions => ({ seen_dir: tempDir('kl-vp-seen-'), key_fingerprint: g.fp, genesis: g.genesis, tsa_roots: tsas.map((t, k) => ({ name: `tsa-${k}`, pem: t.root.pem })), ...extra });
const args = (g: Golden) => ['--key-fingerprint', g.fp, '--genesis', g.genesis, '--tsa-roots', g.rootsDir];
function cli(a: string[]) {
  const r = spawnSync(process.execPath, [CLI, ...a], { encoding: 'utf8', env: cleanEnv({ KRONICLE_LITE_DATA_DIR: tempDir('kl-vp-cli-') }) });
  return { code: r.status, out: r.stdout, err: r.stderr };
}
const copy = (g: Golden) => {
  const d = join(tempDir('kl-vp-copy-'), 'package');
  cpSync(g.pkg, d, { recursive: true });
  return d;
};
/** Re-make SHA256SUMS, its signature and its two tokens over a pack copy, as the auditor key holder could. */
function reseal(d: string, g: Golden): void {
  for (const f of readdirSync(d).filter(isSumsFile)) rmSync(join(d, f));
  const sums = sha256sums(d, listPackFiles(d).files.filter((f) => !isSumsFile(f)));
  writeFileSync(join(d, 'SHA256SUMS'), sums);
  const store = new KronicleLite({ dataDir: g.dataDir });
  try {
    writeFileSync(join(d, 'SHA256SUMS.sig'), Buffer.from(store.identity.signer.sign(Buffer.from(sums)), 'base64'));
  } finally {
    store.close();
  }
  tsas.forEach((t, k) => writeFileSync(join(d, `SHA256SUMS.${TSA_NAMES[k]}.tsr`), t.stamp(sums)));
}
const failed = (r: VerifyAuditResult) => r.checks.filter((c) => c.status === 'fail').map((c) => `${c.claim ?? '-'} | ${c.subject ? `${c.subject} ` : ''}${c.check}: ${c.evidence}`);
const claimOf = (r: VerifyAuditResult, c: string) => r.claims.find((x) => x.claim === c)!.status;

/** Every tamper exits 1 on the CLI, and the library names the claim and check that caught it. */
function expectCaught(d: string, g: Golden, claim: string, check: RegExp | string): VerifyAuditResult {
  const c = cli(['verify-audit', d, ...args(g)]);
  expect(c.code, c.out).toBe(1);
  expect(c.out).toMatch(/^RESULT: FAILED /m);
  const r = verifyAudit(d, trust(g));
  expect(r.ok).toBe(false);
  expect(r.verdict).toBe('failed');
  expect(claimOf(r, claim), failed(r).join('\n')).toBe('fail');
  expect(failed(r).some((x) => x.startsWith(`${claim} |`) && (typeof check === 'string' ? x.includes(check) : check.test(x))), failed(r).join('\n')).toBe(true);
  return r;
}

describe('the audit profile: a golden pack', () => {
  let g: Golden;
  beforeAll(async () => {
    g = await build();
  });

  it('packages as format /3 with SHA256SUMS stamped twice, the reproducer key, every claim declared', () => {
    expect(g.pack.bundle_format).toBe(BUNDLE_FORMAT_V3);
    expect(g.pack.profile).toBe('audit');
    expect(g.pack.sums_stamps.map((s) => [s.tsa, s.ok])).toEqual([['alpha', true], ['beta', true]]);
    expect(readdirSync(g.pkg).sort()).toEqual(['COMPLETION.txt', 'SHA256SUMS', 'SHA256SUMS.alpha.tsr', 'SHA256SUMS.beta.tsr', 'SHA256SUMS.sig', 'VERIFY.md', 'allowed_signers', 'anchor-keys.json', 'anchors', 'auditor-key.pem', 'bundle', 'claims.json', 'tsa-roots']);
    expect((JSON.parse(readFileSync(join(g.pkg, 'claims.json'), 'utf8')) as { claims: string[] }).claims).toEqual(['integrity', 'chain', 'receipts', 'independent_timestamps', 'harness_frozen_before_runs', 'run_sequence', 'plan_complete', 'reproductions_signed', 'closed']);
    expect(g.pack.check.verdict).toBe('verified');
  });

  it('passes verify-audit with nothing pending: exit 0, VERIFIED, every claim PASS', () => {
    const c = cli(['verify-audit', g.pkg, ...args(g)]);
    expect(c.err).toBe('');
    expect(c.code, c.out).toBe(0);
    expect(c.out).toMatch(/^profile {8}audit /m);
    expect(c.out).toContain('RESULT: VERIFIED  integrity, chain, receipts, independent_timestamps, harness_frozen_before_runs, run_sequence, plan_complete, reproductions_signed, closed');
    expect(c.out).not.toMatch(/FAIL|not checked|not declared|N\/A {2}milestone/);
    expect(c.out).toMatch(/PASS {2}pending stamps +none pending/);
    expect(c.out).toMatch(/PASS {2}milestone anchors +freeze 01-harness-frozen, last run 02-run-abandoned, report 03-audit-closed: each verified and stamped under two pinned TSA CAs/);
    expect(c.out).toMatch(/PASS {2}independent TSAs +SHA256SUMS stamped under 2 pinned TSA CAs/);
    expect(c.out).toMatch(/PASS {2}run plan +4 planned run\(s\) frozen at seq 1: 3 completed, 1 abandoned \(run-4: harness refused: API key not exported\); none unplanned, missing or repeated; report run_count 3/);
    expect(c.out).toMatch(new RegExp(`PASS {2}sign-off F1 +seq \\d+: ${SIGNER.replace('.', '\\.')}, key SHA256:`));
    expect(c.out).toMatch(/PASS {2}accepted findings +1 accepted finding\(s\) \(F1\), each with a verified human sign-off/);
    expect(c.out).toMatch(/PASS {2}audit closed +seq \d+, the bundle's last event: report R1/);
    expect(c.out).toMatch(/PASS {2}this audit only/);
    const r = verifyAudit(g.pkg, trust(g));
    expect(failed(r)).toEqual([]);
    expect(r.claims.every((x) => x.status === 'pass')).toBe(true);
    expect(r.ordering).toMatchObject({ status: 'pass', basis: 'derived_nonce', nonce: g.freezeNonce });
    expect(g.freezeNonce).not.toBe(g.freezeDigest);
    expect(r.plan).toMatchObject({ status: 'pass', planned: ['run-1', 'run-2', 'run-3', 'run-4'], completed: ['run-1', 'run-2', 'run-3'], abandoned: [{ run_id: 'run-4' }] });
    expect(r.reproductions).toMatchObject([{ finding_id: 'F1', signer: SIGNER, ok: true }]);
    expect(r.closed).toMatchObject({ status: 'pass', report_id: 'R1', run_count: 3 });
    expect(r.sums_timestamps.every((t) => t.ok)).toBe(true);
    expect(VerifyAuditJsonSchema.safeParse(JSON.parse(cli(['verify-audit', g.pkg, ...args(g), '--json']).out)).success).toBe(true);
  });

  it('W1: claims.json can add claims but never remove one; every claim is still checked', () => {
    const d = copy(g);
    const p = join(d, 'claims.json');
    const c = JSON.parse(readFileSync(p, 'utf8')) as { claims: string[] };
    c.claims = ['integrity', 'chain'];
    rmSync(p);
    writeFileSync(p, JSON.stringify(c));
    reseal(d, g);
    const r = verifyAudit(d, trust(g));
    expect(r.claims.map((x) => x.status)).toEqual(r.claims.map(() => 'pass'));
    expect(r.checks.find((x) => x.check === 'claims.json')!.evidence).toMatch(/the audit profile checks receipts, independent_timestamps, .* too/);
    // and a pack with no anchors at all no longer verifies (the 0.10.0 hole: VERIFIED with no anchors)
    const e = copy(g);
    rmSync(join(e, 'anchors'), { recursive: true });
    mkdirSync(join(e, 'anchors'));
    reseal(e, g);
    const none = verifyAudit(e, trust(g));
    expect(none.verdict).toBe('failed');
    expect(claimOf(none, 'receipts')).toBe('fail');
  });

  it('--skip-claim under the audit profile: PARTIAL, exit 2', () => {
    const c = cli(['verify-audit', g.pkg, ...args(g), '--skip-claim', 'reproductions_signed']);
    expect(c.code).toBe(2);
    expect(c.out).toMatch(/^RESULT: PARTIAL .*\(reproductions_signed skipped by user\)$/m);
    expect(c.out).toContain('PARTIAL: every check that ran passed, but the pack does not meet the audit profile (skipped by user: reproductions_signed). Exit 2.');
  });

  it('the bundle verifies on its own (verify-bundle accepts /3)', () => {
    expect(verifyBundle(join(g.pkg, 'bundle')).ok).toBe(true);
  });

  // ── the tamper suite: each exits 1 ──

  it('a changed byte', () => {
    const d = copy(g);
    const blobs = join(d, 'bundle', 'blobs');
    const b = join(blobs, readdirSync(blobs)[0]!);
    const bytes = readFileSync(b);
    bytes[0] = bytes[0]! ^ 0x01;
    rmSync(b);
    writeFileSync(b, bytes);
    expectCaught(d, g, 'integrity', /SHA256SUMS: bundle\/blobs\/[0-9a-f]{64} does not match its SHA256SUMS line/);
  });

  it('an added file', () => {
    const d = copy(g);
    writeFileSync(join(d, 'NOTES.txt'), 'added after packaging\n');
    expectCaught(d, g, 'integrity', 'not in SHA256SUMS: NOTES.txt');
  });

  it('a removed file', () => {
    const d = copy(g);
    rmSync(join(d, 'VERIFY.md'));
    expectCaught(d, g, 'integrity', 'VERIFY.md is listed but absent');
  });

  it('a missing anchor (the one after the last run), the pack re-sealed', () => {
    const d = copy(g);
    for (const f of readdirSync(join(d, 'anchors')).filter((x) => x.startsWith('02-'))) rmSync(join(d, 'anchors', f));
    reseal(d, g);
    expectCaught(d, g, 'receipts', /milestone anchors: missing an anchor after the last run \(seq \d+\) that does not yet commit the report/);
  });

  it('a missing timestamp token, the pack re-sealed', () => {
    const d = copy(g);
    rmSync(join(d, 'anchors', '03-audit-closed.beta.tsr'));
    reseal(d, g);
    expectCaught(d, g, 'independent_timestamps', /03-audit-closed independent TSAs: valid tokens under 1 pinned TSA CA\(s\) \(tsa-0\); at least two different TSA CAs are required/);
  });

  it('two tokens from the same CA, the pack re-sealed', () => {
    const d = copy(g);
    const receipt = readFileSync(join(d, 'anchors', '03-audit-closed.receipt.json'));
    rmSync(join(d, 'anchors', '03-audit-closed.beta.tsr'));
    writeFileSync(join(d, 'anchors', '03-audit-closed.beta.tsr'), tsas[0]!.stamp(receipt));
    reseal(d, g);
    expectCaught(d, g, 'independent_timestamps', /03-audit-closed independent TSAs: valid tokens under 1 pinned TSA CA\(s\)/);
  });

  it('an unplanned run', async () => {
    const t = await build('unplanned_run');
    expectCaught(t.pkg, t, 'plan_complete', /run\(s\) not in the plan frozen at seq 1: run-9 \(seq \d+\)/);
  });

  it('a missing planned run', async () => {
    const t = await build('missing_planned_run');
    expectCaught(t.pkg, t, 'plan_complete', 'planned run(s) with neither run_completed nor run_abandoned: run-5');
  });

  it('a duplicate run', async () => {
    const t = await build('duplicate_run');
    expectCaught(t.pkg, t, 'plan_complete', /planned run\(s\) recorded more than once: run-2 \(seq \d+ run_completed, \d+ run_completed\)/);
  });

  it('a run before the freeze anchor', async () => {
    const t = await build('run_before_freeze_anchor');
    const r = expectCaught(t.pkg, t, 'harness_frozen_before_runs', /harness frozen before runs: the freeze event \(seq 1\) is first committed by 01-run-abandoned together with 3 run\(s\) \(seq 2\.\.4\)/);
    expect(claimOf(r, 'receipts')).toBe('fail'); // and no anchor closes the freeze before the runs
  });

  it('a nonce mismatch (runs carry the 0.10.0 nonce, the freeze receipt digest, not the derived one)', async () => {
    const t = await build('nonce_mismatch');
    expectCaught(t.pkg, t, 'harness_frozen_before_runs', /carries a nonce that is not the derived freeze nonce sha256\(01-harness-frozen receipt digest ‖ its 2 TSA token\(s\)\)/);
  });

  it('a foreign stub (another document recorded inside the audit range)', async () => {
    const t = await build('foreign_stub');
    expectCaught(t.pkg, t, 'integrity', /this audit only: the bundle holds \d+ stub\(s\): events of other documents or audits inside its range/);
  });

  it('a pending stamp, the pack re-sealed', () => {
    const d = copy(g);
    writeFileSync(join(d, 'anchors', '03-audit-closed.gamma.pending'), 'http://tsa.invalid/: fetch failed\n');
    reseal(d, g);
    expectCaught(d, g, 'independent_timestamps', 'pending stamps: 1 stamp(s) pending: anchors/03-audit-closed.gamma.pending');
  });

  it('a pack made after audit stamp --allow-pending (0.11.1): the marker is carried and the audit profile rejects it', async () => {
    const t = await build('allow_pending');
    expect(t.pack.check.verdict).toBe('failed');
    expect(readdirSync(join(t.pkg, 'anchors'))).toContain('03-audit-closed.gamma.pending');
    expectCaught(t.pkg, t, 'independent_timestamps', 'pending stamps: 1 stamp(s) pending: anchors/03-audit-closed.gamma.pending');
  });

  it('an unsigned accepted finding', async () => {
    const t = await build('unsigned_accepted_finding');
    expectCaught(t.pkg, t, 'reproductions_signed', 'accepted findings: accepted finding(s) without a verified human sign-off (reproduction_signed): F1');
  });

  it('a wrong run count', async () => {
    const t = await build('wrong_run_count');
    expectCaught(t.pkg, t, 'plan_complete', "the report's run_count is 2; the bundle records 3 run_completed event(s)");
  });

  it('a tampered human sign-off', async () => {
    const t = await build('tampered_signoff');
    const r = expectCaught(t.pkg, t, 'reproductions_signed', /sign-off F1: seq \d+: the signature does not verify under SHA256:/);
    expect(r.reproductions).toMatchObject([{ finding_id: 'F1', ok: false }]);
  });

  it('a sign-off made with the auditor key, or by a key the allowed signers do not list: FAIL', () => {
    const other = reproducer();
    const r = verifyAudit(g.pkg, trust(g, { allowed_signers: other.allowed }));
    expect(claimOf(r, 'reproductions_signed')).toBe('fail');
    expect(r.reproductions[0]!.problem).toMatch(/is not in the allowed signers for reproducer@isokron\.test/);
  });
});

describe('legacy packs (made before 0.11.0)', () => {
  let l: Golden;
  beforeAll(async () => {
    l = await build('legacy');
  });

  it('a /2 pack exits 2 with PARTIAL under --profile legacy', () => {
    expect(l.pack.bundle_format).toBe(BUNDLE_FORMAT_V2);
    const c = cli(['verify-audit', l.pkg, ...args(l), '--profile', 'legacy']);
    expect(c.code, c.out).toBe(2);
    expect(c.out).toMatch(/^profile {8}legacy /m);
    expect(c.out).toMatch(/^RESULT: PARTIAL {2}integrity, chain, receipts, independent_timestamps, harness_frozen_before_runs, run_sequence$/m);
    expect(c.out).toContain('PARTIAL: every check that ran passed, but the pack does not meet the audit profile (checked under --profile legacy (the 0.10.0 rules); not checked: plan_complete, reproductions_signed, closed). Exit 2.');
    const r = verifyAudit(l.pkg, trust(l, { profile: 'legacy' }));
    expect(r).toMatchObject({ ok: false, profile: 'legacy', verdict: 'partial', failed: 0 });
    expect(r.ordering).toMatchObject({ status: 'pass', basis: 'freeze_nonce' });
  });

  it('the same pack under the default audit profile: exit 1, named as an older format', () => {
    const c = cli(['verify-audit', l.pkg, ...args(l)]);
    expect(c.code).toBe(1);
    expect(c.out).toMatch(/FAIL +bundle format +kronicle-lite-evidence-bundle\/2 is not kronicle-lite-evidence-bundle\/3: .*verify a pack made before 0\.11\.0 with --profile legacy/);
    const r = verifyAudit(l.pkg, trust(l));
    expect(claimOf(r, 'plan_complete')).toBe('fail');
    expect(claimOf(r, 'closed')).toBe('fail');
    expect(renderVerifyAudit(r)).toMatch(/^RESULT: FAILED /m);
  });

  it('the package step says PARTIAL for an older store and points at --profile legacy', () => {
    expect(l.pack.profile).toBe('legacy');
    expect(l.pack.check.verdict).toBe('partial');
    expect(readFileSync(join(l.pkg, 'VERIFY.md'), 'utf8')).toContain('--profile legacy');
  });

  it('--profile takes audit or legacy', () => {
    const c = cli(['verify-audit', l.pkg, ...args(l), '--profile', 'lenient']);
    expect(c.code).toBe(2);
    expect(c.err).toMatch(/--profile must be one of audit, legacy/);
  });
});

describe('audit stamp: the derived nonce and pending markers', () => {
  it('0.11.1: a TSA that fails leaves no .pending marker unless allow_pending is set', async () => {
    const store = new KronicleLite({ dataDir: tempDir('kl-vp-stamp-') });
    try {
      store.audit.record(AUDIT, [{ kind: 'harness_frozen', event_key: 'freeze', payload: { harness_id: 'h', fingerprint: H, manifest: store.audit.putBlob(Buffer.from('h'), 'text/plain'), plan: ['run-1'] } }], 'auditor');
      store.chain.checkpoint();
      await pushCheckpoint(store, { anchorUrl: backend.url, licenseKey: STUB_LICENSE });
      const out = tempDir('kl-vp-stamp-out-');
      const r = await stampAnchor(store, { out_dir: out, tsas: [{ name: 'alpha', url: servers[0]!.url }, { name: 'gamma', url: 'http://127.0.0.1:9/' }], timeoutMs: 2000 });
      expect(r.results.map((x) => [x.tsa, x.ok])).toEqual([['alpha', true], ['gamma', false]]);
      expect(r.pending).toEqual([]);
      expect(readdirSync(out)).toEqual([`${r.anchor_id}.alpha.tsr`]);
    } finally {
      store.close();
    }
  });

  it('prints the freeze nonce over both tokens and, with allow_pending, leaves a .pending marker for a TSA that failed', async () => {
    const store = new KronicleLite({ dataDir: tempDir('kl-vp-stamp-') });
    try {
      store.audit.record(AUDIT, [{ kind: 'harness_frozen', event_key: 'freeze', payload: { harness_id: 'h', fingerprint: H, manifest: store.audit.putBlob(Buffer.from('h'), 'text/plain'), plan: ['run-1'] } }], 'auditor');
      store.chain.checkpoint();
      await pushCheckpoint(store, { anchorUrl: backend.url, licenseKey: STUB_LICENSE });
      const out = tempDir('kl-vp-stamp-out-');
      const r = await stampAnchor(store, { out_dir: out, tsas: [{ name: 'alpha', url: servers[0]!.url }, { name: 'beta', url: servers[1]!.url }, { name: 'gamma', url: 'http://127.0.0.1:9/' }], timeoutMs: 2000, allow_pending: true });
      expect(r.results.map((x) => [x.tsa, x.ok])).toEqual([['alpha', true], ['beta', true], ['gamma', false]]);
      expect(readdirSync(out).sort()).toEqual([`${r.anchor_id}.alpha.tsr`, `${r.anchor_id}.beta.tsr`, `${r.anchor_id}.gamma.pending`]);
      const toks = ['alpha', 'beta'].map((tsa) => ({ tsa, bytes: readFileSync(join(out, `${r.anchor_id}.${tsa}.tsr`)) }));
      expect(r.nonce).toBe(freezeNonce(r.receipt_sha256, toks));
      // the recipe: sha256(raw receipt digest ‖ tokens in TSA-label order), whatever order they are given in
      expect(freezeNonce(r.receipt_sha256, [...toks].reverse())).toBe(sha(Buffer.concat([Buffer.from(r.receipt_sha256, 'hex'), toks[0]!.bytes, toks[1]!.bytes])));
      expect(() => freezeNonce(r.receipt_sha256, toks.slice(0, 1))).toThrow(/at least two/);
    } finally {
      store.close();
    }
  });
});

describe('SSH signatures (ssh-keygen -Y sign / verify)', () => {
  const k = reproducer();
  const msg = reproductionStatement({ audit_id: AUDIT, finding_id: 'F1', signer: SIGNER, reproduced_at: '2026-12-01T10:00:00Z', commands: 'aa'.repeat(32), output: 'bb'.repeat(32) });

  it('verifies against the allowed-signers entry; another message, namespace, principal or key fails', () => {
    const sig = sshSignWith(k, msg);
    const ok = verifySshSignature(sig, msg, { namespace: REPRODUCTION_NAMESPACE, principal: SIGNER, allowed_signers: k.allowed });
    expect(ok).toMatchObject({ ok: true, key_type: 'ssh-ed25519', line: 1 });
    expect(verifySshSignature(sig, msg + 'x', { namespace: REPRODUCTION_NAMESPACE, principal: SIGNER, allowed_signers: k.allowed }).problem).toMatch(/does not verify/);
    expect(verifySshSignature(sig, msg, { namespace: 'git', principal: SIGNER, allowed_signers: k.allowed }).problem).toMatch(/signed in namespace "kronicle-lite-reproduction", not "git"/);
    expect(verifySshSignature(sig, msg, { namespace: REPRODUCTION_NAMESPACE, principal: 'someone@else', allowed_signers: k.allowed }).problem).toMatch(/not in the allowed signers for someone@else/);
    expect(verifySshSignature(sig, msg, { namespace: REPRODUCTION_NAMESPACE, principal: SIGNER, allowed_signers: reproducer().allowed }).ok).toBe(false);
    // an entry limited to other namespaces, or not valid at the time, or a cert-authority entry, does not match
    const line = k.allowed.replace(/^(\S+) namespaces="[^"]*"/, '$1');
    expect(verifySshSignature(sig, msg, { namespace: REPRODUCTION_NAMESPACE, principal: SIGNER, allowed_signers: line.replace(SIGNER, `${SIGNER} namespaces="git"`) }).problem).toMatch(/does not allow namespace/);
    expect(verifySshSignature(sig, msg, { namespace: REPRODUCTION_NAMESPACE, principal: SIGNER, allowed_signers: line.replace(SIGNER, `${SIGNER} valid-before="20260101Z"`), at: new Date('2026-12-01T10:00:00Z') }).problem).toMatch(/is not valid at/);
    expect(verifySshSignature(sig, msg, { namespace: REPRODUCTION_NAMESPACE, principal: SIGNER, allowed_signers: line.replace(SIGNER, `${SIGNER} cert-authority`) }).problem).toMatch(/cert-authority entries are not supported/);
    expect(parseAllowedSigners('# comment\n\nbad line\n').problems).toHaveLength(1);
  });

  it('hostile input fails cleanly', () => {
    const sig = sshSignWith(k, msg);
    const b64 = sig.split('\n').slice(1, -2).join('');
    const blob = Buffer.from(b64, 'base64');
    for (let i = 0; i < blob.length; i += 7) {
      const m = Buffer.from(blob);
      m[i] = m[i]! ^ 0x40;
      const armored = `-----BEGIN SSH SIGNATURE-----\n${m.toString('base64')}\n-----END SSH SIGNATURE-----\n`;
      expect(verifySshSignature(armored, msg, { namespace: REPRODUCTION_NAMESPACE, principal: SIGNER, allowed_signers: k.allowed }).ok, `byte ${i}`).toBe(false);
    }
    for (const junk of ['', 'not a signature', '-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----', Buffer.alloc(20000, 0x41).toString()]) {
      expect(verifySshSignature(junk, msg, { namespace: REPRODUCTION_NAMESPACE, principal: SIGNER, allowed_signers: k.allowed }).ok).toBe(false);
    }
  });

  const sshKeygen = process.platform !== 'win32' && spawnSync('ssh-keygen', ['-Y', 'sign'], { encoding: 'utf8' }).stderr.length > 0;
  it.skipIf(!sshKeygen)('differential: ssh-keygen -Y sign is accepted here, and ssh-keygen -Y verify accepts what sshSign writes', () => {
    const d = tempDir('kl-vp-ssh-');
    const key = join(d, 'id_ed25519');
    expect(spawnSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'test', '-f', key]).status).toBe(0);
    writeFileSync(join(d, 'statement.json'), msg);
    const s = spawnSync('ssh-keygen', ['-Y', 'sign', '-f', key, '-n', REPRODUCTION_NAMESPACE, join(d, 'statement.json')], { encoding: 'utf8' });
    expect(s.status, s.stderr).toBe(0);
    const pub = readFileSync(`${key}.pub`, 'utf8').trim().split(' ').slice(0, 2).join(' ');
    const allowed = `${SIGNER} namespaces="${REPRODUCTION_NAMESPACE}" ${pub}\n`;
    const v = verifySshSignature(readFileSync(join(d, 'statement.json.sig')), msg, { namespace: REPRODUCTION_NAMESPACE, principal: SIGNER, allowed_signers: allowed });
    expect(v.ok, v.problem ?? '').toBe(true);
    // the other way: an in-process signature checked by ssh-keygen
    writeFileSync(join(d, 'allowed_signers'), k.allowed);
    writeFileSync(join(d, 'mine.sig'), sshSignWith(k, msg));
    const back = spawnSync('ssh-keygen', ['-Y', 'verify', '-f', join(d, 'allowed_signers'), '-I', SIGNER, '-n', REPRODUCTION_NAMESPACE, '-s', join(d, 'mine.sig')], { input: msg, encoding: 'utf8' });
    expect(back.status, back.stderr + back.stdout).toBe(0);
    expect(back.stdout).toMatch(/Good "kronicle-lite-reproduction" signature for reproducer@isokron\.test/);
  });

  it('a hardware-key (sk-ssh-ed25519) signature verifies with user presence and fails without it', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const pk = (publicKey.export({ type: 'spki', format: 'der' }) as Buffer).subarray(12);
    const str = (b: Buffer | string) => {
      const v = typeof b === 'string' ? Buffer.from(b) : b;
      const n = Buffer.alloc(4);
      n.writeUInt32BE(v.length);
      return Buffer.concat([n, v]);
    };
    const type = 'sk-ssh-ed25519@openssh.com';
    const app = 'ssh:';
    const pub = Buffer.concat([str(type), str(pk), str(app)]);
    const make = (flags: number) => {
      const h = createHash('sha512').update(msg).digest();
      const signed = Buffer.concat([Buffer.from('SSHSIG'), str(REPRODUCTION_NAMESPACE), str(''), str('sha512'), str(h)]);
      const counter = Buffer.from([0, 0, 0, 7]);
      const toSign = Buffer.concat([createHash('sha256').update(app).digest(), Buffer.from([flags]), counter, createHash('sha256').update(signed).digest()]);
      const sig = Buffer.concat([str(type), str(edSign(null, toSign, privateKey)), Buffer.from([flags]), counter]);
      const v = Buffer.alloc(4);
      v.writeUInt32BE(1);
      const blob = Buffer.concat([Buffer.from('SSHSIG'), v, str(pub), str(REPRODUCTION_NAMESPACE), str(''), str('sha512'), str(sig)]);
      return `-----BEGIN SSH SIGNATURE-----\n${blob.toString('base64')}\n-----END SSH SIGNATURE-----\n`;
    };
    const allowed = `${SIGNER} ${type} ${pub.toString('base64')}\n`;
    expect(verifySshSignature(make(0x01), msg, { namespace: REPRODUCTION_NAMESPACE, principal: SIGNER, allowed_signers: allowed })).toMatchObject({ ok: true, key_type: type });
    expect(verifySshSignature(make(0x00), msg, { namespace: REPRODUCTION_NAMESPACE, principal: SIGNER, allowed_signers: allowed }).problem).toMatch(/user presence/);
  });
});

// ── differential: the pack's tokens against openssl ts -verify, and VERIFY.md's raw commands ──
// CI's openssl-differential job sets KL_REQUIRE_RAW_TOOLS=1 so a missing tool fails instead of skipping.
const tool = (cmd: string, a: string[]) => spawnSync(cmd, a, { encoding: 'utf8' });
const opensslOk = process.platform !== 'win32' && /^OpenSSL [3-9]\./.test(tool('openssl', ['version']).stdout ?? '');
const rawOk = opensslOk && tool('jq', ['--version']).status === 0 && tool('shasum', ['--version']).status === 0 && tool('xxd', ['-v']).status === 0 && tool('ssh-keygen', ['-Y', 'sign']).stderr.length > 0;
const required = process.env['KL_REQUIRE_RAW_TOOLS'] === '1';

describe('openssl differential', () => {
  let g: Golden;
  beforeAll(async () => {
    if (opensslOk || required) g = await build();
  });

  it('the raw tools are available when CI requires them', () => {
    if (required) expect({ openssl: opensslOk, raw: rawOk }).toEqual({ openssl: true, raw: true });
  });

  it.skipIf(!opensslOk)('openssl ts -verify accepts every token in the pack (anchors and SHA256SUMS) and refuses each over other bytes', () => {
    const roots = join(g.pkg, 'tsa-roots');
    const caFor = (tsa: string) => join(roots, tsa === 'alpha' ? 'custom-1.pem' : 'custom-2.pem');
    let n = 0;
    for (const f of readdirSync(join(g.pkg, 'anchors')).filter((x) => x.endsWith('.tsr'))) {
      const [base, tsa] = [f.split('.')[0]!, f.split('.')[1]!];
      const d = sha(readFileSync(join(g.pkg, 'anchors', `${base}.receipt.json`)));
      const ok = tool('openssl', ['ts', '-verify', '-digest', d, '-in', join(g.pkg, 'anchors', f), '-CAfile', caFor(tsa), '-partial_chain']);
      expect(ok.stdout + ok.stderr, f).toMatch(/Verification: OK/);
      const bad = tool('openssl', ['ts', '-verify', '-digest', sha('other'), '-in', join(g.pkg, 'anchors', f), '-CAfile', caFor(tsa), '-partial_chain']);
      expect(bad.status, f).not.toBe(0);
      n++;
    }
    for (const tsa of TSA_NAMES) {
      const ok = tool('openssl', ['ts', '-verify', '-data', join(g.pkg, 'SHA256SUMS'), '-in', join(g.pkg, `SHA256SUMS.${tsa}.tsr`), '-CAfile', caFor(tsa), '-partial_chain']);
      expect(ok.stdout + ok.stderr, tsa).toMatch(/Verification: OK/);
      const bad = tool('openssl', ['ts', '-verify', '-data', join(g.pkg, 'VERIFY.md'), '-in', join(g.pkg, `SHA256SUMS.${tsa}.tsr`), '-CAfile', caFor(tsa), '-partial_chain']);
      expect(bad.status, tsa).not.toBe(0);
      n++;
    }
    expect(n).toBe(8);
  });

  it.skipIf(!rawOk)('every raw command in VERIFY.md succeeds, and the nonce it computes is the one the runs carry', () => {
    const d = copy(g);
    const md = readFileSync(join(d, 'VERIFY.md'), 'utf8');
    const raw = md.slice(md.indexOf('## Without kronicle-lite'));
    const script = [...raw.matchAll(/```sh\n([\s\S]*?)```/g)]
      .map((m) => m[1]!)
      .join('\n')
      .split('\n')
      .filter((l) => !/^sha256sum /.test(l) || tool('sha256sum', ['--version']).status === 0);
    const r = spawnSync('bash', ['-euo', 'pipefail', '-c', script.join('\n')], { cwd: d, encoding: 'utf8' });
    const all = r.stdout + r.stderr;
    expect(all).not.toMatch(/Verification: FAILED|Signature Verification Failure|: FAILED/);
    expect(r.status, all).toBe(0);
    expect(all.match(/Verification: OK/g)?.length).toBeGreaterThanOrEqual(14);
    expect(all).toMatch(/Good "kronicle-lite-reproduction" signature for reproducer@isokron\.test/);
    // the nonce line and the runs' nonce (jq) print the same value
    expect(all.match(new RegExp(g.freezeNonce, 'g'))?.length).toBeGreaterThanOrEqual(2);
  });
});
