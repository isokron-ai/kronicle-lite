/**
 * verify-audit / audit package / audit stamp (0.10.0): IsoKron Evidence Packs.
 *
 * End to end on a synthetic pack: a store records an audit with three milestones, anchors each
 * on the in-test anchor stub, stamps each receipt with two throwaway RFC 3161 TSAs
 * (test/helpers/tsa.ts), packages it, and the CLI verifies exactly the claims the pack declares.
 * Then the attacks: one byte flipped, history rewritten and re-signed with the auditor's own key,
 * bad / expired / foreign timestamp tokens, an untrusted service key, gaps in the run sequence,
 * runs under another harness. Real Sectigo and DigiCert tokens (from the prototype GitHub audit;
 * receipts and tokens only: hashes and certificates, no audit data) cover the production TSA
 * chains, including DigiCert's cross-signed root.
 */

import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign as edSign, X509Certificate } from 'node:crypto';
import { copyFileSync, cpSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { pushCheckpoint } from '../src/anchor/anchor.js';
import { serviceKeyIdFromPem, SHIPPED_SERVICE_KEY_PINS, SHIPPED_SERVICE_KEYS, successorSigningPayload } from '../src/anchor/trust.js';
import { exportBundle, signManifest, type BundleManifest } from '../src/audit/bundle.js';
import { buildAuditPackage, stampAnchor } from '../src/audit/package.js';
import { inspectTimestamp, OID, timestampRequest, checkTimestampReply, verifyTimestamp } from '../src/audit/rfc3161.js';
import { BUNDLE_FORMAT_V1, BUNDLE_FORMAT_V2 } from '../src/audit/schemas.js';
import { SHIPPED_TSA_ROOTS } from '../src/audit/tsa-roots.js';
import { listPackFiles, sha256sums, SUMS_FILES, verifyAudit, VerifyAuditJsonSchema, type VerifyAuditOptions } from '../src/audit/verify-audit.js';
import { verifyBundle } from '../src/audit/verify-bundle.js';
import { canonicalize } from '../src/crypto/canonical.js';
import { KronicleLite } from '../src/index.js';
import { startAnchorStub, STUB_LICENSE, type AnchorBackend } from './helpers/anchor-stub.js';
import { CLI, cleanEnv, tempDir } from './helpers/fs.js';
import { makeTsa, serveTsa, type TestTsa } from './helpers/tsa.js';

const AUDIT = 'acme-mcp-2026-11';
const H = 'ab'.repeat(32);
const sha = (b: string | Buffer) => createHash('sha256').update(b).digest('hex');

let backend: AnchorBackend;
beforeAll(async () => {
  backend = await startAnchorStub();
});
afterAll(async () => {
  await backend.stop();
});

type Variant = 'milestones' | 'v1' | 'v1-early' | 'no-freeze';

interface RecordOpts {
  /** run_seq of each run (milestones): default 1, 2, 3. */
  runSeqs?: number[];
  plannedRuns?: number;
  /** Harness digest run i ran under (default H). */
  runHarness?: (i: number) => string;
  /** Change run 2's status (a forgery). */
  tweak?: boolean;
}

/**
 * Record the audit: freeze → anchor → runs → anchor → report → anchor. `anchor` returns the
 * anchored receipt's sha256 (the freeze nonce for runs).
 */
async function recordAudit(store: KronicleLite, variant: Variant, anchor: (label: string) => Promise<string>, o: RecordOpts = {}): Promise<void> {
  const blob = (s: string, t = 'text/plain') => store.audit.putBlob(Buffer.from(s), t);
  const seqs = o.runSeqs ?? [1, 2, 3];
  if (variant === 'milestones') {
    store.audit.record(AUDIT, [{ kind: 'harness_frozen', event_key: 'freeze', payload: { harness_id: 'harness-v1', fingerprint: H, manifest: blob('harness files'), hypotheses: blob('H1: reads stay under 2 KB'), planned_runs: o.plannedRuns ?? seqs.length } }], 'auditor');
  } else if (variant !== 'no-freeze') {
    store.audit.record(AUDIT, [{ kind: 'finding', event_key: 'protocol', payload: { finding_id: 'PROTOCOL', status: 'discovered', class: 'protocol_freeze', fingerprint: H, detail: blob('harness files') } }], 'auditor');
  } else {
    store.audit.record(AUDIT, [{ kind: 'catalog_snapshot', event_key: 'catalog', payload: { fingerprint: H, server: { name: 'acme' }, tool_count: 3, bytes: 10, snapshot: blob('{"tools":[]}', 'application/json') } }], 'auditor');
  }
  const nonce = await anchor('freeze');
  const runs = seqs.map((n, idx) => {
    const i = idx + 1;
    const status = o.tweak && i === 2 ? 'fail' : 'pass';
    const out = blob(`run ${n} wire log ${status}`);
    const fingerprint = o.runHarness?.(i) ?? H;
    if (variant === 'milestones') {
      return {
        kind: 'run_completed' as const,
        event_key: `run:${n}`,
        payload: { run_id: `run-${n}`, run_seq: n, fingerprint, status, nonce, result: out, ...(i === 3 ? { capture: 'interrupted', interruption: 'proxy restarted; resumed' } : {}) },
      };
    }
    const measured_at = variant === 'v1-early' ? `2020-01-0${i}T00:00:00Z` : new Date(Date.now() + 2000 + i).toISOString();
    return { kind: 'call_measured' as const, event_key: `run:${n}`, payload: { fingerprint, tool: 'bench', status, is_error: false, latency_ms: 10, bytes_out: out.size, measured_at, response: out } };
  });
  store.audit.record(AUDIT, runs, 'proxy');
  await anchor('runs');
  if (variant === 'milestones') store.audit.record(AUDIT, [{ kind: 'report_issued', event_key: 'report', payload: { report_id: 'R1', report: blob('# Report'), run_count: seqs.length } }], 'auditor');
  else store.audit.record(AUDIT, [{ kind: 'finding', event_key: 'report', payload: { finding_id: 'REPORT', status: 'discovered', class: 'report', detail: blob('# Report') } }], 'auditor');
  await anchor('report');
}

interface Fixture {
  dataDir: string;
  pkg: string;
  keyFile: string;
  keysFile: string;
  rootsDir: string;
  tsDir: string;
  digests: string[];
  tsas: TestTsa[];
  pack: ReturnType<typeof buildAuditPackage>;
}

async function build(variant: Variant, o: { tsas?: TestTsa[]; genTime?: (i: number) => Date } & RecordOpts = {}): Promise<Fixture> {
  const dataDir = tempDir('kl-va-store-');
  const work = tempDir('kl-va-work-');
  const tsDir = join(work, 'timestamps');
  mkdirSync(tsDir);
  const tsas = o.tsas ?? [makeTsa({ name: 'Alpha' }), makeTsa({ name: 'Beta' })];
  const store = new KronicleLite({ dataDir });
  const digests: string[] = [];
  await recordAudit(
    store,
    variant,
    async () => {
      store.chain.checkpoint(1, store.chain.head().seq);
      const r = await pushCheckpoint(store, { anchorUrl: backend.url, licenseKey: STUB_LICENSE });
      const row = store.chain.listAnchors().find((a) => a.anchor_id === r.anchor_id)!;
      const i = digests.length;
      digests.push(sha(row.receipt_json));
      tsas.forEach((t, k) => writeFileSync(join(tsDir, `${r.anchor_id}.${k === 0 ? 'alpha' : 'beta'}.tsr`), t.stamp(row.receipt_json, o.genTime ? { genTime: o.genTime(i) } : {})));
      return digests[i]!;
    },
    o,
  );
  const rootsDir = join(work, 'roots');
  mkdirSync(rootsDir);
  tsas.forEach((t, k) => writeFileSync(join(rootsDir, `tsa-${k}.pem`), t.root.pem));
  const keyFile = join(work, 'auditor.pem');
  writeFileSync(keyFile, store.identity.signer.public_key_pem);
  const keysFile = join(work, 'anchor-keys.trusted.json');
  writeFileSync(keysFile, JSON.stringify(await (await fetch(`${backend.url}/.well-known/anchor-keys.json`)).json()));
  const pkg = join(work, 'package');
  const pack = buildAuditPackage(store, { audit_id: AUDIT, out: pkg, timestamps_dir: tsDir, tsa_roots: tsas.map((t) => t.root.pem) });
  store.close();
  return { dataDir, pkg, keyFile, keysFile, rootsDir, tsDir, digests, tsas, pack };
}

const trustOpts = (f: Fixture): VerifyAuditOptions => ({
  key_pem: readFileSync(f.keyFile, 'utf8'),
  anchor_keys: JSON.parse(readFileSync(f.keysFile, 'utf8')) as unknown,
  tsa_roots: f.tsas.map((t) => t.root.pem),
});

function cli(args: string[], env: Record<string, string> = {}) {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env: cleanEnv(env) });
  return { code: r.status, out: r.stdout, err: r.stderr };
}
const trustArgs = (f: Fixture) => ['--key', f.keyFile, '--anchor-keys', f.keysFile, '--tsa-roots', f.rootsDir];
const copyPkg = (f: Fixture) => {
  const d = join(tempDir('kl-va-copy-'), 'package');
  cpSync(f.pkg, d, { recursive: true });
  return d;
};
/** Rewrite a file of a pack copy (a fresh inode: the copy's files are not hard links). */
const rewrite = (p: string, data: string | Buffer) => {
  rmSync(p);
  writeFileSync(p, data);
};
/** Re-sign SHA256SUMS of a pack copy with the auditor's key, as the key holder could. */
function resign(d: string, dataDir: string): void {
  const store = new KronicleLite({ dataDir });
  try {
    for (const f of SUMS_FILES) rmSync(join(d, f));
    const sums = sha256sums(d, listPackFiles(d).files);
    writeFileSync(join(d, 'SHA256SUMS'), sums);
    writeFileSync(join(d, 'SHA256SUMS.sig'), Buffer.from(store.identity.signer.sign(Buffer.from(sums)), 'base64'));
  } finally {
    store.close();
  }
}
const failedChecks = (r: ReturnType<typeof verifyAudit>) => r.checks.filter((c) => c.status === 'fail').map((c) => `${c.subject ? `${c.subject} ` : ''}${c.check}`);
const claimStatus = (r: ReturnType<typeof verifyAudit>) => Object.fromEntries(r.claims.map((c) => [c.claim, c.status]));

describe('verify-audit: a synthetic evidence pack end to end', () => {
  let f: Fixture;
  beforeAll(async () => {
    f = await build('milestones');
  });

  it('audit package writes the pack layout, declares what the store supports, and verifies itself', () => {
    expect(readdirSync(f.pkg).sort()).toEqual(['COMPLETION.txt', 'SHA256SUMS', 'SHA256SUMS.sig', 'VERIFY.md', 'anchor-keys.json', 'anchors', 'auditor-key.pem', 'bundle', 'claims.json', 'tsa-roots']);
    expect(readdirSync(join(f.pkg, 'anchors')).sort()).toEqual([
      '01-harness-frozen.alpha.tsr',
      '01-harness-frozen.beta.tsr',
      '01-harness-frozen.receipt.json',
      '02-run-completed.alpha.tsr',
      '02-run-completed.beta.tsr',
      '02-run-completed.receipt.json',
      '03-report-issued.alpha.tsr',
      '03-report-issued.beta.tsr',
      '03-report-issued.receipt.json',
      'index.json',
    ]);
    expect(readdirSync(join(f.pkg, 'tsa-roots')).sort()).toEqual(['custom-1.pem', 'custom-2.pem', 'digicert.pem', 'sectigo.pem']);
    expect(sha(readFileSync(join(f.pkg, 'anchors', '01-harness-frozen.receipt.json')))).toBe(f.digests[0]); // the stamped digest
    const claims = JSON.parse(readFileSync(join(f.pkg, 'claims.json'), 'utf8')) as Record<string, unknown>;
    expect(claims).toEqual({
      format: 'isokron-evidence-pack-claims/1',
      audit_id: AUDIT,
      claims: ['integrity', 'chain', 'receipts', 'independent_timestamps', 'harness_frozen_before_runs', 'run_sequence'],
      runs: { count: 3, seqs: [1, 2, 3], interruptions: [{ run_seq: 3, event_key: 'run:3', note: 'proxy restarted; resumed' }] },
    });
    expect(f.pack.check.ok).toBe(true);
    const completion = readFileSync(join(f.pkg, 'COMPLETION.txt'), 'utf8');
    expect(completion).toContain('IsoKron Evidence Pack: acme-mcp-2026-11');
    expect(completion).toContain('Tamper-evident, independently timestamped audit evidence.');
    expect(completion).toContain(`Manifest SHA-256      ${f.pack.manifest_sha256}`);
    expect(completion).toContain(`Final anchored root   ${f.pack.root}`);
    expect(completion).toMatch(/Signing key +ed25519-[0-9a-f]{16} \(SHA-256 of the public key's SPKI: [0-9a-f]{64}\)/);
    expect(completion).toMatch(/timestamps +\d{4}-.*\(alpha\), .*\(beta\)/);
    const verify = readFileSync(join(f.pkg, 'VERIFY.md'), 'utf8');
    expect(verify).toContain('openssl pkeyutl -verify -pubin -inkey auditor-key.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig');
    expect(verify).toContain('openssl ts -verify -digest $D -in anchors/01-harness-frozen.alpha.tsr -CAfile tsa-roots/custom-1.pem -partial_chain');
    expect(verify).toMatch(/-attime \d{10}/);
    for (const t of [readFileSync(join(f.pkg, 'VERIFY.md'), 'utf8'), completion]) expect(t).not.toMatch(/immutable|tamper-proof|certified|trustless/i);
  });

  it('verifies: exit 0, one PASS per declared claim, check lines with evidence, values to compare', () => {
    const r = cli(['verify-audit', f.pkg, ...trustArgs(f)]);
    expect(r.err).toBe('');
    expect(r.code).toBe(0);
    expect(r.out.split('\n')[0]).toBe(`IsoKron Evidence Pack  ${f.pkg}`);
    for (const c of ['integrity', 'chain', 'receipts', 'independent_timestamps', 'harness_frozen_before_runs', 'run_sequence']) expect(r.out).toMatch(new RegExp(`^ {2}PASS {10}${c} `, 'm'));
    expect(r.out).toMatch(/PASS {2}harness frozen before runs +harness abababababababab… frozen, committed .*3\/3 run\(s\) name that harness and carry the freeze receipt digest/);
    expect(r.out).toMatch(/PASS {2}run sequence +3 run\(s\), run_seq 1\.\.3 contiguous; matches planned_runs 3, report_run_count 3, claims\.json 3; 1 capture interruption\(s\): run 3 \(proxy restarted; resumed\)/);
    expect(r.out).toMatch(/PASS {2}SHA256SUMS +\d+ file\(s\) match; signed by ed25519-/);
    expect(r.out).toMatch(/PASS {2}RFC 3161 alpha +\d{4}-\d\d-\d\dT.*signed by CN=Alpha TSA Signer, root CN=Alpha TSA Root/);
    expect(r.out).toMatch(/PASS {2}root matches bundle +seq 1\.\.1 root [0-9a-f]{64}/);
    expect(r.out).toContain(`manifest sha256  ${f.pack.manifest_sha256}`);
    expect(r.out).toMatch(/final root +[0-9a-f]{64} \(seq 1\.\.5, 03-report-issued\)/);
    expect(r.out).toContain('RESULT: VERIFIED  integrity, chain, receipts, independent_timestamps, harness_frozen_before_runs, run_sequence');
    expect(r.out).not.toContain('FAIL');
    expect(r.out).not.toMatch(/does not prove|NOT proven|not prove/i); // scope statements live in --help and the docs
    expect(cli(['help']).out).toContain('Establishes integrity, ordering and independent');
  });

  it('--json follows the published schema', () => {
    const r = cli(['verify-audit', f.pkg, ...trustArgs(f), '--json']);
    expect(r.code).toBe(0);
    const j = VerifyAuditJsonSchema.parse(JSON.parse(r.out));
    expect(j).toMatchObject({ ok: true, failed: 0, audit_id: AUDIT, bundle_format: BUNDLE_FORMAT_V2, manifest_sha256: f.pack.manifest_sha256, auditor: { source: 'pinned' }, trust: { service_keys: 'file', tsa_roots: 'dir', tsa_time: 'now' } });
    expect(j.claims.map((c) => [c.claim, c.status])).toEqual([
      ['integrity', 'pass'],
      ['chain', 'pass'],
      ['receipts', 'pass'],
      ['independent_timestamps', 'pass'],
      ['harness_frozen_before_runs', 'pass'],
      ['run_sequence', 'pass'],
    ]);
    expect(j.ordering).toMatchObject({ status: 'pass', basis: 'freeze_nonce', harness_digest: H, runs: { count: 3, nonce_bound: 3 } });
    expect(j.run_sequence).toMatchObject({ status: 'pass', count: 3, seqs: [1, 2, 3], interruptions: [{ run_seq: 3, event_key: 'run:3', note: 'proxy restarted; resumed' }] });
    expect(j.anchors.every((a) => a.ok && a.timestamps.length === 2 && a.timestamps.every((t) => t.ok))).toBe(true);
    expect(j.final).toMatchObject({ from_seq: 1, anchor: '03-report-issued' });
    expect(j.timeline.map((t) => t.kind)).toEqual(['harness_frozen', 'run_completed', 'run_completed', 'run_completed', 'report_issued']);
  });

  it('does not depend on openssl (PATH empty)', () => {
    const r = cli(['verify-audit', f.pkg, ...trustArgs(f)], { PATH: '' });
    expect(r.code).toBe(0);
    expect(r.out).toContain('RESULT: VERIFIED');
  });

  const rawTools = (() => {
    if (process.platform === 'win32') return false;
    const o = spawnSync('openssl', ['version'], { encoding: 'utf8' });
    const j = spawnSync('jq', ['--version'], { encoding: 'utf8' });
    const s = spawnSync('shasum', ['--version'], { encoding: 'utf8' });
    return o.status === 0 && /^OpenSSL 3/.test(o.stdout) && j.status === 0 && s.status === 0;
  })();
  it.skipIf(!rawTools)('every raw command in VERIFY.md succeeds with openssl / jq / shasum alone', () => {
    const d = copyPkg(f);
    const md = readFileSync(join(d, 'VERIFY.md'), 'utf8');
    const raw = md.slice(md.indexOf('## Without kronicle-lite'));
    const blocks = [...raw.matchAll(/```sh\n([\s\S]*?)```/g)].map((m) => m[1]!).join('\n');
    const script = blocks.split('\n').filter((l) => !/^sha256sum /.test(l) || spawnSync('sha256sum', ['--version']).status === 0);
    const r = spawnSync('bash', ['-euo', 'pipefail', '-c', script.join('\n')], { cwd: d, encoding: 'utf8' });
    expect(r.stderr + r.stdout).not.toMatch(/fail|error/i);
    expect(r.status).toBe(0);
    expect((r.stdout + r.stderr).match(/Verification: OK/g)?.length).toBeGreaterThanOrEqual(12);
    expect(r.stdout + r.stderr).toMatch(/Signature Verified Successfully/);
  });

  it('one byte flipped in an artifact: exit 1, integrity FAIL (SHA256SUMS and the bundle artifacts check)', () => {
    const d = copyPkg(f);
    const blobs = join(d, 'bundle', 'blobs');
    const name = readdirSync(blobs)[0]!;
    const b = readFileSync(join(blobs, name));
    b[0] = b[0]! ^ 0x01;
    rewrite(join(blobs, name), b);
    const r = cli(['verify-audit', d, ...trustArgs(f)]);
    expect(r.code).toBe(1);
    expect(r.out).toMatch(/FAIL {2}artifacts +blob [0-9a-f]{12}… does not hash to its name/);
    expect(r.out).toMatch(new RegExp(`FAIL {2}SHA256SUMS +bundle/blobs/${name} does not match its SHA256SUMS line`));
    expect(r.out).toMatch(/^ {2}FAIL {10}integrity /m);
    expect(r.out).toMatch(/RESULT: FAILED {2}integrity \(2 failed check\(s\)\)/);
  });

  it('one byte flipped in a receipt (SHA256SUMS re-signed): the receipt and its tokens fail', () => {
    const d = copyPkg(f);
    const p = join(d, 'anchors', '02-run-completed.receipt.json');
    rewrite(p, readFileSync(p, 'utf8').replace('"received_at":"2', '"received_at":"3'));
    resign(d, f.dataDir);
    const r = verifyAudit(d, trustOpts(f));
    expect(r.ok).toBe(false);
    expect(failedChecks(r)).toEqual(expect.arrayContaining(['02-run-completed service signature', '02-run-completed RFC 3161 alpha', '02-run-completed RFC 3161 beta']));
    expect(claimStatus(r)).toMatchObject({ integrity: 'pass', receipts: 'fail', independent_timestamps: 'fail' });
  });

  it('history rewritten and re-signed with the auditor key: integrity passes, the anchors do not', async () => {
    const forgedDir = tempDir('kl-va-forged-');
    copyFileSync(join(f.dataDir, 'signing-key.pem'), join(forgedDir, 'signing-key.pem'));
    const forged = new KronicleLite({ dataDir: forgedDir });
    expect(forged.identity.signer.public_key_pem).toBe(readFileSync(f.keyFile, 'utf8'));
    let i = 0;
    await recordAudit(forged, 'milestones', async () => f.digests[i++]!, { tweak: true });
    const d = copyPkg(f);
    rmSync(join(d, 'bundle'), { recursive: true });
    exportBundle({ chain: forged.chain, audit: forged.audit, signer: forged.identity.signer, audit_id: AUDIT, dir: join(d, 'bundle') });
    forged.close();
    resign(d, forgedDir);
    expect(verifyBundle(join(d, 'bundle'), { public_key_pem: readFileSync(f.keyFile, 'utf8') }).ok).toBe(true); // a bundle alone cannot catch the key holder
    const r = cli(['verify-audit', d, ...trustArgs(f), '--json']);
    expect(r.code).toBe(1);
    const j = VerifyAuditJsonSchema.parse(JSON.parse(r.out));
    const bad = j.checks.filter((c) => c.status === 'fail');
    // anchor 1 covers only the freeze (unchanged); anchors 2 and 3 cover run 2
    expect(bad.map((c) => `${c.subject} ${c.check}`)).toEqual(expect.arrayContaining(['02-run-completed root matches bundle', '03-report-issued root matches bundle']));
    expect(bad.find((c) => c.check === 'root matches bundle')!.evidence).toMatch(/bundle seq 1\.\.\d+ has root [0-9a-f]{16}…, the anchor holds [0-9a-f]{16}…/);
    expect(j.claims.find((c) => c.claim === 'integrity')!.status).toBe('pass');
    expect(j.claims.find((c) => c.claim === 'receipts')!.status).toBe('fail');
  });

  it('bad timestamp tokens: altered signature, a token for another receipt, an untrusted TSA, a missing token', () => {
    {
      const d = copyPkg(f);
      const p = join(d, 'anchors', '01-harness-frozen.alpha.tsr');
      const b = readFileSync(p);
      b[b.length - 1] = b[b.length - 1]! ^ 0xff; // the last byte of the reply is the signature's
      rewrite(p, b);
      resign(d, f.dataDir);
      const r = verifyAudit(d, trustOpts(f));
      expect(failedChecks(r)).toEqual(['01-harness-frozen RFC 3161 alpha', 'harness frozen before runs']); // the freeze is then first committed with the runs
      expect(r.checks.find((c) => c.check === 'RFC 3161 alpha' && c.status === 'fail')!.evidence).toMatch(/signature|DER|signed/i);
      expect(claimStatus(r)).toMatchObject({ integrity: 'pass', receipts: 'pass', independent_timestamps: 'fail', harness_frozen_before_runs: 'fail' });
    }
    {
      const d = copyPkg(f);
      rewrite(join(d, 'anchors', '01-harness-frozen.beta.tsr'), readFileSync(join(d, 'anchors', '02-run-completed.beta.tsr')));
      resign(d, f.dataDir);
      const r = verifyAudit(d, trustOpts(f));
      expect(r.checks.find((c) => c.subject === '01-harness-frozen' && c.check === 'RFC 3161 beta')).toMatchObject({ status: 'fail', evidence: 'messageImprint is not the hash of the stamped bytes' });
      expect(r.ordering.status).toBe('fail'); // the freeze anchor no longer counts as timestamped
    }
    {
      const { tsa_roots: _drop, ...o } = trustOpts(f);
      const r = verifyAudit(f.pkg, o);
      expect(r.ok).toBe(false);
      expect(r.checks.filter((c) => c.group === 'timestamp').every((c) => c.status === 'fail' && /does not chain to a trusted TSA root/.test(c.evidence))).toBe(true);
    }
    {
      const d = copyPkg(f);
      for (const t of ['alpha', 'beta']) rmSync(join(d, 'anchors', `03-report-issued.${t}.tsr`));
      resign(d, f.dataDir);
      const r = verifyAudit(d, trustOpts(f));
      expect(r.checks.find((c) => c.subject === '03-report-issued' && c.group === 'timestamp')).toMatchObject({ status: 'fail', evidence: 'no timestamp token for this receipt' });
      expect(r.checks.find((c) => c.check === 'coverage')!.status).toBe('fail');
    }
  });

  it('anchor service keys: shipped pins by default (no trust on first use); successors need a signature', () => {
    const { anchor_keys: _k, ...noKeys } = trustOpts(f);
    const r = verifyAudit(f.pkg, noKeys); // the pack's own anchor-keys.json lists the stub key: not a trust root
    expect(r.ok).toBe(false);
    expect(r.checks.filter((c) => c.check === 'service signature').every((c) => c.status === 'fail' && c.evidence.includes('is not trusted (trusted: anchor-ed25519-3dca1ecf66c2993e'))).toBe(true);
    expect(r.checks.find((c) => c.check === 'anchor-keys.json')).toMatchObject({ status: 'fail', evidence: expect.stringMatching(/anchor-ed25519-[0-9a-f]{16} does not chain to a genesis key/) });

    // Rotation: trust K0 only; the pack lists the stub key with a successor signature by K0.
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const k0pem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const k0 = serviceKeyIdFromPem(k0pem);
    const s = (JSON.parse(readFileSync(f.keysFile, 'utf8')) as { keys: { key_id: string; public_key_pem: string; valid_from: string }[] }).keys[0]!;
    const successor_signature = edSign(null, Buffer.from(successorSigningPayload({ key_id: s.key_id, public_key_pem: s.public_key_pem, valid_from: s.valid_from })), privateKey).toString('base64');
    const d = copyPkg(f);
    rewrite(join(d, 'anchor-keys.json'), JSON.stringify({ v: 1, keys: [{ key_id: k0, public_key_pem: k0pem, status: 'retired', valid_from: '2026-01-01T00:00:00.000Z', valid_to: s.valid_from }, { ...s, status: 'active', successor_signature, signed_by: k0 }] }));
    resign(d, f.dataDir);
    const trustK0 = { ...noKeys, anchor_keys: { keys: [{ key_id: k0, public_key_pem: k0pem }] } };
    const ok = verifyAudit(d, trustK0);
    expect(failedChecks(ok)).toEqual([]);
    expect(ok.checks.find((c) => c.check === 'anchor-keys.json')!.evidence).toContain(`${s.key_id} ← ${k0} (genesis)`);
    rewrite(join(d, 'anchor-keys.json'), JSON.stringify({ v: 1, keys: [{ ...s, successor_signature: successor_signature.replace(/^./, (c) => (c === 'A' ? 'B' : 'A')), signed_by: k0 }] }));
    resign(d, f.dataDir);
    const broken = verifyAudit(d, trustK0); // no valid successor signature: not admitted, and the break fails
    expect(broken.ok).toBe(false);
    expect(broken.checks.find((c) => c.check === 'anchor-keys.json')).toMatchObject({ status: 'fail', evidence: expect.stringContaining(`${s.key_id} does not chain to a genesis key`) });
  });

  it('the shipped genesis key must match its pinned fingerprint', () => {
    const entry = SHIPPED_SERVICE_KEYS['https://anchor.isokron.ai']![0]! as { public_key_pem: string };
    const real = entry.public_key_pem;
    entry.public_key_pem = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }) as string;
    try {
      const { anchor_keys: _k, ...noKeys } = trustOpts(f);
      const r = verifyAudit(f.pkg, noKeys);
      expect(r.checks.find((c) => c.check === 'anchor keys')).toMatchObject({ status: 'fail', evidence: expect.stringMatching(/shipped genesis key anchor-ed25519-3dca1ecf66c2993e does not match its pinned fingerprint 3dca1ecf/) });
      expect(r.trust.service_key_ids).toEqual([]);
    } finally {
      entry.public_key_pem = real;
    }
  });

  it('--no-tsa: independent_timestamps not checked, no RFC 3161 lines, times from the anchor service', () => {
    const r = cli(['verify-audit', f.pkg, '--key', f.keyFile, '--anchor-keys', f.keysFile, '--no-tsa']);
    expect(r.code).toBe(0);
    expect(r.out).not.toContain('RFC 3161 alpha');
    expect(r.out).toMatch(/^ {2}not checked {3}independent_timestamps +skipped \(--no-tsa\)/m);
    expect(r.out).toMatch(/no later than .* \(anchor service\)/);
    expect(r.out).toContain('(independent_timestamps not checked)');
  });

  it('usage errors exit 2', () => {
    expect(cli(['verify-audit']).code).toBe(2);
    expect(cli(['verify-audit', join(f.pkg, 'nope')]).code).toBe(2);
    expect(cli(['verify-audit', f.pkg, '--bogus']).code).toBe(2);
    expect(cli(['verify-audit', f.pkg, '--no-tsa', '--tsa-roots', f.rootsDir]).code).toBe(2);
    expect(cli(['verify-audit', f.pkg, '--key', join(f.pkg, 'missing.pem')]).code).toBe(2);
    expect(cli(['verify-audit', f.pkg, '--require', 'thoroughness']).code).toBe(2);
  });

  it('a pack missing its anchors fails (exit 1); an unlisted file fails integrity', () => {
    const d = copyPkg(f);
    rmSync(join(d, 'anchors'), { recursive: true });
    resign(d, f.dataDir);
    const r = cli(['verify-audit', d, ...trustArgs(f)]);
    expect(r.code).toBe(1);
    expect(r.out).toContain('FAIL  anchors');
    const e = copyPkg(f);
    writeFileSync(join(e, 'extra.txt'), 'x');
    expect(verifyAudit(e, trustOpts(f)).checks.find((c) => c.check === 'SHA256SUMS')).toMatchObject({ status: 'fail', evidence: 'not in SHA256SUMS: extra.txt' });
  });

  it('audit package refuses a non-empty --out', () => {
    const store = new KronicleLite({ dataDir: f.dataDir });
    try {
      expect(() => buildAuditPackage(store, { audit_id: AUDIT, out: f.pkg })).toThrow(/not empty/);
    } finally {
      store.close();
    }
  });
});

describe('verify-audit: claims, ordering, run sequence and the v1 convention', () => {
  it('v1 kinds (finding class protocol_freeze, call_measured): format /1, ordering by recorded measured_at, no run_sequence claim', async () => {
    const f = await build('v1');
    const r = verifyAudit(f.pkg, trustOpts(f));
    expect(failedChecks(r)).toEqual([]);
    expect(r.bundle_format).toBe(BUNDLE_FORMAT_V1);
    expect(r.ordering).toMatchObject({ status: 'pass', basis: 'recorded_measured_at', runs: { count: 3, nonce_bound: 0 } });
    expect(claimStatus(r)).toMatchObject({ harness_frozen_before_runs: 'pass', run_sequence: 'not_declared' });
  });

  it('runs recorded before the freeze anchor (a retroactive record): the pack does not declare the ordering; declaring it fails with the times', async () => {
    const f = await build('v1-early');
    expect(f.pack.claims.find((c) => c.claim === 'harness_frozen_before_runs')).toMatchObject({ declared: false, why: expect.stringMatching(/3 of 3 run\(s\) record measured_at before it/) });
    const r = cli(['verify-audit', f.pkg, ...trustArgs(f)]);
    expect(r.code).toBe(0);
    expect(r.out).toMatch(/^ {2}not declared {2}harness_frozen_before_runs/m);
    expect(r.out).not.toContain('harness frozen before runs');
    // a client requiring the claim
    const req = cli(['verify-audit', f.pkg, ...trustArgs(f), '--require', 'harness_frozen_before_runs']);
    expect(req.code).toBe(1);
    expect(req.out).toMatch(/^ {2}FAIL {10}harness_frozen_before_runs +required \(--require\) but not declared by the pack/m);
    // a pack that declares it anyway
    const d = copyPkg(f);
    const claims = JSON.parse(readFileSync(join(d, 'claims.json'), 'utf8')) as { claims: string[] };
    claims.claims.push('harness_frozen_before_runs');
    rewrite(join(d, 'claims.json'), JSON.stringify(claims));
    resign(d, f.dataDir);
    const lie = cli(['verify-audit', d, ...trustArgs(f)]);
    expect(lie.code).toBe(1);
    expect(lie.out).toMatch(/FAIL {2}harness frozen before runs +harness abababababababab… frozen, committed \S+ \(01-harness-frozen, RFC 3161\); 3 of 3 run\(s\) record measured_at before it \(2020-01-01T00:00:00Z to 2020-01-03T00:00:00Z\)/);
    expect(lie.out).toMatch(/RESULT: FAILED {2}harness_frozen_before_runs \(1 failed check\(s\)\)/);
  });

  it('no freeze marker: harness_frozen_before_runs not declared; JSON ordering status not_declared', async () => {
    const f = await build('no-freeze');
    const r = cli(['verify-audit', f.pkg, ...trustArgs(f), '--json']);
    expect(r.code).toBe(0);
    const j = VerifyAuditJsonSchema.parse(JSON.parse(r.out));
    expect(j.ordering).toEqual({ status: 'not_declared', basis: null, harness_digest: null, freeze: null, runs: null, problem: null });
    expect(j.claims.find((c) => c.claim === 'harness_frozen_before_runs')).toEqual({ claim: 'harness_frozen_before_runs', status: 'not_declared', declared: false, required: false, evidence: '' });
    expect(j.checks.some((c) => c.group === 'ordering')).toBe(false);
  });

  it('a freeze committed together with runs is not declared as an ordering', async () => {
    const store = new KronicleLite({ dataDir: tempDir('kl-va-late-') });
    const tsa = makeTsa();
    const tsDir = tempDir('kl-va-late-ts-');
    let first = true;
    await recordAudit(store, 'v1', async () => {
      if (first) {
        first = false;
        return 'c'.repeat(64); // no anchor after the freeze
      }
      store.chain.checkpoint(1, store.chain.head().seq);
      const p = await pushCheckpoint(store, { anchorUrl: backend.url, licenseKey: STUB_LICENSE });
      const row = store.chain.listAnchors().find((a) => a.anchor_id === p.anchor_id)!;
      writeFileSync(join(tsDir, `${p.anchor_id}.alpha.tsr`), tsa.stamp(row.receipt_json));
      return sha(row.receipt_json);
    });
    const res = buildAuditPackage(store, { audit_id: AUDIT, out: join(tempDir('kl-va-late-pkg-'), 'p'), timestamps_dir: tsDir, tsa_roots: [tsa.root.pem] });
    store.close();
    expect(res.claims.find((c) => c.claim === 'harness_frozen_before_runs')).toMatchObject({ declared: false, why: expect.stringMatching(/is first committed by 01-call-measured together with 3 run\(s\)/) });
    expect(res.check.ok).toBe(true);
  });

  it('a run under another harness digest fails the ordering', async () => {
    const f = await build('milestones', { runHarness: (i) => (i === 2 ? 'cd'.repeat(32) : H) });
    expect(f.pack.claims.find((c) => c.claim === 'harness_frozen_before_runs')).toMatchObject({ declared: false, why: expect.stringMatching(/run seq 3 ran under harness cdcdcdcdcdcdcdcd…, not the frozen abababababababab…/) });
  });

  it('run sequence: a gap, a count that differs from planned_runs, interruptions that disagree with claims.json', async () => {
    const gap = await build('milestones', { runSeqs: [1, 2, 4] });
    const g = verifyAudit(gap.pkg, trustOpts(gap));
    expect(g.checks.find((c) => c.check === 'run sequence')).toMatchObject({ status: 'fail', evidence: 'run_seq is not contiguous: 3 missing of 1..4' });
    expect(claimStatus(g)).toMatchObject({ run_sequence: 'fail', harness_frozen_before_runs: 'pass' });
    expect(gap.pack.check.ok).toBe(false); // the packager sees it too

    const short = await build('milestones', { plannedRuns: 5 });
    expect(verifyAudit(short.pkg, trustOpts(short)).checks.find((c) => c.check === 'run sequence')!.evidence).toBe('3 run(s) recorded; declared 5 (planned_runs)');

    const good = await build('milestones');
    const d = copyPkg(good);
    const claims = JSON.parse(readFileSync(join(d, 'claims.json'), 'utf8')) as { runs: { interruptions: unknown[] } };
    claims.runs.interruptions = [];
    rewrite(join(d, 'claims.json'), JSON.stringify(claims));
    resign(d, good.dataDir);
    const r = verifyAudit(d, trustOpts(good));
    expect(r.run_sequence).toMatchObject({ status: 'fail', problem: 'claims.json lists interruptions for run(s) none; the bundle records them for 3' });
  });

  it('an expired TSA certificate fails at the current time and passes with --tsa-at-gentime', async () => {
    const old = [makeTsa({ name: 'Old', signerNotBefore: new Date('2020-01-01T00:00:00Z'), signerNotAfter: new Date('2021-01-01T00:00:00Z') })];
    const f = await build('milestones', { tsas: old, genTime: (i) => new Date(Date.UTC(2020, 5, 1, 0, 0, i)) });
    const now = cli(['verify-audit', f.pkg, ...trustArgs(f)]);
    expect(now.code).toBe(1);
    expect(now.out).toMatch(/FAIL {2}RFC 3161 alpha +certificate CN=Old TSA Signer is not valid at/);
    const at = cli(['verify-audit', f.pkg, ...trustArgs(f), '--tsa-at-gentime']);
    expect(at.code).toBe(0);
    expect(at.out).toContain('validity checked at genTime');
  });
});

describe('bundle format /2', () => {
  it('a /1 bundle may not carry milestone kinds (what a 0.9.0 reader would refuse)', () => {
    const kl = new KronicleLite({ memory: true });
    kl.audit.record(AUDIT, [{ kind: 'report_issued', event_key: 'r', payload: { report_id: 'R', report: kl.audit.putBlob(Buffer.from('# R'), 'text/markdown') } }], 'a');
    const dir = tempDir('kl-va-v2-');
    const r = exportBundle({ chain: kl.chain, audit: kl.audit, signer: kl.identity.signer, audit_id: AUDIT, dir });
    expect(r.manifest.format).toBe(BUNDLE_FORMAT_V2);
    expect(verifyBundle(dir).ok).toBe(true);
    const downgraded = signManifest({ ...r.manifest, format: BUNDLE_FORMAT_V1 } as BundleManifest, kl.identity.signer);
    rmSync(join(dir, 'manifest.json'));
    writeFileSync(join(dir, 'manifest.json'), canonicalize(downgraded) + '\n');
    const v = verifyBundle(dir);
    expect(v.checks.find((c) => c.check === 'events')).toMatchObject({ ok: false, problem: expect.stringMatching(/report_issued is not allowed in a kronicle-lite-evidence-bundle\/1 bundle/) });
    kl.close();
  });
});

describe('audit stamp', () => {
  it('fetches tokens over sha256(receipt), keeps an existing one, refuses a mismatched reply', async () => {
    const dataDir = tempDir('kl-va-stamp-');
    const store = new KronicleLite({ dataDir });
    store.docs.putDocument({ slug: 'n', title: 'n', markdown: '# n\n', actor_id: 'a' });
    store.chain.checkpoint();
    const p = await pushCheckpoint(store, { anchorUrl: backend.url, licenseKey: STUB_LICENSE });
    const tsa = makeTsa();
    const good = await serveTsa(tsa);
    const bad = await serveTsa(tsa, { reply: 'wrong-nonce' });
    const rejected = await serveTsa(tsa, { reply: 'rejected' });
    const out = tempDir('kl-va-stamp-out-');
    try {
      const r = await stampAnchor(store, { out_dir: out, tsas: [{ name: 'good', url: good.url }, { name: 'bad', url: bad.url }, { name: 'nope', url: rejected.url }] });
      expect(r.anchor_id).toBe(p.anchor_id);
      const row = store.chain.listAnchors()[0]!;
      expect(r.receipt_sha256).toBe(sha(row.receipt_json));
      expect(r.results.map((x) => [x.tsa, x.ok])).toEqual([['good', true], ['bad', false], ['nope', false]]);
      expect(r.results[1]!.problem).toMatch(/nonce/);
      expect(r.results[2]!.problem).toMatch(/did not grant/);
      const tok = readFileSync(join(out, `${p.anchor_id}.good.tsr`));
      expect(verifyTimestamp(tok, { message: row.receipt_json, roots: [tsa.root.pem] }).ok).toBe(true);
      const again = await stampAnchor(store, { out_dir: out, tsas: [{ name: 'good', url: good.url }] });
      expect(again.results[0]).toMatchObject({ ok: true, existing: true });
      expect(good.requests).toBe(1); // the first stamp is kept, not replaced
    } finally {
      await Promise.all([good.stop(), bad.stop(), rejected.stop()]);
      store.close();
    }
  });

  it('timestampRequest / checkTimestampReply round trip', () => {
    const tsa = makeTsa();
    const req = timestampRequest('hello');
    const reply = tsa.stamp('hello', { nonce: Buffer.from(req.nonce, 'hex') });
    expect(checkTimestampReply(reply, req).imprint).toBe(sha('hello'));
    expect(() => checkTimestampReply(tsa.stamp('other', { nonce: Buffer.from(req.nonce, 'hex') }), req)).toThrow(/different digest/);
  });
});

describe('RFC 3161: real Sectigo and DigiCert tokens against the shipped roots', () => {
  const dir = join(__dirname, 'fixtures', 'verify-audit', 'real-tsa');
  const roots = SHIPPED_TSA_ROOTS.map((r) => r.pem);
  const at = new Date('2026-11-10T00:00:00Z');
  const tokens = readdirSync(dir).filter((f) => f.endsWith('.tsr'));

  it('the fixture holds no credentials', () => {
    for (const f of readdirSync(dir)) expect(readFileSync(join(dir, f)).toString('latin1')).not.toMatch(/\?token=|ghp_|github_pat_|gho_/);
  });

  it('every token verifies over sha256(receipt file) to the pinned timestamping CA (Sectigo Root R46, DigiCert G4 TimeStamping CA)', () => {
    expect(tokens).toHaveLength(6);
    for (const t of tokens) {
      const receipt = readFileSync(join(dir, `${t.split('.')[0]}.receipt.json`));
      const v = verifyTimestamp(readFileSync(join(dir, t)), { message: receipt, roots, now: at });
      expect(v.problem, t).toBeNull();
      expect(v.ok).toBe(true);
      expect(v.root).toMatch(t.includes('sectigo') ? /CN=Sectigo Public Time Stamping Root R46$/ : /CN=DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1$/);
      expect(v.signer).toMatch(t.includes('sectigo') ? /^C=GB, ST=Greater London, O=Sectigo Limited, CN=Sectigo Public Time Stamping Signer R37$/ : /^C=US, O=DigiCert\\, Inc\., CN=DigiCert SHA256 RSA4096 Timestamp Responder 2026 1$/);
      expect(v.info!.gen_time).toMatch(/^2026-11-09T05:02:\d\d\.000Z$/);
    }
  });

  it('each TSA verifies only under its own pinned CA (the embedded cross-certificates are never needed)', () => {
    const pins = (name: string) => SHIPPED_TSA_ROOTS.filter((r) => r.name === name).map((r) => r.pem);
    for (const t of tokens) {
      const receipt = readFileSync(join(dir, `${t.split('.')[0]}.receipt.json`));
      const own = t.includes('sectigo') ? 'sectigo' : 'digicert';
      const other = own === 'sectigo' ? 'digicert' : 'sectigo';
      expect(verifyTimestamp(readFileSync(join(dir, t)), { message: receipt, roots: pins(own), now: at }).ok).toBe(true);
      expect(verifyTimestamp(readFileSync(join(dir, t)), { message: receipt, roots: pins(other), now: at }).problem).toMatch(/does not chain to a trusted TSA root/);
    }
    // the self-signed R46 alone is enough for Sectigo: its key is the cross-signed R46's
    const t = tokens.find((x) => x.includes('sectigo'))!;
    const r46 = SHIPPED_TSA_ROOTS.find((r) => r.subject.includes('R46 (self-signed)'))!.pem;
    expect(verifyTimestamp(readFileSync(join(dir, t)), { message: readFileSync(join(dir, `${t.split('.')[0]}.receipt.json`)), roots: [r46], now: at }).ok).toBe(true);
  });

  it('fails for other bytes, and once the chain has expired (unless checked at genTime)', () => {
    const t = tokens[0]!;
    const tok = readFileSync(join(dir, t));
    const receipt = readFileSync(join(dir, `${t.split('.')[0]}.receipt.json`));
    expect(verifyTimestamp(tok, { message: Buffer.concat([receipt, Buffer.from('\n')]), roots, now: at }).problem).toBe('messageImprint is not the hash of the stamped bytes');
    expect(verifyTimestamp(tok, { message: receipt, roots, now: new Date('2045-01-01T00:00:00Z') }).problem).toMatch(/is not valid at 2045/);
    expect(verifyTimestamp(tok, { message: receipt, roots, at: 'gentime' }).ok).toBe(true);
    expect(inspectTimestamp(tok).imprint).toBe(sha(receipt));
  });

  it('hostile bytes fail cleanly', () => {
    for (const b of [Buffer.alloc(0), Buffer.from([0x30, 0x84, 0xff, 0xff, 0xff, 0xff]), Buffer.from([0x30, 0x80, 0, 0]), readFileSync(join(dir, tokens[0]!)).subarray(0, 500)]) {
      const v = verifyTimestamp(b, { message: 'x', roots });
      expect(v.ok).toBe(false);
      expect(typeof v.problem).toBe('string');
    }
  });
});

describe('RFC 3161: certificate profile', () => {
  const at = { now: new Date('2030-01-01T00:00:00Z') };
  const check = (tsa: TestTsa) => verifyTimestamp(tsa.stamp('m'), { message: 'm', roots: [tsa.root.pem], ...at });

  it('a conforming chain (signer → intermediate → pinned root) verifies and reports the signer subject', () => {
    const v = check(makeTsa({ name: 'Ok', intermediate: { eku: [OID.timeStamping], ekuCritical: false } }));
    expect(v).toMatchObject({ ok: true, signer: 'CN=Ok TSA Signer', root: 'CN=Ok TSA Root' });
  });

  it('signer EKU must be critical and timeStamping only', () => {
    expect(check(makeTsa({ signer: { ekuCritical: false } })).problem).toBe('signing certificate CN=Test TSA Signer: extended key usage must be critical and timeStamping only');
    expect(check(makeTsa({ signer: { eku: [OID.timeStamping, '1.3.6.1.5.5.7.3.1'] } })).problem).toMatch(/must be critical and timeStamping only/);
    expect(check(makeTsa({ signer: { eku: [] } })).problem).toMatch(/must be critical and timeStamping only/);
  });

  it('intermediates: timeStamping or no EKU, and keyCertSign', () => {
    expect(check(makeTsa({ intermediate: {} })).ok).toBe(true); // no EKU
    expect(check(makeTsa({ intermediate: { eku: ['1.3.6.1.5.5.7.3.1'], ekuCritical: false } })).problem).toBe('intermediate CN=Test TSA CA: extended key usage does not include timeStamping');
    // without keyCertSign the CA cannot issue: path building finds no issuer (the profile check would refuse it too)
    expect(check(makeTsa({ intermediate: { keyUsage: 0x02 } })).problem).toMatch(/does not chain to a trusted TSA root|keyUsage lacks keyCertSign/);
  });

  it('unknown critical extensions and mismatched inner / outer signature algorithms are refused', () => {
    expect(check(makeTsa({ signer: { unknownCritical: true } })).problem).toBe('certificate CN=Test TSA Signer has an unrecognised critical extension 1.3.6.1.4.1.99999.7');
    expect(check(makeTsa({ intermediate: { unknownCritical: true } })).problem).toMatch(/CN=Test TSA CA has an unrecognised critical extension/);
    expect(check(makeTsa({ signer: { innerAlgMismatch: true } })).problem).toBe('certificate CN=Test TSA Signer: tbsCertificate.signature differs from signatureAlgorithm');
  });
});

describe('shipped trust', () => {
  it('the genesis anchor key pin derives its key id and fingerprint; the TSA CAs match their fingerprints', () => {
    const prod = SHIPPED_SERVICE_KEYS['https://anchor.isokron.ai']!;
    expect(prod.map((k) => k.key_id)).toEqual(['anchor-ed25519-3dca1ecf66c2993e']);
    expect(createHash('sha256').update(new X509Certificate(SHIPPED_TSA_ROOTS[0]!.pem).publicKey.export({ type: 'spki', format: 'der' })).digest('hex')).toBe(
      createHash('sha256').update(new X509Certificate(SHIPPED_TSA_ROOTS[1]!.pem).publicKey.export({ type: 'spki', format: 'der' })).digest('hex'),
    ); // both R46 forms are one key
    expect(prod[0]!.spki_sha256).toBe('3dca1ecf66c2993e534ff08fe350dc9368ca52042e38b20a9d58cd7c2b7b3367');
    expect(serviceKeyIdFromPem(prod[0]!.public_key_pem)).toBe('anchor-ed25519-3dca1ecf66c2993e');
    expect(SHIPPED_SERVICE_KEY_PINS['https://anchor.isokron.ai']).toEqual([prod[0]!.public_key_pem]);
    for (const r of SHIPPED_TSA_ROOTS) {
      const c = new X509Certificate(r.pem);
      expect(c.fingerprint256.replace(/:/g, '').toLowerCase()).toBe(r.sha256);
      expect(c.subject).toContain(`CN=${r.subject.split(' (')[0]}`);
      expect(c.ca).toBe(true);
    }
    expect(SHIPPED_TSA_ROOTS.map((r) => [r.name, r.sha256])).toEqual([
      ['sectigo', '4941b001b8a97e961b7817c9d9e960ec4b056bfc915a8c1aabf6ef6b3ac046a5'],
      ['sectigo', 'b53ac15cc1afb6e2ac06828f555bb3bf5bad8b2bac1733ce4cb7aafe729356de'],
      ['digicert', 'ca0b1554ecd901ea19dcad8749e9f2648c8d6dfcea1add9d2c2109415bb82ccd'],
      ['digicert', '281734d4592d1291d27190709cb510b07e22c405d5e0d6119b70e73589f98acf'],
    ]);
  });
});
