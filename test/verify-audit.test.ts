/**
 * verify-audit / audit package / audit stamp (0.10.0): IsoKron Evidence Packs.
 *
 * End to end on a synthetic pack: a store records an audit with three milestones, anchors each
 * on the in-test anchor stub, stamps each receipt with two throwaway RFC 3161 TSAs
 * (test/helpers/tsa.ts), packages it, and the CLI verifies it with the auditor key pinned by
 * fingerprint and the stub's key as the genesis pin. Then every probe of the independent review
 * (PR #37, kl-va-review P1–P7), each of which must now fail closed: downgraded or forged claims,
 * a pack's own key, broken / rolled-back / back-dated anchor key chains, forward-dated or
 * single-TSA timestamps, path-length and CA-signer certificates, DER mutations, measured_at
 * outside the timestamped window, symlinks and unreadable receipts.
 */

import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign as edSign, X509Certificate, type KeyObject } from 'node:crypto';
import { copyFileSync, cpSync, existsSync, linkSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { pushCheckpoint } from '../src/anchor/anchor.js';
import { formatGenesisPin, keyListRegression, PRODUCTION_GENESIS, retirementSigningPayload, successorSigningPayload, type ServiceKeyEntry } from '../src/anchor/keychain.js';
import { anchorReceiptSigningPayload } from '../src/anchor/receipt.js';
import { serviceKeyIdFromPem, SHIPPED_SERVICE_KEYS } from '../src/anchor/trust.js';
import { exportBundle, signManifest, type BundleManifest } from '../src/audit/bundle.js';
import { buildAuditPackage, stampAnchor } from '../src/audit/package.js';
import { inspectTimestamp, OID, timestampRequest, checkTimestampReply, verifyTimestamp } from '../src/audit/rfc3161.js';
import { BUNDLE_FORMAT_V1, BUNDLE_FORMAT_V2 } from '../src/audit/schemas.js';
import { readTime, TAG } from '../src/audit/der.js';
import { SHIPPED_TSA_ROOTS } from '../src/audit/tsa-roots.js';
import { listPackFiles, openTrustInput, readTrustInput, refuseInsidePack, renderVerifyAudit, SEEN_KEYS_FILE, sha256sums, SUMS_FILES, verifyAudit, VerifyAuditJsonSchema, VerifyAuditUsageError, type VerifyAuditOptions } from '../src/audit/verify-audit.js';
import { verifyBundle } from '../src/audit/verify-bundle.js';
import { canonicalize } from '../src/crypto/canonical.js';
import { chainIdFromPublicKeyPem } from '../src/crypto/keys.js';
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
  runSeqs?: number[];
  plannedRuns?: number;
  runHarness?: (i: number) => string;
  tweak?: boolean;
}

/** Record the audit: freeze → anchor → runs → anchor → report → anchor. `anchor` returns the anchored receipt's sha256. */
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
  if (variant !== 'milestones') await new Promise((r) => setTimeout(r, 1100)); // TSA times have whole seconds
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
    // measured_at inside the window the timestamps prove: after the freeze stamp, before the next anchor's stamp.
    const measured_at = variant === 'v1-early' ? `2020-01-0${i}T00:00:00Z` : new Date(Date.now() - 500 + i).toISOString();
    return { kind: 'call_measured' as const, event_key: `run:${n}`, payload: { fingerprint, tool: 'bench', status, is_error: false, latency_ms: 10, bytes_out: out.size, measured_at, response: out } };
  });
  store.audit.record(AUDIT, runs, 'proxy');
  if (variant !== 'milestones') await new Promise((r) => setTimeout(r, 1100));
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
  pack: Awaited<ReturnType<typeof buildAuditPackage>>;
  /** SHA-256(SPKI) of the auditor key; the anchor stub's genesis pin (<sha256>@<valid_from>) and its sha256. */
  fp: string;
  genesis: string;
  genesisFp: string;
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
  const keysFile = join(work, 'anchor-keys.published.json');
  const doc = (await (await fetch(`${backend.url}/.well-known/anchor-keys.json`)).json()) as { keys: { public_key_pem: string; valid_from: string }[] };
  writeFileSync(keysFile, JSON.stringify(doc));
  const genesisFp = chainIdFromPublicKeyPem(doc.keys[0]!.public_key_pem);
  const genesis = `${genesisFp}@${doc.keys[0]!.valid_from}`;
  const pkg = join(work, 'package');
  const pack = await buildAuditPackage(store, { audit_id: AUDIT, out: pkg, timestamps_dir: tsDir, tsa_roots: tsas.map((t) => t.root.pem), genesis });
  store.close();
  return { dataDir, pkg, keyFile, keysFile, rootsDir, tsDir, digests, tsas, pack, fp: chainIdFromPublicKeyPem(readFileSync(keyFile, 'utf8')), genesis, genesisFp };
}

/** A fresh rollback cache per call unless the test passes its own seen_dir. */
const trustOpts = (f: Fixture): VerifyAuditOptions => ({ seen_dir: tempDir('kl-va-seen-'), key_fingerprint: f.fp, genesis: f.genesis, tsa_roots: f.tsas.map((t) => t.root.pem) });

function cli(args: string[], env: Record<string, string> = {}) {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env: cleanEnv({ KRONICLE_LITE_DATA_DIR: tempDir('kl-va-cli-'), ...env }) });
  return { code: r.status, out: r.stdout, err: r.stderr };
}
const trustArgs = (f: Fixture) => ['--key-fingerprint', f.fp, '--genesis', f.genesis, '--tsa-roots', f.rootsDir];
const copyPkg = (f: Fixture) => {
  const d = join(tempDir('kl-va-copy-'), 'package');
  cpSync(f.pkg, d, { recursive: true });
  return d;
};
const rewrite = (p: string, data: string | Buffer) => {
  rmSync(p);
  writeFileSync(p, data);
};
/** Re-sign SHA256SUMS of a pack copy with the auditor's key, as the key holder could. */
function resign(d: string, dataDir: string): void {
  const store = new KronicleLite({ dataDir });
  try {
    for (const f of SUMS_FILES) rmSync(join(d, f), { force: true });
    const sums = sha256sums(d, listPackFiles(d).files);
    writeFileSync(join(d, 'SHA256SUMS'), sums);
    writeFileSync(join(d, 'SHA256SUMS.sig'), Buffer.from(store.identity.signer.sign(Buffer.from(sums)), 'base64'));
  } finally {
    store.close();
  }
}
function setClaims(d: string, mut: (c: { claims: string[]; runs?: unknown }) => void) {
  const p = join(d, 'claims.json');
  const c = JSON.parse(readFileSync(p, 'utf8')) as { claims: string[]; runs?: unknown };
  mut(c);
  rewrite(p, JSON.stringify(c, null, 1) + '\n');
}
const failedChecks = (r: ReturnType<typeof verifyAudit>) => r.checks.filter((c) => c.status === 'fail').map((c) => `${c.subject ? `${c.subject} ` : ''}${c.check}`);
const claimStatus = (r: ReturnType<typeof verifyAudit>) => Object.fromEntries(r.claims.map((c) => [c.claim, c.status]));

// ── service keys under test control (the stub's private key is not exposed) ──
interface SK {
  priv: KeyObject;
  pem: string;
  id: string;
  fp: string;
}
function newKey(): SK {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
  return { priv: privateKey, pem, id: serviceKeyIdFromPem(pem), fp: chainIdFromPublicKeyPem(pem) };
}
const b64sig = (k: SK, msg: string) => edSign(null, Buffer.from(msg), k.priv).toString('base64');
/** A rotation P → K as the service's scripts/rotate-key.mjs writes it. */
function rotated(p: SK, pFrom: string, k: SK, kFrom: string, pStatus: 'retired' | 'revoked' = 'retired') {
  return [
    { key_id: k.id, public_key_pem: k.pem, valid_from: kFrom, status: 'active', successor_signature: b64sig(p, successorSigningPayload({ key_id: k.id, public_key_pem: k.pem, valid_from: kFrom })), signed_by: p.id },
    { key_id: p.id, public_key_pem: p.pem, valid_from: pFrom, valid_to: kFrom, status: pStatus, retirement_signature: b64sig(k, retirementSigningPayload({ key_id: p.id, status: pStatus, valid_to: kFrom })), retirement_signed_by: k.id },
  ];
}
/** Revoke `key` in `keys` as the service's scripts/rotate-key.mjs revoke() does: signed by `signer` (the key itself or an earlier one). */
function revokeKey(keys: Record<string, unknown>[], key: SK, signer: SK, compromisedSince: string, validTo?: string) {
  return keys.map((k) => {
    if (k['key_id'] !== key.id) return k;
    const valid_to = validTo ?? (k['valid_to'] as string);
    const statement = { key_id: key.id, status: 'revoked', valid_to, compromised_since: compromisedSince };
    return { ...k, status: 'revoked', valid_to, compromised_since: compromisedSince, retirement_signature: b64sig(signer, retirementSigningPayload(statement)), retirement_signed_by: signer.id };
  });
}
const ANCH = ['01-harness-frozen', '02-run-completed', '03-report-issued'];
/** Re-sign a pack copy's receipts with `k` at the given received_at, and re-stamp them (both TSAs). */
function resignReceipts(d: string, f: Fixture, k: SK, receivedAt: (i: number) => string, genTime?: (i: number) => Date, tsas = f.tsas) {
  ANCH.forEach((b, i) => {
    const p = join(d, 'anchors', `${b}.receipt.json`);
    const r = JSON.parse(readFileSync(p, 'utf8')) as Record<string, unknown>;
    r['service_key_id'] = k.id;
    r['received_at'] = receivedAt(i);
    delete r['signature'];
    r['signature'] = b64sig(k, anchorReceiptSigningPayload(r as never));
    const bytes = canonicalize(r);
    rewrite(p, bytes);
    tsas.forEach((t, j) => rewrite(join(d, 'anchors', `${b}.${j === 0 ? 'alpha' : 'beta'}.tsr`), t.stamp(bytes, genTime ? { genTime: genTime(i) } : {})));
  });
}
const setPackKeys = (d: string, keys: unknown[]) => rewrite(join(d, 'anchor-keys.json'), JSON.stringify({ v: 1, keys }));
const noOrdering = (c: { claims: string[] }) => {
  c.claims = c.claims.filter((x) => x !== 'harness_frozen_before_runs');
};
const iso = (ms: number) => new Date(ms).toISOString();

describe('verify-audit: a synthetic evidence pack end to end', () => {
  let f: Fixture;
  beforeAll(async () => {
    f = await build('milestones');
  });

  it('audit package writes the pack layout, ships the published key list, declares what the store supports, and verifies itself', () => {
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
    expect(sha(readFileSync(join(f.pkg, 'anchors', '01-harness-frozen.receipt.json')))).toBe(f.digests[0]);
    expect((JSON.parse(readFileSync(join(f.pkg, 'anchor-keys.json'), 'utf8')) as { keys: { key_id: string }[] }).keys.map((k) => k.key_id)).toEqual(
      (JSON.parse(readFileSync(f.keysFile, 'utf8')) as { keys: { key_id: string }[] }).keys.map((k) => k.key_id),
    );
    expect(JSON.parse(readFileSync(join(f.pkg, 'claims.json'), 'utf8'))).toEqual({
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
    // N6: files in the pack carry no trust values, only where to get them
    expect(completion).toContain('verify-audit <this directory> --key-fingerprint <auditor key fingerprint from your statement of work> --genesis <the anchor service genesis pin');
    const verify = readFileSync(join(f.pkg, 'VERIFY.md'), 'utf8');
    for (const t of [completion, verify, readFileSync(join(f.pkg, 'claims.json'), 'utf8')]) {
      expect(t).not.toContain(f.fp);
      expect(t).not.toContain(f.genesisFp);
    }
    expect(verify).toContain('openssl pkeyutl -verify -pubin -inkey auditor-key.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig');
    expect(verify).toContain('openssl ts -verify -digest $D -in anchors/01-harness-frozen.alpha.tsr -CAfile tsa-roots/custom-1.pem -partial_chain');
    expect(verify).toMatch(/-attime \d{10}/);
    // P1f: no document tells the client to trust the pack's own key file
    for (const t of [verify, completion]) {
      expect(t).not.toMatch(/--key auditor-key\.pem/);
      expect(t).not.toMatch(/immutable|tamper-proof|certified|trustless/i);
    }
  });

  it('verifies: exit 0, one PASS per claim, the key pinned by fingerprint, values to compare', () => {
    const r = cli(['verify-audit', f.pkg, ...trustArgs(f)]);
    expect(r.err).toBe('');
    expect(r.code).toBe(0);
    expect(r.out.split('\n')[0]).toBe(`IsoKron Evidence Pack  ${f.pkg}`);
    expect(r.out).toContain('(pinned by --key-fingerprint)');
    for (const c of ['integrity', 'chain', 'receipts', 'independent_timestamps', 'harness_frozen_before_runs', 'run_sequence']) expect(r.out).toMatch(new RegExp(`^ {2}PASS {10}${c} `, 'm'));
    expect(r.out).toMatch(/PASS {2}anchor key list +intact: 1 key\(s\), each verified back to the pinned genesis key: anchor-ed25519-[0-9a-f]{16} \(genesis\)/);
    expect(r.out).toMatch(/PASS {2}independent TSAs +valid tokens under 2 pinned TSA CAs \(tsa-0, tsa-1\)/);
    expect(r.out).toMatch(/PASS {2}harness frozen before runs +harness abababababababab… frozen, committed .*3\/3 run\(s\) name that harness, carry the freeze receipt digest/);
    expect(r.out).toMatch(/PASS {2}run sequence +3 run\(s\), run_seq 1\.\.3 contiguous; matches planned_runs 3, report_run_count 3, claims\.json 3; 1 capture interruption\(s\): run 3 \(proxy restarted; resumed\)/);
    expect(r.out).toMatch(/PASS {2}SHA256SUMS +\d+ file\(s\) match; signed by ed25519-/);
    expect(r.out).toMatch(/PASS {2}stamped within key validity/);
    expect(r.out).toContain(`manifest sha256  ${f.pack.manifest_sha256}`);
    expect(r.out).toContain('RESULT: VERIFIED  integrity, chain, receipts, independent_timestamps, harness_frozen_before_runs, run_sequence');
    expect(r.out).not.toContain('FAIL');
    expect(r.out).not.toMatch(/does not prove|NOT proven|not prove/i);
    expect(cli(['help']).out).toContain('Establishes integrity, ordering');
  });

  it('--json follows the published schema', () => {
    const r = cli(['verify-audit', f.pkg, ...trustArgs(f), '--json']);
    expect(r.code).toBe(0);
    const j = VerifyAuditJsonSchema.parse(JSON.parse(r.out));
    expect(j).toMatchObject({ ok: true, failed: 0, audit_id: AUDIT, bundle_format: BUNDLE_FORMAT_V2, manifest_sha256: f.pack.manifest_sha256, auditor: { source: 'fingerprint', spki_sha256: f.fp }, trust: { key_list: 'pack', genesis_sha256: f.genesisFp, genesis_valid_from: '2026-11-01T00:00:00.000Z', genesis_source: 'option', key_chain: { status: 'intact' }, tsa_roots: 'dir', tsa_time: 'now' } });
    expect(j.claims.map((c) => [c.claim, c.status])).toEqual(['integrity', 'chain', 'receipts', 'independent_timestamps', 'harness_frozen_before_runs', 'run_sequence'].map((c) => [c, 'pass']));
    expect(j.ordering).toMatchObject({ status: 'pass', basis: 'freeze_nonce', harness_digest: H, runs: { count: 3, nonce_bound: 3 } });
    expect(j.anchors.every((a) => a.ok && a.timestamps.length === 2 && a.timestamps.every((t) => t.ok) && new Set(a.timestamps.map((t) => t.ca)).size === 2)).toBe(true);
  });

  it('does not depend on openssl (PATH empty)', () => {
    const r = cli(['verify-audit', f.pkg, ...trustArgs(f)], { PATH: '' });
    expect(r.code).toBe(0);
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
    const all = r.stdout + r.stderr;
    expect(all).not.toMatch(/Verification: FAILED|Signature Verification Failure|: FAILED/);
    expect(r.status).toBe(0);
    expect(all.match(/Verification: OK/g)?.length).toBeGreaterThanOrEqual(12);
    expect(all.match(/Signature Verified Successfully/g)?.length).toBe(3);
  });

  const opensslTs = (() => {
    if (process.platform === 'win32') return false;
    const o = spawnSync('openssl', ['version'], { encoding: 'utf8' });
    return o.status === 0 && /^OpenSSL [3-9]\./.test(o.stdout);
  })();
  it.skipIf(!opensslTs)("the pack's tsa-roots/ files verify real Sectigo and DigiCert tokens with openssl ts -verify -partial_chain", () => {
    const real = join(__dirname, 'fixtures', 'verify-audit', 'real-tsa');
    const roots = join(f.pkg, 'tsa-roots');
    // sectigo.pem holds only the USERTrust-issued R46, the form the tokens embed; verify-audit still pins both forms
    const certsIn = (file: string) => readFileSync(file, 'utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)!.map((p) => new X509Certificate(p).fingerprint256.replace(/:/g, '').toLowerCase());
    expect(certsIn(join(roots, 'sectigo.pem'))).toEqual(['b53ac15cc1afb6e2ac06828f555bb3bf5bad8b2bac1733ce4cb7aafe729356de']);
    expect(certsIn(join(roots, 'digicert.pem'))).toEqual(['ca0b1554ecd901ea19dcad8749e9f2648c8d6dfcea1add9d2c2109415bb82ccd', '281734d4592d1291d27190709cb510b07e22c405d5e0d6119b70e73589f98acf']);
    expect(SHIPPED_TSA_ROOTS.filter((r) => r.name === 'sectigo')).toHaveLength(2);
    const ts = (tok: string, ca: string, extra: string[] = []) => {
      const receipt = readFileSync(join(real, `${tok.split('.')[0]}.receipt.json`));
      const r = spawnSync('openssl', ['ts', '-verify', '-digest', sha(receipt), '-in', join(real, tok), '-CAfile', ca, '-partial_chain', ...extra], { encoding: 'utf8' });
      return { ok: r.status === 0 && /Verification: OK/.test(r.stdout), out: r.stdout + r.stderr };
    };
    const tokens = readdirSync(real).filter((t) => t.endsWith('.tsr'));
    expect(tokens).toHaveLength(6);
    for (const t of tokens) {
      const ca = join(roots, t.includes('sectigo') ? 'sectigo.pem' : 'digicert.pem');
      const now = ts(t, ca);
      expect(now.ok, `${t}: ${now.out}`).toBe(true);
      const at = ts(t, ca, ['-attime', String(Math.floor(Date.parse(inspectTimestamp(readFileSync(join(real, t))).gen_time) / 1000))]);
      expect(at.ok, `${t} -attime: ${at.out}`).toBe(true);
      // the same file verifies in-process (VERIFY.md picks each token's CA file this way)
      const pems = readFileSync(ca, 'utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----\n?/g)!;
      expect(verifyTimestamp(readFileSync(join(real, t)), { message: readFileSync(join(real, `${t.split('.')[0]}.receipt.json`)), roots: pems, at: 'gentime' }).ok, t).toBe(true);
    }
    // the 0.10.0 file (self-signed R46 first, then the USERTrust-issued form) fails every Sectigo token in openssl
    const both = join(tempDir('kl-va-r46-'), 'sectigo-both.pem');
    writeFileSync(both, SHIPPED_TSA_ROOTS.filter((r) => r.name === 'sectigo').map((r) => r.pem).join(''));
    for (const t of tokens.filter((x) => x.includes('sectigo'))) expect(ts(t, both).out).toMatch(/ess cert id not found/);
  });

  it('one byte flipped in an artifact: exit 1, integrity FAIL', () => {
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
  });

  it('history rewritten and re-signed with the auditor key: integrity passes, the anchors do not', async () => {
    const forgedDir = tempDir('kl-va-forged-');
    copyFileSync(join(f.dataDir, 'signing-key.pem'), join(forgedDir, 'signing-key.pem'));
    const forged = new KronicleLite({ dataDir: forgedDir });
    let i = 0;
    await recordAudit(forged, 'milestones', async () => f.digests[i++]!, { tweak: true });
    const d = copyPkg(f);
    rmSync(join(d, 'bundle'), { recursive: true });
    exportBundle({ chain: forged.chain, audit: forged.audit, signer: forged.identity.signer, audit_id: AUDIT, dir: join(d, 'bundle') });
    forged.close();
    resign(d, forgedDir);
    expect(verifyBundle(join(d, 'bundle'), { public_key_pem: readFileSync(f.keyFile, 'utf8') }).ok).toBe(true);
    const r = verifyAudit(d, trustOpts(f));
    expect(failedChecks(r)).toEqual(expect.arrayContaining(['02-run-completed root matches bundle', '03-report-issued root matches bundle']));
    expect(claimStatus(r)).toMatchObject({ integrity: 'pass', receipts: 'fail' });
  });

  it('usage errors exit 2', () => {
    expect(cli(['verify-audit']).code).toBe(2);
    expect(cli(['verify-audit', join(f.pkg, 'nope'), ...trustArgs(f)]).code).toBe(2);
    expect(cli(['verify-audit', f.pkg, '--bogus']).code).toBe(2);
    expect(cli(['verify-audit', f.pkg, '--no-tsa', '--tsa-roots', f.rootsDir]).code).toBe(2);
    expect(cli(['verify-audit', f.pkg, '--key', join(tempDir('kl-va-nokey-'), 'missing.pem')]).code).toBe(2);
    expect(cli(['verify-audit', f.pkg, '--require', 'thoroughness']).code).toBe(2);
    expect(cli(['verify-audit', f.pkg, '--key-fingerprint', 'abc']).code).toBe(2);
  });

  it('audit package refuses a non-empty --out', async () => {
    const store = new KronicleLite({ dataDir: f.dataDir });
    try {
      await expect(buildAuditPackage(store, { audit_id: AUDIT, out: f.pkg })).rejects.toThrow(/not empty/);
    } finally {
      store.close();
    }
  });
});

describe('audit package text: the final root label and the anchor sections', () => {
  const rawTools = (() => {
    if (process.platform === 'win32') return false;
    const o = spawnSync('openssl', ['version'], { encoding: 'utf8' });
    return o.status === 0 && /^OpenSSL 3/.test(o.stdout) && spawnSync('jq', ['--version']).status === 0 && spawnSync('shasum', ['--version']).status === 0;
  })();
  const shBlocks = (md: string) => [...md.matchAll(/```sh\n([\s\S]*?)```/g)].map((m) => m[1]!);
  /** No empty or comment-only command block. */
  const expectNoEmptyBlocks = (md: string) => {
    for (const b of shBlocks(md)) expect(b.split('\n').filter((l) => l.trim() && !l.trim().startsWith('#')).length).toBeGreaterThan(0);
  };
  /** Every raw command in VERIFY.md succeeds with openssl / jq / shasum alone. */
  const expectRawCommandsPass = (pkg: string) => {
    if (!rawTools) return;
    const md = readFileSync(join(pkg, 'VERIFY.md'), 'utf8');
    const script = shBlocks(md.slice(md.indexOf('## Without kronicle-lite')))
      .join('\n')
      .split('\n')
      .filter((l) => !/^sha256sum /.test(l) || spawnSync('sha256sum', ['--version']).status === 0);
    const r = spawnSync('bash', ['-euo', 'pipefail', '-c', script.join('\n')], { cwd: pkg, encoding: 'utf8' });
    expect(r.stdout + r.stderr).not.toMatch(/Verification: FAILED|Signature Verification Failure|: FAILED/);
    expect(r.status).toBe(0);
  };

  /** A small audit: `before` events, an anchor after them (stamped or not) when `anchor`, then `after` more events. */
  async function pack(o: { anchor: boolean; stamp?: boolean; after?: number }) {
    const dataDir = tempDir('kl-pt-store-');
    const work = tempDir('kl-pt-work-');
    const tsDir = join(work, 'timestamps');
    mkdirSync(tsDir);
    const tsa = makeTsa({ name: 'Alpha' });
    const store = new KronicleLite({ dataDir });
    const snap = (key: string) => ({ kind: 'catalog_snapshot' as const, event_key: key, payload: { fingerprint: H, server: { name: 'acme' }, tool_count: 3, bytes: 10, snapshot: store.audit.putBlob(Buffer.from(`{"tools":["${key}"]}`), 'application/json') } });
    store.audit.record(AUDIT, [snap('catalog-1'), snap('catalog-2')], 'auditor');
    let anchorRoot: string | null = null;
    let anchorSeq = 0;
    if (o.anchor) {
      anchorSeq = store.chain.head().seq;
      store.chain.checkpoint(1, anchorSeq);
      const r = await pushCheckpoint(store, { anchorUrl: backend.url, licenseKey: STUB_LICENSE });
      const row = store.chain.listAnchors().find((a) => a.anchor_id === r.anchor_id)!;
      anchorRoot = row.root;
      if (o.stamp) writeFileSync(join(tsDir, `${r.anchor_id}.alpha.tsr`), tsa.stamp(row.receipt_json));
    }
    for (let i = 0; i < (o.after ?? 0); i++) store.audit.record(AUDIT, [snap(`later-${i}`)], 'auditor');
    const out = join(work, 'package');
    const p = await buildAuditPackage(store, { audit_id: AUDIT, out, timestamps_dir: tsDir, tsa_roots: [tsa.root.pem], genesis: backend.genesis });
    store.close();
    return { p, out, anchorRoot, anchorSeq, completion: readFileSync(join(out, 'COMPLETION.txt'), 'utf8'), verify: readFileSync(join(out, 'VERIFY.md'), 'utf8') };
  }

  it('the last anchor commits the bundle root: "Final anchored root", every section present', async () => {
    const r = await pack({ anchor: true, stamp: true });
    expect(r.anchorRoot).toBe(r.p.root);
    expect(r.completion).toContain('Tamper-evident, independently timestamped audit evidence.');
    expect(r.completion).toContain(`Final anchored root   ${r.p.root}\n  covering            seq 1..${r.anchorSeq}`);
    expect(r.completion).toMatch(/\n {2}anchor {14}01-catalog-snapshot, /);
    expect(r.completion).toContain('\nMilestones\n');
    expect(r.completion).not.toContain('Last anchored root');
    expect(r.verify).toContain(`- Final anchored root: \`${r.p.root}\``);
    expect(r.verify).not.toContain('Last anchored root');
    for (const h of ['### 1. Files: SHA256SUMS and its signature', '### 2. Independent time: each RFC 3161 token', '### 3. Anchor receipts: Ed25519 signatures', '## Re-verifying in later years']) expect(r.verify).toContain(h);
    expect(r.verify).not.toMatch(/no anchor receipts|no RFC 3161 timestamp tokens/);
    expectNoEmptyBlocks(r.verify);
    expectRawCommandsPass(r.out);
  });

  it('events after the last anchor: "Final root", and the last anchored root on its own line with its range', async () => {
    const r = await pack({ anchor: true, stamp: true, after: 2 });
    expect(r.anchorRoot).not.toBe(r.p.root);
    expect(r.p.to_seq).toBe(r.anchorSeq + 2);
    for (const t of [r.completion, r.verify]) expect(t).not.toContain('Final anchored root');
    expect(r.completion).toContain(`Final root            ${r.p.root}\n  covering            seq 1..${r.p.to_seq}`);
    expect(r.completion).toContain(`Last anchored root    ${r.anchorRoot} (seq 1..${r.anchorSeq})\n  anchor              01-catalog-snapshot, `);
    expect(r.verify).toContain(`- Final root: \`${r.p.root}\`\n- Last anchored root: \`${r.anchorRoot}\` (seq 1..${r.anchorSeq})`);
    expect(r.verify).toContain('### 2. Independent time: each RFC 3161 token');
    expectNoEmptyBlocks(r.verify);
    expectRawCommandsPass(r.out);
  });

  it('an anchor without tokens: one line instead of the timestamp sections, the receipt section stays', async () => {
    const r = await pack({ anchor: true });
    expect(r.completion).toContain(`Final anchored root   ${r.p.root}`);
    expect(r.completion).toContain('Tamper-evident audit evidence.');
    expect(r.completion).not.toContain('independently timestamped');
    expect(r.verify).toContain('This pack has no RFC 3161 timestamp tokens.');
    expect(r.verify).toContain('### 2. Anchor receipts: Ed25519 signatures');
    expect(r.verify).not.toMatch(/Independent time|Re-verifying in later years|openssl ts /);
    expectNoEmptyBlocks(r.verify);
    expectRawCommandsPass(r.out);
  });

  it('no anchors: "Final root", one line saying so, no anchor or timestamp sections and no empty blocks', async () => {
    const r = await pack({ anchor: false });
    expect(r.p.anchors).toEqual([]);
    for (const t of [r.completion, r.verify]) {
      expect(t).not.toMatch(/anchored root/i);
      expect(t).not.toContain('independently timestamped');
      expect(t).not.toMatch(/immutable|tamper-proof|certified|trustless/i);
    }
    expect(r.completion).toContain('Tamper-evident audit evidence.');
    expect(r.completion).toContain(`Final root            ${r.p.root}`);
    expect(r.completion).toContain('Anchors               none (this pack has no anchor receipts)');
    expect(r.completion).not.toMatch(/Milestones|\n {2}anchor |\n {2}timestamps /);
    expect(r.verify).toContain(`- Final root: \`${r.p.root}\``);
    expect(r.verify).toContain('This pack has no anchor receipts, so it carries no anchor signatures or RFC 3161 timestamp tokens to check.');
    expect(r.verify).toContain('### 1. Files: SHA256SUMS and its signature');
    expect(r.verify).not.toMatch(/### 2\.|Independent time|Anchor receipts:|Re-verifying in later years|holds no anchors/);
    expectNoEmptyBlocks(r.verify);
    expectRawCommandsPass(r.out);
  });
});

describe('review probes P1: claims and the auditor key', () => {
  let f: Fixture;
  beforeAll(async () => {
    f = await build('milestones');
  });

  it('P1a: tampered artifact + extra file + edited COMPLETION.txt + integrity dropped from claims.json: exit 1', () => {
    const d = copyPkg(f);
    const blobs = join(d, 'bundle', 'blobs');
    const name = readdirSync(blobs)[0]!;
    const b = readFileSync(join(blobs, name));
    b[0] = b[0]! ^ 0x01;
    rewrite(join(blobs, name), b);
    setClaims(d, (c) => {
      c.claims = c.claims.filter((x) => x !== 'integrity');
    });
    writeFileSync(join(d, 'extra-unlisted.sh'), 'echo planted\n');
    rewrite(join(d, 'COMPLETION.txt'), 'edited by a third party\n');
    const r = cli(['verify-audit', d, ...trustArgs(f), '--json']);
    expect(r.code).toBe(1);
    const j = VerifyAuditJsonSchema.parse(JSON.parse(r.out));
    expect(j.ok).toBe(false);
    expect(j.claims.find((c) => c.claim === 'integrity')!.status).toBe('fail'); // always checked
    expect(j.checks.find((c) => c.check === 'claims.json')).toMatchObject({ status: 'fail', evidence: 'not authenticated (SHA256SUMS does not verify): every claim is checked' });
    expect(j.checks.find((c) => c.check === 'artifacts')!.status).toBe('fail');
  });

  it('P1b: claims.json reduced to [chain] (unsigned edit): exit 1; re-signed by the auditor: integrity still checked and passes', () => {
    const d = copyPkg(f);
    setClaims(d, (c) => {
      c.claims = ['chain'];
      delete c.runs;
    });
    expect(cli(['verify-audit', d, ...trustArgs(f)]).code).toBe(1);
    resign(d, f.dataDir);
    const r = verifyAudit(d, trustOpts(f));
    expect(claimStatus(r)).toEqual({ integrity: 'pass', chain: 'pass', receipts: 'not_declared', independent_timestamps: 'not_declared', harness_frozen_before_runs: 'not_declared', run_sequence: 'not_declared' });
  });

  it('P1c / P1d: claims.json deleted, or [] unsigned: every claim is checked', () => {
    const d = copyPkg(f);
    rmSync(join(d, 'claims.json'));
    resign(d, f.dataDir);
    const r = verifyAudit(d, trustOpts(f));
    expect(r.checks.find((c) => c.check === 'claims.json')).toMatchObject({ status: 'fail', evidence: 'claims.json is missing: every claim is checked' });
    expect(r.claims.every((c) => c.status !== 'not_declared')).toBe(true);
    expect(r.ok).toBe(false);
    const e = copyPkg(f);
    setClaims(e, (c) => {
      c.claims = [];
      delete c.runs;
    });
    const r2 = verifyAudit(e, trustOpts(f));
    expect(r2.ok).toBe(false);
    expect(r2.claims.every((c) => c.status !== 'not_declared')).toBe(true);
  });

  it('P1e: --require independent_timestamps --no-tsa is a usage error', () => {
    expect(cli(['verify-audit', f.pkg, '--key-fingerprint', f.fp, '--genesis', f.genesis, '--no-tsa', '--require', 'independent_timestamps']).code).toBe(2);
    expect(cli(['verify-audit', f.pkg, '--key-fingerprint', f.fp, '--genesis', f.genesis, '--no-tsa', '--require', 'harness_frozen_before_runs']).code).toBe(2);
    // a declared claim left unchecked blocks exit 0 (R7a)
    const r = cli(['verify-audit', f.pkg, '--key-fingerprint', f.fp, '--genesis', f.genesis, '--no-tsa']);
    expect(r.code).toBe(1);
    expect(r.out).toMatch(/^ {2}not checked {3}independent_timestamps +not checked \(--no-tsa\); the pack declares it/m);
    expect(r.out).toMatch(/^ {2}not checked {3}harness_frozen_before_runs/m);
  });

  it('P1g: a pack re-made under a fresh key fails however it is pinned; --key inside the pack is refused', async () => {
    const d = copyPkg(f);
    const forgedDir = tempDir('kl-va-forge2-');
    const forged = new KronicleLite({ dataDir: forgedDir });
    forged.audit.record(AUDIT, [{ kind: 'harness_frozen', event_key: 'freeze', payload: { harness_id: 'h', fingerprint: H, manifest: forged.audit.putBlob(Buffer.from('x'), 'text/plain'), planned_runs: 1 } }], 'auditor');
    forged.audit.record(AUDIT, [{ kind: 'run_completed', event_key: 'run:1', payload: { run_id: 'run-1', run_seq: 1, fingerprint: H, status: 'pass' } }], 'proxy');
    rmSync(join(d, 'bundle'), { recursive: true });
    exportBundle({ chain: forged.chain, audit: forged.audit, signer: forged.identity.signer, audit_id: AUDIT, dir: join(d, 'bundle') });
    rewrite(join(d, 'auditor-key.pem'), forged.identity.signer.public_key_pem);
    forged.close();
    setClaims(d, (c) => {
      c.claims = ['integrity', 'chain', 'run_sequence'];
      c.runs = { count: 1, seqs: [1], interruptions: [] };
    });
    resign(d, forgedDir);
    // the old VERIFY.md command: the pack's own key file
    const inside = cli(['verify-audit', d, '--key', join(d, 'auditor-key.pem'), '--genesis', f.genesis, '--tsa-roots', f.rootsDir]);
    expect(inside.code).toBe(2);
    expect(inside.err).toMatch(/is inside the pack/);
    // the real auditor's fingerprint
    const pinned = cli(['verify-audit', d, ...trustArgs(f)]);
    expect(pinned.code).toBe(1);
    expect(pinned.out).toMatch(/FAIL {2}auditor key +the pack's auditor key has SHA-256\(SPKI\) [0-9a-f]{64}, not the pinned/);
    // nothing pinned
    const none = cli(['verify-audit', d, '--genesis', f.genesis, '--tsa-roots', f.rootsDir]);
    expect(none.code).toBe(1);
    expect(none.out).toMatch(/FAIL {2}auditor key +not pinned: pass --key-fingerprint/);
    // an unpinned key never exits 0, even on the genuine pack
    expect(cli(['verify-audit', f.pkg, '--genesis', f.genesis, '--tsa-roots', f.rootsDir]).code).toBe(1);
  });
});

describe('review probes P3/P4a: the anchor key chain and the receipt times', () => {
  let f: Fixture;
  beforeAll(async () => {
    f = await build('milestones');
  });
  const now = Date.now();
  /** Receipts re-signed by `signer`, the pack's key list replaced, claims without the ordering, SHA256SUMS re-signed. */
  const run = (keys: unknown[], signer: SK, genesis: SK, receivedAt: (i: number) => string, genTime?: (i: number) => Date, extra: Partial<VerifyAuditOptions> = {}) => {
    const d = copyPkg(f);
    resignReceipts(d, f, signer, receivedAt, genTime);
    setPackKeys(d, keys);
    setClaims(d, noOrdering);
    resign(d, f.dataDir);
    return verifyAudit(d, { ...trustOpts(f), genesis: `${genesis.fp}@${GENESIS_FROM}`, ...extra });
  };
  /** The genesis pin's valid_from in these lists (the pin's, never the list's, counts). */
  const GENESIS_FROM = '2026-01-01T00:00:00.000Z';
  const R = newKey();
  const S = newKey();
  const X = newKey();
  const Y = newKey();
  const ent = (k: SK, extra: Record<string, unknown> = {}) => ({ key_id: k.id, public_key_pem: k.pem, ...extra });
  const recent = (i: number) => iso(now - 60e3 + i * 1e3);
  const keyListFailure = (r: ReturnType<typeof verifyAudit>) => r.checks.find((c) => c.check === 'anchor key list');

  it('a well-formed rotation R → S verifies (the service rotate-key.mjs shape)', () => {
    const r = run(rotated(R, '2026-01-01T00:00:00.000Z', S, iso(now - 86400e3)), S, R, recent);
    expect(failedChecks(r)).toEqual([]);
    expect(r.trust.key_chain.entries.map((e) => e.state)).toEqual(['verified', 'genesis']);
  });

  it('P3a: a retired R signs a successor S without the successor-signed status statement: BROKEN', () => {
    const vf = iso(now - 86400e3);
    const keys = [ent(R, { status: 'retired', valid_from: '2026-01-01T00:00:00.000Z', valid_to: '2026-06-01T00:00:00.000Z' }), ent(S, { status: 'active', valid_from: vf, successor_signature: b64sig(R, successorSigningPayload({ key_id: S.id, public_key_pem: S.pem, valid_from: vf })), signed_by: R.id })];
    const r = run(keys, S, R, recent);
    expect(keyListFailure(r)).toMatchObject({ status: 'fail', evidence: expect.stringMatching(/status "retired" is not signed by its successor/) });
    expect(claimStatus(r).receipts).toBe('fail');
  });

  it('P3b: a successor back-dated before its predecessor: BROKEN', () => {
    const keys = rotated(R, '2026-11-01T00:00:00.000Z', S, '2026-11-02T00:00:00.000Z').map((k) => (k.key_id === S.id ? { ...k, valid_from: '2020-01-01T00:00:00.000Z' } : k));
    const r = run(keys, S, R, (i) => `2021-01-01T00:00:0${i}.000Z`);
    expect(keyListFailure(r)!.status).toBe('fail');
    expect(r.ok).toBe(false);
  });

  it('P3c: a predecessor still active after its successor: BROKEN', () => {
    const keys = rotated(R, '2026-01-01T00:00:00.000Z', S, iso(now - 86400e3)).map((k) => (k.key_id === R.id ? { ...k, status: 'active' } : k));
    const r = run(keys, R, R, recent);
    expect(keyListFailure(r)).toMatchObject({ status: 'fail', evidence: expect.stringMatching(/has successor .* but is active; it must be retired or revoked/) });
  });

  it('P3d: a retired key signs receipts dated inside its old window, stamped after it ended: FAIL', () => {
    const end = iso(now - 3600e3);
    const r = run(rotated(R, '2026-01-01T00:00:00.000Z', S, end), R, R, (i) => iso(now - 4 * 3600e3 + i * 60e3));
    expect(failedChecks(r)).toEqual(expect.arrayContaining(['01-harness-frozen stamped within key validity']));
    expect(r.checks.find((c) => c.check === 'stamped within key validity' && c.status === 'fail')!.evidence).toMatch(/is after anchor-ed25519-[0-9a-f]{16} ended at/);
  });

  it('P3e–P3i: revoked signer, rogue key, cycle, an unchained key in --anchor-keys, a successor of an unlisted key: BROKEN', () => {
    const vf = iso(now - 86400e3);
    const sig = (p: SK, k: SK, from: string) => b64sig(p, successorSigningPayload({ key_id: k.id, public_key_pem: k.pem, valid_from: from }));
    // a revocation signed by the successor (the old shape) and without compromised_since: BROKEN
    expect(keyListFailure(run(rotated(R, '2026-01-01T00:00:00.000Z', S, vf, 'revoked'), S, R, recent))!.evidence).toMatch(/revoked without a parseable compromised_since/);
    // a proper revocation of R: S, whose successor statement R signed, is not trusted
    const after = run(revokeKey(rotated(R, '2026-01-01T00:00:00.000Z', S, vf), R, R, iso(now - 2 * 86400e3)), S, R, recent);
    expect(keyListFailure(after)!.status).toBe('pass');
    expect(after.trust.key_chain).toMatchObject({ status: 'revoked_descendants', entries: [{ key_id: S.id, state: 'broken', revoked_ancestor: R.id }, { key_id: R.id, state: 'revoked' }] });
    expect(after.checks.find((c) => c.check === 'service signature' && c.status === 'fail')!.evidence).toMatch(/is not trusted/);
    expect(claimStatus(after).receipts).toBe('fail');
    expect(keyListFailure(run([ent(X, { status: 'active', valid_from: '2026-01-01T00:00:00.000Z' })], X, R, recent))!.evidence).toMatch(/genesis fingerprint [0-9a-f]{64} does not match the pinned/);
    const v0 = '2026-01-01T00:00:00.000Z';
    expect(keyListFailure(run([ent(X, { valid_from: v0, successor_signature: sig(Y, X, v0), signed_by: Y.id }), ent(Y, { valid_from: v0, successor_signature: sig(X, Y, v0), signed_by: X.id })], X, R, recent))!.status).toBe('fail');
    const file = { keys: [ent(R, { status: 'active', valid_from: v0 }), ent(X, { status: 'active', valid_from: v0 })] };
    expect(keyListFailure(run([], X, R, recent, undefined, { anchor_keys: file }))!.evidence).toMatch(/2 keys have no successor_signature; exactly one genesis key is allowed/);
    const unlisted = { keys: [ent(X, { status: 'active', valid_from: v0, successor_signature: 'A'.repeat(86) + '==', signed_by: 'anchor-ed25519-0000000000000000' })] };
    expect(keyListFailure(run([], X, X, recent, undefined, { anchor_keys: unlisted }))!.status).toBe('fail');
  });

  it('P4a: received_at forward-dated past the TSA time: FAIL; and stamped more than 24 h after received_at: FAIL', () => {
    const r = run([ent(R, { status: 'active', valid_from: '2026-01-01T00:00:00.000Z' })], R, R, (i) => `2030-01-01T00:00:0${i}.000Z`);
    expect(r.checks.find((c) => c.check === 'RFC 3161 alpha' && c.status === 'fail')!.evidence).toMatch(/receipt is forward-dated: received_at 2030-01-01T00:00:00.000Z is later than the TSA time/);
    const late = run([ent(R, { status: 'active', valid_from: '2026-01-01T00:00:00.000Z' })], R, R, (i) => iso(now - 3 * 86400e3 + i * 1e3));
    expect(late.checks.find((c) => c.check === 'RFC 3161 alpha' && c.status === 'fail')!.evidence).toMatch(/more than 24 h after received_at/);
  });

  it('F5: --anchor-keys is chain-checked against --genesis / KRONICLE_ANCHOR_GENESIS (<sha256>@<valid_from>); the compiled pin rejects a foreign genesis', () => {
    const d = copyPkg(f);
    // the stub list with the compiled production genesis: BROKEN, with the self-hosting hint
    const r = verifyAudit(d, { rollback: 'off', key_fingerprint: f.fp, tsa_roots: f.tsas.map((t) => t.root.pem) });
    expect(r.checks.find((c) => c.check === 'anchor key list')).toMatchObject({ status: 'fail', evidence: expect.stringMatching(/pass --genesis <sha256>@<valid_from>/) });
    const env = cli(['verify-audit', f.pkg, '--key-fingerprint', f.fp, '--tsa-roots', f.rootsDir], { KRONICLE_ANCHOR_GENESIS: f.genesis });
    expect(env.code).toBe(0);
    // the anchor client's rules: a bare hash is not a pin, and the old variable is refused, not ignored
    expect(cli(['verify-audit', f.pkg, '--key-fingerprint', f.fp, '--genesis', f.genesisFp, '--tsa-roots', f.rootsDir]).code).toBe(2);
    const old = cli(['verify-audit', f.pkg, ...trustArgs(f)], { KRONICLE_ANCHOR_GENESIS_SHA256: f.genesisFp });
    expect(old.code).toBe(2);
    expect(old.err).toMatch(/KRONICLE_ANCHOR_GENESIS_SHA256 is no longer read: set KRONICLE_ANCHOR_GENESIS=<sha256>@<valid_from>/);
    // the pin's valid_from, not the list's, bounds the genesis key: a receipt before it fails
    const late = verifyAudit(d, { ...trustOpts(f), genesis: `${f.genesisFp}@2099-01-01T00:00:00.000Z` });
    expect(late.checks.find((c) => c.check === 'service signature' && c.status === 'fail')!.evidence).toMatch(/precedes anchor-ed25519-[0-9a-f]{16} valid_from 2099-01-01T00:00:00.000Z/);
    const file = cli(['verify-audit', f.pkg, ...trustArgs(f), '--anchor-keys', f.keysFile]);
    expect(file.code).toBe(0);
  });

  it('rollback: a shorter key list than one seen before fails (cache in the data dir)', () => {
    const seen = tempDir('kl-va-seen-');
    const vf = iso(now - 86400e3);
    const newer = run(rotated(R, '2026-01-01T00:00:00.000Z', S, vf), S, R, recent, undefined, { seen_dir: seen });
    expect(failedChecks(newer)).toEqual([]);
    // N7: a first list is recorded and said so, but it is not a PASS
    expect(newer.checks.find((c) => c.check === 'key list rollback')).toBeUndefined();
    expect(newer.trust.rollback).toEqual({ status: 'first_seen', path: join(seen, 'anchor-keys.seen.json'), seen_at: null, recorded: true });
    expect(renderVerifyAudit(newer)).toContain(`key list       first seen for this genesis; recorded in ${join(seen, 'anchor-keys.seen.json')}`);
    const older = run([ent(R, { status: 'active', valid_from: '2026-01-01T00:00:00.000Z' })], R, R, (i) => iso(now - 2 * 86400e3 + i * 1e3), (i) => new Date(now - 2 * 86400e3 + 60e3 + i * 1e3), { seen_dir: seen });
    expect(older.checks.find((c) => c.check === 'key list rollback')).toMatchObject({ status: 'fail', evidence: expect.stringMatching(/older or weaker list than the one seen .*: anchor-ed25519-[0-9a-f]{16} is in the key list seen earlier but missing now/) });
    expect(older.ok).toBe(false);
  });
});

describe('a revoked anchor service key: only a verified TSA time before compromised_since − 5 min keeps its receipts', () => {
  let f: Fixture;
  beforeAll(async () => {
    f = await build('milestones');
  });
  const now = Date.now();
  const GENESIS_FROM = '2026-01-01T00:00:00.000Z';
  const R = newKey();
  const run = (cs: string, receivedAt: (i: number) => string, genTime?: (i: number) => Date, extra: Partial<VerifyAuditOptions> = {}) => {
    const keys = revokeKey([{ key_id: R.id, public_key_pem: R.pem, valid_from: GENESIS_FROM, status: 'active' }], R, R, cs, iso(now + 2 * 3600e3));
    const d = copyPkg(f);
    resignReceipts(d, f, R, receivedAt, genTime);
    setPackKeys(d, keys);
    setClaims(d, noOrdering);
    resign(d, f.dataDir);
    return verifyAudit(d, { ...trustOpts(f), genesis: `${R.fp}@${GENESIS_FROM}`, ...extra });
  };
  const recent = (i: number) => iso(now - 60e3 + i * 1e3);
  const stampCheck = (r: ReturnType<typeof verifyAudit>) => r.checks.filter((c) => c.check === 'stamped before compromise');

  it('stamped well before compromised_since: the receipts pass (the head may be revoked; the chain is intact)', () => {
    const r = run(iso(now + 3600e3), recent);
    expect(failedChecks(r)).toEqual([]);
    expect(r.trust.key_chain).toMatchObject({ status: 'intact', entries: [{ key_id: R.id, state: 'revoked', compromised_since: iso(now + 3600e3) }] });
    expect(stampCheck(r)).toHaveLength(3);
    expect(stampCheck(r)[0]!.evidence).toMatch(/earliest verified TSA time .* < .* − 5 min/);
    expect(r.ok).toBe(true);
  });

  it('stamped inside the 5 min before compromised_since: FAIL', () => {
    const r = run(iso(now + 2 * 60e3), recent);
    expect(stampCheck(r).every((c) => c.status === 'fail')).toBe(true);
    expect(stampCheck(r)[0]!.evidence).toMatch(/is not before .* − 5 min/);
    expect(claimStatus(r).receipts).toBe('fail');
    expect(r.ok).toBe(false);
  });

  it('received_at back-dated before compromised_since, stamped after it: FAIL (received_at never counts)', () => {
    const cs = iso(now - 3600e3);
    const r = run(cs, (i) => iso(now - 3 * 3600e3 + i * 1e3));
    expect(r.anchors.every((a) => Date.parse(a.received_at!) < Date.parse(cs) - 5 * 60e3)).toBe(true);
    expect(stampCheck(r).every((c) => c.status === 'fail')).toBe(true);
    expect(stampCheck(r)[0]!.evidence).toMatch(/received_at is the signer's own claim and does not count/);
    expect(r.ok).toBe(false);
  });

  it('with RFC 3161 tokens not checked (--no-tsa): FAIL, whatever received_at says', () => {
    const r = run(iso(now + 3600e3), recent, undefined, { no_tsa: true });
    expect(stampCheck(r).every((c) => c.status === 'fail')).toBe(true);
    expect(stampCheck(r)[0]!.evidence).toMatch(/RFC 3161 tokens are not checked here \(--no-tsa\)/);
    expect(claimStatus(r).receipts).toBe('fail');
    expect(r.ok).toBe(false);
  });

  it('a key after the revoked one fails; a key before it keeps its receipts', () => {
    const S = newKey();
    const vf = iso(now - 86400e3);
    // R → S, then S revoked by R (an earlier key), compromised long after the receipts below were stamped
    const keys = revokeKey(rotated(R, GENESIS_FROM, S, vf), S, R, iso(now + 3600e3), iso(now + 2 * 3600e3));
    const d = copyPkg(f);
    resignReceipts(d, f, S, recent);
    setPackKeys(d, keys);
    setClaims(d, noOrdering);
    resign(d, f.dataDir);
    const r = verifyAudit(d, { ...trustOpts(f), genesis: `${R.fp}@${GENESIS_FROM}` });
    expect(r.trust.key_chain.status).toBe('intact');
    expect(r.ok).toBe(true);
    // and the reverse: R revoked, S after it: S's receipts fail
    const e = copyPkg(f);
    resignReceipts(e, f, S, recent);
    setPackKeys(e, revokeKey(rotated(R, GENESIS_FROM, S, vf), R, R, iso(now + 3600e3)));
    setClaims(e, noOrdering);
    resign(e, f.dataDir);
    const r2 = verifyAudit(e, { ...trustOpts(f), genesis: `${R.fp}@${GENESIS_FROM}` });
    expect(r2.trust.key_chain.status).toBe('revoked_descendants');
    expect(claimStatus(r2).receipts).toBe('fail');
  });

  it('rollback: a list that drops the revocation, or moves compromised_since later, is refused against the data-dir cache', () => {
    const seen = tempDir('kl-va-seen-');
    const cs = iso(now + 3600e3);
    const first = run(cs, recent, undefined, { seen_dir: seen });
    expect(first.trust.rollback.status).toBe('first_seen');
    const later = run(iso(now + 7200e3), recent, undefined, { seen_dir: seen });
    expect(later.checks.find((c) => c.check === 'key list rollback')).toMatchObject({ status: 'fail', evidence: expect.stringMatching(/compromised_since was .* in the list seen earlier and is .* now/) });
    expect(later.ok).toBe(false);
    const d = copyPkg(f);
    resignReceipts(d, f, R, recent);
    setPackKeys(d, [{ key_id: R.id, public_key_pem: R.pem, valid_from: GENESIS_FROM, status: 'active' }]);
    setClaims(d, noOrdering);
    resign(d, f.dataDir);
    const unrevoked = verifyAudit(d, { ...trustOpts(f), genesis: `${R.fp}@${GENESIS_FROM}`, seen_dir: seen });
    expect(unrevoked.checks.find((c) => c.check === 'key list rollback')).toMatchObject({ status: 'fail', evidence: expect.stringMatching(/was revoked in the list seen earlier and is active now/) });
  });
});

describe('review probes P4b–P4f: timestamps', () => {
  let f: Fixture;
  beforeAll(async () => {
    f = await build('milestones');
  });

  it('P4b / P4c: one TSA only, or the same TSA under two labels: FAIL (two different pinned TSA CAs required)', () => {
    const d = copyPkg(f);
    for (const b of ANCH) rmSync(join(d, 'anchors', `${b}.beta.tsr`));
    resign(d, f.dataDir);
    const r = verifyAudit(d, trustOpts(f));
    expect(r.checks.find((c) => c.check === 'independent TSAs')).toMatchObject({ status: 'fail', evidence: expect.stringMatching(/^valid tokens under 1 pinned TSA CA\(s\) \(ca-[0-9a-f]{12}\); at least two different TSA CAs are required$/) });
    const e = copyPkg(f);
    for (const b of ANCH) rewrite(join(e, 'anchors', `${b}.beta.tsr`), f.tsas[0]!.stamp(readFileSync(join(e, 'anchors', `${b}.receipt.json`))));
    resign(e, f.dataDir);
    expect(claimStatus(verifyAudit(e, trustOpts(f))).independent_timestamps).toBe('fail');
  });

  it('P7: an unreadable receipt fails independent_timestamps instead of skipping its tokens', () => {
    const d = copyPkg(f);
    rewrite(join(d, 'anchors', '02-run-completed.receipt.json'), 'not json');
    for (const t of ['alpha', 'beta']) rewrite(join(d, 'anchors', `02-run-completed.${t}.tsr`), Buffer.from('garbage token'));
    setClaims(d, (c) => {
      c.claims = ['integrity', 'chain', 'independent_timestamps', 'run_sequence'];
    });
    resign(d, f.dataDir);
    const r = verifyAudit(d, trustOpts(f));
    expect(r.checks.find((c) => c.subject === '02-run-completed' && c.check === 'RFC 3161')).toMatchObject({ status: 'fail', evidence: 'receipt unreadable (not valid JSON); 2 token(s) over it cannot be checked' });
    expect(claimStatus(r)).toMatchObject({ receipts: 'fail', independent_timestamps: 'fail' });
  });
});

describe('review probes P5: ordering', () => {
  const blob = (s: KronicleLite, x: string) => s.audit.putBlob(Buffer.from(x), 'text/plain');
  async function buildCustom(rec: (store: KronicleLite, anchor: (to?: number) => Promise<string>) => Promise<void>) {
    const dataDir = tempDir('kl-va-store-');
    const tsDir = tempDir('kl-va-ts-');
    const tsas = [makeTsa({ name: 'Alpha' }), makeTsa({ name: 'Beta' })];
    const store = new KronicleLite({ dataDir });
    await rec(store, async (to?: number) => {
      store.chain.checkpoint(1, to ?? store.chain.head().seq);
      const r = await pushCheckpoint(store, { anchorUrl: backend.url, licenseKey: STUB_LICENSE });
      const row = store.chain.listAnchors().find((a) => a.anchor_id === r.anchor_id)!;
      tsas.forEach((t, k) => writeFileSync(join(tsDir, `${r.anchor_id}.${k === 0 ? 'alpha' : 'beta'}.tsr`), t.stamp(row.receipt_json)));
      return sha(row.receipt_json);
    });
    const doc = (await (await fetch(`${backend.url}/.well-known/anchor-keys.json`)).json()) as { keys: { public_key_pem: string; valid_from: string }[] };
    const genesis = `${chainIdFromPublicKeyPem(doc.keys[0]!.public_key_pem)}@${doc.keys[0]!.valid_from}`;
    const pkg = join(tempDir('kl-va-work-'), 'package');
    const pack = await buildAuditPackage(store, { audit_id: AUDIT, out: pkg, timestamps_dir: tsDir, tsa_roots: tsas.map((t) => t.root.pem), genesis });
    const fp = chainIdFromPublicKeyPem(store.identity.signer.public_key_pem);
    store.close();
    return { pkg, pack, dataDir, opts: { seen_dir: tempDir('kl-va-seen-'), key_fingerprint: fp, genesis, tsa_roots: tsas.map((t) => t.root.pem) } as VerifyAuditOptions };
  }
  const freezeV1 = (s: KronicleLite) => s.audit.record(AUDIT, [{ kind: 'finding', event_key: 'protocol', payload: { finding_id: 'PROTOCOL', status: 'discovered', class: 'protocol_freeze', fingerprint: H, detail: blob(s, 'h') } }], 'auditor');
  const runsV1 = (s: KronicleLite, at: (i: number) => string) =>
    s.audit.record(AUDIT, [1, 2].map((i) => ({ kind: 'call_measured' as const, event_key: `run:${i}`, payload: { fingerprint: H, tool: 'b', status: 'pass', is_error: false, latency_ms: 1, bytes_out: 1, measured_at: at(i), response: blob(s, `r${i}`) } })), 'proxy');
  const declareOrdering = (pkg: string, dataDir: string) => {
    setClaims(pkg, (c) => {
      if (!c.claims.includes('harness_frozen_before_runs')) c.claims.push('harness_frozen_before_runs');
    });
    resign(pkg, dataDir);
  };

  it('P5a: measured_at in 2099 is outside the timestamped window: not declared by the packager; declared, it fails', async () => {
    const b = await buildCustom(async (s, anchor) => {
      freezeV1(s);
      await anchor();
      runsV1(s, (i) => `2099-01-0${i}T00:00:00Z`);
      await anchor();
    });
    expect(b.pack.claims.find((c) => c.claim === 'harness_frozen_before_runs')).toMatchObject({ declared: false, why: expect.stringMatching(/do not carry the freeze nonce/) });
    declareOrdering(b.pkg, b.dataDir);
    const r = verifyAudit(b.pkg, b.opts);
    expect(r.checks.find((c) => c.group === 'ordering')).toMatchObject({ status: 'fail', evidence: expect.stringMatching(/2 of 2 run\(s\) do not carry the freeze nonce .*never by recorded times/) });
  });

  it('P5b: runs no anchor commits fail the ordering, even with receipts dropped from claims.json', async () => {
    const b = await buildCustom(async (s, anchor) => {
      freezeV1(s);
      await anchor();
      runsV1(s, (i) => new Date(Date.now() + 60_000 * i).toISOString());
    });
    expect(b.pack.claims.find((c) => c.claim === 'harness_frozen_before_runs')!.declared).toBe(false);
    setClaims(b.pkg, (c) => {
      c.claims = ['integrity', 'chain', 'independent_timestamps', 'harness_frozen_before_runs'];
    });
    resign(b.pkg, b.dataDir);
    const r = verifyAudit(b.pkg, b.opts);
    expect(claimStatus(r)).toMatchObject({ receipts: 'fail', harness_frozen_before_runs: 'fail' }); // receipts is a dependency: checked anyway
    expect(r.checks.find((c) => c.group === 'ordering')!.evidence).toMatch(/run seq 2, 3 are not committed by a timestamped anchor later than the freeze anchor/);
  });

  it('R2 (N1): runs recorded before the freeze anchor, measured_at written ahead: not declared; declared, FAIL', async () => {
    const b = await buildCustom(async (s, anchor) => {
      freezeV1(s);
      const freezeSeq = s.chain.head().seq;
      const t0 = Date.now();
      // the runs are recorded now, before any anchor exists; their measured_at is written ahead
      runsV1(s, (i) => new Date(t0 + 2500 + i).toISOString());
      await anchor(freezeSeq); // a prefix anchor over the freeze only, pushed after the runs were recorded
      await new Promise((r) => setTimeout(r, 4200));
      await anchor();
    });
    expect(b.pack.claims.find((c) => c.claim === 'harness_frozen_before_runs')).toMatchObject({ declared: false, why: expect.stringMatching(/do not carry the freeze nonce/) });
    declareOrdering(b.pkg, b.dataDir);
    const r = verifyAudit(b.pkg, b.opts);
    expect(claimStatus(r).harness_frozen_before_runs).toBe('fail');
    expect(r.ordering.basis).toBeNull();
    expect(r.ok).toBe(false);
  }, 30_000);

  it('a /2 bundle shows the ordering by the freeze nonce only', async () => {
    const b = await buildCustom(async (s, anchor) => {
      s.audit.record(AUDIT, [{ kind: 'harness_frozen', event_key: 'freeze', payload: { harness_id: 'h', fingerprint: H, manifest: blob(s, 'h') } }], 'auditor');
      await anchor();
      await new Promise((r) => setTimeout(r, 1100));
      s.audit.record(AUDIT, [{ kind: 'run_completed', event_key: 'run:1', payload: { run_id: 'r1', run_seq: 1, fingerprint: H, status: 'pass', measured_at: new Date().toISOString() } }], 'proxy');
      await new Promise((r) => setTimeout(r, 1100));
      await anchor();
    });
    expect(b.pack.claims.find((c) => c.claim === 'harness_frozen_before_runs')).toMatchObject({ declared: false, why: expect.stringMatching(/do not carry the freeze nonce/) });
  });
});

describe('review probes P6: pack filesystem', () => {
  let f: Fixture;
  beforeAll(async () => {
    f = await build('milestones');
  });
  it('symlinked bundle/ or receipt, a traversal line in SHA256SUMS, a listed file deleted: FAIL', () => {
    const a = copyPkg(f);
    const outside = tempDir('kl-va-outside-');
    renameSync(join(a, 'bundle'), join(outside, 'bundle'));
    symlinkSync(join(outside, 'bundle'), join(a, 'bundle'));
    const ra = verifyAudit(a, trustOpts(f));
    expect(ra.checks.find((c) => c.check === 'bundle/')).toMatchObject({ status: 'fail', evidence: 'bundle/ is a symbolic link' });
    setClaims(a, (c) => {
      c.claims = c.claims.filter((x) => x !== 'integrity');
    });
    expect(claimStatus(verifyAudit(a, trustOpts(f))).integrity).toBe('fail');
    const b = copyPkg(f);
    const rp = join(b, 'anchors', '01-harness-frozen.receipt.json');
    renameSync(rp, join(outside, 'r.json'));
    symlinkSync(join(outside, 'r.json'), rp);
    expect(verifyAudit(b, trustOpts(f)).ok).toBe(false);
    const c = copyPkg(f);
    rmSync(join(c, 'SHA256SUMS'));
    rmSync(join(c, 'SHA256SUMS.sig'));
    const sums = sha256sums(c, listPackFiles(c).files) + `${'0'.repeat(64)}  ../outside.txt\n`;
    writeFileSync(join(c, 'SHA256SUMS'), sums);
    const st = new KronicleLite({ dataDir: f.dataDir });
    writeFileSync(join(c, 'SHA256SUMS.sig'), Buffer.from(st.identity.signer.sign(Buffer.from(sums)), 'base64'));
    st.close();
    expect(verifyAudit(c, trustOpts(f)).checks.find((x) => x.check === 'SHA256SUMS')!.evidence).toMatch(/is not "<sha256> {2}<relative path>" for a pack file/);
    const e = copyPkg(f);
    rmSync(join(e, 'VERIFY.md'));
    expect(verifyAudit(e, trustOpts(f)).checks.find((x) => x.check === 'SHA256SUMS')!.evidence).toBe('VERIFY.md is listed but absent');
  });
});

describe('verify-audit: run sequence, ordering details and the v1 convention', () => {
  it('N1: v1 kinds (format /1): measured_at inside the timestamped window is not a basis; the packager does not declare the ordering', async () => {
    const f = await build('v1');
    const r = verifyAudit(f.pkg, trustOpts(f));
    expect(failedChecks(r)).toEqual([]);
    expect(r.bundle_format).toBe(BUNDLE_FORMAT_V1);
    expect(f.pack.claims.find((c) => c.claim === 'harness_frozen_before_runs')).toMatchObject({ declared: false, why: expect.stringMatching(/do not carry the freeze nonce/) });
    expect(r.ordering.status).toBe('not_declared');
    expect(claimStatus(r)).toMatchObject({ harness_frozen_before_runs: 'not_declared', run_sequence: 'not_declared' });
    // declared anyway: FAIL
    const d = copyPkg(f);
    setClaims(d, (c) => {
      c.claims = [...c.claims, 'harness_frozen_before_runs'];
    });
    resign(d, f.dataDir);
    const r2 = verifyAudit(d, trustOpts(f));
    expect(r2.ordering).toMatchObject({ status: 'fail', basis: null });
    expect(r2.ok).toBe(false);
  });

  it('runs recorded before the freeze anchor: not declared; required, it fails', async () => {
    const f = await build('v1-early');
    expect(f.pack.claims.find((c) => c.claim === 'harness_frozen_before_runs')).toMatchObject({ declared: false, why: expect.stringMatching(/do not carry the freeze nonce/) });
    expect(cli(['verify-audit', f.pkg, ...trustArgs(f)]).code).toBe(0);
    const req = cli(['verify-audit', f.pkg, ...trustArgs(f), '--require', 'harness_frozen_before_runs']);
    expect(req.code).toBe(1);
    expect(req.out).toMatch(/^ {2}FAIL {10}harness_frozen_before_runs +harness frozen before runs: .*do not carry the freeze nonce/m);
  });

  it('a run under another harness digest fails the ordering', async () => {
    const f = await build('milestones', { runHarness: (i) => (i === 2 ? 'cd'.repeat(32) : H) });
    expect(f.pack.claims.find((c) => c.claim === 'harness_frozen_before_runs')).toMatchObject({ declared: false, why: expect.stringMatching(/run seq 3 ran under harness cdcdcdcdcdcdcdcd…, not the frozen abababababababab…/) });
  });

  it('run sequence: a gap, a count that differs from planned_runs, interruptions that disagree with claims.json', async () => {
    const gap = await build('milestones', { runSeqs: [1, 2, 4] });
    expect(verifyAudit(gap.pkg, trustOpts(gap)).checks.find((c) => c.check === 'run sequence')).toMatchObject({ status: 'fail', evidence: 'run_seq is not contiguous: 3 missing of 1..4' });
    const short = await build('milestones', { plannedRuns: 5 });
    expect(verifyAudit(short.pkg, trustOpts(short)).checks.find((c) => c.check === 'run sequence')!.evidence).toBe('3 run(s) recorded; declared 5 (planned_runs)');
    const good = await build('milestones');
    const d = copyPkg(good);
    setClaims(d, (c) => {
      (c.runs as { interruptions: unknown[] }).interruptions = [];
    });
    resign(d, good.dataDir);
    expect(verifyAudit(d, trustOpts(good)).run_sequence).toMatchObject({ status: 'fail', problem: 'claims.json lists interruptions for run(s) none; the bundle records them for 3' });
  });

  it('an expired TSA certificate fails at the current time', async () => {
    const old = [1, 2].map((n) => makeTsa({ name: `Old${n}`, signerNotBefore: new Date('2020-01-01T00:00:00Z'), signerNotAfter: new Date('2021-01-01T00:00:00Z') }));
    const f = await build('no-freeze', { tsas: old, genTime: (i) => new Date(Date.UTC(2020, 5, 1, 0, 0, i)) });
    const now = cli(['verify-audit', f.pkg, ...trustArgs(f)]);
    expect(now.code).toBe(1);
    expect(now.out).toMatch(/FAIL {2}RFC 3161 alpha +certificate CN=Old1 TSA Signer is not valid at/);
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
    // with only the self-signed R46 pinned, the embedded cross-signed R46 is an unpinned, unused certificate: refused
    const t = tokens.find((x) => x.includes('sectigo'))!;
    const r46 = SHIPPED_TSA_ROOTS.find((r) => r.subject.includes('R46 (self-signed)'))!.pem;
    expect(verifyTimestamp(readFileSync(join(dir, t)), { message: readFileSync(join(dir, `${t.split('.')[0]}.receipt.json`)), roots: [r46], now: at }).problem).toMatch(/embedded certificate .*Sectigo Public Time Stamping Root R46 is neither on the path nor a pinned/);
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

describe('review probes P4d–P4g: certificate paths and DER', () => {
  const at = { now: new Date('2030-01-01T00:00:00Z') };
  const check = (tsa: TestTsa) => verifyTimestamp(tsa.stamp('m'), { message: 'm', roots: [tsa.root.pem], ...at });

  it('P4d: pathLenConstraint is enforced', () => {
    const v = check(makeTsa({ intermediates: [{ pathLen: 0 }, {}] }));
    expect(v.problem).toBe('certificate CN=Test TSA CA allows 0 intermediate(s) below it (pathLenConstraint); the path has 1');
    expect(check(makeTsa({ intermediates: [{ pathLen: 1 }, {}] })).ok).toBe(true);
  });

  it('P4e: a signer with cA=TRUE, or without a digitalSignature / nonRepudiation keyUsage, is refused', () => {
    expect(check(makeTsa({ signer: { ca: true, keyUsage: 0x86 } })).problem).toBe('signing certificate CN=Test TSA Signer is a CA certificate (cA=TRUE)');
    expect(check(makeTsa({ signer: { keyUsage: 0x04 } })).problem).toMatch(/keyUsage must allow digitalSignature or nonRepudiation/);
    expect(check(makeTsa({ signer: { keyUsage: undefined } as never })).problem).toMatch(/keyUsage must allow/);
  });

  it('an embedded certificate that is neither on the path nor pinned is refused', () => {
    const stray = makeTsa({ name: 'Stray' }).root;
    expect(check(makeTsa({ extraCerts: [stray] })).problem).toBe('embedded certificate CN=Stray TSA Root is neither on the path nor a pinned or known TSA chain certificate');
  });

  it('readTime refuses out-of-range calendar fields', () => {
    for (const t of ['20260231000000Z', '20261301000000Z', '20261109250000Z', '20261109236000Z', '20261109235960Z']) {
      expect(() => readTime({ tag: TAG.GENERALIZED_TIME, constructed: false, bytes: Buffer.alloc(0), value: Buffer.from(t, 'latin1') })).toThrow(/not a valid calendar time/);
    }
    expect(readTime({ tag: TAG.GENERALIZED_TIME, constructed: false, bytes: Buffer.alloc(0), value: Buffer.from('20280229235959Z', 'latin1') }).toISOString()).toBe('2028-02-29T23:59:59.000Z');
  });

  const dir = join(__dirname, 'fixtures', 'verify-audit', 'real-tsa');
  const roots = SHIPPED_TSA_ROOTS.map((r) => r.pem);
  it('P4g: no single-bit flip of a real Sectigo or DigiCert token verifies', () => {
    for (const t of ['01-harness-frozen.sectigo.tsr', '01-harness-frozen.digicert.tsr']) {
      const base = readFileSync(join(dir, t));
      const message = readFileSync(join(dir, `${t.split('.')[0]}.receipt.json`));
      const at2 = new Date(Date.parse(inspectTimestamp(base).gen_time));
      expect(verifyTimestamp(base, { message, roots, at: at2 }).ok).toBe(true);
      const accepted: number[] = [];
      for (let p = 0; p < base.length; p++) {
        const b = Buffer.from(base);
        b[p] = b[p]! ^ 0x01;
        if (verifyTimestamp(b, { message, roots, at: at2 }).ok) accepted.push(p);
      }
      expect(accepted, t).toEqual([]);
    }
  });

  it('P4g: random mutations, truncations, bogus lengths and trailing bytes never verify and never throw', () => {
    let seed = 12345;
    const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
    for (const t of readdirSync(dir).filter((x) => x.endsWith('.tsr'))) {
      const base = readFileSync(join(dir, t));
      const message = readFileSync(join(dir, `${t.split('.')[0]}.receipt.json`));
      const at2 = new Date(Date.parse(inspectTimestamp(base).gen_time));
      for (let k = 0; k < 400; k++) {
        const b = Buffer.from(base);
        let input: Buffer = b;
        const mode = k % 4;
        if (mode === 0) for (let m = 0; m < 1 + Math.floor(rnd() * 3); m++) b[Math.floor(rnd() * b.length)] = Math.floor(rnd() * 256);
        if (mode === 1) input = b.subarray(0, Math.floor(rnd() * b.length));
        if (mode === 2) {
          const p = Math.floor(rnd() * (b.length - 4));
          b[p] = 0x84;
          b[p + 1] = 0xff;
          b[p + 2] = 0xff;
          b[p + 3] = 0xff;
        }
        if (mode === 3) input = Buffer.concat([b, Buffer.alloc(1 + Math.floor(rnd() * 64), 0x30)]);
        if (input.equals(base)) continue;
        const v = verifyTimestamp(input, { message, roots, at: at2 });
        expect(v.ok, `${t} mutation ${k}`).toBe(false);
      }
    }
    expect(verifyTimestamp(Buffer.concat([Buffer.from([0x30, 0x84, 0x7f, 0xff, 0xff, 0xff]), Buffer.alloc(300 * 1024)]), { message: 'x', roots: [] }).problem).toMatch(/limit is/);
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
    // verify-audit's compiled genesis pin is that key with its valid_from (isokron-anchor src/core/genesis.ts)
    expect(formatGenesisPin(PRODUCTION_GENESIS)).toBe(`${prod[0]!.spki_sha256}@${prod[0]!.valid_from}`);
    expect(chainIdFromPublicKeyPem(prod[0]!.public_key_pem)).toBe(PRODUCTION_GENESIS.sha256);
    expect(serviceKeyIdFromPem(prod[0]!.public_key_pem)).toBe('anchor-ed25519-3dca1ecf66c2993e');
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

describe('review round 2 (N1–N9): every R-case fails closed', () => {
  let f: Fixture;
  beforeAll(async () => {
    f = await build('milestones');
  });
  const GF = '2026-01-01T00:00:00.000Z';
  const now = Date.now();
  const R = newKey();
  const S = newKey();
  const recent = (i: number) => iso(now - 60e3 + i * 1e3);
  const keyPack = (keys: unknown[], signer: SK, receivedAt: (i: number) => string, claims: string[] | null, genTime?: (i: number) => Date) => {
    const d = copyPkg(f);
    resignReceipts(d, f, signer, receivedAt, genTime);
    setPackKeys(d, keys);
    setClaims(d, (c) => {
      if (claims) {
        c.claims = claims;
        if (!claims.includes('run_sequence')) delete c.runs;
      } else noOrdering(c);
    });
    resign(d, f.dataDir);
    return d;
  };
  const pinR = `${R.fp}@${GF}`;

  describe('R1 (N2): a leaked retired key signs receipts dated inside its old window', () => {
    const retired = () => rotated(R, GF, S, iso(now - 3600e3)); // R retired an hour ago, S active
    const inWindow = (i: number) => iso(now - 3 * 3600e3 + i * 1e3);
    it('R1a: independent_timestamps not declared: receipts pulls it in, and the TSA time after valid_to + 5 min fails', () => {
      const r = verifyAudit(keyPack(retired(), R, inWindow, ['integrity', 'chain', 'receipts']), { ...trustOpts(f), genesis: pinR });
      expect(claimStatus(r)).toMatchObject({ receipts: 'fail', independent_timestamps: 'pass' });
      expect(r.claims.find((c) => c.claim === 'independent_timestamps')!.evidence).toMatch(/^checked for receipts \(anchor-ed25519-[0-9a-f]{16} is retired\)/);
      expect(r.checks.find((c) => c.check === 'stamped within key validity' && c.status === 'fail')!.evidence).toMatch(/is after anchor-ed25519-[0-9a-f]{16} ended at/);
      expect(r.ok).toBe(false);
    });
    it('R1b: independent_timestamps declared: FAIL', () => {
      const r = verifyAudit(keyPack(retired(), R, inWindow, null), { ...trustOpts(f), genesis: pinR });
      expect(claimStatus(r).receipts).toBe('fail');
      expect(r.ok).toBe(false);
    });
    it('R1c: --no-tsa: FAIL (received_at is the signer\'s own claim)', () => {
      const r = verifyAudit(keyPack(retired(), R, inWindow, null), { ...trustOpts(f), genesis: pinR, no_tsa: true });
      expect(r.checks.find((c) => c.check === 'stamped within key validity' && c.status === 'fail')!.evidence).toMatch(/is retired; its receipt counts only with a verified RFC 3161 time no later than .* \+ 5 min \(valid_to\), and RFC 3161 tokens are not checked here \(--no-tsa\)/);
      expect(claimStatus(r).receipts).toBe('fail');
      expect(r.ok).toBe(false);
    });
    it('a retired key whose receipts were stamped inside its window still passes (TSA checked as a dependency)', () => {
      const d = keyPack(retired(), R, inWindow, ['integrity', 'chain', 'receipts'], (i) => new Date(now - 3 * 3600e3 + 60e3 + i * 1e3));
      const r = verifyAudit(d, { ...trustOpts(f), genesis: pinR });
      expect(failedChecks(r)).toEqual([]);
      expect(claimStatus(r)).toMatchObject({ receipts: 'pass', independent_timestamps: 'pass' });
      expect(r.ok).toBe(true);
    });
    it('the active head needs no TSA for receipts: independent_timestamps stays not declared', () => {
      const r = verifyAudit(keyPack([{ key_id: R.id, public_key_pem: R.pem, valid_from: GF, status: 'active' }], R, recent, ['integrity', 'chain', 'receipts']), { ...trustOpts(f), genesis: pinR });
      expect(claimStatus(r)).toMatchObject({ receipts: 'pass', independent_timestamps: 'not_declared' });
    });
  });

  describe('R3 / R7b (N4, N5, N7): the rollback cache', () => {
    const revokedList = () => revokeKey([{ key_id: R.id, public_key_pem: R.pem, valid_from: GF, status: 'active' }], R, R, iso(now + 3600e3), iso(now + 7200e3));
    const activeList = () => [{ key_id: R.id, public_key_pem: R.pem, valid_from: GF, status: 'active' }];
    const rollbackCheck = (r: ReturnType<typeof verifyAudit>) => r.checks.find((c) => c.check === 'key list rollback');
    it('R3: the pin spelled five ways is one cache slot: the rolled-back list fails under each', () => {
      const revoked = keyPack(revokedList(), R, recent, null);
      const rolled = keyPack(activeList(), R, recent, null);
      for (const v of [pinR, `${R.fp.toUpperCase()}@${GF}`, `${R.fp}@2026-01-01T00:00:00Z`, `${R.fp}@2026-01-01T00:00:00.0Z`, `${R.fp.match(/../g)!.join(':')}@${GF}`]) {
        const seen = tempDir('kl-va-seen-');
        expect(verifyAudit(revoked, { ...trustOpts(f), genesis: pinR, seen_dir: seen }).ok).toBe(true);
        const b = verifyAudit(rolled, { ...trustOpts(f), genesis: v, seen_dir: seen });
        expect(rollbackCheck(b)).toMatchObject({ status: 'fail', evidence: expect.stringMatching(/was revoked in the list seen earlier and is active now/) });
        expect(b.trust.genesis_valid_from).toBe(GF);
        expect(b.ok).toBe(false);
      }
    });
    it('R3 / R7b: a damaged cache fails with its reason and is never overwritten', () => {
      const revoked = keyPack(revokedList(), R, recent, null);
      const rolled = keyPack(activeList(), R, recent, null);
      const shapes: [string, string, RegExp][] = [
        ['keys is a string', JSON.stringify({ v: 1, lists: { [pinR]: { seen_at: GF, keys: 'garbage' } } }), /keys is not a non-empty array/],
        ['a key entry lacks public_key_pem', JSON.stringify({ v: 1, lists: { [pinR]: { seen_at: GF, keys: [{ key_id: R.id }] } } }), /a key entry lacks key_id or public_key_pem/],
        ['the slot is a number (R7b)', JSON.stringify({ v: 1, lists: { [pinR]: 5 } }), /is not an object/],
        ['keys = []', JSON.stringify({ v: 1, lists: { [pinR]: { seen_at: GF, keys: [] } } }), /keys is not a non-empty array/],
        ['seen_at is not a time', JSON.stringify({ v: 1, lists: { [pinR]: { seen_at: 'x', keys: activeList() } } }), /seen_at is not a timestamp/],
        ['a non-canonical slot', JSON.stringify({ v: 1, lists: { [`${R.fp}@2026-01-01T00:00:00Z`]: { seen_at: GF, keys: activeList() } } }), /is not a canonical genesis pin/],
        ['a field of the wrong type', JSON.stringify({ v: 1, lists: { [pinR]: { seen_at: GF, keys: [{ ...activeList()[0], valid_to: 5 }] } } }), /valid_to is not a string/],
        ['lists is an array', JSON.stringify({ v: 1, lists: [] }), /lists is not an object/],
        ['an empty object', '{}', /expected \{v: 1, lists/],
        ['not JSON', 'nope', /is not JSON/],
      ];
      for (const [label, body, why] of shapes) {
        const seen = tempDir('kl-va-seen-');
        verifyAudit(revoked, { ...trustOpts(f), genesis: pinR, seen_dir: seen });
        writeFileSync(join(seen, SEEN_KEYS_FILE), body);
        const b = verifyAudit(rolled, { ...trustOpts(f), genesis: pinR, seen_dir: seen });
        expect(rollbackCheck(b), label).toMatchObject({ status: 'fail', evidence: expect.stringMatching(why) });
        expect(b.checks.find((c) => c.check === 'verifier'), label).toBeUndefined();
        expect(readFileSync(join(seen, SEEN_KEYS_FILE), 'utf8'), label).toBe(body);
        expect(claimStatus(b).receipts, label).toBe('fail');
        expect(b.ok, label).toBe(false);
      }
    });
    it('R3 (N7): a fresh data dir records the list and says so, not as PASS; a library call must pass seen_dir or rollback: off', () => {
      const rolled = keyPack(activeList(), R, recent, null);
      const seen = tempDir('kl-va-seen-');
      const fresh = verifyAudit(rolled, { ...trustOpts(f), genesis: pinR, seen_dir: seen });
      expect(rollbackCheck(fresh)).toBeUndefined();
      expect(fresh.trust.rollback).toMatchObject({ status: 'first_seen', recorded: true });
      expect(renderVerifyAudit(fresh)).toMatch(/^key list {7}first seen for this genesis; recorded in .*anchor-keys\.seen\.json/m);
      expect(renderVerifyAudit(fresh)).not.toMatch(/PASS .*key list rollback/);
      const { seen_dir: _s, ...noSeen } = trustOpts(f);
      void _s;
      expect(() => verifyAudit(rolled, { ...noSeen, genesis: pinR })).toThrow(VerifyAuditUsageError);
      const off = verifyAudit(rolled, { ...noSeen, genesis: pinR, rollback: 'off' });
      expect(off.trust.rollback.status).toBe('off');
      expect(renderVerifyAudit(off)).toContain('key list       rollback check off (library option rollback: off)');
    });
    it('R3 CLI: the same data dir with the pin from KRONICLE_ANCHOR_GENESIS in another spelling still fails; labelled by its source', () => {
      const revoked = keyPack(revokedList(), R, recent, null);
      const rolled = keyPack(activeList(), R, recent, null);
      const dd = tempDir('kl-va-dd-');
      const base = ['--key-fingerprint', f.fp, '--tsa-roots', f.rootsDir];
      expect(cli(['verify-audit', revoked, ...base, '--genesis', pinR], { KRONICLE_LITE_DATA_DIR: dd }).code).toBe(0);
      const e = cli(['verify-audit', rolled, ...base], { KRONICLE_LITE_DATA_DIR: dd, KRONICLE_ANCHOR_GENESIS: `${R.fp}@2026-01-01T00:00:00Z` });
      expect(e.code).toBe(1);
      expect(e.out).toMatch(/^service keys {3}genesis [0-9a-f]{64}@2026-01-01T00:00:00\.000Z \(KRONICLE_ANCHOR_GENESIS\)/m);
      expect(e.out).toMatch(/FAIL +key list rollback +anchor-keys\.json is an older or weaker list/);
      const other = cli(['verify-audit', rolled, ...base, '--genesis', pinR]);
      expect(other.code).toBe(0);
      expect(other.out).toMatch(/^key list {7}first seen for this genesis; recorded in /m);
      expect(other.out).not.toMatch(/PASS +key list rollback/);
    });
  });

  it('R4 (N8): keyListRegression refuses a moved valid_from and a changed signed_by (service 7e0e96f)', () => {
    const G = newKey();
    const l1 = rotated(G, GF, S, '2026-11-01T00:00:00.000Z') as unknown as ServiceKeyEntry[];
    const l2 = rotated(G, GF, S, '2026-10-01T00:00:00.000Z') as unknown as ServiceKeyEntry[];
    expect(keyListRegression(l1, l2)).toMatch(new RegExp(`${G.id} valid_to was 2026-11-01T00:00:00.000Z in the list seen earlier and is 2026-10-01T00:00:00.000Z now|${S.id} valid_from was 2026-11-01T00:00:00.000Z in the list seen earlier and is 2026-10-01T00:00:00.000Z now`));
    expect(keyListRegression(l1.filter((k) => k.key_id === S.id), l2.filter((k) => k.key_id === S.id))).toMatch(/valid_from was 2026-11-01T00:00:00.000Z in the list seen earlier and is 2026-10-01T00:00:00.000Z now/);
    const l3 = l1.map((k) => (k.key_id === S.id ? { ...k, signed_by: 'anchor-ed25519-0000000000000000' } : k));
    expect(keyListRegression(l1, l3)).toMatch(/signed_by was anchor-ed25519-[0-9a-f]{16} in the list seen earlier and is anchor-ed25519-0000000000000000 now/);
  });

  describe('R5 (N3, N6): trust inputs from inside the pack', () => {
    it('R5a/R5b: --key as the pack file, a ..-prefixed pack file, a symlink to it, or a hard link to it: exit 2', () => {
      const d = copyPkg(f);
      copyFileSync(join(d, 'auditor-key.pem'), join(d, '..auditor-key.pem'));
      const outside = tempDir('kl-va-out-');
      symlinkSync(join(d, 'auditor-key.pem'), join(outside, 'sym.pem'));
      linkSync(join(d, 'auditor-key.pem'), join(outside, 'hard.pem'));
      const rest = ['--genesis', f.genesis, '--tsa-roots', f.rootsDir];
      for (const k of [join(d, 'auditor-key.pem'), join(d, '..auditor-key.pem'), join(outside, 'sym.pem')]) {
        const r = cli(['verify-audit', d, '--key', k, ...rest]);
        expect(r.code, k).toBe(2);
        expect(r.err, k).toMatch(/--key .* is inside the pack/);
      }
      const h = cli(['verify-audit', d, '--key', join(outside, 'hard.pem'), ...rest]);
      expect(h.code).toBe(2);
      expect(h.err).toMatch(/is a hard link to a file inside the pack/);
      // a key file genuinely outside the pack is still accepted
      expect(cli(['verify-audit', f.pkg, '--key', f.keyFile, ...rest]).code).toBe(0);
    });
    it('--anchor-keys or --tsa-roots inside the pack, or a roots dir holding a symlink into it: exit 2', () => {
      const d = copyPkg(f);
      const ak = cli(['verify-audit', d, ...trustArgs(f), '--anchor-keys', join(d, 'anchor-keys.json')]);
      expect(ak.code).toBe(2);
      expect(ak.err).toMatch(/--anchor-keys .* is inside the pack/);
      const tr = cli(['verify-audit', d, '--key-fingerprint', f.fp, '--genesis', f.genesis, '--tsa-roots', join(d, 'tsa-roots')]);
      expect(tr.code).toBe(2);
      expect(tr.err).toMatch(/--tsa-roots .* is inside the pack/);
      const roots = tempDir('kl-va-roots-');
      cpSync(f.rootsDir, roots, { recursive: true });
      symlinkSync(join(d, 'tsa-roots', readdirSync(join(d, 'tsa-roots'))[0]!), join(roots, 'z-from-pack.pem'));
      const sl = cli(['verify-audit', d, '--key-fingerprint', f.fp, '--genesis', f.genesis, '--tsa-roots', roots]);
      expect(sl.code).toBe(2);
      expect(sl.err).toMatch(/--tsa-roots .*z-from-pack\.pem is inside the pack/);
    });
    describe('T6: inside the pack is decided by filesystem identity (dev, ino), not by the path as typed', () => {
      // A pack under a directory whose name has a letter that changes with case and with Unicode normalization.
      const NFC = 'pack-\u00e9'; // é, one code point
      const NFD = 'pack-e\u0301'; // e + combining acute
      const mk = () => {
        const root = tempDir('kl-va-t6-');
        const d = join(root, NFC);
        // copied under an ASCII name, then renamed: Node 22's native cpSync mangles non-ASCII destinations on Windows
        cpSync(f.pkg, join(root, 'ascii'), { recursive: true });
        renameSync(join(root, 'ascii'), d);
        return { root, d };
      };
      const same = (a: string, b: string) => {
        if (!existsSync(a) || !existsSync(b)) return false;
        const x = statSync(a, { bigint: true });
        const y = statSync(b, { bigint: true });
        return x.dev === y.dev && x.ino === y.ino;
      };
      // Probed at collection time on an empty directory of the same name (the fixture is built later).
      const probe = { root: tempDir('kl-va-t6-probe-'), d: '' };
      probe.d = join(probe.root, NFC);
      mkdirSync(probe.d);
      const caseInsensitive = same(probe.d, join(probe.root, NFC.toUpperCase()));
      const normInsensitive = same(probe.d, join(probe.root, NFD));
      const refused = (pack: string, input: string) => () => refuseInsidePack(pack, input, '--key');

      it.skipIf(!caseInsensitive)('a case variant of the pack path, and the pack given in the other case: refused (skipped on a case-sensitive filesystem)', () => {
        const { root, d } = mk();
        const upper = join(root, NFC.toUpperCase());
        expect(refused(d, join(upper, 'auditor-key.pem'))).toThrow(/--key .* is inside the pack/);
        expect(refused(upper, join(d, 'auditor-key.pem'))).toThrow(/--key .* is inside the pack/);
        expect(refused(d, join(upper, 'tsa-roots'))).toThrow(/is inside the pack/);
        // the CLI too: exit 2, never "pinned by --key"
        const r = cli(['verify-audit', d, '--key', join(upper, 'auditor-key.pem'), '--genesis', f.genesis, '--tsa-roots', f.rootsDir]);
        expect(r.code).toBe(2);
        expect(r.out).not.toMatch(/pinned by --key/);
        for (const extra of [['--anchor-keys', join(upper, 'anchor-keys.json')], ['--tsa-roots', join(upper, 'tsa-roots')]]) {
          expect(cli(['verify-audit', d, '--key-fingerprint', f.fp, '--genesis', f.genesis, ...extra]).code, extra[0]).toBe(2);
        }
      });

      it.skipIf(!normInsensitive)('NFC vs NFD spellings of the pack path: refused both ways (skipped on a normalization-sensitive filesystem)', () => {
        const { root, d } = mk();
        const nfd = join(root, NFD);
        expect(refused(d, join(nfd, 'auditor-key.pem'))).toThrow(/is inside the pack/);
        expect(refused(nfd, join(d, 'auditor-key.pem'))).toThrow(/is inside the pack/);
        expect(cli(['verify-audit', d, '--key', join(nfd, 'auditor-key.pem'), '--genesis', f.genesis, '--tsa-roots', f.rootsDir]).code).toBe(2);
      });

      it('on a filesystem that tells the spellings apart they are other paths: they do not resolve, and nothing inside the pack is accepted', () => {
        const { root, d } = mk();
        for (const v of [join(root, NFC.toUpperCase(), 'auditor-key.pem'), join(root, NFD, 'auditor-key.pem')]) {
          if (existsSync(v)) expect(refused(d, v)).toThrow(/is inside the pack/);
          else expect(refused(d, v)).toThrow(/--key .*(ENOENT|no such file)/i);
        }
      });

      it('T8: a trust input is read from the descriptor that was checked; swapping the path after the check changes nothing', () => {
        const { d } = mk();
        const out = tempDir('kl-va-t8-');
        writeFileSync(join(out, 'outside.pem'), 'OUTSIDE\n');
        const link = join(out, 'key.pem');
        symlinkSync(join(out, 'outside.pem'), link);
        const h = openTrustInput(d, link, '--key', 64 * 1024);
        try {
          // the race the reviewer won: flip the symlink into the pack between the check and the read
          rmSync(link);
          symlinkSync(join(d, 'auditor-key.pem'), link);
          expect(h.read().toString('utf8')).toBe('OUTSIDE\n');
        } finally {
          h.close();
        }
        // opened afresh, the flipped link is refused
        expect(() => readTrustInput(d, link, '--key', 64 * 1024)).toThrow(/is inside the pack/);
        // the same for a file in a --tsa-roots directory, and a file that is not regular or too large
        expect(() => readTrustInput(d, out, '--tsa-roots', 64 * 1024)).toThrow(/is not a regular file/);
        writeFileSync(join(out, 'big.pem'), Buffer.alloc(2048));
        expect(() => readTrustInput(d, join(out, 'big.pem'), '--tsa-roots', 1024)).toThrow(/is larger than 1024 bytes/);
        expect(readTrustInput(d, join(out, 'outside.pem'), '--key', 1024).toString('utf8')).toBe('OUTSIDE\n');
      });

      it('T8: the CLI reads --key, --anchor-keys and each --tsa-roots file through that path (and still verifies a good pack)', () => {
        expect(cli(['verify-audit', f.pkg, '--key', f.keyFile, '--genesis', f.genesis, '--tsa-roots', f.rootsDir, '--anchor-keys', f.keysFile]).code).toBe(0);
        const roots = tempDir('kl-va-t8-roots-');
        writeFileSync(join(roots, 'empty.pem'), 'no certificates here\n');
        const r = cli(['verify-audit', f.pkg, '--key-fingerprint', f.fp, '--genesis', f.genesis, '--tsa-roots', roots]);
        expect(r.code).toBe(2);
        expect(r.err).toMatch(/holds no PEM certificates/);
      });

      it('the symlink and hard-link cases, decided by identity: a symlinked directory into the pack, a symlinked file, a hard link', () => {
        const { d } = mk();
        const out = tempDir('kl-va-t6-out-');
        symlinkSync(d, join(out, 'pack-link'), 'junction'); // a junction on Windows (no privilege needed); a symlink elsewhere
        expect(refused(d, join(out, 'pack-link', 'auditor-key.pem'))).toThrow(/is inside the pack/);
        expect(refused(d, join(out, 'pack-link'))).toThrow(/is inside the pack/);
        symlinkSync(join(d, 'auditor-key.pem'), join(out, 'key.pem'));
        expect(refused(d, join(out, 'key.pem'))).toThrow(/is inside the pack/);
        linkSync(join(d, 'auditor-key.pem'), join(out, 'hard.pem'));
        expect(refused(d, join(out, 'hard.pem'))).toThrow(/is a hard link to a file inside the pack/);
        // a file genuinely outside is accepted
        expect(refused(d, f.keyFile)).not.toThrow();
      });
    });

    it('R5c: COMPLETION.txt and VERIFY.md name where the fingerprint comes from and never carry it', () => {
      const completion = readFileSync(join(f.pkg, 'COMPLETION.txt'), 'utf8');
      expect(completion).not.toContain(f.fp);
      expect(completion).toMatch(/--key-fingerprint <auditor key fingerprint from your statement of work>/);
      expect(readFileSync(join(f.pkg, 'VERIFY.md'), 'utf8')).not.toContain(f.fp);
      // the operator's own terminal gets it
      expect(f.pack.auditor_spki_sha256).toBe(f.fp);
    });
  });

  describe('R6 (N9): --require', () => {
    const declared = () => {
      const d = copyPkg(f);
      setClaims(d, (c) => {
        c.claims = ['integrity', 'chain', 'independent_timestamps'];
        delete c.runs;
      });
      resign(d, f.dataDir);
      return d;
    };
    it('R6a: --require receipts, checked as a dependency of a declared claim and passing: PASS', () => {
      const r = verifyAudit(declared(), { ...trustOpts(f), require: ['receipts'] });
      expect(claimStatus(r).receipts).toBe('pass');
      expect(r.claims.find((c) => c.claim === 'receipts')).toMatchObject({ declared: false, required: true });
      expect(r.ok).toBe(true);
    });
    it('R6b: --require run_sequence (not declared): checked; it passes when the runs are 1..N', () => {
      const r = verifyAudit(declared(), { ...trustOpts(f), require: ['run_sequence'] });
      expect(claimStatus(r).run_sequence).toBe('pass');
      expect(r.ok).toBe(true);
    });
    it('R6b: --require of a claim that is checked and fails: FAIL', () => {
      const r = verifyAudit(declared(), { ...trustOpts(f), require: ['harness_frozen_before_runs'] });
      expect(claimStatus(r).harness_frozen_before_runs).toBe(r.ordering.status === 'pass' ? 'pass' : 'fail');
      const bad = copyPkg(f);
      for (const b of ANCH) rmSync(join(bad, 'anchors', `${b}.beta.tsr`));
      setClaims(bad, (c) => {
        c.claims = ['integrity', 'chain'];
        delete c.runs;
      });
      resign(bad, f.dataDir);
      const r2 = verifyAudit(bad, { ...trustOpts(f), require: ['independent_timestamps'] });
      expect(claimStatus(r2).independent_timestamps).toBe('fail');
      expect(r2.ok).toBe(false);
    });
    it('R6c: --no-tsa with --tsa-roots is a usage error; R6d: declared claims only: PASS', () => {
      expect(cli(['verify-audit', f.pkg, ...trustArgs(f), '--no-tsa']).code).toBe(2);
      expect(verifyAudit(declared(), trustOpts(f)).ok).toBe(true);
    });
  });

  describe('R7a: a declared claim that is not checked blocks exit 0; --skip-claim opts out explicitly', () => {
    const base = () => ['verify-audit', f.pkg, '--key-fingerprint', f.fp, '--genesis', f.genesis];
    it('--no-tsa on a pack that declares TSA claims: exit 1, NOT VERIFIED, each printed as not checked (--no-tsa)', () => {
      const r = cli([...base(), '--no-tsa']);
      expect(r.code).toBe(1);
      expect(r.out).toMatch(/^ {2}not checked {3}independent_timestamps +not checked \(--no-tsa\)/m);
      expect(r.out).toMatch(/^ {2}not checked {3}harness_frozen_before_runs +not checked \(--no-tsa\)/m);
      expect(r.out).toMatch(/^RESULT: NOT VERIFIED {2}independent_timestamps, harness_frozen_before_runs not checked; passed: integrity, chain, receipts, run_sequence$/m);
      const j = verifyAudit(f.pkg, { ...trustOpts(f), no_tsa: true });
      expect(j.ok).toBe(false);
      expect(VerifyAuditJsonSchema.safeParse(j).success).toBe(true);
    });
    it('--no-tsa --skip-claim for both: exit 0, reported as skipped by user', () => {
      const r = cli([...base(), '--no-tsa', '--skip-claim', 'independent_timestamps,harness_frozen_before_runs']);
      expect(r.code).toBe(0);
      expect(r.out).toMatch(/^ {2}skipped {7}independent_timestamps +skipped by user \(--skip-claim independent_timestamps\); the pack declares it/m);
      expect(r.out).toMatch(/^ {2}skipped {7}harness_frozen_before_runs +skipped by user/m);
      expect(r.out).toMatch(/^RESULT: VERIFIED {2}integrity, chain, receipts, run_sequence {2}\(independent_timestamps, harness_frozen_before_runs skipped by user\)$/m);
      const j = verifyAudit(f.pkg, { ...trustOpts(f), no_tsa: true, skip_claims: ['independent_timestamps', 'harness_frozen_before_runs'] });
      expect(claimStatus(j)).toMatchObject({ independent_timestamps: 'skipped', harness_frozen_before_runs: 'skipped' });
      expect(j.ok).toBe(true);
      expect(VerifyAuditJsonSchema.safeParse(j).success).toBe(true);
    });
    it('skipping one but not the other still blocks; a claim that depends on a skipped one is not checked', () => {
      expect(cli([...base(), '--no-tsa', '--skip-claim', 'harness_frozen_before_runs']).code).toBe(1);
      // with tokens checked: skipping independent_timestamps leaves harness_frozen_before_runs (which needs it) unchecked
      const r = verifyAudit(f.pkg, { ...trustOpts(f), skip_claims: ['independent_timestamps'] });
      expect(claimStatus(r)).toMatchObject({ independent_timestamps: 'skipped', harness_frozen_before_runs: 'not_checked' });
      expect(r.claims.find((c) => c.claim === 'harness_frozen_before_runs')!.evidence).toBe('not checked: it depends on independent_timestamps, which was skipped by user (--skip-claim)');
      expect(r.ok).toBe(false);
      const r2 = verifyAudit(f.pkg, { ...trustOpts(f), skip_claims: ['receipts'] });
      expect(claimStatus(r2)).toMatchObject({ receipts: 'skipped', independent_timestamps: 'not_checked', harness_frozen_before_runs: 'not_checked' });
      expect(r2.ok).toBe(false);
      const r3 = verifyAudit(f.pkg, { ...trustOpts(f), skip_claims: ['independent_timestamps', 'harness_frozen_before_runs'] });
      expect(r3.ok).toBe(true);
    });
    it('--skip-claim of integrity or chain, of a claim also --require\'d, or of an unknown claim: exit 2', () => {
      for (const extra of [['--skip-claim', 'integrity'], ['--skip-claim', 'chain'], ['--skip-claim', 'receipts', '--require', 'receipts'], ['--skip-claim', 'thoroughness']]) {
        expect(cli([...base(), '--tsa-roots', f.rootsDir, ...extra]).code, extra.join(' ')).toBe(2);
      }
    });
    it('a skipped claim never vouches for a retired key: receipts still needs its TSA time', () => {
      const d = keyPack(rotated(R, GF, S, iso(now - 3600e3)), R, (i) => iso(now - 3 * 3600e3 + i * 1e3), null);
      // stamped inside R's window, so only the skip can make receipts fail here
      const ok = keyPack(rotated(R, GF, S, iso(now - 3600e3)), R, (i) => iso(now - 3 * 3600e3 + i * 1e3), ['integrity', 'chain', 'receipts'], (i) => new Date(now - 3 * 3600e3 + 60e3 + i * 1e3));
      const s = verifyAudit(ok, { ...trustOpts(f), genesis: pinR, skip_claims: ['independent_timestamps'] });
      expect(claimStatus(s)).toMatchObject({ receipts: 'fail', independent_timestamps: 'skipped' });
      expect(s.checks.find((c) => c.check === 'stamped within key validity' && c.status === 'fail')!.evidence).toMatch(/RFC 3161 tokens are not checked here \(independent_timestamps skipped by user\)/);
      const r = verifyAudit(d, { ...trustOpts(f), genesis: pinR, skip_claims: ['independent_timestamps'] });
      expect(claimStatus(r).receipts).toBe('fail');
      expect(r.ok).toBe(false);
    });
  });

  it('N5: when the verifier stops part way, every claim it was checking is FAIL, none PASS', () => {
    const boom = {
      get keys(): unknown {
        throw new Error('boom');
      },
    };
    const r = verifyAudit(f.pkg, { ...trustOpts(f), anchor_keys: boom });
    expect(r.checks.find((c) => c.check === 'verifier')).toMatchObject({ status: 'fail', evidence: 'verifier error: boom' });
    for (const c of r.claims) expect(c.status, c.claim).toBe('fail');
    expect(r.claims.find((c) => c.claim === 'integrity')!.evidence).toBe('not finished: the verifier stopped (boom)');
    expect(r.ok).toBe(false);
  });
});
