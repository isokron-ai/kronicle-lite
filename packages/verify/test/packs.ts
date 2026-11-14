/**
 * Evidence Packs of every bundle format, made the way the repository's own tests make them
 * (test/verify-audit.test.ts, test/verify-audit-profile.test.ts, test/verify-audit-late-anchor.test.ts):
 * a kronicle-lite store records the audit, the in-test anchor stub countersigns each checkpoint,
 * two throwaway RFC 3161 TSAs stamp each receipt, and `audit package` builds the pack.
 *
 *   v1       0.9/0.10 style: finding + call_measured events            kronicle-lite-evidence-bundle/1
 *   v2       0.10 milestones: harness_frozen, run_completed, report     kronicle-lite-evidence-bundle/2
 *   v3       0.11 audit profile: plan, nonce, sign-off, close, stamped SHA256SUMS   /3
 *   v3-late  /3 with the freeze anchored late (freeze-pending record)   /3
 *
 * No network: the stub and the TSAs listen on 127.0.0.1.
 */

import { createHash, generateKeyPairSync, sign as edSign, type KeyObject } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { pushCheckpoint } from '../../../src/anchor/anchor.js';
import { anchorReceiptSigningPayload } from '../../../src/anchor/receipt.js';
import { serviceKeyIdFromPem } from '../../../src/anchor/trust.js';
import { buildAuditPackage } from '../../../src/audit/package.js';
import { findingsDigest, freezeNonce, REPRODUCTION_NAMESPACE, reproductionStatement } from '../../../src/audit/profile.js';
import type { AuditEventInput } from '../../../src/audit/schemas.js';
import { allowedSignerLine, sshSign } from '../../../src/audit/sshsig.js';
import { isSumsFile, listPackFiles, sha256sums } from '../../../src/audit/verify-audit.js';
import { canonicalize } from '../../../src/crypto/canonical.js';
import { chainIdFromPublicKeyPem } from '../../../src/crypto/keys.js';
import { KronicleLite } from '../../../src/index.js';
import { STUB_LICENSE, type AnchorBackend } from '../../../test/helpers/anchor-stub.js';
import { tempDir } from '../../../test/helpers/fs.js';
import type { TestTsa } from '../../../test/helpers/tsa.js';

export type Format = 'v1' | 'v2' | 'v3' | 'v3-late';

export interface Pack {
  format: Format;
  dir: string;
  /** The auditor key's SHA-256(SPKI) and the store that holds it (to re-sign a copy). */
  fp: string;
  dataDir: string;
  genesis: string;
  rootsDir: string;
}

export interface Env {
  backend: AnchorBackend;
  tsas: TestTsa[];
  servers: { url: string }[];
}

const H = 'ab'.repeat(32);
const TSA_NAMES = ['alpha', 'beta'] as const;
const sha = (b: string | Buffer) => createHash('sha256').update(b).digest('hex');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function buildPack(format: Format, env: Env): Promise<Pack> {
  const { backend, tsas, servers } = env;
  const AUDIT = `verify-diff-${format}`;
  const dataDir = tempDir('kl-vd-store-');
  const work = tempDir('kl-vd-work-');
  const tsDir = join(work, 'timestamps');
  mkdirSync(tsDir);
  const store = new KronicleLite({ dataDir });
  const blob = (s: string | Buffer, t = 'text/plain') => store.audit.putBlob(typeof s === 'string' ? Buffer.from(s) : s, t);
  const rec = (events: AuditEventInput[], actor = 'auditor') => store.audit.record(AUDIT, events, actor);
  const anchor = async (genTime?: Date): Promise<{ digest: string; nonce: string }> => {
    store.chain.checkpoint(1, store.chain.head().seq);
    const r = await pushCheckpoint(store, { anchorUrl: backend.url, licenseKey: STUB_LICENSE });
    const row = store.chain.listAnchors().find((a) => a.anchor_id === r.anchor_id)!;
    const tokens = tsas.map((t, k) => ({ tsa: TSA_NAMES[k]!, bytes: t.stamp(row.receipt_json, genTime ? { genTime } : {}) }));
    for (const t of tokens) writeFileSync(join(tsDir, `${r.anchor_id}.${t.tsa}.tsr`), t.bytes);
    return { digest: sha(row.receipt_json), nonce: freezeNonce(sha(row.receipt_json), tokens) };
  };
  let allowed: string | undefined;
  let pendingDir: string | undefined;

  if (format === 'v1') {
    rec([{ kind: 'finding', event_key: 'protocol', payload: { finding_id: 'PROTOCOL', status: 'discovered', class: 'protocol_freeze', fingerprint: H, detail: blob('harness files') } }]);
    await anchor();
    await sleep(1100); // TSA times have whole seconds
    rec([1, 2, 3].map((i) => {
      const out = blob(`run ${i} wire log`);
      return { kind: 'call_measured' as const, event_key: `run:${i}`, payload: { fingerprint: H, tool: 'bench', status: 'pass', is_error: false, latency_ms: 10, bytes_out: out.size, measured_at: new Date(Date.now() - 500 + i).toISOString(), response: out } };
    }), 'proxy');
    await sleep(1100);
    await anchor();
    rec([{ kind: 'finding', event_key: 'report', payload: { finding_id: 'REPORT', status: 'discovered', class: 'report', detail: blob('# Report') } }]);
    await anchor();
  } else if (format === 'v2') {
    rec([{ kind: 'harness_frozen', event_key: 'freeze', payload: { harness_id: 'harness-v1', fingerprint: H, manifest: blob('harness files'), hypotheses: blob('H1'), planned_runs: 3 } }]);
    const f = await anchor();
    rec([1, 2, 3].map((n) => ({ kind: 'run_completed' as const, event_key: `run:${n}`, payload: { run_id: `run-${n}`, run_seq: n, fingerprint: H, status: 'pass', nonce: f.digest, result: blob(`run ${n}`), ...(n === 3 ? { capture: 'interrupted', interruption: 'proxy restarted; resumed' } : {}) } })), 'proxy');
    await anchor();
    rec([{ kind: 'report_issued', event_key: 'report', payload: { report_id: 'R1', report: blob('# Report'), run_count: 3 } }]);
    await anchor();
  } else if (format === 'v3') {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const raw = (publicKey.export({ type: 'spki', format: 'der' }) as Buffer).subarray(12);
    const SIGNER = 'reproducer@isokron.test';
    allowed = allowedSignerLine(SIGNER, raw, REPRODUCTION_NAMESPACE);
    const plan = ['run-1', 'run-2', 'run-3', 'run-4'];
    rec([{ kind: 'harness_frozen', event_key: 'freeze', payload: { harness_id: 'harness-v1', fingerprint: H, manifest: blob('harness files'), hypotheses: blob('H1'), plan, plan_detail: blob(JSON.stringify(plan), 'application/json') } }]);
    const f = await anchor();
    rec([
      ...['run-1', 'run-2', 'run-3'].map((run_id, i) => ({ kind: 'run_completed' as const, event_key: `run:${i + 1}`, payload: { run_id, run_seq: i + 1, fingerprint: H, status: 'pass', nonce: f.nonce, result: blob(`run ${i + 1}`) } })),
      { kind: 'run_abandoned' as const, event_key: 'run:4', payload: { run_id: 'run-4', reason: 'harness refused: API key not exported', fingerprint: H } },
    ], 'proxy');
    await anchor();
    rec([
      { kind: 'finding', event_key: 'f1', payload: { finding_id: 'F1', status: 'discovered', title: 'lost update', severity: 'S2' } },
      { kind: 'gate_result', event_key: 'f1-gate', payload: { finding_id: 'F1', gate: 'refuter', verdict: 'upheld' } },
    ]);
    const commands = blob('./repro.sh F1\n');
    const output = blob('second write lost\n');
    const reproduced_at = '2026-12-01T10:00:00Z';
    const statement = reproductionStatement({ audit_id: AUDIT, finding_id: 'F1', signer: SIGNER, reproduced_at, commands: commands.sha256, output: output.sha256 });
    const signature = blob(sshSign(statement, { namespace: REPRODUCTION_NAMESPACE, public_key: raw, sign: (d) => edSign(null, d, privateKey as KeyObject) }));
    rec([{ kind: 'reproduction_signed', event_key: 'f1-signoff', payload: { finding_id: 'F1', signer: SIGNER, reproduced_at, commands, output, signature } }], 'human');
    rec([{ kind: 'finding', event_key: 'f1-accept', payload: { finding_id: 'F1', status: 'accepted' } }]);
    rec([{ kind: 'report_issued', event_key: 'report', payload: { report_id: 'R1', report: blob('# Report'), run_count: 3 } }]);
    rec([{ kind: 'audit_closed', event_key: 'close', payload: { report_id: 'R1', run_count: 3, findings_digest: findingsDigest([{ finding_id: 'F1', status: 'accepted' }]) } }]);
    await anchor();
  } else {
    // v3-late: freeze with the anchor pending (a signed checkpoint and two tokens 20 h before the late anchor)
    const plan = ['run-1', 'run-2', 'run-3'];
    const manifestBytes = Buffer.from(JSON.stringify({ format: 'mcp-audit/harness-manifest@2', harness: H }) + '\n');
    const planBytes = Buffer.from(JSON.stringify({ runs: plan.map((run_id) => ({ run_id, command: 'probe' })) }) + '\n');
    rec([{ kind: 'harness_frozen', event_key: 'freeze', payload: { harness_id: 'harness-v1', fingerprint: H, manifest: blob(manifestBytes, 'application/json'), plan, plan_detail: blob(planBytes, 'application/json') } }]);
    const F = store.chain.head().seq;
    const cpBytes = Buffer.from(JSON.stringify({ ...store.chain.checkpoint(1, F) }, null, 1) + '\n');
    pendingDir = join(work, 'freeze-pending');
    mkdirSync(pendingDir);
    writeFileSync(join(pendingDir, 'checkpoint.json'), cpBytes);
    writeFileSync(join(pendingDir, 'manifest.json'), manifestBytes);
    writeFileSync(join(pendingDir, 'plan-detail.json'), planBytes);
    const sums = Buffer.from(['checkpoint.json', 'manifest.json', 'plan-detail.json'].map((f) => `${sha(readFileSync(join(pendingDir!, f)))}  ${f}\n`).join(''));
    writeFileSync(join(pendingDir, 'SHA256SUMS'), sums);
    const frozenAt = new Date(Date.now() - 20 * 3600e3);
    const tokens = tsas.map((t, k) => ({ tsa: TSA_NAMES[k]!, file: `SHA256SUMS.${TSA_NAMES[k]}.tsr`, bytes: t.stamp(sums, { genTime: new Date(frozenAt.getTime() + k * 1000) }) }));
    for (const t of tokens) writeFileSync(join(pendingDir, t.file), t.bytes);
    const nonce = freezeNonce(sha(sums), tokens);
    writeFileSync(
      join(pendingDir, 'freeze-pending.json'),
      JSON.stringify({ format: 'isokron/freeze-pending@1', audit_id: AUDIT, fingerprint: H, commit: 'c0ffee', chain_head_seq: F, checkpoint_sha256: sha(cpBytes), sha256sums_sha256: sha(sums), tokens: tokens.map((t) => ({ tsa: t.tsa, gen_time: null, file: t.file, sha256: sha(t.bytes) })), nonce, anchor: 'pending', nonce_recipe: 'freezeNonce(sha256(SHA256SUMS), tokens)', recorded_at: frozenAt.toISOString(), events: [{ seq: F, kind: 'harness_frozen' }] }, null, 1) + '\n',
    );
    rec([
      ...plan.slice(0, 2).map((run_id, i) => ({ kind: 'run_completed' as const, event_key: `run:${run_id}`, payload: { run_id, run_seq: i + 1, fingerprint: H, status: 'pass', nonce, result: blob(`run ${i + 1}`) } })),
      { kind: 'run_abandoned' as const, event_key: 'run:run-3', payload: { run_id: 'run-3', reason: 'server crashed at start', fingerprint: H } },
    ], 'harness');
    await anchor();
    rec([{ kind: 'report_issued', event_key: 'report', payload: { report_id: 'R1', report: blob('# Report\n', 'text/markdown'), run_count: 2 } }]);
    rec([{ kind: 'audit_closed', event_key: 'close', payload: { report_id: 'R1', run_count: 2, findings_digest: findingsDigest([]) } }]);
    await anchor();
    allowed = 'nobody@isokron.test namespaces="kronicle-lite-reproduction" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n';
  }

  const rootsDir = join(work, 'roots');
  mkdirSync(rootsDir);
  tsas.forEach((t, k) => writeFileSync(join(rootsDir, `tsa-${k}.pem`), t.root.pem));
  const doc = (await (await fetch(`${backend.url}/.well-known/anchor-keys.json`)).json()) as { keys: { public_key_pem: string; valid_from: string }[] };
  const genesis = `${chainIdFromPublicKeyPem(doc.keys[0]!.public_key_pem)}@${doc.keys[0]!.valid_from}`;
  const dir = join(work, 'pack');
  const v3 = format === 'v3' || format === 'v3-late';
  await buildAuditPackage(store, {
    audit_id: AUDIT,
    out: dir,
    timestamps_dir: tsDir,
    tsa_roots: tsas.map((t) => t.root.pem),
    genesis,
    anchor_keys: doc,
    ...(allowed ? { allowed_signers: allowed } : {}),
    ...(pendingDir ? { freeze_pending_dir: pendingDir } : {}),
    ...(v3 ? { stamp_sums: { tsas: TSA_NAMES.map((name, k) => ({ name, url: servers[k]!.url })) } } : {}),
  });
  const fp = chainIdFromPublicKeyPem(store.identity.signer.public_key_pem);
  store.close();
  return { format, dir, fp, dataDir, genesis, rootsDir };
}

// ── service keys under test control, for the key-rotation case (as test/verify-audit.test.ts) ──

export interface ServiceKey {
  priv: KeyObject;
  pem: string;
  id: string;
  fp: string;
}
export function newServiceKey(): ServiceKey {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
  return { priv: privateKey, pem, id: serviceKeyIdFromPem(pem), fp: chainIdFromPublicKeyPem(pem) };
}
const b64sig = (k: ServiceKey, msg: string) => edSign(null, Buffer.from(msg), k.priv).toString('base64');

/** Re-sign a pack's receipts with `k` at the given received_at and re-stamp them; replace its key list; re-seal SHA256SUMS. */
export function resignPack(p: Pack, env: Env, k: ServiceKey, keys: unknown[], receivedAt: (i: number) => string, genTime: (i: number) => Date): void {
  const anchors = join(p.dir, 'anchors');
  const receipts = listPackFiles(p.dir).files.filter((f) => f.startsWith('anchors/') && f.endsWith('.receipt.json')).sort();
  receipts.forEach((f, i) => {
    const path = join(p.dir, f);
    const r = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
    r['service_key_id'] = k.id;
    r['received_at'] = receivedAt(i);
    delete r['signature'];
    r['signature'] = b64sig(k, anchorReceiptSigningPayload(r as never));
    const bytes = canonicalize(r);
    rmSync(path);
    writeFileSync(path, bytes);
    const base = f.slice('anchors/'.length, -'.receipt.json'.length);
    env.tsas.forEach((t, j) => {
      const tsr = join(anchors, `${base}.${TSA_NAMES[j]}.tsr`);
      rmSync(tsr, { force: true });
      writeFileSync(tsr, t.stamp(bytes, { genTime: genTime(i) }));
    });
  });
  rmSync(join(p.dir, 'anchor-keys.json'));
  writeFileSync(join(p.dir, 'anchor-keys.json'), JSON.stringify({ v: 1, keys }));
  // claims without the ordering claim (its nonce named the old freeze receipt)
  const claimsPath = join(p.dir, 'claims.json');
  const c = JSON.parse(readFileSync(claimsPath, 'utf8')) as { claims: string[] };
  c.claims = c.claims.filter((x) => x !== 'harness_frozen_before_runs');
  rmSync(claimsPath);
  writeFileSync(claimsPath, JSON.stringify(c, null, 1) + '\n');
  for (const f of listPackFiles(p.dir).files.filter(isSumsFile)) rmSync(join(p.dir, f));
  const sums = sha256sums(p.dir, listPackFiles(p.dir).files.filter((f) => !isSumsFile(f)));
  writeFileSync(join(p.dir, 'SHA256SUMS'), sums);
  const store = new KronicleLite({ dataDir: p.dataDir });
  try {
    writeFileSync(join(p.dir, 'SHA256SUMS.sig'), Buffer.from(store.identity.signer.sign(Buffer.from(sums)), 'base64'));
  } finally {
    store.close();
  }
}
