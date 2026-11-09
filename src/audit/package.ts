/**
 * `kronicle-lite audit package` and `audit stamp` (0.10.0): the auditor side
 * of verifiable audits (docs/EVIDENCE-BUNDLE.md "Audit packages").
 *
 *   audit stamp    right after `checkpoint --push`: fetch RFC 3161 tokens over
 *                  sha256(receipt) from independent TSAs (Sectigo and DigiCert
 *                  by default) into a timestamps directory, as
 *                  <anchor_id>.<tsa>.tsr. Take the stamp at anchor time: a
 *                  later stamp carries a later time.
 *   audit package  the client package: the evidence bundle, every anchor whose
 *                  range lies inside the bundle's, the tokens for those anchors,
 *                  the auditor key, the anchor service keys, the TSA roots and a
 *                  README with the verification commands; then it runs
 *                  verify-audit on what it wrote.
 */

import { closeSync, constants, existsSync, lstatSync, mkdirSync, openSync, readdirSync, writeSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import { parseAnchorReceipt } from '../anchor/receipt.js';
import { keyListOf } from '../anchor/keychain.js';
import { canonicalize } from '../crypto/canonical.js';
import { sha256Hex } from '../crypto/hash.js';
import { chainIdFromPublicKeyPem } from '../crypto/keys.js';
import type { KronicleLite } from '../store.js';
import { exportBundle } from './bundle.js';
import { AuditError } from './log.js';
import { checkTimestampReply, inspectTimestamp, MAX_TSR_BYTES, timestampRequest, verifyTimestamp } from './rfc3161.js';
import { kindOfEventType } from './schemas.js';
import { SHIPPED_TSA_ROOTS } from './tsa-roots.js';
import { VERSION } from '../version.js';
import { readBundleFile } from './verify-bundle.js';
import { CLAIMS, CLAIMS_FORMAT, listPackFiles, PACK_NAME, sha256sums, verifyAudit, type Claim, type ClaimsFile, type TsaRoot, type VerifyAuditOptions, type VerifyAuditResult } from './verify-audit.js';

export const DEFAULT_TSAS: readonly { name: string; url: string }[] = [
  { name: 'sectigo', url: 'http://timestamp.sectigo.com' },
  { name: 'digicert', url: 'http://timestamp.digicert.com' },
];
const TSA_NAME = /^[a-z0-9][a-z0-9-]{0,31}$/;

/** Create a NEW file (never an existing one, never through a symlink) and write it. */
function writeNew(path: string, data: string | Buffer): void {
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o644);
  try {
    writeSync(fd, typeof data === 'string' ? Buffer.from(data, 'utf8') : data);
  } finally {
    closeSync(fd);
  }
}

/** --tsa name=url[,name=url]: the TSAs to ask. */
export function parseTsaList(spec: string): { name: string; url: string }[] {
  return spec
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean)
    .map((pair) => {
      const eq = pair.indexOf('=');
      const name = pair.slice(0, eq);
      const url = pair.slice(eq + 1);
      if (eq <= 0 || !TSA_NAME.test(name)) throw new Error(`--tsa expects name=url pairs (name: lowercase letters, digits, -), got "${pair}"`);
      let u: URL;
      try {
        u = new URL(url);
      } catch {
        throw new Error(`--tsa ${name}: "${url}" is not a URL`);
      }
      if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error(`--tsa ${name}: only http(s) URLs`);
      return { name, url };
    });
}

/** PEM certificates from every *.pem / *.crt file in DIR (several per file allowed); each file is one TSA. */
export function readPemDir(dir: string): { name: string; pem: string }[] {
  const out: { name: string; pem: string }[] = [];
  for (const f of readdirSync(dir).sort()) {
    if (!/\.(pem|crt)$/i.test(f)) continue;
    const text = readBundleFile(join(dir, f), 1024 * 1024, { followLinks: true }).toString('utf8');
    for (const m of text.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)) out.push({ name: f.replace(/\.(pem|crt)$/i, ''), pem: m[0] + '\n' });
  }
  if (out.length === 0) throw new Error(`${dir} holds no PEM certificates (*.pem, *.crt)`);
  return out;
}

// ───────────────────────────── stamp ─────────────────────────────

export interface StampResult {
  anchor_id: string;
  receipt_sha256: string;
  results: { tsa: string; url: string; ok: boolean; file: string | null; gen_time: string | null; problem: string | null; existing: boolean }[];
}

/** RFC 3161 tokens over sha256(receipt) for one anchor (the latest by default), written to `out_dir`. */
export async function stampAnchor(
  store: KronicleLite,
  opts: { anchor_id?: string; out_dir: string; tsas?: readonly { name: string; url: string }[]; fetch?: typeof fetch; timeoutMs?: number },
): Promise<StampResult> {
  const chainId = chainIdFromPublicKeyPem(store.identity.signer.public_key_pem);
  const mine = store.chain.listAnchors().filter((a) => a.chain_id === chainId);
  const row = opts.anchor_id ? mine.find((a) => a.anchor_id === opts.anchor_id) : [...mine].sort((a, b) => a.to_seq - b.to_seq || a.received_at.localeCompare(b.received_at)).pop();
  if (!row) throw new AuditError('invalid_audit_event', opts.anchor_id ? `no anchor ${opts.anchor_id} for this store's chain` : 'no anchors yet: run `kronicle-lite checkpoint --push` first');
  const receipt = row.receipt_json;
  const digest = sha256Hex(receipt);
  mkdirSync(opts.out_dir, { recursive: true, mode: 0o700 });
  const doFetch = opts.fetch ?? fetch;
  const out: StampResult = { anchor_id: row.anchor_id, receipt_sha256: digest, results: [] };
  for (const t of opts.tsas ?? DEFAULT_TSAS) {
    const file = join(opts.out_dir, `${row.anchor_id}.${t.name}.tsr`);
    if (existsSync(file)) {
      // Keep the first stamp: an earlier time is the stronger statement.
      try {
        const info = inspectTimestamp(readBundleFile(file, MAX_TSR_BYTES));
        const same = info.imprint === digest;
        out.results.push({ tsa: t.name, url: t.url, ok: same, file, gen_time: info.gen_time, problem: same ? null : `${file} exists and stamps a different digest`, existing: true });
      } catch (err) {
        out.results.push({ tsa: t.name, url: t.url, ok: false, file, gen_time: null, problem: `${file} exists and is not a timestamp reply: ${(err as Error).message}`, existing: true });
      }
      continue;
    }
    const req = timestampRequest(receipt);
    try {
      const res = await doFetch(t.url, {
        method: 'POST',
        headers: { 'content-type': 'application/timestamp-query', accept: 'application/timestamp-reply' },
        body: new Uint8Array(req.der),
        signal: AbortSignal.timeout(opts.timeoutMs ?? 20_000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = Buffer.from(await res.arrayBuffer());
      const info = checkTimestampReply(body, req);
      writeNew(file, body);
      out.results.push({ tsa: t.name, url: t.url, ok: true, file, gen_time: info.gen_time, problem: null, existing: false });
    } catch (err) {
      out.results.push({ tsa: t.name, url: t.url, ok: false, file: null, gen_time: null, problem: err instanceof Error ? err.message : String(err), existing: false });
    }
  }
  return out;
}

// ───────────────────────────── package ─────────────────────────────

export interface PackageAnchor {
  file: string;
  anchor_id: string;
  from_seq: number;
  to_seq: number;
  root: string;
  received_at: string;
  receipt_sha256: string;
  timestamps: { file: string; tsa: string; gen_time: string }[];
}

export interface PackageResult {
  dir: string;
  audit_id: string;
  bundle_format: string;
  manifest_sha256: string;
  root: string;
  from_seq: number;
  to_seq: number;
  events: number;
  blobs: number;
  auditor_key_id: string;
  auditor_spki_sha256: string;
  anchors: PackageAnchor[];
  /** Anchors of this chain left out (range outside the bundle), with why. */
  skipped: string[];
  /** What claims.json declares, and why each claim is or is not declared. */
  claims: { claim: Claim; declared: boolean; why: string }[];
  /** verify-audit run on the written pack. */
  check: VerifyAuditResult;
}

const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'anchor';

/** File label of the milestone an anchor closes on: the kind of the event at its to_seq. */
function milestoneLabel(store: KronicleLite, seq: number): string {
  const [ev] = store.chain.range(seq, seq);
  if (!ev) return `seq-${seq}`;
  const kind = kindOfEventType(ev.event_type);
  if (!kind) return `seq-${seq}`;
  const p = ev.payload as Record<string, unknown>;
  if (kind === 'harness_frozen' || (kind === 'finding' && p['class'] === 'protocol_freeze')) return 'harness-frozen';
  if (kind === 'report_issued' || (kind === 'finding' && p['class'] === 'report')) return 'report-issued';
  return slug(kind);
}

export async function buildAuditPackage(
  store: KronicleLite,
  opts: {
    audit_id: string;
    out: string;
    timestamps_dir?: string;
    tsa_roots?: TsaRoot[];
    /** The anchor service's published key list ({keys: [...]}); fetched from <anchor_url>/.well-known/anchor-keys.json when absent. */
    anchor_keys?: unknown;
    /** Genesis pin for the key list, `<sha256>@<valid_from>` (default: the compiled production pin). */
    genesis?: string;
    fetch?: typeof fetch;
    now?: Date;
  },
): Promise<PackageResult> {
  const out = resolve(opts.out);
  for (let p = out; ; p = dirname(p)) {
    if (lstatSync(p, { throwIfNoEntry: false })?.isSymbolicLink()) throw new AuditError('invalid_audit_event', `refusing to write through a symlink: ${p} (pass the real path)`);
    if (dirname(p) === p) break;
  }
  if (existsSync(out)) {
    if (!lstatSync(out).isDirectory()) throw new AuditError('invalid_audit_event', `--out ${out} exists and is not a directory`);
    if (readdirSync(out).length > 0) throw new AuditError('invalid_audit_event', `--out ${out} is not empty; package into a new or empty directory`);
  } else mkdirSync(out, { recursive: true, mode: 0o755 });

  const signer = store.identity.signer;
  const chainId = chainIdFromPublicKeyPem(signer.public_key_pem);
  const exp = exportBundle({ chain: store.chain, audit: store.audit, signer, audit_id: opts.audit_id, dir: join(out, 'bundle') });
  const m = exp.manifest;

  // Anchors of this chain whose range lies inside the bundle's (their roots can be recomputed from it).
  const anchorsDir = join(out, 'anchors');
  mkdirSync(anchorsDir, { mode: 0o755 });
  const skipped: string[] = [];
  const seen = new Set<string>();
  const rows = store.chain
    .listAnchors()
    .filter((a) => a.chain_id === chainId)
    .sort((a, b) => a.to_seq - b.to_seq || a.received_at.localeCompare(b.received_at));
  const picked: typeof rows = [];
  for (const a of rows) {
    if (seen.has(a.anchor_id)) continue;
    seen.add(a.anchor_id);
    if (a.from_seq < m.range.from_seq || a.to_seq > m.range.to_seq) {
      skipped.push(`${a.anchor_id} (seq ${a.from_seq}..${a.to_seq}) is outside the bundle's seq ${m.range.from_seq}..${m.range.to_seq}`);
      continue;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(a.receipt_json);
    } catch {
      skipped.push(`${a.anchor_id}: stored receipt is not JSON`);
      continue;
    }
    if (!parseAnchorReceipt(parsed).ok || canonicalize(parsed) !== a.receipt_json) {
      skipped.push(`${a.anchor_id}: stored receipt is not a canonical anchor receipt`);
      continue;
    }
    picked.push(a);
  }

  const tokenFiles = opts.timestamps_dir ? readdirSync(opts.timestamps_dir).filter((f) => f.endsWith('.tsr')) : [];
  const anchors: PackageAnchor[] = [];
  const width = Math.max(2, String(picked.length).length);
  for (const [i, a] of picked.entries()) {
    const base = `${String(i + 1).padStart(width, '0')}-${milestoneLabel(store, a.to_seq)}`;
    const digest = sha256Hex(a.receipt_json);
    writeNew(join(anchorsDir, `${base}.receipt.json`), a.receipt_json);
    const pa: PackageAnchor = { file: `${base}.receipt.json`, anchor_id: a.anchor_id, from_seq: a.from_seq, to_seq: a.to_seq, root: a.root, received_at: a.received_at, receipt_sha256: digest, timestamps: [] };
    for (const f of tokenFiles) {
      const mt = f.match(/^(.+)\.([a-z0-9][a-z0-9-]{0,31})\.tsr$/);
      if (!mt || (mt[1] !== a.anchor_id && mt[1] !== digest)) continue;
      const bytes = readBundleFile(join(opts.timestamps_dir!, f), MAX_TSR_BYTES, { followLinks: true });
      const info = inspectTimestamp(bytes);
      if (info.imprint !== digest || info.hash_algorithm !== 'sha256') throw new AuditError('invalid_audit_event', `${f} does not stamp sha256 of anchor ${a.anchor_id}'s receipt (${digest})`);
      const name = `${base}.${mt[2]}.tsr`;
      writeNew(join(anchorsDir, name), bytes);
      pa.timestamps.push({ file: name, tsa: mt[2]!, gen_time: info.gen_time });
    }
    pa.timestamps.sort((x, y) => x.tsa.localeCompare(y.tsa));
    anchors.push(pa);
  }

  // Keys and TSA roots. anchor-keys.json is the service's published key list as is (signed statements
  // included): the client checks it as one chain from the genesis pin, exactly as the service does.
  writeNew(join(out, 'auditor-key.pem'), signer.public_key_pem);
  let keyDoc = opts.anchor_keys;
  if (keyDoc === undefined && picked.length > 0) {
    const urls = [...new Set(picked.map((a) => a.anchor_url))];
    if (urls.length !== 1) throw new AuditError('invalid_audit_event', `anchors come from ${urls.length} anchor services (${urls.join(', ')}); pass the key list with --anchor-keys`);
    const res = await (opts.fetch ?? fetch)(`${urls[0]!.replace(/\/+$/, '')}/.well-known/anchor-keys.json`, { signal: AbortSignal.timeout(20_000) });
    if (!res.ok) throw new AuditError('invalid_audit_event', `cannot fetch the anchor key list from ${urls[0]} (HTTP ${res.status}); pass it with --anchor-keys`);
    keyDoc = (await res.json()) as unknown;
  }
  const keyList = keyDoc === undefined ? [] : keyListOf(keyDoc);
  if (keyList === null) throw new AuditError('invalid_audit_event', 'the anchor key list is not {keys: [{key_id, public_key_pem, …}]}');
  writeNew(join(out, 'anchor-keys.json'), JSON.stringify({ v: 1, keys: keyList.map((k) => Object.fromEntries(Object.entries(k).filter(([, v]) => v !== null))) }, null, 1) + '\n');
  mkdirSync(join(out, 'tsa-roots'), { mode: 0o755 });
  // The pinned TSA CAs, one file per TSA (several certificates each), then any custom roots.
  const rootFiles: { file: string; pems: string[] }[] = [];
  for (const r of SHIPPED_TSA_ROOTS) {
    const f = rootFiles.find((x) => x.file === `${r.name}.pem`);
    if (f) f.pems.push(r.pem);
    else rootFiles.push({ file: `${r.name}.pem`, pems: [r.pem] });
  }
  let custom = 0;
  for (const r of opts.tsa_roots ?? []) {
    const pem = typeof r === 'string' ? r : r.pem;
    if (rootFiles.some((x) => x.pems.some((y) => y.trim() === pem.trim()))) continue;
    rootFiles.push({ file: `custom-${++custom}.pem`, pems: [pem] });
  }
  for (const r of rootFiles) writeNew(join(out, 'tsa-roots', r.file), r.pems.join(''));
  // The root each token chains to, for VERIFY.md's openssl commands.
  const rootFor = new Map<string, string>();
  for (const a of anchors) {
    const receipt = readBundleFile(join(anchorsDir, a.file), 64 * 1024);
    for (const t of a.timestamps) {
      const bytes = readBundleFile(join(anchorsDir, t.file), MAX_TSR_BYTES);
      const hit = rootFiles.find((r) => verifyTimestamp(bytes, { message: receipt, roots: r.pems, at: 'gentime' }).ok);
      rootFor.set(t.file, hit?.file ?? `${t.tsa}.pem`);
    }
  }
  writeNew(join(anchorsDir, 'index.json'), JSON.stringify(anchors, null, 1) + '\n');

  // Which claims the store's contents support: check all of them once, declare what holds.
  const trustOpts: VerifyAuditOptions = {
    key_pem: signer.public_key_pem,
    ...(opts.genesis !== undefined ? { genesis: opts.genesis } : {}),
    ...(opts.tsa_roots ? { tsa_roots: [...SHIPPED_TSA_ROOTS.map((r) => ({ name: r.name, pem: r.pem })), ...opts.tsa_roots] } : {}),
    ...(opts.now ? { now: opts.now } : {}),
  };
  const probe = verifyAudit(out, { ...trustOpts, claims_override: CLAIMS });
  // A self-hosted anchor service's pin goes into the printed commands (the compiled pin needs none).
  const genesisArg = opts.genesis !== undefined ? ` --genesis ${probe.trust.genesis_sha256}@${probe.trust.genesis_valid_from}` : '';
  const runs = probe.run_sequence;
  const decisions: { claim: Claim; declared: boolean; why: string }[] = [
    { claim: 'integrity', declared: true, why: 'always' },
    { claim: 'chain', declared: true, why: 'always' },
    { claim: 'receipts', declared: anchors.length > 0, why: anchors.length > 0 ? `${anchors.length} anchor(s)` : 'no anchors inside the bundle range' },
    {
      claim: 'independent_timestamps',
      declared: anchors.length > 0 && anchors.every((a) => a.timestamps.length > 0),
      why: anchors.length === 0 ? 'no anchors' : anchors.every((a) => a.timestamps.length > 0) ? 'every anchor has RFC 3161 tokens' : `no RFC 3161 token for ${anchors.filter((a) => a.timestamps.length === 0).map((a) => a.file.replace(/\.receipt\.json$/, '')).join(', ')}`,
    },
    { claim: 'harness_frozen_before_runs', declared: probe.ordering.status === 'pass', why: probe.ordering.status === 'pass' ? `basis ${probe.ordering.basis}` : (probe.ordering.problem ?? 'not shown') },
    {
      claim: 'run_sequence',
      declared: runs.seqs.length > 0 && runs.seqs.every((s) => Number.isInteger(s)),
      why: runs.seqs.length > 0 ? `${runs.count} run(s) with run_seq` : 'no run_completed events with run_seq',
    },
  ];
  const claims: ClaimsFile = {
    format: CLAIMS_FORMAT,
    audit_id: opts.audit_id,
    claims: decisions.filter((d) => d.declared).map((d) => d.claim),
    ...(decisions.find((d) => d.claim === 'run_sequence')!.declared
      ? { runs: { count: runs.count ?? 0, seqs: runs.seqs, interruptions: runs.interruptions.map((x) => ({ run_seq: x.run_seq, event_key: x.event_key ?? '', note: x.note })) } }
      : {}),
  };
  writeNew(join(out, 'claims.json'), JSON.stringify(claims, null, 1) + '\n');

  const last = anchors[anchors.length - 1];
  const keyLine = `${signer.key_id} (SHA-256 of the public key's SPKI: ${chainId})`;
  const finalTimes = last ? (last.timestamps.length ? last.timestamps.map((t) => `${t.gen_time} (${t.tsa})`).join(', ') : `${last.received_at} (anchor service)`) : '-';
  writeNew(
    join(out, 'COMPLETION.txt'),
    [
      `${PACK_NAME}: ${opts.audit_id}`,
      'Tamper-evident, independently timestamped audit evidence.',
      '',
      `Audit ID              ${opts.audit_id}`,
      `Manifest SHA-256      ${exp.manifest_sha256}`,
      `Signing key           ${keyLine}`,
      `Final anchored root   ${m.root.root}`,
      `  covering            seq ${m.range.from_seq}..${m.range.to_seq} (${m.events.length} audit event(s), ${m.blobs.length} artifact(s))`,
      `  anchor              ${last ? `${last.file.replace(/\.receipt\.json$/, '')}, ${last.anchor_id}, received ${last.received_at}` : '-'}`,
      `  timestamps          ${finalTimes}`,
      `Milestones`,
      ...anchors.map((a) => `  ${a.file.replace(/\.receipt\.json$/, '').padEnd(26)} seq ${a.from_seq}..${a.to_seq}  ${a.timestamps.length ? a.timestamps.map((t) => `${t.tsa} ${t.gen_time}`).join(', ') : `anchor service ${a.received_at}`}`),
      `Claims                ${claims.claims.join(', ')}`,
      '',
      `Verify:  npx -y kronicle-lite@${VERSION} verify-audit <this directory> --key-fingerprint ${chainId}${genesisArg}`,
      '         (take the fingerprint from the report or SOW, not from a copy of this file)',
      'Raw commands without kronicle-lite: VERIFY.md',
      '',
    ].join('\n'),
  );
  writeNew(join(out, 'VERIFY.md'), verifyMd({ audit_id: opts.audit_id, keyLine, manifestSha: exp.manifest_sha256, root: m.root.root, anchors, rootFor, claims: claims.claims, genesisArg }));

  // SHA256SUMS over every file, and its raw Ed25519 signature by the auditor key (openssl pkeyutl checks it).
  const { files } = listPackFiles(out);
  const sums = sha256sums(out, files);
  writeNew(join(out, 'SHA256SUMS'), sums);
  writeNew(join(out, 'SHA256SUMS.sig'), Buffer.from(signer.sign(Buffer.from(sums, 'utf8')), 'base64'));

  const check = verifyAudit(out, trustOpts);
  return {
    dir: out,
    audit_id: opts.audit_id,
    bundle_format: m.format,
    manifest_sha256: exp.manifest_sha256,
    root: m.root.root,
    from_seq: m.range.from_seq,
    to_seq: m.range.to_seq,
    events: m.events.length,
    blobs: m.blobs.length,
    auditor_key_id: signer.key_id,
    auditor_spki_sha256: chainId,
    anchors,
    skipped,
    claims: decisions,
    check,
  };
}

const epoch = (iso: string) => Math.floor(Date.parse(iso) / 1000);

function verifyMd(v: { audit_id: string; keyLine: string; manifestSha: string; root: string; anchors: PackageAnchor[]; rootFor: Map<string, string>; claims: readonly Claim[]; genesisArg: string }): string {
  const a0 = v.anchors[0];
  return [
    `# ${PACK_NAME}: ${v.audit_id}`,
    '',
    'Tamper-evident, independently timestamped audit evidence. Every check below runs offline on',
    'this directory. The one-command route uses kronicle-lite (open source); the raw route uses only',
    '`shasum` / `openssl` / `jq`.',
    '',
    `- Manifest SHA-256: \`${v.manifestSha}\``,
    `- Signing key: \`${v.keyLine}\``,
    `- Final anchored root: \`${v.root}\``,
    `- Claims: ${v.claims.join(', ')}`,
    '',
    'Compare the signing key with the fingerprint in your report or statement of work before you rely',
    'on anything else here.',
    '',
    '## One command',
    '',
    '```sh',
    `npx -y kronicle-lite@${VERSION} verify-audit . --key-fingerprint <the auditor key fingerprint from your report or SOW>${v.genesisArg}`,
    '```',
    '',
    'It pins the auditor key by the fingerprint you give it, verifies SHA256SUMS before it reads',
    '`claims.json`, always checks integrity and chain, then the claims in `claims.json`, and prints',
    'PASS or FAIL for each with its evidence, then the values to compare with the report. Exit 0 means',
    'every checked claim passed.',
    '',
    '## Without kronicle-lite',
    '',
    'Needs OpenSSL 3 (macOS: `brew install openssl@3`; LibreSSL lacks raw Ed25519 verification) and `jq`.',
    '',
    '### 1. Files: SHA256SUMS and its signature',
    '',
    '```sh',
    '# the auditor key signed SHA256SUMS (raw Ed25519 signature)',
    'openssl pkeyutl -verify -pubin -inkey auditor-key.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig',
    '# every file matches its line (either command)',
    'shasum -a 256 -c SHA256SUMS',
    'sha256sum -c SHA256SUMS',
    '# one file by hand',
    'openssl dgst -sha256 bundle/manifest.json',
    '```',
    '',
    '`bundle/manifest.json` also lists the SHA-256 of `events.jsonl` (`events_sha256`) and of every',
    'artifact in `bundle/blobs/` (each file is named by its own SHA-256).',
    '',
    '### 2. Independent time: each RFC 3161 token',
    '',
    'Each token stamps the SHA-256 of its receipt file and embeds the timestamp authority\'s certificate',
    'chain. `tsa-roots/` holds the pinned timestamping CAs (not the general public roots):',
    '`sectigo.pem` is Sectigo Public Time Stamping Root R46 (self-signed and USERTrust cross-signed forms',
    'of one key), `digicert.pem` the DigiCert Trusted G4 TimeStamping CAs. `-partial_chain` lets openssl',
    'stop at a pinned CA that is not self-signed. Check the fingerprints against the authorities\' sites',
    '(`openssl crl2pkcs7 -nocrl -certfile tsa-roots/digicert.pem | openssl pkcs7 -print_certs -noout`,',
    'then `openssl x509 -noout -fingerprint -sha256` on each).',
    '',
    '```sh',
    ...v.anchors.flatMap((a) => [
      `D=$(shasum -a 256 anchors/${a.file} | cut -c1-64)`,
      ...a.timestamps.map((t) => `openssl ts -verify -digest $D -in anchors/${t.file} -CAfile tsa-roots/${v.rootFor.get(t.file)} -partial_chain`),
      ...a.timestamps.slice(0, 1).map((t) => `openssl ts -reply -in anchors/${t.file} -text | grep 'Time stamp'`),
    ]),
    '```',
    '',
    '### 3. Anchor receipts: Ed25519 signatures',
    '',
    'The anchor service signed each receipt over its canonical JSON without `signature`; the',
    'checkpoint inside it is signed by the auditor key. With `jq -cjS` (sorted keys, compact, no',
    'trailing newline) the bytes equal the canonical form for these ASCII, integer-only objects.',
    '',
    '```sh',
    ...(a0
      ? [
          `R=anchors/${a0.file}`,
          '# anchor service countersignature (key from anchor-keys.json; compare it with isokron.ai/verify)',
          `jq -r --arg k "$(jq -r .service_key_id $R)" '.keys[] | select(.key_id == $k) | .public_key_pem' anchor-keys.json > service-key.pem`,
          `jq -cjS 'del(.signature)' $R > receipt-body.bin`,
          `jq -r .signature $R | openssl base64 -d -A > receipt.sig`,
          'openssl pkeyutl -verify -pubin -inkey service-key.pem -rawin -in receipt-body.bin -sigfile receipt.sig',
          '# auditor checkpoint signature',
          `jq -cjS '.checkpoint | {v, from_seq, to_seq, leaf_count, root}' $R > checkpoint-body.bin`,
          `jq -r .checkpoint.signature $R | openssl base64 -d -A > checkpoint.sig`,
          'openssl pkeyutl -verify -pubin -inkey auditor-key.pem -rawin -in checkpoint-body.bin -sigfile checkpoint.sig',
        ]
      : ['# (this pack holds no anchors)']),
    '```',
    '',
    'Recomputing each anchored root from `bundle/events.jsonl` follows kronicle-lite docs/FORMAT.md §2',
    '(leaf = sha256 of the canonical `{seq, this_hash}`, node = sha256(left ‖ right), an odd node is',
    'promoted); `verify-audit` does it for you.',
    '',
    '## Re-verifying in later years',
    '',
    'Timestamp authority certificates expire, and `openssl ts -verify` checks them at the current time',
    'by default. After expiry, verify each token at its own genTime against the same pinned roots:',
    '',
    '```sh',
    ...v.anchors.flatMap((a) =>
      a.timestamps.map((t) => `openssl ts -verify -digest $(shasum -a 256 anchors/${a.file} | cut -c1-64) -in anchors/${t.file} -CAfile tsa-roots/${v.rootFor.get(t.file)} -partial_chain -attime ${epoch(t.gen_time)}   # ${t.gen_time}`),
    ),
    '```',
    '',
    `or \`kronicle-lite verify-audit . --key-fingerprint <fingerprint>${v.genesisArg} --tsa-at-gentime\`. Keep this directory`,
    'whole: the tokens carry the TSA chains and `tsa-roots/` the roots they verify against.',
    '',
  ].join('\n');
}

/** The human-readable summary of `audit package`. */
export function renderPackage(r: PackageResult): string {
  const L: string[] = [];
  L.push(`${PACK_NAME}  ${r.dir}`);
  L.push(`audit          ${r.audit_id}  (${r.bundle_format}, seq ${r.from_seq}..${r.to_seq}, ${r.events} event(s), ${r.blobs} artifact(s))`);
  L.push(`auditor key    ${r.auditor_key_id}  spki sha256 ${r.auditor_spki_sha256}`);
  L.push(`manifest       sha256 ${r.manifest_sha256}`);
  L.push(`final root     ${r.root}`);
  L.push('', 'Anchors');
  if (r.anchors.length === 0) L.push('  none');
  for (const a of r.anchors) {
    L.push(`  ${a.file.replace(/\.receipt\.json$/, '').padEnd(26)} seq ${a.from_seq}..${a.to_seq}  root ${a.root.slice(0, 16)}…  received ${a.received_at}`);
    for (const t of a.timestamps) L.push(`  ${''.padEnd(26)} RFC 3161 ${t.tsa.padEnd(10)} ${t.gen_time}`);
    if (a.timestamps.length === 0) L.push(`  ${''.padEnd(26)} RFC 3161 none (kronicle-lite audit stamp --anchor-id ${a.anchor_id} --out DIR, then --timestamps DIR)`);
  }
  for (const s of r.skipped) L.push(`  skipped ${s}`);
  L.push('', 'Claims (claims.json)');
  for (const d of r.claims) L.push(`  ${(d.declared ? 'declared' : 'not declared').padEnd(12)}  ${d.claim.padEnd(26)} ${d.why}`);
  const fin = r.check.final;
  if (fin) L.push('', `timestamped    ${fin.tsa_times.length ? fin.tsa_times.map((t) => `${t.gen_time} (${t.tsa})`).join(', ') : `${fin.service_time} (anchor service)`}`);
  const bad = r.check.checks.filter((c) => c.status === 'fail');
  L.push('');
  if (r.check.ok) L.push(`verify-audit   PASS  ${r.check.claims.filter((c) => c.status === 'pass').map((c) => c.claim).join(', ')}`);
  else {
    L.push(`verify-audit   FAIL (${r.check.failed} failed check(s))`);
    for (const c of bad) L.push(`  FAIL  ${c.subject ? `${c.subject} ` : ''}${c.check}: ${c.evidence}`);
  }
  return L.join('\n') + '\n';
}
