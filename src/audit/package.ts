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
 *                  the auditor key, the anchor service keys, the TSA roots, the
 *                  reproducers' allowed signers and a README with the
 *                  verification commands; SHA256SUMS, its signature and (0.11.0)
 *                  RFC 3161 tokens over it; then it runs verify-audit on what it
 *                  wrote (the audit profile for a /3 bundle, legacy otherwise).
 *
 * 0.11.1: a stamp that fails is an error and leaves nothing behind (audit
 * mode). Only with `allow_pending` (`audit stamp --allow-pending`) is it left
 * as `<anchor_id>.<tsa>.pending` beside the tokens; the package carries it,
 * and the audit profile fails while one is there.
 */

import { closeSync, constants, existsSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, rmSync, writeFileSync, writeSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import { parseAnchorReceipt } from '../anchor/receipt.js';
import { keyListOf } from '../anchor/keychain.js';
import { CHECKPOINT_VERSION } from '../chain/chain.js';
import { canonicalize } from '../crypto/canonical.js';
import { sha256Hex } from '../crypto/hash.js';
import { chainIdFromPublicKeyPem } from '../crypto/keys.js';
import type { KronicleLite } from '../store.js';
import { exportBundle } from './bundle.js';
import { AuditError } from './log.js';
import { checkTimestampReply, inspectTimestamp, MAX_TSR_BYTES, timestampRequest, verifyTimestamp } from './rfc3161.js';
import { findFreezePending, FREEZE_PENDING_DIR, FREEZE_PENDING_RECORD, isFreezePendingFile, parseFreezePending, REPORT_ARCHIVE_PREFIX } from './freeze-pending.js';
import { freezeNonce } from './profile.js';
import { BUNDLE_FORMAT_V3, kindOfEventType } from './schemas.js';
import { parseAllowedSigners } from './sshsig.js';
import { SHIPPED_TSA_ROOTS } from './tsa-roots.js';
import { VERSION } from '../version.js';
import { readBundleFile } from './verify-bundle.js';
import {
  ALLOWED_SIGNERS_FILE,
  CLAIMS,
  CLAIMS_FORMAT,
  formatDuration,
  LATE_ANCHOR_RESULT,
  LEGACY_CLAIMS,
  listPackFiles,
  PACK_NAME,
  PENDING_SUFFIX,
  sha256sums,
  verifyAudit,
  type Claim,
  type ClaimsFile,
  type Profile,
  type TsaRoot,
  type VerifyAuditOptions,
  type VerifyAuditResult,
} from './verify-audit.js';

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
/** The certificate files of a TSA roots directory (*.pem, *.crt), sorted. */
export const pemFileNames = (dir: string): string[] => readdirSync(dir).filter((f) => /\.(pem|crt)$/i.test(f)).sort();

/** The PEM certificates in one file's text, named after the file (one TSA per file). */
export function pemsFromText(file: string, text: string): { name: string; pem: string }[] {
  const name = file.replace(/\.(pem|crt)$/i, '');
  return [...text.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)].map((m) => ({ name, pem: m[0] + '\n' }));
}

export function readPemDir(dir: string): { name: string; pem: string }[] {
  const out: { name: string; pem: string }[] = [];
  for (const f of pemFileNames(dir)) out.push(...pemsFromText(f, readBundleFile(join(dir, f), 1024 * 1024, { followLinks: true }).toString('utf8')));
  if (out.length === 0) throw new Error(`${dir} holds no PEM certificates (*.pem, *.crt)`);
  return out;
}

// ───────────────────────────── stamp ─────────────────────────────

export interface StampResult {
  anchor_id: string;
  receipt_sha256: string;
  results: { tsa: string; url: string; ok: boolean; file: string | null; gen_time: string | null; problem: string | null; existing: boolean }[];
  /**
   * The /3 freeze nonce over this receipt and every token for it now in out_dir (freezeNonce), when
   * there are two or more: what the runs after a freeze record as `nonce`. Stamp every TSA first: a
   * token added later changes it.
   */
  nonce: string | null;
  /** `<anchor_id>.<tsa>.pending` markers left in out_dir for the TSAs that failed (only with `allow_pending`). */
  pending: string[];
}

/** Ask one TSA for a token over `message`; the reply is checked against the request. */
async function fetchStamp(message: Buffer | string, t: { name: string; url: string }, doFetch: typeof fetch, timeoutMs: number): Promise<{ body: Buffer; gen_time: string }> {
  const req = timestampRequest(message);
  const res = await doFetch(t.url, {
    method: 'POST',
    headers: { 'content-type': 'application/timestamp-query', accept: 'application/timestamp-reply' },
    body: new Uint8Array(req.der),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const body = Buffer.from(await res.arrayBuffer());
  const info = checkTimestampReply(body, req);
  return { body, gen_time: info.gen_time };
}

/** RFC 3161 tokens over sha256(receipt) for one anchor (the latest by default), written to `out_dir`. */
export async function stampAnchor(
  store: KronicleLite,
  opts: {
    anchor_id?: string;
    out_dir: string;
    tsas?: readonly { name: string; url: string }[];
    fetch?: typeof fetch;
    timeoutMs?: number;
    /** 0.11.1: record a TSA that failed as a `.pending` marker (which verify-audit's audit profile rejects). Default: no marker. */
    allow_pending?: boolean;
  },
): Promise<StampResult> {
  const chainId = chainIdFromPublicKeyPem(store.identity.signer.public_key_pem);
  const mine = store.chain.listAnchors().filter((a) => a.chain_id === chainId);
  const row = opts.anchor_id ? mine.find((a) => a.anchor_id === opts.anchor_id) : [...mine].sort((a, b) => a.to_seq - b.to_seq || a.received_at.localeCompare(b.received_at)).pop();
  if (!row) throw new AuditError('invalid_audit_event', opts.anchor_id ? `no anchor ${opts.anchor_id} for this store's chain` : 'no anchors yet: run `kronicle-lite checkpoint --push` first');
  const receipt = row.receipt_json;
  const digest = sha256Hex(receipt);
  mkdirSync(opts.out_dir, { recursive: true, mode: 0o700 });
  const doFetch = opts.fetch ?? fetch;
  const out: StampResult = { anchor_id: row.anchor_id, receipt_sha256: digest, results: [], nonce: null, pending: [] };
  for (const t of opts.tsas ?? DEFAULT_TSAS) {
    const file = join(opts.out_dir, `${row.anchor_id}.${t.name}.tsr`);
    const marker = join(opts.out_dir, `${row.anchor_id}.${t.name}${PENDING_SUFFIX}`);
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
    try {
      const got = await fetchStamp(receipt, t, doFetch, opts.timeoutMs ?? 20_000);
      writeNew(file, got.body);
      rmSync(marker, { force: true });
      out.results.push({ tsa: t.name, url: t.url, ok: true, file, gen_time: got.gen_time, problem: null, existing: false });
    } catch (err) {
      const problem = err instanceof Error ? err.message : String(err);
      if (opts.allow_pending === true) {
        // Asked for: leave the failure in the directory; the package carries it and the audit profile fails until it is stamped.
        writeFileSync(marker, `${t.url}: ${problem}\n`, { mode: 0o644 });
        out.pending.push(marker);
      }
      out.results.push({ tsa: t.name, url: t.url, ok: false, file: null, gen_time: null, problem, existing: false });
    }
  }
  const tokens = readdirSync(opts.out_dir)
    .map((f) => f.match(/^(.+)\.([a-z0-9][a-z0-9-]{0,31})\.tsr$/))
    .filter((m): m is RegExpMatchArray => m !== null && (m[1] === row.anchor_id || m[1] === digest))
    .map((m) => ({ tsa: m[2]!, bytes: readBundleFile(join(opts.out_dir, m[0]), MAX_TSR_BYTES) }));
  if (tokens.length >= 2) out.nonce = freezeNonce(digest, tokens);
  return out;
}

/** RFC 3161 tokens over a pack's SHA256SUMS, written as SHA256SUMS.<tsa>.tsr (after SHA256SUMS and its signature). */
export async function stampSums(packDir: string, opts: { tsas?: readonly { name: string; url: string }[]; fetch?: typeof fetch; timeoutMs?: number } = {}): Promise<{ tsa: string; ok: boolean; file: string | null; gen_time: string | null; problem: string | null }[]> {
  const sums = readBundleFile(join(packDir, 'SHA256SUMS'), 16 * 1024 * 1024);
  const out: { tsa: string; ok: boolean; file: string | null; gen_time: string | null; problem: string | null }[] = [];
  for (const t of opts.tsas ?? DEFAULT_TSAS) {
    const file = join(packDir, `SHA256SUMS.${t.name}.tsr`);
    try {
      const got = await fetchStamp(sums, t, opts.fetch ?? fetch, opts.timeoutMs ?? 20_000);
      writeNew(file, got.body);
      out.push({ tsa: t.name, ok: true, file, gen_time: got.gen_time, problem: null });
    } catch (err) {
      out.push({ tsa: t.name, ok: false, file: null, gen_time: null, problem: err instanceof Error ? err.message : String(err) });
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
  /** The profile the pack was checked under: audit for a /3 bundle, legacy otherwise. */
  profile: Profile;
  /** RFC 3161 tokens over SHA256SUMS (empty when not asked for). */
  sums_stamps: { tsa: string; ok: boolean; file: string | null; gen_time: string | null; problem: string | null }[];
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
    /** The reproducers' public keys (allowed-signers text), written as allowed_signers. */
    allowed_signers?: string;
    /**
     * A freeze made with the anchor pending (A8): the folder holding its pending-freeze record
     * (freeze-pending.json, SHA256SUMS, checkpoint.json, manifest.json, plan-detail.json and the
     * SHA256SUMS.<tsa>.tsr tokens), copied into the pack as freeze-pending/ and listed in SHA256SUMS.
     */
    freeze_pending_dir?: string;
    /** Stamp SHA256SUMS with these TSAs (the audit profile needs two). Absent: no tokens over SHA256SUMS. */
    stamp_sums?: { tsas?: readonly { name: string; url: string }[]; fetch?: typeof fetch; timeoutMs?: number };
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

  const tokenFiles = opts.timestamps_dir ? readdirSync(opts.timestamps_dir).filter((f) => f.endsWith('.tsr') || f.endsWith(PENDING_SUFFIX)) : [];
  const anchors: PackageAnchor[] = [];
  const width = Math.max(2, String(picked.length).length);
  for (const [i, a] of picked.entries()) {
    const base = `${String(i + 1).padStart(width, '0')}-${milestoneLabel(store, a.to_seq)}`;
    const digest = sha256Hex(a.receipt_json);
    writeNew(join(anchorsDir, `${base}.receipt.json`), a.receipt_json);
    const pa: PackageAnchor = { file: `${base}.receipt.json`, anchor_id: a.anchor_id, from_seq: a.from_seq, to_seq: a.to_seq, root: a.root, received_at: a.received_at, receipt_sha256: digest, timestamps: [] };
    for (const f of tokenFiles) {
      const pend = f.match(/^(.+)\.([a-z0-9][a-z0-9-]{0,31})\.pending$/);
      if (pend && (pend[1] === a.anchor_id || pend[1] === digest)) {
        // A stamp that failed stays visible in the pack (verify-audit fails while it is there).
        writeNew(join(anchorsDir, `${base}.${pend[2]}${PENDING_SUFFIX}`), readBundleFile(join(opts.timestamps_dir!, f), 64 * 1024, { followLinks: true }));
        continue;
      }
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
  const rootFiles = packTsaRootFiles(opts.tsa_roots ?? []);
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
  if (opts.allowed_signers !== undefined) {
    const as = parseAllowedSigners(opts.allowed_signers);
    if (as.entries.length === 0) throw new AuditError('invalid_audit_event', `--allowed-signers lists no usable key${as.problems.length ? ` (${as.problems[0]})` : ''}`);
    writeNew(join(out, ALLOWED_SIGNERS_FILE), opts.allowed_signers.endsWith('\n') ? opts.allowed_signers : `${opts.allowed_signers}\n`);
  }
  if (opts.freeze_pending_dir !== undefined) {
    const src = opts.freeze_pending_dir;
    const names = readdirSync(src).filter((f) => isFreezePendingFile(f)).sort();
    if (!names.includes(FREEZE_PENDING_RECORD)) throw new AuditError('invalid_audit_event', `--freeze-pending ${src} holds no ${FREEZE_PENDING_RECORD}`);
    const got = new Map(names.map((f) => [f, readBundleFile(join(src, f), 16 * 1024 * 1024, { followLinks: true })] as const));
    const p = parseFreezePending(got, 'pack_dir');
    if (typeof p === 'string') throw new AuditError('invalid_audit_event', `--freeze-pending ${src}: ${p}`);
    mkdirSync(join(out, FREEZE_PENDING_DIR), { mode: 0o755 });
    for (const [f, b] of got) writeNew(join(out, FREEZE_PENDING_DIR, f), b);
  }
  const v3 = m.format === BUNDLE_FORMAT_V3;
  const profile: Profile = v3 ? 'audit' : 'legacy';
  const sumsTsas = opts.stamp_sums ? (opts.stamp_sums.tsas ?? DEFAULT_TSAS) : [];

  // Which claims the store's contents support: check all of them once, declare what holds.
  const trustOpts: VerifyAuditOptions = {
    key_pem: signer.public_key_pem,
    ...(opts.genesis !== undefined ? { genesis: opts.genesis } : {}),
    ...(opts.tsa_roots ? { tsa_roots: [...SHIPPED_TSA_ROOTS.map((r) => ({ name: r.name, pem: r.pem })), ...opts.tsa_roots] } : {}),
    ...(opts.now ? { now: opts.now } : {}),
    // The packager is an anchor client too: its data dir keeps the key list it has seen (an in-memory store opts out, and says so).
    ...(store.dataDir !== null ? { seen_dir: store.dataDir } : { rollback: 'off' as const }),
  };
  const probe = verifyAudit(out, { ...trustOpts, profile, claims_override: v3 ? CLAIMS : LEGACY_CLAIMS });
  // Files inside the pack never carry trust values (the auditor fingerprint, a genesis pin): a forger
  // would write their own. They name where the reader gets them; a self-hosted service needs its pin.
  const genesisArg = opts.genesis !== undefined ? ' --genesis <the anchor service genesis pin, sha256@valid_from, from its operator>' : '';
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
    // The 0.11.0 claims: a /3 bundle only (an older pack is verified under --profile legacy).
    ...(v3
      ? [
          { claim: 'plan_complete' as const, declared: probe.plan.status === 'pass', why: probe.plan.status === 'pass' ? `${probe.plan.planned.length} planned run(s), each ended once` : (probe.plan.problem ?? 'not shown') },
          {
            claim: 'reproductions_signed' as const,
            declared: probe.claims.find((c) => c.claim === 'reproductions_signed')?.status === 'pass',
            why: probe.claims.find((c) => c.claim === 'reproductions_signed')?.evidence || 'not shown',
          },
          { claim: 'closed' as const, declared: probe.closed.status === 'pass', why: probe.closed.status === 'pass' ? `closed at seq ${probe.closed.seq}` : (probe.closed.problem ?? 'not shown') },
        ]
      : [{ claim: 'plan_complete' as const, declared: false, why: `a ${m.format} bundle (no run plan, sign-offs or close; ${BUNDLE_FORMAT_V3} needed)` }]),
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
  // The bundle root counts as anchored only when the last anchor commits it (the test verify-audit uses for its final root).
  const finalAnchored = last !== undefined && last.to_seq === m.range.to_seq && last.root === m.root.root;
  const rootLabel = finalAnchored ? 'Final anchored root' : 'Final root';
  const tagline = claims.claims.includes('independent_timestamps') ? 'Tamper-evident, independently timestamped audit evidence.' : 'Tamper-evident audit evidence.';
  const keyLine = `${signer.key_id} (compare its SPKI SHA-256 with the fingerprint in your statement of work)`;
  const finalTimes = last ? (last.timestamps.length ? last.timestamps.map((t) => `${t.gen_time} (${t.tsa})`).join(', ') : `${last.received_at} (anchor service)`) : '-';
  writeNew(
    join(out, 'COMPLETION.txt'),
    [
      `${PACK_NAME}: ${opts.audit_id}`,
      tagline,
      '',
      `Audit ID              ${opts.audit_id}`,
      `Manifest SHA-256      ${exp.manifest_sha256}`,
      `Signing key           ${keyLine}`,
      `${rootLabel.padEnd(22)}${m.root.root}`,
      `  covering            seq ${m.range.from_seq}..${m.range.to_seq} (${m.events.length} audit event(s), ${m.blobs.length} artifact(s))`,
      // Never call a root anchored that no anchor commits: an earlier last anchor gets its own line.
      ...(last && !finalAnchored ? [`${'Last anchored root'.padEnd(22)}${last.root} (seq ${last.from_seq}..${last.to_seq})`] : []),
      ...(last
        ? [`  anchor              ${last.file.replace(/\.receipt\.json$/, '')}, ${last.anchor_id}, received ${last.received_at}`, `  timestamps          ${finalTimes}`]
        : []),
      ...(anchors.length > 0
        ? ['Milestones', ...anchors.map((a) => `  ${a.file.replace(/\.receipt\.json$/, '').padEnd(26)} seq ${a.from_seq}..${a.to_seq}  ${a.timestamps.length ? a.timestamps.map((t) => `${t.tsa} ${t.gen_time}`).join(', ') : `anchor service ${a.received_at}`}`)]
        : ['Anchors               none (this pack has no anchor receipts)']),
      `Claims                ${claims.claims.join(', ')}`,
      // A8: a freeze made with the anchor pending says so, with the window no third party saw.
      ...(probe.late_anchor.status === 'accepted' && probe.late_anchor.window
        ? [
            `Freeze anchor         LATE: frozen with the anchor pending (stamped ${probe.late_anchor.freeze_stamped.map((t) => `${t.gen_time ?? '?'} ${t.tsa}`).join(', ')}), anchored later by ${probe.late_anchor.anchor?.file.replace(/\.receipt\.json$/, '') ?? '?'}`,
            `  unwitnessed window  ${probe.late_anchor.window.from} → ${probe.late_anchor.window.to} (${formatDuration(probe.late_anchor.window.ms)}): ${probe.late_anchor.window.runs} run(s) recorded before any third party held the chain; verify-audit reports ${LATE_ANCHOR_RESULT}`,
          ]
        : []),
      '',
      `Verify:  npx -y kronicle-lite@${VERSION} verify-audit <this directory> --key-fingerprint <auditor key fingerprint from your statement of work>${genesisArg}${profile === 'legacy' ? ' --profile legacy' : ''}`,
      '         (this file does not carry the fingerprint: take it from the statement of work, never from the pack)',
      'Raw commands without kronicle-lite: VERIFY.md',
      '',
    ].join('\n'),
  );
  // The root file each TSA's tokens verify under (by label), for the SHA256SUMS commands.
  const rootOfTsa = new Map<string, string>();
  for (const a of anchors) for (const t of a.timestamps) if (!rootOfTsa.has(t.tsa)) rootOfTsa.set(t.tsa, rootFor.get(t.file) ?? `${t.tsa}.pem`);
  const freezeAnchor = v3 ? anchors.find((a) => a.file.includes('-harness-frozen.')) : undefined;
  // A freeze made with the anchor pending: the runs carry the record's nonce, not one derived from an
  // anchor receipt, so VERIFY.md derives that one (from the record's SHA256SUMS and tokens) instead.
  const pending = v3 ? pendingFreezeForVerifyMd(out, rootFiles) : null;
  writeNew(
    join(out, 'VERIFY.md'),
    verifyMd({
      audit_id: opts.audit_id,
      tagline,
      keyLine,
      manifestSha: exp.manifest_sha256,
      rootLabel,
      root: m.root.root,
      lastAnchored: last && !finalAnchored ? last : null,
      anchors,
      rootFor,
      claims: claims.claims,
      genesisArg,
      profile,
      sumsTsas: sumsTsas.map((t) => ({ tsa: t.name, root: rootOfTsa.get(t.name) ?? `${t.name}.pem` })),
      freezeAnchor: freezeAnchor ?? null,
      pending,
      lateAnchored: probe.late_anchor.status === 'accepted',
      signers: opts.allowed_signers !== undefined,
    }),
  );

  // SHA256SUMS over every file, and its raw Ed25519 signature by the auditor key (openssl pkeyutl checks it).
  const { files } = listPackFiles(out);
  const sums = sha256sums(out, files);
  writeNew(join(out, 'SHA256SUMS'), sums);
  writeNew(join(out, 'SHA256SUMS.sig'), Buffer.from(signer.sign(Buffer.from(sums, 'utf8')), 'base64'));
  // Then RFC 3161 over SHA256SUMS: the pack as a whole existed no later than these times.
  const sumsStamps = opts.stamp_sums ? await stampSums(out, { tsas: sumsTsas, ...(opts.stamp_sums.fetch ? { fetch: opts.stamp_sums.fetch } : opts.fetch ? { fetch: opts.fetch } : {}), ...(opts.stamp_sums.timeoutMs ? { timeoutMs: opts.stamp_sums.timeoutMs } : {}) }) : [];

  const check = verifyAudit(out, { ...trustOpts, profile });
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
    profile,
    sums_stamps: sumsStamps,
    check,
  };
}

/**
 * The pack's tsa-roots/ files: one per shipped TSA (its CAs that `openssl ts -verify -partial_chain`
 * accepts, see ShippedTsaCa.in_pack), then each custom root that is not a shipped one.
 */
export function packTsaRootFiles(custom: readonly TsaRoot[] = []): { file: string; pems: string[] }[] {
  const files: { file: string; pems: string[] }[] = [];
  for (const r of SHIPPED_TSA_ROOTS) {
    if (r.in_pack === false) continue;
    const f = files.find((x) => x.file === `${r.name}.pem`);
    if (f) f.pems.push(r.pem);
    else files.push({ file: `${r.name}.pem`, pems: [r.pem] });
  }
  let n = 0;
  for (const r of custom) {
    const pem = typeof r === 'string' ? r : r.pem;
    if (SHIPPED_TSA_ROOTS.some((x) => x.pem.trim() === pem.trim()) || files.some((x) => x.pems.some((y) => y.trim() === pem.trim()))) continue;
    files.push({ file: `custom-${++n}.pem`, pems: [pem] });
  }
  return files;
}

const epoch = (iso: string) => Math.floor(Date.parse(iso) / 1000);

/** Where VERIFY.md finds a pending-freeze record, and the pinned root file for each of its tokens. */
interface PendingForVerifyMd {
  /** The pack's freeze-pending/ folder, or the report_issued archive blob holding it. */
  source: 'pack_dir' | 'report_archive';
  archive: string | null;
  tokens: { tsa: string; file: string; root: string }[];
}

function pendingFreezeForVerifyMd(out: string, rootFiles: { file: string; pems: string[] }[]): PendingForVerifyMd | null {
  const reports: string[] = [];
  for (const line of readFileSync(join(out, 'bundle', 'events.jsonl'), 'utf8').split('\n')) {
    if (!line) continue;
    const e = JSON.parse(line) as { event_type?: unknown; payload?: { report?: { sha256?: unknown } } };
    if (e.event_type === 'audit.report_issued' && typeof e.payload?.report?.sha256 === 'string') reports.push(e.payload.report.sha256);
  }
  const p = findFreezePending(out, reports);
  if (p === null || 'problem' in p) return null;
  return {
    source: p.source,
    archive: p.archive_sha256 ?? null,
    tokens: [...p.tokens]
      .sort((a, b) => (a.tsa < b.tsa ? -1 : a.tsa > b.tsa ? 1 : 0))
      .map((t) => ({ tsa: t.tsa, file: t.file, root: rootFiles.find((r) => verifyTimestamp(t.bytes, { message: p.sums, roots: r.pems, at: 'gentime' }).ok)?.file ?? `${t.tsa}.pem` })),
  };
}

function verifyMd(v: {
  audit_id: string;
  tagline: string;
  keyLine: string;
  manifestSha: string;
  rootLabel: string;
  root: string;
  lastAnchored: PackageAnchor | null;
  anchors: PackageAnchor[];
  rootFor: Map<string, string>;
  claims: readonly Claim[];
  genesisArg: string;
  profile: Profile;
  sumsTsas: { tsa: string; root: string }[];
  freezeAnchor: PackageAnchor | null;
  pending: PendingForVerifyMd | null;
  lateAnchored: boolean;
  signers: boolean;
}): string {
  const a0 = v.anchors[0];
  const stamped = v.anchors.filter((a) => a.timestamps.length > 0);
  let n = 0;
  const h3 = (title: string) => `### ${++n}. ${title}`;
  // Sections are numbered in the order they print.
  const filesSection = [
    h3('Files: SHA256SUMS and its signature'),
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
    ...(v.sumsTsas.length
      ? [
          'SHA256SUMS itself is timestamped (it is not listed in itself, nor are its tokens):',
          '',
          '```sh',
          ...v.sumsTsas.map((t) => `openssl ts -verify -data SHA256SUMS -in SHA256SUMS.${t.tsa}.tsr -CAfile tsa-roots/${t.root} -partial_chain`),
          '```',
          '',
        ]
      : []),
  ];
  const P = v.pending?.source === 'report_archive' ? 'freeze-pending-record' : FREEZE_PENDING_DIR;
  const pendingSection = v.pending
    ? [
        h3('The freeze nonce every run carries (freeze made with the anchor pending)'),
        '',
        'The harness was frozen with the anchor pending, so the runs do not carry a nonce derived from an',
        'anchor receipt: they carry the nonce of the pending-freeze record. That record is an auditor-signed',
        'checkpoint of the chain up to the freeze, the frozen manifest and plan detail, their `SHA256SUMS`,',
        'and an RFC 3161 token over that `SHA256SUMS` from each timestamp authority. The nonce is SHA-256',
        'over the SHA-256 of the record\'s `SHA256SUMS` (32 bytes) followed by every token over it, in byte',
        'order of the TSA name; nobody could know it before the authorities signed. Each `run_completed`',
        'and `call_measured` in `bundle/events.jsonl` must record it as `nonce`.',
        '',
        ...(v.pending.source === 'report_archive'
          ? [
              `The record is inside the report archive \`bundle/blobs/${v.pending.archive}\` (a ustar archive, on the chain),`,
              `as \`${REPORT_ARCHIVE_PREFIX}<file>\`. The first commands copy it out to \`${P}/\`.`,
              '',
            ]
          : [`The record is in \`${P}/\` (listed in the pack's SHA256SUMS).`, '']),
        '```sh',
        ...(v.pending.source === 'report_archive'
          ? [
              `mkdir -p ${P}.x ${P} && tar -xf bundle/blobs/${v.pending.archive} -C ${P}.x`,
              `for f in ${P}.x/${REPORT_ARCHIVE_PREFIX}*; do cp "$f" "${P}/\${f##*/${REPORT_ARCHIVE_PREFIX}}"; done`,
            ]
          : []),
        '# the stamped files match the record\'s SHA256SUMS',
        `(cd ${P} && shasum -a 256 -c SHA256SUMS)`,
        '# each authority stamped that SHA256SUMS',
        ...v.pending.tokens.map((t) => `openssl ts -verify -data ${P}/SHA256SUMS -in ${P}/${t.file} -CAfile tsa-roots/${t.root} -partial_chain`),
        '# the checkpoint at the freeze is signed by the auditor key',
        `jq -cjS '{v: ${CHECKPOINT_VERSION}, from_seq, to_seq, leaf_count, root}' ${P}/checkpoint.json > pending-checkpoint-body.bin`,
        `jq -r .signature ${P}/checkpoint.json | openssl base64 -d -A > pending-checkpoint.sig`,
        'openssl pkeyutl -verify -pubin -inkey auditor-key.pem -rawin -in pending-checkpoint-body.bin -sigfile pending-checkpoint.sig',
        '# the nonce, then the nonces the runs carry (one line, the same value)',
        `D=$(shasum -a 256 ${P}/SHA256SUMS | cut -c1-64)`,
        `{ printf %s "$D" | xxd -r -p; LC_ALL=C cat ${v.pending.tokens.map((t) => `${P}/${t.file}`).join(' ')}; } | shasum -a 256`,
        `jq -r 'select(.event_type == "audit.run_completed" or .event_type == "audit.call_measured") | .payload.nonce' bundle/events.jsonl | sort -u`,
        '```',
        '',
        'That the checkpoint root is the bundle\'s own Merkle root over seq 1..F, and that a timestamped',
        'anchor later commits the freeze and every run, follow kronicle-lite docs/FORMAT.md §2;',
        '`verify-audit` checks both and prints the window in which only the auditor\'s key held the chain.',
        '',
      ]
    : [];
  const nonceSection = !v.pending && v.freezeAnchor && v.freezeAnchor.timestamps.length >= 2
    ? [
        h3('The freeze nonce every run carries'),
        '',
        'The nonce is SHA-256 over the freeze receipt digest (32 bytes) followed by every timestamp token',
        'over that receipt, in byte order of the TSA name. The authorities sign the tokens at their own',
        'time, so nobody could know the nonce before the freeze was stamped. Each `run_completed` and',
        '`call_measured` in `bundle/events.jsonl` must record it as `nonce`.',
        '',
        '```sh',
        `D=$(shasum -a 256 anchors/${v.freezeAnchor.file} | cut -c1-64)`,
        `{ printf %s "$D" | xxd -r -p; LC_ALL=C cat ${v.freezeAnchor.timestamps.map((t) => `anchors/${t.file}`).join(' ')}; } | shasum -a 256`,
        `jq -r 'select(.event_type == "audit.run_completed" or .event_type == "audit.call_measured") | .payload.nonce' bundle/events.jsonl | sort -u`,
        '```',
        '',
      ]
    : [];
  const signersSection = v.signers
    ? [
        h3('Human sign-offs'),
        '',
        'Each `reproduction_signed` event carries an SSH signature (`ssh-keygen -Y sign -n kronicle-lite-reproduction`)',
        'over the statement `verify-audit` rebuilds from the event; `allowed_signers` lists the reproducers\' keys.',
        'Compare those keys with the ones the reproducers gave you, then check one sign-off (the first here):',
        '',
        '```sh',
        `P=$(jq -c 'select(.event_type == "audit.reproduction_signed") | .payload' bundle/events.jsonl | head -1)`,
        `{ echo "$P" | jq -cjS '{format: "kronicle-lite-reproduction/1", audit_id, finding_id, signer, reproduced_at, commands: .commands.sha256, output: .output.sha256}'; echo; } > statement.json`,
        'cp "bundle/blobs/$(echo "$P" | jq -r .signature.sha256)" statement.sig',
        'ssh-keygen -Y verify -f allowed_signers -I "$(echo "$P" | jq -r .signer)" -n kronicle-lite-reproduction -s statement.sig < statement.json',
        '```',
        '',
      ]
    : [];
  const tokenSection = stamped.length
    ? [
        h3('Independent time: each RFC 3161 token'),
        '',
        'Each token stamps the SHA-256 of its receipt file and embeds the timestamp authority\'s certificate',
        'chain. `tsa-roots/` holds the pinned timestamping CAs (not the general public roots):',
        '`sectigo.pem` is Sectigo Public Time Stamping Root R46 as issued by USERTrust RSA Certification',
        'Authority (the form Sectigo\'s tokens embed), `digicert.pem` the DigiCert Trusted G4 TimeStamping',
        'CAs. `-partial_chain` lets openssl stop at a pinned CA that is not self-signed. Check the',
        'fingerprints against the authorities\' sites (`openssl crl2pkcs7 -nocrl -certfile tsa-roots/digicert.pem | openssl pkcs7 -print_certs -noout`,',
        'then `openssl x509 -noout -fingerprint -sha256` on each).',
        '',
        '```sh',
        ...stamped.flatMap((a) => [
          `D=$(shasum -a 256 anchors/${a.file} | cut -c1-64)`,
          ...a.timestamps.map((t) => `openssl ts -verify -digest $D -in anchors/${t.file} -CAfile tsa-roots/${v.rootFor.get(t.file)} -partial_chain`),
          ...a.timestamps.slice(0, 1).map((t) => `openssl ts -reply -in anchors/${t.file} -text | grep 'Time stamp'`),
        ]),
        '```',
        '',
      ]
    : [];
  const receiptSection = a0
    ? [
        h3('Anchor receipts: Ed25519 signatures'),
        '',
        'The anchor service signed each receipt over its canonical JSON without `signature`; the',
        'checkpoint inside it is signed by the auditor key. With `jq -cjS` (sorted keys, compact, no',
        'trailing newline) the bytes equal the canonical form for these ASCII, integer-only objects.',
        '',
        '```sh',
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
        '```',
        '',
        'Recomputing each anchored root from `bundle/events.jsonl` follows kronicle-lite docs/FORMAT.md §2',
        '(leaf = sha256 of the canonical `{seq, this_hash}`, node = sha256(left ‖ right), an odd node is',
        'promoted); `verify-audit` does it for you.',
        '',
      ]
    : [];
  // Never an empty section: a pack without anchors, or without tokens, says so in one line.
  const absent = !a0
    ? ['This pack has no anchor receipts, so it carries no anchor signatures or RFC 3161 timestamp tokens to check.', '']
    : !stamped.length
      ? ['This pack has no RFC 3161 timestamp tokens.', '']
      : [];
  return [
    `# ${PACK_NAME}: ${v.audit_id}`,
    '',
    `${v.tagline} Every check below runs offline on`,
    'this directory. The one-command route uses kronicle-lite (open source); the raw route uses only',
    '`shasum` / `openssl` / `jq`.',
    '',
    `- Manifest SHA-256: \`${v.manifestSha}\``,
    `- Signing key: \`${v.keyLine}\``,
    `- ${v.rootLabel}: \`${v.root}\``,
    ...(v.lastAnchored ? [`- Last anchored root: \`${v.lastAnchored.root}\` (seq ${v.lastAnchored.from_seq}..${v.lastAnchored.to_seq})`] : []),
    `- Claims: ${v.claims.join(', ')}`,
    '',
    'This file does not carry the auditor key fingerprint: take it from your statement of work, never',
    'from the pack, and compare `auditor-key.pem` with it before you rely on anything else here.',
    '',
    '## One command',
    '',
    '```sh',
    `npx -y kronicle-lite@${VERSION} verify-audit . --key-fingerprint <the auditor key fingerprint from your statement of work>${v.genesisArg}${v.profile === 'legacy' ? ' --profile legacy' : ''}`,
    '```',
    '',
    'It pins the auditor key by the fingerprint you give it, verifies SHA256SUMS before it reads',
    ...(v.profile === 'audit'
      ? [
          '`claims.json`, checks every claim of the audit profile (whatever `claims.json` says), and prints',
          'PASS or FAIL for each with its evidence, then the values to compare with the completion letter',
          'you were sent. Exit 0 (VERIFIED) means every claim was checked and passed.',
          ...(v.lateAnchored
            ? [
                '',
                `This pack's freeze was made with the anchor pending and anchored later: the result is`,
                `\`${LATE_ANCHOR_RESULT}\` (exit 0), never the plain \`VERIFIED\`, and the`,
                'report prints the unwitnessed window, in which only the auditor\'s key held the chain.',
                '`--strict-freeze` refuses such a pack.',
              ]
            : []),
        ]
      : [
          '`claims.json`, always checks integrity and chain, then the claims in `claims.json`, and prints',
          'PASS or FAIL for each with its evidence, then the values to compare with the completion letter',
          'you were sent. This pack was made without the 0.11.0 audit profile (no run plan, sign-offs or',
          'close): verify it with `--profile legacy`; the best result is PARTIAL (exit 2).',
        ]),
    '',
    '## Without kronicle-lite',
    '',
    'Needs OpenSSL 3 (macOS: `brew install openssl@3`; LibreSSL lacks raw Ed25519 verification) and `jq`.',
    '',
    ...filesSection,
    ...absent,
    ...tokenSection,
    ...nonceSection,
    ...pendingSection,
    ...receiptSection,
    ...signersSection,
    ...(stamped.length
      ? [
          '## Re-verifying in later years',
          '',
          'Timestamp authority certificates expire, and `openssl ts -verify` checks them at the current time',
          'by default. After expiry, verify each token at its own genTime against the same pinned roots:',
          '',
          '```sh',
          ...stamped.flatMap((a) =>
            a.timestamps.map((t) => `openssl ts -verify -digest $(shasum -a 256 anchors/${a.file} | cut -c1-64) -in anchors/${t.file} -CAfile tsa-roots/${v.rootFor.get(t.file)} -partial_chain -attime ${epoch(t.gen_time)}   # ${t.gen_time}`),
          ),
          '```',
          '',
          `or \`kronicle-lite verify-audit . --key-fingerprint <fingerprint>${v.genesisArg} --tsa-at-gentime\`. Keep this directory`,
          'whole: the tokens carry the TSA chains and `tsa-roots/` the roots they verify against.',
          '',
        ]
      : []),
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
  for (const t of r.sums_stamps) L.push(`SHA256SUMS     RFC 3161 ${t.tsa.padEnd(10)} ${t.ok ? t.gen_time : `FAIL ${t.problem}`}`);
  const bad = r.check.checks.filter((c) => c.status === 'fail');
  L.push('');
  const passed = r.check.claims.filter((c) => c.status === 'pass').map((c) => c.claim).join(', ');
  const la = r.check.late_anchor;
  if (r.check.verdict === 'verified') L.push(`verify-audit   VERIFIED (${r.profile} profile)  ${passed}`);
  else if (r.check.verdict === 'verified_late_anchor') {
    L.push(`verify-audit   ${LATE_ANCHOR_RESULT} (${r.profile} profile)  ${passed}`);
    if (la.window) {
      L.push(
        `  unwitnessed window  ${la.window.from} → ${la.window.to} (${formatDuration(la.window.ms)}): ${la.window.seqs ? `seq ${la.window.seqs.from}..${la.window.seqs.to} (${la.window.events} event(s), ${la.window.runs} run(s))` : 'no events'} held only by the auditor's key until ${la.anchor?.file.replace(/\.receipt\.json$/, '') ?? 'the late anchor'}`,
      );
    }
  }
  else if (r.check.verdict === 'partial') L.push(`verify-audit   PARTIAL (${r.profile} profile: an older bundle format; verify with --profile legacy)  ${passed}`);
  else {
    L.push(`verify-audit   FAIL (${r.profile} profile, ${r.check.failed} failed check(s))`);
    for (const c of bad) L.push(`  FAIL  ${c.subject ? `${c.subject} ` : ''}${c.check}: ${c.evidence}`);
  }
  return L.join('\n') + '\n';
}
