/**
 * `kronicle-lite verify-audit PACK` (0.10.0): offline verification of an
 * IsoKron Evidence Pack, tamper-evident, independently timestamped audit
 * evidence (docs/EVIDENCE-BUNDLE.md "Evidence packs"):
 *
 *   PACK/claims.json                       what the pack claims (the verification policy)
 *   PACK/SHA256SUMS, SHA256SUMS.sig        sha256 of every other file; raw Ed25519 signature by the auditor key
 *   PACK/bundle/                           evidence bundle (manifest.json signed, events.jsonl, blobs/)
 *   PACK/anchors/NN-<label>.receipt.json   anchor receipt, canonical JSON; sha256(file) is the stamped digest
 *   PACK/anchors/NN-<label>.<tsa>.tsr      RFC 3161 timestamp reply over sha256(receipt file)
 *   PACK/auditor-key.pem                   auditor public key (pin it with --key from the report or SOW)
 *   PACK/anchor-keys.json                  anchor service keys: rotation candidates only, never a trust root
 *   PACK/tsa-roots/*.pem                   TSA roots for the openssl path; never a trust root here
 *   PACK/COMPLETION.txt, VERIFY.md         values for the report, raw verification commands
 *
 * Claims and the checks behind each:
 *   integrity                   SHA256SUMS (signature, every file) and the bundle's canonical / signature /
 *                               events / artifacts / refs / missing steps, under the auditor key
 *   chain                       the bundle's chain and signed Merkle root
 *   receipts                    each receipt: canonical, countersigned by a TRUSTED anchor service key valid at
 *                               received_at, checkpoint signed by the auditor key, root equal to the Merkle root
 *                               recomputed from the bundle; anchors extend each other; every audit event committed
 *   independent_timestamps      each RFC 3161 token (src/audit/rfc3161.ts) against the trusted TSA roots; every
 *                               anchor stamped
 *   harness_frozen_before_runs  the freeze event is committed by an anchor that covers no run, every run names the
 *                               frozen harness digest, and every run carries the freeze nonce or a measured_at
 *                               after the freeze anchor's time
 *   run_sequence                run_completed.run_seq is 1..N with no gap or repeat, N agrees with every declared
 *                               count (planned_runs at freeze, the report's run_count, claims.json), and the
 *                               interruptions claims.json lists are the runs whose capture was interrupted
 *
 * Exactly the declared claims are checked (plus any the caller requires); the
 * rest are reported as not declared. Trust comes from the package source or
 * the operator, never from the pack: anchor service keys are the shipped pins
 * (SHIPPED_SERVICE_KEYS) or an explicit --anchor-keys file, plus successors
 * those keys sign; TSA roots are SHIPPED_TSA_ROOTS or an explicit --tsa-roots
 * directory. Hostile input yields failed checks, never a throw.
 */

import { createPublicKey, X509Certificate } from 'node:crypto';
import { lstatSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { join } from 'node:path';

import { z } from 'zod';

import { isUsableEd25519PublicKeyPem, verifyEd25519Strict } from '../anchor/ed25519-strict.js';
import { parseAnchorReceipt, verifyAnchorReceiptSignature, type AnchorReceipt } from '../anchor/receipt.js';
import { serviceKeyIdFromPem, serviceKeyRefusal, SHIPPED_SERVICE_KEYS, successorSigningPayload } from '../anchor/trust.js';
import { isJsonObject } from '../anchor/wire.js';
import { checkpointSigningPayload } from '../chain/chain.js';
import { merkleRootHex } from '../chain/merkle.js';
import { canonicalize } from '../crypto/canonical.js';
import { sha256Hex } from '../crypto/hash.js';
import { chainIdFromPublicKeyPem, keyIdFromPublicKey } from '../crypto/keys.js';
import { MAX_TSR_BYTES, verifyTimestamp } from './rfc3161.js';
import { kindOfEventType } from './schemas.js';
import { SHIPPED_TSA_ROOTS } from './tsa-roots.js';
import { DEFAULT_MAX_BUNDLE_BYTES, hashRegularFile, MAX_BUNDLE_BLOB_BYTES, MAX_MANIFEST_BYTES, readBundleFile, verifyBundle } from './verify-bundle.js';

export const VERIFY_AUDIT_FORMAT = 'kronicle-lite-verify-audit/1';
export const PACK_NAME = 'IsoKron Evidence Pack';
export const CLAIMS_FORMAT = 'isokron-evidence-pack-claims/1';
export const CLAIMS = ['integrity', 'chain', 'receipts', 'independent_timestamps', 'harness_frozen_before_runs', 'run_sequence'] as const;
export type Claim = (typeof CLAIMS)[number];
/** What a pack without claims.json is checked against. */
const DEFAULT_CLAIMS: readonly Claim[] = ['integrity', 'chain', 'receipts', 'independent_timestamps'];
const MAX_RECEIPT_BYTES = 64 * 1024;
const MAX_KEYDOC_BYTES = 1024 * 1024;
const MAX_SUMS_BYTES = 16 * 1024 * 1024;
const TSA_LABEL = /^[a-z0-9][a-z0-9-]{0,31}$/;
const RUN_KINDS = new Set(['call_measured', 'run_completed']);
/** Files of the pack that SHA256SUMS does not (cannot) list. */
export const SUMS_FILES = ['SHA256SUMS', 'SHA256SUMS.sig'] as const;
const SAFE_PATH = /^(?!.*(^|\/)\.\.?(\/|$))[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/;

/** The pack directory itself cannot be read (exit 2), as opposed to a pack that fails verification. */
export class VerifyAuditUsageError extends Error {
  override readonly name = 'VerifyAuditUsageError';
}

export const ClaimsFileSchema = z.strictObject({
  format: z.literal(CLAIMS_FORMAT),
  audit_id: z.string().min(1).max(128),
  claims: z.array(z.enum(CLAIMS)).refine((c) => new Set(c).size === c.length, 'claims listed twice'),
  runs: z
    .strictObject({
      count: z.number().int().nonnegative(),
      seqs: z.array(z.number().int().positive()).max(100_000),
      interruptions: z.array(z.strictObject({ run_seq: z.number().int().positive(), event_key: z.string(), note: z.string().nullable() })).max(100_000),
    })
    .optional(),
});
export type ClaimsFile = z.infer<typeof ClaimsFileSchema>;

export type CheckGroup = 'pack' | 'bundle' | 'anchor' | 'timestamp' | 'timeline' | 'ordering' | 'runs';
export type CheckStatus = 'pass' | 'fail' | 'not_applicable';
export type ClaimStatus = 'pass' | 'fail' | 'not_declared' | 'not_checked';

export interface AuditCheck {
  group: CheckGroup;
  /** The claim this check backs; null for the pack's structure (key, claims.json, anchors/ present). */
  claim: Claim | null;
  /** The receipt (NN-label) a check is about, or null. */
  subject: string | null;
  check: string;
  status: CheckStatus;
  /** What was checked: hashes, roots, keys, times; or why it failed. */
  evidence: string;
}

export interface ClaimResult {
  claim: Claim;
  status: ClaimStatus;
  /** Declared in claims.json (or required by the caller). */
  declared: boolean;
  required: boolean;
  evidence: string;
}

export interface AnchorTimestampReport {
  file: string;
  tsa: string;
  ok: boolean;
  gen_time: string | null;
  signer: string | null;
  root: string | null;
  problem: string | null;
}

export interface AnchorReport {
  file: string;
  label: string;
  anchor_id: string | null;
  from_seq: number | null;
  to_seq: number | null;
  root: string | null;
  received_at: string | null;
  service_key_id: string | null;
  receipt_sha256: string;
  /** Receipt checks all passed. */
  ok: boolean;
  timestamps: AnchorTimestampReport[];
}

export interface OrderingReport {
  status: 'pass' | 'fail' | 'not_declared';
  basis: 'freeze_nonce' | 'recorded_measured_at' | null;
  harness_digest: string | null;
  freeze: { seq: number; event_key: string | null; anchor: string | null; time: string | null; clock: 'tsa' | 'service' | null } | null;
  runs: { count: number; first_measured_at: string | null; last_measured_at: string | null; nonce_bound: number } | null;
  problem: string | null;
}

export interface RunSequenceReport {
  status: 'pass' | 'fail' | 'not_declared';
  count: number | null;
  seqs: number[];
  declared_counts: { source: 'planned_runs' | 'report_run_count' | 'claims.json'; count: number }[];
  interruptions: { run_seq: number; event_key: string | null; note: string | null }[];
  problem: string | null;
}

export interface TimelineEntry {
  seq: number;
  kind: string;
  event_key: string | null;
  measured_at: string | null;
  committed_by: string | null;
  no_later_than: string | null;
  clock: 'tsa' | 'service' | null;
}

export interface VerifyAuditResult {
  format: typeof VERIFY_AUDIT_FORMAT;
  ok: boolean;
  package: string;
  audit_id: string | null;
  bundle_format: string | null;
  /** sha256 of bundle/manifest.json (the value the report and COMPLETION.txt print). */
  manifest_sha256: string | null;
  auditor: { key_id: string | null; spki_sha256: string | null; source: 'pinned' | 'package' };
  trust: {
    service_keys: 'shipped' | 'file';
    service_key_ids: string[];
    tsa_roots: 'shipped' | 'dir' | 'skipped';
    tsa_root_sha256: string[];
    tsa_time: 'now' | 'gentime';
  };
  claims: ClaimResult[];
  checks: AuditCheck[];
  failed: number;
  anchors: AnchorReport[];
  ordering: OrderingReport;
  run_sequence: RunSequenceReport;
  timeline: TimelineEntry[];
  final: {
    root: string;
    from_seq: number;
    to_seq: number;
    manifest_sha256: string | null;
    anchor: string;
    service_time: string;
    tsa_times: { tsa: string; gen_time: string }[];
  } | null;
}

export interface VerifyAuditOptions {
  /** Auditor public key (PEM) pinned out of band; without it PACK/auditor-key.pem is used. */
  key_pem?: string;
  /** Anchor service key document ({keys: [...]}, the /.well-known/anchor-keys.json shape) trusted instead of the shipped pins. */
  anchor_keys?: unknown;
  /** Trusted TSA roots (PEMs) instead of the shipped ones. */
  tsa_roots?: string[];
  /** Skip RFC 3161 tokens (independent_timestamps is then reported as not checked; times come from the anchor service). */
  no_tsa?: boolean;
  /** Check TSA certificate validity at genTime instead of now (certificates that expired since the stamp). */
  tsa_at?: 'now' | 'gentime';
  /** Claims the caller requires: one the pack does not declare fails. */
  require?: Claim[];
  /** Check exactly these claims, ignoring claims.json (the packager's own pass, before claims.json exists). */
  claims_override?: readonly Claim[];
  /** Clock (tests). */
  now?: Date;
  max_bytes?: number;
  allow_hardlinks?: boolean;
}

// ───────────────────────────── trust ─────────────────────────────

interface TrustedKey {
  key_id: string;
  public_key_pem: string;
  status: string;
  valid_from: string | null;
  valid_to: string | null;
  source: 'shipped' | 'file' | 'successor';
  signed_by: string | null;
}

interface KeyEntry {
  key_id: string;
  public_key_pem: string;
  status: string;
  valid_from: string | null;
  valid_to: string | null;
  successor_signature: string | null;
  signed_by: string | null;
}

const sOrNull = (x: unknown): string | null => (typeof x === 'string' ? x : null);

function keyEntries(doc: unknown, what: string, problems: string[]): KeyEntry[] {
  const raw = isJsonObject(doc) && Array.isArray(doc['keys']) ? (doc['keys'] as unknown[]) : null;
  if (raw === null) {
    problems.push(`${what} has no keys array`);
    return [];
  }
  const out: KeyEntry[] = [];
  for (const e of raw) {
    if (!isJsonObject(e) || typeof e['key_id'] !== 'string' || typeof e['public_key_pem'] !== 'string') {
      problems.push(`${what} holds a malformed key entry`);
      continue;
    }
    const pem = e['public_key_pem'];
    if (!isUsableEd25519PublicKeyPem(pem)) {
      problems.push(`${what}: ${e['key_id']} is not a usable Ed25519 public key`);
      continue;
    }
    if (serviceKeyIdFromPem(pem) !== e['key_id']) {
      problems.push(`${what}: ${e['key_id']} does not derive from its public key`);
      continue;
    }
    out.push({
      key_id: e['key_id'],
      public_key_pem: pem,
      status: sOrNull(e['status']) ?? 'active',
      valid_from: sOrNull(e['valid_from']),
      valid_to: sOrNull(e['valid_to']),
      successor_signature: sOrNull(e['successor_signature']),
      signed_by: sOrNull(e['signed_by']),
    });
  }
  return out;
}

const RANK: Record<string, number> = { active: 0, retired: 1 };
const rank = (s: string) => RANK[s] ?? 2;
const spki = (pem: string): string | null => {
  try {
    return chainIdFromPublicKeyPem(pem);
  } catch {
    return null;
  }
};

/**
 * The anchor service keys receipts are checked against: the shipped pins (or the operator's file),
 * plus keys in the pack's anchor-keys.json that carry a valid successor signature from a key
 * already trusted. The pack's document can only add successors and tighten status / validity.
 */
function serviceTrust(opts: VerifyAuditOptions, pkgDoc: unknown | undefined): { keys: Map<string, TrustedKey>; fileProblems: string[]; pkgProblems: string[] } {
  const keys = new Map<string, TrustedKey>();
  const fileProblems: string[] = [];
  const pkgProblems: string[] = [];
  if (opts.anchor_keys !== undefined) {
    for (const e of keyEntries(opts.anchor_keys, '--anchor-keys file', fileProblems)) {
      keys.set(e.key_id, { key_id: e.key_id, public_key_pem: e.public_key_pem, status: e.status, valid_from: e.valid_from, valid_to: e.valid_to, source: 'file', signed_by: null });
    }
  } else {
    for (const list of Object.values(SHIPPED_SERVICE_KEYS)) {
      for (const k of list) keys.set(k.key_id, { key_id: k.key_id, public_key_pem: k.public_key_pem, status: 'active', valid_from: k.valid_from, valid_to: null, source: 'shipped', signed_by: null });
    }
  }
  if (pkgDoc === undefined) return { keys, fileProblems, pkgProblems };
  const entries = keyEntries(pkgDoc, 'anchor-keys.json', pkgProblems);
  const later = (a: string | null, b: string | null) => (a === null ? b : b === null ? a : Date.parse(b) > Date.parse(a) ? b : a);
  const earlier = (a: string | null, b: string | null) => (a === null ? b : b === null ? a : Date.parse(b) < Date.parse(a) ? b : a);
  for (const e of entries) {
    const have = keys.get(e.key_id);
    if (!have) continue;
    if (spki(have.public_key_pem) !== spki(e.public_key_pem)) {
      pkgProblems.push(`anchor-keys.json lists ${e.key_id} with a public key other than the trusted one`);
      continue;
    }
    const status = rank(e.status) > rank(have.status) ? e.status : have.status;
    keys.set(e.key_id, { ...have, status, valid_from: later(have.valid_from, e.valid_from), valid_to: earlier(have.valid_to, e.valid_to) });
  }
  let pending = entries.filter((e) => !keys.has(e.key_id));
  for (let progress = true; progress && pending.length > 0; ) {
    progress = false;
    const still: KeyEntry[] = [];
    for (const e of pending) {
      const signer = e.signed_by ? keys.get(e.signed_by) : undefined;
      const ok =
        signer !== undefined &&
        rank(signer.status) < 2 &&
        e.signed_by !== e.key_id &&
        e.successor_signature !== null &&
        e.valid_from !== null &&
        verifyEd25519Strict(signer.public_key_pem, successorSigningPayload({ key_id: e.key_id, public_key_pem: e.public_key_pem, valid_from: e.valid_from }), e.successor_signature);
      if (ok) {
        keys.set(e.key_id, { key_id: e.key_id, public_key_pem: e.public_key_pem, status: e.status, valid_from: e.valid_from, valid_to: e.valid_to, source: 'successor', signed_by: signer.key_id });
        progress = true;
      } else still.push(e);
    }
    pending = still;
  }
  return { keys, fileProblems, pkgProblems };
}

// ───────────────────────────── helpers ─────────────────────────────

const short = (h: string | null | undefined, n = 16) => (h ? `${h.slice(0, n)}…` : '?');
const isoMax = (xs: string[]): string | null => (xs.length === 0 ? null : xs.reduce((a, b) => (Date.parse(b) > Date.parse(a) ? b : a)));

interface BundleEvent {
  seq: number;
  this_hash: string;
  stub: boolean;
  kind: string | null;
  payload: Record<string, unknown> | null;
}

/** events.jsonl as leaves + the audit events' payloads; null when it cannot be read. */
function readEvents(path: string, max: number, allowHardlinks: boolean): Map<number, BundleEvent> | null {
  let text: string;
  try {
    text = readBundleFile(path, max, { allowHardlinks }).toString('utf8');
  } catch {
    return null;
  }
  const out = new Map<number, BundleEvent>();
  for (const line of text.split('\n')) {
    if (line.length === 0) continue;
    let v: unknown;
    try {
      v = JSON.parse(line);
    } catch {
      return null;
    }
    if (!isJsonObject(v) || typeof v['seq'] !== 'number' || typeof v['this_hash'] !== 'string') return null;
    const stub = v['stub'] === true;
    const kind = !stub && typeof v['event_type'] === 'string' ? kindOfEventType(v['event_type']) : null;
    out.set(v['seq'], { seq: v['seq'], this_hash: v['this_hash'], stub, kind, payload: !stub && isJsonObject(v['payload']) ? v['payload'] : null });
  }
  return out;
}

function readJsonFile(path: string, max: number, allowHardlinks: boolean): { ok: true; value: unknown; raw: Buffer } | { ok: false; problem: string } {
  let raw: Buffer;
  try {
    raw = readBundleFile(path, max, { allowHardlinks });
  } catch (err) {
    return { ok: false, problem: (err as Error).message };
  }
  try {
    return { ok: true, value: JSON.parse(raw.toString('utf8')), raw };
  } catch {
    return { ok: false, problem: 'not valid JSON' };
  }
}

const exists = (p: string): boolean => lstatSync(p, { throwIfNoEntry: false }) !== undefined;

/** Every regular file under `dir`, as forward-slash relative paths; symlinks and other entries are reported. */
export function listPackFiles(dir: string): { files: string[]; odd: string[] } {
  const files: string[] = [];
  const odd: string[] = [];
  const walk = (rel: string, depth: number) => {
    for (const name of readdirSync(join(dir, rel)).sort()) {
      const r = rel ? `${rel}/${name}` : name;
      const st = lstatSync(join(dir, r));
      if (st.isDirectory() && depth < 8) walk(r, depth + 1);
      else if (st.isFile()) files.push(r);
      else odd.push(r);
    }
  };
  walk('', 0);
  return { files, odd };
}

/** SHA256SUMS text (`<sha256>  <path>` lines, sorted by path) over `files` of `dir`. */
export function sha256sums(dir: string, files: readonly string[]): string {
  return [...files]
    .sort()
    .map((f) => `${hashRegularFile(join(dir, f), { max: MAX_BUNDLE_BLOB_BYTES * 4, allowHardlinks: true }).sha256}  ${f}\n`)
    .join('');
}

const fp256 = (pem: string): string => new X509Certificate(pem).fingerprint256.replace(/:/g, '').toLowerCase();

// ───────────────────────────── verify ─────────────────────────────

export function verifyAudit(packageDir: string, opts: VerifyAuditOptions = {}): VerifyAuditResult {
  let dir: string;
  try {
    dir = realpathSync(packageDir);
    if (!statSync(dir).isDirectory()) throw new Error('not a directory');
  } catch (err) {
    throw new VerifyAuditUsageError(`cannot read evidence pack ${packageDir}: ${(err as Error).message}`);
  }
  const allowHardlinks = opts.allow_hardlinks === true;
  const maxBytes = opts.max_bytes !== undefined && Number.isFinite(opts.max_bytes) && opts.max_bytes > 0 ? Math.floor(opts.max_bytes) : DEFAULT_MAX_BUNDLE_BYTES;
  const tsaAt = opts.tsa_at ?? 'now';
  const checks: AuditCheck[] = [];
  const add = (group: CheckGroup, claim: Claim | null, subject: string | null, check: string, status: CheckStatus | boolean, evidence: string): boolean => {
    const st: CheckStatus = typeof status === 'boolean' ? (status ? 'pass' : 'fail') : status;
    checks.push({ group, claim, subject, check, status: st, evidence });
    return st !== 'fail';
  };
  const result: VerifyAuditResult = {
    format: VERIFY_AUDIT_FORMAT,
    ok: false,
    package: dir,
    audit_id: null,
    bundle_format: null,
    manifest_sha256: null,
    auditor: { key_id: null, spki_sha256: null, source: opts.key_pem !== undefined ? 'pinned' : 'package' },
    trust: {
      service_keys: opts.anchor_keys !== undefined ? 'file' : 'shipped',
      service_key_ids: [],
      tsa_roots: opts.no_tsa === true ? 'skipped' : opts.tsa_roots !== undefined ? 'dir' : 'shipped',
      tsa_root_sha256: [],
      tsa_time: tsaAt,
    },
    claims: [],
    checks,
    failed: 0,
    anchors: [],
    ordering: { status: 'not_declared', basis: null, harness_digest: null, freeze: null, runs: null, problem: null },
    run_sequence: { status: 'not_declared', count: null, seqs: [], declared_counts: [], interruptions: [], problem: null },
    timeline: [],
    final: null,
  };

  // ── policy: claims.json (or the override), plus what the caller requires ──
  let claimsFile: ClaimsFile | null = null;
  let declared: Set<Claim>;
  if (opts.claims_override) declared = new Set(opts.claims_override);
  else {
    declared = new Set(DEFAULT_CLAIMS);
    const cf = exists(join(dir, 'claims.json')) ? readJsonFile(join(dir, 'claims.json'), MAX_KEYDOC_BYTES, allowHardlinks) : null;
    if (!cf) add('pack', null, null, 'claims.json', false, 'claims.json is missing; checked the default claims (integrity, chain, receipts, independent_timestamps)');
    else if (!cf.ok) add('pack', null, null, 'claims.json', false, `claims.json: ${cf.problem}`);
    else {
      const p = ClaimsFileSchema.safeParse(cf.value);
      if (!p.success) add('pack', null, null, 'claims.json', false, `claims.json: ${p.error.issues[0]!.path.join('.') || '(root)'}: ${p.error.issues[0]!.message}`);
      else {
        claimsFile = p.data;
        declared = new Set(p.data.claims);
        add('pack', null, null, 'claims.json', true, `declares ${p.data.claims.join(', ') || 'nothing'}`);
      }
    }
  }
  const required = new Set(opts.require ?? []);
  const checked = new Set<Claim>([...declared, ...required]);
  const noTsa = opts.no_tsa === true || !checked.has('independent_timestamps');
  const on = (c: Claim) => checked.has(c);

  try {
    run();
  } catch (err) {
    // why: belt and braces; each step guards its input, but a pack must never crash the verifier.
    add('pack', null, null, 'verifier', false, `verifier error: ${err instanceof Error ? err.message : String(err)}`);
  }

  // ── claim results ──
  const summary = claimSummaries();
  for (const c of CLAIMS) {
    const mine = checks.filter((k) => k.claim === c);
    const isDeclared = declared.has(c);
    const isRequired = required.has(c);
    let status: ClaimStatus;
    let evidence: string;
    if (!isDeclared && !isRequired) {
      status = 'not_declared';
      evidence = '';
    } else if (!isDeclared) {
      status = 'fail';
      evidence = 'required (--require) but not declared by the pack';
    } else if (c === 'independent_timestamps' && opts.no_tsa === true) {
      status = 'not_checked';
      evidence = 'skipped (--no-tsa)';
    } else if (mine.some((k) => k.status === 'fail')) {
      status = 'fail';
      evidence = mine.filter((k) => k.status === 'fail').map((k) => `${k.subject ? `${k.subject} ` : ''}${k.check}: ${k.evidence}`)[0]!;
    } else if (mine.some((k) => k.status === 'pass')) {
      status = 'pass';
      evidence = summary[c] ?? '';
    } else {
      status = 'fail';
      evidence = 'nothing in the pack backs this claim';
    }
    result.claims.push({ claim: c, status, declared: isDeclared, required: isRequired, evidence });
  }
  result.failed = checks.filter((c) => c.status === 'fail').length + result.claims.filter((c) => c.status === 'fail' && !checks.some((k) => k.claim === c.claim && k.status === 'fail')).length;
  result.ok = result.failed === 0 && result.claims.some((c) => c.status === 'pass');
  return result;

  function claimSummaries(): Partial<Record<Claim, string>> {
    const out: Partial<Record<Claim, string>> = {};
    const sums = checks.find((c) => c.check === 'SHA256SUMS' && c.status === 'pass');
    const b = checks.find((c) => c.check === 'canonical' && c.group === 'bundle');
    const ev = checks.find((c) => c.check === 'events' && c.group === 'bundle');
    const art = checks.find((c) => c.check === 'artifacts' && c.group === 'bundle');
    out.integrity = [ev?.evidence, art?.evidence, b?.evidence, sums?.evidence].filter(Boolean).join('; ');
    out.chain = [checks.find((c) => c.check === 'chain')?.evidence, checks.find((c) => c.check === 'root' && c.group === 'bundle')?.evidence].filter(Boolean).join(', ');
    const okAnchors = result.anchors.filter((a) => a.ok).length;
    out.receipts = `${okAnchors} anchor(s) countersigned by ${[...new Set(result.anchors.map((a) => a.service_key_id).filter(Boolean))].join(', ')}; roots match the bundle`;
    const toks = result.anchors.flatMap((a) => a.timestamps);
    out.independent_timestamps = `${toks.filter((t) => t.ok).length} of ${toks.length} RFC 3161 token(s) (${[...new Set(toks.map((t) => t.tsa))].sort().join(', ')})`;
    out.harness_frozen_before_runs = checks.find((c) => c.group === 'ordering' && c.status === 'pass')?.evidence ?? '';
    out.run_sequence = checks.find((c) => c.group === 'runs' && c.status === 'pass')?.evidence ?? '';
    return out;
  }

  function run(): void {
    // ── auditor key ──
    let auditorPem: string | null = opts.key_pem ?? null;
    const keyFile = join(dir, 'auditor-key.pem');
    let filePem: string | null = null;
    if (exists(keyFile)) {
      try {
        filePem = readBundleFile(keyFile, 64 * 1024, { allowHardlinks }).toString('utf8');
      } catch (err) {
        add('pack', null, null, 'auditor key', false, `auditor-key.pem: ${(err as Error).message}`);
        if (auditorPem === null) return;
      }
    }
    auditorPem ??= filePem;
    if (auditorPem === null) {
      add('pack', null, null, 'auditor key', false, 'auditor-key.pem is missing (pass --key with the auditor key from the report)');
      return;
    }
    let chainId: string;
    let keyId: string;
    try {
      const k = createPublicKey(auditorPem);
      if (k.asymmetricKeyType !== 'ed25519') throw new Error(`a ${k.asymmetricKeyType ?? 'non-Ed25519'} key`);
      chainId = chainIdFromPublicKeyPem(auditorPem);
      keyId = keyIdFromPublicKey(k);
    } catch (err) {
      add('pack', null, null, 'auditor key', false, `the auditor key is not an Ed25519 public key: ${(err as Error).message}`);
      return;
    }
    result.auditor.key_id = keyId;
    result.auditor.spki_sha256 = chainId;
    if (opts.key_pem !== undefined && filePem !== null) {
      add('pack', null, null, 'auditor key', spki(filePem) === chainId, spki(filePem) === chainId ? `auditor-key.pem is the pinned key ${keyId}` : `auditor-key.pem (${short(spki(filePem))}) is not the pinned key ${keyId}`);
    }

    // ── integrity: SHA256SUMS over every file, signed by the auditor key ──
    if (on('integrity') && !opts.claims_override) checkSums(auditorPem, keyId);

    // ── bundle ──
    const bundleDir = join(dir, 'bundle');
    const vb = verifyBundle(bundleDir, { public_key_pem: auditorPem, max_bytes: maxBytes, allow_hardlinks: allowHardlinks });
    result.audit_id = vb.audit_id;
    result.manifest_sha256 = vb.manifest_sha256;
    let manifest: Record<string, unknown> | null = null;
    const mf = readJsonFile(join(bundleDir, 'manifest.json'), MAX_MANIFEST_BYTES, allowHardlinks);
    if (mf.ok && isJsonObject(mf.value)) manifest = mf.value;
    result.bundle_format = typeof manifest?.['format'] === 'string' ? manifest['format'] : null;
    const range = isJsonObject(manifest?.['range']) ? (manifest['range'] as { from_seq?: unknown; to_seq?: unknown }) : null;
    const from = typeof range?.from_seq === 'number' ? range.from_seq : null;
    const to = typeof range?.to_seq === 'number' ? range.to_seq : null;
    const evidenceFor: Record<string, string> = {
      canonical: `manifest sha256 ${vb.manifest_sha256 ?? '?'}`,
      signature: `signed by ${keyId}`,
      events: `${vb.counts.events} event(s), ${vb.counts.stubs} stub(s)${result.bundle_format ? `, ${result.bundle_format}` : ''}`,
      chain: from !== null && to !== null ? `seq ${from}..${to} linked` : 'linked',
      root: `root ${vb.root ?? '?'}`,
      artifacts: `${vb.counts.blobs} artifact(s) hash to their names`,
      refs: `every reference resolves${vb.counts.redacted ? ` (${vb.counts.redacted} declared redacted)` : ''}`,
      missing: `${vb.counts.missing} missing`,
    };
    for (const c of vb.checks) {
      const claim: Claim = c.check === 'chain' || c.check === 'root' ? 'chain' : 'integrity';
      if (on(claim)) add('bundle', claim, null, c.check, c.ok, c.ok ? evidenceFor[c.check]! : (c.problem ?? 'failed'));
    }
    if (claimsFile && vb.audit_id !== null && claimsFile.audit_id !== vb.audit_id) add('pack', null, null, 'claims.json', false, `claims.json is for audit ${claimsFile.audit_id}, the bundle for ${vb.audit_id}`);
    const eventsTrusted = vb.checks.find((c) => c.check === 'canonical')?.ok === true && vb.checks.find((c) => c.check === 'signature')?.ok === true;
    const events = eventsTrusted ? readEvents(join(bundleDir, 'events.jsonl'), maxBytes, allowHardlinks) : null;
    const full = events ? [...events.values()].filter((e) => !e.stub && e.kind !== null).sort((x, y) => x.seq - y.seq) : [];

    // ── run sequence (needs only the bundle) ──
    if (on('run_sequence')) checkRunSequence(events !== null, full);

    const needAnchors = on('receipts') || on('independent_timestamps') || on('harness_frozen_before_runs');
    if (!needAnchors) {
      timeline([], full, events !== null, to, vb.root, vb.manifest_sha256);
      return;
    }

    // ── anchors: pack files ──
    const anchorsDir = join(dir, 'anchors');
    const ast = lstatSync(anchorsDir, { throwIfNoEntry: false });
    if (!ast || ast.isSymbolicLink() || !ast.isDirectory()) {
      add('pack', null, null, 'anchors', false, !ast ? 'anchors/ is missing' : 'anchors/ is not a directory');
      timeline([], full, events !== null, to, vb.root, vb.manifest_sha256);
      return;
    }
    const names = readdirSync(anchorsDir).sort();
    const receipts = names.filter((f) => f.endsWith('.receipt.json'));
    if (receipts.length === 0) {
      add('pack', null, null, 'anchors', false, 'anchors/ holds no receipts');
      timeline([], full, events !== null, to, vb.root, vb.manifest_sha256);
      return;
    }
    const bases = receipts.map((f) => f.slice(0, -'.receipt.json'.length));
    const orphans = names.filter((f) => f.endsWith('.tsr') && !bases.some((b) => f.startsWith(`${b}.`) && TSA_LABEL.test(f.slice(b.length + 1, -4))));
    if (orphans.length > 0) add('pack', null, null, 'anchors', false, `timestamp token(s) with no matching receipt: ${orphans.join(', ')}`);

    // ── trust ──
    let pkgDoc: unknown | undefined;
    if (exists(join(dir, 'anchor-keys.json'))) {
      const d = readJsonFile(join(dir, 'anchor-keys.json'), MAX_KEYDOC_BYTES, allowHardlinks);
      if (d.ok) pkgDoc = d.value;
      else add('pack', null, null, 'anchor-keys.json', false, `anchor-keys.json: ${d.problem}`);
    }
    const trust = serviceTrust(opts, pkgDoc);
    for (const p of trust.fileProblems) add('pack', null, null, 'anchor keys', false, p);
    if (pkgDoc !== undefined) {
      const listed = isJsonObject(pkgDoc) && Array.isArray(pkgDoc['keys']) ? (pkgDoc['keys'] as unknown[]).map((k) => (isJsonObject(k) ? sOrNull(k['key_id']) : null)).filter((k): k is string => k !== null) : [];
      const desc = listed.map((k) => `${k} (${trust.keys.has(k) ? (trust.keys.get(k)!.source === 'successor' ? `successor of ${trust.keys.get(k)!.signed_by}` : 'trusted') : 'not trusted'})`).join(', ');
      add('pack', null, null, 'anchor-keys.json', trust.pkgProblems.length === 0, trust.pkgProblems.length === 0 ? `lists ${desc || 'no keys'}` : trust.pkgProblems.join('; '));
    }
    result.trust.service_key_ids = [...trust.keys.keys()];
    const roots: string[] = [];
    if (!noTsa) {
      for (const pem of opts.tsa_roots ?? SHIPPED_TSA_ROOTS.map((r) => r.pem)) {
        try {
          result.trust.tsa_root_sha256.push(fp256(pem));
          roots.push(pem);
        } catch {
          add('pack', null, null, 'tsa roots', false, 'a --tsa-roots file is not a PEM certificate');
        }
      }
    }

    // ── receipts ──
    const rc = on('receipts') ? ('receipts' as const) : null;
    const addR = (base: string, check: string, ok: boolean, evidence: string) => (rc ? add('anchor', rc, base, check, ok, evidence) : ok);
    for (const [i, file] of receipts.entries()) {
      const base = bases[i]!;
      const report: AnchorReport = { file, label: base.replace(/^\d+-/, ''), anchor_id: null, from_seq: null, to_seq: null, root: null, received_at: null, service_key_id: null, receipt_sha256: '', ok: false, timestamps: [] };
      result.anchors.push(report);
      let raw: Buffer;
      try {
        raw = readBundleFile(join(anchorsDir, file), MAX_RECEIPT_BYTES, { allowHardlinks });
      } catch (err) {
        addR(base, 'receipt', false, (err as Error).message);
        continue;
      }
      report.receipt_sha256 = sha256Hex(raw);
      let parsedJson: unknown;
      try {
        parsedJson = JSON.parse(raw.toString('utf8'));
      } catch {
        addR(base, 'receipt canonical', false, 'not valid JSON');
        continue;
      }
      const parsed = parseAnchorReceipt(parsedJson);
      if (!parsed.ok) {
        addR(base, 'receipt canonical', false, `malformed receipt: ${parsed.detail}`);
        continue;
      }
      const r: AnchorReceipt = parsed.value;
      Object.assign(report, { anchor_id: r.anchor_id, from_seq: r.checkpoint.from_seq, to_seq: r.checkpoint.to_seq, root: r.checkpoint.root, received_at: r.received_at, service_key_id: r.service_key_id });
      const canonical = raw.toString('utf8') === canonicalize(parsedJson);
      let ok = addR(base, 'receipt canonical', canonical, canonical ? `sha256 ${report.receipt_sha256}` : 'the file is not canonical JSON (RFC 8785), so its sha256 is not the receipt digest');

      const sk = trust.keys.get(r.service_key_id);
      const skProblem = !sk
        ? `service key ${r.service_key_id} is not trusted (trusted: ${[...trust.keys.keys()].join(', ') || 'none'}; for a self-hosted anchor service pass --anchor-keys with its key document)`
        : (serviceKeyRefusal(sk, r.received_at) ?? (verifyAnchorReceiptSignature(r, sk.public_key_pem) ? null : 'the countersignature does not verify'));
      ok = addR(base, 'service signature', skProblem === null, skProblem ?? `${r.service_key_id} (${sk!.source}), received_at ${r.received_at}`) && ok;

      const cp = r.checkpoint;
      const cpProblem =
        r.chain_id !== chainId || r.key_id !== keyId || cp.key_id !== keyId
          ? `the receipt is for chain ${short(r.chain_id)} / ${cp.key_id}, not the auditor key ${keyId}`
          : verifyEd25519Strict(auditorPem, checkpointSigningPayload(cp), cp.signature)
            ? null
            : 'the checkpoint signature does not verify against the auditor key';
      ok = addR(base, 'auditor checkpoint', cpProblem === null, cpProblem ?? `${keyId}, seq ${cp.from_seq}..${cp.to_seq}`) && ok;

      let rootProblem: string | null = null;
      if (events === null) rootProblem = 'not checked: the bundle events are not verified';
      else if (from === null || to === null || cp.from_seq < from || cp.to_seq > to) rootProblem = `range ${cp.from_seq}..${cp.to_seq} is not inside the bundle's ${from ?? '?'}..${to ?? '?'}`;
      else if (cp.leaf_count !== cp.to_seq - cp.from_seq + 1) rootProblem = 'leaf_count does not match the range';
      else {
        const leaves: { seq: number; this_hash: string }[] = [];
        for (let s = cp.from_seq; s <= cp.to_seq; s++) {
          const e = events.get(s);
          if (!e) break;
          leaves.push({ seq: s, this_hash: e.this_hash });
        }
        const got = leaves.length === cp.leaf_count ? merkleRootHex(leaves) : null;
        if (got !== cp.root) rootProblem = `bundle seq ${cp.from_seq}..${cp.to_seq} has root ${short(got)}, the anchor holds ${short(cp.root)}`;
      }
      ok = addR(base, 'root matches bundle', rootProblem === null, rootProblem ?? `seq ${cp.from_seq}..${cp.to_seq} root ${cp.root}`) && ok;
      report.ok = ok;

      // ── RFC 3161 ──
      if (noTsa) continue;
      const tokens = names.filter((f) => f.startsWith(`${base}.`) && f.endsWith('.tsr') && TSA_LABEL.test(f.slice(base.length + 1, -4)));
      if (tokens.length === 0) add('timestamp', 'independent_timestamps', base, 'RFC 3161', false, 'no timestamp token for this receipt');
      for (const t of tokens) {
        const tsa = t.slice(base.length + 1, -4);
        let bytes: Buffer;
        try {
          bytes = readBundleFile(join(anchorsDir, t), MAX_TSR_BYTES, { allowHardlinks });
        } catch (err) {
          report.timestamps.push({ file: t, tsa, ok: false, gen_time: null, signer: null, root: null, problem: (err as Error).message });
          add('timestamp', 'independent_timestamps', base, `RFC 3161 ${tsa}`, false, (err as Error).message);
          continue;
        }
        const v = verifyTimestamp(bytes, { message: raw, roots, at: tsaAt, ...(opts.now ? { now: opts.now } : {}) });
        report.timestamps.push({ file: t, tsa, ok: v.ok, gen_time: v.info?.gen_time ?? null, signer: v.signer, root: v.root, problem: v.problem });
        add('timestamp', 'independent_timestamps', base, `RFC 3161 ${tsa}`, v.ok, v.ok ? `${v.info!.gen_time}, signed by ${v.signer}, root ${v.root}` : v.problem!);
      }
    }
    timeline(result.anchors, full, events !== null, to, vb.root, vb.manifest_sha256);
  }

  function checkSums(auditorPem: string, keyId: string): void {
    const sumsPath = join(dir, 'SHA256SUMS');
    if (!exists(sumsPath)) {
      add('pack', 'integrity', null, 'SHA256SUMS', false, 'SHA256SUMS is missing');
      return;
    }
    let sums: Buffer;
    let sig: Buffer;
    try {
      sums = readBundleFile(sumsPath, MAX_SUMS_BYTES, { allowHardlinks });
      sig = readBundleFile(join(dir, 'SHA256SUMS.sig'), 1024, { allowHardlinks });
    } catch (err) {
      add('pack', 'integrity', null, 'SHA256SUMS', false, (err as Error).message);
      return;
    }
    if (sig.length !== 64 || !verifyEd25519Strict(auditorPem, sums, sig.toString('base64'))) {
      add('pack', 'integrity', null, 'SHA256SUMS', false, `SHA256SUMS.sig is not an Ed25519 signature of SHA256SUMS by ${keyId}`);
      return;
    }
    const listed = new Map<string, string>();
    for (const [i, line] of sums.toString('utf8').split('\n').entries()) {
      if (line === '') continue;
      const m = line.match(/^([0-9a-f]{64}) {2}(.+)$/);
      if (!m || !SAFE_PATH.test(m[2]!) || listed.has(m[2]!) || (SUMS_FILES as readonly string[]).includes(m[2]!)) {
        add('pack', 'integrity', null, 'SHA256SUMS', false, `SHA256SUMS line ${i + 1} is not "<sha256>  <relative path>" for a pack file`);
        return;
      }
      listed.set(m[2]!, m[1]!);
    }
    const { files, odd } = listPackFiles(dir);
    const problems: string[] = [];
    if (odd.length) problems.push(`not regular files: ${odd.slice(0, 5).join(', ')}`);
    const present = files.filter((f) => !(SUMS_FILES as readonly string[]).includes(f));
    const unlisted = present.filter((f) => !listed.has(f));
    if (unlisted.length) problems.push(`not in SHA256SUMS: ${unlisted.slice(0, 5).join(', ')}${unlisted.length > 5 ? ` (+${unlisted.length - 5})` : ''}`);
    let budget = maxBytes;
    for (const [f, want] of listed) {
      if (!present.includes(f)) {
        problems.push(`${f} is listed but absent`);
        continue;
      }
      try {
        const h = hashRegularFile(join(dir, f), { max: Math.min(budget, MAX_BUNDLE_BLOB_BYTES * 4), allowHardlinks });
        budget -= h.size;
        if (h.sha256 !== want) problems.push(`${f} does not match its SHA256SUMS line`);
      } catch (err) {
        problems.push(`${f}: ${(err as Error).message}`);
      }
    }
    add('pack', 'integrity', null, 'SHA256SUMS', problems.length === 0, problems.length === 0 ? `${listed.size} file(s) match; signed by ${keyId}` : problems.slice(0, 3).join('; '));
  }

  function checkRunSequence(haveEvents: boolean, full: BundleEvent[]): void {
    const rs = result.run_sequence;
    const fail = (why: string) => {
      rs.status = 'fail';
      rs.problem = why;
      add('runs', 'run_sequence', null, 'run sequence', false, why);
    };
    if (!haveEvents) return fail('not checked: the bundle events are not verified');
    const runs = full.filter((e) => e.kind === 'run_completed');
    if (runs.length === 0) return fail('the bundle holds no run_completed events');
    const seqs = runs.map((r) => (typeof r.payload?.['run_seq'] === 'number' ? (r.payload['run_seq'] as number) : NaN));
    rs.seqs = [...seqs].sort((a, b) => a - b);
    rs.count = runs.length;
    rs.interruptions = runs
      .filter((r) => r.payload?.['capture'] === 'interrupted')
      .map((r) => ({ run_seq: r.payload!['run_seq'] as number, event_key: sOrNull(r.payload?.['event_key']), note: sOrNull(r.payload?.['interruption']) }))
      .sort((a, b) => a.run_seq - b.run_seq);
    const freeze = full.find((e) => e.kind === 'harness_frozen');
    if (typeof freeze?.payload?.['planned_runs'] === 'number') rs.declared_counts.push({ source: 'planned_runs', count: freeze.payload['planned_runs'] });
    const report = [...full].reverse().find((e) => e.kind === 'report_issued' && typeof e.payload?.['run_count'] === 'number');
    if (report) rs.declared_counts.push({ source: 'report_run_count', count: report.payload!['run_count'] as number });
    if (claimsFile?.runs) rs.declared_counts.push({ source: 'claims.json', count: claimsFile.runs.count });
    const dupes = rs.seqs.filter((s, i) => i > 0 && s === rs.seqs[i - 1]);
    if (dupes.length) return fail(`run_seq ${[...new Set(dupes)].join(', ')} appears more than once`);
    const gaps: number[] = [];
    for (let i = 1; i <= (rs.seqs[rs.seqs.length - 1] ?? 0); i++) if (!rs.seqs.includes(i)) gaps.push(i);
    if (gaps.length) return fail(`run_seq is not contiguous: ${gaps.slice(0, 10).join(', ')} missing of 1..${rs.seqs[rs.seqs.length - 1]}`);
    const off = rs.declared_counts.filter((d) => d.count !== runs.length);
    if (off.length) return fail(`${runs.length} run(s) recorded; declared ${off.map((d) => `${d.count} (${d.source})`).join(', ')}`);
    if (claimsFile?.runs) {
      if (canonicalize([...claimsFile.runs.seqs].sort((a, b) => a - b)) !== canonicalize(rs.seqs)) return fail('claims.json runs.seqs differ from the run_seq values in the bundle');
      const ci = claimsFile.runs.interruptions.map((x) => x.run_seq).sort((a, b) => a - b);
      if (canonicalize(ci) !== canonicalize(rs.interruptions.map((x) => x.run_seq))) return fail(`claims.json lists interruptions for run(s) ${ci.join(', ') || 'none'}; the bundle records them for ${rs.interruptions.map((x) => x.run_seq).join(', ') || 'none'}`);
    }
    rs.status = 'pass';
    const decl = rs.declared_counts.length ? `; matches ${rs.declared_counts.map((d) => `${d.source} ${d.count}`).join(', ')}` : '';
    const intr = rs.interruptions.length ? `; ${rs.interruptions.length} capture interruption(s): ${rs.interruptions.map((x) => `run ${x.run_seq}${x.note ? ` (${x.note})` : ''}`).join(', ')}` : '; no capture interruptions';
    add('runs', 'run_sequence', null, 'run sequence', true, `${runs.length} run(s), run_seq 1..${runs.length} contiguous${decl}${intr}`);
  }

  function timeline(anchors: AnchorReport[], full: BundleEvent[], haveEvents: boolean, to: number | null, bundleRoot: string | null, manifestSha: string | null): void {
    interface Valid {
      base: string;
      a: AnchorReport;
      from: number;
      to: number;
      svc: string;
      tsa: Map<string, string>;
      time: string;
      clock: 'tsa' | 'service';
    }
    const valid: Valid[] = [];
    for (const a of anchors) {
      if (!a.ok || a.from_seq === null || a.to_seq === null || a.received_at === null) continue;
      const tsa = new Map(a.timestamps.filter((t) => t.ok && t.gen_time).map((t) => [t.tsa, t.gen_time!] as const));
      if (!noTsa && (tsa.size === 0 || a.timestamps.some((t) => !t.ok))) continue;
      const base = a.file.slice(0, -'.receipt.json'.length);
      valid.push({ base, a, from: a.from_seq, to: a.to_seq, svc: a.received_at, tsa, time: noTsa ? a.received_at : isoMax([...tsa.values()])!, clock: noTsa ? 'service' : 'tsa' });
    }
    valid.sort((x, y) => x.to - y.to || Date.parse(x.svc) - Date.parse(y.svc));
    const tc: Claim | null = on('receipts') ? 'receipts' : null;
    if (tc && anchors.length > 0) {
      if (valid.length >= 2) {
        const bad: string[] = [];
        for (let i = 1; i < valid.length; i++) {
          const a = valid[i - 1]!;
          const b = valid[i]!;
          if (!(b.from <= a.from && b.to > a.to)) bad.push(`${b.base} (seq ${b.from}..${b.to}) does not extend ${a.base} (seq ${a.from}..${a.to})`);
          if (!(Date.parse(b.svc) > Date.parse(a.svc))) bad.push(`${b.base} received_at ${b.svc} is not after ${a.base} ${a.svc}`);
          for (const [tsa, t] of b.tsa) {
            const prev = a.tsa.get(tsa);
            if (prev && Date.parse(t) < Date.parse(prev)) bad.push(`${b.base} ${tsa} time ${t} is before ${a.base} ${prev}`);
          }
        }
        add('timeline', tc, null, 'anchor order', bad.length === 0, bad.length === 0 ? `${valid.map((v) => v.base).join(' → ')}: ranges extend, every clock moves forward` : bad.join('; '));
      } else add('timeline', tc, null, 'anchor order', 'not_applicable', `${valid.length} verified anchor(s)`);
      if (haveEvents) {
        const uncovered = full.filter((e) => !valid.some((v) => v.from <= e.seq && e.seq <= v.to)).map((e) => e.seq);
        const what = noTsa ? 'verified anchors' : 'timestamped anchors';
        add(
          'timeline',
          tc,
          null,
          'coverage',
          uncovered.length === 0 && full.length > 0,
          uncovered.length === 0
            ? `${full.length} audit event(s), seq ${full[0]?.seq ?? '?'}..${full[full.length - 1]?.seq ?? '?'}, committed by ${what}`
            : `seq ${uncovered.slice(0, 10).join(', ')}${uncovered.length > 10 ? ` (+${uncovered.length - 10} more)` : ''} not committed by ${what}`,
        );
      }
    }
    const committing = (seq: number) => valid.find((v) => v.from <= seq && seq <= v.to) ?? null;
    for (const e of full) {
      const c = committing(e.seq);
      result.timeline.push({ seq: e.seq, kind: e.kind!, event_key: sOrNull(e.payload?.['event_key']), measured_at: sOrNull(e.payload?.['measured_at']), committed_by: c?.base ?? null, no_later_than: c?.time ?? null, clock: c?.clock ?? null });
    }
    const last = valid[valid.length - 1];
    if (last && to !== null && last.to === to && bundleRoot !== null && last.a.root === bundleRoot) {
      result.final = { root: last.a.root, from_seq: last.from, to_seq: last.to, manifest_sha256: manifestSha, anchor: last.base, service_time: last.svc, tsa_times: [...last.tsa.entries()].map(([tsa, gen_time]) => ({ tsa, gen_time })) };
    }
    if (on('harness_frozen_before_runs')) checkOrdering(full, haveEvents, committing);
  }

  function checkOrdering(full: BundleEvent[], haveEvents: boolean, committing: (seq: number) => { base: string; a: AnchorReport; to: number; time: string; clock: 'tsa' | 'service' } | null): void {
    const o = result.ordering;
    const label = 'harness frozen before runs';
    const fail = (why: string) => {
      o.status = 'fail';
      o.problem = why;
      add('ordering', 'harness_frozen_before_runs', null, label, false, why);
    };
    if (!haveEvents) return fail('not checked: the bundle events are not verified');
    const freeze = full.find((e) => e.kind === 'harness_frozen' || (e.kind === 'finding' && e.payload?.['class'] === 'protocol_freeze'));
    const runs = full.filter((e) => e.kind !== null && RUN_KINDS.has(e.kind));
    if (!freeze) return fail('the bundle holds no harness-freeze event (harness_frozen, or finding class protocol_freeze)');
    if (runs.length === 0) return fail('the bundle holds no runs (run_completed or call_measured)');
    const fa = committing(freeze.seq);
    const measured = runs.map((r) => sOrNull(r.payload?.['measured_at'])).filter((x): x is string => x !== null && Number.isFinite(Date.parse(x)));
    const sortedM = [...measured].sort((a, b) => Date.parse(a) - Date.parse(b));
    const digest = fa ? fa.a.receipt_sha256 : null;
    const nonceBound = runs.filter((r) => digest !== null && r.payload?.['nonce'] === digest).length;
    const harness = sOrNull(freeze.payload?.['fingerprint']);
    o.harness_digest = harness;
    o.freeze = { seq: freeze.seq, event_key: sOrNull(freeze.payload?.['event_key']), anchor: fa?.base ?? null, time: fa?.time ?? null, clock: fa?.clock ?? null };
    o.runs = { count: runs.length, first_measured_at: sortedM[0] ?? null, last_measured_at: sortedM[sortedM.length - 1] ?? null, nonce_bound: nonceBound };
    if (harness === null) return fail(`the freeze event (seq ${freeze.seq}) records no harness digest (fingerprint)`);
    const otherHarness = runs.filter((r) => r.payload?.['fingerprint'] !== harness);
    if (otherHarness.length) return fail(`run seq ${otherHarness.map((r) => r.seq).slice(0, 10).join(', ')} ran under harness ${short(sOrNull(otherHarness[0]!.payload?.['fingerprint']))}, not the frozen ${short(harness)}`);
    if (!fa) return fail(`the freeze event (seq ${freeze.seq}) is not committed by a ${noTsa ? 'verified' : 'timestamped'} anchor`);
    const withFreeze = runs.filter((r) => r.seq <= fa.to);
    if (withFreeze.length > 0) return fail(`the freeze event (seq ${freeze.seq}) is first committed by ${fa.base} together with ${withFreeze.length} run(s) (seq ${withFreeze[0]!.seq}..${withFreeze[withFreeze.length - 1]!.seq})`);
    const wrongNonce = runs.filter((r) => typeof r.payload?.['nonce'] === 'string' && r.payload['nonce'] !== digest);
    if (wrongNonce.length > 0) return fail(`run seq ${wrongNonce.map((r) => r.seq).join(', ')} carries a nonce that is not the freeze receipt digest ${digest}`);
    const freezeAt = `harness ${short(harness)} frozen, committed ${fa.time} (${fa.base}, ${fa.clock === 'tsa' ? 'RFC 3161' : 'anchor service'})`;
    if (nonceBound === runs.length) {
      o.status = 'pass';
      o.basis = 'freeze_nonce';
      add('ordering', 'harness_frozen_before_runs', null, label, true, `${freezeAt}; ${runs.length}/${runs.length} run(s) name that harness and carry the freeze receipt digest ${digest}`);
      return;
    }
    o.basis = 'recorded_measured_at';
    const noTime = runs.filter((r) => typeof r.payload?.['nonce'] !== 'string' && !Number.isFinite(Date.parse(sOrNull(r.payload?.['measured_at']) ?? '')));
    if (noTime.length > 0) return fail(`run seq ${noTime.map((r) => r.seq).slice(0, 10).join(', ')} records neither measured_at nor a freeze nonce`);
    const early = runs.filter((r) => typeof r.payload?.['nonce'] !== 'string' && Date.parse(String(r.payload?.['measured_at'])) < Date.parse(fa.time));
    if (early.length > 0) {
      const em = early.map((r) => String(r.payload?.['measured_at'])).sort((a, b) => Date.parse(a) - Date.parse(b));
      return fail(`${freezeAt}; ${early.length} of ${runs.length} run(s) record measured_at before it (${em[0]}${em.length > 1 ? ` to ${em[em.length - 1]}` : ''})`);
    }
    o.status = 'pass';
    add('ordering', 'harness_frozen_before_runs', null, label, true, `${freezeAt}; ${runs.length} run(s) name that harness, committed later with measured_at ${o.runs.first_measured_at}${runs.length > 1 ? ` to ${o.runs.last_measured_at}` : ''}${nonceBound ? `; ${nonceBound} carry the freeze nonce` : ''}`);
  }
}

// ───────────────────────────── output ─────────────────────────────

const STATUS = z.enum(['pass', 'fail', 'not_applicable']);

/** The JSON output (`--json`), as a schema: tests and docs hold the CLI to it. */
export const VerifyAuditJsonSchema = z.strictObject({
  format: z.literal(VERIFY_AUDIT_FORMAT),
  ok: z.boolean(),
  package: z.string(),
  audit_id: z.string().nullable(),
  bundle_format: z.string().nullable(),
  manifest_sha256: z.string().nullable(),
  auditor: z.strictObject({ key_id: z.string().nullable(), spki_sha256: z.string().nullable(), source: z.enum(['pinned', 'package']) }),
  trust: z.strictObject({
    service_keys: z.enum(['shipped', 'file']),
    service_key_ids: z.array(z.string()),
    tsa_roots: z.enum(['shipped', 'dir', 'skipped']),
    tsa_root_sha256: z.array(z.string().regex(/^[0-9a-f]{64}$/)),
    tsa_time: z.enum(['now', 'gentime']),
  }),
  claims: z.array(z.strictObject({ claim: z.enum(CLAIMS), status: z.enum(['pass', 'fail', 'not_declared', 'not_checked']), declared: z.boolean(), required: z.boolean(), evidence: z.string() })).length(CLAIMS.length),
  checks: z.array(
    z.strictObject({ group: z.enum(['pack', 'bundle', 'anchor', 'timestamp', 'timeline', 'ordering', 'runs']), claim: z.enum(CLAIMS).nullable(), subject: z.string().nullable(), check: z.string(), status: STATUS, evidence: z.string() }),
  ),
  failed: z.number().int().nonnegative(),
  anchors: z.array(
    z.strictObject({
      file: z.string(),
      label: z.string(),
      anchor_id: z.string().nullable(),
      from_seq: z.number().int().nullable(),
      to_seq: z.number().int().nullable(),
      root: z.string().nullable(),
      received_at: z.string().nullable(),
      service_key_id: z.string().nullable(),
      receipt_sha256: z.string(),
      ok: z.boolean(),
      timestamps: z.array(z.strictObject({ file: z.string(), tsa: z.string(), ok: z.boolean(), gen_time: z.string().nullable(), signer: z.string().nullable(), root: z.string().nullable(), problem: z.string().nullable() })),
    }),
  ),
  ordering: z.strictObject({
    status: z.enum(['pass', 'fail', 'not_declared']),
    basis: z.enum(['freeze_nonce', 'recorded_measured_at']).nullable(),
    harness_digest: z.string().nullable(),
    freeze: z.strictObject({ seq: z.number().int(), event_key: z.string().nullable(), anchor: z.string().nullable(), time: z.string().nullable(), clock: z.enum(['tsa', 'service']).nullable() }).nullable(),
    runs: z.strictObject({ count: z.number().int(), first_measured_at: z.string().nullable(), last_measured_at: z.string().nullable(), nonce_bound: z.number().int() }).nullable(),
    problem: z.string().nullable(),
  }),
  run_sequence: z.strictObject({
    status: z.enum(['pass', 'fail', 'not_declared']),
    count: z.number().int().nullable(),
    seqs: z.array(z.number()),
    declared_counts: z.array(z.strictObject({ source: z.enum(['planned_runs', 'report_run_count', 'claims.json']), count: z.number().int() })),
    interruptions: z.array(z.strictObject({ run_seq: z.number().int(), event_key: z.string().nullable(), note: z.string().nullable() })),
    problem: z.string().nullable(),
  }),
  timeline: z.array(
    z.strictObject({ seq: z.number().int(), kind: z.string(), event_key: z.string().nullable(), measured_at: z.string().nullable(), committed_by: z.string().nullable(), no_later_than: z.string().nullable(), clock: z.enum(['tsa', 'service']).nullable() }),
  ),
  final: z
    .strictObject({
      root: z.string(),
      from_seq: z.number().int(),
      to_seq: z.number().int(),
      manifest_sha256: z.string().nullable(),
      anchor: z.string(),
      service_time: z.string(),
      tsa_times: z.array(z.strictObject({ tsa: z.string(), gen_time: z.string() })),
    })
    .nullable(),
});

const LABEL: Record<CheckStatus | ClaimStatus, string> = { pass: 'PASS', fail: 'FAIL', not_applicable: 'N/A', not_declared: 'not declared', not_checked: 'not checked' };
const GROUP_TITLE: Record<CheckGroup, string> = { pack: 'Pack', bundle: 'Evidence bundle', anchor: 'Anchors', timestamp: 'Anchors', timeline: 'Timeline', ordering: 'Ordering', runs: 'Runs' };

/** The human-readable report: claims, one PASS / FAIL / N/A line per check with its evidence, values to compare. */
export function renderVerifyAudit(r: VerifyAuditResult): string {
  const L: string[] = [];
  const line = (c: AuditCheck, indent = '  ', w = 26) => L.push(`${indent}${LABEL[c.status].padEnd(4)}  ${c.check.padEnd(w)} ${c.evidence}`);
  L.push(`${PACK_NAME}  ${r.package}`);
  L.push(`audit          ${r.audit_id ?? '?'}${r.bundle_format ? `  (${r.bundle_format})` : ''}`);
  L.push(`auditor key    ${r.auditor.key_id ?? '?'}  spki sha256 ${r.auditor.spki_sha256 ?? '?'}  (${r.auditor.source === 'pinned' ? 'pinned with --key' : 'from auditor-key.pem'})`);
  L.push(`service keys   ${r.trust.service_key_ids.join(', ') || '-'}  (${r.trust.service_keys === 'shipped' ? 'shipped pins' : '--anchor-keys'})`);
  L.push(`TSA roots      ${r.trust.tsa_roots === 'skipped' ? 'not used (--no-tsa)' : `${r.trust.tsa_roots === 'shipped' ? 'shipped' : '--tsa-roots'}, validity checked at ${r.trust.tsa_time === 'now' ? 'the current time' : 'genTime'}`}`);
  L.push('', 'Claims');
  for (const c of r.claims) L.push(`  ${LABEL[c.status].padEnd(12)}  ${c.claim.padEnd(27)} ${c.evidence}`.trimEnd());
  for (const g of ['pack', 'bundle'] as const) {
    const cs = r.checks.filter((c) => c.group === g);
    if (!cs.length) continue;
    L.push('', GROUP_TITLE[g]);
    cs.forEach((c) => line(c));
  }
  const anchorChecks = r.checks.filter((c) => c.group === 'anchor' || c.group === 'timestamp');
  if (anchorChecks.length) {
    L.push('', 'Anchors');
    for (const a of r.anchors) {
      const base = a.file.slice(0, -'.receipt.json'.length);
      L.push(`  ${base}${a.from_seq !== null ? `  seq ${a.from_seq}..${a.to_seq}` : ''}${a.received_at ? `  received ${a.received_at}` : ''}${a.anchor_id ? `  id ${a.anchor_id}` : ''}`);
      for (const c of anchorChecks.filter((x) => x.subject === base)) line(c, '    ', 20);
    }
  }
  for (const g of ['timeline', 'ordering', 'runs'] as const) {
    const cs = r.checks.filter((c) => c.group === g);
    if (!cs.length) continue;
    L.push('', GROUP_TITLE[g]);
    cs.forEach((c) => line(c));
  }
  if (r.timeline.some((t) => t.committed_by)) {
    L.push('', 'Milestones');
    const groups = new Map<string, TimelineEntry[]>();
    for (const t of r.timeline) {
      const k = t.committed_by ?? '(not committed by a verified anchor)';
      (groups.get(k) ?? groups.set(k, []).get(k)!).push(t);
    }
    for (const [k, ts] of groups) {
      const t0 = ts[0]!;
      L.push(`  ${k}${t0.no_later_than ? `: no later than ${t0.no_later_than} (${t0.clock === 'tsa' ? 'RFC 3161' : 'anchor service'})` : ''}`);
      for (const t of ts) L.push(`    seq ${String(t.seq).padStart(3)}  ${t.kind.padEnd(17)} ${t.event_key ?? ''}${t.measured_at ? `  measured_at ${t.measured_at}` : ''}`);
    }
  }
  L.push('', 'Values to compare');
  L.push(`  manifest sha256  ${r.manifest_sha256 ?? '?'}`);
  L.push(`  auditor key      ${r.auditor.key_id ?? '?'} (spki sha256 ${r.auditor.spki_sha256 ?? '?'})`);
  if (r.final) {
    L.push(`  final root       ${r.final.root} (seq ${r.final.from_seq}..${r.final.to_seq}, ${r.final.anchor})`);
    L.push(`  timestamped      ${r.final.tsa_times.length ? r.final.tsa_times.map((t) => `${t.gen_time} (${t.tsa})`).join(', ') : `${r.final.service_time} (anchor service)`}`);
  }
  L.push('');
  const passed = r.claims.filter((c) => c.status === 'pass').map((c) => c.claim);
  const unchecked = r.claims.filter((c) => c.status === 'not_checked').map((c) => c.claim);
  L.push(
    r.ok
      ? `RESULT: VERIFIED  ${passed.join(', ')}${unchecked.length ? `  (${unchecked.join(', ')} not checked)` : ''}`
      : `RESULT: FAILED  ${r.claims.filter((c) => c.status === 'fail').map((c) => c.claim).join(', ') || 'pack structure'} (${r.failed} failed check(s))`,
  );
  return L.join('\n') + '\n';
}
