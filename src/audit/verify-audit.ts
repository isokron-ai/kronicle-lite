/**
 * `kronicle-lite verify-audit PACK` (0.10.0): offline verification of an
 * IsoKron Evidence Pack, tamper-evident, independently timestamped audit
 * evidence (docs/EVIDENCE-BUNDLE.md "Evidence packs"):
 *
 *   PACK/SHA256SUMS, SHA256SUMS.sig        sha256 of every other file; raw Ed25519 signature by the auditor key
 *   PACK/claims.json                       what the pack claims (read only after SHA256SUMS verifies)
 *   PACK/bundle/                           evidence bundle (manifest.json signed, events.jsonl, blobs/)
 *   PACK/anchors/NN-<label>.receipt.json   anchor receipt, canonical JSON; sha256(file) is the stamped digest
 *   PACK/anchors/NN-<label>.<tsa>.tsr      RFC 3161 timestamp reply over sha256(receipt file)
 *   PACK/auditor-key.pem                   auditor public key; trusted only when it matches --key-fingerprint
 *   PACK/anchor-keys.json                  the anchor service key list; trusted only through the key chain
 *                                          back to the pinned genesis key (src/anchor/keychain.ts)
 *   PACK/tsa-roots/*.pem                   the pinned TSA CAs, for the openssl route; never a trust root here
 *   PACK/COMPLETION.txt, VERIFY.md         values for the report, raw verification commands
 *
 * Order (fail closed at every step):
 *   1. the auditor key is pinned out of band (--key-fingerprint from the report / SOW, or --key FILE
 *      outside the pack); an unpinned key is a FAIL;
 *   2. SHA256SUMS and its signature are checked against that key BEFORE claims.json is read; a pack
 *      whose SHA256SUMS fails, or that has no valid claims.json, is checked against every claim;
 *   3. integrity and chain are always checked; the declared claims, the --require'd ones and what
 *      they depend on (independent_timestamps → receipts; harness_frozen_before_runs → receipts,
 *      independent_timestamps) are checked; nothing else is reported as passing.
 *
 * Claims and the checks behind each:
 *   integrity                   SHA256SUMS (signature, every file, no extra file) and the bundle's canonical /
 *                               signature / events (payload schemas) / artifacts / refs / missing steps
 *   chain                       the bundle's chain and signed Merkle root
 *   receipts                    the anchor key list is one intact chain from the genesis pin (and not a
 *                               rollback of a list seen before); each receipt: canonical, countersigned by a
 *                               listed key valid at received_at, checkpoint signed by the auditor key, root
 *                               equal to the Merkle root recomputed from the bundle; with timestamps checked,
 *                               no token later than the signing key's valid_to + 5 min; a receipt of a
 *                               revoked key only with a verified TSA time before compromised_since − 5 min
 *                               (received_at never counts; without checked tokens it fails); keys after a
 *                               revoked key are untrusted; anchors extend each
 *                               other; every audit event committed
 *   independent_timestamps      every receipt readable; each RFC 3161 token verifies (src/audit/rfc3161.ts)
 *                               against the pinned TSA CAs; received_at no later than genTime + 5 min and no
 *                               more than 24 h before it; at least two tokens per receipt from different
 *                               pinned TSA CAs
 *   harness_frozen_before_runs  the freeze event records a harness digest every run names; the freeze is
 *                               committed by a timestamped anchor that covers no run; every run is committed
 *                               by a later timestamped anchor; every run carries the freeze nonce (the only
 *                               basis for a /2 bundle) or, for a /1 bundle, records a measured_at between the
 *                               freeze anchor's latest genTime and its committing anchor's earliest genTime
 *   run_sequence                run_completed.run_seq is integers 1..N with no gap or repeat, N agrees with
 *                               every declared count, and the interruptions claims.json lists are the runs
 *                               whose capture was interrupted
 *
 * Hostile input yields failed checks, never a throw.
 */

import { createPublicKey, X509Certificate } from 'node:crypto';
import { chmodSync, lstatSync, mkdirSync, readdirSync, readFileSync, realpathSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { z } from 'zod';

import { verifyEd25519Strict } from '../anchor/ed25519-strict.js';
import { checkKeyChain, checkServiceKey, formatGenesisPin, KEY_TIME_SKEW_MS, keyListOf, keyListRegression, parseGenesisPin, PRODUCTION_GENESIS, type GenesisPin, type ServiceKeyEntry } from '../anchor/keychain.js';
import { parseAnchorReceipt, verifyAnchorReceiptSignature, type AnchorReceipt } from '../anchor/receipt.js';
import { isJsonObject } from '../anchor/wire.js';
import { checkpointSigningPayload } from '../chain/chain.js';
import { merkleRootHex } from '../chain/merkle.js';
import { canonicalize } from '../crypto/canonical.js';
import { sha256Hex } from '../crypto/hash.js';
import { chainIdFromPublicKeyPem, keyIdFromPublicKey } from '../crypto/keys.js';
import { MAX_TSR_BYTES, verifyTimestamp } from './rfc3161.js';
import { BUNDLE_FORMAT_V2, kindOfEventType } from './schemas.js';
import { SHIPPED_TSA_EXTRAS, SHIPPED_TSA_ROOTS } from './tsa-roots.js';
import { DEFAULT_MAX_BUNDLE_BYTES, hashRegularFile, MAX_BUNDLE_BLOB_BYTES, MAX_MANIFEST_BYTES, readBundleFile, verifyBundle } from './verify-bundle.js';

export const VERIFY_AUDIT_FORMAT = 'kronicle-lite-verify-audit/1';
export const PACK_NAME = 'IsoKron Evidence Pack';
export const CLAIMS_FORMAT = 'isokron-evidence-pack-claims/1';
export const CLAIMS = ['integrity', 'chain', 'receipts', 'independent_timestamps', 'harness_frozen_before_runs', 'run_sequence'] as const;
export type Claim = (typeof CLAIMS)[number];
/** Always checked, whatever claims.json says. */
const ALWAYS: readonly Claim[] = ['integrity', 'chain'];
/** Claims that need others to mean anything. */
const DEPENDS: Partial<Record<Claim, readonly Claim[]>> = {
  independent_timestamps: ['receipts'],
  harness_frozen_before_runs: ['receipts', 'independent_timestamps'],
};
/** Claims that need RFC 3161 tokens (not checked under --no-tsa). */
const NEEDS_TSA: readonly Claim[] = ['independent_timestamps', 'harness_frozen_before_runs'];
/** Accepted difference between the service's received_at and a TSA genTime (the anchor service's FORWARD_DATE_SKEW_MS). */
export const CLOCK_SKEW_MS = 5 * 60 * 1000;
/** Longest accepted delay between a receipt's received_at and its RFC 3161 genTime (bounds back-dating with a leaked key). */
export const MAX_STAMP_DELAY_MS = 24 * 60 * 60 * 1000;
const MAX_RECEIPT_BYTES = 64 * 1024;
const MAX_KEYDOC_BYTES = 1024 * 1024;
const MAX_SUMS_BYTES = 16 * 1024 * 1024;
const TSA_LABEL = /^[a-z0-9][a-z0-9-]{0,31}$/;
const RUN_KINDS = new Set(['call_measured', 'run_completed']);
/** Files of the pack that SHA256SUMS does not (cannot) list. */
export const SUMS_FILES = ['SHA256SUMS', 'SHA256SUMS.sig'] as const;
/** The rollback cache in the data dir: the newest anchor key list seen per genesis pin. */
export const SEEN_KEYS_FILE = 'anchor-keys.seen.json';
const SAFE_PATH = /^(?!.*(^|\/)\.\.?(\/|$))[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/;
const HEX64 = /^[0-9a-f]{64}$/;

/** The pack directory cannot be read, or the options contradict each other (exit 2). */
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

export type CheckGroup = 'pack' | 'bundle' | 'keys' | 'anchor' | 'timestamp' | 'timeline' | 'ordering' | 'runs';
export type CheckStatus = 'pass' | 'fail' | 'not_applicable';
export type ClaimStatus = 'pass' | 'fail' | 'not_declared' | 'not_checked';

export interface AuditCheck {
  group: CheckGroup;
  /** The claim this check backs; null for the pack's structure. */
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
  /** Declared in an authenticated claims.json. */
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
  /** The pinned TSA CA group the token chains to (sectigo, digicert, or a --tsa-roots file). */
  ca: string | null;
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
  status: 'pass' | 'fail' | 'not_declared' | 'not_checked';
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
  auditor: { key_id: string | null; spki_sha256: string | null; source: 'key_file' | 'fingerprint' | 'unpinned' };
  trust: {
    /** Where the anchor key list came from: the pack's anchor-keys.json or --anchor-keys. */
    key_list: 'pack' | 'file';
    genesis_sha256: string;
    /** The genesis key's valid_from, from the pin (never from the list). */
    genesis_valid_from: string;
    genesis_source: 'compiled' | 'option';
    /**
     * intact: every key verified. revoked_descendants: a key was revoked and the keys after it are
     * untrusted (their receipts fail; earlier keys still count). broken: the list is not usable.
     */
    key_chain: {
      status: 'intact' | 'revoked_descendants' | 'broken' | 'not_checked';
      detail: string;
      entries: { key_id: string; state: 'genesis' | 'verified' | 'revoked' | 'broken'; detail: string; compromised_since: string | null; revoked_ancestor: string | null }[];
    };
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

/** A trusted TSA CA certificate, in a named group (one TSA operator). */
export type TsaRoot = string | { name: string; pem: string };

export interface VerifyAuditOptions {
  /** Auditor public key (PEM) obtained out of band, never the pack's own file. */
  key_pem?: string;
  /** SHA-256 of the auditor key's SPKI (hex), from the report / SOW: PACK/auditor-key.pem must match it. */
  key_fingerprint?: string;
  /** The anchor service key list ({keys: [...]}) to use instead of the pack's anchor-keys.json; it must still chain to the genesis pin. */
  anchor_keys?: unknown;
  /**
   * The genesis pin of the anchor service key chain, `<sha256>@<valid_from>` or {sha256, valid_from}
   * (default: the compiled production pin). Only for a self-hosted anchor service.
   */
  genesis?: string | GenesisPin;
  /** Trusted TSA CAs instead of the shipped ones; a plain PEM is its own group. */
  tsa_roots?: TsaRoot[];
  /** Skip RFC 3161 tokens (independent_timestamps and harness_frozen_before_runs are then not checked). */
  no_tsa?: boolean;
  /** Check TSA certificate validity at genTime instead of now (certificates that expired since the stamp). */
  tsa_at?: 'now' | 'gentime';
  /** Claims the caller requires: one the pack does not declare fails. */
  require?: Claim[];
  /** Check exactly these claims and skip SHA256SUMS / claims.json (the packager's own pass, before they exist). */
  claims_override?: readonly Claim[];
  /** Directory of the rollback cache (anchor-keys.seen.json); null or absent: no cache. */
  seen_dir?: string | null;
  /** Clock (tests). */
  now?: Date;
  max_bytes?: number;
  allow_hardlinks?: boolean;
}

// ───────────────────────────── helpers ─────────────────────────────

const sOrNull = (x: unknown): string | null => (typeof x === 'string' ? x : null);
const short = (h: string | null | undefined, n = 16) => (h ? `${h.slice(0, n)}…` : '?');
const isoMax = (xs: string[]): string | null => (xs.length === 0 ? null : xs.reduce((a, b) => (Date.parse(b) > Date.parse(a) ? b : a)));
const isoMin = (xs: string[]): string | null => (xs.length === 0 ? null : xs.reduce((a, b) => (Date.parse(b) < Date.parse(a) ? b : a)));
const normFp = (s: string) => s.replace(/:/g, '').trim().toLowerCase();
const spki = (pem: string): string | null => {
  try {
    return chainIdFromPublicKeyPem(pem);
  } catch {
    return null;
  }
};

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

/**
 * The genesis pin a command line asks for: --genesis, else KRONICLE_ANCHOR_GENESIS, else undefined
 * (the compiled pin). The old KRONICLE_ANCHOR_GENESIS_SHA256 is refused, as the anchor client does:
 * a bare hash leaves out the genesis key's valid_from, which is part of the pin.
 */
export function genesisFromCli(flag: string | undefined, env: NodeJS.ProcessEnv = process.env): string | undefined {
  if (env['KRONICLE_ANCHOR_GENESIS_SHA256'] !== undefined) {
    throw new VerifyAuditUsageError("KRONICLE_ANCHOR_GENESIS_SHA256 is no longer read: set KRONICLE_ANCHOR_GENESIS=<sha256>@<valid_from> (the genesis key's valid_from is part of the pin)");
  }
  const v = flag ?? env['KRONICLE_ANCHOR_GENESIS'];
  if (v !== undefined && parseGenesisPin(v) === null) throw new VerifyAuditUsageError(`${flag !== undefined ? '--genesis' : 'KRONICLE_ANCHOR_GENESIS'} must be <sha256>@<valid_from> (the genesis key's SPKI SHA-256 and its valid_from, ISO 8601 UTC)`);
  return v;
}

// ───────────────────────────── verify ─────────────────────────────

export function verifyAudit(packageDir: string, opts: VerifyAuditOptions = {}): VerifyAuditResult {
  let dir: string;
  try {
    dir = realpathSync(packageDir);
    if (!statSync(dir).isDirectory()) throw new Error('not a directory');
  } catch (err) {
    throw new VerifyAuditUsageError(`cannot read evidence pack ${packageDir}: ${(err as Error).message}`);
  }
  const noTsa = opts.no_tsa === true;
  for (const c of opts.require ?? []) {
    if (noTsa && NEEDS_TSA.includes(c)) throw new VerifyAuditUsageError(`--require ${c} needs RFC 3161 tokens; it cannot be combined with --no-tsa`);
  }
  if (opts.key_fingerprint !== undefined && !HEX64.test(normFp(opts.key_fingerprint))) throw new VerifyAuditUsageError('--key-fingerprint must be the 64-hex SHA-256 of the auditor key (colons allowed)');
  const pinOrNull: GenesisPin | null = opts.genesis === undefined ? PRODUCTION_GENESIS : parseGenesisPin(opts.genesis);
  if (pinOrNull === null) throw new VerifyAuditUsageError('--genesis must be <sha256>@<valid_from> (the genesis key\'s SPKI SHA-256 and its valid_from, ISO 8601 UTC)');
  const allowHardlinks = opts.allow_hardlinks === true;
  const maxBytes = opts.max_bytes !== undefined && Number.isFinite(opts.max_bytes) && opts.max_bytes > 0 ? Math.floor(opts.max_bytes) : DEFAULT_MAX_BUNDLE_BYTES;
  const tsaAt = opts.tsa_at ?? 'now';
  const pin: GenesisPin = pinOrNull;
  const genesis = pin.sha256;
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
    auditor: { key_id: null, spki_sha256: null, source: opts.key_pem !== undefined ? 'key_file' : opts.key_fingerprint !== undefined ? 'fingerprint' : 'unpinned' },
    trust: {
      key_list: opts.anchor_keys !== undefined ? 'file' : 'pack',
      genesis_sha256: genesis,
      genesis_valid_from: pin.valid_from,
      genesis_source: opts.genesis !== undefined ? 'option' : 'compiled',
      key_chain: { status: 'not_checked', detail: '', entries: [] },
      tsa_roots: noTsa ? 'skipped' : opts.tsa_roots !== undefined ? 'dir' : 'shipped',
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

  let claimsFile: ClaimsFile | null = null;
  let declared = new Set<Claim>();
  const required = new Set(opts.require ?? []);
  let checked = new Set<Claim>();
  const on = (c: Claim) => checked.has(c);
  /** The policy: authenticated claims.json (or every claim), plus the always-checked ones, the required ones and their dependencies. */
  const setPolicy = (d: Iterable<Claim>) => {
    declared = new Set(d);
    checked = new Set<Claim>([...ALWAYS, ...declared, ...required]);
    for (let grew = true; grew; ) {
      grew = false;
      for (const c of [...checked]) for (const dep of DEPENDS[c] ?? []) {
          if (!checked.has(dep)) {
            checked.add(dep);
            grew = true;
          }
        }
    }
  };
  setPolicy(opts.claims_override ?? CLAIMS);

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
    if (!checked.has(c)) {
      status = 'not_declared';
      evidence = '';
    } else if (isRequired && !isDeclared && !ALWAYS.includes(c)) {
      status = 'fail';
      evidence = 'required (--require) but not declared by the pack';
    } else if (noTsa && NEEDS_TSA.includes(c)) {
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
  result.ok =
    result.failed === 0 &&
    result.auditor.source !== 'unpinned' &&
    ALWAYS.every((c) => result.claims.find((x) => x.claim === c)!.status === 'pass') &&
    result.claims.every((c) => c.status !== 'fail');
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
    out.receipts = `${okAnchors} anchor(s) countersigned by ${[...new Set(result.anchors.map((a) => a.service_key_id).filter(Boolean))].join(', ')} (key chain intact to genesis ${short(genesis)}); roots match the bundle`;
    const toks = result.anchors.flatMap((a) => a.timestamps);
    out.independent_timestamps = `${toks.filter((t) => t.ok).length} of ${toks.length} RFC 3161 token(s), each receipt stamped under ≥ 2 pinned TSA CAs (${[...new Set(toks.map((t) => t.ca).filter(Boolean))].sort().join(', ')})`;
    out.harness_frozen_before_runs = checks.find((c) => c.group === 'ordering' && c.status === 'pass')?.evidence ?? '';
    out.run_sequence = checks.find((c) => c.group === 'runs' && c.status === 'pass')?.evidence ?? '';
    return out;
  }

  function run(): void {
    // ── 1. the auditor key, pinned out of band ──
    const keyFile = join(dir, 'auditor-key.pem');
    let filePem: string | null = null;
    if (exists(keyFile)) {
      try {
        filePem = readBundleFile(keyFile, 64 * 1024, { allowHardlinks }).toString('utf8');
      } catch (err) {
        add('pack', null, null, 'auditor key', false, `auditor-key.pem: ${(err as Error).message}`);
      }
    }
    const auditorPem = opts.key_pem ?? filePem;
    if (auditorPem === null) {
      add('pack', null, null, 'auditor key', false, 'no auditor key: auditor-key.pem is missing and no --key was given');
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
    if (opts.key_fingerprint !== undefined) {
      const want = normFp(opts.key_fingerprint);
      add('pack', null, null, 'auditor key', want === chainId, want === chainId ? `${keyId}, SHA-256(SPKI) ${chainId} = --key-fingerprint` : `the pack's auditor key has SHA-256(SPKI) ${chainId}, not the pinned ${want}`);
    } else if (opts.key_pem !== undefined) {
      add('pack', null, null, 'auditor key', filePem === null || spki(filePem) === chainId, filePem === null || spki(filePem) === chainId ? `${keyId}, SHA-256(SPKI) ${chainId} (--key)` : `auditor-key.pem (${short(spki(filePem))}) is not the pinned key ${keyId}`);
    } else {
      add('pack', null, null, 'auditor key', false, `not pinned: pass --key-fingerprint with the auditor key fingerprint from the report or SOW (the pack's own key is ${keyId}, SHA-256(SPKI) ${chainId})`);
    }

    // ── 2. pack layout, then SHA256SUMS before anything the pack says about itself ──
    for (const d of ['bundle', 'anchors']) {
      const st = lstatSync(join(dir, d), { throwIfNoEntry: false });
      if (st && (st.isSymbolicLink() || !st.isDirectory())) add('pack', 'integrity', null, `${d}/`, false, `${d}/ is ${st.isSymbolicLink() ? 'a symbolic link' : 'not a directory'}`);
    }
    if (!opts.claims_override) {
      const sumsOk = checkSums(auditorPem, keyId);
      const cfPath = join(dir, 'claims.json');
      if (!sumsOk) {
        add('pack', null, null, 'claims.json', false, 'not authenticated (SHA256SUMS does not verify): every claim is checked');
        setPolicy(CLAIMS);
      } else if (!exists(cfPath)) {
        add('pack', null, null, 'claims.json', false, 'claims.json is missing: every claim is checked');
        setPolicy(CLAIMS);
      } else {
        const cf = readJsonFile(cfPath, MAX_KEYDOC_BYTES, allowHardlinks);
        const p = cf.ok ? ClaimsFileSchema.safeParse(cf.value) : null;
        if (!cf.ok || !p || !p.success) {
          add('pack', null, null, 'claims.json', false, `${!cf.ok ? cf.problem : p && !p.success ? `${p.error.issues[0]!.path.join('.') || '(root)'}: ${p.error.issues[0]!.message}` : 'invalid'}: every claim is checked`);
          setPolicy(CLAIMS);
        } else {
          claimsFile = p.data;
          setPolicy(p.data.claims);
          add('pack', null, null, 'claims.json', true, `declares ${p.data.claims.join(', ') || 'nothing'} (authenticated by SHA256SUMS)`);
        }
      }
    }

    // ── 3. bundle (integrity, chain: always) ──
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
      events: `${vb.counts.events} event(s), ${vb.counts.stubs} stub(s), payloads match their schemas${result.bundle_format ? `, ${result.bundle_format}` : ''}`,
      chain: from !== null && to !== null ? `seq ${from}..${to} linked` : 'linked',
      root: `root ${vb.root ?? '?'}`,
      artifacts: `${vb.counts.blobs} artifact(s) hash to their names`,
      refs: `every reference resolves${vb.counts.redacted ? ` (${vb.counts.redacted} declared redacted)` : ''}`,
      missing: `${vb.counts.missing} missing`,
    };
    for (const c of vb.checks) add('bundle', c.check === 'chain' || c.check === 'root' ? 'chain' : 'integrity', null, c.check, c.ok, c.ok ? evidenceFor[c.check]! : (c.problem ?? 'failed'));
    if (claimsFile && vb.audit_id !== null && claimsFile.audit_id !== vb.audit_id) add('pack', 'integrity', null, 'claims.json', false, `claims.json is for audit ${claimsFile.audit_id}, the bundle for ${vb.audit_id}`);
    const eventsTrusted = vb.ok;
    const events = eventsTrusted ? readEvents(join(bundleDir, 'events.jsonl'), maxBytes, allowHardlinks) : null;
    const full = events ? [...events.values()].filter((e) => !e.stub && e.kind !== null).sort((x, y) => x.seq - y.seq) : [];

    // ── 4. run sequence (needs only the bundle) ──
    if (on('run_sequence')) checkRunSequence(events !== null, full);

    if (!on('receipts')) {
      timeline([], full, events !== null, to, vb.root, vb.manifest_sha256, null);
      return;
    }

    // ── 5. the anchor key list: one intact chain from the genesis pin, and not a rollback ──
    let listDoc: unknown;
    if (opts.anchor_keys !== undefined) listDoc = opts.anchor_keys;
    else if (exists(join(dir, 'anchor-keys.json'))) {
      const d = readJsonFile(join(dir, 'anchor-keys.json'), MAX_KEYDOC_BYTES, allowHardlinks);
      listDoc = d.ok ? d.value : undefined;
      if (!d.ok) add('keys', 'receipts', null, 'anchor key list', false, `anchor-keys.json: ${d.problem}`);
    } else add('keys', 'receipts', null, 'anchor key list', false, 'anchor-keys.json is missing (or pass --anchor-keys)');
    const keyList: ServiceKeyEntry[] | null = listDoc === undefined ? null : keyListOf(listDoc);
    if (listDoc !== undefined && keyList === null) add('keys', 'receipts', null, 'anchor key list', false, `${opts.anchor_keys !== undefined ? '--anchor-keys' : 'anchor-keys.json'} is not a key list ({keys: [{key_id, public_key_pem, …}]})`);
    let listOk = false;
    if (keyList) {
      // The genesis key's valid_from comes from the pin, never from the list (checkKeyChain applies it).
      const kc = checkKeyChain(keyList, pin);
      listOk = kc.usable;
      result.trust.key_chain = {
        status: kc.ok ? 'intact' : kc.usable ? 'revoked_descendants' : 'broken',
        detail: kc.detail,
        entries: kc.entries.map((e) => ({
          key_id: e.key_id,
          state: e.state,
          detail: e.detail,
          compromised_since: e.state === 'revoked' ? (keyList!.find((k) => k.key_id === e.key_id)?.compromised_since ?? null) : null,
          revoked_ancestor: e.revoked_ancestor ?? null,
        })),
      };
      const brokenOnes = kc.entries.filter((e) => e.state === 'broken' && !e.revoked_ancestor);
      const untrusted = kc.entries.filter((e) => e.state === 'broken' && e.revoked_ancestor);
      const hint = opts.genesis === undefined && keyList.every((k) => spki(k.public_key_pem) !== genesis) ? ' (for a self-hosted anchor service pass --genesis <sha256>@<valid_from> with its genesis key pin)' : '';
      const chainText = kc.entries.map((e) => `${e.key_id} (${e.state}${e.revoked_ancestor ? ` after revoked ${e.revoked_ancestor}` : ''})`).join(' → ');
      add(
        'keys',
        'receipts',
        null,
        'anchor key list',
        kc.usable,
        kc.usable
          ? `${kc.detail}: ${chainText}; genesis ${formatGenesisPin(pin)}${untrusted.length ? `; untrusted (signed by a revoked key): ${untrusted.map((e) => e.key_id).join(', ')}` : ''}`
          : `${kc.detail}: ${brokenOnes.map((e) => `${e.key_id}: ${e.detail}`).slice(0, 3).join('; ')}${hint}`,
      );
      if (kc.usable && opts.seen_dir) checkRollback(keyList);
    }

    // TSA trust: groups by operator (the shipped sectigo / digicert files, or one per --tsa-roots entry).
    const groupOf = new Map<string, string>();
    const roots: string[] = [];
    if (!noTsa) {
      const list: { name: string; pem: string }[] =
        opts.tsa_roots !== undefined ? opts.tsa_roots.map((r) => (typeof r === 'string' ? { name: '', pem: r } : r)) : SHIPPED_TSA_ROOTS.map((r) => ({ name: r.name, pem: r.pem }));
      for (const r of list) {
        try {
          const fp = fp256(r.pem);
          const name = r.name || `ca-${(spki(new X509Certificate(r.pem).publicKey.export({ type: 'spki', format: 'pem' }) as string) ?? fp).slice(0, 12)}`;
          result.trust.tsa_root_sha256.push(fp);
          groupOf.set(fp, name);
          roots.push(r.pem);
        } catch {
          add('pack', null, null, 'tsa roots', false, 'a --tsa-roots file is not a PEM certificate');
        }
      }
    }

    // ── 6. receipts and their tokens ──
    const anchorsDir = join(dir, 'anchors');
    const ast = lstatSync(anchorsDir, { throwIfNoEntry: false });
    if (!ast || ast.isSymbolicLink() || !ast.isDirectory()) {
      add('anchor', 'receipts', null, 'anchors', false, !ast ? 'anchors/ is missing' : 'anchors/ is not a directory');
      timeline([], full, events !== null, to, vb.root, vb.manifest_sha256, null);
      return;
    }
    const names = readdirSync(anchorsDir).sort();
    const receipts = names.filter((f) => f.endsWith('.receipt.json'));
    if (receipts.length === 0) {
      add('anchor', 'receipts', null, 'anchors', false, 'anchors/ holds no receipts');
      timeline([], full, events !== null, to, vb.root, vb.manifest_sha256, null);
      return;
    }
    const bases = receipts.map((f) => f.slice(0, -'.receipt.json'.length));
    const orphans = names.filter((f) => f.endsWith('.tsr') && !bases.some((b) => f.startsWith(`${b}.`) && TSA_LABEL.test(f.slice(b.length + 1, -4))));
    if (orphans.length > 0) add('anchor', 'receipts', null, 'anchors', false, `timestamp token(s) with no matching receipt: ${orphans.join(', ')}`);

    const keyEndOk = new Map<string, boolean>();
    for (const [i, file] of receipts.entries()) {
      const base = bases[i]!;
      const report: AnchorReport = { file, label: base.replace(/^\d+-/, ''), anchor_id: null, from_seq: null, to_seq: null, root: null, received_at: null, service_key_id: null, receipt_sha256: '', ok: false, timestamps: [] };
      result.anchors.push(report);
      const tokens = names.filter((f) => f.startsWith(`${base}.`) && f.endsWith('.tsr') && TSA_LABEL.test(f.slice(base.length + 1, -4)));
      const unreadable = (why: string) => {
        add('anchor', 'receipts', base, 'receipt', false, why);
        // Tokens over a receipt that cannot be read vouch for nothing: the claim fails, it is not skipped.
        if (on('independent_timestamps') && !noTsa) add('timestamp', 'independent_timestamps', base, 'RFC 3161', false, `receipt unreadable (${why}); ${tokens.length} token(s) over it cannot be checked`);
      };
      let raw: Buffer;
      try {
        raw = readBundleFile(join(anchorsDir, file), MAX_RECEIPT_BYTES, { allowHardlinks });
      } catch (err) {
        unreadable((err as Error).message);
        continue;
      }
      report.receipt_sha256 = sha256Hex(raw);
      let parsedJson: unknown;
      try {
        parsedJson = JSON.parse(raw.toString('utf8'));
      } catch {
        unreadable('not valid JSON');
        continue;
      }
      const parsed = parseAnchorReceipt(parsedJson);
      if (!parsed.ok) {
        unreadable(`malformed receipt: ${parsed.detail}`);
        continue;
      }
      const r: AnchorReceipt = parsed.value;
      Object.assign(report, { anchor_id: r.anchor_id, from_seq: r.checkpoint.from_seq, to_seq: r.checkpoint.to_seq, root: r.checkpoint.root, received_at: r.received_at, service_key_id: r.service_key_id });
      const canonical = raw.toString('utf8') === canonicalize(parsedJson);
      let ok = add('anchor', 'receipts', base, 'receipt canonical', canonical, canonical ? `sha256 ${report.receipt_sha256}` : 'the file is not canonical JSON (RFC 8785), so its sha256 is not the receipt digest');

      // The service's checkServiceKey with revoked: 'tsa': a revoked key's receipt counts only with a
      // verified RFC 3161 time before compromised_since − 5 min (checked below, never received_at).
      const sk = listOk ? checkServiceKey(keyList!, r.service_key_id, r.received_at, pin, { revoked: 'tsa' }) : null;
      const entry: ServiceKeyEntry | null = sk?.ok ? sk.entry : null;
      const compromisedSince = sk?.ok ? (sk.revoked?.compromised_since ?? null) : null;
      const skProblem = sk === null
        ? 'the anchor key list does not chain to the genesis pin'
        : !sk.ok
          ? sk.detail
          : verifyAnchorReceiptSignature(r, sk.entry.public_key_pem)
            ? null
            : 'the countersignature does not verify';
      ok = add('anchor', 'receipts', base, 'service signature', skProblem === null, skProblem ?? `${sk!.ok ? sk!.detail : ''}, received_at ${r.received_at}`) && ok;
      if (compromisedSince !== null && (noTsa || !on('independent_timestamps'))) {
        ok = add('timestamp', 'receipts', base, 'stamped before compromise', false, `${r.service_key_id} is revoked (compromised since ${compromisedSince}); its receipt counts only with a verified RFC 3161 time before ${compromisedSince} − 5 min, and RFC 3161 tokens are not checked here (${noTsa ? '--no-tsa' : 'independent_timestamps not claimed'})`) && ok;
      }

      const cp = r.checkpoint;
      const cpProblem =
        r.chain_id !== chainId || r.key_id !== keyId || cp.key_id !== keyId
          ? `the receipt is for chain ${short(r.chain_id)} / ${cp.key_id}, not the auditor key ${keyId}`
          : verifyEd25519Strict(auditorPem, checkpointSigningPayload(cp), cp.signature)
            ? null
            : 'the checkpoint signature does not verify against the auditor key';
      ok = add('anchor', 'receipts', base, 'auditor checkpoint', cpProblem === null, cpProblem ?? `${keyId}, seq ${cp.from_seq}..${cp.to_seq}`) && ok;

      let rootProblem: string | null = null;
      if (events === null) rootProblem = 'not checked: the bundle does not verify';
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
      ok = add('anchor', 'receipts', base, 'root matches bundle', rootProblem === null, rootProblem ?? `seq ${cp.from_seq}..${cp.to_seq} root ${cp.root}`) && ok;
      report.ok = ok;

      // ── RFC 3161 ──
      if (noTsa || !on('independent_timestamps')) continue;
      if (tokens.length === 0) add('timestamp', 'independent_timestamps', base, 'RFC 3161', false, 'no timestamp token for this receipt');
      const rcvd = Date.parse(r.received_at);
      for (const t of tokens) {
        const tsa = t.slice(base.length + 1, -4);
        let bytes: Buffer;
        try {
          bytes = readBundleFile(join(anchorsDir, t), MAX_TSR_BYTES, { allowHardlinks });
        } catch (err) {
          report.timestamps.push({ file: t, tsa, ok: false, gen_time: null, signer: null, root: null, ca: null, problem: (err as Error).message });
          add('timestamp', 'independent_timestamps', base, `RFC 3161 ${tsa}`, false, (err as Error).message);
          continue;
        }
        const v = verifyTimestamp(bytes, { message: raw, roots, at: tsaAt, known_extras: opts.tsa_roots === undefined ? SHIPPED_TSA_EXTRAS.map((x) => x.sha256) : [], ...(opts.now ? { now: opts.now } : {}) });
        let problem = v.problem;
        if (v.ok) {
          const g = Date.parse(v.info!.gen_time);
          if (rcvd > g + CLOCK_SKEW_MS) problem = `receipt is forward-dated: received_at ${r.received_at} is later than the TSA time ${v.info!.gen_time} (+5 min)`;
          else if (g - rcvd > MAX_STAMP_DELAY_MS) problem = `stamped ${v.info!.gen_time}, more than 24 h after received_at ${r.received_at}`;
        }
        const ca = v.ok && v.root_sha256 ? (groupOf.get(v.root_sha256) ?? null) : null;
        report.timestamps.push({ file: t, tsa, ok: problem === null, gen_time: v.info?.gen_time ?? null, signer: v.signer, root: v.root, ca, problem });
        add('timestamp', 'independent_timestamps', base, `RFC 3161 ${tsa}`, problem === null, problem === null ? `${v.info!.gen_time}, signed by ${v.signer}, CA ${v.root} (${ca})` : problem);
      }
      const goodCas = new Set(report.timestamps.filter((t) => t.ok && t.ca).map((t) => t.ca!));
      add('timestamp', 'independent_timestamps', base, 'independent TSAs', goodCas.size >= 2, goodCas.size >= 2 ? `valid tokens under ${goodCas.size} pinned TSA CAs (${[...goodCas].sort().join(', ')})` : `valid tokens under ${goodCas.size} pinned TSA CA(s)${goodCas.size ? ` (${[...goodCas].join(', ')})` : ''}; at least two different TSA CAs are required`);
      // A token issued after the signing key's validity ended cannot vouch for a receipt dated inside it (the service's rule).
      const times = report.timestamps.filter((t) => t.ok && t.gen_time).map((t) => t.gen_time!);
      const earliest = isoMin(times);
      if (compromisedSince !== null) {
        const before = earliest !== null && Date.parse(earliest) < Date.parse(compromisedSince) - KEY_TIME_SKEW_MS;
        if (!before) keyEndOk.set(base, false);
        if (!before) report.ok = false;
        add(
          'timestamp',
          'receipts',
          base,
          'stamped before compromise',
          before,
          before
            ? `${r.service_key_id} is revoked (compromised since ${compromisedSince}); earliest verified TSA time ${earliest} < ${compromisedSince} − 5 min`
            : `${r.service_key_id} is revoked (compromised since ${compromisedSince}); ${earliest ? `earliest verified TSA time ${earliest} is not before ${compromisedSince} − 5 min` : 'no verified TSA time'} (received_at is the signer's own claim and does not count)`,
        );
      }
      if (entry && earliest) {
        const end = entry.valid_to ? Date.parse(entry.valid_to) : null;
        const fine = end === null || Date.parse(earliest) <= end + CLOCK_SKEW_MS;
        if (!fine || !keyEndOk.has(base)) keyEndOk.set(base, fine);
        add('timestamp', 'receipts', base, 'stamped within key validity', fine, fine ? `earliest TSA time ${earliest}${end === null ? `; ${r.service_key_id} has no valid_to` : ` ≤ ${r.service_key_id} valid_to ${entry.valid_to} + 5 min`}` : `earliest TSA time ${earliest} is after ${r.service_key_id} ended at ${entry.valid_to}`);
      }
    }
    timeline(result.anchors, full, events !== null, to, vb.root, vb.manifest_sha256, keyEndOk);
  }

  function checkRollback(list: ServiceKeyEntry[]): void {
    const path = join(opts.seen_dir!, SEEN_KEYS_FILE);
    let cache: { v: 1; lists: Record<string, { seen_at: string; keys: ServiceKeyEntry[] }> } = { v: 1, lists: {} };
    if (exists(path)) {
      try {
        const j = JSON.parse(readFileSync(path, 'utf8')) as unknown;
        if (!isJsonObject(j) || !isJsonObject(j['lists'])) throw new Error('no lists');
        cache = j as typeof cache;
      } catch {
        add('keys', 'receipts', null, 'key list rollback', false, `${path} is unreadable; fix or remove it (it records the newest key list seen)`);
        return;
      }
    }
    const slot = formatGenesisPin(pin);
    const prev = cache.lists[slot];
    const rollback = prev ? keyListRegression(keyListOf({ keys: prev.keys }) ?? [], list) : null;
    if (rollback) {
      add('keys', 'receipts', null, 'key list rollback', false, `anchor-keys.json is an older or weaker list than the one seen ${prev!.seen_at}: ${rollback}`);
      return;
    }
    const grew = !prev || canonicalize(prev.keys) !== canonicalize(list);
    add('keys', 'receipts', null, 'key list rollback', true, prev ? `at least as new as the list seen ${prev.seen_at} (${prev.keys.length} key(s))` : 'first list seen for this genesis; recorded');
    if (grew) {
      cache.lists[slot] = { seen_at: (opts.now ?? new Date()).toISOString(), keys: list };
      try {
        mkdirSync(opts.seen_dir!, { recursive: true, mode: 0o700 });
        const tmp = `${path}.${process.pid}.tmp`;
        writeFileSync(tmp, JSON.stringify(cache, null, 1) + '\n', { mode: 0o600 });
        chmodSync(tmp, 0o600);
        renameSync(tmp, path);
      } catch {
        // a read-only data dir: the check above still ran against what was cached
      }
    }
  }

  function checkSums(auditorPem: string, keyId: string): boolean {
    const sumsPath = join(dir, 'SHA256SUMS');
    if (!exists(sumsPath)) return add('pack', 'integrity', null, 'SHA256SUMS', false, 'SHA256SUMS is missing');
    let sums: Buffer;
    let sig: Buffer;
    try {
      sums = readBundleFile(sumsPath, MAX_SUMS_BYTES, { allowHardlinks });
      sig = readBundleFile(join(dir, 'SHA256SUMS.sig'), 1024, { allowHardlinks });
    } catch (err) {
      return add('pack', 'integrity', null, 'SHA256SUMS', false, (err as Error).message);
    }
    if (sig.length !== 64 || !verifyEd25519Strict(auditorPem, sums, sig.toString('base64'))) {
      return add('pack', 'integrity', null, 'SHA256SUMS', false, `SHA256SUMS.sig is not an Ed25519 signature of SHA256SUMS by ${keyId}`);
    }
    const listed = new Map<string, string>();
    for (const [i, line] of sums.toString('utf8').split('\n').entries()) {
      if (line === '') continue;
      const m = line.match(/^([0-9a-f]{64}) {2}(.+)$/);
      if (!m || !SAFE_PATH.test(m[2]!) || listed.has(m[2]!) || (SUMS_FILES as readonly string[]).includes(m[2]!)) {
        return add('pack', 'integrity', null, 'SHA256SUMS', false, `SHA256SUMS line ${i + 1} is not "<sha256>  <relative path>" for a pack file`);
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
    return add('pack', 'integrity', null, 'SHA256SUMS', problems.length === 0, problems.length === 0 ? `${listed.size} file(s) match; signed by ${keyId}` : problems.slice(0, 3).join('; '));
  }

  function checkRunSequence(haveEvents: boolean, full: BundleEvent[]): void {
    const rs = result.run_sequence;
    const fail = (why: string) => {
      rs.status = 'fail';
      rs.problem = why;
      add('runs', 'run_sequence', null, 'run sequence', false, why);
    };
    if (!haveEvents) return fail('not checked: the bundle does not verify');
    const runs = full.filter((e) => e.kind === 'run_completed');
    if (runs.length === 0) return fail('the bundle holds no run_completed events');
    const bad = runs.filter((r) => !Number.isSafeInteger(r.payload?.['run_seq']) || (r.payload!['run_seq'] as number) < 1);
    if (bad.length) return fail(`run_seq of seq ${bad.map((r) => r.seq).slice(0, 10).join(', ')} is not an integer ≥ 1`);
    rs.seqs = runs.map((r) => r.payload!['run_seq'] as number).sort((a, b) => a - b);
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

  interface Valid {
    base: string;
    a: AnchorReport;
    from: number;
    to: number;
    svc: string;
    tsa: Map<string, string>;
    /** Latest verified time (the "no later than" bound). */
    time: string;
    /** Earliest verified time. */
    first: string;
    clock: 'tsa' | 'service';
  }

  function timeline(anchors: AnchorReport[], full: BundleEvent[], haveEvents: boolean, to: number | null, bundleRoot: string | null, manifestSha: string | null, keyEndOk: Map<string, boolean> | null): void {
    const useTsa = !noTsa && on('independent_timestamps');
    const valid: Valid[] = [];
    for (const a of anchors) {
      if (!a.ok || a.from_seq === null || a.to_seq === null || a.received_at === null) continue;
      const base = a.file.slice(0, -'.receipt.json'.length);
      const good = a.timestamps.filter((t) => t.ok && t.gen_time);
      const cas = new Set(good.map((t) => t.ca).filter(Boolean));
      if (useTsa && (cas.size < 2 || a.timestamps.some((t) => !t.ok) || keyEndOk?.get(base) === false)) continue;
      const tsa = new Map(good.map((t) => [t.tsa, t.gen_time!] as const));
      valid.push({
        base,
        a,
        from: a.from_seq,
        to: a.to_seq,
        svc: a.received_at,
        tsa,
        time: useTsa ? isoMax([...tsa.values()])! : a.received_at,
        first: useTsa ? isoMin([...tsa.values()])! : a.received_at,
        clock: useTsa ? 'tsa' : 'service',
      });
    }
    valid.sort((x, y) => x.to - y.to || Date.parse(x.svc) - Date.parse(y.svc));
    if (on('receipts') && anchors.length > 0) {
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
        add('timeline', 'receipts', null, 'anchor order', bad.length === 0, bad.length === 0 ? `${valid.map((v) => v.base).join(' → ')}: ranges extend, every clock moves forward` : bad.join('; '));
      } else add('timeline', 'receipts', null, 'anchor order', 'not_applicable', `${valid.length} verified anchor(s)`);
      if (haveEvents) {
        const uncovered = full.filter((e) => !valid.some((v) => v.from <= e.seq && e.seq <= v.to)).map((e) => e.seq);
        const what = useTsa ? 'timestamped anchors' : 'verified anchors';
        add(
          'timeline',
          'receipts',
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
    if (on('harness_frozen_before_runs')) {
      if (noTsa) result.ordering.status = 'not_checked';
      else checkOrdering(full, haveEvents, committing);
    }
  }

  function checkOrdering(full: BundleEvent[], haveEvents: boolean, committing: (seq: number) => Valid | null): void {
    const o = result.ordering;
    const label = 'harness frozen before runs';
    const fail = (why: string) => {
      o.status = 'fail';
      o.problem = why;
      add('ordering', 'harness_frozen_before_runs', null, label, false, why);
    };
    if (!haveEvents) return fail('not checked: the bundle does not verify');
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
    if (!fa) return fail(`the freeze event (seq ${freeze.seq}) is not committed by a timestamped anchor`);
    const withFreeze = runs.filter((r) => r.seq <= fa.to);
    if (withFreeze.length > 0) return fail(`the freeze event (seq ${freeze.seq}) is first committed by ${fa.base} together with ${withFreeze.length} run(s) (seq ${withFreeze[0]!.seq}..${withFreeze[withFreeze.length - 1]!.seq})`);
    // Every run is committed by a later timestamped anchor.
    const runAnchor = new Map<number, Valid>();
    const uncommitted: number[] = [];
    for (const r of runs) {
      const ra = committing(r.seq);
      if (!ra || ra.to <= fa.to || Date.parse(ra.first) < Date.parse(fa.time)) uncommitted.push(r.seq);
      else runAnchor.set(r.seq, ra);
    }
    if (uncommitted.length) return fail(`run seq ${uncommitted.slice(0, 10).join(', ')} ${uncommitted.length > 1 ? 'are' : 'is'} not committed by a timestamped anchor later than the freeze anchor ${fa.base}`);
    const wrongNonce = runs.filter((r) => typeof r.payload?.['nonce'] === 'string' && r.payload['nonce'] !== digest);
    if (wrongNonce.length > 0) return fail(`run seq ${wrongNonce.map((r) => r.seq).join(', ')} carries a nonce that is not the freeze receipt digest ${digest}`);
    const freezeAt = `harness ${short(harness)} frozen, committed ${fa.time} (${fa.base}, RFC 3161)`;
    if (nonceBound === runs.length) {
      o.status = 'pass';
      o.basis = 'freeze_nonce';
      add('ordering', 'harness_frozen_before_runs', null, label, true, `${freezeAt}; ${runs.length}/${runs.length} run(s) name that harness, carry the freeze receipt digest ${digest} and are committed by later timestamped anchors (${[...new Set([...runAnchor.values()].map((v) => v.base))].join(', ')})`);
      return;
    }
    if (result.bundle_format === BUNDLE_FORMAT_V2) return fail(`a ${BUNDLE_FORMAT_V2} bundle shows the ordering by the freeze nonce only; ${runs.length - nonceBound} of ${runs.length} run(s) do not carry it`);
    o.basis = 'recorded_measured_at';
    // measured_at is the auditor's record: accept it only inside the window the timestamps prove.
    const outside: string[] = [];
    for (const r of runs) {
      if (typeof r.payload?.['nonce'] === 'string') continue;
      const m = sOrNull(r.payload?.['measured_at']);
      const ra = runAnchor.get(r.seq)!;
      const tm = m === null ? Number.NaN : Date.parse(m);
      if (!Number.isFinite(tm)) outside.push(`seq ${r.seq} records no measured_at`);
      else if (tm < Date.parse(fa.time)) outside.push(`seq ${r.seq} measured_at ${m} is before the freeze ${fa.time}`);
      else if (tm > Date.parse(ra.first)) outside.push(`seq ${r.seq} measured_at ${m} is after its committing anchor ${ra.base} (${ra.first})`);
    }
    if (outside.length) return fail(`${freezeAt}; ${outside.length} of ${runs.length} run(s) fall outside the timestamped window: ${outside.slice(0, 3).join('; ')}`);
    o.status = 'pass';
    add('ordering', 'harness_frozen_before_runs', null, label, true, `${freezeAt}; ${runs.length} run(s) name that harness, with measured_at ${o.runs.first_measured_at}${runs.length > 1 ? ` to ${o.runs.last_measured_at}` : ''} between the freeze and their committing anchors' TSA times`);
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
  auditor: z.strictObject({ key_id: z.string().nullable(), spki_sha256: z.string().nullable(), source: z.enum(['key_file', 'fingerprint', 'unpinned']) }),
  trust: z.strictObject({
    key_list: z.enum(['pack', 'file']),
    genesis_sha256: z.string().regex(/^[0-9a-f]{64}$/),
    genesis_valid_from: z.string(),
    genesis_source: z.enum(['compiled', 'option']),
    key_chain: z.strictObject({
      status: z.enum(['intact', 'revoked_descendants', 'broken', 'not_checked']),
      detail: z.string(),
      entries: z.array(
        z.strictObject({
          key_id: z.string(),
          state: z.enum(['genesis', 'verified', 'revoked', 'broken']),
          detail: z.string(),
          compromised_since: z.string().nullable(),
          revoked_ancestor: z.string().nullable(),
        }),
      ),
    }),
    tsa_roots: z.enum(['shipped', 'dir', 'skipped']),
    tsa_root_sha256: z.array(z.string().regex(/^[0-9a-f]{64}$/)),
    tsa_time: z.enum(['now', 'gentime']),
  }),
  claims: z.array(z.strictObject({ claim: z.enum(CLAIMS), status: z.enum(['pass', 'fail', 'not_declared', 'not_checked']), declared: z.boolean(), required: z.boolean(), evidence: z.string() })).length(CLAIMS.length),
  checks: z.array(
    z.strictObject({ group: z.enum(['pack', 'bundle', 'keys', 'anchor', 'timestamp', 'timeline', 'ordering', 'runs']), claim: z.enum(CLAIMS).nullable(), subject: z.string().nullable(), check: z.string(), status: STATUS, evidence: z.string() }),
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
      timestamps: z.array(z.strictObject({ file: z.string(), tsa: z.string(), ok: z.boolean(), gen_time: z.string().nullable(), signer: z.string().nullable(), root: z.string().nullable(), ca: z.string().nullable(), problem: z.string().nullable() })),
    }),
  ),
  ordering: z.strictObject({
    status: z.enum(['pass', 'fail', 'not_declared', 'not_checked']),
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
const GROUP_TITLE: Record<CheckGroup, string> = { pack: 'Pack', bundle: 'Evidence bundle', keys: 'Anchor service keys', anchor: 'Anchors', timestamp: 'Anchors', timeline: 'Timeline', ordering: 'Ordering', runs: 'Runs' };

/** The human-readable report: claims, one PASS / FAIL / N/A line per check with its evidence, values to compare. */
export function renderVerifyAudit(r: VerifyAuditResult): string {
  const L: string[] = [];
  const line = (c: AuditCheck, indent = '  ', w = 26) => L.push(`${indent}${LABEL[c.status].padEnd(4)}  ${c.check.padEnd(w)} ${c.evidence}`);
  L.push(`${PACK_NAME}  ${r.package}`);
  L.push(`audit          ${r.audit_id ?? '?'}${r.bundle_format ? `  (${r.bundle_format})` : ''}`);
  L.push(`auditor key    ${r.auditor.key_id ?? '?'}  spki sha256 ${r.auditor.spki_sha256 ?? '?'}  (${r.auditor.source === 'fingerprint' ? 'pinned by --key-fingerprint' : r.auditor.source === 'key_file' ? 'pinned by --key' : 'NOT pinned'})`);
  L.push(`service keys   genesis ${r.trust.genesis_sha256}@${r.trust.genesis_valid_from} (${r.trust.genesis_source === 'compiled' ? 'compiled pin' : '--genesis'}); key list from ${r.trust.key_list === 'pack' ? 'anchor-keys.json' : '--anchor-keys'}: ${r.trust.key_chain.status}`);
  L.push(`TSA CAs        ${r.trust.tsa_roots === 'skipped' ? 'not used (--no-tsa)' : `${r.trust.tsa_roots === 'shipped' ? 'shipped timestamping CA pins (Sectigo R46, DigiCert G4 TimeStamping)' : '--tsa-roots'}, validity checked at ${r.trust.tsa_time === 'now' ? 'the current time' : 'genTime'}`}`);
  L.push('', 'Claims');
  for (const c of r.claims) L.push(`  ${LABEL[c.status].padEnd(12)}  ${c.claim.padEnd(27)} ${c.evidence}`.trimEnd());
  for (const g of ['pack', 'bundle', 'keys'] as const) {
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
