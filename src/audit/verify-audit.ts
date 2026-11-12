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
 * Profiles (0.11.0):
 *   audit    (default) every claim is checked, whatever claims.json says (it may add claims, never
 *            remove them); the bundle must be format /3 and hold this audit only (no stubs); anchors
 *            must close the freeze, the last run and the report, each stamped by two TSA CAs; the
 *            SHA256SUMS file is stamped too; no stamp may be pending. Exit 0 = VERIFIED.
 *   legacy   the 0.10.0 rules (claims.json picks the claims) for packs made before 0.11.0. The best
 *            result is PARTIAL (exit 2): the checks that ran passed, the audit profile was not met.
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
 *                               by a later timestamped anchor; every run carries the freeze nonce, the only
 *                               basis in every bundle format (measured_at is the auditor's own record)
 *   run_sequence                run_completed.run_seq is integers 1..N with no gap or repeat, N agrees with
 *                               every declared count, and the interruptions claims.json lists are the runs
 *                               whose capture was interrupted
 *   plan_complete               (/3) one freeze with a plan of run IDs; every run_completed / run_abandoned
 *                               names a planned run, each planned run ends exactly once (abandoned with a
 *                               reason), planned_runs and the report's run_count agree
 *   reproductions_signed        every accepted finding has a human sign-off (reproduction_signed) whose SSH
 *                               signature verifies under an allowed-signers entry that is not the auditor key
 *   closed                      one audit_closed, the bundle's last event, after the report it names, with the
 *                               run count and the digest of every finding's final status
 *
 * Hostile input yields failed checks, never a throw.
 */

import { createPublicKey, X509Certificate } from 'node:crypto';
import { chmodSync, closeSync, fstatSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, readSync, realpathSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, sep } from 'node:path';

import { z } from 'zod';

import { rawEd25519PublicKey, verifyEd25519Strict } from '../anchor/ed25519-strict.js';
import { checkKeyChain, checkServiceKey, formatGenesisPin, KEY_TIME_SKEW_MS, keyListOf, keyListRegression, parseGenesisPin, PRODUCTION_GENESIS, type GenesisPin, type ServiceKeyEntry } from '../anchor/keychain.js';
import { parseAnchorReceipt, verifyAnchorReceiptSignature, type AnchorReceipt } from '../anchor/receipt.js';
import { isJsonObject } from '../anchor/wire.js';
import { checkpointSigningPayload } from '../chain/chain.js';
import { merkleRootHex } from '../chain/merkle.js';
import { canonicalize } from '../crypto/canonical.js';
import { sha256Hex } from '../crypto/hash.js';
import { chainIdFromPublicKeyPem, keyIdFromPublicKey } from '../crypto/keys.js';
import { findFreezePending, FREEZE_PENDING_RECORD, type FreezePending } from './freeze-pending.js';
import { finalFindingStatuses, findingsDigest, freezeNonce, REPRODUCTION_NAMESPACE, reproductionStatement } from './profile.js';
import { MAX_TSR_BYTES, verifyTimestamp } from './rfc3161.js';
import { BUNDLE_FORMAT_V3, kindOfEventType } from './schemas.js';
import { MAX_SSHSIG_BYTES, verifySshSignature } from './sshsig.js';
import { SHIPPED_TSA_EXTRAS, SHIPPED_TSA_ROOTS } from './tsa-roots.js';
import { DEFAULT_MAX_BUNDLE_BYTES, hashRegularFile, MAX_BUNDLE_BLOB_BYTES, MAX_MANIFEST_BYTES, readBundleFile, verifyBundle } from './verify-bundle.js';

/** /3 (A8): the verdict verified_late_anchor, ordering basis pending_freeze and the late_anchor report. */
export const VERIFY_AUDIT_FORMAT = 'kronicle-lite-verify-audit/3';
export const PACK_NAME = 'IsoKron Evidence Pack';
export const CLAIMS_FORMAT = 'isokron-evidence-pack-claims/1';
export const CLAIMS = ['integrity', 'chain', 'receipts', 'independent_timestamps', 'harness_frozen_before_runs', 'run_sequence', 'plan_complete', 'reproductions_signed', 'closed'] as const;
export type Claim = (typeof CLAIMS)[number];
/** The 0.10.0 claims (what a legacy pack can declare). */
export const LEGACY_CLAIMS: readonly Claim[] = ['integrity', 'chain', 'receipts', 'independent_timestamps', 'harness_frozen_before_runs', 'run_sequence'];
export const PROFILES = ['audit', 'legacy'] as const;
export type Profile = (typeof PROFILES)[number];
/** The audit profile checks all of these on every pack; claims.json may add to them, never remove one. */
export const AUDIT_PROFILE_CLAIMS: readonly Claim[] = CLAIMS;
/**
 * verified: the audit profile, every claim checked and passed. verified_late_anchor (A8): the same,
 * for a freeze made with the anchor pending and anchored later; the two freeze-anchor checks are
 * shown instead by the pending-freeze record, and the unwitnessed window is reported (exit 0;
 * --strict-freeze turns it back into FAILED). partial: every check that ran passed, but the audit
 * profile was not met (--profile legacy, or a claim skipped by user): exit 2. not_verified: a claim
 * the pack needs was not checked. failed: a check failed.
 */
export type Verdict = 'verified' | 'verified_late_anchor' | 'partial' | 'not_verified' | 'failed';
/**
 * The RESULT line's verdict for verified_late_anchor. A plain pass is exactly `RESULT: VERIFIED` and
 * two spaces; this one never is, so a script that keys on the verdict cannot take it for one. Scripts
 * should read `--json` `.verdict`: `ok` (and exit 0) is true for both.
 */
export const LATE_ANCHOR_RESULT = 'VERIFIED WITH UNWITNESSED WINDOW (FREEZE ANCHORED LATE)';
export const VERDICTS = ['verified', 'verified_late_anchor', 'partial', 'not_verified', 'failed'] as const;

/**
 * The two audit-profile checks a late freeze anchor cannot pass (its proof is a freeze anchor that
 * commits no run), matched exactly: anything else in their evidence keeps them failed.
 */
export const LATE_ANCHOR_REPLACEABLE: readonly { claim: Claim; check: string; evidence: RegExp }[] = [
  { claim: 'receipts', check: 'milestone anchors', evidence: /^missing an anchor after the freeze \(seq \d+\) that commits no run(?: \(the first is seq \d+\))? \([^;]*\)$/ },
  { claim: 'harness_frozen_before_runs', check: 'harness frozen before runs', evidence: /^the freeze event \(seq \d+\) is first committed by \S+ together with \d+ run\(s\) \(seq \d+\.\.\d+\)$/ },
  // Anchored after the freeze but before the runs: the runs carry the pending-freeze nonce, not the anchor's.
  { claim: 'harness_frozen_before_runs', check: 'harness frozen before runs', evidence: /^run seq [\d, ]+ carries a nonce that is not the derived freeze nonce sha256\(\S+ receipt digest ‖ its \d+ TSA token\(s\)\) = [0-9a-f]{64}$/ },
];

/** A freeze made with the anchor pending and anchored later (A8). */
export interface LateAnchorReport {
  /**
   * none: no pending-freeze record (a normal freeze). accepted: the record proves the freeze order and a
   * later anchor commits the freeze and every run; the two freeze-anchor checks are replaced. not_needed:
   * a record is there but the freeze anchor commits no run anyway. rejected: the record or its proof
   * fails. strict: --strict-freeze, the record was not used.
   */
  status: 'none' | 'accepted' | 'not_needed' | 'rejected' | 'strict';
  source: FreezePending['source'] | null;
  nonce: string | null;
  checkpoint_to_seq: number | null;
  /** The RFC 3161 times over the record's SHA256SUMS. */
  freeze_stamped: { tsa: string; gen_time: string | null; ca: string | null }[];
  /** The anchor that commits the freeze and every run. */
  anchor: { file: string; from_seq: number; to_seq: number; received_at: string; first_tsa_time: string } | null;
  /**
   * From the freeze stamp to the late anchor's first TSA time: the events after the freeze were held
   * only by the auditor's key, with no third party, until the late anchor.
   */
  window: { from: string; to: string; ms: number; seqs: { from: number; to: number } | null; events: number; runs: number } | null;
  replaced: { claim: Claim; check: string; evidence: string }[];
  problem: string | null;
}
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
/** RFC 3161 replies over SHA256SUMS (0.11.0): `SHA256SUMS.<tsa>.tsr`, made after it, so not listed in it. */
export const SUMS_TOKEN = /^SHA256SUMS\.([a-z0-9][a-z0-9-]{0,31})\.tsr$/;
/** A file SHA256SUMS does not list: SHA256SUMS, its signature and its timestamp replies. */
export const isSumsFile = (f: string): boolean => (SUMS_FILES as readonly string[]).includes(f) || SUMS_TOKEN.test(f);
/** A stamp that was asked for and not obtained (`<name>.<tsa>.pending`): the audit profile fails while one is in the pack. */
export const PENDING_SUFFIX = '.pending';
/** The reproducers' public keys (ssh-keygen ALLOWED SIGNERS format), in the pack root. */
export const ALLOWED_SIGNERS_FILE = 'allowed_signers';
/** The rollback cache in the data dir: the newest anchor key list seen per genesis pin. */
export const SEEN_KEYS_FILE = 'anchor-keys.seen.json';
interface SeenKeysFile {
  v: 1;
  lists: Record<string, { seen_at: string; keys: ServiceKeyEntry[] }>;
}
const KEY_ENTRY_FIELDS = ['status', 'valid_from', 'valid_to', 'successor_signature', 'signed_by', 'retirement_signature', 'retirement_signed_by', 'compromised_since'] as const;
/** null when `raw` is a well-formed rollback cache (every slot a canonical pin with a non-empty, well-typed key list); else what is wrong. */
export function seenKeysProblem(raw: unknown): string | null {
  if (!isJsonObject(raw) || raw['v'] !== 1) return 'has the wrong shape (expected {v: 1, lists: {…}})';
  const lists = raw['lists'];
  if (!isJsonObject(lists)) return 'has the wrong shape (lists is not an object)';
  for (const [slot, rec] of Object.entries(lists)) {
    const p = parseGenesisPin(slot);
    const name = slot.slice(0, 90);
    if (p === null || formatGenesisPin(p) !== slot) return `has the wrong shape (slot ${name} is not a canonical genesis pin)`;
    if (!isJsonObject(rec)) return `has the wrong shape (slot ${name} is not an object)`;
    if (typeof rec['seen_at'] !== 'string' || !Number.isFinite(Date.parse(rec['seen_at']))) return `has the wrong shape (slot ${name}: seen_at is not a timestamp)`;
    const keys = rec['keys'];
    if (!Array.isArray(keys) || keys.length === 0) return `has the wrong shape (slot ${name}: keys is not a non-empty array)`;
    for (const k of keys) {
      if (!isJsonObject(k) || typeof k['key_id'] !== 'string' || typeof k['public_key_pem'] !== 'string') return `has the wrong shape (slot ${name}: a key entry lacks key_id or public_key_pem)`;
      for (const f of KEY_ENTRY_FIELDS) if (k[f] !== undefined && k[f] !== null && typeof k[f] !== 'string') return `has the wrong shape (slot ${name}: ${k['key_id']} ${f} is not a string)`;
    }
  }
  return null;
}
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

export type CheckGroup = 'pack' | 'bundle' | 'keys' | 'anchor' | 'timestamp' | 'timeline' | 'ordering' | 'runs' | 'plan' | 'signoff' | 'close';
export type CheckStatus = 'pass' | 'fail' | 'not_applicable';
/** not_checked blocks exit 0 (a claim the pack makes that was not verified); skipped is the user's explicit --skip-claim. */
export type ClaimStatus = 'pass' | 'fail' | 'not_declared' | 'not_checked' | 'skipped';

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
  /** freeze_nonce: the freeze receipt digest (/1, /2); derived_nonce: sha256(receipt digest ‖ its TSA tokens) (/3); pending_freeze: the pending-freeze record's nonce over its TSA tokens (A8). */
  basis: 'freeze_nonce' | 'derived_nonce' | 'pending_freeze' | null;
  /** The nonce every run must carry, as the verifier computed it. */
  nonce: string | null;
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

export interface PlanReport {
  status: 'pass' | 'fail' | 'not_declared';
  planned: string[];
  completed: string[];
  abandoned: { run_id: string; reason: string }[];
  problem: string | null;
}

export interface ReproductionReport {
  seq: number;
  finding_id: string | null;
  signer: string | null;
  ok: boolean;
  /** SHA256:… of the reproducer key (ssh-keygen -l). */
  key: string | null;
  problem: string | null;
}

export interface CloseReport {
  status: 'pass' | 'fail' | 'not_declared';
  seq: number | null;
  report_id: string | null;
  run_count: number | null;
  findings_digest: string | null;
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
  /** verdict === 'verified'. */
  ok: boolean;
  profile: Profile;
  verdict: Verdict;
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
    /** compiled: the shipped pin; option: --genesis (or the library option); env: KRONICLE_ANCHOR_GENESIS. */
    genesis_source: 'compiled' | 'option' | 'env';
    /**
     * The rollback check against the data-dir cache. checked: the list is at least as new as the one
     * kept (or failed against it); first_seen: nothing kept for this pin yet, the list is now recorded
     * (or could not be: recorded false); off: the library caller opted out; not_checked: the list was
     * not usable, so nothing was compared or kept.
     */
    rollback: { status: 'checked' | 'first_seen' | 'off' | 'not_checked'; path: string | null; seen_at: string | null; recorded: boolean };
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
  plan: PlanReport;
  reproductions: ReproductionReport[];
  closed: CloseReport;
  /** RFC 3161 replies over SHA256SUMS. */
  sums_timestamps: AnchorTimestampReport[];
  timeline: TimelineEntry[];
  late_anchor: LateAnchorReport;
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
  /** audit (default): every claim, /3 rules; legacy: the 0.10.0 rules, PARTIAL at best. */
  profile?: Profile;
  /** Allowed-signers text for the reproducers, obtained out of band (default: the pack's allowed_signers). */
  allowed_signers?: string;
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
  /** Claims the caller explicitly does not check (--skip-claim): reported as skipped by user, never as passing. */
  skip_claims?: Claim[];
  /** Claims the caller requires: each is checked (with what it depends on) and must pass, declared or not. */
  require?: Claim[];
  /** Check exactly these claims and skip SHA256SUMS / claims.json (the packager's own pass, before they exist). */
  claims_override?: readonly Claim[];
  /** Directory of the rollback cache (anchor-keys.seen.json): the data dir. Required unless rollback is 'off'. */
  seen_dir?: string;
  /** 'off' skips the rollback check, explicitly (reported as such); otherwise seen_dir is required. */
  rollback?: 'on' | 'off';
  /** Where `genesis` came from, for the report (default 'option'). */
  genesis_source?: 'option' | 'env';
  /**
   * A freeze made with the anchor pending and anchored later (A8). accept (default): a valid
   * pending-freeze record replaces the two freeze-anchor checks (verdict verified_late_anchor).
   * strict: the record is not used; such a pack FAILS those two checks (--strict-freeze).
   */
  late_anchor?: 'accept' | 'strict';
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
export function genesisFromCli(flag: string | undefined, env: NodeJS.ProcessEnv = process.env): { genesis?: string; genesis_source?: 'option' | 'env' } {
  if (env['KRONICLE_ANCHOR_GENESIS_SHA256'] !== undefined) {
    throw new VerifyAuditUsageError("KRONICLE_ANCHOR_GENESIS_SHA256 is no longer read: set KRONICLE_ANCHOR_GENESIS=<sha256>@<valid_from> (the genesis key's valid_from is part of the pin)");
  }
  const source = flag !== undefined ? 'option' : env['KRONICLE_ANCHOR_GENESIS'] !== undefined ? 'env' : null;
  if (source === null) return {};
  const v = flag ?? env['KRONICLE_ANCHOR_GENESIS']!;
  if (parseGenesisPin(v) === null) throw new VerifyAuditUsageError(`${source === 'option' ? '--genesis' : 'KRONICLE_ANCHOR_GENESIS'} must be <sha256>@<valid_from> (the genesis key's SPKI SHA-256 and its valid_from, ISO 8601 UTC)`);
  return { genesis: v, genesis_source: source };
}

/**
 * Trust inputs (--key, --anchor-keys, --tsa-roots) must come from outside the pack: whoever made the
 * pack wrote everything in it. Throws when `p` resolves (symlinks followed) to the pack directory or
 * anything under it, or is a hard link to a file in the pack.
 */
export function refuseInsidePack(packDir: string, p: string, flag: string): void {
  // Decided by filesystem identity (dev, ino), not by comparing path strings: on a case- or
  // normalization-insensitive filesystem (APFS, NTFS) `…/PACKAGE/x` and `…/package/x` are one file.
  // realpathSync.native first (the OS's canonical path); the JS resolver where the native one fails
  // (libuv's Windows realpath refuses some non-ASCII paths). Either way the decision below is by identity.
  const resolve = (x: string) => {
    try {
      return realpathSync.native(x);
    } catch {
      return realpathSync(x);
    }
  };
  let pack: string;
  let real: string;
  try {
    pack = resolve(packDir);
    real = resolve(p);
  } catch (err) {
    throw new VerifyAuditUsageError(`${flag} ${p}: ${(err as Error).message}`);
  }
  const id = (x: string) => {
    const st = statSync(x, { bigint: true });
    return `${st.dev}:${st.ino}`;
  };
  const packId = id(pack);
  const inside = () => new VerifyAuditUsageError(`${flag} ${p} is inside the pack; trust inputs must come from outside it (the auditor key fingerprint from the statement of work)`);
  // the input itself, then every directory above it, up to the root
  for (let d = real; ; ) {
    if (id(d) === packId) throw inside();
    const up = dirname(d);
    if (up === d) break;
    d = up;
  }
  // belt and braces: the path strings too
  const rel = relative(pack, real);
  if (!(rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel))) throw inside();
  // the same file as one inside the pack (a hard link, or any other route to it)
  const st = statSync(real, { bigint: true });
  if (st.isFile() && packInodes(pack).has(`${st.dev}:${st.ino}`)) {
    throw new VerifyAuditUsageError(`${flag} ${p} is ${st.nlink > 1n ? 'a hard link to ' : ''}a file inside the pack; trust inputs must come from outside it`);
  }
}
const MAX_PACK_ENTRIES = 200_000;
/** (dev, ino) of every regular file under the pack. Fails closed when the pack is too deep or too large to list. */
function packInodes(pack: string): Set<string> {
  const out = new Set<string>();
  let entries = 0;
  const walk = (d: string, depth: number) => {
    if (depth > 64) throw new VerifyAuditUsageError(`the pack is nested deeper than 64 directories; trust inputs cannot be checked against it`);
    for (const e of readdirSync(d, { withFileTypes: true })) {
      if (++entries > MAX_PACK_ENTRIES) throw new VerifyAuditUsageError(`the pack holds more than ${MAX_PACK_ENTRIES} entries; trust inputs cannot be checked against it`);
      const f = join(d, e.name);
      if (e.isDirectory()) walk(f, depth + 1);
      else if (e.isFile()) {
        const st = lstatSync(f, { bigint: true });
        out.add(`${st.dev}:${st.ino}`);
      }
    }
  };
  walk(pack, 0);
  return out;
}

/** An opened trust input: checked by the identity of the open file, read from the same descriptor. */
export interface OpenTrustInput {
  /** Reads the whole file from the checked descriptor (at most `maxBytes`). */
  read(): Buffer;
  close(): void;
}

/**
 * T8: open a trust input (--key, --anchor-keys, a --tsa-roots file) ONCE. The path checks run first
 * (refuseInsidePack); then the descriptor's own (dev, ino), from fstat, must be a regular file that
 * is not a file of the pack; and the content is read from that descriptor. Swapping the path (a
 * symlink flipped after the check) cannot change what is read.
 */
export function openTrustInput(packDir: string, p: string, flag: string, maxBytes: number): OpenTrustInput {
  refuseInsidePack(packDir, p, flag);
  let fd: number;
  try {
    fd = openSync(p, 'r');
  } catch (err) {
    throw new VerifyAuditUsageError(`${flag} ${p}: ${(err as Error).message}`);
  }
  try {
    const st = fstatSync(fd, { bigint: true });
    if (!st.isFile()) throw new VerifyAuditUsageError(`${flag} ${p} is not a regular file`);
    let pack: string;
    try {
      pack = realpathSync.native(packDir);
    } catch {
      pack = realpathSync(packDir);
    }
    if (packInodes(pack).has(`${st.dev}:${st.ino}`)) throw new VerifyAuditUsageError(`${flag} ${p} is a file inside the pack; trust inputs must come from outside it`);
    if (st.size > BigInt(maxBytes)) throw new VerifyAuditUsageError(`${flag} ${p} is larger than ${maxBytes} bytes`);
  } catch (err) {
    closeSync(fd);
    throw err;
  }
  let open = true;
  return {
    read(): Buffer {
      const chunks: Buffer[] = [];
      let total = 0;
      let pos = 0;
      for (;;) {
        const buf = Buffer.alloc(64 * 1024);
        const n = readSync(fd, buf, 0, buf.length, pos);
        if (n === 0) break;
        pos += n;
        total += n;
        if (total > maxBytes) throw new VerifyAuditUsageError(`${flag} ${p} is larger than ${maxBytes} bytes`);
        chunks.push(buf.subarray(0, n));
      }
      return Buffer.concat(chunks);
    },
    close(): void {
      if (open) closeSync(fd);
      open = false;
    },
  };
}

/** openTrustInput, read, close. */
export function readTrustInput(packDir: string, p: string, flag: string, maxBytes: number): Buffer {
  const h = openTrustInput(packDir, p, flag, maxBytes);
  try {
    return h.read();
  } finally {
    h.close();
  }
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
  const profile: Profile = opts.profile ?? 'audit';
  if (!(PROFILES as readonly string[]).includes(profile)) throw new VerifyAuditUsageError(`--profile must be one of ${PROFILES.join(', ')}`);
  const auditProfile = profile === 'audit';
  for (const c of opts.require ?? []) {
    if (noTsa && NEEDS_TSA.includes(c)) throw new VerifyAuditUsageError(`--require ${c} needs RFC 3161 tokens; it cannot be combined with --no-tsa`);
  }
  const skipped = new Set<Claim>(opts.skip_claims ?? []);
  for (const c of skipped) {
    if (!(CLAIMS as readonly string[]).includes(c)) throw new VerifyAuditUsageError(`--skip-claim: unknown claim ${c} (one of ${CLAIMS.join(', ')})`);
    if (ALWAYS.includes(c)) throw new VerifyAuditUsageError(`--skip-claim ${c}: ${ALWAYS.join(' and ')} are always checked`);
    if ((opts.require ?? []).includes(c)) throw new VerifyAuditUsageError(`--skip-claim ${c} contradicts --require ${c}`);
  }
  if (opts.key_fingerprint !== undefined && !HEX64.test(normFp(opts.key_fingerprint))) throw new VerifyAuditUsageError('--key-fingerprint must be the 64-hex SHA-256 of the auditor key (colons allowed)');
  const pinOrNull: GenesisPin | null = opts.genesis === undefined ? PRODUCTION_GENESIS : parseGenesisPin(opts.genesis);
  if (pinOrNull === null) throw new VerifyAuditUsageError('--genesis must be <sha256>@<valid_from> (the genesis key\'s SPKI SHA-256 and its valid_from, ISO 8601 UTC)');
  const allowHardlinks = opts.allow_hardlinks === true;
  const maxBytes = opts.max_bytes !== undefined && Number.isFinite(opts.max_bytes) && opts.max_bytes > 0 ? Math.floor(opts.max_bytes) : DEFAULT_MAX_BUNDLE_BYTES;
  const tsaAt = opts.tsa_at ?? 'now';
  const pin: GenesisPin = pinOrNull;
  const rollbackOff = opts.rollback === 'off';
  if (!rollbackOff && (typeof opts.seen_dir !== 'string' || opts.seen_dir === '')) {
    throw new VerifyAuditUsageError("seen_dir is required (the data dir that keeps the anchor key list seen per genesis pin), or pass rollback: 'off' to skip the rollback check explicitly");
  }
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
    profile,
    verdict: 'failed',
    package: dir,
    audit_id: null,
    bundle_format: null,
    manifest_sha256: null,
    auditor: { key_id: null, spki_sha256: null, source: opts.key_pem !== undefined ? 'key_file' : opts.key_fingerprint !== undefined ? 'fingerprint' : 'unpinned' },
    trust: {
      key_list: opts.anchor_keys !== undefined ? 'file' : 'pack',
      genesis_sha256: genesis,
      genesis_valid_from: pin.valid_from,
      genesis_source: opts.genesis !== undefined ? (opts.genesis_source ?? 'option') : 'compiled',
      rollback: { status: rollbackOff ? 'off' : 'not_checked', path: rollbackOff ? null : join(opts.seen_dir!, SEEN_KEYS_FILE), seen_at: null, recorded: false },
      key_chain: { status: 'not_checked', detail: '', entries: [] },
      tsa_roots: noTsa ? 'skipped' : opts.tsa_roots !== undefined ? 'dir' : 'shipped',
      tsa_root_sha256: [],
      tsa_time: tsaAt,
    },
    claims: [],
    checks,
    failed: 0,
    anchors: [],
    ordering: { status: 'not_declared', basis: null, nonce: null, harness_digest: null, freeze: null, runs: null, problem: null },
    run_sequence: { status: 'not_declared', count: null, seqs: [], declared_counts: [], interruptions: [], problem: null },
    plan: { status: 'not_declared', planned: [], completed: [], abandoned: [], problem: null },
    reproductions: [],
    closed: { status: 'not_declared', seq: null, report_id: null, run_count: null, findings_digest: null, problem: null },
    sums_timestamps: [],
    timeline: [],
    late_anchor: { status: 'none', source: null, nonce: null, checkpoint_to_seq: null, freeze_stamped: [], anchor: null, window: null, replaced: [], problem: null },
    final: null,
  };

  let claimsFile: ClaimsFile | null = null;
  let declared = new Set<Claim>();
  const required = new Set(opts.require ?? []);
  let checked = new Set<Claim>();
  /** Claims that need a claim the user skipped (claim → the skipped one): not checked, which blocks exit 0. */
  const blocked = new Map<Claim, Claim>();
  const on = (c: Claim) => checked.has(c);
  /** Set when receipts pulled in independent_timestamps: a receipt is signed by a key that is not the active head. */
  let tsaForKeys: string | null = null;
  /** Every timestamp reply read per receipt (NN-label → replies by TSA label): the /3 freeze nonce is derived from them. */
  const tokenBytes = new Map<string, { tsa: string; bytes: Buffer }[]>();
  /** The verified anchors the timeline uses (filled by timeline()), for the late-anchor check. */
  const validAnchors: Valid[] = [];
  /**
   * The policy: authenticated claims.json (or every claim), plus the always-checked ones, the required ones and their
   * dependencies. Under the audit profile every claim is checked: claims.json can add claims, never remove one.
   */
  const setPolicy = (d: Iterable<Claim>) => {
    declared = new Set(d);
    checked = new Set<Claim>([...ALWAYS, ...(auditProfile ? AUDIT_PROFILE_CLAIMS : []), ...declared, ...required]);
    for (let grew = true; grew; ) {
      grew = false;
      for (const c of [...checked]) for (const dep of DEPENDS[c] ?? []) {
          if (!checked.has(dep)) {
            checked.add(dep);
            grew = true;
          }
        }
    }
    // The user's --skip-claim: not checked; a claim that depends on a skipped one cannot be checked either.
    blocked.clear();
    for (const c of skipped) checked.delete(c);
    for (let grew = true; grew; ) {
      grew = false;
      for (const c of [...checked]) {
        const dep = (DEPENDS[c] ?? []).find((d) => skipped.has(d) || blocked.has(d));
        if (dep !== undefined) {
          checked.delete(c);
          blocked.set(c, skipped.has(dep) ? dep : blocked.get(dep)!);
          grew = true;
        }
      }
    }
  };
  setPolicy(opts.claims_override ?? CLAIMS);

  let crashed: string | null = null;
  try {
    run();
  } catch (err) {
    // why: belt and braces; each step guards its input, but a pack must never crash the verifier.
    crashed = err instanceof Error ? err.message : String(err);
    add('pack', null, null, 'verifier', false, `verifier error: ${crashed}`);
  }

  // ── claim results ──
  const summary = claimSummaries();
  for (const c of CLAIMS) {
    const mine = checks.filter((k) => k.claim === c);
    const isDeclared = declared.has(c);
    const isRequired = required.has(c);
    let status: ClaimStatus;
    let evidence: string;
    if (skipped.has(c)) {
      status = 'skipped';
      evidence = `skipped by user (--skip-claim ${c})${isDeclared ? '; the pack declares it' : ''}`;
    } else if (blocked.has(c)) {
      status = 'not_checked';
      evidence = `not checked: it depends on ${blocked.get(c)}, which was skipped by user (--skip-claim)`;
    } else if (!checked.has(c)) {
      status = 'not_declared';
      evidence = '';
    } else if (crashed !== null) {
      // The verifier stopped part way: no claim it was checking is shown as passing.
      status = 'fail';
      evidence = `not finished: the verifier stopped (${crashed})`;
    } else if (noTsa && NEEDS_TSA.includes(c)) {
      status = 'not_checked';
      evidence = `not checked (--no-tsa)${isDeclared ? '; the pack declares it: --skip-claim ' + c + ' to verify without it' : ''}`;
    } else if (mine.some((k) => k.status === 'fail')) {
      status = 'fail';
      evidence = mine.filter((k) => k.status === 'fail').map((k) => `${k.subject ? `${k.subject} ` : ''}${k.check}: ${k.evidence}`)[0]!;
    } else if (mine.some((k) => k.status === 'pass')) {
      status = 'pass';
      evidence = summary[c] ?? '';
      if (c === 'independent_timestamps' && !isDeclared && tsaForKeys !== null) evidence = `checked for receipts (${tsaForKeys}): ${evidence}`;
    } else {
      status = 'fail';
      evidence = 'nothing in the pack backs this claim';
    }
    result.claims.push({ claim: c, status, declared: isDeclared, required: isRequired, evidence });
  }
  result.failed = checks.filter((c) => c.status === 'fail').length + result.claims.filter((c) => c.status === 'fail' && !checks.some((k) => k.claim === c.claim && k.status === 'fail')).length;
  const allPassed =
    result.failed === 0 &&
    result.auditor.source !== 'unpinned' &&
    ALWAYS.every((c) => result.claims.find((x) => x.claim === c)!.status === 'pass') &&
    // A claim the pack makes (or the checks need) that was not verified blocks exit 0, unless the user skipped it.
    result.claims.every((c) => c.status !== 'fail' && c.status !== 'not_checked');
  // VERIFIED only under the audit profile with every claim checked; the legacy rules, or a claim the
  // user skipped, can at best show that what ran passed: PARTIAL.
  const failedAny = result.failed > 0 || result.claims.some((c) => c.status === 'fail') || result.auditor.source === 'unpinned';
  result.verdict = allPassed ? (auditProfile && AUDIT_PROFILE_CLAIMS.every((c) => result.claims.find((x) => x.claim === c)!.status === 'pass') ? 'verified' : 'partial') : failedAny ? 'failed' : 'not_verified';
  // A8: the same pass, but the freeze order rests on the pending-freeze record and a late anchor.
  if (result.verdict === 'verified' && result.late_anchor.status === 'accepted') result.verdict = 'verified_late_anchor';
  result.ok = result.verdict === 'verified' || result.verdict === 'verified_late_anchor';
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
    out.plan_complete = checks.find((c) => c.group === 'plan' && c.status === 'pass')?.evidence ?? '';
    out.reproductions_signed = checks.filter((c) => c.group === 'signoff' && c.status === 'pass').map((c) => c.evidence).join('; ');
    out.closed = checks.find((c) => c.group === 'close' && c.status === 'pass')?.evidence ?? '';
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
      add('pack', null, null, 'auditor key', false, `not pinned: pass --key-fingerprint with the auditor key fingerprint from the statement of work (the pack's own key is ${keyId}, SHA-256(SPKI) ${chainId})`);
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
          const left = auditProfile ? AUDIT_PROFILE_CLAIMS.filter((c) => !p.data.claims.includes(c)) : [];
          add('pack', null, null, 'claims.json', true, `declares ${p.data.claims.join(', ') || 'nothing'} (authenticated by SHA256SUMS)${left.length ? `; the audit profile checks ${left.join(', ')} too` : ''}`);
        }
      }
    }

    // A stamp asked for and not obtained is pending: nothing it would vouch for is timestamped yet.
    if (on('independent_timestamps')) {
      const pending = listPackFiles(dir).files.filter((f) => f.endsWith(PENDING_SUFFIX));
      add('timestamp', 'independent_timestamps', null, 'pending stamps', pending.length === 0, pending.length === 0 ? 'none pending' : `${pending.length} stamp(s) pending: ${pending.slice(0, 5).join(', ')} (stamp them, then package again)`);
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

    // ── audit profile: a /3 bundle of this audit alone ──
    if (auditProfile) {
      const v3 = result.bundle_format === BUNDLE_FORMAT_V3;
      add('pack', 'integrity', null, 'bundle format', v3, v3 ? `${BUNDLE_FORMAT_V3} (audit profile)` : `${result.bundle_format ?? 'unknown'} is not ${BUNDLE_FORMAT_V3}: the audit profile needs the run plan, the derived nonce and the run count; verify a pack made before 0.11.0 with --profile legacy (PARTIAL at best)`);
      // Stubs are events of other documents or audits inside the range: one store per audit, so none.
      add('bundle', 'integrity', null, 'this audit only', vb.counts.stubs === 0 && manifest !== null, vb.counts.stubs === 0 ? `the bundle holds only audit ${vb.audit_id ?? '?'}'s events (no stubs)` : `the bundle holds ${vb.counts.stubs} stub(s): events of other documents or audits inside its range (record each audit in its own store)`);
    }

    // ── 4. run sequence, plan, sign-offs, close (need only the bundle) ──
    if (on('run_sequence')) checkRunSequence(events !== null, full);
    if (on('plan_complete')) checkPlan(events !== null, full);
    if (on('reproductions_signed')) checkReproductions(events !== null, full, auditorPem, bundleDir);
    if (on('closed')) checkClosed(events !== null, full, to);

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
      if (kc.usable && !rollbackOff) checkRollback(keyList);
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

    // A receipt signed by a key that is not the active head (retired or revoked) is valid only with a
    // verified RFC 3161 time inside the key's validity (before valid_to + 5 min; for a revoked key,
    // before compromised_since − 5 min): received_at is the signer's own claim. For such receipts,
    // receipts depends on independent timestamps; under --no-tsa they fail.
    if (listOk && !noTsa && !on('independent_timestamps') && !skipped.has('independent_timestamps')) {
      for (const f of receipts) {
        let id: unknown = null;
        try {
          id = (JSON.parse(readBundleFile(join(anchorsDir, f), MAX_RECEIPT_BYTES, { allowHardlinks }).toString('utf8')) as Record<string, unknown>)['service_key_id'];
        } catch {
          continue; // the receipt loop reports it
        }
        const e = typeof id === 'string' ? keyList!.find((k) => k.key_id === id) : undefined;
        if (e && (e.status ?? 'active') !== 'active') {
          checked.add('independent_timestamps');
          tsaForKeys = `${id} is ${e.status}`;
          break;
        }
      }
    }

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

      // The service's checkServiceKey with revoked: 'tsa' and nonHead: 'tsa' (the verify page's rules): a
      // retired key's receipt counts only with a verified RFC 3161 time no later than valid_to + 5 min, a
      // revoked key's only with one before compromised_since − 5 min (checked below, never received_at).
      const sk = listOk ? checkServiceKey(keyList!, r.service_key_id, r.received_at, pin, { revoked: 'tsa', nonHead: 'tsa' }) : null;
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
      const notHead = entry !== null && (entry.status ?? 'active') !== 'active';
      if (notHead && (noTsa || !on('independent_timestamps'))) {
        const need = compromisedSince !== null ? `before ${compromisedSince} − 5 min (compromised_since)` : `no later than ${entry!.valid_to ?? '?'} + 5 min (valid_to)`;
        ok = add('timestamp', 'receipts', base, compromisedSince !== null ? 'stamped before compromise' : 'stamped within key validity', false, `${r.service_key_id} is ${entry!.status}; its receipt counts only with a verified RFC 3161 time ${need}, and RFC 3161 tokens are not checked here (${noTsa ? '--no-tsa' : skipped.has('independent_timestamps') ? 'independent_timestamps skipped by user' : 'independent_timestamps not checked'}); received_at is the signer's own claim and does not count`) && ok;
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
        (tokenBytes.get(base) ?? tokenBytes.set(base, []).get(base)!).push({ tsa, bytes });
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
      if (notHead && compromisedSince === null && earliest === null) {
        keyEndOk.set(base, false);
        report.ok = false;
        add('timestamp', 'receipts', base, 'stamped within key validity', false, `${r.service_key_id} is ${entry!.status}; no verified TSA time shows the receipt existed before ${entry!.valid_to} + 5 min (received_at is the signer's own claim and does not count)`);
      }
      if (entry && earliest) {
        const end = entry.valid_to ? Date.parse(entry.valid_to) : null;
        const fine = end === null || Date.parse(earliest) <= end + CLOCK_SKEW_MS;
        if (!fine || !keyEndOk.has(base)) keyEndOk.set(base, fine);
        add('timestamp', 'receipts', base, 'stamped within key validity', fine, fine ? `earliest TSA time ${earliest}${end === null ? `; ${r.service_key_id} has no valid_to` : ` ≤ ${r.service_key_id} valid_to ${entry.valid_to} + 5 min`}` : `earliest TSA time ${earliest} is after ${r.service_key_id} ended at ${entry.valid_to}`);
      }
    }
    if (on('independent_timestamps') && !noTsa) checkSumsTokens(roots, groupOf);
    timeline(result.anchors, full, events !== null, to, vb.root, vb.manifest_sha256, keyEndOk);
    if (auditProfile && on('harness_frozen_before_runs') && !noTsa && events !== null && vb.ok) checkLateAnchor(full, auditorPem, roots, groupOf);
  }

  /**
   * A8: a freeze made with the anchor pending and anchored later. The pending-freeze record must hold
   * together, its RFC 3161 tokens must verify under two pinned TSA CAs, its auditor-signed checkpoint
   * must be the bundle's own root over seq 1..F, the freeze event must be inside it and name the stamped
   * manifest and plan detail, every run must carry its nonce and the frozen harness, and one verified,
   * timestamped anchor must commit the freeze and every run. Then, and only then, the two freeze-anchor
   * checks (in exactly the form a late anchor produces) are replaced, and the unwitnessed window is
   * reported.
   */
  function checkLateAnchor(full: BundleEvent[], auditorPem: string, roots: string[], groupOf: Map<string, string>): void {
    const la = result.late_anchor;
    const reports = full.filter((e) => e.kind === 'report_issued').map((e) => (isJsonObject(e.payload?.['report']) ? sOrNull((e.payload['report'] as Record<string, unknown>)['sha256']) : null)).filter((x): x is string => x !== null);
    const found = findFreezePending(dir, reports, allowHardlinks);
    if (found === null) return;
    la.source = found.source;
    const where = found.source === 'pack_dir' ? 'freeze-pending/' : 'the report archive (attachments/freeze-pending.*)';
    const sub = (check: string, ok: boolean | CheckStatus, evidence: string) => add('ordering', 'harness_frozen_before_runs', 'pending freeze', check, ok, evidence);
    if ('problem' in found) {
      la.status = 'rejected';
      la.problem = found.problem;
      sub('record', false, `${where}: ${found.problem}`);
      return;
    }
    const p = found;
    la.nonce = p.nonce;
    la.checkpoint_to_seq = p.checkpoint.to_seq;
    if (opts.late_anchor === 'strict') {
      la.status = 'strict';
      sub('late anchor', 'not_applicable', `the pack carries a pending-freeze record (${where}); --strict-freeze: not used, the freeze-anchor checks stand`);
      return;
    }
    const problems: string[] = [];
    const check = (name: string, ok: boolean, evidence: string) => {
      if (!ok) problems.push(`${name}: ${evidence}`);
      sub(name, ok, evidence);
    };
    check('record', true, `${where}: SHA256SUMS, ${p.tokens.length} token(s) and ${FREEZE_PENDING_RECORD} agree; nonce ${short(p.nonce)} re-derived from SHA256SUMS and the tokens`);
    // RFC 3161 tokens over the record's SHA256SUMS, under the pinned TSA CAs.
    const toks = p.tokens.map((t) => {
      const v = verifyTimestamp(t.bytes, { message: p.sums, roots, at: tsaAt, known_extras: opts.tsa_roots === undefined ? SHIPPED_TSA_EXTRAS.map((x) => x.sha256) : [], ...(opts.now ? { now: opts.now } : {}) });
      return { t, v, ca: v.ok && v.root_sha256 ? (groupOf.get(v.root_sha256) ?? null) : null };
    });
    la.freeze_stamped = toks.map((x) => ({ tsa: x.t.tsa, gen_time: x.v.info?.gen_time ?? null, ca: x.ca }));
    const cas = new Set(toks.filter((x) => x.v.ok && x.ca).map((x) => x.ca!));
    const tokOk = toks.every((x) => x.v.ok) && cas.size >= 2;
    check('freeze stamped', tokOk, `${toks.map((x) => (x.v.ok ? `${x.t.tsa} ${x.v.info!.gen_time} (CA ${x.ca ?? x.v.root})` : `${x.t.tsa}: ${x.v.problem ?? 'does not verify'}`)).join('; ')}${tokOk ? '' : cas.size < 2 ? `; valid tokens under ${cas.size} pinned TSA CA(s), two different CAs are required` : ''}`);
    // The checkpoint: signed by the pinned auditor key, its root the bundle's own root over 1..F.
    const F = p.checkpoint.to_seq;
    const upTo = full.filter((e) => e.seq <= F);
    const contiguous = upTo.length === F && upTo.every((e, i) => e.seq === i + 1);
    const root = contiguous ? merkleRootHex(upTo.map((e) => ({ seq: e.seq, this_hash: e.this_hash }))) : null;
    const sigOk = verifyEd25519Strict(auditorPem, checkpointSigningPayload(p.checkpoint), p.checkpoint.signature);
    check(
      'checkpoint',
      sigOk && root !== null && root === p.checkpoint.root,
      !sigOk
        ? 'the checkpoint signature does not verify under the pinned auditor key'
        : root === null
          ? `the bundle does not hold seq 1..${F} contiguously`
          : root !== p.checkpoint.root
            ? `the checkpoint root ${short(p.checkpoint.root)} is not the bundle's root over seq 1..${F} (${short(root)}): the chain was rewritten after the freeze stamp`
            : `signed by the pinned auditor key; root ${short(root)} is the bundle's root over seq 1..${F}`,
    );
    // The freeze event: inside the checkpoint, naming the stamped manifest and plan detail.
    const freeze = full.find((e) => e.kind === 'harness_frozen');
    const ref = (k: string) => (isJsonObject(freeze?.payload?.[k]) ? sOrNull((freeze!.payload![k] as Record<string, unknown>)['sha256']) : null);
    const fwhy: string[] = [];
    if (!freeze) fwhy.push('the bundle holds no harness_frozen event');
    else {
      if (freeze.seq > F) fwhy.push(`harness_frozen is seq ${freeze.seq}, after the stamped checkpoint (1..${F})`);
      if (freeze.payload?.['fingerprint'] !== p.record.fingerprint) fwhy.push('it names another harness fingerprint than the record');
      if (ref('manifest') !== sha256Hex(p.files.get('manifest.json')!)) fwhy.push('its manifest is not the stamped manifest.json');
      if (ref('plan_detail') !== sha256Hex(p.files.get('plan-detail.json')!)) fwhy.push('its plan detail is not the stamped plan-detail.json');
    }
    check('freeze event', fwhy.length === 0, fwhy.length ? fwhy.join('; ') : `harness_frozen seq ${freeze!.seq} inside the checkpoint, harness ${short(p.record.fingerprint)}, manifest and plan detail as stamped`);
    // Every run (each kind the ordering check counts: run_completed and call_measured) comes after the
    // stamped checkpoint and carries the record's nonce and the frozen harness.
    const runs = full.filter((e) => e.kind !== null && RUN_KINDS.has(e.kind));
    const early = runs.filter((r) => r.seq <= F);
    const off = runs.filter((r) => r.payload?.['nonce'] !== p.nonce || r.payload?.['fingerprint'] !== p.record.fingerprint);
    const seqList = (xs: BundleEvent[]) => `${xs.map((r) => `${r.seq} (${r.kind})`).slice(0, 10).join(', ')}${xs.length > 10 ? ` (+${xs.length - 10})` : ''}`;
    const runWhy = [
      ...(early.length ? [`run seq ${seqList(early)} ${early.length > 1 ? 'are' : 'is'} inside the stamped checkpoint (seq 1..${F}), recorded before the freeze stamp`] : []),
      ...(off.length ? [`run seq ${off.map((r) => r.seq).slice(0, 10).join(', ')} do not carry the pending-freeze nonce and harness (${off.map((r) => r.kind).filter((k, i, a) => a.indexOf(k) === i).join(', ')})`] : []),
    ];
    const badRuns = new Set([...early, ...off]);
    check('runs carry the nonce', runWhy.length === 0, runWhy.length ? runWhy.join('; ') : `${runs.length}/${runs.length} run(s) after seq ${F} carry nonce ${short(p.nonce)} (unknown before the freeze tokens) and harness ${short(p.record.fingerprint)}`);
    // One verified, timestamped anchor commits the freeze and every run.
    const isRunEnd = (e: BundleEvent) => e.kind !== null && (RUN_KINDS.has(e.kind) || e.kind === 'run_abandoned');
    const ends = full.filter(isRunEnd);
    const lastEnd = ends.length ? ends[ends.length - 1]!.seq : 0;
    const late = freeze ? validAnchors.find((v) => v.clock === 'tsa' && v.from <= freeze.seq && v.to >= Math.max(freeze.seq, lastEnd)) : undefined;
    check('late anchor', late !== undefined, late ? `${late.base} (received ${late.svc}, stamped ${[...late.tsa.values()].join(', ')}) commits seq ${late.from}..${late.to}: the freeze and every run` : 'no verified anchor stamped under two TSA CAs commits the freeze and every run');
    if (problems.length) {
      la.status = 'rejected';
      la.problem = problems.join('; ');
      return;
    }
    // The two freeze-anchor checks, in exactly the form a late anchor gives them.
    const hits = checks.filter((c) => c.status === 'fail' && LATE_ANCHOR_REPLACEABLE.some((x) => x.claim === c.claim && x.check === c.check && x.evidence.test(c.evidence)));
    const fromT = isoMin(la.freeze_stamped.map((x) => x.gen_time).filter((x): x is string => x !== null))!;
    // The first third party to hold the chain after the freeze: the earliest timestamped anchor that commits it.
    const witness = validAnchors.filter((v) => v.clock === 'tsa' && v.from <= freeze!.seq && v.to >= freeze!.seq).sort((x, y) => x.to - y.to)[0] ?? late!;
    la.anchor = { file: `${witness.base}.receipt.json`, from_seq: witness.from, to_seq: witness.to, received_at: witness.svc, first_tsa_time: witness.first };
    const inWindow = full.filter((e) => e.seq > F && e.seq <= witness.to);
    la.window = {
      from: fromT,
      to: witness.first,
      ms: Math.max(0, Date.parse(witness.first) - Date.parse(fromT)),
      seqs: inWindow.length ? { from: inWindow[0]!.seq, to: inWindow[inWindow.length - 1]!.seq } : null,
      events: inWindow.length,
      runs: inWindow.filter(isRunEnd).length,
    };
    if (hits.length === 0) {
      la.status = 'not_needed';
      return;
    }
    for (const c of hits) {
      la.replaced.push({ claim: c.claim!, check: c.check, evidence: c.evidence });
      c.status = 'pass';
      c.evidence = `late anchor: the freeze was stamped over the pending-freeze record (${la.freeze_stamped.map((x) => `${x.tsa} ${x.gen_time ?? '?'}`).join(', ')}) and anchored later by ${witness.base}; every run carries its nonce (in place of: ${c.evidence})`;
    }
    const o = result.ordering;
    if (hits.some((c) => c.claim === 'harness_frozen_before_runs')) {
      o.status = 'pass';
      o.basis = 'pending_freeze';
      o.nonce = p.nonce;
      o.problem = null;
      o.freeze = { seq: freeze!.seq, event_key: sOrNull(freeze!.payload?.['event_key']), anchor: witness.base, time: isoMax(la.freeze_stamped.map((x) => x.gen_time).filter((x): x is string => x !== null)), clock: 'tsa' };
      if (o.runs) o.runs.nonce_bound = runs.length - badRuns.size;
    }
    la.status = 'accepted';
  }

  /** RFC 3161 replies over SHA256SUMS: required (two pinned TSA CAs) by the audit profile; checked when present otherwise. */
  function checkSumsTokens(roots: string[], groupOf: Map<string, string>): void {
    const names = readdirSync(dir).filter((f) => SUMS_TOKEN.test(f)).sort();
    if (names.length === 0) {
      if (auditProfile) add('timestamp', 'independent_timestamps', 'SHA256SUMS', 'RFC 3161', false, 'no timestamp token over SHA256SUMS (the audit profile stamps the pack itself: SHA256SUMS.<tsa>.tsr)');
      return;
    }
    let sums: Buffer;
    try {
      sums = readBundleFile(join(dir, 'SHA256SUMS'), MAX_SUMS_BYTES, { allowHardlinks });
    } catch (err) {
      add('timestamp', 'independent_timestamps', 'SHA256SUMS', 'RFC 3161', false, `SHA256SUMS: ${(err as Error).message}`);
      return;
    }
    for (const t of names) {
      const tsa = SUMS_TOKEN.exec(t)![1]!;
      let bytes: Buffer;
      try {
        bytes = readBundleFile(join(dir, t), MAX_TSR_BYTES, { allowHardlinks });
      } catch (err) {
        result.sums_timestamps.push({ file: t, tsa, ok: false, gen_time: null, signer: null, root: null, ca: null, problem: (err as Error).message });
        add('timestamp', 'independent_timestamps', 'SHA256SUMS', `RFC 3161 ${tsa}`, false, (err as Error).message);
        continue;
      }
      const v = verifyTimestamp(bytes, { message: sums, roots, at: tsaAt, known_extras: opts.tsa_roots === undefined ? SHIPPED_TSA_EXTRAS.map((x) => x.sha256) : [], ...(opts.now ? { now: opts.now } : {}) });
      const ca = v.ok && v.root_sha256 ? (groupOf.get(v.root_sha256) ?? null) : null;
      result.sums_timestamps.push({ file: t, tsa, ok: v.ok, gen_time: v.info?.gen_time ?? null, signer: v.signer, root: v.root, ca, problem: v.problem });
      add('timestamp', 'independent_timestamps', 'SHA256SUMS', `RFC 3161 ${tsa}`, v.ok, v.ok ? `${v.info!.gen_time}, signed by ${v.signer}, CA ${v.root} (${ca})` : (v.problem ?? 'does not verify'));
    }
    const cas = new Set(result.sums_timestamps.filter((t) => t.ok && t.ca).map((t) => t.ca!));
    if (auditProfile || names.length > 0) {
      add('timestamp', 'independent_timestamps', 'SHA256SUMS', 'independent TSAs', cas.size >= 2, cas.size >= 2 ? `SHA256SUMS stamped under ${cas.size} pinned TSA CAs (${[...cas].sort().join(', ')})` : `SHA256SUMS has valid tokens under ${cas.size} pinned TSA CA(s); at least two different TSA CAs are required`);
    }
  }

  function checkRollback(list: ServiceKeyEntry[]): void {
    const path = join(opts.seen_dir!, SEEN_KEYS_FILE);
    const rb = result.trust.rollback;
    rb.path = path;
    let cache: SeenKeysFile = { v: 1, lists: {} };
    if (exists(path)) {
      let raw: unknown;
      try {
        raw = JSON.parse(readFileSync(path, 'utf8'));
      } catch {
        raw = undefined;
      }
      const why = raw === undefined ? 'is not JSON' : seenKeysProblem(raw);
      if (why !== null) {
        // A damaged cache cannot be the reference, and is never overwritten: the operator decides.
        rb.status = 'checked';
        add('keys', 'receipts', null, 'key list rollback', false, `${path} ${why}, so the key list cannot be checked for rollback; it is left as it is (delete it only if you trust the list in this pack)`);
        return;
      }
      cache = raw as SeenKeysFile;
    }
    const slot = formatGenesisPin(pin);
    const prev = cache.lists[slot];
    if (prev) {
      rb.status = 'checked';
      rb.seen_at = prev.seen_at;
      const rollback = keyListRegression(keyListOf({ keys: prev.keys })!, list);
      if (rollback) {
        add('keys', 'receipts', null, 'key list rollback', false, `anchor-keys.json is an older or weaker list than the one seen ${prev.seen_at}: ${rollback}`);
        return;
      }
      add('keys', 'receipts', null, 'key list rollback', true, `at least as new as the list seen ${prev.seen_at} (${prev.keys.length} key(s)), kept in ${path}`);
      if (canonicalize(prev.keys) === canonicalize(list)) {
        rb.recorded = true;
        return;
      }
    } else rb.status = 'first_seen';
    cache.lists[slot] = { seen_at: (opts.now ?? new Date()).toISOString(), keys: list };
    try {
      mkdirSync(opts.seen_dir!, { recursive: true, mode: 0o700 });
      const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
      writeFileSync(tmp, JSON.stringify(cache, null, 1) + '\n', { mode: 0o600, flag: 'wx' });
      chmodSync(tmp, 0o600);
      renameSync(tmp, path);
      rb.recorded = true;
    } catch {
      rb.recorded = false; // a read-only data dir: reported, the check above still ran
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
      if (!m || !SAFE_PATH.test(m[2]!) || listed.has(m[2]!) || isSumsFile(m[2]!)) {
        return add('pack', 'integrity', null, 'SHA256SUMS', false, `SHA256SUMS line ${i + 1} is not "<sha256>  <relative path>" for a pack file`);
      }
      listed.set(m[2]!, m[1]!);
    }
    const { files, odd } = listPackFiles(dir);
    const problems: string[] = [];
    if (odd.length) problems.push(`not regular files: ${odd.slice(0, 5).join(', ')}`);
    const present = files.filter((f) => !isSumsFile(f));
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
    // /3: planned_runs counts the plan, so the abandoned runs too; the report and claims.json count the completed runs.
    const abandoned = result.bundle_format === BUNDLE_FORMAT_V3 ? full.filter((e) => e.kind === 'run_abandoned').length : 0;
    const off = rs.declared_counts.filter((d) => d.count !== runs.length + (d.source === 'planned_runs' ? abandoned : 0));
    if (off.length) return fail(`${runs.length} run(s) recorded${abandoned ? ` and ${abandoned} abandoned` : ''}; declared ${off.map((d) => `${d.count} (${d.source})`).join(', ')}`);
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

  function checkPlan(haveEvents: boolean, full: BundleEvent[]): void {
    const pr = result.plan;
    const fail = (why: string) => {
      pr.status = 'fail';
      pr.problem = why;
      add('plan', 'plan_complete', null, 'run plan', false, why);
    };
    if (!haveEvents) return fail('not checked: the bundle does not verify');
    if (result.bundle_format !== BUNDLE_FORMAT_V3) return fail(`a ${result.bundle_format ?? 'bundle of unknown format'} has no run plan (${BUNDLE_FORMAT_V3} records harness_frozen.plan)`);
    const freezes = full.filter((e) => e.kind === 'harness_frozen');
    if (freezes.length !== 1) return fail(freezes.length === 0 ? 'the bundle holds no harness_frozen event' : `the bundle holds ${freezes.length} harness_frozen events; one freeze per audit (record a retest as its own audit)`);
    const fz = freezes[0]!;
    const rawPlan = fz.payload?.['plan'];
    const plan = Array.isArray(rawPlan) ? rawPlan.filter((x): x is string => typeof x === 'string') : [];
    if (plan.length === 0) return fail(`the freeze (seq ${fz.seq}) records no plan of run IDs`);
    pr.planned = plan;
    const planned = new Set(plan);
    const ends = full.filter((e) => e.kind === 'run_completed' || e.kind === 'run_abandoned');
    const byRun = new Map<string, BundleEvent[]>();
    for (const e of ends) {
      const id = sOrNull(e.payload?.['run_id']) ?? `(seq ${e.seq}: no run_id)`;
      (byRun.get(id) ?? byRun.set(id, []).get(id)!).push(e);
    }
    pr.completed = ends.filter((e) => e.kind === 'run_completed').map((e) => sOrNull(e.payload?.['run_id']) ?? '?');
    pr.abandoned = ends.filter((e) => e.kind === 'run_abandoned').map((e) => ({ run_id: sOrNull(e.payload?.['run_id']) ?? '?', reason: sOrNull(e.payload?.['reason']) ?? '' }));
    const list = (xs: string[]) => `${xs.slice(0, 10).join(', ')}${xs.length > 10 ? ` (+${xs.length - 10} more)` : ''}`;
    const unplanned = [...byRun.keys()].filter((id) => !planned.has(id));
    if (unplanned.length) return fail(`run(s) not in the plan frozen at seq ${fz.seq}: ${list(unplanned.map((id) => `${id} (seq ${byRun.get(id)!.map((e) => e.seq).join(', ')})`))}`);
    const dup = [...byRun].filter(([, es]) => es.length > 1);
    if (dup.length) return fail(`planned run(s) recorded more than once: ${list(dup.map(([id, es]) => `${id} (seq ${es.map((e) => `${e.seq} ${e.kind}`).join(', ')})`))}`);
    const missing = plan.filter((id) => !byRun.has(id));
    if (missing.length) return fail(`planned run(s) with neither run_completed nor run_abandoned: ${list(missing)}`);
    const early = ends.filter((e) => e.seq < fz.seq);
    if (early.length) return fail(`run(s) recorded before the freeze (seq ${fz.seq}): seq ${list(early.map((e) => String(e.seq)))}`);
    const pl = fz.payload?.['planned_runs'];
    if (typeof pl === 'number' && pl !== plan.length) return fail(`planned_runs is ${pl}; the plan lists ${plan.length} run(s)`);
    const report = [...full].reverse().find((e) => e.kind === 'report_issued');
    if (!report) return fail('the bundle holds no report_issued event, so no run_count');
    const rc = report.payload?.['run_count'];
    if (typeof rc !== 'number') return fail(`the report (seq ${report.seq}) records no run_count`);
    if (rc !== pr.completed.length) return fail(`the report's run_count is ${rc}; the bundle records ${pr.completed.length} run_completed event(s)`);
    pr.status = 'pass';
    const ab = pr.abandoned.length ? ` (${pr.abandoned.map((a) => `${a.run_id}: ${a.reason}`).slice(0, 5).join('; ')})` : '';
    add('plan', 'plan_complete', null, 'run plan', true, `${plan.length} planned run(s) frozen at seq ${fz.seq}: ${pr.completed.length} completed, ${pr.abandoned.length} abandoned${ab}; none unplanned, missing or repeated; report run_count ${rc}`);
  }

  function checkReproductions(haveEvents: boolean, full: BundleEvent[], auditorPem: string, bundleDir: string): void {
    const no = (check: string, why: string) => add('signoff', 'reproductions_signed', null, check, false, why);
    if (!haveEvents) return void no('sign-offs', 'not checked: the bundle does not verify');
    const statuses = finalFindingStatuses(full);
    const accepted = [...statuses].filter(([, st]) => st === 'accepted').map(([id]) => id).sort();
    const signoffs = full.filter((e) => e.kind === 'reproduction_signed');
    let allowed: string | null = opts.allowed_signers ?? null;
    let source = 'allowed signers given out of band';
    const asPath = join(dir, ALLOWED_SIGNERS_FILE);
    if (allowed === null && exists(asPath)) {
      try {
        allowed = readBundleFile(asPath, 64 * 1024, { allowHardlinks }).toString('utf8');
        source = `the pack's ${ALLOWED_SIGNERS_FILE}, authenticated by SHA256SUMS`;
      } catch (err) {
        return void no('allowed signers', `${ALLOWED_SIGNERS_FILE}: ${(err as Error).message}`);
      }
    }
    const auditorRaw = rawEd25519PublicKey(auditorPem);
    const good = new Set<string>();
    for (const e of signoffs) {
      const p = e.payload ?? {};
      const fid = sOrNull(p['finding_id']);
      const signer = sOrNull(p['signer']);
      const at = sOrNull(p['reproduced_at']);
      const ref = (k: string) => (isJsonObject(p[k]) ? sOrNull((p[k] as Record<string, unknown>)['sha256']) : null);
      const rep: ReproductionReport = { seq: e.seq, finding_id: fid, signer, ok: false, key: null, problem: null };
      result.reproductions.push(rep);
      const check = `sign-off ${fid ?? '?'}`;
      const bad = (why: string) => {
        rep.problem = why;
        no(check, `seq ${e.seq}: ${why}`);
      };
      if (allowed === null) {
        bad(`no allowed signers: the pack has no ${ALLOWED_SIGNERS_FILE} and none was given out of band`);
        continue;
      }
      const sigSha = ref('signature');
      const cmd = ref('commands');
      const out = ref('output');
      if (fid === null || signer === null || at === null || sigSha === null || cmd === null || out === null || result.audit_id === null) {
        bad('the sign-off lacks finding_id, signer, reproduced_at, commands, output or signature');
        continue;
      }
      let sig: Buffer;
      try {
        sig = readBundleFile(join(bundleDir, 'blobs', sigSha), MAX_SSHSIG_BYTES, { allowHardlinks });
      } catch {
        bad(`the signature blob ${short(sigSha)} is not in the bundle`);
        continue;
      }
      const stmt = reproductionStatement({ audit_id: result.audit_id, finding_id: fid, signer, reproduced_at: at, commands: cmd, output: out });
      const v = verifySshSignature(sig, stmt, { namespace: REPRODUCTION_NAMESPACE, principal: signer, allowed_signers: allowed, at: new Date(at) });
      rep.key = v.fingerprint;
      if (!v.ok) {
        bad(v.problem ?? 'the signature does not verify');
        continue;
      }
      if (auditorRaw !== null && v.ed25519 !== null && Buffer.from(auditorRaw).equals(v.ed25519)) {
        bad('signed with the auditor key; a sign-off needs the reproducer\'s own key');
        continue;
      }
      rep.ok = true;
      good.add(fid);
      add('signoff', 'reproductions_signed', null, check, true, `seq ${e.seq}: ${signer}, key ${v.fingerprint} (${source}), reproduced ${at}`);
    }
    const unsigned = accepted.filter((id) => !good.has(id));
    add(
      'signoff',
      'reproductions_signed',
      null,
      'accepted findings',
      unsigned.length === 0,
      unsigned.length === 0
        ? `${accepted.length} accepted finding(s)${accepted.length ? ` (${accepted.slice(0, 10).join(', ')})` : ''}, each with a verified human sign-off`
        : `accepted finding(s) without a verified human sign-off (reproduction_signed): ${unsigned.slice(0, 10).join(', ')}`,
    );
  }

  function checkClosed(haveEvents: boolean, full: BundleEvent[], to: number | null): void {
    const c = result.closed;
    const fail = (why: string) => {
      c.status = 'fail';
      c.problem = why;
      add('close', 'closed', null, 'audit closed', false, why);
    };
    if (!haveEvents) return fail('not checked: the bundle does not verify');
    const closes = full.filter((e) => e.kind === 'audit_closed');
    if (closes.length !== 1) return fail(closes.length === 0 ? 'the bundle holds no audit_closed event: the audit was not closed' : `the bundle holds ${closes.length} audit_closed events`);
    const ce = closes[0]!;
    const p = ce.payload ?? {};
    Object.assign(c, { seq: ce.seq, report_id: sOrNull(p['report_id']), run_count: typeof p['run_count'] === 'number' ? p['run_count'] : null, findings_digest: sOrNull(p['findings_digest']) });
    if (to === null || ce.seq !== to) return fail(`audit_closed (seq ${ce.seq}) is not the bundle's last event (seq ${to ?? '?'})`);
    const report = full.find((e) => e.kind === 'report_issued' && e.seq < ce.seq && e.payload?.['report_id'] === c.report_id);
    if (!report) return fail(`audit_closed names report ${c.report_id ?? '?'}, which no earlier report_issued records`);
    const completed = full.filter((e) => e.kind === 'run_completed').length;
    if (c.run_count !== completed) return fail(`audit_closed run_count is ${c.run_count ?? '?'}; the bundle records ${completed} run_completed event(s)`);
    const want = findingsDigest(finalFindingStatuses(full.filter((e) => e.seq < ce.seq)));
    if (c.findings_digest !== want) return fail(`audit_closed findings_digest ${short(c.findings_digest)} is not the digest of the findings' final status (${short(want)})`);
    c.status = 'pass';
    add('close', 'closed', null, 'audit closed', true, `seq ${ce.seq}, the bundle's last event: report ${c.report_id} (seq ${report.seq}), ${completed} run(s), findings digest ${want}`);
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
    const valid: Valid[] = validAnchors;
    valid.length = 0;
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
    if (auditProfile && on('receipts') && haveEvents) checkMilestoneAnchors(valid, full, to);
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

  /** Audit profile: verified, two-CA anchors close the freeze (before any run), the last run (before the report) and the report (the whole bundle). */
  function checkMilestoneAnchors(valid: Valid[], full: BundleEvent[], to: number | null): void {
    const freeze = full.find((e) => e.kind === 'harness_frozen');
    const runs = full.filter((e) => e.kind === 'run_completed' || e.kind === 'run_abandoned');
    const report = [...full].reverse().find((e) => e.kind === 'report_issued');
    const need: string[] = [];
    const got: string[] = [];
    const firstRun = runs[0]?.seq ?? Number.POSITIVE_INFINITY;
    if (!freeze) need.push('a freeze anchor (the bundle holds no harness_frozen event)');
    else {
      const a = valid.find((v) => v.to >= freeze.seq && v.to < firstRun);
      if (a) got.push(`freeze ${a.base}`);
      else need.push(`an anchor after the freeze (seq ${freeze.seq}) that commits no run${runs.length ? ` (the first is seq ${firstRun})` : ''}`);
    }
    const lastRun = runs[runs.length - 1];
    if (!lastRun) need.push('an anchor after the last run (no runs recorded)');
    else {
      const until = report?.seq ?? Number.POSITIVE_INFINITY;
      const a = valid.find((v) => v.to >= lastRun.seq && v.to < until);
      if (a) got.push(`last run ${a.base}`);
      else need.push(`an anchor after the last run (seq ${lastRun.seq})${report ? ` that does not yet commit the report (seq ${report.seq})` : ''}`);
    }
    if (!report) need.push('an anchor at the report (the bundle holds no report_issued event)');
    else {
      const a = valid.find((v) => to !== null && v.to === to && v.to >= report.seq);
      if (a) got.push(`report ${a.base}`);
      else need.push(`an anchor at the report that commits the whole bundle (seq ${report.seq}..${to ?? '?'})`);
    }
    const how = !noTsa && on('independent_timestamps') ? 'each verified and stamped under two pinned TSA CAs' : 'each verified';
    add('timeline', 'receipts', null, 'milestone anchors', need.length === 0, need.length === 0 ? `${got.join(', ')}: ${how}` : `missing ${need.join('; ')} (${how})`);
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
    // /3: the nonce is derived from the freeze receipt and the TSA tokens over it (W2), which the
    // auditor cannot know before the TSAs sign; /1, /2: the receipt digest, as 0.10.0 recorded it.
    const v3 = result.bundle_format === BUNDLE_FORMAT_V3;
    const toks = fa ? (tokenBytes.get(fa.base) ?? []) : [];
    const digest = !fa ? null : v3 ? (toks.length >= 2 ? freezeNonce(fa.a.receipt_sha256, toks) : null) : fa.a.receipt_sha256;
    const nonceName = v3 ? `derived freeze nonce sha256(${fa?.base ?? 'freeze'} receipt digest ‖ its ${toks.length} TSA token(s)) = ${digest}` : `freeze receipt digest ${digest}`;
    o.nonce = digest;
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
    if (wrongNonce.length > 0) return fail(`run seq ${wrongNonce.map((r) => r.seq).slice(0, 10).join(', ')} carries a nonce that is not the ${nonceName}`);
    const freezeAt = `harness ${short(harness)} frozen, committed ${fa.time} (${fa.base}, RFC 3161)`;
    if (nonceBound === runs.length) {
      o.status = 'pass';
      o.basis = v3 ? 'derived_nonce' : 'freeze_nonce';
      add('ordering', 'harness_frozen_before_runs', null, label, true, `${freezeAt}; ${runs.length}/${runs.length} run(s) name that harness, carry the ${nonceName} and are committed by later timestamped anchors (${[...new Set([...runAnchor.values()].map((v) => v.base))].join(', ')})`);
      return;
    }
    // measured_at is the auditor's own record: whoever holds the auditor key can write any time into it.
    // Only the freeze nonce (the freeze receipt's digest, unknown before the freeze anchor) shows the order.
    return fail(`${freezeAt}; ${runs.length - nonceBound} of ${runs.length} run(s) do not carry the freeze nonce (the ${nonceName}); the order is shown by the freeze nonce only, never by recorded times`);
  }
}

// ───────────────────────────── output ─────────────────────────────

const STATUS = z.enum(['pass', 'fail', 'not_applicable']);

/** The JSON output (`--json`), as a schema: tests and docs hold the CLI to it. */
const TOKEN_REPORT = z.strictObject({ file: z.string(), tsa: z.string(), ok: z.boolean(), gen_time: z.string().nullable(), signer: z.string().nullable(), root: z.string().nullable(), ca: z.string().nullable(), problem: z.string().nullable() });

export const VerifyAuditJsonSchema = z.strictObject({
  format: z.literal(VERIFY_AUDIT_FORMAT),
  ok: z.boolean(),
  profile: z.enum(PROFILES),
  verdict: z.enum(VERDICTS),
  package: z.string(),
  audit_id: z.string().nullable(),
  bundle_format: z.string().nullable(),
  manifest_sha256: z.string().nullable(),
  auditor: z.strictObject({ key_id: z.string().nullable(), spki_sha256: z.string().nullable(), source: z.enum(['key_file', 'fingerprint', 'unpinned']) }),
  trust: z.strictObject({
    key_list: z.enum(['pack', 'file']),
    genesis_sha256: z.string().regex(/^[0-9a-f]{64}$/),
    genesis_valid_from: z.string(),
    genesis_source: z.enum(['compiled', 'option', 'env']),
    rollback: z.strictObject({ status: z.enum(['checked', 'first_seen', 'off', 'not_checked']), path: z.string().nullable(), seen_at: z.string().nullable(), recorded: z.boolean() }),
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
  claims: z.array(z.strictObject({ claim: z.enum(CLAIMS), status: z.enum(['pass', 'fail', 'not_declared', 'not_checked', 'skipped']), declared: z.boolean(), required: z.boolean(), evidence: z.string() })).length(CLAIMS.length),
  checks: z.array(
    z.strictObject({ group: z.enum(['pack', 'bundle', 'keys', 'anchor', 'timestamp', 'timeline', 'ordering', 'runs', 'plan', 'signoff', 'close']), claim: z.enum(CLAIMS).nullable(), subject: z.string().nullable(), check: z.string(), status: STATUS, evidence: z.string() }),
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
      timestamps: z.array(TOKEN_REPORT),
    }),
  ),
  ordering: z.strictObject({
    status: z.enum(['pass', 'fail', 'not_declared', 'not_checked']),
    basis: z.enum(['freeze_nonce', 'derived_nonce', 'pending_freeze']).nullable(),
    nonce: z.string().nullable(),
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
  plan: z.strictObject({
    status: z.enum(['pass', 'fail', 'not_declared']),
    planned: z.array(z.string()),
    completed: z.array(z.string()),
    abandoned: z.array(z.strictObject({ run_id: z.string(), reason: z.string() })),
    problem: z.string().nullable(),
  }),
  reproductions: z.array(z.strictObject({ seq: z.number().int(), finding_id: z.string().nullable(), signer: z.string().nullable(), ok: z.boolean(), key: z.string().nullable(), problem: z.string().nullable() })),
  closed: z.strictObject({
    status: z.enum(['pass', 'fail', 'not_declared']),
    seq: z.number().int().nullable(),
    report_id: z.string().nullable(),
    run_count: z.number().int().nullable(),
    findings_digest: z.string().nullable(),
    problem: z.string().nullable(),
  }),
  sums_timestamps: z.array(TOKEN_REPORT),
  late_anchor: z.strictObject({
    status: z.enum(['none', 'accepted', 'not_needed', 'rejected', 'strict']),
    source: z.enum(['pack_dir', 'report_archive']).nullable(),
    nonce: z.string().nullable(),
    checkpoint_to_seq: z.number().int().nullable(),
    freeze_stamped: z.array(z.strictObject({ tsa: z.string(), gen_time: z.string().nullable(), ca: z.string().nullable() })),
    anchor: z.strictObject({ file: z.string(), from_seq: z.number().int(), to_seq: z.number().int(), received_at: z.string(), first_tsa_time: z.string() }).nullable(),
    window: z.strictObject({ from: z.string(), to: z.string(), ms: z.number().int().nonnegative(), seqs: z.strictObject({ from: z.number().int(), to: z.number().int() }).nullable(), events: z.number().int(), runs: z.number().int() }).nullable(),
    replaced: z.array(z.strictObject({ claim: z.enum(CLAIMS), check: z.string(), evidence: z.string() })),
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

const LABEL: Record<CheckStatus | ClaimStatus, string> = { pass: 'PASS', fail: 'FAIL', not_applicable: 'N/A', not_declared: 'not declared', not_checked: 'not checked', skipped: 'skipped' };
const GROUP_TITLE: Record<CheckGroup, string> = { pack: 'Pack', bundle: 'Evidence bundle', keys: 'Anchor service keys', anchor: 'Anchors', timestamp: 'Anchors', timeline: 'Timeline', ordering: 'Ordering', runs: 'Runs', plan: 'Run plan', signoff: 'Human sign-offs', close: 'Close' };

/** 20h31m, 3h24m, 12m, 45s. */
export function formatDuration(ms: number): string {
  const s = Math.round(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return h > 0 ? `${h}h${String(m).padStart(2, '0')}m` : m > 0 ? `${m}m` : `${s}s`;
}

/** The human-readable report: claims, one PASS / FAIL / N/A line per check with its evidence, values to compare. */
export function renderVerifyAudit(r: VerifyAuditResult): string {
  const L: string[] = [];
  const line = (c: AuditCheck, indent = '  ', w = 26) => L.push(`${indent}${LABEL[c.status].padEnd(4)}  ${c.check.padEnd(w)} ${c.evidence}`);
  L.push(`${PACK_NAME}  ${r.package}`);
  L.push(`audit          ${r.audit_id ?? '?'}${r.bundle_format ? `  (${r.bundle_format})` : ''}`);
  L.push(`profile        ${r.profile === 'audit' ? 'audit (every claim checked; claims.json can add claims, not remove them)' : 'legacy (0.10.0 rules: claims.json picks the claims; PARTIAL at best)'}`);
  L.push(`auditor key    ${r.auditor.key_id ?? '?'}  spki sha256 ${r.auditor.spki_sha256 ?? '?'}  (${r.auditor.source === 'fingerprint' ? 'pinned by --key-fingerprint' : r.auditor.source === 'key_file' ? 'pinned by --key' : 'NOT pinned'})`);
  L.push(`service keys   genesis ${r.trust.genesis_sha256}@${r.trust.genesis_valid_from} (${r.trust.genesis_source === 'compiled' ? 'compiled pin' : r.trust.genesis_source === 'env' ? 'KRONICLE_ANCHOR_GENESIS' : '--genesis'}); key list from ${r.trust.key_list === 'pack' ? 'anchor-keys.json' : '--anchor-keys'}: ${r.trust.key_chain.status}`);
  const rb = r.trust.rollback;
  if (rb.status === 'first_seen') L.push(`key list       first seen for this genesis; ${rb.recorded ? `recorded in ${rb.path}` : `could not be recorded in ${rb.path}`} (later lists are checked against it)`);
  else if (rb.status === 'off') L.push('key list       rollback check off (library option rollback: off)');
  else if (rb.status === 'checked' && rb.seen_at) L.push(`key list       checked against the list seen ${rb.seen_at} (${rb.path})`);
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
    const bases = new Set<string>();
    for (const a of r.anchors) {
      const base = a.file.slice(0, -'.receipt.json'.length);
      bases.add(base);
      L.push(`  ${base}${a.from_seq !== null ? `  seq ${a.from_seq}..${a.to_seq}` : ''}${a.received_at ? `  received ${a.received_at}` : ''}${a.anchor_id ? `  id ${a.anchor_id}` : ''}`);
      for (const c of anchorChecks.filter((x) => x.subject === base)) line(c, '    ', 20);
    }
    // Checks about the pack as a whole (SHA256SUMS tokens, pending stamps) or a receipt not listed above.
    const rest = anchorChecks.filter((x) => x.subject === null || !bases.has(x.subject));
    for (const subject of [...new Set(rest.map((x) => x.subject ?? 'pack'))]) {
      L.push(`  ${subject}`);
      for (const c of rest.filter((x) => (x.subject ?? 'pack') === subject)) line(c, '    ', 20);
    }
  }
  for (const g of ['timeline', 'ordering', 'runs', 'plan', 'signoff', 'close'] as const) {
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
  const skippedC = r.claims.filter((c) => c.status === 'skipped').map((c) => c.claim);
  const failedC = r.claims.filter((c) => c.status === 'fail').map((c) => c.claim);
  const notDeclared = r.claims.filter((c) => c.status === 'not_declared').map((c) => c.claim);
  const la = r.late_anchor;
  if (la.status !== 'none') {
    L.push('', 'Late anchor (freeze made with the anchor pending)');
    if (la.status === 'accepted' || la.status === 'not_needed') {
      L.push(`  freeze stamped   ${la.freeze_stamped.map((t) => `${t.gen_time ?? '?'} (${t.tsa})`).join(', ')} over the auditor-signed checkpoint of seq 1..${la.checkpoint_to_seq}`);
      if (la.anchor) L.push(`  anchored later   ${la.anchor.file.replace(/\.receipt\.json$/, '')} (seq ${la.anchor.from_seq}..${la.anchor.to_seq}), first RFC 3161 time ${la.anchor.first_tsa_time}`);
      if (la.window) {
        L.push(`  UNWITNESSED WINDOW  ${la.window.from} → ${la.window.to} (${formatDuration(la.window.ms)}): ${la.window.seqs ? `seq ${la.window.seqs.from}..${la.window.seqs.to} (${la.window.events} event(s), ${la.window.runs} run(s))` : 'no events'} were held only by the auditor's key until the late anchor.`);
        L.push('                      Their order after the freeze is shown by the nonce they carry; that none was rewritten or replayed in this window rests on the auditor alone.');
      }
      for (const x of la.replaced) L.push(`  replaced         ${x.claim} / ${x.check}: "${x.evidence}"`);
      if (la.status === 'accepted') L.push('  --strict-freeze requires a freeze anchor that commits no run (this pack then FAILS those checks).');
    } else if (la.status === 'strict') L.push('  --strict-freeze: the pending-freeze record in the pack was not used');
    else L.push(`  REJECTED: ${la.problem ?? 'the pending-freeze proof does not hold'}`);
  }
  L.push(
    r.verdict === 'verified'
      ? `RESULT: VERIFIED  ${passed.join(', ')}`
      : r.verdict === 'verified_late_anchor'
        ? `RESULT: ${LATE_ANCHOR_RESULT}  ${passed.join(', ')}${la.window ? `; unwitnessed window ${formatDuration(la.window.ms)}` : ''}`
      : r.verdict === 'partial'
        ? `RESULT: PARTIAL  ${passed.join(', ')}${skippedC.length ? `  (${skippedC.join(', ')} skipped by user)` : ''}`
        : r.verdict === 'not_verified'
          ? `RESULT: NOT VERIFIED  ${unchecked.join(', ')} not checked${passed.length ? `; passed: ${passed.join(', ')}` : ''}`
          : `RESULT: FAILED  ${failedC.join(', ') || 'pack structure'} (${r.failed} failed check(s))${unchecked.length ? `; not checked: ${unchecked.join(', ')}` : ''}`,
  );
  if (r.verdict === 'verified_late_anchor') {
    L.push(`  ${LATE_ANCHOR_RESULT}: every claim passed, with the freeze shown by the pending-freeze record; for ${la.window ? formatDuration(la.window.ms) : 'a window'} after the freeze only the auditor's key held the chain. Exit 0 and JSON ok: true, as for VERIFIED; a plain pass is verdict "verified" (RESULT: VERIFIED and two spaces). --strict-freeze refuses it.`);
  }
  if (r.verdict === 'partial') {
    const why = r.profile === 'legacy' ? `checked under --profile legacy (the 0.10.0 rules)${notDeclared.length ? `; not checked: ${notDeclared.join(', ')}` : ''}` : `skipped by user: ${skippedC.join(', ')}`;
    L.push(`  PARTIAL: every check that ran passed, but the pack does not meet the audit profile (${why}). Exit 2.`);
  }
  return L.join('\n') + '\n';
}
