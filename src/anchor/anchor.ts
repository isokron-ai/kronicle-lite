/**
 * Hosted anchoring: `checkpoint --push`, `verify --remote [--offline]`,
 * `anchor status`, and the MCP `checkpoint_chain {push}` / `anchor_status`
 * tools. Ported from isokron-anchor `client/src/anchor.ts`, wired to
 * KronicleLite instead of a second SQLite handle.
 *
 * Nothing here appends to the chain or changes a hash. Every remote call can
 * fail with AnchorUnreachableError ("anchor service unreachable …"); local
 * state is never touched before the service has answered and the receipt
 * has verified.
 */

import { createPublicKey } from 'node:crypto';

import type { Checkpoint } from '../chain/chain.js';
import { chainIdFromPublicKeyPem, keyIdFromPublicKey } from '../crypto/keys.js';
import type { KronicleLite } from '../store.js';
import { AnchorApiError, AnchorClient, AnchorListingError, AnchorRateLimitedError, AnchorUnreachableError, type RemoteAnchor, type RemoteChain } from './client.js';
import { AnchorConfigError, assertAnchorTransport, configFileLicenseKey, loadConfig, type AnchorConfig } from './config.js';
import { anchorKeySource, NO_KEY_MESSAGE, resolveAnchorKey, type AnchorKeySource } from './key-source.js';
import { anchorReceiptJcs, type AnchorReceipt } from './receipt.js';
import { acceptServiceKeys, anchorGenesis, keptServiceKeys, receiptChainRefusal, ServiceKeyTrustError, verifyReceiptWithKeys, type KeyListCheck, type ServiceKeySet } from './trust.js';
import { parseWireCheckpoint, type WireCheckpoint } from './wire.js';

export interface AnchorCallOptions {
  /** Overrides KRONICLE_ANCHOR_URL / config.json. */
  anchorUrl?: string;
  /** Overrides every other key source (CLI `--key`). */
  licenseKey?: string;
  /** 0.11.1: read the license key from this file (CLI `--anchor-key-file`); overrides KRONICLE_ANCHOR_KEY_CMD, KRONICLE_ANCHOR_KEY, config.json. */
  licenseKeyFile?: string;
  /** 0.11.1: timeout for KRONICLE_ANCHOR_KEY_CMD (default KRONICLE_ANCHOR_KEY_CMD_TIMEOUT_MS, else 30 s). */
  keyCommandTimeoutMs?: number;
  /** Allow an http:// anchor_url to a non-loopback host (CLI `--insecure-http`). */
  insecureHttp?: boolean;
  fetch?: typeof fetch;
  timeoutMs?: number;
  /** Waits between 429 retries (tests inject a fake clock). */
  sleep?: (ms: number) => Promise<void>;
  /** The service's genesis pin, `<sha256>@<valid_from>` (CLI `--genesis`); else KRONICLE_ANCHOR_GENESIS, config.json anchor_genesis, the compiled pin. */
  genesis?: string;
}

function configFor(store: KronicleLite, opts: AnchorCallOptions): AnchorConfig {
  return loadConfig(store.dataDir, {
    ...(opts.anchorUrl ? { anchor_url: opts.anchorUrl } : {}),
    ...(opts.licenseKey ? { license_key: opts.licenseKey } : {}),
  });
}

const keyInputs = (store: KronicleLite, opts: AnchorCallOptions) => ({
  licenseKey: opts.licenseKey,
  licenseKeyFile: opts.licenseKeyFile,
  configKey: configFileLicenseKey(store.dataDir),
  ...(opts.keyCommandTimeoutMs !== undefined ? { commandTimeoutMs: opts.keyCommandTimeoutMs } : {}),
});

/** Where the license key would come from, without running KRONICLE_ANCHOR_KEY_CMD or reading a key file. */
export function licenseKeySource(store: KronicleLite, opts: AnchorCallOptions = {}): AnchorKeySource | null {
  return anchorKeySource(keyInputs(store, opts));
}

/**
 * 0.11.1: the license key for a push, from `--key` / `--anchor-key-file` >
 * KRONICLE_ANCHOR_KEY_CMD > KRONICLE_ANCHOR_KEY > config.json. Throws
 * AnchorConfigError (never containing the key) when none is configured or the
 * configured source fails.
 */
export function requireLicenseKey(store: KronicleLite, opts: AnchorCallOptions = {}): string {
  const r = resolveAnchorKey(keyInputs(store, opts));
  if (!r) throw new AnchorConfigError(NO_KEY_MESSAGE);
  return r.key;
}

/** `opts` with the license key resolved once (requireLicenseKey), so later calls run no command and read no file. */
export function withLicenseKey(store: KronicleLite, opts: AnchorCallOptions = {}): AnchorCallOptions {
  const { licenseKeyFile: _file, ...rest } = opts;
  return { ...rest, licenseKey: requireLicenseKey(store, opts) };
}

/** Every network call goes through here: refuses clear-text transport first. */
function clientFor(cfg: AnchorConfig, opts: AnchorCallOptions): AnchorClient {
  assertAnchorTransport(cfg.anchor_url, opts.insecureHttp === true);
  return new AnchorClient(cfg.anchor_url, {
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
    ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
    ...(opts.sleep ? { sleep: opts.sleep } : {}),
  });
}

/** Fetch the service key list: rollback check against the kept one, then the chain check against the genesis pin. */
async function fetchKeys(store: KronicleLite, cfg: AnchorConfig, api: AnchorClient, opts: AnchorCallOptions): Promise<KeyListCheck> {
  const { pin } = anchorGenesis(store.dataDir, opts.genesis);
  return acceptServiceKeys(store, cfg.anchor_url, pin, await api.serviceKeys());
}

/** The key list kept in the data dir (no network). A damaged cache or a bad pin is a violation, not trusted. */
function keptKeys(store: KronicleLite, cfg: AnchorConfig, opts: AnchorCallOptions): KeyListCheck {
  try {
    const { pin } = anchorGenesis(store.dataDir, opts.genesis);
    return keptServiceKeys(store, cfg.anchor_url, pin);
  } catch (e) {
    if (e instanceof ServiceKeyTrustError || e instanceof AnchorConfigError) return { set: null, notes: [], violations: [e.message] };
    throw e;
  }
}

/**
 * Verify a receipt against the service key list (head key only) AND tie it to
 * this chain (chain_id, checkpoint key, checkpoint signature). Only a receipt
 * that passes both may supply a root or range to compare.
 */
export function checkHeldReceipt(
  store: KronicleLite,
  input: unknown,
  keys: ServiceKeySet | null,
  expectedChainId: string | null,
): { ok: true; receipt: AnchorReceipt } | { ok: false; reason: string; claimed: AnchorReceipt | null } {
  const v = verifyReceiptWithKeys(input, keys);
  if (!v.ok) return v;
  const refusal = receiptChainRefusal(store.db, v.receipt, expectedChainId);
  return refusal ? { ok: false, reason: refusal, claimed: v.receipt } : v;
}

/** The active local signing identity as the service names it. */
export function localChainIdentity(store: KronicleLite): { chain_id: string; key_id: string; public_key_pem: string } {
  const pem = store.identity.signer.public_key_pem;
  return { chain_id: chainIdFromPublicKeyPem(pem), key_id: store.identity.signer.key_id, public_key_pem: pem };
}

export function toWireCheckpoint(cp: Checkpoint): WireCheckpoint {
  const parsed = parseWireCheckpoint({
    v: 1,
    from_seq: cp.from_seq,
    to_seq: cp.to_seq,
    leaf_count: cp.leaf_count,
    root: cp.root,
    key_id: cp.key_id,
    signature: cp.signature,
  });
  if (!parsed.ok) throw new Error(`local checkpoint ${cp.checkpoint_id} is malformed: ${parsed.detail}`);
  return parsed.value;
}

export interface PushResult {
  anchor_id: string;
  duplicate: boolean;
  conflict: boolean;
  conflicting_anchor_ids: string[];
  checkpoint_id: string;
  range: [number, number];
  root: string;
  received_at: string;
  verify_url: string;
  public_status: string;
  usage?: { used_this_month: number; limit: number | null; tier: string };
  /** Service-key pinning events (first-use pin, rotation, ignored keys). */
  key_notes: string[];
}

/**
 * Push one local checkpoint (latest by default). Refuses a checkpoint that
 * does not verify against signing_keys, and one whose range the local chain
 * no longer matches. After the POST the service key document is reconciled
 * with the local pins, the receipt's countersignature is checked against a
 * pinned key (status and validity window included), its checkpoint
 * signature against the local chain key, its checkpoint compared field by
 * field with what was sent, and `receipt_jcs` checked to be exactly that
 * receipt — before anything is stored in `anchors`.
 */
export async function pushCheckpoint(store: KronicleLite, opts: AnchorCallOptions & { checkpointId?: string } = {}): Promise<PushResult> {
  const cfg = configFor(store, opts);
  const licenseKey = requireLicenseKey(store, opts);
  const local = opts.checkpointId ? store.chain.getCheckpoint(opts.checkpointId) : store.chain.latestCheckpoint();
  if (!local) {
    throw new AnchorConfigError(opts.checkpointId ? `no checkpoint ${opts.checkpointId}` : 'no checkpoints yet: run `kronicle-lite checkpoint` first');
  }
  const check = store.chain.verifyCheckpoint(local);
  if (!check.ok) {
    if (check.reason === 'root_mismatch') {
      const now = store.chain.rootOver(local.from_seq, local.to_seq);
      throw new Error(
        `local chain no longer matches checkpoint ${local.checkpoint_id} over [${local.from_seq}, ${local.to_seq}] (root ${now?.root.slice(0, 16) ?? 'n/a'} ≠ ${local.root.slice(0, 16)}); run verify-chain`,
      );
    }
    throw new Error(`local checkpoint ${local.checkpoint_id} does not verify against signing_keys (${check.reason}); refusing to push`);
  }
  const keyRow = store.db.prepare(`SELECT public_key_pem FROM signing_keys WHERE key_id = ? AND revoked_at IS NULL`).get(local.key_id) as
    | { public_key_pem: string }
    | undefined;
  if (!keyRow) throw new Error(`no active signing key ${local.key_id}`);
  const pem = keyRow.public_key_pem;
  if (keyIdFromPublicKey(createPublicKey(pem)) !== local.key_id) throw new Error(`signing_keys row ${local.key_id} does not derive to its own key_id`);
  const chain_id = chainIdFromPublicKeyPem(pem);
  const cp = toWireCheckpoint(local);

  const api = clientFor(cfg, opts);
  // The key list (rollback and chain checks) before anything is sent, as the service's own client does.
  const pins = await fetchKeys(store, cfg, api, opts);
  if (pins.violations.length > 0 || !pins.set) throw new ServiceKeyTrustError(`${pins.violations.join('; ')}; nothing sent`);
  const resp = await api.push(licenseKey, { chain_id, pubkey: pem, checkpoint: cp });
  const checked = checkHeldReceipt(store, resp.receipt, pins.set, chain_id);
  if (!checked.ok) throw new Error(`anchor receipt rejected: ${checked.reason}; nothing stored`);
  const receipt = checked.receipt;
  if (
    receipt.chain_id !== chain_id ||
    receipt.checkpoint.root !== cp.root ||
    receipt.checkpoint.from_seq !== cp.from_seq ||
    receipt.checkpoint.to_seq !== cp.to_seq ||
    receipt.checkpoint.leaf_count !== cp.leaf_count ||
    receipt.checkpoint.signature !== cp.signature
  ) {
    throw new Error('anchor receipt does not describe the checkpoint that was sent; nothing stored');
  }
  // A2-17: what is stored is the verified receipt's JCS. A receipt_jcs string
  // from the service must be exactly that, or nothing is stored.
  const jcs = anchorReceiptJcs(receipt);
  if (resp.receipt_jcs !== undefined && resp.receipt_jcs !== null) {
    if (typeof resp.receipt_jcs !== 'string') throw new Error('anchor response receipt_jcs is not a string; nothing stored');
    let parsedJcs: unknown;
    try {
      parsedJcs = JSON.parse(resp.receipt_jcs);
    } catch {
      throw new Error('anchor response receipt_jcs is not JSON; nothing stored');
    }
    const again = checkHeldReceipt(store, parsedJcs, pins.set, chain_id);
    if (!again.ok) throw new Error(`anchor response receipt_jcs rejected: ${again.reason}; nothing stored`);
    if (resp.receipt_jcs !== jcs) throw new Error('anchor response receipt_jcs is not the JCS of the countersigned receipt; nothing stored');
  }
  store.chain.recordAnchor({
    anchor_id: receipt.anchor_id,
    checkpoint_id: local.checkpoint_id,
    chain_id: receipt.chain_id,
    anchor_url: cfg.anchor_url,
    from_seq: cp.from_seq,
    to_seq: cp.to_seq,
    root: cp.root,
    received_at: receipt.received_at,
    receipt_json: jcs,
    day: resp.public?.day ?? null,
    leaf_index: resp.public?.leaf_index ?? null,
    path_json: resp.public?.path ? JSON.stringify(resp.public.path) : null,
    status: resp.conflict ? 'conflict' : (resp.public?.status ?? 'pending_public'),
  });
  return {
    anchor_id: receipt.anchor_id,
    duplicate: resp.duplicate,
    conflict: resp.conflict,
    conflicting_anchor_ids: resp.conflicting_anchor_ids ?? [],
    checkpoint_id: local.checkpoint_id,
    range: [cp.from_seq, cp.to_seq],
    root: cp.root,
    received_at: receipt.received_at,
    verify_url: resp.verify_url,
    public_status: resp.public?.status ?? 'pending_public',
    ...(resp.usage ? { usage: resp.usage } : {}),
    key_notes: pins.notes,
  };
}

/** unverified: no receipt whose countersignature verifies against a pinned key, so the range was not compared. */
export type RangeResult = 'match' | 'diverged' | 'beyond_head' | 'gap' | 'unverified';

export interface RangeCheck {
  anchor_id: string;
  from_seq: number;
  to_seq: number;
  /** The root inside the countersigned receipt (what the comparison used); the receipt's unverified claim when result=unverified. */
  anchored_root: string;
  local_root: string | null;
  received_at: string;
  source: 'remote' | 'local';
  countersignature: 'ok' | 'failed' | 'unchecked';
  conflict_remote: boolean;
  result: RangeResult;
}

export interface VerifyRemoteResult {
  ok: boolean;
  chain_id: string;
  head_seq: number;
  checks: RangeCheck[];
  divergences: string[];
  /** Trust failures (untrusted receipts, key document violations, listings that contradict their signed receipts). Any one fails verification. */
  problems: string[];
  /** Informational: first-use pins, rotations, anchors we hold that the service did not list. */
  notes: string[];
  summary: string;
}

/** Compare one anchored range with the local rows. */
export function compareRange(store: KronicleLite, from_seq: number, to_seq: number, root: string): { result: RangeResult; local_root: string | null } {
  const head = store.chain.head();
  if (to_seq > head.seq) return { result: 'beyond_head', local_root: null };
  const lr = store.chain.rootOver(from_seq, to_seq);
  if (!lr) return { result: 'gap', local_root: null };
  return { result: lr.root === root ? 'match' : 'diverged', local_root: lr.root };
}

function divergenceLine(e: { from_seq: number; to_seq: number; root: string; received_at: string }, result: RangeResult, local_root: string | null): string {
  return `local chain diverges from anchor at [${e.from_seq},${e.to_seq}] (${result}; anchored ${e.root.slice(0, 16)}… at ${e.received_at}${
    local_root ? `, local ${local_root.slice(0, 16)}…` : ''
  })`;
}

/** Unsigned fields (a service listing or the local `anchors` row) that disagree with the signed receipt. */
function unsignedMismatch(
  signed: AnchorReceipt,
  claimed: { anchor_id?: string; from_seq?: number; to_seq?: number; root?: string; received_at?: string },
): string[] {
  const bad: string[] = [];
  if (claimed.anchor_id !== undefined && claimed.anchor_id !== signed.anchor_id) bad.push('anchor_id');
  if (claimed.from_seq !== undefined && claimed.from_seq !== signed.checkpoint.from_seq) bad.push('from_seq');
  if (claimed.to_seq !== undefined && claimed.to_seq !== signed.checkpoint.to_seq) bad.push('to_seq');
  if (claimed.root !== undefined && claimed.root !== signed.checkpoint.root) bad.push('root');
  if (claimed.received_at !== undefined && claimed.received_at !== signed.received_at) bad.push('received_at');
  return bad;
}

interface Candidate {
  anchor_id: string;
  receipt: unknown;
  source: 'remote' | 'local';
  conflict: boolean;
  /** Unsigned values shown next to the receipt, cross-checked only. */
  unsigned: { anchor_id?: string; from_seq?: number; to_seq?: number; root?: string; received_at?: string };
  unsignedLabel: string;
  /** Offline: the service this receipt was pushed to (its kept key list is the one that counts). */
  anchorUrl?: string;
}

/**
 * `verify --remote`: fetch this chain's anchors from the service (or, with
 * `offline`, use the stored receipts), and for every receipt — every one the
 * service lists AND every one held locally — verify its countersignature
 * against a pinned service key and its checkpoint signature against the
 * local chain key, then recompute the local root over the SIGNED range and
 * compare with the SIGNED root. Unsigned listing fields and the local
 * `anchors.root` column are never comparison values; when they disagree with
 * the signed receipt that is reported as a problem. A mismatch is the
 * sentence verify_chain cannot say on its own: "local chain diverges from
 * anchor at [a,b]".
 */
export async function verifyRemote(store: KronicleLite, opts: AnchorCallOptions & { offline?: boolean } = {}): Promise<VerifyRemoteResult> {
  const cfg = configFor(store, opts);
  const { chain_id } = localChainIdentity(store);
  const head = store.chain.head();
  const problems: string[] = [];
  const notes: string[] = [];
  const held = store.chain.listAnchors();
  const candidates: Candidate[] = [];
  let keys: ServiceKeySet | null;

  // Offline: each stored receipt is checked against the key list kept for the service it was pushed to.
  const keptByUrl = new Map<string, ServiceKeySet | null>();
  const keptFor = (url: string): ServiceKeySet | null => {
    if (!keptByUrl.has(url)) {
      const lp = keptKeys(store, { ...cfg, anchor_url: url }, opts);
      keptByUrl.set(url, lp.set);
      problems.push(...lp.violations);
      notes.push(...lp.notes);
    }
    return keptByUrl.get(url)!;
  };
  if (opts.offline) {
    keys = null;
    for (const a of held) {
      candidates.push({
        anchorUrl: a.anchor_url,
        anchor_id: a.anchor_id,
        receipt: safeJson(a.receipt_json),
        source: 'local',
        conflict: a.status === 'conflict',
        unsigned: { anchor_id: a.anchor_id, from_seq: a.from_seq, to_seq: a.to_seq, root: a.root, received_at: a.received_at },
        unsignedLabel: 'local anchors row',
      });
    }
  } else {
    const api = clientFor(cfg, opts);
    let remote: RemoteChain | null = null;
    try {
      remote = await api.chain(chain_id);
    } catch (e) {
      // A listing that breaks pagination is never a complete list: report it
      // (verification fails) and still check every receipt held locally.
      if (!(e instanceof AnchorListingError)) throw e;
      problems.push(e.message);
    }
    const rec = await fetchKeys(store, cfg, api, opts);
    keys = rec.set;
    problems.push(...rec.violations);
    notes.push(...rec.notes);
    const listed = remote?.anchors ?? [];
    const listedIds = new Set(listed.map((a) => a.anchor_id));
    const heldById = new Map(held.map((h) => [h.anchor_id, h]));
    for (const a of listed as RemoteAnchor[]) {
      candidates.push({
        anchor_id: a.anchor_id,
        receipt: a.receipt,
        source: 'remote',
        conflict: a.conflict === true,
        unsigned: { anchor_id: a.anchor_id, from_seq: a.from_seq, to_seq: a.to_seq, root: a.root, received_at: a.received_at },
        unsignedLabel: `listing from ${cfg.anchor_url}`,
      });
      const mine = heldById.get(a.anchor_id);
      if (mine && !sameReceipt(mine.receipt_json, a.receipt)) {
        notes.push(`anchor ${a.anchor_id}: the receipt ${cfg.anchor_url} lists differs from the one stored locally; checking both`);
        candidates.push({
          anchor_id: mine.anchor_id,
          receipt: safeJson(mine.receipt_json),
          source: 'local',
          conflict: mine.status === 'conflict',
          unsigned: { anchor_id: mine.anchor_id, from_seq: mine.from_seq, to_seq: mine.to_seq, root: mine.root, received_at: mine.received_at },
          unsignedLabel: 'local anchors row',
        });
      }
    }
    // A2-11: a receipt we hold is checked even when the service leaves it out.
    for (const h of held) {
      if (listedIds.has(h.anchor_id)) continue;
      notes.push(`anchor ${h.anchor_id} [${h.from_seq},${h.to_seq}] is held locally but not listed by ${cfg.anchor_url}; checked from the local receipt`);
      candidates.push({
        anchor_id: h.anchor_id,
        receipt: safeJson(h.receipt_json),
        source: 'local',
        conflict: h.status === 'conflict',
        unsigned: { anchor_id: h.anchor_id, from_seq: h.from_seq, to_seq: h.to_seq, root: h.root, received_at: h.received_at },
        unsignedLabel: 'local anchors row',
      });
    }
    // Refresh the public status of anchors we hold whose listed receipt verifies.
    for (const a of listed) {
      const m = heldById.get(a.anchor_id);
      if (!m || !checkHeldReceipt(store, a.receipt, keys, chain_id).ok) continue;
      store.chain.recordAnchor({
        ...m,
        day: a.public?.day ?? null,
        leaf_index: a.public?.leaf_index ?? null,
        path_json: a.public?.path ? JSON.stringify(a.public.path) : null,
        status: a.conflict ? 'conflict' : (a.public?.status ?? m.status),
        fetched_at: new Date().toISOString(),
      });
    }
  }

  const divergences: string[] = [];
  const checks: RangeCheck[] = [];
  for (const c of candidates) {
    // Listed anchors must be for the chain we asked about; a held receipt
    // must derive from one of our own signing keys (checked either way).
    const v = checkHeldReceipt(store, c.receipt, c.anchorUrl !== undefined ? keptFor(c.anchorUrl) : keys, c.source === 'remote' ? chain_id : null);
    if (!v.ok) {
      const claimed = v.claimed;
      problems.push(`anchor ${c.anchor_id} (${c.source}): ${v.reason}; range not compared`);
      checks.push({
        anchor_id: c.anchor_id,
        from_seq: claimed?.checkpoint.from_seq ?? c.unsigned.from_seq ?? 0,
        to_seq: claimed?.checkpoint.to_seq ?? c.unsigned.to_seq ?? 0,
        anchored_root: claimed?.checkpoint.root ?? c.unsigned.root ?? '',
        local_root: null,
        received_at: claimed?.received_at ?? c.unsigned.received_at ?? '',
        source: c.source,
        countersignature: 'failed',
        conflict_remote: c.conflict,
        result: 'unverified',
      });
      continue;
    }
    const r = v.receipt;
    const off = unsignedMismatch(r, c.unsigned);
    if (off.length > 0) problems.push(`anchor ${c.anchor_id}: ${c.unsignedLabel} disagrees with its countersigned receipt (${off.join(', ')}); the signed values were used`);
    const e = { from_seq: r.checkpoint.from_seq, to_seq: r.checkpoint.to_seq, root: r.checkpoint.root, received_at: r.received_at };
    const { result, local_root } = compareRange(store, e.from_seq, e.to_seq, e.root);
    if (result !== 'match') divergences.push(divergenceLine(e, result, local_root));
    checks.push({
      anchor_id: r.anchor_id,
      from_seq: e.from_seq,
      to_seq: e.to_seq,
      anchored_root: e.root,
      local_root,
      received_at: e.received_at,
      source: c.source,
      countersignature: 'ok',
      conflict_remote: c.conflict,
      result,
    });
  }
  const badSigs = checks.filter((c) => c.countersignature === 'failed');
  const ok = divergences.length === 0 && badSigs.length === 0 && problems.length === 0 && checks.length > 0;
  const summary =
    checks.length === 0
      ? problems.length > 0
        ? `nothing anchored for this chain; ${problems.length} problem(s)`
        : 'nothing anchored for this chain'
      : ok
        ? `${checks.length} anchored range(s) match the local chain (head ${head.seq})`
        : `${divergences.length} divergence(s), ${badSigs.length} untrusted receipt(s), ${problems.length} problem(s) across ${checks.length} anchored range(s)`;
  return { ok, chain_id, head_seq: head.seq, checks, divergences, problems, notes, summary };
}

function sameReceipt(storedJson: string, other: unknown): boolean {
  try {
    return anchorReceiptJcs(other as AnchorReceipt) === anchorReceiptJcs(JSON.parse(storedJson) as AnchorReceipt);
  } catch {
    return false;
  }
}

function safeJson(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}

export interface AnchorStatus {
  chain_id: string;
  key_id: string;
  head_seq: number;
  anchor_url: string;
  license_key_configured: boolean;
  anchors: number;
  last: null | {
    anchor_id: string;
    range: [number, number];
    root: string;
    received_at: string;
    status: string;
    verify_url: string;
    events_since: number;
  };
}

/** Local only: no network. */
export function anchorStatus(store: KronicleLite, opts: AnchorCallOptions = {}): AnchorStatus {
  const cfg = configFor(store, opts);
  const { chain_id, key_id } = localChainIdentity(store);
  const head = store.chain.head();
  const last = store.chain.lastAnchor();
  return {
    chain_id,
    key_id,
    head_seq: head.seq,
    anchor_url: cfg.anchor_url,
    license_key_configured: licenseKeySource(store, opts) !== null,
    anchors: store.chain.listAnchors().length,
    last: last
      ? {
          anchor_id: last.anchor_id,
          range: [last.from_seq, last.to_seq],
          root: last.root,
          received_at: last.received_at,
          status: last.status,
          verify_url: `${cfg.anchor_url.replace(/\/+$/, '')}/v/${chain_id}`,
          events_since: Math.max(0, head.seq - last.to_seq),
        }
      : null,
  };
}

export interface LastAnchorVerification {
  /** Local root over the range in the last anchor's countersigned receipt vs that receipt's root; `none` when never anchored; `unverified` when the receipt is not trusted. */
  result: RangeResult | 'none';
  countersignature: 'ok' | 'failed' | 'unchecked';
  /** remote: checked against the service; skipped: local pins only; unreachable: the service did not answer; invalid: its listing broke the pagination protocol (never a complete check). */
  remote: 'checked' | 'skipped' | 'unreachable' | 'invalid';
  remote_conflict: boolean | null;
  detail: string | null;
}

/**
 * The MCP `anchor_status` check: verify the latest stored receipt against
 * the pinned service keys (refreshed from the service when `remote`) and the
 * local chain key, then compare the local root over the receipt's signed
 * range with its signed root — never the `anchors.root` column. When
 * `remote`, also read the service's conflict flag. Never throws for network
 * trouble: reports `remote: 'unreachable'` and falls back to local pins.
 */
export async function verifyLastAnchor(store: KronicleLite, opts: AnchorCallOptions & { remote?: boolean } = {}): Promise<LastAnchorVerification> {
  const last = store.chain.lastAnchor();
  if (!last) return { result: 'none', countersignature: 'unchecked', remote: 'skipped', remote_conflict: null, detail: 'never anchored' };
  const cfg = configFor(store, opts);
  const { chain_id } = localChainIdentity(store);
  const extra: string[] = [];
  let remoteState: LastAnchorVerification['remote'] = 'skipped';
  let remoteConflict: boolean | null = null;
  let keys: ServiceKeySet | null = null;
  let violations = false;
  let fromNetwork = false;
  if (opts.remote) {
    try {
      const api = clientFor(cfg, opts);
      const remote = await api.chain(chain_id);
      const rec = await fetchKeys(store, cfg, api, opts);
      keys = rec.set;
      fromNetwork = true;
      extra.push(...rec.violations);
      violations = rec.violations.length > 0;
      remoteState = 'checked';
      remoteConflict = remote ? remote.conflict : null;
      const entry = remote?.anchors.find((a) => a.anchor_id === last.anchor_id) ?? null;
      if (!entry) extra.push(`anchor ${last.anchor_id} not listed by ${cfg.anchor_url}`);
    } catch (err) {
      if (err instanceof ServiceKeyTrustError || err instanceof AnchorConfigError) {
        extra.push(err.message);
        violations = true;
        remoteState = 'checked';
      } else if (err instanceof AnchorListingError) {
        extra.push(err.message);
        remoteState = 'invalid';
      } else {
        remoteState = 'unreachable';
        extra.push(err instanceof Error ? err.message : String(err));
      }
    }
  }
  if (!fromNetwork) {
    const lp = keptKeys(store, { ...cfg, anchor_url: last.anchor_url }, opts);
    keys = lp.set;
    if (lp.violations.length) {
      extra.push(...lp.violations);
      violations = true;
    }
  }
  const v = checkHeldReceipt(store, safeJson(last.receipt_json), keys, null);
  const join = (d: string | null) => {
    const all = [...(d ? [d] : []), ...extra];
    return all.length > 0 ? all.join('; ') : null;
  };
  if (!v.ok) {
    return { result: 'unverified', countersignature: 'failed', remote: remoteState, remote_conflict: remoteConflict, detail: join(`anchor ${last.anchor_id}: ${v.reason}; range not compared`) };
  }
  const r = v.receipt;
  const e = { from_seq: r.checkpoint.from_seq, to_seq: r.checkpoint.to_seq, root: r.checkpoint.root, received_at: r.received_at };
  const off = unsignedMismatch(r, { anchor_id: last.anchor_id, from_seq: last.from_seq, to_seq: last.to_seq, root: last.root, received_at: last.received_at });
  if (off.length > 0) extra.push(`local anchors row disagrees with its countersigned receipt (${off.join(', ')}); the signed values were used`);
  const { result, local_root } = compareRange(store, e.from_seq, e.to_seq, e.root);
  return {
    result,
    countersignature: violations ? 'failed' : 'ok',
    remote: remoteState,
    remote_conflict: remoteConflict,
    detail: join(result === 'match' ? null : divergenceLine(e, result, local_root)),
  };
}

export interface PushOutcome {
  ok: boolean;
  anchor_id: string | null;
  duplicate: boolean | null;
  conflict: boolean | null;
  conflicting_anchor_ids: string[];
  received_at: string | null;
  verify_url: string | null;
  public_status: string | null;
  error: 'anchor_unreachable' | 'anchor_refused' | 'anchor_config' | 'anchor_failed' | null;
  message: string | null;
  /** Service-key pinning events from this push (first-use pin, rotation, ignored keys). */
  key_notes: string[];
}

/**
 * pushCheckpoint for callers that must not fail when the service does: the
 * MCP tool and `checkpoint --push` report the outcome next to the local
 * checkpoint, which is already stored.
 */
export async function tryPushCheckpoint(store: KronicleLite, opts: AnchorCallOptions & { checkpointId?: string } = {}): Promise<PushOutcome> {
  try {
    const r = await pushCheckpoint(store, opts);
    return {
      ok: !r.conflict,
      anchor_id: r.anchor_id,
      duplicate: r.duplicate,
      conflict: r.conflict,
      conflicting_anchor_ids: r.conflicting_anchor_ids,
      received_at: r.received_at,
      verify_url: r.verify_url,
      public_status: r.public_status,
      error: null,
      message: r.conflict
        ? `CONFLICT: [${r.range[0]}, ${r.range[1]}] was already anchored with a different root (${r.conflicting_anchor_ids.join(', ')}); the chain was rewritten after an earlier anchor`
        : null,
      key_notes: r.key_notes,
    };
  } catch (err) {
    if (err instanceof AnchorApiError && err.status === 410 && err.code === 'chain_erased') {
      return {
        ok: false,
        anchor_id: null,
        duplicate: null,
        conflict: null,
        conflicting_anchor_ids: [],
        received_at: null,
        verify_url: null,
        public_status: null,
        error: 'anchor_refused',
        message:
          'anchor service refused (410 chain_erased): this chain was erased on the anchor service and accepts no further anchors; receipts already issued stay valid and verifiable. Not retried.',
        key_notes: [],
      };
    }
    const error: PushOutcome['error'] =
      err instanceof AnchorUnreachableError
        ? 'anchor_unreachable'
        : err instanceof AnchorApiError || err instanceof AnchorRateLimitedError
          ? 'anchor_refused'
          : err instanceof AnchorConfigError || err instanceof ServiceKeyTrustError
            ? 'anchor_config'
            : 'anchor_failed';
    return {
      ok: false,
      anchor_id: null,
      duplicate: null,
      conflict: null,
      conflicting_anchor_ids: [],
      received_at: null,
      verify_url: null,
      public_status: null,
      error,
      message: err instanceof Error ? err.message : String(err),
      key_notes: [],
    };
  }
}
