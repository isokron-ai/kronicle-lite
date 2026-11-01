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
import { AnchorApiError, AnchorClient, AnchorUnreachableError, type RemoteAnchor, type ServiceKeys } from './client.js';
import { AnchorConfigError, loadConfig, readKeysCache, writeKeysCache, type AnchorConfig } from './config.js';
import { parseWireCheckpoint, type WireCheckpoint } from './wire.js';

export interface AnchorCallOptions {
  /** Overrides KRONICLE_ANCHOR_URL / config.json. */
  anchorUrl?: string;
  /** Overrides KRONICLE_ANCHOR_KEY / config.json. */
  licenseKey?: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
}

function configFor(store: KronicleLite, opts: AnchorCallOptions): AnchorConfig {
  return loadConfig(store.dataDir, {
    ...(opts.anchorUrl ? { anchor_url: opts.anchorUrl } : {}),
    ...(opts.licenseKey ? { license_key: opts.licenseKey } : {}),
  });
}

function clientFor(cfg: AnchorConfig, opts: AnchorCallOptions, preloadedKeys: ServiceKeys | null = null): AnchorClient {
  return new AnchorClient(cfg.anchor_url, {
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
    ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
    preloadedKeys,
  });
}

async function refreshKeysCache(store: KronicleLite, api: AnchorClient): Promise<void> {
  try {
    writeKeysCache(store.dataDir, await api.serviceKeys());
  } catch {
    // best effort
  }
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
}

/**
 * Push one local checkpoint (latest by default). Refuses a checkpoint that
 * does not verify against signing_keys, and one whose range the local chain
 * no longer matches. After the POST the receipt is parsed, its
 * countersignature checked against the service's published keys, and its
 * checkpoint compared field by field with what was sent, before anything is
 * stored in `anchors`.
 */
export async function pushCheckpoint(store: KronicleLite, opts: AnchorCallOptions & { checkpointId?: string } = {}): Promise<PushResult> {
  const cfg = configFor(store, opts);
  if (!cfg.license_key) {
    throw new AnchorConfigError(
      'no license key: pass --key, set KRONICLE_ANCHOR_KEY, or write {"license_key": …} to <data-dir>/config.json',
    );
  }
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
  const resp = await api.push(cfg.license_key, { chain_id, pubkey: pem, checkpoint: cp });
  const receipt = await api.verifyReceipt(resp.receipt);
  await refreshKeysCache(store, api);
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
  store.chain.recordAnchor({
    anchor_id: receipt.anchor_id,
    checkpoint_id: local.checkpoint_id,
    chain_id: receipt.chain_id,
    anchor_url: cfg.anchor_url,
    from_seq: cp.from_seq,
    to_seq: cp.to_seq,
    root: cp.root,
    received_at: receipt.received_at,
    receipt_json: typeof resp.receipt_jcs === 'string' ? resp.receipt_jcs : JSON.stringify(receipt),
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
  };
}

export type RangeResult = 'match' | 'diverged' | 'beyond_head' | 'gap';

export interface RangeCheck {
  anchor_id: string;
  from_seq: number;
  to_seq: number;
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

/**
 * `verify --remote`: fetch this chain's anchors from the service (or, with
 * `offline`, use the stored receipts and the cached service keys), recompute
 * the local root for every anchored range, compare. A mismatch is the
 * sentence verify_chain cannot say on its own: "local chain diverges from
 * anchor at [a,b]".
 */
export async function verifyRemote(store: KronicleLite, opts: AnchorCallOptions & { offline?: boolean } = {}): Promise<VerifyRemoteResult> {
  const cfg = configFor(store, opts);
  const { chain_id } = localChainIdentity(store);
  const head = store.chain.head();
  const cached = readKeysCache(store.dataDir);
  const api = clientFor(cfg, opts, opts.offline ? cached : null);
  const checks: RangeCheck[] = [];

  type Entry = { anchor_id: string; from_seq: number; to_seq: number; root: string; received_at: string; receipt: unknown; conflict: boolean; source: 'remote' | 'local' };
  let entries: Entry[];
  if (opts.offline) {
    entries = store.chain.listAnchors().map((a) => ({
      anchor_id: a.anchor_id,
      from_seq: a.from_seq,
      to_seq: a.to_seq,
      root: a.root,
      received_at: a.received_at,
      receipt: safeJson(a.receipt_json),
      conflict: a.status === 'conflict',
      source: 'local' as const,
    }));
  } else {
    const remote = await api.chain(chain_id);
    await refreshKeysCache(store, api);
    entries = (remote?.anchors ?? []).map((a: RemoteAnchor) => ({
      anchor_id: a.anchor_id,
      from_seq: a.from_seq,
      to_seq: a.to_seq,
      root: a.root,
      received_at: a.received_at,
      receipt: a.receipt,
      conflict: a.conflict,
      source: 'remote' as const,
    }));
    // Refresh the public status of anchors we already hold.
    const mine = new Map(store.chain.listAnchors().map((x) => [x.anchor_id, x]));
    for (const a of remote?.anchors ?? []) {
      const m = mine.get(a.anchor_id);
      if (m) {
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
  }

  const divergences: string[] = [];
  for (const e of entries) {
    let countersignature: RangeCheck['countersignature'] = 'unchecked';
    if (!(opts.offline && !cached)) {
      try {
        await api.verifyReceipt(e.receipt);
        countersignature = 'ok';
      } catch {
        countersignature = 'failed';
      }
    }
    const { result, local_root } = compareRange(store, e.from_seq, e.to_seq, e.root);
    if (result !== 'match') divergences.push(divergenceLine(e, result, local_root));
    checks.push({
      anchor_id: e.anchor_id,
      from_seq: e.from_seq,
      to_seq: e.to_seq,
      anchored_root: e.root,
      local_root,
      received_at: e.received_at,
      source: e.source,
      countersignature,
      conflict_remote: e.conflict,
      result,
    });
  }
  const badSigs = checks.filter((c) => c.countersignature === 'failed');
  const ok = divergences.length === 0 && badSigs.length === 0 && checks.length > 0;
  const summary =
    checks.length === 0
      ? 'nothing anchored for this chain'
      : ok
        ? `${checks.length} anchored range(s) match the local chain (head ${head.seq})`
        : `${divergences.length} divergence(s), ${badSigs.length} bad countersignature(s) across ${checks.length} anchored range(s)`;
  return { ok, chain_id, head_seq: head.seq, checks, divergences, summary };
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
    license_key_configured: cfg.license_key !== null,
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
  /** Local root comparison for the latest anchor; `none` when never anchored. */
  result: RangeResult | 'none';
  countersignature: 'ok' | 'failed' | 'unchecked';
  /** remote: checked against the service; skipped: local + cached keys only; unreachable: the service did not answer. */
  remote: 'checked' | 'skipped' | 'unreachable';
  remote_conflict: boolean | null;
  detail: string | null;
}

/**
 * The MCP `anchor_status` check: compare the latest anchor's root with the
 * local rows (always), check its countersignature with cached keys (or fresh
 * ones when `remote`), and, when `remote`, read the service's conflict flag.
 * Never throws for network trouble: reports `remote: 'unreachable'`.
 */
export async function verifyLastAnchor(store: KronicleLite, opts: AnchorCallOptions & { remote?: boolean } = {}): Promise<LastAnchorVerification> {
  const last = store.chain.lastAnchor();
  if (!last) return { result: 'none', countersignature: 'unchecked', remote: 'skipped', remote_conflict: null, detail: 'never anchored' };
  const { result, local_root } = compareRange(store, last.from_seq, last.to_seq, last.root);
  const detail = result === 'match' ? null : divergenceLine(last, result, local_root);
  const cfg = configFor(store, opts);
  const cached = readKeysCache(store.dataDir);
  if (!opts.remote) {
    let countersignature: LastAnchorVerification['countersignature'] = 'unchecked';
    if (cached) {
      try {
        await clientFor(cfg, opts, cached).verifyReceipt(safeJson(last.receipt_json));
        countersignature = 'ok';
      } catch {
        countersignature = 'failed';
      }
    }
    return { result, countersignature, remote: 'skipped', remote_conflict: null, detail };
  }
  const api = clientFor(cfg, opts);
  try {
    const remote = await api.chain(localChainIdentity(store).chain_id);
    let countersignature: LastAnchorVerification['countersignature'] = 'failed';
    try {
      await api.verifyReceipt(safeJson(last.receipt_json));
      countersignature = 'ok';
    } catch {
      countersignature = 'failed';
    }
    const entry = remote?.anchors.find((a) => a.anchor_id === last.anchor_id) ?? null;
    return {
      result,
      countersignature,
      remote: 'checked',
      remote_conflict: remote ? remote.conflict : null,
      detail: entry ? detail : `${detail ? detail + '; ' : ''}anchor ${last.anchor_id} not listed by ${cfg.anchor_url}`,
    };
  } catch (err) {
    return { result, countersignature: 'unchecked', remote: 'unreachable', remote_conflict: null, detail: err instanceof Error ? err.message : String(err) };
  }
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
    };
  } catch (err) {
    const error: PushOutcome['error'] =
      err instanceof AnchorUnreachableError
        ? 'anchor_unreachable'
        : err instanceof AnchorApiError
          ? 'anchor_refused'
          : err instanceof AnchorConfigError
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
    };
  }
}
