/**
 * Evidence bundle (0.9.0): one audit's events, exported as a directory that
 * verifies offline (`kronicle-lite verify-bundle DIR`, src/audit/verify-bundle.ts).
 *
 *   DIR/manifest.json   canonical JSON (RFC 8785): the index and the root
 *   DIR/events.jsonl    one canonical JSON line per event in [from_seq, to_seq]:
 *                       the audit's events in full, every other event as a
 *                       link stub {seq, prev_hash, this_hash, stub: true}
 *   DIR/blobs/<sha256>  the referenced artifacts present in the blob store
 *
 * Stubs keep the segment's hash links continuous without disclosing other
 * documents. The root is the checkpoint Merkle root (FORMAT §2) over the
 * segment's this_hash leaves, signed by the store key (a stored checkpoint,
 * so `anchor push` can anchor the same range). Every byte is a function of
 * the chain and the blob store: exporting twice gives identical files.
 *
 * docs/EVIDENCE-BUNDLE.md is the format and the verification procedure.
 */

import { closeSync, constants, existsSync, lstatSync, mkdirSync, openSync, readdirSync, writeSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import type { Chain, ChainEvent } from '../chain/index.js';
import { canonicalize, type JsonValue } from '../crypto/canonical.js';
import { sha256Hex } from '../crypto/hash.js';
import type { Signer } from '../crypto/keys.js';
import { AuditError, type AuditLog } from './log.js';
import { blobRefsOf, BUNDLE_FORMAT } from './schemas.js';

export { BUNDLE_FORMAT };


export interface BundleStub {
  seq: number;
  prev_hash: string;
  this_hash: string;
  stub: true;
}
export type BundleLine = ChainEvent | BundleStub;

export interface BundleManifest {
  format: typeof BUNDLE_FORMAT;
  audit_id: string;
  range: { from_seq: number; to_seq: number; leaf_count: number; first_prev_hash: string };
  /** sha256 of events.jsonl's exact bytes. */
  events_sha256: string;
  /** The audit's events (full lines), ascending seq. */
  events: { seq: number; event_id: string; event_type: string; this_hash: string }[];
  /** Events in range that are stubs (other events; payload withheld), with the hash each one must carry. */
  stubs: { seq: number; this_hash: string }[];
  blobs: { sha256: string; size: number; media_type: string | null; unscanned_encoding?: true }[];
  /** Refs declared `redacted: true` at record time: deliberately never stored. */
  redacted: { sha256: string; size: number; referenced_by: string[] }[];
  /** Refs to blobs the store no longer holds (should be empty; listed, never hidden). */
  missing: { sha256: string; size: number; referenced_by: string[] }[];
  root: { root: string; leaf_count: number; key_id: string; public_key_pem: string; signature: string };
  /**
   * Ed25519 by the store key over MANIFEST_SIGNING_DOMAIN + JCS(manifest
   * without `signature`): binds the index (which seqs are full events and
   * which are stubs), the blob lists and every digest, not just the root.
   */
  signature?: { key_id: string; signature: string };
}

export const MANIFEST_SIGNING_DOMAIN = 'kronicle-lite/evidence-bundle-manifest/1\n';

/** The bytes the manifest signature covers. */
export function manifestSigningPayload(m: BundleManifest): string {
  const { signature: _sig, ...rest } = m;
  return MANIFEST_SIGNING_DOMAIN + canonicalize(rest as unknown as JsonValue);
}

/** `m` with its manifest signature (re)computed by `signer`. */
export function signManifest(m: BundleManifest, signer: Signer): BundleManifest {
  const { signature: _old, ...rest } = m;
  return { ...rest, signature: { key_id: signer.key_id, signature: signer.sign(manifestSigningPayload(rest as BundleManifest)) } };
}

export interface ExportResult {
  dir: string;
  manifest_sha256: string;
  manifest: BundleManifest;
}

/** Canonical bytes of a JSON value plus a trailing newline (the on-disk form of every bundle file). */
export const canonicalLine = (v: unknown): string => canonicalize(v as JsonValue) + '\n';

/**
 * The output directory, made safe to write into: it must not exist yet or be
 * an empty real directory; neither it nor any existing ancestor may be a
 * symlink (a planted link would redirect the writes). Created fresh (0700).
 */
function prepareOut(dir: string): string {
  const abs = resolve(dir);
  for (let p = abs; ; p = dirname(p)) {
    let st: ReturnType<typeof lstatSync> | null = null;
    try {
      st = lstatSync(p);
    } catch {
      // does not exist (yet)
    }
    if (st?.isSymbolicLink()) throw new AuditError('invalid_audit_event', `refusing to export through a symlink: ${p} (pass the real path)`);
    if (dirname(p) === p) break;
  }
  if (existsSync(abs)) {
    if (!lstatSync(abs).isDirectory()) throw new AuditError('invalid_audit_event', `--out ${abs} exists and is not a directory`);
    if (readdirSync(abs).length > 0) throw new AuditError('invalid_audit_event', `--out ${abs} is not empty; export into a new or empty directory`);
  } else {
    mkdirSync(abs, { recursive: true, mode: 0o700 });
  }
  mkdirSync(join(abs, 'blobs'), { mode: 0o700 });
  return abs;
}

/** Create a NEW file (never an existing one, never through a symlink) and write it. */
function writeNew(path: string, data: string | Buffer): void {
  // why: O_EXCL refuses any existing entry, a symlink included; O_NOFOLLOW is belt and braces where it exists.
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o644);
  try {
    writeSync(fd, typeof data === 'string' ? Buffer.from(data, 'utf8') : data);
  } finally {
    closeSync(fd);
  }
}

export function exportBundle(args: { chain: Chain; audit: AuditLog; signer: Signer; audit_id: string; dir: string }): ExportResult {
  const seqs = args.audit.seqsOf(args.audit_id);
  if (seqs.length === 0) throw new AuditError('invalid_audit_event', `no audit events for "${args.audit_id}"`);
  const dir = prepareOut(args.dir);
  const from = seqs[0]!;
  const to = seqs[seqs.length - 1]!;
  const mine = new Set(seqs);
  const lines: BundleLine[] = [];
  const events: BundleManifest['events'] = [];
  const stubs: BundleManifest['stubs'] = [];
  const refs = new Map<string, { size: number; redacted: boolean; by: Set<string> }>();
  for (const ev of args.chain.range(from, to)) {
    if (mine.has(ev.seq)) {
      lines.push(ev);
      events.push({ seq: ev.seq, event_id: ev.event_id, event_type: ev.event_type, this_hash: ev.this_hash });
      for (const { ref } of blobRefsOf(ev.payload)) {
        const r = refs.get(ref.sha256) ?? { size: ref.size, redacted: ref.redacted === true, by: new Set<string>() };
        r.by.add(ev.event_id);
        if (ref.redacted !== true) r.redacted = false; // stored by any event → not redacted
        refs.set(ref.sha256, r);
      }
    } else {
      lines.push({ seq: ev.seq, prev_hash: ev.prev_hash, this_hash: ev.this_hash, stub: true });
      stubs.push({ seq: ev.seq, this_hash: ev.this_hash });
    }
  }
  if (lines.length !== to - from + 1) throw new Error(`bundle: chain range ${from}..${to} has a gap`);

  // A stored checkpoint over exactly this range: the store key signs the root; anchoring can reuse it.
  const cp = args.chain.checkpoint(from, to);
  const blobs: BundleManifest['blobs'] = [];
  const redacted: BundleManifest['redacted'] = [];
  const missing: BundleManifest['missing'] = [];
  for (const [sha256, r] of [...refs.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const by = [...r.by].sort();
    if (r.redacted) {
      redacted.push({ sha256, size: r.size, referenced_by: by });
      continue;
    }
    const b = args.audit.getBlob(sha256);
    if (!b) {
      missing.push({ sha256, size: r.size, referenced_by: by });
      continue;
    }
    writeNew(join(dir, 'blobs', sha256), b.bytes);
    blobs.push({ sha256, size: b.size, media_type: b.media_type, ...(b.flags === 'unscanned_encoding' ? { unscanned_encoding: true as const } : {}) });
  }
  const eventsText = lines.map(canonicalLine).join('');
  writeNew(join(dir, 'events.jsonl'), eventsText);
  const manifest: BundleManifest = signManifest({
    format: BUNDLE_FORMAT,
    audit_id: args.audit_id,
    range: { from_seq: from, to_seq: to, leaf_count: cp.leaf_count, first_prev_hash: lines[0]!.prev_hash },
    events_sha256: sha256Hex(eventsText),
    events,
    stubs,
    blobs,
    redacted,
    missing,
    root: { root: cp.root, leaf_count: cp.leaf_count, key_id: cp.key_id, public_key_pem: args.signer.public_key_pem, signature: cp.signature },
  }, args.signer);
  const manifestText = canonicalLine(manifest);
  writeNew(join(dir, 'manifest.json'), manifestText);
  return { dir, manifest_sha256: sha256Hex(manifestText), manifest };
}
