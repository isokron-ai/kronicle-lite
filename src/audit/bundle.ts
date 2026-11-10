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

import { closeSync, constants, existsSync, lstatSync, mkdirSync, openSync, readdirSync, statSync, writeSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import type { Chain, ChainEvent } from '../chain/index.js';
import { canonicalize, type JsonValue } from '../crypto/canonical.js';
import { sha256Hex } from '../crypto/hash.js';
import type { Signer } from '../crypto/keys.js';
import { AuditError, type AuditLog } from './log.js';
import { blobRefsOf, BUNDLE_FORMAT, formatForKinds, kindOfEventType, type AuditKind, type BundleFormat } from './schemas.js';

export { BUNDLE_FORMAT };


export interface BundleStub {
  seq: number;
  prev_hash: string;
  this_hash: string;
  stub: true;
}
export type BundleLine = ChainEvent | BundleStub;

export interface BundleManifest {
  /** /1 when every event is a 0.9.0 kind (0.9.0 readers verify it), /2 when a milestone kind is present, /3 with a run plan or a 0.11.0 kind. */
  format: BundleFormat;
  audit_id: string;
  range: { from_seq: number; to_seq: number; leaf_count: number; first_prev_hash: string };
  /** sha256 of events.jsonl's exact bytes. */
  events_sha256: string;
  /** The audit's events (full lines), ascending seq. */
  events: { seq: number; event_id: string; event_type: string; this_hash: string }[];
  /** Events in range that are stubs (other events; payload withheld), with the hash each one must carry. */
  stubs: { seq: number; this_hash: string }[];
  blobs: { sha256: string; size: number; media_type: string | null; unscanned_encoding?: true; unscanned_size?: true }[];
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

/** A directory as checked: its path and its identity (dev, ino). */
interface PinnedDir {
  path: string;
  dev: bigint;
  ino: bigint;
}

/**
 * The output directory, made safe to write into: it must not exist yet or be
 * an empty real directory; neither it nor any existing ancestor may be a
 * symlink (a planted link would redirect the writes). Created fresh (0700).
 */
function prepareOut(dir: string): PinnedDir {
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
  return pin(abs);
}

function pin(path: string): PinnedDir {
  const st = lstatSync(path, { bigint: true });
  if (!st.isDirectory()) throw changed(path);
  return { path, dev: st.dev, ino: st.ino };
}

const changed = (path: string) => new AuditError('invalid_audit_event', `refusing to export: ${path} changed during export (swapped or replaced by a link); nothing more was written`);

/**
 * #15: run `fn` with the working directory pinned to `d`, the directory that
 * was checked. Writes then use names relative to it, so they land in that
 * inode whatever happens to the path meanwhile (an openat on a directory fd,
 * which Node does not expose). The export is synchronous: no other JS runs
 * while the working directory is moved, and it is always restored. (Not
 * callable from a worker thread, where process.chdir is unavailable; the CLI
 * is the caller.)
 */
function inDir<T>(d: PinnedDir, fn: () => T): T {
  const back = process.cwd();
  process.chdir(d.path);
  try {
    const st = statSync('.', { bigint: true });
    if (st.dev !== d.dev || st.ino !== d.ino) throw changed(d.path);
    return fn();
  } finally {
    process.chdir(back);
  }
}

/** Create a NEW file (never an existing one, never through a symlink) and write it. */
function writeNew(name: string, data: string | Buffer): void {
  // why: O_EXCL refuses any existing entry, a symlink included; O_NOFOLLOW is belt and braces where it exists.
  const fd = openSync(name, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o644);
  try {
    writeSync(fd, typeof data === 'string' ? Buffer.from(data, 'utf8') : data);
  } finally {
    closeSync(fd);
  }
}

export function exportBundle(args: { chain: Chain; audit: AuditLog; signer: Signer; audit_id: string; dir: string }): ExportResult {
  const seqs = args.audit.seqsOf(args.audit_id);
  if (seqs.length === 0) throw new AuditError('invalid_audit_event', `no audit events for "${args.audit_id}"`);
  const out = prepareOut(args.dir);
  const from = seqs[0]!;
  const to = seqs[seqs.length - 1]!;
  const mine = new Set(seqs);
  const lines: BundleLine[] = [];
  const events: BundleManifest['events'] = [];
  const stubs: BundleManifest['stubs'] = [];
  const refs = new Map<string, { size: number; redacted: boolean; by: Set<string> }>();
  const kinds = new Set<AuditKind>();
  let planned = false;
  for (const ev of args.chain.range(from, to)) {
    if (mine.has(ev.seq)) {
      lines.push(ev);
      const k = kindOfEventType(ev.event_type);
      if (k) kinds.add(k);
      if (k === 'harness_frozen' && Array.isArray(ev.payload['plan'])) planned = true;
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
  const stored: string[] = []; // fetched again when written: one blob's bytes in memory at a time
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
    stored.push(sha256);
    const flags = (b.flags ?? '').split(',');
    blobs.push({
      sha256,
      size: b.size,
      media_type: b.media_type,
      ...(flags.includes('unscanned_encoding') ? { unscanned_encoding: true as const } : {}),
      ...(flags.includes('unscanned_size') ? { unscanned_size: true as const } : {}),
    });
  }
  const eventsText = lines.map(canonicalLine).join('');
  const manifest: BundleManifest = signManifest({
    format: formatForKinds(kinds, planned),
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
  // Every write goes through a working directory pinned to a checked inode: out, then
  // out/blobs (entered by a relative chdir from out), then out again.
  const blobsPath = join(out.path, 'blobs');
  const blobsDir = inDir(out, () => {
    mkdirSync('blobs', { mode: 0o700 });
    const made = lstatSync('blobs', { bigint: true });
    process.chdir('blobs');
    const st = statSync('.', { bigint: true });
    if (st.dev !== made.dev || st.ino !== made.ino) throw changed(blobsPath);
    for (const sha256 of stored) {
      const b = args.audit.getBlob(sha256);
      if (!b) throw new AuditError('invalid_audit_event', `blob ${sha256} disappeared during export`);
      writeNew(sha256, b.bytes);
    }
    return made;
  });
  inDir(out, () => {
    const st = lstatSync('blobs', { bigint: true });
    if (!st.isDirectory() || st.dev !== blobsDir.dev || st.ino !== blobsDir.ino) throw changed(blobsPath);
    writeNew('events.jsonl', eventsText);
    writeNew('manifest.json', manifestText);
  });
  return { dir: out.path, manifest_sha256: sha256Hex(manifestText), manifest };
}
