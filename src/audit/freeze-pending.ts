/**
 * A freeze made with the anchor pending, anchored later (A8): the audit profile's late-anchor mode.
 *
 * The audit profile shows "harness frozen before runs" with the freeze anchor: an anchor that commits
 * the freeze and no run, whose receipt and TSA tokens fix the freeze nonce every run carries. When
 * the anchor key is not available at the freeze, the recorder (mcp-audit `freeze --anchor-pending`)
 * instead freezes against a pending-freeze record (`isokron/freeze-pending@1`):
 *
 *   checkpoint.json        an auditor-signed checkpoint of the chain over seq 1..F (F = the freeze event)
 *   manifest.json          the bytes of the harness_frozen event's manifest blob
 *   plan-detail.json       the bytes of its plan_detail blob
 *   SHA256SUMS             sha256 of those three files
 *   SHA256SUMS.<tsa>.tsr   one RFC 3161 token over SHA256SUMS per TSA (two at least)
 *   freeze-pending.json    the record: harness fingerprint, checkpoint and SHA256SUMS hashes, the
 *                          tokens, and the nonce freezeNonce(sha256(SHA256SUMS), tokens)
 *
 * and anchors the chain later: one anchor that commits the freeze and every run so far. The tokens
 * fix the chain's root at the freeze; the nonce, which nobody could know before the tokens, is what
 * every run carries. Between the tokens and the late anchor, only the auditor's own key holds the
 * chain: that is the unwitnessed window, which verify-audit prints.
 *
 * Where the record is in a pack: `freeze-pending/` (written by `audit package --freeze-pending DIR`,
 * listed in SHA256SUMS), or, as mcp-audit's `close` writes it, inside the report_issued blob when that
 * blob is a ustar archive holding `attachments/freeze-pending.<file>` (on the chain, so covered by
 * the bundle's root).
 *
 * This module reads and checks the record's own consistency. verify-audit checks it against the pack
 * (tokens under the pinned TSA roots, the checkpoint against the bundle, the runs, the late anchor).
 */

import { existsSync, lstatSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

import { sha256Hex } from '../crypto/hash.js';
import { freezeNonce } from './profile.js';
import { readBundleFile } from './verify-bundle.js';

export const FREEZE_PENDING_FORMAT = 'isokron/freeze-pending@1';
/** The folder a pack carries the record in (audit package --freeze-pending). */
export const FREEZE_PENDING_DIR = 'freeze-pending';
export const FREEZE_PENDING_RECORD = 'freeze-pending.json';
/** The files SHA256SUMS lists, exactly. */
export const FREEZE_PENDING_FILES = ['checkpoint.json', 'manifest.json', 'plan-detail.json'] as const;
/** The prefix mcp-audit's report archive gives the record's files. */
export const REPORT_ARCHIVE_PREFIX = 'attachments/freeze-pending.';
const TOKEN = /^SHA256SUMS\.([a-z0-9][a-z0-9-]{0,31})\.tsr$/;
const NAMES = new RegExp(`^(?:${[FREEZE_PENDING_RECORD, 'SHA256SUMS', ...FREEZE_PENDING_FILES].map((f) => f.replace(/[.-]/g, '\\$&')).join('|')}|SHA256SUMS\\.[a-z0-9][a-z0-9-]{0,31}\\.tsr)$`);
const MAX_FILE = 16 * 1024 * 1024;

export interface FreezePendingCheckpoint {
  checkpoint_id?: string;
  from_seq: number;
  to_seq: number;
  leaf_count: number;
  root: string;
  key_id?: string;
  signature: string;
  created_at?: string;
}

export interface FreezePendingRecord {
  format: typeof FREEZE_PENDING_FORMAT;
  audit_id: string;
  fingerprint: string;
  commit?: string;
  chain_head_seq: number;
  checkpoint_sha256: string;
  sha256sums_sha256: string;
  tokens: { tsa: string; gen_time: string | null; file: string | null; sha256: string | null }[];
  nonce: string;
}

export interface FreezePending {
  source: 'pack_dir' | 'report_archive';
  record: FreezePendingRecord;
  checkpoint: FreezePendingCheckpoint;
  /** The record's files by name. */
  files: Map<string, Buffer>;
  sums: Buffer;
  tokens: { tsa: string; file: string; bytes: Buffer }[];
  /** freezeNonce(sha256(SHA256SUMS), tokens), re-derived. */
  nonce: string;
}

/** Is this a name the record may hold? */
export const isFreezePendingFile = (name: string): boolean => NAMES.test(name);

/**
 * Check the record's own consistency: SHA256SUMS lists exactly the three files with their hashes,
 * the record names these bytes and these tokens, and the nonce re-derives. A string is the problem.
 */
export function parseFreezePending(files: Map<string, Buffer>, source: FreezePending['source']): FreezePending | string {
  const rec = files.get(FREEZE_PENDING_RECORD);
  if (!rec) return `${FREEZE_PENDING_RECORD} is missing`;
  let record: FreezePendingRecord;
  try {
    record = JSON.parse(rec.toString('utf8')) as FreezePendingRecord;
  } catch (err) {
    return `${FREEZE_PENDING_RECORD} is not JSON: ${(err as Error).message}`;
  }
  if (record === null || typeof record !== 'object' || record.format !== FREEZE_PENDING_FORMAT) return `${FREEZE_PENDING_RECORD} is not ${FREEZE_PENDING_FORMAT}`;
  if (typeof record.fingerprint !== 'string' || typeof record.nonce !== 'string' || !Number.isInteger(record.chain_head_seq)) return `${FREEZE_PENDING_RECORD} lacks fingerprint, nonce or chain_head_seq`;
  const sums = files.get('SHA256SUMS');
  if (!sums) return 'SHA256SUMS is missing';
  const listed = new Map<string, string>();
  for (const line of sums.toString('utf8').split('\n')) {
    if (!line) continue;
    const m = /^([0-9a-f]{64}) {2}(\S+)$/.exec(line);
    if (!m) return `SHA256SUMS line ${JSON.stringify(line.slice(0, 80))} is not "<sha256>  <file>"`;
    listed.set(m[2]!, m[1]!);
  }
  if ([...listed.keys()].sort().join(',') !== [...FREEZE_PENDING_FILES].sort().join(',')) return `SHA256SUMS lists ${[...listed.keys()].join(', ') || 'nothing'}, not ${FREEZE_PENDING_FILES.join(', ')}`;
  for (const f of FREEZE_PENDING_FILES) {
    const b = files.get(f);
    if (!b) return `${f} is missing`;
    if (sha256Hex(b) !== listed.get(f)) return `${f} does not hash to its SHA256SUMS entry (changed after the stamps)`;
  }
  if (record.sha256sums_sha256 !== sha256Hex(sums)) return 'SHA256SUMS is not the one the record names';
  const cpBytes = files.get('checkpoint.json')!;
  if (record.checkpoint_sha256 !== sha256Hex(cpBytes)) return 'checkpoint.json is not the one the record names';
  const tokens = [...files.entries()]
    .map(([file, bytes]) => ({ file, bytes, m: TOKEN.exec(file) }))
    .filter((x): x is { file: string; bytes: Buffer; m: RegExpExecArray } => x.m !== null)
    .sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0))
    .map((x) => ({ tsa: x.m[1]!, file: x.file, bytes: x.bytes }));
  const named = Array.isArray(record.tokens) ? record.tokens : [];
  for (const t of named) {
    if (!t || !t.file || !t.sha256) continue;
    const have = tokens.find((x) => x.file === t.file);
    if (!have) return `the token ${t.file} the record names is missing`;
    if (sha256Hex(have.bytes) !== t.sha256) return `the token ${t.file} is not the one the record names`;
  }
  // why: a token added later would change the nonce; every token must be in the record.
  if (tokens.some((t) => !named.some((r) => r && r.file === t.file))) return 'a token is not in the record (a token added later changes the nonce)';
  if (tokens.length < 2) return `${tokens.length} TSA token(s) over SHA256SUMS; two are required`;
  const nonce = freezeNonce(sha256Hex(sums), tokens.map((t) => ({ tsa: t.tsa, bytes: t.bytes })));
  if (nonce !== record.nonce) return `the nonce re-derived from SHA256SUMS and the tokens (${nonce}) is not the recorded one (${record.nonce}): stamps changed`;
  let checkpoint: FreezePendingCheckpoint;
  try {
    checkpoint = JSON.parse(cpBytes.toString('utf8')) as FreezePendingCheckpoint;
  } catch (err) {
    return `checkpoint.json is not JSON: ${(err as Error).message}`;
  }
  if (checkpoint.from_seq !== 1 || checkpoint.to_seq !== record.chain_head_seq || !Number.isInteger(checkpoint.leaf_count) || typeof checkpoint.root !== 'string' || typeof checkpoint.signature !== 'string') {
    return `the checkpoint covers seq ${String(checkpoint.from_seq)}..${String(checkpoint.to_seq)}, not 1..${record.chain_head_seq} (or lacks leaf_count, root, signature)`;
  }
  return { source, record, checkpoint, files, sums, tokens, nonce };
}

/** The record's files in `<pack>/freeze-pending/`, or null when the folder is absent. */
export function readFreezePendingDir(packDir: string, allowHardlinks = false): Map<string, Buffer> | string | null {
  const d = join(packDir, FREEZE_PENDING_DIR);
  const st = lstatSync(d, { throwIfNoEntry: false });
  if (!st) return null;
  if (st.isSymbolicLink() || !st.isDirectory()) return `${FREEZE_PENDING_DIR}/ is not a directory`;
  const files = new Map<string, Buffer>();
  for (const f of readdirSync(d).sort()) {
    if (!isFreezePendingFile(f)) return `${FREEZE_PENDING_DIR}/${f} is not a file of a pending-freeze record`;
    try {
      files.set(f, readBundleFile(join(d, f), MAX_FILE, { allowHardlinks }));
    } catch (err) {
      return `${FREEZE_PENDING_DIR}/${f}: ${(err as Error).message}`;
    }
  }
  return files;
}

/** Read a POSIX ustar archive (regular files only); null when `buf` is not one. */
export function readUstar(buf: Buffer): { name: string; data: Buffer }[] | null {
  if (buf.length < 512 || buf.subarray(257, 262).toString('ascii') !== 'ustar') return null;
  const out: { name: string; data: Buffer }[] = [];
  for (let off = 0; off + 512 <= buf.length; ) {
    const h = buf.subarray(off, off + 512);
    if (h.every((b) => b === 0)) break;
    if (h.subarray(257, 262).toString('ascii') !== 'ustar') return null;
    const name = h.subarray(0, 100).toString('utf8').replace(/\0.*$/s, '');
    const prefix = h.subarray(345, 500).toString('utf8').replace(/\0.*$/s, '');
    const size = parseInt(h.subarray(124, 136).toString('ascii').replace(/\0.*$/s, '').trim() || '0', 8);
    if (!Number.isFinite(size) || size < 0 || off + 512 + size > buf.length) return null;
    const type = String.fromCharCode(h[156]!);
    off += 512;
    if (type === '0' || type === '\0') out.push({ name: prefix ? `${prefix}/${name}` : name, data: Buffer.from(buf.subarray(off, off + size)) });
    off += Math.ceil(size / 512) * 512;
  }
  return out;
}

/** The record's files inside a report archive blob (mcp-audit's `attachments/freeze-pending.<file>`), or null. */
export function freezePendingFromArchive(blob: Buffer): Map<string, Buffer> | null {
  const entries = readUstar(blob);
  if (!entries) return null;
  const files = new Map<string, Buffer>();
  for (const e of entries) {
    if (!e.name.startsWith(REPORT_ARCHIVE_PREFIX)) continue;
    const f = e.name.slice(REPORT_ARCHIVE_PREFIX.length);
    if (isFreezePendingFile(f)) files.set(f, e.data);
  }
  return files.has(FREEZE_PENDING_RECORD) ? files : null;
}

/**
 * Find a pending-freeze record in a pack: `freeze-pending/` first, else the report_issued blob(s).
 * null: none (a normal freeze). A string: one is there but cannot be read.
 */
export function findFreezePending(packDir: string, reportBlobs: string[], allowHardlinks = false): FreezePending | { problem: string; source: FreezePending['source'] } | null {
  const fromDir = readFreezePendingDir(packDir, allowHardlinks);
  if (typeof fromDir === 'string') return { problem: fromDir, source: 'pack_dir' };
  if (fromDir) {
    const p = parseFreezePending(fromDir, 'pack_dir');
    return typeof p === 'string' ? { problem: p, source: 'pack_dir' } : p;
  }
  for (const sha of reportBlobs) {
    if (!/^[0-9a-f]{64}$/.test(sha)) continue;
    const path = join(packDir, 'bundle', 'blobs', sha);
    if (!existsSync(path)) continue;
    let bytes: Buffer;
    try {
      bytes = readBundleFile(path, 64 * 1024 * 1024, { allowHardlinks });
    } catch {
      continue;
    }
    if (sha256Hex(bytes) !== sha) continue; // integrity reports it
    const files = freezePendingFromArchive(bytes);
    if (!files) continue;
    const p = parseFreezePending(files, 'report_archive');
    return typeof p === 'string' ? { problem: p, source: 'report_archive' } : p;
  }
  return null;
}
