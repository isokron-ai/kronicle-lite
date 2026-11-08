/**
 * Offline evidence-bundle verification (0.9.0). Needs only the bundle
 * directory: no store, no network. Each check is one step of the procedure
 * in docs/EVIDENCE-BUNDLE.md; the first failure of each step is reported.
 * Hostile input (any shape, any depth, any file name) yields ok:false with a
 * reason, never a throw, and never reads outside DIR/blobs/.
 *
 * What a pass proves: the manifest is signed by the key it names (pin it
 * with `--key`), so its index, blob lists and digests are the signer's; the
 * files are canonical and match it; the audit's events hash correctly and,
 * with the stubs, form one contiguous segment of a single hash chain whose
 * signed Merkle root matches; every artifact present hashes to its name;
 * every reference resolves, and nothing is missing (unless `allow_missing`,
 * which the result reports). It does NOT prove the audit's conclusions are
 * correct, and an anchor of the root proves only that the root existed at a
 * time.
 */

import { constants as bufferConstants } from 'node:buffer';
import { createHash, createPublicKey } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, readFileSync, readSync, realpathSync } from 'node:fs';
import { basename, join } from 'node:path';

import { checkpointSigningPayload } from '../chain/chain.js';
import { recomputeEventHash, type ChainEvent } from '../chain/event.js';
import { merkleRootHex } from '../chain/merkle.js';
import { canonicalize, type JsonValue } from '../crypto/canonical.js';
import { sha256Hex } from '../crypto/hash.js';
import { keyIdFromPublicKey, verifyEd25519 } from '../crypto/keys.js';
import { manifestSigningPayload, type BundleManifest } from './bundle.js';
import { blobRefsOf, BUNDLE_FORMAT, evidenceOf, kindOfEventType, parseAuditPayload } from './schemas.js';

export const BUNDLE_CHECKS = ['canonical', 'signature', 'events', 'chain', 'root', 'artifacts', 'refs', 'missing'] as const;
export type BundleCheck = (typeof BUNDLE_CHECKS)[number];

export interface VerifyBundleResult {
  ok: boolean;
  audit_id: string | null;
  manifest_sha256: string | null;
  root: string | null;
  /** true when the caller allowed missing artifacts (they are still counted and listed). */
  allow_missing: boolean;
  checks: { check: BundleCheck; ok: boolean; problem: string | null }[];
  counts: { events: number; stubs: number; blobs: number; redacted: number; missing: number };
}

const HEX64 = /^[0-9a-f]{64}$/;
/** Deepest JSON nesting a bundle file may have (the real format needs 8). */
const MAX_DEPTH = 64;

/** JSON.parse with a nesting bound checked first (V8's parser recurses; so does canonicalize). */
function parseBounded(text: string): unknown {
  let depth = 0;
  let inStr = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (inStr) {
      if (c === 92) i++;
      else if (c === 34) inStr = false;
    } else if (c === 34) inStr = true;
    else if (c === 123 || c === 91) {
      if (++depth > MAX_DEPTH) throw new Error(`nested deeper than ${MAX_DEPTH}`);
    } else if (c === 125 || c === 93) depth--;
  }
  return JSON.parse(text);
}

/** Largest manifest.json / events.jsonl read: the longest string V8 can hold (a larger file cannot be checked anyway). */
export const MAX_BUNDLE_FILE_BYTES = bufferConstants.MAX_STRING_LENGTH;

/**
 * Read a bundle file only if it is a regular file (not a symlink, device, FIFO or
 * directory) of at most `max` bytes (`followLinks`: a link to a regular file is fine, as for
 * the operator's own --key). Opened O_NOFOLLOW | O_NONBLOCK and checked with fstat, so
 * a FIFO cannot block, a link to /dev/zero cannot exhaust memory, and a file swapped after a
 * check is still the file that was checked.
 */
export function readBundleFile(path: string, max: number, opts: { followLinks?: boolean } = {}): Buffer {
  const name = basename(path);
  const follow = opts.followLinks === true;
  if (!follow && lstatSync(path).isSymbolicLink()) throw new Error(`${name} is a symbolic link, not a regular file`);
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | (follow ? 0 : (constants.O_NOFOLLOW ?? 0)) | (constants.O_NONBLOCK ?? 0));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ELOOP') throw new Error(`${name} is a symbolic link, not a regular file`);
    throw err;
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new Error(`${name} is not a regular file`);
    if (st.size > max) throw new Error(`${name} is ${st.size} bytes; the limit is ${max}`);
    const bytes = readFileSync(fd);
    if (bytes.byteLength > max) throw new Error(`${name} grew past the limit of ${max} bytes while being read`);
    return bytes;
  } finally {
    closeSync(fd);
  }
}

/** Largest blob a store accepts (src/audit/log.ts MAX_BLOB_BYTES); a manifest listing a bigger one is refused unread. */
export const MAX_BUNDLE_BLOB_BYTES = 64 * 1024 * 1024;

/**
 * sha256 of a regular file of exactly `size` bytes, read in 1 MiB chunks (never whole into memory),
 * opened O_NOFOLLOW | O_NONBLOCK and checked with fstat. Throws on anything else.
 */
function hashRegularFile(path: string, size: number): string {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new Error('not a regular file');
    if (st.size !== size) throw new Error('size differs');
    const h = createHash('sha256');
    const buf = Buffer.allocUnsafe(1024 * 1024);
    let total = 0;
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, null);
      if (n === 0) break;
      total += n;
      if (total > size) throw new Error('size differs');
      h.update(buf.subarray(0, n));
    }
    if (total !== size) throw new Error('size differs');
    return h.digest('hex');
  } finally {
    closeSync(fd);
  }
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const isList = (v: unknown): v is unknown[] => Array.isArray(v);
const int = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v);

/** The manifest's shape, or the first problem. Everything below relies on it. */
function shapeProblem(m: Record<string, unknown>): string | null {
  if (m['format'] !== BUNDLE_FORMAT) return `unknown format ${JSON.stringify(m['format'])} (expected ${BUNDLE_FORMAT})`;
  if (typeof m['audit_id'] !== 'string') return 'audit_id is not a string';
  const r = m['range'];
  if (!isObj(r) || !int(r['from_seq']) || !int(r['to_seq']) || !int(r['leaf_count']) || typeof r['first_prev_hash'] !== 'string' || r['from_seq'] < 1 || r['to_seq'] < r['from_seq']) {
    return 'range is missing or malformed';
  }
  if (typeof m['events_sha256'] !== 'string') return 'events_sha256 is not a string';
  const ev = m['events'];
  if (!isList(ev) || !ev.every((e) => isObj(e) && int(e['seq']) && typeof e['event_id'] === 'string' && typeof e['event_type'] === 'string' && typeof e['this_hash'] === 'string')) return 'events is not a list of {seq, event_id, event_type, this_hash}';
  const st = m['stubs'];
  if (!isList(st) || !st.every((e) => isObj(e) && int(e['seq']) && typeof e['this_hash'] === 'string')) return 'stubs is not a list of {seq, this_hash}';
  const b = m['blobs'];
  if (!isList(b) || !b.every((e) => isObj(e) && typeof e['sha256'] === 'string' && HEX64.test(e['sha256']) && int(e['size']) && e['size'] >= 0)) return 'blobs is not a list of {sha256 (64 hex), size}';
  for (const k of ['redacted', 'missing'] as const) {
    const l = m[k];
    if (!isList(l) || !l.every((e) => isObj(e) && typeof e['sha256'] === 'string' && HEX64.test(e['sha256']))) return `${k} is not a list of {sha256 (64 hex), …}`;
  }
  const root = m['root'];
  if (!isObj(root) || typeof root['root'] !== 'string' || !int(root['leaf_count']) || typeof root['key_id'] !== 'string' || typeof root['public_key_pem'] !== 'string' || typeof root['signature'] !== 'string') return 'root is missing or malformed';
  const sig = m['signature'];
  if (!isObj(sig) || typeof sig['key_id'] !== 'string' || typeof sig['signature'] !== 'string') return 'manifest signature is missing or malformed';
  return null;
}

export function verifyBundle(dir: string, opts: { public_key_pem?: string; allow_missing?: boolean } = {}): VerifyBundleResult {
  const checks = new Map<BundleCheck, string | null>(BUNDLE_CHECKS.map((c) => [c, null]));
  const fail = (c: BundleCheck, p: string) => {
    if (checks.get(c) === null) checks.set(c, p);
  };
  const failAll = (p: string) => {
    for (const c of BUNDLE_CHECKS) fail(c, p);
  };
  let m: BundleManifest | null = null;
  let msha: string | null = null;
  const allow_missing = opts.allow_missing === true;
  const out = (): VerifyBundleResult => ({
    ok: [...checks.values()].every((v) => v === null),
    audit_id: m?.audit_id ?? null,
    manifest_sha256: msha,
    root: m?.root?.root ?? null,
    allow_missing,
    checks: BUNDLE_CHECKS.map((c) => ({ check: c, ok: checks.get(c) === null, problem: checks.get(c) ?? null })),
    counts: { events: m?.events.length ?? 0, stubs: m?.stubs.length ?? 0, blobs: m?.blobs.length ?? 0, redacted: m?.redacted.length ?? 0, missing: m?.missing.length ?? 0 },
  });
  try {
    verifyInto();
  } catch (err) {
    // why: belt and braces; every step guards its input, but a bundle must never crash the verifier.
    failAll(`verifier error: ${err instanceof Error ? err.message : String(err)}`);
  }
  return out();

  function verifyInto(): void {
    // The path given is resolved once (a symlinked DIR, such as macOS /tmp, is fine); every
    // component below it (manifest.json, events.jsonl, blobs/, blobs/<sha>) must not be a link.
    try {
      dir = realpathSync(dir);
    } catch (err) {
      failAll(`cannot read bundle: ${(err as Error).message}`);
      return;
    }
    // 1. canonical: manifest.json and every events.jsonl line are RFC 8785 bytes (+ "\n").
    let manifestText: string;
    let eventsText: string;
    try {
      manifestText = readBundleFile(join(dir, 'manifest.json'), MAX_BUNDLE_FILE_BYTES).toString('utf8');
      eventsText = readBundleFile(join(dir, 'events.jsonl'), MAX_BUNDLE_FILE_BYTES).toString('utf8');
    } catch (err) {
      failAll(`cannot read bundle: ${(err as Error).message}`);
      return;
    }
    msha = sha256Hex(manifestText);
    let raw: unknown;
    try {
      raw = parseBounded(manifestText);
    } catch (err) {
      failAll(`manifest.json is not usable JSON: ${(err as Error).message}`);
      return;
    }
    if (!isObj(raw)) return failAll('manifest.json is not an object');
    const shape = shapeProblem(raw);
    if (shape) return failAll(`manifest: ${shape}`);
    m = raw as unknown as BundleManifest;
    if (manifestText !== canonicalize(raw as JsonValue) + '\n') fail('canonical', 'manifest.json is not canonical JSON');
    const rawLines = eventsText.split('\n');
    if (rawLines.pop() !== '') fail('canonical', 'events.jsonl does not end with a newline');
    const lines: Record<string, unknown>[] = [];
    for (const [i, l] of rawLines.entries()) {
      let v: unknown;
      try {
        v = parseBounded(l);
      } catch (err) {
        fail('canonical', `events.jsonl line ${i + 1} is not usable JSON: ${(err as Error).message}`);
        fail('chain', `events.jsonl line ${i + 1} is unreadable`);
        continue;
      }
      if (!isObj(v)) {
        fail('canonical', `events.jsonl line ${i + 1} is not an object`);
        fail('chain', `events.jsonl line ${i + 1} is unreadable`);
        continue;
      }
      if (l !== canonicalize(v as JsonValue)) fail('canonical', `events.jsonl line ${i + 1} is not canonical JSON`);
      lines.push(v);
    }
    if (sha256Hex(eventsText) !== m.events_sha256) fail('canonical', 'events.jsonl does not hash to manifest.events_sha256');

    // 2. signature: the store key signed the whole manifest (index, lists, digests, root), and is the pinned key if one is given.
    const pem = opts.public_key_pem ?? m.root.public_key_pem;
    try {
      const keyId = keyIdFromPublicKey(createPublicKey(pem));
      if (opts.public_key_pem !== undefined && (m.signature!.key_id !== keyId || m.root.key_id !== keyId)) fail('signature', `manifest is signed by ${m.signature!.key_id}, not the pinned key ${keyId}`);
      else if (m.signature!.key_id !== keyId || m.root.key_id !== keyId) fail('signature', 'manifest key ids do not match its public key');
      if (!verifyEd25519(pem, manifestSigningPayload(m), m.signature!.signature)) fail('signature', 'manifest signature does not verify');
    } catch (err) {
      fail('signature', `cannot check the manifest signature: ${(err as Error).message}`);
    }

    // 3. events: each full line re-hashes, belongs to the audit, validates; full lines and stubs match the signed index exactly.
    const full: ChainEvent[] = [];
    const stubIndex: { seq: number; this_hash: string }[] = [];
    for (const l of lines) {
      if (l['stub'] === true) {
        const keys = Object.keys(l).sort().join(',');
        if (keys !== 'prev_hash,seq,stub,this_hash') fail('events', `stub at seq ${String(l['seq'])} carries fields other than {seq, prev_hash, this_hash, stub}`);
        stubIndex.push({ seq: Number(l['seq']), this_hash: String(l['this_hash']) });
        continue;
      }
      const ev = l as unknown as ChainEvent;
      full.push(ev);
      let h: string | null = null;
      try {
        h = recomputeEventHash(ev);
      } catch {
        // malformed line: reported below
      }
      if (h !== ev.this_hash) fail('events', `seq ${String(ev.seq)}: this_hash does not recompute`);
      const kind = kindOfEventType(String(ev.event_type));
      if (!kind) {
        fail('events', `seq ${String(ev.seq)}: ${String(ev.event_type)} is not an audit event type`);
        continue;
      }
      if (!isObj(ev.payload) || ev.payload['audit_id'] !== m.audit_id) {
        fail('events', `seq ${String(ev.seq)}: audit_id is not ${m.audit_id}`);
        continue;
      }
      const p = parseAuditPayload(kind, ev.payload);
      if (!p.ok) fail('events', `seq ${String(ev.seq)} (${kind}): ${p.problem}`);
    }
    const index = full.map((e) => ({ seq: e.seq, event_id: e.event_id, event_type: e.event_type, this_hash: e.this_hash }));
    if (canonicalize(index as unknown as JsonValue) !== canonicalize(m.events as unknown as JsonValue)) fail('events', 'full events in events.jsonl differ from manifest.events');
    if (canonicalize(stubIndex as unknown as JsonValue) !== canonicalize(m.stubs as unknown as JsonValue)) fail('events', 'stubs in events.jsonl differ from manifest.stubs');

    // 4. chain: contiguous seqs from_seq..to_seq, each prev_hash = previous this_hash (through stubs), first = range.first_prev_hash.
    const r = m.range;
    if (lines.length !== r.to_seq - r.from_seq + 1 || lines.length !== r.leaf_count) fail('chain', `range ${r.from_seq}..${r.to_seq} needs ${r.to_seq - r.from_seq + 1} lines; events.jsonl has ${lines.length}`);
    let prev = r.first_prev_hash;
    for (const [i, l] of lines.entries()) {
      if (l['seq'] !== r.from_seq + i) {
        fail('chain', `line ${i + 1}: seq ${String(l['seq'])}, expected ${r.from_seq + i}`);
        break;
      }
      if (typeof l['this_hash'] !== 'string' || !HEX64.test(l['this_hash'])) {
        fail('chain', `seq ${String(l['seq'])}: this_hash is not a sha256`);
        break;
      }
      if (l['prev_hash'] !== prev) {
        fail('chain', `seq ${String(l['seq'])}: prev_hash does not link to seq ${r.from_seq + i - 1}`);
        break;
      }
      prev = l['this_hash'];
    }

    // 5. root: Merkle root over the segment's leaves, signed by the same key as the manifest.
    try {
      if (lines.length === 0) throw new Error('empty segment');
      const root = merkleRootHex(lines.map((l) => ({ seq: Number(l['seq']), this_hash: String(l['this_hash']) })));
      if (root !== m.root.root) fail('root', 'Merkle root over events.jsonl differs from manifest.root.root');
      if (m.root.leaf_count !== lines.length) fail('root', 'root.leaf_count differs from the segment');
      const msg = checkpointSigningPayload({ from_seq: r.from_seq, to_seq: r.to_seq, leaf_count: m.root.leaf_count, root: m.root.root });
      if (!verifyEd25519(pem, msg, m.root.signature)) fail('root', 'root signature does not verify');
    } catch (err) {
      fail('root', `cannot check root: ${(err as Error).message}`);
    }

    // 6. artifacts: every listed blob is a regular file DIR/blobs/<64 hex>, hashing to its name and size; no unlisted entries.
    // Nothing is read until the manifest is trusted: when its signature does not verify (or not under the pinned key),
    // the sizes and names it lists are an attacker's (a 16 KB bundle could list gigabytes of sparse blobs): not run.
    const listed = new Set<string>(m.blobs.map((b) => b.sha256));
    const blobsDir = join(dir, 'blobs');
    const untrusted = checks.get('signature') !== null;
    let blobsSt: ReturnType<typeof lstatSync> | null = null;
    try {
      blobsSt = lstatSync(blobsDir);
    } catch {
      // no blobs/ directory: fine when nothing is listed (absences reported below)
    }
    if (untrusted) {
      if (m.blobs.length > 0) fail('artifacts', 'not checked: the manifest signature does not verify, so no blob is read');
    } else if (blobsSt !== null && blobsSt.isSymbolicLink()) {
      fail('artifacts', 'blobs/ is a symbolic link; a bundle directory must not link out');
    } else if (blobsSt !== null && !blobsSt.isDirectory()) {
      fail('artifacts', 'blobs/ is not a directory');
    } else {
      for (const b of m.blobs) {
        const p = join(blobsDir, b.sha256); // shape check: 64 hex, so the join stays inside DIR/blobs
        let st: ReturnType<typeof lstatSync> | null = null;
        try {
          st = lstatSync(p);
        } catch {
          fail('artifacts', `blob ${b.sha256.slice(0, 12)}… listed but absent`);
          continue;
        }
        if (!st.isFile()) {
          fail('artifacts', `blob ${b.sha256.slice(0, 12)}… is not a regular file`);
          continue;
        }
        if (b.size > MAX_BUNDLE_BLOB_BYTES) {
          fail('artifacts', `blob ${b.sha256.slice(0, 12)}… is listed at ${b.size} bytes; the limit is ${MAX_BUNDLE_BLOB_BYTES}`);
          continue;
        }
        if (st.size !== b.size) {
          fail('artifacts', `blob ${b.sha256.slice(0, 12)}… size differs`);
          continue;
        }
        let digest: string;
        try {
          digest = hashRegularFile(p, b.size);
        } catch (err) {
          fail('artifacts', `blob ${b.sha256.slice(0, 12)}… cannot be read: ${(err as Error).message}`);
          continue;
        }
        if (digest !== b.sha256) fail('artifacts', `blob ${b.sha256.slice(0, 12)}… does not hash to its name`);
      }
      // blobs/ swapped while it was read: the files hashed above may not be the bundle's.
      if (blobsSt !== null) {
        const now = lstatSync(blobsDir, { throwIfNoEntry: false });
        if (!now || now.isSymbolicLink() || now.dev !== blobsSt.dev || now.ino !== blobsSt.ino) fail('artifacts', 'blobs/ changed during verification');
      }
      let entries: string[] = [];
      try {
        entries = blobsSt !== null ? readdirSync(blobsDir) : [];
      } catch {
        // unreadable: absences are reported above
      }
      for (const f of entries) if (!listed.has(f)) fail('artifacts', `unlisted entry blobs/${f}`);
    }

    // 7. refs: every blob ref is present, or declared redacted / missing (exactly one); every evidence id is an event of the bundle.
    const redacted = new Set(m.redacted.map((x) => x.sha256));
    const missing = new Set(m.missing.map((x) => x.sha256));
    const ids = new Set(full.map((e) => e.event_id));
    const seen = new Set<string>();
    for (const ev of full) {
      const payload = isObj(ev.payload) ? ev.payload : {};
      for (const { field, ref } of blobRefsOf(payload)) {
        seen.add(ref.sha256);
        const where = [listed.has(ref.sha256), redacted.has(ref.sha256), missing.has(ref.sha256)].filter(Boolean).length;
        if (where !== 1) fail('refs', `seq ${ev.seq} ${field} ${ref.sha256.slice(0, 12)}…: ${where === 0 ? 'neither present nor declared redacted/missing' : 'listed more than once'}`);
        if (ref.redacted !== true && redacted.has(ref.sha256) && !listed.has(ref.sha256)) fail('refs', `seq ${ev.seq} ${field}: stored ref listed as redacted`);
      }
      for (const id of evidenceOf(payload)) if (!ids.has(id)) fail('refs', `seq ${ev.seq}: evidence ${id} is not in the bundle`);
    }
    for (const s of [...listed, ...redacted, ...missing]) if (!seen.has(s)) fail('refs', `${s.slice(0, 12)}… is listed but no event references it`);

    // 8. missing: artifacts the store no longer held at export fail the bundle unless the caller allows it (reported in the result).
    if (m.missing.length > 0 && !allow_missing) fail('missing', `${m.missing.length} referenced artifact(s) missing from the bundle (pass allow_missing / --allow-missing to accept, reported)`);
  }
}
