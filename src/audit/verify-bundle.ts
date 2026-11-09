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

/** Longest events.jsonl line (one chain event; an audit event's schema keeps it to a few KB): a longer one stops the read. */
export const MAX_EVENT_LINE_BYTES = 1024 * 1024;
/** Canonical-form problems kept per bundle (the first one fails the check; the rest are only counted out). */
const MAX_PROBLEMS = 20;
/** Largest manifest.json read (about 700,000 index entries); it is read before anything is trusted. */
export const MAX_MANIFEST_BYTES = 64 * 1024 * 1024;
/** Default read budget for one bundle: manifest, events and blobs together (raise with max_bytes / --max-bytes). */
export const DEFAULT_MAX_BUNDLE_BYTES = 1024 * 1024 * 1024;

const hardlinked = (name: string, n: number) =>
  `${name} has ${n} hard links: it may be a file outside the bundle (pass allow_hardlinks / --allow-hardlinks to accept)`;

/**
 * Read a bundle file only if it is a regular file (not a symlink, device, FIFO or
 * directory) of at most `max` bytes (`followLinks`: a link to a regular file is fine, as for
 * the operator's own --key). Opened O_NOFOLLOW | O_NONBLOCK and checked with fstat, so
 * a FIFO cannot block, a link to /dev/zero cannot exhaust memory, and a file swapped after a
 * check is still the file that was checked.
 */
export function readBundleFile(path: string, max: number, opts: { followLinks?: boolean; allowHardlinks?: boolean } = {}): Buffer {
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
    if (!follow && opts.allowHardlinks !== true && st.nlink > 1) throw new Error(hardlinked(name, st.nlink));
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
 * sha256 of a regular file, read in 1 MiB chunks (never whole into memory), opened O_NOFOLLOW |
 * O_NONBLOCK and checked with fstat: at most `max` bytes, exactly `size` when given, one link
 * unless `allowHardlinks`. Throws on anything else.
 */
function hashRegularFile(path: string, opts: { size?: number; max: number; allowHardlinks: boolean }): { sha256: string; size: number } {
  const name = basename(path);
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new Error('not a regular file');
    if (!opts.allowHardlinks && st.nlink > 1) throw new Error(hardlinked(name, st.nlink));
    if (opts.size !== undefined && st.size !== opts.size) throw new Error('size differs');
    if (st.size > opts.max) throw new Error(`${name} is ${st.size} bytes; the limit is ${opts.max}`);
    const h = createHash('sha256');
    const buf = Buffer.allocUnsafe(1024 * 1024);
    let total = 0;
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, null);
      if (n === 0) break;
      total += n;
      if (total > opts.max || (opts.size !== undefined && total > opts.size)) throw new Error(`${name} grew while being read`);
      h.update(buf.subarray(0, n));
    }
    if (opts.size !== undefined && total !== opts.size) throw new Error('size differs');
    return { sha256: h.digest('hex'), size: total };
  } finally {
    closeSync(fd);
  }
}

/**
 * One streaming pass over events.jsonl: sha256 of every byte, and each line parsed as it completes
 * and handed to `onLine` (nothing is retained here). Stops early, without reading the rest, when
 * the file passes `max` bytes (`budget`), a line passes MAX_EVENT_LINE_BYTES, there are more lines
 * than `maxLines` (the signed index), or a line is not a JSON object: then `sha256` is null. At most
 * MAX_PROBLEMS canonical-form problems are kept.
 */
function streamEvents(
  path: string,
  opts: { max: number; maxLines: number; allowHardlinks: boolean; onLine: (v: Record<string, unknown>) => void },
): { sha256: string | null; bytes: number; lines: number; problems: string[]; stopped: 'budget' | 'shape' | null; stoppedWhy: string | null } {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  const problems: string[] = [];
  let n = 0; // lines seen
  const out = (sha256: string | null, bytes: number, stopped: 'budget' | 'shape' | null, stoppedWhy: string | null) => ({ sha256, bytes, lines: n, problems, stopped, stoppedWhy });
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new Error('events.jsonl is not a regular file');
    if (!opts.allowHardlinks && st.nlink > 1) throw new Error(hardlinked('events.jsonl', st.nlink));
    if (st.size > opts.max) return out(null, 0, 'budget', null);
    const h = createHash('sha256');
    const buf = Buffer.allocUnsafe(1024 * 1024);
    let carry: Buffer[] = [];
    let carryLen = 0;
    let total = 0;
    const line = (bytes: Buffer): string | null => {
      n++;
      if (n > opts.maxLines) return `events.jsonl has more than the ${opts.maxLines} line(s) the manifest's index lists`;
      const l = bytes.toString('utf8');
      let v: unknown;
      try {
        v = parseBounded(l);
      } catch (err) {
        return `events.jsonl line ${n} is not usable JSON: ${(err as Error).message}`;
      }
      if (!isObj(v)) return `events.jsonl line ${n} is not an object`;
      if (l !== canonicalize(v as JsonValue) && problems.length < MAX_PROBLEMS) problems.push(`events.jsonl line ${n} is not canonical JSON`);
      opts.onLine(v);
      return null;
    };
    for (;;) {
      const got = readSync(fd, buf, 0, buf.length, null);
      if (got === 0) break;
      total += got;
      if (total > opts.max) return out(null, total, 'budget', null);
      const chunk = buf.subarray(0, got);
      h.update(chunk);
      let start = 0;
      for (let i = chunk.indexOf(10); i !== -1; i = chunk.indexOf(10, start)) {
        const piece = chunk.subarray(start, i);
        const whole = carryLen === 0 ? piece : Buffer.concat([...carry, piece]);
        carry = [];
        carryLen = 0;
        if (whole.byteLength > MAX_EVENT_LINE_BYTES) return out(null, total, 'shape', `events.jsonl line ${n + 1} is longer than ${MAX_EVENT_LINE_BYTES} bytes`);
        const stop = line(whole);
        if (stop) return out(null, total, 'shape', stop);
        start = i + 1;
      }
      if (start < chunk.length) {
        carry.push(Buffer.from(chunk.subarray(start)));
        carryLen += chunk.length - start;
        if (carryLen > MAX_EVENT_LINE_BYTES) return out(null, total, 'shape', `events.jsonl line ${n + 1} is longer than ${MAX_EVENT_LINE_BYTES} bytes`);
      }
    }
    if (carryLen > 0) {
      problems.push('events.jsonl does not end with a newline');
      const stop = line(Buffer.concat(carry));
      if (stop) return out(null, total, 'shape', stop);
    }
    return out(h.digest('hex'), total, null, null);
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
  const seenBlobs = new Set<string>();
  for (const e of b as { sha256: string }[]) {
    if (seenBlobs.has(e.sha256)) return `blobs lists ${e.sha256.slice(0, 12)}… more than once`;
    seenBlobs.add(e.sha256);
  }
  for (const k of ['redacted', 'missing'] as const) {
    const l = m[k];
    if (!isList(l) || !l.every((e) => isObj(e) && typeof e['sha256'] === 'string' && HEX64.test(e['sha256']))) return `${k} is not a list of {sha256 (64 hex), …}`;
  }
  // The range, its leaf count and the signed index must agree before anything is sized from them.
  const rr = r as Record<string, number>;
  if (rr['leaf_count'] !== rr['to_seq']! - rr['from_seq']! + 1) return 'range.leaf_count is not to_seq - from_seq + 1';
  if (rr['leaf_count'] !== ev.length + st.length) return `range.leaf_count (${rr['leaf_count']}) is not the number of events and stubs the manifest lists (${ev.length + st.length})`;
  const root = m['root'];
  if (!isObj(root) || typeof root['root'] !== 'string' || !int(root['leaf_count']) || typeof root['key_id'] !== 'string' || typeof root['public_key_pem'] !== 'string' || typeof root['signature'] !== 'string') return 'root is missing or malformed';
  if (root['leaf_count'] !== rr['leaf_count']) return 'root.leaf_count is not range.leaf_count';
  const sig = m['signature'];
  if (!isObj(sig) || typeof sig['key_id'] !== 'string' || typeof sig['signature'] !== 'string') return 'manifest signature is missing or malformed';
  return null;
}

export interface VerifyBundleOptions {
  /** The store's public key (PEM): without it the bundle is only checked under the key it names. */
  public_key_pem?: string;
  allow_missing?: boolean;
  /** Most bytes read from the bundle (manifest, events, blobs); default DEFAULT_MAX_BUNDLE_BYTES. */
  max_bytes?: number;
  /** Accept bundle files with more than one hard link (by default refused: they may be files outside DIR). */
  allow_hardlinks?: boolean;
}

export function verifyBundle(dir: string, opts: VerifyBundleOptions = {}): VerifyBundleResult {
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
  const allowHardlinks = opts.allow_hardlinks === true;
  const budget = opts.max_bytes !== undefined && Number.isFinite(opts.max_bytes) && opts.max_bytes > 0 ? Math.floor(opts.max_bytes) : DEFAULT_MAX_BUNDLE_BYTES;
  let left = budget;
  const overBudget = (what: string) => `${what} would take the read past the budget of ${budget} bytes (pass max_bytes / --max-bytes to raise it)`;
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
    // 1. canonical (manifest): manifest.json is RFC 8785 bytes + "\n". Nothing else is read until step 2 passes.
    let manifestText: string;
    try {
      manifestText = readBundleFile(join(dir, 'manifest.json'), Math.min(MAX_MANIFEST_BYTES, left), { allowHardlinks }).toString('utf8');
    } catch (err) {
      failAll(`cannot read bundle: ${(err as Error).message}`);
      return;
    }
    left -= Buffer.byteLength(manifestText);
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
    // An unsigned (or wrongly signed) manifest's digests, sizes and names are an attacker's: read nothing it lists.
    if (checks.get('signature') !== null) {
      for (const c of ['events', 'chain', 'root', 'artifacts', 'refs', 'missing'] as const) fail(c, 'not checked: the manifest signature does not verify, so nothing it lists is read');
      return;
    }

    // 1 (events) + 3, 4, 5: events.jsonl is read ONCE, as a stream: each 1 MiB chunk is hashed and split into
    // lines, and each line is checked as it completes (event hash, schema, index, chain link) and dropped. What is
    // kept per line is bounded by the signed index (a Merkle leaf; for an audit event its refs and evidence ids),
    // and the line count by the index too (validated against range.leaf_count above). The findings count only
    // when the whole file hashes to the signed events_sha256.
    const r = m.range;
    const found: [BundleCheck, string][] = [];
    const later = (c: BundleCheck, p: string) => {
      if (!found.some(([k]) => k === c)) found.push([c, p]);
    };
    const leaves: { seq: number; this_hash: string }[] = [];
    const full: { seq: number; event_id: string; refs: { field: string; ref: { sha256: string; redacted?: true } }[]; evidence: string[] }[] = [];
    let nFull = 0;
    let nStub = 0;
    let prev = r.first_prev_hash;
    let linked = true;
    const onLine = (l: Record<string, unknown>): void => {
      const i = leaves.length;
      leaves.push({ seq: Number(l['seq']), this_hash: String(l['this_hash']) });
      // 4. chain: contiguous seqs from_seq..to_seq, each prev_hash = previous this_hash (through stubs).
      if (linked) {
        if (l['seq'] !== r.from_seq + i) {
          later('chain', `line ${i + 1}: seq ${String(l['seq'])}, expected ${r.from_seq + i}`);
          linked = false;
        } else if (typeof l['this_hash'] !== 'string' || !HEX64.test(l['this_hash'])) {
          later('chain', `seq ${String(l['seq'])}: this_hash is not a sha256`);
          linked = false;
        } else if (l['prev_hash'] !== prev) {
          later('chain', `seq ${String(l['seq'])}: prev_hash does not link to seq ${r.from_seq + i - 1}`);
          linked = false;
        } else prev = l['this_hash'];
      }
      // 3. events: stubs and full lines match the signed index exactly, in order.
      if (l['stub'] === true) {
        const keys = Object.keys(l).sort().join(',');
        if (keys !== 'prev_hash,seq,stub,this_hash') later('events', `stub at seq ${String(l['seq'])} carries fields other than {seq, prev_hash, this_hash, stub}`);
        const want = m!.stubs[nStub++];
        if (!want || want.seq !== l['seq'] || want.this_hash !== l['this_hash']) later('events', 'stubs in events.jsonl differ from manifest.stubs');
        return;
      }
      const ev = l as unknown as ChainEvent;
      const want = m!.events[nFull++];
      if (!want || want.seq !== ev.seq || want.event_id !== ev.event_id || want.event_type !== ev.event_type || want.this_hash !== ev.this_hash) {
        later('events', 'full events in events.jsonl differ from manifest.events');
      }
      let h: string | null = null;
      try {
        h = recomputeEventHash(ev);
      } catch {
        // malformed line: reported below
      }
      if (h !== ev.this_hash) later('events', `seq ${String(ev.seq)}: this_hash does not recompute`);
      const kind = kindOfEventType(String(ev.event_type));
      if (!kind) return later('events', `seq ${String(ev.seq)}: ${String(ev.event_type)} is not an audit event type`);
      if (!isObj(ev.payload) || ev.payload['audit_id'] !== m!.audit_id) return later('events', `seq ${String(ev.seq)}: audit_id is not ${m!.audit_id}`);
      const p = parseAuditPayload(kind, ev.payload);
      if (!p.ok) later('events', `seq ${String(ev.seq)} (${kind}): ${p.problem}`);
      full.push({
        seq: ev.seq,
        event_id: String(ev.event_id),
        refs: blobRefsOf(ev.payload).map(({ field, ref }) => ({ field, ref: { sha256: ref.sha256, ...(ref.redacted === true ? { redacted: true as const } : {}) } })),
        evidence: [...evidenceOf(ev.payload)],
      });
    };
    let trusted = false;
    const evPath = join(dir, 'events.jsonl');
    try {
      if (lstatSync(evPath).isSymbolicLink()) throw new Error('events.jsonl is a symbolic link, not a regular file');
      const ev = streamEvents(evPath, { max: left, maxLines: m.events.length + m.stubs.length, allowHardlinks, onLine });
      left -= ev.bytes;
      for (const p of ev.problems) fail('canonical', p);
      if (ev.stopped !== null) fail('canonical', ev.stopped === 'budget' ? overBudget('events.jsonl') : ev.stoppedWhy!);
      else if (ev.sha256 !== m.events_sha256) fail('canonical', 'events.jsonl does not hash to manifest.events_sha256');
      else trusted = true;
    } catch (err) {
      fail('canonical', `cannot read events.jsonl: ${(err as Error).message}`);
    }
    if (!trusted) {
      for (const c of ['events', 'chain', 'root', 'refs'] as const) fail(c, 'not checked: events.jsonl is not the file the manifest signs');
      full.length = 0;
    } else {
      for (const [c, p] of found) fail(c, p);
      if (nFull !== m.events.length) fail('events', 'full events in events.jsonl differ from manifest.events');
      if (nStub !== m.stubs.length) fail('events', 'stubs in events.jsonl differ from manifest.stubs');
      if (leaves.length !== r.leaf_count) fail('chain', `range ${r.from_seq}..${r.to_seq} needs ${r.leaf_count} lines; events.jsonl has ${leaves.length}`);
      // 5. root: Merkle root over the segment's leaves, signed by the same key as the manifest.
      try {
        if (leaves.length === 0) throw new Error('empty segment');
        const root = merkleRootHex(leaves);
        if (root !== m.root.root) fail('root', 'Merkle root over events.jsonl differs from manifest.root.root');
        if (m.root.leaf_count !== leaves.length) fail('root', 'root.leaf_count differs from the segment');
        const msg = checkpointSigningPayload({ from_seq: r.from_seq, to_seq: r.to_seq, leaf_count: m.root.leaf_count, root: m.root.root });
        if (!verifyEd25519(pem, msg, m.root.signature)) fail('root', 'root signature does not verify');
      } catch (err) {
        fail('root', `cannot check root: ${(err as Error).message}`);
      }
    }

    // 6. artifacts: every listed blob is a regular file DIR/blobs/<64 hex>, hashing to its name and size; no unlisted entries.
    // Only reached with a verified manifest signature (step 2 returns otherwise). Each listed blob (no duplicates:
    // shape check) is stream-hashed once; together they must fit the read budget.
    const listed = new Set<string>(m.blobs.map((b) => b.sha256));
    const blobsDir = join(dir, 'blobs');
    let blobsSt: ReturnType<typeof lstatSync> | null = null;
    try {
      blobsSt = lstatSync(blobsDir);
    } catch {
      // no blobs/ directory: fine when nothing is listed (absences reported below)
    }
    if (blobsSt !== null && blobsSt.isSymbolicLink()) {
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
        if (b.size > left) {
          fail('artifacts', overBudget(`blob ${b.sha256.slice(0, 12)}… (${b.size} bytes)`));
          break;
        }
        left -= b.size;
        let digest: string;
        try {
          digest = hashRegularFile(p, { size: b.size, max: b.size, allowHardlinks }).sha256;
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
      for (const { field, ref } of ev.refs) {
        seen.add(ref.sha256);
        const where = [listed.has(ref.sha256), redacted.has(ref.sha256), missing.has(ref.sha256)].filter(Boolean).length;
        if (where !== 1) fail('refs', `seq ${ev.seq} ${field} ${ref.sha256.slice(0, 12)}…: ${where === 0 ? 'neither present nor declared redacted/missing' : 'listed more than once'}`);
        if (ref.redacted !== true && redacted.has(ref.sha256) && !listed.has(ref.sha256)) fail('refs', `seq ${ev.seq} ${field}: stored ref listed as redacted`);
      }
      for (const id of ev.evidence) if (!ids.has(id)) fail('refs', `seq ${ev.seq}: evidence ${id} is not in the bundle`);
    }
    for (const s of [...listed, ...redacted, ...missing]) if (!seen.has(s)) fail('refs', `${s.slice(0, 12)}… is listed but no event references it`);

    // 8. missing: artifacts the store no longer held at export fail the bundle unless the caller allows it (reported in the result).
    if (m.missing.length > 0 && !allow_missing) fail('missing', `${m.missing.length} referenced artifact(s) missing from the bundle (pass allow_missing / --allow-missing to accept, reported)`);
  }
}
