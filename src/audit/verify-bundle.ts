/**
 * Offline evidence-bundle verification (0.9.0). Needs only the bundle
 * directory: no store, no network. Each check is one step of the procedure
 * in docs/EVIDENCE-BUNDLE.md; the first failure of each step is reported.
 *
 * What a pass proves: the files are canonical and unmodified relative to
 * the manifest; the audit's events hash correctly and form one contiguous
 * segment of a single hash chain (stubs included); the Merkle root over that
 * segment is signed by the key in the manifest (pin it with `--key`); every
 * artifact present hashes to its name; every reference resolves or is
 * declared redacted / missing. It does NOT prove the audit's conclusions are
 * correct, and an anchor of the root proves only that the root existed at a
 * time.
 */

import { createHash, createPublicKey } from 'node:crypto';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { checkpointSigningPayload } from '../chain/chain.js';
import { recomputeEventHash, type ChainEvent } from '../chain/event.js';
import { merkleRootHex } from '../chain/merkle.js';
import { canonicalize, type JsonValue } from '../crypto/canonical.js';
import { sha256Hex } from '../crypto/hash.js';
import { keyIdFromPublicKey, verifyEd25519 } from '../crypto/keys.js';
import type { BundleManifest } from './bundle.js';
import { blobRefsOf, BUNDLE_FORMAT, evidenceOf, kindOfEventType, parseAuditPayload } from './schemas.js';

export const BUNDLE_CHECKS = ['canonical', 'events', 'chain', 'root', 'artifacts', 'refs'] as const;
export type BundleCheck = (typeof BUNDLE_CHECKS)[number];

export interface VerifyBundleResult {
  ok: boolean;
  audit_id: string | null;
  manifest_sha256: string | null;
  root: string | null;
  checks: { check: BundleCheck; ok: boolean; problem: string | null }[];
  counts: { events: number; stubs: number; blobs: number; redacted: number; missing: number };
}

export function verifyBundle(dir: string, opts: { public_key_pem?: string } = {}): VerifyBundleResult {
  const checks = new Map<BundleCheck, string | null>(BUNDLE_CHECKS.map((c) => [c, null]));
  const fail = (c: BundleCheck, p: string) => {
    if (checks.get(c) === null) checks.set(c, p);
  };
  const out = (m: BundleManifest | null, msha: string | null): VerifyBundleResult => ({
    ok: [...checks.values()].every((v) => v === null),
    audit_id: m?.audit_id ?? null,
    manifest_sha256: msha,
    root: m?.root?.root ?? null,
    checks: BUNDLE_CHECKS.map((c) => ({ check: c, ok: checks.get(c) === null, problem: checks.get(c) ?? null })),
    counts: { events: m?.events?.length ?? 0, stubs: m?.stubs?.length ?? 0, blobs: m?.blobs?.length ?? 0, redacted: m?.redacted?.length ?? 0, missing: m?.missing?.length ?? 0 },
  });
  const failAll = (p: string) => {
    for (const c of BUNDLE_CHECKS) fail(c, p);
  };

  // 1. canonical: manifest.json and every events.jsonl line are RFC 8785 bytes (+ "\n").
  let manifestText: string;
  let eventsText: string;
  try {
    manifestText = readFileSync(join(dir, 'manifest.json'), 'utf8');
    eventsText = readFileSync(join(dir, 'events.jsonl'), 'utf8');
  } catch (err) {
    failAll(`cannot read bundle: ${(err as Error).message}`);
    return out(null, null);
  }
  const msha = sha256Hex(manifestText);
  let m: BundleManifest;
  try {
    m = JSON.parse(manifestText) as BundleManifest;
  } catch {
    failAll('manifest.json is not JSON');
    return out(null, msha);
  }
  if (m.format !== BUNDLE_FORMAT) {
    failAll(`unknown format ${String(m.format)} (expected ${BUNDLE_FORMAT})`);
    return out(m, msha);
  }
  if (manifestText !== canonicalize(m as unknown as JsonValue) + '\n') fail('canonical', 'manifest.json is not canonical JSON');
  const rawLines = eventsText.split('\n');
  if (rawLines.pop() !== '') fail('canonical', 'events.jsonl does not end with a newline');
  const lines: Record<string, unknown>[] = [];
  for (const [i, l] of rawLines.entries()) {
    let v: unknown;
    try {
      v = JSON.parse(l);
    } catch {
      fail('canonical', `events.jsonl line ${i + 1} is not JSON`);
      continue;
    }
    if (l !== canonicalize(v as JsonValue)) fail('canonical', `events.jsonl line ${i + 1} is not canonical JSON`);
    lines.push(v as Record<string, unknown>);
  }
  if (sha256Hex(eventsText) !== m.events_sha256) fail('canonical', 'events.jsonl does not hash to manifest.events_sha256');

  // 2. events: each full line re-hashes, belongs to the audit, validates against its kind's schema, and matches the manifest index.
  const full: ChainEvent[] = [];
  const stubSeqs: number[] = [];
  for (const l of lines) {
    if (l['stub'] === true) {
      stubSeqs.push(Number(l['seq']));
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
    if (ev.payload?.['audit_id'] !== m.audit_id) fail('events', `seq ${String(ev.seq)}: audit_id is not ${m.audit_id}`);
    const p = parseAuditPayload(kind, ev.payload);
    if (!p.ok) fail('events', `seq ${String(ev.seq)} (${kind}): ${p.problem}`);
  }
  const index = full.map((e) => ({ seq: e.seq, event_id: e.event_id, event_type: e.event_type, this_hash: e.this_hash }));
  if (canonicalize(index as unknown as JsonValue) !== canonicalize((m.events ?? []) as unknown as JsonValue)) fail('events', 'events.jsonl full events differ from manifest.events');
  if (canonicalize(stubSeqs) !== canonicalize((m.stubs ?? []) as unknown as JsonValue)) fail('events', 'events.jsonl stubs differ from manifest.stubs');

  // 3. chain: contiguous seqs from_seq..to_seq, each prev_hash = previous this_hash, first = range.first_prev_hash.
  const r = m.range;
  if (lines.length !== r.to_seq - r.from_seq + 1 || lines.length !== r.leaf_count) fail('chain', `range ${r.from_seq}..${r.to_seq} needs ${r.to_seq - r.from_seq + 1} lines; events.jsonl has ${lines.length}`);
  let prev = r.first_prev_hash;
  for (const [i, l] of lines.entries()) {
    if (l['seq'] !== r.from_seq + i) {
      fail('chain', `line ${i + 1}: seq ${String(l['seq'])}, expected ${r.from_seq + i}`);
      break;
    }
    if (l['prev_hash'] !== prev) {
      fail('chain', `seq ${String(l['seq'])}: prev_hash does not link to seq ${r.from_seq + i - 1}`);
      break;
    }
    prev = String(l['this_hash']);
  }

  // 4. root: Merkle root over the segment's leaves, signed by the manifest key (or the pinned one).
  try {
    const root = merkleRootHex(lines.map((l) => ({ seq: Number(l['seq']), this_hash: String(l['this_hash']) })));
    if (root !== m.root.root) fail('root', 'Merkle root over events.jsonl differs from manifest.root.root');
    if (m.root.leaf_count !== lines.length) fail('root', 'root.leaf_count differs from the segment');
    const pem = opts.public_key_pem ?? m.root.public_key_pem;
    if (opts.public_key_pem !== undefined && keyIdFromPublicKey(createPublicKey(opts.public_key_pem)) !== m.root.key_id) {
      fail('root', `root is signed by ${m.root.key_id}, not the pinned key`);
    } else if (keyIdFromPublicKey(createPublicKey(pem)) !== m.root.key_id) {
      fail('root', 'manifest public key does not match root.key_id');
    }
    const msg = checkpointSigningPayload({ from_seq: r.from_seq, to_seq: r.to_seq, leaf_count: m.root.leaf_count, root: m.root.root });
    if (!verifyEd25519(pem, msg, m.root.signature)) fail('root', 'root signature does not verify');
  } catch (err) {
    fail('root', `cannot check root: ${(err as Error).message}`);
  }

  // 5. artifacts: every listed blob file exists, hashes to its name and size; no unlisted files.
  const listed = new Set<string>();
  for (const b of m.blobs ?? []) {
    listed.add(b.sha256);
    const p = join(dir, 'blobs', b.sha256);
    if (!existsSync(p)) {
      fail('artifacts', `blob ${b.sha256.slice(0, 12)}… listed but absent`);
      continue;
    }
    const bytes = readFileSync(p);
    if (createHash('sha256').update(bytes).digest('hex') !== b.sha256) fail('artifacts', `blob ${b.sha256.slice(0, 12)}… does not hash to its name`);
    else if (bytes.byteLength !== b.size) fail('artifacts', `blob ${b.sha256.slice(0, 12)}… size differs`);
  }
  if (existsSync(join(dir, 'blobs'))) {
    for (const f of readdirSync(join(dir, 'blobs'))) if (!listed.has(f)) fail('artifacts', `unlisted file blobs/${f}`);
  }

  // 6. refs: every blob ref is present, or declared redacted / missing (exactly one); every evidence id is an event of the bundle.
  const redacted = new Set((m.redacted ?? []).map((x) => x.sha256));
  const missing = new Set((m.missing ?? []).map((x) => x.sha256));
  const ids = new Set(full.map((e) => e.event_id));
  const seen = new Set<string>();
  for (const ev of full) {
    for (const { field, ref } of blobRefsOf(ev.payload ?? {})) {
      seen.add(ref.sha256);
      const where = [listed.has(ref.sha256), redacted.has(ref.sha256), missing.has(ref.sha256)].filter(Boolean).length;
      if (where !== 1) fail('refs', `seq ${ev.seq} ${field} ${ref.sha256.slice(0, 12)}…: ${where === 0 ? 'neither present nor declared redacted/missing' : 'listed more than once'}`);
      if (ref.redacted !== true && redacted.has(ref.sha256) && !listed.has(ref.sha256)) fail('refs', `seq ${ev.seq} ${field}: stored ref listed as redacted`);
    }
    for (const id of evidenceOf(ev.payload ?? {})) if (!ids.has(id)) fail('refs', `seq ${ev.seq}: evidence ${id} is not in the bundle`);
  }
  for (const s of [...listed, ...redacted, ...missing]) if (!seen.has(s)) fail('refs', `${s.slice(0, 12)}… is listed but no event references it`);
  return out(m, msha);
}
