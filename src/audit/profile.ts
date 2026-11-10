/**
 * The audit profile's recipes (0.11.0), shared by the recorder (mcp-audit's
 * evidence module, `audit stamp`) and `verify-audit`, so both compute the
 * same bytes. docs/EVIDENCE-BUNDLE.md "The audit profile" is the reference.
 *
 *   freezeNonce          sha256(freeze receipt digest ‖ every TSA token over it): no one, the
 *                        auditor included, can know it before the TSAs sign at genTime
 *   reproductionStatement the bytes a human signs with `ssh-keygen -Y sign -n kronicle-lite-reproduction`
 *   findingsDigest       the final status of every finding, as one sha256 (audit_closed)
 */

import { canonicalize } from '../crypto/canonical.js';
import { sha256Hex } from '../crypto/hash.js';
import { statusEffect, type AuditKind, type FindingStatus } from './schemas.js';

/** SSH signature namespace of a reproduction sign-off (ssh-keygen -Y sign -n). */
export const REPRODUCTION_NAMESPACE = 'kronicle-lite-reproduction';
export const REPRODUCTION_FORMAT = 'kronicle-lite-reproduction/1';

/**
 * The freeze nonce of a /3 bundle: SHA-256 over the 32 raw bytes of the freeze receipt's digest
 * followed by every timestamp reply (.tsr file bytes) over that receipt, in byte order of the TSA
 * label. In a shell, with the pack's file names:
 *   { printf %s "$D" | xxd -r -p; LC_ALL=C cat anchors/01-harness-frozen.*.tsr; } | shasum -a 256
 * The tokens are signed by third parties at genTime, so the nonce cannot be known before the freeze
 * is stamped (the 0.10.0 nonce, the receipt digest alone, was the auditor's own anchor's hash).
 */
export function freezeNonce(receipt_sha256: string, tokens: readonly { tsa: string; bytes: Uint8Array }[]): string {
  if (!/^[0-9a-f]{64}$/.test(receipt_sha256)) throw new Error('freezeNonce: receipt_sha256 must be 64 lowercase hex');
  if (tokens.length < 2) throw new Error('freezeNonce: needs the tokens of at least two timestamp authorities');
  const sorted = [...tokens].sort((a, b) => (a.tsa < b.tsa ? -1 : a.tsa > b.tsa ? 1 : 0));
  return sha256Hex(Buffer.concat([Buffer.from(receipt_sha256, 'hex'), ...sorted.map((t) => Buffer.from(t.bytes))]));
}

export interface ReproductionFields {
  audit_id: string;
  finding_id: string;
  /** The reproducer's principal in the allowed-signers file. */
  signer: string;
  reproduced_at: string;
  /** sha256 of the commands blob and of the output blob. */
  commands: string;
  output: string;
}

/** The statement a reproducer signs: canonical JSON (RFC 8785) of the fields plus the format, and a newline. */
export function reproductionStatement(f: ReproductionFields): string {
  return (
    canonicalize({ format: REPRODUCTION_FORMAT, audit_id: f.audit_id, finding_id: f.finding_id, signer: f.signer, reproduced_at: f.reproduced_at, commands: f.commands, output: f.output }) + '\n'
  );
}

/** The status each finding ends with, from the audit's events in seq order. */
export function finalFindingStatuses(events: Iterable<{ kind: AuditKind | string | null; payload: Record<string, unknown> | null }>): Map<string, FindingStatus> {
  const out = new Map<string, FindingStatus>();
  for (const e of events) {
    if (!e.kind || !e.payload) continue;
    const id = e.payload['finding_id'];
    if (typeof id !== 'string') continue;
    const eff = statusEffect(e.kind as AuditKind, e.payload);
    if (eff !== null) out.set(id, eff);
  }
  return out;
}

/** sha256 of the canonical [{finding_id, status}] sorted by finding_id: what audit_closed.findings_digest records. */
export function findingsDigest(statuses: ReadonlyMap<string, FindingStatus> | readonly { finding_id: string; status: FindingStatus }[]): string {
  const list = statuses instanceof Map ? [...statuses].map(([finding_id, status]) => ({ finding_id, status })) : [...(statuses as readonly { finding_id: string; status: FindingStatus }[])];
  list.sort((a, b) => (a.finding_id < b.finding_id ? -1 : a.finding_id > b.finding_id ? 1 : 0));
  return sha256Hex(canonicalize(list.map((x) => ({ finding_id: x.finding_id, status: x.status }))));
}
