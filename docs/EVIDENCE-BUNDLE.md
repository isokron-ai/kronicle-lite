# Evidence bundles: format and verification procedure

An evidence bundle is one audit's events exported from a kronicle-lite store. It
is a directory that anyone can check offline with `kronicle-lite verify-bundle DIR`.
The check needs no store and no network. Source: `src/audit/bundle.ts` (export)
and `src/audit/verify-bundle.ts` (verify). The audit event types themselves are
described in [AUDIT.md](AUDIT.md).

```
kronicle-lite audit export --audit-id A1 --out bundle/   # on the auditor's machine
kronicle-lite verify-bundle bundle/ [--key store.pem]     # anywhere; exit 0 = verifies
```

## What a passing check proves, and what it does not

**A pass proves four things:**
- The files are exactly what the manifest describes.
- The audit's events hash correctly and form one contiguous segment of a single
  hash chain.
- The store key named in the manifest signed that segment's Merkle root. Pin the
  key with `--key`, or the check only proves the key is self-consistent.
- Every artifact reference resolves, or is openly declared redacted or missing.

**A pass does not prove the audit is correct.** The findings, verdicts and
measurements are claims made by whoever recorded them. A bundle shows they were
recorded, in order, unchanged since. It doesn't show they are true.

**An anchor proves existence at a time, and nothing more.** Anchoring the root
(the checkpoint over the same range, `checkpoint --push`) proves that this root
existed no later than the anchor's timestamp. It says nothing about whether the
audit was right, complete, or honest.

## Files

| File | Content |
|---|---|
| `manifest.json` | Canonical JSON ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)) plus `\n`: format, audit_id, range, index, blob lists, signed root |
| `events.jsonl` | One canonical JSON line per chain event in `[from_seq, to_seq]`. Audit events are in full (the stored chain event). Every other event in the range is a **stub**: `{seq, prev_hash, this_hash, stub: true}`, with no payload |
| `blobs/<sha256>` | Each referenced artifact the store holds, named by the sha256 of its bytes |

- **Range:** the audit's first event to its last.
- **Why stubs:** they keep the hash links continuous without disclosing other
  documents or other audits.
- **Determinism:** every byte is a function of the chain and the blob store, so
  exporting twice gives identical files. The SHA-256 of `manifest.json` is the
  bundle's identity (printed as `manifest sha256`).

## Verification procedure

`verify-bundle` reports the first failure in each of the six steps below.

### 1. `canonical`
1. `manifest.json` must equal `JCS(manifest) + "\n"`.
2. Every line of `events.jsonl` must equal `JCS(line)`, and the file must end with `\n`.
3. `sha256(events.jsonl bytes)` must equal `manifest.events_sha256`.

### 2. `events`
For every full line (not a stub):
1. Recompute `this_hash` with the FORMAT §1 recipe:
   `sha256(JCS({event_id, event_type, actor_id, occurred_at, payload}) | seq | prev_hash | nonce)`.
2. `event_type` must be `audit.<kind>`.
3. `payload.audit_id` must equal the manifest's `audit_id`.
4. The payload must validate against that kind's schema (AUDIT.md).

Then check that the full lines match `manifest.events` and the stubs match
`manifest.stubs`, exactly and in order.

### 3. `chain`
1. Lines must run `from_seq, from_seq+1, … to_seq` with no gaps.
2. `leaf_count` must equal the number of lines.
3. The first line's `prev_hash` must equal `range.first_prev_hash`.
4. Every later line's `prev_hash` must equal the previous line's `this_hash`.

A stub contributes its `prev_hash` and `this_hash`, so links stay checkable
through events whose payloads are withheld.

### 4. `root`
1. Compute the Merkle root (FORMAT §2) over the segment's leaves.
   - Each leaf is `sha256(JCS({seq, this_hash}))`.
   - Each node is `sha256(left ‖ right)`.
   - An odd node is promoted unchanged.
2. The root must equal `root.root`.
3. The Ed25519 signature `root.signature` must verify over
   `JCS({v: 1, from_seq, to_seq, leaf_count, root})` with `root.public_key_pem`.
4. That key's id, `ed25519-` plus the first 16 hex of `sha256(SPKI DER)`, must
   equal `root.key_id`.
5. With `--key`, the pinned key must be the one that signed.

This root is the same checkpoint the store keeps for the range, so the existing
anchor flow can anchor it.

### 5. `artifacts`
1. Every entry in `manifest.blobs` must exist as `blobs/<sha256>`, hash to its
   name and have the stated size.
2. No file may sit in `blobs/` unless it is listed.

### 6. `refs`
1. Every blob ref in every event payload must appear in exactly one of:
   - `blobs` (present);
   - `redacted` (declared at record time as `redacted: true`: never stored);
   - `missing` (the store no longer held it at export).
2. Every listed hash must be referenced by some event.
3. Every `evidence` event id must be an event in the bundle.

## The redacted and missing lists

- **`redacted`:** artifacts that were deliberately never stored, because
  credentials and private data are redacted *before* persistence. The ref
  carries the hash of the original, so anyone holding the original can prove
  it matches.
- **`missing`:** artifacts that were stored once and are gone now. Export lists
  them and exits 1, so they are never silently dropped.

A verifier should read both lists as part of the result. "Verifies, with 3
redacted and 0 missing" is a different statement from "verifies, with 0 and 0".
