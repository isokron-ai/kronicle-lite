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

**A pass proves five things:**
- **The store key signed the whole manifest.** The signature covers its index
  (which seqs are full audit events and which are stubs, with each stub's hash),
  the blob lists and every digest, not just the root. Pin the key with `--key`.
  Without it, the check only proves the bundle is self-consistent under
  *some* key, and anyone can produce such a bundle: it is tamper-evidence,
  not authenticity. The CLI says so on stderr (`signer NOT verified`), and
  `--strict` exits 1 without `--key`.
- **The files are exactly what the manifest describes.**
- **The events form one chain segment.** The audit's events hash correctly and,
  together with the stubs, form one contiguous segment of a single hash chain.
  The same key signs that segment's Merkle root.
- **Every artifact reference resolves**, or is openly declared redacted.
- **Nothing is missing.** A missing artifact fails the bundle unless you pass
  `--allow-missing`, and the result reports that you did.

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
| `manifest.json` signature | `signature: {key_id, signature}`: the store key over the canonical manifest (step 2) |
| `events.jsonl` | One canonical JSON line per chain event in `[from_seq, to_seq]`. Audit events are in full (the stored chain event). Every other event in the range is a **stub**: `{seq, prev_hash, this_hash, stub: true}`, with no payload; `manifest.stubs` lists each stub's `{seq, this_hash}` |
| `blobs/<sha256>` | Each referenced artifact the store holds, named by the sha256 of its bytes. Blobs pass the write-time secret guard when they are stored (AUDIT.md) |

- **Range:** the audit's first event to its last.
- **Why stubs:** they keep the hash links continuous without disclosing other
  documents or other audits.
- **Safe export:** `--out` must be a new or empty directory, and neither it nor
  any existing parent may be a symlink. Every file is created new with
  `O_CREAT|O_EXCL|O_NOFOLLOW`, so a planted link is never written through.
  Files are written by name relative to a working directory pinned to the
  checked directory's inode (`--out`, then `blobs/`), so swapping either one
  for a link mid-export cannot redirect a write; the export then fails with
  "changed during export".
- **Determinism:** every byte is a function of the chain and the blob store, so
  exporting twice gives identical files. The SHA-256 of `manifest.json` is the
  bundle's identity (printed as `manifest sha256`).

## Verification procedure

`verify-bundle` reports the first failure in each of the eight steps below
(step 2 runs before `events.jsonl` is read; see the order above).

Hostile input fails cleanly:
- Any manifest shape, any nesting depth (more than 64 levels is refused before
  parsing) and any file name yields `ok: false` with a reason, never a crash.
- **Order: nothing a manifest lists is read before its signature verifies.**
  `manifest.json` is read and checked first (at most 64 MiB): its
  `range.leaf_count` must equal `to_seq - from_seq + 1`, the number of
  events and stubs it lists, and `root.leaf_count`. When its signature does
  not verify (or not under `--key`), every later step reports `not checked`
  and fails: the digests, sizes and names it lists could be an attacker's.
  Then `events.jsonl` is read once, as a stream, in 1 MiB chunks: each chunk
  is hashed, and each line is checked as it completes (steps 3 and 4: event
  hash, schema, index, chain link) and dropped, so what is kept is bounded by
  the signed index (a Merkle leaf per line; refs and evidence ids per audit
  event). A line longer than 1 MiB, more lines than the index lists, a line
  that is not a JSON object, or more bytes than the read budget stop the read
  at once. The findings of steps 3 to 5 count only when the whole file
  hashes to the signed `events_sha256`. Measured on a self-signed bundle
  with no `--key`, a correct digest and 64 MiB of `{}` or `x` lines (macOS
  arm64, Node 25): with `leaf_count` 1e12 (refused from the manifest) or a
  consistent one (stopped at the first surplus or bad line), exit 1 in about
  0.1 s at about 70 MB RSS. Before, the verifier ran out of heap after 52 s
  and 103 s at 4.4 GB (exit 134). A self-signed sparse 500 MiB
  `events.jsonl` that matches its digest fails in about 40 ms (Linux,
  Node 22).
- **Files.** `manifest.json`, `events.jsonl` and every blob must be regular
  files with one link, not symlinks, hard links (which may be files outside
  `DIR`; `--allow-hardlinks` accepts them), devices, FIFOs or directories, and
  `blobs/` must be a real directory, not a link: no path component below
  `DIR` may be a link (`DIR` itself is resolved once). Blob names must be 64
  lowercase hex characters, each listed once. `--key` must be a regular file
  of at most 64 KB (a link to one is fine).
- **Blobs** are hashed as a stream in 1 MiB chunks, each file once. A blob
  listed above 64 MiB (the store's limit) or whose size differs from the
  manifest is reported without being read.
- **Read budget.** At most 1 GiB is read per bundle: every byte of the
  manifest, events and blobs counts, and each file is read once. A bundle
  that needs more fails with the budget named; raise it with `--max-bytes N`
  (API `max_bytes`; the flag needs a value).

### 1. `canonical`
1. `manifest.json` must equal `JCS(manifest) + "\n"`.
2. Every line of `events.jsonl` must equal `JCS(line)`, and the file must end with `\n`.
3. `sha256(events.jsonl bytes)` must equal `manifest.events_sha256`.

### 2. `signature`
1. `signature.signature` must be an Ed25519 signature over
   `"kronicle-lite/evidence-bundle-manifest/1\n" + JCS(manifest without "signature")`
   by `root.public_key_pem`, or by the `--key` given.
2. `signature.key_id` and `root.key_id` must both equal that key's id.

### 3. `events`
For every full line (not a stub):
1. Recompute `this_hash` with the FORMAT §1 recipe:
   `sha256(JCS({event_id, event_type, actor_id, occurred_at, payload}) | seq | prev_hash | nonce)`.
2. `event_type` must be `audit.<kind>`.
3. `payload.audit_id` must equal the manifest's `audit_id`.
4. The payload must validate against that kind's schema (AUDIT.md).

A stub is exactly `{seq, prev_hash, this_hash, stub: true}`. The full lines
must match `manifest.events`, and the stubs must match `manifest.stubs`
(`{seq, this_hash}`), exactly and in order. Because the manifest is signed,
turning an audit event into a stub breaks the signature, even if every digest
is recomputed.

### 4. `chain`
1. Lines must run `from_seq, from_seq+1, … to_seq` with no gaps.
2. `leaf_count` must equal the number of lines.
3. The first line's `prev_hash` must equal `range.first_prev_hash`.
4. Every later line's `prev_hash` must equal the previous line's `this_hash`.

A stub contributes its `prev_hash` and `this_hash`, so links stay checkable
through events whose payloads are withheld.

### 5. `root`
1. Compute the Merkle root (FORMAT §2) over the segment's leaves.
   - Each leaf is `sha256(JCS({seq, this_hash}))`.
   - Each node is `sha256(left ‖ right)`.
   - An odd node is promoted unchanged.
2. The root must equal `root.root`.
3. The Ed25519 signature `root.signature` must verify over
   `JCS({v: 1, from_seq, to_seq, leaf_count, root})` with the same key as
   step 2. The key's id is `ed25519-` plus the first 16 hex of `sha256(SPKI DER)`.

This root is the same checkpoint the store keeps for the range, so the existing
anchor flow can anchor it.

### 6. `artifacts`
1. Every entry in `manifest.blobs` must exist as a regular file
   `blobs/<sha256>`, where the name is 64 hex. It must hash to its name and
   have the stated size.
2. No entry may sit in `blobs/` unless it is listed.

### 7. `refs`
1. Every blob ref in every event payload must appear in exactly one of:
   - `blobs` (present);
   - `redacted` (declared at record time as `redacted: true`: never stored);
   - `missing` (the store no longer held it at export).
2. Every listed hash must be referenced by some event.
3. Every `evidence` event id must be an event in the bundle.

### 8. `missing`
`manifest.missing` must be empty, unless the caller passes `--allow-missing`
(`allow_missing` in the JSON result). The bundle then verifies with the
missing count reported.

## The redacted and missing lists

- **`redacted`:** artifacts that were deliberately never stored, because
  credentials and private data are redacted *before* persistence. The ref
  carries the hash of the original, so anyone holding the original can prove
  it matches.
- **`missing`:** artifacts that were stored once and are gone now. Export lists
  them and exits 1, and `verify-bundle` fails without `--allow-missing`, so
  they are never silently dropped.

A verifier should read both lists as part of the result. "Verifies, with 3
redacted and 0 missing" is a different statement from "verifies, with 0 and 0".
