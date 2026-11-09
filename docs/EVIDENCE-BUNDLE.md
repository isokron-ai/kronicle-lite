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
| `manifest.json` | Canonical JSON ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)) plus `\n`: format (`kronicle-lite-evidence-bundle/1`, or `/2` when a milestone kind is present), audit_id, range, index, blob lists, signed root |
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
  and 103 s at 4.4 GB (exit 134). Memory is bounded by the signed index,
  not by the bundle: a 56 MB manifest listing 600k stubs takes 2.5 to 4.8 s
  at about 1 GB. A self-signed sparse 500 MiB
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
2. `event_type` must be `audit.<kind>`, a kind the bundle's format allows:
   `/1` the six 0.9.0 kinds, `/2` also the milestone kinds (AUDIT.md).
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

## Evidence packs (0.10.0)

An **IsoKron Evidence Pack** is tamper-evident, independently timestamped audit
evidence: one bundle plus everything needed to check, offline, when each stage
of the audit was committed. Source: `src/audit/package.ts` (`audit stamp`,
`audit package`), `src/audit/verify-audit.ts` (`verify-audit`),
`src/audit/rfc3161.ts` (timestamp tokens).

```
# auditor, after each milestone (harness frozen, runs done, report issued)
kronicle-lite checkpoint --push                       # anchor [1..head]
kronicle-lite audit stamp --out stamps/               # RFC 3161 over sha256(receipt), Sectigo + DigiCert
# at delivery
kronicle-lite audit package --audit-id A --out pack/ --timestamps stamps/
# client
kronicle-lite verify-audit pack/ --key-fingerprint <SHA-256 of the auditor key, from the report or SOW>
```

Use one store per audit, so the bundle starts at seq 1 and every anchor's range
`[1..k]` lies inside it: an anchor's root is recomputed from the bundle's own
`events.jsonl`, which needs every leaf from the anchor's `from_seq`.
`audit package` includes only anchors whose range lies inside the bundle's and
lists the others as skipped. Take each stamp right after its anchor: a later
stamp carries a later time.

### Layout

| File | Content |
|---|---|
| `bundle/` | the evidence bundle above |
| `anchors/NN-<label>.receipt.json` | anchor receipt v1 (FORMAT §9), canonical JSON, no trailing newline: `sha256(file)` is the digest the TSAs stamped. `<label>` names the milestone the anchor closes on (`harness-frozen`, `run-completed`, `report-issued`, or the kind at its last seq) |
| `anchors/NN-<label>.<tsa>.tsr` | RFC 3161 TimeStampResp over `sha256(receipt file)`, with the TSA's certificate chain embedded (`certReq`) |
| `anchors/index.json` | summary of the anchors (informational; `verify-audit` does not read it) |
| `auditor-key.pem` | the auditor (store) public key; trusted only when its SHA-256(SPKI) equals the `--key-fingerprint` the client takes from the report or SOW |
| `anchor-keys.json` | the anchor service's published key list, as is (with its successor and status statements); trusted only as one chain from the genesis pin |
| `tsa-roots/*.pem` | the pinned timestamping CAs: `sectigo.pem` = Sectigo Public Time Stamping Root R46 (self-signed and USERTrust cross-signed forms of one key), `digicert.pem` = DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1 and the 2022 G4 RSA4096 SHA256 TimeStamping CA; `custom-N.pem` for other TSAs |
| `claims.json` | what the pack claims (below) and, with `run_sequence`, the run count, each `run_seq` and every capture interruption |
| `COMPLETION.txt` | one page: manifest SHA-256, signing key fingerprint, final anchored root, timestamp times, claims |
| `VERIFY.md` | the one-command check and the raw commands (`shasum`, `openssl`, `jq`) with this pack's file names |
| `SHA256SUMS` | `<sha256>  <path>` for every other file, sorted (`shasum -a 256 -c` format) |
| `SHA256SUMS.sig` | raw 64-byte Ed25519 signature of `SHA256SUMS` by the auditor key (`openssl pkeyutl -verify -rawin`) |

### Claims

`claims.json` (`isokron-evidence-pack-claims/1`) lists the claims the pack
makes. `audit package` declares what the store's contents support:
`integrity` and `chain` always, `receipts` with at least one anchor,
`independent_timestamps` when every anchor has a token,
`harness_frozen_before_runs` only when that check passes, and `run_sequence`
when the runs carry `run_seq`. It prints why a claim is not declared.

`verify-audit` fails closed, in this order:

1. The auditor key is pinned out of band: `--key-fingerprint` (SHA-256 of its
   SPKI, from the report, the SOW or isokron.ai/verify) checked against
   `auditor-key.pem`, or `--key FILE` from outside the pack (a `--key` inside
   the pack directory is refused, exit 2). An unpinned key is a FAIL: no
   unpinned pack exits 0.
2. `SHA256SUMS` and its signature are checked against that key **before**
   `claims.json` is read. If they do not verify, or `claims.json` is missing or
   invalid, every claim is checked (and the `claims.json` check fails).
3. `integrity` and `chain` are always checked. Then the declared claims, any
   `--require`d one, and what they depend on: `independent_timestamps` needs
   `receipts`; `harness_frozen_before_runs` needs `receipts` and
   `independent_timestamps`.

It prints one line per claim: `PASS`, `FAIL`, `not declared`, or `not checked`
(the claims that need RFC 3161 tokens, under `--no-tsa`; `--require` of one of
them with `--no-tsa` is a usage error). Exit 0 means every checked claim
passed.

| Claim | Checks |
|---|---|
| `integrity` | `bundle/` and `anchors/` are real directories; `SHA256SUMS.sig` verifies under the pinned auditor key and every file matches `SHA256SUMS` with none unlisted or missing; the bundle's canonical, signature, events (including every payload against its schema), artifacts, refs and missing steps |
| `chain` | the bundle's chain and signed root steps |
| `receipts` | the anchor key list is one intact chain from the genesis pin (below) and not a rollback of a list seen before; per receipt: readable and canonical; countersigned by a listed key that was active or retired at `received_at` (inside its validity window); `chain_id`/`key_id` derive from the auditor key and the checkpoint signature verifies; the root equals the FORMAT §2 Merkle root of that range recomputed from `events.jsonl`; with timestamps checked, the earliest valid TSA time is no later than the signing key's `valid_to` + 5 min (a key that has ended cannot vouch for a receipt stamped afterwards). Then: each anchor extends the previous one on range and on every clock, and every audit event is committed by a verified anchor |
| `independent_timestamps` | every receipt readable (an unreadable one fails the claim); per token: granted (`grantedWithMods` refused); CMS SignedData v3 over TSTInfo v1 with exactly one signer and no unexpected fields; messageImprint = hash of the receipt file; signed attributes (contentType, messageDigest, ESS signing-certificate, every certificate the ESS list names embedded unchanged) and signature verify; the signer is not a CA, has keyUsage digitalSignature or nonRepudiation (and not certificate signing), EKU critical and timeStamping only, and was valid at genTime; the path through embedded CAs ends at a pinned timestamping CA; intermediates have keyCertSign and timeStamping (or no) EKU; pathLenConstraint holds; no unknown critical extension; inner and outer certificate signature algorithms agree; every embedded certificate is on the path, pinned, or a known chain certificate; every certificate valid at the check time. `received_at` is no later than genTime + 5 min (not forward-dated) and no more than 24 h before it. Each receipt has valid tokens from at least two different pinned TSA CAs. The signer's subject DN is reported |
| `harness_frozen_before_runs` | the freeze event (`harness_frozen`, or the 0.9.0 `finding` with `class: protocol_freeze`) records a harness digest; every run names that digest; the freeze is first committed by a timestamped anchor that covers no run; every run is committed by a later timestamped anchor; every run carries the freeze nonce (the only accepted basis for a `/2` bundle), or, in a `/1` bundle, records a `measured_at` between the freeze anchor's latest RFC 3161 time and its committing anchor's earliest one |
| `run_sequence` | `run_seq` over the `run_completed` events is integers ≥ 1, 1..N with no gap or repeat; N equals `planned_runs`, the report's `run_count` and `claims.json` `runs.count` where present; `claims.json` lists exactly the runs recorded as `capture: "interrupted"` |

The output ends with the values to compare against the report and
`COMPLETION.txt`: manifest SHA-256, auditor key fingerprint, final root and its
timestamp times. `--json` (`kronicle-lite-verify-audit/1`) has `claims[]`,
`checks[]` (each with `claim`, `status` pass \| fail \| not_applicable and
`evidence`), `anchors[]`, `ordering`, `run_sequence`, `timeline[]` and `final`;
`VerifyAuditJsonSchema` in `src/audit/verify-audit.ts` is its schema.

**Scope.** The claims establish integrity (the files are the ones the auditor
key signed and anchored), ordering (the hash chain and the anchored prefixes,
and the harness freeze when declared) and independent time (each anchor existed
no later than its RFC 3161 time). The depth, method and correctness of the audit
are described in the report. Anything recorded before the first anchor carries
no timestamp; `measured_at` and payload values are recorded by the auditor.

### Trust

- **Auditor key:** `--key-fingerprint` from the report, the SOW or
  isokron.ai/verify (never from the pack), or `--key FILE` from outside the pack.
- **Anchor service keys:** the same key-list model as the anchor service
  (isokron-anchor `src/core/servicekeys.ts`; `src/anchor/keychain.ts` is a
  port, and `test/keychain.test.ts` checks it against lists built by the
  service's `scripts/rotate-key.mjs` and judged by the service):
  - one linear chain from a genesis key pinned by SHA-256(SPKI): compiled in
    (`anchor-ed25519-3dca1ecf66c2993e`,
    `3dca1ecf66c2993e534ff08fe350dc9368ca52042e38b20a9d58cd7c2b7b3367`, valid
    from 2026-11-01T02:29:25.705Z, for `https://anchor.isokron.ai`; its
    `valid_from` comes from the compiled pin, never from a pack), or
    `--genesis <sha256>@<valid_from>` / `KRONICLE_ANCHOR_GENESIS` for a
    self-hosted service, as the anchor client takes it (the old
    `KRONICLE_ANCHOR_GENESIS_SHA256` is refused: the pin includes `valid_from`);
  - signed statements, byte for byte as the service's README "Signed key
    statements (byte-exact)" specifies (and `test/keychain.test.ts` checks its
    test vectors): the UTF-8 bytes of the RFC 8785 canonical JSON of exactly
    these members, pure Ed25519, standard base64 (88 characters):

    | Statement | Field | Signed by | Members |
    |---|---|---|---|
    | successor | `successor_signature` | the predecessor (`signed_by`) | `key_id`, `public_key_pem`, `valid_from` |
    | retirement | `retirement_signature` | the successor (`retirement_signed_by`) | `key_id`, `status: "retired"`, `valid_to` |
    | revocation | `retirement_signature` | the key itself or an earlier key on its chain | `compromised_since`, `key_id`, `status: "revoked"`, `valid_to` |

  - no forks; a retired key's `valid_to` is no later than its successor's
    `valid_from`; the newest key is `active` with no `valid_to`, or `revoked`;
  - a revocation without `compromised_since`, or signed by a later key, is
    BROKEN;
  - keys after a revoked key are not trusted (the revoked key signed their
    successor statements, and nothing timestamps those before
    `compromised_since`): their receipts fail; keys before it are unaffected.
  Anything else is BROKEN and no receipt verifies. The list comes from the
  pack's `anchor-keys.json` (or `--anchor-keys FILE`, checked the same way).
  The genesis key's validity, and a new genesis after a revocation, ship in
  kronicle-lite releases.
- **Revoked key:** a receipt signed by a revoked key passes only when its
  earliest verified RFC 3161 genTime is before `compromised_since` minus 5
  minutes. Its `received_at` never counts (the leaked key signs it), and with
  tokens not checked (`--no-tsa`, or `independent_timestamps` not claimed) the
  receipt fails. (The anchor client, which checks no tokens, rejects every such
  receipt.)
- **Rollback:** `verify-audit` keeps the newest usable list it has seen per
  genesis pin in `<data-dir>/anchor-keys.seen.json`; a pack whose list is
  shorter (a key missing), or weaker (a status moved back, a `valid_to` or
  `compromised_since` dropped or moved later), fails with the date of the list
  it contradicts. The cache is reset only by deleting that file.
- **Receipt times:** the service's `received_at` must be no later than each
  TSA genTime + 5 min and no more than 24 h before it, and a token issued more
  than 5 min after the signing key's `valid_to` invalidates the receipt (the
  service's rule).
- **TSA CAs:** pinned to the timestamping-specific CAs, not the general
  public roots above them (`src/audit/tsa-roots.ts`): Sectigo Public Time
  Stamping Root R46 (both forms of its key) and the DigiCert Trusted G4
  TimeStamping CAs; or `--tsa-roots DIR` (each file one TSA). Each receipt
  needs valid tokens from two different TSAs (`sectigo` and `digicert` by
  default). A token may embed only path certificates, pinned ones, or the
  known chain certificates in `SHIPPED_TSA_EXTRAS` (DigiCert's G4 cross-signed
  by its retired Assured ID root). A certificate from another branch of
  USERTrust or DigiCert G4 cannot sign a timestamp that verifies. A TSA moving
  to a new issuing CA needs a kronicle-lite release (or `--tsa-roots`). The
  pack's `tsa-roots/` holds the same certificates for the openssl route and is
  never trusted by `verify-audit`. Path building asks the pinned certificates
  first, so embedded cross-certificates are never needed.
- **No openssl needed.** RFC 3161 tokens are verified in-process with
  `node:crypto` (a small DER reader in `src/audit/der.ts` and the CMS checks above). It runs the
  same on Linux, macOS and Windows, and a missing or old openssl cannot turn a
  check into a skip. Revocation (CRL / OCSP) is not checked: verification is
  offline.

### Without kronicle-lite

Each pack's `VERIFY.md` lists the commands with its own file names. In short,
with OpenSSL 3 and `jq`:

```sh
openssl pkeyutl -verify -pubin -inkey auditor-key.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
shasum -a 256 -c SHA256SUMS                 # or sha256sum -c, or openssl dgst -sha256 FILE
D=$(shasum -a 256 anchors/01-harness-frozen.receipt.json | cut -c1-64)
openssl ts -verify -digest $D -in anchors/01-harness-frozen.sectigo.tsr -CAfile tsa-roots/sectigo.pem -partial_chain
# anchor service countersignature: canonical receipt minus signature (jq -cjS sorts keys, no newline)
R=anchors/01-harness-frozen.receipt.json
jq -r --arg k "$(jq -r .service_key_id $R)" '.keys[] | select(.key_id == $k) | .public_key_pem' anchor-keys.json > service-key.pem
jq -cjS 'del(.signature)' $R > body.bin && jq -r .signature $R | openssl base64 -d -A > sig.bin
openssl pkeyutl -verify -pubin -inkey service-key.pem -rawin -in body.bin -sigfile sig.bin
```

`-partial_chain` lets openssl stop at a pinned CA that is not self-signed (the
DigiCert TimeStamping CAs, the cross-signed R46). `jq -cjS` output equals RFC
8785 for these objects (ASCII strings, integers).
Compare `service-key.pem` with the key published at isokron.ai/verify (or the
shipped pin above). LibreSSL (macOS's default `openssl`) lacks raw Ed25519
verification; use OpenSSL 3 (`brew install openssl@3`).

### Re-verifying in later years

TSA certificates expire, and `openssl ts -verify` checks them at the current
time by default. After expiry:

- verify each token at its own genTime against the same pinned roots:
  `openssl ts -verify … -partial_chain -attime <genTime as Unix seconds>` (`VERIFY.md` prints
  the value per token), or `kronicle-lite verify-audit PACK --tsa-at-gentime`;
- keep the pack whole: each token carries its TSA chain and `tsa-roots/` the
  roots, so nothing has to be fetched again;
- before the signing certificates expire, re-stamp the final receipt (an
  archive timestamp) and keep both tokens.
