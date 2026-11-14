# IsoKron Evidence Pack: isokron-sample-2026-11

Tamper-evident, independently timestamped audit evidence. Every check below runs offline on
this directory. The one-command route uses kronicle-lite (open source); the raw route uses only
`shasum` / `openssl` / `jq`.

- Manifest SHA-256: `45905afc920359eaac8516bd57f0a056b6d216267d08b80110d804df29000587`
- Signing key: `ed25519-d70b311bf6e25c0c (compare its SPKI SHA-256 with the fingerprint in your report or SOW)`
- Final anchored root: `e5f727cfe1462aa4a7c7dd3f3d82c0c87eaf5c221450a0ac398560f33e71a863`
- Claims: integrity, chain, receipts, independent_timestamps, harness_frozen_before_runs, run_sequence

This file does not carry the auditor key fingerprint: take it from your report or statement of
work, and compare `auditor-key.pem` with it before you rely on anything else here.

## One command

```sh
npx -y kronicle-lite@0.10.1 verify-audit . --key-fingerprint <the auditor key fingerprint from your report or SOW>
```

It pins the auditor key by the fingerprint you give it, verifies SHA256SUMS before it reads
`claims.json`, always checks integrity and chain, then the claims in `claims.json`, and prints
PASS or FAIL for each with its evidence, then the values to compare with the report. Exit 0 means
every checked claim passed.

## Without kronicle-lite

Needs OpenSSL 3 (macOS: `brew install openssl@3`; LibreSSL lacks raw Ed25519 verification) and `jq`.

### 1. Files: SHA256SUMS and its signature

```sh
# the auditor key signed SHA256SUMS (raw Ed25519 signature)
openssl pkeyutl -verify -pubin -inkey auditor-key.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
# every file matches its line (either command)
shasum -a 256 -c SHA256SUMS
sha256sum -c SHA256SUMS
# one file by hand
openssl dgst -sha256 bundle/manifest.json
```

`bundle/manifest.json` also lists the SHA-256 of `events.jsonl` (`events_sha256`) and of every
artifact in `bundle/blobs/` (each file is named by its own SHA-256).

### 2. Independent time: each RFC 3161 token

Each token stamps the SHA-256 of its receipt file and embeds the timestamp authority's certificate
chain. `tsa-roots/` holds the pinned timestamping CAs (not the general public roots):
`sectigo.pem` is Sectigo Public Time Stamping Root R46 as issued by USERTrust RSA Certification
Authority (the form Sectigo's tokens embed), `digicert.pem` the DigiCert Trusted G4 TimeStamping
CAs. `-partial_chain` lets openssl stop at a pinned CA that is not self-signed. Check the
fingerprints against the authorities' sites (`openssl crl2pkcs7 -nocrl -certfile tsa-roots/digicert.pem | openssl pkcs7 -print_certs -noout`,
then `openssl x509 -noout -fingerprint -sha256` on each).

```sh
D=$(shasum -a 256 anchors/01-harness-frozen.receipt.json | cut -c1-64)
openssl ts -verify -digest $D -in anchors/01-harness-frozen.digicert.tsr -CAfile tsa-roots/digicert.pem -partial_chain
openssl ts -verify -digest $D -in anchors/01-harness-frozen.sectigo.tsr -CAfile tsa-roots/sectigo.pem -partial_chain
openssl ts -reply -in anchors/01-harness-frozen.digicert.tsr -text | grep 'Time stamp'
D=$(shasum -a 256 anchors/02-run-completed.receipt.json | cut -c1-64)
openssl ts -verify -digest $D -in anchors/02-run-completed.digicert.tsr -CAfile tsa-roots/digicert.pem -partial_chain
openssl ts -verify -digest $D -in anchors/02-run-completed.sectigo.tsr -CAfile tsa-roots/sectigo.pem -partial_chain
openssl ts -reply -in anchors/02-run-completed.digicert.tsr -text | grep 'Time stamp'
D=$(shasum -a 256 anchors/03-report-issued.receipt.json | cut -c1-64)
openssl ts -verify -digest $D -in anchors/03-report-issued.digicert.tsr -CAfile tsa-roots/digicert.pem -partial_chain
openssl ts -verify -digest $D -in anchors/03-report-issued.sectigo.tsr -CAfile tsa-roots/sectigo.pem -partial_chain
openssl ts -reply -in anchors/03-report-issued.digicert.tsr -text | grep 'Time stamp'
```

### 3. Anchor receipts: Ed25519 signatures

The anchor service signed each receipt over its canonical JSON without `signature`; the
checkpoint inside it is signed by the auditor key. With `jq -cjS` (sorted keys, compact, no
trailing newline) the bytes equal the canonical form for these ASCII, integer-only objects.

```sh
R=anchors/01-harness-frozen.receipt.json
# anchor service countersignature (key from anchor-keys.json; compare it with isokron.ai/verify)
jq -r --arg k "$(jq -r .service_key_id $R)" '.keys[] | select(.key_id == $k) | .public_key_pem' anchor-keys.json > service-key.pem
jq -cjS 'del(.signature)' $R > receipt-body.bin
jq -r .signature $R | openssl base64 -d -A > receipt.sig
openssl pkeyutl -verify -pubin -inkey service-key.pem -rawin -in receipt-body.bin -sigfile receipt.sig
# auditor checkpoint signature
jq -cjS '.checkpoint | {v, from_seq, to_seq, leaf_count, root}' $R > checkpoint-body.bin
jq -r .checkpoint.signature $R | openssl base64 -d -A > checkpoint.sig
openssl pkeyutl -verify -pubin -inkey auditor-key.pem -rawin -in checkpoint-body.bin -sigfile checkpoint.sig
```

Recomputing each anchored root from `bundle/events.jsonl` follows kronicle-lite docs/FORMAT.md §2
(leaf = sha256 of the canonical `{seq, this_hash}`, node = sha256(left ‖ right), an odd node is
promoted); `verify-audit` does it for you.

## Re-verifying in later years

Timestamp authority certificates expire, and `openssl ts -verify` checks them at the current time
by default. After expiry, verify each token at its own genTime against the same pinned roots:

```sh
openssl ts -verify -digest $(shasum -a 256 anchors/01-harness-frozen.receipt.json | cut -c1-64) -in anchors/01-harness-frozen.digicert.tsr -CAfile tsa-roots/digicert.pem -partial_chain -attime 1794233240   # 2026-11-09T14:07:20.000Z
openssl ts -verify -digest $(shasum -a 256 anchors/01-harness-frozen.receipt.json | cut -c1-64) -in anchors/01-harness-frozen.sectigo.tsr -CAfile tsa-roots/sectigo.pem -partial_chain -attime 1794233239   # 2026-11-09T14:07:19.000Z
openssl ts -verify -digest $(shasum -a 256 anchors/02-run-completed.receipt.json | cut -c1-64) -in anchors/02-run-completed.digicert.tsr -CAfile tsa-roots/digicert.pem -partial_chain -attime 1794233244   # 2026-11-09T14:07:24.000Z
openssl ts -verify -digest $(shasum -a 256 anchors/02-run-completed.receipt.json | cut -c1-64) -in anchors/02-run-completed.sectigo.tsr -CAfile tsa-roots/sectigo.pem -partial_chain -attime 1794233244   # 2026-11-09T14:07:24.000Z
openssl ts -verify -digest $(shasum -a 256 anchors/03-report-issued.receipt.json | cut -c1-64) -in anchors/03-report-issued.digicert.tsr -CAfile tsa-roots/digicert.pem -partial_chain -attime 1794233249   # 2026-11-09T14:07:29.000Z
openssl ts -verify -digest $(shasum -a 256 anchors/03-report-issued.receipt.json | cut -c1-64) -in anchors/03-report-issued.sectigo.tsr -CAfile tsa-roots/sectigo.pem -partial_chain -attime 1794233248   # 2026-11-09T14:07:28.000Z
```

or `kronicle-lite verify-audit . --key-fingerprint <fingerprint> --tsa-at-gentime`. Keep this directory
whole: the tokens carry the TSA chains and `tsa-roots/` the roots they verify against.
