# @isokron/verify

Check an IsoKron Evidence Pack offline with one file: `verify.mjs`, about 250 KB of readable
JavaScript. It needs Node.js 22 or later and nothing else. There are no dependencies, no native
code and no network access (it imports only `node:crypto`, `node:fs`, `node:os`, `node:path` and
`node:zlib`).

It runs the same checks as `kronicle-lite verify-audit`, prints the same report and exits with the
same codes, because it is built from the same source files
([`src/audit/verify-audit.ts`](../../src/audit/verify-audit.ts) and what it imports). You do not need
to install `kronicle-lite`, its SQLite binding or the MCP SDK.

> The package name `@isokron/verify` is set once, in `package.json` `name`. The workflow and the
> release checks read it from there, and `test/package.test.ts` fails if this README or the workflow
> names another package.

## Run it

Take the auditor key fingerprint from your signed statement of work. Never take it from the pack or
the report.

**The single file** (from the GitHub release, tag `verify/vX.Y.Z`):

```sh
curl -LO https://github.com/isokron-ai/kronicle-lite/releases/download/verify/v0.1.0/verify.mjs
echo '<sha256 from the release notes>  verify.mjs' | shasum -a 256 -c -
gh attestation verify verify.mjs --repo isokron-ai/kronicle-lite   # optional: built by the release workflow from that tag
node verify.mjs PACK --key-fingerprint <SHA-256 from your statement of work>
```

You can read the whole file before you run it. Its header names the commit it was built from and
every source file in it.

**From npm** (published with trusted publishing and a provenance attestation):

```sh
npx -y @isokron/verify@0.1.0 PACK --key-fingerprint <SHA-256>
npm view @isokron/verify@0.1.0 dist.integrity dist.attestations   # compare with the verify page
```

**From source**: `git checkout verify/v0.1.0 && npm ci && npm run verify:build` writes
`packages/verify/dist/verify.mjs`. The build is deterministic, so its SHA-256 matches the released
file. That is how you check that the file came from the public source.

`node verify.mjs verify-audit PACK …` also works, so a `kronicle-lite verify-audit` command line can
be reused as it is.

## Exit codes and results

| exit | result | meaning |
|---|---|---|
| 0 | `RESULT: VERIFIED` | every claim was checked and passed |
| 0 | `RESULT: VERIFIED WITH UNWITNESSED WINDOW (FREEZE ANCHORED LATE)` | as above, but the freeze was anchored after the fact; the report prints the window that no third party witnessed |
| 1 | `RESULT: FAILED` / `NOT VERIFIED` | a check failed, or a claim the pack declares was not checked |
| 2 | `RESULT: PARTIAL` | a pack made before kronicle-lite 0.11.0 (formats `/1`, `/2`) under `--profile legacy`: every check that ran passed, but the audit profile was not met |
| 2 | (usage) | bad arguments, an unreadable pack, or a trust input inside the pack |

`--json` prints the report as `kronicle-lite-verify-audit/3`. A consumer that must accept only a
plain pass checks `.verdict == "verified"`.

Pack formats: `kronicle-lite-evidence-bundle/3` (kronicle-lite 0.11.x) and `/4` (`/3` with the
OAuth evidence kinds, kronicle-lite 0.12.0) under the default audit profile. Formats `/1` and `/2`
(0.10.x) need `--profile legacy` and give PARTIAL at best.

## What it checks

In order, failing closed at every step:

1. **The auditor key is pinned out of band** (`--key-fingerprint`, or `--key FILE` from outside the
   pack). An unpinned key is a FAIL.
2. **`integrity`**: `SHA256SUMS` lists every file, its Ed25519 signature verifies under the pinned key,
   and no file is missing or extra. Then the evidence bundle: the canonical manifest, its signature,
   every event against its schema, every artifact against its hash, and every reference.
3. **`chain`**: the events form one hash chain with the signed Merkle root.
4. **`receipts`**: the anchor service key list is one signed chain from the genesis pin compiled in
   (or `--genesis`), and is not a rollback of a list this machine has seen. Each anchor receipt is
   countersigned by a key that was valid then, commits the auditor-signed checkpoint, and its root
   equals the root recomputed from the bundle.
5. **`independent_timestamps`**: every receipt, and `SHA256SUMS` itself, has RFC 3161 tokens from two
   different pinned TSA CAs (Sectigo, DigiCert) over its exact bytes. The CMS signatures, ESS
   certificate binding, certificate paths and key usages are all checked.
6. **`harness_frozen_before_runs`**: the freeze is committed by a timestamped anchor that covers no
   run, and every run carries the freeze nonce, which can only be computed after the freeze.
7. **`run_sequence`**, **`plan_complete`**, **`reproductions_signed`** (an SSH signature by a person
   who is not the auditor) and **`closed`**.

[`docs/EVIDENCE-BUNDLE.md`](../../docs/EVIDENCE-BUNDLE.md) has every rule.

## What it does not prove

- **It shows nothing was edited after the freeze. It cannot show there were no exploratory runs
  before it.** The freeze is the first point a third party witnessed. Whatever the auditor tried
  before then is outside the record.
- It does not show that a finding is correct. The report's reproduction steps do that, and
  `reproductions_signed` only shows that a named person signed that they reproduced it.
- It trusts what you pin: the auditor key fingerprint from your statement of work, the TSA CAs it
  ships with, and the anchor service's genesis key. A pack signed by a different key fails, whatever
  the pack says about itself.
- Rollback protection is local. The verifier keeps the newest anchor key list it has seen per genesis
  pin in `anchor-keys.seen.json` in its data dir (`--data-dir`, else `$KRONICLE_LITE_DATA_DIR`, else
  `~/.kronicle-lite`, the same file `kronicle-lite` uses). On a machine that has seen no list, the
  pack's own list is recorded, not compared.

## Key rotation (`keyListRegression`)

An Evidence Pack carries the anchor key list that was current when it was made. Up to kronicle-lite
0.11.2, once a machine had seen a newer list (after a planned rotation, R retired and S added), an
honest older pack failed with "key list rollback": S was missing from the pack's list.

Now, when the kept list is a lawful later state of the pack's list (the same keys, changed only by
a later rotation, retirement or revocation), that is not a rollback. The receipts are checked
against the kept list, which is the stronger of the two. A key retired since then needs a verified
TSA time inside its window, and a key revoked since then needs one before `compromised_since`
minus 5 minutes. A list that changes a kept key or forks the chain is still a rollback. Each receipt must still be
signed by a key the pack's own list names. `trust.rollback.list_used` (`given` or `seen`) and the
`service keys` and `key list` lines of the report say which list was used.

One consequence: on a machine that has seen the newer list, such an older pack fails under
`--no-tsa`. Its signing key is retired in the kept list, and a retired key's receipt counts only with
a verified TSA time. On a machine that has seen no newer list, the same pack passes under `--no-tsa`.

The fix is in the shared source, so `kronicle-lite verify-audit` behaves the same way.

## How "the same results" is shown

`npm run verify:test` (from the repository root, after `npm ci`) runs:

- **`test/differential.test.ts`** (parity): `node verify.mjs` and `kronicle-lite verify-audit` on the same
  packs with the same arguments and the same data dir. stdout (text and `--json`), stderr (up to the
  program name), the exit code and the rollback cache must all be identical. The packs are one of each
  format (`/1`, `/2`, `/3`, `/3` with a late-anchored freeze, `/4` with OAuth events) made by kronicle-lite, the published
  sample pack, eight tampers of each, the usage errors, the rollback cache, and the rotation case.
  `KL_VERIFY_EXTRA_PACKS=list.json` adds packs from disk. Both tools run the same `verify-audit.ts`,
  so this shows the standalone build changes nothing. Whether verify-audit's verdicts are right is
  tested by kronicle-lite's own suite (`test/verify-audit*.test.ts`).
- **`test/shims.test.ts`**: the three replaced modules (zod, canonicalize and @noble/hashes, all in
  `src/shims/`) give the same results as the packages on a corpus of valid and mutated inputs: every
  payload schema, `claims.json`, canonical JSON and SHA-256.
- **`test/package.test.ts`**: no dependencies, the exact tarball contents, only `node:` imports, no
  network or dynamic code, and a byte-identical rebuild.

## Publishing (owner setup, once)

Nothing publishes until all of this is done. `.github/workflows/release-verify.yml` does not run
before step 5. Once it does run, Actions → release-verify → Run workflow is a dry run: it builds,
tests and packs, and publishes nothing. Only a pushed `verify/vX.Y.Z` tag publishes.

1. **npm scope.** The `@isokron` organization on npmjs.com must exist and own the name in
   `package.json` (`@isokron/verify`).
2. **npm trusted publisher.** npmjs.com → package `@isokron/verify` → Settings → Trusted Publisher →
   GitHub Actions:
   - Organization or user: `isokron-ai`
   - Repository: `kronicle-lite`
   - Workflow filename: `release-verify.yml`
   - Environment name: `npm-publish-verify`

   If npmjs.com only offers this for a package that already exists, see "First publish" below.
   npm's trusted-publisher page (read 14 Nov 2026) also said a new configuration must complete its
   first publish within 2 days. Check that against the npm UI, and set the publisher up right before
   the first tag.
3. **GitHub environment.** Repository → Settings → Environments → `npm-publish-verify`: required
   reviewer = the owner; deployment branches and tags = selected, tag rule `verify/v*.*.*`; no
   secrets.
4. **Tag ruleset.** Repository → Settings → Rules → Rulesets: restrict creating, updating and
   deleting `verify/v*.*.*` tags to the owner.
5. **Turn the workflow on.** Repository → Settings → Secrets and variables → Actions → Variables →
   `VERIFY_NPM_TRUSTED_PUBLISHER` = `configured`.
6. **After the first release succeeds:** npmjs.com → `@isokron/verify` → Settings → Publishing
   access → "Require two-factor authentication and disallow tokens".

**First publish.** npm trusted publishing is set up in the package's settings. If the npm UI does
not offer it before the package exists, the owner can publish `0.0.0` by hand once to reserve the
name (`npm publish --access public` from `packages/verify` after `npm run verify:build`, with 2FA),
and then do steps 2 to 6. Every later version then comes only from the workflow.

**Each release.** Bump `version` in `packages/verify/package.json` in a PR and merge it with CI green.
Then `git tag -s verify/vX.Y.Z && git push origin verify/vX.Y.Z` and approve the
`npm-publish-verify` deployment. The workflow works in three jobs:

- The `build` job holds no token. It installs, runs the verifier's tests, builds `verify.mjs` and
  packs it.
- The `publish` job installs nothing. It checks that the artifact is what `build` packed, attests
  `verify.mjs`, publishes the tarball with `--provenance`, and checks that the registry serves the
  packed integrity with a provenance attestation.
- The `github-release` job creates the GitHub release with `verify.mjs` and its SHA-256.

The `verify/` tag prefix keeps this separate from kronicle-lite's own `vX.Y.Z` releases
(`release.yml`). Neither workflow matches the other's tags.
