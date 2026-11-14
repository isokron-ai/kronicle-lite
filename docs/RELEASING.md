# Releasing kronicle-lite

kronicle-lite is the verifier a buyer runs against an Evidence Pack, so every published version
must be traceable to a tagged commit of this repository. Releases are published by
`.github/workflows/release.yml` with **npm trusted publishing** (OpenID Connect, no npm token) and
an npm **provenance** attestation. Nobody publishes from a laptop.

## One-time setup (owner, in the npm and GitHub web UIs)

These steps need the package owner's npm account and repository admin rights; the workflow
cannot do them.

1. **GitHub environment.** Repository → Settings → Environments → New environment
   `npm-publish`.
   - Required reviewers: the owner (so a pushed tag waits for an approval before it publishes).
   - Deployment branches and tags: "Selected branches and tags", add the tag rule `v*.*.*`.
   - Add no secrets to it.
2. **npm trusted publisher.** npmjs.com → package `kronicle-lite` → Settings →
   Trusted Publisher → GitHub Actions:
   - Organization or user: `isokron-ai`
   - Repository: `kronicle-lite`
   - Workflow filename: `release.yml`
   - Environment name: `npm-publish`

   All fields are case-sensitive, and npm checks them only at publish time. **A new trusted
   publisher expires if it has not published within 2 days**, so add it when the first release
   is ready to tag (after steps 1 and 3), not earlier. An expired one has to be deleted and
   added again.
3. **Protect the tags.** Repository → Settings → Rules → Rulesets → new tag ruleset for
   `v*.*.*`: restrict creation, update and deletion to the owner.
4. **After the first release from the workflow succeeds** (and only then):
   - npmjs.com → package → Settings → Publishing access: choose
     "Require two-factor authentication and disallow tokens", so the trusted publisher is the
     only way to publish;
   - revoke any npm automation or publish tokens that were used for earlier releases
     (npmjs.com → Access Tokens).

A dry run needs none of the above: Actions → release → Run workflow builds, tests and packs on
the chosen branch and prints the tarball's integrity in the job summary. A manual run never
publishes; only a pushed `vX.Y.Z` tag does.

The standalone verifier (`packages/verify`, once merged) has its own workflow,
`release-verify.yml`, with its own tags (`verify/vX.Y.Z`), environment (`npm-publish-verify`)
and npm trusted publisher. `release.yml` and `v*.*.*` do not match those tags.

## Each release

1. On a branch, bump the version everywhere `test/release.test.ts` checks (package.json, the
   lockfile, server.json, `src/version.ts`, `src/catalog-pin.ts`, the catalog snapshots), date
   the CHANGELOG entry (`## [X.Y.Z] — YYYY-MM-DD`), and update the README and docs pins. Merge
   the PR with CI green.
2. Tag the merge commit and push the tag:
   ```sh
   git tag -s vX.Y.Z -m "kronicle-lite X.Y.Z"   # or -a if you do not sign tags
   git push origin vX.Y.Z
   ```
3. The workflow runs:
   - `verify` (no token): the tag names package.json's version, the CHANGELOG entry is dated and
     package.json's `repository.url` names this repository (`scripts/release-check.mjs tag`);
     then lint, typecheck, the test suite and the catalog check; then `npm pack` of the tested
     build, its integrity, `npm publish --dry-run`, and the tarball handed on as an artifact.
     Dependency install scripts run only in this job;
   - `publish` (waits for the `npm-publish` approval; holds the OIDC token): npm 11.5.1+ on
     Node 22.14.0+, the tag check again, a check that the downloaded tarball has the integrity
     `verify` recorded, `npm publish <tarball> --provenance --ignore-scripts`, then a check that
     the registry serves the same integrity with a provenance attestation. It installs no
     dependencies. The job summary shows the integrity.
4. Approve the `npm-publish` deployment when the `verify` job is green.

## After a release

- Check the attestation and the integrity:
  ```sh
  npm view kronicle-lite@X.Y.Z dist.integrity dist.attestations
  mkdir /tmp/kl-check && cd /tmp/kl-check && npm init -y >/dev/null \
    && npm install kronicle-lite@X.Y.Z && npm audit signatures
  ```
  The npm package page also shows "Built and signed on GitHub Actions" with a link to the
  workflow run and the commit.
- Publish the integrity value from the job summary next to the version pin wherever buyers are
  told to run `npx -y kronicle-lite@X.Y.Z verify-audit` (the verify page, the method article,
  `llms.txt`), so a buyer can compare it with `npm view kronicle-lite@X.Y.Z dist.integrity`.

## If the publish step fails

- `E404`/`E403` on publish: the trusted publisher on npmjs.com does not match this workflow
  (organization, repository, workflow file name and environment must all match exactly).
- `E422 … repository.url`: package.json `repository.url` does not name
  `github.com/isokron-ai/kronicle-lite`; the provenance statement names the repository the
  workflow ran in, and npm refuses a mismatch.
- `npm 10.x cannot publish with trusted publishing`: the npm upgrade step did not run.
- `ENEEDAUTH` / "Unable to authenticate": usually the same mismatch as `E404`; npm does not
  validate the trusted publisher form when it is saved, only at publish time. All fields are
  case-sensitive. A new trusted publisher must see its first successful publish within 2 days.

Do not add an `NPM_TOKEN` secret to make a failing publish pass: a token bypasses trusted
publishing and drops the provenance guarantee.
