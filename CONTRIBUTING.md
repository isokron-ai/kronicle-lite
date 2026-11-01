# Contributing to kronicle-lite

Thanks for taking a look. kronicle-lite is small on purpose; contributions
that keep it small are the most welcome.

## Ground rules

- **Apache-2.0.** By contributing you agree your contribution is licensed
  under the Apache License 2.0 (see `LICENSE`).
- **Developer Certificate of Origin (DCO).** Every commit must be signed off
  (`git commit -s`), which adds a `Signed-off-by:` trailer certifying the
  [DCO 1.1](https://developercertificate.org/): you wrote the change or have
  the right to submit it under the project's license. Unsigned commits will
  be asked to be re-pushed with sign-off.
- **No secrets, ever.** No keys, tokens, `.env` files, database URLs or
  fixtures containing real credentials. CI and reviewers will reject them.
- **Format changes are breaking.** Anything that changes how an event hash,
  receipt signature, checkpoint or cursor is computed must bump the relevant
  version tag (`v` on receipts, `sxt1` on cursors, the genesis string) and
  update `docs/FORMAT.md` with a worked example. Old data must still verify.

## Dev loop

```sh
npm install
npm run build      # tsup → dist/
npm test           # vitest
npm run lint       # eslint flat config
npm run typecheck  # tsc --noEmit
```

Run the server against a scratch data dir:

```sh
node dist/cli.js serve --data-dir /tmp/kl-dev
```

The MCP catalog is pinned twice: `.mcp-catalog/kronicle-lite.json` (CI runs
`npm run catalog:check`) and `CATALOG_FINGERPRINT` / `CATALOG_VERSION` in
`src/catalog.ts` (what `doctor` compares the running build against). After a
deliberate tool change run `npm run build && npm run catalog:snapshot`, copy
the printed `sha256` into `src/catalog.ts`, and explain the drift in
CHANGELOG; `test/doctor.test.ts` fails until all three agree.

## Pull requests

- One logical change per PR. Tests for anything that touches the chain,
  receipts, verification or cursor code paths.
- Explain in the PR body what an attacker could do before your change that
  they cannot do after (or vice-versa) if you touch verification.
- Keep dependencies minimal. New runtime dependencies need a reason.

## Reporting security issues

Please do not open a public issue for a suspected integrity or signature
bypass. Email the maintainer (see `package.json`) with details and a
reproduction; you will get a response within a few days.
