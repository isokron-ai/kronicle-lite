# `apply`: transactional batch writes with preview (0.9.0)

`apply` runs up to 50 `put` / `supersede` / `tombstone` ops against the local
store. Source: `src/apply/apply.ts`.

- **`all_or_nothing` (default).** kronicle-lite is one SQLite file, so this is
  a real transaction: every op lands, or none does, and nothing needs
  compensating. Every op runs in order. The first failure stops the plan and
  rolls everything back: earlier ops report `rolled_back`, later ones
  `not_run`.
- **`best_effort`.** Each op runs in its own savepoint. A failed op leaves no
  partial rows; the ops that succeeded are committed.

**One chain event per commit.** Each commit writes one `apply.committed`
event carrying `plan_hash`, `result_hash`, the mode, the policy version, any
`idempotency_key` / `confirm_nonce`, and per-op status, target, version and
receipt. The receipt is the op's chain seq range and the last hash. The ops'
own `document.*` / `block.*` events land in the same transaction.

## expect_version

`expect_version` is the document revision the op expects; `0` means the
document must not exist. When the current revision differs, the op fails with
`version_conflict`, which in `all_or_nothing` rolls back the whole plan.

## dry_run and the confirm token

**`dry_run: true` runs the real writes inside a transaction that is always
rolled back.** The per-op results and diffs are exactly what a commit would do
now, and nothing persists. If the plan would succeed, the preview also returns
a `confirm_token`.

**What the token binds.** The token itself is only a handle,
`klc2.<nonce>.<HMAC(cursor secret, nonce)>`, about 80 characters whatever the
plan size. The binding is kept server-side in `apply_confirmations`, keyed by
the nonce, and covers:

| Field | Meaning |
|---|---|
| `plan_hash` | sha256 of the canonical plan |
| `actor_id` | the actor that previewed |
| `tenant` | the workspace |
| `sandbox` | this chain's id |
| `server` | the target server |
| `catalog_fingerprint` | the pinned MCP catalog |
| `resources` / `versions` | the resource ids and the versions they had at preview |
| `policy_version` | the policy in force at preview |
| `nonce` | per-token random value |
| `exp` | expiry (`ttl_seconds`, default 300, max 900) |
| `idempotency_key` | the request's idempotency key |
| `project` | the project a `put` records (the server's project, as for `put_document`) |

**When the token is required.**
- **After a dry run.** Once a plan has been previewed, committing the same plan
  by the same actor without the token is `confirm_required`, until the preview
  expires.
- **Over HTTP.** `serve --http` sets `requireApplyConfirm`, so every commit
  needs a token. A remote-capable server never commits a batch blind.

**What a commit with the token re-checks.** All of the following happens
inside the commit transaction, so a check and the writes can never be split:

1. The signature and the expiry.
2. Every bound field against the current request and server: a different plan,
   actor, key, store, catalog or policy gives `confirm_mismatch`.
3. **Single use.** The nonce is consumed by the commit. If the token's own
   actor tries a commit and it fails, the token is burned too, so a replay
   gives `confirm_used`. An attempt by another actor is refused
   (`confirm_mismatch`) and does *not* burn the owner's token.
4. **TOCTOU.** The previewed versions of every resource are compared with the
   current ones. Any change gives `stale_plan`; preview again.
5. **Authorization, per op, again.** The token proves a preview happened; it
   authorizes nothing. A policy that denies at commit wins over a valid token
   (`forbidden`).

The default policy (`kl-apply-policy/1`) refuses instruction-file documents
(`instructions/…`, `memory/…`): they mirror files on disk, so edit the file.

## Idempotency

`idempotency_key` stores the committed result.
- **Replay.** The same request from the same actor returns it with
  `replayed: true` and writes nothing.
- **Re-checked inside the transaction.** The actor must match, and the policy
  must still allow every op, because a replay discloses the result.
- **Refusals.** Another actor or a different plan under the same key is
  `idempotency_key_reused`. A revoked actor is `forbidden`.
- **Rollback.** A rolled-back apply stores nothing under its key, so a
  corrected retry can commit.

**The chain key is reserved.** The commit's chain key is
`apply:<sha256(idempotency_key)>`. `put_document` refuses `apply:` and `audit:`
keys. If the chain still returns an existing event under the key (a squatter
that bypassed that check), the apply fails with `idempotency_conflict`.
Nothing is committed, and nobody else's event is ever reported as the
receipt.

## Not in v1

There is no DAG, no `$ref`s between ops, and no remote targets. A dependent
write is a second `apply` that takes the first one's receipts as input.
Inferred lineage is off for apply writes.
