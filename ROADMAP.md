# Roadmap

Things deliberately left out so far, roughly in the order they are likely
to land. Open an issue if one matters to you.

## Shipped

- **0.3.0 — MCP 2026-07-28 + SDK v2; HTTP transport.** Streamable HTTP
  (`serve --http`, loopback, bearer from the data dir), `server/discover`,
  `outputSchema`/`structuredContent` on every tool, cache hints, catalog
  drift gate. stdio stays dual-era for 2025 `initialize` clients.
- **0.4.0 — off-box anchoring, chained instructions, git-aware blocks,
  doctor.** `checkpoint --push` / `verify --remote` / `anchor status` and
  the `anchor_status` tool (client side; the service is not live yet);
  `watch` and `put --from-instructions` with retraction kind
  `instruction`; `bind_git` with `STALE_SOURCE` / `stale_source` and a
  Source drift section; `kronicle-lite doctor`; Windows CI.
- **0.5.0 — integrity and diet.** Every read re-hashes the text it serves
  (tampered text is withheld), project-keyed instructions, retractions with
  old/new text, `demo`, `rebuild`, tools/list 43 KB → 12 KB.
- **0.6.0 — honest labels.** `can_act / inspect_only /
  never_act` on every recall hit (block-level evidence only for
  `can_act`), honest absence, attention rerank, secret guard on every write
  path with an independent read-time scrub, `serve --core`, recall content
  caps. See docs/HONESTY.md.
- **0.7.0 — never hide a real change.** Format-only edits (whitespace,
  reflow, emphasis, list markers) stay quiet; every other change is a
  retraction (38-case adversarial corpus, property and mutation tests).
  Section moves retract; corrupt events report `integrity.ok=false`;
  project-scoped recall; decision text through compaction; one-line
  "nothing changed"; atomic first start (Linux, macOS, Windows);
  docs/PUSH.md hook contract.
- **0.8.0 — derived notes, version-bound reconciliation, exec-time
  shims.** Notes record the block versions they rest on (`derived_from`,
  inferred from the author's session reads) and go `never_act` /
  `stale_derived` when a source changes (Track A S1 next-session stale
  copy 20/20 → 0/20); `pending`: a change stays open for an actor until it
  re-reads the current version; `kronicle-lite shim install` wrappers check
  `git push` / `terraform apply` / `kubectl apply` / `npm publish` at exec
  time in any client, cleared by that re-read (`shim ack` as override).
- **0.8.1 — raw text is what agents copy.** Format-only = raw-text
  equivalence (line endings, trailing whitespace, reflow, blank lines); glob
  `*`↔`_`, renumbered ports and hard breaks retract (hardening round 2,
  R2-01..03); block reorders within a section retract; `## Use C#` keeps its
  `#`; lineage inference spans the cursor chain; staleness memo, typo-hint
  and long-diff fixes.

## Next

*Top of the queue (2026-11-01), from the agent-memory-bench results and two
external review rounds:*

- **Track B gate on `pending_count`** — a live-agent variant that gates
  `deploy` on `pending_count` (hook) and on the shims' version-bound check,
  to measure retractions missed under compaction end to end.
- **Typed assertions** — `assert(key, value, scope, source)` and
  `check_conflicts(keys)`: same key and scope, different value. The tractable
  start of contradiction detection (Track A S2: 0/140 for every tool).

- **Anchor service launch and inclusion proofs** — deploy the hosted
  service, then `prove --seq N` (a proof bundle: receipt v2 + checkpoint +
  Merkle inclusion path) and refreshing `anchors` with published day roots
  (`day`, `leaf_index`, `path_json` are already in the table).
- **Consistency proofs between anchors** — show that `[1..N+k]` extends an
  earlier `[1..N]`, which a v1 countersignature cannot.
- **Git binding for instruction import** — `put --from-instructions
  --bind-git`, so a CLAUDE.md edited but not yet re-imported shows up as
  Source drift too.
- **Richer `audit_assumptions` symbols** — grades block ids, document
  slugs and the chain head today. Next: `slug#heading` paths and free-text
  claims matched through recall.
- **HTTP hardening for shared boxes** — per-token actor binding, token
  rotation without restart, optional mTLS. The 0.3.0 HTTP mode is a
  single-tenant base (one token = the whole store), on purpose.
- **Semantic recall** — optional embedding index next to FTS5 (sqlite-vec),
  same receipt shape.

## Later

- **Tickets** — small, chain-backed work items (`ticket.opened`,
  `ticket.closed`, `ticket.retracted`) so an agent's TODO list gets the same
  supersession and retraction treatment as its notes.
- **Document tombstone / rename** — whole-document retirement and slug
  changes as first-class events.
- **Key rotation** — rotate the server key, keep old public keys
  verifiable, mark the old one `rotated` rather than `revoked`.
- **Projection rebuild command** — `kronicle-lite rebuild` to recompute
  documents/blocks from events in place without export/import.
- **Replay check** — re-fold stored flight-recorder briefings and flag any
  whose recomputed delta hash differs (detects fold-logic drift).
- **Multi-actor etiquette** — per-actor write counts and "who changed this"
  in the delta rollups.

## Not planned

- Multi-tenant auth, RLS, OAuth. Run one data dir per trust domain.
- Compatibility with any other chain or receipt format. The format in
  `docs/FORMAT.md` is kronicle-lite's own.
