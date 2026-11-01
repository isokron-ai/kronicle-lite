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

## Next

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
