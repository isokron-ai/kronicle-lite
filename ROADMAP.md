# Roadmap

Things deliberately left out so far, roughly in the order they are likely
to land. Open an issue if one matters to you.

## Shipped

- **0.3.0 — MCP 2026-07-28 + SDK v2; HTTP transport.** Streamable HTTP
  (`serve --http`, loopback, bearer from the data dir), `server/discover`,
  `outputSchema`/`structuredContent` on every tool, cache hints, catalog
  drift gate. stdio stays dual-era for 2025 `initialize` clients.

## Next

- **Remote checkpoint anchoring** — push signed Merkle roots to somewhere
  the local box cannot rewrite (a gist, an S3 object with object lock, a
  transparency log). This is the step that turns local integrity into
  evidence; see `docs/THREAT-MODEL.md`. Now that HTTP exists, the natural
  shape is a `checkpoint --anchor <target>` plus a `verify_chain` that
  compares against the remote root.
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
