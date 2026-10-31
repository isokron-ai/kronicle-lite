# Roadmap

Things deliberately left out of v0.1, roughly in the order they are likely
to land. Open an issue if one matters to you.

## Next

- **`audit_assumptions {claims:[{symbol, value}]}`** — grade a list of beliefs
  against the chain (`current | stale | contradicted | unknown`) and return
  the reconciliation line for each. The orient skill already describes the
  discipline; this makes it a tool call. Stub only in v0.1.
- **HTTP transport** — Streamable HTTP alongside stdio, for clients that
  cannot spawn a process, with a bearer token read from the data dir.
- **Remote checkpoint anchoring** — push signed Merkle roots to somewhere
  the local box cannot rewrite (a gist, an S3 object with object lock, a
  transparency log). This is the step that turns local integrity into
  evidence; see `docs/THREAT-MODEL.md`.
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
