# Changelog

All notable changes to kronicle-lite. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses semantic versioning once past 0.x.

## [0.2.0] — 2026-10-31

Small additive release so a companion projection ([sea-lite](https://github.com/rafe-walker/sea-lite),
a fenced work queue) can share the same SQLite file and chain cleanly.

### Added

- `Chain.findByIdempotencyKey(key)`: look up the event previously appended
  under an idempotency key, so a caller that mutates projection rows before
  its append can detect a replay up front.
- `Db` and `Opened` types exported from the package root.

### Changed

- Default volume-rollup set now also covers `sea_ticket.claimed`,
  `sea_ticket.claim_released` and `sea_ticket.claim_expired`, so claim churn
  from a shared work queue does not dominate `get_system_state` deltas.
  `sea_ticket.claim_force_released` stays enumerated.
- CLI and server now report 0.2.0.

## [0.1.1] — 2026-10-31

### Added

- `mcpName` in package.json and `server.json` for the official MCP Registry.

### Changed

- README: "Beyond one agent" section pointing at IsoKron (isokron.ai).
- package.json normalized by `npm pkg fix` (bin path, repository URL).

## [0.1.0] — 2026-10-31

First public release.

### Added

- Hash chain: RFC 8785 canonical envelope, SHA-256 event hashes, public
  genesis, single-writer append with compare-and-swap and idempotency keys.
- Signed Merkle checkpoints over seq ranges (Ed25519, local server key).
- `verify_chain`: recompute every hash and link, report first mismatch,
  validate checkpoints.
- Documents → revisions → blocks with BLAKE3 content addresses;
  `put_document`, `supersede_block`, `tombstone_block`; deterministic
  Markdown splitter; recursive supersession walk.
- `recall` over SQLite FTS5 (bm25) with receipt v2 bound to the chain head.
- `verify` for receipts: `VERIFIED | SUPERSEDED | TOMBSTONED | UNVERIFIED`
  with a closed reason enum.
- Orient protocol: HMAC cursors (full and compact), typed delta fold with
  budget demotion, retraction classifier, drift banner (≥100 events or ≥4h),
  stale-write advisory, flight recorder, cursor recovery ladder.
- `audit_assumptions`: grade claims about blocks, documents and the chain
  head as `current | stale | contradicted | retracted | unknown`.
- MCP server over stdio (`@modelcontextprotocol/sdk`) with nine tools and a
  `kronicle://docs/{slug}` resource template.
- CLI: `serve`, `verify-chain`, `checkpoint`, `export`, `import`, `keys`,
  `put`, `orient`.
- `skills/orient/SKILL.md` wake protocol; client config examples.
- `docs/FORMAT.md` with worked hash examples; `docs/THREAT-MODEL.md`.
