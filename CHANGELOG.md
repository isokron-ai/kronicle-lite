# Changelog

All notable changes to kronicle-lite. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses semantic versioning once past 0.x.

## [0.4.0] — unreleased

Four additive features. Every 0.3.0 chain verifies byte-for-byte: no hash
recipe, receipt, checkpoint or cursor layout changed; new event payload
fields and tables are optional and old databases gain them on open.

### Added — hosted anchoring

The isokron-anchor client folded in (protocol code copied, not depended
on; kronicle-lite's own DB, key and Merkle code replace the duplicates).

- `kronicle-lite checkpoint --push [--key K] [--url U]`: sign a checkpoint,
  send root + range + signature + public key (never events) to the anchor
  service, verify the countersigned receipt (service key from
  `/.well-known/anchor-keys.json`, field-by-field match with what was sent)
  and store it. Refuses a checkpoint that no longer matches the local rows.
- `kronicle-lite verify --remote [--offline]`: recompute the §2 root for
  every anchored range → `match | diverged | beyond_head | gap`, print
  `local chain diverges from anchor at [a,b]`, exit 1. `--offline` uses the
  stored receipts and `<data-dir>/anchor-keys.cache.json`. `verify` without
  `--remote` is `verify-chain`.
- `kronicle-lite anchor status [--json]`: last anchor, status, events since
  (no network).
- Config: `<data-dir>/config.json {anchor_url, license_key}` (created `0600`
  with the default `anchor_url` on first open), `KRONICLE_ANCHOR_URL`,
  `KRONICLE_ANCHOR_KEY`; flags win.
- Additive `anchors` table (FORMAT §9); `export` appends one
  `{"kronicle_lite_anchors":1, …}` line when anchors exist, `import` skips it.
- MCP: `checkpoint_chain` gains `push` (result gains an optional `anchor`
  outcome; `openWorldHint: true`); new read-only `anchor_status` tool
  (local root vs anchored root, countersignature with cached keys,
  `remote: true` asks the service). `get_system_state` gains `anchor`
  (latest anchor or null) and the Markdown banner a line
  `anchored N events ago (status)` / `never anchored`.
- `Chain.rootOver()`, `latestCheckpoint()`, `getCheckpoint()`,
  `recordAnchor()`, `listAnchors()`, `lastAnchor()`;
  `chainIdFromPublicKeyPem()`; `pushCheckpoint`, `tryPushCheckpoint`,
  `verifyRemote`, `anchorStatus`, `verifyLastAnchor`, `AnchorClient`
  exported.
- The default service (`https://anchor.isokron.ai`) is **not deployed yet**.
  Every remote call fails with `AnchorUnreachableError` ("anchor service
  unreachable at …": refused connection, timeout after 10 s, or a non-JSON
  answer such as a parked-domain 404) and never touches local state;
  `checkpoint --push` keeps the local checkpoint and exits 2.
- Tests: the isokron-anchor client acceptance suite ported (13 cases per
  backend) and run against an in-test HTTP stub of the service; with
  `KRONICLE_ANCHOR_WORKER_DIR` set they also run against the real Worker
  under Miniflare. Plus unreachable-service, config and export cases.

### Added — chained instructions and `watch`

- `kronicle-lite watch [paths…] [--interval MS] [--debounce MS] [--poll]
  [--cwd DIR] [--list [--json]] [--once]`: re-put instruction files when
  they change. `fs.watch` on the containing directories (non-recursive,
  rename-safe) with a debounce, plus a polling pass that rescans the
  patterns (new rule files, new subdirectories, deletions) and catches what
  `fs.watch` misses; `--poll` for polling only. No new dependency.
- Default set: `CLAUDE.md`, `AGENTS.md`, `.claude/rules/**/*.md`,
  `.cursor/rules/**`, and Claude Code's auto memory `MEMORY.md` at
  `<config>/projects/<project>/memory/` — `<project>` derived from the git
  repository's main worktree root (non-alphanumerics → `-`; >200 chars found
  by prefix), with `CLAUDE_CONFIG_DIR`, `CLAUDE_CODE_PROJECT_DIR_NAME` and
  `autoMemoryDirectory` honoured, per code.claude.com/docs/en/memory.md and
  /sessions.md (checked 2026-10-31).
- Deterministic namespaced slugs (`instructions/claude-md`,
  `instructions/claude-rules/<path>`, `memory/MEMORY`, …; FORMAT §3.4).
- A changed instruction is a supersession; orient reports it as a
  retraction of the new kind `instruction` (severity of the underlying
  event; a deleted file tombstones its blocks → `safety`).
- `kronicle-lite put --from-instructions [paths…]`: one-shot import;
  unchanged files append nothing. `--stdin-hook` makes it a Claude Code
  hook: `SessionStart` syncs and answers `watchPaths`, `FileChanged`
  re-puts the changed file; never fails the hook. README documents the
  hook wiring (cc-anchor's `watchPaths`/`FileChanged` shape) as the
  in-Claude-Code way and `watch` as the everywhere-else way.
- `document.put` gains an optional `source {kind, path}` (recorded only
  when given; puts without it hash as before) projected into a new
  `doc_sources` table.
- MCP resources: namespaced slugs are listed percent-encoded
  (`kronicle://docs/instructions%2Fclaude-md`) and decoded on read.
- CLI arg parser: boolean flags never swallow the next positional;
  `--flag=value` accepted.

### Added — git-aware blocks

- `put --bind-git` / `put_document {bind_git: true, source_path}` record
  `{repo_root, commit, path, blob_sha}` for the source file in the
  `document.put` `source.git` field (FORMAT §3.5), via `git rev-parse` and
  `git hash-object` (no libgit2).
- Receipt `verify` gains status `STALE_SOURCE` / reason `stale_source`
  and `audit_assumptions` the verdict `stale_source` when the working-tree
  blob differs from the bound one (or the file is gone), with
  `source_drift` (bound vs working blob, HEAD, diff stat from a built-in
  Myers line diff against `git cat-file` or the stored revision). Only a
  would-be `VERIFIED` / `current` is downgraded. `counts.stale_source`
  appears only when non-zero, so the 0.3.0 counts shape is unchanged.
- `get_system_state` gains `source_drift` (null for pulse); Markdown lists
  drifted documents under "Source drift" and adds a next step.
- Graceful outside git or without git: the put succeeds with a warning and
  no binding; a vanished repository is `unavailable`, not drift.

## [0.3.0] — 2026-11-01

MCP spec **2026-07-28** and the TypeScript SDK **v2**
(`@modelcontextprotocol/server` 2.4, `@modelcontextprotocol/client` 2.4 in
tests). Tool names, descriptions, titles, annotations, input schemas and
the `kronicle://docs/{slug}` resource are unchanged; the wire gains the
fields the new revision requires.

### Added

- **Streamable HTTP transport**: `kronicle-lite serve --http [--port N]
  [--host H] [--bearer T | --bearer-file F] [--allow-origin H] [--allow-host H]`.
  Binds `127.0.0.1:7417/mcp`, validates `Host` and `Origin` against
  loopback, requires `Authorization: Bearer` (token generated into
  `<data dir>/http-bearer.token` with mode `0600`), stateless, POST only,
  2026-07-28 only — a 2025-era `initialize` gets `400` /
  `UnsupportedProtocolVersionError` (`-32022`). Single-tenant trust
  domain; see `docs/THREAT-MODEL.md` → "HTTP transport".
- **`outputSchema` + `structuredContent` on every tool.** Schemas are
  derived from the actual result types (`src/schemas.ts`) and validated
  server-side on every call. The text block is kept for text-only clients;
  `get_system_state` keeps rendering Markdown in the text block and now
  also returns the JSON state as `structuredContent`.
- **`server/discover`** (identity, `supportedVersions: ["2026-07-28"]`,
  capabilities, instructions), `resultType: "complete"` on every result,
  `_meta["io.modelcontextprotocol/serverInfo"]` on every 2026-era result,
  and cache hints: `tools/list`, `server/discover` and
  `resources/templates/list` are `cacheScope: public` with `ttlMs:
  3600000`; `resources/list` and `resources/read` are `private`, `ttlMs: 0`.
- **Catalog drift gate**: `.mcp-catalog/kronicle-lite.json` pins the
  `tools/list` bytes (fingerprint
  `11f99985cdee9ac69e2f746a5ce4592fa239be8018c8018fd33d9e2af2a329d6`);
  `npm run catalog:check` (CI) fails on drift, `npm run catalog:snapshot`
  re-pins deliberately.
- `createServerFactory(store, opts)` export for the SDK serving entries
  (`serveStdio`, `createMcpHandler`); `createServer` still returns a plain
  `McpServer` for embedding.
- README sections for Codex (`~/.codex/config.toml`), GitHub Copilot
  (repo MCP settings, read-only allowlist for code review) and a fuller
  Cursor entry, each cited to the vendor docs at time of writing.
- Tests for the new surface: in-memory 2026-07-28 client, in-memory
  2025-06-18 `initialize` client, built CLI over stdio with auto
  negotiation, raw JSON-RPC era checks (legacy served without 2026
  fields; modern opening gets them; unsupported version → `-32022`), HTTP
  round trip with bearer plus 401/403/404/405 and legacy-refusal cases.

### Changed

- **Dependencies**: `@modelcontextprotocol/sdk` 1.x → `@modelcontextprotocol/server`
  ^2.4.0 + `@modelcontextprotocol/node` ^2.1.2; `zod` 3 → 4
  (`z.uuid()`, `z.iso.datetime()`; the SDK's Standard-Schema path requires
  zod 4 at runtime).
- **stdio serving** now goes through `serveStdio(factory)`: the opening
  message selects the era per connection. A `server/discover` or any
  request carrying the 2026-07-28 `_meta` envelope pins the connection
  modern; an `initialize` pins it legacy and the client is served under
  the version it negotiated (2025-11-25, 2025-06-18, 2025-03-26,
  2024-11-05) with no 2026 fields on the wire.
- Server `instructions` rewritten as one paragraph ≤ 512 characters (the
  window Codex uses), guarded by a test.
- Emitted input schemas now come from zod 4's JSON Schema converter:
  `$schema: 2020-12` is explicit and `additionalProperties: false` is no
  longer emitted. This is the bulk of the catalog fingerprint change.
- `package.json` / `server.json` → 0.3.0.

### Known limits

- The SDK's `server/discover` reports `supportedVersions: ["2026-07-28"]`
  only; legacy revisions are reachable through `initialize`, not listed.
- On a stdio connection already pinned modern, the SDK does not re-check
  the per-request `_meta` protocol version (it is checked on the opening
  request, and on every HTTP request).

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
