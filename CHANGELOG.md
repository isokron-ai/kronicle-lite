# Changelog

All notable changes to kronicle-lite. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses semantic versioning once past 0.x.

## [Unreleased]

Fixes measured by agent-memory-bench Track A (deterministic, 20 seeds per
cell; before = 0.6.0, after = this branch). Additive: no hash recipe,
receipt, checkpoint, cursor or event layout changed; new payload and result
fields are optional; one local column (`documents.project_key`) is added and
backfilled on open.

### Fixed — formatting edits no longer cry wolf (bench S7: 20% → 100% quiet)

- Orient classifies every supersession as cosmetic or semantic
  (`src/orient/cosmetic.ts`, rules in docs/FORMAT.md §3.8). Cosmetic:
  whitespace, line endings, reflow, quote and dash style, trailing
  punctuation, emphasis markers, list markers, intra-word hyphens, case, a
  one-letter typo in an ordinary word (two for 8+ letters), the date on a
  "Last reviewed / updated" line. Never cosmetic: anything in a code span or
  code block, any number / host / path / URL / flag / identifier (changed
  or reordered), negations and other meaning-bearing words, ordinary word
  swaps, added or removed words.
- Cosmetic edits are listed under `cosmetic_edits` and not in
  `retractions`, so they are not "reconcile before acting" and a push hook
  does not push them. They stay on the chain and queryable:
  `include_cosmetic: true` (`--include-cosmetic`) lists them as
  `informational` retractions with `cosmetic: [rules]`. The Markdown says
  "N cosmetic edit(s) recorded … no action needed" and the delta shows them
  as `cosmetic edit`.

### Fixed — a moved file is a rename, not a removal (S8: 75% → 100%)

- When an instruction file moves inside its project with its content
  intact, the sync appends `document.renamed` and a put recording the new
  path with every block carried: same `doc_id` and block ids, receipts keep
  verifying, no "REMOVED — stop following it" safety retraction. Works
  whichever path the FileChanged hook / watcher syncs first. A real
  deletion (no intact copy, or an ambiguous one) still retires the blocks.
  New sync action `renamed` (`renamed_from`).

### Fixed — decisions survive compaction as text (S4a: 0% → 100%)

- `get_system_state` (focus `orientation` / `recent_changes`) carries back
  the orienting actor's own notes written since its cursor
  (`carried_notes`, Markdown "Your notes since seq N"): up to 3 documents,
  600 characters each, 1500 in total, integrity-checked and secret-scrubbed.
  Other actors' notes are not inlined. A note that copies an identifier a
  retraction in the same briefing changed is marked ("this note repeats
  `X`, changed at seq N").

### Fixed — one repository's notes no longer leak into another (S11: 50% → 100%)

- Documents record their project: `put_document` and CLI `put SLUG FILE`
  add `project: {key, root}` (the server's / CLI's working directory, same
  key as instruction slugs) to the `document.put` payload; instruction
  files already carry `source.project`. Projected into
  `documents.project_key`.
- `recall` searches this project's documents plus unscoped ones by default
  (`scope.other_projects_hidden`, `absence.not_searched: other_projects`);
  `all_projects: true` opts out. `get_system_state` leaves other projects'
  events out of the delta and digest (`scope.hidden_events`) and their
  retractions out of `retractions` (was: instruction retractions only).
  Documents written before this release have no project and stay visible
  everywhere, so a single-repo store behaves as before.

### Fixed — concurrent first start (S3d)

- The signing key, cursor secret and HTTP bearer are created with
  `link(tmp, path)` (create-if-absent with the full content); EEXIST re-reads
  the winner; a short or invalid file is re-read for up to 2 s before it is
  reported corrupt; a concurrent `mkdir` of the data dir is tolerated.
  Before: 50 processes on a fresh data dir could crash on a half-written
  `cursor-secret` (sea-lite, 1/20 bench seeds) or end up signing with
  different keys (1–2 of 20 stress trials of 50 processes). After: 0
  crashes and one identity in 1000 concurrent starts (20 × 50).

### Changed — response diet

- With a verified cursor and nothing new, `get_system_state` answers in one
  line (`kronicle-lite: no change since seq N. Proceed; next cursor: …`:
  78 B, was 878 B; `focus=pulse` 126 B, was 603 B).
- The Markdown briefing omits the digest when a cursor was presented (still
  in `structuredContent`).
- MCP `recall`: receipts by id (`receipt_id` per hit; the receipt is stored
  and `verify` takes `{receipt_id}`; `receipts: "inline"` for the old
  shape), compact JSON text, `max_chars` default 4000 (library default
  unchanged at 16000). Bench: recall 2.2 KB → 1.3 KB per query (S12),
  S1 per-turn orient 2.7 → 2.4 KB, S8 6.0 → 1.0 KB.
- `tools/list` grows by ~0.6 KB (14.2 KB full, 10.5 KB `--core`) for the
  new parameters and result fields.

### Added — push contract for hooks

- `kronicle-lite orient --cursor C --focus retractions --json` is the
  documented contract for a PostToolUse / PreToolUse push hook
  (docs/PUSH.md): stable fields, cosmetic edits excluded, no git calls
  (`source_drift: null`), the integrity pass re-hashes the events since the
  cursor (not the last 1000) and still every live block. The CLI loads the MCP SDK, HTTP, anchor and doctor code only for the
  commands that use them (code splitting): ~0.33 s per call on a 300-file
  store, was ~0.5 s.
- The orient skill, the example wake contract and the server instructions
  say to orient before world-changing commands (deploy, migrate, publish,
  `git push`): the no-hook fallback for Cursor, Codex and Hermes.

## [0.6.0] — 2026-11-01

Honest labels: deterministic, LLM-free checks ported from IsoKron
(`packages/reality` retrieval-honesty-tags and the C-1 inherit ladder,
`sb1-substrate-shapes` certify-absence, `library-retrieval`
attention-decay recall, `sextant-scrub`). Additive only: no hash recipe,
receipt, checkpoint, cursor or event layout changed; the 0.3.0 export
fixture imports, verifies and re-exports byte-for-byte. New result fields
are additive; one local column (`receipts.actor_id`) is added on open.

### Added — authority on every recall hit

- Each hit carries `authority` (`can_act | inspect_only | never_act`),
  `authority_reason` and `authority_basis` (`block | document | none`);
  the result carries `authority_floor` (meet of the hits; `null` when
  empty, so an empty result is never permission). `withheld` entries say
  `never_act / integrity_failed`.
- Only block-level evidence reaches `can_act`: the block's exact text
  (same kind, same BLAKE3) found at recall time in the document's recorded
  source file (git binding, absolute or `~/` path, or an instruction file's
  project root). Document-level provenance caps at `inspect_only`; a
  block superseded after binding is `never_act / not_in_source` even while
  the file's blob still matches. Superseded, tombstoned, missing-source and
  withheld are never `can_act`; model-written memory (`source.kind:
  memory`) caps at `inspect_only`. Rule table: new `docs/HONESTY.md`.

### Added — honest absence

- Every recall result carries `absence {searched, not_searched,
  index_fresh, verdict, reason}`. `absent_in_searched` only from a fresh
  index with nothing withheld; `cannot_certify` when the index is stale
  (projection behind the chain's last document event) or cold (full-text
  index short of the block count), a match was withheld, or the query had
  no searchable terms. Scopes: `live_blocks`, `tombstoned_blocks`,
  `superseded_blocks`; no global "not found".
- `get_system_state`: `scope.verdict` (`complete | partial`). A briefing
  that hid other projects' instruction retractions says "Retractions: none
  in this project (partial view)" and adds a next step that they were not
  reviewed.

### Added — attention rerank

- `recall` takes `cursor` and `actor_id`: hits the actor already read
  since the orient that issued its cursor (else its latest orient) are
  ranked lower (relevance × 0.5, stable), never hidden; `already_read` per
  hit, `attention {actor_id, session_since, already_read}` per result.
  `score` stays raw bm25. Reads are recorded in the new local
  `receipts.actor_id` column (not in the signed receipt).
- `Orient.sessionStart(actor, cursor?)`, `FlightRecorder.briefingAt()`.

### Added — secret guard

- Write time: `put_document`, `supersede_block`, `tombstone_block`
  (reason), `kronicle-lite put`, `put --from-instructions`, `watch` and
  `import` scan for API keys and tokens (AWS, GitHub, GitLab, Anthropic,
  OpenAI, Slack, Stripe, Google, npm, Vault, Doppler), private keys, JWTs,
  password-bearing connection strings, bearer headers and sensitive
  assignments, and refuse before anything is chained
  (`secret_detected`, findings `{field, detector, line}`, never the
  secret). Overrides: `redact_secrets: true` / `--redact-secrets` chains a
  `[REDACTED:<detector>]` copy and returns `redactions`; `import
  --allow-secrets` imports verbatim (chained bytes cannot be redacted).
  A refused instruction file syncs as `error`; in redact mode an unchanged
  file stays `unchanged`.
- Read time, an independent broader ruleset: `recall` content (hit gains
  `read_scrubbed` and loses `can_act`), orient retraction text and delta
  payloads, `audit_assumptions`, `kronicle://docs/{slug}`.
- Why: the chain is append-only; a tombstone hides a block but cannot
  erase a chained secret from the events, exports or backups
  (THREAT-MODEL.md "Secrets"). IsoKron's entropy detector and CLI
  grammars are not ported (noisy on Markdown and code).

### Added — small contexts

- `serve --core` (`profile: 'core'`, `CORE_TOOLS`): six tools —
  `get_system_state`, `audit_assumptions`, `recall`, `verify`,
  `put_document`, `supersede_block`. `tools/list` 9,865 bytes vs 13,628
  for the full profile (JSON of `{tools}` over stdio). Pinned separately:
  `.mcp-catalog/kronicle-lite-core.json`, `CORE_CATALOG_FINGERPRINT`.
- `recall` `max_chars` (default 16000): content over budget is cut
  (short hits stay whole) with `truncated {shown_chars, total_chars,
  read: "kronicle://docs/<slug>"}` per hit and `truncated {hits,
  max_chars, hint}` per result. Receipts still cover the whole block.

### Changed

- `kronicle-lite demo` gains step 7: a put holding an AWS key is refused
  with nothing chained, an empty recall answers `absent_in_searched` with
  the scopes it did not search, and a hit shows `inspect_only (no_source)`.
  The chain-edit step is now 8.
- `tools/list` (full profile): 12,441 → 13,628 bytes (the new recall
  inputs, `redact_secrets`, and the new top-level result fields).
- Flight-recorder `delta_hash` is computed over the briefing as served,
  i.e. after the read-time scrub.
- Catalog re-pinned: `0c25eb80d24f3cecab677dabcfc139f970c0440391a53539d5a820bb265e5e64`
  (core: `47b3f289201a66ec3983fc82e60d355af1da1869a6563ed00efb55f5e0227b42`).

## [0.5.0] — 2026-11-01

Fixes from an adoption audit (B3, B4, G3, G4, G5, G6, H2 and the first-run
items). No hash recipe, receipt, checkpoint or cursor layout changed: every
0.3.0 and 0.4.0 chain imports, verifies and re-exports byte-for-byte. One
new event type (`document.renamed`) and one new optional `source` field
(`project`) are additive; older readers ignore them.

### Fixed — what the agent reads is checked against the chain (B4)

Before: editing `blocks.content` in the SQLite file passed `verify-chain`
and `doctor`, and `recall` served the edited text with a receipt that
verified `VERIFIED` (`verify` compared the stored hash column with the
receipt and never re-hashed the content). THREAT-MODEL.md claimed this
case was caught.

- Every read path that serves text re-hashes it (BLAKE3, FORMAT §3.6) and
  checks it against the `block.created` / `document.put` event that made
  it, including that event's own hash. `recall` withholds a failing block
  (new `withheld: [{block_id, doc_slug, problem}]`, no content, no
  receipt); `verify` returns `UNVERIFIED / content_tampered` (+
  `integrity_problem`) and, for a block the projection calls live but the
  chain retired, `UNVERIFIED / projection_mismatch`; the
  `kronicle://docs/{slug}` resource refuses a revision that does not match.
- `verify-chain` / `verify` (local) over the whole chain, or with `--full`,
  and the MCP `verify_chain` tool over the whole chain replay every event
  into a scratch schema and compare `documents`, `document_revisions`,
  `blocks` and `doc_sources` column by column, then re-hash every block and
  revision (new `projection` result; `ok` covers both). Exit 1 on mismatch
  with a one-line summary on stderr.
- `doctor` gains a `projection` check (fails on mismatch).
- `get_system_state` gains `integrity {ok, events_checked, blocks_checked,
  problem}`: it re-checks the events of its window (at least the last 1000)
  and the newest 2000 live blocks, and leads with an `INTEGRITY FAILURE`
  banner and next step when one fails.
- New `kronicle-lite rebuild`: re-derive the projection from a chain that
  verifies (refuses a broken chain).
- THREAT-MODEL.md now states exactly what is and is not detected.

### Fixed — instructions are keyed by project (B3)

Before: every repository sharing `~/.kronicle-lite` wrote `CLAUDE.md` to
`instructions/claude-md`, so syncing repo B tombstoned repo A's rules and
told A's agent, at `safety` severity, to stop following them.

- Instruction and auto-memory slugs carry a project key after the
  namespace: `instructions/<repo>-<8 hex>/claude-md`,
  `memory/<repo>-<8 hex>/MEMORY` (key from the worktree root, resp. the
  main worktree root; `$KRONICLE_LITE_PROJECT` overrides). `source` gains
  `project {key, root}`.
- Migration, additive: the first sync of a file whose 0.4.0 un-keyed
  document still holds exactly that file's text renames it in place
  (`document.renamed`), keeping doc_id, blocks and receipts, with no
  retraction. Any other legacy document is left alone.
- `get_system_state` hides instruction retractions from documents of other
  projects (`scope {project_keys, hidden_retractions}`); `all_projects:
  true` / `orient --all-projects` shows them. `serve` and `orient` scope to
  their working directory (`--cwd`).
- Slugs deeper than 16 segments are now bounded too (they used to fail
  validation).

### Changed — retractions say what changed, in words (G3)

- Retractions gain `heading_path`, `old_text`, `new_text` (≤ 160 chars)
  and `diff` (word diff `[-old-]{+new+}`, ≤ 400 chars); `reason_line`
  quotes the old and new text instead of block ids when the store has it
  (falls back to the 0.4.0 wording otherwise). The Markdown briefing adds a
  `changed:` / `removed:` line under each.

### Changed — first run, demo, noise (G5, G6)

- New `kronicle-lite demo [--dir D] [--keep]`: the stale-runbook story end
  to end in a temp dir (put, orient, change, retraction with the diff,
  receipt SUPERSEDED, direct table edit withheld / UNVERIFIED / verify-chain
  exit 1 / integrity banner, rebuild, chain edit caught at its seq). No LLM,
  no network; exits 1 if any step does not play out.
- The README tour is self-contained (it writes `runbook.md` itself) and
  covered by a test that runs it in an empty directory with a fresh HOME.
- `put SLUG FILE` reads the file and validates the slug before opening the
  store: a failed put no longer creates the data dir and signing key.
  `import` checks its input file first too.
- `put SLUG FILE` prints one summary line; `--json` prints the full result
  as before.
- No `never anchored` line in orient until something was anchored
  (`anchorLine()` returns null); `doctor` skips the anchor reachability
  probe unless a license key or anchor URL is configured.

### Changed — token diet (G4)

- `tools/list`: **43,185 → 12,439 bytes** (−71%; measured over stdio).
  Tool descriptions shortened, the longer guidance moved to
  `skills/orient/SKILL.md`. Output schemas are advertised in a compact form
  (top-level fields with type, enum and `required`; nested shapes as bare
  types; no descriptions, patterns or bounds). Inputs keep their
  constraints minus ±2^53 integer bounds and regexes beside a `format`.
  Results are still validated against the full zod schemas, now served by
  the new `kronicle://schemas/tools` resource. No tool, parameter or result
  field was removed.
- Catalog re-pinned: `7eed4b72e51af9da660f2a0af4749205791f67338e632104819009600257337f`.

### Changed — HTTP serves 2025-era clients (H2)

- `serve --http` serves 2025-era (`initialize`) clients such as Cursor's
  through the SDK's stateless legacy leg (fresh server per request, same
  Host/Origin/bearer checks). `--modern-only` (`modernOnly`) restores the
  0.4.0 refusal (`-32022`).

## [0.4.0] — 2026-11-01

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

### Added — `kronicle-lite doctor`

- `kronicle-lite doctor [--json] [--no-network] [--full] [--cwd DIR]`,
  read-only, exit 0/1: Node version; data dir `0700` and key files `0600`
  (secret files readable by others fail); `PRAGMA integrity_check`; chain
  verify over the last 1000 events plus every checkpoint (`--full` for the
  whole chain); FTS5 `integrity-check` and row count vs `blocks`; live MCP
  catalog fingerprint (served in-process) vs `CATALOG_FINGERPRINT` pinned
  for this version, and vs `.mcp-catalog/` when run in a checkout;
  `config.json` sanity; last anchor vs local root; anchor reachability
  (non-fatal); MCP clients configured with kronicle-lite in
  `~/.claude.json` (user + local scopes), `.mcp.json`, `.cursor/mcp.json`,
  `~/.cursor/mcp.json`, `~/.codex/config.toml` (read-only, with their
  `--data-dir`); a Windows note that POSIX modes are no-ops there.
- `src/catalog.ts`: `CATALOG_FINGERPRINT`, `CATALOG_VERSION`,
  `liveCatalogFingerprint()`; a test keeps them equal to the snapshot.
- New databases are created `0600` (WAL/SHM inherit it).

### Changed

- **Catalog fingerprint** `11f99985…` → `fa8d1d6f50b1c461af859c6520515c621c7aee09be19f516a03e366b42a48dee`,
  re-snapshotted deliberately in each feature commit. The drift: new tool
  `anchor_status`; `checkpoint_chain` gains input `push`, optional output
  `anchor`, `openWorldHint: true` and a longer description; `put_document`
  gains inputs `source_path` / `bind_git`, optional outputs `source` /
  `warnings` and a longer description; `verify` gains status
  `STALE_SOURCE`, reason `stale_source`, optional `source_drift`;
  `audit_assumptions` gains verdict `stale_source`, optional
  `counts.stale_source` and `source_drift`; `get_system_state` gains
  `anchor`, `source_drift` and retraction kind `instruction`. Nothing was
  removed or renamed, no input became required, every 0.3.0 output field
  is still there. Clients take one prompt-cache miss.
- The fingerprint is also pinned in `src/catalog.ts` (`CATALOG_FINGERPRINT`,
  `CATALOG_VERSION`) for `doctor`; a test keeps it equal to the snapshot.
- New databases are created `0600`.
- CI gains a `windows-latest` / Node 22 job; `.gitattributes` pins LF.
  POSIX-only assertions (file modes) skip on win32 with a reason.
- `package.json` / `server.json` → 0.4.0; `server.json` lists
  `KRONICLE_ANCHOR_URL` and `KRONICLE_ANCHOR_KEY` (secret).

### Compatibility

- FORMAT changes are additive only: §1.2 event hash, §2 checkpoints, §4
  receipts and §5 cursors are untouched. New: optional `source` in
  `document.put`, namespaced slugs, tables `anchors` and `doc_sources`
  (created on open), a trailing export line only when anchors exist.
- `test/fixtures/export-0.3.0.jsonl`, written by the 0.3.0 CLI, imports
  under 0.4.0 with every hash and link re-verified and re-exports its
  event lines byte-for-byte; a real 0.3.0 data dir opens, gains the new
  tables and its checkpoint still verifies.
- An export that carries the anchors line is not importable by 0.3.0
  (strict event parsing there); exports of un-anchored stores are
  unchanged.

### Tests

76 → 123: anchor acceptance suite against an in-test service stub (plus,
with `KRONICLE_ANCHOR_WORKER_DIR`, the same 13 cases against the real
isokron-anchor Worker under Miniflare — 31/31 locally), instruction
import/watch/hooks (12), git binding (7), doctor + catalog pin (8), 0.3.0
compatibility (2).

### Known limits

- The hosted anchor service is not deployed; remote calls report "anchor
  service unreachable". Inclusion proofs (`prove --seq N`) and day-root
  refresh from the integration doc's days 6–12 are not in this release.
- cc-anchor 0.2.0 (current) has no `FileChanged` / `watchPaths` hook; the
  README shows the two settings entries that do the same job.
- Claude Code project directory names over 200 characters carry an
  unspecified hash suffix; `watch` finds that directory by prefix.
- The Windows CI job was added but could not be run from the build
  environment; it exercises paths, fs.watch, git and both transports.

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
