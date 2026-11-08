# Changelog

All notable changes to kronicle-lite. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses semantic versioning once past 0.x.

## [Unreleased] — 0.9.0

### Added — audit events, batch verify, evidence bundles (MCP audit toolkit)

- **Audit event types on the chain** (`audit.catalog_snapshot`,
  `audit.call_measured`, `audit.finding`, `audit.gate_result`,
  `audit.fix_applied`, `audit.regression_result`): schema-validated per
  kind, hashes and blob refs only, write-time secret guard, all or nothing
  per call (≤ 500). Ingest is idempotent by a stable id: `(audit_id,
  event_key)` fixes the chain idempotency key and a UUID-shaped `event_id`;
  a retry replays, a different payload under the same key is
  `event_key_conflict`. New tools `audit_record`, `audit_query`; resource
  `kronicle://schemas/audit`; CLI `audit put-blob | record | query`.
- **Content-addressed blob store** (`blobs` table, outside the chain; never
  touched by `rebuild`). Refs must resolve unless declared `redacted`.
- **Projection** (`audit_events`, `audit_event_fingerprints`,
  `audit_findings`): query by audit id and by catalog fingerprint (incl.
  before/after); per-finding state discovered / refuted / reopened /
  accepted with enforced transitions. `rebuild` and `import` re-derive it;
  `verify-chain` reports a projection that disagrees with the chain.
- **Batch `verify`**: `receipts` / `receipt_ids`, up to 100; `results[]` in
  input order and `counts`; the top level is the first non-VERIFIED result
  (fail closed for single-status readers).
- **Evidence bundles**: `audit export --audit-id A --out DIR` (manifest,
  events with link stubs for unrelated events, blobs, redacted / missing
  lists, store-signed Merkle root = a stored checkpoint) and
  `verify-bundle DIR [--key PEM]`, offline. Deterministic canonical JSON.
  docs/EVIDENCE-BUNDLE.md is the verification procedure; a pass (or an
  anchor) proves integrity and existence, not that the audit is correct.
- **Review hardening (before release).**
  - **Manifest signature.** The store key signs the whole canonical manifest:
    index, stub hashes, blob lists and digests. Before this, the signature
    covered only the root, so an audit event could be turned into a stub and
    the bundle still verified, even with `--key`.
  - **Missing artifacts** fail `verify-bundle` unless `--allow-missing` is
    passed, and the result reports it.
  - **Hostile bundles** yield `ok: false`, never a throw. That covers any
    shape, any depth, blob names that are not 64 hex, and blobs that are
    directories.
  - **Blobs** go through the write-time secret guard: refused, or stored
    redacted with `--redact-secrets`.
  - **Ingest:** `__proto__` keys and nesting deeper than 16 are refused. A
    second refuting `gate_result` is allowed.
  - **Reserved keys:** the `audit:` and `apply:` idempotency-key prefixes are
    reserved, and `put_document` refuses them (`reserved_key`).
  - **0.8.x stores:** verification works on a 0.8.x store without migrating
    it. Before this fix, `verify-chain` / `verify` on a 0.8.1 store failed
    with "no such table: audit_events" and exit 1, the divergence code. The
    test uses a real 0.8.1 store (`test/fixtures/store-0.8.1.db.gz`) and a
    read-only medium.
  - **Safe export:** `--out` must be new or empty and free of symlinks, and
    every file is created with `O_EXCL|O_NOFOLLOW`, so no symlink planted in
    `--out` is written through.
  - **Encoded secrets:** the blob scan decodes gzip / deflate, UTF-16LE,
    base64 and base64url (nested). Anything it cannot decode within the cap
    is flagged `unscanned_encoding`.
  - **Scan limits (#15).** A single base64 or alphanumeric run of 8 MB made
    the blob scan throw `RangeError: Maximum call stack size exceeded` (a
    regex); runs are now found by a loop. A 60 MB random binary took 2.2 GB of
    heap; the scan now reads the blob in 2 MB windows (512 KB overlap) and
    stops at 32 MB: a larger blob is stored flagged `unscanned_size` (put
    result, `blobs.flags`, bundle manifest). `blobs.flags` is now
    comma-separated. A base64 run that would decode past 16 MB is flagged
    `unscanned_encoding` instead of decoded.
  - **Private key detector in linear time (#15).** The write-time
    `private_key` regex backtracked: 64 KB of BEGIN headers with no END took
    8 s, a 1 MB body line over a minute, in `put_document` as well as blobs.
    It is now matched by a linear scan with the same matches (property test
    against the regex). The detector's `re` is unchanged for display.
  - **Every decoder's output is scanned; bounded decode work (#15 review).**
    Raw deflate often "decodes" a brotli stream into a few junk bytes, and
    only the first decoder that succeeded was scanned, so a brotli-wrapped
    token (or a 40-byte brotli bomb) passed unflagged. Every decoder that
    succeeds is now scanned. A stream that hits the 16 MB cap (or fails past
    a 64 KB probe) is charged the whole cap against the 48 MB per-blob decode
    budget, decoding stops when that is spent, and a per-blob work cap
    (`MAX_SCAN_WORK`, 512 Mi units: bytes read, decoded and scanned) flags
    `unscanned_encoding` when reached. 63 bombs in one view took 2.2 s, and
    base64-wrapped copies scaled linearly to hours; now a few decoder calls.
  - **Encoded secrets that got through silently (#15).** Five-deep nesting,
    an HTTP message with a gzip body, brotli, raw deflate, UTF-16LE after
    4 KB of ASCII, and UTF-16BE produced neither a finding nor
    `unscanned_encoding`. All are now decoded and refused. The scan nests 12
    levels. It tries gzip at every member header, raw deflate and brotli on
    non-text views, and the declared encoding after each HTTP header block,
    and it finds UTF-16 in any 128-byte window at either parity. What it
    cannot decode is flagged: nesting past the limit, a declared encoding it
    cannot decode or that fails, and more than 64 stream starts or 8192 views.
  - **Migration (#15).** `blobs.flags` is in `ADDED_COLUMNS`: a store made by
    an unreleased 0.9.0 dev build (blobs table without it) gains the column on
    open. Before this, every put-blob on such a store failed with "table blobs
    has no column named flags". Released stores are unaffected.
  - **Export race (#15).** `--out` was checked, then written by path, so
    swapping `blobs/` or the out dir for a link mid-export created new files
    in the victim directory (nothing was overwritten). Writes now use names
    relative to a working directory pinned to the checked inode (openat
    style; Node has no openat), and the export fails if either directory
    changed. Blob bytes are fetched one at a time while writing.
  - **Global confirmation cap (#15).** Actor ids are self-asserted, so
    previews under distinct actors grew `apply_confirmations` without bound
    until TTL. The table now holds at most 10,000 rows (`MAX_CONFIRMATIONS`);
    a new preview evicts the oldest first. Denial of service only, documented
    in docs/APPLY.md.
  - **Canonical MAC (#15).** The token MAC (32 bytes in 43 base64url
    characters, so 2 unused bits in the last one) was compared after decoding,
    so 4 spellings of every MAC verified. It is now compared as the canonical
    base64url string.
  - **Mutation gap closed (#15).** A test now pins `AuditLog.checkProjection`'s
    missing-table branch: a store whose chain holds audit events but has no
    `audit_events` table is a divergence (`verifyAll` not ok, `verify-chain`
    exit 1). Before, making the branch return null failed no test.
  - **Linear secret-guard bookkeeping (#15 review).** Each write-time match
    was checked against every earlier one for overlap, and its line number
    was counted from the start of the text: both quadratic in the number of
    matches. A 2 MB blob of AWS keys took 15 s (32 MB about 6 min); now
    0.16 s. Matches are merged with a forward sweep and lines counted in one
    pass; same findings.
  - **env_secret in linear time (#24).** The write-time `env_secret` regex
    backtracked quadratically on one long line of name characters
    (`PASSWORD` repeated: 0.5 / 2.1 / 7.7 s at 64 / 128 / 256 KB in
    `putDocument`, about 2 hours for an 8 MB MCP document). It is now matched
    by a linear scan with the same matches (property test against the regex);
    256 KB takes 67 ms, 8 MB 1 s.
  - **Blob scan budget counts regex passes and time (#24).** Every regex pass
    is charged (`REGEX_PASSES` units per character, one per write-time
    detector; `MAX_SCAN_WORK` is now 3 Gi), and a per-blob time budget
    (`MAX_SCAN_MS`, 30 s) is checked before each scan window and decoded
    view: out of time, the raw scan stops (flag `unscanned_size`) and
    decoding stops (flag `unscanned_encoding`) instead of blocking.
  - **The overlap-linearity test can fail (#24).** It asserts the step
    counter is live; with the old quadratic check restored it fails.
  - **No false `unscanned_encoding` on base64'd Windows gzip (#24 CI).** A
    base64 run is also read as base64url pieces (split at `+` / `/`); a piece
    of base64'd gzip whose OS byte is 0x0a decoded to a truncated gzip header
    and was flagged. A run strictly inside the other alphabet's run is now a
    fragment: still decoded and scanned, but its gzip header is not flagged.
  - **A failed decode no longer drains the decode budget (#24 CI).** A
    stream that fails after producing more than the 64 KB probe is charged
    the cap as work only; one that hits the cap is still charged against the
    48 MB decode budget and flagged. Before, junk base64url pieces that
    brotli decodes past the probe drained the budget, and later real streams
    were flagged (64 base64'd gzips with the Windows OS byte).

### Added — `apply`: transactional batch writes with preview

- `apply` (MCP tool; `store.applier`): up to 50 put / supersede / tombstone
  ops in one local SQLite transaction (`all_or_nothing`, default) or
  per-op savepoints (`best_effort`); `expect_version` per op; one
  `apply.committed` chain event per commit (plan hash, result hash, per-op
  receipts); `idempotency_key` replays the committed result, a different
  plan under it is refused. `dry_run` executes and always rolls back
  (exact diffs) and returns a single-use, expiring `confirm_token` bound to
  plan hash, actor, tenant, sandbox, server, catalog fingerprint, resource
  ids and versions, policy version, nonce and idempotency key; the commit
  re-validates all of it inside its transaction (`stale_plan` on any state
  change) and re-checks authorization per op (the token authorizes
  nothing). docs/APPLY.md.
- **apply review hardening (before release).**
  - **Small tokens.** Confirm tokens are a nonce plus a MAC (about 80
    characters), with the binding stored server-side. Before this, a 20-op
    token was 5 KB and failed the MCP schema.
  - **No false receipts.** A commit whose chain key already holds another
    event fails with `idempotency_conflict` instead of reporting that event as
    its receipt.
  - **When a token is required.** After a dry run of the same plan
    (`confirm_required`), and always over HTTP.
  - **Burning.** A wrong-actor attempt no longer burns the owner's token.
  - **Replays.** Idempotent replays re-check the actor and authz inside the
    transaction.
  - **Project scope.** `put` ops keep the server's project scope.
  - **TTL.** A non-finite `ttl_seconds` gets the default; any value is capped
    at 900.
  - **Bounded confirmations.** Before this, 5,000 expired dry runs left
    3.4 MB in `apply_confirmations`. Confirmations are now indexed by expiry
    and by actor and plan, expired rows are pruned on write (bounded batches),
    and each actor holds at most 100 live ones.
  - **Strict MAC.** The token's MAC must be exactly 43 base64url characters,
    so a trailing `=` is refused.

### Changed

- Catalog pins moved to `src/catalog-pin.ts` (no imports; apply binds the
  fingerprint), re-exported from `src/catalog.ts`.
- Catalog: three new tools (`apply`, `audit_record`, `audit_query`) and a batch-capable `verify` (full and core
  catalogs re-snapshotted; `CATALOG_VERSION` 0.9.0). Existing tools,
  hashes, receipts and cursors are unchanged; stores from 0.8.x open and
  gain the new tables on first open.

## [0.8.1] — 2026-11-01

Safety patch from agent-memory-bench hardening round 2. Every item was
reproduced on 0.8.0 before it was fixed and has a regression test.

- Track 1 (`hardening-retractions`): R2-01..17, including the leads first
  filed as L1–L6.
- Track 2 (scale): C2-09, C2-10.
- Track 3 (exec-time shims): H2-*.
- Track 4 (MCP protocol and storage): P2-02..14, F11, F12, F14, C2-01,
  C2-08.
- Track 6 (anchor client): A2-*.
- Live-agent track: L2-01, L2-03, L2-07, L2-09.
- Chaos track: C2-03..05.

No hash recipe, receipt, cursor or event layout changed. Stores written by
0.8.0 open and verify unchanged; the forward-only migrations are listed
under Migration.

### Fixed — format-only is now RAW-TEXT equivalence (R2-01, R2-02, R2-03)

- **R2-01 (S1).** The format-only parser read a `N.` / `N)` line after a
  paragraph line as a list item, treated a `.` → `)` switch as the same
  list and dropped nested ordered starts — then discarded every number
  after the first. So `Open these ports:\n8080. web\n9090. admin` →
  `…9091. admin` was format-only: no retraction, `pending_count` 0, `pulse`
  exit 0. Port, back-off, year and list-start changes are retractions now.
- **R2-02 (S1, design).** Edits CommonMark renders the same but that change
  the raw text an agent copies into a command were format-only: `*` ↔ `_`
  in unfenced globs and identifiers (`/tmp/*/cache/*` → `/tmp/_/cache/_`,
  `__init__.py` → `**init**.py`, `PATTERN=*.log*`), and contradictory raw
  list numbering. **Format-only now means the raw Markdown is
  byte-identical after only: CRLF/CR → LF, trailing whitespace per line,
  reflow inside a paragraph (a whitespace run that contains a line break,
  between two non-space characters → one space; not inside inline
  code, link destinations, HTML or quoted strings, never across a hard
  break or before a line that could start a block construct), and
  blank-line runs.** No whitespace-run (two spaces → one, tab → space
  inside a line), emphasis-marker, list-marker, renumbering,
  heading-style, escape or Unicode normalization. Code blocks, front
  matter, HTML blocks and blocks with an unclosed code span, quote, tag or
  link destination are opaque (docs/FORMAT.md §3.8).
- **R2-03 (S3).** A backslash hard break (`deploy\` + newline + `--force`)
  vs a literal backslash (`deploy\ --force`) was format-only. The line break
  after a backslash is kept.
- **Honest cost:** a double space or a tab changed inside a line, list
  renumbering, ordered-list delimiter (`1)` ↔ `1.`), bullet style (`-` ↔
  `*`) and emphasis-marker (`*x*` ↔ `_x_`) edits now produce retractions
  (and `pending`, and a refusing pulse) where 0.7.0–0.8.0 stayed quiet.
  Deliberate: agents copy commands out of unfenced prose, where a double
  space or a tab can matter, and a false format-only is far worse than a
  false alarm. Bench S7 (benign-edit quiet rate): see "Bench" below.
- `format_rules` only ever holds `whitespace` now (`markup` stays in the type).

### Fixed — a reorder inside a section made no event (R2-06, S2; lead L2)

- `planRevision` carried blocks by content hash and heading path regardless
  of order, so swapping two runbook steps made no event at all. Inside a
  section, the fewest blocks that changed order are now superseded by an
  identical-text block (reason `reordered in revision N`): a retraction
  "MOVED within …" with diff `order: same text, new position within …`, the
  old receipt verifies `SUPERSEDED`, readers have it `pending`, and notes
  derived from it go stale. Insertions and removals are not reorders;
  reordering whole sections still carries (docs/FORMAT.md §3.2 step 1a).
  Two swapped `kubectl` code blocks: 0.8.0 `pulse -- git push` exit 0,
  0.8.1 exit 77.

### Fixed — a section moved AND renamed, with an edit, read as a removal (live L2-09, S4)

- A block whose section was renamed and whose text also changed was
  tombstoned ("REMOVED", no successor, no new value) while its new version
  was "created" elsewhere. A leftover block that closely matches a new block
  of the same kind under another heading path (word-multiset Dice ≥ 0.6) is
  now superseded by it: a retraction with `new_heading_path`, the new text
  and a `section: …; …` diff (docs/FORMAT.md §3.2 step 3b). Renamed
  headings themselves are still a removal plus an addition.

### Fixed — `## Use C#` was stored as "Use C" (R2-13, S3; lead L1)

- The ATX heading pattern stripped any trailing `#`, so `C#` → `C` (or
  `F#`, `#` in a channel name at the end of a heading) made no event. A
  closing sequence is now stripped only when a space precedes it, as in
  CommonMark. A stored heading that lost its `#` gets one retraction the
  next time its file is put.

### Fixed — robustness

- **R2-12 (S3; lead L5).** The `likely_typo` hint ran an O(m·n) edit distance on the one
  differing word: a 6,000-letter word made `orient` take 13 s (past the
  10 s shim timeout, so the shim failed open) and 10,000 letters ran out of
  memory. Words over 64 letters are not "ordinary words" for the hint.
- **R2-16 (S3; lead L6).** For blocks over 400 tokens the word diff fell
  back to snippets of both whole texts, which for a change near the end
  were identical prefixes, and `old_text` / `new_text` (and so the reason
  line) were the same first 160 characters. The diff now trims the common
  head and tail first and, when the changed region is still too long,
  shows that region with context; `old_text` / `new_text` (retractions,
  pending, `stale_derived`) start just before the first changed character
  when the change lies beyond the first 160. A whitespace-only change is
  shown visibly (`[-··-]{+·+}`, `→` tab, `⏎` newline), never as an empty
  marker.

### Fixed — anchor chain listing always paged; 429 honoured (anchor re-review)

- `verify --remote` and MCP `anchor_status` could never verify a large
  chain against the hardened anchor service: the first
  `GET /v1/chains/{id}` carried no parameters, so it took the service's
  unpaged path, which serves at most `CHAIN_UNPAGED_MAX` anchors (5,000 in
  the current review revision) and answers `400 paginate_required` above
  that. Every listing request now
  carries `?limit=500` (and `&cursor=` after the first page). A
  pre-pagination service (7327b55) ignores both and still returns its one
  full page. A `400 paginate_required` is retried once and then rejects
  the listing.
- A `429` on a listing page or on the service key document is no longer an
  immediate error. The client waits `retry-after` (delta-seconds or
  HTTP-date; 1 s when absent) and retries, at most 3 times per request.
  When the wait asked for is over 60 s, or the 429 persists, it fails
  closed: a listing is rejected (`verify --remote` exit 1, held receipts
  still checked, MCP `remote: "invalid"`), and a key document makes the
  command exit 2. `POST /v1/anchor` is not retried.

### Security — anchor client trusts only countersigned, pinned receipts (hardening track 6)

- **A2-01 (S1):** `verify --remote`, `verify --remote --offline`, MCP
  `anchor_status` (`verifyLastAnchor`) and `doctor` compared the local root
  with unsigned values — the service listing's top-level `root`/range, or the
  local `anchors.root` column — so a rewritten chain passed behind a MITM or
  after one `UPDATE anchors`. They now compare only against
  `receipt.checkpoint.root` and the signed range of a receipt whose
  countersignature verifies, whose `chain_id` is this chain's and whose
  checkpoint signature verifies against the local chain key. `--offline`
  re-verifies the stored `receipt_json`. Disagreeing unsigned fields are
  reported as problems (exit 1). New range result `unverified` (receipt not
  trusted, nothing compared) in `verify --remote --json` and the MCP
  `anchor_status` schema; `VerifyRemoteResult` gains `problems` and `notes`.
- **A2-11 (S2):** online `verify --remote` also checks every receipt held
  locally; an anchor the service does not list is still compared, and the
  omission is reported.
- **A2-12 (S2):** the anchor service key is pinned in
  `<data-dir>/anchor-keys.pinned.json` (0600) on first use, or from
  `service_key_pins` in `config.json` / a package-shipped pin (both turn
  first-use pinning off; the shipped list is empty for now). A pinned key is
  never overwritten from the network; `key_id` must derive from
  `public_key_pem`; a new key needs a valid `successor_signature` from a
  pinned key or `kronicle-lite anchor keys add PEM-FILE`
  (`anchor keys [list|remove|reset]` too). `anchor-keys.cache.json` is no
  longer written or trusted.
- **A2-04 (S2, client side):** a service key vouches for a receipt only with
  status `active` or `retired` and with the receipt's signed `received_at`
  inside `valid_from`/`valid_to`; pinned status only tightens. Applies to
  `AnchorClient.verifyReceipt` too.
- **A2-17 (S3):** `checkpoint --push` refuses (exit 2, nothing stored) a
  `receipt_jcs` that is not exactly the JCS of the verified receipt.
- **A2-20 (S4):** `http://` anchor URLs are refused unless the host is
  localhost/127.0.0.1/[::1] or `--insecure-http` is passed; `--key` on argv
  prints a warning (prefer `KRONICLE_ANCHOR_KEY` or `config.json`).
- **A2-21 (S4):** THREAT-MODEL and README: the service is deployed (Free
  tier); `409 CONFLICT` only for the identical range; what the client checks.
- **Compatibility with the hardened anchor service (isokron-anchor
  hardening A2), while staying compatible with the current one:**
  - `GET /v1/chains/{id}` is followed across pages (`next_cursor`, ≤ 500
    per page). A paginated page without `next_cursor`, a repeated cursor, an
    anchor listed twice, another chain's page, or fewer anchors than the
    service's `anchor_count` rejects the listing: `verify --remote` reports
    it as a problem (exit 1) and still checks every receipt held locally;
    MCP `anchor_status` reports `remote: "invalid"`. A pre-pagination
    service (one page, no `next_cursor`) still works.
  - A push to an erased chain (`410 chain_erased`) is reported as such,
    exits 2 and is not retried.
  - Service-key rules match the service's `src/core/servicekeys.ts`:
    absent status = active; `retired` needs `valid_to`; `valid_from ≤
    received_at < valid_to`; a key listed twice, or with a
    `successor_signature` that does not verify against a listed, trusted
    predecessor, is refused.
  - Strict Ed25519 for service keys, receipt countersignatures, successor
    and re-checked checkpoint signatures: small-order or non-canonical keys
    and R, and S ≥ L, are refused (node:crypto alone accepts the identity key
    with R = identity, S = 0 over any message).

Behaviour you will notice: the first online push or `verify --remote` per
data dir prints `note: pinned 1 anchor service key(s) … on first use`;
`verify --remote --offline` on a data dir anchored with ≤ 0.8.0 reports
`unverified` until one online call pins the key; a non-loopback `http://`
`anchor_url` exits 2 without `--insecure-http`.


### Fixed — exec-time shims (hardening round 2, track 3: H2-12 … H2-16)

- **`shim ack` is an operator action (H2-12, S2).** The refusal ended with
  "To override without re-reading: `kronicle-lite shim ack --through N`",
  and an agent that ran exactly that cleared the gate without reading. The
  refusal now says who still has to re-read the current version and to ask
  the operator otherwise; it never mentions `ack`. `shim ack` runs only
  from an interactive terminal or with `--operator` (else exit 2, nothing
  changes), and every ack and every refused attempt is logged in
  `.kronicle-shim/shim.log` with the actor (`--actor`, `KRONICLE_LITE_ACTOR`
  or the OS user), the OS user, the through-seq and how it was confirmed.
  `shim status` no longer prints the ack command either. Re-running
  `shim install` keeps the existing starting point instead of moving it to
  the head (that acknowledged every pending change by the back door).
- **Git pre-push hook (H2-13, S2):** `shim install --git-hook [--repo PATH]`
  writes a `pre-push` hook that runs the same check for every push from the
  repository and its initialized submodules, whatever started git: git's
  exec-path (`/usr/lib/git-core`) comes first on PATH for aliases, hooks,
  `rebase -x` and `submodule foreach`, so the PATH shim never saw those, nor
  `/usr/bin/git`, `sudo`, `env -i`, `command -p` or a PATH prefix. It goes
  into the hooks dir git reports (`core.hooksPath` respected), chains an
  existing pre-push hook (moved to `pre-push.kronicle-chained`, run after
  the check with the same arguments and stdin, put back on uninstall),
  refuses rather than overwrite, never writes git config, and never prints
  the remote URL. `shim status` shows each hook (active / INACTIVE /
  missing); `shim uninstall` removes them, `shim uninstall --git-hook
  [--repo PATH]` removes only the hooks. `git push --no-verify` skips it
  (git's rule; the PATH shim still sees that).
- **The project is the one the command acts on (H2-14, S2):**
  `cd /tmp && git -C ~/work/api push` was checked against `/tmp`. The pulse
  now resolves the target from `git -C` (cumulative), `--git-dir`,
  `--work-tree`, `GIT_DIR` / `GIT_WORK_TREE`, `terraform -chdir=`,
  `make -C`, `npm --prefix`, `pnpm -C/--dir` and `yarn --cwd`; a submodule
  is also checked against its superproject. A directory option that does
  not resolve is refused (`reason: "target"`). `shim exec --project DIR`
  names the project explicitly (a missing DIR refuses).
- **PATH bypasses documented (H2-15, S3):** docs/PUSH.md lists `sudo`,
  `sudo -E`, `env -i`, `command -p`, `hash -p`, a PATH prefix, an absolute
  path, git aliases, git running git and the forged same-process marker,
  each with what catches it (for git: the pre-push hook).
- **The invoking actor re-reads for itself (H2-16, S3):** with no
  `--pending-actor`, the shim now checks the actor in the command's
  environment (`KRONICLE_LITE_ACTOR`; `pulse --invoking-actor`): a change
  blocks it when it read an earlier version (or the change is to an
  instruction file, or nobody read it), and its own re-read clears it, so a
  stale or finished agent no longer keeps another agent's gate shut. Each
  actor keeps its own cursor per project; an operator ack still clears
  them all. Without `KRONICLE_LITE_ACTOR`, or with the new
  `shim install --all-readers` / `pulse --all-readers`, every reader must
  re-read, as in 0.8.0 (the shim cannot tell whose reads count otherwise),
  and the refusal now says that and names exactly who is left.
- **A corrupt store fails closed (live finding L2-03, S2).** A store whose
  file is damaged (a zeroed page, a bad header, SQLITE_CORRUPT / NOTADB)
  was reported as "unavailable" (exit 3) and the command ran. It is now an
  integrity failure: refused in deny mode, and in warn mode run with a loud
  `running UNCHECKED — the kronicle-lite store is CORRUPT` line every time
  (logged, `last-error`). A store that is there but unreadable for any
  reason other than a lock (permissions, I/O error) is treated the same way
  (`UNREADABLE`). Only a locked or slow store is transient and keeps the
  `--on-timeout` behaviour; `--on-timeout deny` now also refuses when the
  store is locked (exit 3), not only on a timeout.
- **The shims check the store the server uses (protocol finding P2-01,
  S2).** The README's own Cursor and Copilot snippets ran the server on a
  project-local `.kronicle-lite/` while the shims checked `~/.kronicle-lite`,
  so a push after a change landed silently. Unless `shim install --data-dir`
  pins a store, the shims now use `$KRONICLE_LITE_DATA_DIR` or
  `~/.kronicle-lite` plus the nearest `.kronicle-lite/` above the
  repository the command acts on. **No store, or two different ones,
  refuses world-changing commands in deny mode** (warn mode runs them with
  a loud line): previously a missing store failed open. The refusal names
  the operator's fix (`kronicle-lite shim install --data-dir DIR`, or
  `KRONICLE_LITE_DATA_DIR=DIR`). A store with nothing read yet still passes
  (the first check records its head). Each store gets its
  own starting point. The Cursor snippet now uses the default store; the
  Cursor and Copilot sections say how the shims find a per-workspace store.
- **`ship` is a world word (live finding L2-08):** `npm run ship`,
  `make ship`, `pnpm ship` / `yarn ship` are checked (with `deploy`,
  `migrate`, `publish`, `release`). A tool given by path uses that tool's
  rules and target (`shim exec --tool /usr/bin/make`, `pulse --
  /usr/bin/git -C x push`); the PATH shim itself still never sees
  `/usr/bin/make release` (documented with the other PATH bypasses).
- `pulse --json` adds `pending_mode`, `invoking_actor`, `not_relied_on[]`,
  `target` and the reasons `target`, `corrupt`, `no-store`,
  `ambiguous-store`; nothing was renamed or removed. `kronicle-lite pulse`
  without `--state` (a hook's own call) still exits 3 without a store.

### Fixed — scale: bounded read log, cheap first contact, idempotent puts (hardening round 2, track 2: C2-09, C2-10)

- **C2-09 (S3) — the read log is bounded and indexed.** `reads` (the local
  log behind `pending`, `readCurrent`, lineage inference and `readersOf`)
  was never pruned, and `pending` was linear in it (10k-doc store: 23 → 169
  ms at 2k → 8k rows). Every question asked of the log is about the latest
  read of a version, so per (actor, block, document, via) it now keeps only
  the latest row by head seq, by read time and by insertion (normally one
  row), pruned in the transaction that records a new read
  (`src/lineage/read-log.ts`). Receipts stay (signed artifacts) but are
  folded into the log, one row per actor and block, behind
  `meta.reads_receipts_mark`; readers union the log with only the receipts
  after the mark, so receipts an older binary writes are still seen. Same
  store, same harness (`kl-reads-growth.mjs`): the log stays at 370 rows
  (the blocks actually read) instead of 8000, `pending` 1–6 ms instead of
  169 ms. New indexes `reads_actor_key_idx`, `reads_block_idx`,
  `reads_doc_idx`, `receipts_actor_rowid_idx`; `reads_actor_block_idx` is
  dropped. **Migration (forward-only, local tables only, no chain or hash
  change):** the indexes are created on open; the first read-log write
  compacts a 0.8.0 log once (`meta.reads_compacted`) and folds its receipts.
  Answers are identical before and after (tested against a store written by
  0.8.0, `test/fixtures/store-0.8.0.db.gz`). An older binary can still open
  the store; it recreates the dropped index and writes unpruned rows, which
  the next 0.8.1 write prunes.
- **C2-09 — a first-contact `orient --focus retractions` answers from
  indexes.** An actor that presents no cursor and has no briefing and no
  reads or receipts has relied
  on nothing, so there is nothing to retract: `retractions` is `[]`, the
  delta counts come from the `(event_type, seq)` index (identical to the
  full fold; with a project scope one SQL pass counts `hidden_events`), and
  integrity re-hashes the last 1000 events and the newest live blocks
  instead of the whole chain. 10k docs (60k events), same loaded host, 0.8.0
  → 0.8.1: in-process 4.7 s → 0.67 s (scoped 7.1 s → 1.1 s); CLI
  `orient --focus retractions --all-projects` 2.2–10.1 s (six runs) → 0.39–1.5 s
  (four runs). An actor that read anything before its first orient, or that
  presents a cursor that is rejected, still gets the full listing.
  In the track's 400-loop server soak the pulse p95 no longer climbs with
  the read log (0.8.0: 98 → 184 and 49 → 176 ms; 0.8.1: 30 → 51 and
  56 → 28 ms).
- **C2-09 — `verify-chain --from N`** was already windowed (0.07 s for the
  last 1000 of 60k events in-process); `verify-chain` without `--from` is the
  whole chain plus the projection by design (the track's "last 1000" label
  ran the whole-chain form).
- **C2-10 (S3) — puts are idempotent by content.** 20 concurrent
  `put --from-instructions` after one CLAUDE.md edit appended 10 and 4
  identical `document.put` events. `putDocument` now appends nothing (and
  reports `events: 0`, the current revision) when the current revision's put
  already records the same markdown, title, source and project, decided
  inside the write transaction; a put with lineage, an idempotency key, or
  any recorded difference appends as before. Instruction import reports such
  a put as `unchanged`.

### Fixed — MCP protocol and real clients (hardening round 2, track 4: P2-02 … P2-14)

- **`put_document` no longer kills the client after the write committed
  (P2-02, S3).** It echoed every block, pretty-printed in the text block on
  top of `structuredContent`: a 90 kB document of 30 000 paragraphs answered
  with a > 10 MiB line, the TS SDK stdio client (v1 and v2, 10 MiB
  `ReadBuffer`) closed the connection and the agent saw a failure for a write
  that had landed. **Compatible result change:** every existing field keeps
  its name, type and order; `blocks` lists at most the first 100 entries
  (and 64 KiB of them). New fields: `block_counts {total, listed, added,
  kept, retired}` over every block, `blocks_truncated`, and `blocks_next`, a
  resource URI `kronicle://docs/{slug}/blocks/{revision}/{offset}` that pages
  the rest (1 000 per page, `next` links). A document of ≤ 100 blocks
  answers exactly as before plus the new fields. The CLI `put --json` still
  prints every block. The text block of every tool result is now compact
  JSON (same value as `structuredContent`), and every tool result is held to
  an 8 MiB budget (`result_too_large` tool error instead of a dead
  connection). Consumers checked: cc-anchor (uses the CLI `put`), sea-lite
  (does not call `put_document`), isokron-plugins `verify.mjs` and the bench
  arm (read the result generically).
- **`get_system_state` results validate against the full served schema
  (P2-04, S3).** `integrity.seq` was missing from the schema at
  `kronicle://schemas/tools` (`additionalProperties: false`), so every JSON
  result failed it. A test now validates random calls of every tool, full and
  `--core`, against both the advertised and the served schema with ajv.
- **Oversize input is answered, not fatal (P2-05 / F11, S3).** One line over
  10 MiB made the server exit 0 with no JSON-RPC error, and a schema-valid
  `put_document` (1.9 M × U+0001 escapes to 11 MiB) reached it. The stdio
  wire is now kronicle-lite's own (`src/stdio.ts`, under the SDK's
  `serveStdio`): a line over the limit is discarded as it streams in and
  answered `-32600 "Message too large"` with its id (when the id is among the
  first 64 KiB, else `null`); the server keeps serving. One inbound limit for
  stdio and HTTP: **16 MiB** (`KRONICLE_LITE_MAX_MESSAGE_BYTES`), above every
  schema-valid `put_document` (2 000 000 characters × 6 bytes escaped).
  `markdown` is also bounded in wire bytes: over 8 MiB as JSON →
  `document_too_large`, nothing written, so reading a document back always
  fits a 10 MiB client buffer. Cursors (`since_cursor`, `cursor`) are now
  `maxLength: 8192`. An outbound line over 9 MiB is replaced by a JSON-RPC
  error for its id. Calls that can still exceed 16 MiB while schema-valid
  (`audit_assumptions` with 100 claims of 200 000 characters each, a huge
  free-form `verify.receipt`) get the `-32600` answer, never a dead server.
- **Malformed input is answered (P2-06, S3).** Parse errors → `-32700`; a
  UTF-8 BOM is stripped; an invalid request with a usable id (`params` an
  array or string, numeric `method`, `jsonrpc` "1.0" or missing, a
  fractional id) → `-32600` with that id; a batch → an array of `-32600`
  ("batches are not supported", removed in 2025-06-18), an empty batch →
  one `-32600`. Before, the SDK logged a zod dump and the client hung.
- **One body limit for both transports (P2-08, S4).** HTTP used the SDK's
  4 MiB default (a schema-max CJK document got 413 over HTTP, accepted over
  stdio); both now use the 16 MiB limit.
- **Host header with userinfo → 400 (P2-09, S4)**, not the SDK's 500.
- **Missing resource is "resource not found" (P2-10, S4)**, not `-32603`
  internal error. It is the SDK's `ResourceNotFoundError`: code `-32602` with
  `data.uri`, which is what the 2026-07-28 spec requires (clients SHOULD also
  accept the older `-32002`; SDK 2.4 re-encodes a thrown `-32002` as
  `-32602` on every revision, so `-32002` cannot be sent through it).
- **Lifecycle and ping on stdio (P2-11, S4).** A request before the
  handshake that is neither `initialize` nor a 2026-07-28 request carrying
  the `_meta` envelope → `-32600 "Server not initialized"` (a `tools/call`
  sent first no longer writes); a notification before it is dropped, so it
  cannot pin a 2025-era connection without its handshake. `ping` is answered
  before the handshake and on 2026-07-28 connections (was `-32601`). On a
  2026-07-28 stdio connection every request must carry the envelope: none →
  `-32602`, an unsupported version → `-32022` (the SDK checked only the
  opening request).
- **Existing `http-bearer.token` readable by others is tightened to 0600
  (P2-13, S4)** and the start-up line says so.
- **Schema-valid ids and ranges (P2-14, S4).** `block_id` accepts every
  8-4-4-4-12 hex id the published `format: uuid` admits (it required an
  RFC 4122 version nibble); `checkpoint_chain` with `to_seq` beyond the head
  → `invalid_params`, not `internal`.

SDK-only limits left: the SDK's own stdio transport still behaves as before
for embedders that call `serveStdio` without kronicle-lite's transport; see
the PR for the upstream issue text.

### Fixed — storage: read-only / full data dirs, readers behind writers, older writers (F12, F14, C2-08, C2-01)

- **Readers never queue behind a writer (C2-08, S3).** `openDatabase()` ran
  its schema setup in `BEGIN IMMEDIATE` on every open, so `pulse`,
  `pending`, `orient` and `get` waited for the write lock: a writer holding
  it 14 s made the pulse exit 3 and the shim's 10 s timeout run the command
  unchecked (likely the 0.8.0 "1 pulse in 80 took ≥ 10 s" open item). Setup
  now runs only when something is missing (first start, upgrade: a
  read-only check of every schema object, column and seed row); a current
  store opens with plain WAL reads. The orient flight-recorder row waits at
  most 1 s for the lock, then is skipped. The concurrent-first-start path is
  unchanged. (sea-lite's `scope-check` gets this when it bundles 0.8.1.)
- **A read-only or full data dir is still read (F12, S3).** `verify-chain`,
  `doctor`, `orient`, `pending`, `get` and `pulse` failed ("unable to open
  database file"; even a read-only handle cannot open a WAL database without
  its `-shm`). The store now falls back to a read-only open, then a private
  snapshot (database + WAL copied to a 0700 temp dir), then an in-memory
  image when there is no WAL to lose; read-path bookkeeping (briefing row,
  read log) is skipped there, and any real write fails loudly
  (`SQLITE_READONLY`). A store that exists but cannot be read at all raises
  `StoreUnreadableError`: the pulse refuses it as `unreadable` (the 0.8.1
  shim classification, exit 77 in deny mode). `verify-chain` / `verify` open
  read-only and exit **2** with "I/O, not a chain divergence" when the store
  cannot be read (1 stays a real divergence); `doctor` exits 2 then (new
  `db-open` check), and on a read-only open no longer reports the FTS index
  as inconsistent (FTS5's integrity-check is an INSERT command: skipped and
  said so).
- **`export | head` (F14, S4)** ends quietly with exit 0 instead of an
  unhandled EPIPE stack trace and exit 1 (every command but `serve`).
- **Older writers (C2-01, S3).** Nothing recorded the writer, so 0.5.0–0.7.0
  opened and wrote 0.8.x stores silently; `0.5.0/0.6.0 rebuild` nulled every
  `project_key` (one project's notes recalled from another) and no check
  noticed. Now:
  - every append records `meta.writer_version` / `meta.writer_head_seq` in
    its transaction;
  - `doctor` (new `writers` check) and `verify-chain` (whole chain) report
    project keys the chain does not derive (fail; `kronicle-lite rebuild`
    repairs) and events appended after the last 0.8.1+ append (warn: an older
    version wrote since);
  - a guard trigger makes the rebuild of 0.7.0 and older fail with "no such
    function: kl_writer_guard" and roll back (only rebuild deletes document
    revisions; normal puts by older versions, e.g. sea-lite 0.6.0's bundled
    kronicle-lite 0.7.0, are unaffected);
  - `meta.min_writer_generation` (now 1): a future version that bumps it
    makes this one refuse to write that store with a clear message.
  Old versions check neither `user_version` nor `schema_version`, so their
  normal writes cannot be refused; they are detected afterwards.

### Fixed — a pulse never says "proceed" on a damaged or tampered store (L2-01, L2-03, R2-09)

- `get_system_state` with `focus: "pulse"` returned `integrity: null` and
  "No changes since your last look; proceed" on a store whose `blocks` rows
  were edited; the other foci reported `ok: false`. Live agents deployed
  from a tampered store 5/6 times. The pulse now runs the same integrity
  pass as `focus=retractions` and always reports it.
- The integrity pass (every focus) and recall now cross-check the
  projection against the chain, cheaply (index lookups and counts, plus a
  replay of the indexed lineage-bearing events cached per process): no live
  row the chain retired, retired/tombstoned/block counts, supersession
  pointers, and `doc_lineage` / `doc_lineage_gaps` rows. Before, a
  superseded row made live again (a partial restore of `blocks`) or deleted
  lineage rows left `integrity.ok` true: recall served the old text,
  `pending` dropped to 0 and a stale note read fresh. Recall now withholds
  such hits (`projection_mismatch`, `lineage_mismatch`).
- A long-lived server (MCP) whose store file changed on disk under its
  SQLite page cache (a zeroed page) kept answering every focus from the
  cache, "proceed" included. Each integrity pass now stats the file; when it
  changed, the cache is dropped and `PRAGMA quick_check` runs. A damaged
  file, or any SQLite error during orient (`SQLITE_CORRUPT`, `NOTADB`, I/O),
  is `integrity.ok: false` with the error and an unmoved cursor; recall
  withholds every hit (`store_damaged`). (The shim's fail-open on an
  unreadable store is fixed on the shim side.)

### Fixed — absence is never certified from an index that disagrees with the text (R2-17)

- A rewritten full-text row let recall certify `absent_in_searched` with
  `index_fresh: true` for a term a live block holds, while orient,
  `verifyAll` and `doctor` all passed. Before certifying absence, recall now
  runs FTS5's content check (`integrity-check` with rank 1, cached until the
  database changes) and answers `cannot_certify` on a mismatch; orient
  (`orientation` / `recent_changes`), `verifyAll` / `verify-chain` (table
  `blocks_fts`) and `doctor`'s `fts` check report it.

### Fixed — lineage (R2-04, R2-05, R2-14, R2-15, C2-05; leads L3, L4)

- Inference counted only reads since the actor's LATEST briefing, so
  recall → orient → write (what the wake contract asks) left the note with
  no lineage, and a file-backed note stayed `can_act` after its source
  changed. The bound is now the union of the session and the last 24 h / 200
  most recent reads, whatever briefings came in between.
- The session is a chain position (the cursor's seq, else the latest
  briefing's), never a wall-clock comparison: a briefing clock 3 s ahead
  dropped every read (0 edges, `truncated: false`, no `derived` retraction).
  An inference that finds nothing while the actor did read blocks outside
  every bound is flagged `derived_from_inferred_truncated`.
- A note whose sources cannot be determined (inference cut short by the
  bound, or more than 4 notes below its sources) is never `can_act`: new
  honesty cap `inspect_only` / `lineage_unknown`. Projected as
  `doc_lineage_gaps`.
- `Lineage.staleness` memoised results cut short by a cycle or the depth
  bound, so in one recall a stale note could be served unmarked
  (`inspect_only / no_source`) after its cycle partner or a deeper note was
  evaluated. Cut-short results are memoised only at the root; a note in a
  cycle with a stale member is `never_act`.
- A note derived from a source that was later removed (or moved to another
  document) stayed stale forever unless lineage was re-declared explicitly.
  A put that re-derives (the author read the source's document after the
  removal, or rewrote the note from material read after it) records
  `derived_from_released` and drops those edges.
- `derived` retractions were listed only for notes with a direct edge to
  the changed block; a note derived from a stale note now gets its own
  (`derived_from_change.via`), within the depth bound.
- **L3.** `Lineage.staleness` memoized results cut short by the depth bound
  (4) or by a cycle, so in one read (recall, orient, pending) a note
  evaluated after its descendant or cycle partner could show fresh while
  derived from a stale note. Cut-short results are no longer reused.
- **L4.** Lineage inference began at the actor's LATEST orient, so recall →
  orient → write — what the wake contract tells agents to do — inferred no
  lineage. Fixed by R2-04 / C2-05 below (session as a chain position, unioned
  with the 24 h / 200 most-recent-reads window); the interim cursor-chain
  walk by briefing time was dropped (it compared wall clocks, C2-05).

### Fixed — the pulse gate and wording (R2-07, R2-08, C2-03, C2-04)

- With no stored shim position (new worktree, wiped state), or one that
  does not decode or verify (junk bytes, a regenerated `cursor-secret`, a
  chain rolled back below it), `pulse --pending-actor A -- git push` seeded
  or re-seeded and allowed although A had an unreconciled change. It now
  asks A's `pending` and refuses (`reason: "pending"`, exit 77) without
  seeding. A regenerated `cursor-secret` is reported on stderr and flagged
  on the identity.
- A denial was recorded as the shim actor's briefing, so after a rollback
  the plain retry recovered from the denial itself and was allowed. Pulse
  briefings are recorded only when the pulse allows.
- A pulse counted changes since the actor's latest briefing, not since the
  cursor it was given: another session with the same actor id could turn an
  old-cursor pulse into "proceed". It now counts from the presented cursor;
  with no valid cursor it never says "proceed".

### Fixed — secret guard (R2-10, R2-11)

- A PEM private key whose body lines are indented or prefixed (YAML block
  scalar, list item, block quote, comment) passed the write guard.
- `db_password: …`, `"dbPassword": "…"`, `db-password=…`, `apiToken: …`
  were neither refused nor scrubbed. New `password_assignment` detector
  (write and read): a key containing password/passwd or ending in
  pwd/secret/token, in snake, camel or kebab case, with `:`, `=` or a JSON
  pair and a real-looking value. Placeholders (`${ENV}`, `<redacted>`,
  `changeme`, `example`, `example-password-1`) still pass; a value that
  merely contains "example" no longer does.
- A soft hyphen or zero-width character inside a token no longer hides it
  (normalised for detection only; never for storage).

### Changed

- skills/orient: orient (`focus=retractions`) before release-type wrappers
  (`make release`, `npm run release/deploy/ship`, deploy scripts) and again
  after a change lands during a world-changing step; recommend the shims or
  the git hook for wrappers (L2-07).
- Recall `withheld[].problem` adds `projection_mismatch`,
  `lineage_mismatch`, `store_damaged`; `authority_reason` adds
  `lineage_unknown`; pulse `reason` adds `pending` (with `pending[]`), and
  in actor mode the invoking actor's `pending` gates a pulse that has no
  usable position.
- Cost: the projection half of the integrity pass (live-block re-hash,
  lifecycle and lineage rows, FTS content) is memoised per database state
  (`data_version`, this connection's `total_changes`, chain head), so repeated
  pulses on a long-lived server cost a lookup; any write by any connection
  re-runs it. The lifecycle check uses `IN` over the retired ids instead of a
  correlated `EXISTS` (seconds → milliseconds on a 1k-document store).

### Migration

- Forward-only and safe on existing stores: a new projection table
  `doc_lineage_gaps`, a partial index `events_lineage_idx`, and a one-time
  backfill of the gaps from the chain (meta `migration.lineage_gaps`). No
  event is touched; `rebuild` re-derives both.

### Tests

- Both bench corpora are permanent tests (`test/stress-corpus.test.ts`):
  round 1 false format-only 0/38; round 2 (69 cases) every real change a
  retraction, 0/61 hidden (W01 two spaces → one and W06 tab → space
  included). The
  R2-01..03 and L2 repros run through the CLI (orient / pending / pulse
  exit 77) with a temp HOME and data dir (`test/fix-081.test.ts`), with
  L1–L6. Two new mutants (emphasis-marker folding, list renumbering) join
  the six; all eight are killed.

### Bench (agent-memory-bench Track A, branch `kl-0.8.1`, 20 seeds)

- S7 benign-edit quiet rate **10/20 (0.8.0) → 4/20 (0.8.1)**, by design:
  only `whitespace_trim` and `line_ending_norm` stay quiet;
  `whitespace_double`, `numbered_list_renumber` and `markdown_emphasis` are
  now delivered as retractions (the typo, comma, quote, period and hyphen
  templates already were). S1, S5, S8 and S11: grades and flags identical
  on every seed.

## [0.8.0] — 2026-11-01

### Fixed — a pulse never reads as a clean bill

- `get_system_state` / `orient` with `focus: "pulse"` used to end with
  "Within threshold; proceed" whenever fewer changes than the drift threshold
  had landed — even when one of them changed a runbook the agent relied on
  (a pulse lists no retractions). In the release re-run of agent-memory-bench
  every pull-only agent failure (2 in T1, 1 in T7) came from trusting that line.
  A pulse now says "proceed" only when nothing changed and nothing is pending;
  otherwise it tells the agent to re-read pending items or call
  `focus=retractions` before a world-changing command. The orient skill says
  the same. Affects 0.5.0–0.7.0.

### Added — derived-note lineage (Track A S1 "next-session stale copy")

- A note an agent writes from what it read now records which exact block
  versions it rests on: `put_document` / `supersede_block` take
  `derived_from: [{block_id, content_hash}]` (CLI `put` / new `supersede`:
  `--derived-from ID:HASH,…`), and every write also records
  `derived_from_inferred`: each block the writing actor read (recall hits,
  document reads) since its session started (the briefing behind the
  `cursor` it passes, else its latest orient), one edge per block (the
  latest version read). Bounded: an actor that never oriented has no
  session, and then only its reads of the last 24 h count, at most the 200
  most recently read blocks; a write that left reads out records
  `derived_from_inferred_truncated: true` (chained, and in the reply's
  `lineage`). Inside those bounds inference over-approximates on purpose
  and downgrades exactly like declared lineage. Instruction-file imports
  infer nothing. Chained as additive
  payload fields (`document.put`, `block.created`); a write without lineage
  hashes as before. Projection table `doc_lineage`, checked by the
  projection check and rebuilt by `rebuild` / `import` (docs/FORMAT.md §3.10).
- When a source block is superseded, moved to another section or
  tombstoned (format-only edits excepted) and the note was not re-derived
  from the current version, the note's recall hits are `never_act` /
  `stale_derived` (new honesty rule 3, rows after it renumbered 4–10) and
  carry `stale_derived: [{source_block_id, source_content_hash,
  source_doc_slug, change, seq, current_block_id, current_content_hash,
  old_text, new_text, inferred, via?}]`. A note derived from a stale note is
  stale (`via`). `can_act` is impossible for a stale note, whatever its own
  file says (docs/HONESTY.md §6).
- `get_system_state` lists a retraction of the new kind `derived` for each
  note made stale by a change in the window: the note's slug and text, the
  source's word diff, and `derived_from_change`.
- Re-deriving clears it: a put / supersede of the note that (declares or
  infers) the current version. A `put` with an explicit `derived_from`
  (even `[]`) replaces the note's lineage; every other write adds to it.

### Added — version-bound reconciliation (`pending`)

- A local read log (`reads`, never chained; docs/FORMAT.md §4.2) records the
  exact version each actor read: recall hits (with or without receipts),
  document reads (`kronicle://docs/<slug>`, new CLI `get`), and the actor's
  own writes.
- `pending`: per actor, every change to a block it read or wrote — or to a
  source of a note it read or wrote — that it has not re-read at the CURRENT
  version (the live lineage head or a format-only twin; for a removal, the
  document or the tombstone read after it). Delivery never clears it;
  reading an older version never clears a newer change. Format-only edits
  are never pending. Project-scoped (`pending_hidden`).
- Exposed on `get_system_state` and every `orient --json` focus (`pulse` and
  `retractions` included) as `pending[]` (≤ 20), `pending_count`,
  `pending_actor`, `pending_hidden`; `orient --pending-actor A` computes it
  for the agent while the hook keeps its own actor. New CLI
  `kronicle-lite pending --actor A --json` for hook gates (docs/PUSH.md
  "Pending"). Rendered as a "Pending" section (and a pulse line); a briefing
  with pending items is never the one-line quiet answer.
- Contract: additive only. Every existing field keeps its meaning;
  `retractions[].kind` gains the value `derived`.

### Added — exec-time pulse shims (any client)

- `kronicle-lite shim install|status|ack|uninstall [--dir D] [--commands …]
  [--world "make release,docker push"] [--data-dir …] [--mode deny|warn]`:
  tiny wrappers on PATH for `git`, `terraform`, `tofu`, `kubectl`, `helm`,
  `npm`, `pnpm`, `yarn` (plus `oc`, `make` and user commands on request)
  that check kronicle-lite at the moment the real binary runs. Covers
  clients without hooks (Cursor, Codex, Hermes, humans, CI) and the cases a
  pre-call check cannot see (a change during `build && deploy`, deploys
  inside `make release`, `bash -c`, wrapper scripts). Council round 2
  "PATH shims" + "action permits".
- POSIX sh wrappers decide with shell builtins only: read-only invocations
  (`git status`, `terraform plan`, `kubectl get`) exec the real binary with
  ~1 ms overhead and no node start. World-changing ones (`git push|subtree
  push|lfs push`, `terraform|tofu apply|destroy`, `kubectl apply|delete|
  patch|replace|rollout …`, `helm install|upgrade|uninstall|rollback`,
  `npm|pnpm|yarn publish`, `run deploy|release|…`, user patterns; tool
  global options skipped as in cc-anchor's pulse matcher) run the pulse
  (~0.2 s) and are refused with exit 77 and the retraction diff on stderr
  while a blocking retraction is unreconciled. `kronicle-lite shim ack
  --through SEQ` clears the gate per project, never past SEQ.
- Fail open (noted once, logged) when kronicle-lite is missing or broken;
  fail closed on a store integrity failure, in warn mode too.
- A check that times out (`KRONICLE_SHIM_TIMEOUT`, default 10 s) is a
  safety check that did not happen, so it is never quiet: every occurrence
  prints ``kronicle-lite check TIMED OUT after Ns — `<cmd>` was NOT
  checked; see .kronicle-shim/shim.log``. `shim install --on-timeout
  allow|deny` (stored in the config, baked into the wrappers): `allow`, the
  default, runs the command; `deny` refuses it with exit 77. In the
  agent-memory-bench S16 runs about 1 call in 80 hit the 10 s timeout and
  ran unchecked; root cause still open.
- `shim.log` records every world-changing call: the wrapper's `check <ms>
  outcome=… rc=…` and the check's own `pulse(node) boot / open / check /
  total` milliseconds, so slow checks can be split into node start-up,
  store open (SQLite lock waits) and the check itself. Real binary resolved on PATH minus
  the shim dir; self-recursion guarded (same-process exec chain via
  `KRONICLE_SHIM_EXEC`, nesting depth 8 via `KRONICLE_SHIM_DEPTH`).
  Install refuses system directories, non-shim files and symlinks;
  uninstall removes only marker-carrying files.
- Windows: `.cmd`/`.ps1` wrappers delegate to `kronicle-lite shim exec`
  (same decision in TypeScript; one node start per call; not yet run on a
  Windows machine).
- `kronicle-lite pulse [--cursor C | --state D] [--mode] [--pending-actor
  A[,B]] [--json] [-- CMD…]`: the check as one CLI call for any hook —
  orient `focus=retractions` plus the integrity pass → `allow | deny | warn
  | seed`; exit 0 / 77 / 3 (no store).
- The gate is version-bound (the `pending` rule): a blocking retraction is
  resolved once every pending actor has read the CURRENT version of the
  changed block (recall hit, document read, own write; for a removal, the
  document after it; for `derived`, the note's source). Pending actors:
  `shim install --pending-actor A[,B]` / `pulse --pending-actor`, else
  everyone who read any version of the changed block (and, for `derived`,
  read or wrote the note). An agent that re-reads the runbook through
  recall clears the gate itself; `shim ack --through SEQ` stays as the
  manual override. Reading an older version, or receiving the push, never
  clears it; no recorded reader = blocking until read or acknowledged;
  integrity failure still fails closed. `pulse --json` adds `resolved[]`,
  `pending_actors` and `blocking[].pending_actors` / `.unread_by`; each
  denial line names who has not re-read.
- docs/PUSH.md § Shims (matcher table, acknowledgement, recursion, Cursor /
  Codex / Hermes set-up); README section. Tests: a 105-case decision table
  run through the TypeScript classifier and the generated sh under dash and
  bash, wrapper end-to-end in temp dirs (argv byte-exact, PATH spellings,
  exec-wrapper and child-wrapper recursion, deny/ack/warn, per-project ack,
  integrity in both modes, fail-open on no store / missing CLI / timeout,
  install safety), the read-only overhead measurement, and version-bound
  reconciliation (re-read clears without ack, an older version does not, a
  newer change blocks again, every reader / the configured actor, removal,
  derived note, ack override, integrity still closed).

### Fixed — a project reached through a symlink lost every retraction (0.7.0)

- 0.7.0 keyed a project by the path spelling it was given: `put` recorded
  the physical working directory (macOS `/private/var/…`) while a hook or
  `--cwd` passed the symlinked spelling (`/var/…`, a linked checkout), so
  the two got different project keys and project-scoped `orient` /
  `get_system_state` / `recall` showed 0 retractions for the other spelling.
  0.7.0 users whose project path goes through a symlink were affected
  (found by cc-anchor's macOS CI). Every working directory, project root and
  instruction file path is now canonicalised with `realpath`
  (`realpathSync.native`; a deleted file through its nearest existing
  ancestor; on Windows a case-only difference keeps the given spelling)
  before a key is computed: put, watch, the FileChanged hook, orient,
  recall, pending, pulse and the shims all agree. Instruction files first
  imported under the symlinked spelling's key are imported once more under
  the canonical key; the old copy stays, scoped to the old key.
  `test/symlink-project.test.ts`: put via the real path and orient / pending
  / pulse via the link, and the reverse, plain dir and git repo.

### Bench (agent-memory-bench Track A, branch `kl-next-release`, 20 seeds)

- **S1 next-session stale copy served unmarked: 20/20 → 0/20**
  (`nextSessionPass` 0/20 → 20/20), with the bench's unchanged adapter: the
  agent never declares lineage, so this is inference alone. S1, S5, S7, S8,
  S11 grades identical to 0.7.0 on every seed. Touch views where something
  the agent read changed grow by the `derived` retraction and the Pending
  section (S1 2.45 → 3.24 KB, S5 3.10 → 3.60 KB, S7 1.44 → 1.61 KB); quiet
  cells are byte-identical. `results/track-a-kl-next-release/COMPARE.md`.
- Derived-retraction noise: S7 0 on every seed (no note); diagnostic
  S7 + note: 10, exactly the 10 real-edit seeds, 0 on format-only seeds
  (within-session over-approximation; grades unchanged). An actor that
  never oriented (2,000 reads over 7 days, 978 blocks): 978 → 200 inferred
  edges, and 50 → 8 of 50 random source edits mark its note stale.
- S16 exec-time gate: refused at exec with the diff as on `shims`; new
  variant "re-read, no ack" 0/19/1 → 20/0/0. Open item, pre-existing on
  `shims`: about 1 pulse in 80 bench cells took ≥ 10 s, hit the shim
  timeout and failed open (documented behavior); not reproduced outside
  the harness (220 runs).
- Hook path, 300-document store, 2.2k reads, 50 changed blocks read:
  `pending` ≈ 87 ms in-process; `orient --focus retractions --json
  --pending-actor` ≈ 0.39 s per CLI call vs ≈ 0.29 s without pending items
  (Node start-up dominates). A partial expression index on the retiring
  block id of `block.superseded` / `block.tombstoned` events (the same
  expression `chainRetired` uses) keeps change lookups indexed.

### Changed

- `tools/list` (full): 14,418 → 15,462 bytes (+1,044: `derived_from` on
  `put_document` and `supersede_block`; `pending*` and `lineage` in output
  schemas). `--core`: 10,655 → 10,879 bytes (+224; `derived_from` is not
  offered in `--core`, inference still runs there; shims are CLI-only).
  Catalog re-pinned for 0.8.0:
  `2e47e0a7236e8640cea65a10228f1cf7b8e4602226635ad50cb35e6bbfca9d40` (full),
  `65245f5a33d781ba611716bc18cd42234088e874e95d67f6676ba8ec799a1611` (core).
- The POSIX shim wrapper tests and the generated-sh decision run are
  skipped on Windows (no POSIX shell; its wrappers are `.cmd`/`.ps1` →
  `shim exec`); the `pulse` CLI contract and the TypeScript decision table
  run everywhere. The "exits 127" test no longer assumes `kubectl` is
  absent from the system PATH (CI images ship one).
- Docs: stale "(unreleased)" labels for 0.6.0 / 0.7.0 features fixed
  (FORMAT §§3.2, 3.7–3.9, §6, README).
- Tests: `test/lineage.test.ts` (unit, including the inference bounds:
  24 h / 200 blocks, truncation flag, session bound, lineage dedupe), `test/lineage-cli.test.ts` (CLI and
  MCP contract), `test/lineage-property.test.ts` (seeded: 60 random
  supersede / format-only / tombstone / move / rename sequences never leave
  a derived note `can_act` after a real source change, and format-only edits
  or renames alone never mark it; 60 random edit / read-a-random-version /
  remove sequences resolve only on a current-version read). Four mutants of
  the rules (older read resolves, removal counts as fresh, no format-only
  equivalence, moves as format-only) are each killed by the suite.

## [0.7.0] — 2026-11-01

### Fixed — 0.7.0's cosmetic classifier hid real changes (release blocker)

- 0.7.0 filed `./bin/deploy --target staging-a` → `staging-b` as a
  "cosmetic edit" (no retraction, nothing pushed): the stale-runbook case.
  An adversarial corpus found 27 of its 38 real changes hidden the same way:
  typo-shaped names, units and formats (http→https, mysql→mssql,
  megabytes→megabits, eight→eighty, Mark→Mary, payments→payment,
  stable→stale), hyphen-joined names (staging-east→west), every date on an
  "As of / Updated / Revised" line, and Unicode folding (`2³` → `23`).
- Redesign: **format-only** = Markdown AST equivalence with exact text
  leaves (docs/FORMAT.md §3.8). Same tree under a narrow pinned parser,
  every text leaf byte-identical except collapsed whitespace runs in prose;
  code, inline code, link targets, raw HTML and unknown syntax opaque; no
  typo, case, hyphen, quote, punctuation, date/review-stamp or Unicode
  normalization anywhere. Covers reflow, whitespace runs, `*`↔`_`, bullet
  and list-delimiter style. Everything else is a normal retraction with its
  diff; `hint: "likely_typo"` is a label only.
- Renames: `cosmetic` → `format_only` (retraction field),
  `format_only_edits` (alias `cosmetic_edits`), `include_format_only` /
  `--include-format-only` (aliases `include_cosmetic` /
  `--include-cosmetic`). The format-only list is the only thing orient may
  leave out of `retractions`.
- Tests in CI: the 38-case stress corpus (false format-only 0/38;
  `test/stress-corpus.test.ts`), 33 must-alarm cases, a seeded property
  test (400 single-character mutations — hyphen, digit, case flip,
  compatibility/combining characters — across prose, identifiers, URLs,
  numbers, dates and code of real runbooks: never format-only, always
  visible), and mutation tests that re-introduce each removed heuristic
  (hyphen strip, lowercase, typo rule, date mask, NFKC, gate trusts the
  label) behind a test-only switch and require the suite to fail (6/6
  killed).
- Bench S7 (benign-edit noise) drops by design: only reflow/whitespace,
  list-delimiter and emphasis-marker templates stay quiet; typo, comma,
  quote, period, hyphen and review-date edits are delivered.

### Fixed — a paragraph moved to another section was invisible

- `planRevision` carried a block by content hash even when its heading path
  changed, so "Force-push" moved from "## Allowed" to "## Forbidden" made no
  retraction and old receipts kept verifying. Now a block whose heading
  path changes (moved section, renamed or re-levelled ancestor heading) is
  superseded by an identical-text block under the new path: a retraction
  with `new_heading_path`, a `section: [-Allowed-]{+Forbidden+}` diff and
  "MOVED to …", and the old receipt verifies `SUPERSEDED`. Reordering whole
  sections still carries.

### Fixed — one corrupt event payload crashed orient

- A non-JSON `events.payload_canonical` made `orient` / `get_system_state`
  throw (exit 1), which a push hook reads as "nothing to push". Events are
  now read with an empty payload; `verify()` reports `payload_unparseable`
  at the seq (verify-chain exits 1 with it, the projection check reports
  instead of throwing); every orient focus, `pulse` included, answers with
  `integrity: {ok: false, problem, seq}` and an INTEGRITY FAILURE line
  first. docs/PUSH.md: "kronicle unavailable" (non-zero exit: fail open)
  vs "integrity failure" (push it; a pulse blocks).


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
- The database side of the same race (seen on Windows CI as "database is
  locked"): every connection sets `busy_timeout` (10 s) before its first
  statement; switching to WAL is retried while another process holds the
  file; schema creation, migrations and the seed rows run in one
  `BEGIN IMMEDIATE` transaction (the write lock is taken up front, so two
  processes never deadlock upgrading a read to a write), retried on
  SQLITE_BUSY / SQLITE_LOCKED for up to 10 s.

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
