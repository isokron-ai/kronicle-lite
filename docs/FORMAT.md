# kronicle-lite data format (v1)

This document is the product. Everything a verifier needs to re-derive every
hash and signature in a kronicle-lite database is specified here, with worked
examples you can reproduce in any language. The format is kronicle-lite's own;
it is not compatible with any other chain or receipt format.

Conventions:

- **Canonical JSON** = RFC 8785 (JSON Canonicalization Scheme). Object keys
  sorted by UTF-16 code units, no whitespace, numbers in ECMAScript shortest
  form, strings escaped per JCS. We use the `canonicalize` npm package.
- **Hex** is lowercase. **Timestamps** are ISO 8601 UTC with milliseconds
  (`2026-01-01T00:00:00.000Z`).
- `||` is byte concatenation of UTF-8 strings unless stated otherwise.

## 1. Chain events

One SQLite row per event in `events`:

| column | meaning |
|---|---|
| `seq` | 1-based position; dense, no gaps |
| `event_id` | UUID (v4), unique |
| `event_type` | dotted name, e.g. `block.created` |
| `payload_canonical` | the payload, stored in canonical JSON |
| `actor_id` | who appended |
| `occurred_at` | timestamp |
| `nonce` | 16 random bytes, hex (32 chars) |
| `prev_hash` | `this_hash` of `seq - 1`, or the genesis hash for `seq = 1` |
| `this_hash` | the event hash (below) |
| `idempotency_key` | optional caller key, unique when present |

`chain_head` holds one row `(seq, hash)` mirroring the last event. It is
written in the same transaction as the insert (`BEGIN IMMEDIATE`), which is the
single-writer discipline: SQLite serializes writers across processes.

### 1.1 Genesis

```
GENESIS_STRING = "kronicle-lite-genesis-v1"
GENESIS_HASH   = sha256(GENESIS_STRING)
               = 82e2f801fe92b883565ca82840049af743d916682007b0345395f067266e0382
```

The genesis hash is public. Anyone holding a copy of the database can verify
the chain from `seq = 1` without any secret or key.

### 1.2 Event hash

```
envelope = canonicalize({
  event_id, event_type, actor_id, occurred_at,
  payload                 // the JSON object, nested allowed
})
preimage  = envelope || "|" || decimal(seq) || "|" || prev_hash || "|" || nonce
this_hash = hex( sha256( utf8(preimage) ) )
```

Design notes:

- The envelope binds `event_type`, `actor_id`, `occurred_at` and `event_id`
  into the hash. A hash over the payload alone would let someone flip
  `block.tombstoned` to `block.noop` undetected.
- `seq` and `prev_hash` bind position and linkage; the `nonce` makes two
  otherwise identical events hash differently and frustrates precomputation.
- The payload is hashed in canonical form, so key order in the caller's object
  is irrelevant.

### 1.3 Worked example

Event 1 (prev = genesis):

```
event_id    = 6f1c2a3e-8b4d-4c5e-9f60-1a2b3c4d5e6f
event_type  = note.added
actor_id    = alice
occurred_at = 2026-01-01T00:00:00.000Z
payload     = { "b": 2, "a": "x", "nested": { "z": [1, 2], "y": null } }
nonce       = 000102030405060708090a0b0c0d0e0f

envelope  = {"actor_id":"alice","event_id":"6f1c2a3e-8b4d-4c5e-9f60-1a2b3c4d5e6f","event_type":"note.added","occurred_at":"2026-01-01T00:00:00.000Z","payload":{"a":"x","b":2,"nested":{"y":null,"z":[1,2]}}}
preimage  = <envelope>|1|82e2f801fe92b883565ca82840049af743d916682007b0345395f067266e0382|000102030405060708090a0b0c0d0e0f
this_hash = 7433c20300c2d4754590bc84201e59784ab5d32601a0ffdf8805519729fb7d7b
```

Event 2 (prev = event 1):

```
event_id    = 7a2d3b4f-9c5e-4d6f-a071-2b3c4d5e6f70
payload     = { "a": "y" }            (other fields as above)
nonce       = 101112131415161718191a1b1c1d1e1f

envelope  = {"actor_id":"alice","event_id":"7a2d3b4f-9c5e-4d6f-a071-2b3c4d5e6f70","event_type":"note.added","occurred_at":"2026-01-01T00:00:00.000Z","payload":{"a":"y"}}
this_hash = a271676cbace94eb0aef27889573fb0629afb55127d32c830cc27066c65007fb
```

Shell check for event 1:

```sh
printf '%s' '{"actor_id":"alice","event_id":"6f1c2a3e-8b4d-4c5e-9f60-1a2b3c4d5e6f","event_type":"note.added","occurred_at":"2026-01-01T00:00:00.000Z","payload":{"a":"x","b":2,"nested":{"y":null,"z":[1,2]}}}|1|82e2f801fe92b883565ca82840049af743d916682007b0345395f067266e0382|000102030405060708090a0b0c0d0e0f' | sha256sum
# 7433c20300c2d4754590bc84201e59784ab5d32601a0ffdf8805519729fb7d7b
```

### 1.4 Verification (`verify_chain`)

Walk `seq` ascending from `from_seq`:

1. `seq` must equal the previous `seq + 1` (else `seq_gap`).
2. `prev_hash` must equal the previous event's `this_hash`, or genesis at
   `seq = 1` (else `link_broken`).
3. Recompute `this_hash` per §1.2; it must match (else `hash_mismatch`).
4. After the last event, `chain_head` must equal `(seq, this_hash)` of the
   last event (else `head_mismatch`).

The first failure is reported with its `seq`. Then every stored checkpoint
whose range lies inside the verified prefix is checked (§2).

## 2. Checkpoints

A checkpoint is a signed Merkle root over the event hashes in `[from_seq, to_seq]`.

```
leaf_i = sha256( utf8( canonicalize({ seq: seq_i, this_hash: hash_i }) ) )   // 32 bytes
node   = sha256( left_bytes || right_bytes )                                  // 32 bytes
```

Leaves are in ascending `seq`. At each level, pairs are hashed left-to-right;
an odd trailing node is promoted unchanged. The root of a single leaf is that
leaf. `root` is the root as hex.

Signing payload and signature:

```
payload   = canonicalize({ v: 1, from_seq, to_seq, leaf_count, root })
signature = base64( Ed25519_sign( utf8(payload) ) )
```

Stored in `checkpoints` with `key_id`. Worked example over events 1–2 above:

```
leaf_1 input = {"seq":1,"this_hash":"7433c20300c2d4754590bc84201e59784ab5d32601a0ffdf8805519729fb7d7b"}
root         = cb7ed764916eb3bbfaa78d0856c79c68841dc2a8163c8d011fd7b74756b4700b
payload      = {"from_seq":1,"leaf_count":2,"root":"cb7ed764916eb3bbfaa78d0856c79c68841dc2a8163c8d011fd7b74756b4700b","to_seq":2,"v":1}
```

A checkpoint verifies when (a) `key_id` is in `signing_keys` and not revoked,
(b) the signature checks over the payload, and (c) the recomputed root over
the current rows equals `root` with the same `leaf_count`.

## 3. Documents and blocks

`put_document(slug, title, markdown)` normalizes line endings to `\n`, trims
trailing whitespace per line, and splits into blocks:

- an ATX heading line (`#`..`######`) is a `heading` block and pushes/pops the
  heading path; a closing sequence of `#`s is stripped only when a space or
  tab precedes it (0.8.1: `## Use C#` is "Use C#", `## Title ##` is "Title");
- a fenced code block (``` or ~~~, fence included) is a `code` block;
- any other run of non-blank lines is a `paragraph` block.

```
content_hash = hex( BLAKE3-256( utf8(block_content) ) )
```

Example: `BLAKE3("Use blue/green for the API.") =
22dc95c8312b3e93aa2a15d4be929b7fbabb3a5e0a624a94196e6355557507f0`.

The heading path is not part of the content hash. Since 0.7.0, a block whose
heading path changes (moved to another section, or an ancestor heading
renamed or re-levelled) is superseded on re-put by a block with the same
text, because "Allowed › X" and "Forbidden › X" mean different things.

### 3.1 Event vocabulary

| event_type | payload fields |
|---|---|
| `document.put` | `doc_id, slug, title, revision, markdown, markdown_hash (BLAKE3), block_ids[], carried[{block_id, ordinal, heading_path}]`, optional `source` (0.4.0, §3.4), optional `project` (0.7.0, §3.7), optional `derived_from[]` / `derived_from_inferred[]` / `derived_from_inferred_truncated` (0.8.0, §3.10), optional `derived_from_released[]` (0.8.1, §3.10) |
| `document.revised` | `doc_id, slug, title, revision, markdown, markdown_hash, cause` |
| `block.created` | `block_id, doc_id, doc_slug, revision, ordinal, kind, level, heading_path[], content, content_hash`; from `supersede_block`, optional `derived_from[]` / `derived_from_inferred[]` / `derived_from_inferred_truncated` (0.8.0, §3.10) |
| `block.superseded` | `block_id, successor_block_id, doc_id, doc_slug, revision, reason` |
| `block.tombstoned` | `block_id, doc_id, doc_slug, revision, reason` |
| `document.renamed` (0.5.0) | `doc_id, from_slug, slug, revision, reason` — same document, new slug; revisions and blocks are keyed by `doc_id` and carry over. Since 0.7.0, also written when an instruction file moves inside its project with its content intact (`reason: "moved: <old path> → <new path> (same content)"`), followed by a `document.put` recording the new `source.path` with every block carried |

Block content and document markdown live in the chain, so the chain alone
rebuilds the tables (`kronicle-lite import`, `kronicle-lite rebuild`).
Readers older than 0.5.0 ignore `document.renamed` (no projection), so the
document keeps its old slug there; nothing else changes.

### 3.2 Revision diff

On a re-put, live blocks are compared to the freshly parsed set:

1. same `(kind, content_hash, heading_path)` → **carried** (block id kept,
   position updated); a reorder of whole sections carries;
1a. (0.8.1) inside one section (same `heading_path`) carried blocks must keep
   their relative order: the fewest blocks that changed order (those outside
   a longest increasing run of old positions) are **superseded** by an
   identical-text block with reason `reordered in revision N` (orient: "MOVED
   within …", diff `order: same text, new position within …`); insertions and
   removals around unmoved blocks are not reorders;
1b. (0.7.0) same `(kind, content_hash)` under a different
   `heading_path` → old is **superseded** by an identical-text block under
   the new path (orient: `new_heading_path`, a `section: [-old-]{+new+}`
   diff, "MOVED to …");
2. remaining old/new paired in order within the same `(kind, heading_path)` →
   old is **superseded** by new;
3. leftover old → **tombstoned** (`removed in revision N`); leftover new →
   **created**, except:
3b. (0.8.1) a leftover non-heading old block that closely matches a leftover
   new block of the same kind under another heading path (word-multiset
   Dice ≥ 0.6, best match first) is **superseded** by it: moved and edited,
   reported with `new_heading_path`, the new text and a diff, not "REMOVED".

`supersede_block` and `tombstone_block` act on one live block and append a
`document.revised` event carrying the re-rendered markdown.

### 3.3 Lineage

`blocks.superseded_by` forms a chain. `verify()` follows it with a recursive
query to the lineage head. A block is **live** when `valid_to IS NULL AND
tombstoned_at IS NULL`.

### 3.4 Slugs and provenance (0.4.0, additive)

Slugs are either flat (`^[a-z0-9][a-z0-9._-]{0,127}$`, unchanged) or
**namespaced**: a lowercase namespace and `/`-separated segments that keep
the source file's case, at most 128 characters
(`^[a-z0-9][a-z0-9._-]{0,63}(/[A-Za-z0-9][A-Za-z0-9._-]{0,127}){1,16}$`).
Namespaced slugs come from file import; the MCP `put_document` tool still
takes flat slugs only. The `instructions/` and `memory/` namespaces are
reserved for instruction files:

| file (relative to the project root) | slug (0.5.0; `<key>` = project key) |
|---|---|
| `CLAUDE.md`, `AGENTS.md`, `CLAUDE.local.md` | `instructions/<key>/claude-md`, `…/agents-md`, `…/claude-local-md` |
| `<dir>/CLAUDE.md` | `instructions/<key>/<dir>/claude-md` |
| `.claude/rules/<path>.md` | `instructions/<key>/claude-rules/<path>` |
| `.cursor/rules/<path>` | `instructions/<key>/cursor-rules/<path>` (a trailing `.md` dropped) |
| Claude Code auto memory `<memory dir>/<name>.md` | `memory/<memory key>/<name>` (e.g. `memory/acme-api-1a2b3c4d/MEMORY`) |
| any other file inside the project | `instructions/<key>/<path without .md>` |
| a file outside the project and its memory dir | `instructions/external/<8 hex of sha256(path)>-<name>` (unchanged) |

**Project key (0.5.0).** `<key>` = the basename of the git worktree
toplevel (outside git: the working directory), sanitized as below,
lowercased, at most 40 characters, then `-` and the first 8 hex chars of
`sha256(absolute root path, '/'-separated)`: `/work/acme-api` →
`acme-api-<8 hex>`. `<memory key>` is the same recipe over the main
worktree root, the directory Claude Code keys auto memory by.
Since 0.8.0 every root, working directory and file path is canonicalised
first (symlinks resolved with `realpath`; a missing file through its
nearest existing ancestor; on Windows a case-only difference keeps the
given spelling), so a project reached through a symlink (macOS `/var` →
`/private/var`, a linked checkout) has one key whichever spelling a caller
passes.
`$KRONICLE_LITE_PROJECT` (`^[a-z0-9][a-z0-9._-]{0,63}$`) replaces both.
0.4.0 wrote the same slugs without the key (`instructions/claude-md`,
`memory/MEMORY`), so two repositories sharing a data dir overwrote each
other. A 0.5.0 sync adopts such a legacy document for this project only when
its current markdown hash equals the file's and its `source.path` equals the
file's project-relative path: it appends `document.renamed` and continues
under the keyed slug with the same `doc_id`. Otherwise the legacy document
is left as it is.

Segments are sanitized (`[^A-Za-z0-9._-]` → `-`, leading `._-` and trailing
`-` dropped); a slug over 128 characters or 17 segments is cut to its first 16
segments and 119 characters and suffixed with `-` and 8 hex chars of
`sha256(full slug)`. In resource URIs a namespaced slug is
percent-encoded: `kronicle://docs/instructions%2Fclaude-md`.

`document.put` may carry `source`, recorded only when the caller supplies it
(a put without it hashes exactly as in 0.3.0):

```json
{ "kind": "instruction" | "memory" | "file", "path": "CLAUDE.md",
  "git": { "repo_root": "/abs/repo", "commit": "<40 hex> | null", "path": "docs/deploy.md", "blob_sha": "<40 hex>" },
  "project": { "key": "acme-api-1a2b3c4d", "root": "/work/acme-api" } }
```

`git` is present when the put was made with `bind_git` (§3.5). `project`
(0.5.0) is present on instruction and memory imports from inside a project;
`get_system_state` leaves instruction retractions whose document recorded a
different project key out of `retractions` (counted in
`scope.hidden_retractions`, with `scope.verdict: "partial"` since 0.6.0)
unless the caller asks for `all_projects`.

`path` is project-relative, `~/`-relative or absolute, always
`/`-separated. The `doc_sources` table projects the latest put's `source`
per document (a later put without one clears it) and is rebuilt by `import`
like every other projection table. A supersession or tombstone in an
`instructions/` or `memory/` document is reported by orient as a retraction
of kind `instruction`.

### 3.5 Git binding (0.4.0, additive)

`put --bind-git` / `put_document {bind_git: true, source_path}` records, for
the source file, `repo_root = git rev-parse --show-toplevel`, `commit = git
rev-parse --verify HEAD` (null before the first commit), `path` (inside
`repo_root`, `/`-separated) and `blob_sha = git hash-object -- <path>` (the
working-tree blob at put time, committed or not). Outside a repository the
put succeeds without `git` and returns a warning.

At check time the working-tree blob is recomputed the same way. When it
differs (`changed`) or the file is gone (`missing`), receipt `verify`
returns `STALE_SOURCE / stale_source` (in place of `VERIFIED` only: a
superseded or tombstoned block keeps its status), `audit_assumptions`
returns `stale_source` (in place of `current`), and orient lists the
document under `source_drift`. Each carries a diff stat (insertions,
deletions) between the bound content — `git cat-file blob <blob_sha>` when
the object exists, else the stored revision's markdown — and the working
file. A vanished repository or missing `git` is `unavailable`, not drift.
Re-putting with `bind_git` rebinds; a put without `source` clears the
binding.

### 3.6 Projection integrity (0.5.0)

The tables are a projection; their rows carry the seq of the event that
made them (`blocks.chain_seq` → `block.created`, `document_revisions.chain_seq`
→ `document.put` / `document.revised`). A row is intact when

```
BLAKE3(blocks.content) == blocks.content_hash
events[chain_seq] is block.created with the same block_id, doc_id, content, content_hash
recompute(events[chain_seq]) == events[chain_seq].this_hash        (§1.2)
```

(for revisions: `markdown` / `markdown_hash` against the document event).
`recall`, `verify`, the document resource and orient check rows this way
before serving them. The whole-projection check replays every event into an
empty schema and compares `documents`, `document_revisions`, `blocks` and
`doc_sources` column by column, then re-hashes every block and revision.

### 3.7 Document projects (0.7.0, additive)

`document.put` may carry `project: {key, root}` (same recipe as the
instruction project key, §3.4): the MCP `put_document` tool and the CLI
`put SLUG FILE` record the project of the server's / CLI's working
directory. A put without it hashes as before. The projection keeps the
latest put's project in `documents.project_key` (`source.project.key` for
instruction and memory files, else `project.key`, else NULL). Opening an
older database adds the column and backfills it from `doc_sources`.

`recall` and `get_system_state` are scoped to the caller's project keys by
default: documents of another project are not served (recall counts them in
`scope.other_projects_hidden` and lists `other_projects` under
`absence.not_searched`; orient leaves their events out of the delta, counted
in `scope.hidden_events`, and their retractions out of `retractions`,
counted in `scope.hidden_retractions`). Documents with no project (every
put made before this field existed) stay visible from every project.
`all_projects: true` / `--all-projects` turns scoping off.

### 3.8 Format-only edits (0.7.0; raw-text rule since 0.8.1)

Orient classifies each supersession whose old and new block text it still
has (`src/orient/cosmetic.ts`). Since 0.8.1 an edit is **format-only** only
when the two RAW texts are byte-identical after exactly these steps:

1. line endings: CRLF / CR → LF;
2. trailing spaces and tabs removed from every line;
3. reflow inside a paragraph: a whitespace run that contains exactly one
   line break (the break plus the spaces and tabs around it), between two
   non-space characters, becomes one space — except
   inside inline code, link destinations (`](…)`), inline HTML and
   autolinks, and quoted strings (`'…'`, `"…"`, `“…”`, `‘…’`; an apostrophe
   inside a word opens nothing); a line break is never collapsed after a
   backslash hard break or before a line that could open a block construct
   (list marker `-`/`*`/`+` or `N.`/`N)`, `#`, `>`, `|`, `<`, a fence, `[`,
   `=`, `_`, `~`); lines that are table rows (any `|`), headings, quotes,
   HTML, fences, reference definitions, thematic breaks or setext
   underlines, or indented by 4+ spaces or a tab keep every byte and the
   breaks around them;
4. runs of blank lines collapse to one.

Nothing else is normalized: no whitespace runs inside a line (two spaces →
one, a tab → a space), no emphasis markers (`*` ↔ `_`), bullet or
ordered-list markers, renumbering, heading style, escapes, entities, letter
case, quotes, punctuation, dates, typo tolerance, and no Unicode
normalization (NFC / NFKC; no-break and thin spaces, U+2028 and zero-width
characters are text). Code blocks, front matter (a block that opens with
`---` / `+++`) and HTML blocks are opaque, and so is a block with a
construct the scanner cannot close (an unclosed code span, double quote,
`<tag` or link destination): only identical text is format-only there. A
block that moved to another section, or within its section (1a), is never
format-only. Only a line break is reflow: a whitespace run inside one line
is text, because agents copy commands out of unfenced prose, where a double
space or a tab can matter (the founding rule: a false format-only is far
worse than a false alarm).

Why raw text (0.8.1, agent-memory-bench hardening round 2, R2-01..03): an
agent copies the raw Markdown into commands. 0.7.0–0.8.0 compared a narrow
Markdown tree and so filed as format-only `*` ↔ `_` in unfenced globs and
identifiers (`/tmp/*/cache/*` → `/tmp/_/cache/_`, `__init__.py` →
`**init**.py`), list renumbering (and, through a parser bug, `9090. admin`
→ `9091. admin` after a paragraph line), and a backslash hard break vs a
literal backslash. Those, list-delimiter / bullet style and emphasis-marker
style edits are retractions now.

Format-only supersessions are listed under `format_only_edits` (alias
`cosmetic_edits`; entries `seq, doc_slug, block_id, successor_block_id,
rules[] (`whitespace`; `markup` is no longer produced since 0.8.1), diff`) instead of `retractions`; with
`include_format_only` (alias `include_cosmetic`) they are also retractions
with `format_only: true` and severity `informational`. This label is
presentation only: it is the single thing orient may move out of
`retractions`. Every other change is a normal retraction with its diff. A
retraction may carry `hint: "likely_typo"` (one ordinary word of 5+ letters
one edit away); the hint never changes severity, delivery or the reconcile
instruction. Nothing on the chain differs: the classification is a
read-time view.

### 3.9 Unreadable events (0.7.0)

An event whose stored `payload_canonical` is not a JSON object (a hand edit,
a torn page) is read with an empty payload instead of throwing. `verify()`
reports it as `first_mismatch.kind: "payload_unparseable"` at its seq; the
projection check reports it and the rows that depended on it; orient (every
focus, `pulse` included, for the events since the cursor) answers normally
with `integrity: {ok: false, problem, seq}` and an INTEGRITY FAILURE line
first.

### 3.10 Derived-note lineage (0.8.0, additive)

A note written from other blocks records which exact versions it rests on:

```json
"derived_from":          [{ "block_id": "<uuid>", "content_hash": "<BLAKE3 hex>" }],
"derived_from_inferred": [{ "block_id": "<uuid>", "content_hash": "<BLAKE3 hex>" }]
```

- `derived_from` — declared by the writer (`put_document` / `supersede_block`
  `derived_from`, CLI `--derived-from ID:HASH,…`). Each `content_hash` must
  be that block's (a block id names one version); unknown blocks or a wrong
  hash are refused with `invalid_lineage`, nothing chained. A block that is
  no longer live is accepted (the note is stale from the start).
- `derived_from_inferred` — the blocks the writing actor read (recall hits,
  document reads; its own writes excluded) outside the document being
  written, within a bound that is the union of (0.8.1):
  - its **session**: every read made at or after the chain position of the
    cursor it passes, else of its latest briefing. Reads are placed by the
    chain head they were made at (`reads.head_seq`, `receipts.chain_seq`),
    never by wall clock, so a skewed clock cannot drop them;
  - the most recently read blocks within the last **24 hours**, at most
    **200**, whatever briefings came in between (0.8.0 started the bound at
    the latest briefing, so recall → orient → write lost the read). The
    24 h test is a coarse wall-clock cap.

  Sorted by `block_id`, deduplicated by block and by lineage (two versions
  of one block read: only the later one). Instruction-file imports infer
  nothing.
- `derived_from_inferred_truncated: true` (present only when true; the
  write's reply says the same in `lineage`) when the bound left reads out:
  the 200 cap cut a read of the window, or the actor read blocks that
  neither bound covers while there was no session or nothing was read in
  it. The note's sources are then undetermined (0.8.1: recall never labels
  it `can_act`, docs/HONESTY.md `lineage_unknown`) until an explicit
  `derived_from` states them.
- `derived_from_released` (0.8.1, `document.put` only) — earlier inferred
  edges of this note to sources that were REMOVED (the source's lineage
  ends in a tombstone: deleted, or moved to another document), which this
  put re-derives past: the author read the source's document after the
  removal, or rewrote the note (new markdown) from current material it read
  after the removal. A removed source has no current version to re-derive
  from, so before 0.8.1 such a note stayed stale until an explicit
  `derived_from` replaced its lineage.

Both fields are present only when non-empty, except that an explicit
`derived_from: []` on a `document.put` is kept: it says "derives from
nothing". A put without either hashes exactly as before. Projection
(`doc_lineage(doc_id, source_block_id, source_content_hash, inferred,
chain_seq)`, compared by the projection check like every other table):

- `document.put` with `derived_from` present (even `[]`): the document's
  rows are replaced by it plus `derived_from_inferred`;
- any other `document.put`, and `block.created` with lineage fields: rows are
  added (`INSERT OR IGNORE`; the first recording seq is kept); 0.8.1: the
  inferred rows named by `derived_from_released` are deleted first.
- 0.8.1: `doc_lineage_gaps(doc_id, chain_seq)` holds the latest
  `derived_from_inferred_truncated` write of a document without an explicit
  statement (a `derived_from`, even `[]`, clears it). Backfilled from the
  chain once on upgrade (meta `migration.lineage_gaps`). Both tables are
  compared with the chain by every orient focus (a replay of the indexed
  lineage-bearing events) and per hit by recall (src/lineage `checkProjection`).

Read-time evaluation (src/lineage/lineage.ts; no chain change): an edge is
**fresh** when its source block's supersession lineage (§3.3) reaches a live
block through format-only edits only (§3.8, same section), or when the note
also has an edge to a block of that current version. Otherwise it is
**stale** with `change`: `superseded`, `moved` (another section), `tombstoned`
or `missing`. A note derived from a stale note is stale (`via`, depth ≤ 4).
A reorder within the source's section (§3.2 1a) is a real change. A result
cut short by the depth bound or a cycle is never reused for another note in
the same read (0.8.1).
Recall labels a stale note's hits `never_act` / `stale_derived`
(docs/HONESTY.md row 3); orient lists a retraction of kind `derived`
(docs/PUSH.md).

## 4. Receipts (v2)

A receipt is issued for each `recall()` hit:

```json
{
  "v": 2,
  "receipt_id": "<uuid>",
  "workspace": "local",
  "block_id": "<uuid>",
  "content_hash": "<blake3 hex>",
  "doc_slug": "deploy",
  "revision": 1,
  "chain_seq": 2,
  "chain_head_hash": "<this_hash of event chain_seq>",
  "query_hash": "<sha256 hex of the query string>",
  "issued_at": "2026-01-01T00:00:05.000Z",
  "key_id": "ed25519-…",
  "signature": "<base64>"
}
```

```
payload   = canonicalize( receipt without "signature" )
signature = base64( Ed25519_sign( utf8(payload) ) )
```

Worked example (with `chain_seq = 2`, `chain_head_hash` = event 2's hash above,
query `"blue green"` → `query_hash = a8036affb32fc5b1c4ddebd055b5cd471de0f4a6566579b6bef9a988b9c1f38c`):

```
payload = {"block_id":"9b8a7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d","chain_head_hash":"a271676cbace94eb0aef27889573fb0629afb55127d32c830cc27066c65007fb","chain_seq":2,"content_hash":"22dc95c8312b3e93aa2a15d4be929b7fbabb3a5e0a624a94196e6355557507f0","doc_slug":"deploy","issued_at":"2026-01-01T00:00:05.000Z","key_id":"ed25519-0123456789abcdef","query_hash":"a8036affb32fc5b1c4ddebd055b5cd471de0f4a6566579b6bef9a988b9c1f38c","receipt_id":"2d1e0f9a-8b7c-4d6e-9f50-0a1b2c3d4e5f","revision":1,"v":2,"workspace":"local"}
```

`key_id` is `"ed25519-" + first 16 hex chars of sha256(SPKI DER of the public key)`.

0.6.0, additive and local: the `receipts` table gains a nullable `actor_id`
column (added to older databases on open) recording which actor `recall`
served, for the attention rerank (docs/HONESTY.md §3). It is not part of
the receipt JSON, its signature or any hash; the receipt layout above is
unchanged. Recall results gain `authority*`, `authority_floor`, `absence`,
`already_read`, `attention`, `read_scrubbed` and `truncated` (labels
computed at read time, never stored or chained; docs/HONESTY.md).

### 4.1 Verification (`verify`)

Fail-closed, in order:

| step | failure → status / reason |
|---|---|
| parse against the schema | `UNVERIFIED / malformed_receipt` |
| `signature` present | `UNVERIFIED / unsigned_receipt` |
| `key_id` known / not revoked | `UNVERIFIED / unknown_key` or `key_revoked` |
| Ed25519 verifies over payload | `UNVERIFIED / signature_invalid` |
| block row exists | `UNVERIFIED / unknown_block` |
| the row is intact (§3.6; 0.5.0) | `UNVERIFIED / content_tampered` (+ `integrity_problem`) |
| stored `content_hash` matches | `UNVERIFIED / content_hash_mismatch` |
| `events[chain_seq].this_hash == chain_head_hash` (seq 0 ⇒ genesis) | `UNVERIFIED / chain_seq_unknown` or `chain_head_mismatch` |
| lineage head tombstoned | `TOMBSTONED / tombstoned` |
| lineage head is a different block | `SUPERSEDED / superseded_by_newer_head` (+ `current_block_id`, `current_content_hash`) |
| the chain has a `block.superseded` / `block.tombstoned` event for a block the projection calls live (0.5.0) | `UNVERIFIED / projection_mismatch` |
| document git-bound and its source blob moved (0.4.0, §3.5) | `STALE_SOURCE / stale_source` (+ `source_drift`) |
| otherwise | `VERIFIED / verified` |

### 4.2 Read log (0.8.0, additive, local)

`reads(actor_id, doc_id, block_id, content_hash, doc_revision, head_seq,
read_at, via)` records which version each actor read: a row per recall hit
served to a known actor (receipts or not), a row per document read
(`block_id` NULL) plus one per live block of it, and a row per write
(`via: write`; a put is a whole-document read of what it wrote, a supersede
a read of the new block, a tombstone a read of the removal). Like
`receipts.actor_id` it is not part of any hash, any signature or the export,
and `import` / `rebuild` leave it alone. Receipts issued to an actor before
the table existed count as reads too. It drives lineage inference (§3.10),
`pending` and the shims' exec-time gate (docs/PUSH.md).

## 5. Cursors

```
full:    sxt1.<base64url(canonicalize(body))>.<base64url(HMAC-SHA256(secret, canonical_body))>
compact: sxt1c.<chain_seq>.<first 8 chars of base64url(HMAC-SHA256(secret, actor_id || "|" || chain_seq))>
body = { actor_id, chain_seq, chain_hash, issued_at }
```

The secret is `cursor-secret` in the data dir (32 random bytes, hex). Cursors
are an optimization, not a credential: a bad cursor makes the server recover
the actor's position from the flight recorder (or genesis). Nothing is granted
by holding one.

## 6. Keys and files

```
<data-dir>/kronicle-lite.db    SQLite (WAL)
<data-dir>/signing-key.pem     Ed25519 private key, PKCS#8 PEM, mode 0600
<data-dir>/cursor-secret       64 hex chars, mode 0600
```

Since 0.7.0, the key, the secret and `http-bearer.token` are created with
`link(tmp, path)` (create-if-absent with the full content), so processes
starting together on a fresh data dir agree on one identity; a reader that
finds a short or invalid file (an older writer mid-write) re-reads it for up
to 2 s before reporting it corrupt.

`signing_keys(key_id, public_key_pem, algorithm, created_at, revoked_at)`
holds the public half so a copied database verifies on its own. Setting
`revoked_at` downgrades every receipt and checkpoint signed by that key to
`UNVERIFIED` / `unknown_key`.

```
<data-dir>/config.json               {"anchor_url", "license_key"}, mode 0600 (0.4.0; created with anchor_url only)
<data-dir>/anchor-keys.pinned.json   pinned anchor service keys, mode 0600 (0.8.1; §9)
<data-dir>/anchor-keys.cache.json    0.4.0–0.8.0: last fetched service key document; no longer written or trusted (0.8.1)
```

## 7. Export

`kronicle-lite export` writes JSONL: a header line
`{"kronicle_lite_export":1, head, key_id, public_key_pem, exported_at}` then
one event object per line, ascending `seq`, with all columns from §1
(`payload` as an object). `import` re-verifies every hash and link while
loading and rebuilds documents and blocks from the events.

0.4.0, additive: when the store holds anchor receipts (§9), one trailing
line `{"kronicle_lite_anchors":1, "anchors":[…]}` follows the events — one
object per `anchors` row with `receipt_json` parsed into `receipt`. A store
that was never anchored exports exactly as before. `import` skips the line
(receipts are re-fetchable from the service by `chain_id`).

## 8. Versioning

Any change to §1.2, §2, §3 content hashing, §4 payloads or §5 token layout is
a format change and must bump the genesis string, the receipt `v`, the
checkpoint `v` or the cursor prefix respectively. Old data must still verify
under its original rules.

## 9. Hosted anchors (0.4.0, additive)

`checkpoint --push` sends one signed checkpoint (§2) to an anchor service
(default `https://anchor.isokron.ai`) and stores the countersigned receipt
it returns. Nothing in §1–§5 changes: anchors are not chain events, no hash
covers them, and old databases gain the empty table on open.

```
chain_id = hex( sha256( SPKI DER of the Ed25519 public key ) )      // key_id = "ed25519-" + chain_id[0..16]
POST /v1/anchor   { chain_id, pubkey: <SPKI PEM>, checkpoint: { v:1, from_seq, to_seq, leaf_count, root, key_id, signature } }
```

The service sees the root, the range, the signature and the public key;
never events or content. It checks `sha256(SPKI DER) == chain_id`, the
key_id derivation, the §2 signature and the range arithmetic, then
countersigns an **anchor receipt v1**:

```
{ v: 1, anchor_id, chain_id, key_id, checkpoint, received_at, tier, service_key_id, verified: ["chain_id","key_id","signature","range"], signature }
signature = base64( Ed25519_sign_service( utf8( canonicalize(receipt without "signature") ) ) )
leaf      = sha256( canonicalize(receipt) )          // the receipt's public-log leaf
```

Service public keys are published at `/.well-known/anchor-keys.json`
(`service_key_id = "anchor-ed25519-" + hex(sha256(SPKI DER))[0..16]`). The
client verifies the countersignature and that `receipt.checkpoint` equals
what it sent before storing anything, and since 0.8.1 that `receipt_jcs` in
the response is exactly `canonicalize(receipt)`:

| `anchors` column | meaning |
|---|---|
| `anchor_id` | service id (uuidv7) |
| `checkpoint_id` | local `checkpoints.checkpoint_id` that was pushed |
| `chain_id`, `anchor_url` | which chain, which service |
| `from_seq`, `to_seq`, `root` | the anchored range and Merkle root |
| `received_at` | service clock at countersigning |
| `receipt_json` | the receipt as JCS bytes |
| `day`, `leaf_index`, `path_json` | public-log inclusion, NULL until published |
| `status` | `pending_public` \| `published` \| `conflict` |

`verify --remote` recomputes §2 over the local rows for every anchored range:
`match`, `diverged` (local root differs: the chain was rewritten after it was
anchored), `beyond_head` (the range is gone: truncation), `gap`, or (0.8.1)
`unverified` (no trusted receipt, so nothing was compared).

**Receipt trust (0.8.1).** The range and root compared come only from a
receipt that passes all of: countersignature against a pinned service key;
that key's `status` is `active` or `retired` and `received_at` lies within
its `valid_from`/`valid_to`; `receipt.chain_id` derives from the local
signing key named by `receipt.checkpoint.key_id` (and equals the local chain
id for entries the service lists); `receipt.checkpoint.signature` verifies
against that local key. Unsigned listing fields and `anchors.root` are
cross-checked and a disagreement is reported, never used. Every receipt held
in `anchors` is checked, whether or not the service lists it; `--offline`
re-verifies the stored `receipt_json`.

Pins (`anchor-keys.pinned.json`, `{v:1, keys:[{key_id, public_key_pem,
status, valid_from, valid_to, source, pinned_at, signed_by, issuer}]}`):
with nothing pinned, the first key document fetched is pinned (`tofu`). A
package-shipped pin for the origin or `service_key_pins: [PEM…]` in
`config.json` is authoritative and turns first-use pinning off. A new key is
pinned only when its `successor_signature` is a valid Ed25519 signature by a
pinned, non-revoked key named in `signed_by` over
`canonicalize({key_id, public_key_pem, valid_from})`, or by
`kronicle-lite anchor keys add PEM-FILE`. A pinned public key is never
replaced from the network; status and validity only tighten (active →
retired → revoked; `valid_to` only earlier). A key document entry whose
key_id does not derive from its public key fails verification. Key rules
match the service's (`isokron-anchor src/core/servicekeys.ts`): absent
status reads as `active`; `retired` needs `valid_to`; `valid_from ≤
received_at < valid_to`; a key listed twice or with a `successor_signature`
that does not verify is refused. Ed25519 checks on these paths are strict:
small-order or non-canonical public keys and R, and S ≥ L, never verify.

The chain listing is paginated by newer services (`next_cursor`, null on
the last page; `?cursor=` to continue). The client sends `?limit=500` on
every listing request (older services ignore it) and honours `429
retry-after` up to 60 s, 3 times per request, before failing closed. The client follows it to the end and
rejects the whole listing — reported, never treated as complete — on a
paginated page without `next_cursor`, a repeated cursor or anchor, another
chain's page, or fewer anchors than `anchor_count`. A push to an erased
chain is answered `410 chain_erased` and is not retried. Pushing a
different root for an already-anchored range is answered `409` and both
anchors are flagged `conflict`.
