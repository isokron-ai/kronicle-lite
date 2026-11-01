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
  heading path;
- a fenced code block (``` or ~~~, fence included) is a `code` block;
- any other run of non-blank lines is a `paragraph` block.

```
content_hash = hex( BLAKE3-256( utf8(block_content) ) )
```

Example: `BLAKE3("Use blue/green for the API.") =
22dc95c8312b3e93aa2a15d4be929b7fbabb3a5e0a624a94196e6355557507f0`.

The heading path is not part of the content hash: the same paragraph under a
renamed heading keeps its address.

### 3.1 Event vocabulary

| event_type | payload fields |
|---|---|
| `document.put` | `doc_id, slug, title, revision, markdown, markdown_hash (BLAKE3), block_ids[], carried[{block_id, ordinal, heading_path}]`, optional `source` (0.4.0, §3.4), optional `project` (unreleased, §3.7) |
| `document.revised` | `doc_id, slug, title, revision, markdown, markdown_hash, cause` |
| `block.created` | `block_id, doc_id, doc_slug, revision, ordinal, kind, level, heading_path[], content, content_hash` |
| `block.superseded` | `block_id, successor_block_id, doc_id, doc_slug, revision, reason` |
| `block.tombstoned` | `block_id, doc_id, doc_slug, revision, reason` |
| `document.renamed` (0.5.0) | `doc_id, from_slug, slug, revision, reason` — same document, new slug; revisions and blocks are keyed by `doc_id` and carry over. Unreleased: also written when an instruction file moves inside its project with its content intact (`reason: "moved: <old path> → <new path> (same content)"`), followed by a `document.put` recording the new `source.path` with every block carried |

Block content and document markdown live in the chain, so the chain alone
rebuilds the tables (`kronicle-lite import`, `kronicle-lite rebuild`).
Readers older than 0.5.0 ignore `document.renamed` (no projection), so the
document keeps its old slug there; nothing else changes.

### 3.2 Revision diff

On a re-put, live blocks are compared to the freshly parsed set:

1. same `(kind, content_hash)` → **carried** (block id kept, position updated);
2. remaining old/new paired in order within the same `(kind, heading_path)` →
   old is **superseded** by new;
3. leftover old → **tombstoned** (`removed in revision N`); leftover new →
   **created**.

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

### 3.7 Document projects (unreleased, additive)

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

### 3.8 Cosmetic edits (unreleased)

Orient classifies each supersession whose old and new block text it still
has (`src/orient/cosmetic.ts`). The classifier is conservative: a false
"cosmetic" hides a real change. An edit is **cosmetic** when the two texts
are equal after normalizing line endings, whitespace and reflow, quote
style, trailing punctuation, emphasis markers and list markers, and every
remaining difference (at most two token pairs) is a case-only change, a
soft hyphen (`e-mail` → `email`: a hyphen followed by 3+ letters, same
letters otherwise) or a one-letter typo in a purely alphabetic word of 5+
letters with the same first letter that is not a meaning-bearing word
(not/never/must/enable/east/...), or when only the date on a "Last
reviewed / updated …" line changed. It is never cosmetic when anything
inside a code span or code block changes, when any token holding a digit,
path or URL separator, `@`, `=`, `~`, an internal `.`/`:`/`_` or a leading
`-`/`--` changes or moves, when any token on a command-like line (a flag, a
path, `./x`, `a=b`, a `$ ` prompt or a code span) changes, or when words
are added or removed. Cosmetic supersessions are listed under
`cosmetic_edits` (`seq, doc_slug, block_id, successor_block_id, rules[],
diff`) instead of `retractions`; with `include_cosmetic` they are also
retractions with `cosmetic: [rules]` and severity `informational`. Nothing
on the chain differs: the classification is a read-time view.

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

Unreleased: the key, the secret and `http-bearer.token` are created with
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
<data-dir>/anchor-keys.cache.json    anchor service public keys from the last online call, mode 0600 (0.4.0)
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

Service public keys are published at `/.well-known/anchor-keys.json`. The
client verifies the countersignature and that `receipt.checkpoint` equals
what it sent before storing anything:

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
anchored), `beyond_head` (the range is gone: truncation) or `gap`. Pushing a
different root for an already-anchored range is answered `409` and both
anchors are flagged `conflict`.
