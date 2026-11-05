# Honest labels (0.6.0)

What `recall` tells an agent besides the text: whether it may act on it,
whether an empty answer means anything, and what it already read. Every
label is computed deterministically at read time (no LLM, no network). The
mechanisms are ported from IsoKron (`packages/reality`
retrieval-honesty-tags + the C-1 inherit ladder, `sb1-substrate-shapes`
certify-absence, `library-retrieval` attention-decay recall,
`sextant-scrub`). The code is `src/recall/honesty.ts`, `absence.ts`,
`attention.ts` and `src/secrets/guard.ts`; a test keeps this table and the
code in step.

## 1. Authority on every hit

| label | meaning |
|---|---|
| `can_act` | This exact block text is, right now, the text of its recorded source file. Act on it. |
| `inspect_only` | Read it and reason with it; verify before acting on it. |
| `never_act` | Do not act on it: retired, drifted, missing, or failed its integrity check. |

Each hit carries `authority`, `authority_reason` and `authority_basis`
(`block` = this block's own evidence, `document` = its document's
provenance, `none`). The result carries `authority_floor`, the meet
(minimum) over the hits; `null` when there are no hits, so an empty result
is never read as permission (IsoKron returns `can_act`, the meet identity,
here).

### Rule table

First matching row wins. Row 0 applies to matches withheld from `hits`.

| # | when | authority | reason | basis |
|---|---|---|---|---|
| 0 | the stored text does not hash to its chained event (listed under `withheld`, no content, no receipt) | `never_act` | `integrity_failed` | block |
| 1 | the block was tombstoned (`include_tombstoned: true`) | `never_act` | `tombstoned` | block |
| 2 | the block was superseded | `never_act` | `superseded` | block |
| 3 | (0.8.0) the document is a derived note and a block it was derived from was superseded, moved or tombstoned, and the note was not re-derived from the current version (§6) | `never_act` | `stale_derived` | document |
| 4 | the document's recorded source file is gone | `never_act` | `source_missing` | document |
| 5 | the source file exists but no longer holds this block's text | `never_act` | `not_in_source` | block |
| 6 | the document is model-written memory (source kind `memory`, e.g. Claude Code auto memory) | `inspect_only` | `model_memory` | document |
| 7 | the source file holds this block's exact text now | `can_act` | `block_matches_source` | block |
| 8 | a source is recorded but could not be checked (repository or file unreadable, file over 4 MiB, repository not on this machine) | `inspect_only` | `source_unavailable` | document |
| 9 | a source is recorded but no block-level check is possible (relative path with no project root) | `inspect_only` | `document_source_only` | document |
| 10 | no source recorded (put by an agent or a human) | `inspect_only` | `no_source` | none |

After the table: if the read-time secret scrub changed the text being
served, `can_act` is capped to `inspect_only` with reason `read_scrubbed`
(the text shown is not the chained text the evidence was about). 0.8.1: if
the document is a derived note whose sources could not all be determined
(its inferred lineage was cut short by the bound, recorded as
`derived_from_inferred_truncated`, or it sits more than 4 notes below its
sources), `can_act` is capped to `inspect_only` with reason
`lineage_unknown`: a note is never `can_act` on the strength of its file
when what it was derived from is unknown (§6).

0.8.1: row 0 also covers matches recall withholds because the projection
disagrees with the chain (`projection_mismatch`: the block is served as
live but the chain retired it; `lineage_mismatch`: the note's lineage rows
are not the chain's) or because the store file failed its check
(`store_damaged`).

### The block-level check (row 7)

At recall time, for each document with a recorded source, the source file is
read once and split into blocks with the same parser `put` uses. A hit
matches when the file has a block of the same kind with the same BLAKE3
content hash. The file is found from the `source` field of the document's
latest `document.put`:

| source | file checked |
|---|---|
| git binding (`bind_git`) | `<repo_root>/<path>` (working tree) |
| absolute `path` | that path |
| `~/…` path | under the home directory |
| relative `path` with `project.root` (instruction files) | `<project.root>/<path>` |
| relative `path`, no root | none: row 9 |

No git process runs for this check; `verify` and orient's "Source drift"
still compare whole-file git blobs.

### The invariants

- **Document-level trust never reaches `can_act`.** A git binding whose blob
  still matches, an instruction-file provenance, a document someone
  "trusts": all cap at `inspect_only` unless the block itself is found in the
  file. Concretely: after `supersede_block` on a git-bound document whose file
  did not change, `verify`'s document-level binding still says `current`,
  but the new block is `never_act` / `not_in_source` (test:
  `test/honesty.test.ts`).
- **Superseded, tombstoned and withheld are never `can_act`**, whatever their
  text matches. Neither is a stale derived note (0.8.0), whatever its
  own source says.
- **Model-written memory is never `can_act`** (IsoKron: `model_asserted →
  inspect_only`).
- `can_act ⇒ basis = block`, status live, source check matched, no scrub
  (checked exhaustively by a test).

### What `can_act` does not mean

It says the text is current and sourced, not that the prose is true. The
source file is the authority: an agent that writes a file and binds it can
get `can_act` for what it wrote, so the gate is whatever reviews that file
(git history, code review). Typed facts with operator attestation are the
planned route to `can_act` for claims rather than text.

## 2. Honest absence

Every recall result carries:

```json
"absence": {
  "searched": ["live_blocks"],
  "not_searched": ["tombstoned_blocks", "superseded_blocks"],
  "index_fresh": true,
  "verdict": "absent_in_searched",
  "reason": "searched live_blocks with a fresh index: nothing matched; not searched: tombstoned_blocks, superseded_blocks"
}
```

| verdict | when |
|---|---|
| `found` | at least one hit |
| `absent_in_searched` | no hit, the index was fresh, nothing was withheld. Absent *from the scopes listed in `searched`*, nothing more. |
| `cannot_certify` | no hit, but the index is stale or cold, a match was withheld for integrity, or the query had no searchable terms (nothing was searched) |

Scopes: `live_blocks` (always), `tombstoned_blocks` (only with
`include_tombstoned`), `superseded_blocks` (never searched by recall; their
successors are). There is no global "not found".

`index_fresh` is false when the projection lacks the revision of the chain's
latest `document.put` / `document.revised` event (stale) or the full-text
index does not hold one row per block (cold). A stale or cold index never
certifies absence ("coverage ≠ freshness").

**Orient.** When `get_system_state` hides instruction retractions from other
projects, `scope.verdict` is `partial`, the briefing says
"Retractions: none in this project (partial view)" instead of
"Retractions: none", and a next step says the hidden projects were not
reviewed. "Blindness is not permission."

## 3. Attention rerank

Pass your cursor (and `actor_id`) to `recall`: hits you already read in this
session rank lower; they are never hidden, and `score` stays the raw bm25.
Each hit says `already_read`; the result says
`attention: {actor_id, session_since, already_read}` (null without an actor
session).

- A read = a receipt issued to you (`receipts.actor_id`, a local column; the
  signed receipt is unchanged). `include_receipts: false` records no read.
- Your session starts at the orient that issued the cursor you pass (a full
  cursor carries its issue time; a compact one is looked up in the flight
  recorder), else at your latest orient. A cursor issued to another actor is
  ignored.
- Weight: relevance × 0.5 for an already-read hit, then a stable sort. If
  every hit was read, the order is unchanged. Rerank happens within the
  `top_k` that matched; it never changes which hits are returned.

## 4. Response caps

`recall` fits hit content into `max_chars` (default 16000): short hits stay
whole, long ones share what is left. A cut hit carries
`truncated: {shown_chars, total_chars, read: "kronicle://docs/<slug>"}` and
the result `truncated: {hits, max_chars, hint}`. Receipts still cover the
whole block, so `verify` is unaffected. Orient has its own `budget_tokens`.

`serve --core` serves six tools (`get_system_state`, `audit_assumptions`,
`recall`, `verify`, `put_document`, `supersede_block`) for small context
windows.

## 5. Secrets

See THREAT-MODEL.md §"Secrets": write-time refusal (or explicit redaction)
before anything is chained, independent read-time scrub on everything served.

## 6. Derived notes (0.8.0)

A note an agent writes from what it read is a copy. When the source changes,
the copy is wrong and, before this, came back next session unmarked
(agent-memory-bench Track A S1: 20/20, every tool). Lineage fixes that:

- `put_document` / `supersede_block` (and `put` / `supersede` on the CLI)
  take `derived_from: [{block_id, content_hash}]` — the exact versions the
  text rests on (`content_hash` must be the block's; a block id names one
  version). Lineage is also **inferred**: every block the writing actor read
  (recall hits, document reads; its own writes excluded) is recorded as
  `derived_from_inferred`, one edge per block (the latest version read),
  within a bound that is the union of (0.8.1) its session — every read made
  at or after the chain position of the `cursor` it passes, else of its
  latest briefing (reads are placed by chain position, never by wall clock)
  — and the blocks it read in the last 24 hours, at most the 200 most
  recent, whatever briefings came in between (recall → orient → write keeps
  the read). A write whose bound left reads out (the 200 cap, or reads that
  neither bound covers while inference found nothing) records
  `derived_from_inferred_truncated: true`: the note's sources are then
  undetermined and it is never `can_act` (`lineage_unknown`) until an
  explicit `derived_from` states them. Within those bounds inference
  over-approximates on purpose; inferred edges downgrade exactly like
  declared ones. Instruction-file imports infer nothing (they are the
  file's text).
- An edge is **fresh** while its source's supersession lineage reaches a
  live block through format-only edits only (docs/FORMAT.md §3.8: since
  0.8.1 raw-text equivalence — line endings, trailing whitespace, reflow,
  blank lines; an emphasis-marker, list-marker or renumbering edit, or a
  reorder inside the section, makes it stale), or when
  the note also has an edge to the current version (it was re-derived:
  re-put or supersede after reading the current version). Otherwise it is
  **stale**: superseded, moved (re-sectioned), tombstoned, or missing. A
  note derived from a stale note is stale too (`via`), up to 4 notes deep;
  a note in a cycle with a stale member is stale. Deeper than that, a note
  that looks fresh is undetermined (`lineage_unknown`, never `can_act`).
- A stale note's hits are `never_act` / `stale_derived` (row 3) and carry
  `stale_derived: [{source_block_id, source_content_hash, source_doc_slug,
  change, seq, current_block_id, current_content_hash, old_text, new_text,
  inferred, via?}]`, placed right after `content`.
- `get_system_state` lists a retraction of kind `derived` for each note made
  stale by a change in the window (the note's slug and text, the source's
  diff, `derived_from_change`), 0.8.1: also for notes derived from such a
  note (`derived_from_change.via` names it, up to 4 notes deep; format-only
  source edits never produce one), and `pending` lists it for every actor that
  read or wrote the note until that actor reads the source's current
  version (docs/PUSH.md).
- A `put` with an explicit `derived_from` (even `[]`) replaces the note's
  lineage: the author's statement of what the text now rests on. Every other
  write (inferred edges, `supersede_block`) adds to it, with one exception
  (0.8.1): an inferred edge to a REMOVED source (tombstoned, or moved to
  another document) has no current version to re-derive from, so a `put`
  of the note drops it (`derived_from_released` on the chain) when the
  author acknowledged the removal (read the document after it) or, changing
  the note's text, re-derived it from current material it read after the
  removal.
