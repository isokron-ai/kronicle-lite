---
name: orient
description: Re-ground the agent against the kronicle-lite chain. Invoke at session start, before write-class tools, before world-changing commands (deploy, migrate, publish, git push), after a context compaction, when the operator types the bare word "orient", or whenever you suspect your notes are stale. Presents your previous cursor to get_system_state as since_cursor, surfaces the delta, drift banner and retraction list, and walks the reconciliation discipline. Call this INSTEAD of trying to recall facts from memory.
---

# orient — the wake protocol

You are an agent doing long-running work with a kronicle-lite store: an
append-only, hash-chained log where **the chain is authoritative** and your
own memory, prior turns and compaction summaries are NOT. This skill keeps
your beliefs aligned with what the store actually says now.

## When to invoke

- **Session start** — every cold start, resume or clear.
- **Before write-class work** — `put_document`, `supersede_block`,
  `tombstone_block`, or any action that depends on a block you read earlier.
- **Before every world-changing command** — deploy, migrate, publish,
  `git push`, anything that sends, pays or deletes, even mid-task and even
  when you oriented a few steps ago: the runbook can change while you work.
  When nothing changed the answer is one line; if it lists retractions,
  reconcile them before you run the command.
- **After a compaction** — the compact summary is the least trustworthy
  belief source you have; it was written from a position that may be stale.
- **Operator types `orient`** — a bare word, no slash. The operator is a drift
  sensor; they are telling you they noticed something you did not.
- **A tool result disagrees with your context** — re-ground before deciding
  which is right.

## The procedure

1. **Find your cursor.** It is the `cursor` (or `cursor_compact`) returned by
   your last `get_system_state`. If a `.kronicle-cursor` file exists in the
   working directory, read it; it is a cache, not authority. If you have no
   cursor, call cold — you will get the digest plus a fresh cursor.

2. **Call `get_system_state`** with `since_cursor=<your cursor>` and the
   default budget. Use `focus=pulse` when you only need to know *whether*
   anything changed (about 50 tokens). A pulse does not list retractions:
   if it reports any change or anything pending, call `focus=retractions`
   before acting, and before a world-changing command never treat a pulse
   alone as clearance — use `focus=retractions`.

3. **Read the response in this order:**
   1. `recovery.method` — `presented`/`presented_compact` means your cursor
      was good. `flight_recorder` or `genesis` means it was missing, invalid
      or belonged to another actor; the server recovered your position, but
      treat anything you "remembered" as unconfirmed.
   2. `drift_banner` — if `surfaced`, you have been operating on stale
      ground; the delta below IS the catch-up.
   0. `integrity` — if `ok` is false (the Markdown starts with
      `INTEGRITY FAILURE`), the store was edited outside kronicle-lite.
      Stop, tell the operator to run `kronicle-lite verify-chain`, and do
      not rely on recalled text until it passes.
   3. `retractions` — things you may have relied on that are now wrong.
      Each carries `old_text`, `new_text` (null when removed) and a word
      `diff` (`[-old-]{+new+}`), so you usually do not need another call
      to learn the current truth. Reconcile EACH before acting on the
      touched documents (step 4). Retractions about other projects'
      documents are hidden (`scope.hidden_retractions`); pass
      `all_projects: true` only when the operator asks. Format-only
      edits (identical raw text up to line endings, trailing whitespace,
      reflow and blank lines) are not retractions: they are listed under
      `format_only_edits` and need no action. Everything else is a
      retraction, including a typo fix (`hint: likely_typo` — still use the
      new wording and check it is not a different name or value) and a
      paragraph that moved to another section (`new_heading_path`). When
      `scope.verdict` is `partial`, "no retractions" covers this project
      only: the hidden ones were not reviewed, not cleared.
   4. `delta.entries` — what changed since your cursor, oldest first.
      Rollups (`volume_rollup`) carry a count and the most recent sample;
      nothing has been dropped, only folded.
   5. `carried_notes` / "Your notes since seq N" — notes you wrote since
      your cursor, as text (bounded). After a compaction this is where your
      own decisions come back; a note marked "repeats `X`, changed at seq N"
      copies a value that has since changed — trust the retraction.
   6. `digest` (cold start) — document list and counts. Follow the
      `kronicle://docs/<slug>` resources or call `recall()` for content.

4. **Reconcile retractions BEFORE acting.** For each item:
   - Affirm the new value first: "I will use Y (seq N), superseding X."
   - Cite authority: the `seq` and, for supersessions, the
     `successor_block_id`.
   - Name the old claim once. Do not keep restating it.
   - State the positive commitment: "I will act on Y going forward."
   - If you hold a receipt for the old block, call `verify(receipt)` and
     expect `SUPERSEDED` or `TOMBSTONED`; fetch the successor with
     `recall()` before using the content again.
   - When you are unsure which of your beliefs are affected, pass them to
     `audit_assumptions` as `{symbol, value}` claims and act on the
     verdicts (`stale`, `contradicted`, `retracted`) it returns.
   - A retraction of kind `derived` means a note (often your own) was
     copied from a block that changed: do not act on the note; re-read the
     source and re-derive the note (`put_document` again after reading the
     current version, or `supersede_block`).
   - `pending` lists changes to things you read that you have not yet
     re-read at their CURRENT version. Seeing the retraction does not clear
     it; re-reading does (`recall()` the block again, or read
     `kronicle://docs/<slug>`). Do not run a world-changing command while
     `pending_count > 0`.

5. **Carry the new cursor.** Pass it as `since_cursor` next time and as
   `cursor` on every write tool so the stale-write advisory can be computed.
   Optionally write it to `.kronicle-cursor` in the working directory.

## Source ranking

When two sources disagree, the authoritative order is:

1. **Chain** — `get_system_state`, `verify`, `verify_chain` results. When
   the chain itself is in question (a teammate restored a backup, the banner
   says the last anchor is far behind), `anchor_status` compares the local
   chain with its last off-box anchor: `diverged` means the local history was
   rewritten after it was anchored — stop and tell the operator.
2. **Fresh tool result** — a `recall()` hit with a receipt that verifies now.
3. **Operator instruction** — the live message outranks your context.
4. **Session reasoning** — earlier turns, IF they were chain-grounded at the
   time and no retraction has touched them since.
5. **Compaction summary** — historical. Never a decision premise on its own.
6. **Long-term memory** — historical. Never a decision premise on its own.

If you catch yourself acting on (5) or (6) without (1)–(3) confirming it,
stop and orient.

## Receipts

Every `recall()` hit carries a signed receipt, by default as a
`receipt_id` (the receipt is stored; `receipts: "inline"` returns the whole
object). Keep it with any claim you derive from the block. Before you build
on that claim again later in the session — and always before writing — call
`verify({receipt_id})` (or `verify({receipt})`):

- `VERIFIED` — proceed.
- `SUPERSEDED` — fetch `current_block_id`; the content you remember is old.
- `TOMBSTONED` — the block was retired; drop the claim.
- `UNVERIFIED` — the receipt, block or chain does not check out; say so
  and re-read from scratch. `content_tampered` / `projection_mismatch`
  mean the stored text no longer matches the chain: treat it as an
  integrity failure, not as news.

`recall` never serves text that fails its integrity check; such hits are
listed under `withheld` instead. A non-empty `withheld` is an integrity
failure too.

## Honest labels on recall (0.6.0)

Read the label before the text. Full table: `docs/HONESTY.md`.

- `authority: can_act` — the block's exact text is in its recorded source
  file right now. You may act on it (still keep the receipt).
- `authority: inspect_only` — reason with it, but verify before acting
  (check the source, ask the operator, or `audit_assumptions`). This is the
  normal label for notes put without a source file, for anything resting on
  document-level provenance only, and for model-written memory.
- `authority: never_act` — do not act on it. `superseded` / `tombstoned`:
  recall the successor or drop the claim. `not_in_source` /
  `source_missing`: the file moved on; re-read the file. `integrity_failed`
  (under `withheld`): stop, tell the operator.
- `authority_floor` is the weakest label in the result. Plan by the floor
  when you combine hits; it is `null` for an empty result.
- `absence.verdict`: `absent_in_searched` means "not in the scopes listed in
  `searched`, with a fresh index" — say it that way, and name
  `not_searched` if it matters. `cannot_certify` means no conclusion: do not
  report "not found". Never turn an empty result into "it doesn't exist".
- Pass your `cursor` to `recall`: blocks you already read this session come
  back with `already_read: true` and rank lower (never hidden).
- `truncated` on a hit: the content was cut to fit `max_chars`; read the
  `truncated.read` resource or raise `max_chars` before quoting it whole.

## Secrets

Never put credentials into the store. `put_document` / `supersede_block`
refuse text holding an API key, token, private key or password-bearing
connection string (`secret_detected`, with detector and line): the chain is
append-only, and a tombstone cannot erase what was chained. Replace the
value with a reference (`${ENV_VAR}`, "stored in the vault") and put again.
Use `redact_secrets: true` only when the operator wants a redacted copy
stored. A `read_scrubbed` field on a hit means a secret was masked on the
way out: tell the operator, it should not be in the store.

## Stale-write advisory

Write tools return `stale_write_advisory`. It never blocks the write. If
`advisory: true`, you wrote without having oriented recently (or ever).
Orient before the next write and re-check anything the delta touched.

## Tool notes (moved out of the tool descriptions to keep tools/list small)

- `get_system_state`: `focus` = `orientation` (digest + delta +
  retractions; default) | `recent_changes` (delta + retractions) |
  `retractions` (only retractions) | `pulse` (head + drift banner; call it
  before every write and escalate when the banner surfaces). With a valid
  cursor and nothing new, any focus answers in one line.
  `include_format_only: true` lists format-only edits as retractions too.
  `budget_tokens` (200–64000, default 3000) bounds the delta; folded
  entries are rolled up, never dropped. `response_format` = `markdown`
  (default) or `json` for the text block; `structuredContent` always has
  the JSON. An invalid or missing cursor never fails: `recovery.method`
  says how your position was recovered (`presented`, `presented_compact`,
  `presented_stale`, `flight_recorder`, `genesis`).
- `recall`: bm25 over live blocks of this project (plus documents with no
  project); `all_projects: true` searches every project. Superseded blocks
  are never returned, tombstoned only with `include_tombstoned`;
  `include_receipts: false` for a lean result (no receipt is stored, so the
  read is not remembered for `already_read`); `max_chars` (default 4000 over
  MCP) bounds the content — raise it or read `truncated.read` when a hit is
  cut.
- Small context? The operator can run `kronicle-lite serve --core`: six
  tools (`get_system_state`, `audit_assumptions`, `recall`, `verify`,
  `put_document`, `supersede_block`).
- `verify`: malformed input yields `UNVERIFIED / malformed_receipt`, never
  a tool error. `SUPERSEDED` carries `current_block_id` and
  `current_content_hash`; `STALE_SOURCE` carries `source_drift`.
- `put_document`: unchanged blocks keep their ids; `idempotency_key`
  replays return the first result; `bind_git` needs `source_path` and
  only warns outside git.
- `supersede_block` / `tombstone_block`: refused on a block that is not
  live; operate on the current head.
- `checkpoint_chain {push: true}` sends the signed root, range,
  signature and public key (never events) to the anchor service; the
  local checkpoint is stored either way.
- Every write tool takes your `cursor` and answers with a
  `stale_write_advisory` (never blocks).
- Full result schemas: the `kronicle://schemas/tools` resource.

## What this skill does NOT do

- It does not modify the chain. Orienting is read-only.
- It does not decide for you. The server reports; you reconcile.
- It does not pretend freshness. If your cursor is more than a few hours old
  or you cannot find it, this skill always calls `get_system_state` even if
  you "feel oriented".
