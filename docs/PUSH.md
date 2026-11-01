# Push: telling the agent what changed while it works

`get_system_state` is a pull: the agent learns about a change only when it
asks. In agent-memory-bench Track B (stale runbook mid-session), agents that
oriented at session start and never again deployed to the stale target in
every run; two cheap additions each fixed it (10/10 on Haiku):

1. **Push** — a hook after every tool call injects retractions that landed
   since the hook's own cursor (Claude Code `PostToolUse`).
2. **Pulse before world-changing commands** — the agent (or a `PreToolUse`
   hook) orients before `deploy`, `migrate`, `publish`, `git push` and the
   like. This is also the fallback for clients without hooks (Cursor, Codex,
   Hermes): the wake contract and the orient skill say it.

A push hook only fires *between* tool calls, so a change that lands inside
one long command (`build && migrate && deploy`) arrives after it. Use both.

## The contract

The hook consumes one CLI call. It is stable within data format
`kronicle-lite/1`: fields below are only ever added to, never renamed or
removed.

```sh
# seed: record where the hook starts (nothing to push yet)
kronicle-lite orient --data-dir DIR --actor push-hook --json --cwd PROJECT --focus pulse
# after each tool call
kronicle-lite orient --data-dir DIR --actor push-hook --json --cwd PROJECT --cursor C --focus retractions
```

- **stdout** is one JSON object (the `get_system_state` result), exit 0.
- **Two different failures — treat them differently:**
  - *kronicle unavailable* — non-zero exit, no JSON on stdout (binary
    missing, usage or I/O error, data dir unreadable): fail open, push
    nothing, never fail the tool call;
  - *integrity failure* — exit 0 with `integrity.ok === false` (an event or
    block no longer matches the chain, e.g. a corrupt payload; `integrity.seq`
    names the event): PUSH it as the first line ("store edited outside
    kronicle-lite: do not rely on recalled text") and make a pre-command
    pulse BLOCK world-changing commands until the operator runs
    `kronicle-lite verify-chain`. Orient never throws on a bad row; every
    focus, `pulse` included, reports it.
- **A bad, foreign or missing cursor never fails.** Check
  `recovery.method`: `presented` / `presented_compact` means the delta is
  since your cursor. `flight_recorder` means it is since this actor's last
  briefing. `genesis` means since the beginning of the chain: store the new
  cursor and push nothing (that is history, not news).
- Use a dedicated `--actor` (e.g. `push-hook`) so the hook's briefings do not
  move the agent's own flight-recorder position.
- `--cwd` sets the project scope: retractions about other projects'
  documents are left out (counted in `scope.hidden_retractions`).
  `--all-projects` turns that off.

Fields a hook reads:

| field | meaning |
|---|---|
| `cursor` | store it; pass it as `--cursor` next time (`cursor_compact` also works) |
| `head.seq` | chain head when the briefing was made |
| `recovery.method`, `recovery.cursor_error` | see above |
| `retractions[]` | things the agent may have relied on that changed; empty when nothing did |
| `retractions[].seq`, `.kind`, `.severity` | `kind`: `instruction` \| `supersession` \| `tombstone` \| `retraction` \| `derived` (unreleased, below); `severity`: `safety` \| `behavioral` \| `informational` |
| `retractions[].doc_slug`, `.heading_path` | where |
| `retractions[].old_text`, `.new_text`, `.diff` | bounded snippets (≤ 160 chars) and a word diff `[-old-]{+new+}` (≤ 400 chars); `new_text` and `diff` are `null` for a removal |
| `retractions[].hint` | `"likely_typo"` on an edit shaped like a one-letter typo fix: a label only (severity and delivery unchanged; such edits include Karen→Karin) |
| `retractions[].new_heading_path` | set when the block moved to another section (`heading_path` is the old one; `diff` starts `section: [-old-]{+new+}`) |
| `retractions[].reason_line` | one sentence: "You previously relied on X; current truth is Y. Reconcile before proceeding." |
| `format_only_edits[]` (alias `cosmetic_edits`) | edits with the same Markdown tree and byte-identical text (reflow, whitespace, emphasis or list-marker style): recorded, **not** in `retractions`, so a hook does not push them. `--include-format-only` folds them back into `retractions` with `format_only: true`. Nothing else is ever left out |
| `integrity.ok`, `integrity.problem`, `integrity.seq` | `false`: the store was edited outside kronicle-lite (see "integrity failure" above) |
| `drift_banner.surfaced` | the actor has not oriented for a while |
| `retractions[]` with `kind: "derived"` (unreleased) | a NOTE derived from a block that changed in this window and was not re-derived: `doc_slug` / `old_text` are the note's, `diff` is the source's word diff (`source <slug>: [-old-]{+new+}`), `derived_from_change` names the source version, its current version and the change (`superseded` \| `moved` \| `tombstoned` \| `missing`); `seq` / `event_type` are the source change's. Severity `safety` when the source was removed, else `behavioral` |
| `pending[]`, `pending_count`, `pending_actor`, `pending_hidden` (unreleased) | see "Pending" below; every focus, `pulse` included |

`focus=retractions` is the cheap path: no delta entries, no digest, no git
calls (`source_drift` is `null`, meaning "not checked"), and the integrity
pass re-hashes the events since the cursor (not the last 1000) plus the
live blocks, so a store edited behind kronicle-lite's back still surfaces on
this path. About 0.33 s per call on a 300-file store, most of it Node
start-up.

## Pending: version-bound reconciliation (unreleased, additive)

Delivery is not reconciliation. A retraction pushed into the context can be
skimmed, compacted away or never acted on, and the cursor has moved on
anyway. `pending` is the other half: per actor, every change to a block the
actor read (or wrote), or to a source of a note it read or wrote, that the
actor has **not re-read at the current version**.

- A read is a recall hit, a document read (`kronicle://docs/<slug>`, CLI
  `get`), or the actor's own write; each records the exact block version
  (docs/FORMAT.md §4.2).
- An item is resolved only when the actor reads a block of the CURRENT
  version: the live lineage head, or a format-only twin of it. For a removal:
  reading the document (or the tombstoned block, recall
  `include_tombstoned`) after the removal. Reading an older version never
  clears a newer change (v1 → v2 → v3: reading v2 leaves the item, now
  `read: v2`, `current: v3`). Receiving the push never clears it.
- Format-only edits are never pending. Another actor's reads never count.
- `derived` items: a note the actor read or wrote whose source changed;
  resolved when the actor reads the source's current version (the note stays
  `stale_derived` in recall until someone re-derives it). When the actor
  also read the source directly, the source item lists the note under
  `derived_notes` instead of a second item.
- Project-scoped like retractions: items about other projects' documents are
  counted in `pending_hidden`, not listed.

Fields (on `get_system_state`, every `orient --json` focus, and
`kronicle-lite pending --actor A --json`):

| field | meaning |
|---|---|
| `pending_count` | unresolved items in scope (the gate keys on `> 0`) |
| `pending[]` | up to 20 items (`pending` CLI: `--limit`, default 50), safety first, then by seq |
| `pending[].kind` | `supersession` \| `tombstone` \| `instruction` (an `instructions/` / `memory/` document) \| `derived` |
| `pending[].change`, `.severity`, `.seq` | `superseded` \| `moved` \| `tombstoned` \| `missing`; `safety` (removed) or `behavioral`; seq of the first real change after the version read |
| `pending[].doc_slug`, `.heading_path` | where the changed block lives (for `derived`: the source's document) |
| `pending[].read` | `{block_id, content_hash, head_seq}`: the version read (for `derived`: the version the note was derived from) |
| `pending[].current` | `{block_id, content_hash}`, or `null` when removed |
| `pending[].old_text`, `.new_text`, `.diff` | bounded snippets and word diff, read version → current |
| `pending[].derived_notes` | notes the actor relied on that were derived from this block |
| `pending[].resolve` | one sentence: what to re-read |
| `pending_actor` | whose reads were checked: `--pending-actor A` (MCP: the caller's `actor_id`), else `--actor` |
| `pending_hidden` | items about other projects' documents |

A hook that orients under its own actor (`push-hook`) passes
`--pending-actor <the agent's actor>`; nothing about that actor's flight
recorder changes. The cheapest gate is one call:

```sh
kronicle-lite pending --data-dir DIR --actor AGENT --cwd PROJECT --json
# {"format":"kronicle-lite/1","actor_id":"AGENT","head":{…},"pending_count":N,"pending_hidden":H,"pending":[…]}
```

Exit 0 with JSON whenever kronicle answers (non-zero = unavailable: fail
open as above). A `PreToolUse` gate for `deploy|migrate|publish|git push`
blocks (or asks) while `pending_count > 0`, quoting each item's `resolve`;
the agent clears it by re-reading, never by acknowledging. Existing fields
are unchanged: a hook that ignores `pending` behaves exactly as before.

## A minimal PostToolUse hook

```js
#!/usr/bin/env node
// .claude/hooks/kronicle-push.mjs — PostToolUse (and SessionStart to seed)
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const ev = JSON.parse(fs.readFileSync(0, 'utf8') || '{}');
const proj = process.env.CLAUDE_PROJECT_DIR || ev.cwd || process.cwd();
const state = path.join(proj, '.claude', 'kronicle-push-cursor');
const orient = (...extra) => JSON.parse(execFileSync('kronicle-lite',
  ['orient', '--actor', 'push-hook', '--json', '--cwd', proj, ...extra], { encoding: 'utf8', timeout: 8000 }));
try {
  const cursor = fs.existsSync(state) ? fs.readFileSync(state, 'utf8').trim() : '';
  if (ev.hook_event_name === 'SessionStart' || !cursor) {
    fs.mkdirSync(path.dirname(state), { recursive: true });
    fs.writeFileSync(state, orient('--focus', 'pulse').cursor);
    process.exit(0);
  }
  const o = orient('--cursor', cursor, '--focus', 'retractions');
  fs.writeFileSync(state, o.cursor);
  if (o.integrity && !o.integrity.ok) {
    process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PostToolUse',
      additionalContext: `kronicle-lite INTEGRITY FAILURE (${o.integrity.problem}): the store was edited outside kronicle-lite. Do not rely on recalled text; ask the operator to run kronicle-lite verify-chain.` } }));
    process.exit(0);
  }
  if (o.recovery.method === 'genesis' || o.retractions.length === 0) process.exit(0);
  const lines = o.retractions.slice(0, 8).map((r) =>
    `- seq ${r.seq} (${r.kind}): ${r.diff ? `changed: ${r.diff}` : `"${r.old_text}" → ${r.new_text == null ? 'REMOVED' : `"${r.new_text}"`}`}`);
  process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PostToolUse',
    additionalContext: `kronicle-lite: ${o.retractions.length} change(s) since your last tool call (head seq ${o.head.seq}):\n${lines.join('\n')}\nRe-read the affected document before acting on it.` } }));
} catch { /* kronicle unavailable: fail open, never fail the tool call */ }
```

The same call works as a `PreToolUse` gate for `Bash` commands matching
`deploy|migrate|publish|git push`: when `retractions` is non-empty, return
the lines as context (or ask) before the command runs. Unreleased: key the
gate on `pending_count` instead (add `--pending-actor <agent>`, or call
`kronicle-lite pending --actor <agent> --json`): it stays non-zero until the
agent has re-read the current version, even after the push was delivered or
compacted away.

## No hooks (Cursor, Codex, Hermes, plain MCP clients)

The wake contract and the orient skill carry the rule instead: call
`get_system_state` with your cursor **before any world-changing command**
(deploy, migrate, publish, `git push`, sending messages, paying), not only
before kronicle write tools. With nothing new, the answer is one line
(under 100 bytes); otherwise reconcile the retractions first.
