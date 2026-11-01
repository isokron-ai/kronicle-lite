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

- **stdout** is one JSON object (the `get_system_state` result), exit 0. A
  usage or I/O error exits non-zero with a message on stderr; a hook must
  treat that as "nothing to push" and never fail the tool call.
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
| `retractions[].seq`, `.kind`, `.severity` | `kind`: `instruction` \| `supersession` \| `tombstone` \| `retraction`; `severity`: `safety` \| `behavioral` \| `informational` |
| `retractions[].doc_slug`, `.heading_path` | where |
| `retractions[].old_text`, `.new_text`, `.diff` | bounded snippets (≤ 160 chars) and a word diff `[-old-]{+new+}` (≤ 400 chars); `new_text` and `diff` are `null` for a removal |
| `retractions[].reason_line` | one sentence: "You previously relied on X; current truth is Y. Reconcile before proceeding." |
| `cosmetic_edits[]` | formatting-only edits (whitespace, quotes, punctuation, typo-level, review dates): recorded, **not** in `retractions`, so a hook does not push them. `--include-cosmetic` folds them back into `retractions` with `cosmetic: [rules]` |
| `integrity.ok`, `integrity.problem` | `false`: the store was edited outside kronicle-lite; tell the agent to stop relying on recalled text |
| `drift_banner.surfaced` | the actor has not oriented for a while |

`focus=retractions` is the cheap path: no delta entries, no digest, no git
calls (`source_drift` is `null`, meaning "not checked"), and the integrity
pass re-hashes the events since the cursor (not the last 1000) plus the
live blocks, so a store edited behind kronicle-lite's back still surfaces on
this path. About 0.33 s per call on a 300-file store, most of it Node
start-up.

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
  if (o.recovery.method === 'genesis' || o.retractions.length === 0) process.exit(0);
  const lines = o.retractions.slice(0, 8).map((r) =>
    `- seq ${r.seq} (${r.kind}): ${r.diff ? `changed: ${r.diff}` : `"${r.old_text}" → ${r.new_text == null ? 'REMOVED' : `"${r.new_text}"`}`}`);
  process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PostToolUse',
    additionalContext: `kronicle-lite: ${o.retractions.length} change(s) since your last tool call (head seq ${o.head.seq}):\n${lines.join('\n')}\nRe-read the affected document before acting on it.` } }));
} catch { /* never fail the tool call */ }
```

The same call works as a `PreToolUse` gate for `Bash` commands matching
`deploy|migrate|publish|git push`: when `retractions` is non-empty, return
the lines as context (or ask) before the command runs.

## No hooks (Cursor, Codex, Hermes, plain MCP clients)

The wake contract and the orient skill carry the rule instead: call
`get_system_state` with your cursor **before any world-changing command**
(deploy, migrate, publish, `git push`, sending messages, paying), not only
before kronicle write tools. With nothing new, the answer is one line
(under 100 bytes); otherwise reconcile the retractions first.
