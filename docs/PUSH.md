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
    focus, `pulse` included, reports it (0.9.0: the pulse runs the same pass
    as `focus=retractions` — events since the cursor, live blocks, the
    projection's block lifecycle and lineage rows against the chain — and a
    store file that is damaged or cannot be read, `SQLITE_CORRUPT` included,
    is `integrity.ok: false` with the error, never a cached "proceed").
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
| `retractions[].seq`, `.kind`, `.severity` | `kind`: `instruction` \| `supersession` \| `tombstone` \| `retraction` \| `derived` (0.8.0, below); `severity`: `safety` \| `behavioral` \| `informational` |
| `retractions[].doc_slug`, `.heading_path` | where |
| `retractions[].old_text`, `.new_text`, `.diff` | bounded snippets (≤ 160 chars) and a word diff `[-old-]{+new+}` (≤ 400 chars); `new_text` and `diff` are `null` for a removal |
| `retractions[].hint` | `"likely_typo"` on an edit shaped like a one-letter typo fix: a label only (severity and delivery unchanged; such edits include Karen→Karin) |
| `retractions[].new_heading_path` | set when the block moved to another section (`heading_path` is the old one; `diff` starts `section: [-old-]{+new+}`) |
| `retractions[].reason_line` | one sentence: "You previously relied on X; current truth is Y. Reconcile before proceeding." |
| `format_only_edits[]` (alias `cosmetic_edits`) | edits whose raw text is byte-identical up to line endings, trailing whitespace, reflow inside a paragraph and blank lines (docs/FORMAT.md §3.8; since 0.9.0 a double space or tab inside a line, emphasis-marker, list-marker and renumbering edits and reorders are retractions): recorded, **not** in `retractions`, so a hook does not push them. `--include-format-only` folds them back into `retractions` with `format_only: true`. Nothing else is ever left out |
| `integrity.ok`, `integrity.problem`, `integrity.seq` | `false`: the store was edited outside kronicle-lite (see "integrity failure" above) |
| `drift_banner.surfaced` | the actor has not oriented for a while |
| `retractions[]` with `kind: "derived"` (0.8.0) | a NOTE derived from a block that changed in this window and was not re-derived: `doc_slug` / `old_text` are the note's, `diff` is the source's word diff (`source <slug>: [-old-]{+new+}`), `derived_from_change` names the source version, its current version and the change (`superseded` \| `moved` \| `tombstoned` \| `missing`); `seq` / `event_type` are the source change's. Severity `safety` when the source was removed, else `behavioral` |
| `pending[]`, `pending_count`, `pending_actor`, `pending_hidden` (0.8.0) | see "Pending" below; every focus, `pulse` included |

`focus=retractions` is the cheap path: no delta entries, no digest, no git
calls (`source_drift` is `null`, meaning "not checked"), and the integrity
pass re-hashes the events since the cursor (not the last 1000) plus the
live blocks, so a store edited behind kronicle-lite's back still surfaces on
this path. About 0.33 s per call on a 300-file store, most of it Node
start-up.

## Pending: version-bound reconciliation (0.8.0, additive)

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
The exec-time [shims](#shims-exec-time-pulse-for-any-client) apply the same
rule to the retractions since their cursor (`kronicle-lite pulse
--pending-actor`).

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
the lines as context (or ask) before the command runs. Since 0.8.0, key the
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

That rule depends on the agent following it. For the commands that matter
most, a [shim](#shims-exec-time-pulse-for-any-client) enforces it at
exec time in any client, hooks or not.

## Shims: exec-time pulse for any client

*0.8.0.* A push hook needs a client with hooks, and a check made before
a Bash call cannot see a change that lands while the call runs
(`build && migrate && deploy`), nor a deploy hidden in `make release`,
`bash -c "$CMD"` or a wrapper script. A shim checks at the moment the real
binary is executed, whatever started it: Claude Code, Cursor, Codex, Hermes,
a CI script or a human.

```sh
kronicle-lite shim install [--dir D] [--commands git,terraform,tofu,kubectl,helm,npm,pnpm,yarn]
                           [--world "make release,docker push,gh release create"]
                           [--data-dir DIR] [--mode deny|warn] [--pending-actor A[,B] | --all-readers]
                           [--on-timeout allow|deny] [--git-hook [--repo PATH]] [--windows]
export PATH="D:$PATH"          # D FIRST on PATH (default D: ~/.kronicle-lite/shims)
export KRONICLE_LITE_ACTOR=agent-a     # in each agent's environment: whose re-read clears its gate (0.9.0)
kronicle-lite shim status      # per tool: active on PATH? real binary? git hook? anything blocking in this project?
kronicle-lite shim ack --operator --through SEQ   # OPERATOR override: clear a denial without a re-read (0.9.0: TTY or --operator, logged)
kronicle-lite shim uninstall [--git-hook [--repo PATH]]   # removes only files carrying the shim marker, D/.kronicle-shim and our pre-push hooks
```

`status`, `ack` and `uninstall` use the first shim dir on PATH when `--dir`
is left out. Install refuses system directories (`/`, `/bin`, `/usr/…`,
`/etc`, `/dev`, …), never overwrites a file that is not one of its shims,
and never writes through a symlink. Re-running install keeps the existing
starting point (0.9.0): it never acknowledges pending changes.

**Two layers, two jobs** (0.9.0). The **PATH shim** catches the commands an
agent launches through its shell (and their children: `npm run`, `make`,
scripts) for every shimmed tool. The **git pre-push hook** (`--git-hook`)
catches **every push** from the repository, whatever started git: an
absolute path, `sudo`, `env -i`, `git -C`, a git alias, another hook,
`rebase -x`, `submodule foreach`. Only `git push --no-verify` skips it
(git's rule for every pre-push hook; the PATH shim still sees that one when
an agent runs it). Use both for git.

### What a shim does

1. **Decide** with shell builtins only (no node, no subshell): is this
   invocation world-changing? If not, `exec` the real binary. Overhead for
   `git status` through the shim: about 1 ms (median of 60 runs, Linux,
   dash; `test/shim.test.ts` prints it).
2. **Pulse** when it is: run `kronicle-lite pulse --state D/.kronicle-shim
   --cwd "$PWD" -- <command>` with the shim dir removed from PATH, bounded
   by `timeout` (or perl's `alarm` where there is no `timeout`;
   `KRONICLE_SHIM_TIMEOUT` seconds, default 10). About 0.2 s, mostly node
   start-up.
3. **Exit 77** with the reason on stderr when the pulse refuses; otherwise
   `exec` the real binary with the original argv, stdin and exit code.

| pulse outcome | shim |
|---|---|
| exit 0 (allow, warn, first check) | runs the command |
| exit 77 (unreconciled retractions, or an integrity failure) | refuses: exit 77, nothing runs |
| timeout (124/137/142: no answer within `KRONICLE_SHIM_TIMEOUT` s) | **loud, every time**: ``kronicle-lite check TIMED OUT after Ns — `<cmd>` was NOT checked; see D/.kronicle-shim/shim.log`` on stderr. `--on-timeout allow` (the default, for compatibility): runs the command. `--on-timeout deny`: refuses it, exit 77 (``… was NOT checked and NOT run (--on-timeout deny)``) |
| no store found, or two different stores (0.9.0, [below](#which-store-the-shims-check)) | `--mode deny`: **refused**, exit 77, saying where it looked / which stores it found. `--mode warn`: runs, with a loud line every time |
| the store file is damaged (0.9.0: bad header, SQLITE_CORRUPT / NOTADB, "database disk image is malformed") or there but unreadable for a reason that is not a lock (permissions, I/O error, a directory) | misconfiguration or damage: `--mode deny` **refuses** (exit 77), `--mode warn` runs with a loud `running UNCHECKED — the kronicle-lite store is CORRUPT` (or `UNREADABLE`) line every time. Never "unavailable" |
| store locked or busy (SQLITE_BUSY / "database is locked": exit 3) | transient: `--on-timeout allow` (default): **fail open** as below. `--on-timeout deny` (0.9.0): refused, exit 77 (``kronicle-lite store UNAVAILABLE … was NOT checked and NOT run``) |
| anything else: CLI missing, crash | **fail open**: runs the command; one line on stderr the first time (`D/.kronicle-shim/unavailable` marks it; cleared on the next good check), every occurrence logged in `D/.kronicle-shim/shim.log`, the reason in `last-error` |

A timeout is a safety check that did not happen, so it is never quiet. Pick
`--on-timeout deny` where an unchecked deploy is worse than a refused one
(CI, production pipelines); `allow` keeps a slow or wedged store from
stopping work. `--on-timeout` is baked into the wrappers and stored in the
shim config; re-run `shim install` to change it. The Windows wrappers check
in-process (`shim exec`) with no timeout.

**`shim.log`** gets one line per world-changing call, for diagnosing slow
checks: from the wrapper, `<time> <tool> check <ms>ms outcome=allow|deny|
timeout-allow|timeout-deny|unavailable|failed rc=<exit>` (wall time of the
whole check, node start-up included), and from the check itself, `<time>
<tool> pulse(node) boot <ms>ms open <ms>ms check <ms>ms total <ms>ms
decision=… reason=… head=<seq>` (boot = node start-up and module load, open =
opening the store, including any SQLite lock wait). A timed-out call has a
`check` line and no `pulse(node)` line; comparing the two tells start-up,
lock waits and the check itself apart. Plus the `fail-open:` lines above.

An **integrity failure** (an event or live block no longer matches the
chain) refuses world-changing commands in `deny` **and** `warn` mode: fail
closed, until `kronicle-lite verify-chain` / `doctor` / `rebuild` clear it.
(cc-anchor's PreToolUse pulse with `pulse_mode: warn` only warns; the shim
is the last line, so it does not.)

### What counts as world-changing

Same matcher semantics as cc-anchor's pulse (`scripts/pulse.jq`): the
tool's own global options are skipped before the verb, and only the verb
position counts (`git commit -m "git push"` is a commit). A shim sees argv
after the shell removed quotes, so `"git" "push"` is `git push`.

| tool | world-changing | read-only exceptions | global options skipped (with a value) |
|---|---|---|---|
| `git` | `push`, `subtree push`, `lfs push` | `--help` anywhere | `-C`, `-c`, `--git-dir`, `--work-tree`, `--namespace`, `--exec-path`, `--super-prefix`, `--config-env` (`--x=v` forms always) |
| `terraform`, `tofu` | `apply`, `destroy` | `--help` | `-chdir=…` |
| `kubectl`, `oc` | `apply`, `delete`, `patch`, `replace`, `rollout`, `create`, `scale`, `set`, `edit`, `label`, `annotate`, `drain`, `cordon`, `uncordon`, `taint`, `autoscale`, `expose` | `rollout status`, `rollout history`, `--help` | `-n`, `--namespace`, `--context`, `--kubeconfig`, `--cluster`, `--user`, `-s`, `--server`, `--as`, `--token`, … |
| `helm` | `install`, `upgrade`, `uninstall` (`delete`, `del`, `un`), `rollback` | `--help` | `-n`, `--namespace`, `--kube-context`, `--kubeconfig`, … |
| `npm`, `pnpm`, `yarn` | `publish` (`yarn npm publish`); `run`/`run-script` SCRIPT and, for pnpm/yarn, a bare SCRIPT whose name contains the word `deploy`, `migrate`, `publish`, `release` or (0.9.0) `ship` (`deploy:prod`, `db-migrate`, `ship`; not `predeploy`) | `--help` | `--prefix`, `-w`, `--workspace`, `-C`, `--dir`, `--filter`, `--cwd`, `--registry`, … |
| `make` (opt-in) | any target with one of those words (`make release`, `make ship`, `make -C sub deploy`) | `--help`; `VAR=value` arguments | — |
| `--world "TOOL WORD…"` | that verb sequence as a prefix (`docker push`, `gh release create`, `aws s3 *`: `*` = any one word) | | |
| `--world "TOOL"`, or a `--commands` name with no rules | every invocation (a deploy script) | | |

A tool given by path is the same tool (0.9.0): `shim exec --tool
/usr/bin/make` and `pulse -- /usr/bin/git -C x push` use the rules and the
target of `make` / `git`. The PATH shim itself never sees `/usr/bin/make
release` (no PATH lookup; see below).

Conservative where it is cheap: when the word before the verb is an option
the table does not know, it may have taken the verb position as its value
(`npm --registry https://r publish`, `kubectl --new-flag v apply`), so the
next word is tried as the verb too. A false positive costs one pulse; a
miss costs a stale deploy. The table is `src/shim/rules.ts`; the decision
table in `test/shim-rules.test.ts` (100+ cases) runs through both the
TypeScript classifier and the generated sh (dash and bash) and requires them
to agree.

### What the PATH shim cannot see

A shim is a guard rail for agents that act in good faith, not a security
boundary: it only runs when the shell finds the tool on PATH with the shim
dir first. These run the real binary without it (round-2 hardening
harness, dash and bash):

| bypass | why | for git |
|---|---|---|
| `/usr/bin/git push` (an absolute path) | no PATH lookup | pre-push hook |
| `sudo git push`, `sudo -E git push` | sudo's `secure_path` replaces PATH (the most likely to happen by accident) | pre-push hook (it embeds the data dir, so root checks the same store) |
| `env -i git push` | the environment, PATH included, is cleared | pre-push hook |
| `command -p git push` | the shell's default PATH | pre-push hook |
| `PATH=/usr/bin:$PATH git push`, `hash -p /usr/bin/git git` (bash) | PATH edited, or the lookup pinned | pre-push hook |
| a git alias (`git -c alias.p=push p`, `git p`) | the shim sees `p`, not `push` | pre-push hook |
| git running git: a `!git push` alias, a hook (`post-commit` that pushes), `rebase -x 'git push'`, `submodule foreach 'git push'`, `bisect run` | git puts its exec-path (`/usr/lib/git-core`) first on PATH for these, so the inner `git` is git-core's | pre-push hook (installed into initialized submodules too) |
| `KRONICLE_SHIM_EXEC="$$:1:" exec git push` | deliberately forges the shim's own same-process marker | pre-push hook (it always checks) |
| `git push --no-verify` | skips pre-push hooks | PATH shim (when an agent runs it) |

For the other tools there is no equivalent of the hook: terraform, kubectl,
helm and npm run by absolute path, under `sudo` or with an edited PATH are
not checked. Keep the cc-anchor PreToolUse pulse (or your client's
equivalent) in front of the shell for those.

### Git pre-push hook (`--git-hook`, 0.9.0)

```sh
kronicle-lite shim install --git-hook [--repo PATH]   # PATH: the repository (default: the working directory)
kronicle-lite shim uninstall --git-hook [--repo PATH] # the hooks only; plain `shim uninstall` removes them too
```

Writes `pre-push` into the hooks dir git itself reports for the repository
(`git rev-parse --git-path hooks`, so `core.hooksPath` is respected; a
shared hooks path gets one hook) and into each initialized submodule's.
Re-run it after adding submodules. It never writes git config, local or
global. The hook runs the same check as the git shim (`kronicle-lite pulse
--state D/.kronicle-shim`, same mode, timeout and `--on-timeout`, the data
dir embedded as an absolute path so `sudo` and `env -i` check the same
store) in the repository git is pushing from, so it sees every push path
in the table above. It prints `git push <remote name>`, never the remote
URL. Exit 77 aborts the push; kronicle-lite unavailable fails open, noted
once, as for the shims.

- **An existing pre-push hook is chained, never overwritten**: it is moved
  to `pre-push.kronicle-chained` (install says so) and run after the check
  passes, with the same arguments and stdin. If both a foreign `pre-push`
  and a `pre-push.kronicle-chained` exist, install refuses before writing
  anything. Uninstall removes our hook (marker-checked) and moves the
  chained one back; a hook someone replaced ours with is left alone.
- `shim status` lists each hook as `active`, `INACTIVE` (git now uses
  another hooks dir), or missing, and says when the repository you are in
  has none.
- A push through the PATH shim is checked twice (shim, then hook); the
  second check finds nothing new (~0.2 s).
- The hook is a POSIX sh script; on Windows, Git for Windows runs it with
  its bundled sh (not yet exercised there).

### Which store the shims check

0.9.0 (protocol finding P2-01: the README's own Cursor and Copilot snippets
ran the server on a project-local `.kronicle-lite/` while the shim checked
`~/.kronicle-lite`, so a push after a change landed silently). The shims
resolve the store the way the server does:

1. `shim install --data-dir DIR` pins it (recorded in the shim config and
   the wrappers): that store only.
2. Otherwise: `$KRONICLE_LITE_DATA_DIR` in the command's environment, else
   `~/.kronicle-lite` (the git hook embeds the installing user's, so `sudo`
   and `env -i` look in the same place), **plus** the nearest
   `.kronicle-lite/` holding a store found walking up from the directory
   the command acts on (the target below).

**No store found → refused; the fix is `kronicle-lite shim install
--data-dir DIR` (DIR = the server's `--data-dir`) or `KRONICLE_LITE_DATA_DIR=DIR`
in the agent's environment.** A store with nothing read yet is fine: the
first check records its head and passes.

Exactly one store found: it is checked. **None**, or **two different
ones**: the shim cannot tell which store the agent uses, says so (where it
looked, or both paths) and refuses world-changing commands in deny mode
(runs them with a loud line in warn mode). Pin one with `shim install
--data-dir DIR` to settle it. `shim status` shows the store it resolved
(`found` / `pinned`) or `AMBIGUOUS`. `kronicle-lite pulse` without
`--state` (a hook's own call) still uses `--data-dir` or the default and
exits 3 without a store, as before.

### Which project a command is checked against

0.9.0: the project the command **acts on**, not only the working directory
(the same key `orient --cwd` uses, taken from that directory):

| tool | target |
|---|---|
| `git` | `-C DIR` (cumulative; `-C ""` is a no-op), `--git-dir[=]G`, `--work-tree[=]W`, `GIT_DIR` / `GIT_WORK_TREE` (relative values against the final `-C` dir, as git does). A work tree wins; a git dir maps to its repository (`/r/.git` → `/r`); a bare repository is its own project |
| `terraform`, `tofu` | `-chdir=DIR` |
| `make` | `-C DIR`, `-CDIR`, `--directory[=]DIR` |
| `npm` / `pnpm` / `yarn` | `--prefix` / `-C`, `--dir` / `--cwd` |

A submodule is also checked against its superproject's documents. A
directory option that does not resolve (`git -C /nope push`, a missing
`--git-dir`) is **refused** (`reason: "target"`): the command would fail
anyway, and checking the wrong project could let a stale one through.
`shim exec --project DIR` names the project explicitly (a missing DIR
refuses).

### Reconciling: re-read the current version

The shim keeps one cursor per project in `D/.kronicle-shim/cursors/`
(and, 0.9.0, one per project and invoking actor), starting from the head at
install time. Each blocking retraction since the
cursor (severity `safety` or `behavioral`; format-only edits are never
retractions) is checked the way [`pending`](#pending-version-bound-reconciliation-080-additive)
is (0.8.0):

- **Resolved** when every *pending actor* has read the **current version**
  of the changed block: a recall hit on it (or a format-only twin), a
  document read (`kronicle://docs/<slug>`, CLI `get`), or its own write; for
  a removal, a read of the document (or the tombstoned block) after the
  removal. For a `derived` retraction, the current version of the note's
  source. Reading an older version never resolves a newer change, and
  receiving the push (a briefing, a retraction in a hook) is not a read.
- **Pending actors**, in this order:
  1. `shim install --pending-actor A[,B]` (stored in the shim config;
     `pulse --pending-actor` for a hook): those actors must re-read.
  2. **The invoking actor** (0.9.0 default): `KRONICLE_LITE_ACTOR` in the
     environment of the command (set it in each agent's environment to the
     `--actor` / `KRONICLE_LITE_ACTOR` of its `serve`; `pulse
     --invoking-actor A` for a hook). A change blocks that actor when it
     relied on it: it read some version of the block (for `derived`: read
     or wrote the note), the change is to an instruction file
     (instructions reach the agent without a kronicle read), or nobody's
     read is recorded. Its own re-read of the current version clears it. A
     change only *other* actors read does not block it (noted once on
     stderr, `not_relied_on[]` in `--json`). Each actor keeps its own
     cursor per project, so one agent clearing the gate never moves
     another's position.
  3. No invoking actor in the environment, or `shim install --all-readers`
     (opt-in): every actor that read any version of the changed block
     (recall hits and document reads; writing a version is not relying on
     it), plus, for `derived`, the actors that read or wrote the note, must
     have re-read: the 0.8.0 default. With nobody to check (no recorded
     reader, or a document-level event without a block) the change stays
     blocking until someone reads the current version or the operator
     acknowledges it.

  Use one stable actor id per agent, not one per session: reads recorded
  as `agent-a#<session>` by one session do not count for
  `agent-a#<another session>` (the shim compares actor ids exactly).

  Why "every reader" is the fallback and not "nobody": without an
  invoking actor the shim cannot tell whose reads count, and the
  per-project cursor is shared by everyone who runs commands there. It
  is also why one stale or finished agent can keep the gate shut for
  another (round-2 H2-16): set `KRONICLE_LITE_ACTOR` per agent.

Then:

- **Denied** (any blocking retraction unresolved): the cursor does **not**
  move, so a plain retry is refused again. Each line names who has not
  re-read yet (`[not yet re-read at the current version by: agent-a]`),
  and the last lines say exactly who must still re-read and why
  (`Still to re-read the current version: agent-b (the invoking actor,
  agent-b).`), then `If you cannot re-read them yourself, stop and ask
  the operator.` Re-read the document and run the command again: an agent
  that recalls the runbook again clears the gate itself. The refusal
  never mentions `ack` (0.9.0, round-2 H2-12: an agent that ran the
  override the 0.8.0 refusal printed cleared the gate without reading).
- **Operator override**: `kronicle-lite shim ack --through SEQ` clears the
  gate without a read (SEQ: the head; `shim status` prints it as
  `through seq SEQ`, `pulse --json` as `ack_through`). A change after SEQ
  still blocks: acknowledging 42 never clears 43. Acknowledging in one
  project does not clear another; it clears every actor's position in
  that project up to SEQ. 0.9.0: ack is an **operator action**. It runs
  only from an interactive terminal (stdin is a TTY) or with an explicit
  `--operator` (confirming that the person running it is the operator), and
  otherwise exits 2 without changing anything. Every ack, and every
  refused attempt, is a line in `D/.kronicle-shim/shim.log`:
  `<time> ack operator-ack through=SEQ from=SEQ acknowledged=N project=KEY
  actor=A user=U confirmed=tty|--operator` (or `ack refused through=…
  actor=A user=U reason=not-an-operator`). `actor` is `--actor A`, else
  `KRONICLE_LITE_ACTOR`, else the OS user. The TTY rule keeps an agent's
  non-interactive shell from acknowledging by accident; it is not a
  security boundary (an agent can type `--operator`): a client with
  hooks should also keep `shim ack` out of the agent's shell (cc-anchor's
  PreToolUse guard does, as a separate change).
- **Allowed** (nothing blocking, or every blocking change resolved): the
  cursor moves to the head; resolved changes are noted once on stderr
  (`… already re-read at the current version (by agent-a)`).
  Informational retractions are printed and do not block.
- **Warn mode**: the denial text is printed, the cursor moves, the command
  runs.
- **Integrity failure**: refused in both modes, whatever was read (fail
  closed).
- (0.9.0) **No usable stored position** — none yet (a new worktree, a
  wiped state dir), or one that does not decode or verify (junk bytes, a
  regenerated `cursor-secret`, a chain rolled back below it): the
  version-bound gate does not need a cursor, so the pending actors'
  `pending` (the configured ones, else the invoking actor) is still asked
  and any unreconciled change refuses
  (`reason: "pending"`, nothing seeded, a plain retry is refused again).
  A regenerated `cursor-secret` is reported on stderr when the store opens.
- (0.9.0) A denial is never recorded as the shim actor's briefing, so it
  can never become the position a later pulse recovers from.

### `kronicle-lite pulse` (the check itself)

```sh
kronicle-lite pulse [--data-dir DIR] [--cwd DIR] [--cursor C | --state D] [--mode deny|warn]
                    [--pending-actor A[,B] | --invoking-actor A | --all-readers] [--json] [--all-projects] [-- CMD…]
```

Usable from any hook. Exit 0 = allow (also warn and a first check), 77 =
refused (message on stderr), 3 = no store / store unreadable. Without
`--cursor` or `--state` it records the head (`decision: "seed"`); with
`--cursor C` it judges the retractions since C and leaves storing the
returned `cursor` to the caller; with `--state D` it keeps the per-project
cursors itself. `--json` prints one object:

| field | meaning |
|---|---|
| `decision` | `allow` \| `deny` \| `warn` \| `seed` |
| `reason` | `clear` \| `retractions` \| `integrity` \| `seeded` \| `genesis` (unreadable cursor: re-seeded) \| `target` (0.9.0: the command names a directory that does not resolve; refused) \| `pending` (0.9.0: no usable position and a pending actor — configured, else the invoking actor — has unreconciled changes; refused, nothing seeded) |
| `pending[]` | (0.9.0) with `reason: "pending"`: `{actor_id, count}` per actor with unreconciled changes |
| `blocking[]`, `informational[]` | retractions (same shape as orient's `retractions[]`); `blocking[]` are the unresolved ones |
| `blocking[].pending_actors`, `.unread_by` | (0.8.0) the actors checked for this change and those that have not read its current version (`[]` / `[]`: no reader recorded) |
| `resolved[]` | (0.8.0) blocking retractions since the cursor that every pending actor has re-read at the current version (same shape as `blocking[]`) |
| `pending_actors` | (0.8.0) the configured actors (`--pending-actor`, or the shim config), `null` = not configured |
| `pending_mode`, `invoking_actor` | (0.9.0) `configured` \| `actor` (only `invoking_actor`'s reads count) \| `readers` (every reader); the invoking actor, when known |
| `not_relied_on[]` | (0.9.0) actor mode: blocking changes to text only other actors read (not blocking for this actor) |
| `target` | (0.9.0) `{dir, explicit, via}`: the directory whose project was checked and what named it (`-C`, `--git-dir`, `GIT_DIR`, `--project`, …; `via: null` = the working directory) |
| `cursor` | carry it: the head when allowed / warned, the unchanged cursor when denied |
| `ack_through` | denied for retractions: the head an operator acknowledges through (not in `message`) |
| `integrity` | orient's integrity summary (`ok: false` ⇒ `decision: "deny"`) |
| `message` | the text a shim prints on stderr (null: nothing to say) |
| `head`, `from_seq`, `recovery`, `project_keys`, `hidden_retractions` | as in orient |

### Recursion and PATH resolution

The real binary is the first executable `TOOL` on PATH outside the shim
dir, as installed (physical and logical path) and as reached (`${0%/*}`),
so a trailing slash, a duplicate or a symlinked alias of the dir on PATH
does not loop. When an `exec` lands on a shim again in the same process (a
wrapper earlier on PATH that `exec`s the tool by name), the shim sees
`KRONICLE_SHIM_EXEC=<its own pid>:…`, skips the dirs already tried and does
not pulse twice; a wrapper that calls the tool in a child process stops
after 8 nested shim calls (`KRONICLE_SHIM_DEPTH`, exit 126). Real binary
not found: exit 127.

### Windows

`--windows` (default on Windows) writes `TOOL.cmd` and `TOOL.ps1`, which
run `kronicle-lite shim exec --dir D --tool TOOL -- ARGS…`: the same
decision in TypeScript, the pulse in-process, then the real binary
(PATHEXT-aware, skipping any file that carries the shim marker). That is
one node start per call, read-only or not; the zero-overhead path is
POSIX only. Not yet exercised on a Windows machine.

### Client set-up

The shim works wherever the agent's shell inherits a PATH with `D` first.

- **Claude Code**: start `claude` from a shell whose profile puts `D`
  first. Shims complement the cc-anchor PreToolUse pulse (which sees the
  whole Bash call and can split chains) at the exec boundary.
- **Cursor** (agent terminal = integrated terminal), `settings.json`:

  ```json
  {
    "terminal.integrated.env.osx":   { "PATH": "/Users/me/.kronicle-lite/shims:${env:PATH}" },
    "terminal.integrated.env.linux": { "PATH": "/home/me/.kronicle-lite/shims:${env:PATH}" }
  }
  ```

- **Codex CLI**: start `codex` from a shell with `D` first (its shell tool
  inherits the environment by default). If `~/.codex/config.toml` sets
  `[shell_environment_policy]`, keep PATH inherited, or set it in full
  there (values are not expanded):

  ```toml
  [shell_environment_policy]
  set = { PATH = "/home/me/.kronicle-lite/shims:/usr/local/bin:/usr/bin:/bin" }
  ```

- **Hermes** (local terminal backend): start `hermes` from a shell with `D`
  first. With a docker / ssh / remote terminal backend, install the shims
  inside that environment (`npx kronicle-lite shim install` there, pointing
  `--data-dir` at a store it can read).
- **Any agent or CI job**: `export PATH="$HOME/.kronicle-lite/shims:$PATH"`
  before it starts; check with `kronicle-lite shim status` from the same
  environment ("active" per tool).

Tell the agent what exit 77 means in its instructions, e.g.: *"A command
that exits 77 with `kronicle-lite shim: did NOT run` was refused because a
document you rely on changed: re-read it (recall it again), check the
command's values, then run the command again. Reading the current version
clears the check. If another actor still has to re-read, stop and ask the
operator; never acknowledge it yourself."*
