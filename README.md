# kronicle-lite

**A local-first MCP server that tells your agent when its notes went stale.**

Agents write notes, runbooks, decisions. Then the world moves: a block gets
rewritten, a decision gets reversed, a procedure gets retired. Nothing in a
plain memory store tells the agent. It keeps reasoning from the thing it read
three sessions ago, confidently.

kronicle-lite is a small SQLite-backed document store where:

- every write is an event on a **hash chain** you can verify from a public
  genesis with `sha256sum`;
- every `recall()` hit comes with a **signed receipt** that later answers
  "is this still the current version?" — `VERIFIED`, `SUPERSEDED` (here is
  the new one), `TOMBSTONED`, or `UNVERIFIED`;
- `get_system_state` gives the agent an **orient** call: pass your last
  cursor, get exactly what changed since, a **drift banner** when you have
  been away too long, and a **retraction list** of things you may have relied
  on that are now wrong;
- every hit carries an **honest label** — `can_act`, `inspect_only` or
  `never_act`, with the reason — and an empty answer says what was searched,
  what was not, and whether the index was fresh. Secrets are refused before
  they reach the append-only chain.

It is one process, one file, no accounts. It runs over stdio next to Claude
Code, Cursor, Claude Desktop, Codex, GitHub Copilot or any MCP client, and
over loopback Streamable HTTP for clients that cannot spawn a process.

## See it in one command

```sh
npx -y kronicle-lite demo
```

No LLM, no network, a temp dir that is removed afterwards. A runbook goes
in; an agent orients and reads "Deploys go to the staging cluster
`stg-west-2` first."; someone changes it to `stg-east-1`; the agent's next
orient says, before it acts:

```
- [behavioral] seq 9: You previously relied on "Deploys go to the staging cluster `stg-west-2` first."
  (runbook › Deploy runbook › Deploy target); current truth is "Deploys go to the staging cluster
  `stg-east-1` first." (seq 9). Reconcile before proceeding.
  changed: Deploys go to the staging cluster [-`stg-west-2`-]{+`stg-east-1`+} first.
```

Then someone edits the SQLite file by hand: `recall` withholds the edited
text, the old receipt verifies `UNVERIFIED (content_tampered)`,
`verify-chain` exits 1, `rebuild` restores the text from the chain. A put
holding an API key is refused before anything is chained, an empty recall
answers `absent_in_searched` with the scopes it did not search, and an edit
to the chain itself is caught at its seq.

> **0.6.0 — honest labels** (unreleased). Every `recall` hit carries
> `authority: can_act | inspect_only | never_act` with a reason; only
> block-level evidence (the block's exact text found, now, in its recorded
> source file) reaches `can_act`; superseded, tombstoned, withheld and drifted
> text never does. `absence {searched, not_searched, index_fresh, verdict}`
> separates "searched, found nothing" from "not searched", and a stale or
> cold index never certifies "not found". Hits you already read this session
> rank lower (never hidden). Secrets (API keys, tokens, private keys,
> connection strings) are refused on put / import / watch, or stored redacted
> on request; served text is scrubbed again at read time. `serve --core`
> serves six tools; `recall` caps content with a "read the whole document"
> pointer. Rules: [`docs/HONESTY.md`](docs/HONESTY.md). All additive: no hash,
> receipt, cursor or event layout changed.

> **0.5.0** closes the gaps an adoption audit found: what the agent reads
> is now checked against the chain, not only the log (`recall`, `verify`,
> `verify-chain`, `doctor`, `rebuild`); instruction files are keyed by
> project, so two repositories sharing a data dir no longer retract each
> other's rules; retractions carry the old and new words; `tools/list` is
> 71% smaller; `serve --http` also serves 2025-era clients such as Cursor.
> Details in [CHANGELOG](CHANGELOG.md).

> **0.3.0 speaks MCP 2026-07-28** (TypeScript SDK v2). Every tool has an
> `outputSchema` and returns `structuredContent`; `tools/list` and
> `server/discover` carry cache hints; results carry `resultType`. The
> stdio server and (since 0.5.0) `serve --http` are **dual-era**: a client
> that still opens with the 2025-era `initialize` handshake (2025-11-25,
> 2025-06-18, 2025-03-26) is served too.

> **0.4.0** adds off-box anchoring (`checkpoint --push`, `verify --remote`),
> chained instructions (`watch`, retractions of kind `instruction`),
> git-aware blocks (`bind_git`, `STALE_SOURCE`) and `kronicle-lite doctor`.
> All additive: 0.3.0 chains verify byte-for-byte.

> kronicle-lite is **not a memory server**. It sits beside one. Keep using
> whatever you use for knowledge graphs or semantic recall; point kronicle-lite
> at the notes whose staleness would hurt.

## Install

Requires Node ≥ 20.

```sh
npm install -g kronicle-lite          # or run via npx, see below
kronicle-lite serve                   # stdio MCP server, data in ~/.kronicle-lite
```

### Claude Code

```sh
claude mcp add kronicle-lite -- npx -y kronicle-lite serve
```

Optional: copy `skills/orient/` to `.claude/skills/orient/` and add the
two-line wake contract from `examples/.claude/CLAUDE.md` to your `CLAUDE.md`.
Then typing `orient` re-grounds the agent against the chain.

### Cursor

Cursor reads `.cursor/mcp.json` (project) or `~/.cursor/mcp.json`
(global) and interpolates `${workspaceFolder}`, `${userHome}` and
`${env:NAME}` in `command`, `args`, `env`, `url` and `headers`:

```json
{
  "mcpServers": {
    "kronicle-lite": {
      "command": "npx",
      "args": ["-y", "kronicle-lite", "serve", "--data-dir", "${workspaceFolder}/.kronicle-lite", "--actor", "cursor"]
    }
  }
}
```

For the HTTP mode below use `{ "url": "http://127.0.0.1:7417/mcp", "headers": { "Authorization": "Bearer ${env:KRONICLE_LITE_BEARER}" } }`
instead of `command`/`args`. Since 0.5.0 a 2025-era HTTP client such as
Cursor's is served (statelessly); before, it was refused.
Source:
[Cursor Docs — Model Context Protocol](https://cursor.com/docs/context/mcp).

### Claude Desktop

`claude_desktop_config.json`:

```json
{ "mcpServers": { "kronicle-lite": { "command": "npx", "args": ["-y", "kronicle-lite", "serve", "--actor", "claude-desktop"] } } }
```

### Codex

`~/.codex/config.toml` (or `.codex/config.toml` in a trusted project):

```toml
[mcp_servers.kronicle-lite]
command = "npx"
args = ["-y", "kronicle-lite", "serve", "--actor", "codex"]
# optional: default_tools_approval_mode = "writes"   # prompt only for put/supersede/tombstone
```

Codex reads the server `instructions` at startup and uses the first 512
characters as server-wide guidance; kronicle-lite's instructions are the
orient loop and fit in that window. Per OpenAI's docs the same file also
takes `enabled_tools` / `disabled_tools`, `startup_timeout_sec` (default
10) and `tool_timeout_sec` (default 60). Source:
[OpenAI — Model Context Protocol](https://developers.openai.com/codex/mcp).

### GitHub Copilot (coding agent + code review)

Repository **Settings → Copilot → MCP servers** (under "Code, planning, and
automation"); the configuration is shared by the Copilot coding agent and
Copilot code review:

```json
{
  "mcpServers": {
    "kronicle-lite": {
      "type": "local",
      "command": "npx",
      "args": ["-y", "kronicle-lite", "serve", "--data-dir", "./.kronicle-lite", "--actor", "copilot"],
      "tools": ["get_system_state", "audit_assumptions", "recall", "verify", "verify_chain", "anchor_status"]
    }
  }
}
```

`tools` is required; GitHub recommends allowlisting read-only tools because
the agent calls them without asking. The six above are the ones
kronicle-lite marks `readOnlyHint: true`, which is also the set Copilot code
review will use (it ignores tools without that annotation). Add
`put_document`, `supersede_block`, `tombstone_block` (or `"*"`) if the
coding agent should write. Secrets must be named `COPILOT_MCP_*` and
referenced from `env`. Source:
[GitHub Docs — Extending Copilot coding agent with MCP](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/extend-coding-agent-with-mcp).

More in [`examples/`](examples/README.md).

### Streamable HTTP: `serve --http`

For a client that cannot spawn a process (or several clients sharing one
store on the same box):

```sh
kronicle-lite serve --http                       # http://127.0.0.1:7417/mcp
kronicle-lite serve --http --port 9000           # other port
kronicle-lite serve --http --bearer-file ./token # token from a file you manage
kronicle-lite serve --http --bearer "$TOKEN"     # token from the environment
```

- **Auth.** Every request must carry `Authorization: Bearer <token>`. By
  default the token lives in `<data dir>/http-bearer.token`, generated on
  first run with mode `0600`; print it with `cat ~/.kronicle-lite/http-bearer.token`.
- **Loopback.** Binds `127.0.0.1`; `Host` and `Origin` are validated
  against loopback (DNS-rebinding defence). `--host 0.0.0.0 --allow-host
  myhost.lan --allow-origin myhost.lan` opens it up; put TLS in front.
- **Stateless, both eras.** No session id, `GET`/`DELETE` answer `405`. A
  2026-07-28 request carries its protocol version in `_meta` and the
  `MCP-Protocol-Version` header; a 2025-era client that opens with
  `initialize` (Cursor, most clients today) is served by a fresh server
  instance per request (0.5.0). `--modern-only` refuses those with
  `UnsupportedProtocolVersionError` (`-32022`), as 0.4.0 did.
- **Trust domain.** Single tenant: the token is the whole store. See
  [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md#http-transport-serve---http).

## Sixty-second tour

Works as-is in an empty directory after `npm install -g kronicle-lite`
(data goes to `~/.kronicle-lite`; add `--data-dir DIR` to keep it apart):

```sh
printf '# Deploy runbook\n\n## Deploy target\nDeploys go to the staging cluster `stg-west-2` first.\n' > runbook.md

# store it: split into blocks, one hash-chained event per change
kronicle-lite put runbook runbook.md --title Runbook

# orient as an agent would, and keep the cursor it hands back
C=$(kronicle-lite orient --actor me --json | node -pe 'JSON.parse(require("fs").readFileSync(0)).cursor_compact')

# change the runbook behind the agent's back
sed -i.bak 's/stg-west-2/stg-east-1/' runbook.md
kronicle-lite put runbook runbook.md --title Runbook

# orient again with the cursor: the retraction says what changed, in words
kronicle-lite orient --actor me --cursor "$C" --focus retractions

# recompute every hash and link, and re-hash every stored block; exit 1 on a mismatch
kronicle-lite verify-chain > /dev/null && echo "chain and store verify"

# sign a Merkle checkpoint; take the chain elsewhere and rebuild from it
kronicle-lite checkpoint > /dev/null
kronicle-lite export --out events.jsonl
kronicle-lite import --data-dir ./copy --in events.jsonl
```

In an agent session the loop is: `get_system_state` → work → `recall` (keep
the receipts) → `verify` before building on an old receipt → write with your
`cursor` → `get_system_state` again next turn with the new cursor.

## Anchor off-box (0.4.0)

kronicle-lite is free and local. Anchoring adds one flag —
`checkpoint --push` — and a URL anyone can check. The local key proves the
rows still match what the box signed; it cannot prove anything against the
box owner, who holds the key. An anchor service countersigns your signed
Merkle root with its own key and a `received_at` time, so a later rewrite of
an anchored range is detectable even when it was re-signed locally.

```sh
# config: flags > env > <data-dir>/config.json > default
export KRONICLE_ANCHOR_KEY=KLA_…                 # or {"license_key": "KLA_…"} in config.json (0600)
# export KRONICLE_ANCHOR_URL=https://anchor.isokron.ai   # the default

kronicle-lite checkpoint --push        # sign a checkpoint, anchor it, store the countersigned receipt
kronicle-lite verify --remote          # recompute every anchored range; exit 1 on
                                       #   "local chain diverges from anchor at [a,b]"
kronicle-lite verify --remote --offline   # same, from stored receipts + cached service keys
kronicle-lite anchor status            # last anchor, status, events since (no network)
```

- **What leaves the box:** the root, range, signature and your public key.
  Never events or content. Details in [FORMAT §9](docs/FORMAT.md#9-hosted-anchors-040-additive)
  and [THREAT-MODEL](docs/THREAT-MODEL.md#what-tamper-evidence-gives-you-here).
- **MCP:** `checkpoint_chain {push: true}` returns the anchor outcome next to
  the local checkpoint; `anchor_status` (read-only) compares the local chain
  with the last anchor (`match | diverged | beyond_head | gap`), `remote:
  true` also asks the service. Once something was anchored,
  `get_system_state` adds one banner line: `anchored N events ago
  (status)`; before that it says nothing about anchoring, and `doctor`
  only probes the service when a license key or URL is configured.
- **Not deployed yet.** The default service, `https://anchor.isokron.ai`, is
  not live. Until it is, `--push` stores the checkpoint locally and exits 2
  with `anchor service unreachable at …`; `verify --remote` exits 2 the same
  way; every local command, the MCP server and `orient` behave exactly as
  without anchoring. Planned pricing at launch: 1,000 anchors a month free,
  $5 a month beyond that.
- Exit codes: 0 ok, 1 divergence or conflict, 2 usage or I/O (incl.
  unreachable).

## Chained instructions (0.4.0)

Your agent's instructions are notes too, and they go stale the same way:
someone edits `CLAUDE.md`, a rule file is rewritten, Claude Code's auto
memory index changes. kronicle-lite can chain them, so a changed instruction
is a **supersession** and the next `get_system_state` lists it as a
retraction of kind `instruction`, in words (`You previously relied on
instruction "Use pnpm, not npm." (instructions/acme-api-1a2b3c4d/claude-md
› Project); current truth is "Use bun, not npm." …`). A deleted file
retires its blocks (severity `safety`).

Default set, relative to the git worktree root (or the working directory).
Since 0.5.0 every slug carries a **project key**, `<repo dir name>-<8 hex
of the root path's sha256>`, so one data dir can serve many repositories:
syncing repo B's `CLAUDE.md` never touches repo A's, and an agent orienting
in A is not shown B's instruction changes (`all_projects: true` /
`--all-projects` shows them). `KRONICLE_LITE_PROJECT=<name>` fixes the key.

| file | slug |
|---|---|
| `CLAUDE.md` | `instructions/<key>/claude-md` |
| `AGENTS.md` | `instructions/<key>/agents-md` |
| `.claude/rules/**/*.md` | `instructions/<key>/claude-rules/<path>` |
| `.cursor/rules/**` | `instructions/<key>/cursor-rules/<path>` |
| Claude Code auto memory `MEMORY.md` | `memory/<key>/MEMORY` |

Upgrading from 0.4.0: the first sync of a file whose un-keyed document
(`instructions/claude-md`) still holds exactly that file's text renames the
document in place (a `document.renamed` event): same blocks, receipts keep
verifying, no retraction. An un-keyed document holding some other text (in
a shared data dir it may be another project's) is left alone.

Auto memory lives at `~/.claude/projects/<project>/memory/MEMORY.md`, where
`<project>` is the git repository's main worktree root (shared by all
worktrees and subdirectories; outside git, the working directory) with every
non-alphanumeric character replaced by `-`. `CLAUDE_CONFIG_DIR`,
`CLAUDE_CODE_PROJECT_DIR_NAME` and `autoMemoryDirectory` are honoured as
Claude Code documents them
([memory](https://code.claude.com/docs/en/memory.md#storage-location),
[sessions](https://code.claude.com/docs/en/sessions.md#where-transcripts-are-stored)).
`kronicle-lite watch --list` prints what it resolved.

```sh
kronicle-lite put --from-instructions          # one shot: chain whatever changed
kronicle-lite watch                            # keep chaining while files change (Ctrl-C to stop)
kronicle-lite watch docs/ AGENTS.md --interval 5000
kronicle-lite watch --list [--json]            # show the resolved set and slugs
```

Unchanged files append nothing. `watch` uses `fs.watch` on the containing
directories with a debounce (150 ms; `--debounce`) plus a polling pass
(`--interval`, default 2000 ms) that also discovers new rule files;
`--poll` uses polling only.

**Inside Claude Code: hooks, not a watcher.** Claude Code already watches
files: a `SessionStart` hook can return `watchPaths`, and a `FileChanged`
hook runs whenever one of them changes on disk, whoever wrote it
([hooks: FileChanged](https://code.claude.com/docs/en/hooks.md#filechanged)).
`put --from-instructions --stdin-hook` is both hooks: on `SessionStart` it
syncs the set and answers with its `watchPaths`; on `FileChanged` it re-puts
the one file and posts a one-line `systemMessage` when something changed. It
never fails the hook. This is the shape of cc-anchor's `watchPaths` /
`FileChanged` hook; with a cc-anchor that does not ship it yet, or without
cc-anchor, add it to `.claude/settings.json`:

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [{ "type": "command", "command": "kronicle-lite put --from-instructions --stdin-hook", "timeout": 30 }] }
    ],
    "FileChanged": [
      { "hooks": [{ "type": "command", "command": "kronicle-lite put --from-instructions --stdin-hook", "timeout": 30 }] }
    ]
  }
}
```

The `FileChanged` group has no `matcher` on purpose: it then runs for every
path in the dynamic watch list. Install kronicle-lite globally for hooks
(`npx` adds seconds per call) and pass the same `--data-dir` your MCP server
uses. **Everywhere else** — Cursor, Codex, Copilot, a plain editor — run
`kronicle-lite watch` in a terminal or as a user service.

## Git-aware blocks (0.4.0)

A document put from a file in a git repository can remember which blob it
came from, so "the runbook says X" gets checked against the runbook file as
it is now, not only against the store:

```sh
kronicle-lite put deploy docs/deploy.md --bind-git     # records {repo_root, commit, path, blob_sha}
```

Over MCP: `put_document {slug, title, markdown, source_path, bind_git: true}`.
When the working-tree file changes (or is deleted), `verify` on a receipt
for that document returns **`STALE_SOURCE`** and `audit_assumptions` grades
claims about it **`stale_source`**, each with a diff stat (`+3 −1`) and the
bound vs working blob; `get_system_state` lists the document under a
**Source drift** heading. Re-put with `--bind-git` to rebind. It only uses
`git rev-parse` / `git hash-object` / `git cat-file`; outside a repository
(or without git) the put succeeds with a warning and nothing is bound.

## `kronicle-lite doctor` (0.4.0)

```sh
kronicle-lite doctor                 # human-readable; exit 1 when any check fails
kronicle-lite doctor --json          # the full report
kronicle-lite doctor --no-network    # skip the anchor reachability probe
kronicle-lite doctor --full          # verify the whole chain, not the last 1000 events
kronicle-lite rebuild                # re-derive documents and blocks from a chain that verifies
```

Read-only: it never creates the data dir or writes a key, config or schema.
Checks: Node version (≥ 20); data dir and key-file modes (`0700` dir,
`0600` keys — a group/world-readable signing key, cursor secret, bearer
token or license-bearing `config.json` fails); `PRAGMA integrity_check`;
chain links and hashes over the last 1000 events plus every checkpoint;
the stored documents, revisions and blocks replayed from the chain and
re-hashed (0.5.0; a mismatch fails, `rebuild` repairs it once the chain
verifies); FTS5 index vs `blocks`; the MCP catalog this build serves vs the
fingerprint pinned for this version; `config.json` sanity; the last anchor
vs the local root (fails on divergence); anchor service reachability
(warning only, and only when anchoring is configured); which MCP clients have kronicle-lite configured
(`~/.claude.json` user and local scopes, `.mcp.json`, `.cursor/mcp.json`,
`~/.cursor/mcp.json`, `~/.codex/config.toml` — read, never written) and with
which `--data-dir`. On Windows it adds a note that the POSIX modes are
no-ops there, with an `icacls` line to lock the data dir down.

## Tools

| tool | what it does | writes chain |
|---|---|---|
| `get_system_state` | Orient. `since_cursor` → delta since then; drift banner; retractions with `old_text` / `new_text` / `diff`; integrity pass; new cursor. `focus`: `orientation` (default), `recent_changes`, `retractions`, `pulse`. `response_format`: `markdown` (default) or `json`. `all_projects`: include other projects' instruction retractions. | no |
| `audit_assumptions` | Grade claims `{symbol, value}` (block id, doc slug, or `head`) → `current \| stale \| contradicted \| retracted \| unknown \| stale_source` with the current truth and a reconcile line. | no |
| `recall` | FTS5 bm25 search over live blocks; each hit carries a receipt v2 bound to the chain head and (0.6.0) `authority` / `authority_reason` / `authority_basis`; the result carries `authority_floor`, `absence` and, with `cursor`, an attention rerank (`already_read`). A block whose stored text no longer hashes to the chain is withheld (`withheld`), never served. `top_k`, `include_tombstoned`, `include_receipts`, `max_chars`, `cursor`, `actor_id`. | no (stores receipts) |
| `verify` | Re-derive a receipt against the live store: signature, block existence, re-hashed block text vs the chain, chain binding, supersession walk, git-bound source → `VERIFIED \| SUPERSEDED \| TOMBSTONED \| UNVERIFIED \| STALE_SOURCE` + reason. | no |
| `verify_chain` | Recompute every hash and link in a range; first mismatch; checkpoint results; over the whole chain also the projection (every stored document and block re-derived and re-hashed). | no |
| `checkpoint_chain` | Sign a Merkle root over a seq range with the local key; `push: true` also anchors it off-box. | no (checkpoints, anchors tables) |
| `anchor_status` | Last off-box anchor, events since, and whether the local chain still matches it (`remote: true` asks the service). | no |
| `put_document` | Create or re-put a Markdown document by slug. Unchanged blocks keep their ids; changed ones are superseded; removed ones tombstoned. `bind_git` + `source_path` bind it to a file's git blob. Refuses a detected secret (`secret_detected`); `redact_secrets: true` stores a redacted copy. | yes |
| `supersede_block` | Replace one live block with new content and a reason (secret guard as for `put_document`). | yes |
| `tombstone_block` | Retire one live block with a reason. | yes |

Every write tool accepts an optional `cursor` and returns the new chain head
plus a `stale_write_advisory` (advisory only; the stale-write check never
blocks; the secret guard does). The `kronicle://docs/{slug}` resource serves
a document's current revision.

**`serve --core`** (0.6.0) serves only `get_system_state`,
`audit_assumptions`, `recall`, `verify`, `put_document` and
`supersede_block`, for small context windows: `tools/list` is 9.9 KB
instead of 13.6 KB. Its catalog is pinned separately
([`.mcp-catalog/kronicle-lite-core.json`](.mcp-catalog/kronicle-lite-core.json)).

### Honest labels (0.6.0)

| you see | it means | do |
|---|---|---|
| `authority: can_act` | this exact block text is in its recorded source file right now | act on it |
| `authority: inspect_only` | no block-level evidence (no source, document-level provenance only, model-written memory, or the source could not be read) | reason with it; verify before acting |
| `authority: never_act` | superseded, tombstoned, withheld for integrity, or the source no longer holds it / is gone | don't act on it; re-read the source or recall the successor |
| `absence.verdict: absent_in_searched` | nothing matched in the scopes listed in `searched`, with a fresh index | treat as absent *there*; `not_searched` lists where it was not looked for |
| `absence.verdict: cannot_certify` | the index was stale/cold, a match was withheld, or nothing was searched | no conclusion; fix the store (`verify-chain`, `rebuild`) or the query |
| `already_read: true` | you read it earlier this session (it ranks lower) | skip it unless you need it again |
| `truncated` | the content was cut to fit `max_chars` | read `truncated.read` or raise `max_chars` |

Full rule table and invariants: [`docs/HONESTY.md`](docs/HONESTY.md).

### Secrets are refused, not tombstoned (0.6.0)

The chain is append-only and every byte of a put is hashed into it. A
tombstone hides a block from `recall`; it does not remove the secret from the
events table, from `export`, or from any backup, and deleting it would break
verification by design. So `put_document`, `supersede_block`,
`tombstone_block`, `kronicle-lite put`, `put --from-instructions`, `watch`
and `import` scan for common secret shapes (provider API keys and tokens,
private keys, JWTs, `scheme://user:password@` connection strings, bearer
headers, `…_PASSWORD=` / `…_TOKEN=` assignments) **before** anything is
chained, and refuse with `secret_detected` naming the detector and line
(never the secret). Overrides: `redact_secrets: true` / `--redact-secrets`
chains a copy with `[REDACTED:<detector>]` in place of each match;
`import --allow-secrets` imports verbatim (chained bytes cannot be redacted
without breaking their hashes). An independent read-time ruleset masks
anything that got in anyway (pre-0.6.0 data, `--allow-secrets`) in `recall`,
orient, `audit_assumptions` and the document resource.

Every tool declares an `outputSchema` and returns the same JSON as
`structuredContent` and as a text block (`get_system_state` renders Markdown
in the text block by default; `response_format: "json"` makes the text the
JSON too). Since 0.5.0 `tools/list` advertises compact output schemas (every
top-level field with its type, enum and `required`; nested shapes as bare
types) and short descriptions: **12.4 KB instead of 43.2 KB** (13.6 KB in 0.6.0 with the honest-label fields). Results are
still validated against the full schemas, which the
`kronicle://schemas/tools` resource serves; the orient skill carries the
longer guidance. The emitted catalog is pinned in
[`.mcp-catalog/kronicle-lite.json`](.mcp-catalog/kronicle-lite.json) and CI
fails on byte drift (`npm run catalog:check`), because a changed description
or schema silently invalidates every client's prompt-cache prefix.

Full hash recipes and payload shapes: [`docs/FORMAT.md`](docs/FORMAT.md).
What the local signature does and does not prove:
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

## How it compares

Four axes that matter for "agent reasons from stale notes". As documented by
each project at time of writing; corrections welcome.

| | local-first | tamper-evident log | staleness detection | signed receipts |
|---|---|---|---|---|
| **kronicle-lite** | yes (SQLite file) | yes (SHA-256 chain, public genesis, signed Merkle checkpoints) | yes (orient delta, drift banner, retractions, receipt `SUPERSEDED`/`TOMBSTONED`) | yes (Ed25519, chain-bound) |
| reference MCP memory server | yes (JSONL knowledge graph) | no | no | no |
| basic-memory | yes (Markdown files + SQLite index) | no | no | no |
| mem0 | partial (self-hostable; hosted platform is the default) | no | no (dedups/updates memories; does not tell the agent) | no |
| InALign | yes by default (provenance of agent *actions*, optional cloud) | yes (SHA-256 chain) | no | not documented |

The honest summary: the first three are memory stores and do their job; none
of them answer "has what I read changed?". InALign hash-chains what an agent
*did*; kronicle-lite hash-chains what an agent *knows* and signs what it was
told.

## Guarantees, briefly

- The chain verifies from a **public genesis** (`sha256("kronicle-lite-genesis-v1")`).
  No secret is needed to check it.
- What the agent reads is checked against the chain, not just the log:
  `recall`, `verify` and the document resource re-hash the stored text
  (BLAKE3) against the event that created it and refuse a mismatch;
  `verify-chain` and `doctor` re-derive the whole store from the chain.
- Receipts bind `(block_id, content_hash, doc_slug, revision)` to
  `(chain_seq, chain_head_hash)`. A store reset or rewrite under the agent
  makes old receipts `UNVERIFIED`, not silently `VERIFIED`.
- The signing key is **local**. This proves integrity against accidents and
  unprivileged edits; it is not third-party notarization. Read the threat
  model before relying on it for anything adversarial.
- Orienting never fails on a bad cursor; the server recovers position from the
  flight recorder and says so.
- (0.6.0) `can_act` comes only from block-level evidence; an empty `recall`
  never claims "not found" from a stale or cold index; a briefing that hid a
  scope says it is partial.

## Development

```sh
npm install
npm run build          # tsup → dist/
npm test               # builds, then vitest (unit + MCP in-process, stdio, HTTP, legacy handshake);
                       # CI runs it on Ubuntu (Node 20, 22) and Windows (Node 22)
npm run lint
npm run catalog:check  # tools/list bytes vs .mcp-catalog/ (re-snapshot with catalog:snapshot)
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) (DCO sign-off required) and
[`ROADMAP.md`](ROADMAP.md) for what is deliberately not here yet: inclusion
proofs against published anchor day roots, chain-backed tickets, semantic
recall.

The anchor acceptance tests run against an in-test stub of the service. To
run them against the real isokron-anchor Worker under Miniflare as well,
point `KRONICLE_ANCHOR_WORKER_DIR` at a checkout with its dependencies
installed: `KRONICLE_ANCHOR_WORKER_DIR=../isokron-anchor npx vitest run test/anchor.test.ts`.

## Beyond one agent

kronicle-lite is one actor, one process, one trust domain, on purpose.
**IsoKron** is the platform growing out of the same ideas — a typed graph
shared by many agents, claim fencing so parallel agents don't collide, and
per-tenant chains. It is in development and not self-serve;
https://isokron.ai explains what exists today and what doesn't.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.

---

Built off-grid in Cochise County, AZ by a laid-off support engineer —
https://theexiledentrepreneur.com
