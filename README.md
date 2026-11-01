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
  on that are now wrong.

It is one process, one file, no accounts. It runs over stdio next to Claude
Code, Cursor, Claude Desktop, Codex, GitHub Copilot or any MCP client, and
over loopback Streamable HTTP for clients that cannot spawn a process.

> **0.3.0 speaks MCP 2026-07-28** (TypeScript SDK v2). Every tool has an
> `outputSchema` and returns `structuredContent`; `tools/list` and
> `server/discover` carry cache hints; results carry `resultType`. The
> stdio server is **dual-era**: a client that still opens with the
> 2025-era `initialize` handshake (2025-11-25, 2025-06-18, 2025-03-26) is
> served exactly as before. HTTP is 2026-07-28 only. Details in
> [CHANGELOG](CHANGELOG.md).

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
instead of `command`/`args` — only if your Cursor build speaks MCP
2026-07-28 over HTTP; a 2025-era HTTP client is refused (stdio serves both).
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
- **2026-07-28 only, stateless.** No session id, `GET`/`DELETE` answer
  `405`, every request carries its protocol version in `_meta` and the
  `MCP-Protocol-Version` header. A 2025-era `initialize` gets `400` with
  `UnsupportedProtocolVersionError` (`-32022`) listing `2026-07-28`; use
  stdio for those clients.
- **Trust domain.** Single tenant: the token is the whole store. See
  [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md#http-transport-serve---http).

## Sixty-second tour

```sh
# store a document (splits into blocks, appends events, returns hashes + head)
kronicle-lite put runbook ./runbook.md --title "Runbook"

# orient as an agent would (markdown; --json for the raw envelope)
kronicle-lite orient --actor me

# verify every hash and link; exit 1 on the first mismatch
kronicle-lite verify-chain

# sign a Merkle checkpoint over the whole chain
kronicle-lite checkpoint

# take the chain somewhere else and rebuild from it
kronicle-lite export --out events.jsonl
kronicle-lite import --data-dir /tmp/copy --in events.jsonl
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
  true` also asks the service. `get_system_state` adds one banner line:
  `anchored N events ago (status)` or `never anchored`.
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
retraction of kind `instruction` ("instruction block … was CHANGED in
instructions/claude-md; re-read kronicle://docs/instructions%2Fclaude-md").
A deleted file retires its blocks (severity `safety`).

Default set, relative to the git worktree root (or the working directory):

| file | slug |
|---|---|
| `CLAUDE.md` | `instructions/claude-md` |
| `AGENTS.md` | `instructions/agents-md` |
| `.claude/rules/**/*.md` | `instructions/claude-rules/<path>` |
| `.cursor/rules/**` | `instructions/cursor-rules/<path>` |
| Claude Code auto memory `MEMORY.md` | `memory/MEMORY` |

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

## Tools

| tool | what it does | writes chain |
|---|---|---|
| `get_system_state` | Orient. `since_cursor` → delta since then; drift banner; retractions; new cursor. `focus`: `orientation` (default), `recent_changes`, `retractions`, `pulse` (~50 tokens). `response_format`: `markdown` (default) or `json`. | no |
| `audit_assumptions` | Grade claims `{symbol, value}` (block id, doc slug, or `head`) → `current \| stale \| contradicted \| retracted \| unknown` with the current truth and a reconcile line. | no |
| `recall` | FTS5 bm25 search over live blocks; each hit carries a receipt v2 bound to the chain head. `top_k`, `include_tombstoned`, `include_receipts`. | no (stores receipts) |
| `verify` | Re-derive a receipt against the live store: signature, block existence, content hash, chain binding, supersession walk → `VERIFIED \| SUPERSEDED \| TOMBSTONED \| UNVERIFIED` + reason. | no |
| `verify_chain` | Recompute every hash and link in a range; first mismatch; checkpoint results. | no |
| `checkpoint_chain` | Sign a Merkle root over a seq range with the local key; `push: true` also anchors it off-box. | no (checkpoints, anchors tables) |
| `anchor_status` | Last off-box anchor, events since, and whether the local chain still matches it (`remote: true` asks the service). | no |
| `put_document` | Create or re-put a Markdown document by slug. Unchanged blocks keep their ids; changed ones are superseded; removed ones tombstoned. | yes |
| `supersede_block` | Replace one live block with new content and a reason. | yes |
| `tombstone_block` | Retire one live block with a reason. | yes |

Every write tool accepts an optional `cursor` and returns the new chain head
plus a `stale_write_advisory` (advisory only; nothing is ever blocked). The
`kronicle://docs/{slug}` resource serves a document's current revision.

Every tool declares an `outputSchema` and returns the same JSON as
`structuredContent` and as a text block (`get_system_state` renders Markdown
in the text block by default; `response_format: "json"` makes the text the
JSON too). The emitted catalog is pinned in
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
- Receipts bind `(block_id, content_hash, doc_slug, revision)` to
  `(chain_seq, chain_head_hash)`. A store reset or rewrite under the agent
  makes old receipts `UNVERIFIED`, not silently `VERIFIED`.
- The signing key is **local**. This proves integrity against accidents and
  unprivileged edits; it is not third-party notarization. Read the threat
  model before relying on it for anything adversarial.
- Orienting never fails on a bad cursor; the server recovers position from the
  flight recorder and says so.

## Development

```sh
npm install
npm run build          # tsup → dist/
npm test               # builds, then vitest (unit + MCP in-process, stdio, HTTP, legacy handshake)
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
