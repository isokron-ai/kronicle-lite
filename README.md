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
Code, Cursor, Claude Desktop or any MCP client.

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

`.cursor/mcp.json`:

```json
{ "mcpServers": { "kronicle-lite": { "command": "npx", "args": ["-y", "kronicle-lite", "serve", "--actor", "cursor"] } } }
```

### Claude Desktop

`claude_desktop_config.json`:

```json
{ "mcpServers": { "kronicle-lite": { "command": "npx", "args": ["-y", "kronicle-lite", "serve", "--actor", "claude-desktop"] } } }
```

More in [`examples/`](examples/README.md).

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

## Tools

| tool | what it does | writes chain |
|---|---|---|
| `get_system_state` | Orient. `since_cursor` → delta since then; drift banner; retractions; new cursor. `focus`: `orientation` (default), `recent_changes`, `retractions`, `pulse` (~50 tokens). `response_format`: `markdown` (default) or `json`. | no |
| `audit_assumptions` | Grade claims `{symbol, value}` (block id, doc slug, or `head`) → `current \| stale \| contradicted \| retracted \| unknown` with the current truth and a reconcile line. | no |
| `recall` | FTS5 bm25 search over live blocks; each hit carries a receipt v2 bound to the chain head. `top_k`, `include_tombstoned`, `include_receipts`. | no (stores receipts) |
| `verify` | Re-derive a receipt against the live store: signature, block existence, content hash, chain binding, supersession walk → `VERIFIED \| SUPERSEDED \| TOMBSTONED \| UNVERIFIED` + reason. | no |
| `verify_chain` | Recompute every hash and link in a range; first mismatch; checkpoint results. | no |
| `checkpoint_chain` | Sign a Merkle root over a seq range with the local key. | no (checkpoints table) |
| `put_document` | Create or re-put a Markdown document by slug. Unchanged blocks keep their ids; changed ones are superseded; removed ones tombstoned. | yes |
| `supersede_block` | Replace one live block with new content and a reason. | yes |
| `tombstone_block` | Retire one live block with a reason. | yes |

Every write tool accepts an optional `cursor` and returns the new chain head
plus a `stale_write_advisory` (advisory only; nothing is ever blocked). The
`kronicle://docs/{slug}` resource serves a document's current revision.

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
npm run build        # tsup → dist/
npm test             # builds, then vitest (unit + MCP in-process + MCP over stdio)
npm run lint
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) (DCO sign-off required) and
[`ROADMAP.md`](ROADMAP.md) for what is deliberately not here yet: chain-backed
tickets, HTTP transport, remote checkpoint anchoring, semantic recall.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.

---

Built off-grid in Cochise County, AZ by a laid-off support engineer —
https://theexiledentrepreneur.com
