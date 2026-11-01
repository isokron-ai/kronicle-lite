# Threat model

kronicle-lite runs on your machine, with one SQLite file and one Ed25519 key
that it generated itself. Be precise about what that buys you.

## What tamper-evidence gives you here

**Detection of accidental or unprivileged modification.** If a process edits
the SQLite file directly (a sync client resolving a conflict badly, a script
with a bug, a partial restore from backup, disk corruption):

- an edit to the **`events` table** (the chain): `verify_chain` /
  `verify-chain` and `doctor` report the first bad `seq` (`hash_mismatch`,
  `link_broken`, `seq_gap`, `head_mismatch`); receipts bound to a head that
  is no longer on the chain come back `UNVERIFIED` (`chain_head_mismatch`,
  `chain_seq_unknown`); `get_system_state` re-checks the events of its
  delta window (at least the last 1000) and puts an `INTEGRITY FAILURE`
  banner first when one fails.
- an edit to the **projection** the agent reads (`blocks`,
  `document_revisions`, `documents`, `doc_sources`), since 0.5.0: every
  read path that serves text re-hashes it (BLAKE3) and compares it with the
  chained event that created it. `recall` withholds such a block (no
  content, no receipt; listed under `withheld`), `verify` returns
  `UNVERIFIED / content_tampered`, and a "live" answer is cross-checked
  against the chain's `block.superseded` / `block.tombstoned` events
  (`UNVERIFIED / projection_mismatch`); the `kronicle://docs/{slug}`
  resource refuses a revision whose markdown does not match; orient's
  integrity pass re-hashes the newest 2000 live blocks. `verify-chain` over
  the whole chain (or with `--full`), the MCP `verify_chain` tool over the
  whole chain and `doctor` replay every event into a scratch copy and
  compare every stored row column by column, so a changed lifecycle column,
  an extra row or a deleted row is reported too. `kronicle-lite rebuild`
  re-derives the projection from a chain that verifies.

Before 0.5.0 the projection was not checked: an edited `blocks.content`
passed `verify_chain` and `doctor`, and `recall` served it with a receipt
that verified `VERIFIED`.

Not covered: the `receipts`, `flight_recorder`, `checkpoints` and
`anchors` tables are not derived from the chain. Editing the flight
recorder changes where a cursor-less orient resumes; editing a stored
receipt breaks its signature; a checkpoint row is verified against the
events on `verify_chain`.

**Detection that an agent is reasoning from a stale block.** This is the main
job. A receipt is a claim the agent can carry across turns, compactions and
sessions; `verify()` answers "is the thing I read still the current thing?"
with `VERIFIED | SUPERSEDED | TOMBSTONED | UNVERIFIED`. The chain binding in
receipt v2 additionally catches the case where the store was reset or replaced
underneath the agent (the `chain_seq/chain_head_hash` pair no longer resolves).

**A reproducible record.** Every hash and signature is specified in
`docs/FORMAT.md` with worked examples. You can check the file from another
language, or from `sha256sum` in a shell, without trusting this code.

**Checkpoints you can take off-box.** A signed Merkle root over a seq range is
a few hundred bytes. If you copy checkpoints (or the whole JSONL export) to a
place the local machine cannot write, a later rewrite of the local chain is
detectable by comparing roots. Since 0.4.0 `checkpoint --push` does this for
you against a hosted anchor service, and `verify --remote` does the comparing:

| evidence | who signs | what it proves | what it cannot |
|---|---|---|---|
| local checkpoint | the box's own key | the rows still hash to the root the box signed | anything against the box owner: they hold the key and can re-sign |
| anchored checkpoint (0.4.0) | the box's key, countersigned by the anchor service, `received_at` bound | that this root for this range existed no later than `received_at`; a later rewrite of that range shows as `diverged` locally and as a `409 CONFLICT` if re-pushed | that the root covers real events (the service never sees leaves); that `[1..N+k]` extends an earlier `[1..N]` (no consistency proof in v1); who holds the signing key (the license key only pays) |
| published anchor (service day roots, later) | as above, plus a public log | as above, without trusting the service's database | as above |

An anchor is a timestamped commitment, not a content audit. The service is
not deployed yet; until it is, `--push` and `--remote` report "anchor service
unreachable" and every local command behaves exactly as without them.

## What it does not give you

**It is not notarization.** The signing key lives next to the database and
is readable by the same user. Anyone (or any process) who can write the
database can also read `signing-key.pem`, rewrite the chain from any point
(events and the projection together, re-linking every later event), re-sign
new receipts and checkpoints, and `verify_chain` will pass. Tamper-
evidence against the box owner, or against malware running as the box owner,
requires a key the box does not hold — a hardware token, a remote signer, or
anchoring roots in a third-party log. 0.4.0 adds the last of these
(`checkpoint --push`); it bounds *when* a root existed, it does not make the
local key trustworthy. If someone
tells you a local signature "proves" something to a third party, they are
wrong.

**Old receipts cannot prove a rewrite by themselves.** If the chain is
rewritten and re-signed with the same key, an old receipt's
`chain_head_hash` will simply not be found and `verify()` returns
`UNVERIFIED / chain_seq_unknown` or `chain_head_mismatch`. That tells you
*something* changed; it does not tell you *who* or *what the old content
was*. Keep exports if you need that.

**Revocation is local.** `signing_keys.revoked_at` is a column in the same
database. It stops the server honoring receipts from a key you decided not to
trust; it does not stop an attacker with the file from un-revoking it.

**Cursors are not credentials.** The cursor HMAC only protects the server
from acting on a position the agent made up. A stolen cursor grants nothing;
a forged cursor just makes the server fall back to the flight recorder.

**No confidentiality.** Nothing is encrypted. Block content, document markdown,
receipts and the flight recorder are plaintext in the SQLite file and in the
chain payloads. Treat the data dir like any other private file (`0700`).

**No access control, no multi-tenancy.** `actor_id` is a label the caller
supplies. It drives per-actor orient state (cursor binding, flight recorder,
drift banner); it is not authentication. Any MCP client that can reach the
stdio process can read and write everything. Run one data dir per trust
domain.

**Availability.** A single writer, a single file. SQLite in WAL mode handles
concurrent processes correctly but not a hostile one holding a lock.

## HTTP transport (`serve --http`)

The Streamable HTTP mode (0.3.0) does not change the trust domain; it changes
who can reach the process. Be precise about what the knobs do.

**Single tenant, one secret.** There is one bearer token, read from
`<data dir>/http-bearer.token` (created with mode `0600` when absent) or
passed with `--bearer` / `--bearer-file`. Every request must present it as
`Authorization: Bearer <token>`; the comparison is constant-time. Holding the
token is holding the whole store: there are no scopes, no per-tool
permissions, no per-actor identity. `actor_id` is still a label the caller
chooses. Rotate by deleting the file and restarting.

**Loopback by default.** The server binds `127.0.0.1` unless `--host` says
otherwise. The `Host` header must name the bound host or loopback and the
`Origin` header, when a browser sends one, must be loopback or in
`--allow-origin` — both are rejected before the bearer is even looked at
(DNS-rebinding defence per the Streamable HTTP spec). Binding `0.0.0.0` or a
LAN address is your decision; add the hostnames clients will use with
`--allow-host`, and put TLS in front — the token travels in clear text
otherwise. kronicle-lite does not do TLS.

**Stateless, both eras (0.5.0).** No session id is minted or honored, `GET`
and `DELETE` answer `405`. A 2026-07-28 request carries its own protocol
version. A 2025-era client (one that opens with `initialize`, which is what
Cursor and most clients still send) is served by the SDK's stateless legacy
leg: every POST gets a fresh server instance over the same store, so there
is no session to hijack or fixate and `initialize` grants nothing a later
request relies on. It passes the same Host, Origin and bearer checks first;
the legacy leg adds no route around them. `--modern-only` refuses those
clients with `UnsupportedProtocolVersionError` (`-32022`) as 0.3.0/0.4.0 did.

**What it is for.** A client on the same machine that cannot spawn a process,
or a trusted single-user box reached over a tunnel you already protect. It is
the base the hosted tier and the sea-lite team mode build on; it is not,
by itself, a multi-user service. Treat the token like an SSH key.

## Git binding (0.4.0)

`bind_git` runs `git rev-parse` and `git hash-object` on the path you give.
Over MCP that path is resolved by the server process: a client can learn
whether a file exists and its blob hash (never its content) anywhere the
server user can read. On stdio that is the same user as the client; over
`serve --http` it is whoever holds the bearer token, which already reads
and writes the whole store. `STALE_SOURCE` says the file changed since it
was bound; it does not say who changed it, and a working tree is as
writable as the database next to it.

## Assumed deployment

- One user, one machine, one or more agents (Claude Code, Cursor, Claude
  Desktop, scripts) attached over stdio, or over loopback HTTP with the
  bearer token.
- The user wants to know when an agent's notes have been superseded or
  retired, and wants a record that is hard to corrupt by accident.
- The user does not need to convince anyone else of anything.

If your situation is different — shared machines, adversarial co-tenants,
compliance evidence — treat kronicle-lite as a well-structured log and anchor
its checkpoints off-box (`checkpoint --push`, `verify --remote`).

**What leaves the box when you anchor.** The checkpoint (range, leaf count,
root, key_id, signature), your public key and your license key. Never events,
block content, document titles or receipts. `config.json` holds the license
key; it is written `0600` and `doctor` flags it when it is not.

## Reporting

Suspected integrity or signature bypasses: see CONTRIBUTING.md. Please do not
open a public issue first.
