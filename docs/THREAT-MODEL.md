# Threat model

kronicle-lite runs on your machine, with one SQLite file and one Ed25519 key
that it generated itself. Be precise about what that buys you.

## What tamper-evidence gives you here

**Detection of accidental or unprivileged modification.** If a process edits
the SQLite file directly (a sync client resolving a conflict badly, a script
with a bug, a partial restore from backup, disk corruption), `verify_chain`
finds the first bad `seq`, and receipts issued before the edit come back
`UNVERIFIED` with a reason that says what moved (`content_hash_mismatch`,
`chain_head_mismatch`, `chain_seq_unknown`).

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
detectable by comparing roots. kronicle-lite does not do this for you.

## What it does not give you

**It is not notarization.** The signing key lives next to the database and
is readable by the same user. Anyone (or any process) who can write the
database can also read `signing-key.pem`, rewrite the chain from any point,
re-sign new receipts and checkpoints, and `verify_chain` will pass. Tamper-
evidence against the box owner, or against malware running as the box owner,
requires a key the box does not hold — a hardware token, a remote signer, or
anchoring roots in a third-party log. None of that is in v0.1. If someone
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

## Assumed deployment

- One user, one machine, one or more agents (Claude Code, Cursor, Claude
  Desktop, scripts) attached over stdio.
- The user wants to know when an agent's notes have been superseded or
  retired, and wants a record that is hard to corrupt by accident.
- The user does not need to convince anyone else of anything.

If your situation is different — shared machines, adversarial co-tenants,
compliance evidence — treat kronicle-lite as a well-structured log and add an
external anchor (see ROADMAP: remote checkpoint anchoring).

## Reporting

Suspected integrity or signature bypasses: see CONTRIBUTING.md. Please do not
open a public issue first.
