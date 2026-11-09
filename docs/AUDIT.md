# Audit events (0.9.0)

kronicle-lite records MCP-audit evidence as first-class chain events.

- **What goes on the chain:** events carry hashes, blob refs, ids and small
  scalars only.
- **What stays off it:** traces, responses, transcripts and reports go to the
  content-addressed **blob store**, a `blobs` table beside the chain that
  events reference by `{sha256, size}`.
- **Workflow state:** a finding's current state is a *projection* of its
  immutable events, not a mutable row on the chain.

Source: `src/audit/`. Bundles: [EVIDENCE-BUNDLE.md](EVIDENCE-BUNDLE.md).

## Blobs

`audit put-blob FILE` stores an artifact by content.
- **Secret guard.** The write-time secret guard runs over the raw bytes (as
  latin1) and over their decoded views (each view capped at 16 MB): gzip and
  zlib deflate (at the start, and at any gzip member header), raw deflate and
  brotli (at the start), the body after an HTTP header block that declares a
  `Content-Encoding`, UTF-16LE and UTF-16BE text anywhere (any 128-byte window
  with NUL bytes at one parity), and base64 / base64url segments. Encodings
  nest up to 12 levels, so gzip inside base64 inside gzip is caught. A match
  is refused and nothing is stored.
- **Redaction.** `--redact-secrets` (API `secrets: 'redact'`) stores a copy with
  each raw match replaced by `[REDACTED:<detector>]` and returns
  `redactions: n`. The ref is the hash of the redacted copy. A match that is
  only visible after decoding cannot be redacted in place, so it is refused in
  either mode.
- **Undecodable views.** A view that cannot be decoded within the cap (a gzip
  bomb, a truncated stream, a declared `Content-Encoding` that does not decode
  or that the scan cannot decode, such as zstd, nesting past 12 levels, more
  than 64 stream starts or 8192 views in one blob, a stream that hits the
  16 MB cap, the 48 MB per-blob decode budget spent, or the per-blob work cap
  reached) is scanned as raw bytes only. A truncated stream (a gzip without
  its trailer, say) is also flagged, but what a decoder recovers from it is
  scanned first, so a secret in it is still refused. Every decoder that fits a stream is
  tried and each output is scanned. The blob is stored
  flagged `unscanned: ["unscanned_encoding"]`, and the bundle manifest marks it
  with `unscanned_encoding: true`. So is a base64 run that would decode to
  more than 16 MB.
- **Size cap.** The scan reads the first 32 MB of a blob (raw bytes and their
  views), in windows, so memory stays bounded. A larger blob is stored flagged
  `unscanned: ["unscanned_size"]` (manifest: `unscanned_size: true`): bytes past
  32 MB were not scanned. The scan also has a time budget (30 s per blob,
  checked between 2 MB windows): when it runs out, the rest of the raw bytes
  is not scanned (`unscanned_size`) and nothing more is decoded
  (`unscanned_encoding`). A match longer than 512 KB that crosses a 2 MB window
  boundary can be cut short or, for a private key block, missed.

## Recording

- **MCP:** `audit_record {audit_id, events: [{kind, event_key, payload}]}`, at
  most 500 per call.
- **CLI:** `kronicle-lite audit record --audit-id A --in events.jsonl`. Add a
  blob first with `audit put-blob FILE`.

**One call is one transaction.** A bad event refuses the whole call, and the
error carries `index`. Each event is checked in this order:

0. **Shape.** `__proto__` keys and nesting deeper than 16 levels are refused,
   not silently dropped.
1. **Kind and schema.** The payload must validate against the schema for its
   `kind` (below). Unknown fields are refused. `audit_id` and `event_key` are
   filled into the payload.
2. **Secrets.** The write-time secret guard runs on the payload (values and
   object keys, such as `deltas` and `tokens` names) and on the actor id, so a
   key is never burned into the chain. Redact first; store the artifact as a ref with
   `redacted: true`.
3. **Blob refs.** Each ref must name a stored blob of that size, unless it is
   `redacted: true`.
4. **Evidence.** `evidence` ids must be events of the same audit.
5. **Finding transitions.** See the finding state section below.

**Idempotent by stable id, not by content.** `(audit_id, event_key)` maps to one
chain idempotency key and one `event_id`, which is UUID-shaped, version 8,
sha256-derived and identical in any store.
- A retry with the same payload returns the original event (`replayed: true`).
- The same key with a different payload is `event_key_conflict`; it is never
  recorded as a second event.

## Kinds

Every payload has `audit_id`, `event_key` and an optional `measured_at`. A ref
is `{sha256, size, media_type?, redacted?: true}`.

| kind | required | optional |
|---|---|---|
| `catalog_snapshot` | `fingerprint`, `server{name, version?}`, `tool_count`, `bytes`, `snapshot` (ref) | `tokens{tokenizer: n}` |
| `call_measured` | `fingerprint`, `tool`, `status`, `is_error`, `latency_ms`, `bytes_out` | `bytes_in`, `tokens`, `request` / `response` (refs) |
| `finding` | `finding_id`, `status` | `title` (≤ 200), `severity` (S1–S4, info), `class`, `fingerprint`, `detail` (ref), `evidence[]` |
| `gate_result` | `finding_id`, `gate`, `verdict` (upheld \| refuted \| inconclusive) | `report` (ref), `evidence[]` |
| `fix_applied` | `finding_id`, `ref` (PR / commit / rule id) | `fingerprint_before` / `_after`, `diff` (ref), `evidence[]` |
| `regression_result` | `fingerprint_before`, `fingerprint_after`, `verdict` (improved \| regressed \| unchanged), `deltas{name: number}` | `finding_id`, `report` (ref), `evidence[]` |
| `harness_frozen` (0.10.0) | `harness_id`, `fingerprint` (sha256 of the harness manifest), `manifest` (ref) | `hypotheses` (ref), `planned_runs`, `title` |
| `run_completed` (0.10.0) | `run_id`, `run_seq` (1-based, no gaps), `fingerprint` (the harness it ran under), `status` | `nonce` (freeze nonce), `capture` (complete \| interrupted), `interruption`, `result` (ref), `evidence[]` |
| `report_issued` (0.10.0) | `report_id`, `report` (ref) | `run_count`, `title`, `evidence[]` |

The full JSON Schemas are served at `kronicle://schemas/audit`.

**Audit milestones (0.10.0).** `harness_frozen`, `run_completed` and
`report_issued` mark the stages an [evidence pack](EVIDENCE-BUNDLE.md#evidence-packs-0100)
timestamps:

- Record `harness_frozen` first, then `checkpoint --push` and `audit stamp`
  before the first run. The freeze anchor is the starting point: nothing
  before it is timestamped.
- The **freeze nonce** is the sha256 of that freeze anchor's receipt file (the
  digest the timestamp authorities stamped). A run that records it as `nonce`
  (and, where it can, uses it in the names of objects it creates on the system
  under test) could not have been recorded before the freeze. `verify-audit`
  checks `harness_frozen_before_runs` on the nonce when every run carries it,
  otherwise on `measured_at`.
- Each run names the harness digest it ran under (`fingerprint`); it must be
  the frozen one.
- `run_seq` numbers the runs 1..N. Declare N at freeze time (`planned_runs`)
  and in the report (`run_count`); `verify-audit` checks that the sequence has
  no gap or repeat and agrees with every declared count (`run_sequence`). A run
  whose evidence capture was interrupted stays in the sequence with
  `capture: "interrupted"` and an `interruption` note.

A bundle holding a milestone kind is exported as
`kronicle-lite-evidence-bundle/2`; 0.9.0's `verify-bundle` refuses it by format
(use 0.10.0 or later). A bundle with only the six 0.9.0 kinds is still `/1`.

**The 0.9.0 convention.** Before these kinds, a harness freeze was recorded as
`finding` with `class: "protocol_freeze"` and `fingerprint`, and runs as
`call_measured` with `measured_at`. `verify-audit` reads that convention too
(ordering on `measured_at`; no `run_sequence`, which needs `run_seq`).

**0.8.x stores.** A store made by 0.8.x gains the tables on its first
read-write open. Opened read-only (`verify-chain`, `verify`, `doctor`, a
read-only medium), it is never migrated: it has no audit events, its audit
queries answer empty, and verification passes.

**Reserved keys.** The chain idempotency keys `audit:…` and `apply:…` are
reserved. `put_document` refuses them (`reserved_key`), so no document write
can squat a future audit event or apply commit.

## Finding state (projection)

| from \ to | discovered | refuted | accepted | reopened |
|---|---|---|---|---|
| (new) | yes | no | no | no |
| discovered | no | yes | yes | no |
| refuted | no | yes (another refuter) | no | yes |
| accepted | no | no | no | yes |
| reopened | no | yes | yes | no |

- **First event:** a finding's first event must be `finding{status: discovered}`.
- **Refuted:** a `gate_result` with `verdict: refuted` refutes the finding.
- **Accepted and reopened:** these are explicit `finding` events, because they
  are a human or reviewer decision.
- **Other events:** these need the finding to exist and don't change its status.

`rebuild` re-derives the projection from the chain. `verify-chain` reports an
`audit_events` table that disagrees with the chain.

## Querying

- **MCP:** `audit_query {audit_id? | fingerprint?, kind?, finding_id?, after_seq?, limit?}`.
- **CLI:** `kronicle-lite audit query --audit-id A [--findings]` or `--fingerprint F`.

A fingerprint matches `fingerprint`, `fingerprint_before` and `fingerprint_after`.
This lets every number in a report trace back to the catalog it was measured
against.

## Batch verify

`verify` takes `receipts` or `receipt_ids`, up to 100 per call. `results[]` is
in input order, and `counts` gives the number per status. The top-level fields
are the first result that is not `VERIFIED` (otherwise the first result), so a
client that reads only `status` fails closed.
