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

## Recording

- **MCP:** `audit_record {audit_id, events: [{kind, event_key, payload}]}`, at
  most 500 per call.
- **CLI:** `kronicle-lite audit record --audit-id A --in events.jsonl`. Add a
  blob first with `audit put-blob FILE`.

**One call is one transaction.** A bad event refuses the whole call, and the
error carries `index`. Each event is checked in this order:

1. **Kind and schema.** The payload must validate against the schema for its
   `kind` (below). Unknown fields are refused. `audit_id` and `event_key` are
   filled into the payload.
2. **Secrets.** The write-time secret guard runs on the payload, so a key is
   never burned into the chain. Redact first; store the artifact as a ref with
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

The full JSON Schemas are served at `kronicle://schemas/audit`.

## Finding state (projection)

A finding moves through four statuses: `discovered → refuted | accepted`,
`refuted | accepted → reopened`, and `reopened → refuted | accepted`.

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
