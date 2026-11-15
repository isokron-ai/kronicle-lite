/**
 * Audit event types (0.9.0): first-class, schema-validated records on the
 * chain for MCP audits. Payloads carry hashes, blob refs, ids and small
 * scalars only: traces, responses, transcripts and reports go to the
 * content-addressed blob store (src/audit/blobs.ts) and are referenced by
 * sha256. docs/AUDIT.md is the reference; docs/EVIDENCE-BUNDLE.md the
 * offline verification procedure.
 *
 * This module has no store dependency so `verify-bundle` can use it alone.
 */

import { createHash } from 'node:crypto';

import { z } from 'zod';

/** The 0.9.0 kinds: a bundle that holds only these is written as format /1, which 0.9.0 readers verify. */
export const AUDIT_KINDS_V1 = ['catalog_snapshot', 'call_measured', 'finding', 'gate_result', 'fix_applied', 'regression_result'] as const;
/** Audit milestones (0.10.0): a bundle holding any of these is written as format /2 (0.9.0 readers refuse it by format). */
export const MILESTONE_KINDS = ['harness_frozen', 'run_completed', 'report_issued'] as const;
/** Audit-profile kinds (0.11.0): a bundle holding any of these, or a planned freeze, is written as format /3. */
export const V3_KINDS = ['run_abandoned', 'reproduction_signed', 'audit_closed'] as const;
/**
 * OAuth evidence kinds (0.12.0): the login, refresh, failure and revocation of an audit identity, and the
 * client registration they use. A bundle holding any of these is written as format /4, which carries every /3
 * rule; 0.11.x readers refuse it by format. Their payloads hold no credential: tokens, codes, verifiers and
 * secrets appear only as keyed commitments (AUTH_COMMITMENT_LABELS).
 */
export const AUTH_KINDS = ['auth_registered', 'auth_granted', 'auth_refreshed', 'auth_failed', 'auth_revoked'] as const;
export const AUDIT_KINDS = [...AUDIT_KINDS_V1, ...MILESTONE_KINDS, ...V3_KINDS, ...AUTH_KINDS] as const;
export type AuditKind = (typeof AUDIT_KINDS)[number];
export const AUDIT_EVENT_PREFIX = 'audit.';
/** Evidence bundle format tags (src/audit/bundle.ts, docs/EVIDENCE-BUNDLE.md). */
export const BUNDLE_FORMAT_V1 = 'kronicle-lite-evidence-bundle/1';
export const BUNDLE_FORMAT_V2 = 'kronicle-lite-evidence-bundle/2';
/** 0.11.0: the run plan is required on the freeze, runs carry the derived nonce, the report its run count (V3_REQUIRED). */
export const BUNDLE_FORMAT_V3 = 'kronicle-lite-evidence-bundle/3';
/** 0.12.0: /3 plus the OAuth evidence kinds (AUTH_KINDS); every /3 rule applies unchanged. */
export const BUNDLE_FORMAT_V4 = 'kronicle-lite-evidence-bundle/4';
export const BUNDLE_FORMATS = [BUNDLE_FORMAT_V1, BUNDLE_FORMAT_V2, BUNDLE_FORMAT_V3, BUNDLE_FORMAT_V4] as const;
export type BundleFormat = (typeof BUNDLE_FORMATS)[number];
/** @deprecated the /1 tag; kept for 0.9.0 callers. */
export const BUNDLE_FORMAT = BUNDLE_FORMAT_V1;
/** The formats the audit profile reads (run plan, derived nonce, run count): /3 and /4. */
export function isProfileFormat(format: unknown): format is typeof BUNDLE_FORMAT_V3 | typeof BUNDLE_FORMAT_V4 {
  return format === BUNDLE_FORMAT_V3 || format === BUNDLE_FORMAT_V4;
}
/** The kinds a bundle of `format` may hold. */
export function kindsOfFormat(format: BundleFormat): readonly AuditKind[] {
  if (format === BUNDLE_FORMAT_V1) return AUDIT_KINDS_V1;
  if (format === BUNDLE_FORMAT_V2) return [...AUDIT_KINDS_V1, ...MILESTONE_KINDS];
  if (format === BUNDLE_FORMAT_V3) return [...AUDIT_KINDS_V1, ...MILESTONE_KINDS, ...V3_KINDS];
  return AUDIT_KINDS;
}
/**
 * The oldest format that can carry every kind in `kinds` (older readers keep working when they can).
 * `planned`: a harness_frozen carries a run plan, which makes the bundle /3 (its rules then apply).
 * An OAuth kind makes it /4. A bundle without one is written exactly as 0.11.x wrote it.
 */
export function formatForKinds(kinds: Iterable<AuditKind>, planned = false): BundleFormat {
  let level = planned ? 3 : 1;
  for (const k of kinds) {
    if ((AUTH_KINDS as readonly string[]).includes(k)) return BUNDLE_FORMAT_V4;
    if ((V3_KINDS as readonly string[]).includes(k)) level = 3;
    else if (level === 1 && !(AUDIT_KINDS_V1 as readonly string[]).includes(k)) level = 2;
  }
  return level === 3 ? BUNDLE_FORMAT_V3 : level === 2 ? BUNDLE_FORMAT_V2 : BUNDLE_FORMAT_V1;
}
export const auditEventType = (kind: AuditKind): string => `${AUDIT_EVENT_PREFIX}${kind}`;
export function kindOfEventType(event_type: string): AuditKind | null {
  if (!event_type.startsWith(AUDIT_EVENT_PREFIX)) return null;
  const k = event_type.slice(AUDIT_EVENT_PREFIX.length);
  return (AUDIT_KINDS as readonly string[]).includes(k) ? (k as AuditKind) : null;
}

export const FINDING_STATUSES = ['discovered', 'refuted', 'reopened', 'accepted'] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

const SHA256 = z.string().regex(/^[0-9a-f]{64}$/, 'lowercase hex sha256');
const ID = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/, 'id: 1-128 of [A-Za-z0-9._:/-], starting alphanumeric');
const SHORT = z.string().min(1).max(200);
const COUNT = z.number().int().nonnegative();
/** Most runs one freeze may plan. */
export const MAX_PLANNED_RUNS = 2000;
/** An allowed-signers principal (ssh-keygen -Y sign -I): no whitespace, quotes or commas. */
const PRINCIPAL = z.string().regex(/^[A-Za-z0-9._@+-]{1,128}$/, 'principal: 1-128 of [A-Za-z0-9._@+-]');
/** Token counts by tokenizer name (bytes, cl100k, o200k, a model id …). */
const TOKENS = z.record(z.string().min(1).max(64), COUNT).refine((r) => Object.keys(r).length <= 16, 'at most 16 tokenizers');

/**
 * A reference to an artifact in the blob store. `redacted: true` declares
 * an artifact that was deliberately NOT stored (redacted before
 * persistence); its sha256 is the hash of the original, so a holder of the
 * original can still prove it matches.
 */
export const BlobRefSchema = z.strictObject({
  sha256: SHA256,
  size: COUNT,
  media_type: z.string().min(1).max(100).optional(),
  redacted: z.literal(true).optional(),
});
export type BlobRef = z.infer<typeof BlobRefSchema>;

/** Event ids (chain event_id, a UUID) of earlier audit events this one rests on. */
const EVIDENCE = z.array(z.uuid()).max(100);

const Common = {
  audit_id: ID,
  /** Stable id of this logical event within the audit (the idempotency handle; see auditIdentity). */
  event_key: ID,
  /** Wall-clock time of the measurement itself, when it differs from the append time. */
  measured_at: z.iso.datetime().optional(),
};

// ── OAuth evidence (0.12.0) ──
//
// What an auth event may hold follows the toolkit's field policy (mcp-audit SYNTHESIS Q9 and Q10): protocol
// structure, issuer, resource, audience, times, scope and client id in clear; every token, code, verifier,
// secret, subject and login hint as a keyed commitment; nothing else. The schemas enforce it structurally:
// - every object is strict, so a field such as `code`, `code_verifier`, `client_secret` or a raw `token` is
//   refused wherever it appears;
// - a credential field holds only a commitment `{commit, len, label}` with a fixed label and 16 hex digits;
// - URLs are https (or http to a loopback host) with no userinfo, query or fragment, so a code, state or token
//   carried in a URL cannot be recorded;
// - codes (stage, OAuth error, replay outcome) are lowercase letters and underscores, with no digits;
// - the free-form public identifiers (client id, audience, issuer claims, scope) refuse anything shaped like a
//   JSON Web Token, and the store's write-time secret guard scans every payload as for every other kind.

/** The credential kinds a commitment may name: HMAC-SHA256(audit key, label "\n" value), first 16 hex. */
export const AUTH_COMMITMENT_LABELS = ['access-token', 'refresh-token', 'id-token', 'authorization-code', 'pkce-verifier', 'code-challenge', 'state', 'client-secret', 'registration-access-token', 'subject', 'jti', 'login-hint'] as const;
export type AuthCommitmentLabel = (typeof AUTH_COMMITMENT_LABELS)[number];
/** A keyed commitment to a credential of kind `label`; the value itself is never recorded. */
const commitment = (label: AuthCommitmentLabel) =>
  z.strictObject({
    commit: z.string().regex(/^[0-9a-f]{16}$/, 'commit: the first 16 lowercase hex digits of the keyed HMAC'),
    len: COUNT.describe('length of the committed value'),
    label: z.literal(label),
  });
/**
 * Anything shaped like a JSON Web Token: a JWS or JWE compact form starts with a base64url JSON header
 * (`eyJ`) and a dot, at the start of the value or after a character that is not base64url.
 */
const JWT_SHAPED = /(?:^|[^A-Za-z0-9_-])eyJ[A-Za-z0-9_-]*\./;
const notJwt = (s: string) => !JWT_SHAPED.test(s);
/** An id (as ID) that is not token-shaped: profile, identity, tenant and registration names. */
const AUTH_ID = ID.refine(notJwt, 'a token-shaped value (JWT) is not recorded');
/** https, or http to a loopback host (a local build or a test fixture); no userinfo, query, fragment or percent-encoding. */
const AUTH_URL = z
  .string()
  .max(512)
  .regex(/^(?:https:\/\/[A-Za-z0-9][A-Za-z0-9.-]*|http:\/\/(?:127\.0\.0\.1|localhost|\[::1\]))(?::[0-9]{1,5})?(?:\/[A-Za-z0-9._~:@/-]*)?$/, 'an https URL (http only to a loopback host) with no userinfo, query, fragment or percent-encoding')
  .refine(notJwt, 'a token-shaped value (JWT) is not recorded');
/** A public identifier the protocol defines as non-secret (client id, audience, issuer claim, key id). */
const PUBLIC_ID = z
  .string()
  .min(1)
  .max(256)
  .regex(/^[!-~]+$/, 'printable ASCII, no spaces')
  .refine(notJwt, 'a token-shaped value (JWT) is not recorded');
/** An OAuth scope (RFC 6749 3.3): scope tokens separated by single spaces. */
const SCOPE = z
  .string()
  .min(1)
  .max(2048)
  .regex(/^[!#-[\]-~]+(?: [!#-[\]-~]+)*$/, 'scope tokens (RFC 6749 3.3) separated by single spaces')
  .refine(notJwt, 'a token-shaped value (JWT) is not recorded');
/** A stage or an error code: lowercase letters and underscores only (no digits, so no token fits). */
const AUTH_CODE = z.string().regex(/^[a-z][a-z_]{0,63}$/, 'lowercase letters and underscores (at most 64)');
const HTTP_STATUS = COUNT.refine((n) => n <= 599, 'an HTTP status (0 when none was received)');
const EPOCH_S = z.number().nonnegative().describe('seconds since the epoch (a NumericDate may have a fraction)');
const REGISTRATION_MODES = ['static', 'cimd', 'dcr'] as const;
const CLAIM_LEVELS = ['rejection_observed', 'request_accepted', 'not_confirmed'] as const;
/** A blob ref whose media type is a bare type/subtype (no parameters, no free text). */
const AuthBlobRefSchema = z.strictObject({
  sha256: SHA256,
  size: COUNT,
  media_type: z
    .string()
    .regex(/^[a-z0-9][a-z0-9!#$&^_.+-]{0,62}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,62}$/, 'a bare media type (type/subtype, lowercase, no parameters)')
    .refine(notJwt, 'a token-shaped value (JWT) is not recorded')
    .optional(),
  redacted: z.literal(true).optional(),
});
const AuthCommon = {
  ...Common,
  /** Built from the profile, kind and generation by the recorder, never from a credential (state, jti …). */
  event_key: AUTH_ID,
  commitment_key: SHA256.describe('sha256 of the audit commitment key (the key itself is never recorded)'),
  journal: AuthBlobRefSchema.optional().describe('the redacted auth journal (mcp-audit/auth-journal@1) of this step'),
  evidence: EVIDENCE.optional(),
};

/** A JWT access token's structure, never its value: header, kept claims, committed subject and id, other claim names. */
const AccessTokenJwtSchema = z.strictObject({
  claims_verified: z.boolean().describe('false unless the signature was checked against the issuer keys'),
  header: z.strictObject({
    alg: z.string().regex(/^[A-Za-z0-9+_-]{1,32}$/, 'a JOSE algorithm name').optional(),
    kid: PUBLIC_ID.optional(),
    typ: z.string().regex(/^[A-Za-z0-9+./_-]{1,64}$/, 'a media type').refine(notJwt, 'a token-shaped value (JWT) is not recorded').optional(),
  }),
  claims: z.strictObject({
    iss: PUBLIC_ID.optional(),
    aud: z.array(PUBLIC_ID).min(1).max(16).optional().describe('a single audience is recorded as a one-element list'),
    exp: EPOCH_S.optional(),
    iat: EPOCH_S.optional(),
    nbf: EPOCH_S.optional(),
    scope: SCOPE.optional(),
    scp: z.array(z.string().min(1).max(256).regex(/^[!#-[\]-~]+$/, 'a scope token').refine(notJwt, 'a token-shaped value (JWT) is not recorded')).max(64).optional(),
    client_id: PUBLIC_ID.optional(),
    azp: PUBLIC_ID.optional(),
    sub: commitment('subject').optional(),
    jti: commitment('jti').optional(),
  }),
  other_claims: z
    .array(z.string().regex(/^[A-Za-z_][A-Za-z0-9_.:/-]{0,127}$/, 'a claim name (a namespaced name may be a URL)').refine(notJwt, 'a token-shaped value (JWT) is not recorded'))
    .max(64)
    .optional()
    .describe('the names of the claims not kept (their values are not recorded)'),
});

export const PAYLOAD_SCHEMAS = {
  catalog_snapshot: z.strictObject({
    ...Common,
    fingerprint: SHA256.describe('catalog fingerprint (mcp-catalog-snap/1)'),
    server: z.strictObject({ name: SHORT, version: z.string().min(1).max(64).optional() }),
    tool_count: COUNT,
    bytes: COUNT,
    tokens: TOKENS.optional(),
    snapshot: BlobRefSchema,
  }),
  call_measured: z.strictObject({
    ...Common,
    fingerprint: SHA256,
    tool: SHORT,
    status: z.string().min(1).max(32),
    is_error: z.boolean(),
    latency_ms: z.number().nonnegative(),
    bytes_in: COUNT.optional(),
    bytes_out: COUNT,
    tokens: TOKENS.optional(),
    request: BlobRefSchema.optional(),
    response: BlobRefSchema.optional(),
  }),
  finding: z.strictObject({
    ...Common,
    finding_id: ID,
    status: z.enum(FINDING_STATUSES),
    title: SHORT.optional(),
    severity: z.enum(['S1', 'S2', 'S3', 'S4', 'info']).optional(),
    class: z.string().min(1).max(64).optional(),
    fingerprint: SHA256.optional(),
    detail: BlobRefSchema.optional(),
    evidence: EVIDENCE.optional(),
  }),
  gate_result: z.strictObject({
    ...Common,
    finding_id: ID,
    gate: z.string().min(1).max(64),
    verdict: z.enum(['upheld', 'refuted', 'inconclusive']),
    report: BlobRefSchema.optional(),
    evidence: EVIDENCE.optional(),
  }),
  fix_applied: z.strictObject({
    ...Common,
    finding_id: ID,
    ref: z.string().min(1).max(500).describe('PR URL, commit or proxy rule id'),
    fingerprint_before: SHA256.optional(),
    fingerprint_after: SHA256.optional(),
    diff: BlobRefSchema.optional(),
    evidence: EVIDENCE.optional(),
  }),
  harness_frozen: z.strictObject({
    ...Common,
    harness_id: ID.describe('name of the frozen harness / protocol version'),
    fingerprint: SHA256.describe('sha256 of the harness manifest (e.g. HARNESS_SHA256.txt)'),
    manifest: BlobRefSchema.describe('the frozen harness (a tar or its manifest)'),
    hypotheses: BlobRefSchema.optional().describe('pre-registered hypotheses / expected outcomes'),
    planned_runs: COUNT.optional().describe('number of runs declared at freeze time (completeness signal)'),
    plan: z
      .array(ID)
      .min(1)
      .max(MAX_PLANNED_RUNS)
      .refine((p) => new Set(p).size === p.length, 'plan lists a run_id twice')
      .optional()
      .describe('0.11.0: the run IDs planned at freeze time; required in a /3 bundle. Every run_completed / run_abandoned names one of them, each exactly once'),
    plan_detail: BlobRefSchema.optional().describe('0.11.0: the plan in full (per run: command, pass criterion, write cap)'),
    title: SHORT.optional(),
  }),
  run_completed: z.strictObject({
    ...Common,
    run_id: ID,
    run_seq: z.number().int().positive().describe('1-based run sequence number: the runs of an audit are numbered 1..N with no gaps'),
    fingerprint: SHA256.describe('harness fingerprint the run executed under'),
    status: z.string().min(1).max(32),
    capture: z.enum(['complete', 'interrupted']).optional().describe('whether evidence capture ran uninterrupted (default complete)'),
    interruption: SHORT.optional().describe('what interrupted capture, when capture is interrupted'),
    nonce: SHA256.optional().describe('freeze nonce, known only after the freeze: /3 sha256(freeze receipt digest ‖ its TSA tokens) (freezeNonce), required; /2 the freeze receipt digest'),
    result: BlobRefSchema.optional(),
    evidence: EVIDENCE.optional(),
  }),
  report_issued: z.strictObject({
    ...Common,
    report_id: ID,
    report: BlobRefSchema,
    run_count: COUNT.optional().describe('number of runs the report covers: the run_completed events (completeness signal); required in a /3 bundle'),
    title: SHORT.optional(),
    evidence: EVIDENCE.optional(),
  }),
  run_abandoned: z.strictObject({
    ...Common,
    run_id: ID.describe('the planned run that will not complete'),
    reason: SHORT.describe('why the run was abandoned (harness refusal, auth failure, budget stop …)'),
    fingerprint: SHA256.optional().describe('harness fingerprint, when the run started'),
    detail: BlobRefSchema.optional(),
    evidence: EVIDENCE.optional(),
  }),
  reproduction_signed: z.strictObject({
    ...Common,
    finding_id: ID,
    signer: PRINCIPAL.describe('the reproducer, as named in the allowed-signers file'),
    reproduced_at: z.iso.datetime().describe('when the human reproduced the finding'),
    commands: BlobRefSchema.describe('the commands run'),
    output: BlobRefSchema.describe('what they printed'),
    signature: BlobRefSchema.describe('armored SSH signature (ssh-keygen -Y sign -n kronicle-lite-reproduction) over reproductionStatement(...)'),
    evidence: EVIDENCE.optional(),
  }),
  audit_closed: z.strictObject({
    ...Common,
    report_id: ID.describe('the report_issued this closes'),
    run_count: COUNT.describe('run_completed events in the audit'),
    findings_digest: SHA256.describe('findingsDigest: sha256 of the canonical [{finding_id, status}] the audit ends with'),
  }),
  regression_result: z.strictObject({
    ...Common,
    finding_id: ID.optional(),
    fingerprint_before: SHA256,
    fingerprint_after: SHA256,
    verdict: z.enum(['improved', 'regressed', 'unchanged']),
    deltas: z.record(z.string().min(1).max(64), z.number()).refine((r) => Object.keys(r).length <= 64, 'at most 64 deltas'),
    report: BlobRefSchema.optional(),
    evidence: EVIDENCE.optional(),
  }),
  auth_registered: z.strictObject({
    ...AuthCommon,
    registration_id: AUTH_ID.describe('the registration, as the auth events that use it name it'),
    issuer: AUTH_URL,
    mode: z.enum(REGISTRATION_MODES),
    client_id: PUBLIC_ID,
    token_endpoint_auth_method: z.enum(['none', 'client_secret_basic', 'client_secret_post', 'private_key_jwt']),
    redirect_uris: z.array(AUTH_URL).min(1).max(8),
    client_id_issued_at: EPOCH_S.optional(),
    client_secret_expires_at: EPOCH_S.optional(),
    client_secret: commitment('client-secret').optional(),
    registration_access_token: commitment('registration-access-token').optional(),
    client_metadata_sha256: SHA256.optional().describe('sha256 of the client metadata document (CIMD) or registration request (DCR)'),
  }),
  auth_granted: z.strictObject({
    ...AuthCommon,
    profile: AUTH_ID,
    identity: AUTH_ID.optional(),
    tenant: AUTH_ID.optional(),
    registration_id: AUTH_ID.optional(),
    registration_mode: z.enum(REGISTRATION_MODES),
    resource: AUTH_URL.describe('the protected resource (RFC 8707)'),
    issuer: AUTH_URL,
    client_id: PUBLIC_ID,
    requested_scope: SCOPE.optional(),
    granted_scope: SCOPE.optional(),
    token_type: z.string().regex(/^[A-Za-z][A-Za-z_-]{0,15}$/, 'a token type (Bearer, DPoP, N_A)'),
    expires_in: COUNT.nullable().optional().describe('seconds; null when the server gave no lifetime'),
    expires_at: z.iso.datetime().optional(),
    refreshable: z.boolean(),
    generation: z.number().int().positive().optional(),
    access_token: commitment('access-token'),
    access_token_jwt: AccessTokenJwtSchema.optional(),
    refresh_token: commitment('refresh-token').optional(),
    id_token: commitment('id-token').optional(),
    login_hint: commitment('login-hint').optional(),
    prm_sha256: SHA256.optional().describe('sha256 of the protected resource metadata document'),
    as_metadata_sha256: SHA256.optional().describe('sha256 of the authorization server metadata document'),
    whoami: z.enum(['passed', 'not_configured']).describe("the identity's whoami control before the tokens were kept"),
    attachment: AuthBlobRefSchema.optional().describe('operator evidence of consent (a screenshot), scanned like any blob'),
  }),
  auth_refreshed: z.strictObject({
    ...AuthCommon,
    profile: AUTH_ID,
    issuer: AUTH_URL.optional(),
    generation: z.number().int().positive(),
    trigger: z.enum(['proactive', 'forced', 'operator', 'rehearse', 'recover']).optional(),
    rotated: z.boolean().describe('the server issued a new refresh token'),
    access_token: commitment('access-token'),
    previous_access_token: commitment('access-token').optional(),
    refresh_token: commitment('refresh-token').optional(),
    previous_refresh_token: commitment('refresh-token').optional(),
    scope: SCOPE.optional(),
    expires_in: COUNT.nullable().optional().describe('seconds; null when the server gave no lifetime'),
    expires_at: z.iso.datetime().optional(),
  }),
  auth_failed: z.strictObject({
    ...AuthCommon,
    profile: AUTH_ID,
    issuer: AUTH_URL.optional(),
    stage: AUTH_CODE.describe('discovery, registration, authorize, callback, token, refresh, revoke, store, verify …'),
    error: AUTH_CODE.describe("the OAuth error code or the toolkit's own code; never the server's description"),
    status: HTTP_STATUS.optional(),
    generation: COUNT.optional(),
  }),
  auth_revoked: z.strictObject({
    ...AuthCommon,
    profile: AUTH_ID,
    issuer: AUTH_URL,
    access_token: commitment('access-token').optional(),
    refresh_token: commitment('refresh-token').optional(),
    refresh: z.strictObject({
      sent: z.boolean(),
      status: HTTP_STATUS.nullable(),
      replay: z.string().regex(/^(?:[a-z][a-z_]{0,63}|http_[1-5][0-9]{2})$/, 'invalid_grant, accepted, skipped, another OAuth error code or http_<status>'),
      revocation_ineffective: z.boolean().optional(),
      claim: z.enum(CLAIM_LEVELS),
    }),
    access: z.strictObject({
      probes: z.array(z.strictObject({ after_ms: COUNT, elapsed_ms: COUNT, status: HTTP_STATUS })).max(100),
      first_rejected_ms: COUNT.nullable(),
      still_valid_at_cap: z.boolean(),
      remaining_lifetime_s: z.number().int().nullable(),
      revoked_explicitly: z.boolean(),
      inconclusive: COUNT,
      claim: z.enum(CLAIM_LEVELS),
    }),
    registration: z.strictObject({ registration_id: AUTH_ID.optional(), deleted: z.boolean(), status: HTTP_STATUS.nullable() }).optional(),
    receipt: AuthBlobRefSchema.optional().describe('the full revocation receipt (JSON)'),
  }),
} as const satisfies Record<AuditKind, z.ZodType>;

export type AuditPayload<K extends AuditKind = AuditKind> = z.infer<(typeof PAYLOAD_SCHEMAS)[K]>;

/** Fields optional in the payload schemas that a /3 or /4 bundle requires (the store still records 0.10.0 events). */
export const V3_REQUIRED: Partial<Record<AuditKind, readonly string[]>> = {
  harness_frozen: ['plan'],
  run_completed: ['nonce'],
  report_issued: ['run_count'],
};

/** parseAuditPayload, plus the fields the bundle format requires. */
export function parseAuditPayloadIn(format: BundleFormat, kind: AuditKind, payload: unknown): { ok: true; value: AuditPayload } | { ok: false; problem: string } {
  const p = parseAuditPayload(kind, payload);
  if (!p.ok || !isProfileFormat(format)) return p;
  const missing = (V3_REQUIRED[kind] ?? []).filter((f) => (p.value as Record<string, unknown>)[f] === undefined);
  return missing.length ? { ok: false, problem: `${missing.join(', ')}: required in a ${format} bundle` } : p;
}

/** One event to record. `event_key` names the LOGICAL event within the audit: a retry with the same key is the same event. */
export const AuditEventInputSchema = z.strictObject({
  kind: z.enum(AUDIT_KINDS),
  event_key: ID.describe('stable id of this logical event within the audit; a retry with the same key is a no-op'),
  payload: z.record(z.string(), z.unknown()),
});
export type AuditEventInput = z.infer<typeof AuditEventInputSchema>;

/** Validate a payload for `kind`; returns the parsed payload or the first problem. */
export function parseAuditPayload(kind: AuditKind, payload: unknown): { ok: true; value: AuditPayload } | { ok: false; problem: string } {
  const r = PAYLOAD_SCHEMAS[kind].safeParse(payload);
  if (r.success) return { ok: true, value: r.data as AuditPayload };
  const i = r.error.issues[0]!;
  return { ok: false, problem: `${i.path.length > 0 ? i.path.join('.') : '(payload)'}: ${i.message}` };
}

/** Every blob ref in a payload, with the field it sits in. */
export function blobRefsOf(payload: Record<string, unknown>): { field: string; ref: BlobRef }[] {
  const out: { field: string; ref: BlobRef }[] = [];
  for (const field of ['snapshot', 'request', 'response', 'detail', 'report', 'diff', 'manifest', 'hypotheses', 'result', 'plan_detail', 'commands', 'output', 'signature', 'journal', 'attachment', 'receipt'] as const) {
    const r = BlobRefSchema.safeParse(payload[field]);
    if (r.success) out.push({ field, ref: r.data });
  }
  return out;
}

/** Every catalog fingerprint a payload names (queryable index). */
export function fingerprintsOf(payload: Record<string, unknown>): string[] {
  const out = new Set<string>();
  for (const k of ['fingerprint', 'fingerprint_before', 'fingerprint_after']) {
    const v = payload[k];
    if (typeof v === 'string') out.add(v);
  }
  return [...out].sort();
}

/** Evidence event ids a payload references. */
export function evidenceOf(payload: Record<string, unknown>): string[] {
  const v = payload['evidence'];
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

/**
 * The status a finding moves to on this event, or null when the event does
 * not move it. A `gate_result` with verdict `refuted` refutes; acceptance and
 * reopening are explicit `finding` events (a human or reviewer decision).
 */
export function statusEffect(kind: AuditKind, payload: Record<string, unknown>): FindingStatus | null {
  if (kind === 'finding') return payload['status'] as FindingStatus;
  if (kind === 'gate_result' && payload['verdict'] === 'refuted') return 'refuted';
  return null;
}

/**
 * Allowed finding transitions (from → to); docs/AUDIT.md has the table.
 * The first event must be `discovered`.
 */
export function transitionAllowed(from: FindingStatus | null, to: FindingStatus): boolean {
  if (from === null) return to === 'discovered';
  switch (to) {
    case 'discovered':
      return false;
    case 'refuted':
      // Several refuters may refute the same finding: refuted → refuted is a no-op transition.
      return from === 'discovered' || from === 'reopened' || from === 'refuted';
    case 'accepted':
      return from === 'discovered' || from === 'reopened';
    case 'reopened':
      return from === 'refuted' || from === 'accepted';
  }
}

/**
 * Stable identity of a logical audit event: the same (audit_id, event_key)
 * always yields the same chain idempotency key and the same event_id (a
 * UUID-shaped slice of sha256), in any store. Not a content hash: a retry
 * with a different payload is a conflict, not a new event.
 */
export function auditIdentity(audit_id: string, event_key: string): { idempotency_key: string; event_id: string } {
  const h = createHash('sha256').update(`kronicle-lite/audit-event/1\n${audit_id}\n${event_key}`, 'utf8').digest('hex');
  // RFC 4122 layout with version 8 (custom) and the variant bits set, so z.uuid() accepts it.
  const v = `8${h.slice(13, 16)}`;
  const variant = ((parseInt(h.slice(16, 17), 16) & 0x3) | 0x8).toString(16) + h.slice(17, 20);
  return { idempotency_key: `audit:${h}`, event_id: `${h.slice(0, 8)}-${h.slice(8, 12)}-${v}-${variant}-${h.slice(20, 32)}` };
}
