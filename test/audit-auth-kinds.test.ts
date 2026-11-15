/**
 * OAuth evidence kinds (0.12.0): mcp-audit records the login, refresh, failure and revocation of each audit
 * identity, and the client registration they use, on the audit chain. 0.11.2 refused any such kind (the
 * toolkit's OAuth phase 0, spike B). These tests define done:
 *
 * - the five kinds record with strict payloads that hold no credential: tokens, codes, verifiers and secrets
 *   only as keyed commitments; URLs without query, fragment or userinfo; codes without digits; public
 *   identifiers that refuse a token-shaped value; the write-time secret guard on top;
 * - a bundle with an OAuth kind is format /4, which carries every /3 rule; a bundle without one is written
 *   exactly as 0.11.x wrote it (format choice unchanged for every set of the older kinds);
 * - a /4 bundle relabelled /3 by the key holder fails, as any kind in a format that does not allow it.
 */

import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { exportBundle, signManifest, type BundleManifest } from '../src/audit/bundle.js';
import {
  AUDIT_KINDS,
  AUDIT_KINDS_V1,
  AUTH_COMMITMENT_LABELS,
  AUTH_KINDS,
  blobRefsOf,
  BUNDLE_FORMAT_V1,
  BUNDLE_FORMAT_V2,
  BUNDLE_FORMAT_V3,
  BUNDLE_FORMAT_V4,
  BUNDLE_FORMATS,
  formatForKinds,
  isProfileFormat,
  kindsOfFormat,
  MILESTONE_KINDS,
  parseAuditPayload,
  parseAuditPayloadIn,
  PAYLOAD_SCHEMAS,
  V3_KINDS,
  type AuditKind,
} from '../src/audit/schemas.js';
import { verifyBundle } from '../src/audit/verify-bundle.js';
import { checkpointSigningPayload } from '../src/chain/chain.js';
import { merkleRootHex } from '../src/chain/merkle.js';
import { canonicalize } from '../src/crypto/canonical.js';
import { sha256Hex } from '../src/crypto/hash.js';
import { audit, KronicleLite } from '../src/index.js';
import { SecretDetectedError } from '../src/secrets/guard.js';
import { tempDir } from './helpers/fs.js';

const SHA = 'ab'.repeat(32);
const KEY = 'cd'.repeat(32);
const ISS = 'https://as.example.test';
const MCP = 'https://mcp.example.test/mcp';
/** A JWT-shaped string (header {"alg":"none"}, a claims part, a signature part): never recordable. */
const JWT = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyLTEyMyIsImF1ZCI6Im1jcCJ9.c2lnbmF0dXJlLXBhcnQtMTIzNDU2';
/** A short unsigned JWT (40 characters): fits most length limits. */
const SHORT_JWT = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1In0.c2ln';
/** An opaque refresh token as an authorization server issues one. */
const OPAQUE = 'rt_Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWo';
const c = (label: string, commit = '0123456789abcdef', len = 43) => ({ commit, len, label });

/** A valid payload of each OAuth kind, with most optional fields present (blob refs are added per test). */
const VALID: Record<(typeof AUTH_KINDS)[number], Record<string, unknown>> = {
  auth_registered: {
    commitment_key: KEY,
    registration_id: 'reg-1',
    issuer: ISS,
    mode: 'dcr',
    client_id: 'c-7f3a9e',
    token_endpoint_auth_method: 'none',
    redirect_uris: ['http://127.0.0.1:33418/callback', 'http://127.0.0.1/callback'],
    client_id_issued_at: 1794700000,
    client_secret_expires_at: 0,
    registration_access_token: c('registration-access-token'),
    client_metadata_sha256: SHA,
  },
  auth_granted: {
    commitment_key: KEY,
    profile: 'owner-a',
    identity: 'owner-a',
    tenant: 'tenant-a',
    registration_id: 'reg-1',
    registration_mode: 'dcr',
    resource: MCP,
    issuer: ISS,
    client_id: 'c-7f3a9e',
    requested_scope: 'read write',
    granted_scope: 'read',
    token_type: 'Bearer',
    expires_in: 3600,
    expires_at: '2026-11-14T22:00:00Z',
    refreshable: true,
    generation: 1,
    access_token: c('access-token'),
    access_token_jwt: {
      claims_verified: false,
      header: { alg: 'EdDSA', kid: 'key-1', typ: 'at+jwt' },
      claims: { iss: ISS, aud: [MCP], exp: 1794703600, iat: 1794700000, nbf: 1794700000, scope: 'read', scp: ['read'], client_id: 'c-7f3a9e', azp: 'c-7f3a9e', sub: c('subject', 'fedcba9876543210', 12), jti: c('jti') },
      other_claims: ['tenant_id', 'auth_time'],
    },
    refresh_token: c('refresh-token'),
    id_token: c('id-token'),
    login_hint: c('login-hint', 'aaaaaaaaaaaaaaaa', 19),
    prm_sha256: SHA,
    as_metadata_sha256: SHA,
    whoami: 'passed',
  },
  auth_refreshed: {
    commitment_key: KEY,
    profile: 'owner-a',
    issuer: ISS,
    generation: 2,
    trigger: 'proactive',
    rotated: true,
    access_token: c('access-token', '1111111111111111'),
    previous_access_token: c('access-token'),
    refresh_token: c('refresh-token', '2222222222222222'),
    previous_refresh_token: c('refresh-token'),
    scope: 'read',
    expires_in: 3600,
    expires_at: '2026-11-14T23:00:00Z',
  },
  auth_failed: { commitment_key: KEY, profile: 'owner-a', issuer: ISS, stage: 'refresh', error: 'invalid_grant', status: 400, generation: 2 },
  auth_revoked: {
    commitment_key: KEY,
    profile: 'owner-a',
    issuer: ISS,
    access_token: c('access-token', '1111111111111111'),
    refresh_token: c('refresh-token', '2222222222222222'),
    refresh: { sent: true, status: 200, replay: 'invalid_grant', revocation_ineffective: false, claim: 'rejection_observed' },
    access: {
      probes: [
        { after_ms: 0, elapsed_ms: 3, status: 200 },
        { after_ms: 5000, elapsed_ms: 5004, status: 401 },
      ],
      first_rejected_ms: 5000,
      still_valid_at_cap: false,
      remaining_lifetime_s: 3400,
      revoked_explicitly: false,
      inconclusive: 0,
      claim: 'rejection_observed',
    },
    registration: { registration_id: 'reg-1', deleted: true, status: 204 },
  },
};
const COMMON = { audit_id: 'oauth-audit', event_key: 'k1' };
const parse = (kind: AuditKind, p: Record<string, unknown>) => parseAuditPayload(kind, { ...COMMON, ...p });
const refused = (kind: AuditKind, p: Record<string, unknown>) => expect(parse(kind, p).ok, JSON.stringify(p).slice(0, 300)).toBe(false);
const accepted = (kind: AuditKind, p: Record<string, unknown>) => expect(parse(kind, p), JSON.stringify(p).slice(0, 300)).toMatchObject({ ok: true });

/** Every path to a leaf of a JSON value. */
function leaves(v: unknown, path: (string | number)[] = []): (string | number)[][] {
  if (Array.isArray(v)) return v.flatMap((x, i) => leaves(x, [...path, i]));
  if (v && typeof v === 'object') return Object.entries(v).flatMap(([k, x]) => leaves(x, [...path, k]));
  return [path];
}
function setAt(o: Record<string, unknown>, path: (string | number)[], value: unknown): Record<string, unknown> {
  const copy = structuredClone(o);
  let cur: Record<string | number, unknown> = copy;
  for (const k of path.slice(0, -1)) cur = cur[k] as Record<string | number, unknown>;
  cur[path[path.length - 1]!] = value;
  return copy;
}
/** Every object inside a payload (the payload itself included), as a path. */
function objects(v: unknown, path: (string | number)[] = []): (string | number)[][] {
  if (Array.isArray(v)) return v.flatMap((x, i) => objects(x, [...path, i]));
  if (v && typeof v === 'object') return [path, ...Object.entries(v).flatMap(([k, x]) => objects(x, [...path, k]))];
  return [];
}
const getAt = (o: unknown, path: (string | number)[]) => path.reduce<unknown>((cur, k) => (cur as Record<string | number, unknown>)[k], o);

describe('the OAuth kinds are audit kinds (spike B: 0.11.2 refused them)', () => {
  it('five kinds, each with a strict payload schema, exported on the audit API', () => {
    expect([...AUTH_KINDS]).toEqual(['auth_registered', 'auth_granted', 'auth_refreshed', 'auth_failed', 'auth_revoked']);
    for (const k of AUTH_KINDS) {
      expect(AUDIT_KINDS).toContain(k);
      expect(PAYLOAD_SCHEMAS[k]).toBeDefined();
    }
    expect(audit.AUTH_KINDS).toEqual(AUTH_KINDS);
    expect(audit.BUNDLE_FORMAT_V4).toBe('kronicle-lite-evidence-bundle/4');
    expect([...AUTH_COMMITMENT_LABELS].sort()).toEqual(['access-token', 'authorization-code', 'client-secret', 'code-challenge', 'id-token', 'jti', 'login-hint', 'pkce-verifier', 'refresh-token', 'registration-access-token', 'state', 'subject']);
  });

  it('each valid payload parses, and a store records all five with their blob refs', () => {
    for (const k of AUTH_KINDS) accepted(k, VALID[k]);
    const kl = new KronicleLite({ memory: true });
    const journal = kl.audit.putBlob(Buffer.from('{"format":"mcp-audit/auth-journal@1","seq":1}\n'), 'application/x-ndjson');
    const shot = kl.audit.putBlob(Buffer.from('consent screenshot bytes'), 'image/png');
    const receipt = kl.audit.putBlob(Buffer.from('{"profile":"owner-a"}'), 'application/json');
    const r = kl.audit.record(
      'oauth-audit',
      AUTH_KINDS.map((kind) => ({ kind, event_key: kind, payload: { ...VALID[kind], journal, ...(kind === 'auth_granted' ? { attachment: shot } : {}), ...(kind === 'auth_revoked' ? { receipt } : {}) } })),
      'auditor',
    );
    expect(r.map((x) => x.kind)).toEqual([...AUTH_KINDS]);
    expect(kl.audit.query({ audit_id: 'oauth-audit' }).map((e) => e.kind)).toEqual([...AUTH_KINDS]);
    kl.close();
  });

  it('their blob fields are blob refs: an unknown journal, attachment or receipt is refused', () => {
    const ref = { sha256: SHA, size: 3 };
    expect(blobRefsOf({ journal: ref, attachment: ref, receipt: ref }).map((x) => x.field)).toEqual(['journal', 'attachment', 'receipt']);
    const kl = new KronicleLite({ memory: true });
    for (const [kind, field] of [['auth_granted', 'journal'], ['auth_granted', 'attachment'], ['auth_revoked', 'receipt']] as const) {
      expect(() => kl.audit.record('oauth-audit', [{ kind, event_key: `${kind}-${field}`, payload: { ...VALID[kind], [field]: ref } }], 'auditor')).toThrow(/not in the blob store/);
    }
    kl.close();
  });
});

describe('no credential can be recorded in an OAuth event', () => {
  const RAW_NAMES = ['token', 'code', 'code_verifier', 'state', 'client_secret', 'client_assertion', 'password', 'assertion', 'device_code', 'authorization', 'cookie', 'value', 'raw', 'access_token_value', 'bearer'];

  it('a raw credential under any extra name, at any level of any OAuth payload, is refused', () => {
    for (const kind of AUTH_KINDS) {
      for (const path of objects(VALID[kind])) {
        if (Array.isArray(getAt(VALID[kind], path))) continue;
        for (const name of RAW_NAMES) for (const raw of [OPAQUE, JWT]) refused(kind, setAt(VALID[kind], [...path, name], raw));
      }
    }
  });

  it('every credential field holds only a commitment with its own label, 16 lowercase hex digits and a length', () => {
    for (const kind of AUTH_KINDS) {
      const commits = objects(VALID[kind]).filter((p) => {
        const o = getAt(VALID[kind], p) as Record<string, unknown>;
        return o && typeof o === 'object' && 'commit' in o;
      });
      expect(commits.length > 0, kind).toBe(kind !== 'auth_failed'); // a failure carries no credential
      for (const p of commits) {
        const o = getAt(VALID[kind], p) as { commit: string; len: number; label: string };
        refused(kind, setAt(VALID[kind], p, OPAQUE)); // the value in place of the commitment
        refused(kind, setAt(VALID[kind], p, JWT));
        refused(kind, setAt(VALID[kind], p, { ...o, value: OPAQUE }));
        refused(kind, setAt(VALID[kind], p, { ...o, commit: sha256Hex(OPAQUE) })); // a full digest is not the commitment format
        refused(kind, setAt(VALID[kind], p, { ...o, commit: o.commit.toUpperCase().replace(/[0-9]/g, 'A') }));
        refused(kind, setAt(VALID[kind], p, { ...o, commit: OPAQUE.slice(0, 16) }));
        refused(kind, setAt(VALID[kind], p, { commit: o.commit, len: o.len }));
        for (const other of AUTH_COMMITMENT_LABELS.filter((l) => l !== o.label)) refused(kind, setAt(VALID[kind], p, { ...o, label: other }));
      }
    }
  });

  it('URLs are https (http only to loopback) with no userinfo, query or fragment', () => {
    const urlFields: [AuditKind, (string | number)[]][] = [
      ['auth_registered', ['issuer']],
      ['auth_registered', ['redirect_uris', 0]],
      ['auth_granted', ['issuer']],
      ['auth_granted', ['resource']],
      ['auth_refreshed', ['issuer']],
      ['auth_failed', ['issuer']],
      ['auth_revoked', ['issuer']],
    ];
    const bad = [
      `${ISS}/authorize?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz`,
      `${ISS}/cb#access_token=${OPAQUE}`,
      `https://user:${OPAQUE}@as.example.test`,
      `https://${OPAQUE}@as.example.test/`,
      'http://as.example.test',
      'http://localhost.evil.test/cb',
      'http://127.0.0.1.evil.test/cb',
      'javascript:alert(1)',
      'ftp://as.example.test',
      `${ISS}/a b`,
      `${ISS}/${'a'.repeat(600)}`,
      `${ISS}/cb%3Fcode%3DSplxlOBeZQQYbYS6WxSbIA%26state%3Daf0ifjsldkj`,
      `${MCP}/${SHORT_JWT}`,
      `${MCP}/${JWT}`,
      '',
    ];
    const good = [ISS, `${ISS}/`, 'https://login.example.test/0b4f7f2c-0000-4000-8000-000000000000/v2.0', 'https://as.example.test:8443/oauth2/default', 'http://127.0.0.1:33418/callback', 'http://localhost/callback', 'http://[::1]:8080/'];
    for (const [kind, path] of urlFields) {
      for (const u of bad) refused(kind, setAt(VALID[kind as (typeof AUTH_KINDS)[number]], path, u));
      for (const u of good) accepted(kind, setAt(VALID[kind as (typeof AUTH_KINDS)[number]], path, u));
    }
  });

  it('a token-shaped value is refused in every public identifier (client id, audience, claims, key id, scope)', () => {
    const fields: [(typeof AUTH_KINDS)[number], (string | number)[]][] = [
      ['auth_registered', ['client_id']],
      ['auth_granted', ['client_id']],
      ['auth_granted', ['requested_scope']],
      ['auth_granted', ['granted_scope']],
      ['auth_granted', ['access_token_jwt', 'header', 'kid']],
      ['auth_granted', ['access_token_jwt', 'claims', 'iss']],
      ['auth_granted', ['access_token_jwt', 'claims', 'aud', 0]],
      ['auth_granted', ['access_token_jwt', 'claims', 'scope']],
      ['auth_granted', ['access_token_jwt', 'claims', 'client_id']],
      ['auth_granted', ['access_token_jwt', 'claims', 'azp']],
      ['auth_refreshed', ['scope']],
    ];
    for (const [kind, path] of fields) {
      refused(kind, setAt(VALID[kind], path, JWT));
      refused(kind, setAt(VALID[kind], path, `prefix:${JWT}`));
      refused(kind, setAt(VALID[kind], path, 'eyJhbGciOiJSUzI1NiJ9.eyJ.x')); // a JWE or a cut JWT too
    }
    // an identifier that merely contains the letters is kept
    accepted('auth_registered', { ...VALID.auth_registered, client_id: 'monkeyJack.example' });
    accepted('auth_granted', setAt(VALID.auth_granted, ['access_token_jwt', 'claims', 'aud', 0], 'api://surveyJobs.v2'));
    // the decoded claims keep the structure of the token, never the subject or the token id in clear
    refused('auth_granted', setAt(VALID.auth_granted, ['access_token_jwt', 'claims', 'sub'], 'user-123'));
    refused('auth_granted', setAt(VALID.auth_granted, ['access_token_jwt', 'claims', 'jti'], 'jti-123'));
    refused('auth_granted', setAt(VALID.auth_granted, ['access_token_jwt', 'claims', 'email'], 'a@b.test'));
    refused('auth_granted', setAt(VALID.auth_granted, ['access_token_jwt', 'signature'], 'c2lnbmF0dXJl'));
    refused('auth_granted', setAt(VALID.auth_granted, ['access_token_jwt', 'other_claims', 0], 'email=a@b.test'));
  });

  it('stages, error codes and replay outcomes are codes: letters and underscores, no digits, no free text', () => {
    for (const v of ['refresh', 'refresh_uncertain', 'invalid_grant', 'server_error_other']) {
      accepted('auth_failed', { ...VALID.auth_failed, stage: v });
      accepted('auth_failed', { ...VALID.auth_failed, error: v });
    }
    for (const v of ['', 'Refresh', 'invalid grant', 'invalid_grant: the refresh token rt_123 is revoked', 'a1b2c3d4e5f6a7b8', OPAQUE, JWT, 'x'.repeat(65), 'http_401']) {
      refused('auth_failed', { ...VALID.auth_failed, stage: v });
      refused('auth_failed', { ...VALID.auth_failed, error: v });
    }
    refused('auth_failed', { ...VALID.auth_failed, error_description: 'the token was revoked' });
    refused('auth_failed', { ...VALID.auth_failed, reason: 'no answer' });
    for (const v of ['invalid_grant', 'accepted', 'skipped', 'http_401', 'http_500']) accepted('auth_revoked', setAt(VALID.auth_revoked, ['refresh', 'replay'], v));
    for (const v of ['http_4011', 'http_099', 'abc123', OPAQUE, '']) refused('auth_revoked', setAt(VALID.auth_revoked, ['refresh', 'replay'], v));
    for (const v of [600, -1, 1.5, '200']) refused('auth_failed', { ...VALID.auth_failed, status: v });
  });

  it('every string leaf of every valid payload (event key and blob media types too) is refused when it becomes a raw token (JWT)', () => {
    const ref = { sha256: SHA, size: 3, media_type: 'application/json' };
    for (const kind of AUTH_KINDS) {
      const base = { ...VALID[kind], journal: ref, ...(kind === 'auth_granted' ? { attachment: { ...ref, media_type: 'image/png' } } : {}), ...(kind === 'auth_revoked' ? { receipt: ref } : {}) };
      accepted(kind, base);
      for (const path of [...leaves(base), ['event_key']]) {
        if (path[0] !== 'event_key' && typeof getAt(base, path) !== 'string') continue;
        for (const jwt of [JWT, SHORT_JWT]) expect(parse(kind, setAt({ ...COMMON, ...base }, path, jwt)).ok, `${kind}.${path.join('.')} = ${jwt}`).toBe(false);
      }
    }
    // the older kinds keep their 0.11.x rules: a token-shaped event key still parses there (the guard scans it)
    expect(parseAuditPayload('finding', { ...COMMON, event_key: SHORT_JWT, finding_id: 'F1', status: 'discovered' }).ok).toBe(true);
  });

  it('a blob ref in an OAuth event names one of a few media types: no parameters, no free text', () => {
    const ref = { sha256: SHA, size: 3 };
    for (const mt of ['application/json', 'application/x-ndjson', 'image/png', 'text/plain']) accepted('auth_revoked', { ...VALID.auth_revoked, receipt: { ...ref, media_type: mt } });
    for (const mt of ['text/plain; code=SplxlOBeZQQYbYS6WxSbIA', OPAQUE, 'Text/Plain', 'text/plain ', 'application/json; charset=utf-8', `x/${SHORT_JWT}`, 'text/a94a8fe5ccb19ba61c4c0873d391e987982fbbd3', 'application/vnd.isokron.receipt+json', '']) {
      refused('auth_revoked', { ...VALID.auth_revoked, receipt: { ...ref, media_type: mt } });
      refused('auth_granted', { ...VALID.auth_granted, journal: { ...ref, media_type: mt } });
    }
    refused('auth_revoked', { ...VALID.auth_revoked, receipt: { ...ref, note: 'x' } });
    // through the store: the blob is stored, the event that names its free-text media type is not
    const kl = new KronicleLite({ memory: true });
    const b = kl.audit.putBlob(Buffer.from('x'), 'text/plain; code=SplxlOBeZQQYbYS6WxSbIA');
    expect(() => kl.audit.record('oauth-audit', [{ kind: 'auth_granted', event_key: 'g', payload: { ...VALID.auth_granted, journal: b } }], 'auditor')).toThrow(/journal\.media_type/);
    kl.close();
  });

  it('shapes real tokens and servers produce are accepted (namespaced claims, fractional times, no lifetime, N_A)', () => {
    accepted('auth_granted', setAt(VALID.auth_granted, ['access_token_jwt', 'other_claims'], ['https://example.com/roles', 'urn:zitadel:iam:org:id', 'auth_time']));
    accepted('auth_granted', setAt(VALID.auth_granted, ['access_token_jwt', 'claims', 'exp'], 1794703600.5));
    accepted('auth_granted', { ...VALID.auth_granted, expires_in: null });
    accepted('auth_refreshed', { ...VALID.auth_refreshed, expires_in: null });
    accepted('auth_granted', { ...VALID.auth_granted, token_type: 'N_A' });
    accepted('auth_granted', { ...VALID.auth_granted, token_type: 'DPoP' });
  });

  it('the write-time secret guard still scans every OAuth payload', () => {
    const kl = new KronicleLite({ memory: true });
    const aws = 'AKIA' + 'IOSFODNN7EXAMPLQ'; // fits an ID; only the guard can tell it is a key
    expect(parse('auth_granted', { ...VALID.auth_granted, identity: aws }).ok).toBe(true);
    expect(() => kl.audit.record('oauth-audit', [{ kind: 'auth_granted', event_key: 'g', payload: { ...VALID.auth_granted, identity: aws } }], 'auditor')).toThrow(SecretDetectedError);
    expect(kl.audit.query({ audit_id: 'oauth-audit' })).toHaveLength(0);
    kl.close();
  });

  it('other shapes the toolkit must not send are refused: unknown labels, wrong types, oversized lists', () => {
    refused('auth_granted', { ...VALID.auth_granted, whoami: 'failed' });
    refused('auth_granted', { ...VALID.auth_granted, registration_mode: 'implicit' });
    refused('auth_granted', { ...VALID.auth_granted, token_type: 'Bearer123' });
    refused('auth_granted', { ...VALID.auth_granted, requested_scope: 'read  write' });
    refused('auth_granted', { ...VALID.auth_granted, requested_scope: 'read "write"' });
    refused('auth_granted', { ...VALID.auth_granted, commitment_key: undefined });
    refused('auth_registered', { ...VALID.auth_registered, redirect_uris: [] });
    refused('auth_registered', { ...VALID.auth_registered, token_endpoint_auth_method: 'client_secret_jwt' });
    refused('auth_revoked', setAt(VALID.auth_revoked, ['access', 'probes'], Array.from({ length: 101 }, () => ({ after_ms: 0, elapsed_ms: 0, status: 200 }))));
    refused('auth_revoked', setAt(VALID.auth_revoked, ['access', 'claim'], 'acknowledged'));
    refused('auth_revoked', setAt(VALID.auth_revoked, ['access', 'probes', 0, 'body'], 'ok'));
    refused('auth_refreshed', { ...VALID.auth_refreshed, generation: 0 });
  });
});

/** kronicle-lite 0.11.2's format rule, kept here to show the older kinds are written exactly as before. */
function formatForKinds0112(kinds: Iterable<string>, planned = false): string {
  let f = planned ? BUNDLE_FORMAT_V3 : BUNDLE_FORMAT_V1;
  for (const k of kinds) {
    if ((V3_KINDS as readonly string[]).includes(k)) return BUNDLE_FORMAT_V3;
    if (f === BUNDLE_FORMAT_V1 && !(AUDIT_KINDS_V1 as readonly string[]).includes(k)) f = BUNDLE_FORMAT_V2;
  }
  return f;
}

describe('format /4: the OAuth kinds, with every /3 rule; older bundles unchanged', () => {
  it('every set of the 0.11.2 kinds gets the format 0.11.2 gave it; any OAuth kind makes /4', () => {
    const old = [...AUDIT_KINDS_V1, ...MILESTONE_KINDS, ...V3_KINDS];
    expect(old).toHaveLength(12);
    for (let mask = 0; mask < 1 << old.length; mask++) {
      const set = old.filter((_, i) => mask & (1 << i));
      for (const planned of [false, true]) {
        expect(formatForKinds(set, planned)).toBe(formatForKinds0112(set, planned));
        for (const a of AUTH_KINDS) if (mask % 97 === 0) expect(formatForKinds([...set, a], planned)).toBe(BUNDLE_FORMAT_V4);
      }
    }
    for (const a of AUTH_KINDS) {
      expect(formatForKinds([a])).toBe(BUNDLE_FORMAT_V4);
      expect(formatForKinds(['finding', a, 'audit_closed'])).toBe(BUNDLE_FORMAT_V4);
    }
  });

  it('only /4 may hold the OAuth kinds; /4 holds every kind; /3 and /4 are the audit-profile formats', () => {
    expect(BUNDLE_FORMATS).toEqual([BUNDLE_FORMAT_V1, BUNDLE_FORMAT_V2, BUNDLE_FORMAT_V3, BUNDLE_FORMAT_V4]);
    for (const f of [BUNDLE_FORMAT_V1, BUNDLE_FORMAT_V2, BUNDLE_FORMAT_V3] as const) for (const a of AUTH_KINDS) expect(kindsOfFormat(f)).not.toContain(a);
    expect([...kindsOfFormat(BUNDLE_FORMAT_V3)].sort()).toEqual([...AUDIT_KINDS_V1, ...MILESTONE_KINDS, ...V3_KINDS].sort());
    expect([...kindsOfFormat(BUNDLE_FORMAT_V4)].sort()).toEqual([...AUDIT_KINDS].sort());
    expect([BUNDLE_FORMAT_V1, BUNDLE_FORMAT_V2, BUNDLE_FORMAT_V3, BUNDLE_FORMAT_V4, 'kronicle-lite-evidence-bundle/5', null].map(isProfileFormat)).toEqual([false, false, true, true, false, false]);
  });

  it('a /4 bundle requires what /3 requires (plan, nonce, run count)', () => {
    const run = { ...COMMON, run_id: 'run-1', run_seq: 1, fingerprint: SHA, status: 'pass' };
    expect(parseAuditPayloadIn(BUNDLE_FORMAT_V4, 'run_completed', run)).toEqual({ ok: false, problem: `nonce: required in a ${BUNDLE_FORMAT_V4} bundle` });
    expect(parseAuditPayloadIn(BUNDLE_FORMAT_V3, 'run_completed', run)).toEqual({ ok: false, problem: `nonce: required in a ${BUNDLE_FORMAT_V3} bundle` });
    expect(parseAuditPayloadIn(BUNDLE_FORMAT_V4, 'run_completed', { ...run, nonce: SHA }).ok).toBe(true);
    expect(parseAuditPayloadIn(BUNDLE_FORMAT_V4, 'report_issued', { ...COMMON, report_id: 'R1', report: { sha256: SHA, size: 1 } })).toMatchObject({ ok: false });
  });
});

/** What a holder of the store key can do: recompute every digest, the root and both signatures over an edited bundle. */
function resign(dir: string, kl: KronicleLite, edit: (m: BundleManifest) => void): void {
  const signer = kl.identity.signer;
  const m = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8')) as BundleManifest & Record<string, unknown>;
  edit(m);
  const text = readFileSync(join(dir, 'events.jsonl'), 'utf8');
  const lines = text.trimEnd().split('\n').map((l) => JSON.parse(l) as Record<string, unknown>);
  m.events_sha256 = sha256Hex(text);
  const root = merkleRootHex(lines.map((l) => ({ seq: Number(l['seq']), this_hash: String(l['this_hash']) })));
  m.root = { root, leaf_count: lines.length, key_id: signer.key_id, public_key_pem: signer.public_key_pem, signature: signer.sign(checkpointSigningPayload({ from_seq: m.range.from_seq, to_seq: m.range.to_seq, leaf_count: lines.length, root })) };
  writeFileSync(join(dir, 'manifest.json'), canonicalize(signManifest(m, signer) as never) + '\n');
}

describe('evidence bundles with OAuth events', () => {
  function store(withAuth: boolean, freeze: 'planned' | 'none' = 'planned') {
    const kl = new KronicleLite({ memory: true });
    const journal = kl.audit.putBlob(Buffer.from('{"format":"mcp-audit/auth-journal@1","seq":1}\n'), 'application/x-ndjson');
    const receipt = kl.audit.putBlob(Buffer.from('{"profile":"owner-a","refresh":{"claim":"rejection_observed"}}'), 'application/json');
    const manifest = kl.audit.putBlob(Buffer.from('harness files'), 'text/plain');
    if (freeze === 'planned') kl.audit.record('oauth-audit', [{ kind: 'harness_frozen', event_key: 'freeze', payload: { harness_id: 'h1', fingerprint: SHA, manifest, plan: ['run-1'] } }], 'auditor');
    if (withAuth) {
      kl.audit.record('oauth-audit', [
        { kind: 'auth_registered', event_key: 'reg', payload: { ...VALID.auth_registered, journal } },
        { kind: 'auth_granted', event_key: 'grant', payload: { ...VALID.auth_granted, journal } },
        { kind: 'auth_revoked', event_key: 'revoke', payload: { ...VALID.auth_revoked, receipt } },
      ], 'auditor');
    }
    const dir = tempDir('kl-auth-bundle-');
    const r = exportBundle({ chain: kl.chain, audit: kl.audit, signer: kl.identity.signer, audit_id: 'oauth-audit', dir });
    return { kl, dir, r, journal, receipt, manifest };
  }

  it('a store with an OAuth event exports /4 with its journal and receipt blobs, and the bundle verifies', () => {
    const { kl, dir, r, journal, receipt, manifest } = store(true);
    expect(r.manifest.format).toBe(BUNDLE_FORMAT_V4);
    expect(readdirSync(join(dir, 'blobs')).sort()).toEqual([journal.sha256, receipt.sha256, manifest.sha256].sort());
    const v = verifyBundle(dir, { public_key_pem: kl.identity.signer.public_key_pem });
    expect(v.checks.filter((x) => !x.ok)).toEqual([]);
    expect(v.ok).toBe(true);
    kl.close();
  });

  it('an anchor over an OAuth event is an audit milestone anchor (audit mode), as over a /3 kind', () => {
    const kl = new KronicleLite({ memory: true });
    kl.audit.record('plain', [{ kind: 'finding', event_key: 'f', payload: { finding_id: 'F1', status: 'discovered' } }], 'auditor');
    kl.audit.record('oauth-audit', [{ kind: 'auth_granted', event_key: 'g', payload: VALID.auth_granted }], 'auditor');
    expect(kl.audit.profileAuditsIn(1, kl.chain.head().seq)).toEqual(['oauth-audit']);
    kl.close();
  });

  it('a store without one exports /3 exactly as before', () => {
    const { kl, r } = store(false);
    expect(r.manifest.format).toBe(BUNDLE_FORMAT_V3);
    kl.close();
  });

  it('the key holder relabelling a /4 bundle /3, /2 or /1 fails events: the OAuth kinds are not allowed there', () => {
    // OAuth events only, so the only rule that can catch any relabelling is the OAuth kind's
    for (const f of [BUNDLE_FORMAT_V3, BUNDLE_FORMAT_V2, BUNDLE_FORMAT_V1] as const) {
      const { kl, dir, r } = store(true, 'none');
      expect(r.manifest.format).toBe(BUNDLE_FORMAT_V4);
      resign(dir, kl, (m) => {
        m.format = f;
      });
      const v = verifyBundle(dir, { public_key_pem: kl.identity.signer.public_key_pem });
      expect(v.ok).toBe(false);
      expect(v.checks.find((x) => x.check === 'events')!.problem).toBe(`seq ${r.manifest.range.from_seq}: auth_registered is not allowed in a ${f} bundle`);
      kl.close();
    }
  });

  it('a format this reader does not know is refused on the manifest, never read by skipping events (how 0.11.x meets /4)', () => {
    const { kl, dir } = store(true);
    resign(dir, kl, (m) => {
      m.format = 'kronicle-lite-evidence-bundle/5' as never;
    });
    const v = verifyBundle(dir, { public_key_pem: kl.identity.signer.public_key_pem });
    expect(v.ok).toBe(false);
    expect(v.checks.find((x) => !x.ok)!.problem).toMatch(/unknown format "kronicle-lite-evidence-bundle\/5"/);
    kl.close();
  });
});
