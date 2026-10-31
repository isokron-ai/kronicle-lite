/**
 * Orient cursor — the opaque token an agent carries between calls so the
 * server can compute "what changed since you last looked".
 *
 * Full form:     sxt1.<base64url(canonical_json_body)>.<base64url(HMAC-SHA256)>
 * Compact form:  sxt1c.<chain_seq>.<first 8 chars of base64url(HMAC-SHA256(actor_id|chain_seq))>
 *
 * The body is `{actor_id, chain_seq, chain_hash, issued_at}`. The agent treats
 * the token as a meaningless cookie; the server validates the HMAC (timing
 * safe), parses the body and reconciles it against the live chain. The
 * secret is the local server secret in the data dir. A cursor that fails
 * verification is never fatal: the caller falls back to the flight recorder
 * (see cursor-recovery in orient.ts).
 *
 * The compact form exists because a ~300-char token is mis-keyed by agents
 * when retyped across turns; 48 bits of HMAC bound to the actor is ample for
 * a position hint whose worst-case failure is "recompute from recorder".
 */

import { createHmac, timingSafeEqual } from 'node:crypto';

import { z } from 'zod';

import { canonicalize } from '../crypto/canonical.js';

export const CURSOR_FORMAT_VERSION = 'sxt1' as const;
export const CURSOR_COMPACT_VERSION = 'sxt1c' as const;
const COMPACT_HMAC_CHARS = 8;

export const CursorBody = z
  .object({
    actor_id: z.string().min(1),
    chain_seq: z.number().int().nonnegative(),
    chain_hash: z.string().regex(/^[0-9a-f]{64}$/),
    issued_at: z.string().min(1),
  })
  .strict();
export type CursorBody = z.infer<typeof CursorBody>;

export class CursorTokenError extends Error {
  override readonly name = 'CursorTokenError';
  constructor(reason: string) {
    super(`cursor token: ${reason}`);
  }
}

function b64UrlEncode(buf: Buffer | string): string {
  const b = typeof buf === 'string' ? Buffer.from(buf, 'utf8') : buf;
  return b.toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function b64UrlDecode(text: string): Buffer {
  const padLen = (4 - (text.length % 4)) % 4;
  return Buffer.from((text + '='.repeat(padLen)).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function hmac(secret: string, message: string): Buffer {
  return createHmac('sha256', secret).update(message).digest();
}

export function serializeCursor(body: CursorBody, secret: string): string {
  if (secret.length === 0) throw new Error('serializeCursor: empty secret refused');
  const canonical = canonicalize(body);
  return `${CURSOR_FORMAT_VERSION}.${b64UrlEncode(canonical)}.${b64UrlEncode(hmac(secret, canonical))}`;
}

export function parseCursor(token: string, secret: string): CursorBody {
  if (secret.length === 0) throw new CursorTokenError('empty secret');
  const parts = token.split('.');
  if (parts.length !== 3) throw new CursorTokenError('expected three dot-separated parts');
  const [ver, bodyEnc, sigEnc] = parts;
  if (ver !== CURSOR_FORMAT_VERSION) throw new CursorTokenError(`unknown format version ${ver}`);
  if (!bodyEnc || !sigEnc) throw new CursorTokenError('missing body or signature segment');
  const canonical = b64UrlDecode(bodyEnc).toString('utf8');
  const expected = hmac(secret, canonical);
  const provided = b64UrlDecode(sigEnc);
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
    throw new CursorTokenError('signature verification failed');
  }
  let json: unknown;
  try {
    json = JSON.parse(canonical);
  } catch {
    throw new CursorTokenError('body is not valid JSON');
  }
  const parsed = CursorBody.safeParse(json);
  if (!parsed.success) {
    throw new CursorTokenError(
      `body fails schema: ${parsed.error.issues.map((i) => `${i.path.join('.') || '$'}: ${i.message}`).join('; ')}`,
    );
  }
  return parsed.data;
}

function compactShortSig(actorId: string, chainSeq: number, secret: string): string {
  return b64UrlEncode(hmac(secret, `${actorId}|${chainSeq}`)).slice(0, COMPACT_HMAC_CHARS);
}

export function isCompactCursor(token: string): boolean {
  return token.startsWith(`${CURSOR_COMPACT_VERSION}.`);
}

export function serializeCompactCursor(actorId: string, chainSeq: number, secret: string): string {
  if (secret.length === 0) throw new Error('serializeCompactCursor: empty secret refused');
  if (!Number.isInteger(chainSeq) || chainSeq < 0) {
    throw new Error('serializeCompactCursor: chain_seq must be a non-negative integer');
  }
  return `${CURSOR_COMPACT_VERSION}.${chainSeq}.${compactShortSig(actorId, chainSeq, secret)}`;
}

export function parseCompactCursor(token: string, actorId: string, secret: string): { chain_seq: number } {
  if (secret.length === 0) throw new CursorTokenError('empty secret');
  const parts = token.split('.');
  if (parts.length !== 3) throw new CursorTokenError('expected three dot-separated parts');
  const [ver, seqStr, sigShort] = parts;
  if (ver !== CURSOR_COMPACT_VERSION) throw new CursorTokenError(`unknown compact format version ${ver}`);
  if (!seqStr || !sigShort) throw new CursorTokenError('missing chain_seq or signature segment');
  if (!/^\d+$/.test(seqStr)) throw new CursorTokenError('chain_seq segment is not a non-negative integer');
  const chainSeq = Number(seqStr);
  if (!Number.isSafeInteger(chainSeq)) throw new CursorTokenError('chain_seq out of range');
  const a = Buffer.from(sigShort, 'utf8');
  const b = Buffer.from(compactShortSig(actorId, chainSeq, secret), 'utf8');
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    throw new CursorTokenError('signature verification failed');
  }
  return { chain_seq: chainSeq };
}

/**
 * Accept either form. Returns the position the token names. For a compact
 * token the chain_hash is unknown (null) — the caller looks it up.
 */
export function parseAnyCursor(
  token: string,
  actorId: string,
  secret: string,
): { form: 'full'; body: CursorBody } | { form: 'compact'; chain_seq: number } {
  if (isCompactCursor(token)) {
    return { form: 'compact', ...parseCompactCursor(token, actorId, secret) };
  }
  return { form: 'full', body: parseCursor(token, secret) };
}
