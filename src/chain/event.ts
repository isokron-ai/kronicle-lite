/**
 * Chain event shape and the hash recipe. This file IS the format; change it
 * only with a new genesis string. Worked example in docs/FORMAT.md.
 */

import { z } from 'zod';

import { canonicalize, type JsonValue } from '../crypto/canonical.js';
import { sha256Hex } from '../crypto/hash.js';

export const HEX64 = /^[0-9a-f]{64}$/;
export const HEX32 = /^[0-9a-f]{32}$/;

export const ChainEventSchema = z
  .object({
    seq: z.number().int().positive(),
    event_id: z.uuid(),
    event_type: z.string().min(1).max(200),
    payload: z.record(z.string(), z.unknown()),
    actor_id: z.string().min(1).max(200),
    occurred_at: z.iso.datetime(),
    nonce: z.string().regex(HEX32),
    prev_hash: z.string().regex(HEX64),
    this_hash: z.string().regex(HEX64),
    idempotency_key: z.string().min(1).max(200).nullable(),
  })
  .strict();
export type ChainEvent = z.infer<typeof ChainEventSchema>;

/**
 * The envelope that is canonicalized as the first hash component. It binds
 * everything that gives the payload its meaning: who, what kind, when,
 * which id. `seq`, `prev_hash` and `nonce` are appended outside the
 * envelope so the recipe reads naturally as "content | position | link |
 * salt".
 */
export interface HashEnvelope {
  event_id: string;
  event_type: string;
  actor_id: string;
  occurred_at: string;
  payload: Record<string, unknown>;
}

export function envelopeCanonical(env: HashEnvelope): string {
  return canonicalize({
    event_id: env.event_id,
    event_type: env.event_type,
    actor_id: env.actor_id,
    occurred_at: env.occurred_at,
    payload: env.payload as JsonValue,
  });
}

/**
 * this_hash = sha256( envelope_canonical || "|" || seq || "|" || prev_hash || "|" || nonce )
 * hex-encoded, lowercase.
 */
export function computeEventHash(args: {
  envelope_canonical: string;
  seq: number;
  prev_hash: string;
  nonce: string;
}): string {
  const preimage = `${args.envelope_canonical}|${args.seq}|${args.prev_hash}|${args.nonce}`;
  return sha256Hex(preimage);
}

/** Recompute an event's hash from its stored fields. */
export function recomputeEventHash(ev: Omit<ChainEvent, 'this_hash'>): string {
  return computeEventHash({
    envelope_canonical: envelopeCanonical({
      event_id: ev.event_id,
      event_type: ev.event_type,
      actor_id: ev.actor_id,
      occurred_at: ev.occurred_at,
      payload: ev.payload,
    }),
    seq: ev.seq,
    prev_hash: ev.prev_hash,
    nonce: ev.nonce,
  });
}
