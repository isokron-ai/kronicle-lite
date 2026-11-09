/**
 * The anchor service key-list model, cross-checked with the service itself: every list in
 * fixtures/keychain/service-verdicts.json was built by isokron-anchor's scripts/rotate-key.mjs
 * (rotation(), revoke()) and judged by its src/core/servicekeys.ts checkKeyChain at the commit
 * named in the fixture's generated_by. kronicle-lite's port must reach the same verdict, entry by
 * entry, with the same detail text: a key list valid for one is valid for the other.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { createPrivateKey, createPublicKey, sign } from 'node:crypto';

import { checkKeyChain, checkServiceKey, keyListOf, keyListRegression, parseGenesisPin, publicKeyFromPem, retirementSigningPayload, serviceKeyIdOf, successorSigningPayload, verifySignature, type GenesisPin } from '../src/anchor/keychain.js';

interface Verdicts {
  generated_by: string;
  genesis: GenesisPin;
  cases: Record<string, { keys: unknown[]; service: { ok: boolean; usable: boolean; detail: string; entries: { key_id: string; state: string; detail: string; revoked_ancestor: string | null }[] } }>;
}
const v = JSON.parse(readFileSync(join(__dirname, 'fixtures', 'keychain', 'service-verdicts.json'), 'utf8')) as Verdicts;
const list = (name: string) => keyListOf({ keys: v.cases[name]!.keys })!;

describe('key chain: same verdicts as the anchor service', () => {
  for (const [name, c] of Object.entries(v.cases)) {
    it(name, () => {
      const r = checkKeyChain(list(name), v.genesis);
      expect({
        ok: r.ok,
        usable: r.usable,
        detail: r.detail,
        entries: r.entries.map((e) => ({ key_id: e.key_id, state: e.state, detail: e.detail, revoked_ancestor: e.revoked_ancestor ?? null })),
      }).toEqual(c.service);
    });
  }

  it('covers rotation, revocation (by the key itself, an earlier key, a later key) and each tampering the review named', () => {
    expect(v.generated_by).toMatch(/^isokron-anchor fix\/rollback-cache 7e0e96f \(PR #3\): /);
    expect(Object.keys(v.cases).sort()).toEqual(
      [
        'empty',
        'fork',
        'genesis_only',
        'genesis_valid_from_in_list_ignored',
        'one_rotation',
        'predecessor_still_active',
        'predecessor_valid_to_moved_later',
        'retirement_unsigned',
        'revoked_by_later_key',
        'revoked_compromised_since_moved',
        'revoked_genesis',
        'revoked_genesis_only',
        'revoked_head',
        'revoked_middle',
        'revoked_middle_by_earlier_key',
        'revoked_without_compromised_since',
        'successor_backdated',
        'two_rotations',
        'wrong_genesis',
      ].sort(),
    );
    const s = (n: string) => v.cases[n]!.service;
    expect(s('two_rotations').ok).toBe(true);
    // the key after a revoked one is untrusted, the list stays usable for the keys before it
    expect(s('revoked_middle')).toMatchObject({ ok: false, usable: true });
    expect(s('revoked_middle').entries.map((e) => e.state)).toEqual(['broken', 'revoked', 'genesis']);
    expect(s('revoked_middle').entries[0]!.revoked_ancestor).toBe(s('revoked_middle').entries[1]!.key_id);
    // a revocation signed by a later key, or one whose compromised_since was dropped or moved: unusable
    for (const n of ['revoked_by_later_key', 'revoked_without_compromised_since', 'revoked_compromised_since_moved']) expect(s(n).usable).toBe(false);
  });
});

describe('checkServiceKey: a revoked key never vouches on received_at alone', () => {
  const pin = v.genesis;
  const keys = list('revoked_middle');
  const [after, revoked, genesis] = v.cases['revoked_middle']!.service.entries.map((e) => e.key_id) as [string, string, string];
  it("revoked: 'tsa' accepts the key only flagged with compromised_since; the caller then needs a TSA time before it", () => {
    const r = checkServiceKey(keys, revoked, '2026-12-10T00:00:00.000Z', pin, { revoked: 'tsa' });
    expect(r).toMatchObject({ ok: true, revoked: { compromised_since: '2026-12-20T00:00:00.000Z' } });
    expect(checkServiceKey(keys, revoked, '2026-12-10T00:00:00.000Z', pin).ok).toBe(false); // default: reject
  });
  it('the key after the revoked one is not trusted; the genesis before it still is', () => {
    expect(checkServiceKey(keys, after, '2027-01-02T00:00:00.000Z', pin, { revoked: 'tsa' })).toMatchObject({ ok: false, detail: expect.stringMatching(/is not trusted/) });
    expect(checkServiceKey(keys, genesis, '2026-11-10T00:00:00.000Z', pin, { revoked: 'tsa' })).toMatchObject({ ok: true });
  });
  it("the pin's valid_from bounds the genesis key, whatever the list says", () => {
    const k = list('genesis_valid_from_in_list_ignored');
    const g = k.find((e) => !e.successor_signature)!;
    expect(g.valid_from).toBe('2020-01-01T00:00:00.000Z');
    expect(checkServiceKey(k, g.key_id, '2021-01-01T00:00:00.000Z', pin)).toMatchObject({ ok: false, detail: expect.stringMatching(/precedes .* valid_from 2026-11-01T00:00:00.000Z/) });
  });
});

describe('genesis pin', () => {
  it('N4: the pin is canonical: case, colons and the spelling of valid_from do not make another pin', () => {
    const want = { sha256: v.genesis.sha256, valid_from: '2026-11-01T00:00:00.000Z' };
    for (const vf of ['2026-11-01T00:00:00Z', '2026-11-01T00:00:00.0Z', '2026-11-01T00:00:00.00Z', '2026-11-01T00:00:00.000Z']) {
      expect(parseGenesisPin(`${v.genesis.sha256.toUpperCase()}@${vf}`)).toEqual(want);
      expect(parseGenesisPin(`${v.genesis.sha256.match(/../g)!.join(':')}@${vf}`)).toEqual(want);
      expect(parseGenesisPin({ sha256: v.genesis.sha256, valid_from: vf })).toEqual(want);
    }
    expect(parseGenesisPin(`${v.genesis.sha256}@2026-02-30T00:00:00Z`)).toBeNull(); // would roll over to March
    expect(parseGenesisPin(`${v.genesis.sha256}@2026-11-01T24:00:00Z`)).toBeNull();
  });
  it('is <sha256>@<valid_from>; a bare hash or a non-UTC time is not a pin', () => {
    expect(parseGenesisPin(`${v.genesis.sha256}@${v.genesis.valid_from}`)).toEqual(v.genesis);
    expect(parseGenesisPin(v.genesis.sha256)).toBeNull();
    expect(parseGenesisPin(`${v.genesis.sha256}@2026-11-01T00:00:00+01:00`)).toBeNull();
    expect(parseGenesisPin(`${'0'.repeat(63)}@${v.genesis.valid_from}`)).toBeNull();
  });
});

describe('key list rollback (keyListRegression)', () => {
  const two = list('two_rotations');
  const one = list('one_rotation');
  it('a newer list is not a rollback of an older one; the older one is a rollback of the newer one', () => {
    expect(keyListRegression(one, two)).toBeNull();
    expect(keyListRegression(two, one)).toMatch(/is in the key list seen earlier but missing now/);
  });
  it('a status moved back, a valid_to moved later, a compromised_since dropped or moved later: rollback', () => {
    const revoked = list('revoked_middle');
    expect(keyListRegression(revoked, two)).toMatch(/was revoked in the list seen earlier and is retired now/);
    const later = two.map((k) => (k.valid_to ? { ...k, valid_to: '2030-01-01T00:00:00.000Z' } : k));
    expect(keyListRegression(two, later)).toMatch(/valid_to was .* and is 2030-01-01T00:00:00.000Z now/);
    expect(keyListRegression(revoked, list('revoked_compromised_since_moved'))).toMatch(/compromised_since was 2026-12-20T00:00:00.000Z in the list seen earlier and is 2026-12-31T00:00:00.000Z now/);
    expect(keyListRegression(revoked, list('revoked_without_compromised_since'))).toMatch(/compromised_since was .* and is unset now/);
  });
});

/**
 * The byte-exact statement spec: isokron-anchor README "Signed key statements (byte-exact)" at
 * feat/audit-anchoring f289c6b, copied verbatim (the service's test/node/keys.test.ts checks the
 * same vectors). Messages are RFC 8785 canonical JSON; signatures pure Ed25519, standard base64.
 */
describe('signed key statements: the service README test vectors', () => {
  const SEED = Buffer.alloc(32, 0x01);
  const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), SEED]), format: 'der', type: 'pkcs8' });
  const KEY_ID = 'anchor-ed25519-fd110d301d2f077d';
  const PEM = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAiojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=\n-----END PUBLIC KEY-----\n';
  const vectors = [
    {
      name: 'successor',
      message: successorSigningPayload({ key_id: KEY_ID, public_key_pem: PEM, valid_from: '2027-03-01T00:00:00.000Z' }),
      expected: String.raw`{"key_id":"anchor-ed25519-fd110d301d2f077d","public_key_pem":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAiojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=\n-----END PUBLIC KEY-----\n","valid_from":"2027-03-01T00:00:00.000Z"}`,
      signature: 'VvEPZo8KlDiR7RHAGxysqzX5VwDA0JavC5VBYYvUKFDJegPwoXObQCA1FWdpuxm2gP/eBvxdBvtIwuBONwp6Bg==',
    },
    {
      name: 'retirement',
      message: retirementSigningPayload({ key_id: KEY_ID, status: 'retired', valid_to: '2027-09-01T00:00:00.000Z' }),
      expected: '{"key_id":"anchor-ed25519-fd110d301d2f077d","status":"retired","valid_to":"2027-09-01T00:00:00.000Z"}',
      signature: 'rYeanm3ON6QeKIlSqFNAcQsTdgimNxiS1pWqmoxURYkGrO0sx7gY8ToSoSAlgtGlqWHd16IrSBH2ztsqAt7ICw==',
    },
    {
      name: 'revocation',
      message: retirementSigningPayload({ key_id: KEY_ID, status: 'revoked', valid_to: '2027-09-01T00:00:00.000Z', compromised_since: '2027-06-01T00:00:00.000Z' }),
      expected: '{"compromised_since":"2027-06-01T00:00:00.000Z","key_id":"anchor-ed25519-fd110d301d2f077d","status":"revoked","valid_to":"2027-09-01T00:00:00.000Z"}',
      signature: '+L3QO3cUyLGoQXi1AUCeN8sufdmOn/CpvSkolH6hKDx1dNAMYdIJOkNf9ItqPp8yohqlqxytGM/a30M+VPq4Bw==',
    },
  ];

  it('the vector key: seed 32 × 0x01 gives that PEM and key_id', () => {
    expect(createPublicKey(priv).export({ type: 'spki', format: 'pem' })).toBe(PEM);
    expect(serviceKeyIdOf(publicKeyFromPem(PEM))).toBe(KEY_ID);
  });
  for (const t of vectors) {
    it(`${t.name}: the message is byte-identical, the signature reproduces and verifies, any other byte fails`, () => {
      expect(t.message).toBe(t.expected);
      expect(Buffer.from(t.message, 'utf8').equals(Buffer.from(t.expected, 'utf8'))).toBe(true);
      expect(sign(null, Buffer.from(t.message, 'utf8'), priv).toString('base64')).toBe(t.signature);
      expect(t.signature).toHaveLength(88);
      const pub = publicKeyFromPem(PEM);
      expect(verifySignature(pub, t.message, t.signature)).toBe(true);
      expect(verifySignature(pub, t.message.replace('2027-', '2028-'), t.signature)).toBe(false);
    });
  }
});

/** isokron-anchor fix/rollback-cache 7e0e96f test/node/keys.test.ts "round 5 L2", on the fixture lists. */
describe('keyListRegression refuses any change to a kept key except the status progression (service 7e0e96f)', () => {
  const kept = list('two_rotations');
  const [k3, k2, k1] = kept.map((k) => k.key_id) as [string, string, string];
  const set = (keys: typeof kept, kid: string, over: Record<string, unknown>) => keys.map((k) => (k.key_id === kid ? { ...k, ...over } : k));
  it('a moved valid_from, successor_signature, signed_by, alg or any other field is refused', () => {
    expect(keyListRegression(kept, set(kept, k2, { valid_from: '2026-11-15T00:00:00.000Z' }))).toMatch(new RegExp(`${k2} valid_from was 2026-12-01T00:00:00.000Z in the list seen earlier and is 2026-11-15T00:00:00.000Z now`));
    expect(keyListRegression(kept, set(kept, k3, { successor_signature: 'A'.repeat(86) + '==' }))).toMatch(/successor_signature was .* now/);
    expect(keyListRegression(kept, set(kept, k3, { signed_by: k1 }))).toMatch(/signed_by was .* now/);
    expect(keyListRegression(kept, set(kept, k3, { alg: 'EdDSA' }))).toMatch(/alg was unset .* is EdDSA now/);
    expect(keyListRegression(kept, set(kept, k3, { note: 'x' }))).toMatch(/note was unset .* is x now/);
    expect(keyListRegression(kept, kept)).toBeNull();
  });
  it('a changed status statement without a status change is refused', () => {
    const k1e = kept.find((k) => k.key_id === k1)!;
    expect(keyListRegression(kept, set(kept, k1, { retirement_signature: 'B'.repeat(86) + '==', retirement_signed_by: k1e.retirement_signed_by }))).toMatch(/status statement changed without a status change/);
  });
  it('allowed: new keys, active/retired → revoked with its statement', () => {
    expect(keyListRegression(list('one_rotation'), kept)).toBeNull();
    expect(keyListRegression(kept, list('revoked_middle'))).toBeNull();
  });
});
