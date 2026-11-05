/**
 * Regression tests from the independent review of #13 (probes in
 * klrev/probes/zz-probe13.test.ts): hidden events, missing artifacts,
 * hostile bundles, secrets in blobs, reserved idempotency keys, __proto__,
 * repeated refutation, and guards that must each be load-bearing.
 */
import { mkdirSync, readFileSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { deflateSync, gzipSync } from 'node:zlib';

import { describe, expect, it } from 'vitest';

import { exportBundle, signManifest, type BundleManifest } from '../src/audit/bundle.js';
import { verifyBundle } from '../src/audit/verify-bundle.js';
import { auditIdentity } from '../src/audit/schemas.js';
import { checkpointSigningPayload } from '../src/chain/chain.js';
import { merkleRootHex } from '../src/chain/merkle.js';
import { canonicalize } from '../src/crypto/canonical.js';
import { sha256Hex } from '../src/crypto/hash.js';
import { ephemeralIdentity, type Signer } from '../src/crypto/keys.js';
import { KronicleLite } from '../src/index.js';
import { SecretDetectedError } from '../src/secrets/guard.js';
import { tempDir } from './helpers/fs.js';

const F1 = 'a'.repeat(64);
const AWS = 'AKIA' + 'IOSFODNN7EXAMPLQ';
const GHP = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';

function build() {
  const kl = new KronicleLite({ memory: true });
  const resp = kl.audit.putBlob(Buffer.from('response body'), 'text/plain');
  kl.audit.record('A1', [{ kind: 'finding', event_key: 'f1', payload: { finding_id: 'V1', status: 'discovered', title: 'bug' } }], 'auditor');
  kl.docs.putDocument({ slug: 'u', title: 'u', markdown: '# U\n\nx.\n', actor_id: 'h' });
  kl.audit.record('A1', [{ kind: 'gate_result', event_key: 'g1', payload: { finding_id: 'V1', gate: 'repro', verdict: 'refuted', report: resp } }], 'gate');
  kl.audit.record('A1', [{ kind: 'call_measured', event_key: 'c1', payload: { fingerprint: F1, tool: 't', status: '200', is_error: false, latency_ms: 1, bytes_out: 1 } }], 'proxy');
  const dir = tempDir('rev-bundle-');
  const r = exportBundle({ chain: kl.chain, audit: kl.audit, signer: kl.identity.signer, audit_id: 'A1', dir });
  return { kl, dir, r, resp };
}
const readLines = (dir: string) => readFileSync(join(dir, 'events.jsonl'), 'utf8').trimEnd().split('\n');
const writeLines = (dir: string, lines: string[]) => {
  const t = lines.join('\n') + '\n';
  writeFileSync(join(dir, 'events.jsonl'), t);
  return t;
};
const manifest = (dir: string) => JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8')) as BundleManifest & Record<string, unknown>;
const writeManifest = (dir: string, m: unknown) => writeFileSync(join(dir, 'manifest.json'), canonicalize(m as never) + '\n');
const failed = (dir: string, o = {}) =>
  verifyBundle(dir, o)
    .checks.filter((c) => !c.ok)
    .map((c) => c.check);

/** What a holder of `signer` can do: recompute every digest, the root and both signatures over the edited bundle. */
function resign(dir: string, signer: Signer, edit: (m: BundleManifest, lines: Record<string, unknown>[]) => void = () => {}) {
  const lines = readLines(dir).map((l) => JSON.parse(l) as Record<string, unknown>);
  const m = manifest(dir);
  edit(m, lines);
  const text = writeLines(dir, lines.map((l) => canonicalize(l as never)));
  m.events_sha256 = sha256Hex(text);
  const leaves = lines.map((l) => ({ seq: Number(l['seq']), this_hash: String(l['this_hash']) }));
  const root = merkleRootHex(leaves);
  m.root = {
    root,
    leaf_count: lines.length,
    key_id: signer.key_id,
    public_key_pem: signer.public_key_pem,
    signature: signer.sign(checkpointSigningPayload({ from_seq: m.range.from_seq, to_seq: m.range.to_seq, leaf_count: lines.length, root })),
  };
  writeManifest(dir, signManifest(m, signer));
}

/** Turn the audit's gate_result into a stub and drop it (and its blob) from the manifest: the B1 attack. */
function hideGate(dir: string, r: ReturnType<typeof build>['r'], m: BundleManifest, lines: Record<string, unknown>[]) {
  const gateSeq = r.manifest.events.find((e) => e.event_type === 'audit.gate_result')!.seq;
  const i = gateSeq - r.manifest.range.from_seq;
  const ev = lines[i]!;
  lines[i] = { seq: ev['seq'], prev_hash: ev['prev_hash'], this_hash: ev['this_hash'], stub: true };
  m.events = m.events.filter((e) => e.seq !== gateSeq);
  m.stubs = [...m.stubs, { seq: gateSeq, this_hash: String(ev['this_hash']) }].sort((a, b) => a.seq - b.seq);
  m.blobs = [];
  unlinkSync(join(dir, 'blobs', r.manifest.blobs[0]!.sha256));
}

describe('review #13 B1: the signature covers the whole manifest; hiding an event is caught', () => {
  it('stubbing the refuting gate_result and fixing up the manifest (no key) fails, pinned or not', () => {
    const { kl, dir, r } = build();
    const lines = readLines(dir).map((l) => JSON.parse(l) as Record<string, unknown>);
    const m = manifest(dir);
    hideGate(dir, r, m, lines);
    const text = writeLines(dir, lines.map((l) => canonicalize(l as never)));
    m.events_sha256 = sha256Hex(text);
    writeManifest(dir, m);
    expect(verifyBundle(dir).ok).toBe(false);
    expect(failed(dir, { public_key_pem: kl.identity.signer.public_key_pem })).toContain('signature');
    kl.close();
  });

  it('an attacker who re-signs everything with their own key fails against the pinned store key', () => {
    const { kl, dir, r } = build();
    const mallory = ephemeralIdentity().signer;
    resign(dir, mallory, (m, lines) => hideGate(dir, r, m, lines));
    expect(verifyBundle(dir).ok).toBe(true); // self-consistent under mallory's key: why --key exists
    expect(verifyBundle(dir, { public_key_pem: kl.identity.signer.public_key_pem })).toMatchObject({ ok: false });
    expect(failed(dir, { public_key_pem: kl.identity.signer.public_key_pem })).toEqual(expect.arrayContaining(['signature']));
    kl.close();
  });

  it('a manifest copied from another audit of the same store fails', () => {
    const a = build();
    a.kl.audit.record('A2', [{ kind: 'call_measured', event_key: 'x', payload: { fingerprint: F1, tool: 't', status: '200', is_error: false, latency_ms: 1, bytes_out: 1 } }], 'p');
    const d2 = tempDir('rev-b2-');
    exportBundle({ chain: a.kl.chain, audit: a.kl.audit, signer: a.kl.identity.signer, audit_id: 'A2', dir: d2 });
    writeFileSync(join(a.dir, 'manifest.json'), readFileSync(join(d2, 'manifest.json')));
    expect(verifyBundle(a.dir, { public_key_pem: a.kl.identity.signer.public_key_pem }).ok).toBe(false);
    a.kl.close();
  });
});

describe('review #13 B2: a missing artifact fails unless explicitly allowed (and the allowance is reported)', () => {
  it('delete an artifact and declare it missing → ok:false; --allow-missing → ok:true with allow_missing reported', () => {
    const { kl, dir, resp } = build();
    unlinkSync(join(dir, 'blobs', resp.sha256));
    resign(dir, kl.identity.signer, (m) => {
      m.blobs = [];
      m.missing = [{ sha256: resp.sha256, size: resp.size, referenced_by: [m.events[1]!.event_id] }];
    });
    const strict = verifyBundle(dir, { public_key_pem: kl.identity.signer.public_key_pem });
    expect(strict).toMatchObject({ ok: false, allow_missing: false, counts: { missing: 1 } });
    expect(failed(dir)).toEqual(['missing']);
    expect(verifyBundle(dir, { public_key_pem: kl.identity.signer.public_key_pem, allow_missing: true })).toMatchObject({ ok: true, allow_missing: true, counts: { missing: 1 } });
    kl.close();
  });
});

describe('review #13: hostile bundles yield ok:false, never a throw or an escape', () => {
  const cases: [string, (m: Record<string, unknown>) => void][] = [
    ['no range', (m) => delete m['range']],
    ['blobs object', (m) => (m['blobs'] = { a: 1 })],
    ['root null', (m) => (m['root'] = null)],
    ['events not a list', (m) => (m['events'] = 'x')],
    ['blob traversal', (m) => (m['blobs'] = [{ sha256: '../../../../../../etc/hostname', size: 1, media_type: null }])],
    ['blob absolute', (m) => (m['blobs'] = [{ sha256: '/etc/hostname', size: 1, media_type: null }])],
    ['blob dir', (m) => (m['blobs'] = [{ sha256: '.', size: 1, media_type: null }])],
  ];
  for (const [name, f] of cases) {
    it(name, () => {
      const { dir } = build();
      const m = manifest(dir);
      f(m);
      writeManifest(dir, m);
      let r: ReturnType<typeof verifyBundle> | null = null;
      expect(() => (r = verifyBundle(dir))).not.toThrow();
      expect(r!.ok).toBe(false);
    });
  }
  it('a blob whose name is a 64-hex directory is an artifact failure, not a crash', () => {
    const { kl, dir, resp } = build();
    unlinkSync(join(dir, 'blobs', resp.sha256));
    mkdirSync(join(dir, 'blobs', resp.sha256));
    expect(() => verifyBundle(dir)).not.toThrow();
    expect(failed(dir)).toContain('artifacts');
    kl.close();
  });
  it('a deeply nested line (stack depth) is a canonical failure, not a crash', () => {
    const { dir } = build();
    const l = readLines(dir);
    l[0] = '['.repeat(200_000) + ']'.repeat(200_000);
    writeLines(dir, l);
    expect(() => verifyBundle(dir)).not.toThrow();
    expect(verifyBundle(dir).ok).toBe(false);
  });
  it('a deeply nested manifest is a failure, not a crash', () => {
    const { dir } = build();
    writeFileSync(join(dir, 'manifest.json'), '{"a":' + '['.repeat(200_000) + ']'.repeat(200_000) + '}\n');
    expect(() => verifyBundle(dir)).not.toThrow();
    expect(verifyBundle(dir).ok).toBe(false);
  });
});

describe('review #13: guards that must each be load-bearing (key holder re-signs a malformed bundle)', () => {
  it('stub index: a stub line the manifest does not list (or lists with another hash) fails events', () => {
    const { kl, dir } = build();
    resign(dir, kl.identity.signer, (m) => {
      m.stubs = m.stubs.map((s, i) => (i === 0 ? { ...s, this_hash: 'f'.repeat(64) } : s));
    });
    expect(failed(dir, { public_key_pem: kl.identity.signer.public_key_pem })).toEqual(['events']);
    kl.close();
  });
  it('full-event index: manifest.events differing from the full lines fails events', () => {
    const { kl, dir } = build();
    resign(dir, kl.identity.signer, (m) => {
      m.events = m.events.slice(1);
    });
    expect(failed(dir, { public_key_pem: kl.identity.signer.public_key_pem })).toContain('events');
    kl.close();
  });
  it('seq contiguity: a renumbered stub (links intact) fails chain', () => {
    const { kl, dir, r } = build();
    const stubSeq = r.manifest.stubs[0]!.seq;
    resign(dir, kl.identity.signer, (m, lines) => {
      const i = stubSeq - m.range.from_seq;
      lines[i]!['seq'] = stubSeq + 100;
      m.stubs = m.stubs.map((s) => (s.seq === stubSeq ? { ...s, seq: stubSeq + 100 } : s));
    });
    expect(failed(dir, { public_key_pem: kl.identity.signer.public_key_pem })).toContain('chain');
    kl.close();
  });
  it('a stub cannot stand in for an event the manifest lists as an audit event of the same seq', () => {
    const { kl, dir, r } = build();
    const gateSeq = r.manifest.events.find((e) => e.event_type === 'audit.gate_result')!.seq;
    resign(dir, kl.identity.signer, (m, lines) => {
      const i = gateSeq - m.range.from_seq;
      const ev = lines[i]!;
      lines[i] = { seq: ev['seq'], prev_hash: ev['prev_hash'], this_hash: ev['this_hash'], stub: true };
    });
    expect(failed(dir, { public_key_pem: kl.identity.signer.public_key_pem })).toContain('events');
    kl.close();
  });
});

describe('review #13 B3: blobs are secret-scanned like chain payloads', () => {
  it('a blob holding a bearer token or an AWS key is refused; nothing is stored', () => {
    const kl = new KronicleLite({ memory: true });
    expect(() => kl.audit.putBlob(Buffer.from(`Authorization: Bearer ${GHP}\n`), 'text/plain')).toThrow(SecretDetectedError);
    expect(() => kl.audit.putBlob(Buffer.from(`x-api-key: ${AWS}\n`), 'text/plain')).toThrow(SecretDetectedError);
    expect((kl.db.prepare('SELECT COUNT(*) AS n FROM blobs').get() as { n: number }).n).toBe(0);
    kl.close();
  });
  it('redact mode stores a redacted copy, flags it, and the bundle never holds the canary', () => {
    const kl = new KronicleLite({ memory: true });
    const ref = kl.audit.putBlob(Buffer.from(`Authorization: Bearer ${GHP}\nx-api-key: ${AWS}\nok\n`), 'text/plain', { secrets: 'redact' });
    expect(ref.redactions).toBeGreaterThanOrEqual(2);
    const stored = kl.audit.getBlob(ref.sha256)!.bytes.toString();
    expect(stored).not.toContain(GHP);
    expect(stored).not.toContain(AWS);
    kl.audit.record('A', [{ kind: 'finding', event_key: 'sb', payload: { finding_id: 'V5', status: 'discovered', detail: { sha256: ref.sha256, size: ref.size } } }], 'x');
    const d = tempDir('rev-sec-');
    exportBundle({ chain: kl.chain, audit: kl.audit, signer: kl.identity.signer, audit_id: 'A', dir: d });
    const blob = readFileSync(join(d, 'blobs', ref.sha256), 'utf8');
    expect(blob).not.toContain(GHP);
    expect(blob).not.toContain(AWS);
    kl.close();
  });
});

describe('review #13: ingest hardening', () => {
  it('__proto__ keys are refused, at the payload root and nested', () => {
    const kl = new KronicleLite({ memory: true });
    const root = JSON.parse('{"finding_id":"V3","status":"discovered","__proto__":{"x":1}}') as Record<string, unknown>;
    expect(() => kl.audit.record('A', [{ kind: 'finding', event_key: 'pp', payload: root }], 'x')).toThrow(/__proto__/);
    const tokens = JSON.parse('{"__proto__": 5, "cl100k": 3}') as Record<string, unknown>;
    expect(() =>
      kl.audit.record('A', [{ kind: 'call_measured', event_key: 'pt', payload: { fingerprint: F1, tool: 't', status: '200', is_error: false, latency_ms: 1, bytes_out: 1, tokens } }], 'x'),
    ).toThrow(/__proto__/);
    expect(kl.chain.head().seq).toBe(0);
    kl.close();
  });
  it('a deeply nested payload is refused quickly', () => {
    const kl = new KronicleLite({ memory: true });
    let deep: unknown = 1;
    for (let i = 0; i < 10_000; i++) deep = { a: deep };
    const t0 = Date.now();
    expect(() => kl.audit.record('A', [{ kind: 'finding', event_key: 'k', payload: { finding_id: 'V', status: 'discovered', x: deep } }], 'x')).toThrow(/deep|nested/);
    expect(Date.now() - t0).toBeLessThan(2000);
    kl.close();
  });
  it('a second refuting gate_result is allowed (several refuters may refute)', () => {
    const kl = new KronicleLite({ memory: true });
    kl.audit.record('A', [{ kind: 'finding', event_key: 'f1', payload: { finding_id: 'V1', status: 'discovered' } }], 'x');
    kl.audit.record('A', [{ kind: 'gate_result', event_key: 'g1', payload: { finding_id: 'V1', gate: 'g', verdict: 'refuted' } }], 'x');
    expect(kl.audit.record('A', [{ kind: 'gate_result', event_key: 'g2', payload: { finding_id: 'V1', gate: 'g2', verdict: 'refuted' } }], 'x')).toHaveLength(1);
    expect(kl.audit.finding('A', 'V1')).toMatchObject({ status: 'refuted', events: 3 });
    kl.close();
  });
  it('query limits that are not finite numbers are clamped, not an SQL error', () => {
    const kl = new KronicleLite({ memory: true });
    kl.audit.record('A', [{ kind: 'finding', event_key: 'f1', payload: { finding_id: 'V1', status: 'discovered' } }], 'x');
    expect(kl.audit.query({ audit_id: 'A', limit: Number.NaN })).toHaveLength(1);
    expect(kl.audit.query({ audit_id: 'A', after_seq: -5 })).toHaveLength(1);
    kl.close();
  });
  it('put_document cannot squat an audit (or apply) idempotency key', () => {
    const kl = new KronicleLite({ memory: true });
    for (const k of [auditIdentity('A', 'future').idempotency_key, `apply:${sha256Hex('K2')}`]) {
      expect(() => kl.docs.putDocument({ slug: 'sq', title: 'sq', markdown: '# s\n\ns.\n', actor_id: 'evil', idempotency_key: k })).toThrow(/reserved/);
    }
    expect(kl.audit.record('A', [{ kind: 'finding', event_key: 'future', payload: { finding_id: 'V6', status: 'discovered' } }], 'x')[0]!.replayed).toBe(false);
    kl.close();
  });
});

describe('re-review #13: export never writes through planted symlinks', () => {
  const POSIX = process.platform !== 'win32';
  it('refuses a non-empty --out directory', () => {
    const { kl } = build();
    const out = tempDir('rev-out-');
    writeFileSync(join(out, 'keep.txt'), 'x');
    expect(() => exportBundle({ chain: kl.chain, audit: kl.audit, signer: kl.identity.signer, audit_id: 'A1', dir: out })).toThrow(/not empty/);
    kl.close();
  });
  it.skipIf(!POSIX)('refuses an --out that is a symlink, or whose parent is', () => {
    const { kl } = build();
    const real = tempDir('rev-real-');
    const base = tempDir('rev-base-');
    symlinkSync(real, join(base, 'link'));
    expect(() => exportBundle({ chain: kl.chain, audit: kl.audit, signer: kl.identity.signer, audit_id: 'A1', dir: join(base, 'link') })).toThrow(/symlink/);
    expect(() => exportBundle({ chain: kl.chain, audit: kl.audit, signer: kl.identity.signer, audit_id: 'A1', dir: join(base, 'link', 'sub') })).toThrow(/symlink/);
    kl.close();
  });
  it.skipIf(!POSIX)('symlinks planted as manifest.json / events.jsonl / blobs/<sha> in an empty-looking dir are never followed; victims unchanged', () => {
    const { kl, resp } = build();
    const victims = tempDir('rev-victim-');
    const vm = join(victims, 'manifest-victim');
    const ve = join(victims, 'events-victim');
    const vb = join(victims, 'blob-victim');
    for (const v of [vm, ve, vb]) writeFileSync(v, 'precious');
    // The planted links make the dir non-empty: refused before anything is written.
    const out = tempDir('rev-out-');
    symlinkSync(vm, join(out, 'manifest.json'));
    symlinkSync(ve, join(out, 'events.jsonl'));
    mkdirSync(join(out, 'blobs'));
    symlinkSync(vb, join(out, 'blobs', resp.sha256));
    expect(() => exportBundle({ chain: kl.chain, audit: kl.audit, signer: kl.identity.signer, audit_id: 'A1', dir: out })).toThrow();
    for (const v of [vm, ve, vb]) expect(readFileSync(v, 'utf8')).toBe('precious');
    kl.close();
  });
  it('writes into a fresh directory it creates', () => {
    const { kl } = build();
    const out = join(tempDir('rev-new-'), 'bundle');
    exportBundle({ chain: kl.chain, audit: kl.audit, signer: kl.identity.signer, audit_id: 'A1', dir: out });
    expect(verifyBundle(out).ok).toBe(true);
    kl.close();
  });
});

describe('re-review #13: verify-bundle never follows a symlinked blob', () => {
  it.skipIf(process.platform === 'win32')('a blob that is a symlink to the right bytes still fails artifacts', () => {
    const { kl, dir, resp } = build();
    const elsewhere = join(tempDir('rev-ln-'), 'b');
    writeFileSync(elsewhere, readFileSync(join(dir, 'blobs', resp.sha256)));
    unlinkSync(join(dir, 'blobs', resp.sha256));
    symlinkSync(elsewhere, join(dir, 'blobs', resp.sha256));
    expect(failed(dir)).toEqual(['artifacts']);
    kl.close();
  });
});

describe('re-review #13: the blob secret scan sees through common encodings', () => {
  const body = `Authorization: Bearer ${GHP}\n`;
  const cases: [string, Buffer][] = [
    ['gzip', gzipSync(Buffer.from(body))],
    ['deflate', deflateSync(Buffer.from(body))],
    ['utf-16le', Buffer.from(body, 'utf16le')],
    ['utf-16le with BOM', Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(body, 'utf16le')])],
    ['base64', Buffer.from(`{"body":"${Buffer.from(body).toString('base64')}"}`)],
    ['base64url', Buffer.from(`data=${Buffer.from(`x-api-key: ${AWS} and more padding text`).toString('base64url')}`)],
    ['gzip inside base64', Buffer.from(`payload: ${gzipSync(Buffer.from(body)).toString('base64')}`)],
  ];
  for (const [name, bytes] of cases) {
    it(`${name}: refused`, () => {
      const kl = new KronicleLite({ memory: true });
      expect(() => kl.audit.putBlob(bytes, 'application/octet-stream')).toThrow(SecretDetectedError);
      expect((kl.db.prepare('SELECT COUNT(*) AS n FROM blobs').get() as { n: number }).n).toBe(0);
      kl.close();
    });
  }
  it('clean encoded bodies are stored; one that cannot be decoded within the cap is stored flagged unscanned_encoding', () => {
    const kl = new KronicleLite({ memory: true });
    expect(kl.audit.putBlob(gzipSync(Buffer.from('hello world\n')), 'application/gzip').unscanned).toBeUndefined();
    // A gzip bomb: decompresses past the cap.
    const bomb = gzipSync(Buffer.alloc(80 * 1024 * 1024, 0x41));
    const r = kl.audit.putBlob(bomb, 'application/gzip');
    expect(r.unscanned).toEqual(['unscanned_encoding']);
    // A truncated gzip stream cannot be decoded either.
    const cut = gzipSync(Buffer.from('a'.repeat(5000))).subarray(0, 30);
    expect(kl.audit.putBlob(cut, 'application/gzip').unscanned).toEqual(['unscanned_encoding']);
    kl.close();
  });
  it('redact mode refuses what it cannot redact in place (an encoded secret)', () => {
    const kl = new KronicleLite({ memory: true });
    expect(() => kl.audit.putBlob(gzipSync(Buffer.from(body)), 'application/gzip', { secrets: 'redact' })).toThrow(SecretDetectedError);
    kl.close();
  });
});
