import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { exportBundle } from '../src/audit/bundle.js';
import { verifyBundle } from '../src/audit/verify-bundle.js';
import { canonicalize } from '../src/crypto/canonical.js';
import { ephemeralIdentity } from '../src/crypto/keys.js';
import { KronicleLite } from '../src/index.js';
import { CLI, cleanEnv, tempDir } from './helpers/fs.js';

const F1 = 'a'.repeat(64);

/** A store with an audit interleaved with ordinary document writes (they become stubs). */
function seeded(kl: KronicleLite) {
  const snap = kl.audit.putBlob(Buffer.from('{"tools":["a","b"]}'), 'application/json');
  const resp = kl.audit.putBlob(Buffer.from('response body'), 'text/plain');
  kl.audit.record('A1', [{ kind: 'catalog_snapshot', event_key: 's', payload: { fingerprint: F1, server: { name: 'srv' }, tool_count: 2, bytes: 19, snapshot: snap } }], 'auditor');
  kl.docs.putDocument({ slug: 'unrelated', title: 'u', markdown: '# U\n\nprivate notes.\n', actor_id: 'someone' });
  const [c] = kl.audit.record(
    'A1',
    [{ kind: 'call_measured', event_key: 'c1', payload: { fingerprint: F1, tool: 'a', status: '200', is_error: false, latency_ms: 5, bytes_out: 13, response: resp, request: { sha256: 'd'.repeat(64), size: 99, redacted: true } } }],
    'proxy',
  );
  kl.audit.record('A2', [{ kind: 'call_measured', event_key: 'other', payload: { fingerprint: F1, tool: 'a', status: '200', is_error: false, latency_ms: 5, bytes_out: 1 } }], 'proxy');
  kl.audit.record('A1', [{ kind: 'finding', event_key: 'f', payload: { finding_id: 'V1', status: 'discovered', evidence: [c!.event_id] } }], 'auditor');
  return { snap, resp };
}

function exported() {
  const kl = new KronicleLite({ memory: true });
  const s = seeded(kl);
  const dir = tempDir('kl-bundle-');
  const r = exportBundle({ chain: kl.chain, audit: kl.audit, signer: kl.identity.signer, audit_id: 'A1', dir });
  return { kl, dir, r, ...s };
}

const failed = (dir: string, opts = {}) =>
  verifyBundle(dir, opts)
    .checks.filter((c) => !c.ok)
    .map((c) => c.check);

describe('evidence bundle: export and offline verification', () => {
  it('exports the audit with stubs for other events, blobs, the redacted list and a signed root; it verifies', () => {
    const { kl, dir, r, snap, resp } = exported();
    const m = r.manifest;
    expect(m.range).toMatchObject({ from_seq: 1, to_seq: kl.chain.head().seq });
    expect(m.events.map((e) => e.event_type)).toEqual(['audit.catalog_snapshot', 'audit.call_measured', 'audit.finding']);
    expect(m.stubs.length).toBeGreaterThanOrEqual(2); // the document's events and audit A2
    expect(m.blobs.map((b) => b.sha256).sort()).toEqual([snap.sha256, resp.sha256].sort());
    expect(m.redacted).toEqual([{ sha256: 'd'.repeat(64), size: 99, referenced_by: [m.events[1]!.event_id] }]);
    expect(m.missing).toEqual([]);
    const text = readFileSync(join(dir, 'events.jsonl'), 'utf8');
    expect(text).not.toContain('private notes'); // stubs carry hashes only
    expect(text).not.toContain('"other"');
    const v = verifyBundle(dir);
    expect(v).toMatchObject({ ok: true, audit_id: 'A1', root: m.root.root, manifest_sha256: r.manifest_sha256, counts: { events: 3, redacted: 1, missing: 0 } });
    // The root is a stored checkpoint over the same range (anchorable with the existing flow).
    expect(kl.chain.listCheckpoints().some((c) => c.root === m.root.root && c.from_seq === m.range.from_seq && c.to_seq === m.range.to_seq)).toBe(true);
    kl.close();
  });

  it('is deterministic: exporting twice gives byte-identical files', () => {
    const { kl, dir } = exported();
    const dir2 = tempDir('kl-bundle2-');
    exportBundle({ chain: kl.chain, audit: kl.audit, signer: kl.identity.signer, audit_id: 'A1', dir: dir2 });
    for (const f of ['manifest.json', 'events.jsonl', ...readdirSync(join(dir, 'blobs')).map((b) => join('blobs', b))]) {
      expect(readFileSync(join(dir2, f)).equals(readFileSync(join(dir, f))), f).toBe(true);
    }
    expect(readFileSync(join(dir, 'manifest.json'), 'utf8')).toBe(canonicalize(JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8'))) + '\n');
    kl.close();
  });

  it('every tamper is caught by the step that owns it', () => {
    const fresh = () => exported();
    // artifact bytes changed
    {
      const { kl, dir, resp } = fresh();
      writeFileSync(join(dir, 'blobs', resp.sha256), 'response bodY');
      expect(failed(dir)).toEqual(['artifacts']);
      kl.close();
    }
    // an event payload edited (and events_sha256 recomputed to hide it): the event hash and root fail
    {
      const { kl, dir } = fresh();
      const p = join(dir, 'events.jsonl');
      const lines = readFileSync(p, 'utf8').trimEnd().split('\n');
      const ev = JSON.parse(lines[0]!) as { payload: { tool_count: number } };
      ev.payload.tool_count = 3;
      lines[0] = canonicalize(ev as never);
      writeFileSync(p, lines.join('\n') + '\n');
      expect(failed(dir)).toEqual(expect.arrayContaining(['canonical', 'events']));
      kl.close();
    }
    // a line dropped: chain continuity fails
    {
      const { kl, dir } = fresh();
      const p = join(dir, 'events.jsonl');
      const lines = readFileSync(p, 'utf8').trimEnd().split('\n');
      lines.splice(1, 1);
      writeFileSync(p, lines.join('\n') + '\n');
      expect(failed(dir)).toEqual(expect.arrayContaining(['chain', 'root']));
      kl.close();
    }
    // a pinned key that did not sign it
    {
      const { kl, dir } = fresh();
      // an untrusted manifest's blob list is never read (its sizes could be an attacker's): artifacts is not run
      expect(failed(dir, { public_key_pem: ephemeralIdentity().signer.public_key_pem })).toEqual(['signature', 'root', 'artifacts']);
      expect(failed(dir, { public_key_pem: kl.identity.signer.public_key_pem })).toEqual([]);
      kl.close();
    }
    // the redacted list emptied: the manifest signature breaks, and the ref dangles
    {
      const { kl, dir } = fresh();
      const p = join(dir, 'manifest.json');
      const m = JSON.parse(readFileSync(p, 'utf8')) as { redacted: unknown[] };
      m.redacted = [];
      writeFileSync(p, canonicalize(m as never) + '\n');
      expect(failed(dir)).toEqual(['signature', 'artifacts', 'refs']); // artifacts: not run on an untrusted manifest
      kl.close();
    }
    // an extra file slipped into blobs/
    {
      const { kl, dir } = fresh();
      writeFileSync(join(dir, 'blobs', 'e'.repeat(64)), 'x');
      expect(failed(dir)).toEqual(['artifacts']);
      kl.close();
    }
    // a pretty-printed manifest is not canonical
    {
      const { kl, dir } = fresh();
      const p = join(dir, 'manifest.json');
      writeFileSync(p, JSON.stringify(JSON.parse(readFileSync(p, 'utf8')), null, 2));
      expect(failed(dir)).toEqual(['canonical']);
      kl.close();
    }
  });

  it('a blob gone from the store is listed as missing (never hidden): the bundle fails unless missing is allowed', () => {
    const kl = new KronicleLite({ memory: true });
    const { resp } = seeded(kl);
    kl.db.prepare(`DELETE FROM blobs WHERE sha256 = ?`).run(resp.sha256);
    const dir = tempDir('kl-bundle-');
    const r = exportBundle({ chain: kl.chain, audit: kl.audit, signer: kl.identity.signer, audit_id: 'A1', dir });
    expect(r.manifest.missing.map((x) => x.sha256)).toEqual([resp.sha256]);
    expect(verifyBundle(dir)).toMatchObject({ ok: false, allow_missing: false, counts: { missing: 1 } });
    expect(verifyBundle(dir, { allow_missing: true })).toMatchObject({ ok: true, allow_missing: true, counts: { missing: 1 } });
    kl.close();
  });

  it('CLI: audit put-blob / record / query / export, then verify-bundle with no store', () => {
    const home = tempDir('kl-home-');
    const data = join(tempDir('kl-data-'), 'd');
    const env = cleanEnv({ HOME: home, USERPROFILE: home });
    const run = (args: string[], input?: string) => spawnSync(process.execPath, [CLI, ...args], { env, encoding: 'utf8', ...(input !== undefined ? { input } : {}) });
    const art = join(home, 'snap.json');
    writeFileSync(art, '{"tools":[]}');
    const put = run(['audit', 'put-blob', art, '--media-type', 'application/json', '--data-dir', data]);
    expect(put.status, put.stderr).toBe(0);
    const ref = JSON.parse(put.stdout) as { sha256: string; size: number };
    const line = JSON.stringify({ kind: 'catalog_snapshot', event_key: 's1', payload: { fingerprint: F1, server: { name: 'x' }, tool_count: 0, bytes: 12, snapshot: ref } });
    const rec = run(['audit', 'record', '--audit-id', 'A9', '--data-dir', data], line + '\n');
    expect(rec.status, rec.stderr).toBe(0);
    expect(rec.stdout).toMatch(/recorded 1 event\(s\), 0 already present/);
    expect(run(['audit', 'record', '--audit-id', 'A9', '--data-dir', data], line + '\n').stdout).toMatch(/recorded 0 event\(s\), 1 already present/);
    expect(run(['audit', 'query', '--fingerprint', F1, '--data-dir', data]).stdout).toMatch(/^1\tcatalog_snapshot\ts1\t/);
    const out = join(home, 'bundle');
    const ex = run(['audit', 'export', '--audit-id', 'A9', '--out', out, '--data-dir', data]);
    expect(ex.status, ex.stderr).toBe(0);
    expect(ex.stdout).toMatch(/manifest sha256 [0-9a-f]{64}/);
    rmSync(data, { recursive: true, force: true }); // offline: the store is gone
    const v = run(['verify-bundle', out]);
    expect(v.status, v.stdout + v.stderr).toBe(0);
    expect(v.stdout).toMatch(/bundle verifies: audit A9, 1 event\(s\)/);
    unlinkSync(join(out, 'blobs', ref.sha256));
    const bad = run(['verify-bundle', out, '--json']);
    expect(bad.status).toBe(1);
    expect((JSON.parse(bad.stdout) as { checks: { check: string; ok: boolean }[] }).checks.find((c) => c.check === 'artifacts')!.ok).toBe(false);
  });
});

describe('verify: batch of receipts', () => {
  it('checks up to 100 in input order; worst result is the first not VERIFIED', () => {
    const kl = new KronicleLite({ memory: true });
    kl.docs.putDocument({ slug: 'a', title: 'a', markdown: '# A\n\nalpha one.\n\nalpha two.\n', actor_id: 'h' });
    const hits = kl.recall.recall({ query: 'alpha', actor_id: 'x' }).hits;
    expect(hits.length).toBe(2);
    const ok = kl.verifier.verifyMany(hits.map((h) => h.receipt));
    expect(ok.results.map((r) => r.status)).toEqual(['VERIFIED', 'VERIFIED']);
    expect(ok.worst.status).toBe('VERIFIED');
    kl.docs.supersedeBlock({ block_id: hits[1]!.block_id, new_content: 'alpha 2.', reason: 'x', actor_id: 'h' });
    const mixed = kl.verifier.verifyMany([hits[0]!.receipt, hits[1]!.receipt, { junk: true }]);
    expect(mixed.results.map((r) => r.status)).toEqual(['VERIFIED', 'SUPERSEDED', 'UNVERIFIED']);
    expect(mixed.worst.status).toBe('SUPERSEDED');
    expect(mixed.counts).toMatchObject({ VERIFIED: 1, SUPERSEDED: 1, UNVERIFIED: 1 });
    expect(() => kl.verifier.verifyMany(Array.from({ length: 101 }, () => hits[0]!.receipt))).toThrow(/1\.\.100/);
    expect(() => kl.verifier.verifyMany([])).toThrow();
    kl.close();
  });
});
