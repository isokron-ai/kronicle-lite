/**
 * verify-bundle on a hostile bundle directory: manifest.json / events.jsonl that are links to
 * devices or outside files, FIFOs, or (sparse) files too large to read must fail with ok:false
 * and a reason, never hang, abort or read outside DIR. So must a --key that is not a small
 * regular file.
 */
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync, renameSync, rmSync, symlinkSync, truncateSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { exportBundle, signManifest, type BundleManifest } from '../src/audit/bundle.js';
import { canonicalize, type JsonValue } from '../src/crypto/canonical.js';
import { ephemeralIdentity } from '../src/crypto/keys.js';
import { verifyBundle } from '../src/audit/verify-bundle.js';
import { KronicleLite } from '../src/index.js';
import { CLI, cleanEnv, tempDir } from './helpers/fs.js';

const POSIX = process.platform !== 'win32';

function bundle(): string {
  const kl = new KronicleLite({ memory: true });
  const art = kl.audit.putBlob(Buffer.from('artifact bytes'), 'text/plain');
  kl.audit.record('A1', [{ kind: 'finding', event_key: 'f', payload: { finding_id: 'V1', status: 'discovered', detail: art } }], 'auditor');
  const dir = tempDir('kl-vbf-');
  exportBundle({ chain: kl.chain, audit: kl.audit, signer: kl.identity.signer, audit_id: 'A1', dir });
  kl.close();
  expect(verifyBundle(dir).ok).toBe(true);
  return dir;
}
const problems = (dir: string) => verifyBundle(dir).checks.map((c) => c.problem ?? '').join(' | ');

describe.skipIf(!POSIX)('verify-bundle: bundle files that are not small regular files', () => {
  for (const name of ['manifest.json', 'events.jsonl']) {
    it(`${name} linked to /dev/zero fails cleanly`, () => {
      const dir = bundle();
      rmSync(join(dir, name));
      symlinkSync('/dev/zero', join(dir, name));
      const t0 = Date.now();
      expect(verifyBundle(dir).ok).toBe(false);
      expect(Date.now() - t0).toBeLessThan(2000);
      expect(problems(dir)).toMatch(/not a regular file|symbolic link/);
    });

    it(`${name} as a FIFO fails cleanly instead of blocking`, () => {
      const dir = bundle();
      rmSync(join(dir, name));
      expect(spawnSync('mkfifo', [join(dir, name)]).status).toBe(0);
      expect(verifyBundle(dir).ok).toBe(false);
      expect(problems(dir)).toMatch(/not a regular file/);
    });

    it(`${name} linked to a regular file outside the bundle is refused`, () => {
      const dir = bundle();
      const outside = join(tempDir('kl-vbf-out-'), name);
      writeFileSync(outside, '{}\n');
      rmSync(join(dir, name));
      symlinkSync(outside, join(dir, name));
      expect(verifyBundle(dir).ok).toBe(false);
      expect(problems(dir)).toMatch(/symbolic link|not a regular file/);
    });

    it(`a sparse 3 GB ${name} is refused by size, not read`, () => {
      const dir = bundle();
      truncateSync(join(dir, name), 3 * 1024 ** 3);
      const t0 = Date.now();
      expect(verifyBundle(dir).ok).toBe(false);
      expect(Date.now() - t0).toBeLessThan(2000);
      expect(problems(dir)).toMatch(/limit/);
    });
  }

  it('a sparse 3 GB blob is reported by size, not read', () => {
    const dir = bundle();
    const [blob] = readdirSync(join(dir, 'blobs'));
    truncateSync(join(dir, 'blobs', blob!), 3 * 1024 ** 3);
    const t0 = Date.now();
    const r = verifyBundle(dir);
    expect(Date.now() - t0).toBeLessThan(2000);
    expect(r.checks.find((c) => c.check === 'artifacts')!.problem).toMatch(/size differs/);
    expect(r.checks.find((c) => c.check === 'canonical')!.ok).toBe(true);
  });

  it('CLI: --key that is a device fails with an error, not an abort', () => {
    const dir = bundle();
    const home = tempDir('kl-vbf-h-');
    const r = spawnSync(process.execPath, [CLI, 'verify-bundle', dir, '--key', '/dev/zero'], { env: cleanEnv({ HOME: home, USERPROFILE: home }), encoding: 'utf8', timeout: 20000 });
    expect(r.signal).toBeNull();
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/not a regular file/);
  });

  it('CLI: --key may be a link to a regular PEM file', () => {
    const dir = bundle();
    const home = tempDir('kl-vbf-h-');
    const m = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8')) as { root: { public_key_pem: string } };
    const keyDir = tempDir('kl-vbf-k-');
    writeFileSync(join(keyDir, 'store.pem'), m.root.public_key_pem);
    symlinkSync(join(keyDir, 'store.pem'), join(keyDir, 'link.pem'));
    const r = spawnSync(process.execPath, [CLI, 'verify-bundle', dir, '--key', join(keyDir, 'link.pem')], { env: cleanEnv({ HOME: home, USERPROFILE: home }), encoding: 'utf8' });
    expect(r.status, r.stdout + r.stderr).toBe(0);
    expect(r.stdout).toMatch(/key pinned/);
  });

  it('blobs/ symlinked to a directory outside the bundle is refused (a linked path component)', () => {
    const dir = bundle();
    const outside = tempDir('kl-vbf-blobs-');
    for (const f of readdirSync(join(dir, 'blobs'))) renameSync(join(dir, 'blobs', f), join(outside, f));
    rmSync(join(dir, 'blobs'), { recursive: true });
    symlinkSync(outside, join(dir, 'blobs'));
    const r = verifyBundle(dir);
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.check === 'artifacts')!.problem).toMatch(/blobs.*symbolic link/);
  });

  it('blobs/ that is a file, not a directory, is refused', () => {
    const dir = bundle();
    rmSync(join(dir, 'blobs'), { recursive: true });
    writeFileSync(join(dir, 'blobs'), 'x');
    expect(verifyBundle(dir).checks.find((c) => c.check === 'artifacts')!.problem).toMatch(/not a directory/);
  });

  it('a bundle reached through a symlinked DIR path still verifies (the path given is resolved once)', () => {
    const dir = bundle();
    const link = join(tempDir('kl-vbf-l-'), 'b');
    symlinkSync(dir, link);
    expect(verifyBundle(link).ok).toBe(true);
  });
});

/** Rewrite the manifest: list the first blob with a new size, optionally re-signed by an attacker key. */
function editBlobSize(dir: string, size: number, resign: boolean): string {
  const m = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8')) as BundleManifest;
  const sha = m.blobs[0]!.sha256;
  (m.blobs[0] as { size: number }).size = size;
  let out = m;
  if (resign) {
    const id = ephemeralIdentity();
    out = signManifest({ ...m, root: { ...m.root, key_id: id.signer.key_id, public_key_pem: id.signer.public_key_pem } }, id.signer);
  }
  writeFileSync(join(dir, 'manifest.json'), canonicalize(out as unknown as JsonValue) + '\n');
  truncateSync(join(dir, 'blobs', sha), size);
  return sha;
}
const rssAfter = (f: () => void) => {
  globalThis.gc?.();
  const before = process.memoryUsage().rss;
  const t0 = Date.now();
  f();
  return { mb: (process.memoryUsage().rss - before) / 1024 ** 2, ms: Date.now() - t0 };
};

describe.skipIf(!POSIX)('verify-bundle: no blob is read before the manifest is trusted, and never whole', () => {
  it('an edited manifest (signature broken) listing a 2 GB sparse blob: no blob is read', () => {
    const dir = bundle();
    editBlobSize(dir, 2 * 1024 ** 3, false);
    let r!: ReturnType<typeof verifyBundle>;
    const cost = rssAfter(() => (r = verifyBundle(dir)));
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.check === 'signature')!.ok).toBe(false);
    expect(r.checks.find((c) => c.check === 'artifacts')!.problem).toMatch(/not checked/);
    expect(cost.ms).toBeLessThan(1000);
    expect(cost.mb).toBeLessThan(100);
  });

  it('a re-signed manifest (no --key) listing a 2 GB blob: refused by the 64 MiB blob cap without reading', () => {
    const dir = bundle();
    editBlobSize(dir, 2 * 1024 ** 3, true);
    let r!: ReturnType<typeof verifyBundle>;
    const cost = rssAfter(() => (r = verifyBundle(dir)));
    expect(r.checks.find((c) => c.check === 'signature')!.ok).toBe(true);
    expect(r.checks.find((c) => c.check === 'artifacts')!.problem).toMatch(/limit/);
    expect(cost.ms).toBeLessThan(1000);
  });

  it('a re-signed manifest listing a 60 MB sparse blob: hashed as a stream, memory stays flat', () => {
    const dir = bundle();
    editBlobSize(dir, 60 * 1024 ** 2, true);
    let r!: ReturnType<typeof verifyBundle>;
    const cost = rssAfter(() => (r = verifyBundle(dir)));
    expect(r.checks.find((c) => c.check === 'artifacts')!.problem).toMatch(/does not hash/);
    expect(cost.mb).toBeLessThan(40);
  });

  it('the same edits pinned with --key fail the signature and read nothing', () => {
    const dir = bundle();
    const pem = (JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8')) as BundleManifest).root.public_key_pem;
    editBlobSize(dir, 60 * 1024 ** 2, true);
    const r = verifyBundle(dir, { public_key_pem: pem });
    expect(r.checks.find((c) => c.check === 'signature')!.ok).toBe(false);
    expect(r.checks.find((c) => c.check === 'artifacts')!.problem).toMatch(/not checked/);
  });
});
