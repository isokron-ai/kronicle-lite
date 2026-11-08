/**
 * verify-bundle on a hostile bundle directory: manifest.json / events.jsonl that are links to
 * devices or outside files, FIFOs, or (sparse) files too large to read must fail with ok:false
 * and a reason, never hang, abort or read outside DIR. So must a --key that is not a small
 * regular file.
 */
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync, rmSync, symlinkSync, truncateSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { exportBundle } from '../src/audit/bundle.js';
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
});
