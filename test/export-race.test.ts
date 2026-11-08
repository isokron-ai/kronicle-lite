/**
 * #15 (0.9.0 blocker): export race. `audit export` checked --out and then
 * wrote by path, so swapping `blobs/` or the out dir for a link mid-export
 * created new files in the victim directory. Writes now go through a working
 * directory pinned to the inode that was checked (openat-style), and the
 * export fails if either directory was swapped.
 */
import { mkdirSync, readdirSync, renameSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { exportBundle } from '../src/audit/bundle.js';
import type { AuditLog, BlobRow } from '../src/audit/log.js';
import { KronicleLite } from '../src/index.js';
import { tempDir } from './helpers/fs.js';

const POSIX = process.platform !== 'win32';

function build() {
  const kl = new KronicleLite({ memory: true });
  const a = kl.audit.putBlob(Buffer.from('first artifact'), 'text/plain');
  const b = kl.audit.putBlob(Buffer.from('second artifact'), 'text/plain');
  kl.audit.record(
    'A',
    [a, b].map((r, i) => ({ kind: 'finding' as const, event_key: `f${i}`, payload: { finding_id: `V${i}`, status: 'discovered', detail: { sha256: r.sha256, size: r.size } } })),
    'x',
  );
  return kl;
}

/** An AuditLog whose blob bytes run `swap` the first time any of them is read: the attacker's move, mid-export. */
function racing(audit: AuditLog, swap: () => void): AuditLog {
  let done = false;
  return new Proxy(audit, {
    get(t, k, r) {
      if (k !== 'getBlob') return Reflect.get(t, k, r) as unknown;
      return (sha: string): BlobRow | null => {
        const row = t.getBlob(sha);
        if (!row) return row;
        const bytes = row.bytes;
        return Object.defineProperty({ ...row }, 'bytes', {
          get() {
            if (!done) {
              done = true;
              swap();
            }
            return bytes;
          },
        });
      };
    },
  });
}

/** Swap a directory for a link to `victim` right before the export's chdir into it (`target` as the export passes it). */
function swapOnChdir(target: string, dir: string, victim: string) {
  const real = process.chdir.bind(process);
  let done = false;
  vi.spyOn(process, 'chdir').mockImplementation((to: string) => {
    if (!done && to === target) {
      done = true;
      renameSync(dir, `${dir}.moved`);
      symlinkSync(victim, dir);
    }
    real(to);
  });
}
afterEach(() => {
  vi.restoreAllMocks();
});

describe('#15 export race: a directory swapped for a link mid-export', () => {
  it.skipIf(!POSIX)('the out dir swapped right before the export enters it: refused, nothing written to the victim', () => {
    const kl = build();
    const out = join(tempDir('race-parent-'), 'bundle');
    const victim = tempDir('race-victim-');
    swapOnChdir(out, out, victim);
    expect(() => exportBundle({ chain: kl.chain, audit: kl.audit, signer: kl.identity.signer, audit_id: 'A', dir: out })).toThrow(/changed during export/);
    expect(readdirSync(victim)).toEqual([]);
    kl.close();
  });
  it.skipIf(!POSIX)('blobs/ swapped right after it is made, before the export enters it: refused, nothing written to the victim', () => {
    const kl = build();
    const out = join(tempDir('race-parent-'), 'bundle');
    const victim = tempDir('race-victim-');
    swapOnChdir('blobs', join(out, 'blobs'), victim);
    expect(() => exportBundle({ chain: kl.chain, audit: kl.audit, signer: kl.identity.signer, audit_id: 'A', dir: out })).toThrow(/changed during export/);
    expect(readdirSync(victim)).toEqual([]);
    kl.close();
  });
  it.skipIf(!POSIX)('blobs/ swapped for a link: nothing is created in the victim, and the export fails', () => {
    const kl = build();
    const out = join(tempDir('race-out-'), 'bundle');
    const victim = tempDir('race-victim-');
    const audit = racing(kl.audit, () => {
      renameSync(join(out, 'blobs'), join(out, 'moved'));
      symlinkSync(victim, join(out, 'blobs'));
    });
    const cwd = process.cwd();
    expect(() => exportBundle({ chain: kl.chain, audit, signer: kl.identity.signer, audit_id: 'A', dir: out })).toThrow(/changed during export/);
    expect(readdirSync(victim)).toEqual([]);
    expect(process.cwd()).toBe(cwd);
    kl.close();
  });
  it.skipIf(!POSIX)('the out dir swapped for a link: nothing is created in the victim, and the export fails', () => {
    const kl = build();
    const parent = tempDir('race-parent-');
    const out = join(parent, 'bundle');
    const victim = tempDir('race-victim-');
    mkdirSync(join(victim, 'blobs'));
    const audit = racing(kl.audit, () => {
      renameSync(out, join(parent, 'moved'));
      symlinkSync(victim, out);
    });
    expect(() => exportBundle({ chain: kl.chain, audit, signer: kl.identity.signer, audit_id: 'A', dir: out })).toThrow(/changed during export/);
    expect(readdirSync(victim)).toEqual(['blobs']);
    expect(readdirSync(join(victim, 'blobs'))).toEqual([]);
    kl.close();
  });
  it('without a race the export is unchanged and the working directory is restored', () => {
    const kl = build();
    const cwd = process.cwd();
    const out = join(tempDir('race-ok-'), 'bundle');
    const r = exportBundle({ chain: kl.chain, audit: kl.audit, signer: kl.identity.signer, audit_id: 'A', dir: out });
    expect(r.manifest.blobs).toHaveLength(2);
    expect(readdirSync(join(out, 'blobs'))).toHaveLength(2);
    expect(process.cwd()).toBe(cwd);
    kl.close();
  });
});
