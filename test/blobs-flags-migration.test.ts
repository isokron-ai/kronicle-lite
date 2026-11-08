/**
 * #15 (0.9.0 blocker): `blobs.flags` was missing from ADDED_COLUMNS, so a store
 * made by an unreleased 0.9.0 dev build (blobs table without `flags`) was never
 * migrated: every put-blob failed with "table blobs has no column named flags".
 */
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';

import Database from 'better-sqlite3';
import { describe, expect, it } from 'vitest';

import { exportBundle } from '../src/audit/bundle.js';
import { KronicleLite } from '../src/index.js';
import { tempDir } from './helpers/fs.js';

describe('#15 migration: blobs.flags on a dev store', () => {
  it('a blobs table without flags gains it on open; old rows read as unflagged; new rows store flags', () => {
    const data = tempDir('kl-flags-');
    let kl = new KronicleLite({ dataDir: data });
    const old = kl.audit.putBlob(Buffer.from('an artifact from the dev build'), 'text/plain');
    kl.close();
    const db = new Database(join(data, 'kronicle-lite.db'));
    db.exec('ALTER TABLE blobs DROP COLUMN flags');
    db.close();

    kl = new KronicleLite({ dataDir: data });
    const cols = (kl.db.prepare(`SELECT name FROM pragma_table_info('blobs')`).all() as { name: string }[]).map((c) => c.name);
    expect(cols).toContain('flags');
    expect(kl.audit.getBlob(old.sha256)!.flags).toBeNull();
    const cut = kl.audit.putBlob(gzipSync(Buffer.from('a'.repeat(5000))).subarray(0, 30), 'application/gzip');
    expect(cut.unscanned).toEqual(['unscanned_encoding']);
    expect(kl.audit.getBlob(cut.sha256)!.flags).toBe('unscanned_encoding');
    kl.audit.record(
      'A',
      [
        { kind: 'finding', event_key: 'f1', payload: { finding_id: 'V1', status: 'discovered', detail: { sha256: old.sha256, size: old.size } } },
        { kind: 'finding', event_key: 'f2', payload: { finding_id: 'V2', status: 'discovered', detail: { sha256: cut.sha256, size: cut.size } } },
      ],
      'x',
    );
    const m = exportBundle({ chain: kl.chain, audit: kl.audit, signer: kl.identity.signer, audit_id: 'A', dir: join(tempDir('kl-flags-out-'), 'b') }).manifest;
    expect(m.blobs.map((b) => b.unscanned_encoding === true).sort()).toEqual([false, true]);
    kl.close();
  });
});
