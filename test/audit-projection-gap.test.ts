/**
 * #15 (0.9.0 blocker): mutation gap. AuditLog.checkProjection's missing-table
 * branch (src/audit/log.ts) could return null and no test failed. A store whose
 * chain holds audit events but has no audit_events table is a divergence:
 * verifyAll is not ok and verify-chain exits 1.
 */
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

import Database from 'better-sqlite3';
import { describe, expect, it } from 'vitest';

import { KronicleLite } from '../src/index.js';
import { CLI, cleanEnv, tempDir } from './helpers/fs.js';

describe('#15 audit projection: chain events without the audit_events table', () => {
  it('checkProjection names the missing table; verifyAll and verify-chain report a divergence', () => {
    const data = tempDir('kl-gap-');
    const kl = new KronicleLite({ dataDir: data });
    kl.audit.record('A', [{ kind: 'finding', event_key: 'f', payload: { finding_id: 'V', status: 'discovered', title: 't' } }], 'x');
    kl.close();
    const db = new Database(join(data, 'kronicle-lite.db'));
    db.exec('DROP TABLE audit_events');
    db.close();

    const ro = new KronicleLite({ dataDir: data, readOnly: true });
    expect(ro.audit.checkProjection()).toMatch(/1 audit events but the store has no audit_events table/);
    const v = ro.verifyAll();
    expect(v.ok).toBe(false);
    expect(v.projection?.mismatches.map((m) => m.table)).toContain('audit_events');
    ro.close();

    const home = tempDir('kl-gap-h-');
    const r = spawnSync(process.execPath, [CLI, 'verify-chain', '--data-dir', data], { env: cleanEnv({ HOME: home, USERPROFILE: home }), encoding: 'utf8' });
    expect(r.status, r.stdout + r.stderr).toBe(1);
  });
});
