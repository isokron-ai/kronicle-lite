/**
 * #24: the write-time env_secret regex (`^…[A-Z0-9_]*(?:PASSWORD|…)[A-Z0-9_]*…`)
 * backtracked quadratically on one long line of name characters: `PASSWORD`
 * repeated took 0.5 / 2.1 / 7.7 s at 64 / 128 / 256 KB in putDocument (an 8 MB
 * MCP document: about 2 hours). It is now matched by a linear scan with the
 * same matches; guardStats.scan_steps counts the characters it examines.
 */
import { describe, expect, it } from 'vitest';

import { guardStats, scanForSecrets, WRITE_DETECTORS } from '../src/secrets/guard.js';

describe('#24 env_secret: linear work, same matches as its regex', () => {
  const env = WRITE_DETECTORS.find((d) => d.id === 'env_secret')!;
  it('one 256 KB line of PASSWORD costs a bounded number of steps per character', () => {
    for (const n of [64 * 1024, 256 * 1024]) {
      const line = 'PASSWORD'.repeat(n / 8);
      guardStats.scan_steps = 0;
      expect(scanForSecrets(line)).toEqual([]);
      expect(guardStats.scan_steps).toBeGreaterThanOrEqual(n);
      expect(guardStats.scan_steps).toBeLessThanOrEqual(3 * n);
    }
    // Also with a separator and a value at the end, and as many lines.
    const long = 'A_'.repeat(64 * 1024) + 'API_KEY=Zq9xT2vLmP4k\n';
    guardStats.scan_steps = 0;
    expect(scanForSecrets(long).map((f) => f.detector)).toEqual(['env_secret']);
    expect(guardStats.scan_steps).toBeLessThanOrEqual(3 * long.length);
  });
  it('agrees with the regex on random token soup', () => {
    const parts = ['export ', 'export\t', '  ', '\t', 'DB_', 'PASSWORD', 'PASSWD', 'SECRET', 'TOKEN', 'API_KEY', 'APIKEY', 'ACCESS_KEY', 'PRIVATEKEY', 'X', '9', '_', '=', ':', ' = ', '"', "'", '#', 'Zq9xT2vL', 'mP4k', 'a1', '\n', '\r\n', '\r', ' ', 'x', '-', 'é', ' '];
    let seed = 11;
    const rnd = (n: number) => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) % n);
    for (let i = 0; i < 5000; i++) {
      let s = '';
      for (let j = rnd(20); j >= 0; j--) s += parts[rnd(parts.length)];
      const want = [...s.matchAll(new RegExp(env.re.source, env.re.flags))].map((m) => [m.index, m[0], m[1]]);
      const got = [...env.find!(s)].map((m) => [m.index, m[0], m[1]]);
      expect(got, JSON.stringify(s)).toEqual(want);
    }
  });
});
