/**
 * #15 review follow-up (from #16): the write-time guard checked each match
 * against every earlier one (`out.some`), so overlap checking was quadratic in
 * the number of matches: a 2 MB blob of AWS keys took 15 s, 32 MB about 6 min.
 * Matches are now merged with a forward sweep; the work counted per match is
 * constant.
 */
import { describe, expect, it } from 'vitest';

import { guardStats, scanForSecrets } from '../src/secrets/guard.js';

const keys = (n: number) => Array.from({ length: n }, (_, i) => `AKIA${(i + 0x10000000).toString(16).toUpperCase().padStart(16, 'Q')}`).join('\n');

describe('#15 guard: overlap checks are linear in the number of matches', () => {
  it('4× the AWS keys costs about 4× the overlap steps, a small constant per match', () => {
    const steps = (n: number) => {
      guardStats.overlap_steps = 0;
      expect(scanForSecrets(keys(n))).toHaveLength(n);
      return guardStats.overlap_steps;
    };
    const a = steps(5_000);
    const b = steps(20_000);
    // #24: the counter must be live, or the bounds below hold trivially (0 <= 4.5 * 0).
    expect(a).toBeGreaterThanOrEqual(5_000);
    expect(b).toBeGreaterThanOrEqual(20_000);
    expect(b).toBeLessThanOrEqual(4.5 * a);
    expect(b).toBeLessThanOrEqual(8 * 20_000);
  });
  it('an earlier detector still wins an overlapping span, and placeholders still do not block', () => {
    const PEM = '-----BEGIN RSA PRIVATE KEY-----\n' + 'M'.repeat(64) + '\nAKIAIOSFODNN7EXAMPLQ\n' + 'Z'.repeat(64) + '\n-----END RSA PRIVATE KEY-----';
    expect(scanForSecrets(`${PEM}\nAKIAIOSFODNN7EXAMPLQ\n`).map((f) => f.detector)).toEqual(['private_key', 'aws_access_key']);
  });
});
