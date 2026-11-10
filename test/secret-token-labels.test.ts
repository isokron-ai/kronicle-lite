/**
 * 0.11.2: "token" is also a unit of measure. An evidence summary line
 * `Tokens: cl100k` (a count label naming the tokenizer) was refused as a
 * password_assignment: the key ends in `tokens` and `cl100k` has a letter and
 * a digit. Under a key whose only sensitive word is token(s), the value now
 * has to look like an issued credential (16+ chars at 3+ bits/char, or a
 * mixed-case alphanumeric run of 8+ with a digit); a count is never one.
 * Real tokens, passwords and provider keys are still refused and scrubbed.
 *
 * Fake secrets are assembled at runtime so this file never contains one literally.
 */

import { describe, expect, it } from 'vitest';

import { scanForSecrets, scrubForRead, SecretDetectedError } from '../src/secrets/guard.js';
import { KronicleLite } from '../src/store.js';

const j = (...p: string[]) => p.join('');

const MEASUREMENTS = [
  'Tokens: cl100k',
  'tokens: 1,234',
  'token_count: 52',
  'max_tokens: 4096',
  'Tokenizer: cl100k_base',
  'Tokens: o200k_base',
  'Tokens: p50k_edit',
  'Tokens: cl100k (est.)',
  'input_tokens: 12345',
  'output_tokens=1.2k',
  'total_tokens: 128000k',
  'tokens: 12.5M/day',
  '"tokens": "cl100k_base"',
  'TOKENIZER=cl100k_base',
  'TOKENS: o200k_base',
  'MAX_TOKENS=128000',
];

const SECRETS: [string, string][] = [
  ['token: ghp_…', j('token: ', 'ghp', '_', 'R8bX2kLq9Wm4Tz7Yc1Vn5Hd3Jf6Gs0Pa8Ue2')],
  ['api_key = sk-ant-…', j('api_key = ', 'sk-', 'ant-', 'api03-', 'Qm8Zt2Lx9Rk4Wb7Nc1Vd5Hf3Jg6Ys0Pa8Ue2Tq')],
  ['Authorization: Bearer eyJ…', j('Authorization: Bearer ', 'eyJ', 'hbGciOiJIUzI1NiJ9', '.', 'eyJ', 'zdWIiOiIxMjM0NTY3ODkwIn0', '.', 'dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U')],
  ['Authorization: Bearer (opaque)', j('Authorization: Bearer ', 'Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA')],
  ['password: hunter2!x', j('pass', 'word: ', 'hunter', '2!x')],
  ['AWS access key id', j('AKIA', 'ZQ7W3XKD9PL2M4NB')],
  ['token: high-entropy random', j('token: ', 'Zq8xK2mP9vL4nR7tY3wB')],
  ['tokens: high-entropy hex', j('tokens: ', '9f8e7d6c5b4a39281706f5e4d3c2b1a0')],
  ['auth_token: hex', j('auth_token: ', '9f8e7d6c5b4a39281706f5e4d3c2b1a0')],
  ['apiToken: base64', j('apiToken: "', 'c2VjcmV0LXZhbHVlLTEyMzQ1', '"')],
  ['session_token: short mixed-case', j('session_token=', 'x9Kp2Lq7')],
  ['SERVICE_TOKEN env', j('SERVICE_', 'TOKEN=', 'h7Gq2xLp9vRt')],
  ['ACCESS_TOKEN env', j('ACCESS_', 'TOKEN=', '9f8e7d6c5b4a39281706')],
  ['DATABASE_PASSWORD env', j('DATABASE_', 'PASSWORD', '=', 'h7Gq2xLp9vRt')],
  ['secret: short', j('sec', 'ret: ', 'aB3dE5gH7jK9')],
];
/** The read-time ruleset has no AWS secret access key rule (it masks only what it can see without context). */
const AWS_SECRET = j('aws_secret_access_key = ', 'wJalrXUtnFEMI/K7MDENG/', 'bPxRfiCYzz9x8Q2kLm');

describe('0.11.2: token-count labels are not secrets', () => {
  it.each(MEASUREMENTS)('%s passes the write scan and the read scrub', (s) => {
    expect(scanForSecrets(s), s).toEqual([]);
    expect(scrubForRead(s), s).toEqual({ text: s, detectors: [] });
  });

  it('an evidence summary carrying the labels is stored without a refusal', () => {
    const store = new KronicleLite({ memory: true });
    const md = `# Evidence run\n\n${MEASUREMENTS.join('\n')}\n`;
    const r = store.docs.putDocument({ slug: 'run', title: 'Run', markdown: md, actor_id: 't' });
    expect(r.redactions ?? []).toEqual([]);
    store.close();
  });
});

describe('0.11.2: real secrets after a token key (and others) are still caught', () => {
  it.each(SECRETS)('%s is refused at write time and masked at read time', (_name, s) => {
    expect(scanForSecrets(s).length, s).toBeGreaterThan(0);
    const value = s.slice(s.search(/[:= ]\s*/) + 1).trim().replace(/^"|"$/g, '');
    expect(scrubForRead(s).text, s).not.toContain(value.slice(-12));
  });

  it('an AWS secret access key is refused at write time', () => {
    expect(scanForSecrets(AWS_SECRET).map((f) => f.detector)).toEqual(['aws_secret_key']);
  });

  it('a store refuses them beside a measurement label', () => {
    const store = new KronicleLite({ memory: true });
    for (const [name, s] of [...SECRETS, ['AWS secret access key', AWS_SECRET] as [string, string]]) {
      expect(() => store.docs.putDocument({ slug: 'run', title: 'Run', markdown: `# Run\n\nTokens: cl100k\n${s}\n`, actor_id: 't' }), name).toThrow(SecretDetectedError);
    }
    store.close();
  });
});
