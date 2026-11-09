/**
 * KL-11 (dogfood): `orient --bogus` exited 0: unknown options were ignored, so a misspelt flag
 * (`verify-bundle --max-byte N`) silently ran with the default. Every command now has an option
 * table (src/cli-flags.ts, ported from mcp-catalog-snap 0.2.0): unknown, repeated or mis-valued
 * options and stray positionals exit 2 with a reason, before anything is opened.
 */
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { COMMAND_OPTIONS } from '../src/cli-flags.js';
import { CLI, cleanEnv, tempDir } from './helpers/fs.js';

const run = (args: string[]) => {
  const home = tempDir('kl-strict-');
  const data = join(home, 'd');
  const r = spawnSync(process.execPath, [CLI, ...args, '--data-dir', data], { env: cleanEnv({ HOME: home, USERPROFILE: home }), encoding: 'utf8' });
  return { ...r, created: existsSync(data) };
};

describe('strict CLI options', () => {
  it.each([
    [['orient', '--bogus'], /unknown option --bogus for orient/],
    [['verify-bundle', '/nonexistent', '--max-byte', '10'], /unknown option --max-byte for verify-bundle \(did you mean --max-bytes\?\)/],
    [['verify-chain', '--form', '3'], /did you mean --from\?/],
    [['export', '--out', 'a', '--out', 'b'], /--out given more than once/],
    [['orient', '--json=yes'], /--json takes no value/],
    [['put', 'slug', 'file.md', 'extra'], /unexpected argument "extra" for put/],
    [['keys', 'extra'], /unexpected argument "extra" for keys/],
    [['orient', '--__proto__', 'x'], /unknown option --__proto__/],
    [['doctor', '--no-netwrok'], /did you mean --no-network\?/],
    // value-taking options given no value: an error, never silently ignored (a bare --key ran unauthenticated)
    [['verify-bundle', '/nonexistent', '--key'], /--key needs a value/],
    [['orient', '--cursor'], /--cursor needs a value/],
    [['put', 'slug', 'file.md', '--title'], /--title needs a value/],
    // each subcommand has its own options
    [['audit', 'put-blob', 'f.bin', '--findings'], /unknown option --findings for audit put-blob/],
    [['audit', 'query', '--out', 'x'], /unknown option --out for audit query/],
    [['anchor', 'keys', '--key', 'k'], /unknown option --key for anchor keys/],
    [['audit', '--json'], /audit needs a subcommand first/],
    // pulse and the shim subcommands parse their own argv, with the same rules
    [['pulse', '--bogus'], /unknown option --bogus for pulse/],
    [['pulse', '--state'], /--state needs a value/],
    [['shim', 'status', '--bogus'], /unknown option --bogus for shim status/],
    [['shim', 'ack', '--through'], /--through needs a value/],
  ])('%j exits 2 with a reason and touches no store', (args, why) => {
    const r = run(args as string[]);
    expect(r.status, r.stdout + r.stderr).toBe(2);
    expect(r.stderr).toMatch(why as RegExp);
    expect(r.created).toBe(false);
  });

  it('known options still work, booleans accept true / false, repeatable options accumulate', () => {
    expect(run(['orient', '--actor', 'a', '--json']).status).toBe(0);
    expect(run(['audit', 'query', '--audit-id', 'A', '--findings', '--json']).status).toBe(0);
    expect(run(['pulse', '--json']).status).not.toBe(2);
    expect(run(['orient', '--json=true']).status).toBe(0);
    expect(run(['verify-chain', '--full']).status).toBe(0);
  });

  it('--data-dir with no value is an error', () => {
    const home = tempDir('kl-strict-');
    const r = spawnSync(process.execPath, [CLI, 'orient', '--data-dir'], { env: cleanEnv({ HOME: home, USERPROFILE: home }), encoding: 'utf8' });
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/--data-dir needs a value/);
  });

  it('every command in the option table is a real command (help lists it)', () => {
    const help = spawnSync(process.execPath, [CLI, 'help'], { encoding: 'utf8' }).stdout;
    for (const cmd of Object.keys(COMMAND_OPTIONS)) expect(help, cmd).toMatch(new RegExp(`kronicle-lite ${cmd}\\b`));
  });
});
