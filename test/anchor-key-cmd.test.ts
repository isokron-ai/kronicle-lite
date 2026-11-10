/**
 * 0.11.1 (GL-6, PH-10): the anchor key from a file or a command, and audit mode.
 *
 * Key sources, first match wins: --anchor-key-file (or --key) > KRONICLE_ANCHOR_KEY_CMD >
 * KRONICLE_ANCHOR_KEY > config.json. The command runs without a shell, with a timeout, its stderr
 * never shown; the key never appears in stdout, stderr or any file written.
 *
 * Audit mode: `audit stamp`, and `checkpoint --push` over a range holding a /3 audit, fail (exit 2)
 * on a missing key, an unreachable anchor service or a failed TSA, and write no `.pending` marker;
 * only `audit stamp --allow-pending` writes one (verify-audit-profile.test.ts: such a pack fails).
 */

import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { anchorKeySource, readAnchorKeyFile, resolveAnchorKey, runAnchorKeyCommand, splitCommand } from '../src/anchor/key-source.js';
import { KronicleLite } from '../src/index.js';
import { startAnchorStub, STUB_GENESIS, STUB_LICENSE, type AnchorBackend } from './helpers/anchor-stub.js';
import { cleanEnv, runCli, tempDir } from './helpers/fs.js';
import { makeTsa, serveTsa } from './helpers/tsa.js';

const KEY = STUB_LICENSE;
const CANARY = 'STDERR-CANARY-5e1f';
const AUDIT = 'audit-key-cmd';
const H = 'ab'.repeat(32);
const DEAD = 'http://127.0.0.1:9/';

let backend: AnchorBackend;
let scripts: string;
let printKey: string;
beforeAll(async () => {
  backend = await startAnchorStub();
  // The key command lives outside every directory a test scans; it reads the key from the
  // environment, prints a canary (and the key) on stderr, and fails or hangs on request.
  scripts = tempDir('kl-keycmd-scripts-');
  printKey = join(scripts, 'print-key.mjs');
  writeFileSync(
    printKey,
    [
      `process.stderr.write(${JSON.stringify(CANARY)} + ' ' + (process.env.KL_TEST_SECRET ?? '') + '\\n');`,
      `const mode = process.argv[2] ?? 'ok';`,
      `if (mode === 'fail') process.exit(3);`,
      `if (mode === 'hang') setTimeout(() => {}, 120000);`,
      `else process.stdout.write((process.env.KL_TEST_SECRET ?? '') + '\\n');`,
    ].join('\n'),
  );
});
afterAll(async () => {
  await backend.stop();
});

const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
const keyCmd = (mode = 'ok') => `${q(process.execPath)} ${q(printKey)} ${mode}`;
const secretEnv = { KL_TEST_SECRET: KEY };

function keyFile(content = `${KEY}\n`): string {
  const p = join(tempDir('kl-keyfile-'), 'anchor-key');
  writeFileSync(p, content, { mode: 0o600 });
  chmodSync(p, 0o600);
  return p;
}

/** Every file under each directory, recursively. */
function filesUnder(...dirs: string[]): string[] {
  const out: string[] = [];
  const walk = (d: string) => {
    if (!existsSync(d)) return;
    for (const f of readdirSync(d)) {
      const p = join(d, f);
      if (statSync(p).isDirectory()) walk(p);
      else out.push(p);
    }
  };
  dirs.forEach(walk);
  return out;
}

/** The key is in none of the outputs and none of the files under `dirs` (the store, its WAL, stamps). */
function expectNoKey(outputs: string[], ...dirs: string[]): void {
  for (const o of outputs) expect(o.includes(KEY)).toBe(false);
  for (const o of outputs) expect(o.includes(CANARY)).toBe(false);
  const files = filesUnder(...dirs);
  expect(files.length).toBeGreaterThan(0);
  for (const f of files) expect(readFileSync(f).includes(KEY), f).toBe(false);
}

function storeWith(audit: 'v3' | 'none'): string {
  const dataDir = tempDir('kl-keycmd-store-');
  const store = new KronicleLite({ dataDir });
  try {
    if (audit === 'v3') {
      const manifest = store.audit.putBlob(Buffer.from('harness'), 'text/plain');
      store.audit.record(AUDIT, [{ kind: 'harness_frozen', event_key: 'freeze', payload: { harness_id: 'h', fingerprint: H, manifest, plan: ['run-1'] } }], 'auditor');
    } else {
      store.docs.putDocument({ slug: 'n', title: 'n', markdown: '# n\n', actor_id: 'a' });
    }
  } finally {
    store.close();
  }
  return dataDir;
}

function counts(dataDir: string): { checkpoints: number; anchors: number } {
  const store = new KronicleLite({ dataDir });
  try {
    return { checkpoints: store.chain.latestCheckpoint() ? 1 : 0, anchors: store.chain.listAnchors().length };
  } finally {
    store.close();
  }
}

const cli = (args: string[], env: Record<string, string> = {}) => runCli(args, { env: cleanEnv({ KRONICLE_ANCHOR_GENESIS: STUB_GENESIS, ...env }) });
const pendingIn = (dir: string) => (existsSync(dir) ? readdirSync(dir).filter((f) => f.endsWith('.pending')) : []);

describe('KRONICLE_ANCHOR_KEY_CMD: splitting without a shell', () => {
  it('splits words with sh-style quotes', () => {
    expect(splitCommand('security find-generic-password -w -s kronicle-anchor')).toEqual(['security', 'find-generic-password', '-w', '-s', 'kronicle-anchor']);
    expect(splitCommand('op read "op://Private/kronicle anchor/credential"')).toEqual(['op', 'read', 'op://Private/kronicle anchor/credential']);
    expect(splitCommand(`'/opt/my tools/get-key' a\\ b "x\\"y" ''`)).toEqual(['/opt/my tools/get-key', 'a b', 'x"y', '']);
  });

  it('refuses shell syntax it would not interpret, and unbalanced quotes', () => {
    for (const bad of ['cat key | tr -d x', 'echo $KEY', 'get; rm -rf x', 'get > out', 'get `id`', 'echo "$HOME"', "op read 'x", 'op read "x', '   ']) {
      expect(() => splitCommand(bad), bad).toThrow(/KRONICLE_ANCHOR_KEY_CMD/);
    }
    // quoted, the same characters are plain arguments
    expect(splitCommand(`printf '%s' 'a|b;c$d'`)).toEqual(['printf', '%s', 'a|b;c$d']);
  });
});

describe('anchor key sources and their order', () => {
  it('--anchor-key-file > KRONICLE_ANCHOR_KEY_CMD > KRONICLE_ANCHOR_KEY > config.json; a failing source never falls through', () => {
    const file = keyFile('KLA_from-file\n');
    const env = { ...secretEnv, KRONICLE_ANCHOR_KEY_CMD: keyCmd(), KRONICLE_ANCHOR_KEY: 'KLA_from-env' };
    expect(resolveAnchorKey({ licenseKeyFile: file, env, configKey: 'KLA_from-config' })).toEqual({ key: 'KLA_from-file', source: 'file' });
    expect(resolveAnchorKey({ env, configKey: 'KLA_from-config' })).toEqual({ key: KEY, source: 'command' });
    expect(resolveAnchorKey({ env: { KRONICLE_ANCHOR_KEY: 'KLA_from-env' }, configKey: 'KLA_from-config' })).toEqual({ key: 'KLA_from-env', source: 'env' });
    expect(resolveAnchorKey({ env: {}, configKey: 'KLA_from-config' })).toEqual({ key: 'KLA_from-config', source: 'config' });
    expect(resolveAnchorKey({ env: {} })).toBeNull();
    expect(resolveAnchorKey({ licenseKey: 'KLA_flag', env })).toEqual({ key: 'KLA_flag', source: 'flag' });
    expect(() => resolveAnchorKey({ licenseKey: 'KLA_flag', licenseKeyFile: file, env })).toThrow(/--key or --anchor-key-file, not both/);
    // a command that fails is an error, even with KRONICLE_ANCHOR_KEY set
    expect(() => resolveAnchorKey({ env: { ...env, KRONICLE_ANCHOR_KEY_CMD: keyCmd('fail') } })).toThrow(/exited with status 3/);
    // the file wins: the failing command is never run
    expect(resolveAnchorKey({ licenseKeyFile: file, env: { ...env, KRONICLE_ANCHOR_KEY_CMD: keyCmd('fail') } })?.source).toBe('file');
  });

  it('anchorKeySource names the source without running the command or reading the file', () => {
    const start = Date.now();
    expect(anchorKeySource({ env: { KRONICLE_ANCHOR_KEY_CMD: keyCmd('hang') } })).toBe('command');
    expect(anchorKeySource({ licenseKeyFile: '/nonexistent/key', env: {} })).toBe('file');
    expect(anchorKeySource({ env: {} })).toBeNull();
    expect(Date.now() - start).toBeLessThan(1000);
  });

  it('key file: trailing newline trimmed; empty, multi-line, oversized or not a file is refused without showing the content', () => {
    expect(readAnchorKeyFile(keyFile())).toBe(KEY);
    expect(() => readAnchorKeyFile(keyFile(''))).toThrow(/empty key/);
    const two = keyFile(`${KEY}\nsecond-line-secret\n`);
    expect(() => readAnchorKeyFile(two)).toThrow(/single-line key/);
    try {
      readAnchorKeyFile(two);
    } catch (e) {
      expect((e as Error).message).not.toContain(KEY);
      expect((e as Error).message).not.toContain('second-line-secret');
    }
    expect(() => readAnchorKeyFile(keyFile('x'.repeat(5000)))).toThrow(/larger than 4096 bytes/);
    expect(() => readAnchorKeyFile(tempDir('kl-keyfile-dir-'))).toThrow(/not a regular file|cannot open \((EISDIR|EPERM|EACCES)\)/); // Windows cannot open a directory
    expect(() => readAnchorKeyFile('/nonexistent/anchor-key')).toThrow(/cannot open \(ENOENT\)/);
  });

  it('command: stdout is the key; a failure, a missing program and a timeout are errors that show neither stdout nor stderr', () => {
    expect(runAnchorKeyCommand(keyCmd(), { env: { ...process.env, ...secretEnv } })).toBe(KEY);
    const messages: string[] = [];
    const fails = (cmd: string, re: RegExp, timeoutMs?: number) => {
      try {
        runAnchorKeyCommand(cmd, { env: { ...process.env, ...secretEnv }, ...(timeoutMs ? { timeoutMs } : {}) });
        expect.unreachable(cmd);
      } catch (e) {
        expect((e as Error).message).toMatch(re);
        messages.push((e as Error).message);
      }
    };
    fails(keyCmd('fail'), /KRONICLE_ANCHOR_KEY_CMD \(.+\) exited with status 3; its output is not shown/);
    fails('kronicle-no-such-program-xyz --print', /kronicle-no-such-program-xyz not found/);
    const start = Date.now();
    fails(keyCmd('hang'), /timed out after 300 ms/, 300);
    expect(Date.now() - start).toBeLessThan(10_000);
    for (const m of messages) {
      expect(m).not.toContain(KEY);
      expect(m).not.toContain(CANARY);
    }
  });

  it('the command does not receive KRONICLE_ANCHOR_KEY', () => {
    // print-key prints KL_TEST_SECRET; point it at nothing and check the env key does not leak in under another name
    const dump = join(scripts, 'env-dump.mjs');
    writeFileSync(dump, `process.stdout.write(process.env.KRONICLE_ANCHOR_KEY ? 'KLA_leaked' : 'KLA_clean');`);
    expect(runAnchorKeyCommand(`${q(process.execPath)} ${q(dump)}`, { env: { ...process.env, KRONICLE_ANCHOR_KEY: 'KLA_env' } })).toBe('KLA_clean');
  });
});

describe('CLI: checkpoint --push with each key source; the key is never printed or written', () => {
  it('--anchor-key-file, KRONICLE_ANCHOR_KEY_CMD and KRONICLE_ANCHOR_KEY each anchor; nothing shows the key', async () => {
    for (const how of ['file', 'command', 'env'] as const) {
      const dataDir = storeWith('none');
      const args = ['checkpoint', '--push', '--data-dir', dataDir, '--url', backend.url];
      const r =
        how === 'file'
          ? await cli([...args, '--anchor-key-file', keyFile()], { ...secretEnv, KRONICLE_ANCHOR_KEY_CMD: keyCmd('fail') })
          : how === 'command'
            ? await cli(args, { ...secretEnv, KRONICLE_ANCHOR_KEY_CMD: keyCmd(), KRONICLE_ANCHOR_KEY: 'KLA_wrong-env-key' })
            : await cli(args, { KRONICLE_ANCHOR_KEY: KEY });
      expect(r.status, `${how}: ${r.stderr}`).toBe(0);
      expect(r.stderr).toMatch(/^anchored \[1, \d+\]/);
      expect(counts(dataDir).anchors).toBe(1);
      if (how !== 'env') expectNoKey([r.stdout, r.stderr], dataDir);
    }
  });

  it('a failing or hanging key command: exit 2, the reason named, its stderr not shown', async () => {
    const dataDir = storeWith('none');
    const failed = await cli(['checkpoint', '--push', '--data-dir', dataDir, '--url', backend.url], { ...secretEnv, KRONICLE_ANCHOR_KEY_CMD: keyCmd('fail'), KRONICLE_ANCHOR_KEY: KEY });
    expect(failed.status).toBe(2);
    expect(failed.stderr).toMatch(/push failed: KRONICLE_ANCHOR_KEY_CMD \(.+\) exited with status 3/);
    const hung = await cli(['checkpoint', '--push', '--data-dir', dataDir, '--url', backend.url], { ...secretEnv, KRONICLE_ANCHOR_KEY_CMD: keyCmd('hang'), KRONICLE_ANCHOR_KEY_CMD_TIMEOUT_MS: '300' });
    expect(hung.status).toBe(2);
    expect(hung.stderr).toMatch(/timed out after 300 ms/);
    expect(counts(dataDir).anchors).toBe(0);
    expectNoKey([failed.stdout, failed.stderr, hung.stdout, hung.stderr], dataDir);
  });

  it('anchor status counts a key command as configured without running it', async () => {
    const dataDir = storeWith('none');
    const r = await cli(['anchor', 'status', '--data-dir', dataDir, '--url', backend.url, '--json'], { KRONICLE_ANCHOR_KEY_CMD: keyCmd('hang') });
    expect(r.status, r.stderr).toBe(0);
    expect(JSON.parse(r.stdout)).toMatchObject({ license_key_configured: true });
  });
});

describe('audit mode: no key, no service or no TSA fails the milestone and records nothing pending', () => {
  let tsaGood: { url: string; stop(): Promise<void> };
  let tsaOther: { url: string; stop(): Promise<void> };
  beforeAll(async () => {
    tsaGood = await serveTsa(makeTsa({ name: 'Alpha' }));
    tsaOther = await serveTsa(makeTsa({ name: 'Beta' }));
  });
  afterAll(async () => {
    await Promise.all([tsaGood.stop(), tsaOther.stop()]);
  });

  it('checkpoint --push over a /3 freeze without a key: exit 2, nothing stored, nothing pending', async () => {
    const dataDir = storeWith('v3');
    const r = await cli(['checkpoint', '--push', '--data-dir', dataDir, '--url', backend.url]);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(new RegExp(`^audit mode \\(${AUDIT}\\): refusing to checkpoint --push, the anchor key is not available: no license key: pass --anchor-key-file PATH`, 'm'));
    expect(r.stderr).toMatch(/nothing is recorded as pending/);
    expect(r.stdout).toBe('');
    expect(counts(dataDir)).toEqual({ checkpoints: 0, anchors: 0 });
    // outside audit mode the 0.11.0 behaviour stays: the checkpoint is stored, the push fails, exit 2
    const plain = storeWith('none');
    const p = await cli(['checkpoint', '--push', '--data-dir', plain, '--url', backend.url]);
    expect(p.status).toBe(2);
    expect(p.stderr).toMatch(/stored locally; push failed: no license key/);
    expect(counts(plain)).toEqual({ checkpoints: 1, anchors: 0 });
  });

  it('checkpoint --push over a /3 freeze with the service unreachable: exit 2, named as the milestone anchor', async () => {
    const dataDir = storeWith('v3');
    const r = await cli(['checkpoint', '--push', '--data-dir', dataDir, '--url', DEAD, '--anchor-key-file', keyFile()]);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(new RegExp(`audit mode \\(${AUDIT}\\): the milestone anchor over \\[1, \\d+\\] was NOT obtained: anchor service unreachable`));
    expect(counts(dataDir).anchors).toBe(0);
  });

  it('audit stamp after a freeze with no anchor and no key: exit 2, nothing anchored or stamped, no .pending marker', async () => {
    const dataDir = storeWith('v3');
    const out = join(tempDir('kl-keycmd-stamps-'), 'stamps');
    const r = await cli(['audit', 'stamp', '--data-dir', dataDir, '--out', out, '--url', backend.url, '--tsa', `alpha=${tsaGood.url},beta=${tsaOther.url}`]);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/audit stamp: seq \d+ is not anchored \(this chain has no anchor yet\), and anchoring it needs the anchor key: no license key/);
    expect(r.stderr).toMatch(/no pending marker was written/);
    expect(existsSync(out)).toBe(false);
    expect(counts(dataDir).anchors).toBe(0);
  });

  it('audit stamp with the anchor service unreachable: exit 2, no .pending marker', async () => {
    const dataDir = storeWith('v3');
    const out = join(tempDir('kl-keycmd-stamps-'), 'stamps');
    const r = await cli(['audit', 'stamp', '--data-dir', dataDir, '--out', out, '--url', DEAD, '--tsa', `alpha=${tsaGood.url},beta=${tsaOther.url}`], { ...secretEnv, KRONICLE_ANCHOR_KEY_CMD: keyCmd() });
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/checkpoint --push of \[1, \d+\] failed: anchor service unreachable/);
    expect(pendingIn(out)).toEqual([]);
    expect(counts(dataDir).anchors).toBe(0);
    expectNoKey([r.stdout, r.stderr], dataDir);
  });

  it('audit stamp anchors the freeze with the key from the command, fails on a dead TSA without a marker, then completes', async () => {
    const dataDir = storeWith('v3');
    const out = join(tempDir('kl-keycmd-stamps-'), 'stamps');
    const env = { ...secretEnv, KRONICLE_ANCHOR_KEY_CMD: keyCmd() };
    const first = await cli(['audit', 'stamp', '--data-dir', dataDir, '--out', out, '--url', backend.url, '--tsa', `alpha=${tsaGood.url},gamma=${DEAD}`], env);
    expect(first.status).toBe(2);
    expect(first.stderr).toMatch(/^anchored \[1, \d+\] at .+; stamping it$/m);
    expect(first.stderr).toMatch(/audit stamp: RFC 3161 from gamma failed; no pending marker was written/);
    expect(first.stdout).toMatch(/PASS {2}RFC 3161 alpha/);
    expect(first.stdout).toMatch(/FAIL {2}RFC 3161 gamma/);
    expect(first.stdout).not.toMatch(/freeze nonce/);
    expect(pendingIn(out)).toEqual([]);
    expect(counts(dataDir).anchors).toBe(1);

    // again with two TSAs that answer: the same anchor (no second push), the kept alpha token, a nonce
    const second = await cli(['audit', 'stamp', '--data-dir', dataDir, '--out', out, '--url', backend.url, '--tsa', `alpha=${tsaGood.url},beta=${tsaOther.url}`], env);
    expect(second.status, second.stderr).toBe(0);
    expect(second.stderr).toBe('');
    expect(second.stdout).toMatch(/alpha .*\(already present\)/);
    expect(second.stdout).toMatch(/^freeze nonce {3}[0-9a-f]{64}/m);
    expect(counts(dataDir).anchors).toBe(1);
    expect(readdirSync(out).sort()).toEqual(expect.arrayContaining([expect.stringMatching(/\.alpha\.tsr$/), expect.stringMatching(/\.beta\.tsr$/)]));
    expectNoKey([first.stdout, first.stderr, second.stdout, second.stderr], dataDir, out);
  });

  it('--allow-pending keeps the 0.11.0 behaviour: a .pending marker for the dead TSA, exit 2', async () => {
    const dataDir = storeWith('v3');
    const out = join(tempDir('kl-keycmd-stamps-'), 'stamps');
    mkdirSync(out);
    const r = await cli(['audit', 'stamp', '--data-dir', dataDir, '--out', out, '--url', backend.url, '--anchor-key-file', keyFile(), '--tsa', `alpha=${tsaGood.url},beta=${tsaOther.url},gamma=${DEAD}`, '--allow-pending']);
    expect(r.status).toBe(2);
    expect(r.stdout).toMatch(/pending .*\.gamma\.pending \(stamp again; the audit profile fails while it is there\)/);
    expect(r.stderr).not.toMatch(/no pending marker/);
    expect(pendingIn(out)).toHaveLength(1);
  });
});
