/**
 * Exec-time pulse shims, end to end: real CLI, real sh wrappers, fake "real"
 * binaries, everything in temp dirs (no shim is ever written outside one).
 */

import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import Database from 'better-sqlite3';
import { describe, expect, it } from 'vitest';

import { forbiddenDir, install, resolveReal, uninstall } from '../src/shim/install.js';
import { VERSION } from '../src/version.js';
import { CLI, cleanEnv, gitInit, gitRun, tempDir, write } from './helpers/fs.js';
import { generous } from './helpers/time.js';

const SYS_PATH = '/usr/local/bin:/usr/bin:/bin';
/**
 * The wrappers under test here are the POSIX sh ones, run through PATH with sh
 * fake binaries: skipped on Windows (its .cmd/.ps1 wrappers delegate to
 * `shim exec`; `kronicle-lite pulse` itself is covered there by the CLI
 * contract tests, which run everywhere).
 */
const POSIX = process.platform !== 'win32';

interface Rig {
  root: string;
  bin: string;
  shims: string;
  data: string;
  proj: string;
  log: string;
  runbook: string;
}

/** A fake "real" binary that records its argv (NUL-separated) and stdin, and exits with $FAKE_EXIT. */
function fakeBin(dir: string, name: string, log: string): string {
  const f = join(dir, name);
  write(
    f,
    `#!/bin/sh\n{ printf '%s' "${name}"; for a in "$@"; do printf '\\0%s' "$a"; done; printf '\\n'; } >> '${log}'\nif [ -n "$FAKE_STDIN" ]; then cat >> '${log}'; fi\necho "REAL ${name} ran"\nexit \${FAKE_EXIT:-0}\n`,
  );
  chmodSync(f, 0o755);
  return f;
}

function kl(args: string[], env: Record<string, string> = {}, cwd?: string) {
  const r = spawnSync(process.execPath, [CLI, ...args], { env: cleanEnv({ KRONICLE_LITE_ACTOR: '', ...env }), encoding: 'utf8', ...(cwd ? { cwd } : {}) });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

function putRunbook(rig: Rig, target: string): void {
  writeFileSync(rig.runbook, `# Runbook\n\n## Deploy\n\nRun terraform apply against target: ${target}\n`);
  const r = kl(['put', 'runbook', rig.runbook, '--data-dir', rig.data, '--all-projects']);
  expect(r.status, r.stderr).toBe(0);
}

function rig(opts: { tools?: string[]; mode?: 'deny' | 'warn'; store?: boolean; extra?: string[] } = {}): Rig {
  const root = tempDir('kl-shim-');
  const r: Rig = {
    root,
    bin: join(root, 'bin'),
    shims: join(root, 'shims'),
    data: join(root, 'data'),
    proj: join(root, 'proj'),
    log: join(root, 'calls.log'),
    runbook: join(root, 'runbook.md'),
  };
  mkdirSync(r.bin, { recursive: true });
  mkdirSync(r.proj, { recursive: true });
  writeFileSync(r.log, '');
  const tools = opts.tools ?? ['terraform', 'kubectl'];
  for (const t of tools) fakeBin(r.bin, t, r.log);
  if (opts.store !== false) putRunbook(r, 'prod-a');
  const res = kl(['shim', 'install', '--dir', r.shims, '--data-dir', r.data, '--commands', tools.join(','), ...(opts.mode ? ['--mode', opts.mode] : []), ...(opts.extra ?? [])]);
  expect(res.status, res.stderr).toBe(0);
  return r;
}

function run(r: Rig, argv: string[], env: Record<string, string> = {}, cwd?: string) {
  const res = spawnSync(argv[0]!, argv.slice(1), {
    cwd: cwd ?? r.proj,
    env: cleanEnv({ PATH: `${r.shims}:${r.bin}:${SYS_PATH}`, HOME: r.root, KRONICLE_LITE_ACTOR: '', ...env }),
    encoding: 'utf8',
  });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

function calls(r: Rig): string[][] {
  return readFileSync(r.log, 'utf8')
    .split('\n')
    .filter((l) => l.length > 0)
    .map((l) => l.split('\0'));
}

describe.skipIf(!POSIX)('shim install / uninstall', () => {
  it('writes one marked, executable sh wrapper per command and a config; uninstall removes only ours', () => {
    const r = rig({ tools: ['terraform'], extra: ['--world', 'docker push'] });
    const files = readdirSync(r.shims).sort();
    expect(files).toEqual(['.kronicle-shim', 'docker', 'terraform']);
    const sh = readFileSync(join(r.shims, 'terraform'), 'utf8');
    expect(sh.startsWith('#!/bin/sh\n# kronicle-lite-shim v1 tool=terraform')).toBe(true);
    const cfg = JSON.parse(readFileSync(join(r.shims, '.kronicle-shim', 'config.json'), 'utf8'));
    expect(cfg).toMatchObject({ tools: ['terraform', 'docker'], world: ['docker push'], mode: 'deny', data_dir: r.data, baseline_seq: expect.any(Number) });
    // a file of the user's own in the same dir survives uninstall
    write(join(r.shims, 'notes.txt'), 'mine');
    const u = kl(['shim', 'uninstall', '--dir', r.shims, '--json']);
    expect(u.status, u.stderr).toBe(0);
    expect(readdirSync(r.shims)).toEqual(['notes.txt']);
    expect(JSON.parse(u.stdout).kept).toEqual([join(r.shims, 'notes.txt')]);
  });

  it('re-install is idempotent; never overwrites a file that is not a shim, nor a symlink', () => {
    const r = rig({ tools: ['terraform'] });
    expect(kl(['shim', 'install', '--dir', r.shims, '--data-dir', r.data, '--commands', 'terraform']).status).toBe(0);
    write(join(r.shims, 'kubectl'), '#!/bin/sh\necho mine\n');
    const bad = kl(['shim', 'install', '--dir', r.shims, '--data-dir', r.data, '--commands', 'terraform,kubectl']);
    expect(bad.status).toBe(1);
    expect(bad.stderr).toMatch(/refusing to overwrite .*kubectl: it is not a kronicle-lite shim/);
    expect(readFileSync(join(r.shims, 'kubectl'), 'utf8')).toBe('#!/bin/sh\necho mine\n');
    // a symlink at the target is refused, and its target is untouched
    const victim = join(r.root, 'victim');
    writeFileSync(victim, 'precious');
    symlinkSync(victim, join(r.shims, 'helm'));
    const sl = kl(['shim', 'install', '--dir', r.shims, '--data-dir', r.data, '--commands', 'helm']);
    expect(sl.status).toBe(1);
    expect(sl.stderr).toMatch(/symlink/);
    expect(readFileSync(victim, 'utf8')).toBe('precious');
  });

  it('refuses system directories (never writes there)', () => {
    for (const d of ['/', '/usr/bin', '/usr/local/bin', '/bin', '/dev', '/dev/null', '/etc', '/sbin', '/proc/self']) {
      expect(forbiddenDir(d), d).not.toBeNull();
      const r = kl(['shim', 'install', '--dir', d, '--commands', 'git', '--data-dir', tempDir('kl-shim-nodata-')]);
      expect(r.status, d).toBe(1);
      expect(r.stderr).toMatch(/refusing to install shims/);
    }
    expect(forbiddenDir('C:\\Windows\\System32', 'win32')).not.toBeNull();
    expect(forbiddenDir('C:\\', 'win32')).not.toBeNull();
    expect(forbiddenDir(tempDir('kl-shim-ok-'))).toBeNull();
    expect(() => uninstall('/usr/bin')).toThrow(/refusing/);
  });

  it('--windows also writes .cmd/.ps1 wrappers that delegate to `shim exec`', () => {
    const r = rig({ tools: ['terraform'], extra: ['--windows'] });
    const cmd = readFileSync(join(r.shims, 'terraform.cmd'), 'utf8');
    const ps1 = readFileSync(join(r.shims, 'terraform.ps1'), 'utf8');
    expect(cmd).toContain('kronicle-lite-shim v1 tool=terraform');
    expect(cmd).toMatch(/shim exec --dir ".*shims" --tool terraform -- %\*\r\nexit \/b %ERRORLEVEL%/);
    expect(ps1).toContain("shim exec --dir '");
    expect(ps1).toContain('-- @args\r\nexit $LASTEXITCODE');
    expect(kl(['shim', 'uninstall', '--dir', r.shims]).status).toBe(0);
    expect(existsSync(join(r.shims, 'terraform.cmd'))).toBe(false);
  });
});

describe.skipIf(!POSIX)('shim wrapper: read-only path', () => {
  it('passes argv through byte-exact (spaces, quotes, globs, empty, newline) with exit code and stdin', () => {
    const r = rig({ tools: ['kubectl'] });
    const args = ['get', 'pods', '-l', 'app=a b', "it's", '"dq"', '*', '', 'line1\nline2', '$HOME', '-n', 'prod'];
    const res = run(r, ['kubectl', ...args], { FAKE_EXIT: '3' });
    expect(res.status).toBe(3);
    expect(res.stdout).toBe('REAL kubectl ran\n');
    expect(res.stderr).toBe('');
    const recorded = readFileSync(r.log, 'utf8');
    expect(recorded).toBe(['kubectl', ...args].join('\0') + '\n');
    const sres = spawnSync('kubectl', ['get', 'x'], {
      cwd: r.proj,
      env: cleanEnv({ PATH: `${r.shims}:${r.bin}:${SYS_PATH}`, FAKE_STDIN: '1' }),
      input: 'piped-in\n',
      encoding: 'utf8',
    });
    expect(sres.status).toBe(0);
    expect(readFileSync(r.log, 'utf8')).toContain('piped-in\n');
  });

  it('never calls kronicle-lite for a read-only command, even with a broken store', () => {
    const r = rig({ tools: ['terraform'] });
    putRunbook(r, 'prod-b'); // pending change
    writeFileSync(join(r.data, 'kronicle-lite.db'), 'not a database');
    const res = run(r, ['terraform', 'plan']);
    expect(res.status).toBe(0);
    expect(res.stderr).toBe('');
    expect(calls(r)).toEqual([['terraform', 'plan']]);
    expect(existsSync(join(r.shims, '.kronicle-shim', 'shim.log'))).toBe(false);
  });
});

describe.skipIf(!POSIX)('shim wrapper: PATH resolution and recursion guard', () => {
  it('skips its own dir however it is spelled on PATH (trailing slash, symlink alias, duplicate)', () => {
    const r = rig({ tools: ['kubectl'] });
    const alias = join(r.root, 'alias');
    symlinkSync(r.shims, alias);
    for (const p of [`${r.shims}/:${r.bin}`, `${alias}:${r.shims}:${r.bin}`, `${r.shims}:${alias}/:${r.shims}:${r.bin}`, `::${r.shims}::${r.bin}:`]) {
      const res = spawnSync('kubectl', ['get', 'x'], { cwd: r.proj, env: cleanEnv({ PATH: `${p}:${SYS_PATH}` }), encoding: 'utf8', timeout: 10_000 });
      expect(res.status, `${p}: ${res.stderr}`).toBe(0);
      expect(res.stdout).toBe('REAL kubectl ran\n');
    }
  });

  it('works from a shim dir whose path needs quoting (space, $, quotes, backslash)', () => {
    const root = tempDir('kl-shim-q-');
    const bin = join(root, 'bin');
    const log = join(root, 'calls.log');
    writeFileSync(log, '');
    mkdirSync(bin);
    fakeBin(bin, 'kubectl', log);
    const shims = join(root, `sh ims $HOME "q" 'a' \\b`);
    install({ dir: shims, commands: ['kubectl'], effectiveDataDir: join(root, 'nodata'), dataDir: join(root, 'nodata'), node: process.execPath, cli: CLI, version: VERSION, path: bin });
    const res = spawnSync('kubectl', ['get', 'x'], { cwd: root, env: cleanEnv({ PATH: `${shims}:${bin}:${SYS_PATH}` }), encoding: 'utf8', timeout: 10_000 });
    expect(res.status, res.stderr).toBe(0);
    expect(res.stdout).toBe('REAL kubectl ran\n');
    const apply = spawnSync('kubectl', ['apply'], { cwd: root, env: cleanEnv({ PATH: `${shims}:${bin}:${SYS_PATH}` }), encoding: 'utf8', timeout: 20_000 });
    expect(apply.status, apply.stderr).toBe(77); // 0.8.1: no store = refused in deny mode (P2-01); logged under the quoted dir
    expect(apply.stderr).toMatch(/found no kronicle-lite store/);
    expect(existsSync(join(shims, '.kronicle-shim', 'shim.log'))).toBe(true);
  });

  it('skips non-executable files and directories named like the tool', () => {
    const r = rig({ tools: ['kubectl'] });
    const d1 = join(r.root, 'd1');
    const d2 = join(r.root, 'd2');
    write(join(d1, 'kubectl'), '#!/bin/sh\necho not executable\n'); // mode 644
    mkdirSync(join(d2, 'kubectl'), { recursive: true });
    const res = spawnSync('kubectl', ['get'], { cwd: r.proj, env: cleanEnv({ PATH: `${r.shims}:${d1}:${d2}:${r.bin}:${SYS_PATH}` }), encoding: 'utf8' });
    expect(res.stdout).toBe('REAL kubectl ran\n');
    expect(resolveReal('kubectl', { path: `${r.shims}:${d1}:${d2}:${r.bin}`, skipDirs: [r.shims] })).toBe(join(r.bin, 'kubectl'));
  });

  it('a wrapper that execs the tool by name lands on the real binary, checked once', () => {
    const r = rig({ tools: ['terraform'] });
    const wrap = join(r.root, 'wrap');
    write(join(wrap, 'terraform'), `#!/bin/sh\necho wrapper >> '${r.log}'\nexec terraform "$@"\n`);
    chmodSync(join(wrap, 'terraform'), 0o755);
    putRunbook(r, 'prod-b');
    const env = { PATH: `${r.shims}:${wrap}:${r.bin}:${SYS_PATH}` };
    const res = spawnSync('terraform', ['apply'], { cwd: r.proj, env: cleanEnv(env), encoding: 'utf8', timeout: 20_000 });
    expect(res.status).toBe(77); // checked before the wrapper ran
    expect(readFileSync(r.log, 'utf8')).toBe('');
    expect(kl(['shim', 'ack', '--operator', '--dir', r.shims, '--data-dir', r.data], {}, r.proj).status).toBe(0);
    const ok = spawnSync('terraform', ['apply'], { cwd: r.proj, env: cleanEnv(env), encoding: 'utf8', timeout: 20_000 });
    expect(ok.status, ok.stderr).toBe(0);
    expect(readFileSync(r.log, 'utf8')).toBe('wrapper\nterraform\0apply\n');
  });

  it('a wrapper that calls the tool in a child process stops at the depth limit (no fork bomb)', () => {
    const r = rig({ tools: ['kubectl'] });
    const wrap = join(r.root, 'wrap');
    write(join(wrap, 'kubectl'), '#!/bin/sh\nkubectl "$@"\nexit $?\n'); // child, not exec: finds the shim again
    chmodSync(join(wrap, 'kubectl'), 0o755);
    const res = spawnSync('kubectl', ['get'], { cwd: r.proj, env: cleanEnv({ PATH: `${r.shims}:${wrap}:${r.bin}:${SYS_PATH}` }), encoding: 'utf8', timeout: 20_000 });
    expect(res.status).toBe(126);
    expect(res.stderr).toMatch(/reached the shims 8 times/);
  });

  it('exits 127 when the real binary is not on PATH', () => {
    const r = rig({ tools: ['kubectl'] });
    // PATH = the shim dir and an empty dir only: CI images ship a real kubectl in /usr/local/bin.
    // The read-only path needs no external command (shell builtins only).
    const empty = join(r.root, 'empty');
    mkdirSync(empty);
    const res = spawnSync(join(r.shims, 'kubectl'), ['get'], { cwd: r.proj, env: cleanEnv({ PATH: `${r.shims}:${empty}` }), encoding: 'utf8' });
    expect(res.status).toBe(127);
    expect(res.stderr).toMatch(/kubectl: command not found on PATH \(outside the shim dir\)/);
  });
});

describe.skipIf(!POSIX)('shim wrapper: world-changing path (real CLI)', () => {
  it('deny: a changed runbook refuses terraform apply with the diff (exit 77) until acknowledged', () => {
    const r = rig({ tools: ['terraform'] });
    expect(run(r, ['terraform', 'apply']).status).toBe(0); // nothing changed since install
    putRunbook(r, 'prod-b');
    const plan = run(r, ['terraform', 'plan']);
    expect(plan.status).toBe(0);
    mkdirSync(join(r.proj, 'infra')); // 0.8.1: a -chdir that does not resolve is refused for that reason instead (H2-14)
    const res = run(r, ['terraform', '-chdir=infra', 'apply', '-auto-approve']);
    expect(res.status).toBe(77);
    expect(res.stdout).toBe('');
    expect(res.stderr).toContain('did NOT run `terraform -chdir=infra apply -auto-approve`');
    expect(res.stderr).toContain('[-prod-a-]{+prod-b+}');
    expect(res.stderr).not.toMatch(/shim ack|override/); // H2-12: the agent is never told how to skip the re-read
    expect(res.stderr).toMatch(/ask the operator/);
    expect(run(r, ['terraform', 'apply']).status).toBe(77); // a plain retry is refused again
    expect(calls(r).map((c) => c.join(' '))).toEqual(['terraform apply', 'terraform plan']);
    const seq = String(JSON.parse(kl(['shim', 'status', '--dir', r.shims, '--json'], {}, r.proj).stdout).project.pending.ack_through);
    const a = kl(['shim', 'ack', '--operator', '--through', seq], { PATH: `${r.shims}:${r.bin}:${SYS_PATH}` }, r.proj); // dir found on PATH
    expect(a.status, a.stderr).toBe(0);
    expect(a.stdout).toMatch(new RegExp(`acknowledged through seq ${seq} .*\\(1 blocking change`));
    expect(run(r, ['terraform', 'apply']).status).toBe(0);
    // a later change blocks again: acknowledging seq N never clears N+1
    putRunbook(r, 'prod-c');
    const again = run(r, ['terraform', 'destroy']);
    expect(again.status).toBe(77);
    expect(again.stderr).toContain('[-prod-b-]{+prod-c+}');
  });

  it('acknowledging in one project does not clear another', () => {
    const r = rig({ tools: ['terraform'] });
    const other = join(r.root, 'other');
    mkdirSync(other);
    putRunbook(r, 'prod-b');
    expect(run(r, ['terraform', 'apply']).status).toBe(77);
    expect(run(r, ['terraform', 'apply'], {}, other).status).toBe(77);
    expect(kl(['shim', 'ack', '--operator', '--dir', r.shims], {}, r.proj).status).toBe(0);
    expect(run(r, ['terraform', 'apply']).status).toBe(0);
    expect(run(r, ['terraform', 'apply'], {}, other).status).toBe(77);
  });

  it('warn mode: runs the command, prints the diff once, then is quiet', () => {
    const r = rig({ tools: ['terraform'], mode: 'warn' });
    putRunbook(r, 'prod-b');
    const res = run(r, ['terraform', 'apply']);
    expect(res.status).toBe(0);
    expect(res.stdout).toBe('REAL terraform ran\n');
    expect(res.stderr).toMatch(/\(warn\): `terraform apply` is running/);
    expect(res.stderr).toContain('[-prod-a-]{+prod-b+}');
    const quiet = run(r, ['terraform', 'apply']);
    expect(quiet.status).toBe(0);
    expect(quiet.stderr).toBe('');
  });

  it('fail-closed on a store integrity failure (deny and warn mode alike)', () => {
    for (const mode of ['deny', 'warn'] as const) {
      const r = rig({ tools: ['terraform'], mode });
      putRunbook(r, 'prod-b');
      const db = new Database(join(r.data, 'kronicle-lite.db'));
      const head = (db.prepare('SELECT MAX(seq) AS s FROM events').get() as { s: number }).s;
      db.prepare(`UPDATE events SET actor_id = 'mallory' WHERE seq = ?`).run(head);
      db.close();
      const res = run(r, ['terraform', 'apply']);
      expect(res.status, mode).toBe(77);
      expect(res.stderr).toMatch(/STORE INTEGRITY FAILURE at seq \d+/);
      expect(calls(r)).toEqual([]);
      expect(run(r, ['terraform', 'plan']).status).toBe(0); // read-only still runs
    }
    // a live block edited behind kronicle-lite's back, with nothing new on the chain
    const r = rig({ tools: ['terraform'] });
    const db = new Database(join(r.data, 'kronicle-lite.db'));
    db.prepare(`UPDATE blocks SET content = 'Run terraform apply against target: evil' WHERE content LIKE '%prod-a%' AND valid_to IS NULL`).run();
    db.close();
    const res = run(r, ['terraform', 'apply']);
    expect(res.status).toBe(77);
    expect(res.stderr).toMatch(/STORE INTEGRITY FAILURE/);
  });

  it('no store: refused in deny mode (0.8.1, P2-01), every time and logged; runs loudly in warn mode', () => {
    const r = rig({ tools: ['terraform'], store: false });
    for (let i = 0; i < 2; i++) {
      const a = run(r, ['terraform', 'apply']);
      expect(a.status).toBe(77);
      expect(a.stderr).toMatch(/^kronicle-lite shim: did NOT run `terraform apply` — the shim found no kronicle-lite store \(looked in .*\), so it could not be checked\./);
    }
    expect(readFileSync(join(r.shims, '.kronicle-shim', 'last-error'), 'utf8')).toMatch(/found no kronicle-lite store/);
    const log = readFileSync(join(r.shims, '.kronicle-shim', 'shim.log'), 'utf8').trim().split('\n');
    expect(log.filter((l) => / terraform pulse\(node\) decision=deny reason=no-store$/.test(l))).toHaveLength(2);
    expect(log.filter((l) => / terraform check \d+ms outcome=deny rc=77$/.test(l))).toHaveLength(2);
    expect(calls(r)).toHaveLength(0);
    // once a store exists the check works
    putRunbook(r, 'prod-a');
    expect(run(r, ['terraform', 'apply']).status).toBe(0); // first check: seeds at the head
    putRunbook(r, 'prod-b');
    expect(run(r, ['terraform', 'apply']).status).toBe(77);
    // warn mode: runs, says so every time
    const w = rig({ tools: ['terraform'], store: false, mode: 'warn' });
    const a = run(w, ['terraform', 'apply']);
    expect(a.status).toBe(0);
    expect(a.stderr).toMatch(/\(warn\): `terraform apply` is running UNCHECKED — the shim found no kronicle-lite store/);
    expect(calls(w)).toHaveLength(1);
  });

  it('fail-open when the kronicle-lite CLI is gone and not on PATH; timeout bounds a hung check', () => {
    const root = tempDir('kl-shim-fake-');
    const bin = join(root, 'bin');
    const log = join(root, 'calls.log');
    writeFileSync(log, '');
    mkdirSync(bin);
    fakeBin(bin, 'terraform', log);
    const shims = join(root, 'shims');
    const base = { dir: shims, commands: ['terraform'], effectiveDataDir: join(root, 'nodata'), dataDir: join(root, 'nodata'), node: process.execPath, version: VERSION, path: bin };
    install({ ...base, cli: join(root, 'missing-cli.js') });
    const env = cleanEnv({ PATH: `${shims}:${bin}:${SYS_PATH}` });
    const a = spawnSync('terraform', ['apply'], { cwd: root, env, encoding: 'utf8' });
    expect(a.status).toBe(0);
    expect(a.stderr).toMatch(/kronicle-lite not found; running terraform unchecked/);
    // a check that hangs is cut off by KRONICLE_SHIM_TIMEOUT and fails open
    const hang = join(root, 'hang.js');
    writeFileSync(hang, 'setTimeout(() => {}, 60_000);\n');
    install({ ...base, cli: hang });
    const t0 = Date.now();
    const b = spawnSync('terraform', ['apply'], { cwd: root, env: { ...env, KRONICLE_SHIM_TIMEOUT: '1' }, encoding: 'utf8', timeout: 20_000 });
    expect(b.status).toBe(0);
    expect(Date.now() - t0).toBeLessThan(generous(8_000));
    expect(readFileSync(join(shims, '.kronicle-shim', 'shim.log'), 'utf8')).toMatch(/ terraform check \d+ms outcome=timeout-allow rc=(?:124|137|142) timeout=1s\n/);
    expect(readFileSync(log, 'utf8').split('\n').filter(Boolean)).toHaveLength(2);
    // loud on EVERY timeout, not only the first (unlike the other fail-open notes)
    const msg = /^kronicle-lite check TIMED OUT after 1s — `terraform apply -auto-approve` was NOT checked; see .*\.kronicle-shim\/shim\.log$/m;
    for (let i = 0; i < 2; i++) {
      const c = spawnSync('terraform', ['apply', '-auto-approve'], { cwd: root, env: { ...env, KRONICLE_SHIM_TIMEOUT: '1' }, encoding: 'utf8', timeout: 20_000 });
      expect(c.status).toBe(0);
      expect(c.stderr).toMatch(msg);
    }
    expect(readFileSync(log, 'utf8').split('\n').filter(Boolean)).toHaveLength(4);
    expect(readFileSync(join(shims, '.kronicle-shim', 'shim.log'), 'utf8').match(/outcome=timeout-allow/g)).toHaveLength(3);
  });

  it('--on-timeout deny: a check that times out refuses the command (exit 77), loudly, every time', () => {
    const root = tempDir('kl-shim-fake-');
    const bin = join(root, 'bin');
    const log = join(root, 'calls.log');
    writeFileSync(log, '');
    mkdirSync(bin);
    fakeBin(bin, 'terraform', log);
    const shims = join(root, 'shims');
    const hang = join(root, 'hang.js');
    writeFileSync(hang, 'setTimeout(() => {}, 60_000);\n');
    const rep = install({ dir: shims, commands: ['terraform'], effectiveDataDir: join(root, 'nodata'), dataDir: join(root, 'nodata'), node: process.execPath, version: VERSION, path: bin, cli: hang, onTimeout: 'deny' });
    expect(rep.on_timeout).toBe('deny');
    expect(JSON.parse(readFileSync(join(shims, '.kronicle-shim', 'config.json'), 'utf8')).on_timeout).toBe('deny');
    const env = cleanEnv({ PATH: `${shims}:${bin}:${SYS_PATH}`, KRONICLE_SHIM_TIMEOUT: '1' });
    for (let i = 0; i < 2; i++) {
      const a = spawnSync('terraform', ['apply'], { cwd: root, env, encoding: 'utf8', timeout: 20_000 });
      expect(a.status).toBe(77);
      expect(a.stdout).toBe('');
      expect(a.stderr).toMatch(/^kronicle-lite check TIMED OUT after 1s — `terraform apply` was NOT checked and NOT run \(--on-timeout deny\); see .*shim\.log$/m);
    }
    expect(readFileSync(log, 'utf8')).toBe(''); // nothing ran
    expect(spawnSync('terraform', ['plan'], { cwd: root, env, encoding: 'utf8' }).status).toBe(0); // read-only still runs
    expect(readFileSync(join(shims, '.kronicle-shim', 'shim.log'), 'utf8').match(/ terraform check \d+ms outcome=timeout-deny rc=(?:124|137|142) timeout=1s/g)).toHaveLength(2);
    // the CLI flag, and its validation
    const cli = kl(['shim', 'install', '--dir', join(root, 'shims2'), '--data-dir', join(root, 'nodata'), '--commands', 'terraform', '--on-timeout', 'deny', '--json']);
    expect(cli.status, cli.stderr).toBe(0);
    expect(JSON.parse(cli.stdout).on_timeout).toBe('deny');
    expect(readFileSync(join(root, 'shims2', 'terraform'), 'utf8')).toContain("kl_onto='deny'");
    expect(kl(['shim', 'install', '--dir', join(root, 'shims3'), '--on-timeout', 'maybe']).status).not.toBe(0);
    // default stays allow (compatibility)
    const d = kl(['shim', 'install', '--dir', join(root, 'shims4'), '--data-dir', join(root, 'nodata'), '--commands', 'terraform', '--json']);
    expect(JSON.parse(d.stdout).on_timeout).toBe('allow');
  });

  it('shim.log records the check time and outcome of every world-changing call (shell side and node side)', () => {
    const r = rig({ tools: ['terraform'] });
    expect(run(r, ['terraform', 'apply']).status).toBe(0);
    expect(run(r, ['terraform', 'plan']).status).toBe(0); // read-only: not logged
    putRunbook(r, 'prod-b');
    expect(run(r, ['terraform', 'destroy']).status).toBe(77);
    const lines = readFileSync(join(r.shims, '.kronicle-shim', 'shim.log'), 'utf8').trim().split('\n');
    const shell = lines.filter((l) => / terraform check /.test(l));
    expect(shell).toHaveLength(2);
    expect(shell[0]).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ terraform check \d+ms outcome=allow rc=0$/);
    expect(shell[1]).toMatch(/ terraform check \d+ms outcome=deny rc=77$/);
    const node = lines.filter((l) => /pulse\(node\)/.test(l));
    expect(node).toHaveLength(2);
    expect(node[1]).toMatch(/ terraform pulse\(node\) boot \d+ms open \d+ms check \d+ms total \d+ms decision=deny reason=retractions head=\d+$/);
  });

  it('a deny from the check is the only thing that stops the command (exit 77 from pulse only)', () => {
    const root = tempDir('kl-shim-fake-');
    const bin = join(root, 'bin');
    const log = join(root, 'calls.log');
    writeFileSync(log, '');
    mkdirSync(bin);
    fakeBin(bin, 'terraform', log);
    const shims = join(root, 'shims');
    const argsLog = join(root, 'pulse-args.log');
    const fake = join(root, 'fake-cli.js');
    writeFileSync(fake, `require('fs').appendFileSync(${JSON.stringify(argsLog)}, JSON.stringify(process.argv.slice(2)) + '\\n'); process.stderr.write('fake says no\\n'); process.exit(Number(process.env.FAKE_PULSE_EXIT || 0));\n`);
    install({ dir: shims, commands: ['terraform'], effectiveDataDir: join(root, 'd'), dataDir: join(root, 'd'), node: process.execPath, cli: fake, version: VERSION, path: bin });
    const env = cleanEnv({ PATH: `${shims}:${bin}:${SYS_PATH}` });
    const deny = spawnSync('terraform', ['apply', '-var', 'x=a b'], { cwd: root, env: { ...env, FAKE_PULSE_EXIT: '77' }, encoding: 'utf8' });
    expect(deny.status).toBe(77);
    expect(deny.stderr).toBe('fake says no\n');
    const pulseArgs = JSON.parse(readFileSync(argsLog, 'utf8').split('\n')[0]!);
    expect(pulseArgs).toEqual(['pulse', '--state', join(shims, '.kronicle-shim'), '--data-dir', join(root, 'd'), '--default-data-dir', '', '--mode', 'deny', '--cwd', root, '--', 'terraform', 'apply', '-var', 'x=a b']);
    expect(spawnSync('terraform', ['apply'], { cwd: root, env: { ...env, FAKE_PULSE_EXIT: '1' }, encoding: 'utf8' }).status).toBe(0);
    expect(spawnSync('terraform', ['apply'], { cwd: root, env: { ...env, FAKE_PULSE_EXIT: '0' }, encoding: 'utf8' }).status).toBe(0);
    expect(readFileSync(log, 'utf8').split('\n').filter(Boolean)).toHaveLength(2);
  });

  it('the check runs with the shim dir removed from PATH (a git-shimmed pulse cannot loop)', () => {
    const r = rig({ tools: ['terraform', 'git'], extra: ['--world', 'git *'] });
    // pulse resolves the project with `git rev-parse`; with every git call world-changing,
    // a pulse that saw the shim would recurse.
    const realGit = execFileSync('sh', ['-c', 'command -v git'], { encoding: 'utf8' }).trim();
    const gitDir = join(r.root, 'realgit');
    mkdirSync(gitDir);
    symlinkSync(realGit, join(gitDir, 'git'));
    const res = spawnSync('terraform', ['apply'], { cwd: r.proj, env: cleanEnv({ PATH: `${r.shims}:${r.bin}:${gitDir}:${SYS_PATH}` }), encoding: 'utf8', timeout: 20_000 });
    expect(res.status, res.stderr).toBe(0);
  });
});

describe('kronicle-lite pulse (CLI contract)', () => {
  it('--json: seed without a cursor, deny 77 with blocking retractions since a cursor, 3 without a store', () => {
    const root = tempDir('kl-pulse-');
    const data = join(root, 'data');
    const rb = join(root, 'rb.md');
    writeFileSync(rb, '# R\n\nTarget: a\n');
    expect(kl(['put', 'rb', rb, '--data-dir', data, '--all-projects']).status).toBe(0);
    const seed = kl(['pulse', '--data-dir', data, '--json', '--cwd', root]);
    expect(seed.status).toBe(0);
    const s = JSON.parse(seed.stdout);
    expect(s).toMatchObject({ format: 'kronicle-lite/1', decision: 'seed', blocking: [], cursor: expect.any(String) });
    writeFileSync(rb, '# R\n\nTarget: b\n');
    expect(kl(['put', 'rb', rb, '--data-dir', data, '--all-projects']).status).toBe(0);
    const d = kl(['pulse', '--data-dir', data, '--json', '--cwd', root, '--cursor', s.cursor, '--', 'deploy', '--prod']);
    expect(d.status).toBe(77);
    const j = JSON.parse(d.stdout);
    expect(j).toMatchObject({ decision: 'deny', reason: 'retractions', cursor: s.cursor, ack_through: j.head.seq });
    expect(j.blocking).toHaveLength(1);
    expect(j.blocking[0]).toMatchObject({ kind: 'supersession', severity: 'behavioral', diff: 'Target: [-a-]{+b+}' });
    expect(d.stderr).toContain('did NOT run `deploy --prod`');
    const w = kl(['pulse', '--data-dir', data, '--json', '--cwd', root, '--cursor', s.cursor, '--mode', 'warn']);
    expect(w.status).toBe(0);
    expect(JSON.parse(w.stdout).decision).toBe('warn');
    const ok = kl(['pulse', '--data-dir', data, '--json', '--cwd', root, '--cursor', JSON.parse(w.stdout).cursor]);
    expect(ok.status).toBe(0);
    expect(JSON.parse(ok.stdout)).toMatchObject({ decision: 'allow', reason: 'clear', message: null });
    const none = kl(['pulse', '--data-dir', join(root, 'nope'), '--json']);
    expect(none.status).toBe(3);
    expect(existsSync(join(root, 'nope'))).toBe(false); // never creates a store
  });
});

describe.skipIf(!POSIX)('kronicle-lite shim exec (Windows wrappers / portable path)', () => {
  it('decides with classify(), pulses in-process, refuses with 77, else runs the real binary', () => {
    const r = rig({ tools: ['terraform'] });
    const env = { PATH: `${r.shims}:${r.bin}:${SYS_PATH}` };
    const x = (args: string[]) => kl(['shim', 'exec', '--dir', r.shims, '--tool', 'terraform', '--', ...args], env, r.proj);
    const plan = x(['plan', '-out', 'a b']);
    expect(plan.status).toBe(0);
    expect(plan.stdout).toBe('REAL terraform ran\n');
    putRunbook(r, 'prod-b');
    const deny = x(['apply']);
    expect(deny.status).toBe(77);
    expect(deny.stderr).toContain('[-prod-a-]{+prod-b+}');
    expect(calls(r)).toEqual([['terraform', 'plan', '-out', 'a b']]);
    expect(kl(['shim', 'ack', '--operator', '--dir', r.shims], {}, r.proj).status).toBe(0);
    expect(x(['apply']).status).toBe(0);
  });
});

describe('version-bound reconciliation: the gate clears when the reader re-reads the current version', () => {
  const read = (r: Rig, actor: string, args: string[] = ['runbook']) => {
    const g = kl(['get', ...args, '--actor', actor, '--data-dir', r.data]);
    expect(g.status, g.stderr).toBe(0);
    return g.stdout;
  };
  const blockWith = (r: Rig, text: string): string => {
    const db = new Database(join(r.data, 'kronicle-lite.db'), { readonly: true });
    try {
      return (db.prepare(`SELECT block_id FROM blocks WHERE content LIKE ? AND kind = 'paragraph'`).get(`%${text}%`) as { block_id: string }).block_id;
    } finally {
      db.close();
    }
  };

  it.skipIf(!POSIX)('re-reading clears it without shim ack; an older version does not; a newer change blocks again', () => {
    const r = rig({ tools: ['terraform'] });
    read(r, 'agent-a');
    putRunbook(r, 'prod-b');
    const d1 = run(r, ['terraform', 'apply']);
    expect(d1.status).toBe(77);
    expect(d1.stderr).toContain('[-prod-a-]{+prod-b+}');
    expect(d1.stderr).toContain('[not yet re-read at the current version by: agent-a]');
    expect(d1.stderr).toContain('Still to re-read the current version: agent-a (every reader of the changed text is checked: no invoking actor is set');
    expect(d1.stderr).not.toMatch(/shim ack|override/);
    putRunbook(r, 'prod-c');
    read(r, 'agent-a', ['--block', blockWith(r, 'prod-b')]); // v2: not the current version
    expect(run(r, ['terraform', 'apply']).status).toBe(77);
    read(r, 'agent-a', ['--block', blockWith(r, 'prod-c')]); // the current version
    const ok = run(r, ['terraform', 'apply']);
    expect(ok.status, ok.stderr).toBe(0);
    expect(ok.stderr).toMatch(/2 change\(s\) since the last check already re-read at the current version \(by agent-a\)/);
    expect(run(r, ['terraform', 'apply']).stderr).toBe(''); // the cursor moved
    putRunbook(r, 'prod-d');
    expect(run(r, ['terraform', 'apply']).status).toBe(77);
    expect(calls(r).map((c) => c.join(' '))).toEqual(['terraform apply', 'terraform apply']);
  });

  it.skipIf(!POSIX)('every reader must re-read; a configured --pending-actor replaces the readers; shim ack still overrides', () => {
    const r = rig({ tools: ['terraform'] });
    read(r, 'agent-a');
    read(r, 'agent-b');
    putRunbook(r, 'prod-b');
    read(r, 'agent-a');
    const d = run(r, ['terraform', 'apply']);
    expect(d.status).toBe(77);
    expect(d.stderr).toContain('by: agent-b]');
    read(r, 'agent-b');
    expect(run(r, ['terraform', 'apply']).status).toBe(0);

    const c = rig({ tools: ['terraform'], extra: ['--pending-actor', 'deployer'] });
    read(c, 'agent-a');
    putRunbook(c, 'prod-b');
    read(c, 'agent-a'); // not the configured actor
    const dc = run(c, ['terraform', 'apply']);
    expect(dc.status).toBe(77);
    expect(dc.stderr).toContain('by: deployer]');
    const st = kl(['shim', 'status', '--dir', c.shims], {}, c.proj);
    expect(st.stdout).toContain('pending actor(s) deployer');
    expect(dc.stderr).toContain('Still to re-read the current version: deployer (the configured pending actor(s)).');
    const seq = String(JSON.parse(kl(['shim', 'status', '--dir', c.shims, '--json'], {}, c.proj).stdout).project.pending.ack_through);
    expect(kl(['shim', 'ack', '--operator', '--dir', c.shims, '--through', seq], {}, c.proj).status).toBe(0); // operator override
    expect(run(c, ['terraform', 'apply']).status).toBe(0);
    putRunbook(c, 'prod-c');
    expect(run(c, ['terraform', 'apply']).status).toBe(77);
    read(c, 'deployer'); // the configured actor reads the current version
    expect(run(c, ['terraform', 'apply']).status).toBe(0);
  }, 60_000);

  it.skipIf(!POSIX)('a removal clears on a read of the document after it; a derived note clears when its source is re-read; integrity still fails closed', () => {
    const r = rig({ tools: ['terraform'] });
    read(r, 'agent-a');
    writeFileSync(join(r.root, 'note.md'), '# Deploy note\n\nWe deploy with terraform to prod-a.\n');
    expect(kl(['put', 'deploy-note', join(r.root, 'note.md'), '--actor', 'agent-a', '--data-dir', r.data, '--all-projects']).status).toBe(0);
    putRunbook(r, 'prod-b');
    const p = JSON.parse(kl(['pulse', '--state', join(r.shims, '.kronicle-shim'), '--data-dir', r.data, '--cwd', r.proj, '--json'], {}, r.proj).stdout);
    expect(p.decision).toBe('deny');
    expect(p.blocking.map((b: { kind: string }) => b.kind).sort()).toEqual(['derived', 'supersession']);
    expect(p.blocking.every((b: { unread_by: string[] }) => b.unread_by.join() === 'agent-a')).toBe(true);
    read(r, 'agent-a');
    const ok = JSON.parse(kl(['pulse', '--state', join(r.shims, '.kronicle-shim'), '--data-dir', r.data, '--cwd', r.proj, '--json'], {}, r.proj).stdout);
    expect(ok).toMatchObject({ decision: 'allow', blocking: [], pending_actors: null });
    expect(ok.resolved).toHaveLength(2);

    // removal: the Deploy section goes away
    writeFileSync(r.runbook, '# Runbook\n\nNothing to deploy.\n');
    expect(kl(['put', 'runbook', r.runbook, '--data-dir', r.data, '--all-projects']).status).toBe(0);
    const rm = run(r, ['terraform', 'apply']);
    expect(rm.status).toBe(77);
    expect(rm.stderr).toContain('now REMOVED');
    read(r, 'agent-a');
    expect(run(r, ['terraform', 'apply']).status).toBe(0);

    // integrity: a reconciled reader does not open a tampered store
    putRunbook(r, 'prod-c');
    read(r, 'agent-a');
    const db = new Database(join(r.data, 'kronicle-lite.db'));
    db.prepare(`UPDATE blocks SET content = 'Run terraform apply against target: evil' WHERE content LIKE '%prod-c%' AND valid_to IS NULL`).run();
    db.close();
    const bad = run(r, ['terraform', 'apply']);
    expect(bad.status).toBe(77);
    expect(bad.stderr).toMatch(/STORE INTEGRITY FAILURE/);
  });

  it('pulse --cursor --pending-actor: blocking[].unread_by, then resolved[] and the head cursor after the read', () => {
    const r = rig({ tools: ['terraform'] });
    const seed = JSON.parse(kl(['pulse', '--data-dir', r.data, '--json', '--all-projects']).stdout);
    putRunbook(r, 'prod-b');
    const args = ['pulse', '--data-dir', r.data, '--json', '--all-projects', '--cursor', seed.cursor, '--pending-actor', 'agent-a'];
    const d = kl(args);
    expect(d.status).toBe(77);
    const dj = JSON.parse(d.stdout);
    expect(dj).toMatchObject({ decision: 'deny', pending_actors: ['agent-a'], cursor: seed.cursor });
    expect(dj.blocking[0]).toMatchObject({ kind: 'supersession', pending_actors: ['agent-a'], unread_by: ['agent-a'] });
    read(r, 'agent-a');
    const a = kl(args);
    expect(a.status).toBe(0);
    const aj = JSON.parse(a.stdout);
    expect(aj).toMatchObject({ decision: 'allow', reason: 'clear', blocking: [] });
    expect(aj.resolved[0]).toMatchObject({ unread_by: [] });
    expect(aj.cursor).not.toBe(seed.cursor);
    // default actors = the change's readers: agent-a, who has re-read
    const n = JSON.parse(kl(['pulse', '--data-dir', r.data, '--json', '--all-projects', '--cursor', seed.cursor]).stdout);
    expect(n).toMatchObject({ decision: 'allow', pending_actors: null });
    // a configured actor that has not read the current version keeps it blocked
    const e = JSON.parse(kl(['pulse', '--data-dir', r.data, '--json', '--all-projects', '--cursor', seed.cursor, '--pending-actor', 'nobody']).stdout);
    expect(e.decision).toBe('deny');
  });
});

describe.skipIf(!POSIX)('shim status', () => {
  it('reports active shims, the real binaries and what is pending in this project', () => {
    const r = rig({ tools: ['terraform'] });
    putRunbook(r, 'prod-b');
    expect(run(r, ['terraform', 'apply']).status).toBe(77);
    const s = kl(['shim', 'status', '--dir', r.shims], { PATH: `${r.shims}:${r.bin}:${SYS_PATH}` }, r.proj);
    expect(s.status, s.stderr).toBe(0);
    expect(s.stdout).toMatch(/terraform\s+active\s+real: .*\/bin\/terraform/);
    expect(s.stdout).toMatch(/BLOCKED — 1 unreconciled change\(s\) through seq \d+; re-read the current version \(operator override: see docs\/PUSH.md\)/);
    expect(s.stdout).toContain('pending actors: the invoking actor (KRONICLE_LITE_ACTOR); not set here, so each change\'s readers');
    const j = JSON.parse(kl(['shim', 'status', '--dir', r.shims, '--json'], { PATH: `${r.bin}:${SYS_PATH}` }, r.proj).stdout);
    expect(j.tools[0]).toMatchObject({ tool: 'terraform', active: false, real: join(r.bin, 'terraform') });
    // status is read-only: still blocked afterwards
    expect(run(r, ['terraform', 'apply']).status).toBe(77);
  });
});

describe.skipIf(!POSIX)('overhead of a read-only command through the shim', () => {
  it('git status: shim adds a few ms (no node start)', () => {
    const root = tempDir('kl-shim-bench-');
    const repo = join(root, 'repo');
    mkdirSync(repo);
    gitInit(repo);
    write(join(repo, 'a.txt'), 'a\n');
    gitRun(repo, ['add', '.']);
    gitRun(repo, ['commit', '-qm', 'a']);
    const shims = join(root, 'shims');
    install({ dir: shims, commands: ['git'], effectiveDataDir: join(root, 'nodata'), dataDir: join(root, 'nodata'), node: process.execPath, cli: CLI, version: VERSION });
    const realGit = execFileSync('sh', ['-c', 'command -v git'], { encoding: 'utf8' }).trim();
    const basePath = process.env['PATH'] ?? SYS_PATH;
    const N = 60;
    const time = (path: string) => {
      const env = cleanEnv({ PATH: path });
      const ms: number[] = [];
      for (let i = 0; i < N; i++) {
        const t0 = process.hrtime.bigint();
        const res = spawnSync('git', ['status', '--short'], { cwd: repo, env, encoding: 'utf8' });
        ms.push(Number(process.hrtime.bigint() - t0) / 1e6);
        expect(res.status).toBe(0);
      }
      ms.sort((a, b) => a - b);
      return { median: ms[Math.floor(N / 2)]!, p90: ms[Math.floor(N * 0.9)]! };
    };
    time(basePath); // warm up
    const direct = time(basePath);
    const viaShim = time(`${shims}:${basePath}`);
    const overhead = viaShim.median - direct.median;
    console.log(
      `[shim overhead] git status --short (${realGit}), N=${N}: direct median ${direct.median.toFixed(2)} ms (p90 ${direct.p90.toFixed(2)}), via shim median ${viaShim.median.toFixed(2)} ms (p90 ${viaShim.p90.toFixed(2)}); overhead ${overhead.toFixed(2)} ms`,
    );
    expect(overhead).toBeLessThan(generous(25));

    // the world-changing path: one `kronicle-lite pulse` (node start + orient) before exec
    const r = rig({ tools: ['terraform'] });
    const t: number[] = [];
    for (let i = 0; i < 7; i++) {
      const t0 = process.hrtime.bigint();
      expect(run(r, ['terraform', 'apply']).status).toBe(0);
      t.push(Number(process.hrtime.bigint() - t0) / 1e6);
    }
    t.sort((a, b) => a - b);
    console.log(`[shim overhead] terraform apply (fake binary) through the shim, nothing pending, N=7: median ${t[3]!.toFixed(0)} ms (includes the pulse)`);
  });
});
