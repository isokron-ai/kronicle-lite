/**
 * 0.8.1 shim hardening (round 2, track 3, stress/findings/hooks.md):
 *   H2-12  `shim ack` is an operator action; the refusal never offers it
 *   H2-13  optional git pre-push hook (catches pushes the PATH shim cannot see)
 *   H2-14  the project is the one the command acts on (git -C, --git-dir, …)
 *   H2-16  the invoking actor's re-read clears its own gate
 * Real git, real CLI, everything in temp dirs: HOME is a temp dir, no global
 * or system git config is read or written, and no hook is written outside a
 * temp repository.
 */

import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { commandTarget, repoOfGitDir } from '../src/shim/target.js';
import { CLI, cleanEnv, tempDir } from './helpers/fs.js';

/** POSIX sh wrappers and sh hooks: skipped on Windows (as in shim.test.ts). */
const POSIX = process.platform !== 'win32';
const SYS_PATH = `/usr/local/bin:/usr/bin:/bin:${dirname(process.execPath)}`;
/** PATH for plain git calls (Windows: the inherited one). */
const gitPath = (): Record<string, string> => (POSIX ? { PATH: SYS_PATH } : {});

interface GRig {
  root: string;
  home: string;
  data: string;
  shims: string;
  state: string;
  proj: string;
  remote: string;
  other: string;
  runbook: string;
  /** proj/.git/config before install (install must never write git config). */
  configBefore: string;
}

function baseEnv(extra: Record<string, string>, home: string): Record<string, string> {
  return cleanEnv({
    HOME: home,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_AUTHOR_NAME: 't',
    GIT_AUTHOR_EMAIL: 't@example.invalid',
    GIT_COMMITTER_NAME: 't',
    GIT_COMMITTER_EMAIL: 't@example.invalid',
    KRONICLE_LITE_ACTOR: '',
    ...extra,
  });
}

function kl(r: { home: string }, args: string[], env: Record<string, string> = {}, cwd?: string) {
  const p = spawnSync(process.execPath, [CLI, ...args], { env: baseEnv(env, r.home), encoding: 'utf8', ...(cwd ? { cwd } : {}) });
  return { status: p.status, stdout: p.stdout, stderr: p.stderr };
}

function git(r: { home: string }, args: string[], cwd: string): string {
  const p = spawnSync('git', ['-c', 'protocol.file.allow=always', '-c', 'commit.gpgsign=false', ...args], { cwd, env: baseEnv(gitPath(), r.home), encoding: 'utf8' });
  if (p.status !== 0) throw new Error(`git ${args.join(' ')}: ${p.stderr}`);
  return p.stdout.trim();
}

/** The agent's shell: `sh -c CMD`, shims first on PATH unless `path` says otherwise. */
function sh(r: GRig, cmd: string, opts: { cwd?: string; path?: string; env?: Record<string, string> } = {}) {
  const p = spawnSync('sh', ['-c', cmd], {
    cwd: opts.cwd ?? r.proj,
    env: baseEnv({ PATH: opts.path ?? `${r.shims}:${SYS_PATH}`, ...(opts.env ?? {}) }, r.home),
    encoding: 'utf8',
    timeout: 60_000,
  });
  return { status: p.status, stdout: p.stdout, stderr: p.stderr };
}

function landed(r: GRig, repo = r.proj, remote = r.remote): boolean {
  const remoteHead = spawnSync('git', ['rev-parse', '-q', '--verify', 'main'], { cwd: remote, env: baseEnv(gitPath(), r.home), encoding: 'utf8' }).stdout.trim();
  return remoteHead === git(r, ['rev-parse', 'HEAD'], repo);
}

function putRunbook(r: GRig, target: string): void {
  writeFileSync(r.runbook, `# Runbook\n\n## Deploy\n\nDeploy to ${target}.\n`);
  const p = kl(r, ['put', 'runbook', r.runbook, '--data-dir', r.data, '--cwd', r.proj]);
  expect(p.status, p.stderr).toBe(0);
}

function read(r: GRig, actor: string): void {
  const p = kl(r, ['get', 'runbook', '--actor', actor, '--data-dir', r.data]);
  expect(p.status, p.stderr).toBe(0);
}

/**
 * A git project with a bare remote, a runbook scoped to it that `readers` read,
 * git shims installed (cursor at the head), then the runbook changed: one
 * blocking change, and one local commit waiting to be pushed.
 */
function gitRig(opts: { readers?: string[]; install?: string[]; before?: (r: GRig) => void } = {}): GRig {
  const root = tempDir('kl-shimh-');
  const r: GRig = {
    root,
    home: join(root, 'home'),
    data: join(root, 'data'),
    shims: join(root, 'shims'),
    state: join(root, 'shims', '.kronicle-shim'),
    proj: join(root, 'proj'),
    remote: join(root, 'remote.git'),
    other: join(root, 'other'),
    runbook: join(root, 'runbook.md'),
    configBefore: '',
  };
  for (const d of [r.home, r.proj, r.other]) mkdirSync(d, { recursive: true });
  git(r, ['init', '-q', '--bare', '-b', 'main', r.remote], root);
  git(r, ['init', '-q', '-b', 'main'], r.proj);
  git(r, ['commit', '-q', '--allow-empty', '-m', 'init'], r.proj);
  git(r, ['remote', 'add', 'origin', r.remote], r.proj);
  git(r, ['push', '-q', 'origin', 'main'], r.proj);
  putRunbook(r, 'stg-west-2');
  for (const a of opts.readers ?? ['agent-a']) read(r, a);
  opts.before?.(r);
  r.configBefore = readFileSync(join(r.proj, '.git', 'config'), 'utf8');
  const i = kl(r, ['shim', 'install', '--dir', r.shims, '--data-dir', r.data, '--commands', 'git', ...(opts.install ?? [])], {}, r.proj);
  expect(i.status, i.stderr).toBe(0);
  putRunbook(r, 'stg-east-1');
  git(r, ['commit', '-q', '--allow-empty', '-m', 'work'], r.proj);
  return r;
}

const PUSH = 'git push -q origin HEAD:main';

// ---------------------------------------------------------------- H2-12

describe.skipIf(!POSIX)('H2-12: acknowledging without a re-read is an operator action', { timeout: 180_000 }, () => {
  it('the refusal names who must re-read and never offers ack; an agent ack is refused and logged', () => {
    const r = gitRig();
    const d = sh(r, PUSH);
    expect(d.status).toBe(77);
    expect(d.stderr).toContain('did NOT run `git push -q origin HEAD:main`');
    expect(d.stderr).toContain('Still to re-read the current version: agent-a');
    expect(d.stderr).toContain('If you cannot re-read them yourself, stop and ask the operator.');
    expect(d.stderr).not.toMatch(/\back\b|override/i);
    expect(landed(r)).toBe(false);

    // what the agent was told in 0.8.0: no TTY (an agent's Bash), no --operator → refused, logged
    const a = kl(r, ['shim', 'ack', '--dir', r.shims, '--data-dir', r.data], { KRONICLE_LITE_ACTOR: 'agent-a' }, r.proj);
    expect(a.status).toBe(2);
    expect(a.stderr).toMatch(/operator action/);
    expect(a.stderr).toMatch(/re-read the pending items instead/);
    expect(sh(r, PUSH).status).toBe(77);
    expect(landed(r)).toBe(false);
    const log1 = readFileSync(join(r.state, 'shim.log'), 'utf8');
    expect(log1).toMatch(/ ack refused through=head actor=agent-a user=\S+ reason=not-an-operator/);

    // the operator, explicitly
    const o = kl(r, ['shim', 'ack', '--operator', '--actor', 'ops-jo', '--dir', r.shims, '--data-dir', r.data], {}, r.proj);
    expect(o.status, o.stderr).toBe(0);
    expect(o.stdout).toMatch(/acknowledged through seq (\d+) .*logged as ops-jo \(--operator\)/);
    const seq = /through seq (\d+)/.exec(o.stdout)![1]!;
    expect(readFileSync(join(r.state, 'shim.log'), 'utf8')).toMatch(new RegExp(` ack operator-ack through=${seq} from=\\d+ acknowledged=1 project=\\S+ actor=ops-jo user=\\S+ confirmed=--operator`));
    expect(sh(r, PUSH).status).toBe(0);
    expect(landed(r)).toBe(true);
  });

  it('re-running shim install keeps the starting point (it is not an ack by the back door)', () => {
    const r = gitRig();
    expect(sh(r, PUSH).status).toBe(77);
    expect(kl(r, ['shim', 'install', '--dir', r.shims, '--data-dir', r.data, '--commands', 'git'], {}, r.proj).status).toBe(0);
    expect(sh(r, PUSH).status).toBe(77);
    expect(landed(r)).toBe(false);
  });
});

// ---------------------------------------------------------------- H2-13

describe.skipIf(!POSIX)('H2-13: git pre-push hook (shim install --git-hook)', { timeout: 180_000 }, () => {
  it('installs a marked hook, writes no git config, shows in status, and catches pushes the PATH shim cannot see', () => {
    const r = gitRig({ install: ['--git-hook', '--repo', '.'] });
    const hook = join(r.proj, '.git', 'hooks', 'pre-push');
    expect(readFileSync(hook, 'utf8')).toMatch(/^#!\/bin\/sh\n# kronicle-lite-shim v1 hook=pre-push\n/);
    expect(readFileSync(join(r.proj, '.git', 'config'), 'utf8')).toBe(r.configBefore);
    expect(existsSync(join(r.home, '.gitconfig'))).toBe(false);
    const st = JSON.parse(kl(r, ['shim', 'status', '--dir', r.shims, '--json'], {}, r.proj).stdout);
    expect(st.git_hooks).toEqual([expect.objectContaining({ file: hook, present: true, active: true, chained: null })]);
    expect(st.repo_hook).toMatchObject({ present: true });
    expect(kl(r, ['shim', 'status', '--dir', r.shims], {}, r.proj).stdout).toMatch(/git hook\s+active\s+.*pre-push/);

    // no shim on PATH at all (= /usr/bin/git, sudo's secure_path, command -p, PATH prefix)
    const bare = sh(r, PUSH, { path: SYS_PATH });
    expect(bare.status).not.toBe(0);
    expect(bare.stderr).toContain('kronicle-lite shim: did NOT run `git push origin`');
    const ours = bare.stderr.split('\n').filter((l) => !/^(error|To |hint):?/.test(l)).join('\n'); // git's own lines name the remote
    expect(ours).not.toContain('remote.git'); // the hook never prints the remote URL
    // git starts git itself (exec-path first on PATH): alias, rebase -x
    expect(sh(r, `git -c alias.p='!git push -q origin HEAD:main' p`).status).not.toBe(0);
    expect(sh(r, `GIT_EDITOR=true git rebase -q --no-ff -x '${PUSH}' HEAD~1`).status).not.toBe(0);
    // env -i and git -C from elsewhere
    expect(sh(r, `env -i git -C '${r.proj}' push -q origin HEAD:main`, { cwd: r.other }).status).not.toBe(0);
    // the forged same-pid marker skips the PATH shim but not the hook
    expect(sh(r, `KRONICLE_SHIM_EXEC="$$:1:" exec ${PUSH}`).status).not.toBe(0);
    expect(landed(r)).toBe(false);
    // --no-verify skips every pre-push hook (git's rule; the PATH shim still sees it)
    expect(sh(r, `${PUSH} --no-verify`).status).toBe(77);
    expect(landed(r)).toBe(false);

    read(r, 'agent-a');
    const ok = sh(r, PUSH, { path: SYS_PATH });
    expect(ok.status, ok.stderr).toBe(0);
    expect(landed(r)).toBe(true);
    expect(readFileSync(join(r.state, 'shim.log'), 'utf8')).toMatch(/ git\(pre-push\) check \d+ms outcome=deny rc=77/);

    // full uninstall removes the hook too
    const u = JSON.parse(kl(r, ['shim', 'uninstall', '--dir', r.shims, '--json']).stdout);
    expect(u.git_hooks).toEqual([expect.objectContaining({ file: hook, removed: true })]);
    expect(existsSync(hook)).toBe(false);
  });

  it('chains an existing pre-push hook (args and stdin), and uninstall puts it back unchanged', () => {
    const rec = { file: '' };
    const r = gitRig({
      before: (g) => {
        rec.file = join(g.root, 'chained.log');
        const own = `#!/bin/sh\necho "args:$1" >> '${rec.file}'\ncat >> '${rec.file}'\nexit 0\n`;
        writeFileSync(join(g.proj, '.git', 'hooks', 'pre-push'), own);
        chmodSync(join(g.proj, '.git', 'hooks', 'pre-push'), 0o755);
      },
    });
    const hooks = join(r.proj, '.git', 'hooks');
    const original = readFileSync(join(hooks, 'pre-push'), 'utf8');
    const i = kl(r, ['shim', 'install', '--dir', r.shims, '--data-dir', r.data, '--commands', 'git', '--git-hook'], {}, r.proj);
    expect(i.status, i.stderr).toBe(0);
    expect(i.stdout).toContain(`the existing hook was moved to ${join(hooks, 'pre-push.kronicle-chained')} and runs after the check`);
    expect(readFileSync(join(hooks, 'pre-push.kronicle-chained'), 'utf8')).toBe(original);

    expect(sh(r, PUSH, { path: SYS_PATH }).status).not.toBe(0);
    expect(existsSync(rec.file)).toBe(false); // refused before the chained hook ran
    read(r, 'agent-a');
    expect(sh(r, PUSH, { path: SYS_PATH }).status).toBe(0);
    const log = readFileSync(rec.file, 'utf8');
    expect(log).toMatch(/^args:origin\nHEAD [0-9a-f]{40} refs\/heads\/main [0-9a-f]{40}\n$/);

    // re-install keeps the chain; uninstall --git-hook restores the original and keeps the shims
    expect(kl(r, ['shim', 'install', '--dir', r.shims, '--data-dir', r.data, '--commands', 'git', '--git-hook'], {}, r.proj).status).toBe(0);
    expect(readFileSync(join(hooks, 'pre-push.kronicle-chained'), 'utf8')).toBe(original);
    const u = kl(r, ['shim', 'uninstall', '--git-hook', '--repo', r.proj, '--dir', r.shims]);
    expect(u.status, u.stderr).toBe(0);
    expect(u.stdout).toMatch(/removed; the chained hook is back in place/);
    expect(readFileSync(join(hooks, 'pre-push'), 'utf8')).toBe(original);
    expect(existsSync(join(hooks, 'pre-push.kronicle-chained'))).toBe(false);
    expect(existsSync(join(r.shims, 'git'))).toBe(true);
    expect(JSON.parse(readFileSync(join(r.state, 'config.json'), 'utf8')).git_hooks).toBeUndefined();
  });

  it('never overwrites: a foreign pre-push plus an existing pre-push.kronicle-chained is refused before anything is written', () => {
    const r = gitRig();
    const hooks = join(r.proj, '.git', 'hooks');
    writeFileSync(join(hooks, 'pre-push'), '#!/bin/sh\nexit 0\n');
    writeFileSync(join(hooks, 'pre-push.kronicle-chained'), '#!/bin/sh\nexit 1\n');
    const before = readdirSync(r.shims).sort();
    const i = kl(r, ['shim', 'install', '--dir', r.shims, '--data-dir', r.data, '--commands', 'git,terraform', '--git-hook'], {}, r.proj);
    expect(i.status).toBe(1);
    expect(i.stderr).toMatch(/refusing to overwrite either/);
    expect(readFileSync(join(hooks, 'pre-push'), 'utf8')).toBe('#!/bin/sh\nexit 0\n');
    expect(readdirSync(r.shims).sort()).toEqual(before); // no terraform shim written either
  });

  it('respects core.hooksPath (repo-local, set by the user) and writes no config of its own', () => {
    const r = gitRig({ before: (g) => git(g, ['config', 'core.hooksPath', 'githooks'], g.proj) });
    const i = kl(r, ['shim', 'install', '--dir', r.shims, '--data-dir', r.data, '--commands', 'git', '--git-hook', '--json'], {}, r.proj);
    expect(i.status, i.stderr).toBe(0);
    expect(JSON.parse(i.stdout).git_hooks[0].file).toBe(join(r.proj, 'githooks', 'pre-push'));
    expect(existsSync(join(r.proj, '.git', 'hooks', 'pre-push'))).toBe(false);
    expect(readFileSync(join(r.proj, '.git', 'config'), 'utf8')).toBe(r.configBefore);
    expect(sh(r, PUSH, { path: SYS_PATH }).status).not.toBe(0);
    expect(landed(r)).toBe(false);
    // the user points hooksPath elsewhere: status says the hook is no longer used
    git(r, ['config', 'core.hooksPath', 'elsewhere'], r.proj);
    expect(kl(r, ['shim', 'status', '--dir', r.shims], {}, r.proj).stdout).toMatch(/git hook\s+INACTIVE .*git now uses hooks dir .*elsewhere/);
  });

  it('covers initialized submodules, and checks a submodule push against the superproject too', () => {
    const sub: { remote: string } = { remote: '' };
    const r = gitRig({
      before: (g) => {
        sub.remote = join(g.root, 'sub.git');
        const src = join(g.root, 'subsrc');
        mkdirSync(src);
        git(g, ['init', '-q', '--bare', '-b', 'main', sub.remote], g.root);
        git(g, ['init', '-q', '-b', 'main'], src);
        git(g, ['commit', '-q', '--allow-empty', '-m', 's'], src);
        git(g, ['push', '-q', sub.remote, 'main'], src);
        git(g, ['submodule', 'add', '-q', sub.remote, 'sub'], g.proj);
        git(g, ['commit', '-q', '-m', 'sub'], g.proj);
      },
      install: ['--git-hook'],
    });
    const subDir = join(r.proj, 'sub');
    const subHook = git(r, ['rev-parse', '--path-format=absolute', '--git-path', 'hooks/pre-push'], subDir);
    expect(readFileSync(subHook, 'utf8')).toContain('kronicle-lite-shim v1 hook=pre-push');
    git(r, ['commit', '-q', '--allow-empty', '-m', 'subwork'], subDir);
    expect(sh(r, `git submodule foreach -q '${PUSH}'`).status).not.toBe(0);
    expect(landed(r, subDir, sub.remote)).toBe(false);
  });
});

// ---------------------------------------------------------------- H2-14

describe('H2-14: the project is the one the command acts on', { timeout: 180_000 }, () => {
  it('commandTarget: git -C (cumulative, "" is a no-op), --git-dir, --work-tree, GIT_DIR; chdir options of other tools', () => {
    const root = tempDir('kl-target-');
    const a = join(root, 'a');
    const b = join(a, 'b');
    mkdirSync(join(b, '.git'), { recursive: true });
    const t = (argv: string[], env: NodeJS.ProcessEnv = {}) => commandTarget(argv, root, env);
    expect(t(['git', 'push'])).toMatchObject({ dir: root, explicit: false, error: null });
    expect(t(['git', '-C', 'a', '-C', '', '-C', 'b', '--no-pager', 'push'])).toMatchObject({ dir: b, explicit: true, via: '-C', error: null });
    expect(t(['git', '-c', 'x.y=1', '-C', b, 'push', '-C', 'ignored'])).toMatchObject({ dir: b });
    expect(t(['git', `--git-dir=${join(b, '.git')}`, 'push'])).toMatchObject({ dir: b, via: '--git-dir' });
    expect(t(['git', '-C', 'a', '--git-dir', 'b/.git', 'push'])).toMatchObject({ dir: b });
    expect(t(['git', '--git-dir=x', `--work-tree=${a}`, 'push'])).toMatchObject({ dir: a, via: '--work-tree' });
    expect(t(['/usr/bin/git', 'push'], { GIT_DIR: join(b, '.git') })).toMatchObject({ dir: b, via: 'GIT_DIR', git_env: true });
    expect(t(['git.exe', 'push'], { GIT_WORK_TREE: 'a' })).toMatchObject({ dir: a, via: 'GIT_WORK_TREE' });
    expect(t(['git', '-C'])).toMatchObject({ error: 'git -C has no directory' });
    expect(t(['git', '-C', 'nope', 'push']).error).toMatch(/is not a directory/);
    expect(t(['git', '--git-dir=nope', 'push']).error).toMatch(/does not exist/);
    expect(t(['terraform', '-chdir=a', 'apply'])).toMatchObject({ dir: a, via: '-chdir' });
    expect(t(['terraform', 'apply', '-chdir=a'])).toMatchObject({ dir: root, explicit: false });
    expect(t(['make', 'release', '-C', 'a', '-Cb'])).toMatchObject({ dir: b });
    expect(t(['make', '--directory=a', 'deploy'])).toMatchObject({ dir: a });
    expect(t(['npm', 'publish', '--prefix', 'a'])).toMatchObject({ dir: a });
    expect(t(['pnpm', '--dir=a', 'publish'])).toMatchObject({ dir: a });
    expect(t(['yarn', '--cwd', 'a', 'npm', 'publish'])).toMatchObject({ dir: a });
    expect(t(['kubectl', 'apply', '-f', 'a'])).toMatchObject({ dir: root, explicit: false });
    expect(repoOfGitDir(join(b, '.git', 'worktrees', 'w'))).toBe(b);
    expect(repoOfGitDir(join(root, 'bare.git'))).toBe(join(root, 'bare.git'));
  });

  it('pulse -- git -C <project> push from another directory checks <project>; an unknown target is refused', () => {
    const r = gitRig();
    const pulse = (cwd: string, cmd: string[], env: Record<string, string> = {}) =>
      kl(r, ['pulse', '--state', r.state, '--data-dir', r.data, '--cwd', cwd, '--json', '--', ...cmd], env, cwd);
    const here = pulse(r.other, ['git', 'push']); // the other dir's own project: the runbook is not about it
    expect(here.status, here.stderr).toBe(0);
    const c = pulse(r.other, ['git', '-C', r.proj, 'push']);
    expect(c.status).toBe(77);
    expect(JSON.parse(c.stdout)).toMatchObject({ decision: 'deny', reason: 'retractions', target: { dir: r.proj, explicit: true, via: '-C' } });
    expect(pulse(r.other, ['git', `--git-dir=${join(r.proj, '.git')}`, 'push']).status).toBe(77);
    expect(pulse(r.other, ['git', 'push'], { GIT_DIR: join(r.proj, '.git') }).status).toBe(77);
    const bad = pulse(r.other, ['git', '-C', join(r.root, 'missing'), 'push']);
    expect(bad.status).toBe(77);
    expect(JSON.parse(bad.stdout)).toMatchObject({ decision: 'deny', reason: 'target' });
    expect(bad.stderr).toMatch(/cannot tell which project it acts on/);
  });

  it.skipIf(!POSIX)('the git shim refuses git -C <project> push from elsewhere (and from the temp dir root)', () => {
    const r = gitRig();
    expect(sh(r, `git -C '${r.proj}' push -q origin HEAD:main`, { cwd: r.other }).status).toBe(77);
    expect(sh(r, `git -C '${r.proj}' push -q origin HEAD:main`, { cwd: dirname(r.root) }).status).toBe(77);
    expect(sh(r, `GIT_DIR='${join(r.proj, '.git')}' git push -q origin HEAD:main`, { cwd: r.other }).status).toBe(77);
    expect(landed(r)).toBe(false);
    expect(readFileSync(join(r.state, 'shim.log'), 'utf8')).not.toMatch(/decision=allow reason=clear/);
  });

  it.skipIf(!POSIX)('shim exec: --project names the project; a world-changing command with an unknown target fails closed', () => {
    const r = gitRig();
    const x = (args: string[], cwd = r.other) =>
      spawnSync(process.execPath, [CLI, 'shim', 'exec', '--dir', r.shims, '--tool', 'git', ...args], { cwd, env: baseEnv({ PATH: `${r.shims}:${SYS_PATH}` }, r.home), encoding: 'utf8' });
    expect(x(['--project', r.proj, '--', '-C', r.proj, 'push', '-q', 'origin', 'HEAD:main']).status).toBe(77);
    expect(x(['--', '-C', r.proj, 'push', '-q', 'origin', 'HEAD:main']).status).toBe(77);
    const missing = x(['--project', join(r.root, 'missing'), '--', 'push']);
    expect(missing.status).toBe(77);
    expect(missing.stderr).toMatch(/--project .* is not a directory/);
    expect(x(['--', '-C', join(r.root, 'missing'), 'push']).status).toBe(77);
    expect(landed(r)).toBe(false);
    expect(x(['--', '-C', r.proj, 'status', '--short']).status).toBe(0); // read-only: no check, runs
  });
});

// ---------------------------------------------------------------- H2-16

describe('H2-16: by default the invoking actor re-reads for itself', { timeout: 180_000 }, () => {
  const pulse = (r: GRig, actor: string, extra: string[] = []) => {
    const p = kl(r, ['pulse', '--state', r.state, '--data-dir', r.data, '--cwd', r.proj, '--json', ...extra, '--', 'git', 'push'], { KRONICLE_LITE_ACTOR: actor }, r.proj);
    return { status: p.status, json: JSON.parse(p.stdout), stderr: p.stderr };
  };

  it('agent-a clears its own gate; agent-b (stale) is still refused and told exactly who must re-read', () => {
    const r = gitRig({ readers: ['agent-a', 'agent-b'] });
    read(r, 'agent-a');
    const a = pulse(r, 'agent-a');
    expect(a.status, a.stderr).toBe(0);
    expect(a.json).toMatchObject({ decision: 'allow', pending_mode: 'actor', invoking_actor: 'agent-a', blocking: [] });
    const b = pulse(r, 'agent-b');
    expect(b.status).toBe(77); // agent-a's clearance did not move agent-b's position
    expect(b.json.blocking[0]).toMatchObject({ pending_actors: ['agent-b'], unread_by: ['agent-b'] });
    expect(b.stderr).toContain('Still to re-read the current version: agent-b (the invoking actor, agent-b).');
    expect(b.stderr).not.toMatch(/\back\b|override/i);
    read(r, 'agent-b');
    expect(pulse(r, 'agent-b').status).toBe(0);
  });

  it('a change only other actors read does not block; an instruction or an unread change still does', () => {
    const r = gitRig({ readers: ['agent-b'] });
    const c = pulse(r, 'agent-c');
    expect(c.status, c.stderr).toBe(0);
    expect(c.json.not_relied_on).toHaveLength(1);
    expect(c.stderr).toMatch(/1 change\(s\) since the last check to text agent-c never read \(read by others only\)/);
    // nobody read it at all: blocks the invoker until it reads the current version
    const n = gitRig({ readers: [] });
    expect(pulse(n, 'agent-c').status).toBe(77);
    read(n, 'agent-c');
    expect(pulse(n, 'agent-c').status).toBe(0);
  });

  it('--all-readers (opt-in) and an unset actor keep the 0.8.0 rule: every reader must re-read', () => {
    const r = gitRig({ readers: ['agent-a', 'agent-b'], install: ['--all-readers'] });
    read(r, 'agent-a');
    const a = pulse(r, 'agent-a');
    expect(a.status).toBe(77);
    expect(a.json).toMatchObject({ pending_mode: 'readers', invoking_actor: 'agent-a' });
    expect(a.stderr).toContain('Still to re-read the current version: agent-b (every reader of the changed text is checked: --all-readers).');
    expect(JSON.parse(readFileSync(join(r.state, 'config.json'), 'utf8')).all_readers).toBe(true);

    const u = gitRig({ readers: ['agent-a', 'agent-b'] });
    read(u, 'agent-a');
    const none = pulse(u, '');
    expect(none.status).toBe(77);
    expect(none.json).toMatchObject({ pending_mode: 'readers', invoking_actor: null });
    expect(none.stderr).toContain('agent-b (every reader of the changed text is checked: no invoking actor is set for this command)');
  });

  it('an operator ack moves every actor past it (the project cursor wins over an older actor cursor)', () => {
    const r = gitRig();
    read(r, 'agent-a');
    expect(pulse(r, 'agent-a').status).toBe(0); // agent-a's own cursor at this head
    putRunbook(r, 'stg-north-3');
    expect(pulse(r, 'agent-a').status).toBe(77);
    expect(kl(r, ['shim', 'ack', '--operator', '--dir', r.shims, '--data-dir', r.data], {}, r.proj).status).toBe(0);
    expect(pulse(r, 'agent-a').status).toBe(0);
  });

  it.skipIf(!POSIX)('the sh wrapper passes KRONICLE_LITE_ACTOR through; status names the mode', () => {
    const r = gitRig({ readers: ['agent-a', 'agent-b'] });
    read(r, 'agent-a');
    expect(sh(r, PUSH).status).toBe(77); // no actor in the environment: every reader
    expect(sh(r, PUSH, { env: { KRONICLE_LITE_ACTOR: 'agent-a' } }).status).toBe(0);
    expect(landed(r)).toBe(true);
    expect(kl(r, ['shim', 'status', '--dir', r.shims], { KRONICLE_LITE_ACTOR: 'agent-a' }, r.proj).stdout).toContain('pending actor: the invoking actor (KRONICLE_LITE_ACTOR=agent-a here)');
  });
});

// ---------------------------------------------------------------- L2-08, L2-03 (live-agent findings)

/** A fake "real" binary that records that it ran. */
function fakeBin(dir: string, name: string, log: string): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, name), `#!/bin/sh\necho "${name} $*" >> '${log}'\nexit 0\n`);
  chmodSync(join(dir, name), 0o755);
}

/** Fake npm/make/terraform, an unscoped runbook agent-a read, shims installed, then the runbook changed. */
function toolRig(opts: { mode?: 'deny' | 'warn' } = {}) {
  const root = tempDir('kl-shimt-');
  const r = { root, home: join(root, 'home'), bin: join(root, 'bin'), shims: join(root, 'shims'), data: join(root, 'data'), proj: join(root, 'proj'), log: join(root, 'ran.log'), runbook: join(root, 'rb.md') };
  for (const d of [r.home, r.proj]) mkdirSync(d, { recursive: true });
  writeFileSync(r.log, '');
  for (const t of ['npm', 'make', 'terraform']) fakeBin(r.bin, t, r.log);
  const put = (v: string) => {
    writeFileSync(r.runbook, `# Runbook\n\n## Ship\n\nShip to ${v}.\n`);
    expect(kl(r, ['put', 'runbook', r.runbook, '--data-dir', r.data, '--all-projects']).status).toBe(0);
  };
  put('stg-a');
  expect(kl(r, ['get', 'runbook', '--actor', 'agent-a', '--data-dir', r.data]).status).toBe(0);
  const i = kl(r, ['shim', 'install', '--dir', r.shims, '--data-dir', r.data, '--commands', 'npm,make,terraform', ...(opts.mode ? ['--mode', opts.mode] : [])]);
  expect(i.status, i.stderr).toBe(0);
  put('stg-b');
  const run = (cmd: string) => {
    const p = spawnSync('sh', ['-c', cmd], { cwd: r.proj, env: baseEnv({ PATH: `${r.shims}:${r.bin}:${SYS_PATH}` }, r.home), encoding: 'utf8', timeout: 60_000 });
    return { status: p.status, stderr: p.stderr };
  };
  const ran = () => readFileSync(r.log, 'utf8');
  return { ...r, run, ran };
}

describe.skipIf(!POSIX)('L2-08: `ship` scripts and targets, tools given by path', { timeout: 180_000 }, () => {
  it('npm run ship / make ship are checked (one-command repros); shim exec --tool /abs/make uses make rules', () => {
    const r = toolRig();
    expect(r.run('npm run ship').status).toBe(77);
    expect(r.run('make ship').status).toBe(77);
    expect(r.run('make shipping-list').status).toBe(0); // not the word
    const x = spawnSync(process.execPath, [CLI, 'shim', 'exec', '--dir', r.shims, '--tool', join(r.bin, 'make'), '--', 'release'], { cwd: r.proj, env: baseEnv({ PATH: `${r.shims}:${r.bin}:${SYS_PATH}` }, r.home), encoding: 'utf8' });
    expect(x.status).toBe(77);
    expect(x.stderr).toContain('did NOT run');
    expect(r.ran()).toBe('make shipping-list\n');
  });
});

describe.skipIf(!POSIX)('L2-03: a corrupt store fails closed (deny) or warns loudly (warn), never "unavailable"', { timeout: 180_000 }, () => {
  const zeroPage = (data: string, offset: number) => {
    const f = join(data, 'kronicle-lite.db');
    const b = readFileSync(f);
    b.fill(0, offset, Math.min(offset + 4096, b.length));
    writeFileSync(f, b);
  };

  it('a zeroed page: deny mode refuses every time; warn mode runs with a loud line every time', () => {
    const d = toolRig();
    zeroPage(d.data, 8192);
    for (let i = 0; i < 2; i++) {
      const a = d.run('terraform apply');
      expect(a.status).toBe(77);
      expect(a.stderr).toMatch(/did NOT run `terraform apply` — the kronicle-lite store is CORRUPT \(.*(malformed|not a database).*\)/);
    }
    expect(d.ran()).toBe('');
    expect(readFileSync(join(d.shims, '.kronicle-shim', 'shim.log'), 'utf8')).toMatch(/pulse\(node\) decision=deny reason=corrupt/);
    expect(readFileSync(join(d.shims, '.kronicle-shim', 'last-error'), 'utf8')).toMatch(/CORRUPT/);

    const w = toolRig({ mode: 'warn' });
    zeroPage(w.data, 8192);
    for (let i = 0; i < 2; i++) {
      const a = w.run('terraform apply');
      expect(a.status).toBe(0);
      expect(a.stderr).toMatch(/\(warn\): `terraform apply` is running UNCHECKED — the kronicle-lite store is CORRUPT/);
    }
    expect(w.ran()).toBe('terraform apply\nterraform apply\n');
  });

  it('a bad header is corrupt too (shim exec refuses as well)', () => {
    const d = toolRig();
    zeroPage(d.data, 0);
    expect(d.run('terraform apply').stderr).toMatch(/CORRUPT \(.*bad header/);
    const x = spawnSync(process.execPath, [CLI, 'shim', 'exec', '--dir', d.shims, '--tool', 'terraform', '--', 'apply'], { cwd: d.proj, env: baseEnv({ PATH: `${d.shims}:${d.bin}:${SYS_PATH}` }, d.home), encoding: 'utf8' });
    expect(x.status).toBe(77);
    expect(x.stderr).toMatch(/CORRUPT/);
    expect(d.ran()).toBe('');
  });
});

// ---------------------------------------------------------------- P2-01

describe('P2-01: the shims check the store the server uses', { timeout: 180_000 }, () => {
  /** Shims installed WITHOUT --data-dir; a store per `stores` (relative to root: 'proj/.kronicle-lite', 'home/.kronicle-lite'). */
  function storeRig(stores: string[], envFor: (root: string) => Record<string, string> = () => ({})) {
    const root = tempDir('kl-shims-');
    const r = { root, home: join(root, 'home'), proj: join(root, 'proj'), shims: join(root, 'shims'), runbook: join(root, 'rb.md') };
    mkdirSync(r.home, { recursive: true });
    mkdirSync(join(r.proj, 'sub'), { recursive: true });
    git(r, ['init', '-q', '-b', 'main'], r.proj);
    const env = { USERPROFILE: r.home, ...envFor(root) };
    const put = (v: string) => {
      writeFileSync(r.runbook, `# Runbook\n\n## Deploy\n\nDeploy to ${v}.\n`);
      for (const s of stores) expect(kl(r, ['put', 'runbook', r.runbook, '--data-dir', join(root, s), '--cwd', r.proj], env).status).toBe(0);
    };
    put('stg-a');
    for (const s of stores) expect(kl(r, ['get', 'runbook', '--actor', 'agent-a', '--data-dir', join(root, s)], env).status).toBe(0);
    expect(kl(r, ['shim', 'install', '--dir', r.shims, '--commands', 'git'], env, r.proj).status).toBe(0);
    put('stg-b');
    const pulse = (cwd: string, cmd: string[], more: Record<string, string> = {}, args: string[] = []) => {
      const p = kl(r, ['pulse', '--state', join(r.shims, '.kronicle-shim'), ...args, '--cwd', cwd, '--json', '--', ...cmd], { ...env, ...more }, cwd);
      return { status: p.status, json: JSON.parse(p.stdout || '{}'), stderr: p.stderr };
    };
    return { ...r, pulse };
  }

  it('finds a project-local .kronicle-lite/ above the target (README Cursor / Copilot layout) and refuses on its change', () => {
    const r = storeRig(['proj/.kronicle-lite']);
    const a = r.pulse(join(r.proj, 'sub'), ['git', 'push']);
    expect(a.status, a.stderr).toBe(77);
    expect(a.json).toMatchObject({ decision: 'deny', reason: 'retractions' });
    expect(r.pulse(r.root, ['git', '-C', r.proj, 'push']).status).toBe(77); // the target's store, from elsewhere
    const st = JSON.parse(kl(r, ['shim', 'status', '--dir', r.shims, '--json'], { USERPROFILE: r.home }, r.proj).stdout);
    expect(st.store).toMatchObject({ source: 'found', exists: true });
  });

  it('two different stores: refused, naming both; pinning one with shim install --data-dir settles it', () => {
    const r = storeRig(['proj/.kronicle-lite', 'home/.kronicle-lite']);
    const a = r.pulse(r.proj, ['git', 'push']);
    expect(a.status).toBe(77);
    expect(a.json).toMatchObject({ decision: 'deny', reason: 'ambiguous-store' });
    expect(a.stderr).toMatch(/found more than one kronicle-lite store \(.*\.kronicle-lite, .*\.kronicle-lite\)/);
    expect(a.stderr).toContain(join(r.proj, '.kronicle-lite'));
    expect(a.stderr).toContain(join(r.home, '.kronicle-lite'));
    expect(a.stderr).toContain('kronicle-lite shim install --data-dir DIR');
    const w = r.pulse(r.proj, ['git', 'push'], {}, ['--mode', 'warn']);
    expect(w.status).toBe(0);
    expect(w.stderr).toMatch(/running UNCHECKED/);
    // pinned: that store only (its change still blocks)
    const p = r.pulse(r.proj, ['git', 'push'], {}, ['--data-dir', join(r.proj, '.kronicle-lite')]);
    expect(p.json).toMatchObject({ reason: 'retractions' });
  });

  it('$KRONICLE_LITE_DATA_DIR is the configured store; none anywhere refuses', () => {
    const r = storeRig(['elsewhere'], (root) => ({ KRONICLE_LITE_DATA_DIR: join(root, 'elsewhere') })); // install sees it too
    expect(r.pulse(r.proj, ['git', 'push']).json).toMatchObject({ decision: 'deny', reason: 'retractions' });
    const none = r.pulse(r.proj, ['git', 'push'], { KRONICLE_LITE_DATA_DIR: '' });
    expect(none.status).toBe(77);
    expect(none.json).toMatchObject({ decision: 'deny', reason: 'no-store' });
    expect(none.stderr).toMatch(/found no kronicle-lite store \(looked in .*home.*\.kronicle-lite; \.kronicle-lite\/ in .*proj and its parents\)/);
  });
});
