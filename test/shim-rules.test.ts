/**
 * The shim decision table: which invocations are world-changing. Every case
 * runs through BOTH implementations — rules.ts classify() (used by `shim
 * exec` / Windows) and the generated POSIX sh (the wrapper itself), under
 * dash and bash --posix when present — and they must agree with the table.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { classify, hasWorldWord, parsePatterns, specFor } from '../src/shim/rules.js';
import { decisionSh } from '../src/shim/script.js';
import { tempDir } from './helpers/fs.js';

type Case = [tool: string, args: string[], world: boolean, patterns?: string[]];

const CASES: Case[] = [
  // git: push / subtree push / lfs push; global options skipped
  ['git', ['status'], false],
  ['git', ['push'], true],
  ['git', ['push', 'origin', 'main'], true],
  ['git', ['push', '--force-with-lease'], true],
  ['git', ['-C', '/tmp/x', 'push'], true],
  ['git', ['-C', 'my dir', 'push'], true],
  ['git', ['--no-pager', 'push'], true],
  ['git', ['-P', 'push'], true],
  ['git', ['-c', 'user.name=x', 'push'], true],
  ['git', ['-c', 'core.sshCommand=ssh -i key', 'push', 'origin'], true],
  ['git', ['--git-dir=/x/.git', 'push'], true],
  ['git', ['--git-dir', '/x/.git', '--work-tree', '/x', 'push'], true],
  ['git', ['commit', '-m', 'git push'], false],
  ['git', ['commit', '-m', 'push'], false],
  ['git', ['log', '--oneline', 'push'], false],
  ['git', ['subtree', 'push', '--prefix=dist', 'origin', 'gh-pages'], true],
  ['git', ['subtree', '-P', 'dist', 'push', 'origin', 'gh-pages'], true],
  ['git', ['subtree', 'pull', '--prefix', 'dist', 'origin', 'main'], false],
  ['git', ['lfs', 'push', 'origin', 'main'], true],
  ['git', ['lfs', 'pull'], false],
  ['git', ['push', '--help'], false],
  ['git', ['help', 'push'], false],
  ['git', ['fetch', '--all'], false],
  ['git', ['pull', '--rebase'], false],
  ['git', ['stash', 'push', '-m', 'wip'], false],
  ['git', ['remote', 'add', 'push', 'https://example.invalid/r.git'], false],
  ['git', ['', 'push'], false],
  ['git', ['--exec-path', 'push'], false],
  ['git', ['--', 'push'], true],
  ['git', [], false],
  // terraform / tofu: apply, destroy
  ['terraform', ['plan'], false],
  ['terraform', ['apply'], true],
  ['terraform', ['apply', '-auto-approve'], true],
  ['terraform', ['-chdir=infra', 'apply'], true],
  ['terraform', ['destroy', '-target=aws_instance.x'], true],
  ['terraform', ['init', '-upgrade'], false],
  ['terraform', ['-chdir=infra', 'plan', '-out', 'p.tfplan'], false],
  ['terraform', ['apply', '--help'], false],
  ['terraform', ['state', 'list'], false],
  ['tofu', ['apply', 'p.tfplan'], true],
  // kubectl: apply/delete/patch/replace/rollout (not rollout status/history)
  ['kubectl', ['get', 'pods'], false],
  ['kubectl', ['apply', '-f', 'x.yaml'], true],
  ['kubectl', ['-n', 'prod', 'apply', '-f', 'x.yaml'], true],
  ['kubectl', ['--namespace', 'prod', 'delete', 'pod', 'x'], true],
  ['kubectl', ['--context', 'prod-ctx', 'patch', 'deploy', 'x', '-p', '{"spec":{}}'], true],
  ['kubectl', ['rollout', 'restart', 'deploy/x'], true],
  ['kubectl', ['rollout', 'status', 'deploy/x'], false],
  ['kubectl', ['-n', 'prod', 'rollout', 'history', 'deploy/x'], false],
  ['kubectl', ['rollout', '-n', 'prod', 'status', 'deploy/x'], false],
  ['kubectl', ['--cache-dir', '/tmp/c', 'apply', '-f', 'x'], true],
  ['kubectl', ['--some-new-flag', 'value', 'apply', '-f', 'x'], true],
  ['kubectl', ['describe', 'pod', 'apply'], false],
  ['kubectl', ['replace', '-f', 'x.yaml'], true],
  ['kubectl', ['logs', 'deploy/x'], false],
  ['kubectl', ['diff', '-f', 'x.yaml'], false],
  ['oc', ['-n', 'prod', 'apply', '-f', 'x'], true],
  // helm
  ['helm', ['list'], false],
  ['helm', ['install', 'rel', './chart'], true],
  ['helm', ['upgrade', '--install', 'rel', './chart'], true],
  ['helm', ['-n', 'prod', 'uninstall', 'rel'], true],
  ['helm', ['template', 'rel', './chart'], false],
  ['helm', ['rollback', 'rel', '3'], true],
  // npm / pnpm / yarn: publish; run scripts named deploy/migrate/publish/release
  ['npm', ['install'], false],
  ['npm', ['publish'], true],
  ['npm', ['publish', '--access', 'public'], true],
  ['npm', ['--prefix', 'pkg', 'publish'], true],
  ['npm', ['--registry', 'https://r.example', 'publish'], true],
  ['npm', ['--some-flag', 'value', 'publish'], true],
  ['npm', ['run', 'build'], false],
  ['npm', ['run', 'deploy'], true],
  ['npm', ['run', 'predeploy'], false],
  ['npm', ['run', 'release:prod'], true],
  ['npm', ['run-script', 'db-migrate'], true],
  ['npm', ['test'], false],
  ['npm', ['publish', '--help'], false],
  ['npm', ['install', 'publish'], false],
  ['pnpm', ['-r', 'publish'], true],
  ['pnpm', ['--filter', 'web', 'publish'], true],
  ['pnpm', ['install'], false],
  ['pnpm', ['deploy', 'out'], true],
  ['pnpm', ['build'], false],
  ['yarn', ['npm', 'publish'], true],
  ['yarn', ['publish'], true],
  ['yarn', ['release'], true],
  ['yarn', ['add', 'release-it'], false],
  ['yarn', ['--cwd', 'pkg', 'run', 'deploy'], true],
  // make (opt-in): any target naming a world-changing step
  ['make', [], false],
  ['make', ['build'], false],
  ['make', ['release'], true],
  ['make', ['-C', 'sub', 'deploy'], true],
  ['make', ['VERSION=deploy', 'build'], false],
  ['make', ['-j4', 'publish'], true],
  ['make', ['predeploy'], false],
  ['make', ['build', 'db-migrate'], true],
  // user patterns
  ['docker', ['push', 'img:1'], true, ['docker push']],
  ['docker', ['build', '.'], false, ['docker push']],
  ['gh', ['release', 'create', 'v1'], true, ['gh release create']],
  ['gh', ['release', 'view', 'v1'], false, ['gh release create']],
  ['deploy-prod', ['--now'], true, ['deploy-prod']],
  ['deploy.sh', ['staging'], true],
  ['aws', ['s3', 'cp', 'a', 's3://b'], true, ['aws s3 *']],
  ['aws', ['s3'], false, ['aws s3 *']],
  ['aws', ['ec2', 'describe-instances'], false, ['aws s3 *']],
  ['git', ['tag', 'v1'], true, ['git tag']],
  ['git', ['status'], false, ['git tag']],
];

const dir = tempDir('kl-shim-rules-');
const shells = ['/bin/dash', '/usr/bin/dash', '/bin/bash', '/usr/bin/bash'].filter((s) => existsSync(s));
const uniqueShells = [...new Set(shells.map((s) => (s.endsWith('dash') ? 'dash' : 'bash')))].map((name) => shells.find((s) => s.endsWith(name))!);
let n = 0;

function shDecision(shell: string, tool: string, args: string[], patterns: string[]): boolean {
  const spec = specFor(tool, parsePatterns(patterns).get(tool) ?? []);
  const file = join(dir, `d${n++}.sh`);
  writeFileSync(file, `${decisionSh(spec)}printf '%s' "$kl_world"\n`);
  const argv = shell.endsWith('bash') ? ['--posix', file, ...args] : [file, ...args];
  const out = execFileSync(shell, argv, { encoding: 'utf8' });
  expect(out === '0' || out === '1').toBe(true);
  return out === '1';
}

afterAll(() => {
  // temp dir is left for the OS; nothing outside it was written
});

describe('shim decision table', () => {
  it('has at least 60 cases', () => {
    expect(CASES.length).toBeGreaterThanOrEqual(60);
  });

  it.each(CASES.map((c) => [`${c[0]} ${c[1].map((a) => JSON.stringify(a)).join(' ')}${c[3] ? ` [${c[3].join(', ')}]` : ''}`, c] as const))('%s', (_label, c) => {
    const [tool, args, world, patterns = []] = c;
    const spec = specFor(tool, parsePatterns(patterns).get(tool) ?? []);
    expect(classify(spec, args).world).toBe(world);
    for (const sh of uniqueShells) expect(shDecision(sh, tool, args, patterns), sh).toBe(world);
  });

  it('runs the sh side under at least one POSIX shell', () => {
    expect(uniqueShells.length).toBeGreaterThan(0);
  });

  it('world words respect word boundaries', () => {
    for (const s of ['deploy', 'deploy:prod', 'db-migrate', 'release.yml', 'x_publish']) expect(hasWorldWord(s), s).toBe(s !== 'x_publish');
    for (const s of ['predeploy', 'deployment', 'released', 'republish']) expect(hasWorldWord(s), s).toBe(false);
  });

  it('rejects unsafe user patterns (nothing reaches the generated sh unvalidated)', () => {
    expect(() => parsePatterns(['docker pu$h'])).toThrow(/word/);
    expect(() => parsePatterns(["make 'release'"])).toThrow(/word/);
    expect(() => parsePatterns(['../evil push'])).toThrow(/command name/);
    expect(() => parsePatterns(['make re*lease'])).toThrow(/word/);
  });
});
