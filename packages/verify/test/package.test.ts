/**
 * What the package promises: no dependencies, exactly these files in the tarball, Node built-ins
 * only (no network, no dynamic code), a byte-identical rebuild, the package name in one place, and a
 * release workflow that publishes only by trusted publishing once the owner has set it up.
 */

import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { SEEN_KEYS_FILE } from '../../../src/audit/verify-audit.js';
import { cleanEnv, tempDir } from '../../../test/helpers/fs.js';
import { bundler, PKG_DIR, REPO, VERIFY } from './helpers.js';

const pkg = JSON.parse(readFileSync(join(PKG_DIR, 'package.json'), 'utf8')) as Record<string, unknown> & { name: string; version: string };
const wf = readFileSync(join(REPO, '.github', 'workflows', 'release-verify.yml'), 'utf8');
const readme = readFileSync(join(PKG_DIR, 'README.md'), 'utf8');

describe('the package', () => {
  it('has no dependencies of any kind, needs Node 22, and ships the single file as its bin', () => {
    for (const f of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies', 'bundleDependencies', 'bundledDependencies']) expect(pkg[f], f).toBeUndefined();
    expect(pkg['engines']).toEqual({ node: '>=22' });
    expect(pkg['bin']).toEqual({ 'isokron-verify': 'dist/verify.mjs' });
    expect(pkg['files']).toEqual(['dist/verify.mjs', 'README.md', 'LICENSE', 'NOTICE']);
    expect(pkg['repository']).toEqual({ type: 'git', url: 'git+https://github.com/isokron-ai/kronicle-lite.git', directory: 'packages/verify' });
  });

  it('packs exactly verify.mjs, the README, LICENSE, NOTICE and package.json', () => {
    const r = spawnSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: PKG_DIR, encoding: 'utf8', shell: process.platform === 'win32' });
    expect(r.status, r.stderr).toBe(0);
    const [p] = JSON.parse(r.stdout) as { name: string; size: number; unpackedSize: number; files: { path: string }[] }[];
    expect(p!.name).toBe(pkg.name);
    expect(p!.files.map((f) => f.path).sort()).toEqual(['LICENSE', 'NOTICE', 'README.md', 'dist/verify.mjs', 'package.json']);
    expect(p!.size).toBeLessThan(150_000); // kronicle-lite: 3.7 MB
  });

  it('names itself in one place: every @isokron/… name in the README and the workflow is package.json name', () => {
    for (const [file, text] of [['README.md', readme], ['release-verify.yml', wf]] as const) {
      const names = new Set([...text.matchAll(/@isokron\/[a-z0-9._-]+/g)].map((m) => m[0]));
      for (const n of names) expect(n, file).toBe(pkg.name);
    }
    expect(readme.startsWith(`# ${pkg.name}\n`)).toBe(true);
    expect(wf).not.toMatch(/npm (view|publish) @isokron/); // the workflow reads the name from package.json
  });
});

describe('verify.mjs', () => {
  it('imports Node built-ins only: no network module, no dynamic code, no package', async () => {
    const { text, builtins, used } = await (await bundler()).bundle({});
    expect(builtins.every((b) => ['node:crypto', 'node:fs', 'node:os', 'node:path', 'node:zlib'].includes(b)), builtins.join(', ')).toBe(true);
    expect(text).not.toMatch(/\bfetch\(|\bimport\(|\brequire\(|node:(http|https|net|dns|tls|child_process|worker_threads|vm)\b|\beval\(|new Function\(/);
    expect(used.every((p) => p.startsWith('src/') || p.startsWith('packages/verify/src/'))).toBe(true);
    expect(used).toContain('src/audit/verify-audit.ts');
    expect(used.filter((p) => p.startsWith('packages/verify/src/shims/')).sort()).toEqual(['packages/verify/src/shims/canonicalize.ts', 'packages/verify/src/shims/noble-hashes.ts', 'packages/verify/src/shims/zod.ts']);
  });

  it('rebuilds byte for byte', async () => {
    const b = await bundler();
    const one = await b.bundle({ source: 'x' });
    const two = await b.bundle({ source: 'x' });
    expect(two.text).toBe(one.text);
  });

  it('prints its version and help, and refuses Node < 22 in its own words', () => {
    const v = spawnSync(process.execPath, [VERIFY, '--version'], { encoding: 'utf8' });
    expect(v.stdout.trim()).toBe(pkg.version);
    const h = spawnSync(process.execPath, [VERIFY, '--help'], { encoding: 'utf8' });
    expect(h.status).toBe(0);
    expect(h.stdout).toContain(`${pkg.name} ${pkg.version}`);
    expect(h.stdout).toMatch(/--key-fingerprint SHA256 +the auditor key's SHA-256\(SPKI\), from your signed statement of work/);
    const text = readFileSync(VERIFY, 'utf8');
    expect(text.startsWith('#!/usr/bin/env node\n/*!\n')).toBe(true);
    expect(text).toMatch(/needs Node\.js 22 or later/);
  });

  it('shares the rollback cache location with kronicle-lite (src/db/open.ts defaultDataDir)', async () => {
    const { defaultDataDir: kl } = await import('../../../src/db/open.js');
    const home = tempDir('kl-vd-home-');
    const saved = { HOME: process.env['HOME'], USERPROFILE: process.env['USERPROFILE'], DD: process.env['KRONICLE_LITE_DATA_DIR'] };
    let expected: string;
    try {
      process.env['HOME'] = home;
      process.env['USERPROFILE'] = home;
      delete process.env['KRONICLE_LITE_DATA_DIR'];
      expected = join(kl(), SEEN_KEYS_FILE);
    } finally {
      for (const [k, v] of [['HOME', saved.HOME], ['USERPROFILE', saved.USERPROFILE], ['KRONICLE_LITE_DATA_DIR', saved.DD]] as const) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
    expect(expected.startsWith(home)).toBe(true);
    const sample = join(PKG_DIR, 'test', 'fixtures', 'isokron-sample-evidence-pack');
    const r = spawnSync(process.execPath, [VERIFY, sample, '--key-fingerprint', 'd70b311bf6e25c0c20ec3b4645f806f28b8712e212142720eeb51d2c6fa5072b', '--profile', 'legacy'], { encoding: 'utf8', env: cleanEnv({ HOME: home, USERPROFILE: home }) });
    expect(r.status, r.stdout + r.stderr).toBe(2);
    expect(r.stdout).toContain(`recorded in ${expected}`);
  });
});

describe('release-verify.yml', () => {
  /** The block of one job: from `  <name>:` to the next job or the end. */
  function job(name: string): string {
    const start = wf.indexOf(`\n  ${name}:\n`);
    expect(start, name).toBeGreaterThan(0);
    const rest = wf.slice(start + 1);
    const next = rest.slice(1).search(/\n {2}[a-z][a-z0-9_-]*:\n/);
    return next < 0 ? rest : rest.slice(0, next + 1);
  }

  it('runs on a verify/vX.Y.Z tag or by hand (a dry run by default), never on kronicle-lite tags', () => {
    expect(wf).toMatch(/push:\n\s+tags: \['verify\/v\*\.\*\.\*'\]/);
    expect(wf).toMatch(/workflow_dispatch:[\s\S]*dry_run:[\s\S]*default: true/);
    const main = readFileSync(join(REPO, '.github', 'workflows', 'release.yml'), 'utf8');
    expect(main).toMatch(/tags: \['v\*\.\*\.\*'\]/); // a GitHub tag glob's * does not match '/', so verify/v1.2.3 is not v*.*.*
  });

  it('does nothing until the owner sets VERIFY_NPM_TRUSTED_PUBLISHER=configured', () => {
    for (const j of ['verify', 'publish', 'github-release']) expect(job(j), j).toMatch(/^ {4}if: vars\.VERIFY_NPM_TRUSTED_PUBLISHER == 'configured'/m);
  });

  it('grants nothing by default; id-token only to the publish job; publishes from npm-publish-verify with --provenance', () => {
    expect(wf).toMatch(/^permissions: \{\}$/m);
    expect(wf.match(/id-token: write/g)).toHaveLength(1);
    const p = job('publish');
    expect(p).toContain('id-token: write');
    expect(p).toMatch(/^ {4}environment: npm-publish-verify$/m);
    expect(p).toMatch(/^ {4}needs: verify$/m);
    expect(p).toMatch(/npm publish "\$PKG_FILE" --provenance --access public/);
    expect(job('verify')).not.toContain('id-token');
    expect(job('github-release')).not.toContain('id-token');
  });

  it('uses no npm token or other secret, pins every action by commit sha, and does not persist checkout credentials', () => {
    const code = wf.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
    expect(code).not.toMatch(/NPM_TOKEN|NODE_AUTH_TOKEN|secrets\./);
    const uses = [...wf.matchAll(/uses: (\S+)/g)].map((m) => m[1]!);
    expect(uses.length).toBeGreaterThan(0);
    for (const u of uses) expect(u, u).toMatch(/^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/);
    const checkouts = wf.match(/uses: actions\/checkout@/g)!.length;
    expect(wf.match(/persist-credentials: false/g)).toHaveLength(checkouts);
  });

  it('the release checks it runs refuse what they should', () => {
    const script = join(PKG_DIR, 'scripts', 'release-check.mjs');
    const run = (...a: string[]) => spawnSync(process.execPath, [script, ...a], { encoding: 'utf8' });
    expect(run('tag', `verify/v${pkg.version}`).status).toBe(0);
    expect(run('tag', `v${pkg.version}`).stderr).toMatch(/is not verify\/vX\.Y\.Z/);
    expect(run('tag', 'verify/v9.9.9').stderr).toMatch(/does not match/);
    expect(run('npm', '10.9.2').status).toBe(1);
    expect(run('npm', '11.6.2').status).toBe(0);
  });

  it('the README names the exact npm trusted-publisher settings the workflow needs', () => {
    expect(readme).toContain('Workflow filename: `release-verify.yml`');
    expect(readme).toContain('Environment name: `npm-publish-verify`');
    expect(readme).toContain('Repository: `kronicle-lite`');
    expect(readme).toContain('Organization or user: `isokron-ai`');
    expect(readme).toContain('`VERIFY_NPM_TRUSTED_PUBLISHER` = `configured`');
    expect(readdirSync(join(REPO, '.github', 'workflows'))).toContain('release-verify.yml');
  });
});
