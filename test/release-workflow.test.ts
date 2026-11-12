/**
 * B11: the release workflow publishes with npm trusted publishing (OIDC) and provenance, from a
 * reviewed environment, with pinned actions and no npm token; and scripts/release-check.mjs (the
 * workflow's tag, npm, pack and registry checks) refuses what it should. Nothing here publishes.
 */

import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

const root = join(__dirname, '..');
const wf = readFileSync(join(root, '.github', 'workflows', 'release.yml'), 'utf8');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { version: string; repository: { url: string } };
const script = join(root, 'scripts', 'release-check.mjs');

function check(args: string[], env: Record<string, string> = {}) {
  const r = spawnSync(process.execPath, [script, ...args], { encoding: 'utf8', env: { ...process.env, ...env } });
  return { status: r.status, out: r.stdout, err: r.stderr };
}

/** The block of one job: from `  <name>:` to the next job or the end. */
function job(name: string): string {
  const start = wf.indexOf(`\n  ${name}:\n`);
  expect(start).toBeGreaterThan(0);
  const rest = wf.slice(start + 1);
  const next = rest.slice(1).search(/\n {2}[a-z][a-z0-9_-]*:\n/);
  return next < 0 ? rest : rest.slice(0, next + 1);
}

describe('release workflow (B11)', () => {
  it('runs on a vX.Y.Z tag or by hand (a dry run by default)', () => {
    expect(wf).toMatch(/push:\n\s+tags: \['v\*\.\*\.\*'\]/);
    expect(wf).toMatch(/workflow_dispatch:[\s\S]*dry_run:[\s\S]*default: true/);
  });

  it('grants no permission by default, and id-token: write only to the publish job', () => {
    expect(wf).toMatch(/^permissions: \{\}$/m);
    expect(wf.match(/id-token: write/g)).toHaveLength(1);
    expect(job('publish')).toContain('id-token: write');
    expect(job('verify')).not.toContain('id-token');
  });

  it('publishes from the npm-publish environment, after the verify job, with --provenance', () => {
    const p = job('publish');
    expect(p).toMatch(/^ {4}environment: npm-publish$/m);
    expect(p).toMatch(/^ {4}needs: verify$/m);
    expect(p).toMatch(/npm publish "\$PKG_FILE" --provenance --access public/);
  });

  it('uses no npm token or other secret (trusted publishing only)', () => {
    const code = wf.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
    expect(code).not.toMatch(/NPM_TOKEN|NODE_AUTH_TOKEN|secrets\./);
  });

  it('pins every action by commit sha and does not persist checkout credentials', () => {
    const uses = [...wf.matchAll(/uses: (\S+)/g)].map((m) => m[1]!);
    expect(uses.length).toBeGreaterThan(0);
    for (const u of uses) expect(u).toMatch(/^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/);
    expect(wf.match(/actions\/checkout@/g)!.length).toBe(wf.match(/persist-credentials: false/g)!.length);
  });

  it('runs the CI gates before publishing, and checks the tag in both jobs', () => {
    const v = job('verify');
    for (const s of ['npm ci', 'npm run lint', 'npm run typecheck', 'npm test', 'npm run catalog:check']) expect(v).toContain(`run: ${s}`);
    expect(v).toContain('release-check.mjs tag "$GITHUB_REF_NAME"');
    expect(job('publish')).toContain('release-check.mjs tag "$GITHUB_REF_NAME"');
    expect(job('publish')).toContain('release-check.mjs registry "$PKG_VERSION" "$PKG_INTEGRITY"');
  });

  it('does not interpolate step outputs into shell scripts', () => {
    for (const block of wf.split(/\n\s+- /)) {
      const run = /run: [|]?([\s\S]*)/.exec(block)?.[1] ?? '';
      expect(run).not.toMatch(/\$\{\{\s*steps\./);
    }
  });

  it('package.json names the repository the provenance will name', () => {
    expect(pkg.repository.url).toBe('git+https://github.com/isokron-ai/kronicle-lite.git');
  });
});

describe('scripts/release-check.mjs', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'kl-release-'));
  afterAll(() => rmSync(tmp, { recursive: true, force: true }));

  /** A copy of package.json and CHANGELOG.md to edit. */
  function fixture(name: string, edit: { pkg?: (p: Record<string, unknown>) => void; log?: (s: string) => string } = {}): string {
    const d = join(tmp, name);
    cpSync(join(root, 'package.json'), join(d, 'package.json'));
    cpSync(join(root, 'CHANGELOG.md'), join(d, 'CHANGELOG.md'));
    if (edit.pkg) {
      const p = JSON.parse(readFileSync(join(d, 'package.json'), 'utf8')) as Record<string, unknown>;
      edit.pkg(p);
      writeFileSync(join(d, 'package.json'), JSON.stringify(p, null, 2));
    }
    if (edit.log) writeFileSync(join(d, 'CHANGELOG.md'), edit.log(readFileSync(join(d, 'CHANGELOG.md'), 'utf8')));
    return d;
  }

  it('tag: accepts v<package.json version> with a dated CHANGELOG entry', () => {
    const r = check(['tag', `v${pkg.version}`]);
    expect(r.err).toBe('');
    expect(r.status).toBe(0);
  });

  it('tag: refuses another version, a malformed tag, an undated entry and another repository', () => {
    expect(check(['tag', 'v0.0.1']).err).toMatch(/does not match package.json version/);
    expect(check(['tag', pkg.version]).err).toMatch(/is not vX\.Y\.Z/);
    const undated = fixture('undated', { log: (s) => s.replace(`## [${pkg.version}] — `, `## [${pkg.version}] - `) });
    expect(check(['tag', `v${pkg.version}`], { RELEASE_CHECK_ROOT: undated }).err).toMatch(/no dated/);
    const other = fixture('other-repo', { pkg: (p) => (p['repository'] = { type: 'git', url: 'git+https://github.com/someone/kronicle-lite.git' }) });
    expect(check(['tag', `v${pkg.version}`], { RELEASE_CHECK_ROOT: other }).err).toMatch(/trusted publishing from isokron-ai\/kronicle-lite/);
  });

  it('npm: needs 11.5.1 or later', () => {
    expect(check(['npm', '10.9.2']).status).toBe(1);
    expect(check(['npm', '11.5.0']).status).toBe(1);
    expect(check(['npm', '11.5.1']).status).toBe(0);
    expect(check(['npm', '11.6.2']).status).toBe(0);
    expect(check(['npm', '12.0.0']).status).toBe(0);
  });

  it('pack: refuses a tarball of another package, version, or one that ships sources', () => {
    const good = { name: 'kronicle-lite', version: pkg.version, filename: `kronicle-lite-${pkg.version}.tgz`, integrity: `sha512-${'A'.repeat(86)}==`, files: ['dist/cli.js', 'dist/index.js', 'package.json', 'LICENSE'].map((path) => ({ path })) };
    const write = (n: string, v: unknown) => {
      const f = join(tmp, n);
      writeFileSync(f, JSON.stringify(v));
      return f;
    };
    const ok = check(['pack', write('good.json', [good])]);
    expect(ok.status).toBe(0);
    expect(ok.out).toBe(`file=${good.filename}\nversion=${pkg.version}\nintegrity=${good.integrity}\n`);
    expect(check(['pack', write('name.json', [{ ...good, name: 'kronicle' }])]).err).toMatch(/packed kronicle/);
    expect(check(['pack', write('ver.json', [{ ...good, version: '9.9.9' }])]).err).toMatch(/packed 9\.9\.9/);
    expect(check(['pack', write('src.json', [{ ...good, files: [...good.files, { path: 'src/cli.ts' }] }])]).err).toMatch(/would ship src\/cli\.ts/);
    expect(check(['pack', write('env.json', [{ ...good, files: [...good.files, { path: 'dist/.env' }] }])]).err).toMatch(/would ship dist\/\.env/);
  });

  // End to end on the real package: `npm pack --dry-run --json` over the built tree, read by the
  // same step the workflow runs. Nothing is written to the registry.
  it.skipIf(process.platform === 'win32')('pack: the real package packs with dist and without sources', () => {
    const out = execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    const f = join(tmp, 'real.json');
    writeFileSync(f, out);
    const r = check(['pack', f]);
    expect(r.err).toBe('');
    expect(r.out).toMatch(new RegExp(`^file=kronicle-lite-${pkg.version.replace(/\./g, '\\.')}\\.tgz\\nversion=`));
  }, 60_000);
});
