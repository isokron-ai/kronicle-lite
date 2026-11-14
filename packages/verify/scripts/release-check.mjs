#!/usr/bin/env node
/**
 * Release checks for .github/workflows/release-verify.yml. Not shipped in the package.
 *
 *   release-check.mjs tag verify/vX.Y.Z    the tag names packages/verify/package.json's version, and
 *                                          package.json names this repository (npm refuses a
 *                                          provenance statement for another one)
 *   release-check.mjs npm 11.6.2           the npm CLI supports trusted publishing (11.5.1 or later)
 *   release-check.mjs pack pack.json       reads `npm pack --json` (run in packages/verify): the tarball
 *                                          holds exactly verify.mjs, the README, LICENSE, NOTICE and
 *                                          package.json, and package.json has no dependencies; prints
 *                                          name=, file=, version=, integrity=, sha256= (of verify.mjs)
 *                                          lines for $GITHUB_OUTPUT
 *   release-check.mjs registry X.Y.Z SRI   the registry serves X.Y.Z with that integrity and a provenance
 *                                          attestation (retries while the registry catches up)
 *
 * The package name is read from packages/verify/package.json, nowhere else.
 * Exit 0 on success; 1 with one `release-check: …` line on stderr otherwise.
 */

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = process.env.RELEASE_CHECK_ROOT ?? join(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = () => JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
/** What the tarball may hold, and must. */
export const PACKED_FILES = ['LICENSE', 'NOTICE', 'README.md', 'dist/verify.mjs', 'package.json'];
const DEPENDENCY_FIELDS = ['dependencies', 'optionalDependencies', 'peerDependencies', 'bundleDependencies', 'bundledDependencies'];

function fail(msg) {
  process.stderr.write(`release-check: ${msg}\n`);
  process.exit(1);
}

function atLeast(a, b) {
  const pa = a.split(/[.-]/).slice(0, 3).map(Number);
  const pb = b.split(/[.-]/).slice(0, 3).map(Number);
  for (let i = 0; i < 3; i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) > (pb[i] ?? 0);
  return true;
}

function checkTag(tag) {
  const p = pkg();
  if (!/^verify\/v\d+\.\d+\.\d+$/.test(tag ?? '')) fail(`tag ${JSON.stringify(tag)} is not verify/vX.Y.Z`);
  if (tag !== `verify/v${p.version}`) fail(`tag ${tag} does not match packages/verify/package.json version ${p.version}`);
  const repo = typeof p.repository === 'string' ? p.repository : p.repository?.url;
  if (repo !== 'git+https://github.com/isokron-ai/kronicle-lite.git') fail(`packages/verify/package.json repository.url is ${JSON.stringify(repo)}; trusted publishing from isokron-ai/kronicle-lite needs it to name that repository`);
  if (p.repository?.directory !== 'packages/verify') fail('packages/verify/package.json repository.directory is not packages/verify');
  for (const f of DEPENDENCY_FIELDS) if (p[f] && Object.keys(p[f]).length) fail(`packages/verify/package.json has ${f}; the verifier has no runtime dependencies`);
  process.stdout.write(`tag ${tag} = ${p.name} ${p.version}; repository ${repo} (packages/verify); no dependencies\n`);
}

function checkNpm(version) {
  if (!version || !atLeast(version, '11.5.1')) fail(`npm ${version} cannot publish with trusted publishing (needs 11.5.1 or later)`);
  process.stdout.write(`npm ${version}: trusted publishing supported\n`);
}

function readPack(file) {
  let out;
  try {
    out = JSON.parse(readFileSync(file, 'utf8'));
  } catch (e) {
    fail(`${file}: not npm pack --json output (${e.message})`);
  }
  const p = pkg();
  const e = Array.isArray(out) ? out[0] : out;
  if (!e || e.name !== p.name) fail(`${file}: packed ${e?.name}, not ${p.name}`);
  if (e.version !== p.version) fail(`${file}: packed ${e.version}, package.json says ${p.version}`);
  if (!/^sha512-[A-Za-z0-9+/]{86}==$/.test(e.integrity ?? '')) fail(`${file}: no sha512 integrity`);
  if (!/^[A-Za-z0-9._-]+\.tgz$/.test(e.filename ?? '')) fail(`${file}: unexpected tarball name ${e.filename}`);
  const files = (e.files ?? []).map((f) => f.path).sort();
  if (JSON.stringify(files) !== JSON.stringify(PACKED_FILES)) fail(`${file}: the tarball holds ${files.join(', ')}; expected exactly ${PACKED_FILES.join(', ')}`);
  for (const f of DEPENDENCY_FIELDS) if (p[f] && Object.keys(p[f]).length) fail(`package.json has ${f}`);
  const sha = createHash('sha256').update(readFileSync(join(dir, 'dist', 'verify.mjs'))).digest('hex');
  process.stdout.write(`name=${e.name}\nfile=${e.filename}\nversion=${e.version}\nintegrity=${e.integrity}\nsha256=${sha}\n`);
}

async function checkRegistry(version, integrity) {
  if (!version || !integrity) fail('registry needs VERSION and INTEGRITY');
  const name = pkg().name;
  let last = '';
  for (let i = 0; i < 10; i++) {
    try {
      const out = execFileSync('npm', ['view', `${name}@${version}`, 'dist', '--json'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      const dist = JSON.parse(out);
      if (dist.integrity !== integrity) fail(`the registry serves ${name}@${version} with integrity ${dist.integrity}, the workflow packed ${integrity}`);
      if (dist.attestations?.provenance) {
        process.stdout.write(`${name}@${version}: integrity ${integrity}; provenance ${dist.attestations.provenance.predicateType ?? 'present'}\n`);
        return;
      }
      last = 'no provenance attestation yet';
    } catch (e) {
      last = e.message.split('\n')[0];
    }
    await new Promise((r) => setTimeout(r, 15_000));
  }
  fail(`${name}@${version}: ${last}`);
}

const [cmd, ...args] = process.argv.slice(2);
switch (cmd) {
  case 'tag':
    checkTag(args[0]);
    break;
  case 'npm':
    checkNpm(args[0]);
    break;
  case 'pack':
    readPack(args[0]);
    break;
  case 'registry':
    await checkRegistry(args[0], args[1]);
    break;
  default:
    fail('usage: release-check.mjs tag verify/vX.Y.Z | npm VERSION | pack PACK.json | registry VERSION INTEGRITY');
}
