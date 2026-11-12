#!/usr/bin/env node
/**
 * Release checks for .github/workflows/release.yml (B11). Not shipped in the package.
 *
 *   release-check.mjs tag vX.Y.Z           the tag names package.json's version, and CHANGELOG.md has a
 *                                          dated `## [X.Y.Z] — YYYY-MM-DD` entry
 *   release-check.mjs npm 11.6.2           the npm CLI supports trusted publishing (11.5.1 or later)
 *   release-check.mjs pack pack.json       reads `npm pack --json`; prints file=, version=, integrity=
 *                                          lines for $GITHUB_OUTPUT
 *   release-check.mjs registry X.Y.Z SRI   the registry serves X.Y.Z with that integrity and a provenance
 *                                          attestation (retries while the registry catches up)
 *
 * Exit 0 on success; 1 with one `release-check: …` line on stderr otherwise.
 */

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = process.env.RELEASE_CHECK_ROOT ?? join(dirname(fileURLToPath(import.meta.url)), '..');
const NAME = 'kronicle-lite';

function fail(msg) {
  process.stderr.write(`release-check: ${msg}\n`);
  process.exit(1);
}

const pkg = () => JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

/** a >= b for x.y.z versions (pre-release suffixes ignored). */
function atLeast(a, b) {
  const pa = a.split(/[.-]/).slice(0, 3).map(Number);
  const pb = b.split(/[.-]/).slice(0, 3).map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) > (pb[i] ?? 0);
  }
  return true;
}

function checkTag(tag) {
  const p = pkg();
  if (p.name !== NAME) fail(`package.json names ${p.name}, not ${NAME}`);
  if (!/^v\d+\.\d+\.\d+$/.test(tag ?? '')) fail(`tag ${JSON.stringify(tag)} is not vX.Y.Z`);
  if (tag !== `v${p.version}`) fail(`tag ${tag} does not match package.json version ${p.version}`);
  const log = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
  const v = p.version.replace(/\./g, '\\.');
  if (!new RegExp(`^## \\[${v}\\] — \\d{4}-\\d{2}-\\d{2}$`, 'm').test(log)) fail(`CHANGELOG.md has no dated "## [${p.version}] — YYYY-MM-DD" entry`);
  // The provenance statement names the repository; npm refuses it when package.json names another.
  const repo = typeof p.repository === 'string' ? p.repository : p.repository?.url;
  if (!/github\.com\/isokron-ai\/kronicle-lite(\.git)?$/.test(repo ?? '')) fail(`package.json repository.url is ${JSON.stringify(repo)}; trusted publishing from isokron-ai/kronicle-lite needs it to name that repository`);
  process.stdout.write(`tag ${tag} = package.json ${p.version}; CHANGELOG entry dated; repository ${repo}\n`);
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
  const e = Array.isArray(out) ? out[0] : out;
  if (!e || e.name !== NAME) fail(`${file}: packed ${e?.name}, not ${NAME}`);
  if (e.version !== pkg().version) fail(`${file}: packed ${e.version}, package.json says ${pkg().version}`);
  if (!/^sha512-[A-Za-z0-9+/]{86}==$/.test(e.integrity ?? '')) fail(`${file}: no sha512 integrity`);
  if (!/^[A-Za-z0-9._-]+\.tgz$/.test(e.filename ?? '')) fail(`${file}: unexpected tarball name ${e.filename}`);
  const files = (e.files ?? []).map((f) => f.path);
  for (const must of ['dist/cli.js', 'dist/index.js', 'package.json', 'LICENSE']) if (!files.includes(must)) fail(`${file}: the tarball has no ${must}`);
  for (const f of files) if (/^(src|test|scripts|\.github)\//.test(f) || /(^|\/)\.env/.test(f)) fail(`${file}: the tarball would ship ${f}`);
  process.stdout.write(`file=${e.filename}\nversion=${e.version}\nintegrity=${e.integrity}\n`);
}

async function checkRegistry(version, integrity) {
  if (!version || !integrity) fail('registry needs VERSION and INTEGRITY');
  let last = '';
  for (let i = 0; i < 10; i++) {
    try {
      const out = execFileSync('npm', ['view', `${NAME}@${version}`, 'dist', '--json'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      const dist = JSON.parse(out);
      if (dist.integrity !== integrity) fail(`the registry serves ${NAME}@${version} with integrity ${dist.integrity}, the workflow packed ${integrity}`);
      if (dist.attestations?.provenance) {
        process.stdout.write(`${NAME}@${version}: integrity ${integrity}; provenance ${dist.attestations.provenance.predicateType ?? 'present'}\n`);
        return;
      }
      last = 'no provenance attestation yet';
    } catch (e) {
      last = e.message.split('\n')[0];
    }
    await new Promise((r) => setTimeout(r, 15_000));
  }
  fail(`${NAME}@${version}: ${last}`);
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
    fail('usage: release-check.mjs tag vX.Y.Z | npm VERSION | pack PACK.json | registry VERSION INTEGRITY');
}
