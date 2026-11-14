#!/usr/bin/env node
/**
 * Build the standalone verifier: one readable ES module, dist/verify.mjs, with Node built-ins only.
 *
 * It bundles kronicle-lite's own verification source (src/audit/verify-audit.ts and what it
 * imports) with esbuild (a devDependency of the repository, not of the package). The three
 * third-party modules that source imports are replaced by files in src/shims/ that use Node
 * built-ins only:
 *
 *   zod             -> src/shims/zod.ts           (the schema subset verification uses)
 *   canonicalize    -> src/shims/canonicalize.ts  (RFC 8785)
 *   @noble/hashes/* -> src/shims/noble-hashes.ts  (SHA-256 on node:crypto)
 *
 * One repository module is replaced too: src/version.ts (it reads kronicle-lite's package.json at
 * load time) by src/shims/version.ts. Any other package import fails the build. Some store code that
 * the shared modules import stays in the file unused (esbuild keeps top-level tables it cannot prove
 * free of side effects, such as the secret scanner's detectors); the header lists every source file. The output is not minified, so it can be read; its header names
 * the commit and every source file in it.
 *
 * Reproducible: the same commit and the same lockfile give the same bytes (checked in CI by
 * building twice). Usage: node packages/verify/build.mjs [--out FILE]
 */

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { build } from 'esbuild';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '../..');
const pkg = JSON.parse(readFileSync(join(here, 'package.json'), 'utf8'));

const shim = (f) => join(here, 'src', 'shims', f);
const SHIMS = {
  zod: shim('zod.ts'),
  canonicalize: shim('canonicalize.ts'),
  '@noble/hashes/sha2.js': shim('noble-hashes.ts'),
  '@noble/hashes/blake3.js': shim('noble-hashes.ts'),
  '@noble/hashes/utils.js': shim('noble-hashes.ts'),
};
/** Repository modules replaced in the verifier: what they do is not verification (see each shim). */
const REPLACED = {
  [join(repo, 'src', 'version.ts')]: shim('version.ts'),
};

/** The commit the build is from (GITHUB_SHA in CI), marked when the tree has changes. */
function sourceCommit() {
  if (process.env.GITHUB_SHA) return process.env.GITHUB_SHA;
  try {
    const sha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8' }).trim();
    const dirty = execFileSync('git', ['status', '--porcelain', '--', 'src', 'packages/verify'], { cwd: repo, encoding: 'utf8' }).trim() !== '';
    return dirty ? `${sha}+local-changes` : sha;
  } catch {
    return 'unknown';
  }
}

const builtinsOnly = {
  name: 'builtins-only',
  setup(b) {
    b.onResolve({ filter: /^[^./]/ }, (args) => {
      if (args.path.startsWith('node:')) return { path: args.path, external: true };
      if (Object.hasOwn(SHIMS, args.path)) return { path: SHIMS[args.path] };
      return { errors: [{ text: `"${args.path}" (imported by ${relative(repo, args.importer)}) is not allowed in the standalone verifier: Node built-ins (node:*) and src/shims only` }] };
    });
    b.onResolve({ filter: /^\.\.?\// }, (args) => {
      const target = resolve(args.resolveDir, args.path).replace(/\.js$/, '.ts');
      return Object.hasOwn(REPLACED, target) ? { path: REPLACED[target] } : undefined;
    });
  },
};

/**
 * Bundle `entry` (default: the verifier's CLI) with Node built-ins and the shims only. Returns the
 * code, the repository source files in it and the Node built-ins it imports. Tests use it to build
 * other entries (the schemas, through the zod shim) the same way.
 */
export async function bundle({ entry = join(here, 'src', 'cli.ts'), source = 'unknown' } = {}) {
  const result = await build({
    entryPoints: [entry],
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node22',
    write: false,
    metafile: true,
    minify: false,
    treeShaking: true,
    legalComments: 'inline',
    charset: 'utf8',
    logLevel: 'warning',
    define: {
      __VERIFY_NAME__: JSON.stringify(pkg.name),
      __VERIFY_VERSION__: JSON.stringify(pkg.version),
      __VERIFY_SOURCE__: JSON.stringify(source),
    },
    plugins: [builtinsOnly],
  });
  const rel = (p) => relative(repo, resolve(repo, p)).split('\\').join('/');
  // Every input is this repository's own source: kronicle-lite's src/ and this package's src/ (and a test entry).
  const foreign = Object.keys(result.metafile.inputs).map(rel).filter((p) => !p.startsWith('src/') && !p.startsWith('packages/verify/'));
  if (foreign.length) throw new Error(`unexpected inputs in the verifier: ${foreign.join(', ')}`);
  const meta = Object.values(result.metafile.outputs)[0];
  const used = Object.entries(meta.inputs)
    .filter(([, v]) => v.bytesInOutput > 0)
    .map(([p]) => rel(p))
    .sort();
  const builtins = [...new Set(meta.imports.filter((i) => i.external).map((i) => i.path))].sort();
  return { text: result.outputFiles[0].text, used, builtins };
}

async function main() {
  const outIdx = process.argv.indexOf('--out');
  const outfile = outIdx > 0 ? resolve(process.argv[outIdx + 1]) : join(here, 'dist', 'verify.mjs');
  const source = `github.com/isokron-ai/kronicle-lite@${sourceCommit()}`;
  const { text: code, used, builtins } = await bundle({ source });
  const header = [
    '#!/usr/bin/env node',
    '/*!',
    ` * ${pkg.name} ${pkg.version}: verify an IsoKron Evidence Pack offline.`,
    ' *',
    ' *   node verify.mjs PACK --key-fingerprint <auditor key SHA-256 from your statement of work>',
    ' *',
    ' * Node.js 22 or later. No dependencies, no network access, no native code: it imports only',
    ` * ${builtins.join(', ')}.`,
    ' * The same checks, report and exit codes as `kronicle-lite verify-audit`, built from the same',
    ' * source files.',
    ' *',
    ` * Source:  ${source}`,
    ' * Build:   packages/verify/build.mjs (esbuild, not minified). Rebuild it from that commit',
    ' *          (npm ci && npm run verify:build) and compare the SHA-256 to check this file.',
    ' * License: Apache-2.0. Includes code adapted from zod (MIT) and canonicalize (Apache-2.0); see',
    ' *          packages/verify/src/shims/.',
    ' *',
    ' * Source files in this build:',
    ...used.map((p) => ` *   ${p}`),
    ' */',
    '',
  ].join('\n');
  const text = header + code.replace(/^#!.*\n/, '');
  mkdirSync(dirname(outfile), { recursive: true });
  writeFileSync(outfile, text, { mode: 0o755 });
  const sha = createHash('sha256').update(text).digest('hex');
  process.stdout.write(`${relative(process.cwd(), outfile)}  ${Buffer.byteLength(text)} bytes  sha256 ${sha}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
