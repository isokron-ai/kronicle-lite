/** Shared by the verifier's tests: build an entry through the verifier's bundler and import it. */

import { mkdtempSync, realpathSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

export const PKG_DIR = join(__dirname, '..');
export const REPO = join(PKG_DIR, '..', '..');
export const VERIFY = join(PKG_DIR, 'dist', 'verify.mjs');
export const KRONICLE_CLI = join(REPO, 'dist', 'cli.js');

interface Bundler {
  bundle(o: { entry?: string; source?: string }): Promise<{ text: string; used: string[]; builtins: string[] }>;
}

export async function bundler(): Promise<Bundler> {
  return (await import(pathToFileURL(join(PKG_DIR, 'build.mjs')).href)) as Bundler;
}

/** Bundle `entry` exactly as the verifier is bundled (shims for zod, canonicalize, @noble/hashes) and import it. */
export async function importBundled<T>(entry: string): Promise<T> {
  const { text } = await (await bundler()).bundle({ entry });
  const dir = realpathSync.native(mkdtempSync(join(tmpdir(), 'kl-verify-bundle-')));
  const file = join(dir, 'entry.mjs');
  writeFileSync(file, text);
  return (await import(pathToFileURL(file).href)) as T;
}
