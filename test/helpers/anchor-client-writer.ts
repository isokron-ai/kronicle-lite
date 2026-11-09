/**
 * The isokron-anchor client's own cache guard, run from a checkout of that repository (the
 * cross-client C3c test): argv is <client checkout> <dataDir> <anchorUrl> <genesis pin> <list.json>
 * <signal file>. Waits until <signal file> exists, runs keysCacheGuard once, prints {ok, refused}.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [checkout, dataDir, url, pin, listFile, signal] = process.argv.slice(2) as [string, string, string, string, string, string];
const anchor = (await import(pathToFileURL(join(checkout, 'client', 'src', 'anchor.ts')).href)) as {
  keysCacheGuard: (dataDir: string, url: string) => (fresh: unknown, genesis: unknown) => void;
  KeyListRollbackError: new (...a: unknown[]) => Error;
};
const genesis = (await import(pathToFileURL(join(checkout, 'src', 'core', 'genesis.ts')).href)) as { parseGenesisPin: (v: string) => unknown };
const list = JSON.parse(readFileSync(listFile, 'utf8')) as unknown;
while (!existsSync(signal)) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2);
let ok = 0;
let refused = 0;
try {
  anchor.keysCacheGuard(dataDir, url)(list, genesis.parseGenesisPin(pin));
  ok++;
} catch (e) {
  if (!(e instanceof anchor.KeyListRollbackError)) throw e;
  refused++;
}
process.stdout.write(JSON.stringify({ ok, refused }) + '\n');
