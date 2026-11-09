/**
 * A separate process that records anchor service key lists in a data dir (the C3c tests). argv:
 *   <dataDir> <anchorUrl> <genesis pin> <list.json> <rounds> <stall ms> [<signal file> <role: hold | wait>]
 * Runs guardKeyList <rounds> times. In its first round it stalls <stall ms> while holding the lock,
 * between the read and the write. With `hold` it creates <signal file> when the stall starts; with
 * `wait` it starts only once <signal file> exists. Prints {pid, ok, refused, last}: `last` is the
 * last refusal's message.
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';

import { parseGenesisPin } from '../../src/anchor/keychain.js';
import { guardKeyList, KeyListRollbackError } from '../../src/anchor/keys-cache.js';

const [dataDir, url, pin, listFile, rounds, stallMs, signal, role] = process.argv.slice(2) as [string, string, string, string, string, string, string | undefined, string | undefined];
const list = JSON.parse(readFileSync(listFile, 'utf8')) as unknown;
const genesis = parseGenesisPin(pin)!;
const spin = (ms: number) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
if (role === 'wait' && signal) while (!existsSync(signal)) spin(2);
let ok = 0;
let refused = 0;
let last = '';
for (let i = 0; i < Number(rounds); i++) {
  try {
    guardKeyList({ dataDir }, url, list, genesis, {
      afterRead: () => {
        if (i !== 0) return;
        if (role === 'hold' && signal) writeFileSync(signal, String(process.pid));
        if (Number(stallMs) > 0) spin(Number(stallMs));
      },
    });
    ok++;
  } catch (e) {
    if (!(e instanceof KeyListRollbackError)) throw e;
    refused++;
    last = e.message;
  }
}
process.stdout.write(JSON.stringify({ pid: process.pid, ok, refused, last }) + '\n');
