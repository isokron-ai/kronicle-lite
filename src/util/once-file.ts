/**
 * Create-if-absent files that several processes may race to create (the
 * signing key, the cursor secret, the HTTP bearer): the first creator wins,
 * everybody else reads the winner's bytes, and nobody ever reads a
 * half-written file.
 *
 *   1. Read the file. Valid → done.
 *   2. Absent → write the content to a private temp file in the same
 *      directory, then `link(tmp, path)`: atomic and exclusive (EEXIST when
 *      someone else won), and the file appears with its full content.
 *   3. EEXIST → re-read the winner's file (step 1).
 *   4. A file that exists but does not validate (an older version's writer
 *      caught between open and write) is re-read for up to `waitMs` before
 *      it is reported corrupt.
 *
 * Filesystems without hard links fall back to `open(O_CREAT|O_EXCL)` + write;
 * readers then rely on the retry in step 4.
 */

import { randomBytes } from 'node:crypto';
import { closeSync, linkSync, mkdirSync, openSync, readFileSync, statSync, unlinkSync, writeFileSync, writeSync } from 'node:fs';

export class CorruptFileError extends Error {
  override readonly name = 'CorruptFileError';
}

/** mkdir -p that tolerates a concurrent creator (and fails only when the path is not a directory). */
export function ensureDir(dir: string, mode = 0o700): void {
  try {
    mkdirSync(dir, { recursive: true, mode });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
    if (!statSync(dir).isDirectory()) throw err;
  }
}

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function readIfPresent(path: string): string | null {
  try {
    return readFileSync(path, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err;
  }
}

const NO_LINK = new Set(['EPERM', 'ENOTSUP', 'EOPNOTSUPP', 'ENOSYS', 'EXDEV', 'EINVAL']);

/** Try to publish `content` at `path` exclusively. true = we created it; false = it already existed. */
function createExclusive(path: string, content: string, mode: number): boolean {
  const tmp = `${path}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  writeFileSync(tmp, content, { mode, flag: 'wx' });
  try {
    linkSync(tmp, path);
    return true;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code ?? '';
    if (code === 'EEXIST') return false;
    if (!NO_LINK.has(code)) throw err;
    // No hard links here: exclusive open, then write (readers retry a short read).
    let fd: number;
    try {
      fd = openSync(path, 'wx', mode);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'EEXIST') return false;
      throw e;
    }
    try {
      writeSync(fd, content);
    } finally {
      closeSync(fd);
    }
    return true;
  } finally {
    try {
      unlinkSync(tmp);
    } catch {
      // already gone
    }
  }
}

/**
 * Return the file's validated content, creating it from `make()` when absent.
 * `validate` receives the raw text; return the parsed value or null when it is
 * not (yet) valid.
 */
export function readOrCreateOnce<T>(
  path: string,
  make: () => string,
  validate: (text: string) => T | null,
  opts: { mode?: number; waitMs?: number } = {},
): { value: T; created: boolean } {
  const mode = opts.mode ?? 0o600;
  const deadline = Date.now() + (opts.waitMs ?? 2000);
  let created = false;
  for (;;) {
    const text = readIfPresent(path);
    if (text === null) {
      if (createExclusive(path, make(), mode)) created = true;
      continue; // re-read whatever won, ours or theirs
    }
    const value = validate(text);
    if (value !== null) return { value, created };
    if (Date.now() >= deadline) throw new CorruptFileError(`${path} is corrupt or empty`);
    sleepSync(20);
  }
}
