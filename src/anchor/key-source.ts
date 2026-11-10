/**
 * 0.11.1: where the anchor license key comes from, first match wins:
 *
 *   1. `--key KEY` or `--anchor-key-file PATH` (explicit; not both)
 *   2. KRONICLE_ANCHOR_KEY_CMD   a command whose stdout is the key, e.g.
 *                                `security find-generic-password -w -s kronicle-anchor`
 *                                or `op read op://vault/kronicle-anchor/credential`
 *   3. KRONICLE_ANCHOR_KEY
 *   4. `license_key` in <data-dir>/config.json
 *
 * The command runs without a shell (the string is split into words with
 * sh-style quoting; a pipe, redirect, `$` or `;` is refused, so use
 * `sh -c '…'` explicitly if one is needed), with a timeout
 * (KRONICLE_ANCHOR_KEY_CMD_TIMEOUT_MS, default 30 s, for a password manager
 * that asks to unlock), with stdin closed and its stderr captured and never
 * shown. The key is held in memory only: it is never logged, never written,
 * and never part of an error message.
 */

import { spawnSync } from 'node:child_process';
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';

import { AnchorConfigError } from './config.js';

export type AnchorKeySource = 'flag' | 'file' | 'command' | 'env' | 'config';

export interface AnchorKeyInputs {
  /** `--key` */
  licenseKey?: string | undefined;
  /** `--anchor-key-file` */
  licenseKeyFile?: string | undefined;
  /** `license_key` from config.json (null: none). */
  configKey?: string | null | undefined;
  env?: NodeJS.ProcessEnv;
  /** Overrides KRONICLE_ANCHOR_KEY_CMD_TIMEOUT_MS. */
  commandTimeoutMs?: number;
}

export const KEY_CMD_ENV = 'KRONICLE_ANCHOR_KEY_CMD';
export const KEY_CMD_TIMEOUT_ENV = 'KRONICLE_ANCHOR_KEY_CMD_TIMEOUT_MS';
export const DEFAULT_KEY_CMD_TIMEOUT_MS = 30_000;
const MAX_KEY_BYTES = 4096;

/** What `pushCheckpoint` says when no source holds a key. */
export const NO_KEY_MESSAGE =
  'no license key: pass --anchor-key-file PATH (or --key), set KRONICLE_ANCHOR_KEY_CMD to a command that prints it (a keychain or password-manager read), set KRONICLE_ANCHOR_KEY, or write {"license_key": …} to <data-dir>/config.json';

const nonEmpty = (v: string | undefined | null): v is string => typeof v === 'string' && v.length > 0;

/** A key is one line of printable ASCII with no spaces; anything else is refused without being shown. */
function checkKey(raw: string, from: string): string {
  const key = raw.replace(/^\s+|\s+$/g, '');
  if (key.length === 0) throw new AnchorConfigError(`${from} gave an empty key`);
  if (!/^[\x21-\x7e]+$/.test(key)) throw new AnchorConfigError(`${from} did not give a single-line key (whitespace or control characters inside; not shown)`);
  return key;
}

/** Which source would supply the key, without running the command or reading the file (`anchor status`, doctor). */
export function anchorKeySource(o: AnchorKeyInputs = {}): AnchorKeySource | null {
  const env = o.env ?? process.env;
  if (nonEmpty(o.licenseKey)) return 'flag';
  if (nonEmpty(o.licenseKeyFile)) return 'file';
  if (nonEmpty(env[KEY_CMD_ENV])) return 'command';
  if (nonEmpty(env['KRONICLE_ANCHOR_KEY'])) return 'env';
  if (nonEmpty(o.configKey)) return 'config';
  return null;
}

/**
 * The anchor license key and where it came from, or null when no source is configured. A source
 * that is configured but fails (an unreadable file, a command that exits non-zero or times out)
 * throws AnchorConfigError; it never falls through to the next source.
 */
export function resolveAnchorKey(o: AnchorKeyInputs = {}): { key: string; source: AnchorKeySource } | null {
  const env = o.env ?? process.env;
  if (nonEmpty(o.licenseKey) && nonEmpty(o.licenseKeyFile)) throw new AnchorConfigError('pass --key or --anchor-key-file, not both');
  const source = anchorKeySource(o);
  switch (source) {
    case 'flag':
      return { key: checkKey(o.licenseKey!, '--key'), source };
    case 'file':
      return { key: readAnchorKeyFile(o.licenseKeyFile!), source };
    case 'command':
      return { key: runAnchorKeyCommand(env[KEY_CMD_ENV]!, { env, timeoutMs: o.commandTimeoutMs ?? timeoutFromEnv(env) }), source };
    case 'env':
      return { key: checkKey(env['KRONICLE_ANCHOR_KEY']!, 'KRONICLE_ANCHOR_KEY'), source };
    case 'config':
      return { key: checkKey(o.configKey!, 'license_key in config.json'), source };
    default:
      return null;
  }
}

function timeoutFromEnv(env: NodeJS.ProcessEnv): number {
  const v = env[KEY_CMD_TIMEOUT_ENV];
  if (!nonEmpty(v)) return DEFAULT_KEY_CMD_TIMEOUT_MS;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 100 || n > 600_000) throw new AnchorConfigError(`${KEY_CMD_TIMEOUT_ENV} must be an integer number of milliseconds between 100 and 600000`);
  return n;
}

/** `--anchor-key-file PATH`: a regular file holding the key (trailing newline allowed), at most 4 KiB. */
export function readAnchorKeyFile(path: string): string {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  } catch (err) {
    throw new AnchorConfigError(`--anchor-key-file ${path}: cannot open (${(err as NodeJS.ErrnoException).code ?? 'error'})`);
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new AnchorConfigError(`--anchor-key-file ${path} is not a regular file`);
    if (st.size > MAX_KEY_BYTES) throw new AnchorConfigError(`--anchor-key-file ${path} is larger than ${MAX_KEY_BYTES} bytes; it should hold only the key`);
    if (process.platform !== 'win32' && (st.mode & 0o077) !== 0) {
      process.stderr.write(`warning: --anchor-key-file ${path} is readable by other users (mode ${(st.mode & 0o777).toString(8)}); chmod 600 it\n`);
    }
    const buf = Buffer.alloc(MAX_KEY_BYTES + 1);
    let n = 0;
    for (let r; n < buf.length && (r = readSync(fd, buf, n, buf.length - n, null)) > 0; ) n += r;
    if (n > MAX_KEY_BYTES) throw new AnchorConfigError(`--anchor-key-file ${path} is larger than ${MAX_KEY_BYTES} bytes; it should hold only the key`);
    const text = buf.subarray(0, n).toString('utf8');
    buf.fill(0);
    return checkKey(text, `--anchor-key-file ${path}`);
  } finally {
    closeSync(fd);
  }
}

/**
 * Split a command line into words the way sh would for plain words and quotes, without running a
 * shell: '…' is literal, "…" honours \" \\ \$ \`, a backslash outside quotes escapes the next
 * character. Unquoted shell syntax (| & ; < > ( ) $ ` or a newline) is refused: nothing would
 * interpret it.
 */
export function splitCommand(cmd: string): string[] {
  const words: string[] = [];
  let cur = '';
  let inWord = false;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i]!;
    if (c === "'") {
      const end = cmd.indexOf("'", i + 1);
      if (end < 0) throw new AnchorConfigError(`${KEY_CMD_ENV}: unterminated single quote`);
      cur += cmd.slice(i + 1, end);
      inWord = true;
      i = end;
    } else if (c === '"') {
      inWord = true;
      let j = i + 1;
      for (; j < cmd.length && cmd[j] !== '"'; j++) {
        if (cmd[j] === '\\' && j + 1 < cmd.length && '"\\$`'.includes(cmd[j + 1]!)) cur += cmd[++j];
        else if (cmd[j] === '$' || cmd[j] === '`') throw new AnchorConfigError(`${KEY_CMD_ENV} is run without a shell: ${cmd[j]} inside double quotes would not be expanded; wrap the command in sh -c '…' if you need a shell`);
        else cur += cmd[j];
      }
      if (j >= cmd.length) throw new AnchorConfigError(`${KEY_CMD_ENV}: unterminated double quote`);
      i = j;
    } else if (c === '\\') {
      if (i + 1 >= cmd.length) throw new AnchorConfigError(`${KEY_CMD_ENV}: trailing backslash`);
      cur += cmd[++i];
      inWord = true;
    } else if (c === ' ' || c === '\t') {
      if (inWord) words.push(cur);
      cur = '';
      inWord = false;
    } else if ('|&;<>()$`\n\r'.includes(c)) {
      throw new AnchorConfigError(
        `${KEY_CMD_ENV} is run without a shell, so ${JSON.stringify(c)} would not work as shell syntax; quote it, or wrap the command in sh -c '…' if you need a shell`,
      );
    } else {
      cur += c;
      inWord = true;
    }
  }
  if (inWord) words.push(cur);
  if (words.length === 0) throw new AnchorConfigError(`${KEY_CMD_ENV} is set but holds no command`);
  return words;
}

/**
 * Run KRONICLE_ANCHOR_KEY_CMD and return its stdout as the key. stdin is closed, stderr is captured
 * and dropped (a password manager may print hints there; none of it is shown), and the anchor key
 * variables are not passed on.
 */
export function runAnchorKeyCommand(cmd: string, o: { env?: NodeJS.ProcessEnv; timeoutMs?: number } = {}): string {
  const argv = splitCommand(cmd);
  const timeoutMs = o.timeoutMs ?? DEFAULT_KEY_CMD_TIMEOUT_MS;
  const env = Object.fromEntries(Object.entries(o.env ?? process.env).filter(([k]) => k !== 'KRONICLE_ANCHOR_KEY' && k !== KEY_CMD_ENV));
  const name = argv[0]!;
  const r = spawnSync(name, argv.slice(1), {
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
    env,
    timeout: timeoutMs,
    killSignal: 'SIGKILL',
    maxBuffer: 64 * 1024,
    windowsHide: true,
  });
  const out = r.stdout as Buffer | null;
  const err = r.stderr as Buffer | null;
  try {
    const code = (r.error as NodeJS.ErrnoException | undefined)?.code;
    if (code === 'ETIMEDOUT') {
      throw new AnchorConfigError(`${KEY_CMD_ENV} (${name}) timed out after ${timeoutMs} ms; nothing was read (raise ${KEY_CMD_TIMEOUT_ENV} if it waits for an unlock)`);
    }
    if (code === 'ENOENT') throw new AnchorConfigError(`${KEY_CMD_ENV}: ${name} not found (the command runs without a shell: give a program on PATH or its full path)`);
    if (code === 'ENOBUFS') throw new AnchorConfigError(`${KEY_CMD_ENV} (${name}) printed more than 64 KiB; it should print only the key`);
    if (r.error) throw new AnchorConfigError(`${KEY_CMD_ENV} (${name}) could not run (${code ?? 'error'})`);
    if (r.status !== 0) {
      throw new AnchorConfigError(
        `${KEY_CMD_ENV} (${name}) ${r.status === null ? `was killed by ${r.signal ?? 'a signal'}` : `exited with status ${r.status}`}; its output is not shown (run it yourself to see why)`,
      );
    }
    return checkKey((out ?? Buffer.alloc(0)).toString('utf8'), `${KEY_CMD_ENV} (${name})`);
  } finally {
    out?.fill(0);
    err?.fill(0);
  }
}
