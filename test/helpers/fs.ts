/** Temp projects, fake homes, git repos and a non-blocking CLI runner for tests. */

import { execFileSync, spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

export const CLI = join(__dirname, '..', '..', 'dist', 'cli.js');

export function tempDir(prefix: string): string {
  return realpathSync.native(mkdtempSync(join(tmpdir(), prefix)));
}

export function write(file: string, content: string): void {
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, content);
}

export function gitRun(cwd: string, args: string[]): string {
  return execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false', '-c', 'core.autocrlf=false', ...args], {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
}

export function gitInit(dir: string): void {
  gitRun(dir, ['init', '-q', '-b', 'main']);
}

/** Env for child processes: no anchor/Claude config leaking in from the developer's shell. */
export function cleanEnv(extra: Record<string, string> = {}): Record<string, string> {
  const e: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v === undefined) continue;
    if (k.startsWith('KRONICLE_ANCHOR_') || k === 'CLAUDE_CONFIG_DIR' || k === 'CLAUDE_CODE_PROJECT_DIR_NAME' || k === 'KRONICLE_LITE_DATA_DIR') continue;
    e[k] = v;
  }
  return { ...e, ...extra };
}

export function runCli(
  args: string[],
  opts: { env?: Record<string, string>; cwd?: string; stdin?: string } = {},
): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], { env: opts.env ?? cleanEnv(), cwd: opts.cwd });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8').on('data', (c: string) => (stdout += c));
    child.stderr.setEncoding('utf8').on('data', (c: string) => (stderr += c));
    child.on('error', reject);
    child.on('close', (status) => resolve({ status, stdout, stderr }));
    if (opts.stdin !== undefined) child.stdin.end(opts.stdin);
    else child.stdin.end();
  });
}

/** Resolve when `pred` returns true, polling every 25 ms; reject after `ms`. */
export async function waitFor(pred: () => boolean, ms = 8_000, what = 'condition'): Promise<void> {
  const start = Date.now();
  while (!pred()) {
    if (Date.now() - start > ms) throw new Error(`timed out after ${ms} ms waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 25));
  }
}
