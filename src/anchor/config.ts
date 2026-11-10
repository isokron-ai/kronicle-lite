/**
 * Anchor configuration and the service-key cache.
 *
 *   <data-dir>/config.json              {"anchor_url", "license_key", "anchor_genesis"}   mode 0600
 *   <data-dir>/anchor-keys.cache.json   0.10.0: the service key list kept per service and genesis
 *                                       pin, the rollback reference (keys-cache.ts; the format of
 *                                       isokron-anchor's own client)
 *   <data-dir>/anchor-keys.pinned.json  0.8.1–0.9.x pin store; no longer read (trust.ts)
 *
 * Precedence: explicit arguments (CLI flags) > KRONICLE_ANCHOR_URL /
 * KRONICLE_ANCHOR_KEY > config.json > defaults. A store opened in memory
 * (tests, embedding) has no data dir; it reads env + defaults (keys-cache.ts
 * keeps its records in process). 0.11.1: the license key a push sends is
 * resolved by key-source.ts (`--key` / `--anchor-key-file` >
 * KRONICLE_ANCHOR_KEY_CMD > KRONICLE_ANCHOR_KEY > config.json); loadConfig's
 * `license_key` does not run the command.
 */

import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export const DEFAULT_ANCHOR_URL = 'https://anchor.isokron.ai';
export const CONFIG_FILE = 'config.json';
export const KEYS_CACHE_FILE = 'anchor-keys.cache.json';
/** Keys config.json may carry. Anything else is reported by `doctor`. */
export const CONFIG_KEYS = ['anchor_url', 'license_key', 'anchor_genesis'] as const;

export interface AnchorConfig {
  anchor_url: string;
  license_key: string | null;
}

export class AnchorConfigError extends Error {
  override readonly name = 'AnchorConfigError';
}

/** Parse config.json; throws AnchorConfigError when it is not a JSON object. */
export function readConfigFile(dataDir: string): Record<string, unknown> | null {
  const p = join(dataDir, CONFIG_FILE);
  if (!existsSync(p)) return null;
  let j: unknown;
  try {
    j = JSON.parse(readFileSync(p, 'utf8'));
  } catch {
    throw new AnchorConfigError(`${p} is not valid JSON`);
  }
  if (j === null || typeof j !== 'object' || Array.isArray(j)) throw new AnchorConfigError(`${p} must hold a JSON object`);
  return j as Record<string, unknown>;
}

export function loadConfig(dataDir: string | null, over: Partial<AnchorConfig> = {}): AnchorConfig {
  const j = dataDir ? readConfigFile(dataDir) : null;
  const file: Partial<AnchorConfig> = {
    ...(typeof j?.['anchor_url'] === 'string' ? { anchor_url: j['anchor_url'] } : {}),
    ...(typeof j?.['license_key'] === 'string' ? { license_key: j['license_key'] } : {}),
  };
  const env = (k: string) => {
    const v = process.env[k];
    return v !== undefined && v.length > 0 ? v : undefined;
  };
  return {
    anchor_url: over.anchor_url ?? env('KRONICLE_ANCHOR_URL') ?? file.anchor_url ?? DEFAULT_ANCHOR_URL,
    license_key: over.license_key ?? env('KRONICLE_ANCHOR_KEY') ?? file.license_key ?? null,
  };
}

/** `license_key` from config.json alone (no env), for key-source.ts. */
export function configFileLicenseKey(dataDir: string | null): string | null {
  const j = dataDir ? readConfigFile(dataDir) : null;
  return typeof j?.['license_key'] === 'string' && j['license_key'].length > 0 ? j['license_key'] : null;
}

/**
 * First run: write `{"anchor_url": <default>}` (no license key) with mode
 * 0600 so `anchor status` and `doctor` have something to show. Never
 * overwrites an existing file. Returns true when it created the file.
 */
export function ensureDefaultConfig(dataDir: string): boolean {
  const p = join(dataDir, CONFIG_FILE);
  if (existsSync(p)) return false;
  try {
    writeFileSync(p, JSON.stringify({ anchor_url: DEFAULT_ANCHOR_URL }, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    chmodSync(p, 0o600);
    return true;
  } catch {
    return false; // raced with another process, or a read-only data dir: both fine
  }
}

/** true for localhost, 127.0.0.1 and [::1]: the hosts an http:// anchor_url may name. */
export function isLoopbackHost(hostname: string): boolean {
  return ['localhost', '127.0.0.1', '[::1]'].includes(hostname);
}

/**
 * Refuse an anchor_url that would send the license key and receipts in
 * clear text (A2-20): https, or http to a loopback host, or http anywhere
 * with an explicit `insecureHttp` (`--insecure-http`).
 */
export function assertAnchorTransport(anchorUrl: string, insecureHttp = false): void {
  let u: URL;
  try {
    u = new URL(anchorUrl);
  } catch {
    throw new AnchorConfigError(`anchor_url ${anchorUrl} is not a URL`);
  }
  if (u.protocol === 'https:') return;
  if (u.protocol === 'http:' && (isLoopbackHost(u.hostname) || insecureHttp)) return;
  if (u.protocol === 'http:') {
    throw new AnchorConfigError(
      `refusing http:// anchor_url ${u.origin}: the license key and receipts would travel in clear text; use https, a loopback host, or pass --insecure-http`,
    );
  }
  throw new AnchorConfigError(`anchor_url ${u.origin} must be https://`);
}

