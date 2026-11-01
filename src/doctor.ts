/**
 * `kronicle-lite doctor`: is this install and this data dir healthy?
 *
 * Read-only by design: it never creates the data dir, never writes a key,
 * config or schema, and only reads MCP client configs. The one network call
 * (anchor reachability) is optional and never fatal. Exit 0 when no check
 * fails, 1 otherwise; `--json` prints the report.
 */

import Database from 'better-sqlite3';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

import { AnchorClient } from './anchor/client.js';
import { CONFIG_KEYS, DEFAULT_ANCHOR_URL, KEYS_CACHE_FILE, readKeysCache } from './anchor/config.js';
import { CATALOG_FINGERPRINT, CATALOG_VERSION, liveCatalogFingerprint } from './catalog.js';
import { Chain, type AnchorRecord, type Checkpoint } from './chain/chain.js';
import type { Signer } from './crypto/keys.js';
import { VERSION } from './version.js';

export type CheckStatus = 'ok' | 'warn' | 'fail' | 'skip';

export interface DoctorCheck {
  id: string;
  status: CheckStatus;
  detail: string;
  data?: Record<string, unknown>;
}

export interface DoctorReport {
  version: string;
  node: string;
  platform: string;
  data_dir: string;
  ok: boolean;
  summary: Record<CheckStatus, number>;
  checks: DoctorCheck[];
}

export interface DoctorOptions {
  dataDir: string;
  /** Project directory for .mcp.json / .cursor/mcp.json / the catalog snapshot (default cwd). */
  cwd?: string;
  home?: string;
  env?: NodeJS.ProcessEnv;
  /** false: skip the anchor reachability probe. */
  network?: boolean;
  /** Verify the whole chain instead of the last 1000 events. */
  full?: boolean;
  anchorTimeoutMs?: number;
  fetch?: typeof fetch;
  /** Injectable for tests. */
  platform?: NodeJS.Platform;
  nodeVersion?: string;
}

const MIN_NODE_MAJOR = 20;
const FAST_WINDOW = 1000;

/** Secret files: group/other access is a failure. */
const SECRET_FILES = ['signing-key.pem', 'cursor-secret', 'http-bearer.token'] as const;

function mode(p: string): number | null {
  try {
    return statSync(p).mode & 0o777;
  } catch {
    return null;
  }
}

function octal(m: number): string {
  return '0' + m.toString(8).padStart(3, '0');
}

function readJsonFile(p: string): { ok: true; value: unknown } | { ok: false; error: string } | null {
  if (!existsSync(p)) return null;
  try {
    return { ok: true, value: JSON.parse(readFileSync(p, 'utf8')) as unknown };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

const noSigner: Signer = {
  key_id: 'doctor-readonly',
  public_key_pem: '',
  sign() {
    throw new Error('doctor is read-only');
  },
};

function checkNode(version: string): DoctorCheck {
  const major = Number(version.split('.')[0]);
  return major >= MIN_NODE_MAJOR
    ? { id: 'node', status: 'ok', detail: `Node ${version} (requires >= ${MIN_NODE_MAJOR})` }
    : { id: 'node', status: 'fail', detail: `Node ${version} is too old; kronicle-lite requires Node >= ${MIN_NODE_MAJOR}` };
}

function checkPermissions(dataDir: string, platform: NodeJS.Platform, licenseInConfig: boolean): DoctorCheck {
  if (platform === 'win32') {
    return {
      id: 'permissions',
      status: 'skip',
      detail: 'Windows: POSIX modes are not enforced (0700/0600 are no-ops); see the windows check',
    };
  }
  const problems: string[] = [];
  let worst: CheckStatus = 'ok';
  const dm = mode(dataDir);
  if (dm !== null && (dm & 0o077) !== 0) {
    problems.push(`data dir is ${octal(dm)} (expected 0700: chmod 700 ${dataDir})`);
    worst = 'warn';
  }
  const files: { name: string; secret: boolean }[] = [
    ...SECRET_FILES.map((name) => ({ name, secret: true })),
    { name: 'config.json', secret: licenseInConfig },
    { name: KEYS_CACHE_FILE, secret: false },
    { name: 'kronicle-lite.db', secret: false },
  ];
  const seen: Record<string, string> = {};
  for (const f of files) {
    const m = mode(join(dataDir, f.name));
    if (m === null) continue;
    seen[f.name] = octal(m);
    if ((m & 0o077) === 0) continue;
    if (f.secret) {
      problems.push(`${f.name} is ${octal(m)}, readable by others (expected 0600: chmod 600 ${join(dataDir, f.name)})`);
      worst = 'fail';
    } else if (dm !== null && (dm & 0o077) !== 0) {
      // Inside a private (0700) directory a looser file mode is unreachable; only flag it when the directory is open too.
      problems.push(`${f.name} is ${octal(m)} in a directory others can enter (expected 0600)`);
      if (worst === 'ok') worst = 'warn';
    }
  }
  return {
    id: 'permissions',
    status: worst,
    detail: problems.length > 0 ? problems.join('; ') : `data dir ${dm !== null ? octal(dm) : '?'}; key files 0600`,
    data: { dir: dm !== null ? octal(dm) : null, files: seen },
  };
}

function tableExists(db: Database.Database, name: string): boolean {
  return db.prepare(`SELECT 1 FROM sqlite_master WHERE type IN ('table','view') AND name = ?`).get(name) !== undefined;
}

function checkIntegrity(db: Database.Database): DoctorCheck {
  try {
    const rows = db.prepare('PRAGMA integrity_check').all() as { integrity_check: string }[];
    const msgs = rows.map((r) => r.integrity_check);
    return msgs.length === 1 && msgs[0] === 'ok'
      ? { id: 'db-integrity', status: 'ok', detail: 'PRAGMA integrity_check: ok' }
      : { id: 'db-integrity', status: 'fail', detail: `PRAGMA integrity_check: ${msgs.slice(0, 5).join('; ')}${msgs.length > 5 ? ` (+${msgs.length - 5} more)` : ''}` };
  } catch (e) {
    return { id: 'db-integrity', status: 'fail', detail: `integrity_check failed: ${e instanceof Error ? e.message : String(e)}` };
  }
}

function checkChain(db: Database.Database, full: boolean): DoctorCheck {
  try {
    const chain = new Chain(db, noSigner);
    const head = chain.head();
    const from = full ? 1 : Math.max(1, head.seq - FAST_WINDOW + 1);
    const r = head.seq === 0 ? null : chain.verify(from);
    const cps: Checkpoint[] = chain.listCheckpoints();
    const bad = cps.map((cp) => chain.verifyCheckpoint(cp)).filter((c) => !c.ok);
    const linkOk = r === null || r.first_mismatch === null;
    const what = `${full || from === 1 ? 'full chain' : `last ${head.seq - from + 1} of ${head.seq} events`}`;
    if (!linkOk) {
      const m = r!.first_mismatch!;
      return { id: 'chain', status: 'fail', detail: `${m.kind} at seq ${m.seq} (${what} checked); run verify-chain`, data: { head, first_mismatch: m } };
    }
    if (bad.length > 0) {
      return {
        id: 'chain',
        status: 'fail',
        detail: `${bad.length} of ${cps.length} checkpoint(s) do not verify: ${bad.slice(0, 3).map((b) => `[${b.from_seq},${b.to_seq}] ${b.reason}`).join(', ')}`,
        data: { head, checkpoints: cps.length, bad },
      };
    }
    return {
      id: 'chain',
      status: 'ok',
      detail: head.seq === 0 ? 'empty chain (genesis)' : `${what} link and hash; ${cps.length} checkpoint(s) valid; head seq ${head.seq}`,
      data: { head, from_seq: from, checkpoints: cps.length },
    };
  } catch (e) {
    return { id: 'chain', status: 'fail', detail: `chain verification failed: ${e instanceof Error ? e.message : String(e)}` };
  }
}

function checkFts(db: Database.Database): DoctorCheck {
  try {
    if (!tableExists(db, 'blocks_fts')) return { id: 'fts', status: 'fail', detail: 'blocks_fts is missing' };
    const blocks = (db.prepare('SELECT COUNT(*) AS n FROM blocks').get() as { n: number }).n;
    const indexed = (db.prepare('SELECT COUNT(*) AS n FROM blocks_fts_docsize').get() as { n: number }).n;
    db.prepare(`INSERT INTO blocks_fts(blocks_fts) VALUES('integrity-check')`).run();
    if (blocks !== indexed) {
      return { id: 'fts', status: 'fail', detail: `blocks_fts indexes ${indexed} row(s) but blocks has ${blocks}; rebuild with: INSERT INTO blocks_fts(blocks_fts) VALUES('rebuild')` };
    }
    return { id: 'fts', status: 'ok', detail: `FTS5 integrity-check ok; ${indexed} block(s) indexed` };
  } catch (e) {
    return {
      id: 'fts',
      status: 'fail',
      detail: `FTS5 index inconsistent with blocks (${e instanceof Error ? e.message : String(e)}); rebuild with: INSERT INTO blocks_fts(blocks_fts) VALUES('rebuild')`,
    };
  }
}

async function checkCatalog(cwd: string): Promise<DoctorCheck> {
  try {
    const live = await liveCatalogFingerprint();
    const problems: string[] = [];
    if (live.fingerprint !== CATALOG_FINGERPRINT) problems.push(`live catalog ${live.fingerprint.slice(0, 12)}… ≠ pinned ${CATALOG_FINGERPRINT.slice(0, 12)}… (a mismatched or patched build)`);
    if (CATALOG_VERSION !== VERSION) problems.push(`catalog pinned for ${CATALOG_VERSION}, package is ${VERSION}`);
    const snap = readJsonFile(join(cwd, '.mcp-catalog', 'kronicle-lite.json'));
    let snapshot: Record<string, unknown> | null = null;
    if (snap?.ok) {
      const s = snap.value as { sha256?: string; server?: { version?: string } };
      snapshot = { sha256: s.sha256 ?? null, version: s.server?.version ?? null };
      if (s.sha256 !== live.fingerprint) problems.push(`.mcp-catalog snapshot ${String(s.sha256).slice(0, 12)}… ≠ live (run npm run catalog:snapshot)`);
      if (s.server?.version !== VERSION) problems.push(`.mcp-catalog snapshot was taken at ${s.server?.version}, package is ${VERSION}`);
    }
    return {
      id: 'catalog',
      status: problems.length > 0 ? 'warn' : 'ok',
      detail: problems.length > 0 ? problems.join('; ') : `${live.tools} tools, fingerprint ${live.fingerprint.slice(0, 12)}… matches ${VERSION}`,
      data: { live: live.fingerprint, pinned: CATALOG_FINGERPRINT, pinned_version: CATALOG_VERSION, version: VERSION, snapshot },
    };
  } catch (e) {
    return { id: 'catalog', status: 'fail', detail: `could not build the MCP catalog: ${e instanceof Error ? e.message : String(e)}` };
  }
}

function checkConfig(dataDir: string, env: NodeJS.ProcessEnv): { check: DoctorCheck; anchorUrl: string; licenseInConfig: boolean } {
  const p = join(dataDir, 'config.json');
  const r = readJsonFile(p);
  const envUrl = env['KRONICLE_ANCHOR_URL'];
  const envKey = env['KRONICLE_ANCHOR_KEY'];
  const envNote = [envUrl ? 'KRONICLE_ANCHOR_URL set' : null, envKey ? 'KRONICLE_ANCHOR_KEY set' : null].filter(Boolean).join(', ');
  if (r === null) {
    return {
      check: { id: 'config', status: 'ok', detail: `no config.json (defaults: ${DEFAULT_ANCHOR_URL}, no license key)${envNote ? `; ${envNote}` : ''}` },
      anchorUrl: envUrl || DEFAULT_ANCHOR_URL,
      licenseInConfig: false,
    };
  }
  if (!r.ok) return { check: { id: 'config', status: 'fail', detail: `${p} is not valid JSON (${r.error}); anchor commands will refuse to run` }, anchorUrl: envUrl || DEFAULT_ANCHOR_URL, licenseInConfig: false };
  if (r.value === null || typeof r.value !== 'object' || Array.isArray(r.value)) {
    return { check: { id: 'config', status: 'fail', detail: `${p} must hold a JSON object` }, anchorUrl: envUrl || DEFAULT_ANCHOR_URL, licenseInConfig: false };
  }
  const j = r.value as Record<string, unknown>;
  const problems: string[] = [];
  let status: CheckStatus = 'ok';
  const unknown = Object.keys(j).filter((k) => !(CONFIG_KEYS as readonly string[]).includes(k));
  if (unknown.length > 0) problems.push(`unknown key(s) ${unknown.join(', ')} (known: ${CONFIG_KEYS.join(', ')})`);
  let anchorUrl = DEFAULT_ANCHOR_URL;
  if (j['anchor_url'] !== undefined) {
    if (typeof j['anchor_url'] !== 'string') {
      problems.push('anchor_url must be a string');
      status = 'fail';
    } else {
      try {
        const u = new URL(j['anchor_url']);
        const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
        if (u.protocol !== 'https:' && !(u.protocol === 'http:' && loopback)) problems.push(`anchor_url ${u.href} is not https (the license key would travel in clear text)`);
        anchorUrl = j['anchor_url'];
      } catch {
        problems.push(`anchor_url ${String(j['anchor_url'])} is not a URL`);
        status = 'fail';
      }
    }
  }
  const lk = j['license_key'];
  if (lk !== undefined && (typeof lk !== 'string' || !/^KLA_[A-Za-z0-9._-]{4,}$/.test(lk))) problems.push('license_key does not look like KLA_…');
  if (problems.length > 0 && status === 'ok') status = 'warn';
  return {
    check: {
      id: 'config',
      status,
      detail: problems.length > 0 ? problems.join('; ') : `anchor_url ${anchorUrl}; license key ${typeof lk === 'string' ? 'configured' : 'not configured'}${envNote ? `; ${envNote}` : ''}`,
      data: { anchor_url: anchorUrl, license_key: typeof lk === 'string' ? 'configured' : null },
    },
    anchorUrl: envUrl || anchorUrl,
    licenseInConfig: typeof lk === 'string',
  };
}

async function checkAnchorLocal(db: Database.Database, dataDir: string, anchorUrl: string): Promise<DoctorCheck> {
  if (!tableExists(db, 'anchors')) return { id: 'anchor-local', status: 'skip', detail: 'no anchors table (opened by kronicle-lite < 0.4.0)' };
  const chain = new Chain(db, noSigner);
  const last: AnchorRecord | null = chain.lastAnchor();
  if (!last) return { id: 'anchor-local', status: 'skip', detail: 'never anchored' };
  const head = chain.head();
  const over = last.to_seq <= head.seq ? chain.rootOver(last.from_seq, last.to_seq) : null;
  const result = last.to_seq > head.seq ? 'beyond_head' : !over ? 'gap' : over.root === last.root ? 'match' : 'diverged';
  let countersig = 'unchecked';
  const keys = readKeysCache(dataDir);
  if (keys) {
    try {
      await new AnchorClient(anchorUrl, { preloadedKeys: keys }).verifyReceipt(JSON.parse(last.receipt_json));
      countersig = 'ok';
    } catch {
      countersig = 'failed';
    }
  }
  const detail = `last anchor [${last.from_seq}, ${last.to_seq}] ${last.status} at ${last.received_at}: local root ${result}, countersignature ${countersig}; ${Math.max(0, head.seq - last.to_seq)} event(s) since`;
  const status: CheckStatus = result !== 'match' || countersig === 'failed' ? 'fail' : 'ok';
  return { id: 'anchor-local', status, detail: status === 'fail' ? `${detail} — the local chain no longer matches what was anchored` : detail };
}

async function checkAnchorReachable(anchorUrl: string, opts: DoctorOptions): Promise<DoctorCheck> {
  if (opts.network === false) return { id: 'anchor-reachable', status: 'skip', detail: 'skipped (--no-network)' };
  try {
    const keys = await new AnchorClient(anchorUrl, { timeoutMs: opts.anchorTimeoutMs ?? 3_000, ...(opts.fetch ? { fetch: opts.fetch } : {}) }).serviceKeys();
    return { id: 'anchor-reachable', status: 'ok', detail: `${anchorUrl} answers; ${keys.keys.length} service key(s) published` };
  } catch (e) {
    return { id: 'anchor-reachable', status: 'warn', detail: `${e instanceof Error ? e.message : String(e)} (non-fatal: everything local works)` };
  }
}

// ───────────────────────────── MCP client configs (read-only) ─────────────────────────────

export interface ClientEntry {
  client: string;
  file: string;
  scope: string;
  name: string;
  transport: 'stdio' | 'http';
  data_dir: string | null;
}

function mentionsKronicle(name: string, server: unknown): boolean {
  const blob = `${name} ${JSON.stringify(server ?? '')}`;
  return /kronicle-lite/.test(blob);
}

function dataDirOf(server: Record<string, unknown>): string | null {
  const args = Array.isArray(server['args']) ? (server['args'] as unknown[]).map(String) : [];
  const i = args.indexOf('--data-dir');
  if (i >= 0 && args[i + 1]) return args[i + 1]!;
  const eq = args.find((a) => a.startsWith('--data-dir='));
  if (eq) return eq.slice('--data-dir='.length);
  const env = server['env'] as Record<string, unknown> | undefined;
  return env && typeof env['KRONICLE_LITE_DATA_DIR'] === 'string' ? env['KRONICLE_LITE_DATA_DIR'] : null;
}

function fromMcpServers(client: string, file: string, scope: string, servers: unknown, out: ClientEntry[]): void {
  if (!servers || typeof servers !== 'object') return;
  for (const [name, s] of Object.entries(servers as Record<string, unknown>)) {
    if (!mentionsKronicle(name, s) || !s || typeof s !== 'object') continue;
    const srv = s as Record<string, unknown>;
    out.push({ client, file, scope, name, transport: typeof srv['url'] === 'string' ? 'http' : 'stdio', data_dir: dataDirOf(srv) });
  }
}

/** Minimal TOML reading for `[mcp_servers.<name>]` tables (command/args on one line each). */
export function codexServers(toml: string): { name: string; command: string | null; args: string[]; url: string | null }[] {
  const out = new Map<string, { name: string; command: string | null; args: string[]; url: string | null }>();
  let current: string | null = null;
  for (const raw of toml.split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, '').trim();
    const h = /^\[\s*mcp_servers\.(?:"([^"]+)"|'([^']+)'|([A-Za-z0-9_-]+))(?:\.[^\]]*)?\s*\]$/.exec(line);
    if (h) {
      current = h[1] ?? h[2] ?? h[3] ?? null;
      if (current && !out.has(current)) out.set(current, { name: current, command: null, args: [], url: null });
      continue;
    }
    if (line.startsWith('[')) {
      current = null;
      continue;
    }
    if (!current) continue;
    const e = out.get(current)!;
    const kv = /^([A-Za-z_]+)\s*=\s*(.+)$/.exec(line);
    if (!kv) continue;
    const [, key, value] = kv;
    if (key === 'command' || key === 'url') {
      const m = /^"((?:[^"\\]|\\.)*)"|^'([^']*)'/.exec(value!);
      if (m) e[key] = m[1] ?? m[2] ?? null;
    } else if (key === 'args') {
      e.args = [...value!.matchAll(/"((?:[^"\\]|\\.)*)"|'([^']*)'/g)].map((m) => m[1] ?? m[2] ?? '');
    }
  }
  return [...out.values()];
}

export function findMcpClients(cwd: string, home: string): { entries: ClientEntry[]; scanned: string[]; errors: string[] } {
  const entries: ClientEntry[] = [];
  const scanned: string[] = [];
  const errors: string[] = [];
  const json = (file: string, fn: (j: Record<string, unknown>) => void) => {
    const r = readJsonFile(file);
    if (r === null) return;
    scanned.push(file);
    if (!r.ok) {
      errors.push(`${file}: ${r.error}`);
      return;
    }
    if (r.value && typeof r.value === 'object' && !Array.isArray(r.value)) fn(r.value as Record<string, unknown>);
  };
  const claudeJson = join(home, '.claude.json');
  json(claudeJson, (j) => {
    fromMcpServers('Claude Code', claudeJson, 'user', j['mcpServers'], entries);
    const projects = j['projects'];
    if (projects && typeof projects === 'object') {
      for (const [path, p] of Object.entries(projects as Record<string, unknown>)) {
        if (p && typeof p === 'object') fromMcpServers('Claude Code', claudeJson, `local (${path})`, (p as Record<string, unknown>)['mcpServers'], entries);
      }
    }
  });
  const projectMcp = join(cwd, '.mcp.json');
  json(projectMcp, (j) => fromMcpServers('Claude Code', projectMcp, 'project', j['mcpServers'], entries));
  for (const [file, scope] of [
    [join(cwd, '.cursor', 'mcp.json'), 'project'],
    [join(home, '.cursor', 'mcp.json'), 'global'],
  ] as const) {
    json(file, (j) => fromMcpServers('Cursor', file, scope, j['mcpServers'], entries));
  }
  const codex = join(home, '.codex', 'config.toml');
  if (existsSync(codex)) {
    scanned.push(codex);
    try {
      for (const s of codexServers(readFileSync(codex, 'utf8'))) {
        if (!mentionsKronicle(s.name, s)) continue;
        entries.push({ client: 'Codex', file: codex, scope: 'user', name: s.name, transport: s.url ? 'http' : 'stdio', data_dir: dataDirOf({ args: s.args }) });
      }
    } catch (e) {
      errors.push(`${codex}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  return { entries, scanned, errors };
}

function checkClients(cwd: string, home: string, dataDir: string): DoctorCheck {
  const { entries, scanned, errors } = findMcpClients(cwd, home);
  const lines = entries.map((e) => `${e.client} ${e.scope} "${e.name}" (${e.transport}${e.data_dir ? `, --data-dir ${e.data_dir}` : ''})`);
  const elsewhere = entries.filter((e) => e.data_dir && !e.data_dir.includes('${') && resolve(cwd, e.data_dir) !== resolve(dataDir));
  const notes = [
    ...(elsewhere.length > 0 ? [`${elsewhere.length} configured with a different data dir than the one checked here`] : []),
    ...errors.map((e) => `unreadable: ${e}`),
  ];
  return {
    id: 'mcp-clients',
    status: entries.length === 0 || errors.length > 0 ? 'warn' : 'ok',
    detail:
      entries.length === 0
        ? `no MCP client config mentions kronicle-lite (scanned ${scanned.length} file(s)); see README → Install`
        : `${lines.join('; ')}${notes.length > 0 ? ` — ${notes.join('; ')}` : ''}`,
    data: { entries, scanned, errors },
  };
}

export async function runDoctor(opts: DoctorOptions): Promise<DoctorReport> {
  const platform = opts.platform ?? process.platform;
  const nodeVersion = opts.nodeVersion ?? process.versions.node;
  const env = opts.env ?? process.env;
  const cwd = resolve(opts.cwd ?? process.cwd());
  const home = opts.home ?? homedir();
  const dataDir = resolve(opts.dataDir);
  const checks: DoctorCheck[] = [checkNode(nodeVersion)];

  const exists = existsSync(dataDir);
  const cfg = exists ? checkConfig(dataDir, env) : null;
  if (!exists) {
    checks.push({ id: 'data-dir', status: 'warn', detail: `${dataDir} does not exist yet; the first serve/put/checkpoint creates it` });
  } else {
    checks.push({ id: 'data-dir', status: 'ok', detail: dataDir });
    checks.push(checkPermissions(dataDir, platform, cfg!.licenseInConfig));
  }

  const dbPath = join(dataDir, 'kronicle-lite.db');
  if (exists && existsSync(dbPath)) {
    let db: Database.Database | null = null;
    try {
      db = new Database(dbPath, { fileMustExist: true });
      db.pragma('busy_timeout = 2000');
      checks.push(checkIntegrity(db));
      checks.push(checkChain(db, opts.full === true));
      checks.push(checkFts(db));
      checks.push(cfg!.check);
      checks.push(await checkAnchorLocal(db, dataDir, cfg!.anchorUrl));
    } catch (e) {
      checks.push({ id: 'db-integrity', status: 'fail', detail: `cannot open ${dbPath}: ${e instanceof Error ? e.message : String(e)}` });
    } finally {
      db?.close();
    }
  } else {
    for (const id of ['db-integrity', 'chain', 'fts']) checks.push({ id, status: 'skip', detail: 'no database yet' });
    if (cfg) checks.push(cfg.check);
  }

  checks.push(await checkCatalog(cwd));
  checks.push(await checkAnchorReachable(cfg?.anchorUrl ?? env['KRONICLE_ANCHOR_URL'] ?? DEFAULT_ANCHOR_URL, opts));
  checks.push(checkClients(cwd, home, dataDir));
  if (platform === 'win32') {
    checks.push({
      id: 'windows',
      status: 'warn',
      detail:
        'Windows: the 0600/0700 modes kronicle-lite sets on keys, config and the data dir are no-ops. Anyone who can read the ' +
        'data dir can read the signing key and license key; on a shared machine restrict it with NTFS ACLs, e.g. ' +
        `icacls "${dataDir}" /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F"`,
    });
  }

  const summary: Record<CheckStatus, number> = { ok: 0, warn: 0, fail: 0, skip: 0 };
  for (const c of checks) summary[c.status]++;
  return { version: VERSION, node: nodeVersion, platform, data_dir: dataDir, ok: summary.fail === 0, summary, checks };
}

export function renderDoctor(r: DoctorReport): string {
  const label: Record<CheckStatus, string> = { ok: 'ok  ', warn: 'warn', fail: 'FAIL', skip: 'skip' };
  const width = Math.max(...r.checks.map((c) => c.id.length));
  const lines = [`kronicle-lite doctor ${r.version} (Node ${r.node}, ${r.platform}) — data dir ${r.data_dir}`];
  for (const c of r.checks) lines.push(`  ${label[c.status]}  ${c.id.padEnd(width)}  ${c.detail}`);
  lines.push(`${r.summary.ok} ok, ${r.summary.warn} warn, ${r.summary.fail} fail, ${r.summary.skip} skipped`);
  return lines.join('\n');
}
