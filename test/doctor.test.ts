/**
 * `kronicle-lite doctor` (0.4.0) and the pinned catalog fingerprint it
 * compares against.
 */

import Database from 'better-sqlite3';
import { chmodSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { pushCheckpoint } from '../src/anchor/anchor.js';
import { CATALOG_FINGERPRINT, CATALOG_VERSION, liveCatalogFingerprint } from '../src/catalog.js';
import { codexServers, findMcpClients, runDoctor, type DoctorReport } from '../src/doctor.js';
import { KronicleLite } from '../src/store.js';
import { VERSION } from '../src/version.js';
import { startAnchorStub, type AnchorBackend } from './helpers/anchor-stub.js';
import { cleanEnv, runCli, tempDir, write } from './helpers/fs.js';

const POSIX = process.platform !== 'win32';

function healthy(): { dataDir: string; home: string; cwd: string } {
  const dataDir = join(tempDir('kl-doc-'), 'data');
  const store = new KronicleLite({ dataDir });
  store.docs.putDocument({ slug: 'runbook', title: 'Runbook', markdown: '# Runbook\n\nRestart with care.\n\nPage the on-call.\n', actor_id: 't' });
  store.chain.checkpoint();
  store.close();
  return { dataDir, home: tempDir('kl-doc-home-'), cwd: tempDir('kl-doc-cwd-') };
}

const check = (r: DoctorReport, id: string) => r.checks.find((c) => c.id === id)!;

describe('catalog pin', () => {
  it('CATALOG_FINGERPRINT equals the .mcp-catalog snapshot and the live in-process catalog; pinned for this version', async () => {
    const snap = JSON.parse(readFileSync(join(__dirname, '..', '.mcp-catalog', 'kronicle-lite.json'), 'utf8')) as { sha256: string; server: { version: string } };
    expect(snap.sha256).toBe(CATALOG_FINGERPRINT);
    expect(CATALOG_VERSION).toBe(VERSION);
    expect(snap.server.version).toBe(VERSION);
    expect((await liveCatalogFingerprint()).fingerprint).toBe(CATALOG_FINGERPRINT);
  });
});

describe('doctor', () => {
  let stub: AnchorBackend;
  beforeAll(async () => {
    stub = await startAnchorStub();
  });
  afterAll(async () => {
    await stub.stop();
  });

  it('a healthy store: every check ok or skipped, read-only, exit 0', async () => {
    const { dataDir, home, cwd } = healthy();
    const before = readFileSync(join(dataDir, 'config.json'), 'utf8');
    const r = await runDoctor({ dataDir, home, cwd, env: {}, network: false });
    expect(r.ok).toBe(true);
    expect(r.checks.map((c) => c.id)).toEqual([
      'node',
      'data-dir',
      'permissions',
      'db-integrity',
      'chain',
      'fts',
      'config',
      'anchor-local',
      'catalog',
      'anchor-reachable',
      'mcp-clients',
      ...(POSIX ? [] : ['windows']),
    ]);
    expect(check(r, 'chain').detail).toMatch(/full chain link and hash; 1 checkpoint\(s\) valid/);
    expect(check(r, 'fts')).toMatchObject({ status: 'ok' });
    expect(check(r, 'catalog')).toMatchObject({ status: 'ok' });
    expect(check(r, 'anchor-reachable')).toMatchObject({ status: 'skip' });
    if (POSIX) {
      expect(check(r, 'permissions')).toMatchObject({ status: 'ok' });
      expect(statSync(join(dataDir, 'kronicle-lite.db')).mode & 0o777).toBe(0o600);
    }
    expect(readFileSync(join(dataDir, 'config.json'), 'utf8')).toBe(before);
    // A data dir that does not exist is reported, not created.
    const missing = join(tempDir('kl-doc-x-'), 'nope');
    const m = await runDoctor({ dataDir: missing, home, cwd, env: {}, network: false });
    expect(m.ok).toBe(true);
    expect(check(m, 'data-dir').status).toBe('warn');
    expect(() => statSync(missing)).toThrow();
  });

  it.skipIf(!POSIX)('permissions: a group/world-readable signing key fails; an open data dir warns (POSIX only: modes are no-ops on Windows)', async () => {
    const { dataDir, home, cwd } = healthy();
    chmodSync(join(dataDir, 'signing-key.pem'), 0o644);
    chmodSync(dataDir, 0o755);
    const r = await runDoctor({ dataDir, home, cwd, env: {}, network: false });
    expect(r.ok).toBe(false);
    expect(check(r, 'permissions')).toMatchObject({ status: 'fail' });
    expect(check(r, 'permissions').detail).toMatch(/signing-key\.pem is 0644, readable by others/);
    expect(check(r, 'permissions').detail).toMatch(/data dir is 0755/);
  });

  it('a tampered event fails the chain check; a missing FTS row fails the FTS check; CLI exits 1 with --json', async () => {
    const { dataDir, home, cwd } = healthy();
    const db = new Database(join(dataDir, 'kronicle-lite.db'));
    db.prepare(`UPDATE events SET payload_canonical = replace(payload_canonical, 'Restart with care', 'Restart freely') WHERE seq = 3`).run();
    db.exec('DROP TRIGGER blocks_ai');
    db.prepare(
      `INSERT INTO blocks (block_id, doc_id, revision, ordinal, kind, level, heading_path, content, content_hash, chain_seq, valid_from)
       SELECT '00000000-0000-4000-8000-000000000001', doc_id, 1, 99, 'paragraph', 0, '', 'orphan', content_hash, 1, valid_from FROM blocks LIMIT 1`,
    ).run();
    db.close();
    const r = await runDoctor({ dataDir, home, cwd, env: {}, network: false });
    expect(r.ok).toBe(false);
    expect(check(r, 'chain')).toMatchObject({ status: 'fail' });
    expect(check(r, 'chain').detail).toMatch(/hash_mismatch at seq 3/);
    expect(check(r, 'fts')).toMatchObject({ status: 'fail' });
    const cli = await runCli(['doctor', '--data-dir', dataDir, '--json', '--no-network', '--cwd', cwd], { env: cleanEnv({ HOME: home, USERPROFILE: home }) });
    expect(cli.status).toBe(1);
    expect((JSON.parse(cli.stdout) as DoctorReport).summary.fail).toBeGreaterThanOrEqual(2);
  });

  it('config.json: invalid JSON fails; unknown keys and plain-http URLs warn', async () => {
    const { dataDir, home, cwd } = healthy();
    write(join(dataDir, 'config.json'), '{oops');
    expect(check(await runDoctor({ dataDir, home, cwd, env: {}, network: false }), 'config')).toMatchObject({ status: 'fail' });
    write(join(dataDir, 'config.json'), JSON.stringify({ anchor_url: 'http://anchor.example', license_key: 'KLA_ok-1234', extra: 1 }));
    const c = check(await runDoctor({ dataDir, home, cwd, env: {}, network: false }), 'config');
    expect(c.status).toBe('warn');
    expect(c.detail).toMatch(/unknown key\(s\) extra/);
    expect(c.detail).toMatch(/not https/);
  });

  it('anchor: reachable service ok, unreachable warns (never fatal); last anchor compared with the local root', async () => {
    const { dataDir, home, cwd } = healthy();
    const store = new KronicleLite({ dataDir });
    await pushCheckpoint(store, { anchorUrl: stub.url, licenseKey: stub.license });
    store.close();
    const ok = await runDoctor({ dataDir, home, cwd, env: { KRONICLE_ANCHOR_URL: stub.url } });
    expect(check(ok, 'anchor-reachable')).toMatchObject({ status: 'ok' });
    expect(check(ok, 'anchor-local')).toMatchObject({ status: 'ok' });
    expect(check(ok, 'anchor-local').detail).toMatch(/local root match, countersignature ok/);
    const down = await runDoctor({ dataDir, home, cwd, env: { KRONICLE_ANCHOR_URL: 'http://127.0.0.1:9' }, anchorTimeoutMs: 1000 });
    expect(check(down, 'anchor-reachable')).toMatchObject({ status: 'warn' });
    expect(check(down, 'anchor-reachable').detail).toMatch(/anchor service unreachable/);
    expect(down.ok).toBe(true);
  });

  it('MCP clients: finds kronicle-lite in ~/.claude.json (user + local), .mcp.json, Cursor and Codex configs without touching them', async () => {
    const { dataDir, home, cwd } = healthy();
    const files = {
      claude: join(home, '.claude.json'),
      mcp: join(cwd, '.mcp.json'),
      cursor: join(cwd, '.cursor', 'mcp.json'),
      cursorGlobal: join(home, '.cursor', 'mcp.json'),
      codex: join(home, '.codex', 'config.toml'),
    };
    write(
      files.claude,
      JSON.stringify({
        mcpServers: { 'kronicle-lite': { command: 'npx', args: ['-y', 'kronicle-lite', 'serve'] }, other: { command: 'x' } },
        projects: { [cwd]: { mcpServers: { kl: { command: 'kronicle-lite', args: ['serve', '--data-dir', dataDir] } } } },
      }),
    );
    write(files.mcp, JSON.stringify({ mcpServers: { 'kronicle-lite': { command: 'npx', args: ['-y', 'kronicle-lite', 'serve', '--data-dir', './.kronicle-lite'] } } }));
    write(files.cursor, JSON.stringify({ mcpServers: { k: { url: 'http://127.0.0.1:7417/mcp', headers: { Authorization: 'Bearer ${env:KRONICLE_LITE_BEARER}' } } } }));
    write(files.cursorGlobal, JSON.stringify({ mcpServers: { 'kronicle-lite': { command: 'npx', args: ['-y', 'kronicle-lite', 'serve', '--data-dir', '${workspaceFolder}/.kronicle-lite'] } } }));
    write(
      files.codex,
      [
        'model = "x"',
        '[mcp_servers.kronicle-lite]',
        'command = "npx"',
        'args = ["-y", "kronicle-lite", "serve", "--actor", "codex"]  # comment',
        '[mcp_servers.kronicle-lite.env]',
        'X = "1"',
        '[mcp_servers."other"]',
        'command = "other"',
      ].join('\n'),
    );
    const before = Object.fromEntries(Object.entries(files).map(([k, f]) => [k, readFileSync(f, 'utf8')]));
    const found = findMcpClients(cwd, home);
    expect(found.entries.map((e) => [e.client, e.scope.replace(cwd, 'CWD'), e.name, e.transport])).toEqual([
      ['Claude Code', 'user', 'kronicle-lite', 'stdio'],
      ['Claude Code', 'local (CWD)', 'kl', 'stdio'],
      ['Claude Code', 'project', 'kronicle-lite', 'stdio'],
      ['Cursor', 'global', 'kronicle-lite', 'stdio'],
      ['Codex', 'user', 'kronicle-lite', 'stdio'],
    ]);
    expect(found.entries[1]!.data_dir).toBe(dataDir);
    const r = await runDoctor({ dataDir, home, cwd, env: {}, network: false });
    expect(check(r, 'mcp-clients')).toMatchObject({ status: 'ok' });
    expect(check(r, 'mcp-clients').detail).toMatch(/1 configured with a different data dir/);
    for (const [k, f] of Object.entries(files)) expect(readFileSync(f, 'utf8'), k).toBe(before[k]);
    expect(codexServers('[mcp_servers.a]\nurl = "http://x"\n')).toEqual([{ name: 'a', command: null, args: [], url: 'http://x' }]);
  });

  it('Windows: permissions skipped and a note on POSIX modes being no-ops (platform injected)', async () => {
    const { dataDir, home, cwd } = healthy();
    const r = await runDoctor({ dataDir, home, cwd, env: {}, network: false, platform: 'win32' });
    expect(check(r, 'permissions')).toMatchObject({ status: 'skip' });
    expect(check(r, 'windows')).toMatchObject({ status: 'warn' });
    expect(check(r, 'windows').detail).toMatch(/no-ops.*icacls/);
    const old = await runDoctor({ dataDir, home, cwd, env: {}, network: false, nodeVersion: '18.20.0' });
    expect(check(old, 'node')).toMatchObject({ status: 'fail' });
  });
});
