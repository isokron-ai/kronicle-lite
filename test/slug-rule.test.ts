/**
 * KL-5 (dogfood): the CLI accepted `finding/G-2` but MCP put_document refused it, because each
 * path had its own slug regex. One rule now (SLUG_PATTERN / isValidSlug): the MCP schema, the
 * CLI and the store agree. MCP put_document (like apply) refuses the instruction namespaces.
 */
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { Client, InMemoryTransport } from '@modelcontextprotocol/client';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { isValidSlug, SLUG_PATTERN } from '../src/docs/documents.js';
import { createServerFactory } from '../src/server.js';
import { KronicleLite } from '../src/store.js';
import { CLI, cleanEnv, tempDir } from './helpers/fs.js';

const VALID = ['deploy-runbook', 'a', 'v1.2_notes', 'finding/G-2', 'notes/Team/Q3-plan', 'x'.repeat(128)];
const INVALID = ['', 'Deploy', '-x', 'a b', '/x', 'x/', 'Finding/G-2', 'a//b', 'x'.repeat(129), `n/${'Y'.repeat(130)}`];

describe('one slug rule for MCP, CLI and the store', () => {
  let client: Client;
  let close: () => Promise<void>;
  beforeAll(async () => {
    const store = new KronicleLite({ memory: true });
    const [clientT, serverT] = InMemoryTransport.createLinkedPair();
    const handle = serveStdio(createServerFactory(store, { defaultActorId: 'test-agent' }), { transport: serverT });
    close = () => handle.close();
    client = new Client({ name: 'slug-test', version: '0.0.0' });
    await client.connect(clientT);
  });
  afterAll(async () => {
    await client.close();
    await close();
  });

  it('isValidSlug and the MCP schema (pattern + maxLength) are the same rule; the pattern has no look-around (RE2)', () => {
    const re = new RegExp(SLUG_PATTERN);
    expect(SLUG_PATTERN).not.toMatch(/\(\?[=!<]/);
    for (const s of [...VALID, ...INVALID]) expect(re.test(s) && s.length >= 1 && s.length <= 128, s).toBe(isValidSlug(s));
    for (const s of VALID) expect(isValidSlug(s), s).toBe(true);
    for (const s of INVALID) expect(isValidSlug(s), s).toBe(false);
  });

  it('MCP put_document accepts a namespaced slug the CLI accepts (finding/G-2)', async () => {
    const r = (await client.callTool({ name: 'put_document', arguments: { slug: 'finding/G-2', title: 'G-2', markdown: '# G-2\n\nrefuted\n' } })) as { isError?: boolean; structuredContent?: { slug: string } };
    expect(r.isError ?? false).toBe(false);
    expect(r.structuredContent?.slug).toBe('finding/G-2');
  });

  it('MCP put_document refuses an invalid slug and the instruction namespaces', async () => {
    for (const slug of ['Finding/G-2', 'instructions/x/claude-md', 'memory/MEMORY']) {
      const r = (await client.callTool({ name: 'put_document', arguments: { slug, title: 't', markdown: 'm' } })) as { isError?: boolean };
      expect(r.isError, slug).toBe(true);
    }
  });

  it('CLI put agrees: finding/G-2 is accepted, Finding/G-2 refused with the rule', () => {
    const dir = tempDir('kl-slug-');
    const f = join(dir, 'f.md');
    writeFileSync(f, '# G-2\n\nrefuted\n');
    const env = cleanEnv({ HOME: dir, USERPROFILE: dir });
    const ok = spawnSync(process.execPath, [CLI, 'put', 'finding/G-2', f, '--data-dir', join(dir, 'd'), '--title', 'G-2'], { env, encoding: 'utf8' });
    expect(ok.status, ok.stderr).toBe(0);
    const bad = spawnSync(process.execPath, [CLI, 'put', 'Finding/G-2', f, '--data-dir', join(dir, 'd'), '--title', 'G-2'], { env, encoding: 'utf8' });
    expect(bad.status).not.toBe(0);
    expect(bad.stderr).toMatch(/namespaced path such as finding\/G-2/);
  });
});
