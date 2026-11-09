/**
 * Release 0.10.1: every place that names the version agrees, and the CHANGELOG has a dated entry
 * for it (not [Unreleased]).
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { CATALOG_VERSION } from '../src/catalog-pin.js';
import { VERSION } from '../src/version.js';

const root = join(__dirname, '..');
const json = (f: string) => JSON.parse(readFileSync(join(root, f), 'utf8')) as Record<string, unknown>;

describe('release 0.10.1', () => {
  it('package.json, the lockfile, server.json, VERSION, CATALOG_VERSION and the catalog snapshots agree', () => {
    expect(VERSION).toBe('0.10.1');
    expect(json('package.json')['version']).toBe(VERSION);
    const lock = json('package-lock.json') as { version: string; packages: Record<string, { version?: string }> };
    expect(lock.version).toBe(VERSION);
    expect(lock.packages['']!.version).toBe(VERSION);
    const server = json('server.json') as { version: string; packages: { version: string }[] };
    expect(server.version).toBe(VERSION);
    for (const p of server.packages) expect(p.version).toBe(VERSION);
    expect(CATALOG_VERSION).toBe(VERSION);
    for (const f of ['.mcp-catalog/kronicle-lite.json', '.mcp-catalog/kronicle-lite-core.json']) {
      expect(JSON.stringify(json(f))).toContain(`"version":"${VERSION}"`);
    }
  });

  it('the CHANGELOG dates 0.10.0 and 0.10.1 and lists #37, #38, the anchor client key model and T8', () => {
    const log = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    expect(log).toMatch(/^## \[0\.10\.0\] — \d{4}-\d{2}-\d{2}$/m);
    expect(log).not.toMatch(/^## \[Unreleased\] — next \(0\.10\.0\)/m);
    expect(log).toMatch(/^## \[0\.10\.1\] — \d{4}-\d{2}-\d{2}$/m);
    const patch = log.slice(log.indexOf('## [0.10.1]'), log.indexOf('\n## ', log.indexOf('## [0.10.1]') + 1));
    expect(patch).toContain('sectigo.pem');
    const entry = log.slice(log.indexOf('## [0.10.0]'), log.indexOf('\n## ', log.indexOf('## [0.10.0]') + 1));
    for (const s of ['(#37)', '(#38)', "the anchor client on the service's key model", '(T8)', '(C3c)', '(C2a, C2b)', '### Known limitations']) expect(entry).toContain(s);
  });

  it('README and docs name npx kronicle-lite@0.10.1 for verify-audit', () => {
    expect(readFileSync(join(root, 'README.md'), 'utf8')).toContain('npx -y kronicle-lite@0.10.1 verify-audit');
    expect(readFileSync(join(root, 'docs', 'EVIDENCE-BUNDLE.md'), 'utf8')).toContain('npx -y kronicle-lite@0.10.1 verify-audit');
  });
});
