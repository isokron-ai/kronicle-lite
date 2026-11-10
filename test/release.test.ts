/**
 * Release 0.11.2: every place that names the version agrees, and the CHANGELOG has a dated entry
 * for it (not [Unreleased]).
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { CATALOG_VERSION } from '../src/catalog-pin.js';
import { VERSION } from '../src/version.js';

const root = join(__dirname, '..');
const json = (f: string) => JSON.parse(readFileSync(join(root, f), 'utf8')) as Record<string, unknown>;

describe('release 0.11.2', () => {
  it('package.json, the lockfile, server.json, VERSION, CATALOG_VERSION and the catalog snapshots agree', () => {
    expect(VERSION).toBe('0.11.2');
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

  it('the CHANGELOG dates 0.10.0, 0.10.1 and 0.10.2 and lists #37, #38, the anchor client key model and T8', () => {
    const log = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    expect(log).toMatch(/^## \[0\.10\.0\] — \d{4}-\d{2}-\d{2}$/m);
    expect(log).not.toMatch(/^## \[Unreleased\] — next \(0\.10\.0\)/m);
    expect(log).toMatch(/^## \[0\.10\.1\] — \d{4}-\d{2}-\d{2}$/m);
    const patch = log.slice(log.indexOf('## [0.10.1]'), log.indexOf('\n## ', log.indexOf('## [0.10.1]') + 1));
    expect(patch).toContain('sectigo.pem');
    expect(log).toMatch(/^## \[0\.10\.2\] — \d{4}-\d{2}-\d{2}$/m);
    const p2 = log.slice(log.indexOf('## [0.10.2]'), log.indexOf('\n## ', log.indexOf('## [0.10.2]') + 1));
    expect(p2).toContain('statement of work');
    const entry = log.slice(log.indexOf('## [0.10.0]'), log.indexOf('\n## ', log.indexOf('## [0.10.0]') + 1));
    for (const s of ['(#37)', '(#38)', "the anchor client on the service's key model", '(T8)', '(C3c)', '(C2a, C2b)', '### Known limitations']) expect(entry).toContain(s);
  });

  it('the CHANGELOG dates 0.11.0 and it is no longer unreleased', () => {
    const log = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    expect(log).toMatch(/^## \[0\.11\.0\] — \d{4}-\d{2}-\d{2}$/m);
    expect(log).not.toMatch(/^## \[Unreleased\] — next \(0\.11\.0\)/m);
  });

  it('the CHANGELOG dates 0.11.1 and lists the key command, --anchor-key-file and the audit-mode failure', () => {
    const log = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    expect(log).toMatch(/^## \[0\.11\.1\] — \d{4}-\d{2}-\d{2}$/m);
    expect(log).not.toMatch(/^## \[Unreleased\].*0\.11\.1/m);
    const entry = log.slice(log.indexOf('## [0.11.1]'), log.indexOf('\n## ', log.indexOf('## [0.11.1]') + 1));
    for (const s of ['KRONICLE_ANCHOR_KEY_CMD', '--anchor-key-file', '--allow-pending', '(GL-6, PH-10)']) expect(entry).toContain(s);
  });

  it('the CHANGELOG dates 0.11.2 and lists the token-label fix in password_assignment and env_secret', () => {
    const log = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    expect(log).toMatch(/^## \[0\.11\.2\] — \d{4}-\d{2}-\d{2}$/m);
    expect(log).not.toMatch(/^## \[Unreleased\].*0\.11\.2/m);
    const entry = log.slice(log.indexOf('## [0.11.2]'), log.indexOf('\n## ', log.indexOf('## [0.11.2]') + 1));
    for (const s of ['Tokens: cl100k', '`password_assignment`', '`env_secret`', 'entropy']) expect(entry).toContain(s);
  });

  it('README and docs name npx kronicle-lite@0.11.2 for verify-audit', () => {
    expect(readFileSync(join(root, 'README.md'), 'utf8')).toContain('npx -y kronicle-lite@0.11.2 verify-audit');
    expect(readFileSync(join(root, 'docs', 'EVIDENCE-BUNDLE.md'), 'utf8')).toContain('npx -y kronicle-lite@0.11.2 verify-audit');
  });
});
