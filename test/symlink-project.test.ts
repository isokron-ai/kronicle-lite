/**
 * 0.8.0 fix: a project reached through a symlink is ONE project. `put` used
 * the physical cwd (macOS: /private/var/…) while a hook passed its --cwd
 * literally (/var/…): different project keys, and orient / pending / pulse
 * scoped to the other spelling showed 0 retractions. Every cwd and project
 * root now goes through realpath (canonicalPath) before a key is computed.
 */

import { spawnSync } from 'node:child_process';
import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { canonicalPath, entryFor, projectScopeFor, resolveContext } from '../src/instructions/paths.js';
import { CLI, cleanEnv, gitInit, tempDir } from './helpers/fs.js';

function kl(args: string[], opts: { cwd?: string; input?: string } = {}) {
  const r = spawnSync(process.execPath, [CLI, ...args], { env: cleanEnv(), encoding: 'utf8', ...(opts.cwd ? { cwd: opts.cwd } : {}), ...(opts.input !== undefined ? { input: opts.input } : {}) });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

/** A real project dir and a symlink to it (a junction on Windows: no privilege needed). */
function linked(git: boolean) {
  const root = tempDir('kl-symlink-');
  const real = join(root, 'real', 'proj');
  mkdirSync(real, { recursive: true });
  if (git) gitInit(real);
  mkdirSync(join(root, 'via'));
  const link = join(root, 'via', 'proj');
  symlinkSync(real, link, process.platform === 'win32' ? 'junction' : 'dir');
  return { root, real, link, data: join(root, 'data'), home: join(root, 'home') };
}

const RULES = (target: string) => `# Rules\n\n## Deploy\n\nDeploy to ${target} only.\n`;

describe('symlinked project root: one project key whichever spelling is used', () => {
  for (const git of [false, true]) {
    it(`keys and instruction slugs agree for the real path and the link (${git ? 'git repo' : 'plain dir'})`, () => {
      const p = linked(git);
      expect(canonicalPath(p.link)).toBe(canonicalPath(p.real));
      expect(projectScopeFor({ cwd: p.link, home: p.home })).toEqual(projectScopeFor({ cwd: p.real, home: p.home }));
      const viaLink = entryFor(join(p.link, 'CLAUDE.md'), resolveContext({ cwd: p.link, home: p.home }));
      const viaReal = entryFor(join(p.real, 'CLAUDE.md'), resolveContext({ cwd: p.real, home: p.home }));
      expect(viaLink.slug).toBe(viaReal.slug);
      expect(viaLink.project).toEqual(viaReal.project);
      expect(viaLink.kind).toBe('instruction');
      // a file that no longer exists (a deletion event) is still classified by its canonical parent
      expect(entryFor(join(p.link, 'gone.md'), resolveContext({ cwd: p.real, home: p.home })).project?.key).toBe(viaReal.project?.key);
    });

    for (const [putVia, readVia] of [['real', 'link'], ['link', 'real']] as const) {
      it(`put via the ${putVia} path, change via a hook, orient / pending / pulse via the ${readVia} path see the retraction (${git ? 'git' : 'plain'})`, () => {
        const p = linked(git);
        const at = (which: 'real' | 'link') => p[which];
        writeFileSync(join(p.real, 'CLAUDE.md'), RULES('prod-a'));
        const put = kl(['put', '--from-instructions', join(at(putVia), 'CLAUDE.md'), '--data-dir', p.data, '--cwd', at(putVia)], { cwd: at(putVia) });
        expect(put.status, put.stderr).toBe(0);
        const o0 = kl(['orient', '--data-dir', p.data, '--actor', 'agent', '--json', '--cwd', at(readVia)]);
        expect(o0.status, o0.stderr).toBe(0);
        const cursor = JSON.parse(o0.stdout).cursor as string;
        expect(kl(['get', `instructions/${projectScopeFor({ cwd: p.real }).keys[0]}/claude-md`, '--data-dir', p.data, '--actor', 'agent']).status).toBe(0);
        const seed = JSON.parse(kl(['pulse', '--data-dir', p.data, '--json', '--cwd', at(readVia)]).stdout).cursor as string;

        writeFileSync(join(p.real, 'CLAUDE.md'), RULES('prod-b'));
        const hook = JSON.stringify({ hook_event_name: 'FileChanged', file_path: join(at(readVia), 'CLAUDE.md'), cwd: at(readVia), session_id: 't' });
        const h = kl(['put', '--from-instructions', '--stdin-hook', '--data-dir', p.data], { cwd: at(readVia), input: hook });
        expect(h.status, h.stderr).toBe(0);

        for (const cwd of [p.link, p.real]) {
          const o = JSON.parse(kl(['orient', '--data-dir', p.data, '--actor', 'agent', '--cursor', cursor, '--focus', 'retractions', '--json', '--cwd', cwd]).stdout);
          expect(o.retractions.length, `orient --cwd ${cwd}`).toBeGreaterThan(0);
          expect(o.retractions[0]).toMatchObject({ kind: 'instruction' });
          expect(o.retractions[0].diff).toContain('[-prod-a-]{+prod-b+}');
          const pend = JSON.parse(kl(['pending', '--data-dir', p.data, '--actor', 'agent', '--json', '--cwd', cwd]).stdout);
          expect(pend.pending_count, `pending --cwd ${cwd}`).toBe(1);
          expect(pend.pending_hidden).toBe(0);
          const pu = kl(['pulse', '--data-dir', p.data, '--json', '--cwd', cwd, '--cursor', seed]);
          expect(pu.status, `pulse --cwd ${cwd}`).toBe(77);
          expect(JSON.parse(pu.stdout).blocking).toHaveLength(1);
        }
        // one document for the file, not one per spelling
        const docs = JSON.parse(kl(['put', '--from-instructions', join(at(readVia), 'CLAUDE.md'), '--data-dir', p.data, '--cwd', at(readVia), '--json']).stdout);
        expect(JSON.stringify(docs)).not.toContain('"status":"created"');
      });
    }
  }
});
