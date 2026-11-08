/**
 * `import` of an export whose tail is gone (a killed or interrupted `export --out`, a full
 * disk, a truncated copy) must not import the shorter chain silently: the export's header
 * names the head it was taken at, and the import refuses when the file does not end there.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { PassThrough, Readable, Writable } from 'node:stream';

import { describe, expect, it } from 'vitest';

import { KronicleLite } from '../src/index.js';
import { CLI, cleanEnv, tempDir } from './helpers/fs.js';

function exported(): string {
  const kl = new KronicleLite({ memory: true });
  for (let i = 0; i < 5; i++) kl.docs.putDocument({ slug: `d${i}`, title: 'T', markdown: `# D${i}\n\nbody ${i}\n`, actor_id: 'a' });
  const out = new PassThrough();
  const chunks: Buffer[] = [];
  out.on('data', (c: Buffer) => chunks.push(c));
  kl.exportEvents(out);
  out.end();
  kl.close();
  return Buffer.concat(chunks).toString('utf8');
}
const importText = (text: string) => new KronicleLite({ memory: true }).importEvents(Readable.from([text]));

describe('import refuses a truncated export', () => {
  it('a whole export imports to the head its header names', async () => {
    const text = exported();
    const head = (JSON.parse(text.split('\n')[0]!) as { head: { seq: number; hash: string } }).head;
    const r = await importText(text);
    expect(r.head).toEqual(head);
  });

  it('an export cut at a line boundary is refused, nothing imported', async () => {
    const lines = exported().split('\n');
    const cut = lines.slice(0, 4).join('\n') + '\n';
    const kl = new KronicleLite({ memory: true });
    await expect(kl.importEvents(Readable.from([cut]))).rejects.toThrow(/truncated|header/i);
    expect(kl.chain.head().seq).toBe(0);
  });

  it('an export holding only its header is refused', async () => {
    const header = exported().split('\n')[0]! + '\n';
    await expect(importText(header)).rejects.toThrow(/truncated|header/i);
  });

  it('a header whose head hash differs from the last event is refused', async () => {
    const lines = exported().trimEnd().split('\n');
    const h = JSON.parse(lines[0]!) as { head: { seq: number; hash: string } };
    h.head.hash = 'f'.repeat(64);
    lines[0] = JSON.stringify(h);
    await expect(importText(lines.join('\n') + '\n')).rejects.toThrow(/header/i);
  });

  it('CLI: import of a truncated file exits non-zero and leaves the store empty', () => {
    const dir = tempDir('kl-imp-');
    const file = join(dir, 'events.jsonl');
    writeFileSync(file, exported().split('\n').slice(0, 3).join('\n') + '\n');
    const env = cleanEnv({ HOME: dir, USERPROFILE: dir });
    const r = spawnSync(process.execPath, [CLI, 'import', '--data-dir', join(dir, 'd'), '--in', file], { env, encoding: 'utf8' });
    expect(r.status, r.stdout + r.stderr).not.toBe(0);
    expect(r.stderr).toMatch(/truncated/i);
    const kl = new KronicleLite({ dataDir: join(dir, 'd'), readOnly: true });
    expect(kl.chain.head().seq).toBe(0);
    kl.close();
    expect(readFileSync(file, 'utf8').length).toBeGreaterThan(0);
  });

  it('an export taken while another writer appends stops at its header head, and imports', async () => {
    const kl = new KronicleLite({ memory: true });
    for (let i = 0; i < 3; i++) kl.docs.putDocument({ slug: `d${i}`, title: 'T', markdown: `# D${i}\n\nbody ${i}\n`, actor_id: 'a' });
    const chunks: Buffer[] = [];
    let appended = false;
    const out = new Writable({
      write(chunk: Buffer, _enc, cb) {
        if (!appended) {
          appended = true;
          kl.docs.putDocument({ slug: 'late', title: 'T', markdown: '# Late\n\nwritten mid-export\n', actor_id: 'b' });
        }
        chunks.push(chunk);
        cb();
      },
    });
    const r = kl.exportEvents(out);
    expect(kl.chain.head().seq).toBeGreaterThan(r.head.seq);
    const text = Buffer.concat(chunks).toString('utf8');
    expect(text).not.toContain('written mid-export');
    expect((await importText(text)).head).toEqual(r.head);
    kl.close();
  });
});
