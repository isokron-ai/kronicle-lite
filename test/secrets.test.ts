/**
 * 0.6.0 secret guard. The chain is append-only and every byte of a put is
 * hashed into it: a tombstone hides a block from recall but the secret stays
 * in the events table, the export and every backup. So writes are scanned
 * BEFORE anything is chained (put / supersede / tombstone / import / watch):
 * refused by default, or stored redacted with an explicit override. A second,
 * independent read-time ruleset masks anything that got in anyway (pre-0.6.0
 * data, `import --allow-secrets`).
 *
 * Fake secrets are assembled at runtime so this file never contains one
 * literally (keeps repository secret scanners quiet).
 */

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { PassThrough, Readable } from 'node:stream';
import { describe, expect, it } from 'vitest';

import { redactSecrets, scanForSecrets, scrubForRead, SecretDetectedError } from '../src/secrets/guard.js';
import { syncInstructionFile } from '../src/instructions/sync.js';
import { entryFor, resolveContext } from '../src/instructions/paths.js';
import { KronicleLite } from '../src/store.js';
import { runCli, tempDir, write, cleanEnv } from './helpers/fs.js';

const j = (...p: string[]) => p.join('');
const AWS_KEY = j('AKIA', 'ZQ7W3XKD9PL2M4NB');
const GH_TOKEN = j('ghp', '_', 'R8bX2kLq9Wm4Tz7Yc1Vn5Hd3Jf6Gs0Pa8Ue2');
const ANTHROPIC = j('sk-', 'ant-', 'api03-', 'Qm8Zt2Lx9Rk4Wb7Nc1Vd5Hf3Jg6Ys0Pa8Ue2Tq');
const OPENAI = j('sk-', 'proj-', 'Xy7Kq2Lm9Rt4Wb8Nc1Vd5Hf3Jg6');
const SLACK = j('xox', 'b-', '1234567890-0987654321-AbCdEfGhIjKlMnOp');
const STRIPE = j('sk', '_live_', '4eC39HqLyjWDarjtT1zdp7dc');
const JWT = j('eyJ', 'hbGciOiJIUzI1NiJ9', '.', 'eyJ', 'zdWIiOiIxMjM0NTY3ODkwIn0', '.', 'dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U');
const PEM = [j('-----BEGIN ', 'RSA PRIVATE KEY-----'), 'MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun', 'VTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK', j('-----END ', 'RSA PRIVATE KEY-----')].join('\n');
const PG_URL = j('postgres://', 'app', ':', 'Xk9-p4ssW0rd-q7', '@db.internal:5432/prod');
const BEARER = j('Authorization: Bearer ', 'Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA');
const DOTENV = j('DATABASE_', 'PASSWORD', '=', 'h7Gq2xLp9vRt');

describe('write-time detectors', () => {
  it.each([
    ['aws_access_key', AWS_KEY],
    ['github_token', GH_TOKEN],
    ['anthropic_key', ANTHROPIC],
    ['openai_key', OPENAI],
    ['slack_token', SLACK],
    ['stripe_key', STRIPE],
    ['jwt', JWT],
    ['private_key', PEM],
    ['connection_string', PG_URL],
    ['bearer_token', BEARER],
    ['env_secret', DOTENV],
  ])('%s is detected, with its line, and never echoed', (id, secret) => {
    const f = scanForSecrets(`# Notes\n\nfirst line\n${secret}\n`);
    expect(f.map((x) => x.detector)).toContain(id);
    expect(f.find((x) => x.detector === id)!.line).toBe(4);
    expect(JSON.stringify(f)).not.toContain(secret.slice(4, 16));
  });

  it('documentation shapes are not secrets: placeholders, examples, env references, hashes, uuids', () => {
    const benign = [
      'postgres://user:password@localhost:5432/db',
      'postgres://${DB_USER}:${DB_PASS}@db/app',
      'mongodb://<user>:<password>@cluster0.example.net',
      'export GITHUB_TOKEN=${{ secrets.GITHUB_TOKEN }}',
      'API_KEY=your-api-key-here',
      'OPENAI_API_KEY=$OPENAI_API_KEY',
      'AWS example key AKIAIOSFODNN7EXAMPLE from the AWS docs',
      'Authorization: Bearer $TOKEN',
      'Authorization: Bearer <token>',
      'content_hash 3f2a9c0b7e6d5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f',
      'block 0f8c2a1e-4b7d-4e2a-9c3f-1a2b3c4d5e6f',
      'pip install scikit-learn; the sk-learn-compatible-estimators API',
      'token: string; // the session token type',
      '-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----',
    ].join('\n\n');
    expect(scanForSecrets(benign)).toEqual([]);
  });

  it("the repository's own docs and sources trip no write detector (precision check)", () => {
    const root = join(__dirname, '..');
    const files = ['README.md', 'CHANGELOG.md', 'ROADMAP.md', 'CONTRIBUTING.md', ...readdirSync(join(root, 'docs')).map((f) => join('docs', f)), join('skills', 'orient', 'SKILL.md')];
    for (const f of files) expect(scanForSecrets(readFileSync(join(root, f), 'utf8')), f).toEqual([]);
  });

  it('redactSecrets replaces every match with a typed marker', () => {
    const r = redactSecrets(`key ${AWS_KEY} and ${GH_TOKEN}\n${PEM}\n`);
    expect(r.text).not.toContain(AWS_KEY);
    expect(r.text).not.toContain(GH_TOKEN);
    expect(r.text).not.toContain('MIIEow');
    expect(r.text).toContain('[REDACTED:aws_access_key]');
    expect(r.text).toContain('[REDACTED:private_key]');
    expect(scanForSecrets(r.text)).toEqual([]);
    expect(r.findings.map((f) => f.detector).sort()).toEqual(['aws_access_key', 'github_token', 'private_key']);
  });
});

describe('read-time scrub (independent ruleset)', () => {
  it('masks secrets at read time and reports which rule fired', () => {
    const r = scrubForRead(`creds ${AWS_KEY} / ${PG_URL}`);
    expect(r.text).not.toContain(AWS_KEY);
    expect(r.text).not.toContain('p4ssW0rd');
    expect(r.detectors.length).toBeGreaterThanOrEqual(2);
    expect(scrubForRead('nothing to see here').detectors).toEqual([]);
  });
  it('catches a shape the write ruleset does not (defense in depth)', () => {
    // A bare PEM header (no body) is not a full key for the write rule, but
    // the read rule masks any private-key armor line.
    const armor = j('-----BEGIN ', 'OPENSSH PRIVATE KEY-----');
    expect(scanForSecrets(armor)).toEqual([]);
    expect(scrubForRead(armor).detectors).toContain('private_key_armor');
  });
});

describe('the store refuses secrets before chaining them', () => {
  it('put: refused by default, nothing appended; redact override stores a redacted copy and says so', () => {
    const store = new KronicleLite({ memory: true });
    const md = `# Deploy\n\nUse key ${AWS_KEY} for the bucket.\n`;
    const before = store.chain.head().seq;
    let err: unknown;
    try {
      store.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: md, actor_id: 't' });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(SecretDetectedError);
    const e = err as SecretDetectedError;
    expect(e.code).toBe('secret_detected');
    expect(e.findings).toEqual([{ field: 'markdown', detector: 'aws_access_key', line: 3 }]);
    expect(e.message).toMatch(/append-only/);
    expect(e.message).toMatch(/redact/);
    expect(e.message).not.toContain(AWS_KEY);
    expect(store.chain.head().seq).toBe(before);

    const r = store.docs.putDocument({ slug: 'deploy', title: 'Deploy', markdown: md, actor_id: 't', secrets: 'redact' });
    expect(r.redactions).toEqual([{ field: 'markdown', detector: 'aws_access_key', line: 3 }]);
    const exported = store.db.prepare(`SELECT group_concat(payload_canonical) AS p FROM events`).get() as { p: string };
    expect(exported.p).not.toContain(AWS_KEY);
    expect(exported.p).toContain('[REDACTED:aws_access_key]');
    store.close();
  });

  it('title, supersede content and reasons are guarded too', () => {
    const store = new KronicleLite({ memory: true });
    expect(() => store.docs.putDocument({ slug: 'x', title: `x ${GH_TOKEN}`, markdown: '# X\n\nok\n', actor_id: 't' })).toThrow(SecretDetectedError);
    const put = store.docs.putDocument({ slug: 'x', title: 'X', markdown: '# X\n\nok\n', actor_id: 't' });
    const para = put.blocks.find((b) => b.kind === 'paragraph')!;
    expect(() => store.docs.supersedeBlock({ block_id: para.block_id, new_content: `token ${SLACK}`, reason: 'r', actor_id: 't' })).toThrow(SecretDetectedError);
    expect(() => store.docs.tombstoneBlock({ block_id: para.block_id, reason: `leaked ${STRIPE}`, actor_id: 't' })).toThrow(SecretDetectedError);
    const s = store.docs.supersedeBlock({ block_id: para.block_id, new_content: `token ${SLACK}`, reason: 'r', actor_id: 't', secrets: 'redact' });
    expect(store.docs.getBlock(s.new_block_id)!.content).toBe('token [REDACTED:slack_token]');
    store.close();
  });

  it('import: an export carrying a secret is refused unless --allow-secrets; read-time scrub masks it in recall', async () => {
    const src = new KronicleLite({ memory: true });
    src.docs.putDocument({ slug: 'old', title: 'Old', markdown: `# Old\n\nLegacy creds ${AWS_KEY} here.\n`, actor_id: 't', secrets: 'allow' });
    const sink = new PassThrough();
    let jsonl = '';
    sink.on('data', (c: Buffer) => (jsonl += c.toString('utf8')));
    src.exportEvents(sink);
    sink.end();
    await new Promise((r) => sink.on('end', r));
    src.close();

    const a = new KronicleLite({ memory: true });
    await expect(a.importEvents(Readable.from([jsonl]))).rejects.toThrow(SecretDetectedError);
    expect(a.chain.head().seq).toBe(0);
    a.close();

    const b = new KronicleLite({ memory: true });
    await b.importEvents(Readable.from([jsonl]), { allow_secrets: true });
    expect(b.chain.verify().ok).toBe(true);
    const hit = b.recall.recall({ query: 'legacy creds' }).hits[0]!;
    expect(hit.content).not.toContain(AWS_KEY);
    expect(hit.read_scrubbed).toEqual(['aws_access_key_id']);
    expect(hit.authority).not.toBe('can_act');
    // The document resource and orient retraction text are scrubbed too.
    const state = b.orient.getSystemState({ actor_id: 'z' });
    expect(JSON.stringify(state)).not.toContain(AWS_KEY);
    b.close();
  });

  it('the 0.3.0 export fixture carries no secret and imports with the guard on', async () => {
    const fixture = readFileSync(join(__dirname, 'fixtures', 'export-0.3.0.jsonl'), 'utf8');
    const s = new KronicleLite({ memory: true });
    await s.importEvents(Readable.from([fixture]));
    expect(s.chain.verify().ok).toBe(true);
    s.close();
  });

  it('watch / put --from-instructions: refused (action error, nothing chained) by default; redact mode converges without re-putting', () => {
    const store = new KronicleLite({ memory: true });
    const root = tempDir('kl-secret-instr-');
    write(join(root, 'CLAUDE.md'), `# Rules\n\nDeploy token: ${GH_TOKEN}\n`);
    const entry = entryFor(join(root, 'CLAUDE.md'), resolveContext({ cwd: root }));
    const r1 = syncInstructionFile(store, entry);
    expect(r1.action).toBe('error');
    expect(r1.error).toMatch(/secret_detected/);
    expect(r1.error).not.toContain(GH_TOKEN);
    expect(store.chain.head().seq).toBe(0);
    const r2 = syncInstructionFile(store, entry, { secrets: 'redact' });
    expect(r2.action).toBe('created');
    const head = store.chain.head().seq;
    const r3 = syncInstructionFile(store, entry, { secrets: 'redact' });
    expect(r3.action).toBe('unchanged');
    expect(store.chain.head().seq).toBe(head);
    store.close();
  });

  it('CLI put: exit 1 with a clear message; --redact-secrets stores a redacted copy', async () => {
    const dir = tempDir('kl-secret-cli-');
    const file = join(dir, 'doc.md');
    write(file, `# Doc\n\n${DOTENV}\n`);
    const env = cleanEnv();
    const r1 = await runCli(['put', 'doc', file, '--data-dir', join(dir, 'data')], { env });
    expect(r1.status).toBe(1);
    expect(r1.stderr).toMatch(/secret_detected/);
    expect(r1.stderr).toMatch(/env_secret \(markdown line 3\)/);
    expect(r1.stderr).toMatch(/--redact-secrets/);
    expect(r1.stderr).not.toContain('h7Gq2xLp9vRt');
    const r2 = await runCli(['put', 'doc', file, '--data-dir', join(dir, 'data'), '--redact-secrets'], { env });
    expect(r2.status).toBe(0);
    expect(r2.stderr).toMatch(/redacted 1 secret/);
  });
});
