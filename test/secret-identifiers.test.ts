/**
 * The write-time secret guard ran on content (title, markdown, block text, reasons, audit
 * payload values) but not on the identifiers and keys that are chained or stored beside it: an
 * actor id, an idempotency key, a slug, a source path, an apply op id, or an audit payload
 * object KEY (`deltas`, `tokens`). A token in any of them was burned into the chain and every
 * export / bundle. They are refused now (identifiers cannot be redacted, so in every mode).
 */
import { PassThrough, Readable } from 'node:stream';

import { describe, expect, it } from 'vitest';

import { KronicleLite } from '../src/index.js';
import { scanValue } from '../src/secrets/guard.js';

const TOKEN = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';
const AKIA = 'AKIA' + 'QWERTYUIOPASDFGH';
const F = 'a'.repeat(64);

function chained(kl: KronicleLite, needle: string): boolean {
  const rows = kl.db.prepare(`SELECT payload_canonical, actor_id, idempotency_key FROM events`).all() as Record<string, string | null>[];
  return rows.some((r) => Object.values(r).some((v) => typeof v === 'string' && v.includes(needle)));
}
const fresh = () => new KronicleLite({ memory: true });

describe('secret guard: identifiers and object keys', () => {
  it('scanValue scans object keys as well as values', () => {
    expect(scanValue({ deltas: { [TOKEN]: 1 } }, 'p').map((f) => f.detector)).toEqual(['github_token']);
  });

  it('put_document: actor_id, idempotency_key, slug and source path are refused; nothing chained', () => {
    const kl = fresh();
    const base = { slug: 'a', title: 't', markdown: '# A\n\nbody\n', actor_id: 'me' };
    expect(() => kl.docs.putDocument({ ...base, actor_id: TOKEN })).toThrow(/secret_detected/);
    expect(() => kl.docs.putDocument({ ...base, idempotency_key: TOKEN })).toThrow(/secret_detected/);
    expect(() => kl.docs.putDocument({ ...base, slug: TOKEN.toLowerCase() })).toThrow(/secret_detected/);
    expect(() => kl.docs.putDocument({ ...base, source: { kind: 'file', path: `/srv/${TOKEN}/notes.md` } as never })).toThrow(/secret_detected/);
    expect(() => kl.docs.putDocument({ ...base, redact_secrets: true, actor_id: TOKEN } as never)).toThrow(/secret_detected/);
    expect(kl.chain.head().seq).toBe(0);
    kl.close();
  });

  it('supersede / tombstone: a credential-shaped actor_id is refused', () => {
    const kl = fresh();
    const r = kl.docs.putDocument({ slug: 'a', title: 't', markdown: '# A\n\nbody\n', actor_id: 'me' });
    const block = r.blocks[1]!.block_id;
    const head = kl.chain.head().seq;
    expect(() => kl.docs.supersedeBlock({ block_id: block, new_content: 'x', reason: 'r', actor_id: TOKEN })).toThrow(/secret_detected/);
    expect(() => kl.docs.tombstoneBlock({ block_id: block, reason: 'r', actor_id: AKIA })).toThrow(/secret_detected/);
    expect(kl.chain.head().seq).toBe(head);
    kl.close();
  });

  it('apply: op ids, idempotency_key and actor_id are refused before anything runs (dry run too)', () => {
    const kl = fresh();
    const op = { id: 'o1', op: 'put' as const, slug: 'a', title: 't', markdown: 'm' };
    expect(() => kl.applier.apply({ ops: [{ ...op, id: TOKEN }], actor_id: 'me' })).toThrow(/secret_detected/);
    expect(() => kl.applier.apply({ ops: [op], actor_id: 'me', idempotency_key: TOKEN })).toThrow(/secret_detected/);
    expect(() => kl.applier.apply({ ops: [op], actor_id: 'me', idempotency_key: TOKEN, dry_run: true })).toThrow(/secret_detected/);
    expect(() => kl.applier.apply({ ops: [op], actor_id: TOKEN })).toThrow(/secret_detected/);
    expect(kl.chain.head().seq).toBe(0);
    const stored = kl.db.prepare(`SELECT COUNT(*) AS n FROM apply_confirmations`).get() as { n: number };
    expect(stored.n).toBe(0);
    kl.close();
  });

  it('audit_record: a token as a deltas / tokens key, or as the actor, is refused', () => {
    const kl = fresh();
    const reg = { kind: 'regression_result' as const, event_key: 'r', payload: { fingerprint_before: F, fingerprint_after: 'b'.repeat(64), verdict: 'improved', deltas: { [TOKEN]: 1 } } };
    expect(() => kl.audit.record('A', [reg], 'auditor')).toThrow(/secret_detected/);
    const call = { kind: 'call_measured' as const, event_key: 'c', payload: { fingerprint: F, tool: 't', status: 'ok', is_error: false, latency_ms: 1, bytes_out: 1, tokens: { [AKIA]: 3 } } };
    expect(() => kl.audit.record('A', [call], 'auditor')).toThrow(/secret_detected/);
    const ok = { kind: 'finding' as const, event_key: 'f', payload: { finding_id: 'V', status: 'discovered' } };
    expect(() => kl.audit.record('A', [ok], TOKEN)).toThrow(/secret_detected/);
    expect(kl.chain.head().seq).toBe(0);
    expect(chained(kl, TOKEN) || chained(kl, AKIA)).toBe(false);
    kl.close();
  });

  it('import: a credential in an event actor_id or a payload key is refused (unless --allow-secrets)', async () => {
    const src = fresh();
    src.docs.putDocument({ slug: 'a', title: 't', markdown: '# A\n\nbody\n', actor_id: 'me' });
    const out = new PassThrough();
    const chunks: Buffer[] = [];
    out.on('data', (c: Buffer) => chunks.push(c));
    src.exportEvents(out);
    out.end();
    src.close();
    const text = Buffer.concat(chunks).toString('utf8');
    // A hand-made export: same events, but the first event's actor is a token (hashes then mismatch, but the scan runs first).
    const lines = text.trimEnd().split('\n');
    const ev = JSON.parse(lines[1]!) as { actor_id: string };
    ev.actor_id = TOKEN;
    lines[1] = JSON.stringify(ev);
    await expect(fresh().importEvents(Readable.from([lines.join('\n') + '\n']))).rejects.toThrow(/secret_detected/);
  });

  it('ordinary identifiers still pass', () => {
    const kl = fresh();
    kl.docs.putDocument({ slug: 'deploy-runbook', title: 't', markdown: '# A\n\nbody\n', actor_id: 'claude-code@host', idempotency_key: 'put-2026-11-08-1' });
    kl.applier.apply({ ops: [{ id: 'op-1', op: 'put', slug: 'b', title: 't', markdown: 'm' }], actor_id: 'agent-7', idempotency_key: 'batch-42' });
    kl.audit.record('A', [{ kind: 'call_measured', event_key: 'c', payload: { fingerprint: F, tool: 't', status: 'ok', is_error: false, latency_ms: 1, bytes_out: 1, tokens: { cl100k: 3, o200k: 4 } } }], 'auditor');
    expect(kl.verifyAll().ok).toBe(true);
    kl.close();
  });
});
