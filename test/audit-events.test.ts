import { describe, expect, it } from 'vitest';

import { AuditError } from '../src/audit/log.js';
import { auditIdentity, type AuditEventInput } from '../src/audit/schemas.js';
import { SecretDetectedError } from '../src/secrets/guard.js';
import { KronicleLite } from '../src/index.js';

const F1 = 'a'.repeat(64);
const F2 = 'b'.repeat(64);

function store() {
  const kl = new KronicleLite({ memory: true });
  const snap = kl.audit.putBlob(Buffer.from('{"tools":[]}'), 'application/json');
  return { kl, snap };
}

const snapshot = (snap: { sha256: string; size: number }, key = 'snap-1', fingerprint = F1): AuditEventInput => ({
  kind: 'catalog_snapshot',
  event_key: key,
  payload: { fingerprint, server: { name: 'posthog-mcp', version: '1.2.3' }, tool_count: 42, bytes: 120_000, tokens: { cl100k: 30_000 }, snapshot: snap },
});
const call = (key: string, fingerprint = F1): AuditEventInput => ({
  kind: 'call_measured',
  event_key: key,
  payload: { fingerprint, tool: 'insights-list', status: '200', is_error: false, latency_ms: 812, bytes_out: 50_000, tokens: { cl100k: 12_000 } },
});
const finding = (id: string, status: string, key = `${id}-${status}`, extra: Record<string, unknown> = {}): AuditEventInput => ({
  kind: 'finding',
  event_key: key,
  payload: { finding_id: id, status, ...extra },
});

describe('audit events: typed, schema-validated records on the chain', () => {
  it('records every kind; each lands as audit.<kind> with audit_id and event_key in the payload', () => {
    const { kl, snap } = store();
    const r = kl.audit.record('A1', [snapshot(snap), call('c1'), finding('V4', 'discovered', 'V4-d', { title: 'credentials unredacted', severity: 'S2' })], 'auditor');
    const ev4 = r[2]!.event_id;
    const more = kl.audit.record(
      'A1',
      [
        { kind: 'gate_result', event_key: 'V4-g1', payload: { finding_id: 'V4', gate: 'gate1-repro', verdict: 'upheld', evidence: [ev4] } },
        { kind: 'fix_applied', event_key: 'V4-fix', payload: { finding_id: 'V4', ref: 'https://github.com/x/y/pull/1', fingerprint_before: F1, fingerprint_after: F2 } },
        { kind: 'regression_result', event_key: 'V4-reg', payload: { finding_id: 'V4', fingerprint_before: F1, fingerprint_after: F2, verdict: 'improved', deltas: { tokens: -4000 } } },
      ],
      'auditor',
    );
    expect([...r, ...more].map((e) => e.replayed)).toEqual([false, false, false, false, false, false]);
    const types = kl.chain.range(1, kl.chain.head().seq).map((e) => e.event_type);
    expect(types).toEqual(['audit.catalog_snapshot', 'audit.call_measured', 'audit.finding', 'audit.gate_result', 'audit.fix_applied', 'audit.regression_result']);
    expect(kl.chain.get(1)!.payload).toMatchObject({ audit_id: 'A1', event_key: 'snap-1', fingerprint: F1 });
    expect(kl.verifyAll().ok).toBe(true);
    kl.close();
  });

  it('refuses a payload that does not match its kind (unknown field, missing fingerprint, bad hash) and names the event', () => {
    const { kl } = store();
    const bad: AuditEventInput[] = [
      { kind: 'call_measured', event_key: 'x', payload: { tool: 't', status: '200', is_error: false, latency_ms: 1, bytes_out: 1 } },
      { kind: 'call_measured', event_key: 'x', payload: { ...call('x').payload, transcript: 'large text' } },
      { kind: 'catalog_snapshot', event_key: 'x', payload: { ...snapshot({ sha256: 'zz', size: 1 }).payload } },
      { kind: 'finding', event_key: 'x', payload: { finding_id: 'F', status: 'fixed' } },
    ];
    for (const b of bad) {
      try {
        kl.audit.record('A1', [b], 'a');
        expect.unreachable();
      } catch (err) {
        expect(err).toBeInstanceOf(AuditError);
        expect((err as AuditError).code).toBe('invalid_audit_event');
      }
    }
    expect(kl.chain.head().seq).toBe(0);
    kl.close();
  });

  it('one call is all or nothing: a bad event at index 2 appends nothing', () => {
    const { kl, snap } = store();
    expect(() => kl.audit.record('A1', [snapshot(snap), call('c1'), call('c2', 'not-a-hash')], 'a')).toThrow(/event 2/);
    expect(kl.chain.head().seq).toBe(0);
    expect(kl.audit.query({ audit_id: 'A1' })).toEqual([]);
    kl.close();
  });

  it('ingest is idempotent by stable id: a retry replays, a different payload under the same key is refused', () => {
    const { kl, snap } = store();
    const first = kl.audit.record('A1', [snapshot(snap), call('c1')], 'proxy');
    const again = kl.audit.record('A1', [snapshot(snap), call('c1')], 'proxy-retry');
    expect(again.map((e) => e.replayed)).toEqual([true, true]);
    expect(again.map((e) => [e.event_id, e.seq])).toEqual(first.map((e) => [e.event_id, e.seq]));
    expect(kl.chain.head().seq).toBe(2);
    const changed = call('c1');
    (changed.payload as { latency_ms: number }).latency_ms = 1;
    expect(() => kl.audit.record('A1', [changed], 'proxy')).toThrow(expect.objectContaining({ code: 'event_key_conflict' }));
    // The same key in ANOTHER audit is another event.
    expect(kl.audit.record('A2', [call('c1')], 'proxy')[0]!.replayed).toBe(false);
    kl.close();
  });

  it('event ids are a function of (audit_id, event_key), identical in any store, and valid UUIDs', () => {
    const a = store();
    const b = store();
    const ra = a.kl.audit.record('A1', [call('c1')], 'x')[0]!;
    const rb = b.kl.audit.record('A1', [call('c1')], 'y')[0]!;
    expect(ra.event_id).toBe(rb.event_id);
    expect(ra.event_id).toBe(auditIdentity('A1', 'c1').event_id);
    expect(ra.event_id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(auditIdentity('A1', 'c2').event_id).not.toBe(ra.event_id);
    a.kl.close();
    b.kl.close();
  });

  it('blob refs must name a stored blob of that size, unless declared redacted', () => {
    const { kl, snap } = store();
    const missing = { sha256: 'c'.repeat(64), size: 10 };
    expect(() => kl.audit.record('A1', [snapshot(missing)], 'a')).toThrow(expect.objectContaining({ code: 'unknown_blob' }));
    expect(() => kl.audit.record('A1', [snapshot({ ...snap, size: snap.size + 1 })], 'a')).toThrow(/size/);
    expect(kl.audit.record('A1', [snapshot({ ...missing, redacted: true } as never)], 'a')[0]!.replayed).toBe(false);
    kl.close();
  });

  it('a secret in a payload is refused before it reaches the chain', () => {
    const { kl } = store();
    const token = 'ghp_' + 'Ab3'.repeat(12);
    expect(() => kl.audit.record('A1', [finding('V9', 'discovered', 'V9-d', { title: `token ${token} leaked` })], 'a')).toThrow(SecretDetectedError);
    expect(kl.chain.head().seq).toBe(0);
    kl.close();
  });

  it('evidence ids must be audit events of the same audit', () => {
    const { kl } = store();
    const other = kl.audit.record('A2', [call('c1')], 'a')[0]!.event_id;
    expect(() => kl.audit.record('A1', [finding('F1', 'discovered', 'd', { evidence: [other] })], 'a')).toThrow(expect.objectContaining({ code: 'unknown_evidence' }));
    const mine = kl.audit.record('A1', [call('c1')], 'a')[0]!.event_id;
    expect(kl.audit.record('A1', [finding('F1', 'discovered', 'd', { evidence: [mine] })], 'a')).toHaveLength(1);
    kl.close();
  });
});

describe('audit queries: by audit, by catalog fingerprint, per finding', () => {
  it('filters by audit_id, fingerprint (incl. before/after), kind and finding', () => {
    const { kl, snap } = store();
    kl.audit.record('A1', [snapshot(snap), call('c1'), call('c2', F2), finding('V1', 'discovered')], 'a');
    kl.audit.record('A1', [{ kind: 'regression_result', event_key: 'r', payload: { fingerprint_before: F1, fingerprint_after: F2, verdict: 'unchanged', deltas: {} } }], 'a');
    kl.audit.record('A2', [call('c1')], 'a');
    expect(kl.audit.query({ audit_id: 'A1' }).map((e) => e.event_key)).toEqual(['snap-1', 'c1', 'c2', 'V1-discovered', 'r']);
    expect(kl.audit.query({ fingerprint: F1 }).map((e) => `${e.audit_id}/${e.event_key}`)).toEqual(['A1/snap-1', 'A1/c1', 'A1/r', 'A2/c1']);
    expect(kl.audit.query({ fingerprint: F2, audit_id: 'A1' }).map((e) => e.event_key)).toEqual(['c2', 'r']);
    expect(kl.audit.query({ audit_id: 'A1', kind: 'call_measured' }).map((e) => e.event_key)).toEqual(['c1', 'c2']);
    expect(kl.audit.query({ audit_id: 'A1', finding_id: 'V1' })).toHaveLength(1);
    expect(kl.audit.query({ audit_id: 'A1', after_seq: 3, limit: 1 }).map((e) => e.seq)).toEqual([4]);
    expect(() => kl.audit.query({ kind: 'finding' })).toThrow(/audit_id or fingerprint/);
    kl.close();
  });

  it('finding state is a projection: discovered → refuted (gate) → reopened → accepted; illegal moves are refused', () => {
    const { kl } = store();
    kl.audit.record('A1', [finding('V2', 'discovered', 'd', { title: 'dup', severity: 'S3' })], 'a');
    expect(kl.audit.finding('A1', 'V2')).toMatchObject({ status: 'discovered', title: 'dup', severity: 'S3', events: 1 });
    kl.audit.record('A1', [{ kind: 'gate_result', event_key: 'g5', payload: { finding_id: 'V2', gate: 'gate5-refuter', verdict: 'refuted' } }], 'refuter');
    expect(kl.audit.finding('A1', 'V2')!.status).toBe('refuted');
    expect(() => kl.audit.record('A1', [finding('V2', 'accepted', 'acc0')], 'a')).toThrow(expect.objectContaining({ code: 'illegal_transition' }));
    kl.audit.record('A1', [finding('V2', 'reopened', 'reo', { severity: 'S2' })], 'human');
    kl.audit.record('A1', [finding('V2', 'accepted', 'acc')], 'human');
    expect(kl.audit.finding('A1', 'V2')).toMatchObject({ status: 'accepted', severity: 'S2', events: 4 });
    expect(kl.audit.findings('A1', 'accepted').map((f) => f.finding_id)).toEqual(['V2']);
    expect(() => kl.audit.record('A1', [finding('V3', 'accepted', 'x')], 'a')).toThrow(/\(new\) → accepted/);
    expect(() => kl.audit.record('A1', [{ kind: 'gate_result', event_key: 'gx', payload: { finding_id: 'NOPE', gate: 'g', verdict: 'upheld' } }], 'a')).toThrow(/no "discovered"/);
    expect(() => kl.audit.record('A1', [finding('V2', 'discovered', 'again')], 'a')).toThrow(expect.objectContaining({ code: 'illegal_transition' }));
    kl.close();
  });

  it('rebuild re-derives the audit projection; verifyAll flags a projection that lost a row', () => {
    const { kl, snap } = store();
    kl.audit.record('A1', [snapshot(snap), finding('V1', 'discovered'), { kind: 'gate_result', event_key: 'g', payload: { finding_id: 'V1', gate: 'g5', verdict: 'refuted' } }], 'a');
    const before = kl.audit.query({ audit_id: 'A1' });
    kl.db.exec(`DELETE FROM audit_events WHERE seq = 2; DELETE FROM audit_findings;`);
    const v = kl.verifyAll();
    expect(v.ok).toBe(false);
    expect(v.projection!.mismatches.some((m) => m.table === 'audit_events')).toBe(true);
    const r = kl.rebuild();
    expect(r.after.ok).toBe(true);
    expect(kl.audit.query({ audit_id: 'A1' })).toEqual(before);
    expect(kl.audit.finding('A1', 'V1')!.status).toBe('refuted');
    expect(kl.audit.getBlob(snap.sha256)!.bytes.toString()).toBe('{"tools":[]}'); // blobs are not projection
    kl.close();
  });
});
