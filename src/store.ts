/**
 * KronicleLite — one object that owns the database and wires the chain,
 * documents, recall/receipts and orient together. The MCP server and CLI
 * both talk to this.
 */

import { join } from 'node:path';
import { createInterface } from 'node:readline';
import type { Readable, Writable } from 'node:stream';

import { ApplyEngine } from './apply/apply.js';
import { AuditLog } from './audit/log.js';
import { Chain, ChainEventSchema, type ChainEvent, type VerifyChainResult } from './chain/index.js';
import type { ServerIdentity } from './crypto/keys.js';
import { StoreFileHealth } from './db/health.js';
import { openDatabase, type Db, type OpenOptions } from './db/open.js';
import { DocumentStore } from './docs/documents.js';
import { rebuildProjection, verifyProjection, type ProjectionResult } from './docs/integrity.js';
import { Lineage } from './lineage/lineage.js';
import { AssumptionAuditor } from './orient/audit.js';
import { Orient, type OrientOptions } from './orient/orient.js';
import { Recall } from './recall/recall.js';
import { ReceiptVerifier } from './recall/verify-receipt.js';
import { scanValue, SecretDetectedError } from './secrets/guard.js';

export interface KronicleLiteOptions extends OpenOptions {
  orient?: OrientOptions;
  workspace?: string;
}

export class KronicleLite {
  readonly db: Db;
  readonly identity: ServerIdentity;
  readonly dataDir: string | null;
  readonly chain: Chain;
  readonly docs: DocumentStore;
  readonly recall: Recall;
  readonly verifier: ReceiptVerifier;
  readonly orient: Orient;
  readonly auditor: AssumptionAuditor;
  /** Unreleased: derived-note lineage, the read log and per-actor pending changes. */
  readonly lineage: Lineage;
  /** 0.8.1: opened read-only (requested, or the data dir refuses writes); writes fail with SQLITE_READONLY. */
  readonly readOnly: boolean;
  /** 0.8.1: how a read-only store was opened (in place, a private snapshot, an in-memory image). */
  readonly openedVia: 'read-write' | 'read-only' | 'snapshot' | 'memory-image';
  private readonly cleanup: (() => void) | undefined;
  /** 0.9.0: audit events, their projection and the blob store. */
  readonly audit: AuditLog;
  /** 0.9.0: transactional batch writes with preview and confirm tokens. */
  readonly applier: ApplyEngine;
  readonly workspace: string;

  constructor(opts: KronicleLiteOptions = {}) {
    const opened = openDatabase(opts);
    this.db = opened.db;
    this.readOnly = opened.readOnly === true;
    this.openedVia = opened.via ?? 'read-write';
    this.cleanup = opened.cleanup;
    this.identity = opened.identity;
    this.dataDir = opened.dataDir;
    this.chain = new Chain(this.db, this.identity.signer);
    this.docs = new DocumentStore(this.db, this.chain);
    this.lineage = new Lineage(this.db, this.chain, this.docs);
    this.recall = new Recall(this.db, this.chain, this.identity.signer, opts.workspace ?? 'local', this.lineage);
    this.verifier = new ReceiptVerifier(this.db, this.chain, this.docs);
    this.orient = new Orient(this.db, this.chain, this.docs, this.identity.cursor_secret, opts.orient, this.lineage);
    // Lineage inference: what the author read since its session started (its cursor's briefing, else its latest orient).
    // 0.8.1: the session as a chain position (C2-05), plus the 24 h / 200 window whatever briefings came between (R2-04).
    this.docs.lineageInference = (actor_id, cursor, exclude, o) => this.lineage.inferForWrite(actor_id, this.orient.sessionStartSeq(actor_id, cursor), exclude, o ?? {});
    // 0.8.1 (L2-03): every integrity pass also checks the store file under this connection's cache.
    const health = new StoreFileHealth(this.db, this.dataDir !== null ? join(this.dataDir, 'kronicle-lite.db') : null);
    this.orient.storeHealth = () => health.check();
    this.recall.storeHealth = () => health.check();
    this.auditor = new AssumptionAuditor(this.chain, this.docs);
    this.audit = new AuditLog(this.db, this.chain);
    this.workspace = opts.workspace ?? 'local';
    this.applier = new ApplyEngine(this.db, this.chain, this.docs, this.identity.signer.public_key_pem, { tenant: this.workspace, secret: this.identity.cursor_secret });
  }

  close(): void {
    this.db.close();
    this.cleanup?.();
  }

  /**
   * 0.5.0: the chain check plus, when the range is the whole chain (or
   * `projection: true`), the projection check: every stored document,
   * revision and block re-derived from the events and re-hashed. `ok` is
   * false when either fails.
   */
  verifyAll(from_seq = 1, to_seq?: number, opts: { projection?: boolean } = {}): VerifyChainResult & { projection: ProjectionResult | null } {
    const chain = this.chain.verify(from_seq, to_seq);
    const whole = from_seq === 1 && (to_seq === undefined || to_seq >= chain.head.seq);
    const projection = (opts.projection ?? whole) ? this.withAuditCheck(verifyProjection(this.db, this.chain)) : null;
    return { ...chain, ok: chain.ok && (projection?.ok ?? true), projection };
  }

  /** 0.9.0: the audit projection (audit_events) against the chain's audit.* events. */
  private withAuditCheck(p: ProjectionResult): ProjectionResult {
    const problem = this.audit.checkProjection();
    if (!problem) return p;
    return { ...p, ok: false, mismatch_count: p.mismatch_count + 1, mismatches: [...p.mismatches, { table: 'audit_events', key: 'count', field: 'rows', detail: problem }] };
  }

  /**
   * 0.5.0: rebuild documents / revisions / blocks / sources from the chain.
   * Refuses when the chain itself does not verify (the events are the only
   * source of truth; rebuilding from a broken chain would launder it).
   */
  rebuild(): { events: number; before: ProjectionResult; after: ProjectionResult } {
    const chain = this.chain.verify();
    if (!chain.ok) {
      const m = chain.first_mismatch!;
      throw new Error(`chain does not verify (${m.kind} at seq ${m.seq}); restore the events table from an export or backup first`);
    }
    const before = this.withAuditCheck(verifyProjection(this.db, this.chain));
    const { events } = rebuildProjection(this.db, this.chain);
    this.db.transaction(() => this.audit.rebuildProjection(this.chain.iterate())).immediate();
    return { events, before, after: this.withAuditCheck(verifyProjection(this.db, this.chain)) };
  }

  /** Write every event as one JSON line, ascending seq. First line is a header. */
  exportEvents(out: Writable): { events: number; head: { seq: number; hash: string } } {
    const head = this.chain.head();
    out.write(
      JSON.stringify({
        kronicle_lite_export: 1,
        head,
        key_id: this.identity.signer.key_id,
        public_key_pem: this.identity.signer.public_key_pem,
        exported_at: new Date().toISOString(),
      }) + '\n',
    );
    let n = 0;
    for (const ev of this.chain.iterate()) {
      // why: iterate() reads in batches, so a writer appending mid-export would add events past the
      // header's head; the export is the chain as of that head (import checks the file ends there).
      if (ev.seq > head.seq) break;
      out.write(JSON.stringify(ev) + '\n');
      n++;
    }
    // 0.4.0, additive: one trailing line with the countersigned anchor
    // receipts, only when there are any (an un-anchored store exports exactly
    // as 0.3.0 did). `import` skips it; receipts are re-fetchable by chain_id.
    const anchors = this.chain.listAnchors();
    if (anchors.length > 0) {
      out.write(
        JSON.stringify({
          kronicle_lite_anchors: 1,
          anchors: anchors.map(({ receipt_json, ...rest }) => ({ ...rest, receipt: JSON.parse(receipt_json) as unknown })),
        }) + '\n',
      );
    }
    return { events: n, head };
  }

  /**
   * Import a JSONL export into an EMPTY store, verifying every hash and link
   * as it goes and rebuilding documents/blocks from the events. Throws on the
   * first inconsistency; nothing is committed in that case.
   *
   * 0.6.0: every event payload is scanned with the write-time secret rules
   * first and the import is refused (SecretDetectedError, nothing committed)
   * when any matches. Chained bytes cannot be redacted without breaking their
   * hashes, so the override (`allow_secrets`) imports them verbatim; the
   * read-time scrub still masks them on the way out.
   */
  async importEvents(input: Readable, opts: { allow_secrets?: boolean } = {}): Promise<{ events: number; head: { seq: number; hash: string } }> {
    if (this.chain.head().seq !== 0) throw new Error('import requires an empty store (head seq must be 0)');
    const lines = createInterface({ input, crlfDelay: Infinity });
    const events: ChainEvent[] = [];
    let header: { key_id?: string; public_key_pem?: string; head?: { seq?: unknown; hash?: unknown } } | null = null;
    let first = true;
    for await (const line of lines) {
      if (line.trim().length === 0) continue;
      const obj: unknown = JSON.parse(line);
      if (typeof obj === 'object' && obj !== null && 'kronicle_lite_anchors' in obj) continue; // trailing anchors line (0.4.0)
      if (first) {
        first = false;
        if (typeof obj === 'object' && obj !== null && 'kronicle_lite_export' in obj) {
          header = obj as { key_id?: string; public_key_pem?: string };
          continue;
        }
      }
      events.push(ChainEventSchema.parse(obj));
    }
    // 0.9.0: the header names the head the export was taken at. A file that ends anywhere else was
    // cut short (an interrupted `export --out`, a full disk, a partial copy): refuse it rather than
    // import a shorter chain as if it were the whole one.
    const claimed = header?.head;
    if (claimed && typeof claimed === 'object' && typeof claimed.seq === 'number') {
      const last = events.at(-1);
      const endSeq = last?.seq ?? 0;
      if (claimed.seq !== endSeq) {
        throw new Error(`import: the export is truncated: its header names head seq ${claimed.seq}, but the file ends at seq ${endSeq}; nothing imported`);
      }
      if (last && typeof claimed.hash === 'string' && claimed.hash !== last.this_hash) {
        throw new Error(`import: the last event (seq ${endSeq}) does not hash to the head the export header names; nothing imported`);
      }
    }
    if (opts.allow_secrets !== true) {
      const findings = events.flatMap((ev) => scanValue({ payload: ev.payload, actor_id: ev.actor_id, idempotency_key: ev.idempotency_key }, `seq ${ev.seq} ${ev.event_type}`));
      if (findings.length > 0) throw new SecretDetectedError(findings, 'this import', 'import with --allow-secrets (verbatim: chained bytes cannot be redacted)');
    }
    const tx = this.db.transaction(() => {
      // Keep the exporting server's public key so its receipts and
      // checkpoints can still be verified against this copy.
      if (header && typeof header.key_id === 'string' && typeof header.public_key_pem === 'string') {
        this.db
          .prepare(
            `INSERT OR IGNORE INTO signing_keys (key_id, public_key_pem, algorithm, created_at) VALUES (?, ?, 'Ed25519', ?)`,
          )
          .run(header.key_id, header.public_key_pem, new Date().toISOString());
      }
      for (const ev of events) {
        this.chain.appendVerbatim(ev);
        this.docs.applyEvent(ev);
        this.audit.applyEvent(ev);
      }
    });
    tx.immediate();
    return { events: events.length, head: this.chain.head() };
  }
}
