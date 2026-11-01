/**
 * KronicleLite — one object that owns the database and wires the chain,
 * documents, recall/receipts and orient together. The MCP server and CLI
 * both talk to this.
 */

import { createInterface } from 'node:readline';
import type { Readable, Writable } from 'node:stream';

import { Chain, ChainEventSchema, type ChainEvent } from './chain/index.js';
import type { ServerIdentity } from './crypto/keys.js';
import { openDatabase, type Db, type OpenOptions } from './db/open.js';
import { DocumentStore } from './docs/documents.js';
import { AssumptionAuditor } from './orient/audit.js';
import { Orient, type OrientOptions } from './orient/orient.js';
import { Recall } from './recall/recall.js';
import { ReceiptVerifier } from './recall/verify-receipt.js';

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

  constructor(opts: KronicleLiteOptions = {}) {
    const opened = openDatabase(opts);
    this.db = opened.db;
    this.identity = opened.identity;
    this.dataDir = opened.dataDir;
    this.chain = new Chain(this.db, this.identity.signer);
    this.docs = new DocumentStore(this.db, this.chain);
    this.recall = new Recall(this.db, this.chain, this.identity.signer, opts.workspace ?? 'local');
    this.verifier = new ReceiptVerifier(this.db, this.chain, this.docs);
    this.orient = new Orient(this.db, this.chain, this.docs, this.identity.cursor_secret, opts.orient);
    this.auditor = new AssumptionAuditor(this.chain, this.docs);
  }

  close(): void {
    this.db.close();
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
   */
  async importEvents(input: Readable): Promise<{ events: number; head: { seq: number; hash: string } }> {
    if (this.chain.head().seq !== 0) throw new Error('import requires an empty store (head seq must be 0)');
    const lines = createInterface({ input, crlfDelay: Infinity });
    const events: ChainEvent[] = [];
    let header: { key_id?: string; public_key_pem?: string } | null = null;
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
      }
    });
    tx.immediate();
    return { events: events.length, head: this.chain.head() };
  }
}
