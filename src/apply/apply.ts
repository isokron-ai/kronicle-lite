/**
 * `apply` (0.9.0): a batch of document writes against the LOCAL store, with
 * a preview step. kronicle-lite is one SQLite file, so `all_or_nothing` is a
 * real transaction: every op lands, or none does (no compensation, no saga).
 *
 *   dry_run  → the plan runs inside a transaction that is always rolled
 *              back: exact per-op results and diffs, nothing persisted, plus
 *              a confirm token.
 *   commit   → optional confirm_token; everything the token binds is
 *              re-validated INSIDE the commit transaction (TOCTOU), authz is
 *              re-checked per op (the token proves a preview happened, it
 *              authorizes nothing), each op's expect_version is checked, and
 *              one `apply.committed` chain event records the plan hash, the
 *              result hash and per-op receipts.
 *
 * The confirm token binds: plan hash, actor, tenant (workspace), sandbox
 * (this chain's id), target server, catalog fingerprint, resource ids, the
 * versions they had at preview, policy version, a nonce, an expiry and the
 * idempotency key. HMAC-SHA256 under the store's cursor secret; single use
 * (the nonce is consumed by the commit, or burned when the commit fails).
 *
 * Idempotency: a key that already committed replays its stored result
 * (`replayed: true`) when the request hashes the same, and is refused when
 * it does not. No DAG and no `$ref`s between ops (v1): a dependent write is a
 * second apply that takes the first one's receipts as input.
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

import { CATALOG_FINGERPRINT } from '../catalog-pin.js';
import type { Chain, ChainHead } from '../chain/index.js';
import { canonicalize, type JsonValue } from '../crypto/canonical.js';
import { sha256Hex } from '../crypto/hash.js';
import { chainIdFromPublicKeyPem } from '../crypto/keys.js';
import type { Db } from '../db/open.js';
import { DocumentError, isInstructionSlug, type DocumentStore } from '../docs/documents.js';
import { snippet, wordDiff } from '../orient/textdiff.js';
import { SecretDetectedError } from '../secrets/guard.js';

export const APPLY_MODES = ['all_or_nothing', 'best_effort'] as const;
export type ApplyMode = (typeof APPLY_MODES)[number];
export const APPLY_POLICY_VERSION = 'kl-apply-policy/1';
export const MAX_APPLY_OPS = 50;
export const CONFIRM_TTL_DEFAULT_S = 300;
export const CONFIRM_TTL_MAX_S = 900;
const TOKEN_PREFIX = 'klc1';
const TOKEN_DOMAIN = 'kronicle-lite/apply-confirm/1\n';

export type ApplyOp =
  | { id: string; op: 'put'; slug: string; title: string; markdown: string; expect_version?: number | undefined }
  | { id: string; op: 'supersede'; block_id: string; new_content: string; reason: string; expect_version?: number | undefined }
  | { id: string; op: 'tombstone'; block_id: string; reason: string; expect_version?: number | undefined };

export interface ApplyInput {
  mode?: ApplyMode | undefined;
  idempotency_key?: string | undefined;
  dry_run?: boolean | undefined;
  confirm_token?: string | undefined;
  ttl_seconds?: number | undefined;
  ops: ApplyOp[];
  actor_id: string;
}

export type OpStatus = 'planned' | 'applied' | 'failed' | 'rolled_back' | 'not_run';

export interface OpResult {
  id: string;
  op: ApplyOp['op'];
  status: OpStatus;
  /** The document (slug) the op touched, and the block when it names one. */
  target: { slug: string | null; doc_id: string | null; block_id: string | null };
  /** Document revision before and after the op (0 = did not exist). */
  version_before: number | null;
  version_after: number | null;
  /** What the op changes (word diff for a block, block counts for a put). */
  diff: string | null;
  /** Chain events this op appended: [first_seq, last_seq] and the last hash. null when nothing landed. */
  receipt: { first_seq: number; last_seq: number; this_hash: string } | null;
  error: { code: string; message: string } | null;
}

export interface ApplyResult {
  status: 'planned' | 'committed' | 'partial' | 'rolled_back' | 'failed';
  mode: ApplyMode;
  dry_run: boolean;
  /** This is a real transaction on the local store: no compensation is ever involved. */
  atomic: boolean;
  plan_hash: string;
  result_hash: string | null;
  replayed: boolean;
  idempotency_key: string | null;
  ops: OpResult[];
  confirm_token: string | null;
  confirm_expires_at: string | null;
  /** The apply.committed event; null on dry run and on rollback. */
  receipt: { seq: number; event_id: string; this_hash: string } | null;
  head: ChainHead;
}

export class ApplyError extends Error {
  override readonly name = 'ApplyError';
  constructor(
    readonly code:
      | 'invalid_plan'
      | 'idempotency_key_reused'
      | 'confirm_invalid'
      | 'confirm_expired'
      | 'confirm_used'
      | 'confirm_mismatch'
      | 'stale_plan'
      | 'version_conflict'
      | 'forbidden',
    message: string,
  ) {
    super(message);
  }
}

/** Authorization for one op, checked at preview AND again at commit. Return null to allow, else the reason. */
export type ApplyPolicy = (actor_id: string, op: ApplyOp, target: { slug: string | null }) => string | null;

/**
 * Default policy (APPLY_POLICY_VERSION): instruction-file documents
 * (`instructions/…`, `memory/…`) mirror files on disk and are written only
 * by `put --from-instructions` / `watch`, never by a batch.
 */
export const defaultApplyPolicy: ApplyPolicy = (_actor, _op, target) =>
  target.slug !== null && isInstructionSlug(target.slug) ? `${target.slug} is an instruction-file document; edit the file instead` : null;

interface TokenBody {
  v: 1;
  plan_hash: string;
  actor_id: string;
  tenant: string;
  sandbox: string;
  server: 'kronicle-lite';
  catalog_fingerprint: string;
  resources: string[];
  versions: Record<string, string>;
  policy_version: string;
  nonce: string;
  exp: string;
  idempotency_key: string | null;
}

export interface ApplyEngineOptions {
  tenant: string;
  secret: string;
  policy?: ApplyPolicy;
  policy_version?: string;
  catalog_fingerprint?: string;
  now?: () => Date;
}

const b64u = (b: Buffer | string) => Buffer.from(b).toString('base64url');

export class ApplyEngine {
  private readonly sandbox: string;
  policy: ApplyPolicy;
  policy_version: string;
  catalog_fingerprint: string;
  now: () => Date;

  constructor(
    private readonly db: Db,
    private readonly chain: Chain,
    private readonly docs: DocumentStore,
    signer_public_key_pem: string,
    private readonly opts: ApplyEngineOptions,
  ) {
    this.sandbox = chainIdFromPublicKeyPem(signer_public_key_pem);
    this.policy = opts.policy ?? defaultApplyPolicy;
    this.policy_version = opts.policy_version ?? APPLY_POLICY_VERSION;
    this.catalog_fingerprint = opts.catalog_fingerprint ?? CATALOG_FINGERPRINT;
    this.now = opts.now ?? (() => new Date());
  }

  apply(input: ApplyInput): ApplyResult {
    const mode: ApplyMode = input.mode ?? 'all_or_nothing';
    const ops = validatePlan(input.ops);
    const plan_hash = planHash(mode, ops);
    const request_hash = sha256Hex(canonicalize({ mode, ops } as unknown as JsonValue));
    const key = input.idempotency_key ?? null;

    if (!input.dry_run && key !== null) {
      const prior = this.db.prepare(`SELECT request_hash, result_json FROM apply_results WHERE idempotency_key = ?`).get(key) as
        | { request_hash: string; result_json: string }
        | undefined;
      if (prior) {
        if (prior.request_hash !== request_hash) throw new ApplyError('idempotency_key_reused', 'idempotency_key was already used for a different plan');
        return { ...(JSON.parse(prior.result_json) as ApplyResult), replayed: true };
      }
    }

    if (input.dry_run) return this.preview(mode, ops, plan_hash, key, input);

    const token = input.confirm_token !== undefined ? this.parseToken(input.confirm_token) : null;
    try {
      const run = this.db.transaction((): ApplyResult => {
        if (token) this.revalidate(token, { plan_hash, actor_id: input.actor_id, key, ops });
        const results = this.execute(mode, ops, input.actor_id);
        const failed = results.some((r) => r.status === 'failed');
        if (failed && mode === 'all_or_nothing') throw new RolledBack(results);
        const result_hash = sha256Hex(canonicalize(results as unknown as JsonValue));
        const ev = this.chain.append({
          event_type: 'apply.committed',
          actor_id: input.actor_id,
          payload: {
            plan_hash,
            result_hash,
            mode,
            ...(key !== null ? { idempotency_key: key } : {}),
            ...(token ? { confirm_nonce: token.nonce } : {}),
            policy_version: this.policy_version,
            ops: results.map((r) => ({ id: r.id, op: r.op, status: r.status, ...(r.target.slug ? { slug: r.target.slug } : {}), ...(r.target.block_id ? { block_id: r.target.block_id } : {}), version_after: r.version_after, receipt: r.receipt })) as unknown as JsonValue,
          },
          ...(key !== null ? { idempotency_key: `apply:${sha256Hex(key)}` } : {}),
        });
        const out: ApplyResult = {
          status: failed ? 'partial' : 'committed',
          mode,
          dry_run: false,
          atomic: true,
          plan_hash,
          result_hash,
          replayed: false,
          idempotency_key: key,
          ops: results,
          confirm_token: null,
          confirm_expires_at: null,
          receipt: { seq: ev.event.seq, event_id: ev.event.event_id, this_hash: ev.event.this_hash },
          head: ev.head,
        };
        if (key !== null) {
          this.db.prepare(`INSERT INTO apply_results (idempotency_key, request_hash, result_json, seq) VALUES (?, ?, ?, ?)`).run(key, request_hash, JSON.stringify(out), ev.event.seq);
        }
        return out;
      });
      return run.immediate();
    } catch (err) {
      // Single use: a token that took part in a failed commit is burned too (the transaction rolled back its consumption).
      if (token) this.db.prepare(`UPDATE apply_confirmations SET used_at = COALESCE(used_at, ?), outcome = COALESCE(outcome, 'failed') WHERE nonce = ?`).run(this.now().toISOString(), token.nonce);
      if (err instanceof RolledBack) {
        return {
          status: 'rolled_back',
          mode,
          dry_run: false,
          atomic: true,
          plan_hash,
          result_hash: null,
          replayed: false,
          idempotency_key: key,
          ops: err.results.map((r) => (r.status === 'applied' ? { ...r, status: 'rolled_back', receipt: null, version_after: r.version_before } : r)),
          confirm_token: null,
          confirm_expires_at: null,
          receipt: null,
          head: this.chain.head(),
        };
      }
      throw err;
    }
  }

  // ───────────────────────────── preview ─────────────────────────────

  private preview(mode: ApplyMode, ops: ApplyOp[], plan_hash: string, key: string | null, input: ApplyInput): ApplyResult {
    const head = this.chain.head();
    const versions = this.versionsOf(ops);
    let results: OpResult[] = [];
    // why: run the real writes and always roll back, so the preview is exactly what a commit would do now.
    try {
      this.db.transaction(() => {
        results = this.execute(mode, ops, input.actor_id);
        throw new RolledBack(results);
      })();
    } catch (err) {
      if (!(err instanceof RolledBack)) throw err;
    }
    const anyFailed = results.some((r) => r.status === 'failed');
    const blocked = anyFailed && mode === 'all_or_nothing';
    const ttl = Math.min(Math.max(input.ttl_seconds ?? CONFIRM_TTL_DEFAULT_S, 1), CONFIRM_TTL_MAX_S);
    let token: string | null = null;
    let exp: string | null = null;
    if (!blocked) {
      const issued = this.now();
      exp = new Date(issued.getTime() + ttl * 1000).toISOString();
      const body: TokenBody = {
        v: 1,
        plan_hash,
        actor_id: input.actor_id,
        tenant: this.opts.tenant,
        sandbox: this.sandbox,
        server: 'kronicle-lite',
        catalog_fingerprint: this.catalog_fingerprint,
        resources: Object.keys(versions).sort(),
        versions,
        policy_version: this.policy_version,
        nonce: randomBytes(16).toString('hex'),
        exp,
        idempotency_key: key,
      };
      token = this.signToken(body);
      this.db
        .prepare(`INSERT INTO apply_confirmations (nonce, plan_hash, actor_id, issued_at, expires_at) VALUES (?, ?, ?, ?, ?)`)
        .run(body.nonce, plan_hash, input.actor_id, issued.toISOString(), exp);
    }
    return {
      status: blocked ? 'failed' : 'planned',
      mode,
      dry_run: true,
      atomic: true,
      plan_hash,
      result_hash: null,
      replayed: false,
      idempotency_key: key,
      ops: results.map((r) => (r.status === 'applied' ? { ...r, status: 'planned', receipt: null } : r)),
      confirm_token: token,
      confirm_expires_at: exp,
      receipt: null,
      head,
    };
  }

  // ───────────────────────────── execution ─────────────────────────────

  /** Run the ops in order inside the caller's transaction. all_or_nothing stops at the first failure. */
  private execute(mode: ApplyMode, ops: ApplyOp[], actor_id: string): OpResult[] {
    const out: OpResult[] = [];
    let stop = false;
    for (const op of ops) {
      const target = this.targetOf(op);
      const base: OpResult = { id: op.id, op: op.op, status: 'not_run', target, version_before: this.revisionOf(target.doc_id), version_after: null, diff: null, receipt: null, error: null };
      if (stop) {
        out.push(base);
        continue;
      }
      const before = this.chain.head().seq;
      const runOne = (): OpResult => {
        const denied = this.policy(actor_id, op, { slug: target.slug });
        if (denied !== null) throw new ApplyError('forbidden', denied);
        if (op.expect_version !== undefined && op.expect_version !== base.version_before) {
          throw new ApplyError('version_conflict', `expect_version ${op.expect_version}, current revision is ${base.version_before ?? 'unknown'}`);
        }
        const diff = this.diffOf(op);
        const after = this.write(op, actor_id);
        const head = this.chain.head();
        return {
          ...base,
          status: 'applied',
          target: { ...target, doc_id: after.doc_id, block_id: after.block_id ?? target.block_id },
          version_after: after.revision,
          diff,
          receipt: head.seq > before ? { first_seq: before + 1, last_seq: head.seq, this_hash: head.hash } : null,
        };
      };
      try {
        // best_effort: each op in its own savepoint, so a failed op leaves no partial rows behind.
        out.push(mode === 'best_effort' ? this.db.transaction(runOne)() : runOne());
      } catch (err) {
        out.push({ ...base, status: 'failed', error: errorOf(err) });
        if (mode === 'all_or_nothing') stop = true;
      }
    }
    return out;
  }

  private write(op: ApplyOp, actor_id: string): { doc_id: string; revision: number; block_id?: string } {
    switch (op.op) {
      case 'put': {
        const r = this.docs.putDocument({ slug: op.slug, title: op.title, markdown: op.markdown, actor_id, infer_lineage: false });
        return { doc_id: r.doc_id, revision: r.revision };
      }
      case 'supersede': {
        const r = this.docs.supersedeBlock({ block_id: op.block_id, new_content: op.new_content, reason: op.reason, actor_id, infer_lineage: false });
        return { doc_id: this.docs.getBlock(r.new_block_id)!.doc_id, revision: r.revision, block_id: r.new_block_id };
      }
      case 'tombstone': {
        const r = this.docs.tombstoneBlock({ block_id: op.block_id, reason: op.reason, actor_id });
        return { doc_id: this.docs.getBlock(op.block_id)!.doc_id, revision: r.revision };
      }
    }
  }

  private diffOf(op: ApplyOp): string | null {
    switch (op.op) {
      case 'put': {
        const doc = this.docs.getDocument(op.slug);
        if (!doc) return `new document ${op.slug}: ${snippet(op.markdown, 200)}`;
        const rev = this.docs.getRevision(doc.doc_id, doc.current_revision);
        return rev ? wordDiff(rev.markdown, op.markdown, 2000) : null;
      }
      case 'supersede': {
        const b = this.docs.getBlock(op.block_id);
        return b ? wordDiff(b.content, op.new_content, 2000) : null;
      }
      case 'tombstone': {
        const b = this.docs.getBlock(op.block_id);
        return b ? `remove: ${snippet(b.content, 200)}` : null;
      }
    }
  }

  private targetOf(op: ApplyOp): OpResult['target'] {
    if (op.op === 'put') return { slug: op.slug, doc_id: this.docs.getDocument(op.slug)?.doc_id ?? null, block_id: null };
    const b = this.docs.getBlock(op.block_id);
    const doc = b ? this.docs.getDocumentById(b.doc_id) : null;
    return { slug: doc?.slug ?? null, doc_id: b?.doc_id ?? null, block_id: op.block_id };
  }

  private revisionOf(doc_id: string | null): number | null {
    if (doc_id === null) return 0;
    return this.docs.getDocumentById(doc_id)?.current_revision ?? null;
  }

  /**
   * The state the plan was previewed against, per resource: `doc:<slug>` →
   * revision (0 = absent), `block:<id>` → content hash + live/retired.
   */
  private versionsOf(ops: readonly ApplyOp[]): Record<string, string> {
    const v: Record<string, string> = {};
    for (const op of ops) {
      if (op.op === 'put') {
        v[`doc:${op.slug}`] = String(this.docs.getDocument(op.slug)?.current_revision ?? 0);
        continue;
      }
      const b = this.docs.getBlock(op.block_id);
      v[`block:${op.block_id}`] = b ? `${b.content_hash}:${b.valid_to === null && b.tombstoned_at === null ? 'live' : 'retired'}` : 'absent';
      const doc = b ? this.docs.getDocumentById(b.doc_id) : null;
      if (doc) v[`doc:${doc.slug}`] = String(doc.current_revision);
    }
    return v;
  }

  // ───────────────────────────── confirm tokens ─────────────────────────────

  private signToken(body: TokenBody): string {
    const json = canonicalize(body as unknown as JsonValue);
    const mac = createHmac('sha256', this.opts.secret).update(TOKEN_DOMAIN + json).digest();
    return `${TOKEN_PREFIX}.${b64u(json)}.${b64u(mac)}`;
  }

  private parseToken(token: string): TokenBody {
    const [prefix, body, mac, extra] = token.split('.');
    if (prefix !== TOKEN_PREFIX || !body || !mac || extra !== undefined) throw new ApplyError('confirm_invalid', 'confirm_token is malformed');
    const json = Buffer.from(body, 'base64url').toString('utf8');
    const want = createHmac('sha256', this.opts.secret).update(TOKEN_DOMAIN + json).digest();
    const got = Buffer.from(mac, 'base64url');
    if (got.length !== want.length || !timingSafeEqual(got, want)) throw new ApplyError('confirm_invalid', 'confirm_token signature does not verify (another store, or altered)');
    return JSON.parse(json) as TokenBody;
  }

  /** Everything the token binds, re-checked inside the commit transaction; consumes the nonce. */
  private revalidate(t: TokenBody, now: { plan_hash: string; actor_id: string; key: string | null; ops: ApplyOp[] }): void {
    if (t.v !== 1) throw new ApplyError('confirm_invalid', 'unknown confirm_token version');
    if (Date.parse(t.exp) <= this.now().getTime()) throw new ApplyError('confirm_expired', `confirm_token expired at ${t.exp}`);
    const mismatch = (what: string) => new ApplyError('confirm_mismatch', `confirm_token was issued for a different ${what}`);
    if (t.plan_hash !== now.plan_hash) throw mismatch('plan');
    if (t.actor_id !== now.actor_id) throw mismatch('actor');
    if (t.tenant !== this.opts.tenant) throw mismatch('tenant');
    if (t.sandbox !== this.sandbox || t.server !== 'kronicle-lite') throw mismatch('store');
    if (t.catalog_fingerprint !== this.catalog_fingerprint) throw mismatch('catalog (the server was upgraded since the preview)');
    if (t.policy_version !== this.policy_version) throw mismatch('policy version');
    if (t.idempotency_key !== now.key) throw mismatch('idempotency_key');
    const used = this.db
      .prepare(`UPDATE apply_confirmations SET used_at = ?, outcome = 'committed' WHERE nonce = ? AND plan_hash = ? AND used_at IS NULL`)
      .run(this.now().toISOString(), t.nonce, t.plan_hash);
    if (used.changes !== 1) {
      const row = this.db.prepare(`SELECT used_at FROM apply_confirmations WHERE nonce = ?`).get(t.nonce);
      throw row ? new ApplyError('confirm_used', 'confirm_token was already used (single use)') : new ApplyError('confirm_invalid', 'confirm_token was not issued by this store');
    }
    const current = this.versionsOf(now.ops);
    const stale = Object.keys(t.versions).filter((k) => t.versions[k] !== current[k]);
    if (stale.length > 0 || canonicalize(Object.keys(current).sort()) !== canonicalize(t.resources)) {
      throw new ApplyError('stale_plan', `state changed since the preview: ${stale.join(', ') || 'resource set'}; preview again`);
    }
  }
}

class RolledBack extends Error {
  constructor(readonly results: OpResult[]) {
    super('rolled back');
  }
}

function errorOf(err: unknown): { code: string; message: string } {
  if (err instanceof ApplyError || err instanceof DocumentError) return { code: err.code, message: err.message };
  if (err instanceof SecretDetectedError) return { code: err.code, message: err.message };
  return { code: 'internal', message: err instanceof Error ? err.message : String(err) };
}

/** Canonical plan hash: sha256(JCS({v, mode, ops})). The same plan always hashes the same. */
export function planHash(mode: ApplyMode, ops: readonly ApplyOp[]): string {
  return sha256Hex(canonicalize({ v: 'kl-apply-plan/1', mode, ops } as unknown as JsonValue));
}

function validatePlan(ops: readonly ApplyOp[]): ApplyOp[] {
  if (!Array.isArray(ops) || ops.length === 0) throw new ApplyError('invalid_plan', 'ops must be a non-empty array');
  if (ops.length > MAX_APPLY_OPS) throw new ApplyError('invalid_plan', `at most ${MAX_APPLY_OPS} ops per apply`);
  const ids = new Set<string>();
  for (const op of ops) {
    if (ids.has(op.id)) throw new ApplyError('invalid_plan', `duplicate op id ${op.id}`);
    ids.add(op.id);
  }
  // Drop undefined fields so the plan hash depends only on what was given.
  return JSON.parse(JSON.stringify(ops)) as ApplyOp[];
}
