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
/** Most live (unused, unexpired) confirmations one actor may hold; a new preview evicts the oldest. */
export const MAX_CONFIRMATIONS_PER_ACTOR = 100;
/**
 * #15: most confirmations the table holds, across all actors. Actor ids are
 * self-asserted, so distinct actors grew the table without bound until TTL; a
 * new preview evicts the oldest rows first (DoS only: an evicted token answers
 * confirm_invalid, it never authorizes anything).
 */
export const MAX_CONFIRMATIONS = 10_000;
/** Most expired confirmations one write prunes (bounded work per call). */
export const PRUNE_BATCH = 1000;
const TOKEN_PREFIX = 'klc2';
const TOKEN_DOMAIN = 'kronicle-lite/apply-confirm/2\n';

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
  /** The project a `put` records (as put_document does with the server's project). Bound into the confirmation. */
  project?: { key: string; root: string } | null | undefined;
  /** Refuse any commit without a confirm_token (remote-capable servers: HTTP). */
  require_confirm?: boolean | undefined;
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
      | 'confirm_required'
      | 'idempotency_conflict'
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

/** What a confirmation binds; kept server-side (apply_confirmations.binding_json), keyed by nonce. */
interface Binding {
  v: 2;
  plan_hash: string;
  project: { key: string; root: string } | null;
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

    if (input.dry_run) return this.preview(mode, ops, plan_hash, key, input);

    const nonce = input.confirm_token !== undefined ? this.parseToken(input.confirm_token) : null;
    const project = input.project ?? null;
    // Burn the token after a failed commit only when its owner made the attempt (a wrong-actor try is not the owner's loss).
    let burnOnFailure = false;
    try {
      const run = this.db.transaction((): ApplyResult => {
        if (key !== null) {
          const prior = this.db.prepare(`SELECT request_hash, actor_id, result_json FROM apply_results WHERE idempotency_key = ?`).get(key) as
            | { request_hash: string; actor_id: string; result_json: string }
            | undefined;
          if (prior) {
            if (prior.request_hash !== request_hash || prior.actor_id !== input.actor_id) {
              throw new ApplyError('idempotency_key_reused', 'idempotency_key was already used for a different plan or by another actor');
            }
            // A replay discloses the committed result: the actor must still be allowed every op.
            for (const op of ops) {
              const denied = this.policy(input.actor_id, op, { slug: this.targetOf(op).slug });
              if (denied !== null) throw new ApplyError('forbidden', denied);
            }
            return { ...(JSON.parse(prior.result_json) as ApplyResult), replayed: true };
          }
        }
        if (nonce !== null) this.revalidate(nonce, { plan_hash, actor_id: input.actor_id, key, ops, project }, () => (burnOnFailure = true));
        else if (input.require_confirm === true) throw new ApplyError('confirm_required', 'this server requires a confirm_token: dry_run first, then commit with it');
        else if (this.pendingConfirmation(plan_hash, input.actor_id)) {
          throw new ApplyError('confirm_required', 'this plan was previewed (dry_run): commit it with the confirm_token it returned');
        }
        const results = this.execute(mode, ops, input.actor_id, project);
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
            ...(nonce !== null ? { confirm_nonce: nonce } : {}),
            ...(project !== null ? { project_key: project.key } : {}),
            policy_version: this.policy_version,
            ops: results.map((r) => ({ id: r.id, op: r.op, status: r.status, ...(r.target.slug ? { slug: r.target.slug } : {}), ...(r.target.block_id ? { block_id: r.target.block_id } : {}), version_after: r.version_after, receipt: r.receipt })) as unknown as JsonValue,
          },
          ...(key !== null ? { idempotency_key: applyChainKey(key) } : {}),
        });
        // why: the chain returns an EXISTING event when the key is taken; that is someone else's event, never this commit's.
        if (ev.replayed) throw new ApplyError('idempotency_conflict', `the chain already holds an event under this apply's key (seq ${ev.event.seq}, ${ev.event.event_type}); nothing committed`);
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
          this.db
            .prepare(`INSERT INTO apply_results (idempotency_key, request_hash, actor_id, result_json, seq) VALUES (?, ?, ?, ?, ?)`)
            .run(key, request_hash, input.actor_id, JSON.stringify(out), ev.event.seq);
        }
        return out;
      });
      return run.immediate();
    } catch (err) {
      // Single use: a token that took part in a failed commit is burned too (the transaction rolled back its consumption).
      if (nonce !== null && burnOnFailure) {
        this.db.prepare(`UPDATE apply_confirmations SET used_at = COALESCE(used_at, ?), outcome = COALESCE(outcome, 'failed') WHERE nonce = ?`).run(this.now().toISOString(), nonce);
      }
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
        results = this.execute(mode, ops, input.actor_id, input.project ?? null);
        throw new RolledBack(results);
      })();
    } catch (err) {
      if (!(err instanceof RolledBack)) throw err;
    }
    const anyFailed = results.some((r) => r.status === 'failed');
    const blocked = anyFailed && mode === 'all_or_nothing';
    const ttlIn = input.ttl_seconds;
    const ttl = typeof ttlIn === 'number' && Number.isFinite(ttlIn) ? Math.min(Math.max(Math.trunc(ttlIn), 1), CONFIRM_TTL_MAX_S) : CONFIRM_TTL_DEFAULT_S;
    let token: string | null = null;
    let exp: string | null = null;
    if (!blocked) {
      const issued = this.now();
      exp = new Date(issued.getTime() + ttl * 1000).toISOString();
      const body: Binding = {
        v: 2,
        plan_hash,
        project: input.project ?? null,
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
      token = this.tokenFor(body.nonce);
      this.pruneConfirmations(input.actor_id, issued);
      this.db
        .prepare(`INSERT INTO apply_confirmations (nonce, plan_hash, actor_id, issued_at, expires_at, binding_json) VALUES (?, ?, ?, ?, ?, ?)`)
        .run(body.nonce, plan_hash, input.actor_id, issued.toISOString(), exp, canonicalize(body as unknown as JsonValue));
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
  private execute(mode: ApplyMode, ops: ApplyOp[], actor_id: string, project: { key: string; root: string } | null): OpResult[] {
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
        const after = this.write(op, actor_id, project);
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

  private write(op: ApplyOp, actor_id: string, project: { key: string; root: string } | null): { doc_id: string; revision: number; block_id?: string } {
    switch (op.op) {
      case 'put': {
        const r = this.docs.putDocument({ slug: op.slug, title: op.title, markdown: op.markdown, actor_id, infer_lineage: false, ...(project !== null ? { project } : {}) });
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

  /** The token is only a handle: `klc2.<nonce>.<HMAC(secret, domain + nonce)>`. Everything it binds stays server-side. */
  private tokenFor(nonce: string): string {
    const mac = createHmac('sha256', this.opts.secret).update(TOKEN_DOMAIN + nonce).digest();
    return `${TOKEN_PREFIX}.${nonce}.${b64u(mac)}`;
  }

  /**
   * Bounded housekeeping on every preview: drop up to PRUNE_BATCH expired
   * confirmations (used or not; past expiry they can only fail), then keep
   * this actor under MAX_CONFIRMATIONS_PER_ACTOR live ones by evicting the
   * oldest (its token then answers confirm_invalid), then the whole table under
   * MAX_CONFIRMATIONS, oldest first.
   */
  private pruneConfirmations(actor_id: string, now: Date): void {
    const t = now.toISOString();
    this.db.prepare(`DELETE FROM apply_confirmations WHERE nonce IN (SELECT nonce FROM apply_confirmations WHERE expires_at <= ? LIMIT ?)`).run(t, PRUNE_BATCH);
    this.db
      .prepare(
        `DELETE FROM apply_confirmations WHERE nonce IN (
           SELECT nonce FROM apply_confirmations WHERE actor_id = ? AND used_at IS NULL AND expires_at > ?
            ORDER BY issued_at DESC, rowid DESC LIMIT -1 OFFSET ?)`,
      )
      .run(actor_id, t, MAX_CONFIRMATIONS_PER_ACTOR - 1);
    // Global cap, oldest (lowest rowid) first, leaving room for the row about to be inserted.
    this.db
      .prepare(`DELETE FROM apply_confirmations WHERE rowid <= (SELECT rowid FROM apply_confirmations ORDER BY rowid DESC LIMIT 1 OFFSET ?)`)
      .run(MAX_CONFIRMATIONS - 1);
  }

  /** The nonce of a token this store issued, or confirm_invalid. */
  private parseToken(token: string): string {
    const [prefix, nonce, mac, extra] = token.split('.');
    // Strict: exactly the canonical unpadded base64url of a 32-byte MAC (Buffer.from would ignore a trailing "=").
    if (prefix !== TOKEN_PREFIX || !nonce || !/^[0-9a-f]{32}$/.test(nonce) || !mac || !/^[A-Za-z0-9_-]{43}$/.test(mac) || extra !== undefined) {
      throw new ApplyError('confirm_invalid', 'confirm_token is malformed');
    }
    // #15: compare the canonical base64url STRING. 32 bytes in 43 characters leave 2 unused bits in
    // the last one, so decoding first accepted 4 spellings of every MAC.
    const want = Buffer.from(b64u(createHmac('sha256', this.opts.secret).update(TOKEN_DOMAIN + nonce).digest()));
    const got = Buffer.from(mac);
    if (got.length !== want.length || !timingSafeEqual(got, want)) throw new ApplyError('confirm_invalid', 'confirm_token does not verify (another store, or altered)');
    return nonce;
  }

  /** An unused, unexpired preview of this exact plan by this actor exists: its commit must present the token. */
  private pendingConfirmation(plan_hash: string, actor_id: string): boolean {
    return (
      this.db
        .prepare(`SELECT 1 FROM apply_confirmations WHERE plan_hash = ? AND actor_id = ? AND used_at IS NULL AND expires_at > ? LIMIT 1`)
        .get(plan_hash, actor_id, this.now().toISOString()) !== undefined
    );
  }

  /**
   * Everything the confirmation binds, re-checked inside the commit
   * transaction; consumes the nonce. `isOwner` fires once the caller is
   * known to be the token's actor (only the owner's failed attempt burns it).
   */
  private revalidate(
    nonce: string,
    now: { plan_hash: string; actor_id: string; key: string | null; ops: ApplyOp[]; project: { key: string; root: string } | null },
    isOwner: () => void,
  ): void {
    const row = this.db.prepare(`SELECT actor_id, used_at, expires_at, binding_json FROM apply_confirmations WHERE nonce = ?`).get(nonce) as
      | { actor_id: string; used_at: string | null; expires_at: string; binding_json: string | null }
      | undefined;
    if (!row || row.binding_json === null) throw new ApplyError('confirm_invalid', 'confirm_token was not issued by this store');
    const mismatch = (what: string) => new ApplyError('confirm_mismatch', `confirm_token was issued for a different ${what}`);
    if (row.actor_id !== now.actor_id) throw mismatch('actor');
    isOwner();
    if (row.used_at !== null) throw new ApplyError('confirm_used', 'confirm_token was already used (single use)');
    const t = JSON.parse(row.binding_json) as Binding;
    if (t.v !== 2 || t.nonce !== nonce) throw new ApplyError('confirm_invalid', 'unknown confirmation record');
    if (Date.parse(row.expires_at) <= this.now().getTime()) throw new ApplyError('confirm_expired', `confirm_token expired at ${row.expires_at}`);
    if (t.plan_hash !== now.plan_hash) throw mismatch('plan');
    if (t.tenant !== this.opts.tenant) throw mismatch('tenant');
    if (t.sandbox !== this.sandbox || t.server !== 'kronicle-lite') throw mismatch('store');
    if (t.catalog_fingerprint !== this.catalog_fingerprint) throw mismatch('catalog (the server was upgraded since the preview)');
    if (t.policy_version !== this.policy_version) throw mismatch('policy version');
    if (t.idempotency_key !== now.key) throw mismatch('idempotency_key');
    if (canonicalize((t.project ?? null) as JsonValue) !== canonicalize((now.project ?? null) as JsonValue)) throw mismatch('project');
    const used = this.db.prepare(`UPDATE apply_confirmations SET used_at = ?, outcome = 'committed' WHERE nonce = ? AND used_at IS NULL`).run(this.now().toISOString(), nonce);
    if (used.changes !== 1) throw new ApplyError('confirm_used', 'confirm_token was already used (single use)');
    const current = this.versionsOf(now.ops);
    const stale = Object.keys(t.versions).filter((k) => t.versions[k] !== current[k]);
    if (stale.length > 0 || canonicalize(Object.keys(current).sort()) !== canonicalize(t.resources)) {
      throw new ApplyError('stale_plan', `state changed since the preview: ${stale.join(', ') || 'resource set'}; preview again`);
    }
  }
}

/** The chain idempotency key of an apply commit: the `apply:` namespace is reserved (documents refuse it). */
export function applyChainKey(idempotency_key: string): string {
  return `apply:${sha256Hex(idempotency_key)}`;
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
