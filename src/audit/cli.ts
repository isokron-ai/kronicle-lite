/**
 * `kronicle-lite audit …` (0.9.0): put-blob, record, query, export; stamp and package (0.10.0).
 * Loaded only for these commands.
 */

import { readFileSync } from 'node:fs';
import { text as readStreamText } from 'node:stream/consumers';

import type { AnchorCallOptions } from '../anchor/anchor.js';
import { AnchorConfigError } from '../anchor/config.js';
import { chainIdFromPublicKeyPem } from '../crypto/keys.js';
import { KronicleLite } from '../store.js';
import { exportBundle } from './bundle.js';
import { AUDIT_KINDS, type AuditEventInput, type AuditKind } from './schemas.js';

type Flags = Record<string, string | true>;
const str = (v: string | true | undefined): string | undefined => (typeof v === 'string' ? v : undefined);

const USAGE =
  'usage: kronicle-lite audit put-blob FILE [--media-type T] | record --audit-id A [--in FILE|-] | query --audit-id A|--fingerprint F [--kind K] [--finding ID] [--findings] [--json] | export --audit-id A --out DIR | stamp [--anchor-id ID] --out DIR [--tsa name=url,…] [--allow-pending] [--anchor-key-file PATH] [--url U] [--genesis PIN] [--json] | package --audit-id A --out DIR [--timestamps DIR] [--tsa-roots DIR] [--anchor-keys FILE] [--genesis SHA256@VALID_FROM] [--allowed-signers FILE] [--tsa name=url,…] [--no-stamp-sums] [--json]\n';

/**
 * 0.11.1: the anchor `audit stamp` stamps. With --anchor-id, that one. Otherwise the latest anchor of
 * this chain, provided it commits the latest audit event (the freeze, the last run or the report just
 * recorded); when it does not, a checkpoint over [1, head] is pushed first with the anchor key
 * (--anchor-key-file, KRONICLE_ANCHOR_KEY_CMD, KRONICLE_ANCHOR_KEY, config.json). A missing key or
 * an unreachable service is an error: nothing is stamped and no pending marker is written.
 */
async function anchorToStamp(store: KronicleLite, anchor: AnchorCallOptions): Promise<{ code: number; anchor_id?: string }> {
  const chainId = chainIdFromPublicKeyPem(store.identity.signer.public_key_pem);
  const latest = store.chain
    .listAnchors()
    .filter((a) => a.chain_id === chainId)
    .sort((a, b) => a.to_seq - b.to_seq || a.received_at.localeCompare(b.received_at))
    .pop();
  const head = store.chain.head().seq;
  const target = store.audit.lastSeq() || head;
  if (target === 0) return { code: 0 }; // an empty chain: stampAnchor says there is nothing to stamp
  if (latest && latest.to_seq >= target) return { code: 0, anchor_id: latest.anchor_id };
  const what = latest ? `the latest anchor ends at seq ${latest.to_seq}` : 'this chain has no anchor yet';
  const nothing = 'Nothing was anchored or stamped, and no pending marker was written.';
  const { tryPushCheckpoint, withLicenseKey } = await import('../anchor/anchor.js');
  let opts: AnchorCallOptions;
  try {
    opts = withLicenseKey(store, anchor);
  } catch (err) {
    if (!(err instanceof AnchorConfigError)) throw err;
    process.stderr.write(`audit stamp: seq ${target} is not anchored (${what}), and anchoring it needs the anchor key: ${err.message}\n${nothing}\n`);
    return { code: 2 };
  }
  const cp = store.chain.checkpoint(1, head);
  const r = await tryPushCheckpoint(store, { ...opts, checkpointId: cp.checkpoint_id });
  if (r.error) {
    process.stderr.write(`audit stamp: seq ${target} is not anchored (${what}); checkpoint --push of [1, ${head}] failed: ${r.message}\n${nothing} The local checkpoint ${cp.checkpoint_id} is kept; fix the cause and run audit stamp again.\n`);
    return { code: 2 };
  }
  if (r.conflict || !r.anchor_id) {
    process.stderr.write(`audit stamp: ${r.message ?? 'the push returned no anchor'}\n${nothing}\n`);
    return { code: 1 };
  }
  process.stderr.write(`${r.duplicate ? 'already anchored' : 'anchored'} [1, ${head}] at ${r.received_at} (${r.anchor_id}); stamping it\n`);
  return { code: 0, anchor_id: r.anchor_id };
}

export async function runAuditCli(positional: string[], flags: Flags, dataDir: string, anchor: AnchorCallOptions = {}): Promise<number> {
  const [op, ...rest] = positional;
  const store = new KronicleLite({ dataDir });
  try {
    switch (op) {
      case 'put-blob': {
        const file = rest[0];
        if (!file) break;
        const ref = store.audit.putBlob(readFileSync(file), str(flags['media-type']), { secrets: flags['redact-secrets'] === true ? 'redact' : 'refuse' });
        process.stdout.write(JSON.stringify(ref) + '\n');
        return 0;
      }
      case 'record': {
        const audit_id = str(flags['audit-id']);
        if (!audit_id) break;
        const src = str(flags['in']) ?? '-';
        const text = src === '-' ? await readStreamText(process.stdin) : readFileSync(src, 'utf8');
        const events = text
          .split('\n')
          .filter((l) => l.trim().length > 0)
          .map((l, i) => {
            try {
              return JSON.parse(l) as AuditEventInput;
            } catch {
              throw new Error(`line ${i + 1} is not JSON`);
            }
          });
        const r = store.audit.record(audit_id, events, str(flags['actor']) ?? process.env['KRONICLE_LITE_ACTOR'] ?? 'local-agent');
        const fresh = r.filter((e) => !e.replayed).length;
        if (flags['json'] === true) process.stdout.write(JSON.stringify({ audit_id, recorded: r }) + '\n');
        else process.stdout.write(`recorded ${fresh} event(s), ${r.length - fresh} already present; head seq ${store.chain.head().seq}\n`);
        return 0;
      }
      case 'query': {
        const kind = str(flags['kind']);
        if (kind !== undefined && !(AUDIT_KINDS as readonly string[]).includes(kind)) throw new Error(`--kind must be one of ${AUDIT_KINDS.join(', ')}`);
        const audit_id = str(flags['audit-id']);
        if (flags['findings'] === true) {
          if (!audit_id) break;
          const f = store.audit.findings(audit_id);
          if (flags['json'] === true) process.stdout.write(JSON.stringify(f) + '\n');
          else for (const x of f) process.stdout.write(`${x.finding_id}\t${x.status}\t${x.severity ?? '-'}\t${x.title ?? ''}\n`);
          return 0;
        }
        const ev = store.audit.query({ audit_id, fingerprint: str(flags['fingerprint']), kind: kind as AuditKind | undefined, finding_id: str(flags['finding']), limit: 5000 });
        if (flags['json'] === true) process.stdout.write(JSON.stringify(ev) + '\n');
        else for (const e of ev) process.stdout.write(`${e.seq}\t${e.kind}\t${e.event_key}\t${e.event_id}\n`);
        return 0;
      }
      case 'export': {
        const audit_id = str(flags['audit-id']);
        const out = str(flags['out']);
        if (!audit_id || !out) break;
        const r = exportBundle({ chain: store.chain, audit: store.audit, signer: store.identity.signer, audit_id, dir: out });
        const m = r.manifest;
        process.stdout.write(
          `exported ${m.events.length} event(s) (${m.stubs.length} stub(s)), ${m.blobs.length} blob(s), ${m.redacted.length} redacted, ${m.missing.length} missing to ${out}\nroot ${m.root.root} (seq ${m.range.from_seq}..${m.range.to_seq}, ${m.root.key_id})\nmanifest sha256 ${r.manifest_sha256}\n`,
        );
        return m.missing.length === 0 ? 0 : 1;
      }
      case 'stamp': {
        const out = str(flags['out']);
        if (!out) break;
        const { stampAnchor, parseTsaList } = await import('./package.js');
        const tsas = str(flags['tsa']) !== undefined ? parseTsaList(str(flags['tsa'])!) : undefined;
        const allowPending = flags['allow-pending'] === true;
        let anchorId = str(flags['anchor-id']);
        if (!anchorId) {
          const a = await anchorToStamp(store, anchor);
          if (a.code !== 0) return a.code;
          anchorId = a.anchor_id;
        }
        const r = await stampAnchor(store, { out_dir: out, ...(anchorId ? { anchor_id: anchorId } : {}), ...(tsas ? { tsas } : {}), allow_pending: allowPending });
        const failed = r.results.filter((x) => !x.ok && !x.existing).map((x) => x.tsa);
        if (flags['json'] === true) process.stdout.write(JSON.stringify(r, null, 2) + '\n');
        else {
          process.stdout.write(`anchor         ${r.anchor_id}\nreceipt sha256 ${r.receipt_sha256}\n`);
          for (const x of r.results) {
            process.stdout.write(`  ${x.ok ? 'PASS' : 'FAIL'}  RFC 3161 ${x.tsa.padEnd(10)} ${x.ok ? `${x.gen_time}  ${x.file}${x.existing ? ' (already present)' : ''}` : x.problem}\n`);
          }
          for (const f of r.pending) process.stdout.write(`  pending ${f} (stamp again; the audit profile fails while it is there)\n`);
          if (r.nonce && (failed.length === 0 || allowPending)) process.stdout.write(`freeze nonce   ${r.nonce}  (sha256 of the receipt digest and its tokens: record it as run_completed.nonce after a freeze)\n`);
        }
        if (failed.length > 0 && !allowPending) {
          process.stderr.write(
            `audit stamp: RFC 3161 from ${failed.join(', ')} failed; no pending marker was written and no freeze nonce is final until every TSA has answered. Run audit stamp again (--allow-pending records the failure as a .pending marker instead, which verify-audit's audit profile rejects).\n`,
          );
        }
        // Network or TSA trouble is I/O (2); a token file that does not match is a conflict (1).
        if (r.results.every((x) => x.ok)) return 0;
        return r.results.some((x) => !x.ok && x.existing) ? 1 : 2;
      }
      case 'package': {
        const audit_id = str(flags['audit-id']);
        const out = str(flags['out']);
        if (!audit_id || !out) break;
        const { buildAuditPackage, readPemDir, renderPackage } = await import('./package.js');
        const ts = str(flags['timestamps']);
        const roots = str(flags['tsa-roots']);
        const keysFile = str(flags['anchor-keys']);
        const { genesisFromCli } = await import('./verify-audit.js');
        const genesis = genesisFromCli(str(flags['genesis']));
        const signers = str(flags['allowed-signers']);
        const sumsTsas = str(flags['tsa']) !== undefined ? (await import('./package.js')).parseTsaList(str(flags['tsa'])!) : undefined;
        const r = await buildAuditPackage(store, {
          audit_id,
          out,
          ...(ts ? { timestamps_dir: ts } : {}),
          ...(roots ? { tsa_roots: readPemDir(roots) } : {}),
          ...(keysFile ? { anchor_keys: JSON.parse(readFileSync(keysFile, 'utf8')) as unknown } : {}),
          ...(genesis.genesis !== undefined ? { genesis: genesis.genesis } : {}),
          ...(signers ? { allowed_signers: readFileSync(signers, 'utf8') } : {}),
          ...(str(flags['freeze-pending']) ? { freeze_pending_dir: str(flags['freeze-pending'])! } : {}),
          // The audit profile needs SHA256SUMS stamped by two TSAs (Sectigo and DigiCert unless --tsa).
          ...(flags['no-stamp-sums'] === true ? {} : { stamp_sums: sumsTsas ? { tsas: sumsTsas } : {} }),
        });
        process.stdout.write(flags['json'] === true ? JSON.stringify(r, null, 2) + '\n' : renderPackage(r));
        return r.check.verdict === 'verified' || r.check.verdict === 'verified_late_anchor' ? 0 : r.check.verdict === 'partial' ? 2 : 1;
      }
    }
    process.stderr.write(USAGE);
    return 2;
  } finally {
    store.close();
  }
}
