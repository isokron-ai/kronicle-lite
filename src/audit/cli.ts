/**
 * `kronicle-lite audit …` (0.9.0): put-blob, record, query, export.
 * Loaded only for these commands.
 */

import { readFileSync } from 'node:fs';
import { text as readStreamText } from 'node:stream/consumers';

import { KronicleLite } from '../store.js';
import { exportBundle } from './bundle.js';
import { AUDIT_KINDS, type AuditEventInput, type AuditKind } from './schemas.js';

type Flags = Record<string, string | true>;
const str = (v: string | true | undefined): string | undefined => (typeof v === 'string' ? v : undefined);

const USAGE =
  'usage: kronicle-lite audit put-blob FILE [--media-type T] | record --audit-id A [--in FILE|-] | query --audit-id A|--fingerprint F [--kind K] [--finding ID] [--findings] [--json] | export --audit-id A --out DIR | stamp [--anchor-id ID] --out DIR [--tsa name=url,…] [--json] | package --audit-id A --out DIR [--timestamps DIR] [--tsa-roots DIR] [--anchor-keys FILE] [--genesis SHA256@VALID_FROM] [--json]\n';

export async function runAuditCli(positional: string[], flags: Flags, dataDir: string): Promise<number> {
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
        const anchorId = str(flags['anchor-id']);
        const r = await stampAnchor(store, { out_dir: out, ...(anchorId ? { anchor_id: anchorId } : {}), ...(tsas ? { tsas } : {}) });
        if (flags['json'] === true) process.stdout.write(JSON.stringify(r, null, 2) + '\n');
        else {
          process.stdout.write(`anchor         ${r.anchor_id}\nreceipt sha256 ${r.receipt_sha256}\n`);
          for (const x of r.results) {
            process.stdout.write(`  ${x.ok ? 'PASS' : 'FAIL'}  RFC 3161 ${x.tsa.padEnd(10)} ${x.ok ? `${x.gen_time}  ${x.file}${x.existing ? ' (already present)' : ''}` : x.problem}\n`);
          }
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
        const r = await buildAuditPackage(store, {
          audit_id,
          out,
          ...(ts ? { timestamps_dir: ts } : {}),
          ...(roots ? { tsa_roots: readPemDir(roots) } : {}),
          ...(keysFile ? { anchor_keys: JSON.parse(readFileSync(keysFile, 'utf8')) as unknown } : {}),
          ...(genesis !== undefined ? { genesis } : {}),
        });
        process.stdout.write(flags['json'] === true ? JSON.stringify(r, null, 2) + '\n' : renderPackage(r));
        return r.check.ok ? 0 : 1;
      }
    }
    process.stderr.write(USAGE);
    return 2;
  } finally {
    store.close();
  }
}
