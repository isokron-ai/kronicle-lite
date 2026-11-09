#!/usr/bin/env node
/**
 * kronicle-lite CLI
 *
 *   kronicle-lite serve [--data-dir DIR] [--actor ID] [--core]   stdio MCP server (dual-era: 2026-07-28 + 2025 initialize)
 *   kronicle-lite serve --http [--port N] [--host H] [--bearer T | --bearer-file F] [--modern-only]   Streamable HTTP
 *   kronicle-lite verify-chain [--data-dir DIR] [--from N] [--to N]
 *   kronicle-lite checkpoint [--data-dir DIR] [--from N] [--to N] [--push [--key K] [--url U]]
 *   kronicle-lite verify [--remote [--offline] [--url U] [--json]]   local by default (= verify-chain)
 *   kronicle-lite anchor status [--url U] [--json]
 *   kronicle-lite anchor keys [list|add PEM-FILE|remove KEY_ID|reset] [--json]
 *   kronicle-lite export [--data-dir DIR] [--out FILE]  JSONL of events (stdout default)
 *   kronicle-lite import [--data-dir DIR] --in FILE [--allow-secrets]   into an empty store
 *   kronicle-lite keys [--data-dir DIR]                 show key id + public key
 *   kronicle-lite put SLUG FILE.md [--title T] [--data-dir DIR] [--bind-git] [--redact-secrets]
 *   kronicle-lite put --from-instructions [PATHS…] [--cwd DIR] [--json] [--stdin-hook]
 *   kronicle-lite watch [PATHS…] [--interval MS] [--debounce MS] [--poll] [--cwd DIR] [--redact-secrets] [--list [--json]]
 *   kronicle-lite doctor [--json] [--no-network] [--full] [--cwd DIR]
 *   kronicle-lite orient [--data-dir DIR] [--actor ID] [--cursor C] [--focus F] [--json] [--all-projects] [--include-format-only] [--pending-actor A]
 *   kronicle-lite supersede BLOCK_ID FILE|- --reason R [--derived-from ID:HASH,…] [--actor A] [--cursor C] [--json]
 *   kronicle-lite get SLUG | --block ID [--actor A] [--json]          read (recorded for --actor)
 *   kronicle-lite pending --actor A [--json] [--cwd DIR] [--all-projects] [--limit N]   unreconciled changes (hooks)
 *   kronicle-lite verify-chain [--full] | rebuild | demo [--dir D] [--keep]
 *   kronicle-lite pulse [--state D | --cursor C] [--cwd DIR] [--mode deny|warn] [--json] [-- CMD…]
 *   kronicle-lite audit put-blob|record|query|export …     audit evidence (src/audit)
 *   kronicle-lite verify-bundle DIR [--key PEM] [--json]  offline evidence-bundle check
 *   kronicle-lite verify-audit PACKAGE [--key PEM] [--json]  offline audit-package check (bundle + anchors + RFC 3161)
 *   kronicle-lite shim install|uninstall|status|ack|exec …   exec-time pulse wrappers (src/shim)
 */

import { createReadStream, createWriteStream, existsSync, readFileSync } from 'node:fs';
import { text as readStreamText } from 'node:stream/consumers';
import { basename, join } from 'node:path';

import type { AnchorCallOptions } from './anchor/anchor.js';
import type { Claim, VerifyAuditOptions } from './audit/verify-audit.js';
import { DB_FILE, defaultDataDir } from './db/open.js';
import { checkWriters, describeWriters } from './db/writers.js';
import { REPEATABLE, validateFlags } from './cli-flags.js';
import { isValidSlug, SLUG_RULE, type DocumentSource } from './docs/documents.js';
import { describeProjection } from './docs/integrity.js';
import type { LineageRef } from './docs/documents.js';
import { bindGit } from './git/binding.js';
import { pendingLines, renderSystemStateMarkdown } from './orient/render.js';
import { checkBlockRow, checkRevisionRow } from './docs/integrity.js';
import { scrubDeep } from './secrets/guard.js';
import { KronicleLite } from './store.js';
import { FOCUSES, type Focus } from './orient/orient.js';
import { entryFor, projectScopeFor, resolveContext } from './instructions/paths.js';
import { describeSync, syncInstructionFile, type SyncResult } from './instructions/sync.js';
import { InstructionWatcher, resolveWatchSet, syncInstructionSet } from './instructions/watch.js';

import { VERSION } from './version.js';

// Heavy modules (MCP SDK, HTTP, anchor client, doctor) load only for the
// commands that use them: `orient` and the hooks stay cheap to start.
const DEFAULT_HTTP_PORT = 7417; // = http.ts DEFAULT_HTTP_PORT (guarded by test)

interface Args {
  cmd: string;
  positional: string[];
  flags: Record<string, string | true>;
  /** Single-value options given more than once. */
  repeated: string[];
}

/** Flags that never take a value, so `put --from-instructions CLAUDE.md` keeps CLAUDE.md positional. */
const BOOLEAN_FLAGS = new Set([
  'http',
  'json',
  'push',
  'remote',
  'offline',
  'from-instructions',
  'stdin-hook',
  'list',
  'poll',
  'once',
  'bind-git',
  'no-network',
  'full',
  'keep',
  'all-projects',
  'include-cosmetic',
  'include-format-only',
  'modern-only',
  'core',
  'redact-secrets',
  'findings',
  'allow-missing',
  'allow-hardlinks',
  'strict',
  'allow-secrets',
  'insecure-http',
  'no-tsa',
  'tsa-at-gentime',
]);

function parseArgs(argv: string[]): Args {
  const [cmd = 'help', ...rest] = argv;
  const positional: string[] = [];
  // null prototype: option names are user input (`--__proto__` stays a key, and is reported as unknown)
  const flags: Record<string, string | true> = Object.create(null) as Record<string, string | true>;
  const repeated: string[] = [];
  const set = (key: string, value: string | true) => {
    if (Object.hasOwn(flags, key)) {
      if (REPEATABLE.has(key) && typeof value === 'string' && typeof flags[key] === 'string') {
        flags[key] = `${flags[key] as string},${value}`;
        return;
      }
      if (!repeated.includes(key)) repeated.push(key);
    }
    flags[key] = value;
  };
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > 2) {
        set(a.slice(2, eq), a.slice(eq + 1));
        continue;
      }
      const key = a.slice(2);
      const next = rest[i + 1];
      if (!BOOLEAN_FLAGS.has(key) && next !== undefined && !next.startsWith('--')) {
        set(key, next);
        i++;
      } else {
        set(key, true);
      }
    } else {
      positional.push(a);
    }
  }
  return { cmd, positional, flags, repeated };
}

function str(v: string | true | undefined): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

function list(v: string | true | undefined): string[] {
  const s = str(v);
  return s === undefined ? [] : s.split(',').map((x) => x.trim()).filter((x) => x.length > 0);
}

function num(v: string | true | undefined): number | undefined {
  const s = str(v);
  if (s === undefined) return undefined;
  const n = Number(s);
  if (!Number.isInteger(n)) throw new Error(`expected an integer, got ${s}`);
  return n;
}

const HELP = `kronicle-lite ${VERSION} — hash-chained document store with signed receipts and an orient protocol

Usage:
  kronicle-lite serve        [--data-dir DIR] [--actor ID] [--core]
                                                                 run the stdio MCP server (--core: 6 tools for small contexts)
  kronicle-lite serve --http [--port N] [--host H] [--bearer T | --bearer-file F] [--allow-origin H]... [--modern-only]
                                                                 Streamable HTTP, 127.0.0.1:${DEFAULT_HTTP_PORT}/mcp, bearer from
                                                                 DIR/http-bearer.token (created 0600); 2026-07-28 and 2025-era
                                                                 clients (stateless), or 2026-07-28 only with --modern-only
  kronicle-lite demo         [--dir D] [--keep]                    the stale-doc + tamper story end to end, in a temp dir
  kronicle-lite verify-chain [--data-dir DIR] [--from N] [--to N] [--full]
                                                                 recompute every hash and link; over the whole chain (or
                                                                 --full) also re-hash every stored document and block
                                                                 against the chain; exit 1 on any mismatch
  kronicle-lite rebuild      [--data-dir DIR]                     re-derive documents and blocks from a verified chain
  kronicle-lite checkpoint   [--data-dir DIR] [--from N] [--to N] sign a Merkle checkpoint
                 [--push [--url U] [--genesis PIN] [--insecure-http]] …and anchor it off-box (hosted service countersigns);
                                                                 license key from KRONICLE_ANCHOR_KEY or config.json
                                                                 (--key K works but warns: argv is visible to other users)
  kronicle-lite verify       [--remote [--offline]] [--url U] [--genesis PIN] [--json]
                                                                 local: = verify-chain; --remote: recompute each anchored
                                                                 range from its countersigned receipt (the service's head
                                                                 key, its list chained to the genesis pin and checked for
                                                                 rollback), exit 1 on "local chain diverges from anchor at
                                                                 [a,b]" or an untrusted receipt (a retired or revoked key's
                                                                 receipt included: check those with their RFC 3161 times)
  kronicle-lite anchor status [--url U] [--json]                 last anchor, its status, events since (no network)
  kronicle-lite anchor keys  [list] [--url U] [--genesis PIN] [--json]
                                                                 the genesis pin in force (compiled, or --genesis /
                                                                 KRONICLE_ANCHOR_GENESIS / anchor_genesis in config.json,
                                                                 <sha256>@<valid_from>) and the kept key list
  kronicle-lite export       [--data-dir DIR] [--out FILE]        JSONL of all events (stdout by default)
  kronicle-lite import       [--data-dir DIR] --in FILE [--allow-secrets]
                                                                 rebuild an EMPTY store from JSONL; refused when an event
                                                                 holds a secret unless --allow-secrets (imported verbatim)
  kronicle-lite keys         [--data-dir DIR]                     print key id + public key PEM
  kronicle-lite put SLUG FILE.md [--title T] [--data-dir DIR] [--json]
                                                                 store a document (one-line summary; --json for every block)
                 [--bind-git]                                    record {repo_root, commit, path, blob_sha}; verify and
                                                                 audit report stale_source when the file changes
                 [--redact-secrets]                              store a redacted copy instead of refusing a detected secret
                                                                 (put, put --from-instructions and watch refuse by default)
                 [--derived-from ID:HASH,…] [--actor A] [--cursor C]
                                                                 lineage: blocks this note was derived from (also inferred from
                                                                 what --actor read since its cursor); stale when one changes
  kronicle-lite supersede BLOCK_ID FILE|- --reason R [--derived-from ID:HASH,…] [--actor A] [--cursor C] [--json]
                                                                 replace one live block (FILE or stdin)
  kronicle-lite get SLUG | --block ID [--actor A] [--json]       print the current document (or one block) and record the read:
                                                                 re-reading the current version resolves a pending change
  kronicle-lite pending --actor A [--json] [--cwd DIR] [--all-projects] [--limit N]
                                                                 changes to what A read (or notes it relied on) that A has not
                                                                 re-read at the current version; the hook-gate contract
                                                                 (docs/PUSH.md); exit 0, gate on pending_count
  kronicle-lite put --from-instructions [PATHS…] [--cwd DIR] [--json] [--redact-secrets]
                                                                 chain CLAUDE.md, AGENTS.md, .claude/rules/**/*.md,
                                                                 .cursor/rules/** and Claude Code auto memory (one shot)
                 [--stdin-hook]                                  as a Claude Code SessionStart / FileChanged hook
  kronicle-lite watch [PATHS…] [--interval MS] [--debounce MS] [--poll] [--cwd DIR] [--redact-secrets]
                                                                 re-put instruction files on change (fs.watch + polling)
                 [--list [--json]]                               print the resolved watch set and exit
  kronicle-lite doctor       [--data-dir DIR] [--json] [--no-network] [--full] [--cwd DIR]
                                                                 health checks (read-only); exit 1 when any check fails
  kronicle-lite orient       [--data-dir DIR] [--actor ID] [--cursor C] [--focus F] [--json] [--cwd DIR] [--all-projects]
                 [--include-format-only] [--pending-actor A]     scoped to the project at --cwd (default: the working
                                                                 directory); "--cursor C --focus retractions --json" is the
                                                                 hook contract (docs/PUSH.md); format-only edits are listed
                                                                 under format_only_edits unless --include-format-only
  kronicle-lite pulse        [--data-dir DIR] [--cwd DIR] [--cursor C | --state D] [--mode deny|warn] [--json] [-- CMD…]
                                                                 the exec-time check: exit 0 allow, 77 refused (unreconciled
                                                                 retractions or integrity failure; reason on stderr), 3 no store
  kronicle-lite audit put-blob FILE [--media-type T] [--redact-secrets]
                                                                 store an artifact by content (outside the chain); prints its ref;
                                                                 refused when it holds a secret unless --redact-secrets
  kronicle-lite audit record --audit-id A [--in FILE|-] [--actor A]
                                                                 append audit events (JSONL of {kind, event_key, payload}),
                                                                 all or nothing; a retried event_key is a no-op
  kronicle-lite audit query  --audit-id A | --fingerprint F [--kind K] [--finding ID] [--findings] [--json]
  kronicle-lite audit export --audit-id A --out DIR             evidence bundle: manifest + events + blobs, signed root
  kronicle-lite verify-bundle DIR [--key PEM-FILE] [--strict] [--allow-missing] [--allow-hardlinks] [--max-bytes N] [--json]
                                                                 verify a bundle offline (no store); exit 1 on any failure
                                                                 (missing artifacts fail unless --allow-missing). Without
                                                                 --key the signer is NOT verified (tamper-evidence only);
                                                                 --strict requires --key. Reads at most 1 GiB (--max-bytes)
  kronicle-lite audit stamp  [--anchor-id ID] --out DIR [--tsa name=url,…] [--json]
                                                                 RFC 3161 tokens over an anchor receipt (latest by default)
                                                                 from Sectigo and DigiCert; run right after checkpoint --push
  kronicle-lite audit package --audit-id A --out DIR [--timestamps DIR] [--tsa-roots DIR] [--anchor-keys FILE] [--genesis SHA256@VALID_FROM] [--json]
                                                                 IsoKron Evidence Pack: bundle, anchors inside its range,
                                                                 their tokens, keys, TSA roots, claims.json (the claims the
                                                                 store supports), SHA256SUMS(.sig), COMPLETION.txt, VERIFY.md;
                                                                 then runs verify-audit on it
  kronicle-lite verify-audit PACK --key-fingerprint SHA256 | --key PEM-FILE [--anchor-keys FILE] [--genesis SHA256@VALID_FROM]
                 [--tsa-roots DIR] [--no-tsa] [--tsa-at-gentime] [--require CLAIM,…] [--skip-claim CLAIM,…] [--max-bytes N] [--allow-hardlinks] [--json]
                                                                 verify an IsoKron Evidence Pack offline. The auditor key is
                                                                 pinned by its SHA-256 from the report or SOW (--key-fingerprint;
                                                                 --key, --anchor-keys, --tsa-roots must not resolve into the
                                                                 pack). SHA256SUMS is
                                                                 verified first; integrity and chain are always checked, then
                                                                 the claims in the authenticated claims.json (receipts,
                                                                 independent_timestamps, harness_frozen_before_runs,
                                                                 run_sequence; every claim when claims.json is missing or
                                                                 unauthenticated), each PASS or FAIL with its evidence; others
                                                                 are "not declared" (--require CLAIM checks one and needs it
                                                                 to pass, declared or not). A declared claim that is not
                                                                 checked (e.g. under --no-tsa) blocks exit 0: NOT VERIFIED;
                                                                 --skip-claim CLAIM opts out of one explicitly ("skipped by
                                                                 user"). Trust: the
                                                                 compiled genesis pin of the anchor service key chain
                                                                 (--genesis or KRONICLE_ANCHOR_GENESIS, <sha256>@<valid_from>,
                                                                 for a self-hosted service) and the pinned TSA CAs (--tsa-roots).
                                                                 A revoked service key's receipt counts only with a verified
                                                                 RFC 3161 time before its compromised_since − 5 min, a retired
                                                                 key's only with one before its valid_to + 5 min (--no-tsa
                                                                 fails both). Remembers the newest anchor key list per genesis
                                                                 pin in the data dir and fails on a rollback or a damaged cache. Establishes integrity, ordering
                                                                 and independent time; the audit's depth is described in its
                                                                 report. Exit 0 every checked claim passed, 1 a check failed,
                                                                 2 usage or an unreadable pack
  kronicle-lite shim install [--dir D] [--commands git,terraform,kubectl,…] [--world "make release,…"] [--mode deny|warn]
  [--git-hook]   | status | ack --operator [--through SEQ] | uninstall   PATH wrappers (+ git pre-push hook) that pulse before
                                                                 world-changing commands (git push, terraform apply, …)
                                                                 for any client; \`kronicle-lite shim help\`

Data dir defaults to $KRONICLE_LITE_DATA_DIR or ~/.kronicle-lite. Instruction slugs carry a project key
(<repo>-<hash8>); $KRONICLE_LITE_PROJECT overrides it.
Anchor config: flags > KRONICLE_ANCHOR_URL / KRONICLE_ANCHOR_KEY > DIR/config.json {anchor_url, license_key}
  > https://anchor.isokron.ai. http:// is refused unless the host is localhost/127.0.0.1/[::1] or
  --insecure-http is given. Exit codes for anchor commands: 0 ok, 1 divergence/conflict/untrusted receipt,
  2 usage or I/O (including "anchor service unreachable").
`;

function anchorOpts(flags: Record<string, string | true>): AnchorCallOptions {
  if (str(flags['key']) !== undefined) {
    process.stderr.write(
      'warning: --key puts the license key on the command line (shell history, `ps` for other users); prefer KRONICLE_ANCHOR_KEY or license_key in <data-dir>/config.json (0600)\n',
    );
  }
  return {
    ...(str(flags['key']) !== undefined ? { licenseKey: str(flags['key'])! } : {}),
    ...(str(flags['url']) !== undefined ? { anchorUrl: str(flags['url'])! } : {}),
    ...(flags['insecure-http'] === true ? { insecureHttp: true } : {}),
    ...(str(flags['genesis']) !== undefined ? { genesis: str(flags['genesis'])! } : {}),
  };
}

function isAnchorIoError(err: unknown): boolean {
  return err instanceof Error && ['AnchorUnreachableError', 'AnchorApiError', 'AnchorConfigError', 'ServiceKeyTrustError', 'AnchorListingError', 'AnchorRateLimitedError'].includes(err.name);
}

/**
 * `anchor keys`: the anchor service key list this data dir trusts (0.10.0): the genesis pin in force,
 * the list kept for the service (anchor-keys.cache.json) and its chain verdict. Nothing to add or
 * pin: trust comes from the service's signed key chain back to its genesis key.
 */
async function anchorKeysCommand(dataDir: string, args: string[], flags: Record<string, string | true>): Promise<number> {
  const trust = await import('./anchor/trust.js');
  const { checkKeyChain, formatGenesisPin, keyListOf } = await import('./anchor/keychain.js');
  const { readKeysCache, KEYS_CACHE_FILE } = await import('./anchor/keys-cache.js');
  const { loadConfig } = await import('./anchor/config.js');
  const { existsSync } = await import('node:fs');
  const { join } = await import('node:path');
  const store = new KronicleLite({ dataDir });
  try {
    const op = args[0] ?? 'list';
    if (op === 'add' || op === 'remove' || op === 'reset') {
      process.stderr.write(
        `error: anchor keys ${op} was removed in 0.10.0: trust comes from the anchor service's signed key chain back to its genesis key (the compiled pin, or --genesis / KRONICLE_ANCHOR_GENESIS / "anchor_genesis" in config.json for a self-hosted service). The kept list (${KEYS_CACHE_FILE}) is the rollback reference and is reset only by deleting that file.\n`,
      );
      return 2;
    }
    if (op !== 'list') {
      process.stderr.write('usage: kronicle-lite anchor keys [list] [--url URL] [--genesis SHA256@VALID_FROM] [--json]\n');
      return 2;
    }
    const url = loadConfig(store.dataDir, str(flags['url']) !== undefined ? { anchor_url: str(flags['url'])! } : {}).anchor_url;
    const { pin, source } = trust.anchorGenesis(store.dataDir, str(flags['genesis']));
    const kept = readKeysCache(store, url, pin);
    const keys = kept ? keyListOf(kept) : null;
    const chain = keys ? checkKeyChain(keys, pin) : null;
    const legacy = store.dataDir !== null && existsSync(join(store.dataDir, trust.LEGACY_PINS_FILE));
    if (flags['json']) {
      process.stdout.write(
        JSON.stringify({ anchor_url: url, genesis: formatGenesisPin(pin), genesis_source: source, kept: keys !== null, chain: chain ? { ok: chain.ok, usable: chain.usable, detail: chain.detail, entries: chain.entries.map((e) => ({ key_id: e.key_id, state: e.state, detail: e.detail })) } : null, legacy_pins_file: legacy }, null, 2) + '\n',
      );
    } else {
      const lines = [`anchor service ${url}`, `genesis pin    ${formatGenesisPin(pin)} (${source === 'compiled' ? 'compiled' : source === 'option' ? '--genesis' : source === 'env' ? 'KRONICLE_ANCHOR_GENESIS' : 'config.json anchor_genesis'})`];
      if (!chain) lines.push(`key list       none kept yet; the next online push or verify --remote fetches, checks and keeps it (${KEYS_CACHE_FILE})`);
      else {
        lines.push(`key list       ${chain.detail}`);
        for (const e of chain.entries) lines.push(`  ${e.key_id} ${e.state}${e.state === 'broken' ? `: ${e.detail}` : ''}`);
      }
      if (legacy) lines.push(`note: ${trust.LEGACY_PINS_FILE} (the 0.9.x pin store) is no longer read; delete it when convenient`);
      process.stdout.write(lines.join('\n') + '\n');
    }
    return 0;
  } catch (err) {
    if (!isAnchorIoError(err)) throw err;
    process.stderr.write(`error: ${(err as Error).message}\n`);
    return 2;
  } finally {
    store.close();
  }
}

async function main(argv: string[]): Promise<number> {
  // pulse / shim parse their own argv (`--` hands the rest over verbatim).
  if (argv[0] === 'pulse' || argv[0] === 'shim') {
    const { runShimCli } = await import('./shim/cli.js');
    return runShimCli(argv[0], argv.slice(1));
  }
  const { cmd, positional, flags, repeated } = parseArgs(argv);
  if (cmd === 'help' || cmd === '--help' || cmd === '-h') {
    process.stdout.write(HELP);
    return 0;
  }
  if (cmd === '--version' || cmd === 'version') {
    process.stdout.write(VERSION + '\n');
    return 0;
  }
  // 0.9.0: an option the command does not take is an error (exit 2), not a silent no-op.
  try {
    validateFlags(cmd, flags, positional, repeated, BOOLEAN_FLAGS);
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n`);
    return 2;
  }
  if (flags['data-dir'] === true) {
    process.stderr.write('error: --data-dir needs a value\n');
    return 2;
  }
  const dataDir = str(flags['data-dir']) ?? defaultDataDir();

  switch (cmd) {
    case 'serve': {
      const { createServerFactory } = await import('./server.js');
      const store = new KronicleLite({ dataDir });
      const factory = createServerFactory(store, {
        version: VERSION,
        // 0.6.0: --core serves the 6-tool profile (orient, audit, recall, verify, put, supersede).
        ...(flags['core'] === true ? { profile: 'core' as const } : {}),
        ...(str(flags['actor']) !== undefined ? { defaultActorId: str(flags['actor'])! } : {}),
        // 0.5.0: orient hides other projects' instruction retractions (the project is the working directory's).
        project: flags['all-projects'] === true ? null : projectScopeFor(instructionCtx(flags)),
        // 0.9.0: over HTTP (remote-capable), apply always needs a confirm_token.
        ...(flags['http'] ? { requireApplyConfirm: true } : {}),
      });
      if (flags['http']) {
        const { loadOrCreateBearer, readBearerFile, serveHttp } = await import('./http.js');
        let bearer: string;
        let bearerNote: string;
        if (str(flags['bearer']) !== undefined) {
          bearer = str(flags['bearer'])!;
          bearerNote = 'bearer from --bearer';
        } else if (str(flags['bearer-file']) !== undefined) {
          bearer = readBearerFile(str(flags['bearer-file'])!);
          bearerNote = `bearer from ${str(flags['bearer-file'])}`;
        } else {
          const b = loadOrCreateBearer(dataDir);
          bearer = b.token;
          bearerNote = `bearer from ${b.file}${b.created ? ' (created, mode 0600)' : ''}${b.tightened !== undefined ? ` (was mode 0${b.tightened.toString(8)}, readable by others; tightened to 0600)` : ''}`;
        }
        const allowedOrigins = list(flags['allow-origin']);
        const allowedHosts = list(flags['allow-host']);
        const handle = await serveHttp({
          factory,
          bearer,
          ...(str(flags['host']) !== undefined ? { host: str(flags['host'])! } : {}),
          ...(num(flags['port']) !== undefined ? { port: num(flags['port'])! } : {}),
          ...(allowedOrigins.length > 0 ? { allowedOrigins } : {}),
          ...(allowedHosts.length > 0 ? { allowedHosts } : {}),
          modernOnly: flags['modern-only'] === true,
          onerror: (err) => process.stderr.write(`http: ${err.message}\n`),
        });
        process.stderr.write(
          `kronicle-lite ${VERSION} serving Streamable HTTP (${flags['modern-only'] === true ? '2026-07-28 only' : '2026-07-28 + 2025-era stateless'}) at ${handle.url}; ${bearerNote}; data dir ${dataDir}; key ${store.identity.signer.key_id}\n`,
        );
        await new Promise<void>((resolve) => {
          const stop = () => {
            handle.close().finally(resolve);
          };
          process.once('SIGINT', stop);
          process.once('SIGTERM', stop);
        });
        store.close();
        return 0;
      }
      process.stderr.write(`kronicle-lite ${VERSION} serving on stdio; data dir ${dataDir}; key ${store.identity.signer.key_id}\n`);
      const { serveStdio } = await import('@modelcontextprotocol/server/stdio');
      // 0.8.1: our own wire (src/stdio.ts): JSON-RPC errors for malformed / oversize input, lifecycle checks, ping.
      const { GuardedStdioTransport } = await import('./stdio.js');
      const log = (line: string) => process.stderr.write(line + '\n');
      const handle = serveStdio(factory, {
        transport: new GuardedStdioTransport(process.stdin, process.stdout, { log }),
        onerror: (err) => process.stderr.write(`stdio: ${err.message}\n`),
      });
      // Keep the process alive until stdin closes, then release the store.
      await new Promise<void>((resolve) => {
        process.stdin.once('end', resolve);
        process.stdin.once('close', resolve);
      });
      await handle.close();
      store.close();
      return 0;
    }
    case 'verify-chain': {
      const store = openForVerify(dataDir);
      if (typeof store === 'number') return store;
      try {
        return printVerifyAll(store, flags);
      } finally {
        store.close();
      }
    }
    case 'verify-bundle': {
      const dir = positional[0];
      if (!dir) throw new Error('usage: kronicle-lite verify-bundle DIR [--key PEM-FILE] [--strict] [--allow-missing] [--allow-hardlinks] [--max-bytes N] [--json]');
      const { verifyBundle, readBundleFile } = await import('./audit/verify-bundle.js');
      const key = str(flags['key']);
      if (!key) {
        // Without a pinned key the bundle is checked under the key it names: anyone can make one that passes.
        if (flags['strict'] === true) {
          process.stderr.write('kronicle-lite verify-bundle --strict: refusing without --key: the signer of a bundle can only be verified against the store public key you pin (kronicle-lite keys on the store prints it)\n');
          return 1;
        }
        process.stderr.write('warning: signer NOT verified (no --key): this checks that the bundle is intact and self-consistent under the key it names (tamper-evidence), not who made it; pass --key with the store public key for authenticity\n');
      }
      if (flags['max-bytes'] === true) throw new Error('--max-bytes needs a value: a positive number of bytes');
      const maxBytes = num(flags['max-bytes']);
      if (maxBytes !== undefined && maxBytes <= 0) throw new Error('--max-bytes must be a positive integer');
      // A PEM public key is a few hundred bytes; a device, FIFO or huge file is refused, not read.
      const r = verifyBundle(dir, {
        ...(key ? { public_key_pem: readBundleFile(key, 64 * 1024, { followLinks: true }).toString('utf8') } : {}),
        allow_missing: flags['allow-missing'] === true,
        allow_hardlinks: flags['allow-hardlinks'] === true,
        ...(maxBytes !== undefined ? { max_bytes: maxBytes } : {}),
      });
      if (flags['json'] === true) process.stdout.write(JSON.stringify(r, null, 2) + '\n');
      else {
        for (const c of r.checks) process.stdout.write(`${c.ok ? 'ok  ' : 'FAIL'} ${c.check}${c.problem ? `: ${c.problem}` : ''}\n`);
        process.stdout.write(
          `${r.ok ? 'bundle verifies' : 'bundle does NOT verify'}: audit ${r.audit_id ?? '?'}, ${r.counts.events} event(s), ${r.counts.stubs} stub(s), ${r.counts.blobs} blob(s), ${r.counts.redacted} redacted, ${r.counts.missing} missing${r.allow_missing ? ' (allowed by --allow-missing)' : ''}; key ${key ? 'pinned' : 'NOT pinned (pass --key)'}; root ${r.root ?? '?'}; manifest sha256 ${r.manifest_sha256 ?? '?'}\n`,
        );
      }
      return r.ok ? 0 : 1;
    }
    case 'verify-audit':
      return verifyAuditCommand(positional, flags, dataDir);
    case 'audit': {
      const { runAuditCli } = await import('./audit/cli.js');
      return runAuditCli(positional, flags, dataDir);
    }
    case 'rebuild': {
      const store = new KronicleLite({ dataDir });
      try {
        const r = store.rebuild();
        process.stdout.write(
          `rebuilt the projection from ${r.events} event(s): before: ${describeProjection(r.before)}; after: ${describeProjection(r.after)}\n`,
        );
        return r.after.ok ? 0 : 1;
      } finally {
        store.close();
      }
    }
    case 'demo': {
      const { runDemo } = await import('./demo.js');
      return runDemo({
        out: process.stdout,
        ...(str(flags['dir']) !== undefined ? { dir: str(flags['dir'])! } : {}),
        keep: flags['keep'] === true,
      });
    }
    case 'checkpoint': {
      const store = new KronicleLite({ dataDir });
      const cp = store.chain.checkpoint(num(flags['from']) ?? 1, num(flags['to']));
      if (flags['push'] !== true) {
        process.stdout.write(JSON.stringify(cp, null, 2) + '\n');
        store.close();
        return 0;
      }
      // The checkpoint is stored locally before anything leaves the box; a
      // failed push never undoes it.
      const { tryPushCheckpoint } = await import('./anchor/anchor.js');
      const anchor = await tryPushCheckpoint(store, { ...anchorOpts(flags), checkpointId: cp.checkpoint_id });
      process.stdout.write(JSON.stringify({ checkpoint: cp, anchor }, null, 2) + '\n');
      store.close();
      if (anchor.error) {
        process.stderr.write(`checkpoint ${cp.checkpoint_id} stored locally; push failed: ${anchor.message}\n`);
        return 2;
      }
      if (anchor.conflict) {
        process.stderr.write(`${anchor.message}\n`);
        return 1;
      }
      process.stderr.write(
        `${anchor.duplicate ? 'already anchored' : 'anchored'} [${cp.from_seq}, ${cp.to_seq}] root ${cp.root.slice(0, 16)}… at ${anchor.received_at}; verify: ${anchor.verify_url}\n`,
      );
      for (const n of anchor.key_notes) process.stderr.write(`note: ${n}\n`);
      return 0;
    }
    case 'verify': {
      const store = flags['remote'] === true ? new KronicleLite({ dataDir }) : openForVerify(dataDir);
      if (typeof store === 'number') return store;
      try {
        // Local verification; identical to verify-chain.
        if (flags['remote'] !== true) return printVerifyAll(store, flags);
        const { verifyRemote } = await import('./anchor/anchor.js');
        const r = await verifyRemote(store, { ...anchorOpts(flags), offline: flags['offline'] === true });
        if (flags['json']) {
          process.stdout.write(JSON.stringify(r, null, 2) + '\n');
        } else {
          const lines = [r.summary];
          for (const c of r.checks) {
            lines.push(
              `  [${c.from_seq}, ${c.to_seq}] ${c.result === 'match' ? 'ok' : c.result.toUpperCase()} anchored ${c.anchored_root.slice(0, 16)}… ${c.received_at} countersig ${c.countersignature}${c.conflict_remote ? ' REMOTE-CONFLICT' : ''} (${c.source})`,
            );
          }
          for (const d of r.divergences) lines.push(d);
          for (const p of r.problems) lines.push(`problem: ${p}`);
          for (const n of r.notes) lines.push(`note: ${n}`);
          process.stdout.write(lines.join('\n') + '\n');
        }
        return r.ok ? 0 : 1;
      } catch (err) {
        if (!isAnchorIoError(err)) throw err;
        process.stderr.write(`error: ${(err as Error).message}\n`);
        if (flags['json']) process.stdout.write(JSON.stringify({ error: (err as Error).message }) + '\n');
        return 2;
      } finally {
        store.close();
      }
    }
    case 'anchor': {
      const sub = positional[0];
      if (sub === 'keys') return anchorKeysCommand(dataDir, positional.slice(1), flags);
      if (sub !== 'status') {
        process.stderr.write(`usage: kronicle-lite anchor status [--url U] [--json] | anchor keys [list|add PEM-FILE|remove KEY_ID|reset]\n`);
        return 2;
      }
      const store = new KronicleLite({ dataDir });
      try {
        const { anchorStatus } = await import('./anchor/anchor.js');
        const r = anchorStatus(store, anchorOpts(flags));
        if (flags['json']) {
          process.stdout.write(JSON.stringify(r, null, 2) + '\n');
        } else {
          const lines = [
            `chain ${r.chain_id.slice(0, 16)}… key ${r.key_id} head ${r.head_seq} anchors ${r.anchors} via ${r.anchor_url}${r.license_key_configured ? '' : ' (no license key configured)'}`,
          ];
          if (r.last) {
            lines.push(
              `last anchor [${r.last.range[0]}, ${r.last.range[1]}] ${r.last.status} at ${r.last.received_at}; ${r.last.events_since} event(s) since; ${r.last.verify_url}`,
            );
          } else {
            lines.push('never anchored: run `kronicle-lite checkpoint --push`');
          }
          process.stdout.write(lines.join('\n') + '\n');
        }
        return 0;
      } catch (err) {
        if (!isAnchorIoError(err)) throw err;
        process.stderr.write(`error: ${(err as Error).message}\n`);
        return 2;
      } finally {
        store.close();
      }
    }
    case 'export': {
      const store = new KronicleLite({ dataDir });
      const out = str(flags['out']);
      if (out) {
        const stream = createWriteStream(out);
        const r = store.exportEvents(stream);
        await new Promise<void>((resolve, reject) => {
          stream.on('error', reject);
          stream.end(() => resolve());
        });
        process.stderr.write(`exported ${r.events} events (head seq ${r.head.seq}) to ${out}\n`);
      } else {
        store.exportEvents(process.stdout);
      }
      store.close();
      return 0;
    }
    case 'import': {
      const file = str(flags['in']);
      if (!file) throw new Error('import requires --in FILE');
      if (!existsSync(file)) throw new Error(`cannot read ${file}: ENOENT`);
      const store = new KronicleLite({ dataDir });
      const r = await store.importEvents(createReadStream(file), { allow_secrets: flags['allow-secrets'] === true });
      if (flags['allow-secrets'] === true) process.stderr.write('warning: --allow-secrets: any secret in the export is now chained verbatim (the read-time scrub masks it in recall)\n');
      process.stdout.write(`imported ${r.events} events; head seq ${r.head.seq} hash ${r.head.hash}\n`);
      store.close();
      return 0;
    }
    case 'keys': {
      const store = new KronicleLite({ dataDir });
      process.stdout.write(`key_id: ${store.identity.signer.key_id}\n${store.identity.signer.public_key_pem}`);
      store.close();
      return 0;
    }
    case 'put': {
      if (flags['from-instructions'] === true) return putFromInstructions(dataDir, positional, flags);
      const [slug, file] = positional;
      if (!slug || !file) throw new Error('put requires SLUG and FILE.md');
      // Read (and fail) before the store exists: a failed put must not create the data dir or a key.
      let markdown: string;
      try {
        markdown = readFileSync(file, 'utf8');
      } catch (err) {
        throw new Error(`cannot read ${file}: ${(err as NodeJS.ErrnoException).code ?? (err as Error).message}`);
      }
      if (!isValidSlug(slug)) throw new Error(`invalid slug "${slug}": ${SLUG_RULE}`);
      const store = new KronicleLite({ dataDir });
      const warnings: string[] = [];
      let source: DocumentSource | undefined;
      if (flags['bind-git'] === true) {
        const b = bindGit(file);
        source = b.binding ? { kind: 'file', path: b.binding.path, git: b.binding } : { kind: 'file', path: file.split(/[\\/]+/).join('/') };
        if (b.warning) warnings.push(b.warning);
      }
      const derived = lineageFlag(flags);
      const actor = str(flags['actor']) ?? 'cli';
      // The same stale-write advisory as MCP put_document (computed before the write): printed when it fires.
      const existing = store.docs.getDocument(slug);
      const advisory = store.orient.staleWriteAdvisory(actor, str(flags['cursor']), new Date(), existing ? { doc_id: existing.doc_id, slug: existing.slug } : null);
      const r = store.docs.putDocument({
        slug,
        title: str(flags['title']) ?? basename(file).replace(/\.md$/i, ''),
        markdown,
        actor_id: actor,
        ...(derived !== undefined ? { derived_from: derived } : {}),
        ...(str(flags['cursor']) !== undefined ? { cursor: str(flags['cursor'])! } : {}),
        ...(source !== undefined ? { source } : {}),
        ...(flags['redact-secrets'] === true ? { secrets: 'redact' as const } : {}),
        // Unreleased (next): the document belongs to the project at --cwd (recall/orient scope).
        ...(flags['all-projects'] === true ? {} : { project: primaryProject(instructionCtx(flags)) }),
      });
      for (const w of warnings) process.stderr.write(`warning: ${w}\n`);
      if (str(flags['cursor']) !== undefined && advisory.advisory && advisory.line) process.stderr.write(`advisory: ${advisory.line}\n`);
      if (r.redactions) process.stderr.write(`warning: redacted ${r.redactions.length} secret(s) before chaining: ${r.redactions.map((f) => `${f.detector} (line ${f.line})`).join(', ')}\n`);
      if (flags['json'] === true) {
        process.stdout.write(JSON.stringify({ ...r, stale_write_advisory: advisory, ...(source !== undefined ? { source } : {}), ...(warnings.length > 0 ? { warnings } : {}) }, null, 2) + '\n');
      } else {
        const n = (st: string) => r.blocks.filter((b) => b.status === st && (st !== 'created' || !b.supersedes)).length;
        const superseded = r.blocks.filter((b) => b.supersedes).length;
        process.stdout.write(
          `${r.slug} rev ${r.revision}: ${n('created')} new, ${superseded} changed, ${n('tombstoned')} removed, ${n('unchanged')} unchanged block(s); head seq ${r.head.seq}${source?.git ? ` (bound to ${source.git.path} @ ${source.git.blob_sha.slice(0, 12)})` : ''}\n`,
        );
      }
      store.close();
      return 0;
    }
    case 'orient': {
      const store = new KronicleLite({ dataDir });
      const focusRaw = str(flags['focus']);
      if (focusRaw !== undefined && !(FOCUSES as readonly string[]).includes(focusRaw)) {
        throw new Error(`focus must be one of ${FOCUSES.join(', ')}`);
      }
      const state = store.orient.getSystemState({
        actor_id: str(flags['actor']) ?? 'cli',
        since_cursor: str(flags['cursor']),
        focus: focusRaw as Focus | undefined,
        ...(num(flags['budget']) !== undefined ? { budget_tokens: num(flags['budget'])! } : {}),
        project: flags['all-projects'] === true ? null : projectScopeFor(instructionCtx(flags)),
        include_format_only: flags['include-format-only'] === true || flags['include-cosmetic'] === true,
        ...(str(flags['pending-actor']) !== undefined ? { pending_actor: str(flags['pending-actor'])! } : {}),
      });
      // --json is the push-hook contract (docs/PUSH.md): one JSON object, the SystemState.
      process.stdout.write(flags['json'] ? JSON.stringify(state, null, 2) + '\n' : renderSystemStateMarkdown(state) + '\n');
      store.close();
      return 0;
    }
    case 'supersede': {
      const [block_id, file] = positional;
      if (!block_id || !file) throw new Error('supersede requires BLOCK_ID and FILE (or - for stdin)');
      const reason = str(flags['reason']);
      if (!reason) throw new Error('supersede requires --reason');
      let content: string;
      try {
        content = file === '-' ? await readStreamText(process.stdin) : readFileSync(file, 'utf8');
      } catch (err) {
        throw new Error(`cannot read ${file}: ${(err as NodeJS.ErrnoException).code ?? (err as Error).message}`);
      }
      const store = new KronicleLite({ dataDir });
      try {
        const derived = lineageFlag(flags);
        const r = store.docs.supersedeBlock({
          block_id,
          new_content: content,
          reason,
          actor_id: str(flags['actor']) ?? 'cli',
          ...(flags['redact-secrets'] === true ? { secrets: 'redact' as const } : {}),
          ...(derived !== undefined ? { derived_from: derived } : {}),
          ...(str(flags['cursor']) !== undefined ? { cursor: str(flags['cursor'])! } : {}),
        });
        process.stdout.write(flags['json'] ? JSON.stringify(r, null, 2) + '\n' : `${r.doc_slug} rev ${r.revision}: ${r.old_block_id} → ${r.new_block_id}; head seq ${r.head.seq}\n`);
        return 0;
      } finally {
        store.close();
      }
    }
    case 'get': {
      const store = new KronicleLite({ dataDir });
      try {
        const actor = str(flags['actor']) ?? 'cli';
        const blockId = str(flags['block']);
        if (blockId !== undefined) {
          const b = store.docs.getBlock(blockId);
          if (!b) throw new Error(`no block ${blockId}`);
          if (checkBlockRow(store.chain, b) !== null) throw new Error(`integrity failure in block ${blockId}: the stored text does not match the chain; run kronicle-lite verify-chain`);
          const status = b.tombstoned_at ? 'tombstoned' : b.valid_to ? 'superseded' : 'live';
          store.lineage.recordBlockReads(actor, [b], 'recall');
          const text = scrubDeep(b.content).value;
          process.stdout.write(
            flags['json']
              ? JSON.stringify({ block_id: b.block_id, doc_slug: store.docs.getDocumentById(b.doc_id)?.slug ?? null, status, superseded_by: b.superseded_by, content_hash: b.content_hash, content: text }, null, 2) + '\n'
              : `${text}\n${status === 'live' ? '' : `[${status}${b.superseded_by ? ` by ${b.superseded_by}` : ''}]\n`}`,
          );
          return 0;
        }
        const [slug] = positional;
        if (!slug) throw new Error('get requires SLUG or --block ID');
        const doc = store.docs.getDocument(slug);
        if (!doc) throw new Error(`no document ${slug}`);
        const rev = store.docs.getRevision(doc.doc_id, doc.current_revision);
        if (!rev) throw new Error(`no revision ${doc.current_revision} of ${slug}`);
        if (checkRevisionRow(store.chain, rev) !== null) throw new Error(`integrity failure in ${slug}@${rev.revision}: the stored text does not match the chain; run kronicle-lite verify-chain`);
        store.lineage.recordDocumentRead(actor, doc.doc_id, 'document');
        const markdown = scrubDeep(rev.markdown).value;
        process.stdout.write(flags['json'] ? JSON.stringify({ slug, revision: rev.revision, markdown_hash: rev.content_hash, markdown }, null, 2) + '\n' : markdown + (markdown.endsWith('\n') ? '' : '\n'));
        return 0;
      } finally {
        store.close();
      }
    }
    case 'pending': {
      const actor = str(flags['actor']);
      if (!actor) throw new Error('pending requires --actor A (whose reads to check)');
      const store = new KronicleLite({ dataDir });
      try {
        const scope = flags['all-projects'] === true ? null : projectScopeFor(instructionCtx(flags));
        const p = store.lineage.pending(actor, { project_keys: scope?.keys ?? null, limit: num(flags['limit']) ?? 50 });
        const head = store.chain.head();
        const out = { format: 'kronicle-lite/1' as const, actor_id: actor, head, pending_count: p.count, pending_hidden: p.hidden, pending: scrubDeep(p.items).value };
        if (flags['json']) process.stdout.write(JSON.stringify(out, null, 2) + '\n');
        else if (p.count === 0) process.stdout.write(`kronicle-lite: nothing pending for ${actor} (head seq ${head.seq})\n`);
        else process.stdout.write(`kronicle-lite: ${p.count} pending for ${actor} — re-read the current version before acting:\n${pendingLines({ pending: out.pending, pending_count: p.count }, 50).join('\n')}\n`);
        return 0;
      } finally {
        store.close();
      }
    }
    case 'watch':
      return watchCommand(dataDir, positional, flags);
    case 'doctor': {
      const { runDoctor, renderDoctor } = await import('./doctor.js');
      const report = await runDoctor({
        dataDir,
        ...(str(flags['cwd']) !== undefined ? { cwd: str(flags['cwd'])! } : {}),
        network: flags['no-network'] !== true,
        full: flags['full'] === true,
      });
      process.stdout.write((flags['json'] ? JSON.stringify(report, null, 2) : renderDoctor(report)) + '\n');
      // 0.8.1 (F12): 2 = the store could not be read at all (I/O), 1 = a check failed.
      if (report.io_error !== undefined) {
        process.stderr.write(`error: cannot read the kronicle-lite store in ${dataDir}: ${report.io_error}\n`);
        return 2;
      }
      return report.ok ? 0 : 1;
    }
    default:
      process.stderr.write(`unknown command: ${cmd}\n\n${HELP}`);
      return 2;
  }
}

/** `verify-audit PACKAGE`: exit 0 verified, 1 a check failed, 2 usage or an unreadable package / trust input. */
async function verifyAuditCommand(positional: string[], flags: Record<string, string | true>, dataDir: string): Promise<number> {
  const usage =
    'usage: kronicle-lite verify-audit PACK --key-fingerprint SHA256 | --key PEM-FILE [--anchor-keys FILE] [--genesis SHA256@VALID_FROM] [--tsa-roots DIR] [--no-tsa] [--tsa-at-gentime] [--require CLAIM,…] [--skip-claim CLAIM,…] [--max-bytes N] [--allow-hardlinks] [--json]';
  const dir = positional[0];
  if (!dir) {
    process.stderr.write(`${usage}\n`);
    return 2;
  }
  const { verifyAudit, renderVerifyAudit, VerifyAuditUsageError, CLAIMS, genesisFromCli, readTrustInput, refuseInsidePack } = await import('./audit/verify-audit.js');
  const { pemFileNames, pemsFromText } = await import('./audit/package.js');
  let opts: VerifyAuditOptions;
  try {
    const key = str(flags['key']);
    const fingerprint = str(flags['key-fingerprint']);
    const genesis = genesisFromCli(str(flags['genesis']));
    const keys = str(flags['anchor-keys']);
    // Trust inputs from inside the pack pin nothing: whoever made the pack wrote them. Each is opened
    // once, checked by the identity of the open file and read from it (T8: no check-then-reopen race).
    const keyPem = key ? readTrustInput(dir, key, '--key', 64 * 1024).toString('utf8') : undefined;
    const keysDoc = keys ? readTrustInput(dir, keys, '--anchor-keys', 1024 * 1024).toString('utf8') : undefined;
    const roots = str(flags['tsa-roots']);
    let tsaRoots: { name: string; pem: string }[] | undefined;
    if (roots) {
      refuseInsidePack(dir, roots, '--tsa-roots');
      const { join } = await import('node:path');
      tsaRoots = [];
      for (const f of pemFileNames(roots)) tsaRoots.push(...pemsFromText(f, readTrustInput(dir, join(roots, f), '--tsa-roots', 1024 * 1024).toString('utf8')));
      if (tsaRoots.length === 0) throw new Error(`${roots} holds no PEM certificates (*.pem, *.crt)`);
    }
    const maxBytes = num(flags['max-bytes']);
    if (maxBytes !== undefined && maxBytes <= 0) throw new Error('--max-bytes must be a positive integer');
    const require = list(flags['require']);
    for (const c of require) if (!(CLAIMS as readonly string[]).includes(c)) throw new Error(`--require: unknown claim ${c} (one of ${CLAIMS.join(', ')})`);
    const skip = list(flags['skip-claim']);
    if (flags['no-tsa'] === true && (roots !== undefined || flags['tsa-at-gentime'] === true)) throw new Error('--no-tsa cannot be combined with --tsa-roots or --tsa-at-gentime');
    opts = {
      ...(keyPem !== undefined ? { key_pem: keyPem } : {}),
      ...(fingerprint ? { key_fingerprint: fingerprint } : {}),
      ...genesis,
      seen_dir: dataDir,
      ...(keysDoc !== undefined ? { anchor_keys: JSON.parse(keysDoc) as unknown } : {}),
      ...(tsaRoots ? { tsa_roots: tsaRoots } : {}),
      ...(flags['no-tsa'] === true ? { no_tsa: true } : {}),
      ...(flags['tsa-at-gentime'] === true ? { tsa_at: 'gentime' as const } : {}),
      ...(maxBytes !== undefined ? { max_bytes: maxBytes } : {}),
      ...(flags['allow-hardlinks'] === true ? { allow_hardlinks: true } : {}),
      ...(require.length ? { require: require as Claim[] } : {}),
      ...(skip.length ? { skip_claims: skip as Claim[] } : {}),
    };
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n${usage}\n`);
    return 2;
  }
  let r;
  try {
    r = verifyAudit(dir, opts);
  } catch (err) {
    if (!(err instanceof VerifyAuditUsageError)) throw err;
    process.stderr.write(`error: ${err.message}\n`);
    return 2;
  }
  process.stdout.write(flags['json'] === true ? JSON.stringify(r, null, 2) + '\n' : renderVerifyAudit(r));
  return r.ok ? 0 : 1;
}

/**
 * 0.8.1 (F12): verify-chain / verify open the store read-only (a read-only or
 * full data dir still verifies). Exit 2 with an I/O message when it cannot be
 * read at all; 1 stays reserved for a real divergence. A missing store is
 * created as before (an empty chain verifies).
 */
function openForVerify(dataDir: string): KronicleLite | number {
  try {
    return existsSync(join(dataDir, DB_FILE)) ? new KronicleLite({ dataDir, readOnly: true }) : new KronicleLite({ dataDir });
  } catch (err) {
    process.stderr.write(`error: cannot read the kronicle-lite store in ${dataDir} (I/O, not a chain divergence): ${err instanceof Error ? err.message : String(err)}\n`);
    return 2;
  }
}

/** verify-chain / verify (local): chain + projection; JSON on stdout, one summary line on stderr when it fails. */
function printVerifyAll(store: KronicleLite, flags: Record<string, string | true>): number {
  const r = store.verifyAll(num(flags['from']) ?? 1, num(flags['to']), flags['full'] === true ? { projection: true } : {});
  process.stdout.write(JSON.stringify(r, null, 2) + '\n');
  const lines: string[] = [];
  if (!r.ok) {
    const m = r.first_mismatch;
    if (m) lines.push(`chain: ${m.kind} at seq ${m.seq}`);
    if (r.projection && !r.projection.ok) lines.push(`projection: ${describeProjection(r.projection)}; run kronicle-lite rebuild once the chain verifies`);
  }
  // 0.8.1 (C2-01): the projection check does not cover project keys; an older writer's damage shows here.
  let writersBad = false;
  if (r.projection) {
    const w = describeWriters(checkWriters(store.db));
    if (w.status !== 'ok') lines.push(`writers: ${w.detail}`);
    writersBad = w.status === 'fail';
  }
  if (lines.length > 0) process.stderr.write(lines.join('\n') + '\n');
  return r.ok && !writersBad ? 0 : 1;
}

/** `--derived-from ID:HASH[,ID:HASH…]` (unreleased); undefined when absent, [] for an explicit empty value. */
function lineageFlag(flags: Record<string, string | true>): LineageRef[] | undefined {
  const v = flags['derived-from'];
  if (v === undefined) return undefined;
  if (v === true) return [];
  return list(v).map((pair) => {
    const [block_id, content_hash, ...rest] = pair.split(':');
    if (!block_id || !content_hash || rest.length > 0) throw new Error(`--derived-from expects BLOCK_ID:CONTENT_HASH pairs, got "${pair}"`);
    return { block_id, content_hash };
  });
}

/** The primary project (instruction key + root) of a working directory. */
function primaryProject(ctx: { cwd?: string }): { key: string; root: string } {
  const scope = projectScopeFor(ctx);
  return { key: scope.keys[0]!, root: scope.root };
}

function instructionCtx(flags: Record<string, string | true>, cwdOverride?: string) {
  const cwd = cwdOverride ?? str(flags['cwd']);
  return cwd !== undefined ? { cwd } : {};
}

/**
 * `put --from-instructions`: one-shot sync of the default instruction set (or
 * the given paths). With `--stdin-hook` it is a Claude Code hook: it reads
 * the hook input JSON from stdin, syncs the changed file (FileChanged) or the
 * whole set (SessionStart, answering with `watchPaths` so Claude Code keeps
 * watching them), never fails the hook, and stays quiet unless something changed.
 */
async function putFromInstructions(dataDir: string, positional: string[], flags: Record<string, string | true>): Promise<number> {
  const actor = str(flags['actor']) ?? 'instructions';
  const secrets = flags['redact-secrets'] === true ? { secrets: 'redact' as const } : {};
  if (flags['stdin-hook'] === true) {
    let input: { hook_event_name?: string; file_path?: string; cwd?: string } = {};
    try {
      input = JSON.parse((await readStreamText(process.stdin)) || '{}') as typeof input;
    } catch {
      input = {};
    }
    const ctx = instructionCtx(flags, typeof input.cwd === 'string' ? input.cwd : undefined);
    const store = new KronicleLite({ dataDir });
    try {
      if (input.hook_event_name === 'FileChanged' && typeof input.file_path === 'string') {
        const rc = resolveContext(ctx);
        const r = syncInstructionFile(store, entryFor(input.file_path, rc), { actor_id: actor, ...secrets, context: rc });
        if (r.action !== 'unchanged' && r.action !== 'missing') {
          process.stdout.write(JSON.stringify({ systemMessage: `kronicle-lite: ${describeSync(r)}` }) + '\n');
        }
        return 0;
      }
      const results = syncInstructionSet(store, { ...ctx, actor_id: actor, ...secrets });
      const { entries, patterns } = resolveWatchSet(ctx);
      const watchPaths = [...new Set([...entries.map((e) => e.path), ...patterns.filter((p) => p.type === 'file').map((p) => p.path)])];
      const changed = results.filter((r) => r.action !== 'unchanged' && r.action !== 'missing');
      process.stdout.write(
        JSON.stringify({
          hookSpecificOutput: { hookEventName: 'SessionStart', watchPaths },
          ...(changed.length > 0 ? { systemMessage: `kronicle-lite: ${changed.map(describeSync).join('; ')}` } : {}),
        }) + '\n',
      );
      return 0;
    } catch (err) {
      process.stderr.write(`kronicle-lite hook: ${err instanceof Error ? err.message : String(err)}\n`);
      return 0;
    } finally {
      store.close();
    }
  }
  const store = new KronicleLite({ dataDir });
  try {
    const results: SyncResult[] = syncInstructionSet(store, { ...instructionCtx(flags), paths: positional, actor_id: actor, ...secrets });
    if (flags['json']) process.stdout.write(JSON.stringify({ results, head: store.chain.head() }, null, 2) + '\n');
    else if (results.length === 0) process.stdout.write('no instruction files found\n');
    else for (const r of results) process.stdout.write(describeSync(r) + '\n');
    return results.some((r) => r.action === 'error') ? 1 : 0;
  } finally {
    store.close();
  }
}

async function watchCommand(dataDir: string, positional: string[], flags: Record<string, string | true>): Promise<number> {
  const ctx = instructionCtx(flags);
  if (flags['list'] === true) {
    const { rc, entries, patterns } = resolveWatchSet({ ...ctx, paths: positional });
    if (flags['json']) {
      process.stdout.write(
        JSON.stringify(
          {
            project_root: rc.projectRoot,
            memory_dir: rc.memoryDir,
            memory_rule: rc.memoryRule,
            patterns,
            files: entries.map((e) => ({ path: e.path, slug: e.slug, kind: e.kind, source_path: e.recordPath })),
          },
          null,
          2,
        ) + '\n',
      );
    } else {
      process.stdout.write(`project root: ${rc.projectRoot}\nauto memory:  ${rc.memoryDir} (${rc.memoryRule})\n`);
      for (const e of entries) process.stdout.write(`${e.slug}\t${e.path}\n`);
      if (entries.length === 0) process.stdout.write('(no instruction files present yet; watching for them)\n');
    }
    return 0;
  }
  const store = new KronicleLite({ dataDir });
  const log = (line: string) => process.stderr.write(`${new Date().toISOString()} ${line}\n`);
  const watcher = new InstructionWatcher(store, {
    ...ctx,
    paths: positional,
    actor_id: str(flags['actor']) ?? 'watch',
    ...(flags['redact-secrets'] === true ? { secrets: 'redact' as const } : {}),
    ...(num(flags['interval']) !== undefined ? { intervalMs: num(flags['interval'])! } : {}),
    ...(num(flags['debounce']) !== undefined ? { debounceMs: num(flags['debounce'])! } : {}),
    poll: flags['poll'] === true,
    onEvent: (e) => {
      if (e.type === 'synced') log(describeSync(e.result));
      else if (e.type === 'warning') log(`warning: ${e.message}`);
      else log(`watching ${e.files.length} file(s) in ${e.dirs} dir(s) (${e.mode}); data dir ${dataDir}; Ctrl-C to stop`);
    },
  });
  watcher.start();
  if (flags['once'] === true) {
    watcher.close();
    store.close();
    return 0;
  }
  await new Promise<void>((resolve) => {
    process.once('SIGINT', resolve);
    process.once('SIGTERM', resolve);
  });
  watcher.close();
  store.close();
  return 0;
}

// 0.8.1 (F14): a reader that goes away (`export | head`) is not an error: stop quietly, exit 0.
// `serve` keeps the SDK's own stdout handling (the client closing stdin ends it).
if (process.argv[2] !== 'serve') {
  process.stdout.on('error', (err: NodeJS.ErrnoException) => {
    if (err.code === 'EPIPE') process.exit(0);
    throw err;
  });
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    process.stderr.write(`error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  },
);
