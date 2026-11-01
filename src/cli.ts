#!/usr/bin/env node
/**
 * kronicle-lite CLI
 *
 *   kronicle-lite serve [--data-dir DIR] [--actor ID]   stdio MCP server (dual-era: 2026-07-28 + 2025 initialize)
 *   kronicle-lite serve --http [--port N] [--host H] [--bearer T | --bearer-file F]   Streamable HTTP (2026-07-28 only)
 *   kronicle-lite verify-chain [--data-dir DIR] [--from N] [--to N]
 *   kronicle-lite checkpoint [--data-dir DIR] [--from N] [--to N] [--push [--key K] [--url U]]
 *   kronicle-lite verify [--remote [--offline] [--url U] [--json]]   local by default (= verify-chain)
 *   kronicle-lite anchor status [--url U] [--json]
 *   kronicle-lite export [--data-dir DIR] [--out FILE]  JSONL of events (stdout default)
 *   kronicle-lite import [--data-dir DIR] --in FILE     into an empty store
 *   kronicle-lite keys [--data-dir DIR]                 show key id + public key
 *   kronicle-lite put SLUG FILE.md [--title T] [--data-dir DIR] [--bind-git]
 *   kronicle-lite put --from-instructions [PATHS…] [--cwd DIR] [--json] [--stdin-hook]
 *   kronicle-lite watch [PATHS…] [--interval MS] [--debounce MS] [--poll] [--cwd DIR] [--list [--json]]
 *   kronicle-lite orient [--data-dir DIR] [--actor ID] [--cursor C] [--focus F]
 */

import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { createReadStream, createWriteStream, readFileSync } from 'node:fs';
import { text as readStreamText } from 'node:stream/consumers';
import { basename } from 'node:path';

import { anchorStatus, tryPushCheckpoint, verifyRemote, type AnchorCallOptions } from './anchor/anchor.js';
import { AnchorApiError, AnchorUnreachableError } from './anchor/client.js';
import { AnchorConfigError } from './anchor/config.js';
import { defaultDataDir } from './db/open.js';
import type { DocumentSource } from './docs/documents.js';
import { bindGit } from './git/binding.js';
import { DEFAULT_HTTP_PORT, loadOrCreateBearer, readBearerFile, serveHttp } from './http.js';
import { createServerFactory, renderSystemStateMarkdown } from './server.js';
import { KronicleLite } from './store.js';
import { FOCUSES, type Focus } from './orient/orient.js';
import { entryFor, resolveContext } from './instructions/paths.js';
import { describeSync, syncInstructionFile, type SyncResult } from './instructions/sync.js';
import { InstructionWatcher, resolveWatchSet, syncInstructionSet } from './instructions/watch.js';

import { VERSION } from './version.js';

interface Args {
  cmd: string;
  positional: string[];
  flags: Record<string, string | true>;
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
]);

function parseArgs(argv: string[]): Args {
  const [cmd = 'help', ...rest] = argv;
  const positional: string[] = [];
  const flags: Record<string, string | true> = {};
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > 2) {
        flags[a.slice(2, eq)] = a.slice(eq + 1);
        continue;
      }
      const key = a.slice(2);
      const next = rest[i + 1];
      if (!BOOLEAN_FLAGS.has(key) && next !== undefined && !next.startsWith('--')) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(a);
    }
  }
  return { cmd, positional, flags };
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
  kronicle-lite serve        [--data-dir DIR] [--actor ID]        run the stdio MCP server
  kronicle-lite serve --http [--port N] [--host H] [--bearer T | --bearer-file F] [--allow-origin H]...
                                                                 Streamable HTTP (2026-07-28), 127.0.0.1:${DEFAULT_HTTP_PORT}/mcp,
                                                                 bearer from DIR/http-bearer.token (created 0600)
  kronicle-lite verify-chain [--data-dir DIR] [--from N] [--to N] recompute every hash; exit 1 on mismatch
  kronicle-lite checkpoint   [--data-dir DIR] [--from N] [--to N] sign a Merkle checkpoint
                 [--push [--key K] [--url U]]                    …and anchor it off-box (hosted service countersigns)
  kronicle-lite verify       [--remote [--offline]] [--url U] [--json]
                                                                 local: = verify-chain; --remote: recompute each anchored
                                                                 range, exit 1 on "local chain diverges from anchor at [a,b]"
  kronicle-lite anchor status [--url U] [--json]                 last anchor, its status, events since (no network)
  kronicle-lite export       [--data-dir DIR] [--out FILE]        JSONL of all events (stdout by default)
  kronicle-lite import       [--data-dir DIR] --in FILE           rebuild an EMPTY store from JSONL
  kronicle-lite keys         [--data-dir DIR]                     print key id + public key PEM
  kronicle-lite put SLUG FILE.md [--title T] [--data-dir DIR]     store a document
                 [--bind-git]                                    record {repo_root, commit, path, blob_sha}; verify and
                                                                 audit report stale_source when the file changes
  kronicle-lite put --from-instructions [PATHS…] [--cwd DIR] [--json]
                                                                 chain CLAUDE.md, AGENTS.md, .claude/rules/**/*.md,
                                                                 .cursor/rules/** and Claude Code auto memory (one shot)
                 [--stdin-hook]                                  as a Claude Code SessionStart / FileChanged hook
  kronicle-lite watch [PATHS…] [--interval MS] [--debounce MS] [--poll] [--cwd DIR]
                                                                 re-put instruction files on change (fs.watch + polling)
                 [--list [--json]]                               print the resolved watch set and exit
  kronicle-lite orient       [--data-dir DIR] [--actor ID] [--cursor C] [--focus F] [--json]

Data dir defaults to $KRONICLE_LITE_DATA_DIR or ~/.kronicle-lite.
Anchor config: flags > KRONICLE_ANCHOR_URL / KRONICLE_ANCHOR_KEY > DIR/config.json {anchor_url, license_key}
  > https://anchor.isokron.ai. Exit codes for anchor commands: 0 ok, 1 divergence/conflict, 2 usage or I/O
  (including "anchor service unreachable").
`;

function anchorOpts(flags: Record<string, string | true>): AnchorCallOptions {
  return {
    ...(str(flags['key']) !== undefined ? { licenseKey: str(flags['key'])! } : {}),
    ...(str(flags['url']) !== undefined ? { anchorUrl: str(flags['url'])! } : {}),
  };
}

function isAnchorIoError(err: unknown): boolean {
  return err instanceof AnchorUnreachableError || err instanceof AnchorApiError || err instanceof AnchorConfigError;
}

async function main(argv: string[]): Promise<number> {
  const { cmd, positional, flags } = parseArgs(argv);
  if (cmd === 'help' || cmd === '--help' || cmd === '-h') {
    process.stdout.write(HELP);
    return 0;
  }
  if (cmd === '--version' || cmd === 'version') {
    process.stdout.write(VERSION + '\n');
    return 0;
  }
  const dataDir = str(flags['data-dir']) ?? defaultDataDir();

  switch (cmd) {
    case 'serve': {
      const store = new KronicleLite({ dataDir });
      const factory = createServerFactory(store, {
        version: VERSION,
        ...(str(flags['actor']) !== undefined ? { defaultActorId: str(flags['actor'])! } : {}),
      });
      if (flags['http']) {
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
          bearerNote = `bearer from ${b.file}${b.created ? ' (created, mode 0600)' : ''}`;
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
          onerror: (err) => process.stderr.write(`http: ${err.message}\n`),
        });
        process.stderr.write(
          `kronicle-lite ${VERSION} serving Streamable HTTP (2026-07-28) at ${handle.url}; ${bearerNote}; data dir ${dataDir}; key ${store.identity.signer.key_id}\n`,
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
      const handle = serveStdio(factory, { onerror: (err) => process.stderr.write(`stdio: ${err.message}\n`) });
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
      const store = new KronicleLite({ dataDir });
      const r = store.chain.verify(num(flags['from']) ?? 1, num(flags['to']));
      process.stdout.write(JSON.stringify(r, null, 2) + '\n');
      store.close();
      return r.ok ? 0 : 1;
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
      return 0;
    }
    case 'verify': {
      const store = new KronicleLite({ dataDir });
      try {
        if (flags['remote'] !== true) {
          // Local verification; identical to verify-chain.
          const r = store.chain.verify(num(flags['from']) ?? 1, num(flags['to']));
          process.stdout.write(JSON.stringify(r, null, 2) + '\n');
          return r.ok ? 0 : 1;
        }
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
      if (sub !== 'status') {
        process.stderr.write(`usage: kronicle-lite anchor status [--url U] [--json]\n`);
        return 2;
      }
      const store = new KronicleLite({ dataDir });
      try {
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
      const store = new KronicleLite({ dataDir });
      const r = await store.importEvents(createReadStream(file));
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
      const store = new KronicleLite({ dataDir });
      const warnings: string[] = [];
      let source: DocumentSource | undefined;
      if (flags['bind-git'] === true) {
        const b = bindGit(file);
        source = b.binding ? { kind: 'file', path: b.binding.path, git: b.binding } : { kind: 'file', path: file.split(/[\\/]+/).join('/') };
        if (b.warning) warnings.push(b.warning);
      }
      const r = store.docs.putDocument({
        slug,
        title: str(flags['title']) ?? basename(file).replace(/\.md$/i, ''),
        markdown: readFileSync(file, 'utf8'),
        actor_id: str(flags['actor']) ?? 'cli',
        ...(source !== undefined ? { source } : {}),
      });
      for (const w of warnings) process.stderr.write(`warning: ${w}\n`);
      process.stdout.write(JSON.stringify({ ...r, ...(source !== undefined ? { source } : {}), ...(warnings.length > 0 ? { warnings } : {}) }, null, 2) + '\n');
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
      });
      process.stdout.write(flags['json'] ? JSON.stringify(state, null, 2) + '\n' : renderSystemStateMarkdown(state) + '\n');
      store.close();
      return 0;
    }
    case 'watch':
      return watchCommand(dataDir, positional, flags);
    default:
      process.stderr.write(`unknown command: ${cmd}\n\n${HELP}`);
      return 2;
  }
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
        const r = syncInstructionFile(store, entryFor(input.file_path, rc), { actor_id: actor });
        if (r.action !== 'unchanged' && r.action !== 'missing') {
          process.stdout.write(JSON.stringify({ systemMessage: `kronicle-lite: ${describeSync(r)}` }) + '\n');
        }
        return 0;
      }
      const results = syncInstructionSet(store, { ...ctx, actor_id: actor });
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
    const results: SyncResult[] = syncInstructionSet(store, { ...instructionCtx(flags), paths: positional, actor_id: actor });
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

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    process.stderr.write(`error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  },
);
