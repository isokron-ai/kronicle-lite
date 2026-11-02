/**
 * CLI entry points for `kronicle-lite pulse` and `kronicle-lite shim …`.
 * Loaded on demand by cli.ts (own argv parser: `--` ends the options and the
 * rest is the command being checked or run, verbatim).
 */

import { realpathSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { defaultDataDir } from '../db/open.js';
import { VERSION } from '../version.js';
import { DEFAULT_COMMANDS } from './rules.js';
import {
  PULSE_UNAVAILABLE_EXIT,
  corruptOutcome,
  exitCodeFor,
  isCorruptError,
  openForPulse,
  pulse,
  resolveStore,
  retractionLine,
  storeExists,
  storeOutcome,
  targetFor,
  type PulseMode,
} from './pulse.js';
import { ACTOR_ENV, AckRefusedError, ackShim, execShim, install, invokingActorFromEnv, locateShimDir, shimLog, status, uninstall, uninstallGitHooks } from './install.js';

interface Parsed {
  positional: string[];
  flags: Record<string, string | true>;
  rest: string[];
}

const BOOL = new Set(['json', 'all-projects', 'windows', 'no-windows', 'posix', 'no-posix', 'git-hook', 'all-readers', 'operator']);

function parse(argv: string[]): Parsed {
  const positional: string[] = [];
  const flags: Record<string, string | true> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--') return { positional, flags, rest: argv.slice(i + 1) };
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > 2) {
        flags[a.slice(2, eq)] = a.slice(eq + 1);
        continue;
      }
      const key = a.slice(2);
      const next = argv[i + 1];
      if (!BOOL.has(key) && next !== undefined && !next.startsWith('--')) {
        flags[key] = next;
        i++;
      } else flags[key] = true;
    } else positional.push(a);
  }
  return { positional, flags, rest: [] };
}

const str = (v: string | true | undefined): string | undefined => (typeof v === 'string' ? v : undefined);
const list = (v: string | true | undefined): string[] =>
  (str(v) ?? '')
    .split(',')
    .map((x) => x.trim())
    .filter((x) => x.length > 0);

function modeOf(v: string | true | undefined): PulseMode | undefined {
  const m = str(v);
  if (m === undefined) return undefined;
  if (m !== 'deny' && m !== 'warn') throw new Error('--mode must be deny or warn');
  return m;
}

function onTimeoutOf(v: string | true | undefined): 'allow' | 'deny' | undefined {
  const m = str(v);
  if (m === undefined) return undefined;
  if (m !== 'allow' && m !== 'deny') throw new Error('--on-timeout must be allow or deny');
  return m;
}

function cliPath(): string {
  const a = process.argv[1] ?? '';
  try {
    return realpathSync.native(a);
  } catch {
    return a;
  }
}

export const SHIM_HELP = `kronicle-lite shim — exec-time pulse wrappers for world-changing commands (docs/PUSH.md)

  kronicle-lite shim install   [--dir D] [--commands ${DEFAULT_COMMANDS.join(',')}] [--world "make release,docker push"]
                               [--data-dir DIR] [--mode deny|warn] [--pending-actor A[,B] | --all-readers]
                               [--on-timeout allow|deny] [--git-hook [--repo PATH]] [--windows] [--json]
        write tiny wrappers into D (default ~/.kronicle-lite/shims); put D FIRST on PATH.
        A change stops blocking once the pending actor(s) re-read its current version:
        --pending-actor A, else the invoking actor ($${ACTOR_ENV} in the command's environment),
        else (not set, or --all-readers) everyone who read the changed block. A check that times out
        (KRONICLE_SHIM_TIMEOUT, default 10 s) is reported every time and runs the command
        (--on-timeout allow, default) or refuses it with exit 77 (--on-timeout deny).
        --git-hook: also install a git pre-push hook in the repository at --repo (default: the
        working directory) and its submodules, which runs the same check for EVERY push (absolute git path, sudo, aliases,
        hooks, rebase -x, submodule foreach); an existing pre-push hook is chained, not replaced
  kronicle-lite shim status    [--dir D] [--cwd DIR] [--json]   what is installed, active on PATH, pending here
  kronicle-lite shim ack       [--dir D] [--cwd DIR] [--through SEQ] [--operator] [--actor A] [--json]
        OPERATOR override: clear this project's gate up to SEQ without anyone re-reading. Needs an
        interactive terminal or --operator; every ack (and every refused one) is logged in shim.log
  kronicle-lite shim uninstall [--dir D] [--git-hook [--repo PATH]] [--json]
        remove our wrappers (marker-checked), state and pre-push hooks (chained hooks are put back);
        --git-hook: only the hooks (of the repository at --repo, or all)
  kronicle-lite shim exec      --dir D --tool T [--project DIR] -- ARGS…   what the Windows wrappers run
  kronicle-lite pulse          [--data-dir DIR] [--cwd DIR] [--cursor C | --state D] [--mode deny|warn]
                               [--pending-actor A[,B] | --invoking-actor A | --all-readers] [--json] [-- CMD…]
        the check itself: exit 0 allow, 77 refused (reason on stderr), 3 store unavailable

Without --dir, status/ack/uninstall use the first shim dir on PATH.
`;

export async function runShimCli(cmd: 'pulse' | 'shim', argv: string[]): Promise<number> {
  const { positional, flags, rest } = parse(argv);
  const dataDirFlag = str(flags['data-dir']);
  const dataDir = dataDirFlag ?? defaultDataDir();
  const cwd = str(flags['cwd']);
  const json = flags['json'] === true;
  const out = (v: unknown) => process.stdout.write(JSON.stringify(v, null, 2) + '\n');

  if (cmd === 'pulse') {
    const stateDir = str(flags['state']);
    let checkDir = dataDir;
    if (stateDir !== undefined) {
      // A shim / hook (P2-01): the store the server uses, found like the server finds it.
      // Pinned with --data-dir; else $KRONICLE_LITE_DATA_DIR / --default-data-dir / ~ plus a
      // project-local .kronicle-lite/ above the target. None, or two: refuse (deny mode).
      const res = resolveStore({ pinned: dataDirFlag, targetDir: targetFor({ cwd, command: rest }).dir, defaultDir: str(flags['default-data-dir']) });
      if (res.dataDir === null || !storeExists(res.dataDir)) {
        const so = storeOutcome(res, modeOf(flags['mode']) ?? 'deny', rest);
        shimLog(stateDir, rest[0] ?? 'pulse', `pulse(node) decision=${so.decision} reason=${so.reason}`);
        try {
          writeFileSync(join(stateDir, 'last-error'), `${new Date().toISOString()} ${so.error}\n`);
        } catch {
          // never block on logging
        }
        if (json) out({ format: 'kronicle-lite/1', decision: so.decision, reason: so.reason, error: so.error, candidates: res.candidates, message: so.message });
        process.stderr.write(so.message + '\n');
        return so.exit;
      }
      checkDir = res.dataDir;
    }
    // Called by a shim (--state): stay quiet on failure (the shim notes it once
    // and logs it); the reason goes to <state>/last-error for `shim status`.
    const unavailable = (msg: string): number => {
      if (stateDir !== undefined) {
        try {
          writeFileSync(join(stateDir, 'last-error'), `${new Date().toISOString()} ${msg}\n`);
        } catch {
          // never block on logging
        }
      } else process.stderr.write(`kronicle-lite pulse: ${msg}\n`);
      if (json) out({ error: msg });
      return PULSE_UNAVAILABLE_EXIT;
    };
    // L2-03: a store that is there but damaged is an integrity failure, never "unavailable".
    const corrupt = (err: unknown): number => {
      const c = corruptOutcome(err, modeOf(flags['mode']) ?? 'deny', rest);
      if (stateDir !== undefined) {
        shimLog(stateDir, rest[0] ?? 'pulse', `pulse(node) decision=${c.decision} reason=corrupt error=${c.error.replace(/\s+/g, '_').slice(0, 160)}`);
        try {
          writeFileSync(join(stateDir, 'last-error'), `${new Date().toISOString()} CORRUPT ${c.error}\n`);
        } catch {
          // never block on logging
        }
      }
      if (json) out({ format: 'kronicle-lite/1', decision: c.decision, reason: c.reason, error: c.error, message: c.message });
      process.stderr.write(c.message + '\n');
      return c.exit;
    };
    // Timing for the shim log (--state): node start-up to here, opening the store, the check.
    const tStart = performance.now();
    let store;
    try {
      store = openForPulse(checkDir);
    } catch (err) {
      if (isCorruptError(err)) return corrupt(err);
      return unavailable(err instanceof Error ? err.message : String(err));
    }
    const tOpen = performance.now();
    try {
      const r = pulse(store, {
        dataDir: checkDir,
        cwd,
        actor: str(flags['actor']),
        cursor: str(flags['cursor']),
        stateDir,
        ...(str(flags['pending-actor']) !== undefined ? { pendingActors: list(flags['pending-actor']) } : {}),
        mode: modeOf(flags['mode']),
        command: rest,
        allProjects: flags['all-projects'] === true,
        // The shim (--state) runs in the agent's environment: its actor is the invoking actor.
        invokingActor: str(flags['invoking-actor']) ?? (stateDir !== undefined ? invokingActorFromEnv() : undefined),
        ...(flags['all-readers'] === true ? { allReaders: true } : {}),
      });
      if (stateDir !== undefined) {
        const t = performance.now();
        shimLog(stateDir, rest[0] ?? 'pulse', `pulse(node) boot ${Math.round(tStart)}ms open ${Math.round(tOpen - tStart)}ms check ${Math.round(t - tOpen)}ms total ${Math.round(t)}ms decision=${r.decision} reason=${r.reason} head=${r.head.seq}`);
      }
      if (json) out(r);
      if (r.message) process.stderr.write(r.message + '\n');
      return exitCodeFor(r);
    } catch (err) {
      if (isCorruptError(err)) return corrupt(err);
      if (stateDir === undefined) throw err;
      return unavailable(err instanceof Error ? err.message : String(err));
    } finally {
      store.close();
    }
  }

  const sub = positional[0];
  const fallbackDir = join(dataDir, 'shims');
  switch (sub) {
    case 'install': {
      const r = install({
        dir: str(flags['dir']) ?? fallbackDir,
        commands: list(flags['commands']),
        world: list(flags['world']),
        mode: modeOf(flags['mode']),
        ...(str(flags['pending-actor']) !== undefined ? { pendingActors: list(flags['pending-actor']) } : {}),
        ...(onTimeoutOf(flags['on-timeout']) !== undefined ? { onTimeout: onTimeoutOf(flags['on-timeout']) } : {}),
        ...(flags['all-readers'] === true ? { allReaders: true } : {}),
        ...(flags['git-hook'] === true ? { gitHookRepo: str(flags['repo']) ?? cwd ?? process.cwd() } : {}),
        dataDir: dataDirFlag,
        effectiveDataDir: dataDir,
        node: process.execPath,
        cli: cliPath(),
        version: VERSION,
        ...(flags['windows'] === true ? { windows: true } : flags['no-windows'] === true ? { windows: false } : {}),
        ...(flags['no-posix'] === true ? { posix: false } : flags['posix'] === true ? { posix: true } : {}),
      });
      if (json) out(r);
      else {
        process.stdout.write(
          `installed ${r.tools.length} shim(s) in ${r.dir}: ${r.tools.join(', ')}\n` +
            `mode ${r.mode}; on timeout ${r.on_timeout}; data dir ${r.data_dir || `${dataDir} (default)`}; ${r.baseline_seq !== null ? `checks start at seq ${r.baseline_seq}` : 'no store yet'}\n` +
            (r.first_on_path ? 'the shim dir is first on PATH\n' : `put it FIRST on PATH (shell profile, and each agent's environment):\n  ${r.path_hint}\n`),
        );
        for (const h of r.git_hooks) {
          process.stdout.write(`git pre-push hook: ${h.file}${h.chained_now ? ` (the existing hook was moved to ${h.chained} and runs after the check)` : h.chained ? ` (chains ${h.chained})` : ''}\n`);
        }
        if (r.git_hooks.length > 0) process.stdout.write('every push from these repositories is checked, however git is started (`git push --no-verify` skips it)\n');
      }
      for (const w of r.warnings) process.stderr.write(`warning: ${w}\n`);
      return 0;
    }
    case 'uninstall': {
      const hookLine = (h: { file: string; removed: boolean; restored: string | null; kept: string | null }) =>
        `git pre-push hook ${h.file}: ${h.kept ? `kept (${h.kept})` : h.removed ? 'removed' : 'already gone'}${h.restored ? '; the chained hook is back in place' : ''}\n`;
      if (flags['git-hook'] === true) {
        const r = uninstallGitHooks(locateShimDir(str(flags['dir']), fallbackDir), str(flags['repo']));
        if (json) out(r);
        else {
          if (r.hooks.length === 0) process.stdout.write(`no recorded pre-push hook${str(flags['repo']) ? ` for ${str(flags['repo'])}` : ''}\n`);
          for (const h of r.hooks) process.stdout.write(hookLine(h));
        }
        return 0;
      }
      const r = uninstall(locateShimDir(str(flags['dir']), fallbackDir));
      if (json) out(r);
      else {
        process.stdout.write(`removed ${r.removed.length} item(s) from ${r.dir}${r.dir_removed ? ' (and the empty dir)' : ''}\n`);
        if (r.kept.length > 0) process.stdout.write(`kept (not ours): ${r.kept.join(', ')}\n`);
        for (const h of r.git_hooks) process.stdout.write(hookLine(h));
        process.stdout.write('remove the dir from PATH in your shell profile if you added it\n');
      }
      return 0;
    }
    case 'status': {
      const r = status(locateShimDir(str(flags['dir']), fallbackDir), { defaultDataDir: dataDir, cwd });
      if (json) {
        out(r);
        return r.installed ? 0 : 1;
      }
      if (!r.installed) {
        process.stdout.write(`no kronicle-lite shims in ${r.dir} (kronicle-lite shim install)\n`);
        return 1;
      }
      const c = r.config!;
      const who =
        c.pending_actors && c.pending_actors.length > 0
          ? `pending actor(s) ${c.pending_actors.join(', ')}`
          : c.all_readers
            ? "pending actors: each change's readers (--all-readers)"
            : r.invoking_actor
              ? `pending actor: the invoking actor (${ACTOR_ENV}=${r.invoking_actor} here)`
              : `pending actors: the invoking actor (${ACTOR_ENV}); not set here, so each change's readers`;
      const lines = [`shims in ${r.dir}: mode ${c.mode}; on timeout ${c.on_timeout ?? 'allow'}; ${who}; data dir ${r.store.data_dir}${r.store.exists ? ` (head seq ${r.store.head_seq ?? '?'}${r.store.source === 'found' ? ', found' : r.store.source === 'pinned' ? ', pinned' : ''})` : r.store.source === 'ambiguous' ? ' (AMBIGUOUS: world-changing commands refused)' : ' (no store: world-changing commands refused in deny mode)'}`];
      for (const t of r.tools) {
        lines.push(
          `  ${t.tool.padEnd(10)} ${t.active ? 'active ' : 'INACTIVE'} real: ${t.real ?? 'NOT FOUND'}${t.active ? '' : `; PATH runs ${t.first_on_path ?? 'nothing'} first`}`,
        );
      }
      if (c.world.length > 0) lines.push(`  user rules: ${c.world.join(', ')}`);
      for (const h of r.git_hooks) {
        lines.push(
          `  git hook   ${h.active ? 'active ' : 'INACTIVE'} ${h.file}${h.chained ? ` (chains ${h.chained})` : ''}${
            !h.present ? '; MISSING or replaced (re-run shim install --git-hook)' : !h.active ? `; git now uses hooks dir ${h.hooks_dir_now ?? '?'}` : ''
          }`,
        );
      }
      if (r.repo_hook && !r.repo_hook.present) {
        lines.push(`  this repository has no kronicle-lite pre-push hook: pushes git starts itself (aliases, hooks, rebase -x, submodule foreach), sudo and absolute paths are not checked (shim install --git-hook)`);
      }
      if (r.project) {
        const p = r.project.pending;
        if (!p) lines.push(`project ${r.project.key}: no check yet (the first world-changing command records the head)`);
        else if (p.decision === 'deny') {
          lines.push(
            p.reason === 'integrity'
              ? `project ${r.project.key}: BLOCKED — store integrity failure`
              : p.reason === 'target'
                ? `project ${r.project.key}: BLOCKED — ${p.message ?? 'target unknown'}`
                : `project ${r.project.key}: BLOCKED — ${p.blocking.length} unreconciled change(s) through seq ${p.ack_through}; re-read the current version (operator override: see docs/PUSH.md)`,
          );
          for (const b of p.blocking.slice(0, 6)) lines.push('  ' + retractionLine(b));
        } else lines.push(`project ${r.project.key}: clear (checked from seq ${p.from_seq}, head ${p.head.seq})`);
      }
      if (r.store.error) lines.push(`store error: ${r.store.error}`);
      if (r.unavailable_noted) lines.push(`note: a shim ran unchecked because kronicle-lite was unavailable (see ${join(r.dir, '.kronicle-shim', 'shim.log')})${r.last_error ? `; last: ${r.last_error}` : ''}`);
      process.stdout.write(lines.join('\n') + '\n');
      return 0;
    }
    case 'ack': {
      const t = str(flags['through']);
      if (t !== undefined && !/^\d+$/.test(t)) throw new Error('--through must be a chain seq');
      // H2-12: an operator action. An agent's shell has no TTY on stdin; --operator is the explicit confirmation.
      const confirmed = flags['operator'] === true ? '--operator' : process.stdin.isTTY === true ? 'tty' : null;
      let r;
      try {
        r = ackShim(locateShimDir(str(flags['dir']), fallbackDir), { defaultDataDir: dataDir, cwd, through: t === undefined ? undefined : Number(t), confirmed, actor: str(flags['actor']) });
      } catch (err) {
        if (!(err instanceof AckRefusedError)) throw err;
        process.stderr.write(err.message + '\n');
        return 2;
      }
      if (json) out(r);
      else {
        process.stdout.write(`acknowledged through seq ${r.through} for project ${r.project_key} (${r.acknowledged.length} blocking change(s)); logged as ${r.actor} (${r.confirmed})\n`);
        for (const a of r.acknowledged.slice(0, 6)) process.stdout.write(retractionLine(a) + '\n');
      }
      return 0;
    }
    case 'exec': {
      const dir = str(flags['dir']);
      const tool = str(flags['tool']);
      if (!dir || !tool) throw new Error('usage: kronicle-lite shim exec --dir D --tool T [--project DIR] -- ARGS…');
      return execShim(dir, tool, rest, { defaultDataDir: dataDir, cwd: cwd ?? process.cwd(), project: str(flags['project']) });
    }
    case undefined:
    case 'help':
      process.stdout.write(SHIM_HELP);
      return sub === undefined ? 2 : 0;
    default:
      process.stderr.write(`unknown shim command: ${sub}\n\n${SHIM_HELP}`);
      return 2;
  }
}
