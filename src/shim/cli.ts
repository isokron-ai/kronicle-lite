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
import { PULSE_UNAVAILABLE_EXIT, exitCodeFor, openForPulse, pulse, retractionLine, type PulseMode } from './pulse.js';
import { ackShim, execShim, install, locateShimDir, status, uninstall } from './install.js';

interface Parsed {
  positional: string[];
  flags: Record<string, string | true>;
  rest: string[];
}

const BOOL = new Set(['json', 'all-projects', 'windows', 'no-windows', 'posix', 'no-posix']);

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
                               [--data-dir DIR] [--mode deny|warn] [--pending-actor A[,B]] [--windows] [--json]
        write tiny wrappers into D (default ~/.kronicle-lite/shims); put D FIRST on PATH.
        A change stops blocking once the pending actor(s) re-read its current version
        (default: whoever read the changed block)
  kronicle-lite shim status    [--dir D] [--cwd DIR] [--json]   what is installed, active on PATH, pending here
  kronicle-lite shim ack       [--dir D] [--cwd DIR] [--through SEQ] [--json]
        manual override: clear this project's gate up to SEQ (the seq a denial printed)
  kronicle-lite shim uninstall [--dir D] [--json]               remove our wrappers (marker-checked) and state
  kronicle-lite shim exec      --dir D --tool T -- ARGS…        what the Windows wrappers run
  kronicle-lite pulse          [--data-dir DIR] [--cwd DIR] [--cursor C | --state D] [--mode deny|warn] [--pending-actor A[,B]] [--json] [-- CMD…]
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
    let store;
    try {
      store = openForPulse(dataDir);
    } catch (err) {
      return unavailable(err instanceof Error ? err.message : String(err));
    }
    try {
      const r = pulse(store, {
        dataDir,
        cwd,
        actor: str(flags['actor']),
        cursor: str(flags['cursor']),
        stateDir,
        ...(str(flags['pending-actor']) !== undefined ? { pendingActors: list(flags['pending-actor']) } : {}),
        mode: modeOf(flags['mode']),
        command: rest,
        allProjects: flags['all-projects'] === true,
      });
      if (json) out(r);
      if (r.message) process.stderr.write(r.message + '\n');
      return exitCodeFor(r);
    } catch (err) {
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
            `mode ${r.mode}; data dir ${r.data_dir || `${dataDir} (default)`}; ${r.baseline_seq !== null ? `checks start at seq ${r.baseline_seq}` : 'no store yet'}\n` +
            (r.first_on_path ? 'the shim dir is first on PATH\n' : `put it FIRST on PATH (shell profile, and each agent's environment):\n  ${r.path_hint}\n`),
        );
      }
      for (const w of r.warnings) process.stderr.write(`warning: ${w}\n`);
      return 0;
    }
    case 'uninstall': {
      const r = uninstall(locateShimDir(str(flags['dir']), fallbackDir));
      if (json) out(r);
      else {
        process.stdout.write(`removed ${r.removed.length} item(s) from ${r.dir}${r.dir_removed ? ' (and the empty dir)' : ''}\n`);
        if (r.kept.length > 0) process.stdout.write(`kept (not ours): ${r.kept.join(', ')}\n`);
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
      const lines = [`shims in ${r.dir}: mode ${c.mode}; ${c.pending_actors && c.pending_actors.length > 0 ? `pending actor(s) ${c.pending_actors.join(', ')}` : 'pending actors: each change\'s readers'}; data dir ${r.store.data_dir}${r.store.exists ? ` (head seq ${r.store.head_seq ?? '?'})` : ' (no store: fail open)'}`];
      for (const t of r.tools) {
        lines.push(
          `  ${t.tool.padEnd(10)} ${t.active ? 'active ' : 'INACTIVE'} real: ${t.real ?? 'NOT FOUND'}${t.active ? '' : `; PATH runs ${t.first_on_path ?? 'nothing'} first`}`,
        );
      }
      if (c.world.length > 0) lines.push(`  user rules: ${c.world.join(', ')}`);
      if (r.project) {
        const p = r.project.pending;
        if (!p) lines.push(`project ${r.project.key}: no check yet (the first world-changing command records the head)`);
        else if (p.decision === 'deny') {
          lines.push(
            p.reason === 'integrity'
              ? `project ${r.project.key}: BLOCKED — store integrity failure`
              : `project ${r.project.key}: BLOCKED — ${p.blocking.length} unreconciled change(s); re-read the current version (or override: kronicle-lite shim ack --through ${p.ack_through})`,
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
      const r = ackShim(locateShimDir(str(flags['dir']), fallbackDir), { defaultDataDir: dataDir, cwd, through: t === undefined ? undefined : Number(t) });
      if (json) out(r);
      else {
        process.stdout.write(`acknowledged through seq ${r.through} for project ${r.project_key} (${r.acknowledged.length} blocking change(s))\n`);
        for (const a of r.acknowledged.slice(0, 6)) process.stdout.write(retractionLine(a) + '\n');
      }
      return 0;
    }
    case 'exec': {
      const dir = str(flags['dir']);
      const tool = str(flags['tool']);
      if (!dir || !tool) throw new Error('usage: kronicle-lite shim exec --dir D --tool T -- ARGS…');
      return execShim(dir, tool, rest, { defaultDataDir: dataDir, cwd: cwd ?? process.cwd() });
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
