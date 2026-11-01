/**
 * Generates the shim wrappers.
 *
 * POSIX (`<dir>/<tool>`, #!/bin/sh): decides with shell builtins only, from
 * the same rule table as rules.ts `classify()`. A read-only invocation costs a
 * loop over the first few arguments, a PATH walk and `exec`: no node, no
 * subshell. A world-changing one runs `kronicle-lite pulse` (bounded by
 * `timeout`, or perl's alarm where there is no `timeout`) with the shim dir
 * removed from PATH, then execs the real binary, or exits 77 when refused.
 *
 * Windows (`<tool>.cmd`, `<tool>.ps1`): delegate to `kronicle-lite shim exec`
 * (one node start per call; the decision is classify()).
 *
 * Self-recursion: the real binary is looked up on PATH minus the shim dir
 * (as installed, and as it was reached: `${0%/*}`). When an exec lands on a
 * shim again in the same process (the shim dir also on PATH under another
 * name, or a wrapper that `exec`s the tool by name), the exec'd shim sees
 * KRONICLE_SHIM_EXEC="<its own pid>:…" and skips the dirs already tried;
 * KRONICLE_SHIM_DEPTH stops a wrapper that calls the tool in a child process
 * from looping forever (8 nested shim calls → exit 126).
 */

import { BUILTIN_TOOLS, WORLD_WORDS, seqDepth, type ToolSpec } from './rules.js';

export const SHIM_MARKER = 'kronicle-lite-shim v1';
export const MAX_DEPTH = 8;

/** Single-quote for sh. */
export function shq(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_';

function optCase(opts: string[], action: string): string {
  if (opts.length === 0) return '';
  for (const o of opts) if (!/^-{1,2}[A-Za-z0-9][A-Za-z0-9-]*$/.test(o)) throw new Error(`bad option name ${o}`);
  return `case $kl_a in ${opts.join('|')}) ${action};; esac`;
}

function wordTest(i: number, w: string): string {
  return w === '*' ? `[ -n "$${i}" ]` : `[ "$${i}" = ${shq(w)} ]`;
}

function seqTest(seq: string): string {
  return seq
    .split(' ')
    .map((w, i) => wordTest(i + 1, w))
    .join(' && ');
}

/** The sh body that sets kl_world=1 for a world-changing invocation of "$@". */
export function decisionSh(spec: ToolSpec): string {
  if (spec.all) return 'kl_world=1\n';
  const depth = seqDepth(spec);
  const want = depth + 1;
  const vs = Array.from({ length: want }, (_, i) => `kl_v${i + 1}`);
  const L: string[] = [];
  // kl_word: a script / target name containing deploy|migrate|publish|release as a word.
  if (spec.scriptRun || spec.directScript || spec.anyTarget) {
    const pats: string[] = [];
    for (const w of WORLD_WORDS) pats.push(w, `${w}[!${ALNUM}]*`, `*[!${ALNUM}]${w}`, `*[!${ALNUM}]${w}[!${ALNUM}]*`);
    L.push(`kl_word() { case $1 in ${pats.join('|')}) return 0;; esac; return 1; }`);
  }
  // kl_match WORD…: one candidate verb sequence.
  L.push('kl_match() {');
  for (const e of spec.except) L.push(`  if ${seqTest(e)}; then return 1; fi`);
  for (const w of spec.world) L.push(`  if ${seqTest(w)}; then return 0; fi`);
  if (spec.scriptRun) L.push(`  if { [ "$1" = run ] || [ "$1" = run-script ]; } && [ -n "$2" ] && kl_word "$2"; then return 0; fi`);
  if (spec.directScript) L.push(`  if [ -n "$1" ] && kl_word "$1"; then return 0; fi`);
  L.push('  return 1', '}');
  L.push('kl_world=0');
  if (spec.anyTarget) {
    L.push(
      'for kl_a in "$@"; do',
      '  case $kl_a in -*) continue;; esac',
      `  case $kl_a in [${ALNUM.slice(0, 52)}_]*=*) kl_k=\${kl_a%%=*}; case $kl_k in *[!${ALNUM}]*) ;; *) continue;; esac;; esac`,
      '  if kl_word "$kl_a"; then kl_world=1; break; fi',
      'done',
    );
  }
  // Positional words after the tool's options (rules.ts positionals()).
  L.push(`if [ $kl_world = 0 ]; then`);
  L.push(`kl_n=0 kl_sk=0 kl_po=0 kl_sh=0 kl_dd=0 ${vs.map((v) => `${v}=`).join(' ')}`);
  L.push('for kl_a in "$@"; do');
  L.push('  if [ $kl_sk = 1 ]; then kl_sk=0; kl_po=0; continue; fi');
  L.push('  if [ $kl_dd = 0 ]; then');
  L.push('    case $kl_a in');
  L.push('      --) kl_dd=1; kl_po=0; continue;;');
  L.push('      -?*)');
  const g = optCase(spec.globalValueOpts, 'kl_sk=1; kl_po=0; continue');
  const s = optCase(spec.subValueOpts, 'kl_sk=1; kl_po=0; continue');
  if (g || s) L.push(`        if [ $kl_n = 0 ]; then ${g || ':'}; else ${s || ':'}; fi`);
  L.push('        case $kl_a in *=*) kl_po=0;; *) kl_po=1;; esac');
  L.push('        continue;;');
  L.push('    esac');
  L.push('  fi');
  L.push('  [ $kl_n = 0 ] && kl_sh=$kl_po');
  L.push('  kl_po=0');
  L.push('  kl_n=$((kl_n + 1))');
  L.push(`  case $kl_n in ${vs.map((v, i) => `${i + 1}) ${v}=$kl_a${i + 1 === want ? '; break' : ''};;`).join(' ')} esac`);
  L.push('done');
  const first = vs.slice(0, depth).map((v) => `"$${v}"`).join(' ');
  const shifted = vs.slice(1, depth + 1).map((v) => `"$${v}"`).join(' ');
  L.push(`if kl_match ${first}; then kl_world=1`);
  L.push(`elif [ $kl_sh = 1 ] && kl_match ${shifted}; then kl_world=1; fi`);
  L.push('fi');
  if (spec.help) {
    L.push('if [ $kl_world = 1 ]; then for kl_a in "$@"; do [ "$kl_a" = --help ] && { kl_world=0; break; }; done; fi');
  }
  return L.join('\n') + '\n';
}

export interface ShimParams {
  tool: string;
  spec: ToolSpec;
  /** Absolute physical shim dir. */
  dir: string;
  /** Extra spellings of the shim dir to skip on PATH (the logical path when it differs). */
  aliases: string[];
  stateDir: string;
  node: string;
  cli: string;
  /** '' = kronicle-lite's default ($KRONICLE_LITE_DATA_DIR or ~/.kronicle-lite) at run time. */
  dataDir: string;
  mode: 'deny' | 'warn';
  /** What a check that times out does: run the command anyway (allow, the default) or refuse it (deny, exit 77). */
  onTimeout?: 'allow' | 'deny';
  version: string;
}

export function posixShim(p: ShimParams): string {
  const builtin = BUILTIN_TOOLS[p.tool] !== undefined;
  const skip = [p.dir, ...p.aliases].map((d) => d.replace(/:/g, '')).join(':');
  return `#!/bin/sh
# ${SHIM_MARKER} tool=${p.tool}
# Generated by \`kronicle-lite shim install\` (kronicle-lite ${p.version}); re-run install instead of editing.
# ${builtin ? `Built-in rules for ${p.tool}` : `User rules for ${p.tool}`}${p.spec.world.length > 0 ? ` (world-changing: ${p.spec.world.join(', ')})` : ''}${p.spec.all ? ' (every invocation is world-changing)' : ''}.
# Read-only invocations exec the real ${p.tool} at once. World-changing ones run
# \`kronicle-lite pulse\` first: exit 77 = refused (unreconciled retractions or a
# store integrity failure; the reason is on stderr). kronicle-lite unavailable
# (missing, broken) = fail open, noted once on stderr. A check that TIMES OUT is
# reported on stderr every time and, with --on-timeout deny, refused (exit 77).
# Every world-changing call is logged with its check time in .kronicle-shim/shim.log.
kl_t=${shq(p.tool)}
kl_state=${shq(p.stateDir)}
kl_node=${shq(p.node)}
kl_cli=${shq(p.cli)}
kl_data=${shq(p.dataDir)}
kl_mode=${shq(p.mode)}
kl_onto=${shq(p.onTimeout ?? 'allow')}
case \${KRONICLE_SHIM_DEPTH-0} in ''|*[!0-9]*) kl_depth=0;; *) kl_depth=\${KRONICLE_SHIM_DEPTH-0};; esac
if [ "$kl_depth" -ge ${MAX_DEPTH} ]; then
  printf '%s\\n' "kronicle-lite shim: $kl_t reached the shims ${MAX_DEPTH} times in nested calls; stopping (does a wrapper named $kl_t call $kl_t again?)" >&2
  exit 126
fi
KRONICLE_SHIM_DEPTH=$((kl_depth + 1)); export KRONICLE_SHIM_DEPTH
kl_skip=:${shq(skip)}:"\${0%/*}":
kl_prev=0 kl_extra=
case \${KRONICLE_SHIM_EXEC-} in
  "$$:"*) kl_r=\${KRONICLE_SHIM_EXEC#*:}; kl_prev=\${kl_r%%:*}; kl_extra=\${kl_r#*:};;
esac
kl_skip="$kl_skip$kl_extra"

${decisionSh(p.spec)}
kl_ifs=$IFS
kl_real= kl_found=
set -f; IFS=:
for kl_d in $PATH; do
  [ -n "$kl_d" ] || continue
  while :; do case $kl_d in ?*/) kl_d=\${kl_d%/};; *) break;; esac; done
  case $kl_skip in *":$kl_d:"*) continue;; esac
  if [ -f "$kl_d/$kl_t" ] && [ -x "$kl_d/$kl_t" ]; then kl_real=$kl_d/$kl_t; kl_found=$kl_d; break; fi
done
IFS=$kl_ifs; set +f
if [ -z "$kl_real" ]; then
  printf '%s\\n' "kronicle-lite shim: $kl_t: command not found on PATH (outside the shim dir)" >&2
  exit 127
fi

kl_unavailable() {
  kl_ts=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
  printf '%s %s fail-open: %s\\n' "$kl_ts" "$kl_t" "$1" >> "$kl_state/shim.log" 2>/dev/null
  if [ ! -e "$kl_state/unavailable" ]; then
    printf '%s\\n' "kronicle-lite shim: $1; running $kl_t unchecked (fail open; noted once, see $kl_state/shim.log)" >&2
    : > "$kl_state/unavailable" 2>/dev/null
  fi
}

kl_now_ms() {
  kl_ns=$(date +%s%N 2>/dev/null)
  case $kl_ns in ''|*[!0-9]*) kl_ns=$(date +%s 2>/dev/null)000;; *) kl_ns=\${kl_ns%??????};; esac
  printf '%s' "$kl_ns"
}

kl_log() {
  kl_ts=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
  printf '%s %s %s\\n' "$kl_ts" "$kl_t" "$1" >> "$kl_state/shim.log" 2>/dev/null
}

kl_pulse() {
  kl_cmd="$kl_t\${*:+ $*}"
  kl_p=
  set -f; IFS=:
  for kl_d in $PATH; do
    [ -n "$kl_d" ] || continue
    kl_e=$kl_d
    while :; do case $kl_e in ?*/) kl_e=\${kl_e%/};; *) break;; esac; done
    case $kl_skip in *":$kl_e:"*) continue;; esac
    kl_p=\${kl_p:+$kl_p:}$kl_d
  done
  IFS=$kl_ifs; set +f
  [ -n "$kl_data" ] || kl_data=\${KRONICLE_LITE_DATA_DIR:-$HOME/.kronicle-lite}
  case \${KRONICLE_SHIM_TIMEOUT-} in ''|*[!0-9]*) kl_to=10;; *) kl_to=$KRONICLE_SHIM_TIMEOUT;; esac
  if [ -x "$kl_node" ] && [ -f "$kl_cli" ]; then
    set -- "$kl_node" "$kl_cli" pulse --state "$kl_state" --data-dir "$kl_data" --mode "$kl_mode" --cwd "$PWD" -- "$kl_t" "$@"
  else
    kl_kb=$(PATH=$kl_p command -v kronicle-lite 2>/dev/null)
    if [ -z "$kl_kb" ]; then kl_unavailable "kronicle-lite not found"; return 0; fi
    set -- "$kl_kb" pulse --state "$kl_state" --data-dir "$kl_data" --mode "$kl_mode" --cwd "$PWD" -- "$kl_t" "$@"
  fi
  kl_tb=$(command -v timeout 2>/dev/null)
  if [ -n "$kl_tb" ]; then
    set -- "$kl_tb" -k 2 "$kl_to" "$@"
  else
    kl_pl=$(command -v perl 2>/dev/null)
    [ -z "$kl_pl" ] || set -- "$kl_pl" -e 'alarm shift @ARGV; exec @ARGV or exit 127' "$kl_to" "$@"
  fi
  kl_t0=$(kl_now_ms)
  PATH=$kl_p "$@"
  kl_rc=$?
  kl_ms=$(( $(kl_now_ms) - kl_t0 ))
  case $kl_rc in
    0) kl_log "check \${kl_ms}ms outcome=allow rc=0"; [ ! -e "$kl_state/unavailable" ] || rm -f "$kl_state/unavailable"; return 0;;
    77) kl_log "check \${kl_ms}ms outcome=deny rc=77"; [ ! -e "$kl_state/unavailable" ] || rm -f "$kl_state/unavailable"; exit 77;;
    3) kl_log "check \${kl_ms}ms outcome=unavailable rc=3"; kl_unavailable "kronicle-lite store unavailable (see $kl_state/last-error)"; return 0;;
    124|137|142)
      if [ "$kl_onto" = deny ]; then
        kl_log "check \${kl_ms}ms outcome=timeout-deny rc=$kl_rc timeout=\${kl_to}s"
        printf '%s\\n' "kronicle-lite check TIMED OUT after \${kl_to}s — \\\`$kl_cmd\\\` was NOT checked and NOT run (--on-timeout deny); see $kl_state/shim.log" >&2
        exit 77
      fi
      kl_log "check \${kl_ms}ms outcome=timeout-allow rc=$kl_rc timeout=\${kl_to}s"
      printf '%s\\n' "kronicle-lite check TIMED OUT after \${kl_to}s — \\\`$kl_cmd\\\` was NOT checked; see $kl_state/shim.log" >&2
      return 0;;
    *) kl_log "check \${kl_ms}ms outcome=failed rc=$kl_rc"; kl_unavailable "kronicle-lite pulse failed (exit $kl_rc)"; return 0;;
  esac
}

kl_ok=0
if [ $kl_world = 1 ]; then
  if [ "$kl_prev" = 1 ]; then kl_ok=1; else kl_pulse "$@"; kl_ok=1; fi
fi
KRONICLE_SHIM_EXEC="$$:$kl_ok:$kl_extra$kl_found:"; export KRONICLE_SHIM_EXEC
exec "$kl_real" "$@"
`;
}

/** Windows: cmd.exe wrapper (delegates the decision to node). */
export function cmdShim(p: ShimParams): string {
  const dq = (s: string) => `"${s.replace(/"/g, '')}"`;
  return [
    '@echo off',
    `rem ${SHIM_MARKER} tool=${p.tool}`,
    'rem Generated by `kronicle-lite shim install`; re-run install instead of editing.',
    'setlocal',
    `${dq(p.node)} ${dq(p.cli)} shim exec --dir ${dq(p.dir)} --tool ${p.tool} -- %*`,
    'exit /b %ERRORLEVEL%',
    '',
  ].join('\r\n');
}

/** Windows: PowerShell wrapper (delegates the decision to node). */
export function ps1Shim(p: ShimParams): string {
  const sq = (s: string) => `'${s.replace(/'/g, "''")}'`;
  return [
    `# ${SHIM_MARKER} tool=${p.tool}`,
    '# Generated by `kronicle-lite shim install`; re-run install instead of editing.',
    `& ${sq(p.node)} ${sq(p.cli)} shim exec --dir ${sq(p.dir)} --tool ${sq(p.tool)} -- @args`,
    'exit $LASTEXITCODE',
    '',
  ].join('\r\n');
}
