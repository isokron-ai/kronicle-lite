/**
 * `verify-audit PACK`: the command line around verifyAudit (flags, trust inputs from outside the
 * pack, output, exit code). Shared by `kronicle-lite verify-audit` (src/cli.ts) and the standalone
 * verifier (packages/verify), so both give the same output and exit code for the same arguments.
 * Moved from src/cli.ts unchanged except for the program name in the usage line.
 */

import { join } from 'node:path';

import { list, num, str } from '../cli-flags.js';
import { pemFileNames, pemsFromText } from './pem-files.js';
import { CLAIMS, genesisFromCli, PROFILES, readTrustInput, refuseInsidePack, renderVerifyAudit, verifyAudit, VerifyAuditUsageError, type Claim, type VerifyAuditOptions } from './verify-audit.js';

/** `verify-audit PACKAGE`: exit 0 VERIFIED (or VERIFIED with the freeze anchored late), 1 a check failed (or a claim was not checked), 2 PARTIAL, usage or an unreadable package / trust input. */
export async function verifyAuditCommand(positional: string[], flags: Record<string, string | true>, dataDir: string, program = 'kronicle-lite verify-audit'): Promise<number> {
  const usage =
    `usage: ${program} PACK --key-fingerprint SHA256 | --key PEM-FILE [--profile audit|legacy] [--anchor-keys FILE] [--genesis SHA256@VALID_FROM] [--tsa-roots DIR] [--allowed-signers FILE] [--no-tsa] [--tsa-at-gentime] [--require CLAIM,…] [--skip-claim CLAIM,…] [--strict-freeze] [--max-bytes N] [--allow-hardlinks] [--json]`;
  const dir = positional[0];
  if (!dir) {
    process.stderr.write(`${usage}\n`);
    return 2;
  }
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
    const signersFile = str(flags['allowed-signers']);
    const allowedSigners = signersFile ? readTrustInput(dir, signersFile, '--allowed-signers', 64 * 1024).toString('utf8') : undefined;
    const profile = str(flags['profile']);
    if (flags['profile'] !== undefined && (profile === undefined || !(PROFILES as readonly string[]).includes(profile))) throw new Error(`--profile must be one of ${PROFILES.join(', ')}`);
    const roots = str(flags['tsa-roots']);
    let tsaRoots: { name: string; pem: string }[] | undefined;
    if (roots) {
      refuseInsidePack(dir, roots, '--tsa-roots');
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
      ...(profile !== undefined ? { profile: profile as 'audit' | 'legacy' } : {}),
      ...(allowedSigners !== undefined ? { allowed_signers: allowedSigners } : {}),
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
      ...(flags['strict-freeze'] === true ? { late_anchor: 'strict' as const } : {}),
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
  return r.verdict === 'verified' || r.verdict === 'verified_late_anchor' ? 0 : r.verdict === 'partial' ? 2 : 1;
}
