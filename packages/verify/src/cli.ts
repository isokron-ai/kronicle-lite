/**
 * The standalone IsoKron Evidence Pack verifier: `node verify.mjs PACK --key-fingerprint SHA256`.
 *
 * It is `kronicle-lite verify-audit` and nothing else. The checks, the report and the exit code come
 * from the same source files (src/audit/verify-audit.ts and src/audit/verify-audit-cli.ts), built
 * into one file with Node built-ins only (packages/verify/build.mjs lists what goes in).
 *
 *   exit 0  VERIFIED (or VERIFIED WITH UNWITNESSED WINDOW: the freeze was anchored late)
 *   exit 1  a check failed, or a declared claim was not checked
 *   exit 2  PARTIAL (a pack made before 0.11.0, under --profile legacy), a usage error, or an
 *           unreadable pack / trust input
 */

import { homedir } from 'node:os';
import { join } from 'node:path';

import { BOOLEAN_FLAGS, checkOptions, COMMAND_OPTIONS, parseArgs, str } from '../../../src/cli-flags.js';
import { verifyAuditCommand } from '../../../src/audit/verify-audit-cli.js';

declare const __VERIFY_NAME__: string;
declare const __VERIFY_VERSION__: string;
declare const __VERIFY_SOURCE__: string;

const PROGRAM = 'verify.mjs';

/**
 * Where the anchor key list seen per genesis pin is kept (the rollback check): the same place as
 * kronicle-lite (src/db/open.ts defaultDataDir), so both tools share what they have seen.
 */
export function defaultDataDir(env: NodeJS.ProcessEnv = process.env): string {
  return env['KRONICLE_LITE_DATA_DIR'] ?? join(homedir(), '.kronicle-lite');
}

const HELP = `${__VERIFY_NAME__} ${__VERIFY_VERSION__}: verify an IsoKron Evidence Pack offline (Node.js 22+, no dependencies)

Usage:
  node ${PROGRAM} PACK --key-fingerprint SHA256 [options]
  node ${PROGRAM} PACK --key PEM-FILE [options]

  --key-fingerprint SHA256   the auditor key's SHA-256(SPKI), from your signed statement of work (never from the pack)
  --key PEM-FILE             the auditor public key, from a file outside the pack
  --profile audit|legacy     audit (default): every claim, bundle format /3; legacy: packs made before
                             kronicle-lite 0.11.0 (formats /1 and /2), PARTIAL at best (exit 2)
  --anchor-keys FILE         the anchor service key list (default: the pack's anchor-keys.json, chain-checked)
  --genesis SHA256@FROM      the anchor service genesis pin (default: the compiled production pin;
                             or KRONICLE_ANCHOR_GENESIS)
  --tsa-roots DIR            TSA CA certificates (default: the pinned Sectigo and DigiCert CAs built in)
  --allowed-signers FILE     ssh allowed-signers for the human sign-offs
  --no-tsa                   do not check RFC 3161 tokens (declared timestamp claims are then not checked)
  --tsa-at-gentime           check TSA certificates at the token's time, not now
  --require CLAIM,...        fail unless these claims were checked and passed
  --skip-claim CLAIM,...     leave these claims out explicitly (not integrity or chain)
  --strict-freeze            do not accept a freeze anchored late (kronicle-lite 0.11.2 behaviour)
  --max-bytes N              largest pack to read
  --allow-hardlinks          accept hard-linked files in the pack
  --json                     the report as JSON (format kronicle-lite-verify-audit/3)
  --data-dir DIR             where the anchor key list seen before is kept (default: $KRONICLE_LITE_DATA_DIR
                             or ~/.kronicle-lite, shared with kronicle-lite)
  --version, --help

Exit: 0 verified, 1 a check failed or a declared claim was not checked, 2 partial / usage / unreadable.
Same checks, report and exit codes as kronicle-lite verify-audit; built from ${__VERIFY_SOURCE__}.
`;

export async function main(argv: string[]): Promise<number> {
  const first = argv[0];
  if (first === '--help' || first === '-h' || first === 'help') {
    process.stdout.write(HELP);
    return 0;
  }
  if (first === '--version' || first === 'version') {
    process.stdout.write(`${__VERIFY_VERSION__}\n`);
    return 0;
  }
  // `verify.mjs verify-audit PACK …` is accepted too, so a kronicle-lite command line works as is.
  const args = first === 'verify-audit' ? argv.slice(1) : argv;
  const { positional, flags, repeated } = parseArgs(['verify-audit', ...args]);
  try {
    checkOptions(PROGRAM, [...COMMAND_OPTIONS['verify-audit']!, 'data-dir'], flags, positional, 1, repeated, BOOLEAN_FLAGS);
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message.replace('; see kronicle-lite help', `; see node ${PROGRAM} --help`)}\n`);
    return 2;
  }
  if (flags['data-dir'] === true) {
    process.stderr.write('error: --data-dir needs a value\n');
    return 2;
  }
  return verifyAuditCommand(positional, flags, str(flags['data-dir']) ?? defaultDataDir(), `node ${PROGRAM}`);
}

// As kronicle-lite's CLI: a reader that goes away (`… | head`) is not an error.
process.stdout.on('error', (err: NodeJS.ErrnoException) => {
  if (err.code === 'EPIPE') process.exit(0);
  throw err;
});

const [major] = process.versions.node.split('.').map(Number);
if ((major ?? 0) < 22) {
  process.stderr.write(`error: ${__VERIFY_NAME__} needs Node.js 22 or later (this is ${process.version})\n`);
  process.exitCode = 2;
} else {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (err: unknown) => {
      process.stderr.write(`error: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exitCode = 1;
    },
  );
}
