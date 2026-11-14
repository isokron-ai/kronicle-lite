/**
 * Evaluated before any other module of verify.mjs (the first import of src/cli.ts), so an older Node
 * gets this message instead of an error from code it cannot run.
 */
declare const __VERIFY_NAME__: string;

const [major] = process.versions.node.split('.').map(Number);
if ((major ?? 0) < 22) {
  process.stderr.write(`error: ${__VERIFY_NAME__} needs Node.js 22 or later (this is ${process.version})\n`);
  process.exit(2);
}
