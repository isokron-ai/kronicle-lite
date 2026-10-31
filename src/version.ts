import { createRequire } from 'node:module';

// Single source of truth is package.json; read at startup so the CLI, the
// MCP server banner and tests can never drift from the published version.
const require = createRequire(import.meta.url);
const pkg = require('../package.json') as { version: string };

export const VERSION: string = pkg.version;
