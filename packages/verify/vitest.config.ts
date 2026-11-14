import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

// The standalone verifier's tests run from the repository root (they use kronicle-lite's test helpers
// and its built CLI as the reference): npm run verify:test.
export default defineConfig({
  root: fileURLToPath(new URL('../..', import.meta.url)),
  test: {
    include: ['packages/verify/test/**/*.test.ts'],
    testTimeout: 120_000,
    hookTimeout: 240_000,
    setupFiles: ['test/helpers/yield.ts', 'test/helpers/anchor-genesis.ts'],
  },
});
