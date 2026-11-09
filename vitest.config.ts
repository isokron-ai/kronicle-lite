import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // generous: a loaded runner (or the full suite in parallel) is several times slower than a quiet laptop
    testTimeout: 60_000,
    setupFiles: ['test/helpers/yield.ts'],
  },
});
