import { defineConfig } from 'tsup';

export default defineConfig({
  entry: { index: 'src/index.ts', core: 'src/core.ts', cli: 'src/cli.ts' },
  format: ['esm'],
  target: 'node20',
  platform: 'node',
  dts: { entry: { index: 'src/index.ts', core: 'src/core.ts' } },
  sourcemap: true,
  clean: true,
  // Chunks let the CLI load the MCP SDK, HTTP and anchor code only for the commands that use them.
  splitting: true,
  banner: ({ format }) => (format === 'esm' ? { js: '' } : {}),
});
