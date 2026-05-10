import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: { cli: 'src/cli.ts' },
    format: ['esm'],
    target: 'node20',
    dts: false,
    clean: true,
    sourcemap: false,
    splitting: false,
    shims: false,
    banner: { js: '#!/usr/bin/env node' },
  },
  {
    entry: { index: 'src/index.ts' },
    format: ['esm'],
    target: 'node20',
    dts: true,
    clean: false,
    sourcemap: false,
    splitting: false,
    shims: false,
  },
]);
