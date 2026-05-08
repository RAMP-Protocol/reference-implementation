// Bundle the Fastly Compute entry + compile to WASM.
//
// 1. esbuild src/index.ts → dist/bundle.js (single ESM file, Fastly target)
// 2. npx js-compute-runtime dist/bundle.js dist/main.wasm

import { execSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { build } from 'esbuild';

mkdirSync('dist', { recursive: true });
mkdirSync('bin', { recursive: true });

await build({
  entryPoints: ['src/index.ts'],
  outfile: 'dist/bundle.js',
  bundle: true,
  format: 'esm',
  target: 'esnext',
  platform: 'neutral',
  conditions: ['fastly', 'worker', 'browser'],
  mainFields: ['module', 'main'],
  external: ['fastly:*'],
  logLevel: 'info',
});

execSync('npx js-compute-runtime dist/bundle.js bin/main.wasm', {
  stdio: 'inherit',
});

console.log('built bin/main.wasm');
