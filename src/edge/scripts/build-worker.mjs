// Bundle the Cloudflare Workers entry into a single ESM file suitable for
// Miniflare / wrangler deployment.
//
// Usage: node scripts/build-worker.mjs [--out dist/worker.mjs]

import { parseArgs } from 'node:util';
import { build } from 'esbuild';

const { values } = parseArgs({
  options: {
    entry: { type: 'string', default: 'src/entries/cloudflare.ts' },
    out: { type: 'string', default: 'dist/worker.mjs' },
    minify: { type: 'boolean', default: false },
  },
});

await build({
  entryPoints: [values.entry],
  outfile: values.out,
  bundle: true,
  format: 'esm',
  target: 'esnext',
  platform: 'neutral',
  conditions: ['workerd', 'worker', 'browser'],
  mainFields: ['module', 'main'],
  logLevel: 'info',
  minify: values.minify,
});

console.log(`built ${values.out} from ${values.entry}`);
