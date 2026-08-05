// Bundle an edge entry into a single ESM file. One bundler for every runtime
// target so the esbuild settings cannot drift between build scripts: the
// Cloudflare worker (default) and the Lambda@Edge bundle differ only in the
// platform preset selected here.
//
// Usage: node scripts/build-worker.mjs [--entry src/entries/cloudflare.ts]
//        [--out dist/worker.mjs] [--platform workerd|node]

import { parseArgs } from 'node:util';
import { build } from 'esbuild';

const { values } = parseArgs({
  options: {
    entry: { type: 'string', default: 'src/entries/cloudflare.ts' },
    out: { type: 'string', default: 'dist/worker.mjs' },
    minify: { type: 'boolean', default: false },
    platform: { type: 'string', default: 'workerd' },
  },
});

// workerd: the Cloudflare Workers runtime (also what Miniflare runs).
// node: the Lambda@Edge nodejs22.x runtime — esbuild's node platform keeps
// node: built-ins external and applies node module resolution.
const platformPresets = {
  workerd: {
    platform: 'neutral',
    target: 'esnext',
    conditions: ['workerd', 'worker', 'browser'],
  },
  node: {
    platform: 'node',
    target: 'node22',
  },
};

const preset = platformPresets[values.platform];
if (!preset) {
  console.error(
    `unknown --platform ${values.platform}; expected one of: ${Object.keys(platformPresets).join(', ')}`,
  );
  process.exit(2);
}

await build({
  entryPoints: [values.entry],
  outfile: values.out,
  bundle: true,
  format: 'esm',
  mainFields: ['module', 'main'],
  logLevel: 'info',
  minify: values.minify,
  ...preset,
});

console.log(`built ${values.out} from ${values.entry} (${values.platform})`);
