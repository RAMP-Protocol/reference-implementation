// Bundle the native CloudFront viewer-request handler (src/cloudfront-edge.ts)
// together with a per-deployment config module into a single ESM index.mjs that
// terraform ships as the Lambda@Edge function. This is what makes the deployed
// edge a build artifact of the reference implementation rather than a hand-
// maintained fork: the generic logic is identical across deployments and only
// the baked config (bot JWK, free rules, mcp endpoints, exchange URL) differs —
// required because Lambda@Edge has no environment variables.
//
// Usage:
//   node scripts/build-lambda-edge.mjs --config <path> [--out dist/lambda-edge/index.mjs] [--minify]
//
// The config module must `export default` an EdgeConfig (see
// scripts/fixtures/edge-config.demo.mjs). resolveBotKey embeds the bot's PUBLIC
// JWK — never a private key.

import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { build } from 'esbuild';

const here = dirname(fileURLToPath(import.meta.url));

const { values } = parseArgs({
  options: {
    config: { type: 'string' },
    out: { type: 'string', default: 'dist/lambda-edge/index.mjs' },
    minify: { type: 'boolean', default: false },
  },
});

if (!values.config) {
  console.error('error: --config <path-to-edge-config.mjs> is required');
  process.exit(2);
}

const handlerModule = resolve(here, '../src/cloudfront-edge.ts');
const configModule = resolve(process.cwd(), values.config);

// Generated entry: wire the handler factory with the deployment config and
// expose the Lambda@Edge `handler` export.
const stdin = `
import { createCloudFrontHandler } from ${JSON.stringify(handlerModule)};
import config from ${JSON.stringify(configModule)};
export const handler = createCloudFrontHandler(config);
`;

await build({
  stdin: {
    contents: stdin,
    resolveDir: here,
    sourcefile: 'lambda-edge-entry.mjs',
    loader: 'js',
  },
  outfile: values.out,
  bundle: true,
  format: 'esm',
  platform: 'node',
  target: 'node22',
  logLevel: 'info',
  minify: values.minify,
});

console.log(`built ${values.out} from cloudfront-edge.ts + ${values.config}`);
