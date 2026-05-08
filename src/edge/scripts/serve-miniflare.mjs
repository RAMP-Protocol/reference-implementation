// Serve a pre-built worker bundle via Miniflare for local E2E / docker use.
// Reads env vars and exposes them to the worker as bindings, matching the
// shape parseEnv() expects in src/config.ts.
//
// Usage:
//   EXCHANGE_URL=... ORIGIN_URL=... node scripts/serve-miniflare.mjs

import process from 'node:process';
import { Miniflare } from 'miniflare';

const port = Number.parseInt(process.env.PORT ?? '8787', 10);

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    console.error(`missing required env ${name}`);
    process.exit(2);
  }
  return value;
}

const mf = new Miniflare({
  modules: true,
  scriptPath: process.env.WORKER_SCRIPT ?? 'dist/worker.mjs',
  host: '0.0.0.0',
  port,
  compatibilityDate: '2024-12-30',
  compatibilityFlags: ['nodejs_compat'],
  bindings: {
    EXCHANGE_URL: requireEnv('EXCHANGE_URL'),
    JWKS_URL: requireEnv('JWKS_URL'),
    MARKETPLACE_MANIFEST_URL: requireEnv('MARKETPLACE_MANIFEST_URL'),
    ORIGIN_URL: requireEnv('ORIGIN_URL'),
    PROVIDER: requireEnv('PROVIDER'),
    EXCHANGES_JSON: requireEnv('EXCHANGES_JSON'),
    RSL_BODY: process.env.RSL_BODY ?? '',
    ACME_TOKENS_JSON: process.env.ACME_TOKENS_JSON ?? '{}',
  },
});

await mf.ready;
const url = await mf.ready;
console.log(`miniflare ready on ${url?.href ?? `http://0.0.0.0:${port}`}`);

const shutdown = async () => {
  await mf.dispose();
  process.exit(0);
};
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
