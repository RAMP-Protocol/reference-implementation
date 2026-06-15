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
    // EXCHANGE_MANIFEST_URL points at the Exchange's /.well-known/ramp.json;
    // the worker resolves signed-URL verify keys from its public_keys[]. The
    // old JWKS_URL binding is gone (jwks.json was collapsed into ramp.json).
    EXCHANGE_MANIFEST_URL: requireEnv('EXCHANGE_MANIFEST_URL'),
    ORIGIN_URL: requireEnv('ORIGIN_URL'),
    PROVIDER: requireEnv('PROVIDER'),
    EXCHANGES_JSON: requireEnv('EXCHANGES_JSON'),
    RSL_BODY: process.env.RSL_BODY ?? '',
    ACME_TOKENS_JSON: process.env.ACME_TOKENS_JSON ?? '{}',
    // Optional; enables Gate 2 (CatalogService contributor authorization)
    // when the deploy lists authorized third-party catalog pushers.
    CATALOG_CONTRIBUTORS_JSON: process.env.CATALOG_CONTRIBUTORS_JSON ?? '',
    // Optional D5 pre-provisioned verify keys (inline JWK array). Passed only
    // when set so the worker falls back to fetching ramp.json otherwise.
    ...(process.env.RAMP_VERIFY_KEYS ? { RAMP_VERIFY_KEYS: process.env.RAMP_VERIFY_KEYS } : {}),
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
