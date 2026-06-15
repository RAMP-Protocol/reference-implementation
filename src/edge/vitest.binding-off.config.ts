import { defineWorkersConfig } from '@cloudflare/vitest-pool-workers/config';

// Workers-pool config for the enforcement-OFF (bearer) default posture, ADR-013
// D6.1. Identical to vitest.config.ts EXCEPT RAMP_ENFORCE_BINDING is 'false'
// (the production/compose default) and it runs only e2e.bearerdefault.test.ts,
// which the default config excludes (that one runs with enforcement ON). This
// pins the default path: a bound URL with no proof is served as a bearer
// credential, not 403'd.
export default defineWorkersConfig({
  test: {
    include: ['tests/e2e.bearerdefault.test.ts'],
    poolOptions: {
      workers: {
        wrangler: { configPath: './wrangler.toml' },
        miniflare: {
          compatibilityDate: '2025-01-15',
          compatibilityFlags: ['nodejs_compat'],
          bindings: {
            EXCHANGE_URL: 'https://exchange.test',
            EXCHANGE_MANIFEST_URL: 'https://exchange.test/.well-known/ramp.json',
            RSL_BODY: '# test rsl',
            ACME_TOKENS_JSON: '{"demo":"response-body"}',
            PROVIDER: 'pub.test',
            EXCHANGES_JSON:
              '[{"domain":"exchange.test","endpoint":"https://exchange.test","supported_profiles":["ramp-news-v1"]}]',
            // Production/compose default — opt-in enforcement stays OFF here.
            RAMP_ENFORCE_BINDING: 'false',
          },
        },
      },
    },
  },
});
