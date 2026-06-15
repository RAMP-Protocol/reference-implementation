import { defineWorkersConfig } from '@cloudflare/vitest-pool-workers/config';

export default defineWorkersConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    // manifest-schema runs in Node (ajv + fs read the canonical Go schema),
    // which the Workers pool can't host; it runs via vitest.node.config.ts.
    exclude: [
      'tests/e2e.aws.test.ts',
      'tests/e2e.fastly.test.ts',
      'tests/manifest-schema.test.ts',
      'tests/thumbprint.test.ts',
      // Reads the repo-root fixture via node:fs/node:url; runs in the Node pool
      // (vitest.node.config.ts), which the Workers pool can't host.
      'tests/signature-base.test.ts',
      // Runs under vitest.binding-off.config.ts (RAMP_ENFORCE_BINDING='false');
      // it must NOT run here, where enforcement is ON.
      'tests/e2e.bearerdefault.test.ts',
    ],
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
            // Enable binding enforcement in the edge test harness so the
            // proof-of-possession e2e (agent-key binding) exercises the enforce
            // path. Production/compose default OFF (opt-in, ADR-013 D6).
            RAMP_ENFORCE_BINDING: 'true',
          },
        },
      },
    },
  },
});
