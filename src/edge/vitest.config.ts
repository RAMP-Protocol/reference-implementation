import { defineWorkersConfig } from '@cloudflare/vitest-pool-workers/config';

export default defineWorkersConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    exclude: ['tests/e2e.aws.test.ts', 'tests/e2e.fastly.test.ts'],
    poolOptions: {
      workers: {
        wrangler: { configPath: './wrangler.toml' },
        miniflare: {
          compatibilityDate: '2025-01-15',
          compatibilityFlags: ['nodejs_compat'],
          bindings: {
            EXCHANGE_URL: 'https://exchange.test',
            MARKETPLACE_MANIFEST_URL: 'https://exchange.test/.well-known/ramp-marketplace.json',
            JWKS_URL: 'https://exchange.test/.well-known/jwks.json',
            RSL_BODY: '# test rsl',
            ACME_TOKENS_JSON: '{"demo":"response-body"}',
            PROVIDER: 'pub.test',
            EXCHANGES_JSON:
              '[{"domain":"exchange.test","endpoint":"https://exchange.test","supported_profiles":["ramp-news-v1"]}]',
            // Free-index fast path (ADR-015). BOT_JWKS_URL is intercepted in the
            // WBA test; ORIGIN_URL is intentionally left unset so the fast path
            // returns 200 + D4 headers without an origin fetch.
            BOT_JWKS_URL: 'https://bot.test/.well-known/jwks.json',
            FREE_RULES_JSON:
              '[{"pathPattern":"/articles/philosophers/*","renditionReplace":["\\\\.txt$",".md"],"licenseId":"tdl:free-index-v1","contentUsage":"ai-index=y","contentHash":"sha256-demo"}]',
          },
        },
      },
    },
  },
});
