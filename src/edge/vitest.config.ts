import { cloudflareTest } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

// One config, four projects (vitest `test.projects`) — each project's
// membership is its test DIRECTORY, so there are no hand-mirrored
// include/exclude lists to keep in sync:
//
//   tests/workers/       real Workers runtime, binding enforcement ON,
//                        origin configured (mocked per test via the shared
//                        fetch-mock helper)
//   tests/article-path/  same runtime, the shared-URL four-outcome acceptance
//                        suite against a mocked origin backend
//   tests/node/          plain Node: fs-reading parity/schema guards, the
//                        console-spy log suites, and the programmatic AWS
//                        Lambda / Fastly harnesses (no CLI dependencies)
//
// Run one project with `vitest run --project <name>`.

const WORKERS_COMPAT = {
  compatibilityDate: '2026-07-01',
  compatibilityFlags: ['nodejs_compat'],
};

// Bindings shared by every Workers-runtime posture. Origin-mode note: the
// Cloudflare entry refuses to run without ORIGIN_URL or SAME_ZONE_ORIGIN;
// suites mock the origin host via the shared fetch-mock helper
// (setupOriginMock or per-test intercepts).
const BASE_BINDINGS = {
  EXCHANGE_URL: 'https://exchange.test',
  EXCHANGE_WBA_URL: 'https://exchange.test/.well-known/http-message-signatures-directory',
  RSL_BODY: '# test rsl',
  ACME_TOKENS_JSON: '{"demo":"response-body"}',
  PROVIDER: 'pub.test',
  EXCHANGES_JSON:
    '[{"domain":"exchange.test","endpoint":"https://exchange.test","supported_profiles":["ramp-news-v1"]}]',
  ORIGIN_URL: 'https://origin.pub.test',
};

// The publisher edge's own WBA directory (a self-signed signing key, no kid),
// served at /.well-known/http-message-signatures-directory.
const WBA_KEYS_JSON =
  '[{"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","not_before":"2020-01-01T00:00:00Z","not_after":"2100-01-01T00:00:00Z"}]';

// A Workers-runtime project: the name doubles as the test directory, the
// bindings define the posture. cloudflareTest is the pool-workers Vite
// plugin (the vitest-4 replacement for defineWorkersProject).
function workersProject(name: string, bindings: Record<string, string>) {
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: './wrangler.toml' },
        miniflare: { ...WORKERS_COMPAT, bindings },
      }),
    ],
    test: {
      name,
      include: [`tests/${name}/**/*.test.ts`],
    },
  };
}

export default defineConfig({
  test: {
    projects: [
      // No project sets RAMP_ENFORCE_BINDING, deliberately: leaving it unset is
      // what makes these suites run against the PRODUCTION default (on), so a
      // change to that default surfaces here rather than only in config.test.ts.
      workersProject('workers', { ...BASE_BINDINGS, WBA_KEYS_JSON }),
      workersProject('article-path', BASE_BINDINGS),
      {
        test: {
          name: 'node',
          environment: 'node',
          include: ['tests/node/**/*.test.ts'],
        },
      },
    ],
  },
});
