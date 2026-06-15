import { defineConfig } from 'vitest/config';

// Node-environment runner for tests that need fs / CommonJS deps (ajv) the
// Cloudflare Workers pool can't host — currently the canonical-schema
// conformance check. Kept separate from the Workers-pooled default config.
//
// CI MUST invoke BOTH this config and vitest.config.ts (the package.json "test"
// script chains them): the cross-language parity specs run here in Node while
// the edge-enforcement e2e runs in the Workers pool, so a CI that skips either
// config silently drops half the TypeScript coverage.
export default defineConfig({
  test: {
    environment: 'node',
    // The parity specs read the shared repo-root fixtures via fs, so they run in
    // Node alongside the canonical-schema check rather than the Workers pool.
    include: [
      'tests/manifest-schema.test.ts',
      'tests/thumbprint.test.ts',
      'tests/signature-base.test.ts',
    ],
  },
});
