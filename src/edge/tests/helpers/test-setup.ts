// Path the edge fetches to resolve the exchange's delivery-URL verify key after
// the WBA split (its offer-signing key lives in the WBA directory, not ramp.json).
// Single-sourced from the production module (re-exported below for consumers) so
// the test path can never drift from the route the worker actually serves.
import { expect } from 'vitest';

import { SIGNATURE_PARAMS } from '../../src/app.js';
import { WBA_PATH } from '../../src/well-known.mjs';
import type { TestKeypair } from './ed25519.js';
import { generateKeypair, keyThumbprint, wbaDirectoryWithKeys } from './ed25519.js';
// Shared test setup for E2E tests
import { fetchMock } from './fetch-mock.js';

export const PUB_ORIGIN = 'https://pub.example.com';

export { WBA_PATH };

// expectNoSignatureParams asserts a URL forwarded to the origin carries none
// of the reserved signature params — keyed off the PRODUCTION list, so a param
// added there is covered here automatically and the suites cannot drift from
// each other (one once asserted three of the four names).
export function expectNoSignatureParams(url: string | URL): void {
  const u = typeof url === 'string' ? new URL(url) : url;
  for (const p of SIGNATURE_PARAMS) {
    expect(u.searchParams.has(p), `reserved param ${p} leaked to the origin`).toBe(false);
  }
}

// Minimum env the CONFIG SCHEMA accepts — shared by the config-surface suites
// (config.test.ts extends it per case; manifest-parity adds WBA_KEYS_JSON).
// Scope note: this is deliberately NOT the runtime suites' env. Those need
// https://exchange.test URLs (to line up with the fetch-mock origins) and
// their own PROVIDER values that the tests assert on — sharing this fixture
// there would mean overriding every field.
export const BASE_SCHEMA_ENV = {
  EXCHANGE_URL: 'http://exchange:8081',
  EXCHANGE_WBA_URL: 'http://exchange:8081/.well-known/http-message-signatures-directory',
  PROVIDER: 'edge.e2e.local',
  EXCHANGES_JSON: JSON.stringify([
    {
      domain: 'exchange.e2e.local',
      endpoint: 'http://exchange:8081',
      supported_profiles: ['ramp-news-v1'],
    },
  ]),
};

/**
 * Standard test setup for E2E tests: the exchange keypair (with its thumbprint
 * kid, since every suite needs both) and the fetch mock armed with net connect
 * disabled. Call from beforeAll.
 */
export async function setupE2ETest(): Promise<{ keypair: TestKeypair; exchangeKid: string }> {
  const keypair = await generateKeypair('k1');
  const exchangeKid = await keyThumbprint(keypair);
  fetchMock.activate();
  fetchMock.disableNetConnect();
  return { keypair, exchangeKid };
}

/**
 * Setup fetchMock intercept for the exchange's WBA directory endpoint. The edge
 * resolves the delivery-URL verify key by fetching this directory and matching
 * the URL's `kid` (RFC 7638 thumbprint) against a locally-computed thumbprint of
 * each published key. Call from beforeEach hook after setupE2ETest.
 */
/**
 * Persistent catch-all intercept for the pass-through origin the test pools
 * configure as ORIGIN_URL. Replies with an empty 200 for any path — enough for
 * suites that assert verification outcomes by status. Byte-level origin-body
 * assertions live in the article-path suite, which registers its own
 * per-test intercepts instead.
 */
export function setupOriginMock(): void {
  fetchMock
    .get('https://origin.pub.test')
    .intercept({ path: /.*/, method: 'GET' })
    .reply(200, '')
    .persist();
}

export function setupWbaDirectoryMock(keypair: TestKeypair): void {
  fetchMock
    .get('https://exchange.test')
    .intercept({ path: WBA_PATH, method: 'GET' })
    .reply(200, wbaDirectoryWithKeys([keypair.publicJwk]), {
      headers: { 'content-type': 'application/jwk-set+json' },
    })
    .persist();
}
