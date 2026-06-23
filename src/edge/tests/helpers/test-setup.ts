// Shared test setup for E2E tests
import { fetchMock } from 'cloudflare:test';
import type { TestKeypair } from './ed25519.js';
import { generateKeypair, manifestWithKeys } from './ed25519.js';

export const PUB_ORIGIN = 'https://pub.example.com';

/**
 * Standard test setup for E2E tests that need a keypair and mocked ramp.json.
 * Call from beforeAll and beforeEach hooks.
 */
export async function setupE2ETest(): Promise<TestKeypair> {
  const keypair = await generateKeypair('k1');
  fetchMock.activate();
  fetchMock.disableNetConnect();
  return keypair;
}

/**
 * Setup fetchMock intercept for /.well-known/ramp.json endpoint.
 * Call from beforeEach hook after setupE2ETest.
 */
export function setupRampJsonMock(keypair: TestKeypair): void {
  fetchMock
    .get('https://exchange.test')
    .intercept({ path: '/.well-known/ramp.json', method: 'GET' })
    .reply(200, manifestWithKeys([keypair.publicJwk]), {
      headers: { 'content-type': 'application/json' },
    })
    .persist();
}
