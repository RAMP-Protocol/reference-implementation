import { describe, expect, it, vi } from 'vitest';

import { type Jwk, createKeyCache } from '../src/keys.js';
import { generateKeypair, manifestWithKeys } from './helpers/ed25519.js';

const MANIFEST_URL = 'https://exchange.test/.well-known/ramp.json';

// Builds a fetcher that serves a ramp.json manifest carrying the given JWKs and
// counts how many times it was invoked (to assert the no-fetch / one-shot-fetch
// contract).
function manifestFetcher(jwks: Jwk[]): {
  fetcher: typeof fetch;
  calls: () => number;
} {
  const fn = vi.fn(async () => {
    const doc = manifestWithKeys(jwks.map((k) => ({ kty: k.kty, crv: k.crv, kid: k.kid, x: k.x })));
    return new Response(JSON.stringify(doc), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  });
  return { fetcher: fn as unknown as typeof fetch, calls: () => fn.mock.calls.length };
}

function toJwk(publicJwk: JsonWebKey & { kid: string }): Jwk {
  return { kty: 'OKP', crv: 'Ed25519', kid: publicJwk.kid, x: publicJwk.x ?? '' };
}

describe('createKeyCache — fetched manifest path', () => {
  it('resolves a kid from public_keys[] of the fetched ramp.json', async () => {
    const kp = await generateKeypair('exchange-primary');
    const { fetcher } = manifestFetcher([toJwk(kp.publicJwk)]);
    const cache = createKeyCache({ manifestUrl: MANIFEST_URL, fetcher });

    const key = await cache.resolve('exchange-primary');
    expect(key?.type).toBe('public');
  });

  it('falls back to the first key when kid is undefined', async () => {
    const kp = await generateKeypair('exchange-primary');
    const { fetcher } = manifestFetcher([toJwk(kp.publicJwk)]);
    const cache = createKeyCache({ manifestUrl: MANIFEST_URL, fetcher });

    const key = await cache.resolve(undefined);
    expect(key?.type).toBe('public');
  });

  it('returns undefined for a kid absent from the manifest', async () => {
    const kp = await generateKeypair('exchange-primary');
    const { fetcher } = manifestFetcher([toJwk(kp.publicJwk)]);
    const cache = createKeyCache({ manifestUrl: MANIFEST_URL, fetcher });

    expect(await cache.resolve('nope')).toBeUndefined();
  });

  it('caches within the TTL — a second resolve does not refetch', async () => {
    const kp = await generateKeypair('exchange-primary');
    const { fetcher, calls } = manifestFetcher([toJwk(kp.publicJwk)]);
    const cache = createKeyCache({ manifestUrl: MANIFEST_URL, fetcher });

    await cache.resolve('exchange-primary');
    await cache.resolve('exchange-primary');
    expect(calls()).toBe(1);
  });
});

describe('createKeyCache — RAMP_VERIFY_KEYS pre-provisioning (D5)', () => {
  it('resolves a pre-provisioned kid WITHOUT fetching the manifest', async () => {
    const kp = await generateKeypair('exchange-primary');
    const { fetcher, calls } = manifestFetcher([]); // would fail schema if hit
    const cache = createKeyCache({
      manifestUrl: MANIFEST_URL,
      staticKeys: [toJwk(kp.publicJwk)],
      fetcher,
    });

    const key = await cache.resolve('exchange-primary');
    expect(key?.type).toBe('public');
    expect(calls()).toBe(0);
  });

  it('one-shot fetches the manifest when a kid misses the static set (rotation self-heal)', async () => {
    const provisioned = await generateKeypair('old-kid');
    const rotated = await generateKeypair('new-kid');
    const { fetcher, calls } = manifestFetcher([toJwk(rotated.publicJwk)]);
    const cache = createKeyCache({
      manifestUrl: MANIFEST_URL,
      staticKeys: [toJwk(provisioned.publicJwk)],
      fetcher,
    });

    // Provisioned kid: no fetch.
    expect(await cache.resolve('old-kid')).toBeDefined();
    expect(calls()).toBe(0);

    // Unknown (rotated) kid: exactly one fetch, then served from the manifest.
    expect(await cache.resolve('new-kid')).toBeDefined();
    expect(calls()).toBe(1);
  });
});
