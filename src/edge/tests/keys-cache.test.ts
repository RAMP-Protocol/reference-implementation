import { describe, expect, it, vi } from 'vitest';

import { createKeyCache } from '../src/keys-cache.js';

// Exercises the verify-agnostic cache core directly with a raw-bytes import
// primitive — the configuration the Fastly shim uses (its SubtleCrypto can't
// import Ed25519, so keys are kept as raw 32-byte values). The production
// CryptoKey configuration is covered by keys.test.ts via keys.ts.

interface RawJwk {
  kid: string;
  x: string;
  kty?: string;
  crv?: string;
}

const MANIFEST_URL = 'https://exchange.test/.well-known/ramp.json';

function manifestFetcher(jwks: RawJwk[]): { fetcher: typeof fetch; calls: () => number } {
  const fn = vi.fn(async () => {
    return new Response(JSON.stringify({ public_keys: jwks }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  });
  return { fetcher: fn as unknown as typeof fetch, calls: () => fn.mock.calls.length };
}

function rawBytesCache(fetcher: typeof fetch, opts?: { now?: () => number; ttlMs?: number }) {
  return createKeyCache<Uint8Array, RawJwk>({
    manifestUrl: MANIFEST_URL,
    importJwk: (jwk) => Promise.resolve(new TextEncoder().encode(jwk.x)),
    parseKeys: (json) =>
      ((json as { public_keys?: RawJwk[] }).public_keys ?? []).filter(
        (k) => k.kty === 'OKP' && k.crv === 'Ed25519',
      ),
    fetcher,
    ...opts,
  });
}

const KEY: RawJwk = { kid: 'exchange-primary', x: 'cHViLWJ5dGVz', kty: 'OKP', crv: 'Ed25519' };

describe('keys-cache — raw-bytes import primitive', () => {
  it('resolves a kid to the imported raw bytes', async () => {
    const { fetcher } = manifestFetcher([KEY]);
    const cache = rawBytesCache(fetcher);
    const bytes = await cache.resolve('exchange-primary');
    expect(bytes).toEqual(new TextEncoder().encode(KEY.x));
  });

  it('falls back to the first key when kid is undefined', async () => {
    const { fetcher } = manifestFetcher([KEY]);
    expect(await rawBytesCache(fetcher).resolve(undefined)).toBeDefined();
  });

  it('returns undefined for an unknown kid', async () => {
    const { fetcher } = manifestFetcher([KEY]);
    expect(await rawBytesCache(fetcher).resolve('nope')).toBeUndefined();
  });

  it('caches within the TTL — a second resolve does not refetch', async () => {
    const { fetcher, calls } = manifestFetcher([KEY]);
    const cache = rawBytesCache(fetcher);
    await cache.resolve('exchange-primary');
    await cache.resolve('exchange-primary');
    expect(calls()).toBe(1);
  });

  it('refetches after the TTL expires', async () => {
    let clock = 1_000;
    const { fetcher, calls } = manifestFetcher([KEY]);
    const cache = rawBytesCache(fetcher, { now: () => clock, ttlMs: 50 });

    await cache.resolve('exchange-primary');
    expect(calls()).toBe(1);

    clock += 51; // advance past ttlMs
    await cache.resolve('exchange-primary');
    expect(calls()).toBe(2);
  });

  it('single-flights concurrent cold-cache resolves into one fetch', async () => {
    const { fetcher, calls } = manifestFetcher([KEY]);
    const cache = rawBytesCache(fetcher);
    await Promise.all([
      cache.resolve('exchange-primary'),
      cache.resolve('exchange-primary'),
      cache.resolve('exchange-primary'),
    ]);
    expect(calls()).toBe(1);
  });
});
