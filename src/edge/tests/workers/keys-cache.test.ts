import { describe, expect, it, vi } from 'vitest';

import { createKeyCache } from '../../src/keys-cache.js';

// Exercises the verify-agnostic cache core directly with a raw-bytes import
// primitive and a stub key-id — the shape the Fastly shim uses (its SubtleCrypto
// can't import Ed25519, so keys are kept as raw 32-byte values). The production
// CryptoKey + thumbprint configuration is covered by keys.test.ts via keys.ts.
// A WBA key carries no kid, so the map key is supplied by the injected `keyId`;
// here it is a stub `id` field to keep the test focused on the cache mechanics
// (TTL, single-flight, default fallback) rather than thumbprint computation.

interface RawJwk {
  id: string;
  x: string;
  kty?: string;
  crv?: string;
}

const WBA_URL = 'https://exchange.test/.well-known/http-message-signatures-directory';

function wbaFetcher(jwks: RawJwk[]): { fetcher: typeof fetch; calls: () => number } {
  const fn = vi.fn(async () => {
    return new Response(JSON.stringify({ keys: jwks }), {
      status: 200,
      headers: { 'content-type': 'application/jwk-set+json' },
    });
  });
  return { fetcher: fn as unknown as typeof fetch, calls: () => fn.mock.calls.length };
}

function rawBytesCache(fetcher: typeof fetch, opts?: { now?: () => number; ttlMs?: number }) {
  return createKeyCache<Uint8Array, RawJwk>({
    wbaUrl: WBA_URL,
    keyId: (jwk) => Promise.resolve(jwk.id),
    importJwk: (jwk) => Promise.resolve(new TextEncoder().encode(jwk.x)),
    parseKeys: (json) =>
      ((json as { keys?: RawJwk[] }).keys ?? []).filter(
        (k) => k.kty === 'OKP' && k.crv === 'Ed25519',
      ),
    fetcher,
    ...opts,
  });
}

const KEY: RawJwk = { id: 'exchange-primary', x: 'cHViLWJ5dGVz', kty: 'OKP', crv: 'Ed25519' };

describe('keys-cache — raw-bytes import primitive', () => {
  it('resolves a keyid to the imported raw bytes', async () => {
    const { fetcher } = wbaFetcher([KEY]);
    const cache = rawBytesCache(fetcher);
    const bytes = await cache.resolve('exchange-primary');
    expect(bytes).toEqual(new TextEncoder().encode(KEY.x));
  });

  it('falls back to the first key when keyid is undefined', async () => {
    const { fetcher } = wbaFetcher([KEY]);
    // Assert the fallback returns the FIRST key's bytes, not merely "something":
    // a bug returning an empty/other buffer would still be defined.
    expect(await rawBytesCache(fetcher).resolve(undefined)).toEqual(
      new TextEncoder().encode(KEY.x),
    );
  });

  it('returns undefined for an unknown keyid', async () => {
    const { fetcher } = wbaFetcher([KEY]);
    expect(await rawBytesCache(fetcher).resolve('nope')).toBeUndefined();
  });

  it('caches within the TTL — a second resolve does not refetch', async () => {
    const { fetcher, calls } = wbaFetcher([KEY]);
    const cache = rawBytesCache(fetcher);
    await cache.resolve('exchange-primary');
    await cache.resolve('exchange-primary');
    expect(calls()).toBe(1);
  });

  it('refetches after the TTL expires', async () => {
    let clock = 1_000;
    const { fetcher, calls } = wbaFetcher([KEY]);
    const cache = rawBytesCache(fetcher, { now: () => clock, ttlMs: 50 });

    await cache.resolve('exchange-primary');
    expect(calls()).toBe(1);

    clock += 51; // advance past ttlMs
    await cache.resolve('exchange-primary');
    expect(calls()).toBe(2);
  });

  it('single-flights concurrent cold-cache resolves into one fetch', async () => {
    const { fetcher, calls } = wbaFetcher([KEY]);
    const cache = rawBytesCache(fetcher);
    await Promise.all([
      cache.resolve('exchange-primary'),
      cache.resolve('exchange-primary'),
      cache.resolve('exchange-primary'),
    ]);
    expect(calls()).toBe(1);
  });
});

// A ReadableStream body keeps a manually-set Content-Length from being recomputed
// by the runtime, letting these tests drive the header short-circuit and the
// streamed-body cap independently.
function streamResponse(body: Uint8Array, contentLength?: string): Response {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(body);
      controller.close();
    },
  });
  const headers = new Headers({ 'content-type': 'application/jwk-set+json' });
  if (contentLength !== undefined) headers.set('content-length', contentLength);
  return new Response(stream, { status: 200, headers });
}

// The cache caps a fetched WBA directory at 64 KiB (mirroring the Go loader's
// maxDocBytes) so a compromised/hostile origin cannot OOM the worker by streaming
// an unbounded body into the JSON parse.
describe('keys-cache — WBA directory response-size bound', () => {
  const CAP = 64 * 1024;

  it('rejects on an over-cap Content-Length before reading the body', async () => {
    const small = new TextEncoder().encode(JSON.stringify({ keys: [KEY] }));
    const fetcher = vi.fn(async () =>
      streamResponse(small, String(CAP + 1)),
    ) as unknown as typeof fetch;
    await expect(rawBytesCache(fetcher).resolve('exchange-primary')).rejects.toThrow(/too large/i);
  });

  it('rejects a body that streams past the cap even when Content-Length under-reports', async () => {
    const oversize = new TextEncoder().encode(`{"keys":[{"id":"x","x":"${'A'.repeat(CAP + 8)}"}]}`);
    const fetcher = vi.fn(async () => streamResponse(oversize, '16')) as unknown as typeof fetch;
    await expect(rawBytesCache(fetcher).resolve('exchange-primary')).rejects.toThrow(/too large/i);
  });

  it('accepts and parses a normal-sized directory streamed under the cap', async () => {
    const body = new TextEncoder().encode(JSON.stringify({ keys: [KEY] }));
    const fetcher = vi.fn(async () => streamResponse(body)) as unknown as typeof fetch;
    expect(await rawBytesCache(fetcher).resolve('exchange-primary')).toEqual(
      new TextEncoder().encode(KEY.x),
    );
  });
});
