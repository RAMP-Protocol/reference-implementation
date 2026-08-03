import { describe, expect, it, vi } from 'vitest';

import { type Jwk, createKeyCache } from '../../src/keys.js';
import {
  type TestKeypair,
  generateKeypair,
  keyThumbprint,
  wbaDirectoryWithKeys,
} from '../helpers/ed25519.js';

const WBA_URL = 'https://exchange.test/.well-known/http-message-signatures-directory';

// Builds a fetcher that serves a WBA directory carrying the given JWKs and
// counts how many times it was invoked (to assert the no-fetch / one-shot-fetch
// contract). Keys carry NO kid — they are resolved by RFC 7638 thumbprint.
function wbaFetcher(jwks: Jwk[]): {
  fetcher: typeof fetch;
  calls: () => number;
} {
  const fn = vi.fn(async () => {
    const doc = wbaDirectoryWithKeys(jwks.map((k) => ({ kty: k.kty, crv: k.crv, x: k.x })));
    return new Response(JSON.stringify(doc), {
      status: 200,
      headers: { 'content-type': 'application/jwk-set+json' },
    });
  });
  return { fetcher: fn as unknown as typeof fetch, calls: () => fn.mock.calls.length };
}

function toJwk(publicJwk: JsonWebKey): Jwk {
  return { kty: 'OKP', crv: 'Ed25519', x: publicJwk.x ?? '' };
}

// assertResolvesToKey checks the cache resolved the SPECIFIC expected keypair,
// not merely "some key" — a keyid-matching regression that returned a different
// directory key would pass toBeDefined() but fail here. Proven by a
// sign(signer.private)/verify(resolved) round-trip, mirroring the Go
// TestRampWBA_KeyVerifiesOfferSignature.
async function assertResolvesToKey(
  resolved: CryptoKey | undefined,
  signer: TestKeypair,
): Promise<void> {
  if (!resolved) throw new Error('expected the cache to resolve a key');
  const msg = new TextEncoder().encode('ramp-edge-key-identity-round-trip');
  const sig = await crypto.subtle.sign('Ed25519', signer.privateKey, msg);
  expect(await crypto.subtle.verify('Ed25519', resolved, sig, msg)).toBe(true);
}

describe('createKeyCache — fetched WBA directory path', () => {
  it('resolves a keyid (thumbprint) from keys[] of the fetched WBA directory', async () => {
    const kp = await generateKeypair('exchange-primary');
    const tp = await keyThumbprint(kp);
    const { fetcher } = wbaFetcher([toJwk(kp.publicJwk)]);
    const cache = createKeyCache({ wbaUrl: WBA_URL, fetcher });

    // Assert IDENTITY, not just type: a regression that returned a different
    // directory key would still be a 'public' CryptoKey but fail the round-trip.
    await assertResolvesToKey(await cache.resolve(tp), kp);
  });

  it('falls back to the first key when keyid is undefined', async () => {
    const kp = await generateKeypair('exchange-primary');
    const { fetcher } = wbaFetcher([toJwk(kp.publicJwk)]);
    const cache = createKeyCache({ wbaUrl: WBA_URL, fetcher });

    await assertResolvesToKey(await cache.resolve(undefined), kp);
  });

  it('returns undefined for a keyid absent from the directory', async () => {
    const kp = await generateKeypair('exchange-primary');
    const { fetcher } = wbaFetcher([toJwk(kp.publicJwk)]);
    const cache = createKeyCache({ wbaUrl: WBA_URL, fetcher });

    expect(await cache.resolve('not-a-real-thumbprint')).toBeUndefined();
  });

  it('caches within the TTL — a second resolve does not refetch', async () => {
    const kp = await generateKeypair('exchange-primary');
    const tp = await keyThumbprint(kp);
    const { fetcher, calls } = wbaFetcher([toJwk(kp.publicJwk)]);
    const cache = createKeyCache({ wbaUrl: WBA_URL, fetcher });

    await cache.resolve(tp);
    await cache.resolve(tp);
    expect(calls()).toBe(1);
  });
});

describe('createKeyCache — RAMP_VERIFY_KEYS pre-provisioning (D5)', () => {
  it('resolves a pre-provisioned keyid WITHOUT fetching the directory', async () => {
    const kp = await generateKeypair('exchange-primary');
    const tp = await keyThumbprint(kp);
    const { fetcher, calls } = wbaFetcher([]); // would fail schema if hit
    const cache = createKeyCache({
      wbaUrl: WBA_URL,
      staticKeys: [toJwk(kp.publicJwk)],
      fetcher,
    });

    const key = await cache.resolve(tp);
    expect(key?.type).toBe('public');
    expect(calls()).toBe(0);
  });

  it('one-shot fetches the directory when a keyid misses the static set (rotation self-heal)', async () => {
    const provisioned = await generateKeypair('old');
    const provisionedTp = await keyThumbprint(provisioned);
    const rotated = await generateKeypair('new');
    const rotatedTp = await keyThumbprint(rotated);
    const { fetcher, calls } = wbaFetcher([toJwk(rotated.publicJwk)]);
    const cache = createKeyCache({
      wbaUrl: WBA_URL,
      staticKeys: [toJwk(provisioned.publicJwk)],
      fetcher,
    });

    // Provisioned thumbprint: no fetch, and it resolves to the PROVISIONED key.
    await assertResolvesToKey(await cache.resolve(provisionedTp), provisioned);
    expect(calls()).toBe(0);

    // Unknown (rotated) thumbprint: exactly one fetch, resolving to the ROTATED key.
    await assertResolvesToKey(await cache.resolve(rotatedTp), rotated);
    expect(calls()).toBe(1);
  });
});
