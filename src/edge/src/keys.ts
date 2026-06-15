import { z } from 'zod';

import { type KeyCache, createKeyCache as createGenericKeyCache } from './keys-cache.js';

// Re-exported so callers depend on one name for the cache type regardless of
// which runtime configuration (CryptoKey here, raw bytes in the Fastly shim)
// produced it.
export type { KeyCache } from './keys-cache.js';

// A single inline Ed25519 JWK as published in the RAMP manifest's public_keys[]
// (kty=OKP, crv=Ed25519). use/alg/not_before/not_after may be present; the edge
// ignores the time bounds — the signed URL's own `exp` governs expiry. Exported
// so the pre-provisioned-keys path (config.ts) validates against the same shape
// the fetched-manifest path uses, rather than a drifting private copy.
export const JwkSchema = z.object({
  kty: z.literal('OKP'),
  crv: z.literal('Ed25519'),
  kid: z.string().min(1),
  x: z.string().min(1),
  alg: z.string().optional(),
  use: z.string().optional(),
  not_before: z.string().optional(),
  not_after: z.string().optional(),
});

// The fetched document is the producer's unified manifest
// (/.well-known/ramp.json), whose public_keys[] carries the signing JWKs.
const ManifestKeysSchema = z.object({
  public_keys: z.array(JwkSchema).min(1),
});

export type Jwk = z.infer<typeof JwkSchema>;

export interface KeyCacheDeps {
  // Absolute URL of the producer's /.well-known/ramp.json. Fetched to resolve a
  // kid that the pre-provisioned static set (if any) does not cover.
  manifestUrl: string;
  // Optional pre-provisioned verify keys (D5). When supplied and they cover the
  // requested kid, the manifest is NOT fetched. A kid that misses the static
  // set triggers a one-shot manifest fetch (rotation self-heal).
  staticKeys?: Jwk[];
  fetcher?: typeof fetch;
  now?: () => number;
  ttlMs?: number;
}

async function importJwk(jwk: Jwk): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk',
    { kty: jwk.kty, crv: jwk.crv, x: jwk.x },
    { name: 'Ed25519' },
    false,
    ['verify'],
  );
}

// createKeyCache wires the verify-agnostic cache core (keys-cache.ts) with the
// production import primitive — crypto.subtle.importKey → CryptoKey — and the
// zod-validated parser. Cloudflare's full WebCrypto runtime verifies via
// crypto.subtle against these CryptoKeys; the Fastly Compute shim wires the same
// core with a raw-bytes import + a dependency-free parser instead, because its
// SubtleCrypto lacks Ed25519.
export function createKeyCache(deps: KeyCacheDeps): KeyCache<CryptoKey> {
  return createGenericKeyCache<CryptoKey, Jwk>({
    manifestUrl: deps.manifestUrl,
    importJwk,
    parseKeys: (json) => ManifestKeysSchema.parse(json).public_keys,
    ...(deps.staticKeys !== undefined ? { staticKeys: deps.staticKeys } : {}),
    ...(deps.fetcher !== undefined ? { fetcher: deps.fetcher } : {}),
    ...(deps.now !== undefined ? { now: deps.now } : {}),
    ...(deps.ttlMs !== undefined ? { ttlMs: deps.ttlMs } : {}),
  });
}
