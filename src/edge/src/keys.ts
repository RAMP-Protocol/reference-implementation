import { z } from 'zod';

import { decodeBase64Url } from '@ramp-protocol/sdk-l1/base64url';
import { thumbprint } from '@ramp-protocol/sdk-l1/thumbprint';

import { type KeyCache, createKeyCache as createGenericKeyCache } from './keys-cache.js';

// Re-exported so callers depend on one name for the cache type regardless of
// which runtime configuration (CryptoKey here, raw bytes in the Fastly shim)
// produced it.
export type { KeyCache } from './keys-cache.js';

// A single Ed25519 JWK as published in a RAMP Web Bot Auth directory's keys[]
// (kty=OKP, crv=Ed25519). After the WBA split there is NO kid — a key is named
// by its RFC 7638 thumbprint. use/alg/not_before/not_after may be present; the
// edge ignores the time bounds — the signed URL's own `exp` governs expiry.
// Exported so the pre-provisioned-keys path (config.ts) validates against the
// same shape the fetched-directory path uses, rather than a drifting private
// copy.
export const JwkSchema = z.object({
  kty: z.literal('OKP'),
  crv: z.literal('Ed25519'),
  x: z.string().min(1),
  alg: z.string().optional(),
  use: z.string().optional(),
  not_before: z.string().optional(),
  not_after: z.string().optional(),
});

// Upper bound on a directory / pre-provisioned key set, mirroring the Go
// schema's maxItems (internal/rampwellknown/schema/ramp-wba-directory.json). A
// directory holds only a handful of keys, so a larger array is malformed; the
// bound complements the 64 KiB body cap by bounding parse work per entry count.
export const MAX_WBA_KEYS = 64;

// The fetched document is the producer's Web Bot Auth directory
// (/.well-known/http-message-signatures-directory), whose keys[] carries the
// signing JWKs. A directory-level revocation_url may also be present; the edge
// verify path ignores it (revocation is enforced upstream by the Go loader).
const WbaFileSchema = z.object({
  keys: z.array(JwkSchema).min(1).max(MAX_WBA_KEYS),
});

export type Jwk = z.infer<typeof JwkSchema>;

export interface KeyCacheDeps {
  // Absolute URL of the producer's WBA directory
  // (/.well-known/http-message-signatures-directory). Fetched to resolve a keyid
  // (RFC 7638 thumbprint) that the pre-provisioned static set (if any) does not
  // cover.
  wbaUrl: string;
  // Optional pre-provisioned verify keys (D5). When supplied and they cover the
  // requested keyid, the directory is NOT fetched. A keyid that misses the
  // static set triggers a one-shot directory fetch (rotation self-heal).
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

// keyId computes a JWK's map key: the RFC 7638 thumbprint of its raw Ed25519
// public key. This is the RFC 9421 keyid a request carries, so the fetched
// directory (which publishes no kid) is keyed the same way the incoming keyid
// is matched. Exported as the single source of the "reject an `x` that is not
// valid base64url before thumbprinting" rule; consumers that cannot import this
// module (the Fastly E2E shim, which must not bundle zod — a transitive import
// here) mirror the same validation rather than duplicate a silent-accept keyer.
export async function keyId(jwk: Jwk): Promise<string> {
  const raw = decodeBase64Url(jwk.x);
  if (!raw) throw new Error('keys: JWK `x` is not valid base64url');
  return thumbprint(raw);
}

// createKeyCache wires the verify-agnostic cache core (keys-cache.ts) with the
// production import primitive — crypto.subtle.importKey → CryptoKey — the
// thumbprint keyer, and the zod-validated parser. Cloudflare's full WebCrypto
// runtime verifies via crypto.subtle against these CryptoKeys; the Fastly
// Compute shim wires the same core with a raw-bytes import + a dependency-free
// parser instead, because its SubtleCrypto lacks Ed25519.
export function createKeyCache(deps: KeyCacheDeps): KeyCache<CryptoKey> {
  return createGenericKeyCache<CryptoKey, Jwk>({
    wbaUrl: deps.wbaUrl,
    keyId,
    importJwk,
    parseKeys: (json) => WbaFileSchema.parse(json).keys,
    ...(deps.staticKeys !== undefined ? { staticKeys: deps.staticKeys } : {}),
    ...(deps.fetcher !== undefined ? { fetcher: deps.fetcher } : {}),
    ...(deps.now !== undefined ? { now: deps.now } : {}),
    ...(deps.ttlMs !== undefined ? { ttlMs: deps.ttlMs } : {}),
  });
}
