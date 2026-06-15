// Verify-agnostic manifest key cache. It fetches a producer's
// /.well-known/ramp.json, parses its public_keys[], imports each JWK into a
// runtime key type K, and caches the kid→K map with a TTL, single-flight
// de-duplication, optional pre-provisioned static keys, and one-shot rotation
// self-heal.
//
// The two runtime-specific steps are injected so the same fetch/cache logic
// serves every edge runtime without pulling a verify primitive or a schema
// library into this module:
//
//   * importJwk — how a JWK becomes a usable key. Full-WebCrypto runtimes
//     (Cloudflare) import to a CryptoKey via crypto.subtle.importKey; Fastly
//     Compute (whose SubtleCrypto lacks Ed25519) decodes `x` to raw bytes for
//     @noble/ed25519.
//   * parseKeys — how the fetched document yields the JWK list (a zod schema in
//     production; a dependency-free filter in the Fastly shim).
//
// keys.ts wraps this with the CryptoKey + zod production configuration; the
// Fastly E2E shim wraps it with raw-bytes + a manual parser. Neither the verify
// primitive nor zod is referenced here.

// KeyedJwk is the minimum the cache needs from a JWK: a kid to key the map by.
export interface KeyedJwk {
  kid: string;
}

export interface KeyCache<K> {
  resolve(kid: string | undefined): Promise<K | undefined>;
  refresh(): Promise<void>;
}

export interface KeyCacheDeps<K, J extends KeyedJwk> {
  // Absolute URL of the producer's /.well-known/ramp.json. Fetched to resolve a
  // kid that the pre-provisioned static set (if any) does not cover.
  manifestUrl: string;
  // Imports one parsed JWK into the runtime key type (CryptoKey, raw bytes, …).
  importJwk: (jwk: J) => Promise<K>;
  // Extracts the JWK list from the fetched manifest document (schema-validated
  // in production; a plain filter in the dependency-free Fastly shim).
  parseKeys: (json: unknown) => J[];
  // Optional pre-provisioned verify keys (D5). When supplied and they cover the
  // requested kid, the manifest is NOT fetched. A kid that misses the static set
  // triggers a one-shot manifest fetch (rotation self-heal).
  staticKeys?: J[];
  fetcher?: typeof fetch;
  now?: () => number;
  ttlMs?: number;
}

interface Imported<K> {
  keys: Map<string, K>;
  defaultKid?: string;
}

export function createKeyCache<K, J extends KeyedJwk>(deps: KeyCacheDeps<K, J>): KeyCache<K> {
  const ttl = deps.ttlMs ?? 60 * 60 * 1000;
  const fetcher = deps.fetcher ?? fetch;
  const now = deps.now ?? Date.now;

  async function importJwks(jwks: J[]): Promise<Imported<K>> {
    const keys = new Map<string, K>();
    for (const jwk of jwks) {
      keys.set(jwk.kid, await deps.importJwk(jwk));
    }
    const first = jwks[0]?.kid;
    return first !== undefined ? { keys, defaultKid: first } : { keys };
  }

  // Pre-provisioned keys are imported lazily once, then never refetched.
  let staticReady: Promise<Imported<K>> | undefined;
  function ensureStatic() {
    if (!deps.staticKeys || deps.staticKeys.length === 0) return undefined;
    if (!staticReady) staticReady = importJwks(deps.staticKeys);
    return staticReady;
  }

  let cache: Map<string, K> | undefined;
  let fetchedAt = 0;
  let defaultKid: string | undefined;
  let inflight: Promise<void> | undefined;

  async function load(): Promise<void> {
    const res = await fetcher(deps.manifestUrl, { headers: { accept: 'application/json' } });
    if (!res.ok) {
      throw new Error(`manifest fetch failed: ${res.status}`);
    }
    const json: unknown = await res.json();
    const imported = await importJwks(deps.parseKeys(json));
    cache = imported.keys;
    defaultKid = imported.defaultKid;
    fetchedAt = now();
  }

  async function ensureFresh(): Promise<void> {
    if (cache && now() - fetchedAt < ttl) return;
    if (!inflight) {
      inflight = load().finally(() => {
        inflight = undefined;
      });
    }
    await inflight;
  }

  // Resolve from the fetched manifest cache. Used both when no static keys are
  // configured and as the one-shot fallback when a kid misses the static set.
  async function resolveFetched(kid: string | undefined): Promise<K | undefined> {
    await ensureFresh();
    const lookup = kid ?? defaultKid;
    if (!lookup) return undefined;
    return cache?.get(lookup);
  }

  return {
    async resolve(kid) {
      const staticSet = ensureStatic();
      if (staticSet) {
        const { keys, defaultKid: staticDefault } = await staticSet;
        const lookup = kid ?? staticDefault;
        if (lookup) {
          const hit = keys.get(lookup);
          if (hit) return hit;
        }
        // Unknown kid (rotation) — one-shot manifest fetch to self-heal.
        return resolveFetched(kid);
      }
      return resolveFetched(kid);
    },
    async refresh() {
      cache = undefined;
      await ensureFresh();
    },
  };
}
