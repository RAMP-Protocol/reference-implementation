import { z } from 'zod';

const JwkSchema = z.object({
  kty: z.literal('OKP'),
  crv: z.literal('Ed25519'),
  kid: z.string().min(1),
  x: z.string().min(1),
  alg: z.string().optional(),
  use: z.string().optional(),
});

const JwksSchema = z.object({
  keys: z.array(JwkSchema).min(1),
});

export type Jwk = z.infer<typeof JwkSchema>;

export interface KeyCache {
  resolve(kid: string | undefined): Promise<CryptoKey | undefined>;
  refresh(): Promise<void>;
}

export interface KeyCacheDeps {
  jwksUrl: string;
  fetcher?: typeof fetch;
  now?: () => number;
  ttlMs?: number;
}

export function createKeyCache(deps: KeyCacheDeps): KeyCache {
  const ttl = deps.ttlMs ?? 60 * 60 * 1000;
  const fetcher = deps.fetcher ?? fetch;
  const now = deps.now ?? Date.now;
  let cache: Map<string, CryptoKey> | undefined;
  let fetchedAt = 0;
  let defaultKid: string | undefined;
  let inflight: Promise<void> | undefined;

  async function load(): Promise<void> {
    const res = await fetcher(deps.jwksUrl, {
      headers: { accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`JWKS fetch failed: ${res.status}`);
    }
    const json: unknown = await res.json();
    const parsed = JwksSchema.parse(json);
    const next = new Map<string, CryptoKey>();
    for (const jwk of parsed.keys) {
      const key = await crypto.subtle.importKey(
        'jwk',
        { kty: jwk.kty, crv: jwk.crv, x: jwk.x },
        { name: 'Ed25519' },
        false,
        ['verify'],
      );
      next.set(jwk.kid, key);
    }
    cache = next;
    fetchedAt = now();
    defaultKid = parsed.keys[0]?.kid;
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

  return {
    async resolve(kid) {
      await ensureFresh();
      const lookup = kid ?? defaultKid;
      if (!lookup) return undefined;
      return cache?.get(lookup);
    },
    async refresh() {
      cache = undefined;
      await ensureFresh();
    },
  };
}
