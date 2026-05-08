import { encodeBase64Url } from '../../src/verify.js';

export interface TestKeypair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  publicJwk: JsonWebKey & { kid: string };
}

interface SubtleLike {
  generateKey(
    algorithm: { name: string },
    extractable: boolean,
    usages: string[],
  ): Promise<CryptoKeyPair>;
  exportKey(format: 'jwk', key: CryptoKey): Promise<JsonWebKey>;
  sign(algorithm: string, key: CryptoKey, data: Uint8Array): Promise<ArrayBuffer>;
}

function subtle(): SubtleLike {
  return crypto.subtle as unknown as SubtleLike;
}

export async function generateKeypair(kid = 'test-key-1'): Promise<TestKeypair> {
  const pair = await subtle().generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pubJwk = await subtle().exportKey('jwk', pair.publicKey);
  return {
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
    publicJwk: { ...pubJwk, kid },
  };
}

export interface SignOptions {
  exp: number;
  kid?: string;
  agent?: string;
  path?: string;
  query?: Record<string, string>;
}

export async function signUrl(
  origin: string,
  privateKey: CryptoKey,
  opts: SignOptions,
): Promise<string> {
  const url = new URL(opts.path ?? '/some/resource', origin);
  url.searchParams.set('exp', String(opts.exp));
  if (opts.kid !== undefined) url.searchParams.set('kid', opts.kid);
  if (opts.agent !== undefined) url.searchParams.set('agent', opts.agent);
  for (const [k, v] of Object.entries(opts.query ?? {})) {
    url.searchParams.set(k, v);
  }
  const canonical = `GET\n${url.toString()}`;
  const sig = new Uint8Array(
    await subtle().sign('Ed25519', privateKey, new TextEncoder().encode(canonical)),
  );
  url.searchParams.set('sig', encodeBase64Url(sig));
  return url.toString();
}

export function jwks(keys: Array<JsonWebKey & { kid: string }>): {
  keys: Array<JsonWebKey & { kid: string; alg: string; use: string }>;
} {
  return {
    keys: keys.map((k) => ({ ...k, alg: 'EdDSA', use: 'sig' })),
  };
}
