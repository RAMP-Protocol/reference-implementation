import { decodeBase64Url, encodeBase64Url } from '../../src/verify.js';

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

// rawPublicKey extracts the raw 32-byte Ed25519 public key from a test keypair's
// JWK (the `x` member is its base64url encoding).
export function rawPublicKey(kp: TestKeypair): Uint8Array {
  const x = decodeBase64Url(kp.publicJwk.x ?? '');
  if (!x) throw new Error('keypair JWK missing x');
  return x;
}

export interface GetSignOptions {
  keyid: string;
  created: number;
  expires: number;
}

// signGetHeaders produces the RFC 9421 proof-of-possession headers for a GET of
// fullUrl, signed by kp over the covered set ADR-013 D2 fixes (@method,
// @target-uri). The signature base and Signature value MUST match the edge
// verifier (src/pop.ts) and the Python agent signer (src/mcp httpsig.py): the
// Signature byte string is STANDARD base64 inside `:...:`.
export async function signGetHeaders(
  fullUrl: string,
  kp: TestKeypair,
  opts: GetSignOptions,
): Promise<Record<string, string>> {
  const rawParams =
    `("@method" "@target-uri");keyid="${opts.keyid}";` +
    `alg="ed25519";created=${opts.created};expires=${opts.expires}`;
  const base = `"@method": GET\n"@target-uri": ${fullUrl}\n"@signature-params": ${rawParams}`;
  const sig = new Uint8Array(
    await subtle().sign('Ed25519', kp.privateKey, new TextEncoder().encode(base)),
  );
  let bin = '';
  for (let i = 0; i < sig.length; i += 1) bin += String.fromCharCode(sig[i] as number);
  return {
    'X-RAMP-Agent-Key': encodeBase64Url(rawPublicKey(kp)),
    'Signature-Input': `sig1=${rawParams}`,
    Signature: `sig1=:${btoa(bin)}:`,
  };
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
  agentId?: string;
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
  if (opts.agentId !== undefined) url.searchParams.set('agent_id', opts.agentId);
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

// Build a unified RAMP /.well-known/ramp.json document carrying the given keys
// in public_keys[] — the shape the edge now fetches to resolve verify keys.
// Each JWK is fleshed out with the full set of manifest fields (use/alg and a
// wide not_before/not_after window) so it matches the production wire shape.
export function manifestWithKeys(keys: Array<JsonWebKey & { kid: string }>): {
  ver: string;
  role: string;
  domain: string;
  public_keys: Array<
    JsonWebKey & { kid: string; alg: string; use: string; not_before: string; not_after: string }
  >;
} {
  return {
    ver: '1.0',
    role: 'ROLE_EXCHANGE',
    domain: 'exchange.test',
    public_keys: keys.map((k) => ({
      ...k,
      alg: 'EdDSA',
      use: 'sig',
      not_before: '2000-01-01T00:00:00Z',
      not_after: '2100-01-01T00:00:00Z',
    })),
  };
}
