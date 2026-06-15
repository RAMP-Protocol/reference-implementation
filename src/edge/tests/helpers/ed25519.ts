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

export interface SignRequestOptions {
  authority: string;
  path: string;
  purpose: string;
  keyid: string;
  agent?: string;
  /** Override the covered component list (default: @authority @path ramp-purpose). */
  components?: string[];
  /** Override the structured-field tag (default 'web-bot-auth'). */
  tag?: string;
  created?: number;
  expires?: number;
  label?: string;
  purposeHeader?: string;
}

// Sign a GET request under the web-bot-auth profile, producing the RFC 9421
// headers a WBA crawler sends. The signature base is built the SAME way as
// src/wba.ts buildSignatureBase, so a successful round-trip proves signer and
// verifier agree on the canonicalization.
export async function signRequest(
  privateKey: CryptoKey,
  opts: SignRequestOptions,
): Promise<Record<string, string>> {
  const label = opts.label ?? 'sig1';
  const purposeHeader = (opts.purposeHeader ?? 'ramp-purpose').toLowerCase();
  const components = (opts.components ?? ['@authority', '@path', purposeHeader]).map((c) =>
    c.toLowerCase(),
  );

  const headers: Record<string, string> = {
    'ramp-purpose': opts.purpose,
  };
  if (opts.agent !== undefined) headers['signature-agent'] = opts.agent;

  const componentList = components.map((c) => `"${c}"`).join(' ');
  let paramsString = `(${componentList})`;
  if (opts.created !== undefined) paramsString += `;created=${opts.created}`;
  if (opts.expires !== undefined) paramsString += `;expires=${opts.expires}`;
  paramsString += `;keyid="${opts.keyid}";alg="ed25519";tag="${opts.tag ?? 'web-bot-auth'}"`;

  const componentValue = (comp: string): string => {
    if (comp === '@method') return 'GET';
    if (comp === '@authority') return opts.authority.toLowerCase();
    if (comp === '@path') return opts.path;
    return (headers[comp] ?? '').trim();
  };

  const base = [
    ...components.map((c) => `"${c}": ${componentValue(c)}`),
    `"@signature-params": ${paramsString}`,
  ].join('\n');

  const sig = new Uint8Array(
    await subtle().sign('Ed25519', privateKey, new TextEncoder().encode(base)),
  );

  const out: Record<string, string> = {
    'RAMP-Purpose': opts.purpose,
    'Signature-Input': `${label}=${paramsString}`,
    Signature: `${label}=:${encodeBase64Url(sig)}:`,
  };
  if (opts.agent !== undefined) out['Signature-Agent'] = opts.agent;
  return out;
}

export function jwks(keys: Array<JsonWebKey & { kid: string }>): {
  keys: Array<JsonWebKey & { kid: string; alg: string; use: string }>;
} {
  return {
    keys: keys.map((k) => ({ ...k, alg: 'EdDSA', use: 'sig' })),
  };
}
