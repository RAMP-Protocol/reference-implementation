import { z } from 'zod';

import { createKeyCache } from './keys.js';
import type { AppDeps, AuthorizedExchange, Manifest, VerifierManifest } from './types.js';

const EnvSchema = z.object({
  EXCHANGE_URL: z.string().url(),
  MARKETPLACE_MANIFEST_URL: z.string().url(),
  JWKS_URL: z.string().url(),
  RSL_BODY: z.string().optional(),
  ACME_TOKENS_JSON: z.string().optional(),
  /**
   * Origin backend the worker proxies verified requests to. Optional — when
   * unset the worker returns 200 empty (for CloudFront-native signed URL
   * setups where the CDN handles origin).
   */
  ORIGIN_URL: z.string().url().optional(),
  /**
   * Publisher identifier advertised in ramp.json. Required.
   */
  PROVIDER: z.string().min(1),
  /**
   * JSON array of AuthorizedExchange entries advertised in ramp.json.
   * Broker reads this to decide which exchanges represent the publisher.
   */
  EXCHANGES_JSON: z.string(),
});

export type EdgeEnv = z.infer<typeof EnvSchema>;

export function parseEnv(env: Record<string, unknown>): EdgeEnv {
  return EnvSchema.parse(env);
}

export function buildDeps(env: EdgeEnv): AppDeps {
  const manifest: Manifest = {
    ver: '0.3',
    provider: env.PROVIDER,
    exchanges: parseExchanges(env.EXCHANGES_JSON),
    exchange: env.EXCHANGE_URL,
    marketplace_manifest: env.MARKETPLACE_MANIFEST_URL,
  };
  const verifierManifest: VerifierManifest = {
    version: '0.3',
    jwks_url: env.JWKS_URL,
    signing_algorithms: ['Ed25519'],
  };
  const cache = createKeyCache({ jwksUrl: env.JWKS_URL });
  const acmeTokens = parseAcmeTokens(env.ACME_TOKENS_JSON);
  return {
    manifest,
    verifierManifest,
    resolveKey: (kid) => cache.resolve(kid),
    ...(env.RSL_BODY !== undefined ? { rslBody: env.RSL_BODY } : {}),
    ...(acmeTokens !== undefined ? { acmeTokens } : {}),
    ...(env.ORIGIN_URL !== undefined ? { originUrl: env.ORIGIN_URL } : {}),
  };
}

function parseAcmeTokens(raw: string | undefined): Record<string, string> | undefined {
  if (!raw) return undefined;
  const parsed: unknown = JSON.parse(raw);
  const schema = z.record(z.string(), z.string());
  return schema.parse(parsed);
}

const AuthorizedExchangeSchema = z.object({
  domain: z.string().min(1),
  endpoint: z.string().url(),
  supported_profiles: z.array(z.string()).default([]),
});

function parseExchanges(raw: string): AuthorizedExchange[] {
  const parsed: unknown = JSON.parse(raw);
  return z.array(AuthorizedExchangeSchema).parse(parsed);
}
