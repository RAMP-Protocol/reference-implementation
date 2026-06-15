import { z } from 'zod';

import { type Jwk, JwkSchema, createKeyCache } from './keys.js';
import { type AppDeps, type CatalogContributor, buildPublisherManifest } from './types.js';

const EnvSchema = z.object({
  EXCHANGE_URL: z.string().url(),
  // Absolute URL of the exchange's /.well-known/ramp.json. This is the single
  // exchange-manifest URL: it is both advertised downstream and used as the
  // fetch source for resolving the Ed25519 delivery-URL verify key.
  EXCHANGE_MANIFEST_URL: z.string().url(),
  RSL_BODY: z.string().optional(),
  ACME_TOKENS_JSON: z.string().optional(),
  /**
   * Origin backend the worker proxies verified requests to. Optional — when
   * unset the worker returns 200 empty (for CloudFront-native signed URL
   * setups where the CDN handles origin).
   */
  ORIGIN_URL: z.string().url().optional(),
  /**
   * Publisher identifier advertised in ramp.json (the `domain` field). Required.
   */
  PROVIDER: z.string().min(1),
  /**
   * JSON array of exchange entries advertised in ramp.json. Broker reads this
   * to decide which exchanges represent the publisher.
   */
  EXCHANGES_JSON: z.string(),
  /**
   * Optional JSON array of CatalogContributor entries. Authorizes third-party
   * callers to push resources on behalf of this publisher via the signed
   * ramp.v1.CatalogService/PushResources RPC. Consumed by the Exchange
   * contributor-authz check (rampwellknown.AuthorizesContributor). Leave unset
   * to only let `PROVIDER` itself push.
   */
  CATALOG_CONTRIBUTORS_JSON: z.string().optional(),
  /**
   * Optional JSON array of inline Ed25519 JWKs (D5 pre-provisioning). When set,
   * the edge verifies delivery URLs against these keys directly and only falls
   * back to fetching EXCHANGE_MANIFEST_URL when a kid misses the static set
   * (rotation self-heal). Leave unset to always fetch the verify key.
   */
  RAMP_VERIFY_KEYS: z.string().optional(),
  /**
   * Delivery-URL identity binding enforcement (ADR-013 D1/D6). When set to
   * "true", a signed URL carrying agent_id requires the fetcher to prove
   * possession of the bound key. Default is OFF (bearer security: short TTL +
   * TLS) because v1's canonical agent topology is MCP→Broker→Exchange: the
   * Exchange binds the URL to the proven caller, which on the relay path is the
   * broker, not the fetching agent — so proof-of-possession is unsatisfiable
   * there until the binding identity is reworked (ADR-013 D6 keeps enforcement
   * OPTIONAL). Enable only on deployments whose fetcher holds the bound key.
   */
  RAMP_ENFORCE_BINDING: z.enum(['true', 'false']).optional(),
});

export type EdgeEnv = z.infer<typeof EnvSchema>;

export function parseEnv(env: Record<string, unknown>): EdgeEnv {
  return EnvSchema.parse(env);
}

export function buildDeps(env: EdgeEnv): AppDeps {
  const contributors = parseCatalogContributors(env.CATALOG_CONTRIBUTORS_JSON);
  const parsedExchanges = parseExchanges(env.EXCHANGES_JSON);
  const manifest = buildPublisherManifest(env.PROVIDER, parsedExchanges, contributors);
  const staticKeys = parseVerifyKeys(env.RAMP_VERIFY_KEYS);
  const cache = createKeyCache({
    manifestUrl: env.EXCHANGE_MANIFEST_URL,
    ...(staticKeys !== undefined ? { staticKeys } : {}),
  });
  const acmeTokens = parseAcmeTokens(env.ACME_TOKENS_JSON);
  return {
    manifest,
    exchangeUrl: env.EXCHANGE_URL,
    resolveKey: (kid) => cache.resolve(kid),
    enforceBinding: env.RAMP_ENFORCE_BINDING === 'true',
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

// EXCHANGES_JSON keeps its historical per-entry shape (domain/endpoint plus an
// optional supported_profiles list). The unified AuthorizedExchange has no
// per-entry profiles slot, so they are hoisted into the manifest's top-level
// supported_profiles; relationship defaults to DIRECT.
const ExchangeEntrySchema = z.object({
  domain: z.string().min(1),
  endpoint: z.string().url(),
  supported_profiles: z.array(z.string()).default([]),
});

type ExchangeEntry = z.infer<typeof ExchangeEntrySchema>;

function parseExchanges(raw: string): ExchangeEntry[] {
  const parsed: unknown = JSON.parse(raw);
  return z.array(ExchangeEntrySchema).parse(parsed);
}

const CatalogContributorSchema = z.object({
  domain: z.string().min(1),
  relationship: z.string().min(1),
});

function parseCatalogContributors(raw: string | undefined): CatalogContributor[] | undefined {
  if (!raw) return undefined;
  const parsed: unknown = JSON.parse(raw);
  return z.array(CatalogContributorSchema).parse(parsed);
}

function parseVerifyKeys(raw: string | undefined): Jwk[] | undefined {
  if (!raw) return undefined;
  const parsed: unknown = JSON.parse(raw);
  return z.array(JwkSchema).min(1).parse(parsed);
}
