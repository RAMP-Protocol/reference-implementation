import { z } from 'zod';

import { type Jwk, JwkSchema, MAX_WBA_KEYS, createKeyCache } from './keys.js';
import {
  type AppDeps,
  type CatalogContributor,
  type WbaKey,
  buildPublisherManifest,
  buildPublisherWba,
} from './types.js';

const EnvSchema = z.object({
  EXCHANGE_URL: z.string().url(),
  // Absolute URL of the exchange's Web Bot Auth directory
  // (/.well-known/http-message-signatures-directory). After the WBA split the
  // exchange's Ed25519 offer-signing key lives ONLY in this directory (keyed by
  // RFC 7638 thumbprint), so this is the fetch source for resolving the
  // delivery-URL verify key.
  EXCHANGE_WBA_URL: z.string().url(),
  RSL_BODY: z.string().optional(),
  ACME_TOKENS_JSON: z.string().optional(),
  /**
   * Origin backend the worker proxies verified requests to. Optional — when
   * unset the worker returns 200 empty (for CloudFront-native signed URL
   * setups where the CDN handles origin). The Cloudflare entry refuses to run
   * without an origin mode: set this or SAME_ZONE_ORIGIN.
   */
  ORIGIN_URL: z.string().url().optional(),
  /**
   * Cloudflare-only alternative to ORIGIN_URL: 'true' forwards pass-through
   * requests to the incoming URL itself (signature params stripped), letting
   * Cloudflare route the same-zone subrequest to the zone's configured origin
   * with the original Host header.
   */
  SAME_ZONE_ORIGIN: z.enum(['true', 'false']).optional(),
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
   * back to fetching EXCHANGE_WBA_URL when a keyid (thumbprint) misses the
   * static set (rotation self-heal). Leave unset to always fetch the verify key.
   */
  RAMP_VERIFY_KEYS: z.string().optional(),
  /**
   * Optional JSON array of this publisher's Ed25519 signing keys (ramp.v1
   * JsonWebKey protojson, NO kid). Served in the WBA directory's keys[] so the
   * Exchange learns a catalog-writer's key via the well-known fetch (Gate-1
   * self-signup) instead of a DB pre-seed. Leave unset for a publisher that
   * issues no keys — no WBA directory is then served.
   */
  WBA_KEYS_JSON: z.string().optional(),
  /**
   * Optional absolute URL advertised as the WBA directory's revocation_url so
   * verifiers learn where to poll this publisher's thumbprint-keyed revocation
   * channel. Ignored unless WBA_KEYS_JSON is also set.
   */
  WBA_REVOCATION_URL: z.string().url().optional(),
  /**
   * Optional overrides for the bot gate's pattern lists: JSON arrays of
   * regular-expression sources (compiled case-insensitive). ALLOW names the
   * search crawlers that read for free; DENY names the AI bots sent to
   * negotiate. Unset = the built-in defaults. A pattern update is then a
   * config change, not a code deploy.
   */
  BOT_UA_ALLOW_JSON: z.string().optional(),
  BOT_UA_DENY_JSON: z.string().optional(),
  /**
   * Proof-of-possession enforcement on agent-bound delivery URLs (ADR-013
   * D6.1). Defaults ON: this edge can run the check, and the rule is "default
   * enforce; bearer only where you can't" — CloudFront-native cannot run it at
   * all and keeps the bearer posture (D6).
   *
   * Set 'false' only to roll this worker ahead of a registry that cannot yet
   * present the bound key; see DEPLOYMENT.md on ordering. With enforcement off
   * a delivery URL is a bearer credential — whoever holds it gets the content
   * until it expires.
   */
  RAMP_ENFORCE_BINDING: z.enum(['true', 'false']).optional(),
});

export type EdgeEnv = z.infer<typeof EnvSchema>;

// Every key the schema knows, for the cross-runtime env parity guard: Fastly
// has no enumerable env and must hand-forward each key, so the guard compares
// its enumeration against this list.
export const ENV_KEYS: readonly (keyof EdgeEnv & string)[] = Object.keys(
  EnvSchema.shape,
) as (keyof EdgeEnv & string)[];

// Accepts unknown on purpose: every runtime hands over its raw settings
// object as-is (no cast needed at any call site) and zod is the validator.
export function parseEnv(env: unknown): EdgeEnv {
  return EnvSchema.parse(env);
}

export function buildDeps(env: EdgeEnv): AppDeps {
  const contributors = parseCatalogContributors(env.CATALOG_CONTRIBUTORS_JSON);
  const parsedExchanges = parseExchanges(env.EXCHANGES_JSON);
  const manifest = buildPublisherManifest(env.PROVIDER, parsedExchanges, contributors);
  const wba = buildWba(env.WBA_KEYS_JSON, env.WBA_REVOCATION_URL);
  const staticKeys = parseVerifyKeys(env.RAMP_VERIFY_KEYS);
  const cache = createKeyCache({
    wbaUrl: env.EXCHANGE_WBA_URL,
    ...(staticKeys !== undefined ? { staticKeys } : {}),
  });
  const acmeTokens = parseAcmeTokens(env.ACME_TOKENS_JSON);
  const botAllow = parseBotPatterns(env.BOT_UA_ALLOW_JSON);
  const botDeny = parseBotPatterns(env.BOT_UA_DENY_JSON);
  return {
    manifest,
    exchangeUrl: env.EXCHANGE_URL,
    resolveKey: (keyid) => cache.resolve(keyid),
    // Default ON, per ADR-013 D6.1: this edge can run the proof-of-possession
    // check, so it does. The custodial-flow objection that once forced it off
    // is answered upstream rather than here — the registry, which holds the
    // key, now makes the bound fetch itself and can satisfy the check
    // (ADR-023). Opting out is explicit and is a downgrade to bearer security.
    enforceBinding: env.RAMP_ENFORCE_BINDING !== 'false',
    ...(wba !== undefined ? { wba } : {}),
    ...(env.RSL_BODY !== undefined ? { rslBody: env.RSL_BODY } : {}),
    ...(acmeTokens !== undefined ? { acmeTokens } : {}),
    ...(env.ORIGIN_URL !== undefined ? { originUrl: env.ORIGIN_URL } : {}),
    ...(env.SAME_ZONE_ORIGIN === 'true' ? { sameZoneOrigin: true } : {}),
    ...(botAllow !== undefined ? { botAllowPatterns: botAllow } : {}),
    ...(botDeny !== undefined ? { botDenyPatterns: botDeny } : {}),
  };
}

// parseBotPatterns compiles a JSON array of regex sources into
// case-insensitive patterns. An invalid source throws rather than being
// skipped, because a broken pattern list must not silently disable the bot
// gate. The throw happens on the first request, not at deploy time: the entries
// call buildDeps from inside fetch, so a bad list passes deployment and then
// fails every request. The
// count/length caps bound only the SIZE of the pattern set; they do NOT
// detect catastrophic backtracking, and no runtime check can interrupt a
// regex mid-match on Workers. These patterns are operator-authored config
// (not caller input): keep them simple substring alternations like the
// built-in defaults and avoid nested quantifiers such as (a+)+ — the
// 512-char UA truncation in classifyClient bounds the cost of well-formed
// patterns but cannot save a backtracking one.
function parseBotPatterns(raw: string | undefined): readonly RegExp[] | undefined {
  if (!raw) return undefined;
  const parsed: unknown = JSON.parse(raw);
  const sources = z.array(z.string().min(1).max(256)).min(1).max(64).parse(parsed);
  return sources.map((s) => new RegExp(s, 'i'));
}

// originModeConfigured is the single statement of "this deployment has an
// origin": an explicit backend URL, or same-zone forwarding. The Cloudflare
// and Fastly entries guard on it (fail loud when neither mode is set); the
// AWS entry deliberately does NOT — on a CloudFront-native deployment "no
// origin mode" is the designed state, where CloudFront owns the origin fetch
// and the worker answers empty 200s. resolveOriginTarget (app.ts) branches
// on the same two fields to pick the target.
export function originModeConfigured(
  env: Pick<EdgeEnv, 'ORIGIN_URL' | 'SAME_ZONE_ORIGIN'>,
): boolean {
  return Boolean(env.ORIGIN_URL) || env.SAME_ZONE_ORIGIN === 'true';
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
  // Optional extension map (mirrors the proto AuthorizedExchange.ext Struct). The
  // publisher attests its resource_owner_id payee here for the Exchange settlement
  // gate; carried through to the served manifest verbatim.
  ext: z.record(z.string(), z.unknown()).optional(),
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

// RFC3339 timestamp, mirroring the canonical WBA schema's not_before/not_after
// pattern (internal/rampwellknown/schema/ramp-wba-directory.json $defs/jwk). A
// loose z.string() here would let a non-RFC3339 bound pass the edge gate only to
// be rejected wholesale by the Exchange's strict ValidateWBA — or, worse, be
// silently treated as never-active by keyActiveAt.
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

// Mirrors the canonical WBA directory keys[] item
// (internal/rampwellknown/schema/ramp-wba-directory.json): an RFC 8037
// OKP/Ed25519 JWK (NO kid) plus a half-open [not_before, not_after) validity
// window. Tightened to the canonical const/pattern values so a malformed env
// fails fast at the edge rather than silently serving an unusable directory the
// Exchange would reject.
const WbaKeySchema = z.object({
  kty: z.literal('OKP'),
  crv: z.literal('Ed25519'),
  use: z.literal('sig'),
  alg: z.literal('EdDSA'),
  x: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  not_before: z.string().regex(RFC3339),
  not_after: z.string().regex(RFC3339),
});

function buildWba(rawKeys: string | undefined, revocationUrl: string | undefined): AppDeps['wba'] {
  const keys = parseWbaKeys(rawKeys);
  if (keys === undefined) return undefined;
  return buildPublisherWba(keys, revocationUrl);
}

function parseWbaKeys(raw: string | undefined): WbaKey[] | undefined {
  if (!raw) return undefined;
  const parsed: unknown = JSON.parse(raw);
  return z.array(WbaKeySchema).min(1).max(MAX_WBA_KEYS).parse(parsed);
}

function parseVerifyKeys(raw: string | undefined): Jwk[] | undefined {
  if (!raw) return undefined;
  const parsed: unknown = JSON.parse(raw);
  return z.array(JwkSchema).min(1).max(MAX_WBA_KEYS).parse(parsed);
}
