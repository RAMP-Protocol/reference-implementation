import type { FreeRule } from './freerule.js';
import type { VerifyResult } from './verify.js';

export interface AuthorizedExchange {
  domain: string;
  endpoint: string;
  // Normalized to [] when absent in the publisher's ramp.json; Broker matches
  // any marketplace when the list is empty.
  supported_profiles: string[];
}

export interface Manifest {
  ver: string;
  provider: string;
  exchanges: AuthorizedExchange[];
  // Extended fields for downstream consumers. Broker only reads ver/provider/exchanges.
  exchange?: string;
  marketplace_manifest?: string;
}

export interface VerifierManifest {
  version: string;
  jwks_url: string;
  signing_algorithms: string[];
}

export interface AppDeps {
  resolveKey: (kid: string | undefined) => Promise<CryptoKey | undefined>;
  manifest: Manifest;
  verifierManifest: VerifierManifest;
  rslBody?: string;
  acmeTokens?: Record<string, string>;
  now?: () => number;
  verify?: (rawUrl: string) => Promise<VerifyResult>;
  /**
   * Origin to proxy pass-through requests to after verification succeeds.
   *
   * When set, the worker rewrites the verified request's URL to
   * `originUrl + pathname + search` and forwards it. When unset, the
   * worker returns a 200 with empty body — the deployment CDN (e.g. CloudFront
   * with a native signed-URL behavior) is expected to handle origin fetch.
   */
  originUrl?: string;
  /**
   * Injectable fetcher for tests. Defaults to the runtime's global fetch.
   */
  fetcher?: typeof fetch;
  /**
   * Free-index fast path (ADR-015). All optional — when unset the fast path is
   * inert and the worker behaves exactly as before.
   *
   * `freeRules` is the collapsed edge-config projection (D12); `resolveBotKey`
   * resolves a WBA crawler's Ed25519 key (e.g. a JWKS-backed cache against the
   * bot's Signature-Agent directory); `purposeHeader` overrides the default
   * `ramp-purpose` request header name.
   */
  freeRules?: readonly FreeRule[];
  resolveBotKey?: (
    keyid: string | undefined,
    agent: string | undefined,
  ) => Promise<CryptoKey | undefined>;
  purposeHeader?: string;
}

export const BOT_UA_PATTERNS: readonly RegExp[] = Object.freeze([
  /bot\b/i,
  /crawler/i,
  /spider/i,
  /GPTBot/i,
  /ClaudeBot/i,
  /anthropic-ai/i,
  /OAI-SearchBot/i,
  /CCBot/i,
  /PerplexityBot/i,
  /Bytespider/i,
  /Google-Extended/i,
]);

export function looksLikeBot(userAgent: string | undefined | null): boolean {
  if (!userAgent) return true;
  return BOT_UA_PATTERNS.some((re) => re.test(userAgent));
}
