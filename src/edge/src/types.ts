import type { PopInput, PopResult } from './pop.js';
import type { VerifyResult } from './verify.js';

export interface AuthorizedExchange {
  domain: string;
  endpoint: string;
  // Full proto enum value name (e.g. PROVIDER_RELATIONSHIP_DIRECT). Emitted by
  // every producer's protojson; the Broker reads it when routing offers.
  relationship: string;
}

export interface CatalogContributor {
  // Caller ID authorized to push resource entries for this publisher via
  // ramp.v1.CatalogService.PushResources. Matched case-sensitively by the
  // Exchange contributor-authz check (rampwellknown.AuthorizesContributor).
  domain: string;
  relationship: string;
}

// Unified RAMP /.well-known/ramp.json document (role=ROLE_PUBLISHER for the
// edge). Wire shape mirrors protojson of ramp.v1.WellKnownManifest with
// UseProtoNames=true: snake_case fields, full enum value names. See
// internal/rampwellknown/schema/ramp-well-known.json for the canonical schema.
export interface Manifest {
  ver: string;
  role: string;
  domain: string;
  // Authorized exchanges the Broker consults when routing offer requests.
  exchanges: AuthorizedExchange[];
  // Publishers list authorized third-party catalog pushers here. Consumed by
  // the Go rampwellknown.AuthorizesContributor check; absent or empty means only
  // `domain` itself can push. Optional on the wire so pre-existing publisher
  // manifests stay compatible.
  catalog_contributors?: CatalogContributor[];
  // Top-level union of the per-exchange supported profiles. Optional; emitted
  // only when the EXCHANGES_JSON entries carry profiles so the Broker can match
  // them. Has no per-exchange home in the unified AuthorizedExchange.
  supported_profiles?: string[];
}

export interface AppDeps {
  resolveKey: (kid: string | undefined) => Promise<CryptoKey | undefined>;
  manifest: Manifest;
  // Exchange base URL advertised to bots via the X-RAMP-Exchange hint header.
  // Not part of the served unified manifest; sourced from EXCHANGE_URL.
  exchangeUrl?: string;
  rslBody?: string;
  acmeTokens?: Record<string, string>;
  now?: () => number;
  verify?: (rawUrl: string) => Promise<VerifyResult>;
  /**
   * Proof-of-possession check for delivery-URL identity binding (ADR-013).
   * Injectable for tests; defaults to pop.verifyAgentBinding.
   */
  verifyBinding?: (input: PopInput) => Promise<PopResult>;
  /**
   * Opt-in agent-key binding enforcement. Only when true does the edge require
   * proof of possession for a signed URL carrying agent_id; otherwise it serves
   * the URL as a bearer credential (short TTL + TLS, ADR-013 D6). Default/unset
   * = bearer, because v1's relay topology binds to the broker, not the fetcher.
   */
  enforceBinding?: boolean;
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

// buildPublisherManifest assembles the canonical ROLE_PUBLISHER manifest. It is
// the single source of the publisher manifest shape: production (config.ts) and
// the Fastly E2E shim import it from here, and the raw-Node AWS shim imports the
// same implementation directly. The body lives in the plain-JS
// ./publisher-manifest.mjs (re-exported here) so the build-step-less AWS shim
// can import it without a TypeScript toolchain; a protocol bump is edited once.
// Re-exported from types.ts (not config.ts) so the Fastly shim still imports it
// without pulling zod into its bundle.
export { buildPublisherManifest, WELL_KNOWN_PATH } from './publisher-manifest.mjs';
