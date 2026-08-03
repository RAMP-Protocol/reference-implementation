import type { PopInput, PopResult } from '@ramp-protocol/sdk-l1/pop';
import type { VerifyResult } from '@ramp-protocol/sdk-l1/verify';
import type { BotSignal } from './bot-classification.js';

export interface AuthorizedExchange {
  domain: string;
  endpoint: string;
  // Full proto enum value name (e.g. PROVIDER_RELATIONSHIP_DIRECT). Emitted by
  // every producer's protojson; the Broker reads it when routing offers.
  relationship: string;
  // Optional extension map (proto AuthorizedExchange.ext Struct). Carries the
  // publisher-attested resource_owner_id payee the Exchange settlement gate reads.
  ext?: Record<string, unknown>;
}

export interface CatalogContributor {
  // Caller ID authorized to push resource entries for this publisher via
  // ramp.v1.CatalogService.PushResources. Matched case-sensitively by the
  // Exchange contributor-authz check (rampwellknown.AuthorizesContributor).
  domain: string;
  relationship: string;
}

// A signing key published in the Web Bot Auth directory
// (/.well-known/http-message-signatures-directory). Wire shape mirrors protojson
// of ramp.v1.JsonWebKey (RFC 8037 OKP/Ed25519 JWK + a half-open
// [not_before, not_after) validity window). After the WBA split there is NO
// `kid`: a key is named by its RFC 7638 thumbprint. The Exchange decodes these
// via the Go rampwellknown.ActiveKeys path; verifiers match a request's keyid
// against the locally-computed thumbprint of these keys. See the canonical
// schema internal/rampwellknown/schema/ramp-wba-directory.json.
export interface WbaKey {
  kty: 'OKP';
  crv: 'Ed25519';
  use: 'sig';
  alg: 'EdDSA';
  x: string;
  not_before: string;
  not_after: string;
}

// A pure Web Bot Auth directory served at
// /.well-known/http-message-signatures-directory. An RFC 7517 JWK Set (keys)
// plus an optional directory-level revocation_url, with zero RAMP-specific
// fields. Wire shape mirrors protojson of ramp.v1.WBAFile with
// UseProtoNames=true. See internal/rampwellknown/schema/ramp-wba-directory.json.
export interface WbaFile {
  keys: WbaKey[];
  // Absolute URL of the thumbprint-keyed revocation channel for this directory's
  // keys. Optional; protojson omits the empty case.
  revocation_url?: string;
}

// RAMP /.well-known/ramp.json commercial overlay (role=ROLE_PUBLISHER for the
// edge). Wire shape mirrors protojson of ramp.v1.WellKnownManifest with
// UseProtoNames=true: snake_case fields, full enum value names. Identity keys
// are NOT here after the WBA split — they live in the WBA directory
// (WbaFile) and are referenced by RFC 7638 thumbprint. See
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
  resolveKey: (keyid: string | undefined) => Promise<CryptoKey | undefined>;
  manifest: Manifest;
  // Web Bot Auth directory served at /.well-known/http-message-signatures-directory.
  // The publisher's Ed25519 signing key(s) as a JWK Set. Absent on deployments
  // that publish no signing key (e.g. the AWS CloudFront-native edge, whose
  // verify key is provisioned out of band).
  wba?: WbaFile;
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
   * Agent-key binding enforcement. Only when true does the edge require proof of
   * possession for a signed URL carrying agent_id; otherwise it serves the URL as
   * a bearer credential (short TTL + TLS, ADR-013 D6).
   *
   * Unset is bearer at THIS layer, which is a fail-safe for a hand-built AppDeps
   * rather than the deployed default: buildDeps sets it from
   * RAMP_ENFORCE_BINDING and defaults it ON wherever the edge can run the check
   * (ADR-013 D6.1, restored by ADR-023). A runtime that assembles AppDeps itself
   * must therefore set this explicitly or it silently keeps the bearer posture.
   */
  enforceBinding?: boolean;
  /**
   * Origin to proxy pass-through requests to after verification succeeds.
   *
   * When set, the worker rewrites the request's URL to `originUrl + pathname
   * + search` and forwards it. When unset AND sameZoneOrigin is false, the
   * worker returns a 200 with empty body — the deployment CDN (e.g. CloudFront
   * with a native signed-URL behavior) is expected to handle origin fetch.
   */
  originUrl?: string;
  /**
   * Cloudflare-only alternative to originUrl: forward to the incoming URL
   * itself (signature params stripped). On a zone route, a same-zone
   * subrequest is sent by Cloudflare to the zone's configured origin with the
   * original Host header — the worker never needs the origin's address, which
   * also serves shared load-balancer origins that route by Host.
   */
  sameZoneOrigin?: boolean;
  /**
   * Injectable fetcher for tests. Defaults to the runtime's global fetch.
   */
  fetcher?: typeof fetch;
  /**
   * Runtime-specific caller verification for the bot gate (see BotSignal).
   * The Cloudflare entry supplies a reader of the request's cf verified-bot
   * data; runtimes without such data leave it unset.
   */
  botSignal?: (req: Request) => BotSignal | undefined;
  /**
   * Overrides for the search-crawler allow list / AI-bot deny list
   * (BOT_UA_ALLOW_JSON / BOT_UA_DENY_JSON). Unset = built-in defaults.
   */
  botAllowPatterns?: readonly RegExp[];
  botDenyPatterns?: readonly RegExp[];
}

// buildPublisherManifest/buildPublisherWba assemble the canonical ROLE_PUBLISHER
// discovery documents (the keyless overlay manifest and the WBA directory). They
// are the single source of those shapes: production (config.ts) and the Fastly
// E2E shim import them from here, and the raw-Node AWS shim imports the same
// implementation directly. The body lives in the plain-JS ./well-known.mjs
// (re-exported here) so the build-step-less AWS shim can import it without a
// TypeScript toolchain; a protocol bump is edited once. Re-exported from types.ts
// (not config.ts) so the Fastly shim still imports it without pulling zod into
// its bundle.
export {
  buildPublisherManifest,
  buildPublisherWba,
  WELL_KNOWN_PATH,
  WBA_PATH,
  WBA_DIRECTORY_CONTENT_TYPE,
} from './well-known.mjs';
