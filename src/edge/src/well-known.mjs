// Canonical ROLE_PUBLISHER discovery builders. Plain ESM JS — no types, no
// dependencies — so they have exactly one home shared by two consumers that
// cannot share a TypeScript module:
//
//   * the Hono edge worker (src/edge), which re-exports through types.ts; and
//   * the raw-Node AWS CloudFront E2E shim (tests/e2e/aws-edge/server.mjs),
//     which has no build step and imports this file directly.
//
// One source means a protocol bump is edited once;
// tests/e2e/harness/test_manifest_parity.py guards the two emitters against
// drift. Per-entry supported_profiles are hoisted into the top-level
// supported_profiles (the unified AuthorizedExchange has no per-entry slot);
// relationship defaults to PROVIDER_RELATIONSHIP_DIRECT.
//
// After the WBA split identity keys are NOT part of the overlay
// manifest: a publisher's signing key(s) are published in a separate Web Bot
// Auth directory (buildPublisherWba below), and referenced elsewhere only by
// RFC 7638 thumbprint.

// Fixed path every RAMP participant serves its commercial overlay manifest at.
// Single-sourced here (plain ESM) so the Hono worker (via types.ts) and the
// build-step-less AWS shim share one literal — no drift between the route mount
// and the X-Content-Rules header URL.
export const WELL_KNOWN_PATH = '/.well-known/ramp.json';

// Fixed path every RAMP participant serves its pure Web Bot Auth directory at.
// The directory is an RFC 7517 JWK Set (keys) plus an optional directory-level
// revocation_url, served with Content-Type application/jwk-set+json. Mirrors
// the Go rampwellknown.WBAPath.
export const WBA_PATH = '/.well-known/http-message-signatures-directory';

// Content-Type for the WBA directory response, matching the Go WBA handler
// (internal/rampwellknown/server) and readable by any off-the-shelf WBA verifier.
export const WBA_DIRECTORY_CONTENT_TYPE = 'application/jwk-set+json';

export function buildPublisherManifest(provider, exchanges, contributors) {
  const profiles = [...new Set(exchanges.flatMap((e) => e.supported_profiles ?? []))];
  return {
    ver: '1.0',
    role: 'ROLE_PUBLISHER',
    domain: provider,
    exchanges: exchanges.map((e) => ({
      domain: e.domain,
      endpoint: e.endpoint,
      relationship: 'PROVIDER_RELATIONSHIP_DIRECT',
      // The publisher attests its resource_owner_id payee in ext for the Exchange's
      // settlement gate. Conditional so an entry without ext stays byte-identical
      // (the manifest-parity emitters and ext-less configs are unaffected).
      ...(e.ext !== undefined ? { ext: e.ext } : {}),
    })),
    ...(profiles.length > 0 ? { supported_profiles: profiles } : {}),
    ...(contributors !== undefined ? { catalog_contributors: contributors } : {}),
  };
}

// buildPublisherWba assembles the publisher's Web Bot Auth directory: a JWK Set
// carrying the publisher's Ed25519 signing key(s) with NO kid (keys are named
// by their RFC 7638 thumbprint), plus an optional directory-level revocation_url
// pointing at the thumbprint-keyed revocation channel. Wire shape mirrors
// protojson of ramp.v1.WBAFile (UseProtoNames=true). A directory always
// publishes at least one key.
export function buildPublisherWba(keys, revocationUrl) {
  return {
    keys,
    ...(revocationUrl !== undefined ? { revocation_url: revocationUrl } : {}),
  };
}
