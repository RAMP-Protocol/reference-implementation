// Canonical ROLE_PUBLISHER /.well-known/ramp.json builder. Plain ESM JS — no
// types, no dependencies — so it has exactly one home shared by two consumers
// that cannot share a TypeScript module:
//
//   * the Hono edge worker (src/edge), which re-exports it through types.ts; and
//   * the raw-Node AWS CloudFront E2E shim (tests/e2e/aws-edge/server.mjs),
//     which has no build step and imports this file directly.
//
// One source means a protocol bump is edited once;
// tests/e2e/harness/test_manifest_parity.py guards the two emitters against
// drift. Per-entry supported_profiles are hoisted into the top-level
// supported_profiles (the unified AuthorizedExchange has no per-entry slot);
// relationship defaults to PROVIDER_RELATIONSHIP_DIRECT.

// Fixed path every RAMP participant serves its discovery manifest at. Single-
// sourced here (plain ESM) so the Hono worker (via types.ts) and the build-step-
// less AWS shim share one literal — no drift between the route mount and the
// X-Content-Rules header URL.
export const WELL_KNOWN_PATH = '/.well-known/ramp.json';

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
    })),
    ...(profiles.length > 0 ? { supported_profiles: profiles } : {}),
    ...(contributors !== undefined ? { catalog_contributors: contributors } : {}),
  };
}
