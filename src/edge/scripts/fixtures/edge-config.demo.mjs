// Example per-deployment EdgeConfig for the Lambda@Edge bundle.
//
// This is the shape the deploy side (pi-terraform) supplies to
// build-lambda-edge.mjs. Lambda@Edge has no env vars, so all config is baked at
// build time. Only the bot's PUBLIC JWK is embedded — never a private key. The
// demo bot key below is a throwaway used for the reference build's smoke test.

const DEMO_BOT_JWK = {
  kty: 'OKP',
  crv: 'Ed25519',
  kid: 'bot-1',
  // biome-ignore lint/nursery/noSecrets: public Ed25519 JWK (throwaway demo bot key), not a secret
  x: 'QD4wPfqHut5bZK5Z7AhqW2VF0JzZAACT47punh-OdAs',
};

let cachedKey;

// Resolve the WBA crawler key. Production would resolve via the Signature-Agent
// directory through a CDN KeyValueStore; here the demo bot's key is bundled so
// the viewer-request function makes no network call on the hot path.
async function resolveBotKey(keyid) {
  if (keyid !== undefined && keyid !== DEMO_BOT_JWK.kid) return undefined;
  cachedKey ??= await crypto.subtle.importKey(
    'jwk',
    { kty: DEMO_BOT_JWK.kty, crv: DEMO_BOT_JWK.crv, x: DEMO_BOT_JWK.x },
    { name: 'Ed25519' },
    false,
    ['verify'],
  );
  return cachedKey;
}

const config = {
  // The collapsed free-index ruleset (D12), static for the demo. Production
  // derives this from the catalog; exceptions only ever shrink the fast set.
  freeRules: [
    {
      pathPattern: '/articles/philosophers/*',
      licenseId: 'tdl:ramp-demo-free-index-v1',
      contentUsage: 'ai-index=y',
      contentHash: '',
    },
  ],
  resolveBotKey,
  exchangeUrl: 'https://exchange.demo.ramp-protocol.org',
  mcpEndpoints: [
    {
      url: 'https://mcp.demo.ramp-protocol.org/mcp',
      transport: 'http-streamable',
      description: 'RAMP-native MCP server — ramp_fetch negotiates via the Broker.',
      extension: 'ramp-0.4-draft',
    },
  ],
};

export default config;
