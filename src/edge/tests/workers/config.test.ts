import { describe, expect, it } from 'vitest';

import { buildDeps, parseEnv } from '../../src/config.js';
// Minimum env the schema accepts. Tests extend this object.
import { BASE_SCHEMA_ENV as baseEnv } from '../helpers/test-setup.js';

describe('unified manifest', () => {
  it('builds a role=ROLE_PUBLISHER manifest with domain from PROVIDER', () => {
    const deps = buildDeps(parseEnv(baseEnv));
    expect(deps.manifest.ver).toBe('1.0');
    expect(deps.manifest.role).toBe('ROLE_PUBLISHER');
    expect(deps.manifest.domain).toBe('edge.e2e.local');
  });

  it('maps EXCHANGES_JSON entries to AuthorizedExchange with DIRECT relationship', () => {
    const deps = buildDeps(parseEnv(baseEnv));
    expect(deps.manifest.exchanges).toEqual([
      {
        domain: 'exchange.e2e.local',
        endpoint: 'http://exchange:8081',
        relationship: 'PROVIDER_RELATIONSHIP_DIRECT',
      },
    ]);
  });

  it('hoists per-exchange supported_profiles into a deduped top-level union', () => {
    const raw = JSON.stringify([
      { domain: 'a.test', endpoint: 'http://a:1', supported_profiles: ['p1', 'p2'] },
      { domain: 'b.test', endpoint: 'http://b:1', supported_profiles: ['p2', 'p3'] },
    ]);
    const deps = buildDeps(parseEnv({ ...baseEnv, EXCHANGES_JSON: raw }));
    expect(deps.manifest.supported_profiles).toEqual(['p1', 'p2', 'p3']);
  });

  it('omits supported_profiles when no exchange declares any', () => {
    const raw = JSON.stringify([{ domain: 'a.test', endpoint: 'http://a:1' }]);
    const deps = buildDeps(parseEnv({ ...baseEnv, EXCHANGES_JSON: raw }));
    expect(deps.manifest.supported_profiles).toBeUndefined();
  });

  it('sources exchangeUrl (X-RAMP-Exchange hint) from EXCHANGE_URL', () => {
    const deps = buildDeps(parseEnv(baseEnv));
    expect(deps.exchangeUrl).toBe('http://exchange:8081');
  });
});

describe('bot pattern overrides', () => {
  it('compiles BOT_UA_ALLOW_JSON / BOT_UA_DENY_JSON case-insensitively', () => {
    const deps = buildDeps(
      parseEnv({
        ...baseEnv,
        BOT_UA_ALLOW_JSON: JSON.stringify(['FriendlyIndexer']),
        BOT_UA_DENY_JSON: JSON.stringify(['EvilScraper']),
      }),
    );
    expect(deps.botAllowPatterns?.[0]?.test('friendlyindexer/1.0')).toBe(true);
    expect(deps.botDenyPatterns?.[0]?.test('EVILSCRAPER/2.0')).toBe(true);
  });

  it('rejects more than 64 patterns — a bloated list must fail the deploy', () => {
    const tooMany = JSON.stringify(Array.from({ length: 65 }, (_, i) => `bot-${i}`));
    expect(() => buildDeps(parseEnv({ ...baseEnv, BOT_UA_DENY_JSON: tooMany }))).toThrow();
  });

  it('rejects a pattern source over 256 chars — oversized sources must fail the deploy', () => {
    // Length cap only: regex STRUCTURE is not analyzed, so a short
    // backtracking pattern would pass. The comment on parseBotPatterns says
    // why and what operators must avoid.
    const oversized = JSON.stringify(['b'.repeat(300)]);
    expect(() => buildDeps(parseEnv({ ...baseEnv, BOT_UA_DENY_JSON: oversized }))).toThrow();
  });
});

describe('binding enforcement', () => {
  it('is ON when the env says nothing', () => {
    // ADR-013 D6.1: default enforce wherever the edge can run the check. The
    // default is the security posture, so an operator who sets nothing gets
    // the safe one — and the custodial flow satisfies it, because the registry
    // holds the bound key and makes the fetch itself (ADR-023).
    const deps = buildDeps(parseEnv(baseEnv));
    expect(deps.enforceBinding).toBe(true);
  });

  it('is ON when the env asks for it', () => {
    const deps = buildDeps(parseEnv({ ...baseEnv, RAMP_ENFORCE_BINDING: 'true' }));
    expect(deps.enforceBinding).toBe(true);
  });

  it('can be opted down to bearer security', () => {
    // The escape hatch exists so a worker can roll AHEAD of a registry that
    // cannot yet present the bound key. With it set, a delivery URL is a plain
    // bearer credential until it expires.
    const deps = buildDeps(parseEnv({ ...baseEnv, RAMP_ENFORCE_BINDING: 'false' }));
    expect(deps.enforceBinding).toBe(false);
  });

  it('rejects a value that is neither true nor false', () => {
    // A typo must fail the deploy rather than silently pick a posture.
    expect(() => parseEnv({ ...baseEnv, RAMP_ENFORCE_BINDING: 'yes' })).toThrow();
  });
});

describe('RAMP_VERIFY_KEYS', () => {
  it('rejects malformed JSON', () => {
    expect(() => buildDeps(parseEnv({ ...baseEnv, RAMP_VERIFY_KEYS: 'not-json' }))).toThrow();
  });

  it('rejects an empty array', () => {
    expect(() => buildDeps(parseEnv({ ...baseEnv, RAMP_VERIFY_KEYS: '[]' }))).toThrow();
  });

  it('rejects a non-Ed25519 JWK', () => {
    const raw = JSON.stringify([{ kty: 'RSA', crv: 'Ed25519', kid: 'k', x: 'AA' }]);
    expect(() => buildDeps(parseEnv({ ...baseEnv, RAMP_VERIFY_KEYS: raw }))).toThrow();
  });
});

describe('CATALOG_CONTRIBUTORS_JSON', () => {
  it('omits the manifest field when env is unset', () => {
    const deps = buildDeps(parseEnv(baseEnv));
    expect(deps.manifest.catalog_contributors).toBeUndefined();
  });

  it('parses a list of contributors', () => {
    const raw = JSON.stringify([
      { domain: 'catalog-contributor-e2e', relationship: 'harness' },
      { domain: 'wordpress-plugin', relationship: 'cms' },
    ]);
    const deps = buildDeps(parseEnv({ ...baseEnv, CATALOG_CONTRIBUTORS_JSON: raw }));
    expect(deps.manifest.catalog_contributors).toEqual([
      { domain: 'catalog-contributor-e2e', relationship: 'harness' },
      { domain: 'wordpress-plugin', relationship: 'cms' },
    ]);
  });

  it('rejects malformed JSON', () => {
    expect(() =>
      buildDeps(parseEnv({ ...baseEnv, CATALOG_CONTRIBUTORS_JSON: 'not-json' })),
    ).toThrow();
  });

  it('rejects entries missing required fields', () => {
    const raw = JSON.stringify([{ domain: 'x' }]); // missing relationship
    expect(() => buildDeps(parseEnv({ ...baseEnv, CATALOG_CONTRIBUTORS_JSON: raw }))).toThrow();
  });
});

describe('WBA_KEYS_JSON canonical JWK validation', () => {
  // A canonical OKP/Ed25519 WBA signing key: const kty/crv/use/alg, a 43-char
  // base64url x, RFC3339 validity bounds, and NO kid (named by thumbprint). Each
  // negative case mutates exactly one field away from canonical.
  const validKey = {
    kty: 'OKP',
    crv: 'Ed25519',
    use: 'sig',
    alg: 'EdDSA',
    x: 'A'.repeat(43),
    not_before: '2020-01-01T00:00:00Z',
    not_after: '2100-01-01T00:00:00Z',
  };

  it('accepts a canonical WBA key and serves it in the directory', () => {
    const raw = JSON.stringify([validKey]);
    const deps = buildDeps(parseEnv({ ...baseEnv, WBA_KEYS_JSON: raw }));
    expect(deps.wba?.keys).toHaveLength(1);
    expect(deps.wba?.keys?.[0]?.use).toBe('sig');
  });

  it('serves no WBA directory when WBA_KEYS_JSON is unset', () => {
    const deps = buildDeps(parseEnv(baseEnv));
    expect(deps.wba).toBeUndefined();
  });

  it('advertises WBA_REVOCATION_URL as the directory revocation_url', () => {
    const raw = JSON.stringify([validKey]);
    const deps = buildDeps(
      parseEnv({
        ...baseEnv,
        WBA_KEYS_JSON: raw,
        WBA_REVOCATION_URL: 'https://edge.e2e.local/.well-known/ramp-key-revocations.json',
      }),
    );
    expect(deps.wba?.revocation_url).toBe(
      'https://edge.e2e.local/.well-known/ramp-key-revocations.json',
    );
  });

  it('rejects use !== "sig" (canonical const)', () => {
    const raw = JSON.stringify([{ ...validKey, use: 'enc' }]);
    expect(() => buildDeps(parseEnv({ ...baseEnv, WBA_KEYS_JSON: raw }))).toThrow();
  });

  it('rejects a non-RFC3339 not_before', () => {
    const raw = JSON.stringify([{ ...validKey, not_before: 'soon' }]);
    expect(() => buildDeps(parseEnv({ ...baseEnv, WBA_KEYS_JSON: raw }))).toThrow();
  });

  it('rejects a non-RFC3339 not_after', () => {
    const raw = JSON.stringify([{ ...validKey, not_after: '2100-01-01' }]);
    expect(() => buildDeps(parseEnv({ ...baseEnv, WBA_KEYS_JSON: raw }))).toThrow();
  });
});
