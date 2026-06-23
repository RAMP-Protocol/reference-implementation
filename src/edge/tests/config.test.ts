import { describe, expect, it } from 'vitest';

import { buildDeps, parseEnv } from '../src/config.js';

// Minimum env the schema accepts. Tests extend this object.
const baseEnv = {
  EXCHANGE_URL: 'http://exchange:8081',
  EXCHANGE_MANIFEST_URL: 'http://exchange:8081/.well-known/ramp.json',
  PROVIDER: 'edge.e2e.local',
  EXCHANGES_JSON: JSON.stringify([
    {
      domain: 'exchange.e2e.local',
      endpoint: 'http://exchange:8081',
      supported_profiles: ['ramp-news-v1'],
    },
  ]),
};

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

describe('RAMP_ENFORCE_BINDING', () => {
  it('defaults binding enforcement ON (ADR-013 D6.1 flip)', () => {
    const deps = buildDeps(parseEnv(baseEnv));
    expect(deps.enforceBinding).toBe(true);
  });

  it('enforces by default, opts out only when explicitly set to "false"', () => {
    const on = buildDeps(parseEnv({ ...baseEnv, RAMP_ENFORCE_BINDING: 'true' }));
    expect(on.enforceBinding).toBe(true);
    const off = buildDeps(parseEnv({ ...baseEnv, RAMP_ENFORCE_BINDING: 'false' }));
    expect(off.enforceBinding).toBe(false);
    const unset = buildDeps(parseEnv(baseEnv));
    expect(unset.enforceBinding).toBe(true); // defaults ON
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
