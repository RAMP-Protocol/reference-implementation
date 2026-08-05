import { generateKeyPairSync } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { buildDeps, parseEnv } from '../../src/config.js';
import { MAX_WBA_KEYS } from '../../src/keys.js';
import { type WbaKey, buildPublisherManifest, buildPublisherWba } from '../../src/types.js';
import { assertValidManifest, assertValidWba } from '../helpers/wellknown-schema.js';

describe('edge publisher overlay manifest conforms to the canonical RAMP schema', () => {
  it('buildPublisherManifest with exchanges, profiles, and contributors', () => {
    const m = buildPublisherManifest(
      'pub.example',
      [
        {
          domain: 'x.example',
          endpoint: 'https://x.example/v1',
          supported_profiles: ['ramp-news-v1'],
        },
      ],
      [{ domain: 'pub.example', relationship: 'publisher' }],
    );
    assertValidManifest(m);
    expect(m.role).toBe('ROLE_PUBLISHER');
    expect(m.supported_profiles).toEqual(['ramp-news-v1']);
  });

  it('buildPublisherManifest minimal (no profiles, no contributors)', () => {
    assertValidManifest(
      buildPublisherManifest('pub.example', [
        { domain: 'x.example', endpoint: 'https://x.example/v1' },
      ]),
    );
  });

  it('overlay manifest carries no identity keys (WBA split)', () => {
    const m = buildPublisherManifest('pub.example', [
      { domain: 'x.example', endpoint: 'https://x.example/v1' },
    ]) as unknown as Record<string, unknown>;
    expect(m.public_keys).toBeUndefined();
    expect(m.invalidation_url).toBeUndefined();
  });

  it('buildDeps manifest assembled from env', () => {
    const env = parseEnv({
      EXCHANGE_URL: 'https://exchange.example',
      EXCHANGE_WBA_URL: 'https://exchange.example/.well-known/http-message-signatures-directory',
      PROVIDER: 'pub.example',
      EXCHANGES_JSON: JSON.stringify([
        {
          domain: 'x.example',
          endpoint: 'https://x.example/v1',
          supported_profiles: ['ramp-news-v1'],
        },
      ]),
      CATALOG_CONTRIBUTORS_JSON: JSON.stringify([
        { domain: 'pub.example', relationship: 'publisher' },
      ]),
    });
    assertValidManifest(buildDeps(env).manifest);
  });
});

describe('edge publisher WBA directory conforms to the canonical RAMP schema', () => {
  // A REAL Ed25519 public key — Node exports OKP/Ed25519 directly as a JWK whose
  // `x` is the RFC 8037 base64url-unpadded 32-byte key (43 chars). Keeps the
  // fixture honest: after the WBA split the key is named by its thumbprint of
  // this very `x`. (Cryptographic verification is the e2e test's job.)
  const { publicKey } = generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string };
  const sampleKey: WbaKey = {
    kty: 'OKP',
    crv: 'Ed25519',
    use: 'sig',
    alg: 'EdDSA',
    x: jwk.x,
    not_before: '2020-01-01T00:00:00Z',
    not_after: '2100-01-01T00:00:00Z',
  };

  it('buildPublisherWba serves keys[] with no kid', () => {
    const wba = buildPublisherWba([sampleKey]);
    assertValidWba(wba);
    expect(wba.keys).toHaveLength(1);
    expect((wba.keys[0] as unknown as Record<string, unknown>).kid).toBeUndefined();
  });

  it('buildPublisherWba carries an optional directory-level revocation_url', () => {
    const wba = buildPublisherWba(
      [sampleKey],
      'https://pub.example/.well-known/ramp-key-revocations.json',
    );
    assertValidWba(wba);
    expect(wba.revocation_url).toBe('https://pub.example/.well-known/ramp-key-revocations.json');
  });

  it('rejects a keys[] over the maxItems bound', () => {
    // 65 keys exceeds the canonical schema's maxItems:64. Each key is valid; the
    // only fault is the array size, so an over-large directory is rejected.
    const tooMany = { keys: Array.from({ length: MAX_WBA_KEYS + 1 }, () => sampleKey) };
    expect(() => assertValidWba(tooMany)).toThrow(/schema validation failed/);
  });

  it('buildDeps wba carries keys from WBA_KEYS_JSON', () => {
    const env = parseEnv({
      EXCHANGE_URL: 'https://exchange.example',
      EXCHANGE_WBA_URL: 'https://exchange.example/.well-known/http-message-signatures-directory',
      PROVIDER: 'pub.example',
      EXCHANGES_JSON: JSON.stringify([{ domain: 'x.example', endpoint: 'https://x.example/v1' }]),
      WBA_KEYS_JSON: JSON.stringify([sampleKey]),
    });
    const wba = buildDeps(env).wba;
    expect(wba).toBeDefined();
    assertValidWba(wba);
    expect(wba?.keys).toHaveLength(1);
  });
});
