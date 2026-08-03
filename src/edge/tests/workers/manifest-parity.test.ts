import { describe, expect, it } from 'vitest';

import { ENV_KEYS, buildDeps, parseEnv } from '../../src/config.js';
import { readFastlyEnv } from '../../src/entries/fastly.js';
import { BASE_SCHEMA_ENV } from '../helpers/test-setup.js';

// A valid WBA directory key item (RFC 8037 OKP/Ed25519 JWK + validity window,
// NO kid — a WBA key is named by its RFC 7638 thumbprint).
const SAMPLE_KEY = {
  kty: 'OKP',
  crv: 'Ed25519',
  use: 'sig',
  alg: 'EdDSA',
  x: 'A'.repeat(43),
  not_before: '2020-01-01T00:00:00Z',
  not_after: '2030-01-01T00:00:00Z',
};

// The runtime env source, with WBA_KEYS_JSON present.
const SOURCE: Record<string, string> = {
  ...BASE_SCHEMA_ENV,
  WBA_KEYS_JSON: JSON.stringify([SAMPLE_KEY]),
};

// Each runtime adapter reads env from a different source: Cloudflare and AWS
// cast the whole env object, while Fastly Compute (no enumerable env) must
// hand-forward every key. A per-adapter omission drops a signal on that runtime
// ONLY — the exact defect where Fastly served an empty key directory.
// This parity table fails the suite the moment any adapter stops forwarding
// WBA_KEYS_JSON into the published WBA directory.
const runtimes: Array<{ name: string; env: () => ReturnType<typeof parseEnv> }> = [
  { name: 'cloudflare/aws (whole-env cast)', env: () => parseEnv(SOURCE) },
  { name: 'fastly (hand-enumerated)', env: () => readFastlyEnv((n) => SOURCE[n]) },
];

describe('WBA directory keys[] parity across edge runtimes', () => {
  for (const rt of runtimes) {
    it(`${rt.name} forwards WBA_KEYS_JSON into wba.keys[]`, () => {
      const { wba } = buildDeps(rt.env());
      expect(wba?.keys ?? [], `${rt.name} dropped WBA_KEYS_JSON`).toHaveLength(1);
      expect(wba?.keys?.[0]?.x).toBe(SAMPLE_KEY.x);
      // A WBA key carries no kid — named by thumbprint.
      expect((wba?.keys?.[0] as unknown as Record<string, unknown>)?.kid).toBeUndefined();
    });
  }
});

// Structural guard for the hand-enumeration itself: readFastlyEnv must ask its
// env reader for every schema key, so a key added to the shared EnvSchema
// cannot be silently dropped on the Fastly runtime. Cloudflare-only keys are
// the documented exception — a runtime that cannot honor a mode must not
// pretend to read it.
const CLOUDFLARE_ONLY_KEYS = ['SAME_ZONE_ORIGIN'];

describe('env-key parity for the Fastly hand-enumeration', () => {
  it('readFastlyEnv requests every schema key except the Cloudflare-only ones', () => {
    const requested = new Set<string>();
    readFastlyEnv((name) => {
      requested.add(name);
      return SOURCE[name];
    });
    const expected = ENV_KEYS.filter((k) => !CLOUDFLARE_ONLY_KEYS.includes(k));
    const missing = expected.filter((k) => !requested.has(k));
    expect(missing, `readFastlyEnv drops schema keys: ${missing.join(', ')}`).toEqual([]);
  });
});
