import { readFileSync } from 'node:fs';
import { URL, fileURLToPath } from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';

import { buildDeps, parseEnv } from '../src/config.js';
import { buildPublisherManifest } from '../src/types.js';

// The edge is the only one of the three manifest producers (Go exchange/broker,
// Python mcp, TS edge) whose output is hand-built rather than schema-validated.
// Pin it to the SAME canonical schema the Go consumer enforces, so a required
// field, renamed enum, or shape change fails here instead of silently serving a
// document the broker probe would reject at runtime.
const schemaPath = fileURLToPath(
  new URL('../../../internal/rampwellknown/schema/ramp-well-known.json', import.meta.url),
);
// biome-ignore lint/suspicious/noExplicitAny: a JSON Schema document is untyped.
const schema = JSON.parse(readFileSync(schemaPath, 'utf8')) as any;
// strict:false: the schema carries a non-standard `comment` keyword for docs.
const ajv = new Ajv2020({ strict: false });
const validateManifest = ajv.compile(schema);

function assertValid(doc: unknown): void {
  if (!validateManifest(doc)) {
    throw new Error(`manifest failed canonical schema: ${JSON.stringify(validateManifest.errors)}`);
  }
}

describe('edge publisher manifest conforms to the canonical RAMP schema', () => {
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
    assertValid(m);
    expect(m.role).toBe('ROLE_PUBLISHER');
    expect(m.supported_profiles).toEqual(['ramp-news-v1']);
  });

  it('buildPublisherManifest minimal (no profiles, no contributors)', () => {
    assertValid(
      buildPublisherManifest('pub.example', [
        { domain: 'x.example', endpoint: 'https://x.example/v1' },
      ]),
    );
  });

  it('buildDeps manifest assembled from env', () => {
    const env = parseEnv({
      EXCHANGE_URL: 'https://exchange.example',
      EXCHANGE_MANIFEST_URL: 'https://exchange.example/.well-known/ramp.json',
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
    assertValid(buildDeps(env).manifest);
  });
});
