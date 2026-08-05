// A publisher that issues no signing keys of its own: the key directory answers
// 404, and that is a correct deployment rather than a fault.
//
// It happens when a named contributor pushes catalog entries on the publisher's
// behalf. The contributor signs those requests with its own key, served from its
// own directory on its own domain, so the publisher has nothing to publish at
// this address. The operator documentation tells people not to open an incident
// over it, which makes the status load-bearing: if it silently became 410 or 200,
// those documents would start giving operators the wrong answer with nothing
// failing.
//
// This project exists for that posture and nothing else. Its bindings are
// BASE_BINDINGS WITHOUT WBA_KEYS_JSON (vitest.config.ts), which is the
// configuration under test rather than an oversight. The case runs on the real
// Workers runtime through SELF, so the answer comes from the route and not from a
// hand-built AppDeps. The other two runtimes cover the same path one level down,
// through their production adapters rather than a real runtime:
// tests/node/fastly-entry.test.ts and tests/node/aws-handler.test.ts.
import { SELF } from 'cloudflare:test';

import { describe, expect, it } from 'vitest';

import { WBA_PATH, WELL_KNOWN_PATH } from '../../src/types.js';
import { PUB_ORIGIN } from '../helpers/test-setup.js';

describe('key directory on a publisher that issues no keys', () => {
  it('answers 404', async () => {
    const res = await SELF.fetch(`${PUB_ORIGIN}${WBA_PATH}`);
    expect(res.status).toBe(404);
  });

  it('leaves the commercial document reachable', async () => {
    // A keyless publisher is not a broken one. Its ramp.json still has to answer,
    // because that is the address a denied bot is sent to, so the 404 above must
    // be the absence of one optional document and not a Worker that stopped
    // serving discovery.
    const res = await SELF.fetch(`${PUB_ORIGIN}${WELL_KNOWN_PATH}`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { role: string };
    expect(body.role).toBe('ROLE_PUBLISHER');
  });
});
