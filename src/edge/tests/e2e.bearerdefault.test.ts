// NOTE: filename intentionally avoids the substring "binding" — the
// @cloudflare/vitest-pool-workers / workerd module loader fails to collect a
// test file named *binding* ("No test suite found"). "bearerdefault" captures
// the same intent (the bearer-by-default posture). Do not rename to *binding*.
import { SELF } from 'cloudflare:test';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { thumbprint } from '../src/thumbprint.js';
import { type TestKeypair, generateKeypair, rawPublicKey, signUrl } from './helpers/ed25519.js';
import { PUB_ORIGIN, setupE2ETest, setupRampJsonMock } from './helpers/test-setup.js';

let keypair: TestKeypair;

beforeAll(async () => {
  keypair = await setupE2ETest();
});

beforeEach(() => {
  setupRampJsonMock(keypair);
});

// This suite runs under vitest.binding-off.config.ts with RAMP_ENFORCE_BINDING
// 'false' — the production default (ADR-013 D6.1 bearer posture). A bound URL
// (carrying agent_id) is then served on a valid URL signature alone; the edge
// does NOT run the proof-of-possession check. This guards against a regression
// that enforced binding by default, which would 403 these requests and break
// v1's MCP -> Broker -> Exchange relay topology (where the fetcher cannot prove
// possession of the broker-bound key).
describe('agent-key binding default (enforcement OFF)', () => {
  async function boundUrl(agentKp: TestKeypair): Promise<string> {
    const agentId = await thumbprint(rawPublicKey(agentKp));
    return signUrl(PUB_ORIGIN, keypair.privateKey, {
      exp: Math.floor(Date.now() / 1000) + 300,
      kid: 'k1',
      agentId,
    });
  }

  it('serves a bound URL with NO proof headers as 200 (bearer default)', async () => {
    const agentKp = await generateKeypair('agent');
    const url = await boundUrl(agentKp);
    const res = await SELF.fetch(url);
    expect(res.status).toBe(200);
  });

  it('serves a bound URL with a garbage proof as 200 (proof ignored when OFF)', async () => {
    const agentKp = await generateKeypair('agent');
    const url = await boundUrl(agentKp);
    // A proof that WOULD be rejected under enforcement (unparseable key) must
    // not matter here — enforcement is off, so the edge never inspects it.
    const res = await SELF.fetch(url, {
      headers: {
        'X-RAMP-Agent-Key': 'garbage',
        'Signature-Input':
          'sig1=("@method" "@target-uri");keyid="x";alg="ed25519";created=1;expires=9999999999',
        Signature: 'sig1=:AAAA:',
      },
    });
    expect(res.status).toBe(200);
  });
});
