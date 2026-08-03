// NOTE: filename intentionally avoids the substring "binding" — the
// @cloudflare/vitest-pool-workers / workerd module loader fails to collect a
// test file named *binding* ("No test suite found"). Do not rename to *binding*.
//
// App-level coverage of the proof-of-possession enforcement path, exercised
// against every failure reason in the vocabulary. Enforcement is the production
// default (ADR-013 D6.1); this suite pins it explicitly through deps so the
// matrix stays independent of whatever the config default happens to be, and so
// a deployment that opts down to bearer security cannot take these cases with
// it.
import { beforeAll, describe, expect, it } from 'vitest';

import { createApp } from '../../src/app.js';
import { type AppDeps, buildPublisherManifest } from '../../src/types.js';
import {
  type TestKeypair,
  generateKeypair,
  keyThumbprint,
  signGetHeaders,
  signUrl,
} from '../helpers/ed25519.js';

const PUB_ORIGIN = 'https://pub.example.com';

let exchangeKeypair: TestKeypair;
let exchangeKid: string;
let app: ReturnType<typeof createApp>;

beforeAll(async () => {
  exchangeKeypair = await generateKeypair('exchange');
  exchangeKid = await keyThumbprint(exchangeKeypair);
  const deps: AppDeps = {
    manifest: buildPublisherManifest('pub.example.com', [
      { domain: 'exchange.test', endpoint: 'https://exchange.test' },
    ]),
    exchangeUrl: 'https://exchange.test',
    // Hand-wired verify key — no WBA directory fetch, so the app runs fully
    // in-memory with no worker env involved.
    resolveKey: async (kid) => (kid === exchangeKid ? exchangeKeypair.publicKey : undefined),
    enforceBinding: true,
  };
  app = createApp(deps);
});

async function boundUrl(agentKp: TestKeypair): Promise<{ url: string; agentId: string }> {
  const agentId = await keyThumbprint(agentKp);
  const url = await signUrl(PUB_ORIGIN, exchangeKeypair.privateKey, {
    exp: Math.floor(Date.now() / 1000) + 300,
    kid: exchangeKid,
    agentId,
  });
  return { url, agentId };
}

function popHeaders(
  url: string,
  agentKp: TestKeypair,
  keyid: string,
): Promise<Record<string, string>> {
  return signGetHeaders(url, agentKp, {
    keyid,
    created: Math.floor(Date.now() / 1000) - 5,
    expires: Math.floor(Date.now() / 1000) + 300,
  });
}

describe('proof-of-possession enforcement (deps-injected ON)', () => {
  it('200 for a bound URL with a valid proof', async () => {
    const agentKp = await generateKeypair('agent');
    const { url, agentId } = await boundUrl(agentKp);
    const res = await app.request(url, { headers: await popHeaders(url, agentKp, agentId) });
    expect(res.status).toBe(200);
  });

  it('403 missing_agent_key when no proof is presented', async () => {
    const agentKp = await generateKeypair('agent');
    const { url } = await boundUrl(agentKp);
    const res = await app.request(url);
    expect(res.status).toBe(403);
    expect(((await res.json()) as { reason: string }).reason).toBe('missing_agent_key');
  });

  it('403 thumbprint_mismatch when a different key is presented', async () => {
    const agentKp = await generateKeypair('agent');
    const wrongKp = await generateKeypair('wrong');
    const { url, agentId } = await boundUrl(agentKp);
    // Sign with the wrong key but claim the bound keyid: the presented key's
    // thumbprint no longer matches agent_id.
    const res = await app.request(url, { headers: await popHeaders(url, wrongKp, agentId) });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { reason: string }).reason).toBe('thumbprint_mismatch');
  });

  it('403 keyid_mismatch when the proof keyid is not the bound agent_id', async () => {
    const agentKp = await generateKeypair('agent');
    const { url } = await boundUrl(agentKp);
    const res = await app.request(url, {
      headers: await popHeaders(url, agentKp, 'not-the-thumbprint'),
    });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { reason: string }).reason).toBe('keyid_mismatch');
  });
});
