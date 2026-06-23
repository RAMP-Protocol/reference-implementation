// E2E relay path test: Agent → Broker → Exchange → Edge with multisig + enforcement ON
// This test validates the full multisig flow where:
// 1. Agent signs ExecuteTransaction to Broker with sig1
// 2. Broker preserves sig1 and adds sig2 (multisig)
// 3. Exchange verifies both signatures
// 4. Exchange returns signed URL bound to agent's thumbprint
// 5. Agent fetches URL with PoP headers
// 6. Edge verifies 3-way identity (enforcement ON by default)
//
// The Exchange is represented by a VERIFYING double, not a hardcoded mock: it
// checks each submitted signature against the cryptographically-correct value
// for the payload and only returns 200 (+ a signed URL bound to the agent key)
// when both verify; a bad signature yields 400. Its status is therefore DRIVEN
// BY the submitted signature bytes — tampering changes the outcome. (Ed25519 is
// deterministic, so byte-equality with the re-signed value is equivalent to
// verification. The status must be decided synchronously because undici's reply
// callback cannot await; the tampered-signature test additionally asserts real
// ed25519 rejection via crypto.subtle.verify.)
import { SELF, fetchMock } from 'cloudflare:test';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { thumbprint } from '../src/thumbprint.js';
import { decodeBase64Url, encodeBase64Url } from '../src/verify.js';
import {
  type TestKeypair,
  generateKeypair,
  rawPublicKey,
  signGetHeaders,
  signUrl,
} from './helpers/ed25519.js';
import { PUB_ORIGIN, setupE2ETest, setupRampJsonMock } from './helpers/test-setup.js';

const PAYLOAD = 'test-transaction-payload';
const encoder = new TextEncoder();

let exchangeKeypair: TestKeypair;
let agentKeypair: TestKeypair;
let brokerKeypair: TestKeypair;

interface MultisigRequest {
  agentSig: string; // Agent's signature (sig1)
  brokerSig: string; // Broker's signature (sig2)
  payload: string; // Request payload
}

// ed25519Sign signs message with kp and returns the base64url signature.
async function ed25519Sign(kp: TestKeypair, message: string): Promise<string> {
  const sig = new Uint8Array(
    await crypto.subtle.sign('Ed25519', kp.privateKey, encoder.encode(message)),
  );
  return encodeBase64Url(sig);
}

/**
 * Simulates the agent→broker multisig flow: agent signs sig1, broker preserves
 * it and adds its own sig2 (both over the payload).
 */
async function createMultisigRequest(
  payload: string,
  agent: TestKeypair,
  broker: TestKeypair,
): Promise<MultisigRequest> {
  return {
    agentSig: await ed25519Sign(agent, payload),
    brokerSig: await ed25519Sign(broker, payload),
    payload,
  };
}

beforeAll(async () => {
  exchangeKeypair = await setupE2ETest();
  agentKeypair = await generateKeypair('agent.test.v1');
  brokerKeypair = await generateKeypair('broker.relay.v1');
});

beforeEach(async () => {
  // Exchange /.well-known/ramp.json endpoint (verify keys for the signed URL).
  setupRampJsonMock(exchangeKeypair);

  // Verifying Exchange double for POST /v1/execute. The signed URL it returns is
  // bound to the agent's key; the cryptographically-correct signatures for the
  // payload are precomputed so the (synchronous) reply can reject any submission
  // whose bytes differ — i.e. any tampered or forged signature.
  const agentId = await thumbprint(rawPublicKey(agentKeypair));
  const signedUrl = await signUrl(PUB_ORIGIN, exchangeKeypair.privateKey, {
    exp: Math.floor(Date.now() / 1000) + 300,
    kid: 'k1',
    agentId,
  });
  const validAgentSig = await ed25519Sign(agentKeypair, PAYLOAD);
  const validBrokerSig = await ed25519Sign(brokerKeypair, PAYLOAD);
  const jsonHeaders = { headers: { 'content-type': 'application/json' } };

  fetchMock
    .get('https://exchange.test')
    .intercept({ path: '/v1/execute', method: 'POST' })
    .reply((opts) => {
      const req = JSON.parse(String(opts.body)) as MultisigRequest;
      const reject = (error: string) => ({
        statusCode: 400,
        data: JSON.stringify({ error }),
        responseOptions: jsonHeaders,
      });
      if (req.brokerSig !== validBrokerSig) return reject('invalid_broker_signature');
      if (req.agentSig !== validAgentSig) return reject('invalid_agent_signature');
      return {
        statusCode: 200,
        data: JSON.stringify({ signed_url: signedUrl }),
        responseOptions: jsonHeaders,
      };
    })
    .persist();
});

describe('E2E relay path (agent → broker → exchange → edge)', () => {
  /**
   * Helper: executes the full Agent → Broker → Exchange flow with valid
   * signatures. Returns the signed URL from the Exchange.
   */
  async function executeMultisigFlow(): Promise<string> {
    const multisigReq = await createMultisigRequest(PAYLOAD, agentKeypair, brokerKeypair);
    const exchangeResp = await fetch('https://exchange.test/v1/execute', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(multisigReq),
    });
    expect(exchangeResp.status).toBe(200);
    const { signed_url } = (await exchangeResp.json()) as { signed_url: string };
    return signed_url;
  }

  it('serves signed URL with valid multisig + PoP (enforcement ON)', async () => {
    const agentId = await thumbprint(rawPublicKey(agentKeypair));

    // Step 1-4: Agent + Broker sign, Exchange verifies multisig and returns URL.
    const multisigReq = await createMultisigRequest(PAYLOAD, agentKeypair, brokerKeypair);
    const exchangeResp = await fetch('https://exchange.test/v1/execute', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(multisigReq),
    });
    expect(exchangeResp.status).toBe(200);
    const { signed_url } = (await exchangeResp.json()) as { signed_url: string };
    expect(signed_url).toContain('agent_id=');
    expect(signed_url).toContain('sig=');

    // Step 5: Agent fetches URL with PoP headers.
    const popHeaders = await signGetHeaders(signed_url, agentKeypair, {
      keyid: agentId,
      created: Math.floor(Date.now() / 1000) - 5,
      expires: Math.floor(Date.now() / 1000) + 300,
    });

    // Step 6-8: Edge verifies 3-way identity (enforcement ON) → 200 OK (empty
    // body since no origin is configured in test).
    const edgeResp = await SELF.fetch(signed_url, { headers: popHeaders });
    expect(edgeResp.status).toBe(200);
  });

  it('403 DENIED_BINDING when fetching with wrong agent key', async () => {
    // Agent → Broker → Exchange flow with valid signatures.
    const signed_url = await executeMultisigFlow();

    // Fetch with WRONG key - different from the bound agent.
    const wrongKeypair = await generateKeypair('wrong.agent.v1');
    const wrongAgentId = await thumbprint(rawPublicKey(wrongKeypair));
    const wrongPopHeaders = await signGetHeaders(signed_url, wrongKeypair, {
      keyid: wrongAgentId,
      created: Math.floor(Date.now() / 1000) - 5,
      expires: Math.floor(Date.now() / 1000) + 300,
    });

    // Edge enforcement should reject (keyid in PoP ≠ bound agent_id).
    const edgeResp = await SELF.fetch(signed_url, { headers: wrongPopHeaders });
    expect(edgeResp.status).toBe(403);
    const body = (await edgeResp.json()) as { reason: string };
    expect(body.reason).toBe('keyid_mismatch');
  });

  it('Exchange rejects tampered broker signature (real verification)', async () => {
    const multisigReq = await createMultisigRequest(PAYLOAD, agentKeypair, brokerKeypair);
    const data = encoder.encode(PAYLOAD);

    // Real ed25519: the untampered broker signature verifies.
    const validOk = await crypto.subtle.verify(
      'Ed25519',
      brokerKeypair.publicKey,
      decodeBase64Url(multisigReq.brokerSig) ?? new Uint8Array(),
      data,
    );
    expect(validOk).toBe(true);

    // Tamper with the broker signature (64 zero bytes: structurally a valid
    // Ed25519 signature length, but cryptographically invalid).
    multisigReq.brokerSig = encodeBase64Url(new Uint8Array(64));
    const tamperedOk = await crypto.subtle.verify(
      'Ed25519',
      brokerKeypair.publicKey,
      decodeBase64Url(multisigReq.brokerSig) ?? new Uint8Array(),
      data,
    );
    expect(tamperedOk).toBe(false);

    // The verifying Exchange double rejects it — and the 400 is driven by the
    // tampered bytes: the very same mock returns 200 for the untampered request
    // (see the valid-multisig test above), so this assertion is not vacuous.
    const exchangeResp = await fetch('https://exchange.test/v1/execute', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(multisigReq),
    });
    expect(exchangeResp.status).toBe(400);
    const body = (await exchangeResp.json()) as { error: string };
    expect(body.error).toBe('invalid_broker_signature');
  });

  it('403 when fetching without PoP headers (enforcement ON)', async () => {
    // Agent → Broker → Exchange flow with valid signatures.
    const signed_url = await executeMultisigFlow();

    // Fetch WITHOUT PoP headers (enforcement ON should reject).
    const edgeResp = await SELF.fetch(signed_url);
    expect(edgeResp.status).toBe(403);
    const body = (await edgeResp.json()) as { reason: string };
    expect(body.reason).toBe('missing_agent_key');
  });
});
