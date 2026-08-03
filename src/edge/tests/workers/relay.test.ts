// E2E relay path test: Agent → Broker → Exchange → Edge with multisig.
// This test validates the full multisig flow where:
// 1. Agent signs ExecuteTransaction to Broker with sig1
// 2. Broker preserves sig1 and adds sig2 (multisig)
// 3. Exchange verifies both signatures
// 4. Exchange returns signed URL bound to agent's thumbprint
// 5. The fetcher presents the URL to the Edge along with proof of possession
//    of the agent key the Exchange bound it to
// 6. Edge verifies the URL signature AND that proof, refusing a fetcher that
//    cannot produce it (ADR-013 D6.1, enforcement on by default). In the
//    custodial registry flow the registry holds that key and makes the fetch
//    itself (ADR-023).
//
// WBA-split identity model: a single Signature-Agent header cannot
// carry a distinct directory per hop, so the multisig chain is classified BY
// POSITION — sig1 is the originating agent, sig2+ are relay hops. The broker
// PRESERVES the agent's Signature-Agent (it only sets its own when the header is
// entirely absent). That classification lives in the Go broker/exchange, which
// this edge test represents with the verifying Exchange double below; the edge
// itself only verifies the resulting delivery URL + proof-of-possession, keyed
// by RFC 7638 thumbprint.
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
import { SELF } from 'cloudflare:test';

import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { fetchMock } from '../helpers/fetch-mock.js';

import { decodeBase64Url, encodeBase64Url } from '@ramp-protocol/sdk-l1/base64url';
import { thumbprint } from '@ramp-protocol/sdk-l1/thumbprint';
import {
  type TestKeypair,
  futureExp,
  generateKeypair,
  popHeaders,
  rawPublicKey,
  signUrl,
} from '../helpers/ed25519.js';
import {
  PUB_ORIGIN,
  setupE2ETest,
  setupOriginMock,
  setupWbaDirectoryMock,
} from '../helpers/test-setup.js';

const PAYLOAD = 'test-transaction-payload';
const encoder = new TextEncoder();

let exchangeKeypair: TestKeypair;
let exchangeKid: string;
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
  ({ keypair: exchangeKeypair, exchangeKid } = await setupE2ETest());
  agentKeypair = await generateKeypair('agent.test.v1');
  brokerKeypair = await generateKeypair('broker.relay.v1');
});

beforeEach(async () => {
  // Reset first: every route below is re-registered per test, and without the
  // reset the persisted intercepts would pile up — dispatch would then keep
  // matching the FIRST test's registration (with its captured signed URL) for
  // every later test.
  fetchMock.reset();
  // Exchange WBA directory endpoint (verify keys for the signed URL).
  setupWbaDirectoryMock(exchangeKeypair);
  // Pass-through origin behind the edge (empty 200s; status-level assertions).
  setupOriginMock();

  // Verifying Exchange double for POST /v1/execute. The signed URL it returns is
  // bound to the agent's key; the cryptographically-correct signatures for the
  // payload are precomputed so the (synchronous) reply can reject any submission
  // whose bytes differ — i.e. any tampered or forged signature.
  const agentId = await thumbprint(rawPublicKey(agentKeypair));
  const signedUrl = await signUrl(PUB_ORIGIN, exchangeKeypair.privateKey, {
    exp: futureExp(),
    kid: exchangeKid,
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

  it('serves the relay-minted bound URL to a fetcher holding the agent key', async () => {
    // Step 1-4: Agent + Broker sign, Exchange verifies multisig and returns URL.
    const signed_url = await executeMultisigFlow();
    // The Exchange binds the URL to the agent's thumbprint, and the parameter is
    // covered by the URL signature — which is what the edge check anchors to.
    expect(signed_url).toContain('agent_id=');
    expect(signed_url).toContain('sig=');

    // Step 5-6: the fetcher proves possession of the bound key and is served
    // (200 with an empty body, since no origin is configured in test).
    const agentId = await thumbprint(rawPublicKey(agentKeypair));
    const headers = await popHeaders(signed_url, agentKeypair, agentId);
    const edgeResp = await SELF.fetch(signed_url, { headers });
    expect(edgeResp.status).toBe(200);
  });

  it('refuses the relay-minted bound URL when the fetcher has no key', async () => {
    // The same URL, leaked. This is what the whole relay chain is FOR: the
    // binding survives every hop, so possession is still required at the end.
    const signed_url = await executeMultisigFlow();
    const edgeResp = await SELF.fetch(signed_url);
    expect(edgeResp.status).toBe(403);
    expect(((await edgeResp.json()) as { reason: string }).reason).toBe('missing_agent_key');
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
});
