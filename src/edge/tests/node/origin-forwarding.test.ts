// Origin body forwarding, driven on the Node fetch implementation (undici —
// what the Lambda@Edge target runs on). This placement is the point: the app
// forwards non-read bodies as streams, and undici refuses a stream body
// unless the request sets duplex, while workerd tolerates its absence. Only
// a Node-pool run makes that requirement load-bearing — remove the duplex
// option from passToOrigin and this suite fails, while every Workers-pool
// test would still pass.
import { describe, expect, it } from 'vitest';

import {
  boundUrl,
  futureExp,
  generateKeypair,
  keyThumbprint,
  popHeaders,
} from '../helpers/ed25519.js';
import { makeLogTestApp } from '../helpers/log-test-app.js';
import { PUB_ORIGIN, expectNoSignatureParams } from '../helpers/test-setup.js';

describe('origin forwarding on the Node fetch implementation', () => {
  it('forwards an unsigned POST with its body to the origin', async () => {
    const keypair = await generateKeypair('k1');
    const exchangeKid = await keyThumbprint(keypair);
    let captured: Request | undefined;
    const app = makeLogTestApp(keypair, exchangeKid, {
      originUrl: 'https://origin.pub.test',
      fetcher: (async (input: RequestInfo | URL) => {
        captured = input as Request;
        return new Response('created', { status: 201 });
      }) as unknown as typeof fetch,
    });

    const res = await app.request(`${PUB_ORIGIN}/kommentar`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'text=danke',
    });

    // A missing duplex option would make the Request construction inside
    // passToOrigin throw on undici, surfacing as the 502 origin-failure path
    // — so the 201 below is structural proof the option is present.
    expect(res.status).toBe(201);
    expect(await res.text()).toBe('created');
    expect(captured).toBeDefined();
    expect(captured?.method).toBe('POST');
    expect(new URL(captured?.url ?? '').host).toBe('origin.pub.test');
    expect(await captured?.text()).toBe('text=danke');
  });

  it('forwards a signed and bound POST with its body, signature params stripped', async () => {
    // The other path through the shared body-forwarding branch: the method
    // gate admits a signed non-read request only when the proof-of-possession
    // check will run (its covered fields include @method). This drives that
    // admitted path — verify, binding check, forward — on undici, so the
    // duplex requirement is proven for the signed write too, not only the
    // unsigned pass-through above.
    const keypair = await generateKeypair('k1');
    const exchangeKid = await keyThumbprint(keypair);
    const agentKp = await generateKeypair('agent');
    let captured: Request | undefined;
    const app = makeLogTestApp(keypair, exchangeKid, {
      originUrl: 'https://origin.pub.test',
      fetcher: (async (input: RequestInfo | URL) => {
        captured = input as Request;
        return new Response('created', { status: 201 });
      }) as unknown as typeof fetch,
    });

    const { url, agentId } = await boundUrl(PUB_ORIGIN, keypair.privateKey, agentKp, {
      path: '/kommentar',
      exp: futureExp(),
      kid: exchangeKid,
    });
    const res = await app.request(url, {
      method: 'POST',
      headers: {
        ...(await popHeaders(url, agentKp, agentId, 'POST')),
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: 'text=danke',
    });

    expect(res.status).toBe(201);
    expect(captured?.method).toBe('POST');
    const forwarded = new URL(captured?.url ?? 'https://invalid.test');
    expect(forwarded.host).toBe('origin.pub.test');
    // The origin must never see the signature params.
    expectNoSignatureParams(forwarded);
    expect(await captured?.text()).toBe('text=danke');
  });
});
