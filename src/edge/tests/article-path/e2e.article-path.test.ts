// Shared-URL delivery on the real Cloudflare runtime: ONE article URL — the
// same URL a browser user opens — carries every outcome. There is no licensed
// path or separate hostname; the worker alone decides per request:
//
//   1. signature params present → verify Ed25519 signature + expiry, then serve
//      the article from the origin (403 on any failure, origin untouched);
//   2. the URL is bound to an agent (agent_id) → additionally require the
//      caller's proof of possession of that agent's key;
//   3. no signature, browser-like client → pass through to the origin untouched;
//   4. no signature, AI-bot User-Agent → 403 with X-Content-Rules pointing at
//      /.well-known/ramp.json, which itself stays fetchable without a signature.
//
// The origin is an external system, so it is mocked at the fetch boundary
// (the shared fetch-mock helper) with net-connect disabled. That makes "the
// content was NOT served" structural in the deny tests: no origin intercept is
// registered there, so any attempted origin fetch would throw inside the worker
// and the response could not be the clean 403 the test asserts. In the serve
// tests the asserted body can only come from the origin mock.
import { SELF } from 'cloudflare:test';

import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { fetchMock } from '../helpers/fetch-mock.js';

import {
  type TestKeypair,
  boundUrl,
  futureExp,
  generateKeypair,
  pastExp,
  popHeaders,
  signUrl,
  tamperSignature,
} from '../helpers/ed25519.js';
import { PUB_ORIGIN, setupE2ETest, setupWbaDirectoryMock } from '../helpers/test-setup.js';

// The article's public URL path — identical for humans and agents.
const ARTICLE_PATH = '/problemloesung-handy-verbindet-sich-nicht-mit-wlan_231474';
const ARTICLE_URL = `${PUB_ORIGIN}${ARTICLE_PATH}`;
const ARTICLE_BODY = '<html><body><h1>Handy verbindet sich nicht mit WLAN</h1></body></html>';

const BROWSER_UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15';

let keypair: TestKeypair;
let exchangeKid: string;

beforeAll(async () => {
  ({ keypair, exchangeKid } = await setupE2ETest());
});

beforeEach(() => {
  // Reset first: a one-shot intercept a previous test registered but never
  // consumed must not linger into this test's route table.
  fetchMock.reset();
  setupWbaDirectoryMock(keypair);
});

// One-shot origin intercept for the article. Registered ONLY by tests that
// expect the article to be served; its absence (plus disabled net connect) is
// what proves the deny paths never reach the origin. The worker strips the
// signature query before forwarding, so the origin sees the bare article path.
function mockOriginArticle(): void {
  fetchMock
    .get('https://origin.pub.test')
    .intercept({ path: ARTICLE_PATH, method: 'GET' })
    .reply(200, ARTICLE_BODY, { headers: { 'content-type': 'text/html; charset=utf-8' } });
}

describe('outcome 1: signed agent request on the article URL', () => {
  it('serves the article for a valid signed URL', async () => {
    mockOriginArticle();
    const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      path: ARTICLE_PATH,
      exp: futureExp(),
      kid: exchangeKid,
    });
    const res = await SELF.fetch(url);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(ARTICLE_BODY);
  });

  it('403 for a tampered signature — article not served', async () => {
    const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      path: ARTICLE_PATH,
      exp: futureExp(),
      kid: exchangeKid,
    });
    const res = await SELF.fetch(tamperSignature(url));
    expect(res.status).toBe(403);
    expect(((await res.json()) as { reason: string }).reason).toBe('signature_mismatch');
  });

  it('403 for a URL signed with the wrong key — article not served', async () => {
    const wrongKp = await generateKeypair('wrong-signer');
    const url = await signUrl(PUB_ORIGIN, wrongKp.privateKey, {
      path: ARTICLE_PATH,
      exp: futureExp(),
      kid: exchangeKid,
    });
    const res = await SELF.fetch(url);
    expect(res.status).toBe(403);
    expect(((await res.json()) as { reason: string }).reason).toBe('signature_mismatch');
  });

  it('403 for an expired URL — article not served', async () => {
    const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      path: ARTICLE_PATH,
      exp: pastExp(),
      kid: exchangeKid,
    });
    const res = await SELF.fetch(url);
    expect(res.status).toBe(403);
    expect(((await res.json()) as { reason: string }).reason).toBe('expired');
  });

  it('serves a HEAD probe of a signed URL — HEAD is a read method like GET', async () => {
    // HEAD is the second member of the method gate's allowlist (the Allow
    // header advertises it); this pins it so a narrowing to GET-only — which
    // would break every prefetch/probe in production — cannot stay green.
    fetchMock
      .get('https://origin.pub.test')
      .intercept({ path: ARTICLE_PATH, method: 'HEAD' })
      .reply(200, '', { headers: { 'content-type': 'text/html; charset=utf-8' } });
    const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      path: ARTICLE_PATH,
      exp: futureExp(),
      kid: exchangeKid,
    });
    const res = await SELF.fetch(url, { method: 'HEAD' });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('');
  });
});

describe('write replay of a signed read URL', () => {
  // The URL signature covers the URL alone — never the method — and the gate
  // is a GET/HEAD allowlist, so every non-read method must be refused
  // identically. Driving all four pins the allowlist shape: a regression that
  // only blocked POST would still let a held read URL turn into a PUT or
  // DELETE against the origin. No origin intercept is registered here, so the
  // clean 405 also proves the origin was never contacted (an attempted fetch
  // would throw and surface as 502).
  it.each(['POST', 'PUT', 'DELETE', 'PATCH'])(
    '405 when the signed article URL is replayed as %s',
    async (method) => {
      const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
        path: ARTICLE_PATH,
        exp: futureExp(),
        kid: exchangeKid,
      });
      const res = await SELF.fetch(url, { method, body: 'payload' });
      expect(res.status).toBe(405);
      expect(res.headers.get('allow')).toBe('GET, HEAD');
      expect(((await res.json()) as { reason: string }).reason).toBe('method_not_bound');
    },
  );
});

// A bound article URL releases the article only against proof of possession of
// the key it names (ADR-013 D3), which is what makes a leaked URL worthless. The
// custodial registry flow satisfies this because the registry holds the agent's
// key in Vault and makes the bound fetch itself (ADR-023) — the agent never holds
// that key and never fetches. The full failure-reason matrix lives in
// tests/workers/pop-enforce.test.ts.
describe('outcome 2: bound URL on the article path requires the bound key', () => {
  it('serves the article when the bound agent proves its key', async () => {
    mockOriginArticle();
    const agentKp = await generateKeypair('agent');
    const { url, agentId } = await boundUrl(PUB_ORIGIN, keypair.privateKey, agentKp, {
      path: ARTICLE_PATH,
      exp: futureExp(),
      kid: exchangeKid,
    });
    const res = await SELF.fetch(url, { headers: await popHeaders(url, agentKp, agentId) });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(ARTICLE_BODY);
  });

  // The security property, asserted rather than left implicit: a leaked bound
  // URL is worthless to whoever holds it, because the article is released only
  // against proof of possession of the key the URL names (ADR-013 D3). This is
  // the assertion the 2026-07-27 bearer amendment had inverted.
  it('refuses a leaked bound URL fetched without any proof', async () => {
    mockOriginArticle();
    const agentKp = await generateKeypair('agent');
    const { url } = await boundUrl(PUB_ORIGIN, keypair.privateKey, agentKp, {
      path: ARTICLE_PATH,
      exp: futureExp(),
      kid: exchangeKid,
    });
    const res = await SELF.fetch(url);
    expect(res.status).toBe(403);
    expect(((await res.json()) as { reason: string }).reason).toBe('missing_agent_key');
  });
});

describe('outcome 3: human browser request on the article URL', () => {
  it('passes through to the origin with no verification and no 403 risk', async () => {
    mockOriginArticle();
    const res = await SELF.fetch(ARTICLE_URL, { headers: { 'user-agent': BROWSER_UA } });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(ARTICLE_BODY);
  });
});

describe('forwarding correctness on the article URL', () => {
  it('keeps the query string on unsigned human pass-through', async () => {
    fetchMock
      .get('https://origin.pub.test')
      .intercept({ path: ARTICLE_PATH, query: { page: '2', utm_source: 'mail' }, method: 'GET' })
      .reply(200, ARTICLE_BODY, { headers: { 'content-type': 'text/html; charset=utf-8' } });
    const res = await SELF.fetch(`${ARTICLE_URL}?page=2&utm_source=mail`, {
      headers: { 'user-agent': BROWSER_UA },
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(ARTICLE_BODY);
  });

  it('strips reserved signature params from UNSIGNED pass-through too', async () => {
    // Reserved-namespace invariant: the origin must never see exp/sig/kid/
    // agent_id. Legitimate traffic never delivers them (the signed path
    // strips them after verification), so on the unsigned path they can only
    // be attacker-injected — a browser-UA caller adding ?agent_id=... must
    // not be able to plant spoofable attribution data at the origin. Exact
    // pathname+search match: the intercept matches ONLY the cleaned URL, so
    // any leaked param would make the fetch throw (net connect disabled).
    fetchMock
      .get('https://origin.pub.test')
      .intercept({ path: `${ARTICLE_PATH}?page=2`, method: 'GET' })
      .reply(200, ARTICLE_BODY, { headers: { 'content-type': 'text/html; charset=utf-8' } });
    const res = await SELF.fetch(`${ARTICLE_URL}?page=2&agent_id=spoofed&kid=fake&exp=123`, {
      headers: { 'user-agent': BROWSER_UA },
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(ARTICLE_BODY);
  });

  it('strips only the signature params on the signed path, keeping the rest', async () => {
    // Exact pathname+search match (no `query` option): the intercept matches
    // ONLY the fully-stripped URL. If any signature param (exp/kid/sig) leaked
    // through to the origin, the fetch would go unmatched and throw (net
    // connect is disabled), so the 200 below proves the strip actually ran —
    // a query-subset match would stay green with the params still attached.
    fetchMock
      .get('https://origin.pub.test')
      .intercept({ path: `${ARTICLE_PATH}?page=2`, method: 'GET' })
      .reply(200, ARTICLE_BODY, { headers: { 'content-type': 'text/html; charset=utf-8' } });
    const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      path: ARTICLE_PATH,
      exp: futureExp(),
      kid: exchangeKid,
      query: { page: '2' },
    });
    const res = await SELF.fetch(url);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(ARTICLE_BODY);
  });

  it('forwards a POST with its body — a form must not 404 or 403', async () => {
    fetchMock
      .get('https://origin.pub.test')
      .intercept({ path: '/kommentar', method: 'POST', body: 'text=danke' })
      .reply(201, 'created');
    const res = await SELF.fetch(`${PUB_ORIGIN}/kommentar`, {
      method: 'POST',
      // No user-agent on purpose: webhook-style callers without a UA must not
      // hit the bot gate on non-GET methods.
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'text=danke',
    });
    expect(res.status).toBe(201);
    expect(await res.text()).toBe('created');
  });

  it('returns an origin redirect to the client instead of following it', async () => {
    fetchMock
      .get('https://origin.pub.test')
      .intercept({ path: ARTICLE_PATH, method: 'GET' })
      .reply(301, '', { headers: { location: '/umgezogen' } });
    const res = await SELF.fetch(ARTICLE_URL, {
      headers: { 'user-agent': BROWSER_UA },
      redirect: 'manual',
    });
    expect(res.status).toBe(301);
    expect(res.headers.get('location')).toBe('/umgezogen');
  });

  it('502 when the origin is unreachable, not a naked 500', async () => {
    // No origin intercept + disabled net connect: the origin fetch throws.
    const res = await SELF.fetch(ARTICLE_URL, { headers: { 'user-agent': BROWSER_UA } });
    expect(res.status).toBe(502);
    const body = (await res.json()) as { error: string; reason: string };
    expect(body.error).toContain('Origin');
    expect(body.reason).toBe('origin_fetch_failed');
  });
});

describe('outcome 4: unsigned AI-bot request on the article URL', () => {
  it('403 with X-Content-Rules and a negotiation hint — article not served', async () => {
    const res = await SELF.fetch(ARTICLE_URL, { headers: { 'user-agent': 'GPTBot/1.0' } });
    expect(res.status).toBe(403);
    expect(res.headers.get('x-content-rules')).toBe(`${PUB_ORIGIN}/.well-known/ramp.json`);
    expect(res.headers.get('x-ramp-exchange')).toBe('https://exchange.test');
    const body = (await res.json()) as { error: string; reason: string };
    expect(body.error).toContain('Negotiate access');
    expect(body.reason).toBe('ai_bot');
  });

  it('a search crawler reads the article for free — indexing must keep working', async () => {
    mockOriginArticle();
    const res = await SELF.fetch(ARTICLE_URL, {
      headers: {
        'user-agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
      },
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(ARTICLE_BODY);
  });

  it("Apple's AI crawler is denied even though its search sibling is allowed", async () => {
    const res = await SELF.fetch(ARTICLE_URL, {
      headers: { 'user-agent': 'Applebot-Extended/0.1' },
    });
    expect(res.status).toBe(403);
  });

  it('the ramp.json the 403 points at is fetchable without any signature', async () => {
    const denied = await SELF.fetch(ARTICLE_URL, { headers: { 'user-agent': 'GPTBot/1.0' } });
    const pointer = denied.headers.get('x-content-rules');
    expect(pointer).not.toBeNull();
    const manifest = await SELF.fetch(pointer as string, {
      headers: { 'user-agent': 'GPTBot/1.0' },
    });
    expect(manifest.status).toBe(200);
    const doc = (await manifest.json()) as { domain: string };
    expect(doc.domain).toBe('pub.test');
  });
});
