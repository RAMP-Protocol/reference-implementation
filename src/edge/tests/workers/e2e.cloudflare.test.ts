import { SELF } from 'cloudflare:test';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  type TestKeypair,
  futureExp,
  generateKeypair,
  keyThumbprint,
  pastExp,
  signGetHeaders,
  signUrl,
  tamperSignature,
} from '../helpers/ed25519.js';
import { fetchMock } from '../helpers/fetch-mock.js';
import {
  PUB_ORIGIN,
  setupE2ETest,
  setupOriginMock,
  setupWbaDirectoryMock,
} from '../helpers/test-setup.js';

let keypair: TestKeypair;
// The exchange's offer-signing key's RFC 7638 thumbprint — the value the signed
// URL's `kid` param carries and the edge matches against the WBA directory.
let exchangeKid: string;

beforeAll(async () => {
  ({ keypair, exchangeKid } = await setupE2ETest());
});

// The edge resolves the verify key by fetching the exchange's WBA directory
// (/.well-known/http-message-signatures-directory) and matching the URL's `kid`
// (thumbprint) against a locally-computed thumbprint of each published key.
beforeEach(() => {
  fetchMock.reset();
  setupWbaDirectoryMock(keypair);
  setupOriginMock();
});

describe('GET /healthz', () => {
  it('returns ok with request-id', async () => {
    const res = await SELF.fetch(`${PUB_ORIGIN}/healthz`);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('ok');
    expect(res.headers.get('x-request-id')).toBeTruthy();
  });

  it('echoes incoming X-Request-ID', async () => {
    const res = await SELF.fetch(`${PUB_ORIGIN}/healthz`, {
      headers: { 'x-request-id': 'trace-42' },
    });
    expect(res.headers.get('x-request-id')).toBe('trace-42');
  });
});

describe('well-known routes', () => {
  it('serves the unified ramp.json manifest', async () => {
    const res = await SELF.fetch(`${PUB_ORIGIN}/.well-known/ramp.json`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ver: string;
      role: string;
      domain: string;
      exchanges: Array<{ domain: string; endpoint: string; relationship: string }>;
    };
    expect(body.ver).toBe('1.0');
    expect(body.role).toBe('ROLE_PUBLISHER');
    expect(body.domain).toBe('pub.test');
    expect(body.exchanges[0]?.relationship).toBe('PROVIDER_RELATIONSHIP_DIRECT');
  });

  it('omits identity keys from the overlay manifest (WBA split)', async () => {
    const res = await SELF.fetch(`${PUB_ORIGIN}/.well-known/ramp.json`);
    const body = (await res.json()) as Record<string, unknown>;
    // Keys live in the WBA directory now — never republished in the overlay.
    expect(body.public_keys).toBeUndefined();
    expect(body.invalidation_url).toBeUndefined();
  });

  it('serves the WBA directory as a JWK Set (no kid)', async () => {
    const res = await SELF.fetch(`${PUB_ORIGIN}/.well-known/http-message-signatures-directory`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('application/jwk-set+json');
    const body = (await res.json()) as {
      keys: Array<Record<string, unknown>>;
    };
    expect(body.keys.length).toBeGreaterThan(0);
    expect(body.keys[0]?.kty).toBe('OKP');
    expect(body.keys[0]?.crv).toBe('Ed25519');
    // A WBA key is named by its RFC 7638 thumbprint — it carries no kid.
    expect(body.keys[0]?.kid).toBeUndefined();
  });

  it('serves rsl.txt', async () => {
    const res = await SELF.fetch(`${PUB_ORIGIN}/rsl.txt`);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('# test rsl');
  });

  it('serves ACME challenge for known token', async () => {
    const res = await SELF.fetch(`${PUB_ORIGIN}/.well-known/ramp-verify/demo`);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('response-body');
  });

  it('404 for unknown ACME token', async () => {
    const res = await SELF.fetch(`${PUB_ORIGIN}/.well-known/ramp-verify/unknown`);
    expect(res.status).toBe(404);
  });
});

describe('signed URL verification', () => {
  it('passes through a valid signed URL with 200', async () => {
    const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      exp: futureExp(),
      kid: exchangeKid,
    });
    const res = await SELF.fetch(url);
    expect(res.status).toBe(200);
  });

  it('returns 403 for tampered signature', async () => {
    const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      exp: futureExp(),
      kid: exchangeKid,
    });
    const res = await SELF.fetch(tamperSignature(url));
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string; reason: string };
    expect(body.reason).toBe('signature_mismatch');
  });

  it('405 when a valid signed URL is replayed with a write method', async () => {
    // The URL signature never covers the method or body; without a
    // proof-of-possession check (this URL binds no agent), a held read URL
    // must not turn into a write against the origin.
    const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      exp: futureExp(),
      kid: exchangeKid,
    });
    const res = await SELF.fetch(url, { method: 'POST', body: 'payload' });
    expect(res.status).toBe(405);
    expect(res.headers.get('allow')).toBe('GET, HEAD');
    expect(((await res.json()) as { reason: string }).reason).toBe('method_not_bound');
  });

  it('returns 403 with expired reason for expired URL', async () => {
    const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      exp: pastExp(10),
      kid: exchangeKid,
    });
    const res = await SELF.fetch(url);
    expect(res.status).toBe(403);
    const body = (await res.json()) as { reason: string };
    expect(body.reason).toBe('expired');
  });
});

describe('agent-bound URLs (binding enforced — proof of possession required)', () => {
  // The exchange key (keypair, published in the WBA directory, named by its
  // thumbprint exchangeKid) signs the URL and binds it to an agent key's
  // thumbprint (agent_id). Enforcement is ON by default (ADR-013 D6.1), so a
  // bound URL is worthless without the key it names — which is the property
  // that makes a leaked URL useless. The custodial registry flow satisfies it
  // because the registry, holding the key, makes the fetch itself (ADR-023).
  async function bindToAgent(agentKp: TestKeypair): Promise<{ url: string; agentId: string }> {
    const agentId = await keyThumbprint(agentKp);
    const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      exp: Math.floor(Date.now() / 1000) + 300,
      kid: exchangeKid,
      agentId,
    });
    return { url, agentId };
  }

  it('refuses a bound URL presented with no proof at all', async () => {
    // The leaked-URL case: holding the URL is not holding the key.
    const agentKp = await generateKeypair('agent');
    const { url } = await bindToAgent(agentKp);
    const res = await SELF.fetch(url);
    expect(res.status).toBe(403);
    expect(((await res.json()) as { reason: string }).reason).toBe('missing_agent_key');
  });

  it('refuses a bound URL presented with an unparseable proof', async () => {
    const agentKp = await generateKeypair('agent');
    const { url } = await bindToAgent(agentKp);
    const res = await SELF.fetch(url, {
      headers: {
        'X-RAMP-Agent-Key': 'garbage',
        'Signature-Input':
          'sig1=("@method" "@target-uri");keyid="x";alg="ed25519";created=1;expires=9999999999',
        Signature: 'sig1=:AAAA:',
      },
    });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { reason: string }).reason).toBe('bad_agent_key');
  });

  it('refuses a bound URL proved with a DIFFERENT agent key', async () => {
    // The stolen-URL case that matters most: a thief with their own valid key
    // and a valid self-signature still cannot fetch, because the presented key
    // does not hash to the agent_id the exchange signed into the URL.
    const agentKp = await generateKeypair('agent');
    const thiefKp = await generateKeypair('thief');
    const { url } = await bindToAgent(agentKp);
    const headers = await signGetHeaders(url, thiefKp, {
      keyid: await keyThumbprint(thiefKp),
      created: Math.floor(Date.now() / 1000) - 5,
      expires: Math.floor(Date.now() / 1000) + 300,
    });
    const res = await SELF.fetch(url, { headers });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { reason: string }).reason).toBe('keyid_mismatch');
  });

  it('serves a bound URL to the agent that proves possession of the bound key', async () => {
    const agentKp = await generateKeypair('agent');
    const { url, agentId } = await bindToAgent(agentKp);
    const headers = await signGetHeaders(url, agentKp, {
      keyid: agentId,
      created: Math.floor(Date.now() / 1000) - 5,
      expires: Math.floor(Date.now() / 1000) + 300,
    });
    const res = await SELF.fetch(url, { headers });
    expect(res.status).toBe(200);
  });

  it('403 signature_mismatch when agent_id is tampered (URL integrity still holds)', async () => {
    const agentKp = await generateKeypair('agent');
    const { url } = await bindToAgent(agentKp);
    const tampered = new URL(url);
    tampered.searchParams.set('agent_id', 'tampered-thumbprint');
    const res = await SELF.fetch(tampered.toString());
    expect(res.status).toBe(403);
    expect(((await res.json()) as { reason: string }).reason).toBe('signature_mismatch');
  });
});

describe('bot handling without signed URL', () => {
  it('blocks bot UA with 403 + X-Content-Rules', async () => {
    const res = await SELF.fetch(`${PUB_ORIGIN}/article/42`, {
      headers: { 'user-agent': 'GPTBot/1.0' },
    });
    expect(res.status).toBe(403);
    expect(res.headers.get('x-content-rules')).toBe(
      'https://pub.example.com/.well-known/ramp.json',
    );
    expect(res.headers.get('x-ramp-exchange')).toBe('https://exchange.test');
  });

  it('passes through a human UA', async () => {
    const res = await SELF.fetch(`${PUB_ORIGIN}/article/42`, {
      headers: {
        'user-agent':
          'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15',
      },
    });
    expect(res.status).toBe(200);
  });

  it('missing user-agent is treated as bot', async () => {
    const res = await SELF.fetch(`${PUB_ORIGIN}/article/42`);
    expect(res.status).toBe(403);
  });
});
