import { SELF, fetchMock } from 'cloudflare:test';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { encodeBase64Url } from '../src/verify.js';
import {
  type TestKeypair,
  generateKeypair,
  jwks,
  signRequest,
  signUrl,
} from './helpers/ed25519.js';

const JWKS_URL = 'https://exchange.test/.well-known/jwks.json';
const PUB_ORIGIN = 'https://pub.example.com';
const FREE_PATH = '/articles/philosophers/socrates.txt';

let keypair: TestKeypair;
let botKeypair: TestKeypair;

beforeAll(async () => {
  keypair = await generateKeypair('k1');
  botKeypair = await generateKeypair('bot-1');
  fetchMock.activate();
  fetchMock.disableNetConnect();
});

beforeEach(() => {
  fetchMock
    .get('https://exchange.test')
    .intercept({ path: '/.well-known/jwks.json', method: 'GET' })
    .reply(200, jwks([keypair.publicJwk]), { headers: { 'content-type': 'application/json' } })
    .persist();
  fetchMock
    .get('https://bot.test')
    .intercept({ path: '/.well-known/jwks.json', method: 'GET' })
    .reply(200, jwks([botKeypair.publicJwk]), { headers: { 'content-type': 'application/json' } })
    .persist();
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
  it('serves ramp.json manifest', async () => {
    const res = await SELF.fetch(`${PUB_ORIGIN}/.well-known/ramp.json`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, string>;
    expect(body.ver).toBe('0.3');
    expect(body.exchange).toBe('https://exchange.test');
  });

  it('serves verifier manifest', async () => {
    const res = await SELF.fetch(`${PUB_ORIGIN}/.well-known/ramp-verifier.json`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      jwks_url: string;
      signing_algorithms: string[];
    };
    expect(body.jwks_url).toBe(JWKS_URL);
    expect(body.signing_algorithms).toContain('Ed25519');
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
      exp: Math.floor(Date.now() / 1000) + 300,
      kid: 'k1',
    });
    const res = await SELF.fetch(url);
    expect(res.status).toBe(200);
  });

  it('returns 403 for tampered signature', async () => {
    const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      exp: Math.floor(Date.now() / 1000) + 300,
      kid: 'k1',
    });
    const tampered = new URL(url);
    tampered.searchParams.set('sig', encodeBase64Url(new Uint8Array(64)));
    const res = await SELF.fetch(tampered.toString());
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string; reason: string };
    expect(body.reason).toBe('signature_mismatch');
  });

  it('returns 403 with expired reason for expired URL', async () => {
    const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      exp: Math.floor(Date.now() / 1000) - 10,
      kid: 'k1',
    });
    const res = await SELF.fetch(url);
    expect(res.status).toBe(403);
    const body = (await res.json()) as { reason: string };
    expect(body.reason).toBe('expired');
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

describe('WBA free-index fast path', () => {
  it('serves free content in ONE request to a signed ai-index crawler (even with a bot UA)', async () => {
    const headers = await signRequest(botKeypair.privateKey, {
      authority: 'pub.example.com',
      path: FREE_PATH,
      purpose: 'ai-index',
      keyid: 'bot-1',
      agent: 'https://bot.test/.well-known/jwks.json',
    });
    const res = await SELF.fetch(`${PUB_ORIGIN}${FREE_PATH}`, {
      // A bot UA that would normally be 403'd — the WBA signature, not the UA,
      // is what authorizes the serve.
      headers: { ...headers, 'user-agent': 'GPTBot/1.0' },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('content-usage')).toBe('ai-index=y');
    expect(res.headers.get('x-ramp-license')).toBe('tdl:free-index-v1');
  });

  it('still 403s an UNSIGNED bot on the same free path', async () => {
    const res = await SELF.fetch(`${PUB_ORIGIN}${FREE_PATH}`, {
      headers: { 'user-agent': 'GPTBot/1.0' },
    });
    expect(res.status).toBe(403);
    expect(res.headers.get('x-content-rules')).toBe(
      'https://pub.example.com/.well-known/ramp.json',
    );
  });

  it('does NOT fast-path when the purpose is not covered by the signature', async () => {
    const headers = await signRequest(botKeypair.privateKey, {
      authority: 'pub.example.com',
      path: FREE_PATH,
      purpose: 'ai-index',
      keyid: 'bot-1',
      components: ['@authority', '@path'], // purpose omitted from the signature
    });
    const res = await SELF.fetch(`${PUB_ORIGIN}${FREE_PATH}`, {
      headers: { ...headers, 'user-agent': 'GPTBot/1.0' },
    });
    // Falls through the fast path; bot UA -> 403 -> Exchange.
    expect(res.status).toBe(403);
  });

  it('does NOT fast-path a signed request to a non-free path', async () => {
    const path = '/premium/secret.txt';
    const headers = await signRequest(botKeypair.privateKey, {
      authority: 'pub.example.com',
      path,
      purpose: 'ai-index',
      keyid: 'bot-1',
    });
    const res = await SELF.fetch(`${PUB_ORIGIN}${path}`, {
      headers: { ...headers, 'user-agent': 'GPTBot/1.0' },
    });
    expect(res.status).toBe(403);
  });
});
