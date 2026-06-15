// Programmatic Fastly Compute harness. The real target is `fastly compute serve`,
// but that CLI is not assumed to be present in CI; this test stubs the Fastly
// service-worker API (`fastly.getEnv`, `addEventListener('fetch', ...)`) so that
// the fastly entry module can be imported and exercised end-to-end.
//
// TODO(edge/fastly): once the fastly CLI is provisioned in CI, replace this
// with `fastly compute serve` + HTTP client.

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { encodeBase64Url } from '../src/verify.js';
import { type TestKeypair, generateKeypair, manifestWithKeys, signUrl } from './helpers/ed25519.js';

interface FetchEvent {
  request: Request;
  respondWith(p: Promise<Response>): void;
}

type FetchListener = (event: FetchEvent) => void;

const PUB_ORIGIN = 'https://pub.example.com';

const env: Record<string, string> = {
  EXCHANGE_URL: 'https://exchange.test',
  EXCHANGE_MANIFEST_URL: 'https://exchange.test/.well-known/ramp.json',
  PROVIDER: 'fastly-edge.test',
  EXCHANGES_JSON: JSON.stringify([
    { domain: 'exchange.test', endpoint: 'https://exchange.test', supported_profiles: [] },
  ]),
  RSL_BODY: '# test rsl',
  ACME_TOKENS_JSON: '{"demo":"response-body"}',
};

let keypair: TestKeypair;
let listener: FetchListener | undefined;
let originalFetch: typeof fetch;

async function invoke(request: Request): Promise<Response> {
  if (!listener) throw new Error('fetch listener not registered');
  let captured: Promise<Response> | undefined;
  listener({
    request,
    respondWith: (p) => {
      captured = p;
    },
  });
  if (!captured) throw new Error('respondWith not called');
  return captured;
}

beforeAll(async () => {
  keypair = await generateKeypair('k1');
  (globalThis as unknown as { fastly: { getEnv(n: string): string } }).fastly = {
    getEnv: (n) => env[n] ?? '',
  };
  (globalThis as unknown as { addEventListener: unknown }).addEventListener = (
    type: string,
    handler: FetchListener,
  ): void => {
    if (type === 'fetch') listener = handler;
  };

  originalFetch = globalThis.fetch;
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
    const url =
      typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    if (url === env.EXCHANGE_MANIFEST_URL) {
      return new Response(JSON.stringify(manifestWithKeys([keypair.publicJwk])), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    return new Response('not mocked', { status: 500 });
  }) as unknown as typeof fetch;

  await import('../src/entries/fastly.js');
});

afterAll(() => {
  globalThis.fetch = originalFetch;
});

describe('Fastly Compute entry (stubbed runtime)', () => {
  it('healthz returns ok', async () => {
    const res = await invoke(new Request(`${PUB_ORIGIN}/healthz`));
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('ok');
  });

  it('serves ramp.json', async () => {
    const res = await invoke(new Request(`${PUB_ORIGIN}/.well-known/ramp.json`));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { role: string; domain: string };
    expect(body.role).toBe('ROLE_PUBLISHER');
    expect(body.domain).toBe('fastly-edge.test');
  });

  it('blocks bot UA', async () => {
    const res = await invoke(
      new Request(`${PUB_ORIGIN}/article/42`, { headers: { 'user-agent': 'GPTBot/1.0' } }),
    );
    expect(res.status).toBe(403);
    expect(res.headers.get('x-content-rules')).toBe(
      'https://pub.example.com/.well-known/ramp.json',
    );
  });

  it('passes through valid signed URL', async () => {
    const signed = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      exp: Math.floor(Date.now() / 1000) + 300,
      kid: 'k1',
    });
    const res = await invoke(new Request(signed));
    expect(res.status).toBe(200);
  });

  it('rejects tampered signature with 403', async () => {
    const signed = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      exp: Math.floor(Date.now() / 1000) + 300,
      kid: 'k1',
    });
    const tampered = new URL(signed);
    tampered.searchParams.set('sig', encodeBase64Url(new Uint8Array(64)));
    const res = await invoke(new Request(tampered.toString()));
    expect(res.status).toBe(403);
  });
});
