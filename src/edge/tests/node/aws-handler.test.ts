// Handler-level test of the Lambda@Edge shape: Hono's real production
// adapter (hono/lambda-edge handle) driven with hand-crafted CloudFront
// viewer-request events. This is NOT a real-Lambda-runtime E2E — the runtime
// bootstrap layer is not exercised here; the Docker-based real-runtime
// harness lives at tests/e2e/aws-edge/ (repo root).
import { handle } from 'hono/lambda-edge';
import type { CloudFrontEdgeEvent, CloudFrontRequest } from 'hono/lambda-edge';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { createApp } from '../../src/app.js';
import type { AppDeps } from '../../src/types.js';
import {
  type TestKeypair,
  futureExp,
  generateKeypair,
  keyThumbprint,
  signUrl,
  tamperSignature,
} from '../helpers/ed25519.js';
import { PUB_ORIGIN, expectNoSignatureParams } from '../helpers/test-setup.js';

const ORIGIN_URL = 'https://origin.pub.test';
const ORIGIN_BODY = 'origin content';

let keypair: TestKeypair;
// Requests the app forwarded to the origin fetcher, captured per test so the
// pass-through assertions can prove forwarding actually happened (a bare
// status check cannot tell "forwarded" from "origin never contacted").
let originRequests: Request[];
// CloudFront-native (Lambda@Edge) edges provision the verify key out of band, so
// resolveKey is hand-wired rather than fetched from a WBA directory. The keyid a
// signed URL carries is the key's RFC 7638 thumbprint.
let exchangeKid: string;
let lambdaHandler: ReturnType<typeof handle>;

beforeAll(async () => {
  keypair = await generateKeypair('k1');
  exchangeKid = await keyThumbprint(keypair);
  const deps: AppDeps = {
    manifest: {
      ver: '1.0',
      role: 'ROLE_PUBLISHER',
      domain: 'pub.example.com',
      exchanges: [
        {
          domain: 'exchange.test',
          endpoint: 'https://exchange.test',
          relationship: 'PROVIDER_RELATIONSHIP_DIRECT',
        },
      ],
      supported_profiles: ['ramp-news-v1'],
    },
    exchangeUrl: 'https://exchange.test',
    resolveKey: async (kid) => (kid === exchangeKid ? keypair.publicKey : undefined),
    acmeTokens: { demo: 'response-body' },
    originUrl: ORIGIN_URL,
    fetcher: (async (input: RequestInfo | URL) => {
      originRequests.push(input as Request);
      return new Response(ORIGIN_BODY, { status: 200 });
    }) as unknown as typeof fetch,
  };
  const app = createApp(deps);
  lambdaHandler = handle(app);
});

beforeEach(() => {
  originRequests = [];
});

function makeEvent(urlStr: string, headers: Record<string, string> = {}): CloudFrontEdgeEvent {
  const url = new URL(urlStr);
  const cfHeaders: CloudFrontRequest['headers'] = {};
  cfHeaders.host = [{ key: 'Host', value: url.host }];
  for (const [k, v] of Object.entries(headers)) {
    cfHeaders[k.toLowerCase()] = [{ key: k, value: v }];
  }
  return {
    Records: [
      {
        cf: {
          config: {
            distributionDomainName: 'test.cloudfront.net',
            distributionId: 'EXAMPLE',
            eventType: 'viewer-request',
            requestId: 'req-1',
          },
          request: {
            clientIp: '127.0.0.1',
            method: 'GET',
            uri: url.pathname,
            querystring: url.search.slice(1),
            headers: cfHeaders,
          },
        },
      },
    ],
  };
}

describe('AWS Lambda@Edge handler', () => {
  it('serves /healthz', async () => {
    const result = await lambdaHandler(makeEvent(`${PUB_ORIGIN}/healthz`));
    expect(result.status).toBe('200');
    expect(result.body).toBe('ok');
  });

  it('serves ramp.json manifest', async () => {
    const result = await lambdaHandler(makeEvent(`${PUB_ORIGIN}/.well-known/ramp.json`));
    expect(result.status).toBe('200');
    const body = JSON.parse(result.body ?? '') as { role: string; domain: string };
    expect(body.role).toBe('ROLE_PUBLISHER');
    expect(body.domain).toBe('pub.example.com');
  });

  it('passes through valid signed URL and serves the origin body', async () => {
    const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      exp: futureExp(),
      kid: exchangeKid,
    });
    const result = await lambdaHandler(makeEvent(url));
    expect(result.status).toBe('200');
    // The body must come from the origin — a bare 200 would also match the
    // no-origin empty-200 shortcut, which proves nothing about forwarding.
    expect(result.body).toBe(ORIGIN_BODY);
    const forwarded = new URL(originRequests[0]?.url ?? 'https://invalid.test');
    expect(forwarded.host).toBe('origin.pub.test');
    expectNoSignatureParams(forwarded);
  });

  it('rejects tampered signature with 403', async () => {
    const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      exp: futureExp(),
      kid: exchangeKid,
    });
    const result = await lambdaHandler(makeEvent(tamperSignature(url)));
    expect(result.status).toBe('403');
  });

  it('blocks bot UA with X-Content-Rules', async () => {
    const result = await lambdaHandler(
      makeEvent(`${PUB_ORIGIN}/article/42`, { 'user-agent': 'ClaudeBot/1.0' }),
    );
    expect(result.status).toBe('403');
    const xcr = result.headers?.['x-content-rules'];
    expect(xcr?.[0]?.value).toBe('https://pub.example.com/.well-known/ramp.json');
  });

  it('passes through a human UA and serves the origin body', async () => {
    const result = await lambdaHandler(
      makeEvent(`${PUB_ORIGIN}/article/42`, {
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/605.1.15',
      }),
    );
    expect(result.status).toBe('200');
    expect(result.body).toBe(ORIGIN_BODY);
  });
});

// Exercises the REAL entry module (src/entries/aws-lambda.ts), not the
// hand-wired app above: the guard under test lives in the entry's env
// handling, which the app-level harness never touches.
describe('AWS entry origin-mode validation', () => {
  it('refuses SAME_ZONE_ORIGIN — same-zone routing is Cloudflare-only and would loop on CloudFront', async () => {
    vi.stubEnv('EXCHANGE_URL', 'https://exchange.test');
    vi.stubEnv(
      'EXCHANGE_WBA_URL',
      'https://exchange.test/.well-known/http-message-signatures-directory',
    );
    vi.stubEnv('PROVIDER', 'pub.example.com');
    vi.stubEnv('EXCHANGES_JSON', '[{"domain":"exchange.test","endpoint":"https://exchange.test"}]');
    vi.stubEnv('SAME_ZONE_ORIGIN', 'true');
    try {
      const { handler } = await import('../../src/entries/aws-lambda.js');
      expect(() => handler(makeEvent(`${PUB_ORIGIN}/healthz`))).toThrow(/SAME_ZONE_ORIGIN/);
    } finally {
      vi.unstubAllEnvs();
    }
  });
});
