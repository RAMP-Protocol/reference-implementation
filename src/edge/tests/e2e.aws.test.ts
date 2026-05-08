import { handle } from 'hono/lambda-edge';
import type { CloudFrontEdgeEvent, CloudFrontRequest } from 'hono/lambda-edge';
import { beforeAll, describe, expect, it } from 'vitest';

import { createApp } from '../src/app.js';
import type { AppDeps } from '../src/types.js';
import { encodeBase64Url } from '../src/verify.js';
import { type TestKeypair, generateKeypair, signUrl } from './helpers/ed25519.js';

const PUB_ORIGIN = 'https://pub.example.com';

let keypair: TestKeypair;
let lambdaHandler: ReturnType<typeof handle>;

beforeAll(async () => {
  keypair = await generateKeypair('k1');
  const deps: AppDeps = {
    manifest: {
      ver: '0.3',
      provider: 'pub.example.com',
      exchanges: [
        {
          domain: 'exchange.test',
          endpoint: 'https://exchange.test',
          supported_profiles: ['ramp-news-v1'],
        },
      ],
      exchange: 'https://exchange.test',
      marketplace_manifest: 'https://exchange.test/.well-known/ramp-marketplace.json',
    },
    verifierManifest: {
      version: '0.3',
      jwks_url: 'https://exchange.test/.well-known/jwks.json',
      signing_algorithms: ['Ed25519'],
    },
    resolveKey: async (kid) => (kid === 'k1' ? keypair.publicKey : undefined),
    acmeTokens: { demo: 'response-body' },
  };
  const app = createApp(deps);
  lambdaHandler = handle(app);
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
    const body = JSON.parse(result.body ?? '') as Record<string, string>;
    expect(body.exchange).toBe('https://exchange.test');
  });

  it('passes through valid signed URL', async () => {
    const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      exp: Math.floor(Date.now() / 1000) + 300,
      kid: 'k1',
    });
    const result = await lambdaHandler(makeEvent(url));
    expect(result.status).toBe('200');
  });

  it('rejects tampered signature with 403', async () => {
    const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      exp: Math.floor(Date.now() / 1000) + 300,
      kid: 'k1',
    });
    const tampered = new URL(url);
    tampered.searchParams.set('sig', encodeBase64Url(new Uint8Array(64)));
    const result = await lambdaHandler(makeEvent(tampered.toString()));
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

  it('passes through a human UA', async () => {
    const result = await lambdaHandler(
      makeEvent(`${PUB_ORIGIN}/article/42`, {
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/605.1.15',
      }),
    );
    expect(result.status).toBe('200');
  });
});
