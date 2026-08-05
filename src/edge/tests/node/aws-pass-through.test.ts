// Entry-level tests of the Lambda@Edge pass-through contract: the REAL entry
// module (src/entries/aws-lambda.ts) run with NO origin mode configured — the
// demo-on-AWS deployment shape, where CloudFront owns the origin fetch. An
// authorized request must come back as the CloudFront REQUEST object (so
// CloudFront continues to its configured origin) with the reserved signature
// params stripped; every denial and every well-known route must come back as
// a generated response. Driven with hand-crafted viewer-request events
// through Hono's production adapter, same harness shape as aws-handler.test.ts.
import type { CloudFrontRequest } from 'hono/lambda-edge';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { CDN_AUTHORIZED_HEADER } from '../../src/app.js';
import type { handler as awsHandler } from '../../src/entries/aws-lambda.js';
import { makeViewerRequestEvent as makeEvent } from '../helpers/cloudfront.js';
import {
  type TestKeypair,
  futureExp,
  generateKeypair,
  keyThumbprint,
  signUrl,
  tamperSignature,
} from '../helpers/ed25519.js';
import { PUB_ORIGIN, expectNoSignatureParams } from '../helpers/test-setup.js';

let keypair: TestKeypair;
let exchangeKid: string;
let handler: typeof awsHandler;

// A pass-through result is the (possibly modified) CloudFront request object;
// a generated response is a result object with a status. The two shapes share
// no required field, so the discriminator is the one field only requests have.
function isRequest(result: Awaited<ReturnType<typeof awsHandler>>): result is CloudFrontRequest {
  return 'uri' in result;
}

beforeAll(async () => {
  keypair = await generateKeypair('k1');
  exchangeKid = await keyThumbprint(keypair);
  // The demo-aws config shape: no ORIGIN_URL, no SAME_ZONE_ORIGIN. Verify
  // keys are pre-provisioned inline so no WBA directory fetch happens.
  vi.stubEnv('EXCHANGE_URL', 'https://exchange.test');
  vi.stubEnv(
    'EXCHANGE_WBA_URL',
    'https://exchange.test/.well-known/http-message-signatures-directory',
  );
  vi.stubEnv('PROVIDER', 'pub.example.com');
  vi.stubEnv('EXCHANGES_JSON', '[{"domain":"exchange.test","endpoint":"https://exchange.test"}]');
  vi.stubEnv(
    'RAMP_VERIFY_KEYS',
    JSON.stringify([{ kty: 'OKP', crv: 'Ed25519', x: keypair.publicJwk.x }]),
  );
  ({ handler } = await import('../../src/entries/aws-lambda.js'));
});

afterAll(() => {
  vi.unstubAllEnvs();
});

describe('AWS entry pass-through (no origin mode)', () => {
  it('returns the request for a valid signed URL, signature params stripped', async () => {
    const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      exp: futureExp(),
      kid: exchangeKid,
      query: { page: '2' },
    });
    const result = await handler(makeEvent(url));
    expect(isRequest(result)).toBe(true);
    if (!isRequest(result)) return;
    expect(result.uri).toBe('/some/resource');
    // The reserved namespace never reaches the origin; the site's own params do.
    const params = new URLSearchParams(result.querystring);
    expectNoSignatureParams(new URL(`${PUB_ORIGIN}${result.uri}?${result.querystring}`));
    expect(params.get('page')).toBe('2');
  });

  it('returns the request for an unsigned human read', async () => {
    const result = await handler(
      makeEvent(`${PUB_ORIGIN}/article/42`, {
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/605.1.15',
      }),
    );
    expect(isRequest(result)).toBe(true);
  });

  it('returns a generated 403 for a tampered signature', async () => {
    const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      exp: futureExp(),
      kid: exchangeKid,
    });
    const result = await handler(makeEvent(tamperSignature(url)));
    expect(isRequest(result)).toBe(false);
    if (isRequest(result)) return;
    expect(result.status).toBe('403');
  });

  it('returns a generated 403 for an AI bot', async () => {
    const result = await handler(
      makeEvent(`${PUB_ORIGIN}/article/42`, { 'user-agent': 'ClaudeBot/1.0' }),
    );
    expect(isRequest(result)).toBe(false);
    if (isRequest(result)) return;
    expect(result.status).toBe('403');
    expect(result.headers?.['x-content-rules']?.[0]?.value).toBe(
      'https://pub.example.com/.well-known/ramp.json',
    );
  });

  it('serves ramp.json as a generated response, never a pass-through', async () => {
    const result = await handler(makeEvent(`${PUB_ORIGIN}/.well-known/ramp.json`));
    expect(isRequest(result)).toBe(false);
    if (isRequest(result)) return;
    expect(result.status).toBe('200');
    const body = JSON.parse(result.body ?? '') as { domain: string };
    expect(body.domain).toBe('pub.example.com');
  });

  it('serves an empty rsl.txt as a generated response, never a pass-through', async () => {
    // RSL_BODY is unset, so this route produces a 200 with an empty body —
    // the exact shape that makes "empty 200" unusable as the pass-through
    // signal. It must still return to the viewer as a generated response.
    const result = await handler(makeEvent(`${PUB_ORIGIN}/rsl.txt`));
    expect(isRequest(result)).toBe(false);
    if (isRequest(result)) return;
    expect(result.status).toBe('200');
    expect(result.body ?? '').toBe('');
  });

  it('never leaks the authorization marker on generated responses', async () => {
    const generated = await Promise.all([
      handler(makeEvent(`${PUB_ORIGIN}/.well-known/ramp.json`)),
      handler(makeEvent(`${PUB_ORIGIN}/rsl.txt`)),
      handler(makeEvent(`${PUB_ORIGIN}/article/42`, { 'user-agent': 'ClaudeBot/1.0' })),
    ]);
    for (const result of generated) {
      expect(isRequest(result)).toBe(false);
      if (isRequest(result)) continue;
      // Keyed off the PRODUCTION constant so a renamed marker cannot leave
      // this test green while the header leaks under its new name.
      expect(result.headers?.[CDN_AUTHORIZED_HEADER]).toBeUndefined();
    }
  });
});
