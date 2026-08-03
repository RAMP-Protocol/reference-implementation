// Origin addressing on the Cloudflare runtime. Two concerns:
//
//   1. The Cloudflare entry must fail LOUD when neither ORIGIN_URL nor
//      SAME_ZONE_ORIGIN is configured — an empty 200 on every article would
//      look healthy while serving nothing.
//   2. SAME_ZONE_ORIGIN=true forwards to the incoming URL itself (signature
//      params stripped): on a zone route, Cloudflare sends a same-zone
//      subrequest to the zone's configured origin with the right Host header,
//      so the Worker never needs to know the origin address.
//
// The same-zone tests drive the Hono app surface directly with an injected
// fetcher that records the forwarded URL — the app is the outermost layer that
// owns target resolution, and the recorded URL is the observable contract.
import { describe, expect, it } from 'vitest';

import { createApp } from '../../src/app.js';
import worker from '../../src/entries/cloudflare.js';
import type { AppDeps } from '../../src/types.js';
import {
  futureExp,
  generateKeypair,
  keyThumbprint,
  signUrl,
  tamperSignature,
} from '../helpers/ed25519.js';

const BROWSER_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/605.1.15';

type WorkerEnv = Parameters<typeof worker.fetch>[1];

const baseEnv = {
  EXCHANGE_URL: 'https://exchange.test',
  EXCHANGE_WBA_URL: 'https://exchange.test/.well-known/http-message-signatures-directory',
  PROVIDER: 'pub.test',
  EXCHANGES_JSON: '[{"domain":"exchange.test","endpoint":"https://exchange.test"}]',
};

describe('Cloudflare entry origin-mode validation', () => {
  it('refuses to serve when neither ORIGIN_URL nor SAME_ZONE_ORIGIN is set', async () => {
    await expect(
      worker.fetch(
        new Request('https://pub.example.com/article'),
        baseEnv as WorkerEnv,
        {} as ExecutionContext,
      ),
    ).rejects.toThrow(/ORIGIN_URL|SAME_ZONE_ORIGIN/);
  });

  // Proves only that the construction guard accepts the same-zone mode (the
  // worker boots and answers); same-zone FORWARDING is proven by the
  // 'same-zone origin mode' block below.
  it('construction guard accepts SAME_ZONE_ORIGIN=true and the worker serves', async () => {
    const env = { ...baseEnv, SAME_ZONE_ORIGIN: 'true' } as WorkerEnv;
    const res = await worker.fetch(
      new Request('https://pub.example.com/healthz'),
      env,
      {} as ExecutionContext,
    );
    expect(res.status).toBe(200);
  });
});

function sameZoneDeps(seen: string[]): AppDeps {
  return {
    manifest: { ver: '1.0', role: 'ROLE_PUBLISHER', domain: 'pub.test' } as AppDeps['manifest'],
    resolveKey: async () => undefined,
    sameZoneOrigin: true,
    verify: async () => ({ valid: true, expired: false }),
    fetcher: (async (req: Request) => {
      seen.push(req.url);
      return new Response('origin body');
    }) as unknown as typeof fetch,
  };
}

describe('same-zone origin mode', () => {
  it('forwards an unsigned human request to the SAME url', async () => {
    const seen: string[] = [];
    const app = createApp(sameZoneDeps(seen));
    const res = await app.request('https://pub.example.com/artikel?page=2', {
      headers: { 'user-agent': BROWSER_UA },
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('origin body');
    expect(seen).toEqual(['https://pub.example.com/artikel?page=2']);
  });

  it('forwards a verified signed request to the incoming url minus signature params', async () => {
    const seen: string[] = [];
    const app = createApp(sameZoneDeps(seen));
    const res = await app.request(
      'https://pub.example.com/artikel?page=2&exp=123&kid=k&agent_id=a&sig=s',
    );
    expect(res.status).toBe(200);
    expect(seen).toEqual(['https://pub.example.com/artikel?page=2']);
  });
});

// The tests above stub verify to isolate target resolution. This block drives
// the REAL Ed25519 verification (no verify stub → the default SDK path) into
// a same-zone forward, so the verify → forward handoff itself is covered on
// the documented staging origin mode — not just its two axes separately.
describe('same-zone origin mode with real verification', () => {
  function realVerifyDeps(seen: string[], resolveKey: AppDeps['resolveKey']): AppDeps {
    return {
      manifest: { ver: '1.0', role: 'ROLE_PUBLISHER', domain: 'pub.test' } as AppDeps['manifest'],
      resolveKey,
      sameZoneOrigin: true,
      fetcher: (async (req: Request) => {
        seen.push(req.url);
        return new Response('origin body');
      }) as unknown as typeof fetch,
    };
  }

  it('serves a really-signed URL and forwards the cleaned same-zone target', async () => {
    const keypair = await generateKeypair('k1');
    const kid = await keyThumbprint(keypair);
    const seen: string[] = [];
    const app = createApp(
      realVerifyDeps(seen, async (k) => (k === kid ? keypair.publicKey : undefined)),
    );
    const url = await signUrl('https://pub.example.com', keypair.privateKey, {
      path: '/artikel',
      exp: futureExp(),
      kid,
      query: { page: '2' },
    });
    const res = await app.request(url);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('origin body');
    expect(seen).toEqual(['https://pub.example.com/artikel?page=2']);
  });

  it('403s a tampered signature and forwards NOTHING same-zone', async () => {
    const keypair = await generateKeypair('k1');
    const kid = await keyThumbprint(keypair);
    const seen: string[] = [];
    const app = createApp(
      realVerifyDeps(seen, async (k) => (k === kid ? keypair.publicKey : undefined)),
    );
    const url = await signUrl('https://pub.example.com', keypair.privateKey, {
      path: '/artikel',
      exp: futureExp(),
      kid,
    });
    const res = await app.request(tamperSignature(url));
    expect(res.status).toBe(403);
    expect(((await res.json()) as { reason: string }).reason).toBe('signature_mismatch');
    expect(seen).toEqual([]);
  });
});
