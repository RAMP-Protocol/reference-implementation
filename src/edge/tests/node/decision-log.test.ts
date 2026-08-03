// Every denial and operational error must leave one structured log record —
// that is all an operator has when a publisher reports "bots get through" or
// "agents get 403s". The denial and origin-failure cases drive the real app
// surface (createApp + app.request); the key-directory case drives
// createKeyCache directly, because that record is emitted by the cache layer
// itself. Only the console records are observed, mirroring verify-log.test.ts.
// Denials log at warn level (expected traffic); operational errors (origin
// unreachable, key directory down) log at error level. No record carries the
// query string — it holds attacker-controlled signature data.
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import type { App } from '../../src/app.js';
import { createKeyCache } from '../../src/keys-cache.js';
import type { AppDeps } from '../../src/types.js';
import {
  type TestKeypair,
  boundUrl,
  futureExp,
  generateKeypair,
  keyThumbprint,
  pastExp,
  signUrl,
} from '../helpers/ed25519.js';
import { makeLogTestApp, recordsFor, spyOnDenyLogs } from '../helpers/log-test-app.js';
import { PUB_ORIGIN } from '../helpers/test-setup.js';

let keypair: TestKeypair;
let exchangeKid: string;

function makeApp(overrides: Partial<AppDeps> = {}): App {
  return makeLogTestApp(keypair, exchangeKid, overrides);
}

beforeAll(async () => {
  keypair = await generateKeypair('k1');
  exchangeKid = await keyThumbprint(keypair);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('denial decision logs', () => {
  it('bot denial logs one edge.deny.bot record with method, path, request id', async () => {
    const { warnSpy: spy, errorSpy } = spyOnDenyLogs();
    const app = makeApp();
    await app.request(`${PUB_ORIGIN}/artikel`, {
      headers: { 'user-agent': 'GPTBot/1.0', 'x-request-id': 'req-bot-1' },
    });
    const records = recordsFor(spy, 'edge.deny.bot');
    expect(records).toHaveLength(1);
    expect(records[0]).toEqual({
      reason: 'ai_bot',
      method: 'GET',
      path: '/artikel',
      request_id: 'req-bot-1',
    });
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it('expired signed URL logs edge.deny.signature with the expiry reason', async () => {
    const { warnSpy: spy, errorSpy } = spyOnDenyLogs();
    const app = makeApp();
    const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      path: '/artikel',
      exp: pastExp(),
      kid: exchangeKid,
    });
    await app.request(url, { headers: { 'x-request-id': 'req-exp-1' } });
    const records = recordsFor(spy, 'edge.deny.signature');
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ reason: 'expired', path: '/artikel' });
    expect(errorSpy).not.toHaveBeenCalled();
  });

  // The signature_mismatch single-record contract (one warn record carrying
  // the kid, no error-level duplicate) is owned by verify-log.test.ts — it is
  // deliberately not re-asserted here.

  it('binding denial logs edge.deny.binding with the proof failure reason', async () => {
    const { warnSpy: spy, errorSpy } = spyOnDenyLogs();
    const app = makeApp();
    const agentKp = await generateKeypair('agent');
    const { url } = await boundUrl(PUB_ORIGIN, keypair.privateKey, agentKp, {
      path: '/artikel',
      exp: futureExp(),
      kid: exchangeKid,
    });
    await app.request(url);
    const records = recordsFor(spy, 'edge.deny.binding');
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ reason: 'missing_agent_key', path: '/artikel' });
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it('a signed write replay without a binding check logs one edge.deny.method record', async () => {
    // The URL signature covers the URL alone; with no agent bound, nothing
    // covers the method — so a POST replay of a read URL is refused before
    // the origin, with the same one-decision-one-record log contract.
    const { warnSpy: spy, errorSpy } = spyOnDenyLogs();
    const app = makeApp();
    const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      path: '/artikel',
      exp: futureExp(),
      kid: exchangeKid,
    });
    const res = await app.request(url, { method: 'POST', body: 'payload' });
    expect(res.status).toBe(405);
    expect(res.headers.get('allow')).toBe('GET, HEAD');
    const records = recordsFor(spy, 'edge.deny.method');
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      reason: 'method_not_bound',
      method: 'POST',
      path: '/artikel',
    });
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it('a bound write replay is answered by the binding check, not the method gate', async () => {
    // When the URL binds an agent and enforcement is on, the proof-of-
    // possession check runs and its RFC 9421 covered fields include the
    // method — so the request reaches that check (and fails it without a
    // proof) instead of the blanket 405.
    const { warnSpy: spy, errorSpy } = spyOnDenyLogs();
    const app = makeApp();
    const agentKp = await generateKeypair('agent');
    const { url } = await boundUrl(PUB_ORIGIN, keypair.privateKey, agentKp, {
      path: '/artikel',
      exp: futureExp(),
      kid: exchangeKid,
    });
    const res = await app.request(url, { method: 'POST', body: 'payload' });
    expect(res.status).toBe(403);
    expect(recordsFor(spy, 'edge.deny.binding')).toHaveLength(1);
    expect(recordsFor(spy, 'edge.deny.method')).toHaveLength(0);
    expect(errorSpy).not.toHaveBeenCalled();
  });
});

describe('operational error logs', () => {
  it('origin fetch failure logs edge.origin.fetch_failed at error level', async () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const app = makeApp({
      originUrl: 'https://origin.pub.test',
      fetcher: (async () => {
        throw new Error('connect refused');
      }) as unknown as typeof fetch,
    });
    const res = await app.request(`${PUB_ORIGIN}/artikel`, {
      headers: { 'user-agent': 'Mozilla/5.0 Safari/605.1.15' },
    });
    expect(res.status).toBe(502);
    const records = recordsFor(spy, 'edge.origin.fetch_failed');
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ method: 'GET', path: '/artikel' });
  });

  it('verification IO failure logs edge.verify.unavailable and answers 503, not a naked 500', async () => {
    // resolveKey has an IO leg (the WBA directory fetch) that rethrows after
    // the cache logs its own record. The app must catch it: fail closed with
    // the canonical {error, reason} body and one request-correlated error
    // record — a naked 500 is indistinguishable from a worker bug.
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const app = makeApp({
      resolveKey: async () => {
        throw new Error('wba directory fetch failed: 503');
      },
    });
    const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      path: '/artikel',
      exp: futureExp(),
      kid: exchangeKid,
    });
    const res = await app.request(url, { headers: { 'x-request-id': 'req-io-1' } });
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: string; reason: string };
    expect(body.reason).toBe('verify_unavailable');
    const records = recordsFor(spy, 'edge.verify.unavailable');
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      message: 'wba directory fetch failed: 503',
      path: '/artikel',
      request_id: 'req-io-1',
    });
  });

  it('key-directory load failure logs edge.keys.load_failed at error level', async () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const cache = createKeyCache<string, { x: string }>({
      wbaUrl: 'https://exchange.test/.well-known/http-message-signatures-directory',
      keyId: async (j) => j.x,
      importJwk: async (j) => j.x,
      parseKeys: () => [],
      fetcher: (async () => new Response('down', { status: 503 })) as unknown as typeof fetch,
    });
    await expect(cache.resolve('some-kid')).rejects.toThrow();
    const records = recordsFor(spy, 'edge.keys.load_failed');
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      message: 'wba directory fetch failed: 503',
      wba_url: 'https://exchange.test/.well-known/http-message-signatures-directory',
    });
  });
});
