// A verified delivery must leave exactly ONE structured record — the
// info-level edge.deliver.authorized — carrying the URL digest the evidence
// chain joins on, the public identifiers from the verified URL, and which
// origin branch served the request. Denials must leave none of it.
//
// The digest is the load-bearing field. The Exchange stores SHA-256 over the
// signed URL's verbatim bytes, so the record must hash the request URL the
// same way. Hashing the canonicalized form the verifier derives internally
// would drop the sig parameter and produce a digest that could never match,
// and no assertion about the record's shape would catch that — so the test
// mints a URL with the real signer and compares against a digest it computes
// itself.
//
// Drives the real app surface (createApp + app.request) with resolveKey
// hand-wired, observing only the console records, in the shape the sibling
// verify-log and decision-log suites use.

import { readFileSync } from 'node:fs';
import { URL, fileURLToPath } from 'node:url';

import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import { DELIVERY_EVENT } from '../../src/log.js';
import type { AppDeps } from '../../src/types.js';
import {
  type TestKeypair,
  futureExp,
  generateKeypair,
  keyThumbprint,
  pastExp,
  signUrl,
  tamperSignature,
} from '../helpers/ed25519.js';
import { makeLogTestApp, recordsFor, spyOnAllLogs } from '../helpers/log-test-app.js';
import { PUB_ORIGIN } from '../helpers/test-setup.js';

let keypair: TestKeypair;
let exchangeKid: string;

beforeAll(async () => {
  keypair = await generateKeypair('k1');
  exchangeKid = await keyThumbprint(keypair);
});

afterEach(() => {
  vi.restoreAllMocks();
});

// hexDigest is the independent oracle: SHA-256 over the string's verbatim
// UTF-8 bytes. Written out here rather than imported from the worker so the
// test cannot pass by sharing a mistake with the code it checks.
async function hexDigest(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function signedUrl(): Promise<string> {
  return signUrl(PUB_ORIGIN, keypair.privateKey, { exp: futureExp(), kid: exchangeKid });
}

// An app whose origin mode is chosen per test. The default (no originUrl, no
// sameZoneOrigin) is the CloudFront-native branch the demo stack runs.
function appWith(overrides: Partial<AppDeps> = {}) {
  return makeLogTestApp(keypair, exchangeKid, overrides);
}

// okFetcher stands in for a reachable origin on the forwarding branches.
function okFetcher(): typeof fetch {
  return statusFetcher(200);
}

// statusFetcher is an origin that answers with the given status. fetch()
// resolves normally for 404 and 500, so a worker that did not record the status
// would write an identical delivery record for all three.
function statusFetcher(status: number): typeof fetch {
  return (async () => new Response('body', { status })) as unknown as typeof fetch;
}

interface DeliveryRecord {
  url_hash?: string;
  outcome?: string;
  kid?: string;
  agent_id?: string;
  request_id?: string;
  method?: string;
  path?: string;
  origin_status?: string;
}

// The shared cross-language vector. The Go parser in src/broker/cmd/ramp-ledger
// reads this same file and asserts every value; this side asserts that a record
// the worker ACTUALLY EMITTED carries every key the vector requires.
//
// Neither language's own tests can close this gap: renaming a key here and in
// the worker together leaves this suite green while Go silently stops reading
// the field. The vector is the third party neither suite controls.
const deliveryVectorsPath = fileURLToPath(
  new URL('../../../../testdata/delivery-record-vectors.json', import.meta.url),
);
const deliveryVectors = JSON.parse(readFileSync(deliveryVectorsPath, 'utf8')) as {
  required_keys: string[];
  optional_keys: Record<string, string>;
  payload: Record<string, string>;
};

describe('authorized-delivery log record', () => {
  it('emits one info record whose url_hash is the digest of the verbatim signed URL', async () => {
    const { infoSpy, warnSpy, errorSpy } = spyOnAllLogs();
    const url = await signedUrl();

    const res = await appWith().request(url, { headers: { 'x-request-id': 'trace-deliver' } });

    expect(res.status).toBe(200);
    const records = recordsFor(infoSpy, DELIVERY_EVENT) as DeliveryRecord[];
    expect(records).toHaveLength(1);
    // The join key: byte-for-byte the digest of the URL that was minted.
    expect(records[0]?.url_hash).toBe(await hexDigest(url));
    expect(records[0]?.kid).toBe(exchangeKid);
    expect(records[0]?.request_id).toBe('trace-deliver');
    expect(records[0]?.method).toBe('GET');
    // One decision, one record: nothing else accompanies the delivery.
    expect(warnSpy).not.toHaveBeenCalled();
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it('hashes the URL verbatim rather than the canonical form the verifier checks', async () => {
    const { infoSpy } = spyOnAllLogs();
    const url = await signedUrl();

    await appWith().request(url);

    const record = (recordsFor(infoSpy, DELIVERY_EVENT) as DeliveryRecord[])[0];
    // The canonical form drops sig before signing. If the record hashed that
    // instead of the URL as delivered, this digest would match and the join
    // against the Exchange's stored digest would silently never succeed.
    const canonical = new URL(url);
    canonical.searchParams.delete('sig');
    expect(record?.url_hash).not.toBe(await hexDigest(canonical.toString()));
  });

  it('names the branch that served the request', async () => {
    const cases: Array<{ deps: Partial<AppDeps>; outcome: string }> = [
      { deps: {}, outcome: 'cdn-origin-fetch' },
      {
        deps: { originUrl: 'https://origin.example.com', fetcher: okFetcher() },
        outcome: 'origin-forwarded',
      },
      { deps: { sameZoneOrigin: true, fetcher: okFetcher() }, outcome: 'same-zone' },
    ];
    for (const { deps, outcome } of cases) {
      const { infoSpy } = spyOnAllLogs();
      await appWith(deps).request(await signedUrl());
      const records = recordsFor(infoSpy, DELIVERY_EVENT) as DeliveryRecord[];
      expect(records).toHaveLength(1);
      expect(records[0]?.outcome).toBe(outcome);
      vi.restoreAllMocks();
    }
  });

  it('carries the bound agent_id when the URL names one', async () => {
    const { infoSpy } = spyOnAllLogs();
    const agentKp = await generateKeypair('agent');
    const agentId = await keyThumbprint(agentKp);
    const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      exp: futureExp(),
      kid: exchangeKid,
      agentId,
    });

    // Binding enforcement off, so the delivery is authorized on the URL
    // signature alone and the record's agent_id comes from the verified URL.
    await appWith({ enforceBinding: false }).request(url);

    const record = (recordsFor(infoSpy, DELIVERY_EVENT) as DeliveryRecord[])[0];
    expect(record?.agent_id).toBe(agentId);
  });

  it('never leaks the signature or the query string', async () => {
    const { infoSpy } = spyOnAllLogs();
    const url = await signedUrl();

    await appWith().request(url);

    const record = (recordsFor(infoSpy, DELIVERY_EVENT) as DeliveryRecord[])[0];
    const serialized = JSON.stringify(record);
    const sig = new URL(url).searchParams.get('sig');
    expect(sig).toBeTruthy();
    expect(serialized).not.toContain(sig as string);
    expect(serialized).not.toContain('?');
    expect(record?.path).toBe('/some/resource');
  });
});

describe('records a delivery did NOT happen', () => {
  it('emits no delivery record when the signature fails', async () => {
    const { infoSpy, warnSpy } = spyOnAllLogs();

    const res = await appWith().request(tamperSignature(await signedUrl()));

    expect(res.status).toBe(403);
    expect(recordsFor(infoSpy, DELIVERY_EVENT)).toHaveLength(0);
    expect(recordsFor(warnSpy, 'edge.deny.signature')).toHaveLength(1);
  });

  it('emits no delivery record when the signed URL has expired', async () => {
    const { infoSpy } = spyOnAllLogs();
    const expired = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      exp: pastExp(),
      kid: exchangeKid,
    });

    const res = await appWith().request(expired);

    expect(res.status).toBe(403);
    expect(recordsFor(infoSpy, DELIVERY_EVENT)).toHaveLength(0);
  });

  it('emits no delivery record when an unsigned bot request is denied', async () => {
    const { infoSpy, warnSpy } = spyOnAllLogs();

    const res = await appWith().request(`${PUB_ORIGIN}/some/resource`, {
      headers: { 'user-agent': 'GPTBot/1.0' },
    });

    expect(res.status).toBe(403);
    expect(recordsFor(infoSpy, DELIVERY_EVENT)).toHaveLength(0);
    expect(recordsFor(warnSpy, 'edge.deny.bot')).toHaveLength(1);
  });

  it('emits no delivery record when the origin cannot be reached', async () => {
    const { infoSpy, errorSpy } = spyOnAllLogs();
    const failing = (async () => {
      throw new Error('connection refused');
    }) as unknown as typeof fetch;

    const res = await appWith({
      originUrl: 'https://origin.example.com',
      fetcher: failing,
    }).request(await signedUrl());

    // Authorized, but nothing was delivered: the failure is the only record.
    expect(res.status).toBe(502);
    expect(recordsFor(infoSpy, DELIVERY_EVENT)).toHaveLength(0);
    expect(recordsFor(errorSpy, 'edge.origin.fetch_failed')).toHaveLength(1);
  });

  it('emits no delivery record for unsigned pass-through traffic', async () => {
    const { infoSpy } = spyOnAllLogs();

    // A plain browser read carries no signature: it passes to the origin, but
    // it is not a licensed delivery and must not enter the evidence chain.
    const res = await appWith().request(`${PUB_ORIGIN}/some/resource`, {
      headers: { 'user-agent': 'Mozilla/5.0' },
    });

    expect(res.status).toBe(200);
    expect(recordsFor(infoSpy, DELIVERY_EVENT)).toHaveLength(0);
  });

  // The status is what separates "the origin answered" from "the origin served
  // the content". Without it a 404 and a licensed 200 write the same record,
  // and the evidence chain would have to treat them the same.
  it('records the origin status on the branches that waited for a response', async () => {
    for (const status of [200, 206, 404, 500]) {
      const { infoSpy } = spyOnAllLogs();
      const app = appWith({
        originUrl: 'https://origin.example.com',
        fetcher: statusFetcher(status),
      });
      await app.request(await signedUrl(), { headers: { 'x-request-id': `trace-${status}` } });

      const records = recordsFor(infoSpy, DELIVERY_EVENT) as DeliveryRecord[];
      expect(records).toHaveLength(1);
      expect(records[0]?.origin_status).toBe(String(status));
      vi.restoreAllMocks();
    }
  });

  // On the CloudFront branch the worker hands the request back and the CDN
  // fetches the origin afterwards, so this worker never sees a response. The
  // field must be ABSENT rather than 0 or 200: an invented value would be the
  // worker asserting something it did not observe, and the renderer could not
  // tell it apart from a real answer.
  it('omits the origin status when it never saw a response', async () => {
    const { infoSpy } = spyOnAllLogs();
    const app = appWith();
    await app.request(await signedUrl(), { headers: { 'x-request-id': 'trace-cdn' } });

    const records = recordsFor(infoSpy, DELIVERY_EVENT) as DeliveryRecord[];
    expect(records).toHaveLength(1);
    expect(records[0]?.outcome).toBe('cdn-origin-fetch');
    expect(records[0]?.origin_status).toBeUndefined();
  });

  // Every key the shared vector requires must appear on a record the worker
  // really wrote. A field renamed on this side fails here; a field renamed on
  // both sides of THIS language still fails on the Go side, which reads the
  // same vector.
  it('emits every field the shared cross-language vector requires', async () => {
    const { infoSpy } = spyOnAllLogs();
    const app = appWith({ originUrl: 'https://origin.example.com', fetcher: okFetcher() });

    await app.request(await signedUrl(), { headers: { 'x-request-id': 'trace-vector' } });

    const records = recordsFor(infoSpy, DELIVERY_EVENT) as Array<Record<string, unknown>>;
    expect(records).toHaveLength(1);
    for (const key of deliveryVectors.required_keys) {
      expect(records[0]).toHaveProperty(key);
      expect(records[0]?.[key]).not.toBe('');
    }
  });

  // The MAXIMAL record: every optional field populated at once — a key id, a
  // bound agent, and an origin the worker waited for. Its key set must equal the
  // vector's payload exactly.
  //
  // Emitting a lesser record here would leave a hole: a field that only appears
  // on the bound-agent branch could be undocumented, and a test that never takes
  // that branch could not see it. Equality in BOTH directions is what makes the
  // vector a complete description rather than a subset.
  it('emits exactly the key set the shared vector documents', async () => {
    const { infoSpy } = spyOnAllLogs();
    const agentKp = await generateKeypair('agent');
    const agentId = await keyThumbprint(agentKp);
    const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      exp: futureExp(),
      kid: exchangeKid,
      agentId,
    });

    // Binding enforcement off so the URL alone authorizes; an origin the worker
    // waits for so the record carries a status too.
    const app = appWith({
      enforceBinding: false,
      originUrl: 'https://origin.example.com',
      fetcher: okFetcher(),
    });
    await app.request(url, { headers: { 'x-request-id': 'trace-vector-maximal' } });

    const record = (recordsFor(infoSpy, DELIVERY_EVENT) as Array<Record<string, unknown>>)[0];
    expect(record).toBeDefined();
    expect(Object.keys(record ?? {}).sort()).toEqual(Object.keys(deliveryVectors.payload).sort());
  });
});
