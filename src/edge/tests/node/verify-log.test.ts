// A failed signature verification must leave exactly ONE structured record —
// the warn-level edge.deny.signature denial — carrying the kid (so a key
// rotation gone wrong is diagnosable) and the request id (X-Request-ID
// propagation) so the record correlates with the rest of the request's trail
// across services. Drives the real app surface — createApp + app.request over
// a genuinely-signed-then-tampered URL — with resolveKey hand-wired (the same
// shape as the Lambda@Edge e2e); the only observation point is the console
// record the worker emits, captured via a spy. The error level is reserved
// for operational failures, so the same request must emit NO console.error.

import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import type { App } from '../../src/app.js';
import {
  type TestKeypair,
  futureExp,
  generateKeypair,
  keyThumbprint,
  signUrl,
  tamperSignature,
} from '../helpers/ed25519.js';
import { makeLogTestApp, recordsFor, spyOnDenyLogs } from '../helpers/log-test-app.js';
import { PUB_ORIGIN } from '../helpers/test-setup.js';

let keypair: TestKeypair;
let exchangeKid: string;
let app: App;

beforeAll(async () => {
  keypair = await generateKeypair('k1');
  exchangeKid = await keyThumbprint(keypair);
  app = makeLogTestApp(keypair, exchangeKid);
});

afterEach(() => {
  vi.restoreAllMocks();
});

// A validly-signed URL whose sig param is then corrupted (shared
// tamperSignature helper) — the verifier resolves the key, recomputes the
// message, and fails on the signature bytes: the signature_mismatch log path.
async function tamperedUrl(): Promise<string> {
  const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
    exp: futureExp(),
    kid: exchangeKid,
  });
  return tamperSignature(url);
}

describe('signature_mismatch verify-failure log', () => {
  it('emits exactly one warn record with kid and the propagated X-Request-ID', async () => {
    const { warnSpy, errorSpy } = spyOnDenyLogs();

    const res = await app.request(await tamperedUrl(), {
      headers: { 'x-request-id': 'trace-verify-log' },
    });

    expect(res.status).toBe(403);
    const records = recordsFor(warnSpy, 'edge.deny.signature');
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      kid: exchangeKid,
      reason: 'signature_mismatch',
      request_id: 'trace-verify-log',
    });
    // The old duplicate error-level record must be gone: error is reserved
    // for operational failures, and one denial produces one record.
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it('carries the generated request id when the caller sends none', async () => {
    const { warnSpy } = spyOnDenyLogs();

    const res = await app.request(await tamperedUrl());

    expect(res.status).toBe(403);
    const generated = res.headers.get('x-request-id');
    expect(generated).toBeTruthy();
    expect(recordsFor(warnSpy, 'edge.deny.signature')[0]).toMatchObject({ request_id: generated });
  });
});
