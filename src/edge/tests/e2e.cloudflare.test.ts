import { SELF } from 'cloudflare:test';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { thumbprint } from '../src/thumbprint.js';
import { encodeBase64Url } from '../src/verify.js';
import {
  type TestKeypair,
  generateKeypair,
  rawPublicKey,
  signGetHeaders,
  signUrl,
} from './helpers/ed25519.js';
import { PUB_ORIGIN, setupE2ETest, setupRampJsonMock } from './helpers/test-setup.js';

let keypair: TestKeypair;

beforeAll(async () => {
  keypair = await setupE2ETest();
});

// The edge resolves the verify key by fetching the exchange's unified
// /.well-known/ramp.json and reading public_keys[] — repoint the intercept to
// it and serve the manifest shape.
beforeEach(() => {
  setupRampJsonMock(keypair);
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

describe('agent-key binding (proof of possession)', () => {
  // The exchange key (keypair, served in the manifest as k1) signs the URL; a
  // separate agent key proves possession. agent_id == thumbprint(agent key).
  async function boundUrl(agentKp: TestKeypair): Promise<{ url: string; agentId: string }> {
    const agentId = await thumbprint(rawPublicKey(agentKp));
    const url = await signUrl(PUB_ORIGIN, keypair.privateKey, {
      exp: Math.floor(Date.now() / 1000) + 300,
      kid: 'k1',
      agentId,
    });
    return { url, agentId };
  }

  function popHeaders(
    url: string,
    agentKp: TestKeypair,
    keyid: string,
  ): Promise<Record<string, string>> {
    return signGetHeaders(url, agentKp, {
      keyid,
      created: Math.floor(Date.now() / 1000) - 5,
      expires: Math.floor(Date.now() / 1000) + 300,
    });
  }

  it('200 for a bound URL with a valid proof', async () => {
    const agentKp = await generateKeypair('agent');
    const { url, agentId } = await boundUrl(agentKp);
    const res = await SELF.fetch(url, { headers: await popHeaders(url, agentKp, agentId) });
    expect(res.status).toBe(200);
  });

  it('403 missing_agent_key when no proof is presented', async () => {
    const agentKp = await generateKeypair('agent');
    const { url } = await boundUrl(agentKp);
    const res = await SELF.fetch(url);
    expect(res.status).toBe(403);
    expect(((await res.json()) as { reason: string }).reason).toBe('missing_agent_key');
  });

  it('403 thumbprint_mismatch when a different key is presented', async () => {
    const agentKp = await generateKeypair('agent');
    const wrongKp = await generateKeypair('wrong');
    const { url, agentId } = await boundUrl(agentKp);
    // Sign with the wrong key but claim the bound keyid: the presented key's
    // thumbprint no longer matches agent_id.
    const res = await SELF.fetch(url, { headers: await popHeaders(url, wrongKp, agentId) });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { reason: string }).reason).toBe('thumbprint_mismatch');
  });

  it('403 keyid_mismatch when the proof keyid is not the bound agent_id', async () => {
    const agentKp = await generateKeypair('agent');
    const { url } = await boundUrl(agentKp);
    const res = await SELF.fetch(url, {
      headers: await popHeaders(url, agentKp, 'not-the-thumbprint'),
    });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { reason: string }).reason).toBe('keyid_mismatch');
  });

  it('403 signature_mismatch when agent_id is tampered (URL signature breaks first)', async () => {
    const agentKp = await generateKeypair('agent');
    const { url, agentId } = await boundUrl(agentKp);
    const headers = await popHeaders(url, agentKp, agentId);
    const tampered = new URL(url);
    tampered.searchParams.set('agent_id', 'tampered-thumbprint');
    const res = await SELF.fetch(tampered.toString(), { headers });
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
