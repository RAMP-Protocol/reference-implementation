import { describe, expect, it } from 'vitest';

import { verifyWebBotAuthRequest } from '../src/wba.js';
import { type TestKeypair, generateKeypair, signRequest } from './helpers/ed25519.js';

const AUTHORITY = 'pub.example.com';
const PATH = '/articles/philosophers/socrates.txt';
const AGENT = 'https://crawler.example/.well-known/web-bot-auth';

async function freshKeypair(kid = 'bot-1'): Promise<TestKeypair> {
  return generateKeypair(kid);
}

function resolver(kp: TestKeypair, kid = 'bot-1') {
  return async (keyid: string | undefined) => (keyid === kid ? kp.publicKey : undefined);
}

describe('verifyWebBotAuthRequest', () => {
  it('accepts a correctly signed request covering authority, path, purpose', async () => {
    const kp = await freshKeypair();
    const headers = await signRequest(kp.privateKey, {
      authority: AUTHORITY,
      path: PATH,
      purpose: 'ai-index',
      keyid: 'bot-1',
      agent: AGENT,
    });

    const res = await verifyWebBotAuthRequest({
      method: 'GET',
      authority: AUTHORITY,
      path: PATH,
      headers,
      resolveBotKey: resolver(kp),
    });

    expect(res.valid).toBe(true);
    expect(res.keyid).toBe('bot-1');
    expect(res.purpose).toBe('ai-index');
    expect(res.agent).toBe(AGENT);
    expect(res.covered).toEqual(['@authority', '@path', 'ramp-purpose']);
    expect(res.sigPrefix).toBeTruthy();
  });

  it('rejects when the purpose header is not covered by the signature', async () => {
    const kp = await freshKeypair();
    // Sign covering only @authority and @path — purpose omitted from the base.
    const headers = await signRequest(kp.privateKey, {
      authority: AUTHORITY,
      path: PATH,
      purpose: 'ai-index',
      keyid: 'bot-1',
      components: ['@authority', '@path'],
    });

    const res = await verifyWebBotAuthRequest({
      method: 'GET',
      authority: AUTHORITY,
      path: PATH,
      headers,
      resolveBotKey: resolver(kp),
    });

    expect(res.valid).toBe(false);
    expect(res.reason).toBe('purpose_not_covered');
  });

  it('rejects when @authority is not covered', async () => {
    const kp = await freshKeypair();
    const headers = await signRequest(kp.privateKey, {
      authority: AUTHORITY,
      path: PATH,
      purpose: 'ai-index',
      keyid: 'bot-1',
      components: ['@path', 'ramp-purpose'],
    });

    const res = await verifyWebBotAuthRequest({
      method: 'GET',
      authority: AUTHORITY,
      path: PATH,
      headers,
      resolveBotKey: resolver(kp),
    });

    expect(res.valid).toBe(false);
    expect(res.reason).toBe('authority_not_covered');
  });

  it('rejects when @path is not covered', async () => {
    const kp = await freshKeypair();
    const headers = await signRequest(kp.privateKey, {
      authority: AUTHORITY,
      path: PATH,
      purpose: 'ai-index',
      keyid: 'bot-1',
      components: ['@authority', 'ramp-purpose'],
    });

    const res = await verifyWebBotAuthRequest({
      method: 'GET',
      authority: AUTHORITY,
      path: PATH,
      headers,
      resolveBotKey: resolver(kp),
    });

    expect(res.valid).toBe(false);
    expect(res.reason).toBe('path_not_covered');
  });

  it('rejects an unsupported signature tag', async () => {
    const kp = await freshKeypair();
    const headers = await signRequest(kp.privateKey, {
      authority: AUTHORITY,
      path: PATH,
      purpose: 'ai-index',
      keyid: 'bot-1',
      tag: 'web-search',
    });

    const res = await verifyWebBotAuthRequest({
      method: 'GET',
      authority: AUTHORITY,
      path: PATH,
      headers,
      resolveBotKey: resolver(kp),
    });

    expect(res.valid).toBe(false);
    expect(res.reason).toBe('unsupported_tag');
  });

  it('signature_mismatch when the path is altered after signing', async () => {
    const kp = await freshKeypair();
    const headers = await signRequest(kp.privateKey, {
      authority: AUTHORITY,
      path: PATH,
      purpose: 'ai-index',
      keyid: 'bot-1',
    });

    const res = await verifyWebBotAuthRequest({
      method: 'GET',
      authority: AUTHORITY,
      path: '/articles/philosophers/plato.txt', // different from what was signed
      headers,
      resolveBotKey: resolver(kp),
    });

    expect(res.valid).toBe(false);
    expect(res.reason).toBe('signature_mismatch');
  });

  it('signature_mismatch when the purpose value is altered after signing', async () => {
    const kp = await freshKeypair();
    const headers = await signRequest(kp.privateKey, {
      authority: AUTHORITY,
      path: PATH,
      purpose: 'ai-index',
      keyid: 'bot-1',
    });
    headers['RAMP-Purpose'] = 'train-ai'; // tamper the covered header value

    const res = await verifyWebBotAuthRequest({
      method: 'GET',
      authority: AUTHORITY,
      path: PATH,
      headers,
      resolveBotKey: resolver(kp),
    });

    expect(res.valid).toBe(false);
    expect(res.reason).toBe('signature_mismatch');
  });

  it('unknown_key when the resolver cannot find the key', async () => {
    const kp = await freshKeypair();
    const headers = await signRequest(kp.privateKey, {
      authority: AUTHORITY,
      path: PATH,
      purpose: 'ai-index',
      keyid: 'bot-1',
    });

    const res = await verifyWebBotAuthRequest({
      method: 'GET',
      authority: AUTHORITY,
      path: PATH,
      headers,
      resolveBotKey: async () => undefined,
    });

    expect(res.valid).toBe(false);
    expect(res.reason).toBe('unknown_key');
  });

  it('expired when the signature deadline has passed', async () => {
    const kp = await freshKeypair();
    const now = 1_710_000_000_000;
    const headers = await signRequest(kp.privateKey, {
      authority: AUTHORITY,
      path: PATH,
      purpose: 'ai-index',
      keyid: 'bot-1',
      expires: Math.floor(now / 1000) - 10,
    });

    const res = await verifyWebBotAuthRequest({
      method: 'GET',
      authority: AUTHORITY,
      path: PATH,
      headers,
      resolveBotKey: resolver(kp),
      now: () => now,
    });

    expect(res.valid).toBe(false);
    expect(res.reason).toBe('expired');
  });

  it('accepts when expires is in the future', async () => {
    const kp = await freshKeypair();
    const now = 1_710_000_000_000;
    const headers = await signRequest(kp.privateKey, {
      authority: AUTHORITY,
      path: PATH,
      purpose: 'ai-index',
      keyid: 'bot-1',
      expires: Math.floor(now / 1000) + 300,
    });

    const res = await verifyWebBotAuthRequest({
      method: 'GET',
      authority: AUTHORITY,
      path: PATH,
      headers,
      resolveBotKey: resolver(kp),
      now: () => now,
    });

    expect(res.valid).toBe(true);
  });

  it('missing_signature_input when the Signature-Input header is absent', async () => {
    const kp = await freshKeypair();
    const res = await verifyWebBotAuthRequest({
      method: 'GET',
      authority: AUTHORITY,
      path: PATH,
      headers: { Signature: 'sig1=:abc:', 'RAMP-Purpose': 'ai-index' },
      resolveBotKey: resolver(kp),
    });
    expect(res.valid).toBe(false);
    expect(res.reason).toBe('missing_signature_input');
  });

  it('missing_signature when the Signature header is absent', async () => {
    const kp = await freshKeypair();
    const res = await verifyWebBotAuthRequest({
      method: 'GET',
      authority: AUTHORITY,
      path: PATH,
      headers: {
        'Signature-Input':
          'sig1=("@authority" "@path" "ramp-purpose");keyid="bot-1";tag="web-bot-auth"',
        'RAMP-Purpose': 'ai-index',
      },
      resolveBotKey: resolver(kp),
    });
    expect(res.valid).toBe(false);
    expect(res.reason).toBe('missing_signature');
  });

  it('malformed_signature_input when the header is not parseable', async () => {
    const kp = await freshKeypair();
    const res = await verifyWebBotAuthRequest({
      method: 'GET',
      authority: AUTHORITY,
      path: PATH,
      headers: {
        'Signature-Input': 'garbage-without-list',
        Signature: 'sig1=:abc:',
        'RAMP-Purpose': 'ai-index',
      },
      resolveBotKey: resolver(kp),
    });
    expect(res.valid).toBe(false);
    expect(res.reason).toBe('malformed_signature_input');
  });

  it('treats authority case-insensitively', async () => {
    const kp = await freshKeypair();
    const headers = await signRequest(kp.privateKey, {
      authority: AUTHORITY,
      path: PATH,
      purpose: 'ai-index',
      keyid: 'bot-1',
    });

    const res = await verifyWebBotAuthRequest({
      method: 'GET',
      authority: AUTHORITY.toUpperCase(),
      path: PATH,
      headers,
      resolveBotKey: resolver(kp),
    });

    expect(res.valid).toBe(true);
  });
});
