import { describe, expect, it } from 'vitest';

import { decodeBase64Url, encodeBase64Url } from '@ramp-protocol/sdk-l1/base64url';
import { canonicalMessage, verifyEd25519SignedUrl } from '@ramp-protocol/sdk-l1/verify';
import { generateKeypair, signUrl } from '../helpers/ed25519.js';

const ORIGIN = 'https://pub.example.com';

describe('verifyEd25519SignedUrl', () => {
  it('accepts a fresh signature with matching kid', async () => {
    const kp = await generateKeypair('k1');
    const fixedNow = 1_710_000_000_000;
    const url = await signUrl(ORIGIN, kp.privateKey, {
      exp: Math.floor(fixedNow / 1000) + 300,
      kid: 'k1',
    });

    const res = await verifyEd25519SignedUrl(url, {
      resolveKey: async (kid) => (kid === 'k1' ? kp.publicKey : undefined),
      now: () => fixedNow,
    });

    expect(res.valid).toBe(true);
    expect(res.expired).toBe(false);
    expect(res.kid).toBe('k1');
  });

  it('rejects a tampered signature', async () => {
    const kp = await generateKeypair('k1');
    const now = 1_710_000_000_000;
    const url = await signUrl(ORIGIN, kp.privateKey, {
      exp: Math.floor(now / 1000) + 300,
      kid: 'k1',
    });
    const parsed = new URL(url);
    const sig = parsed.searchParams.get('sig') ?? '';
    const sigBytes = decodeBase64Url(sig);
    if (!sigBytes) throw new Error('decode failed');
    sigBytes[0] = sigBytes[0] === undefined ? 0 : sigBytes[0] ^ 0xff;
    parsed.searchParams.set('sig', encodeBase64Url(sigBytes));

    const res = await verifyEd25519SignedUrl(parsed.toString(), {
      resolveKey: async () => kp.publicKey,
      now: () => now,
    });

    expect(res.valid).toBe(false);
    expect(res.reason).toBe('signature_mismatch');
  });

  it('flags expired signature', async () => {
    const kp = await generateKeypair('k1');
    const now = 1_710_000_000_000;
    const url = await signUrl(ORIGIN, kp.privateKey, {
      exp: Math.floor(now / 1000) - 10,
      kid: 'k1',
    });

    const res = await verifyEd25519SignedUrl(url, {
      resolveKey: async () => kp.publicKey,
      now: () => now,
    });

    expect(res.valid).toBe(false);
    expect(res.expired).toBe(true);
    expect(res.reason).toBe('expired');
  });

  it('returns missing_sig when ?sig is absent', async () => {
    const kp = await generateKeypair('k1');
    const res = await verifyEd25519SignedUrl(`${ORIGIN}/r?exp=1`, {
      resolveKey: async () => kp.publicKey,
    });
    expect(res.reason).toBe('missing_sig');
  });

  it('returns missing_exp when ?exp is absent', async () => {
    const kp = await generateKeypair('k1');
    const res = await verifyEd25519SignedUrl(`${ORIGIN}/r?sig=abc`, {
      resolveKey: async () => kp.publicKey,
    });
    expect(res.reason).toBe('missing_exp');
  });

  it('returns bad_sig_encoding for malformed sig', async () => {
    const kp = await generateKeypair('k1');
    const now = 1_710_000_000_000;
    const res = await verifyEd25519SignedUrl(
      `${ORIGIN}/r?sig=!!!invalid!!!&exp=${Math.floor(now / 1000) + 10}`,
      { resolveKey: async () => kp.publicKey, now: () => now },
    );
    expect(res.reason).toBe('bad_sig_encoding');
  });

  it('signature_mismatch when key resolver returns undefined', async () => {
    const kp = await generateKeypair('k1');
    const now = 1_710_000_000_000;
    const url = await signUrl(ORIGIN, kp.privateKey, {
      exp: Math.floor(now / 1000) + 300,
      kid: 'k1',
    });
    const res = await verifyEd25519SignedUrl(url, {
      resolveKey: async () => undefined,
      now: () => now,
    });
    expect(res.valid).toBe(false);
    expect(res.reason).toBe('signature_mismatch');
  });

  it('signature_mismatch when path is altered after signing', async () => {
    const kp = await generateKeypair('k1');
    const now = 1_710_000_000_000;
    const signed = await signUrl(ORIGIN, kp.privateKey, {
      exp: Math.floor(now / 1000) + 300,
      kid: 'k1',
      path: '/original',
    });
    const tampered = signed.replace('/original', '/attacker');
    const res = await verifyEd25519SignedUrl(tampered, {
      resolveKey: async () => kp.publicKey,
      now: () => now,
    });
    expect(res.valid).toBe(false);
    expect(res.reason).toBe('signature_mismatch');
  });

  it('exposes decoded agent hash when agent param present', async () => {
    const kp = await generateKeypair('k1');
    const now = 1_710_000_000_000;
    const agentBytes = new Uint8Array([1, 2, 3, 4]);
    const url = await signUrl(ORIGIN, kp.privateKey, {
      exp: Math.floor(now / 1000) + 300,
      kid: 'k1',
      agentId: encodeBase64Url(agentBytes),
    });
    const res = await verifyEd25519SignedUrl(url, {
      resolveKey: async () => kp.publicKey,
      now: () => now,
    });
    expect(res.valid).toBe(true);
    // The public surface carries the agent_id param VERBATIM (base64url string),
    // matching Go VerifiedURL.AgentID / Python SignedUrlResult.agent_id.
    expect(res.agentId).toBe(encodeBase64Url(agentBytes));
  });
});

describe('canonicalMessage', () => {
  it('strips only the sig parameter', () => {
    const url = new URL(`${ORIGIN}/r?exp=1&sig=abc&kid=k1`);
    const msg = new TextDecoder().decode(canonicalMessage(url.toString()));
    expect(msg).toContain('exp=1');
    expect(msg).toContain('kid=k1');
    expect(msg).not.toContain('sig=');
  });

  it('is method-prefixed with GET', () => {
    const url = new URL(`${ORIGIN}/r?exp=1`);
    const msg = new TextDecoder().decode(canonicalMessage(url.toString()));
    expect(msg.startsWith('GET\n')).toBe(true);
  });
});

describe('base64url helpers', () => {
  it('round-trips arbitrary bytes', () => {
    const input = new Uint8Array([0, 1, 2, 250, 251, 252]);
    const encoded = encodeBase64Url(input);
    expect(encoded).not.toContain('=');
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
    const decoded = decodeBase64Url(encoded);
    expect(decoded).toBeDefined();
    expect(Array.from(decoded as Uint8Array)).toEqual(Array.from(input));
  });

  it('decodeBase64Url returns undefined for garbage', () => {
    expect(decodeBase64Url('!!!')).toBeUndefined();
  });
});
