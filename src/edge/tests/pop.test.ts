import { describe, expect, it } from 'vitest';

import { type PopFailure, verifyAgentBinding } from '../src/pop.js';
import { thumbprint } from '../src/thumbprint.js';
import { encodeBase64Url } from '../src/verify.js';
import {
  type TestKeypair,
  generateKeypair,
  rawPublicKey,
  signGetHeaders,
} from './helpers/ed25519.js';

const URL_UNDER_TEST = 'https://pub.example.com/article/42?exp=4102444800&sig=abc&agent_id=';

async function thumbOf(kp: TestKeypair): Promise<string> {
  return thumbprint(rawPublicKey(kp));
}

function headersFrom(rec: Record<string, string>): Headers {
  const h = new Headers();
  for (const [k, v] of Object.entries(rec)) h.set(k, v);
  return h;
}

const FAR_FUTURE = 4_102_444_800; // 2100-01-01
const NOW_MS = 1_710_000_000_000;
const now = () => NOW_MS;

describe('verifyAgentBinding', () => {
  it('accepts a valid proof (3-way identity holds)', async () => {
    const kp = await generateKeypair();
    const agentId = await thumbOf(kp);
    const url = URL_UNDER_TEST + agentId;
    const headers = headersFrom(
      await signGetHeaders(url, kp, {
        keyid: agentId,
        created: 1_700_000_000,
        expires: FAR_FUTURE,
      }),
    );

    const res = await verifyAgentBinding({ url, method: 'GET', headers, agentId, now });
    expect(res.ok).toBe(true);
  });

  const expectFail = async (
    mutate: (h: Record<string, string>, agentId: string) => void,
    reason: PopFailure,
    opts: { keyid?: (a: string) => string } = {},
  ) => {
    const kp = await generateKeypair();
    const agentId = await thumbOf(kp);
    const url = URL_UNDER_TEST + agentId;
    const rec = await signGetHeaders(url, kp, {
      keyid: opts.keyid ? opts.keyid(agentId) : agentId,
      created: 1_700_000_000,
      expires: FAR_FUTURE,
    });
    mutate(rec, agentId);
    const res = await verifyAgentBinding({
      url,
      method: 'GET',
      headers: headersFrom(rec),
      agentId,
      now,
    });
    expect(res.ok).toBe(false);
    expect(res.reason).toBe(reason);
  };

  it('rejects a missing presented key', async () => {
    await expectFail((h) => {
      h['X-RAMP-Agent-Key'] = '';
    }, 'missing_agent_key');
  });

  it('rejects a malformed presented key', async () => {
    await expectFail((h) => {
      h['X-RAMP-Agent-Key'] = 'AAEC';
    }, 'bad_agent_key');
  });

  it('rejects a missing signature', async () => {
    await expectFail((h) => {
      h.Signature = '';
    }, 'missing_sig');
  });

  it('rejects keyid != agent_id', async () => {
    await expectFail(() => {}, 'keyid_mismatch', { keyid: () => 'not-the-agent-id' });
  });

  it('rejects a presented key whose thumbprint != agent_id', async () => {
    const wrong = await generateKeypair();
    await expectFail((h) => {
      h['X-RAMP-Agent-Key'] = encodeBase64Url(rawPublicKey(wrong));
    }, 'thumbprint_mismatch');
  });

  it('rejects an invalid signature', async () => {
    await expectFail((h) => {
      h.Signature = 'sig1=:AAAA:';
    }, 'pop_sig_invalid');
  });

  it('rejects a proof with no expires', async () => {
    await expectFail((h) => {
      h['Signature-Input'] = (h['Signature-Input'] as string).replace(/;expires=\d+/, '');
    }, 'pop_missing_exp');
  });

  it('rejects a proof with no created', async () => {
    await expectFail((h) => {
      h['Signature-Input'] = (h['Signature-Input'] as string).replace(/;created=\d+/, '');
    }, 'pop_missing_created');
  });

  it('rejects a proof whose created is beyond the future-skew bound', async () => {
    const kp = await generateKeypair();
    const agentId = await thumbOf(kp);
    const url = URL_UNDER_TEST + agentId;
    const headers = headersFrom(
      await signGetHeaders(url, kp, {
        keyid: agentId,
        created: Math.floor(NOW_MS / 1000) + 600, // > 300s future-skew bound
        expires: FAR_FUTURE,
      }),
    );
    const res = await verifyAgentBinding({ url, method: 'GET', headers, agentId, now });
    expect(res.ok).toBe(false);
    expect(res.reason).toBe('pop_future_created');
  });

  it('rejects an expired proof', async () => {
    const kp = await generateKeypair();
    const agentId = await thumbOf(kp);
    const url = URL_UNDER_TEST + agentId;
    const headers = headersFrom(
      await signGetHeaders(url, kp, {
        keyid: agentId,
        created: 1_700_000_000,
        expires: Math.floor(NOW_MS / 1000) - 10,
      }),
    );
    const res = await verifyAgentBinding({ url, method: 'GET', headers, agentId, now });
    expect(res.ok).toBe(false);
    expect(res.reason).toBe('pop_expired');
  });

  it('rejects an incomplete covered-component set', async () => {
    const kp = await generateKeypair();
    const agentId = await thumbOf(kp);
    const url = URL_UNDER_TEST + agentId;
    const rawParams = `("@method");keyid="${agentId}";alg="ed25519";created=1700000000;expires=${FAR_FUTURE}`;
    const headers = headersFrom({
      'X-RAMP-Agent-Key': encodeBase64Url(rawPublicKey(kp)),
      'Signature-Input': `sig1=${rawParams}`,
      Signature: 'sig1=:AAAA:',
    });
    const res = await verifyAgentBinding({ url, method: 'GET', headers, agentId, now });
    expect(res.reason).toBe('bad_covered_components');
  });

  it('rejects an unsupported algorithm', async () => {
    const kp = await generateKeypair();
    const agentId = await thumbOf(kp);
    const url = URL_UNDER_TEST + agentId;
    const rec = await signGetHeaders(url, kp, {
      keyid: agentId,
      created: 1_700_000_000,
      expires: FAR_FUTURE,
    });
    rec['Signature-Input'] = (rec['Signature-Input'] as string).replace('ed25519', 'rsa');
    const res = await verifyAgentBinding({
      url,
      method: 'GET',
      headers: headersFrom(rec),
      agentId,
      now,
    });
    expect(res.reason).toBe('unsupported_alg');
  });
});
