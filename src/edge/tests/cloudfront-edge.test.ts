import type {
  CloudFrontHeaders,
  CloudFrontRequest,
  CloudFrontRequestEvent,
  CloudFrontResultResponse,
} from 'aws-lambda';
import { beforeAll, describe, expect, it } from 'vitest';

import { type EdgeConfig, createCloudFrontHandler } from '../src/cloudfront-edge.js';
import type { FreeRule } from '../src/freerule.js';
import { type TestKeypair, generateKeypair, signRequest } from './helpers/ed25519.js';

const HOST = 'demo.ramp-protocol.org';
const FREE_PATH = '/articles/philosophers/socrates.txt';

const FREE_RULES: FreeRule[] = [
  {
    pathPattern: '/articles/philosophers/*',
    licenseId: 'tdl:free-index-v1',
    contentUsage: 'ai-index=y',
    contentHash: 'sha256-demo',
  },
];

let bot: TestKeypair;

beforeAll(async () => {
  bot = await generateKeypair('bot-1');
});

function makeConfig(logs: Record<string, unknown>[]): EdgeConfig {
  return {
    freeRules: FREE_RULES,
    resolveBotKey: async (kid) => (kid === 'bot-1' ? bot.publicKey : undefined),
    exchangeUrl: 'https://exchange.demo.ramp-protocol.org',
    mcpEndpoints: [
      {
        url: 'https://mcp.demo.ramp-protocol.org/mcp',
        transport: 'http-streamable',
        description: 'RAMP MCP',
        extension: 'ramp-0.4-draft',
      },
    ],
    log: (line) => logs.push(line),
    newRequestId: () => 'req-test-1',
  };
}

function toCfHeaders(record: Record<string, string>): CloudFrontHeaders {
  const out: CloudFrontHeaders = {};
  for (const [k, v] of Object.entries(record)) {
    out[k.toLowerCase()] = [{ key: k, value: v }];
  }
  return out;
}

function makeEvent(opts: {
  uri: string;
  querystring?: string;
  headers: Record<string, string>;
}): CloudFrontRequestEvent {
  const request: CloudFrontRequest = {
    clientIp: '203.0.113.1',
    method: 'GET',
    uri: opts.uri,
    querystring: opts.querystring ?? '',
    headers: toCfHeaders({ host: HOST, ...opts.headers }),
  };
  return {
    Records: [{ cf: { config: { distributionDomainName: HOST } as never, request } }],
  } as CloudFrontRequestEvent;
}

function isResult(r: unknown): r is CloudFrontResultResponse {
  return typeof r === 'object' && r !== null && 'status' in r;
}

describe('createCloudFrontHandler', () => {
  it('fast-paths a signed ai-index crawler: serves the requested resource + logs pass:free-index', async () => {
    const logs: Record<string, unknown>[] = [];
    const handler = createCloudFrontHandler(makeConfig(logs));
    const headers = await signRequest(bot.privateKey, {
      authority: HOST,
      path: FREE_PATH,
      purpose: 'ai-index',
      keyid: 'bot-1',
      agent: 'https://bot.example/.well-known/jwks.json',
    });

    const result = await handler(makeEvent({ uri: FREE_PATH, headers }));

    expect(isResult(result)).toBe(false);
    const req = result as CloudFrontRequest;
    // Passthrough: the requested URI is served unchanged (one request).
    expect(req.uri).toBe(FREE_PATH);

    const line = logs.at(-1) as Record<string, unknown>;
    expect(line.decision).toBe('pass:free-index');
    expect(line.purpose).toBe('ai-index');
    expect(line.bot_kid).toBe('bot-1');
    expect(line.license_id).toBe('tdl:free-index-v1');
    expect(line.content_hash).toBe('sha256-demo');
    expect(line.sig_prefix).toBeTruthy();
    expect(line).not.toHaveProperty('tx_id'); // free serve carries no transaction
  });

  it('does not fast-path when the signature omits the purpose (falls through to bot 403)', async () => {
    const logs: Record<string, unknown>[] = [];
    const handler = createCloudFrontHandler(makeConfig(logs));
    const headers = await signRequest(bot.privateKey, {
      authority: HOST,
      path: FREE_PATH,
      purpose: 'ai-index',
      keyid: 'bot-1',
      components: ['@authority', '@path'],
    });

    const result = await handler(
      makeEvent({ uri: FREE_PATH, headers: { ...headers, 'user-agent': 'GPTBot/1.0' } }),
    );

    expect(isResult(result)).toBe(true);
    expect((result as CloudFrontResultResponse).status).toBe('403');
  });

  it('passes a signed-URL request through as pass:signed (existing behavior)', async () => {
    const logs: Record<string, unknown>[] = [];
    const handler = createCloudFrontHandler(makeConfig(logs));
    const result = await handler(
      makeEvent({
        uri: '/articles/philosophers/plato.txt',
        querystring: 'Signature=abc123def456ghijk&tx_id=tx-9&req_id=req-9',
        headers: { 'user-agent': 'GPTBot/1.0' },
      }),
    );
    expect(isResult(result)).toBe(false);
    const line = logs.at(-1) as Record<string, unknown>;
    expect(line.decision).toBe('pass:signed');
    expect(line.tx_id).toBe('tx-9');
    expect(line.signature_prefix).toBe('abc123def456ghij'); // first 16 chars
  });

  it('403s an unsigned bot with X-Content-Rules + mcp endpoints', async () => {
    const logs: Record<string, unknown>[] = [];
    const handler = createCloudFrontHandler(makeConfig(logs));
    const result = await handler(
      makeEvent({ uri: FREE_PATH, headers: { 'user-agent': 'GPTBot/1.0' } }),
    );
    expect(isResult(result)).toBe(true);
    const res = result as CloudFrontResultResponse;
    expect(res.status).toBe('403');
    expect(res.headers?.['x-content-rules']?.[0]?.value).toBe(
      `https://${HOST}/.well-known/ramp.json`,
    );
    const body = JSON.parse(res.body ?? '{}') as { mcp_endpoints: unknown[] };
    expect(body.mcp_endpoints).toHaveLength(1);
    expect((logs.at(-1) as Record<string, unknown>).decision).toBe('block:bot');
  });

  it('passes a human UA through as pass:human', async () => {
    const logs: Record<string, unknown>[] = [];
    const handler = createCloudFrontHandler(makeConfig(logs));
    const result = await handler(
      makeEvent({
        uri: '/index.html',
        headers: {
          'user-agent':
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15',
        },
      }),
    );
    expect(isResult(result)).toBe(false);
    expect((logs.at(-1) as Record<string, unknown>).decision).toBe('pass:human');
  });
});
