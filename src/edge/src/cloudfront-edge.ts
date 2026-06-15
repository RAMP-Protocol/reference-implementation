// Native CloudFront Lambda@Edge viewer-request handler.
//
// This is the SINGLE SOURCE of the deployed bot-redirect Lambda: the deploy
// build (scripts/build-lambda-edge.mjs) bundles this module with a per-
// deployment config object into the index.mjs that terraform ships. Authoring
// it here — rather than as a hand-maintained .mjs in the infra repo — keeps the
// reference implementation and the live edge identical save for baked config
// (Lambda@Edge has no env vars, so config cannot be injected at runtime).
//
// It preserves the existing decision ladder (signed-URL passthrough, bot 403,
// human passthrough) and adds the ADR-015 free-index fast path ahead of it: a
// WBA-signed crawler declaring a covered purpose over a free path is served the
// markdown rendition in a single request and recorded with its signature.

import type {
  CloudFrontHeaders,
  CloudFrontRequest,
  CloudFrontRequestEvent,
  CloudFrontResultResponse,
} from 'aws-lambda';

import { type FreeRule, matchFreeRule } from './freerule.js';
import { verifyWebBotAuthRequest } from './wba.js';

export interface BotPattern {
  name: string;
  re: RegExp;
}

export interface McpEndpoint {
  url: string;
  transport: string;
  description: string;
  extension: string;
}

export interface EdgeConfig {
  freeRules: readonly FreeRule[];
  resolveBotKey: (
    keyid: string | undefined,
    agent: string | undefined,
  ) => Promise<CryptoKey | undefined>;
  exchangeUrl: string;
  mcpEndpoints: McpEndpoint[];
  /** Bot UA patterns for the heuristic 403 (advisory only — never authorizes). */
  botPatterns?: readonly BotPattern[];
  /** ramp.json path served at the publisher origin. Default '/.well-known/ramp.json'. */
  rampJsonPath?: string;
  purposeHeader?: string;
  now?: () => number;
  /** Sink for the JSON decision log line. Default console.log(JSON.stringify(...)). */
  log?: (line: Record<string, unknown>) => void;
  /** Request-id generator (injectable for tests). Default crypto.randomUUID. */
  newRequestId?: () => string;
}

// The current deployed bot list (advisory heuristic for the 403 branch). A UA
// match never releases bytes — only the WBA signature does (ADR-015 D2).
const DEFAULT_BOT_PATTERNS: readonly BotPattern[] = Object.freeze([
  { name: 'bot-suffix', re: /bot\b/i },
  { name: 'crawler', re: /crawler/i },
  { name: 'spider', re: /spider/i },
  { name: 'scraper', re: /scraper/i },
  { name: 'fetcher', re: /\bfetch\w*/i },
  { name: 'GPTBot', re: /GPTBot/i },
  { name: 'ChatGPT', re: /ChatGPT/i },
  { name: 'OAI-SearchBot', re: /OAI-SearchBot/i },
  { name: 'ClaudeBot', re: /ClaudeBot/i },
  { name: 'Claude-User', re: /Claude-User/i },
  { name: 'Claude-SearchBot', re: /Claude-SearchBot/i },
  { name: 'Claude-Web', re: /Claude-Web/i },
  { name: 'claude-generic', re: /\bclaude\b/i },
  { name: 'anthropic-ai', re: /anthropic-ai/i },
  { name: 'anthropic-generic', re: /anthropic/i },
  { name: 'CCBot', re: /CCBot/i },
  { name: 'PerplexityBot', re: /PerplexityBot/i },
  { name: 'Perplexity-User', re: /Perplexity-User/i },
  { name: 'Bytespider', re: /Bytespider/i },
  { name: 'Google-Extended', re: /Google-Extended/i },
  { name: 'Googlebot', re: /Googlebot/i },
  { name: 'Bingbot', re: /Bingbot/i },
  { name: 'Applebot', re: /Applebot/i },
  { name: 'Amazonbot', re: /Amazonbot/i },
  { name: 'curl', re: /^curl\//i },
  { name: 'wget', re: /^wget\//i },
  { name: 'python-requests', re: /python-requests/i },
  { name: 'python-httpx', re: /python-httpx/i },
  { name: 'node-fetch', re: /node-fetch/i },
  { name: 'axios', re: /axios/i },
  { name: 'go-http', re: /^Go-http-client/i },
]);

type EdgeResult = CloudFrontRequest | CloudFrontResultResponse;

export function createCloudFrontHandler(
  config: EdgeConfig,
): (event: CloudFrontRequestEvent) => Promise<EdgeResult> {
  const botPatterns = config.botPatterns ?? DEFAULT_BOT_PATTERNS;
  const rampJsonPath = config.rampJsonPath ?? '/.well-known/ramp.json';
  const log = config.log ?? ((line) => console.log(JSON.stringify(line)));
  const newRequestId = config.newRequestId ?? (() => crypto.randomUUID());

  return async (event) => {
    const request = event.Records[0]?.cf.request as CloudFrontRequest;
    const headers = headerRecord(request.headers);
    const userAgent = headers['user-agent'] ?? '';
    const qs = request.querystring ?? '';
    const audit = parseAuditFields(qs);

    // 1. Free-index fast path (ADR-015): a WBA-signed crawler over a free path.
    const fast = await tryFreeIndex(request, headers, audit, config, newRequestId, log);
    if (fast) return fast;

    // 2–4. Existing ladder: signed-URL passthrough, bot 403, human passthrough.
    const botPattern = matchBot(userAgent, botPatterns);
    const decision = qs.includes('Signature=')
      ? 'pass:signed'
      : botPattern === null
        ? 'pass:human'
        : 'block:bot';

    log({
      msg: 'ramp-demo-edge',
      method: request.method,
      uri: request.uri,
      qs,
      ua: userAgent,
      decision,
      bot_pattern: botPattern,
      tx_id: audit.txId,
      req_id: audit.reqId,
      signature_prefix: audit.signaturePrefix,
    });

    if (decision !== 'block:bot') return request;
    return denyBot(headers, config, rampJsonPath);
  };
}

// Returns a passthrough request on a successful free-index serve, else
// undefined to fall through to the normal ladder. The authority is the WBA
// signature, never the UA — an unverified or uncovered request never serves.
async function tryFreeIndex(
  request: CloudFrontRequest,
  headers: Record<string, string | undefined>,
  audit: AuditFields,
  config: EdgeConfig,
  newRequestId: () => string,
  log: (line: Record<string, unknown>) => void,
): Promise<CloudFrontRequest | undefined> {
  if (headers.signature === undefined || headers['signature-input'] === undefined) {
    return undefined;
  }

  const verifyInput = {
    method: request.method,
    authority: headers.host ?? '',
    path: request.uri,
    headers,
    resolveBotKey: config.resolveBotKey,
    ...(config.purposeHeader !== undefined ? { purposeHeader: config.purposeHeader } : {}),
    ...(config.now !== undefined ? { now: config.now } : {}),
  };
  const wba = await verifyWebBotAuthRequest(verifyInput);
  if (!wba.valid) return undefined;

  const free = matchFreeRule(request.uri, config.freeRules);
  if (!free) return undefined;

  const reqId = audit.reqId !== '' ? audit.reqId : newRequestId();
  log({
    msg: 'ramp-demo-edge',
    method: request.method,
    uri: request.uri,
    rendition: free.renditionPath,
    ua: headers['user-agent'] ?? '',
    decision: 'pass:free-index',
    purpose: wba.purpose,
    bot_kid: wba.keyid,
    signature_agent: wba.agent,
    sig_prefix: wba.sigPrefix,
    license_id: free.licenseId,
    content_hash: free.contentHash ?? '',
    req_id: reqId,
  });

  // Serve the hosted markdown rendition in one request: rewrite the origin path
  // and let CloudFront fetch it from S3. Response labeling (D4 Content-Usage /
  // license pointer) would be attached at origin-response in production; the
  // binding act is the signed request above, not the response label.
  request.uri = free.renditionPath;
  return request;
}

function denyBot(
  headers: Record<string, string | undefined>,
  config: EdgeConfig,
  rampJsonPath: string,
): CloudFrontResultResponse {
  const host = headers.host ?? 'demo.ramp-protocol.org';
  const rampJsonUrl = `https://${host}${rampJsonPath}`;
  const mcp = config.mcpEndpoints;
  const responseHeaders: CloudFrontHeaders = {
    'content-type': [{ key: 'Content-Type', value: 'application/json' }],
    'x-content-rules': [{ key: 'X-Content-Rules', value: rampJsonUrl }],
  };
  if (mcp[0]) {
    responseHeaders['x-ramp-mcp'] = [{ key: 'X-Ramp-Mcp', value: mcp[0].url }];
  }
  return {
    status: '403',
    statusDescription: 'Forbidden',
    headers: responseHeaders,
    body: JSON.stringify({
      error: 'Access denied. Negotiate access via the exchange.',
      exchange: config.exchangeUrl,
      ramp_json: rampJsonUrl,
      mcp_endpoints: mcp,
    }),
  };
}

function matchBot(userAgent: string, patterns: readonly BotPattern[]): string | null {
  if (!userAgent) return 'missing-ua';
  for (const { name, re } of patterns) {
    if (re.test(userAgent)) return name;
  }
  return null;
}

interface AuditFields {
  txId: string;
  reqId: string;
  signaturePrefix: string;
}

// Parse audit correlators + signature prefix out of the CloudFront-style
// querystring (the Exchange embeds tx_id + req_id before signing). Mirrors the
// existing deployed handler so the paid ledger join keeps working.
function parseAuditFields(qs: string): AuditFields {
  const out: AuditFields = { txId: '', reqId: '', signaturePrefix: '' };
  if (!qs) return out;
  for (const pair of qs.split('&')) {
    const eq = pair.indexOf('=');
    if (eq < 0) continue;
    const k = pair.slice(0, eq);
    const v = pair.slice(eq + 1);
    if (k === 'tx_id') out.txId = decodeURIComponent(v);
    else if (k === 'req_id') out.reqId = decodeURIComponent(v);
    else if (k === 'Signature') out.signaturePrefix = v.slice(0, 16);
  }
  return out;
}

function headerRecord(headers: CloudFrontHeaders): Record<string, string | undefined> {
  const out: Record<string, string> = {};
  for (const key of Object.keys(headers)) {
    const value = headers[key]?.[0]?.value;
    if (value !== undefined) out[key.toLowerCase()] = value;
  }
  return out;
}
