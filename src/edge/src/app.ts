import { Hono } from 'hono';
import type { Context, MiddlewareHandler } from 'hono';

import { matchFreeRule } from './freerule.js';
import { type AppDeps, looksLikeBot } from './types.js';
import { type VerifyResult, verifyEd25519SignedUrl } from './verify.js';
import { verifyWebBotAuthRequest } from './wba.js';

export type AppVariables = { requestId: string };

export type App = Hono<{ Variables: AppVariables }>;

export function createApp(deps: AppDeps): App {
  const app = new Hono<{ Variables: AppVariables }>();
  app.use('*', requestIdMiddleware);
  mountWellKnownRoutes(app, deps);
  mountCatchall(app, deps);
  return app;
}

const requestIdMiddleware: MiddlewareHandler<{ Variables: AppVariables }> = async (c, next) => {
  const incoming = c.req.header('x-request-id');
  const id = incoming && incoming.length > 0 ? incoming : crypto.randomUUID();
  c.set('requestId', id);
  c.header('X-Request-ID', id);
  await next();
};

function mountWellKnownRoutes(app: App, deps: AppDeps): void {
  app.get('/healthz', (c) => c.text('ok'));
  app.get('/.well-known/ramp.json', (c) => c.json(deps.manifest));
  app.get('/.well-known/ramp-verifier.json', (c) => c.json(deps.verifierManifest));
  app.get('/rsl.txt', (c) => c.text(deps.rslBody ?? '', 200, { 'content-type': 'text/plain' }));
  app.get('/.well-known/ramp-verify/:token', (c) => {
    const token = c.req.param('token');
    const body = deps.acmeTokens?.[token];
    if (!body) return c.text('not found', 404);
    return c.text(body, 200, { 'content-type': 'text/plain' });
  });
}

function mountCatchall(app: App, deps: AppDeps): void {
  app.get('*', async (c) => catchallHandler(c, deps));
}

async function catchallHandler(
  c: Context<{ Variables: AppVariables }>,
  deps: AppDeps,
): Promise<Response> {
  const url = new URL(c.req.url);
  const hasSig = url.searchParams.has('sig');
  const userAgent = c.req.header('user-agent');

  if (!hasSig) {
    const fast = await tryFreeIndex(c, deps);
    if (fast) return fast;
    if (looksLikeBot(userAgent)) return denyBot(c, deps);
    return passToOrigin(c, deps);
  }

  const verify = deps.verify ?? ((raw: string) => defaultVerify(raw, deps));
  const result = await verify(c.req.url);
  if (!result.valid) return handleVerifyResult(c, result);
  return passToOrigin(c, deps);
}

// tryFreeIndex serves the ADR-015 free-index fast path: a WBA-signed crawler
// declaring a covered purpose over a free-rule path gets the markdown rendition
// in one request, recorded by its signature. Returns undefined to fall through
// to the existing bot/human handling. Inert unless fast-path deps are wired.
async function tryFreeIndex(
  c: Context<{ Variables: AppVariables }>,
  deps: AppDeps,
): Promise<Response | undefined> {
  if (!deps.resolveBotKey || !deps.freeRules) return undefined;
  if (!c.req.header('signature') || !c.req.header('signature-input')) return undefined;

  const url = new URL(c.req.url);
  const wba = await verifyWebBotAuthRequest({
    method: c.req.method,
    authority: url.host,
    path: url.pathname,
    headers: c.req.raw.headers,
    resolveBotKey: deps.resolveBotKey,
    ...(deps.purposeHeader !== undefined ? { purposeHeader: deps.purposeHeader } : {}),
    ...(deps.now !== undefined ? { now: deps.now } : {}),
  });
  if (!wba.valid) return undefined;

  const free = matchFreeRule(url.pathname, deps.freeRules);
  if (!free) return undefined;

  // biome-ignore lint/suspicious/noConsole: free-index decision log, parity with the deployed edge handler (scanned by ledger.py)
  console.log(
    JSON.stringify({
      msg: 'ramp-edge',
      decision: 'pass:free-index',
      uri: url.pathname,
      purpose: wba.purpose,
      bot_kid: wba.keyid,
      signature_agent: wba.agent,
      sig_prefix: wba.sigPrefix,
      license_id: free.licenseId,
      content_hash: free.contentHash ?? '',
      req_id: c.get('requestId'),
    }),
  );

  // Serve the requested free resource; attach D4 notice headers (Content-Usage
  // + license pointer). The binding act is the signed request, not these labels.
  const origin = await passToOrigin(c, deps);
  const resp = new Response(origin.body, origin);
  resp.headers.set('Content-Usage', free.contentUsage);
  resp.headers.set('X-RAMP-License', free.licenseId);
  return resp;
}

async function passToOrigin(
  c: Context<{ Variables: AppVariables }>,
  deps: AppDeps,
): Promise<Response> {
  if (!deps.originUrl) return c.body(null, 200);
  const incoming = new URL(c.req.url);
  const origin = new URL(deps.originUrl);
  origin.pathname = incoming.pathname;
  origin.search = '';
  const fetcher = deps.fetcher ?? fetch;
  const upstreamReq = new Request(origin.toString(), {
    method: c.req.method,
    headers: c.req.raw.headers,
  });
  return fetcher(upstreamReq);
}

async function defaultVerify(rawUrl: string, deps: AppDeps): Promise<VerifyResult> {
  return verifyEd25519SignedUrl(rawUrl, {
    resolveKey: deps.resolveKey,
    ...(deps.now !== undefined ? { now: deps.now } : {}),
  });
}

function handleVerifyResult(
  c: Context<{ Variables: AppVariables }>,
  result: VerifyResult,
): Response {
  if (result.expired) {
    return c.json({ error: 'Signed URL has expired', reason: 'expired' }, 403);
  }
  return c.json({ error: 'Invalid signature', reason: result.reason ?? 'unknown' }, 403);
}

function denyBot(c: Context<{ Variables: AppVariables }>, deps: AppDeps): Response {
  const headers: Record<string, string> = {
    'X-Content-Rules': new URL('/.well-known/ramp.json', withProtocol(c.req.url)).toString(),
  };
  if (deps.manifest.exchange) headers['X-RAMP-Exchange'] = deps.manifest.exchange;
  return c.json({ error: 'Access denied. Negotiate access via the marketplace.' }, 403, headers);
}

function withProtocol(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
}
