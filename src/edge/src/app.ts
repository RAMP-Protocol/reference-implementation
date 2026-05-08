import { Hono } from 'hono';
import type { Context, MiddlewareHandler } from 'hono';

import { type AppDeps, looksLikeBot } from './types.js';
import { type VerifyResult, verifyEd25519SignedUrl } from './verify.js';

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
    if (looksLikeBot(userAgent)) return denyBot(c, deps);
    return passToOrigin(c, deps);
  }

  const verify = deps.verify ?? ((raw: string) => defaultVerify(raw, deps));
  const result = await verify(c.req.url);
  if (!result.valid) return handleVerifyResult(c, result);
  return passToOrigin(c, deps);
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
