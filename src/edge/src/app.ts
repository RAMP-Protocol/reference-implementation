import { Hono } from 'hono';
import type { Context, MiddlewareHandler } from 'hono';

import { type PopResult, verifyAgentBinding } from './pop.js';
import { type AppDeps, WELL_KNOWN_PATH, looksLikeBot } from './types.js';
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
  app.get(WELL_KNOWN_PATH, (c) => c.json(deps.manifest));
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

  const bindingError = await enforceBinding(c, deps, url);
  if (bindingError) return bindingError;

  return passToOrigin(c, deps);
}

// enforceBinding runs the proof-of-possession check when the verified URL is
// bound to an agent (carries agent_id) and binding enforcement is explicitly
// enabled (ADR-013 D1/D6). Returns a 403 Response on failure, or undefined to
// proceed. Enforcement is OPT-IN: it defaults OFF (bearer security — short TTL
// + TLS) because v1's MCP→Broker→Exchange topology binds the URL to the proven
// caller (the broker on the relay path), which the fetching agent cannot prove
// possession of. Set enforceBinding true only where the fetcher holds the
// bound key.
async function enforceBinding(
  c: Context<{ Variables: AppVariables }>,
  deps: AppDeps,
  url: URL,
): Promise<Response | undefined> {
  const agentId = url.searchParams.get('agent_id');
  if (!agentId || deps.enforceBinding !== true) return undefined;

  const verifyBinding = deps.verifyBinding ?? verifyAgentBinding;
  const pop = await verifyBinding({
    url: c.req.url,
    method: c.req.method,
    headers: c.req.raw.headers,
    agentId,
    ...(deps.now !== undefined ? { now: deps.now } : {}),
  });
  if (!pop.ok) return handlePopResult(c, pop);
  return undefined;
}

function handlePopResult(c: Context<{ Variables: AppVariables }>, pop: PopResult): Response {
  return c.json({ error: 'Agent binding check failed', reason: pop.reason ?? 'unknown' }, 403);
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
    'X-Content-Rules': new URL(WELL_KNOWN_PATH, withProtocol(c.req.url)).toString(),
  };
  if (deps.exchangeUrl) headers['X-RAMP-Exchange'] = deps.exchangeUrl;
  return c.json({ error: 'Access denied. Negotiate access via the exchange.' }, 403, headers);
}

function withProtocol(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
}
