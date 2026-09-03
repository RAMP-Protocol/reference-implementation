import { Hono } from 'hono';
import type { Context, MiddlewareHandler } from 'hono';

import { type PopResult, verifyAgentBinding } from '@ramp-protocol/sdk-l1/pop';
import { type VerifyResult, verifyEd25519SignedUrl } from '@ramp-protocol/sdk-l1/verify';

import { classifyClient } from './bot-classification.js';
import { type DeliveryFacts, logDelivery, logDeny, logEvent } from './log.js';
import {
  type AppDeps,
  type AppVariables,
  WBA_DIRECTORY_CONTENT_TYPE,
  WBA_PATH,
  WELL_KNOWN_PATH,
} from './types.js';

export type { AppVariables } from './types.js';

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
  // Pure Web Bot Auth directory: the publisher's Ed25519 signing key(s) as a JWK
  // Set, served with application/jwk-set+json so any off-the-shelf WBA verifier
  // can read it. Absent (404) on deployments that publish no signing key.
  app.get(WBA_PATH, (c) => {
    if (!deps.wba) return c.text('not found', 404);
    return c.body(JSON.stringify(deps.wba), 200, { 'content-type': WBA_DIRECTORY_CONTENT_TYPE });
  });
  app.get('/rsl.txt', (c) => c.text(deps.rslBody ?? '', 200, { 'content-type': 'text/plain' }));
  app.get('/.well-known/ramp-verify/:token', (c) => {
    const token = c.req.param('token');
    const body = deps.acmeTokens?.[token];
    if (!body) return c.text('not found', 404);
    return c.text(body, 200, { 'content-type': 'text/plain' });
  });
}

function mountCatchall(app: App, deps: AppDeps): void {
  app.all('*', async (c) => catchallHandler(c, deps));
}

async function catchallHandler(
  c: Context<{ Variables: AppVariables }>,
  deps: AppDeps,
): Promise<Response> {
  const url = new URL(c.req.url);
  const hasSig = url.searchParams.has('sig');
  const userAgent = c.req.header('user-agent');

  if (!hasSig) {
    // The bot gate applies only to content reads (GET/HEAD). Non-read methods
    // (form posts, webhooks, APIs) carry no licensable content in the response
    // and routinely come from clients without a browser User-Agent, so they
    // pass straight to the origin. Search crawlers pass like humans — the
    // publisher wants indexing; only AI bots are sent to negotiate.
    if (isReadMethod(c.req.method)) {
      const cls = classifyClient(
        userAgent,
        deps.botSignal?.(c.req.raw),
        deps.botAllowPatterns,
        deps.botDenyPatterns,
      );
      if (cls === 'ai_bot') return denyBot(c, deps);
    }
    return passToOrigin(c, deps);
  }

  const verify = deps.verify ?? ((raw: string) => defaultVerify(raw, deps));
  let result: VerifyResult;
  try {
    result = await verify(c.req.url);
  } catch (err) {
    return handleVerifyUnavailable(c, err);
  }
  if (!result.valid) return handleVerifyResult(c, result);

  // The URL signature covers the URL alone — never the HTTP method or body.
  // Only the proof-of-possession check binds the method (its RFC 9421 covered
  // fields include @method), so a signed request may use a non-read method
  // only when that check will actually run. Without this refusal, one leaked
  // signed read URL could be replayed as POST/PUT/DELETE with an arbitrary
  // body against the origin. Unsigned non-read traffic (form posts, webhooks)
  // is unaffected — it takes the pass-through above.
  if (!isReadMethod(c.req.method) && !bindingWillRun(deps, url)) {
    return denySignedNonRead(c);
  }

  const bindingError = await enforceBinding(c, deps, url);
  if (bindingError) return bindingError;

  // Authorized. passToOrigin emits the delivery record once it knows which
  // branch served the request, and only if that branch answered.
  return passToOrigin(c, deps, {
    ...(result.kid !== undefined ? { kid: result.kid } : {}),
    ...(result.agentId !== undefined ? { agentId: result.agentId } : {}),
  });
}

function isReadMethod(method: string): boolean {
  return method === 'GET' || method === 'HEAD';
}

// bindingWillRun mirrors enforceBinding's own skip condition: the check runs
// only for a URL bound to an agent, on a deployment with enforcement on. Kept
// as the single shared predicate so the method gate above can never disagree
// with the check it relies on.
function bindingWillRun(deps: AppDeps, url: URL): boolean {
  return Boolean(url.searchParams.get('agent_id')) && deps.enforceBinding === true;
}

function denySignedNonRead(c: Context<{ Variables: AppVariables }>): Response {
  const reason = 'method_not_bound';
  logDeny(c, 'edge.deny.method', reason);
  return c.json({ error: 'Signed URLs authorize content reads only', reason }, 405, {
    Allow: 'GET, HEAD',
  });
}

// enforceBinding runs the proof-of-possession check when the verified URL is
// bound to an agent (carries agent_id) and deps.enforceBinding is true.
// Returns a 403 Response on failure, or undefined to proceed.
//
// Enforcement defaults ON wherever the edge can run the check (ADR-013 D6.1);
// RAMP_ENFORCE_BINDING=false opts a deployment down to bearer security. The
// custodial registry flow satisfies the check because the registry — which
// holds the agent's key — makes the bound fetch itself (ADR-023); the agent
// never holds that key and never fetches. CloudFront-native cannot run this
// path at all and keeps the bearer posture (D6).
async function enforceBinding(
  c: Context<{ Variables: AppVariables }>,
  deps: AppDeps,
  url: URL,
): Promise<Response | undefined> {
  if (!bindingWillRun(deps, url)) return undefined;
  const agentId = url.searchParams.get('agent_id') as string;

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
  const reason = pop.reason ?? 'unknown';
  logDeny(c, 'edge.deny.binding', reason);
  return c.json({ error: 'Agent binding check failed', reason }, 403);
}

// The query parameters the Exchange's URL signer appends — a reserved
// namespace. Exactly these are stripped before EVERY forward to the origin;
// everything else in the query belongs to the site and passes through
// untouched. Stripping on the unsigned path too is deliberate: legitimate
// traffic never delivers these names to the origin (the signed path strips
// them after verification), so any occurrence there could only be
// attacker-injected — forwarding them would hand the origin spoofable
// attribution data that looks like it survived verification.
// Exported so strip tests assert against THIS list — a param added here is
// automatically covered; a hand-copied list in a test would drift.
export const SIGNATURE_PARAMS = ['exp', 'sig', 'kid', 'agent_id'] as const;

// Marks the "authorized, and the deployment's CDN owns the origin fetch"
// answer (the empty 200 below). A CDN-side entry — the Lambda@Edge wrapper —
// needs to tell that answer apart from a real generated response so it can
// hand the request back to the CDN instead of serving the empty body; the
// status and body alone are ambiguous (/rsl.txt with no RSL_BODY configured
// is also an empty 200). Only the no-target branch of passToOrigin may emit
// it: the entries with an origin mode never reach that branch, so on those
// runtimes the header simply never appears.
export const CDN_AUTHORIZED_HEADER = 'x-edge-authorized';

// resolveOrigin picks where a pass-through request goes: an explicit origin
// (keeping path + query), the incoming URL itself (same-zone mode, where
// Cloudflare routes the subrequest to the zone's origin), or nowhere — an
// absent target means the deployment's CDN owns the origin fetch (CloudFront-
// native) and the worker answers an empty 200.
//
// It also names the branch it took. The delivery record reports which branch
// served the request, and deriving that name anywhere else would be a second
// copy of this decision that could disagree with the routing it describes.
function resolveOrigin(
  rawUrl: string,
  deps: AppDeps,
): { target?: URL; outcome: 'origin-forwarded' | 'same-zone' | 'cdn-origin-fetch' } {
  const incoming = new URL(rawUrl);
  let target: URL;
  let outcome: 'origin-forwarded' | 'same-zone';
  if (deps.originUrl) {
    target = new URL(deps.originUrl);
    target.pathname = incoming.pathname;
    target.search = incoming.search;
    outcome = 'origin-forwarded';
  } else if (deps.sameZoneOrigin) {
    target = incoming;
    outcome = 'same-zone';
  } else {
    return { outcome: 'cdn-origin-fetch' };
  }
  for (const p of SIGNATURE_PARAMS) target.searchParams.delete(p);
  return { target, outcome };
}

async function passToOrigin(
  c: Context<{ Variables: AppVariables }>,
  deps: AppDeps,
  delivery?: DeliveryFacts,
): Promise<Response> {
  const { target, outcome } = resolveOrigin(c.req.url, deps);
  if (!target) {
    if (delivery) await logDelivery(c, delivery, outcome);
    return c.body(null, 200, { [CDN_AUTHORIZED_HEADER]: 'cdn-origin-fetch' });
  }
  const fetcher = deps.fetcher ?? fetch;
  const method = c.req.method;
  const init: RequestInit & { duplex?: 'half' } = {
    method,
    headers: c.req.raw.headers,
    redirect: 'manual',
  };
  // GET/HEAD must not carry a body; every other method forwards it as-is.
  // duplex is required by the Fetch spec (and enforced by Node/undici, which
  // the Lambda@Edge target runs on) whenever the body is a stream; workerd
  // tolerates its absence, so omitting it would pass every Workers-pool test
  // while breaking the other runtimes this shared app serves.
  if (!isReadMethod(method)) {
    init.body = c.req.raw.body;
    init.duplex = 'half';
  }
  try {
    const response = await fetcher(new Request(target.toString(), init));
    // Emitted only once the origin has answered, so a delivery that failed to
    // reach the origin reports the failure below and nothing else — one
    // decision, one record. The status travels with it: this is the only call
    // site that has seen an origin response, so it is the only one that may
    // say what the origin answered.
    if (delivery) await logDelivery(c, delivery, outcome, response.status);
    return response;
  } catch (err) {
    // The origin being down or misaddressed is a gateway problem, not an
    // internal error of this worker; say so with a 502 the operator can tell
    // apart from application failures in the logs, and keep the cause — a
    // reason-less 502 is undebuggable from Workers Logs.
    logEvent(c, 'error', 'edge.origin.fetch_failed', {
      message: err instanceof Error ? err.message : String(err),
    });
    // Same {error, reason} contract as every other rejection in this file;
    // the detailed cause stays in the structured log only.
    return c.json({ error: 'Origin fetch failed', reason: 'origin_fetch_failed' }, 502);
  }
}

// Verification has an IO leg — resolveKey may fetch the Exchange's WBA key
// directory — and that leg can fail. When it does, the request cannot be
// judged: fail closed with a retryable 503 the operator can tell apart from
// both a worker bug (naked 500) and a dead origin (502), the same structured
// treatment passToOrigin gives its IO failure. The record carries the cause
// message but never the URL, which embeds attacker-influenced signature data.
function handleVerifyUnavailable(c: Context<{ Variables: AppVariables }>, err: unknown): Response {
  logEvent(c, 'error', 'edge.verify.unavailable', {
    message: err instanceof Error ? err.message : String(err),
  });
  return c.json(
    { error: 'Signature verification is temporarily unavailable', reason: 'verify_unavailable' },
    503,
  );
}

async function defaultVerify(rawUrl: string, deps: AppDeps): Promise<VerifyResult> {
  return verifyEd25519SignedUrl(rawUrl, {
    resolveKey: deps.resolveKey,
    ...(deps.now !== undefined ? { now: deps.now } : {}),
  });
}

// One denial, one record: the warn-level edge.deny.signature is the ONLY log
// a failed verification emits. It carries the kid when the verifier resolved
// one, so a key-rotation gone wrong is diagnosable — but never the full URL,
// which embeds attacker-influenced signature data.
function handleVerifyResult(
  c: Context<{ Variables: AppVariables }>,
  result: VerifyResult,
): Response {
  if (result.expired) {
    logDeny(c, 'edge.deny.signature', 'expired');
    return c.json({ error: 'Signed URL has expired', reason: 'expired' }, 403);
  }
  const reason = result.reason ?? 'unknown';
  logEvent(c, 'warn', 'edge.deny.signature', {
    reason,
    ...(result.kid !== undefined ? { kid: result.kid } : {}),
  });
  return c.json({ error: 'Invalid signature', reason }, 403);
}

function denyBot(c: Context<{ Variables: AppVariables }>, deps: AppDeps): Response {
  const reason = 'ai_bot';
  logDeny(c, 'edge.deny.bot', reason);
  const headers: Record<string, string> = {
    'X-Content-Rules': new URL(WELL_KNOWN_PATH, withProtocol(c.req.url)).toString(),
  };
  if (deps.exchangeUrl) headers['X-RAMP-Exchange'] = deps.exchangeUrl;
  // Same {error, reason} body as every other denial, with the reason token
  // matching the log record — one machine-readable vocabulary on both sides.
  return c.json(
    { error: 'Access denied. Negotiate access via the exchange.', reason },
    403,
    headers,
  );
}

function withProtocol(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
}
