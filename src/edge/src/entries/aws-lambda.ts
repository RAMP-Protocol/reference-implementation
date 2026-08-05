import { handle } from 'hono/lambda-edge';
import type { Callback, CloudFrontEdgeEvent, CloudFrontRequest } from 'hono/lambda-edge';

import { type App, CDN_AUTHORIZED_HEADER, SIGNATURE_PARAMS, createApp } from '../app.js';
import { buildDeps, parseEnv } from '../config.js';

type HonoHandler = ReturnType<typeof handle>;
type CloudFrontResult = Awaited<ReturnType<HonoHandler>>;

let cachedHandler: HonoHandler | undefined;

function getHandler(): HonoHandler {
  if (cachedHandler) return cachedHandler;
  const env = parseEnv(process.env);
  // Same-zone forwarding is Cloudflare zone routing. On Lambda@Edge the
  // incoming URL is the CloudFront distribution itself, so honoring it would
  // make the worker fetch its own distribution — a request loop. Refuse
  // loudly, like the Cloudflare entry's origin guard (the Fastly entry
  // reaches the same end differently: it never forwards the key at all).
  // ORIGIN_URL stays optional here, and this entry deliberately skips the
  // originModeConfigured guard the other two runtimes use: with neither mode
  // set, CloudFront owns the origin fetch — the app answers the authorized
  // marker and this entry hands the request back to CloudFront below.
  if (env.SAME_ZONE_ORIGIN === 'true') {
    throw new Error(
      'edge misconfigured: SAME_ZONE_ORIGIN is Cloudflare-only and would loop on CloudFront; unset it (set ORIGIN_URL if this function must proxy an explicit backend)',
    );
  }
  const deps = buildDeps(env);
  const app: App = createApp(deps);
  cachedHandler = handle(app);
  return cachedHandler;
}

// The app must never complete the Lambda invocation through the callback —
// this entry decides via its async return value alone, so the callback the
// adapter exposes to routes is a no-op.
const noopCallback: Callback = () => undefined;

// Turns the app's "authorized, the CDN owns the origin fetch" answer into an
// actual CloudFront continuation: return the original request (instead of a
// generated response) and CloudFront fetches the distribution's configured
// origin. The reserved signature params are stripped first, so the origin
// never sees the spoofable attribution namespace and the cache key stays
// clean. Every other response — denials, well-known routes — returns to the
// viewer as the generated response it is. At viewer-request a generated
// response is capped at ~40 KB, which is exactly why content bodies take the
// pass-through path and never transit this function.
function passThroughOrRespond(
  event: CloudFrontEdgeEvent,
  result: CloudFrontResult,
): CloudFrontResult | CloudFrontRequest {
  if (result.headers?.[CDN_AUTHORIZED_HEADER] === undefined) return result;
  const request = event.Records[0]?.cf.request;
  if (!request) return result;
  const params = new URLSearchParams(request.querystring);
  for (const p of SIGNATURE_PARAMS) params.delete(p);
  request.querystring = params.toString();
  return request;
}

// getHandler() runs OUTSIDE the promise chain on purpose: a misconfigured
// environment throws synchronously on the first invocation, the same contract
// the entry always had.
export const handler = (
  event: CloudFrontEdgeEvent,
): Promise<CloudFrontResult | CloudFrontRequest> =>
  getHandler()(event, {}, noopCallback).then((result) => passThroughOrRespond(event, result));
