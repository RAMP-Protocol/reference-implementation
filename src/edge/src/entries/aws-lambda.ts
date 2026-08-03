import { handle } from 'hono/lambda-edge';

import { type App, createApp } from '../app.js';
import { buildDeps, parseEnv } from '../config.js';

let cachedHandler: ReturnType<typeof handle> | undefined;

function getHandler(): ReturnType<typeof handle> {
  if (cachedHandler) return cachedHandler;
  const env = parseEnv(process.env);
  // Same-zone forwarding is Cloudflare zone routing. On Lambda@Edge the
  // incoming URL is the CloudFront distribution itself, so honoring it would
  // make the worker fetch its own distribution — a request loop. Refuse
  // loudly, like the Cloudflare entry's origin guard (the Fastly entry
  // reaches the same end differently: it never forwards the key at all).
  // ORIGIN_URL stays optional here, and this entry deliberately skips the
  // originModeConfigured guard the other two runtimes use: with neither mode
  // set, CloudFront owns the origin fetch and empty 200s are the designed
  // answer, not a misconfiguration.
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

export const handler: ReturnType<typeof handle> = (event, context, callback) =>
  getHandler()(event, context, callback);
