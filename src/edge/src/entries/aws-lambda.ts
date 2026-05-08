import { handle } from 'hono/lambda-edge';

import { type App, createApp } from '../app.js';
import { buildDeps, parseEnv } from '../config.js';

let cachedHandler: ReturnType<typeof handle> | undefined;

function getHandler(): ReturnType<typeof handle> {
  if (cachedHandler) return cachedHandler;
  const env = parseEnv(process.env as unknown as Record<string, unknown>);
  const deps = buildDeps(env);
  const app: App = createApp(deps);
  cachedHandler = handle(app);
  return cachedHandler;
}

export const handler: ReturnType<typeof handle> = (event, context, callback) =>
  getHandler()(event, context, callback);
