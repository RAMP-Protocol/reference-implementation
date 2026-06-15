import { type App, createApp } from '../app.js';
import { buildDeps, parseEnv } from '../config.js';

interface Env {
  EXCHANGE_URL: string;
  EXCHANGE_MANIFEST_URL: string;
  RSL_BODY?: string;
  ACME_TOKENS_JSON?: string;
  RAMP_VERIFY_KEYS?: string;
}

let cachedApp: App | undefined;

function getApp(env: Env): App {
  if (cachedApp) return cachedApp;
  const deps = buildDeps(parseEnv(env as unknown as Record<string, unknown>));
  cachedApp = createApp(deps);
  return cachedApp;
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    return getApp(env).fetch(request);
  },
};
