import { type App, createApp } from '../app.js';
import { buildDeps, parseEnv } from '../config.js';

interface FastlyLike {
  addEventListener(
    type: 'fetch',
    listener: (event: { request: Request; respondWith(p: Promise<Response>): void }) => void,
  ): void;
}

declare const addEventListener: FastlyLike['addEventListener'];

let cachedApp: App | undefined;

function getApp(): App {
  if (cachedApp) return cachedApp;
  const env = parseEnv({
    EXCHANGE_URL: fastlyEnv('EXCHANGE_URL'),
    EXCHANGE_MANIFEST_URL: fastlyEnv('EXCHANGE_MANIFEST_URL'),
    RSL_BODY: fastlyEnv('RSL_BODY'),
    ACME_TOKENS_JSON: fastlyEnv('ACME_TOKENS_JSON'),
    RAMP_VERIFY_KEYS: fastlyEnv('RAMP_VERIFY_KEYS'),
    PROVIDER: fastlyEnv('PROVIDER'),
    EXCHANGES_JSON: fastlyEnv('EXCHANGES_JSON'),
    CATALOG_CONTRIBUTORS_JSON: fastlyEnv('CATALOG_CONTRIBUTORS_JSON'),
    ORIGIN_URL: fastlyEnv('ORIGIN_URL'),
  });
  cachedApp = createApp(buildDeps(env));
  return cachedApp;
}

function fastlyEnv(name: string): string | undefined {
  type EnvReader = { getEnv(n: string): string };
  const mod = (globalThis as unknown as { fastly?: EnvReader }).fastly;
  if (!mod) return undefined;
  const value = mod.getEnv(name);
  return value === '' ? undefined : value;
}

addEventListener('fetch', (event) => {
  event.respondWith(Promise.resolve(getApp().fetch(event.request)));
});
