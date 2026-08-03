import { type App, createApp } from '../app.js';
import { type EdgeEnv, buildDeps, originModeConfigured, parseEnv } from '../config.js';

interface FastlyLike {
  addEventListener(
    type: 'fetch',
    listener: (event: { request: Request; respondWith(p: Promise<Response>): void }) => void,
  ): void;
}

declare const addEventListener: FastlyLike['addEventListener'];

let cachedApp: App | undefined;

// readFastlyEnv assembles the EdgeEnv from a Fastly env reader. Fastly Compute
// has no enumerable env object (unlike Cloudflare/AWS, which cast the whole env),
// so every schema key MUST be hand-forwarded here — an omission silently drops
// that signal on the Fastly runtime ONLY. Exported so the cross-runtime
// manifest-parity test can exercise this hand-enumeration directly.
export function readFastlyEnv(getEnv: (name: string) => string | undefined): EdgeEnv {
  return parseEnv({
    EXCHANGE_URL: getEnv('EXCHANGE_URL'),
    EXCHANGE_WBA_URL: getEnv('EXCHANGE_WBA_URL'),
    RSL_BODY: getEnv('RSL_BODY'),
    ACME_TOKENS_JSON: getEnv('ACME_TOKENS_JSON'),
    RAMP_VERIFY_KEYS: getEnv('RAMP_VERIFY_KEYS'),
    WBA_KEYS_JSON: getEnv('WBA_KEYS_JSON'),
    WBA_REVOCATION_URL: getEnv('WBA_REVOCATION_URL'),
    PROVIDER: getEnv('PROVIDER'),
    EXCHANGES_JSON: getEnv('EXCHANGES_JSON'),
    CATALOG_CONTRIBUTORS_JSON: getEnv('CATALOG_CONTRIBUTORS_JSON'),
    ORIGIN_URL: getEnv('ORIGIN_URL'),
    RAMP_ENFORCE_BINDING: getEnv('RAMP_ENFORCE_BINDING'),
    BOT_UA_ALLOW_JSON: getEnv('BOT_UA_ALLOW_JSON'),
    BOT_UA_DENY_JSON: getEnv('BOT_UA_DENY_JSON'),
    // SAME_ZONE_ORIGIN is deliberately NOT forwarded: same-zone forwarding is
    // a Cloudflare routing behavior this runtime cannot honor.
  });
}

function getApp(): App {
  if (cachedApp) return cachedApp;
  const env = readFastlyEnv(fastlyEnv);
  // Fail loud on a missing origin, same contract as the Cloudflare entry: a
  // proxy deployment with no backend would answer every verified request with
  // an empty 200 — healthy-looking, serving nothing. Fastly cannot use
  // SAME_ZONE_ORIGIN (not forwarded above), so this requires ORIGIN_URL.
  if (!originModeConfigured(env)) {
    throw new Error('edge misconfigured: set ORIGIN_URL to the origin backend');
  }
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

// Guarded so the module is importable off-runtime (e.g. the manifest-parity
// unit test) where the Fastly `addEventListener` global is absent. The listener
// resolves getApp() lazily, so registering it has no import-time side effects.
if (typeof addEventListener === 'function') {
  addEventListener('fetch', (event) => {
    event.respondWith(Promise.resolve(getApp().fetch(event.request)));
  });
}
