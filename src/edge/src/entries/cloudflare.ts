import { type App, createApp } from '../app.js';
import type { BotSignal } from '../bot-classification.js';
import { type EdgeEnv, buildDeps, originModeConfigured, parseEnv } from '../config.js';

// cfBotSignal reads Cloudflare's verified-bot data off the incoming request.
// Cloudflare exposes its bot classification to Workers as fields on
// request.cf — verifiedBotCategory carries the verified bot's type (see
// https://developers.cloudflare.com/bots/reference/bot-management-variables/);
// the category string values are listed at
// https://developers.cloudflare.com/bots/concepts/bot/verified-bots/categories/.
// The platform verifies crawlers by IP/behavior, so this outranks User-Agent
// matching in BOTH directions: a verified search crawler passes the bot gate
// even with an unusual UA, and a verified AI crawler is gated even when its
// UA is not on our deny list yet. Absent (older plans, other runtimes,
// tests) → undefined and the gate falls back to the UA pattern lists.
//
// The category strings are matched EXACTLY, and deliberately so: Cloudflare
// is merging AI search into a unified 'Search' behavior taxonomy
// (announced for 2026-07-01). Our policy splits exactly there — Googlebot
// indexes for free while AI search crawlers (e.g. OAI-SearchBot, on the deny
// list) pay — and because this signal outranks the UA lists, a loose match
// against a widened 'Search' category would silently grant AI search
// crawlers free content. If a category string stops matching, the gate falls
// back to the UA lists (safe); revisit the mapping when Cloudflare's
// migration reaches request.cf.
const CF_SEARCH_CATEGORY = 'Search Engine Crawler';
const CF_AI_CATEGORIES: readonly string[] = ['AI Assistant', 'AI Crawler', 'AI Search'];

export function cfBotSignal(req: Request): BotSignal | undefined {
  const cf = (req as Request & { cf?: { verifiedBotCategory?: string } }).cf;
  if (!cf) return undefined;
  const category = cf.verifiedBotCategory ?? '';
  return {
    verifiedSearchCrawler: category === CF_SEARCH_CATEGORY,
    verifiedAiCrawler: CF_AI_CATEGORIES.includes(category),
  };
}

// The bindings the Cloudflare runtime hands the fetch handler. Derived from
// the shared schema (config.ts EnvSchema) so the two can never drift: EdgeEnv
// is the schema's parsed shape, and Partial<> reflects that raw bindings
// arrive unvalidated — parseEnv is what decides which are actually required.
type Env = Partial<EdgeEnv>;

let cachedApp: App | undefined;

function getApp(env: Env): App {
  // Fail loud on a missing origin mode — before the cache lookup, so a
  // misconfigured deployment can never serve. Without this, every verified
  // request would get an empty 200: a deployment that looks healthy while
  // delivering no content.
  if (!originModeConfigured(env)) {
    throw new Error(
      'edge misconfigured: set ORIGIN_URL to the origin backend, or SAME_ZONE_ORIGIN="true" to forward to this zone\'s configured origin',
    );
  }
  if (cachedApp) return cachedApp;
  const deps = buildDeps(parseEnv(env));
  cachedApp = createApp({ ...deps, botSignal: cfBotSignal });
  return cachedApp;
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    return getApp(env).fetch(request);
  },
} satisfies ExportedHandler<Env>;
