// The bot gate's decision logic: who is a human, who is a search crawler
// (reads for free — the publisher wants indexing), and who is an AI bot
// (sent to negotiate paid access). Pure logic, no runtime dependencies; the
// per-runtime verified-bot signal is injected by the entry (see BotSignal).

export const BOT_UA_PATTERNS: readonly RegExp[] = Object.freeze([
  /bot\b/i,
  /crawler/i,
  /spider/i,
  /GPTBot/i,
  /ClaudeBot/i,
  /anthropic-ai/i,
  /OAI-SearchBot/i,
  /CCBot/i,
  /PerplexityBot/i,
  /Bytespider/i,
  /Google-Extended/i,
  /Meta-ExternalAgent/i,
  // User-initiated assistant fetchers. A human asked for the page, which
  // makes these a distinct class from the autonomous crawlers above — but the
  // publisher stance is the same: AI access to paid content is licensed,
  // regardless of who initiated the fetch. The identifying tokens carry no
  // "bot" marker, so without a dedicated pattern classification depends on
  // incidental text elsewhere in the UA: ChatGPT-User's documented full UA
  // ends in a "+https://openai.com/bot" URL that /bot\b/ catches, and
  // Meta-ExternalFetcher's ends in a "…/webmasters/crawler" docs URL that
  // /crawler/i catches — but the bare forms, which plain clients send, fall
  // through to 'human', and a direct assistant fetch then reads paid content
  // free, bypassing the purchase flow. The dedicated entries close that.
  /Claude-User/i,
  /ChatGPT-User/i,
  /Perplexity-User/i,
  /Meta-ExternalFetcher/i,
]);

// Search-engine crawlers read for free: the publisher wants indexing (and the
// search traffic it brings), while AI crawlers buy access. This mirrors the
// split already present in the deny list, which names Google-Extended (the AI
// opt-out token) separately from Google's search crawler. Applebot's AI
// sibling is excluded by the lookahead: Applebot-Extended stays a bot.
//
// ADVISORY, not a security boundary: the User-Agent is caller-chosen, so a
// scraper claiming "Googlebot" passes free — exactly as it always could by
// claiming a browser UA. The gate keeps honest bots out; licensed access is
// enforced only by signed URLs. Nothing security-sensitive may ever key off
// the 'search_crawler' label (the platform-verified BotSignal is the
// trustworthy input, and it only ever promotes, never demotes).
export const SEARCH_CRAWLER_ALLOW_PATTERNS: readonly RegExp[] = Object.freeze([
  /Googlebot/i,
  /bingbot/i,
  /DuckDuckBot/i,
  /Applebot(?!-Extended)/i,
  /YandexBot/i,
]);

export type ClientClass = 'human' | 'search_crawler' | 'ai_bot';

// Platform-provided caller verification, injected per runtime (the Cloudflare
// entry reads the request's cf verified-bot data; other runtimes pass
// nothing). The platform signal is trusted over User-Agent matching — the UA
// string is caller-controlled, the platform verification (by IP/behavior) is
// not. Two directions:
//   * verifiedSearchCrawler PROMOTES to free pass-through (indexing wanted);
//   * verifiedAiCrawler DEMOTES to the paid gate, so a brand-new AI crawler
//     the platform already verified is gated before our deny list learns its
//     UA — the signal reduces how much pattern-list freshness matters.
// When both are somehow set, search wins: wrongly charging an indexer hurts
// the publisher more than wrongly indexing a payer.
export interface BotSignal {
  verifiedSearchCrawler?: boolean;
  verifiedAiCrawler?: boolean;
}

// Upper bound on the User-Agent slice the patterns run against. Real UAs stay
// well under this; the cap keeps regex time bounded when a caller sends a
// garbage-length UA against operator-supplied patterns (BOT_UA_*_JSON). A
// marker pushed past the bound is simply not seen, which gives an attacker
// nothing — dodging 'ai_bot' was always possible with a plain browser UA.
const MAX_UA_MATCH_LENGTH = 512;

// classifyClient decides the caller's class for the unsigned-request gate.
// Order matters: the platform signal outranks UA patterns, the allow list
// outranks the deny list (so Googlebot survives the generic /bot\b/ pattern),
// and an absent User-Agent is a bot — honest browsers always send one.
export function classifyClient(
  userAgent: string | undefined | null,
  signal?: BotSignal,
  allow: readonly RegExp[] = SEARCH_CRAWLER_ALLOW_PATTERNS,
  deny: readonly RegExp[] = BOT_UA_PATTERNS,
): ClientClass {
  if (signal?.verifiedSearchCrawler) return 'search_crawler';
  if (signal?.verifiedAiCrawler) return 'ai_bot';
  if (!userAgent) return 'ai_bot';
  const ua = userAgent.slice(0, MAX_UA_MATCH_LENGTH);
  if (allow.some((re) => re.test(ua))) return 'search_crawler';
  if (deny.some((re) => re.test(ua))) return 'ai_bot';
  return 'human';
}
