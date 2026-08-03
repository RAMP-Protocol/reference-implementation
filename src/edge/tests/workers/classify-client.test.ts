// Unit tests for the pure client-classification logic (permitted as a unit
// surface: pure logic with more than three branches). The policy under test:
// search crawlers read for free (the publisher wants indexing), AI crawlers
// must buy access, humans pass, and an absent User-Agent on a content read is
// treated as a bot.
import { describe, expect, it } from 'vitest';

import { createApp } from '../../src/app.js';
import { classifyClient } from '../../src/bot-classification.js';
import { cfBotSignal } from '../../src/entries/cloudflare.js';
import type { AppDeps } from '../../src/types.js';

describe('classifyClient', () => {
  it.each([
    ['Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', 'search_crawler'],
    ['Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)', 'search_crawler'],
    ['DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)', 'search_crawler'],
    ['Mozilla/5.0 (compatible; YandexBot/3.0)', 'search_crawler'],
    ['Mozilla/5.0 (compatible; Applebot/0.1; +http://www.apple.com/go/applebot)', 'search_crawler'],
  ])('classifies %s as a search crawler', (ua, expected) => {
    expect(classifyClient(ua)).toBe(expected);
  });

  it.each([
    ['GPTBot/1.0', 'ai_bot'],
    ['Mozilla/5.0 (compatible; ClaudeBot/1.0)', 'ai_bot'],
    ['Mozilla/5.0 (compatible; Google-Extended)', 'ai_bot'],
    ['Applebot-Extended/0.1', 'ai_bot'],
    ['PerplexityBot/1.0', 'ai_bot'],
    ['unknown-crawler spider v2', 'ai_bot'],
  ])('classifies %s as an AI bot', (ua, expected) => {
    expect(classifyClient(ua)).toBe(expected);
  });

  it('classifies a normal browser as human', () => {
    const ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15';
    expect(classifyClient(ua)).toBe('human');
  });

  it('treats a missing user-agent as an AI bot', () => {
    expect(classifyClient(undefined)).toBe('ai_bot');
    expect(classifyClient(null)).toBe('ai_bot');
    expect(classifyClient('')).toBe('ai_bot');
  });

  it('a verified-search platform signal wins over an unknown UA', () => {
    expect(classifyClient('StrangeFetcher/9', { verifiedSearchCrawler: true })).toBe(
      'search_crawler',
    );
  });

  it('a verified-search signal wins even when the UA is on the deny list', () => {
    // The UA must match the DENY list only ('unknown-crawler spider v2' is
    // classified ai_bot without a signal — see the it.each above). A UA that
    // also matches the allow list (e.g. anything containing 'Googlebot')
    // would pass without the signal, and the assertion would prove nothing
    // about the signal's precedence over the deny list.
    expect(classifyClient('unknown-crawler spider v2', { verifiedSearchCrawler: true })).toBe(
      'search_crawler',
    );
  });

  it('reads the verified-search signal from Cloudflare cf data', () => {
    const asReq = (cf: unknown) => ({ cf }) as unknown as Request;
    expect(cfBotSignal(asReq({ verifiedBotCategory: 'Search Engine Crawler' }))).toEqual({
      verifiedSearchCrawler: true,
      verifiedAiCrawler: false,
    });
    expect(cfBotSignal(new Request('https://pub.example.com/'))).toBeUndefined();
  });

  it.each(['AI Assistant', 'AI Crawler', 'AI Search'])(
    'maps the verified %s category to an AI-crawler signal',
    (category) => {
      const req = { cf: { verifiedBotCategory: category } } as unknown as Request;
      expect(cfBotSignal(req)).toEqual({
        verifiedSearchCrawler: false,
        verifiedAiCrawler: true,
      });
    },
  );

  it('leaves both signals off for unrelated verified categories', () => {
    const req = { cf: { verifiedBotCategory: 'Aggregator' } } as unknown as Request;
    expect(cfBotSignal(req)).toEqual({
      verifiedSearchCrawler: false,
      verifiedAiCrawler: false,
    });
  });

  it("does not promote the announced unified 'Search' category", () => {
    // Pins the exact-match boundary the entry comment warns about: Cloudflare
    // is merging AI search into a unified 'Search' taxonomy, and because this
    // signal outranks the UA lists, a loosened comparator (prefix or substring
    // match) would silently grant AI search crawlers free content. 'Search'
    // must fall through to the UA lists, promoting nothing.
    const req = { cf: { verifiedBotCategory: 'Search' } } as unknown as Request;
    expect(cfBotSignal(req)).toEqual({
      verifiedSearchCrawler: false,
      verifiedAiCrawler: false,
    });
  });

  it('a verified AI crawler is denied even behind a browser-like UA', () => {
    // Demotion on platform-verified identity: the UA is caller-chosen, the
    // cf verification is not — so a brand-new AI crawler Cloudflare already
    // verified is gated even before our deny list learns its UA.
    const browserUa = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/605.1.15';
    expect(classifyClient(browserUa, { verifiedAiCrawler: true })).toBe('ai_bot');
  });

  it('the search signal outranks the AI signal', () => {
    expect(
      classifyClient('anything', { verifiedSearchCrawler: true, verifiedAiCrawler: true }),
    ).toBe('search_crawler');
  });

  it('matches only the first 512 chars — an oversized UA cannot drive regex cost', () => {
    // A marker planted beyond the bound is not seen: the caller gains nothing
    // (an attacker avoiding 'ai_bot' could always just send a browser UA),
    // while regex time stays bounded on garbage-length inputs.
    const beyond = `Mozilla/5.0 ${'x'.repeat(600)} GPTBot/1.0`;
    expect(classifyClient(beyond)).toBe('human');
    const within = `${'x'.repeat(100)} GPTBot/1.0`;
    expect(classifyClient(within)).toBe('ai_bot');
  });

  it('honors custom allow and deny pattern overrides', () => {
    const allow = [/FriendlyIndexer/i];
    const deny = [/EvilScraper/i];
    expect(classifyClient('FriendlyIndexer/1.0', undefined, allow, deny)).toBe('search_crawler');
    expect(classifyClient('EvilScraper/1.0', undefined, allow, deny)).toBe('ai_bot');
    // With overrides in place the defaults no longer apply.
    expect(classifyClient('GPTBot/1.0', undefined, allow, deny)).toBe('human');
  });
});

describe('bot signal at the app surface', () => {
  it('403s a verified AI crawler even when it presents a browser UA', async () => {
    const app = createApp({
      manifest: { ver: '1.0', role: 'ROLE_PUBLISHER', domain: 'pub.test' } as AppDeps['manifest'],
      resolveKey: async () => undefined,
      sameZoneOrigin: true,
      botSignal: () => ({ verifiedAiCrawler: true }),
      fetcher: (async () => new Response('must not be served')) as unknown as typeof fetch,
    });
    const res = await app.request('https://pub.example.com/artikel', {
      headers: { 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/605.1.15' },
    });
    expect(res.status).toBe(403);
    expect(res.headers.get('x-content-rules')).toContain('/.well-known/ramp.json');
  });
});
