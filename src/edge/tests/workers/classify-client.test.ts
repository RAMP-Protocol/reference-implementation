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
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    'DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)',
    'Mozilla/5.0 (compatible; YandexBot/3.0)',
    'Mozilla/5.0 (compatible; Applebot/0.1; +http://www.apple.com/go/applebot)',
  ])('classifies %s as a search crawler', (ua) => {
    expect(classifyClient(ua)).toBe('search_crawler');
  });

  it.each([
    'GPTBot/1.0',
    'Mozilla/5.0 (compatible; ClaudeBot/1.0)',
    'Mozilla/5.0 (compatible; Google-Extended)',
    'Applebot-Extended/0.1',
    'PerplexityBot/1.0',
    // Bare form on purpose: Meta-ExternalAgent's documented full UA ends in a
    // "…/webmasters/crawler" docs URL that /crawler/i already matches, so the
    // full string would pass without a Meta-ExternalAgent pattern and prove
    // nothing. The bare form is also what a plain client sends.
    'Meta-ExternalAgent/1.1',
    'unknown-crawler spider v2',
    // User-initiated assistant fetchers: a human asked for the page, but the
    // publisher stance is the same as for autonomous crawlers — AI access to
    // paid content is licensed. None of these UAs contain the word "bot", so
    // without their own deny patterns they would fall through to 'human' and
    // read paid content free.
    'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; Claude-User/1.0; +Claude-User@anthropic.com',
    // Bare form on purpose: the full ChatGPT-User UA ends in the URL
    // "+https://openai.com/bot", which the generic /bot\b/ pattern already
    // matches, so the full string would pass without a ChatGPT-User pattern
    // and prove nothing. The bare form is also what a plain client sends.
    'ChatGPT-User/1.0',
    'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)',
    'Meta-ExternalFetcher/1.1',
  ])('classifies %s as an AI bot', (ua) => {
    expect(classifyClient(ua)).toBe('ai_bot');
  });

  it.each(['python-httpx/0.28.1', 'python-httpx/0.27.0'])('lets %s through as human', (ua) => {
    // The E2E harness drives every edge with httpx, which sends this UA. If a
    // deny pattern ever matched it — /python/i is the obvious candidate — the
    // whole harness would start getting 403s on requests that were never about
    // bots, and the failures would look like broken signing rather than a
    // classification change. Pinned so that change fails here first.
    expect(classifyClient(ua)).toBe('human');
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
