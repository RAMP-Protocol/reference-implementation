import { describe, expect, it } from 'vitest';

import { type FreeRule, matchFreeRule } from '../src/freerule.js';

const RULES: FreeRule[] = [
  {
    pathPattern: '/articles/philosophers/*',
    licenseId: 'tdl:free-index-v1',
    contentUsage: 'ai-index=y',
    contentHash: 'sha256-abc',
  },
  {
    pathPattern: '/articles/philosophers/premium/*',
    licenseId: 'tdl:premium',
    contentUsage: 'ai-index=n',
  },
];

describe('matchFreeRule', () => {
  it('matches a prefix rule and returns its license + notice', () => {
    const m = matchFreeRule('/articles/philosophers/socrates.txt', RULES);
    expect(m).toBeDefined();
    expect(m?.licenseId).toBe('tdl:free-index-v1');
    expect(m?.contentUsage).toBe('ai-index=y');
    expect(m?.contentHash).toBe('sha256-abc');
  });

  it('returns undefined when no rule matches', () => {
    expect(matchFreeRule('/blog/post-1', RULES)).toBeUndefined();
  });

  it('most-specific (longest prefix) wins', () => {
    const m = matchFreeRule('/articles/philosophers/premium/kant.txt', RULES);
    expect(m?.licenseId).toBe('tdl:premium');
  });

  it('omits contentHash when the rule has none', () => {
    const m = matchFreeRule('/articles/philosophers/premium/kant.txt', RULES);
    expect(m?.contentHash).toBeUndefined();
  });

  it('supports exact-path rules', () => {
    const exact: FreeRule[] = [
      {
        pathPattern: '/llms.txt',
        licenseId: 'tdl:free',
        contentUsage: 'ai-index=y',
      },
    ];
    expect(matchFreeRule('/llms.txt', exact)?.licenseId).toBe('tdl:free');
    expect(matchFreeRule('/llms.txt.bak', exact)).toBeUndefined();
  });
});
