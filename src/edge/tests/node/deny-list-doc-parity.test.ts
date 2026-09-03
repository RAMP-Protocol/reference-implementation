// Doc-parity guard for the built-in bot pattern lists.
//
// The built-in allow and deny lists are enumerated in two places: the code
// arrays in src/bot-classification.ts and the operator-facing code fences in
// CONFIGURATION.md §3.3 (the single documentation home — README.md and the
// design docs link there instead of restating the names). Nothing else checks
// that the copies agree, and this drift class already produced a real bug:
// the design doc listed a fetcher token the code did not match.
// This guard reads the §3.3 fences from disk and compares them, token by
// token and in order, against the exported arrays. It fails the moment either
// side changes without the other.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { BOT_UA_PATTERNS, SEARCH_CRAWLER_ALLOW_PATTERNS } from '../../src/bot-classification.js';

const edgeDir = fileURLToPath(String(new URL('../..', import.meta.url)));

// The §3.3 slice of CONFIGURATION.md: from its heading to the next heading.
function section33(): string {
  const doc = readFileSync(`${edgeDir}/CONFIGURATION.md`, 'utf-8');
  const start = doc.indexOf('### 3.3');
  const end = doc.indexOf('### 3.4');
  expect(start, 'CONFIGURATION.md no longer has a §3.3 heading').toBeGreaterThan(-1);
  expect(end, 'CONFIGURATION.md no longer has a §3.4 heading').toBeGreaterThan(start);
  return doc.slice(start, end);
}

// §3.3 documents each list as a whitespace-separated code fence of regex
// sources. The first fence is the allow list, the second the deny list.
function fenceTokens(section: string): string[][] {
  const fences = [...section.matchAll(/```\n([^`]*?)```/g)].map((m) =>
    (m[1] ?? '').split(/\s+/).filter((t) => t.length > 0),
  );
  expect(
    fences,
    '§3.3 must contain exactly two code fences: the allow list, then the deny list',
  ).toHaveLength(2);
  return fences;
}

describe('CONFIGURATION.md §3.3 parity with the code pattern lists', () => {
  const [allowFence, denyFence] = fenceTokens(section33());

  it('the allow-list fence matches SEARCH_CRAWLER_ALLOW_PATTERNS, in order', () => {
    expect(allowFence).toEqual(SEARCH_CRAWLER_ALLOW_PATTERNS.map((re) => re.source));
  });

  it('the deny-list fence matches BOT_UA_PATTERNS, in order', () => {
    expect(denyFence).toEqual(BOT_UA_PATTERNS.map((re) => re.source));
  });
});
