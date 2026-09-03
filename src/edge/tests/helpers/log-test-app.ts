// Shared app factory for the node-pool console-spy suites (verify-log,
// decision-log). Both drive the real app surface with a hand-wired resolveKey
// and observe only console records; this is the one place their AppDeps shape
// lives, so the two suites cannot drift apart.
import { vi } from 'vitest';

import { type App, createApp } from '../../src/app.js';
import type { AppDeps } from '../../src/types.js';
import type { TestKeypair } from './ed25519.js';

// The minimal shape of a vitest console spy this helper needs — structural,
// so the suites can pass vi.spyOn(console, ...) without importing vitest
// generics here.
interface SpyLike {
  mock: { calls: unknown[][] };
}

// recordsFor pulls the structured payloads of the console records whose event
// name matches — the one observation helper both console-spy suites share, so
// "find the record for event X" cannot drift between them.
//
// The payload argument is a JSON string, not an object: the worker serializes
// it so every runtime writes the same bytes to its log. Parsing here means the
// suites keep asserting against a plain object, and a payload that stopped
// being valid JSON — the one defect this shape exists to prevent — fails the
// tests rather than passing them.
export function recordsFor(spy: SpyLike, event: string): unknown[] {
  return spy.mock.calls
    .filter((call) => call[0] === event)
    .map((call) => JSON.parse(call[1] as string));
}

// spyOnDenyLogs installs spies on BOTH console levels a decision may touch.
// The "one decision, one record" contract has two halves: the expected warn
// record exists, AND no error-level record accompanied it. A suite that spies
// only console.warn silently accepts a stray console.error — so denial tests
// take both spies from here and assert errorSpy was never called.
export function spyOnDenyLogs() {
  return {
    warnSpy: vi.spyOn(console, 'warn').mockImplementation(() => {}),
    errorSpy: vi.spyOn(console, 'error').mockImplementation(() => {}),
  };
}

// spyOnAllLogs installs spies on every level a decision may touch. The
// delivery suite needs all three: it asserts the info record exists on an
// authorized delivery AND that no record of any level accompanies it, and that
// a denial emits no info record — neither half is checkable with one spy.
export function spyOnAllLogs() {
  return {
    infoSpy: vi.spyOn(console, 'info').mockImplementation(() => {}),
    warnSpy: vi.spyOn(console, 'warn').mockImplementation(() => {}),
    errorSpy: vi.spyOn(console, 'error').mockImplementation(() => {}),
  };
}

export function makeLogTestApp(
  keypair: TestKeypair,
  exchangeKid: string,
  overrides: Partial<AppDeps> = {},
): App {
  const deps: AppDeps = {
    manifest: {
      ver: '1.0',
      role: 'ROLE_PUBLISHER',
      domain: 'pub.example.com',
      exchanges: [
        {
          domain: 'exchange.test',
          endpoint: 'https://exchange.test',
          relationship: 'PROVIDER_RELATIONSHIP_DIRECT',
        },
      ],
      supported_profiles: ['ramp-news-v1'],
    },
    exchangeUrl: 'https://exchange.test',
    resolveKey: async (kid) => (kid === exchangeKid ? keypair.publicKey : undefined),
    enforceBinding: true,
    ...overrides,
  };
  return createApp(deps);
}
