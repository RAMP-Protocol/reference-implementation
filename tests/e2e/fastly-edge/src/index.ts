// Fastly Compute entry for the RAMP edge verifier.
//
// Fastly's js-compute SubtleCrypto does NOT support Ed25519 natively, so the
// shared edge app's default verify path (crypto.subtle.verify('Ed25519', …))
// fails with NotSupportedError. We override `deps.verify` with a @noble/ed25519
// implementation that runs identically on any modern JS runtime.
//
// The rest of the stack (origin proxy, ramp.json, bot-redirect, ACME, etc.)
// is the runtime-agnostic Hono app from @ramp/edge.

/// <reference types="@fastly/js-compute" />

import { ConfigStore } from 'fastly:config-store';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { createApp } from '@ramp/edge/src/app.js';
import { type KeyCache, createKeyCache } from '@ramp/edge/src/keys-cache.js';
import { type App, type AppDeps, buildPublisherManifest } from '@ramp/edge/src/types.js';
import type { VerifyResult } from '@ramp/edge/src/verify.js';

// @noble/ed25519 v2 async path uses WebCrypto subtle.digest; also expose a
// sync sha512 so the sync verify code paths work on runtimes that lack
// crypto.subtle.digest (Fastly Compute's SubtleCrypto doesn't support Ed25519
// but does support SHA-512; this fallback keeps us portable either way).
(ed.etc as unknown as { sha512Sync: (...msgs: Uint8Array[]) => Uint8Array }).sha512Sync = (
  ...msgs
) => sha512(ed.etc.concatBytes(...msgs));

let store: ConfigStore | undefined;
const getStore = () => {
  if (!store) store = new ConfigStore('ramp_edge');
  return store;
};

const readEnv = (name: string, fallback = '') => getStore().get(name) || fallback;
const requireEnv = (name: string) => {
  const v = getStore().get(name);
  if (!v) throw new Error(`missing env ${name}`);
  return v;
};

// ---------------------------------------------------------------------------
// Manifest public_keys fetch + @noble/ed25519 verify. Replaces the shared
// verify path for this runtime only. Strictly ed25519 / EdDSA — the verify key
// is read from the Exchange's unified /.well-known/ramp.json public_keys[].
// ---------------------------------------------------------------------------

interface JwkEd25519 {
  kid: string;
  kty?: string;
  crv?: string;
  x: string;
}

function b64urlDecode(input: string): Uint8Array {
  const pad = input.length % 4 === 0 ? '' : '='.repeat(4 - (input.length % 4));
  const b64 = input.replaceAll('-', '+').replaceAll('_', '/') + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

// Dependency-free public_keys[] parser (the shared cache's zod schema lives in
// production's keys.ts; pulling it here would bundle zod into the Fastly WASM).
function parsePublicKeys(json: unknown): JwkEd25519[] {
  const keys = (json as { public_keys?: JwkEd25519[] }).public_keys ?? [];
  return keys.filter((k) => k.kty === 'OKP' && k.crv === 'Ed25519' && !!k.kid && !!k.x);
}

// Fastly's fetch needs an explicit backend; the manifest always lives on the
// exchange. The shared cache calls this with its own { headers } init.
const exchangeFetch: typeof fetch = (input, init) =>
  fetch(input, { ...init, backend: 'exchange' } as RequestInit & { backend: string });

function canonicalBytes(rawUrl: string): Uint8Array {
  const url = new URL(rawUrl);
  url.searchParams.delete('sig');
  return new TextEncoder().encode(`GET\n${url.toString()}`);
}

function buildVerify(manifestUrl: string): AppDeps['verify'] {
  // Reuse the production fetch/cache/TTL/single-flight core (keys-cache.ts);
  // only the import primitive differs — Fastly's SubtleCrypto can't import
  // Ed25519, so keys are kept as the raw 32-byte public key for @noble/ed25519.
  const keys: KeyCache<Uint8Array> = createKeyCache<Uint8Array, JwkEd25519>({
    manifestUrl,
    importJwk: (jwk) => Promise.resolve(b64urlDecode(jwk.x)),
    parseKeys: parsePublicKeys,
    fetcher: exchangeFetch,
  });
  return async (rawUrl: string): Promise<VerifyResult> => {
    const url = new URL(rawUrl);
    const sigB64 = url.searchParams.get('sig');
    const expStr = url.searchParams.get('exp');
    const kid = url.searchParams.get('kid') ?? undefined;
    if (!sigB64 || !expStr) {
      return { valid: false, expired: false, reason: 'missing-params' };
    }
    const nowSec = Math.floor(Date.now() / 1000);
    if (nowSec >= Number(expStr)) {
      return { valid: false, expired: true, reason: 'expired' };
    }
    const pub = await keys.resolve(kid);
    if (!pub) return { valid: false, expired: false, reason: 'kid-unknown' };
    let sig: Uint8Array;
    try {
      sig = b64urlDecode(sigB64);
    } catch {
      return { valid: false, expired: false, reason: 'sig-decode' };
    }
    const ok = await ed.verifyAsync(sig, canonicalBytes(rawUrl), pub);
    return ok
      ? { valid: true, expired: false, kid }
      : { valid: false, expired: false, reason: 'signature_mismatch' };
  };
}

// ---------------------------------------------------------------------------
// App wiring — lazy, so Wizer's build-time module init doesn't read env.
// ---------------------------------------------------------------------------

interface RawExchange {
  domain: string;
  endpoint: string;
  supported_profiles?: string[];
}

let cachedApp: App | undefined;

function getApp(): App {
  if (cachedApp) return cachedApp;

  const exchangeUrl = requireEnv('EXCHANGE_URL');
  const manifestUrl = requireEnv('EXCHANGE_MANIFEST_URL');
  const originUrl = requireEnv('ORIGIN_URL');
  const provider = requireEnv('PROVIDER');
  const rawExchanges: RawExchange[] = JSON.parse(requireEnv('EXCHANGES_JSON'));
  // Authorized third-party catalog pushers (optional). Consumed by the
  // Exchange's contributor-authorization gate.
  const rawContributors = readEnv('CATALOG_CONTRIBUTORS_JSON');
  const catalogContributors = rawContributors ? JSON.parse(rawContributors) : undefined;

  // Shared with production (src/edge/src/types.ts) so the shim cannot drift.
  const manifest = buildPublisherManifest(provider, rawExchanges, catalogContributors);

  const fastlyFetcher: typeof fetch = (input, init) => {
    const url = typeof input === 'string' ? input : input.url;
    const backend = url.startsWith(exchangeUrl) ? 'exchange' : 'publisher';
    return fetch(input, { ...init, backend } as RequestInit & { backend: string });
  };

  const deps: AppDeps = {
    manifest,
    exchangeUrl,
    resolveKey: async () => undefined, // unused: deps.verify overrides
    verify: buildVerify(manifestUrl),
    originUrl,
    fetcher: fastlyFetcher,
    rslBody: readEnv('RSL_BODY'),
  };

  cachedApp = createApp(deps);
  return cachedApp;
}

addEventListener('fetch', (event) => {
  event.respondWith(getApp().fetch(event.request));
});
