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
import type {
  App,
  AppDeps,
  AuthorizedExchange,
  Manifest,
} from '@ramp/edge/src/types.js';
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
// JWKS fetch + @noble/ed25519 verify. Replaces the shared verify path for
// this runtime only. Strictly ed25519 / EdDSA — matches the Exchange's JWKS.
// ---------------------------------------------------------------------------

interface JwkEd25519 {
  kid: string;
  kty: string;
  crv: string;
  x: string;
}

let jwksCache: { expiresAt: number; keys: Map<string, Uint8Array> } | undefined;
const JWKS_TTL_MS = 60 * 60 * 1000;

function b64urlDecode(input: string): Uint8Array {
  const pad = input.length % 4 === 0 ? '' : '='.repeat(4 - (input.length % 4));
  const b64 = input.replaceAll('-', '+').replaceAll('_', '/') + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

async function loadKeys(jwksUrl: string): Promise<Map<string, Uint8Array>> {
  if (jwksCache && jwksCache.expiresAt > Date.now()) return jwksCache.keys;
  const resp = await fetch(jwksUrl, { backend: 'exchange' } as RequestInit & { backend: string });
  if (!resp.ok) throw new Error(`jwks fetch ${resp.status}`);
  const data = (await resp.json()) as { keys?: JwkEd25519[] };
  const keys = new Map<string, Uint8Array>();
  for (const k of data.keys ?? []) {
    if (k.kty === 'OKP' && k.crv === 'Ed25519' && k.kid && k.x) {
      keys.set(k.kid, b64urlDecode(k.x));
    }
  }
  jwksCache = { expiresAt: Date.now() + JWKS_TTL_MS, keys };
  return keys;
}

function canonicalBytes(rawUrl: string): Uint8Array {
  const url = new URL(rawUrl);
  url.searchParams.delete('sig');
  return new TextEncoder().encode(`GET\n${url.toString()}`);
}

function buildVerify(jwksUrl: string): AppDeps['verify'] {
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
    const keys = await loadKeys(jwksUrl);
    const pub = kid ? keys.get(kid) : keys.values().next().value;
    if (!pub) return { valid: false, expired: false, reason: 'kid-unknown' };
    let sig: Uint8Array;
    try {
      sig = b64urlDecode(sigB64);
    } catch {
      return { valid: false, expired: false, reason: 'sig-decode' };
    }
    const ok = await ed.verifyAsync(sig, canonicalBytes(rawUrl), pub);
    return ok ? { valid: true, expired: false, kid } : { valid: false, expired: false, reason: 'signature_mismatch' };
  };
}

// ---------------------------------------------------------------------------
// App wiring — lazy, so Wizer's build-time module init doesn't read env.
// ---------------------------------------------------------------------------

let cachedApp: App | undefined;

function getApp(): App {
  if (cachedApp) return cachedApp;

  const exchangeUrl = requireEnv('EXCHANGE_URL');
  const jwksUrl = requireEnv('JWKS_URL');
  const originUrl = requireEnv('ORIGIN_URL');
  const provider = requireEnv('PROVIDER');
  const exchanges: AuthorizedExchange[] = JSON.parse(requireEnv('EXCHANGES_JSON'));

  const manifest: Manifest = {
    ver: '0.3',
    provider,
    exchanges,
    exchange: exchangeUrl,
    marketplace_manifest: readEnv('MARKETPLACE_MANIFEST_URL'),
  };

  const fastlyFetcher: typeof fetch = (input, init) => {
    const url = typeof input === 'string' ? input : input.url;
    const backend = url.startsWith(exchangeUrl) ? 'exchange' : 'publisher';
    return fetch(input, { ...init, backend } as RequestInit & { backend: string });
  };

  const deps: AppDeps = {
    manifest,
    verifierManifest: {
      ver: '0.3',
      jwks_url: jwksUrl,
      signing_algorithms: ['Ed25519'],
    },
    resolveKey: async () => undefined, // unused: deps.verify overrides
    verify: buildVerify(jwksUrl),
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
