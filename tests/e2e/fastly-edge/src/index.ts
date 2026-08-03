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
import { decodeBase64Url } from '@ramp-protocol/sdk-l1/base64url';
import { verifyAgentBinding } from '@ramp-protocol/sdk-l1/pop';
import { thumbprint } from '@ramp-protocol/sdk-l1/thumbprint';
import { verifyEd25519SignedUrl } from '@ramp-protocol/sdk-l1/verify';
import { createApp } from '@ramp/edge/src/app.js';
import { type KeyCache, createKeyCache } from '@ramp/edge/src/keys-cache.js';
import {
  type App,
  type AppDeps,
  buildPublisherManifest,
  buildPublisherWba,
} from '@ramp/edge/src/types.js';

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
// WBA directory fetch + @noble/ed25519 verify. Replaces the shared verify path
// for this runtime only. Strictly ed25519 / EdDSA — the verify key is read from
// the Exchange's WBA directory (/.well-known/http-message-signatures-directory)
// keys[] and resolved by RFC 7638 thumbprint (a WBA key carries no kid).
// ---------------------------------------------------------------------------

interface JwkEd25519 {
  kty?: string;
  crv?: string;
  x: string;
}

// Dependency-free WBA directory keys[] parser (the shared cache's zod schema
// lives in production's keys.ts; pulling it here would bundle zod into the
// Fastly WASM). WBA keys carry no kid.
function parseWbaKeys(json: unknown): JwkEd25519[] {
  const keys = (json as { keys?: JwkEd25519[] }).keys ?? [];
  return keys.filter((k) => k.kty === 'OKP' && k.crv === 'Ed25519' && !!k.x);
}

// mustDecodeJwkX base64url-decodes a WBA JWK's `x`, rejecting an `x` that is
// empty or not valid base64url so a malformed key surfaces a clear error instead
// of being thumbprinted / imported over garbage. Shared by both key-cache
// primitives below (wbaKeyId, decodeJwkX) so the decode + guard rule lives once.
// Mirrors production keys.ts's `keyId` rule; we mirror rather than import `keyId`
// directly because keys.ts wires the zod-validated parser this shim replaces.
function mustDecodeJwkX(jwk: JwkEd25519): Uint8Array {
  if (!jwk.x) throw new Error('wba: JWK `x` is empty');
  const raw = decodeBase64Url(jwk.x);
  if (!raw) throw new Error('wba: JWK `x` is not valid base64url');
  return raw;
}

// wbaKeyId computes a WBA key's map key — its RFC 7638 thumbprint (matched
// against the URL's `kid` param). Reuses the SDK's byte-parity-pinned thumbprint
// primitive over the guarded decode.
function wbaKeyId(jwk: JwkEd25519): Promise<string> {
  return thumbprint(mustDecodeJwkX(jwk));
}

// decodeJwkX is the key-cache import primitive: it yields the raw 32-byte public
// key through the same guarded decode. The cache awaits it, so the guard's throw
// surfaces as a rejected import exactly as before.
function decodeJwkX(jwk: JwkEd25519): Promise<Uint8Array> {
  return Promise.resolve(mustDecodeJwkX(jwk));
}

// Fastly's fetch needs an explicit backend; the WBA directory always lives on
// the exchange. The shared cache calls this with its own { headers } init.
const exchangeFetch: typeof fetch = (input, init) =>
  fetch(input, { ...init, backend: 'exchange' } as RequestInit & { backend: string });

function buildVerify(wbaUrl: string): AppDeps['verify'] {
  // Reuse the production fetch/cache/TTL/single-flight core (keys-cache.ts);
  // only the import primitive differs — Fastly's SubtleCrypto can't import
  // Ed25519, so keys are kept as the raw 32-byte public key for @noble/ed25519.
  const keys: KeyCache<Uint8Array> = createKeyCache<Uint8Array, JwkEd25519>({
    wbaUrl,
    keyId: wbaKeyId,
    importJwk: decodeJwkX,
    parseKeys: parseWbaKeys,
    fetcher: exchangeFetch,
  });
  // Reuse the SDK verify envelope (param parse, expiry, base64url decode, and the
  // missing_sig/missing_exp/expired/bad_sig_encoding/signature_mismatch reason
  // mapping) instead of re-hand-rolling it: this runtime only needs to swap the
  // Ed25519 primitive. verifyEd25519SignedUrl is made generic over the resolved-key
  // type (K = Uint8Array here, the raw 32-byte public key the WBA key-cache yields,
  // since Fastly's SubtleCrypto cannot import Ed25519) and takes the primitive as an
  // injected `verify` fn — here @noble/ed25519, which runs on any modern JS runtime.
  // The reason strings the SDK emits are the canonical VerifyFailure members the
  // app's 403 body carries verbatim, so this runtime speaks the same vocabulary as
  // the SDK verifier the other runtimes use (a key-cache miss maps to
  // signature_mismatch inside the SDK envelope, the same as before).
  return (rawUrl: string) =>
    verifyEd25519SignedUrl<Uint8Array>(rawUrl, {
      resolveKey: (kid) => keys.resolve(kid),
      // @noble/ed25519 takes (sig, message, publicKey); the injectable contract is
      // (key, message, sig).
      verify: (key, message, sig) => ed.verifyAsync(sig, message, key),
    });
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
  const wbaUrl = requireEnv('EXCHANGE_WBA_URL');
  const originUrl = requireEnv('ORIGIN_URL');
  const provider = requireEnv('PROVIDER');
  const rawExchanges: RawExchange[] = JSON.parse(requireEnv('EXCHANGES_JSON'));
  // Authorized third-party catalog pushers (optional). Consumed by the
  // Exchange's contributor-authorization gate.
  const rawContributors = readEnv('CATALOG_CONTRIBUTORS_JSON');
  const catalogContributors = rawContributors ? JSON.parse(rawContributors) : undefined;

  // This publisher's self-publish signing key(s), served in the WBA directory's
  // keys[] (no kid) so the Exchange learns them via the well-known fetch (Gate-1
  // self-signup) instead of a DB pre-seed. Optional — omitted when no
  // key is provisioned (no WBA directory is then served).
  const rawWbaKeys = readEnv('WBA_KEYS_JSON');
  const wbaKeys = rawWbaKeys ? JSON.parse(rawWbaKeys) : undefined;
  const wbaRevocationUrl = readEnv('WBA_REVOCATION_URL') || undefined;

  // Shared with production (src/edge/src/types.ts) so the shim cannot drift.
  const manifest = buildPublisherManifest(provider, rawExchanges, catalogContributors);
  const wba = wbaKeys ? buildPublisherWba(wbaKeys, wbaRevocationUrl) : undefined;

  const fastlyFetcher: typeof fetch = (input, init) => {
    const url = typeof input === 'string' ? input : input.url;
    const backend = url.startsWith(exchangeUrl) ? 'exchange' : 'publisher';
    return fetch(input, { ...init, backend } as RequestInit & { backend: string });
  };

  const deps: AppDeps = {
    manifest,
    exchangeUrl,
    resolveKey: async () => undefined, // unused: deps.verify overrides
    verify: buildVerify(wbaUrl),
    // Same default as production config.ts: enforce unless explicitly opted down.
    enforceBinding: readEnv('RAMP_ENFORCE_BINDING') !== 'false',
    // The proof-of-possession check needs the SAME Ed25519 substitution the
    // signed-URL check does. Without this the app falls back to the SDK's
    // WebCrypto default, whose importKey('Ed25519') throws NotSupportedError on
    // this runtime and is caught into `false` — so every bound fetch would 403
    // pop_sig_invalid, indistinguishable from a genuine refusal.
    //
    // Mind the argument order: the SDK's primitive is (publicKey, signature,
    // message), which is NOT the (key, message, sig) contract the signed-URL
    // injectable above uses. Swapping them fails silently, as the same 403.
    verifyBinding: (input) =>
      verifyAgentBinding({
        ...input,
        verifyEd25519: (publicKey, signature, message) =>
          ed.verifyAsync(signature, message, publicKey),
      }),
    originUrl,
    fetcher: fastlyFetcher,
    rslBody: readEnv('RSL_BODY'),
    ...(wba !== undefined ? { wba } : {}),
  };

  cachedApp = createApp(deps);
  return cachedApp;
}

addEventListener('fetch', (event) => {
  event.respondWith(getApp().fetch(event.request));
});
