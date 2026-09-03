// Verify-agnostic key-directory cache. It fetches a producer's Web Bot Auth
// directory (/.well-known/http-message-signatures-directory), parses its keys[],
// imports each JWK into a runtime key type K, and caches a keyid→K map with a
// TTL, single-flight de-duplication, optional pre-provisioned static keys, and
// one-shot rotation self-heal.
//
// After the WBA split a key has NO kid: it is named by its RFC 7638
// thumbprint. The map is keyed by the thumbprint the caller computes via
// `keyId`, and a request's `keyid` (== thumbprint) resolves against it.
//
// Three runtime-specific steps are injected so the same fetch/cache logic serves
// every edge runtime without pulling a verify primitive or a schema library into
// this module:
//
//   * keyId — how a JWK yields its map key. Production computes the RFC 7638
//     thumbprint of the key (keys.ts); a test/shim may substitute a stub.
//   * importJwk — how a JWK becomes a usable key. Full-WebCrypto runtimes
//     (Cloudflare) import to a CryptoKey via crypto.subtle.importKey; Fastly
//     Compute (whose SubtleCrypto lacks Ed25519) decodes `x` to raw bytes for
//     @noble/ed25519.
//   * parseKeys — how the fetched document yields the JWK list (a zod schema in
//     production; a dependency-free filter in the Fastly shim).
//
// keys.ts wraps this with the CryptoKey + zod production configuration; the
// Fastly E2E shim wraps it with raw-bytes + a manual parser. Neither the verify
// primitive nor zod is referenced here.

import { logRecord } from './log.js';

export interface KeyCache<K> {
  resolve(keyid: string | undefined): Promise<K | undefined>;
  refresh(): Promise<void>;
}

export interface KeyCacheDeps<K, J> {
  // Absolute URL of the producer's WBA directory
  // (/.well-known/http-message-signatures-directory). Fetched to resolve a keyid
  // that the pre-provisioned static set (if any) does not cover.
  wbaUrl: string;
  // Computes a parsed JWK's map key — its RFC 7638 thumbprint in production.
  keyId: (jwk: J) => Promise<string>;
  // Imports one parsed JWK into the runtime key type (CryptoKey, raw bytes, …).
  importJwk: (jwk: J) => Promise<K>;
  // Extracts the JWK list from the fetched WBA directory (schema-validated in
  // production; a plain filter in the dependency-free Fastly shim).
  parseKeys: (json: unknown) => J[];
  // Optional pre-provisioned verify keys (D5). When supplied and they cover the
  // requested keyid, the directory is NOT fetched. A keyid that misses the
  // static set triggers a one-shot directory fetch (rotation self-heal).
  staticKeys?: J[];
  fetcher?: typeof fetch;
  now?: () => number;
  ttlMs?: number;
}

interface Imported<K> {
  keys: Map<string, K>;
  defaultKeyId?: string;
}

// Upper bound on a fetched WBA directory, mirroring the Go loader's 64 KiB cap
// (internal/rampwellknown/fetch.go `maxDocBytes`). A compromised or hostile
// origin could otherwise stream an unbounded body straight into res.json() and
// exhaust the worker's memory; an over-cap response is rejected before parsing.
const MAX_WBA_DIRECTORY_BYTES = 64 * 1024;

// readBoundedJson parses a fetch Response as JSON while refusing to buffer more
// than maxBytes. It short-circuits on a Content-Length already over the cap,
// then enforces the same cap on the bytes actually read — Content-Length may be
// absent or dishonest — by draining the body stream chunk-by-chunk.
async function readBoundedJson(res: Response, maxBytes: number): Promise<unknown> {
  const declared = res.headers.get('content-length');
  if (declared !== null && Number(declared) > maxBytes) {
    throw new Error(`wba directory too large: content-length ${declared} over ${maxBytes} bytes`);
  }
  return JSON.parse(await readBoundedText(res, maxBytes));
}

async function readBoundedText(res: Response, maxBytes: number): Promise<string> {
  const body = res.body;
  if (!body) {
    // No readable stream (e.g. a stubbed Response): buffer then check the bytes.
    const text = await res.text();
    if (new TextEncoder().encode(text).byteLength > maxBytes) {
      throw new Error(`wba directory too large: over ${maxBytes} bytes`);
    }
    return text;
  }
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let out = '';
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error(`wba directory too large: over ${maxBytes} bytes`);
    }
    out += decoder.decode(value, { stream: true });
  }
  return out + decoder.decode();
}

export function createKeyCache<K, J>(deps: KeyCacheDeps<K, J>): KeyCache<K> {
  const ttl = deps.ttlMs ?? 60 * 60 * 1000;
  const fetcher = deps.fetcher ?? fetch;
  const now = deps.now ?? Date.now;

  async function importJwks(jwks: J[]): Promise<Imported<K>> {
    const keys = new Map<string, K>();
    let defaultKeyId: string | undefined;
    for (const jwk of jwks) {
      const id = await deps.keyId(jwk);
      keys.set(id, await deps.importJwk(jwk));
      if (defaultKeyId === undefined) defaultKeyId = id;
    }
    return defaultKeyId !== undefined ? { keys, defaultKeyId } : { keys };
  }

  // Pre-provisioned keys are imported lazily once, then never refetched.
  let staticReady: Promise<Imported<K>> | undefined;
  function ensureStatic() {
    if (!deps.staticKeys || deps.staticKeys.length === 0) return undefined;
    if (!staticReady) staticReady = importJwks(deps.staticKeys);
    return staticReady;
  }

  let cache: Map<string, K> | undefined;
  let fetchedAt = 0;
  let defaultKeyId: string | undefined;
  let inflight: Promise<void> | undefined;

  async function load(): Promise<void> {
    try {
      const res = await fetcher(deps.wbaUrl, { headers: { accept: 'application/jwk-set+json' } });
      if (!res.ok) {
        throw new Error(`wba directory fetch failed: ${res.status}`);
      }
      const json: unknown = await readBoundedJson(res, MAX_WBA_DIRECTORY_BYTES);
      const imported = await importJwks(deps.parseKeys(json));
      cache = imported.keys;
      defaultKeyId = imported.defaultKeyId;
      fetchedAt = now();
    } catch (err) {
      // A key directory that is down OR malformed means every signed-URL
      // verification starts failing — the operational record is what lets an
      // operator tell "the exchange's directory is broken" apart from "agents
      // send bad URLs". The event says load (not fetch) because this catch
      // spans the whole step: fetch, JSON read, parse, and key import — the
      // message carries which leg actually failed.
      // Deliberately NO request_id: the cache is a context-free singleton and
      // single-flight de-duplicates concurrent loads, so one fetch serves
      // many requests — naming any single request would be misleading. The
      // directory URL is the correlating fact instead.
      logRecord('error', 'edge.keys.load_failed', {
        message: err instanceof Error ? err.message : String(err),
        wba_url: deps.wbaUrl,
      });
      throw err;
    }
  }

  async function ensureFresh(): Promise<void> {
    if (cache && now() - fetchedAt < ttl) return;
    if (!inflight) {
      inflight = load().finally(() => {
        inflight = undefined;
      });
    }
    await inflight;
  }

  // Resolve from the fetched directory cache. Used both when no static keys are
  // configured and as the one-shot fallback when a keyid misses the static set.
  async function resolveFetched(keyid: string | undefined): Promise<K | undefined> {
    await ensureFresh();
    const lookup = keyid ?? defaultKeyId;
    if (!lookup) return undefined;
    return cache?.get(lookup);
  }

  return {
    async resolve(keyid) {
      const staticSet = ensureStatic();
      if (staticSet) {
        const { keys, defaultKeyId: staticDefault } = await staticSet;
        const lookup = keyid ?? staticDefault;
        if (lookup) {
          const hit = keys.get(lookup);
          if (hit) return hit;
        }
        // Unknown keyid (rotation) — one-shot directory fetch to self-heal.
        return resolveFetched(keyid);
      }
      return resolveFetched(keyid);
    },
    async refresh() {
      cache = undefined;
      await ensureFresh();
    },
  };
}
