import type { CatalogContributor, Manifest, WbaFile, WbaKey } from './types.js';

// Type declaration for the plain-JS well-known.mjs (which carries no
// types so the build-step-less aws-edge shim can import it). types.ts re-exports
// the functions, so production callers get these typed signatures.
export function buildPublisherManifest(
  provider: string,
  exchanges: { domain: string; endpoint: string; supported_profiles?: string[] }[],
  contributors?: CatalogContributor[],
): Manifest;

// buildPublisherWba assembles the publisher's Web Bot Auth directory (a JWK Set
// of the publisher's Ed25519 signing keys, no kid, plus an optional
// directory-level revocation_url).
export function buildPublisherWba(keys: WbaKey[], revocationUrl?: string): WbaFile;

// Fixed discovery paths + WBA content type, single-sourced in
// well-known.mjs.
export const WELL_KNOWN_PATH: string;
export const WBA_PATH: string;
export const WBA_DIRECTORY_CONTENT_TYPE: string;
