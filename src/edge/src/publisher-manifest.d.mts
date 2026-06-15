import type { CatalogContributor, Manifest } from './types.js';

// Type declaration for the plain-JS publisher-manifest.mjs (which carries no
// types so the build-step-less aws-edge shim can import it). types.ts re-exports
// the function, so production callers get this typed signature.
export function buildPublisherManifest(
  provider: string,
  exchanges: { domain: string; endpoint: string; supported_profiles?: string[] }[],
  contributors?: CatalogContributor[],
): Manifest;

// Fixed discovery-manifest path, single-sourced in publisher-manifest.mjs.
export const WELL_KNOWN_PATH: string;
