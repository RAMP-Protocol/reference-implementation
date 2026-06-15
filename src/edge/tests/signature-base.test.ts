import { readFileSync } from 'node:fs';
import { URL, fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { signatureBase } from '../src/pop.js';

// Shared cross-language fixture (ADR-013 D2/D4). The Python agent signer
// (src/mcp ramp_mcp_shim.httpsig.pop_signature_base) is pinned to the SAME file,
// so a byte-level divergence in the PoP @target-uri signature base between the
// edge verifier and the agent signer fails here — before it rejects every bound
// fetch in production. Reads the repo-root fixture via fs, so it runs in the
// Node pool (vitest.node.config.ts), not the Workers pool.
const vectorsPath = fileURLToPath(
  new URL('../../../testdata/pop-signature-base-vectors.json', import.meta.url),
);

interface Vector {
  method: string;
  url: string;
  params: string;
  expected_base: string;
}

const vectors = (JSON.parse(readFileSync(vectorsPath, 'utf8')) as { vectors: Vector[] }).vectors;

describe('PoP signature base (RFC 9421) — shared parity vectors', () => {
  it('has vectors to check', () => {
    expect(vectors.length).toBeGreaterThan(0);
  });

  for (const v of vectors) {
    it(`matches the shared base for ${v.url}`, () => {
      expect(signatureBase(v.method, v.url, v.params)).toBe(v.expected_base);
    });
  }
});
