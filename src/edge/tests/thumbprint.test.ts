import { readFileSync } from 'node:fs';
import { URL, fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { thumbprint } from '../src/thumbprint.js';
import { decodeBase64Url } from '../src/verify.js';

// Shared cross-language fixture (ADR-013 D4). The Go (internal/rampthumbprint)
// and Python (src/mcp ramp_mcp_shim.thumbprint) implementations are pinned to
// the SAME file, so a byte-level divergence between any of the three thumbprint
// implementations fails here — the interop guarantee the bound-fetch path
// depends on.
const vectorsPath = fileURLToPath(
  new URL('../../../testdata/thumbprint-vectors.json', import.meta.url),
);

interface Vector {
  public_key_b64url: string;
  thumbprint: string;
}

const vectors = (JSON.parse(readFileSync(vectorsPath, 'utf8')) as { vectors: Vector[] }).vectors;

describe('thumbprint (RFC 7638, Ed25519) — shared parity vectors', () => {
  it('has vectors to check', () => {
    expect(vectors.length).toBeGreaterThan(0);
  });

  for (const v of vectors) {
    it(`matches the shared vector ${v.thumbprint}`, async () => {
      const pub = decodeBase64Url(v.public_key_b64url);
      expect(pub).toBeDefined();
      const got = await thumbprint(pub as Uint8Array);
      expect(got).toBe(v.thumbprint);
    });
  }

  it('rejects a non-32-byte key', async () => {
    await expect(thumbprint(new Uint8Array(31))).rejects.toThrow();
  });
});
