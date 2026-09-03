// Structural disease guard for edge SDK adoption.
//
// This test pins the THREE structural pre-conditions that the edge SDK-adoption
// implementation must satisfy. It uses source-level assertions, which is
// permitted under the structural-disease exception for these guards:
// the diseases are non-behavioral (local
// copies instead of SDK imports, missing package dependency, out-of-vocabulary
// reason strings) with no runtime-observable surface that could carry them.
//
// Each guard pins one of the three structural invariants stated below; they stay
// green as long as the edge keeps importing the SDK helpers, declaring the SDK
// dependency, and using in-vocabulary reason strings.

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const edgeDir = fileURLToPath(String(new URL('../..', import.meta.url)));
const repoRoot = fileURLToPath(String(new URL('../../../..', import.meta.url)));

// ---------------------------------------------------------------------------
// Guard 1: @ramp-protocol/sdk-l1 MUST appear in src/edge/package.json
// ---------------------------------------------------------------------------
// Disease: the SDK is NOT listed — `grep -rn "@ramp-protocol/sdk-l1" src scripts
// deploy tests | grep -v node_modules` returns ZERO hits. After SDK adoption the
// package is installed as 'file:../../../RAMP-Protocol/protocol/sdk/ts' (dev pin).

describe('sdk-adoption guard: package.json', () => {
  it('src/edge/package.json lists @ramp-protocol/sdk-l1 as a dependency', () => {
    const raw = readFileSync(`${edgeDir}/package.json`, 'utf-8');
    const pkg = JSON.parse(raw) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const allDeps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
    expect(
      Object.keys(allDeps),
      '@ramp-protocol/sdk-l1 must be listed in dependencies or devDependencies — ' +
        'add it as "file:../../../RAMP-Protocol/protocol/sdk/ts"',
    ).toContain('@ramp-protocol/sdk-l1');
  });
});

// ---------------------------------------------------------------------------
// Guard 2: hand-rolled local copies MUST be deleted
// ---------------------------------------------------------------------------
// Disease: src/edge/src/{pop,verify,thumbprint}.ts are near-verbatim forks of
// sdk-l1 L1 helpers. After SDK adoption they are deleted; imports repoint to the SDK.

describe('sdk-adoption guard: local copies deleted', () => {
  for (const file of ['pop.ts', 'verify.ts', 'thumbprint.ts']) {
    it(`src/edge/src/${file} must NOT exist after SDK adoption`, () => {
      const path = `${edgeDir}/src/${file}`;
      expect(
        existsSync(path),
        `${file} still present — delete it and repoint imports to @ramp-protocol/sdk-l1`,
      ).toBe(false);
    });
  }
});

// ---------------------------------------------------------------------------
// Guard 3: Fastly standalone shim MUST use canonical VerifyFailure reason strings
// ---------------------------------------------------------------------------
// Disease: tests/e2e/fastly-edge/src/index.ts returns out-of-vocabulary kebab-
// case strings ('missing-params', 'kid-unknown', 'sig-decode') as VerifyResult
// reasons. These are NOT members of VerifyFailure and leak through the HTTP 403
// JSON body (app.ts handleVerifyResult: `reason: result.reason ?? 'unknown'`).
// After SDK adoption the shim imports VerifyFailure from @ramp-protocol/sdk-l1/verify
// which makes these strings compile errors; the fix replaces them with canonical
// members and splits the combined missing-params branch into missing_sig /
// missing_exp.
//
// The strings are checked at the source level because the standalone shim is a
// build-only WASM package with no test runner — there is no HTTP surface to
// drive them through in CI.

describe('sdk-adoption guard: fastly shim canonical reason strings', () => {
  const shimPath = `${repoRoot}/tests/e2e/fastly-edge/src/index.ts`;

  // Checked quote-agnostically (bare substring, not a quoted literal) so a
  // reintroduction via double quotes or a template literal cannot slip the
  // guard.
  it("fastly shim does not return 'missing-params' (must be missing_sig / missing_exp)", () => {
    const src = readFileSync(shimPath, 'utf-8');
    expect(
      src,
      "Found 'missing-params' in fastly shim — split the combined !sigB64 || !expStr " +
        "check into two returns ('missing_sig', 'missing_exp')",
    ).not.toContain('missing-params');
  });

  it("fastly shim does not return 'kid-unknown' (must be 'signature_mismatch')", () => {
    const src = readFileSync(shimPath, 'utf-8');
    expect(
      src,
      "Found 'kid-unknown' in fastly shim — replace with 'signature_mismatch'",
    ).not.toContain('kid-unknown');
  });

  it("fastly shim does not return 'sig-decode' (must be 'bad_sig_encoding')", () => {
    const src = readFileSync(shimPath, 'utf-8');
    expect(
      src,
      "Found 'sig-decode' in fastly shim — replace with 'bad_sig_encoding'",
    ).not.toContain('sig-decode');
  });
});

// ---------------------------------------------------------------------------
// Guard 4: edge source MUST import only the SDK's transport-free subpaths
// ---------------------------------------------------------------------------
// Disease: the SDK declares undici as a runtime dependency, and its client and
// resolver trees use it — resolvers/http.ts also imports node:dns/promises.
// Neither Cloudflare Workers nor Fastly Compute can run either module, so an
// import that reaches those trees breaks the worker at bundle or run time, not
// here.
//
// Nothing breaks today because both edge packages import exactly four leaf
// subpaths, and those four carry no IO. That is the whole reason undici never
// enters a wrangler or esbuild module graph, and until this guard existed it was
// a property nobody had written down — a bare `import { request } from "undici"`
// resolves from anywhere in either package.
//
// Scope is the SHIPPED source of both packages. Test helpers are excluded on
// purpose: they run under Node, where undici and node:dns both work, so an
// import there is not the defect this guards against.

const SDK_LEAF_SUBPATHS = ['base64url', 'pop', 'thumbprint', 'verify'];

// Node modules the two worker runtimes cannot provide. undici is the SDK's HTTP
// client; the rest are the dial surface a naive undici-only ban would let slip.
const NON_WORKER_MODULES = ['undici', 'node:dns', 'node:http', 'node:https', 'node:net'];

/** `dir` without a trailing separator, so joins do not produce a doubled one.
 * fileURLToPath of a directory URL keeps the trailing slash, which reached the
 * assertion messages as `src/edge//src/keys.ts`. */
function trimmed(dir: string): string {
  return dir.endsWith('/') ? dir.slice(0, -1) : dir;
}

/** Every shipped .ts file of both edge packages, as absolute paths. */
function shippedEdgeSources(): string[] {
  const roots = [`${trimmed(edgeDir)}/src`, `${trimmed(repoRoot)}/tests/e2e/fastly-edge/src`];
  const out: string[] = [];
  for (const root of roots) {
    if (!existsSync(root)) continue;
    for (const entry of readdirSync(root, { recursive: true, withFileTypes: true })) {
      if (entry.isFile() && entry.name.endsWith('.ts')) {
        out.push(`${entry.parentPath}/${entry.name}`);
      }
    }
  }
  return out;
}

/** The module specifiers `src` imports, from both the static and dynamic forms. */
function importedModules(src: string): string[] {
  const specifiers: string[] = [];
  const pattern = /(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g;
  for (const match of src.matchAll(pattern)) {
    specifiers.push(match[1] as string);
  }
  return specifiers;
}

describe('sdk-adoption guard: edge stays on transport-free SDK subpaths', () => {
  const sources = shippedEdgeSources();

  it('finds the shipped edge sources at all', () => {
    // A walk that matches nothing would pass both checks below in silence.
    expect(
      sources.length,
      'no shipped edge .ts files matched — the walk has stopped seeing them, so ' +
        'this guard is passing without checking anything',
    ).toBeGreaterThan(0);
  });

  for (const path of sources) {
    const rel = path.slice(trimmed(repoRoot).length + 1);

    it(`${rel} imports only the SDK's leaf subpaths`, () => {
      const reached = importedModules(readFileSync(path, 'utf-8'))
        .filter((m) => m.startsWith('@ramp-protocol/sdk-l1/'))
        .map((m) => m.slice('@ramp-protocol/sdk-l1/'.length))
        .filter((sub) => !SDK_LEAF_SUBPATHS.includes(sub));
      expect(
        reached,
        `${rel} imports @ramp-protocol/sdk-l1/${reached.join(', ')}.
Only ${SDK_LEAF_SUBPATHS.join(', ')} carry no IO. The client and resolver trees pull in
undici and node:dns, which neither Cloudflare Workers nor Fastly Compute can run, so
importing them breaks the worker rather than this test.`,
      ).toEqual([]);
    });

    it(`${rel} imports no module a worker runtime cannot provide`, () => {
      const reached = importedModules(readFileSync(path, 'utf-8')).filter((m) =>
        NON_WORKER_MODULES.some((mod) => m === mod || m.startsWith(`${mod}/`)),
      );
      expect(
        reached,
        `${rel} imports ${reached.join(', ')}.
Neither Cloudflare Workers nor Fastly Compute provides these. Use the runtime-agnostic
fetch the worker already has.`,
      ).toEqual([]);
    });
  }
});
