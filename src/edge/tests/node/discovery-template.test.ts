import { readFileSync } from 'node:fs';
import { URL, fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { createApp } from '../../src/app.js';
import { buildDeps, originModeConfigured, parseEnv } from '../../src/config.js';
import worker from '../../src/entries/cloudflare.js';
import { readFastlyEnv } from '../../src/entries/fastly.js';
import { WBA_PATH, WELL_KNOWN_PATH } from '../../src/types.js';
import { assertValidManifest, assertValidWba } from '../helpers/wellknown-schema.js';

// The files under deploy/publisher-wellknown/ are what an operator compares
// against the documents their own Worker serves. That only works while the
// templates and the Worker agree, and nothing in a JSON file can keep itself
// aligned with the code that emits it.
//
// So this suite drives template-env.json — the checked-in variable values that
// folder hands operators as the input half of its worked example — through the
// production path: parseEnv, then buildDeps, then a request to each address
// through the Worker's own routes. Each response body must be deep-equal to the
// template on disk. Schema validation alone would not do it: a template can
// satisfy the schema perfectly and still describe a document this Worker never
// emits.
//
// The request goes through the routes rather than stopping at the objects
// buildDeps returns, because the routes are what produce the bytes an operator
// receives. They also own the directory's content type. A handler that started
// post-processing either document would leave a buildDeps-level comparison
// passing while the served document changed.
//
// EXCHANGE_URL and EXCHANGE_WBA_URL are NOT pinned by the deep-equal assertions.
// EXCHANGE_URL becomes deps.exchangeUrl and EXCHANGE_WBA_URL goes to
// createKeyCache (src/config.ts), so neither reaches either document; both are in
// the fixture only because EnvSchema requires them. ORIGIN_URL reaches neither
// document either, and the last describe block is what pins it instead. Every
// remaining key is pinned by the deep-equal assertions: change one and the
// corresponding template must change with it, or they fail.
//
// The payee placeholder's SHAPE and the absent revocation_url are pinned on the
// Go side, which reads the same two files through the CONSUMER path
// (internal/rampwellknown/template_test.go). Asserting either here as well would
// be one property checked twice in two languages under two rules that can
// disagree, which is how the payee guard here and the one there came to accept
// different templates.
//
// What stays below is what nothing else covers: ext's key set, and the absent
// kid. The canonical schema constrains neither — ext is a protobuf Struct, and
// the schema permits extra properties — and ResourceOwnerID reads one key and
// ignores the rest, so an extra key would reach the served document with nothing
// rejecting it.

function readTemplate(name: string): unknown {
  const path = fileURLToPath(
    new URL(`../../../../deploy/publisher-wellknown/${name}`, import.meta.url),
  );
  return JSON.parse(readFileSync(path, 'utf8'));
}

// Typed once here because two of the assertions below index it by name, which
// does not compile against readTemplate's `unknown`. The cast is not taken on
// trust: EnvSchema declares every field a string, so parseEnv one line down
// throws if the fixture is not a flat map of strings.
const templateEnv = readTemplate('template-env.json') as Record<string, string>;

// The env the Cloudflare entry hands its fetch handler: Partial<EdgeEnv>.
type WorkerEnv = Parameters<typeof worker.fetch>[1];

describe('deploy/publisher-wellknown templates match what the Worker serves', () => {
  const manifestTemplate = readTemplate('ramp.json.example');
  const wbaTemplate = readTemplate('http-message-signatures-directory.example');
  const app = createApp(buildDeps(parseEnv(templateEnv)));

  it('ramp.json.example satisfies the canonical manifest schema', () => {
    assertValidManifest(manifestTemplate);
  });

  it('http-message-signatures-directory.example satisfies the canonical WBA schema', () => {
    assertValidWba(wbaTemplate);
  });

  it('the manifest route serves ramp.json.example for the documented env', async () => {
    const res = await app.request(WELL_KNOWN_PATH);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual(manifestTemplate);
  });

  it('the key-directory route serves the directory template as a JWK Set', async () => {
    const res = await app.request(WBA_PATH);
    expect(res.status).toBe(200);
    // Written out rather than compared against WBA_DIRECTORY_CONTENT_TYPE. The
    // route sets the header from that same constant, so comparing the two would
    // hold whatever the constant said and the assertion could never fail. This
    // string is the wire contract an off-the-shelf Web Bot Auth verifier reads
    // the directory by, and the README tells operators to curl for it.
    expect(res.headers.get('content-type')).toBe('application/jwk-set+json');
    expect(await res.json()).toEqual(wbaTemplate);
  });

  it('the template attests one payee and nothing else in ext', () => {
    // The Go suite owns the placeholder's shape — it must be a value no operator
    // could mistake for a real id. This owns the key SET, which nothing else
    // checks: a second key in ext is copied through to the served document and
    // then silently ignored by every consumer.
    const entry = (manifestTemplate as { exchanges: { ext?: Record<string, unknown> }[] })
      .exchanges[0];
    expect(Object.keys(entry?.ext ?? {})).toEqual(['resource_owner_id']);
  });

  it('the template directory key carries no kid', () => {
    // Web Bot Auth keys are named by their RFC 7638 thumbprint. A kid here is a
    // defect, and the schema allows extra properties, so it is asserted directly.
    const key = (wbaTemplate as { keys: Record<string, unknown>[] }).keys[0];
    expect(key?.kid).toBeUndefined();
  });
});

// The block above enters at createApp(buildDeps(parseEnv(...))). The guard that
// decides whether a deployment can serve at all sits one layer higher, in the
// runtime entries, so nothing above can see a fixture that no deployment would
// start on. The README tells operators this file holds every setting the Worker
// requires; these two assertions are what make that sentence checkable.
//
// What they prove: the Cloudflare entry's construction guard accepts these values
// and the manifest route answers under them. What they do NOT prove: anything
// about article traffic, and they are not real-runtime coverage. This suite reads
// its fixtures off disk, which is what puts it in the plain-node project
// (vitest.config.ts) rather than a Workers one. Both discovery routes do have
// real-runtime coverage, through SELF in tests/wellknown-keyless/.
describe('the documented environment is one the Worker starts on', () => {
  it('the Cloudflare entry accepts the fixture and serves the manifest', async () => {
    // The host only has to be a valid absolute URL; this route does not read it.
    const res = await worker.fetch(
      new Request(`https://www.publisher.example${WELL_KNOWN_PATH}`),
      templateEnv as unknown as WorkerEnv,
      {} as ExecutionContext,
    );
    expect(res.status).toBe(200);
  });

  it('the fixture names an origin mode the Fastly entry can also use', () => {
    // originModeConfigured on its own would not be enough: SAME_ZONE_ORIGIN
    // satisfies it and still leaves Fastly with no origin, because readFastlyEnv
    // deliberately never forwards that key. Reading the fixture THROUGH
    // readFastlyEnv is what makes the assertion hold for both runtimes.
    expect(originModeConfigured(readFastlyEnv((n) => templateEnv[n]))).toBe(true);
  });
});
