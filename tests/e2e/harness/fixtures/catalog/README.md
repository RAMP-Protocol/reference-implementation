# E2E catalog feeds

The three publisher feeds this harness seeds its catalog from. They are owned by
the test suite. Change them when a test needs a term shape that is missing, and
do not change them to make a demo look better.

These started as a copy of the demo feeds under `deploy/fixtures/demo/`. That
directory is now demo-only. The two sets are free to diverge, and are expected
to: a demo wants one currency and a tidy story, a test suite wants the awkward
combinations.

## How they are used

`seed.py` shells out to the production `ramp-ingest` binary once per feed, each
a single signed `PushResources` RPC. There is no Python re-implementation of the
mapper and no direct catalog write. That is the property the suite depends on,
and it comes from the ingest path, not from which feed is on the other end of it.

Paths are resolved from the harness package, not from the repository root. The
runner image copies this tree to `/runner/harness`, so a repo-root-relative path
would not exist inside the container.

## Invariants the tests rely on

Change any of these and expect failures well away from the file you edited.

- **One feed per publisher domain, one edge runtime each.** `philosophy` is
  Cloudflare, `music` is Fastly, `sfx` is AWS. `sfx` is also the only
  `AWS_CLOUDFRONT_RSA` tenant, so it is the only feed that exercises RSA signing.
- **Currency spread: 11 EUR, 9 USD, 6 GBP across 26 terms in 22 records.** The
  suite needs more than one currency. The in-memory billing adapter denominates
  every balance in `billing.DemoCurrency` ("USD"), so USD terms are the only ones
  a funded buyer can transact — priced-path coverage depends on them existing.
  A EUR or GBP priced term is a currency-mismatch case, which is also worth
  keeping.
- **At least one FREE term per edge runtime.** The EUR buyer is unfunded by
  construction, so FREE terms are what it can reach. A zero charge skips the
  currency and balance gates.
- **Term shapes stay varied:** flat and per-unit pricing, quotas, obligations,
  prohibited functions, geo and user-type restrictions, and a subscription /
  reference-only entry. Each backs at least one scenario.
- **Every record stays VALID.** Malformed prices, unknown vocabulary tokens and
  other rejection cases belong in per-test inputs. One bad record here makes the
  whole seed fail, and every test with it.

## Content bodies

The feeds point at content served from `deploy/content/demo`, which
`docker-compose.e2e.yml` mounts into the origin container. Currency and licence
terms are catalog metadata; the article bodies are neutral, so they are still
shared. The retrieval canary the tests assert on lives in that content, so an
edit to the demo copy can break a test here. Split the content tree when that
starts happening, or when a test needs a body of its own.
