package transport_test

// harnessExchangeDomain is this test Exchange's own canonical domain: the
// identity it publishes, what it stamps into the offers it issues, and the
// recipient every addressed request in this package names.
//
// It lives in an UNTAGGED file so that the tests which run without the
// integration tag name the same Exchange as the ones that run with it. Held
// under the tag, it forced those tests to write the domain as a literal, and a
// literal beside a constant is the drift the constant exists to prevent.
//
// The catalog resource-owner gate reads resource_owner_id from the
// AuthorizedExchange entry whose domain equals this, so the manifest stubs
// attest on this same domain — one source threaded into both
// NewCatalogService and the stub manifests.
const harnessExchangeDomain = "exchange.ramp.test"
