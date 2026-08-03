// Package tigerbeetle owns the Exchange's connection to a TigerBeetle cluster
// and the non-lifecycle primitives the billing adapter builds on: a shared,
// thread-safe client, a deterministic string->u128 id mapping, and lazy,
// idempotent account creation. It deliberately holds no billing.Adapter logic —
// that is the tigerbeetle_adapter, a sibling in package billing.
//
// The client is CGO-backed (github.com/tigerbeetle/tigerbeetle-go links a native
// library). A single instance is shared across goroutines so the client can
// batch requests; callers must not open one per request.
package tigerbeetle
