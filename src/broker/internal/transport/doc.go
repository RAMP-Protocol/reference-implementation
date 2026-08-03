// Package transport exposes the Broker's HTTP + Connect-Go handlers.
//
// The canonical proto-JSON Resolve endpoint (DiscoveryRequest → DiscoveryResponse)
// is the primary agent entrypoint; BrokerConnectHandler is the thin Connect
// adapter over the resolve business core (package
// src/broker/internal/resolve) — it decodes the wire request, maps it to a
// resolve.Request, runs the validate → authorize pipeline, calls
// (*resolve.Service).Resolve, and renders the result back to the wire
// DiscoveryResponse. The bespoke relay routes and the unified
// /.well-known/ramp.json route are also served here.
package transport
