package transport

import "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/broker"

// brokerIntermediaryHops is the number of intermediaries the Broker adds to a
// request chain: exactly one — itself, relaying Agent → Exchange. The repo is
// single-hop, so a resolved chain is always Agent → Broker → Exchange.
//
// Response-path invariant (RAMP ramp.proto, "Response Routing"): responses are
// delivered DIRECTLY, they do not retrace the request's intermediary chain.
// With a single Broker hop this is vacuously satisfied — the Broker returns the
// resolve result synchronously to its caller in ServeHTTP; nothing relays the
// response back through a chain. The invariant is stated here (and asserted in
// hopguard_test.go) so a future multi-hop relay preserves it deliberately.
const brokerIntermediaryHops int32 = 1

// enforceHopBudget implements the agent's RequestConstraints.max_hops self-cap
// (RAMP ramp.proto: "Broker MUST NOT forward a chain that would exceed
// max_hops"). maxHops is the agent's declared ceiling on intermediaries; the
// Broker contributes brokerIntermediaryHops. When the ceiling is below what the
// Broker would add, the request is refused rather than forwarded.
//
// Vacuous at the current single-hop depth (1 ≤ any max_hops ≥ 1); wired
// declaratively so a future multi-hop relay inherits the bound. The Exchange's
// own chain-depth tolerance is published as
// WellKnownManifest.max_intermediary_hops (set by the Exchange producer) and is
// now enforced Exchange-side via httpsig.VerifyRequestOptions.MaxSignatures
// (= max_intermediary_hops + 1, wired in the Exchange middleware), which rejects
// an over-long signature chain with httpsig.ErrTooManyHops.
func enforceHopBudget(maxHops *int32) error {
	if maxHops != nil && brokerIntermediaryHops > *maxHops {
		return broker.Newf(broker.KindInvalidArgument,
			"max_hops=%d forbids the broker relay hop (chain needs at least %d intermediary)",
			*maxHops, brokerIntermediaryHops).WithField("max_hops")
	}
	return nil
}
