// Package ramproute answers one question about a failed endpoint resolution:
// was it a VERDICT about the address, or a peer that did not answer?
//
// The two call for opposite responses. A verdict — the value is not a usable
// host, the Exchange advertises no endpoint, or it advertises one on a host its
// manifest does not speak for — will be the same verdict on every attempt, so
// retrying only repeats the work. A dial failure or a timeout may succeed on the
// next try, and reporting one as a verdict permanently drops work over a
// momentary outage.
//
// It lives here, in one place, because the set of sentinels is the SDK's
// EndpointResolver contract rather than any one caller's opinion, and the
// contract can grow. Two services resolve Exchange endpoints — the identity
// service's account legs and the Broker's execute relay — and each used to
// carry its own copy of this test. If the SDK adds a fourth sentinel, a copy
// that was missed reports a final refusal as retryable.
package ramproute

import (
	"errors"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
)

// IsVerdict reports whether err is a decision the resolver reached about the
// address, rather than a failure to reach anything.
//
// helpers.ErrInvalidHost is in the set because a resolver checks the host
// itself, and a value that is not a host does not become one later. A caller
// that vets the host before resolving will not see it from the SDK's own
// resolver; an injected one can still produce it.
func IsVerdict(err error) bool {
	return errors.Is(err, helpers.ErrInvalidHost) ||
		errors.Is(err, resolvers.ErrNoEndpoint) ||
		errors.Is(err, resolvers.ErrEndpointRefused)
}
